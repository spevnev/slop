#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/kd.h>
#include <linux/vt.h>
#include <locale.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <utmpx.h>
#include "args.h"

#if defined(__has_attribute) && __has_attribute(unused)
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif

#ifndef _PATH_BTMP
#define _PATH_BTMP "/var/log/btmp"
#endif

#define GETPWNAM_BUFFER_SIZE 4096

#define ROOT_PATH_ENV "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
#define USER_PATH_ENV "/usr/local/bin:/usr/bin:/bin"

typedef struct {
    const char *path;
    const char *name;
    const char *number;
} tty_info;

#define ASSERT(condition)                                                                     \
    do {                                                                                      \
        if (!(condition)) {                                                                   \
            syslog(LOG_ALERT, "Assert (%s) failed at %s:%d", #condition, __FILE__, __LINE__); \
            exit(EXIT_FAILURE);                                                               \
        }                                                                                     \
    } while (0)

static volatile sig_atomic_t should_exit = false;

static void sig_handler(UNUSED int signal) {
    should_exit = true;
    syslog(LOG_INFO, "Received signal %d. Terminating", signal);
}

static pid_t child_pid = -1;
static void parent_sig_handler(UNUSED int signal) {
    ASSERT(child_pid != -1);
    // Shells ignore SIGTERM, so always send SIGHUP.
    kill(child_pid, SIGHUP);
}

static struct sigaction set_sig_handler(int signal, void (*handler)(int), int flags) {
    struct sigaction act = {0};
    sigemptyset(&act.sa_mask);
    act.sa_handler = handler;
    act.sa_flags = flags;

    struct sigaction old_act;
    sigaction(signal, &act, &old_act);
    return old_act;
}

static struct sigaction ignore_sig(int signal) { return set_sig_handler(signal, SIG_IGN, 0); }

static void restore_sig_handler(int signal, struct sigaction act) { sigaction(signal, &act, NULL); }

static void clear_tty(void) { printf("\033[H\033[J"); }

static int open_tty(const char *path) {
    ASSERT(path != NULL);

    int fd = open(path, O_RDWR);
    if (fd == -1) {
        syslog(LOG_ERR, "Failed to reopen TTY: %s", strerror(errno));
        return -1;
    }

    if (dup2(fd, STDIN_FILENO) == -1 ||   //
        dup2(fd, STDOUT_FILENO) == -1 ||  //
        dup2(fd, STDERR_FILENO) == -1) {
        syslog(LOG_ERR, "Failed to dup fd: %s", strerror(errno));
        return -1;
    }

    if (fd >= 3) close(fd);
    return 0;
}

static int chown_tty(uid_t uid) {
    if (fchown(STDIN_FILENO, uid, -1)) {
        syslog(LOG_ERR, "Failed to chown TTY: %s", strerror(errno));
        return -1;
    }

    if (fchmod(STDIN_FILENO, 0600)) {
        syslog(LOG_ERR, "Failed to chmod TTY: %s", strerror(errno));
        return -1;
    }

    return 0;
}

// Reset TTY attributes to reasonable settings, equivalent to `stty sane pass8` (see `man stty`).
// Set canonical mode, clear character delays, set 8-bit characters, reset control characters.
// See `man termios` to read about each option.
static int set_tty_attributes(void) {
    struct termios tp;
    if (tcgetattr(STDIN_FILENO, &tp) != 0) {
        syslog(LOG_ERR, "Failed to get terminal attributes: %s", strerror(errno));
        return -1;
    }

    // Reset flags.
    tp.c_iflag |= TTYDEF_IFLAG | BRKINT | ICRNL | IMAXBEL;
    tp.c_iflag &= ~(IGNBRK | INLCR | IGNCR | IXOFF | IUCLC | IXANY | ISTRIP | IUTF8);

    tp.c_oflag |= TTYDEF_OFLAG | OPOST | ONLCR | NL0 | CR0 | TAB0 | BS0 | VT0 | FF0;
    tp.c_oflag &= ~(OLCUC | OCRNL | ONOCR | ONLRET | OFILL | OFDEL | NLDLY | CRDLY | TABDLY | BSDLY | VTDLY | FFDLY);

    tp.c_cflag |= TTYDEF_CFLAG | CREAD | CS8;
    tp.c_cflag &= ~PARENB;

    tp.c_lflag |= TTYDEF_LFLAG | ISIG | ICANON | IEXTEN | ECHO | ECHOE | ECHOK | ECHOKE | ECHOCTL;
    tp.c_lflag &= ~(ECHONL | ECHOPRT | NOFLSH | TOSTOP | XCASE);

    // Set UTF8 mode if supported.
    int kbmode;
    if (ioctl(STDIN_FILENO, KDGKBMODE, &kbmode) == 0 && kbmode == K_UNICODE) tp.c_iflag |= IUTF8;

    // Reset special characters.
    // From `man termios`, VTIME and VMIN may overlap with VEOL and VEOF.
    // The former are ignored in canonical mode (ICANON), so set them first so
    // that they get overwritten in case of the overlap.
    tp.c_cc[VTIME] = 0;
    tp.c_cc[VMIN] = 1;

    tp.c_cc[VINTR] = CINTR;
    tp.c_cc[VQUIT] = CQUIT;
    tp.c_cc[VERASE] = CERASE;
    tp.c_cc[VKILL] = CKILL;
    tp.c_cc[VEOF] = CEOF;
    tp.c_cc[VSTART] = CSTART;
    tp.c_cc[VSTOP] = CSTOP;
    tp.c_cc[VSUSP] = CSUSP;
    tp.c_cc[VREPRINT] = CREPRINT;
    tp.c_cc[VDISCARD] = CDISCARD;
    tp.c_cc[VWERASE] = CWERASE;
    tp.c_cc[VLNEXT] = CLNEXT;

    // Disable alternative new line characters.
    tp.c_cc[VEOL] = _POSIX_VDISABLE;
    tp.c_cc[VEOL2] = _POSIX_VDISABLE;

    if (tcsetattr(STDIN_FILENO, TCSADRAIN, &tp)) {
        syslog(LOG_ERR, "Failed to set terminal attributes: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static int init_tty(tty_info *tty) {
    ASSERT(tty != NULL);

    if (!isatty(STDIN_FILENO)) {
        syslog(LOG_CRIT, "stdin is not TTY");
        return -1;
    }

    if ((fcntl(STDIN_FILENO, F_GETFL) & O_RDWR) != O_RDWR) {
        syslog(LOG_CRIT, "TTY is not open for read and write");
        return -1;
    }

    tty->path = ttyname(STDIN_FILENO);
    if (tty->path == NULL) {
        syslog(LOG_CRIT, "Failed to get TTY name: %s", strerror(errno));
        return -1;
    }
    tty->name = strncmp(tty->path, "/dev/", 5) == 0 ? tty->path + 5 : tty->path;

    tty->number = NULL;
    for (const char *c = tty->name; *c != '\0'; c++) {
        if (isdigit(*c)) {
            tty->number = c;
            break;
        }
    }
    if (tty->number == NULL) {
        syslog(LOG_CRIT, "Failed to get TTY number: bad path \"%s\"", tty->path);
        return -1;
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    struct sigaction old_act = ignore_sig(SIGHUP);
    vhangup();
    restore_sig_handler(SIGHUP, old_act);

    // Start a new session and reopen the TTY to make it the controlling terminal.
    setsid();
    if (open_tty(tty->path) != 0) return -1;
    if (chown_tty(0) != 0) return -1;
    if (set_tty_attributes() != 0) return -1;

    // Make the current process the foreground job of the session.
    // Only foreground can read from the terminal, and it receives all signals.
    if (tcsetpgrp(STDIN_FILENO, getpgrp()) != 0) {
        syslog(LOG_ERR, "Failed to set foreground job PGID: %s", strerror(errno));
        return -1;
    }

    return 0;
}

static struct utmpx new_utmpx_entry(const char *username, const tty_info *tty) {
    ASSERT(tty != NULL);

    struct timeval tv;
    gettimeofday(&tv, NULL);

    struct utmpx ut = {0};
    ut.ut_type = USER_PROCESS;
    ut.ut_pid = getpid();
    strncpy(ut.ut_line, tty->name, sizeof(ut.ut_line));
    strncpy(ut.ut_id, tty->number, sizeof(ut.ut_id));
    strncpy(ut.ut_user, username, sizeof(ut.ut_user));
    ut.ut_tv.tv_sec = tv.tv_sec;
    ut.ut_tv.tv_usec = tv.tv_usec;
    return ut;
}

// Log a failed login attempt to btmp.
static void log_btmp(const char *username, const tty_info *tty) {
    // NULL username indicates logout, use "(unknown)" instead.
    struct utmpx ut = new_utmpx_entry(username == NULL ? "(unknown)" : username, tty);
    updwtmpx(_PATH_BTMP, &ut);
}

// Log login to utmp and wtmp.
static void log_utmp_login(const char *username, const tty_info *tty) {
    struct utmpx ut = new_utmpx_entry(username, tty);

    utmpxname(_PATH_UTMP);
    setutxent();
    pututxline(&ut);
    endutxent();

    updwtmpx(_PATH_WTMP, &ut);
}

// Log logout to utmp and wtmp.
static void log_utmp_logout(const char *username, const tty_info *tty) {
    struct utmpx ut = new_utmpx_entry(username, tty);
    ut.ut_type = DEAD_PROCESS;

    utmpxname(_PATH_UTMP);
    setutxent();
    pututxline(&ut);
    endutxent();

    // wtmp uses NULL username to indicate logout.
    memset(ut.ut_user, 0, sizeof(ut.ut_user));
    updwtmpx(_PATH_WTMP, &ut);
}

static void log_pam_error(const char *where, pam_handle_t *pamh, int result) {
    ASSERT(where != NULL && pamh != NULL);

    const char *msg = pam_strerror(pamh, result);
    ASSERT(msg != NULL);
    syslog(LOG_ERR, "PAM error in %s: %s", where, msg);
}

static const char *pamx_get_username(const pam_handle_t *pamh) {
    ASSERT(pamh != NULL);
    const void *item = NULL;
    if (pam_get_item(pamh, PAM_USER, &item) != PAM_SUCCESS) return NULL;
    return (const char *) item;
}

// Wrapper around `misc_conv` that returns error to finish PAM call instead of blocking.
static int conv_wrapper(int num_msg, const struct pam_message **msgm, struct pam_response **response,
                        void *appdata_ptr) {
    if (should_exit) return PAM_CONV_ERR;
    return misc_conv(num_msg, msgm, response, appdata_ptr);
}

static pam_handle_t *pamx_init(const tty_info *tty, const char *username) {
    ASSERT(tty != NULL);

    struct pam_conv conv = {
        .conv = conv_wrapper,
        .appdata_ptr = NULL,
    };
    pam_handle_t *pamh = NULL;
    int result = pam_start("slop", username, &conv, &pamh);
    if (result != PAM_SUCCESS) {
        log_pam_error("start", pamh, result);
        return NULL;
    }

    if ((result = pam_set_item(pamh, PAM_TTY, tty->path)) != PAM_SUCCESS ||  //
        (result = pam_set_item(pamh, PAM_USER_PROMPT, "Login: ")) != PAM_SUCCESS) {
        log_pam_error("set_item", pamh, result);
        pam_end(pamh, result);
        return NULL;
    }

    return pamh;
}

static int pamx_auth(pam_handle_t *pamh, const tty_info *tty, const char *title, int retry_delay) {
    ASSERT(pamh != NULL && tty != NULL);

    while (true) {
        clear_tty();
        if (title != NULL) printf("%s\n", title);

        int result = pam_authenticate(pamh, 0);
        if (should_exit) return -1;
        if (result == PAM_SUCCESS) break;

        const char *username = result == PAM_USER_UNKNOWN ? NULL : pamx_get_username(pamh);
        log_btmp(username, tty);

        if (result == PAM_USER_UNKNOWN) {
            fprintf(stderr, "Incorrect login\n");
            pam_set_item(pamh, PAM_USER, NULL);
        } else if (result == PAM_AUTH_ERR) {
            fprintf(stderr, "Incorrect password\n");
        } else if (result == PAM_MAXTRIES) {
            fprintf(stderr, "Too many tries\n");
            return -1;
        } else {
            log_pam_error("authenticate", pamh, result);
            return -1;
        }

        // Wait before retrying to slow down login attempts and give time to read error messages.
        sleep(retry_delay);
    }

    int result = pam_acct_mgmt(pamh, 0);
    if (should_exit) return -1;
    if (result == PAM_NEW_AUTHTOK_REQD) {
        result = pam_chauthtok(pamh, PAM_CHANGE_EXPIRED_AUTHTOK);
        if (should_exit) return -1;
    }
    if (result != PAM_SUCCESS) {
        log_pam_error("acct_mgmt", pamh, result);
        return -1;
    }

    return 0;
}

static int pamx_open_session(pam_handle_t *pamh) {
    ASSERT(pamh != NULL);

    int result = pam_open_session(pamh, 0);
    if (should_exit) return -1;
    if (result != PAM_SUCCESS) {
        log_pam_error("open_session", pamh, result);
        return -1;
    }

    result = pam_setcred(pamh, PAM_ESTABLISH_CRED);
    if (should_exit) return -1;
    if (result != PAM_SUCCESS) {
        log_pam_error("setcred", pamh, result);
        pam_close_session(pamh, 0);
        return -1;
    }

    return 0;
}

static int init_environ(pam_handle_t *pamh, const struct passwd *pwd) {
    ASSERT(pamh != NULL && pwd != NULL);

    if (setenv("TERM", "linux", 0) != 0 ||          //
        setenv("HOME", pwd->pw_dir, 1) != 0 ||      //
        setenv("USER", pwd->pw_name, 1) != 0 ||     //
        setenv("LOGNAME", pwd->pw_name, 1) != 0 ||  //
        setenv("SHELL", pwd->pw_shell, 1) != 0 ||   //
        setenv("PATH", pwd->pw_uid == 0 ? ROOT_PATH_ENV : USER_PATH_ENV, 1) != 0) {
        syslog(LOG_ERR, "Failed to set environment variable: %s", strerror(errno));
        return -1;
    }

    char **env = pam_getenvlist(pamh);
    if (env == NULL) {
        syslog(LOG_ERR, "Failed to get PAM environment variables");
        return -1;
    }
    for (int i = 0; env[i] != NULL; i++) {
        putenv(env[i]);
        free(env[i]);
    }
    free(env);

    return 0;
}

static struct passwd *get_passwd(const char *username, char **buffer) {
    ASSERT(username != NULL && buffer != NULL);

    struct passwd *passwd_buffer = malloc(sizeof(*passwd_buffer));
    if (passwd_buffer == NULL) {
        syslog(LOG_ERR, "Process ran out of memory");
        return NULL;
    }

    *buffer = malloc(GETPWNAM_BUFFER_SIZE);
    if (*buffer == NULL) {
        free(passwd_buffer);
        syslog(LOG_ERR, "Process ran out of memory");
        return NULL;
    }

    struct passwd *passwd = NULL;
    int result = getpwnam_r(username, passwd_buffer, *buffer, GETPWNAM_BUFFER_SIZE, &passwd);
    if (result != 0 || passwd == NULL) {
        if (result != 0) {
            syslog(LOG_ERR, "Failed to get password record: %s", strerror(result));
        } else {
            syslog(LOG_ERR, "Unknown username \"%s\"", username);
        }
        free(passwd_buffer);
        free(*buffer);
        return NULL;
    }

    if (passwd->pw_shell == NULL) passwd->pw_shell = _PATH_BSHELL;
    return passwd;
}

static char *get_shell_name(const char *shell_path) {
    ASSERT(shell_path != NULL);

    const char *last_slash = strrchr(shell_path, '/');
    const char *name = last_slash == NULL ? shell_path : last_slash + 1;

    size_t buffer_size = strlen(name) + 2;
    char *buffer = malloc(buffer_size);
    if (buffer == NULL) {
        syslog(LOG_ERR, "Process ran out of memory");
        return NULL;
    }
    // Prepend '-' to the shell name to indicate that this is a login shell,
    // so that it runs `/etc/profile` and other initial configuration files.
    int written = snprintf(buffer, buffer_size, "-%s", name);
    ASSERT(written == (int) (buffer_size - 1));
    return buffer;
}

int main(int argc, char **argv) {
    bool success = false;

    // Prevent user from killing the program using 'Ctrl+C' and 'Ctrl+\'.
    ignore_sig(SIGINT);
    ignore_sig(SIGQUIT);

    // Exit gracefully on SIGTERM and SIGHUP.
    // Do not set `SA_RESTART` so that signal interrupts PAM conversation and causes
    // a PAM function to fail instead of waiting for user input indefinitely.
    set_sig_handler(SIGTERM, sig_handler, 0);
    set_sig_handler(SIGHUP, sig_handler, 0);

    // If locale is "", it is set according to the environment variables.
    setlocale(LC_ALL, "");

    openlog("slop", 0, LOG_AUTHPRIV);

    args a = {0};
    bool *help = option_flag(&a, 'h', "help", "Show help");
    long *retry_delay = option_long(&a, 'd', "delay", "Number of seconds to wait after failed login attempt", true, 2);
    const char **title = option_str(&a, 't', "title", "Title to print above the prompt", true, NULL);
    const char **provided_username = option_str(&a, 'u', "username", "Use the provided username", true, NULL);
    const char **command = option_str(&a, 'c', "command", "Command to run on successful login", true, NULL);
    bool *focus_tty = option_flag(&a, 'f', "focus", "Focus the TTY");

    char **pos_args;
    int pos_args_len = parse_args(&a, argc, argv, &pos_args);

    if (*help) {
        printf("%s - simple login program\n", argv[0]);
        printf("Usage: %s [options]\n", argv[0]);
        printf("\n");
        print_options(&a, stdout);
        success = true;
        goto exit1;
    }

    if (pos_args_len > 0) {
        fprintf(stderr, "Positional arguments are not allowed. See \"--help\".\n");
        syslog(LOG_CRIT, "Invalid argument: positional arguments are not allowed");
        goto exit1;
    }

    if (*retry_delay <= 0) {
        fprintf(stderr, "Retry delay must be a positive integer.\n");
        syslog(LOG_CRIT, "Invalid argument: retry delay must be a positive integer");
        goto exit1;
    }

    tty_info tty = {0};
    if (init_tty(&tty) != 0) goto exit1;

    if (*focus_tty) {
        ASSERT(tty.number != NULL);
        ioctl(STDIN_FILENO, VT_ACTIVATE, atoi(tty.number));
    }

    pam_handle_t *pamh = pamx_init(&tty, *provided_username);
    if (pamh == NULL) goto exit1;
    if (pamx_auth(pamh, &tty, *title, *retry_delay) != 0) goto exit2;

    const char *username = pamx_get_username(pamh);
    if (username == NULL) {
        syslog(LOG_ERR, "Failed to get username");
        goto exit2;
    }

    char *pwdbuf = NULL;
    struct passwd *pwd = get_passwd(username, &pwdbuf);
    if (pwd == NULL) goto exit2;

    // Set user groups from `/etc/group`. `initgroups` overwrites current groups
    // so it should be done before opening PAM session in case that `pam_setcred`
    // adds more groups.
    if (initgroups(username, pwd->pw_gid) != 0) {
        syslog(LOG_ERR, "Failed to initialize groups: %s", strerror(errno));
        goto exit3;
    }

    if (pamx_open_session(pamh) != 0) goto exit3;
    log_utmp_login(username, &tty);
    if (init_environ(pamh, pwd) != 0) goto exit4;
    if (chown_tty(pwd->pw_uid) != 0) goto exit4;

    // Give up the controlling terminal and reacquire it in the child process.
    struct sigaction old_act = ignore_sig(SIGHUP);
    if (ioctl(STDIN_FILENO, TIOCNOTTY) != 0) {
        syslog(LOG_ERR, "Failed to detach the controlling TTY: %s", strerror(errno));
        goto exit4;
    }
    restore_sig_handler(SIGHUP, old_act);

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    sigset_t signals = {0};
    sigaddset(&signals, SIGHUP);
    sigaddset(&signals, SIGTERM);
    sigprocmask(SIG_BLOCK, &signals, NULL);

    pid_t pid = fork();
    if (pid < 0) {
        syslog(LOG_ERR, "Failed to fork");
        goto exit4;
    }

    if (pid != 0) {
        // Setup handlers that will forward signals to the child process.
        child_pid = pid;
        set_sig_handler(SIGHUP, parent_sig_handler, 0);
        set_sig_handler(SIGTERM, parent_sig_handler, 0);
        sigprocmask(SIG_UNBLOCK, &signals, NULL);

        while (wait(NULL) == -1 && errno == EINTR);

        success = true;
        goto exit4;
    }

    sigprocmask(SIG_UNBLOCK, &signals, NULL);

    // Use `PAM_DATA_SILENT` to indicate that we just want to release the resources,
    // and the other process (parent) will properly end it.
    pam_end(pamh, PAM_SUCCESS | PAM_DATA_SILENT);
    // Unset pam handler to skip PAM cleanup.
    pamh = NULL;

    // Start a new session and reacquire the TTY, again.
    setsid();
    if (open_tty(tty.path) != 0) goto exit4;

    int result = setgid(pwd->pw_gid);
    ASSERT(result == 0);
    // Drop the root privileges.
    result = setuid(pwd->pw_uid);
    ASSERT(result == 0);

    const char *home_env = getenv("HOME");
    const char *home = home_env == NULL ? pwd->pw_dir : home_env;
    if (chdir(home) != 0) {
        syslog(LOG_ERR, "Failed to change directory to \"%s\": %s", home, strerror(errno));
        goto exit4;
    }

    // Ignored signals may remain ignored after exec, reset their handlers.
    set_sig_handler(SIGINT, SIG_DFL, 0);
    set_sig_handler(SIGQUIT, SIG_DFL, 0);

    if (should_exit) goto exit4;

    char *shell_name = get_shell_name(pwd->pw_shell);
    if (shell_name == NULL) goto exit4;
    if (*command == NULL) {
        execlp(pwd->pw_shell, shell_name, NULL);
        syslog(LOG_ERR, "Failed to exec shell \"%s\": %s", pwd->pw_shell, strerror(errno));
    } else {
        execlp(pwd->pw_shell, shell_name, "-c", *command, NULL);
        syslog(LOG_ERR, "Failed to exec shell \"%s\" with command \"%s\": %s", pwd->pw_shell, *command,
               strerror(errno));
    }
    free(shell_name);

exit4:
    if (pamh != NULL) {
        log_utmp_logout(username, &tty);
        pam_close_session(pamh, 0);
        pam_setcred(pamh, PAM_DELETE_CRED);
    }
exit3:
    free(pwdbuf);
    free(pwd);
exit2:
    if (pamh != NULL) pam_end(pamh, success ? PAM_SUCCESS : PAM_SYSTEM_ERR);
exit1:
    free_args(&a);
    closelog();
    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
