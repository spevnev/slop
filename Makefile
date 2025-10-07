prefix      := /usr
exec_prefix := $(prefix)
bindir      := $(exec_prefix)/bin
sysconfdir  := /etc

BIN_NAME := slop
OUT_DIR  := build
BIN_PATH := $(OUT_DIR)/$(BIN_NAME)
PAM_PATH := pam/$(BIN_NAME)

BIN_INSTALL_PATH := $(DESTDIR)$(bindir)/$(BIN_NAME)
PAM_INSTALL_PATH := $(DESTDIR)$(sysconfdir)/$(BIN_NAME)

CFLAGS := -O2 -std=c99 -Wall -Wextra -pedantic
LDLIBS := -lpam -lpam_misc

.PHONY: all clean install uninstall
all: $(BIN_PATH)

$(BIN_PATH): src/main.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

clean:
	rm -rf $(OUT_DIR)

install: $(BIN_PATH)
	install -D -m 755 $(BIN_PATH) $(BIN_INSTALL_PATH)
	install -D -m 644 $(PAM_PATH) $(PAM_INSTALL_PATH)

uninstall:
	rm -f $(BIN_INSTALL_PATH)
	rm -f $(PAM_INSTALL_PATH)
