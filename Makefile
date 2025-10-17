prefix      := /usr/local
exec_prefix := $(prefix)
bindir      := $(exec_prefix)/bin

BIN_NAME := slop
OUT_DIR  := build
BIN_PATH := $(OUT_DIR)/$(BIN_NAME)
PAM_PATH := pam/$(BIN_NAME)

BIN_INSTALL_PATH := $(DESTDIR)$(bindir)/$(BIN_NAME)
PAM_INSTALL_PATH := $(DESTDIR)/etc/pam.d/$(BIN_NAME)

BASH_COMPLETION_PATH := $(DESTDIR)/usr/share/bash-completion/completions/$(BIN_NAME)
ZSH_COMPLETION_PATH  := $(DESTDIR)/usr/share/zsh/site-functions/_$(BIN_NAME)
FISH_COMPLETION_PATH := $(DESTDIR)/usr/share/fish/vendor_completions.d/$(BIN_NAME).fish

CFLAGS := -O2 -std=c99 -Wall -Wextra -pedantic
LDLIBS := -lpam -lpam_misc

.PHONY: all clean install uninstall
all: $(BIN_PATH)

$(BIN_PATH): src/main.c src/args.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LDLIBS)

clean:
	rm -rf $(OUT_DIR)

install: $(BIN_PATH)
	-$(BIN_PATH) completion bash > $(BASH_COMPLETION_PATH)
	-$(BIN_PATH) completion zsh > $(ZSH_COMPLETION_PATH)
	-$(BIN_PATH) completion fish > $(FISH_COMPLETION_PATH)
	-chmod 644 $(BASH_COMPLETION_PATH) $(ZSH_COMPLETION_PATH) $(FISH_COMPLETION_PATH)
	install -D -m 755 $(BIN_PATH) $(BIN_INSTALL_PATH)
	install -D -m 644 $(PAM_PATH) $(PAM_INSTALL_PATH)

uninstall:
	rm -f $(BIN_INSTALL_PATH) $(PAM_INSTALL_PATH) $(BASH_COMPLETION_PATH) $(ZSH_COMPLETION_PATH) $(FISH_COMPLETION_PATH)
