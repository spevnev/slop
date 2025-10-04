prefix      := /usr/local
exec_prefix := $(prefix)
bindir      := $(exec_prefix)/bin

SRC_DIR := src
OUT_DIR := build

BIN_NAME := slop
BIN_PATH := $(OUT_DIR)/$(BIN_NAME)
INSTALL_PATH := $(DESTDIR)$(bindir)/$(BIN_NAME)

CFLAGS := -std=c99 -Wall -Wextra -pedantic -MMD -MP -O2
LDLIBS := -lpam -lpam_misc

ifeq ($(DEBUG), 1)
	CFLAGS += -g3 -fsanitize=address,leak,undefined
endif

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst %.c, $(OUT_DIR)/%.o, $(SRCS))
DEPS := $(OBJS:.o=.d)

.PHONY: all clean install uninstall
all: $(BIN_PATH)

clean:
	rm -rf $(OUT_DIR)

install:
	install -D -m755 $(BIN_PATH) $(INSTALL_PATH)

uninstall:
	rm $(INSTALL_PATH)

$(BIN_PATH): $(OBJS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(OUT_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

-include $(DEPS)
