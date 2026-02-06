CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -g -pthread
LDFLAGS ?=

LIBBPF_CFLAGS ?=
LIBBPF_LDFLAGS ?= -lbpf -lelf

SYSTEMD_CFLAGS := $(shell pkg-config --cflags libsystemd 2>/dev/null)
SYSTEMD_LIBS := $(shell pkg-config --libs libsystemd 2>/dev/null)

ifneq ($(strip $(SYSTEMD_LIBS)),)
  LIBBPF_CFLAGS += $(SYSTEMD_CFLAGS) -DHONEYBAN_WITH_SYSTEMD
  LIBBPF_LDFLAGS += $(SYSTEMD_LIBS)
endif

BIN := honeyban-daemon
OUT_DIR := build

 SRC := \
  src/main.c \
  src/log.c \
  src/timeutil.c \
  src/json.c \
  src/bpf_loader.c \
  src/bans.c \
  src/config.c \
  src/api_server.c \
  src/cleanup.c \
  src/telemetry.c \
  src/journal.c \
  src/actions/actions.c \
  src/detection/detection.c \
  src/jails/ini.c \
  src/jails/cidr.c \
  src/jails/jails.c \
  src/jails/ipkey.c \
  src/filters/filters.c

OBJ := $(patsubst src/%.c,$(OUT_DIR)/%.o,$(SRC))

INSTALL_BIN ?= /usr/local/bin

.PHONY: all clean install

all: $(OUT_DIR) $(BIN)

$(OUT_DIR):
	mkdir -p $(OUT_DIR) $(OUT_DIR)/jails $(OUT_DIR)/filters $(OUT_DIR)/detection $(OUT_DIR)/actions

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $(BIN) $(OBJ) $(LIBBPF_LDFLAGS) $(LDFLAGS)

$(OUT_DIR)/%.o: src/%.c
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -Isrc -Iinclude -c $< -o $@

install: $(BIN)
	install -m 0755 $(BIN) $(INSTALL_BIN)/$(BIN)

clean:
	rm -rf $(OUT_DIR) $(BIN)
