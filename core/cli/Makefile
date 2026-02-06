CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -g

BIN := honeyban

SRC := \
  src/main.c \
  src/client.c \
  src/pretty.c \
  src/service.c

OBJ := $(SRC:.c=.o)

.PHONY: all clean install

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $(BIN) $(OBJ)

src/%.o: src/%.c include/honeyban_cli.h
	$(CC) $(CFLAGS) -Iinclude -c $< -o $@

install: $(BIN)
	install -m 0755 $(BIN) /usr/local/bin/$(BIN)

clean:
	rm -f $(BIN) $(OBJ)
