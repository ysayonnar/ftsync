.PHONY: build clean

CC:=gcc
COMMON=./src/common/common.c ./src/common/protocol.c ./src/common/auth.c
DAEMON_SRC=./src/daemon/daemon.c
CP_SRC=./src/cp/cp.c

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	OPENSSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null || echo /opt/homebrew/opt/openssl@3)
	CFLAGS  := -I$(OPENSSL_PREFIX)/include -std=c11 -W -Wall -Wextra -pedantic -pthread
	LDFLAGS := -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto
	BUILD_DIR := ./build/mac
else
	CFLAGS  := -std=c11 -W -Wall -Wextra -pedantic -pthread
	LDFLAGS := -lssl -lcrypto -luuid
	BUILD_DIR := ./build/linux
endif

build:
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(DAEMON_SRC) $(COMMON) -o $(BUILD_DIR)/daemon $(LDFLAGS)
	$(CC) $(CFLAGS) $(CP_SRC) $(COMMON) -o $(BUILD_DIR)/cp $(LDFLAGS) -lncurses

clean:
	rm -rf ./build