.PHONY: build clean

CC:=gcc
COMMON=./src/common/common.c ./src/common/protocol.c ./src/common/auth.c
DAEMON_SRC=./src/daemon/daemon.c
CP_SRC=./src/cp/cp.c

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	OPENSSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null || echo /opt/homebrew/opt/openssl@3)
	CFLAGS  := -I$(OPENSSL_PREFIX)/include
	LDFLAGS := -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto
else
	CFLAGS  :=
	LDFLAGS := -lssl -lcrypto -luuid
endif

build:
	mkdir -p ./build
	$(CC) $(CFLAGS) $(DAEMON_SRC) $(COMMON) -o ./build/daemon $(LDFLAGS)
	$(CC) $(CFLAGS) $(CP_SRC) $(COMMON) -o ./build/cp $(LDFLAGS)

clean:
	rm -rf build/*

run-daemon:
	docker build -f src/daemon/Dockerfile -t daemon . && docker run -d -p 8080:8080 daemon
