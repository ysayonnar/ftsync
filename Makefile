.PHONY: build clean

CC:=gcc
COMMON=./src/common/common.c ./src/common/protocol.c
DAEMON_SRC=./src/daemon/daemon.c
CP_SRC=./src/cp/cp.c

build:
	mkdir -p ./build
	$(CC) $(DAEMON_SRC) $(COMMON) -o ./build/daemon
	$(CC) $(CP_SRC) $(COMMON) -o ./build/cp

clean:
	rm -rf build/*

run-daemon:
	docker build -f src/daemon/Dockerfile -t daemon . && docker run -d -p 8080:8080 daemon
