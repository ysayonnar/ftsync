.PHONY: build clean

CC:=gcc
COMMON=./src/common/common.c
DAEMON_SRC=./src/daemon/daemon.c
CP_SRC=./src/cp/cp.c

build:
	$(CC) $(DAEMON_SRC) $(COMMON) -o ./build/daemon
	$(CC) $(CP_SRC) $(COMMON) -o ./build/cp

clean:
	rm -rf build/*
