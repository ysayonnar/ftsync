# CLAUDE.md

NEVER write comments. All printf's MUST BE english-language. Naming patter is snake_case.

ALWAYS write code that will compile and work both on macOS and any Linux distro. If this is impossible, say to user about this to figure the approach.

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

```bash
make build          # compile both binaries to ./build/
./build/daemon      # start the daemon (listens on 0.0.0.0:8080)
./build/cp          # start the control program (prompts for host:port, default 127.0.0.1:8080)

make run-daemon     # build Docker image and run daemon in container
make clean          # remove build artifacts
```

The Makefile auto-detects the platform: on macOS it finds OpenSSL via `brew --prefix openssl`, on Linux it uses system paths with `-luuid`.

The Dockerfile (`src/daemon/Dockerfile`) builds daemon-only on Alpine Linux.

## Architecture

Two binaries communicate over raw TCP on port 8080 using a custom binary protocol.

**Shared code** (`src/common/`):
- `common.c` — `send_exact`/`recv_exact`: loop until exactly N bytes are sent/received over TCP
- `protocol.c` — `validate_magic`: validates the `FX` magic bytes that prefix every message
- `auth.c` — full UUID+RSA handshake logic for both sides

**Protocol framing** (`include/protocol.h`): every message is a 7-byte packed header (`magic[2]` + `command_id` + `payload_size` BE uint32) followed by an optional payload.

**Authentication sequence** (happens before any commands):
1. CP generates RSA-2048 key pair, sends public key → daemon (`CMD_AUTH_PUBKEY`)
2. Daemon generates UUID, encrypts with client's public key → CP (`CMD_AUTH_CHALLENGE`)
3. CP decrypts with private key, sends UUID back → daemon (`CMD_AUTH_RESPONSE`)
4. Daemon compares UUIDs → sends `CMD_AUTH_OK` or `CMD_AUTH_FAIL`

**Daemon** (`src/daemon/daemon.c`): single-threaded, handles one client at a time in a blocking loop. Maintains a heap-allocated `client**` array (socket fd + cwd string). After each `accept()`, runs auth handshake before entering the command dispatch loop.

**CP** (`src/cp/cp.c`): interactive CLI. After connect + auth, accepts `ping`, `ls`, `cd <path>`, `quit`.

**Adding a new command**: define `CMD_*` constant in `protocol.h`, add handler in `daemon.c`'s switch, add send/recv function in `cp.c`.
