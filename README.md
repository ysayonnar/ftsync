# File Exchange Manager

A multithreaded, portable file exchange management program implemented as a client-server system over TCP using a custom application-layer protocol.

## Overview

The system consists of two components:

- **Daemon** — runs on each host, manages the local filesystem, accepts connections, and handles file transfers.
- **CP (Control Program)** — initiates file exchange between two hosts, both running the daemon.

The CP allows the user to navigate the daemon's filesystem tree and initiate file/directory transfers between daemons.

## Features

- Custom binary application protocol over TCP (magic bytes `FX`, packed headers)
- UUID + RSA-based authentication on connection establishment (`uuid/uuid.h`, `openssl/ssl.h`)
- Integrity verification of transferred data
- Resume support — transfers can continue from a checkpoint after a connection interruption
- Multithreaded and portable

## Protocol

Messages use a fixed header (`message_header_t`):

| Field          | Type       | Description              |
|----------------|------------|--------------------------|
| `magic`        | `uint8_t[2]` | Always `FX` (`0x46 0x58`) |
| `command_id`   | `uint8_t`  | Command type             |
| `payload_size` | `uint32_t` | Payload length in bytes  |

Currently defined commands: `PING` (`0x01`), `PONG` (`0x02`).

## Build

```sh
make build
```

Produces `./build/daemon` and `./build/cp`.

```sh
make clean
```

## Dependencies

- GCC
- `libuuid` (`uuid/uuid.h`)
- OpenSSL (`openssl/ssl.h`)

## Usage

Start the daemon on each host:

```sh
./build/daemon
```

Use the CP to connect and manage file exchange:

```sh
./build/cp
```
