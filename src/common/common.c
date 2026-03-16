#include "../../include/common.h"

#include <sys/socket.h>

int send_exact(int sock, const void *buf, size_t len) {
  size_t total_sent = 0;
  const char *ptr = (const char *)buf;

  while (total_sent < len) {
    ssize_t sent = send(sock, ptr + total_sent, len - total_sent, 0);
    if (sent <= 0) {
      return -1;
    }

    total_sent += sent;
  }

  return 1;
}

int recv_exact(int sock, void *buf, size_t len) {
  size_t total_read = 0;
  char *ptr = (char *)buf;

  while (total_read < len) {
    ssize_t bytes_read = recv(sock, ptr + total_read, len - total_read, 0);
    if (bytes_read <= 0) {
      return -1;
    }

    total_read += bytes_read;
  }

  return 1;
}
