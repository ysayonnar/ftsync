#ifndef COMMON_H
#define COMMON_H

#include <unistd.h>

int send_exact(int sock, const void *buf, size_t len);

int recv_exact(int sock, void *buf, size_t len);

#endif
