#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <unistd.h>

#define MAGIC_1 'F'
#define MAGIC_2 'X'

#define CMD_PING 0x01
#define CMD_PONG 0x02

#pragma pack(push, 1)
typedef struct {
  uint8_t magic[2];
  uint8_t command_id;
  uint32_t payload_size;
} message_header_t;
#pragma pack(pop)

#endif
