#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <unistd.h>

#define MAGIC_1 'F'
#define MAGIC_2 'X'

#define CMD_PING 0x01
#define CMD_PONG 0x02
#define CMD_LS 0x03
#define CMD_CD 0x04
#define CMD_LS_DETAIL  0x05
#define CMD_READ_FILE  0x06
#define CMD_FILE_INFO  0x07
#define CMD_DOWNLOAD   0x08
#define CMD_UPLOAD     0x09

#define CMD_AUTH_PUBKEY    0x10
#define CMD_AUTH_CHALLENGE 0x11
#define CMD_AUTH_RESPONSE  0x12
#define CMD_AUTH_OK        0x13
#define CMD_AUTH_FAIL      0x14

#pragma pack(push, 1)
typedef struct {
	uint8_t magic[2];
	uint8_t command_id;
	uint32_t payload_size;
} message_header_t;
#pragma pack(pop)

int validate_magic(uint8_t magic[2]);

#endif
