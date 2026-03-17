#include "../../include/protocol.h"

int validate_magic(uint8_t magic[2]) {
	return magic[0] == MAGIC_1 && magic[1] == MAGIC_2;
}
