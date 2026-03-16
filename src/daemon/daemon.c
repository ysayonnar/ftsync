#include "../../include/common.h"
#include "../../include/protocol.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>

#define DEFAULT_PORT 8080

int main() {
	int server_sock = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in server_addr = {0};
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(DEFAULT_PORT);
	server_addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
		perror("binding socket error");
		return -1;
	}

	if (listen(server_sock, 5) == -1) {
		perror("listening socker error");
		return -1;
	}

	printf("demon started listening on port %d...\n", DEFAULT_PORT);

	while (1) {
		int client_sock = accept(server_sock, NULL, NULL);
		if (client_sock == -1) {
			perror("accept error");
			continue;
		}

		printf("somebody connected...\n");

		message_header_t header;

		if (recv_exact(client_sock, &header, sizeof(header)) > 0) {
			if (header.magic[0] == MAGIC_1 && header.magic[1] == MAGIC_2) {
				printf("valid protocol signature received!\n");

				if (header.command_id == CMD_PING) {
					printf("received PING, sending PONG...\n");

					message_header_t response;
					response.magic[0] = MAGIC_1;
					response.magic[1] = MAGIC_2;
					response.command_id = CMD_PONG;
					response.payload_size = 0;

					send_exact(client_sock, &response, sizeof(response));
				} else {
					printf("unknown command ID: %d\n", header.command_id);
				}
			} else {
				printf("invalid magic bytes. Disconnecting.\n");
			}
		} else {
			printf("failed to read header or client disconnected.\n");
		}

		close(client_sock);
		printf("client disconnected.\n\n");
	}
}
