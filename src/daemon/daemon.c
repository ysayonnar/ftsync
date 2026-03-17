#include "../../include/common.h"
#include "../../include/protocol.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>

#define DEFAULT_PORT 8080

int init_socket() {
	int server_sock = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in server_addr = {0};
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(DEFAULT_PORT);
	server_addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
		perror("binding socket error");
		return -1;
	}

	return server_sock;
}

int command_ping(int client_sock) {
	message_header_t response;
	response.magic[0] = MAGIC_1;
	response.magic[1] = MAGIC_2;
	response.command_id = CMD_PONG;
	response.payload_size = 0;

	send_exact(client_sock, &response, sizeof(response));

	return 0;
}

int handle(int server_sock) {
	while (1) {
		int client_sock = accept(server_sock, NULL, NULL);
		if (client_sock == -1) {
			perror("accept error");
			continue;
		}

		message_header_t header;

		if (recv_exact(client_sock, &header, sizeof(header)) <= 0) {
			printf("failed to read header or client disconnected.\n");
			continue;
		}

		if (!validate_magic(header.magic)) {
			printf("invalid magic bytes. Disconnecting.\n");
			continue;
		}

		switch (header.command_id) {
		case CMD_PING:
			command_ping(client_sock);
			break;

		default:
			printf("unknown command ID: %d\n", header.command_id);
			break;
		}

		close(client_sock);
	}

	return 0;
}

int main() {
	int server_sock = init_socket();
	if (server_sock == -1) {
		perror("initializing socker error");
		return -1;
	}

	if (listen(server_sock, 5) == -1) {
		perror("listening socker error");
		return -1;
	}

	printf("demon started listening on port %d...\n", DEFAULT_PORT);

	if (handle(server_sock) == -1) {
		perror("handle socket error");
		return -1;
	}
}
