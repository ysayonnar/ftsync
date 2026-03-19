#include "../../include/common.h"
#include "../../include/protocol.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_PORT 8080
#define PATH_MAX 4096

typedef struct {
	int socket;
	char cwd[PATH_MAX];
} client;

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

int command_ls(int client_sock, char *path) {
	char command[1024];
	snprintf(command, sizeof(command), "ls -la \"%s\"", path);

	FILE *fp = popen(command, "r");
	if (fp == NULL) {
		perror("popen error");
		return -1;
	}

	char output_buffer[8192] = {0};

	size_t total_read = fread(output_buffer, 1, sizeof(output_buffer), fp);
	pclose(fp);

	message_header_t resp;
	resp.magic[0] = MAGIC_1;
	resp.magic[1] = MAGIC_2;
	resp.command_id = CMD_LS;

	resp.payload_size = htonl(total_read);

	if (send_exact(client_sock, &resp, sizeof(resp)) <= 0) {
		perror("sending error");
		return -1;
	}

	if (total_read > 0) {
		if (send_exact(client_sock, output_buffer, total_read) <= 0) {
			perror("sending error");
			return -1;
		}
	}

	return 0;
}

// NOTE: memory leaks here are not resolved
int handle(int server_sock) {
	client **clients = NULL;
	int clients_amount = 0;

	while (1) {
		int client_sock = accept(server_sock, NULL, NULL);
		if (client_sock == -1) {
			perror("accept error");
			continue;
		}

		client *c = NULL;

		if (clients_amount != 0) {
			for (int i = 0; i < clients_amount; i++) {
				client *current = *(clients + i);
				if (current->socket == client_sock) {
					c = current;
				}
			}
		}

		if (c == NULL) {
			printf("New client 'socket:%d' connected\n", client_sock);

			c = malloc(sizeof(client));

			if (clients_amount == 0) {
				clients = malloc(sizeof(client *));
			} else {
				clients = realloc(clients, sizeof(client *) * (clients_amount + 1));
			}

			if (clients == NULL) {
				perror("allocation error");
				return -1;
			}

			clients_amount++;
			strncpy(c->cwd, "/", PATH_MAX);
			c->socket = client_sock;

			*(clients + clients_amount - 1) = c;
		}

		message_header_t header;

		while (recv_exact(client_sock, &header, sizeof(header)) > 0) {
			if (!validate_magic(header.magic)) {
				printf("invalid magic bytes. Disconnecting.\n");
				break;
			}

			switch (header.command_id) {
			case CMD_PING:
				printf("[PING] received from socket:%d\n", client_sock);
				command_ping(client_sock);
				break;
			case CMD_LS:
				printf("[LS] received from socket:%d\n", client_sock);
				command_ls(client_sock, c->cwd);
				break;
			default:
				printf("[UNKNOWN] command '%d' received form socket:%d\n", header.command_id, client_sock);
				break;
			}
		}

		printf("disconnected client socket:%d\n", client_sock);
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
