#include "../../include/auth.h"
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
#include <sys/stat.h>
#include <unistd.h>

#define DEFAULT_PORT 8080

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
		close(server_sock);
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

int command_cd(client *c, const char *path) {
	char new_path[PATH_MAX];
	char resolved_path[PATH_MAX];

	if (path[0] == '/') {
		strncpy(new_path, path, PATH_MAX - 1);
		new_path[PATH_MAX - 1] = '\0';
	} else {
		if (snprintf(new_path, PATH_MAX, "%s/%s", c->cwd, path) >= PATH_MAX) {
			message_header_t resp = {{MAGIC_1, MAGIC_2}, CMD_CD, 0};
			send_exact(c->socket, &resp, sizeof(resp));
			return -1;
		}
	}

	message_header_t resp;
	resp.magic[0] = MAGIC_1;
	resp.magic[1] = MAGIC_2;
	resp.command_id = CMD_CD;

	if (realpath(new_path, resolved_path) == NULL) {
		resp.payload_size = 0;
		send_exact(c->socket, &resp, sizeof(resp));
		return -1;
	}

	struct stat st;
	if (stat(resolved_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
		resp.payload_size = 0;
		send_exact(c->socket, &resp, sizeof(resp));
		return -1;
	}

	strncpy(c->cwd, resolved_path, PATH_MAX - 1);
	c->cwd[PATH_MAX - 1] = '\0';

	uint32_t len = strlen(c->cwd);
	resp.payload_size = htonl(len);
	send_exact(c->socket, &resp, sizeof(resp));
	send_exact(c->socket, c->cwd, len);

	return 0;
}

int command_ls(int client_sock, char *path) {
	char command[1024];
	snprintf(command, sizeof(command), "ls \"%s\"", path);

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

			if (auth_server_handshake(client_sock) < 0) {
				printf("auth failed for socket:%d, disconnecting\n", client_sock);
				close(client_sock);
				continue;
			}

			c = malloc(sizeof(client));
			if (c == NULL) {
				perror("allocation error");
				close(client_sock);
				continue;
			}

			client **new_clients;
			if (clients_amount == 0) {
				new_clients = malloc(sizeof(client *));
			} else {
				new_clients = realloc(clients, sizeof(client *) * (clients_amount + 1));
			}

			if (new_clients == NULL) {
				perror("allocation error");
				free(c);
				close(client_sock);
				continue;
			}

			clients = new_clients;
			clients_amount++;
			strncpy(c->cwd, getenv("HOME"), PATH_MAX);
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
			case CMD_CD: {
				uint32_t path_len = ntohl(header.payload_size);
				if (path_len == 0 || path_len >= PATH_MAX) {
					printf("[CD] invalid payload size from socket:%d\n", client_sock);
					break;
				}
				char path[PATH_MAX];
				if (recv_exact(client_sock, path, path_len) <= 0) {
					break;
				}
				path[path_len] = '\0';
				printf("[CD] '%s' from socket:%d\n", path, client_sock);
				command_cd(c, path);
				break;
			}
			default:
				printf("[UNKNOWN] command '%d' received form socket:%d\n", header.command_id, client_sock);
				break;
			}
		}

		printf("disconnected client socket:%d\n", client_sock);
		close(client_sock);

		for (int i = 0; i < clients_amount; i++) {
			if (*(clients + i) == c) {
				free(c);
				for (int j = i; j < clients_amount - 1; j++) {
					*(clients + j) = *(clients + j + 1);
				}
				clients_amount--;
				if (clients_amount == 0) {
					free(clients);
					clients = NULL;
				} else {
					clients = realloc(clients, sizeof(client *) * clients_amount);
				}
				break;
			}
		}
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
		close(server_sock);
		return -1;
	}

	printf("demon started listening on port %d...\n", DEFAULT_PORT);

	if (handle(server_sock) == -1) {
		perror("handle socket error");
		return -1;
	}
}
