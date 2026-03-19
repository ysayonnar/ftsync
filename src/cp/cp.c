#include "../../include/common.h"
#include "../../include/protocol.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 8080

int connect_to_daemon(const char *daemon_host, int daemon_port) {
	printf("connecting to -> %s:%d\n", daemon_host, daemon_port);

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		perror("socket creation error");
		return -1;
	}

	struct sockaddr_in server_addr = {0};
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(daemon_port);

	if (inet_pton(AF_INET, daemon_host, &server_addr.sin_addr) <= 0) {
		perror("invalid address or address not supported");
		return -1;
	}

	printf("connecting to daemon %s:%d...\n", daemon_host, daemon_port);
	if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
		perror("connection failed");
		return -1;
	}
	printf("connected to daemon!\n");

	return sock;
}

int send_ping(int sock) {
	message_header_t req;
	req.magic[0] = MAGIC_1;
	req.magic[1] = MAGIC_2;
	req.command_id = CMD_PING;
	req.payload_size = 0;

	printf("sending PING...\n");
	if (send_exact(sock, &req, sizeof(req)) <= 0) {
		perror("failed to send data");
		close(sock);
		return -1;
	}

	message_header_t resp;
	if (recv_exact(sock, &resp, sizeof(resp)) <= 0) {
		perror("receiving error");
		return -1;
	}

	if (!validate_magic(resp.magic)) {
		perror("invalid magic");
		return -1;
	}

	if (resp.command_id == CMD_PONG) {
		printf("received PONG\n");
	} else {
		printf("unknown command received: %d\n", resp.command_id);
	}

	return 0;
}

int send_ls(int sock) {
	message_header_t req;
	req.magic[0] = MAGIC_1;
	req.magic[1] = MAGIC_2;
	req.command_id = CMD_LS;
	req.payload_size = 0;

	if (send_exact(sock, &req, sizeof(req)) <= 0) {
		perror("error sending ls");
		return -1;
	}

	message_header_t resp;

	if (recv_exact(sock, &resp, sizeof(resp)) <= 0) {
		printf("daemon connection refused");
		return -1;
	}

	if (!validate_magic(resp.magic)) {
		printf("invalid magic");
		return -1;
	}

	uint32_t payload_size = ntohl(resp.payload_size);
	if (payload_size == 0) {
		printf("empty daemon response");
		return -1;
	}

	char *buffer = malloc(payload_size + 1);
	if (buffer == NULL) {
		perror("malloc error");
		return -1;
	}

	if (recv_exact(sock, buffer, payload_size) <= 0) {
		printf("error reading data from daemon");
		free(buffer);
		return -1;
	}

	buffer[payload_size] = '\0';
	printf("\n--- Daemon LS ---\n%s", buffer);
	printf("---------------------------\n");

	free(buffer);

	return 0;
}

int send_cd(int sock, const char *path) {
	uint32_t path_len = strlen(path);

	message_header_t req;
	req.magic[0] = MAGIC_1;
	req.magic[1] = MAGIC_2;
	req.command_id = CMD_CD;
	req.payload_size = htonl(path_len);

	if (send_exact(sock, &req, sizeof(req)) <= 0) {
		perror("error sending cd");
		return -1;
	}

	if (send_exact(sock, path, path_len) <= 0) {
		perror("error sending cd path");
		return -1;
	}

	message_header_t resp;
	if (recv_exact(sock, &resp, sizeof(resp)) <= 0) {
		printf("daemon connection refused");
		return -1;
	}

	if (!validate_magic(resp.magic)) {
		printf("invalid magic");
		return -1;
	}

	uint32_t payload_size = ntohl(resp.payload_size);
	if (payload_size == 0) {
		printf("cd: no such directory: %s\n", path);
		return -1;
	}

	char *new_cwd = malloc(payload_size + 1);
	if (new_cwd == NULL) {
		perror("malloc error");
		return -1;
	}

	if (recv_exact(sock, new_cwd, payload_size) <= 0) {
		printf("error reading response from daemon");
		free(new_cwd);
		return -1;
	}

	new_cwd[payload_size] = '\0';
	printf("cwd: %s\n", new_cwd);
	free(new_cwd);

	return 0;
}

int main() {
	char daemon_host[256] = DEFAULT_HOST;
	int daemon_port = DEFAULT_PORT;
	char buffer[256];

	printf("enter daemon address [host:port] => ");

	if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
		if (buffer[0] != '\n') {
			int parsed = sscanf(buffer, "%255[^:]:%d", daemon_host, &daemon_port);

			if (parsed < 2) {
				printf("invalid format, using default/partial values\n");
			}
		}
	}

	int sock = connect_to_daemon(daemon_host, daemon_port);
	if (sock == -1) {
		perror("connecting to daemon error");
		return -1;
	}

	char cmd[256];
	while (1) {
		printf("\ncommand [ping/ls/cd <path>/quit] => ");
		if (fgets(cmd, sizeof(cmd), stdin) == NULL) {
			break;
		}

		if (strncmp(cmd, "ping", 4) == 0) {
			send_ping(sock);
		} else if (strncmp(cmd, "ls", 2) == 0) {
			send_ls(sock);
		} else if (strncmp(cmd, "cd", 2) == 0) {
			char path[256] = "/";
			sscanf(cmd, "cd %255s", path);
			send_cd(sock, path);
		} else if (strncmp(cmd, "quit", 4) == 0) {
			break;
		} else {
			printf("unknown command\n");
		}
	}

	close(sock);
	return 0;
}