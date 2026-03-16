#include "../../include/common.h"
#include "../../include/protocol.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#define DAEMON_PORT 8080
#define DAEMON_IP "127.0.0.1"

int main() {
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		perror("socket creation error");
		return -1;
	}

	struct sockaddr_in server_addr = {0};
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(DAEMON_PORT);

	if (inet_pton(AF_INET, DAEMON_IP, &server_addr.sin_addr) <= 0) {
		perror("invalid address or address not supported");
		return -1;
	}

	printf("connecting to daemon %s:%d...\n", DAEMON_IP, DAEMON_PORT);
	if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
		perror("connection failed");
		return -1;
	}
	printf("connected to daemon!\n");

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
	if (recv_exact(sock, &resp, sizeof(resp)) > 0) {
		if (resp.magic[0] == MAGIC_1 && resp.magic[1] == MAGIC_2) {
			if (resp.command_id == CMD_PONG) {
				printf("received PONG\n");
			} else {
				printf("unknown command received: %d\n", resp.command_id);
			}
		} else {
			printf("invalid magic\n");
		}
	} else {
		printf("unable to get response\n");
	}

	close(sock);
	return 0;
}
