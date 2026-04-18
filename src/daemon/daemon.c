#define _FILE_OFFSET_BITS 64
#include "../../include/auth.h"
#include "../../include/common.h"
#include "../../include/protocol.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define DEFAULT_PORT 8080
#define MAX_VIEW_SIZE (1024 * 1024)

static pthread_mutex_t log_mtx = PTHREAD_MUTEX_INITIALIZER;

#define log_printf(...)                 \
	do {                                \
		pthread_mutex_lock(&log_mtx);   \
		printf(__VA_ARGS__);            \
		fflush(stdout);                 \
		pthread_mutex_unlock(&log_mtx); \
	} while (0)

typedef struct {
	int socket;
	char cwd[PATH_MAX];
} client;

static void write_uint64_be(uint8_t *buf, uint64_t val) {
	buf[0] = (val >> 56) & 0xFF;
	buf[1] = (val >> 48) & 0xFF;
	buf[2] = (val >> 40) & 0xFF;
	buf[3] = (val >> 32) & 0xFF;
	buf[4] = (val >> 24) & 0xFF;
	buf[5] = (val >> 16) & 0xFF;
	buf[6] = (val >> 8) & 0xFF;
	buf[7] = val & 0xFF;
}

static uint64_t read_uint64_be(const uint8_t *buf) {
	uint64_t v = 0;
	for (int i = 0; i < 8; i++)
		v = (v << 8) | buf[i];
	return v;
}

static int compute_sha256(const char *path, uint8_t out[32]) {
	FILE *f = fopen(path, "rb");
	if (!f)
		return -1;

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		fclose(f);
		return -1;
	}

	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
		EVP_MD_CTX_free(ctx);
		fclose(f);
		return -1;
	}

	uint8_t chunk[65536];
	size_t n;
	while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0) {
		EVP_DigestUpdate(ctx, chunk, n);
	}
	fclose(f);

	unsigned int out_len = 32;
	EVP_DigestFinal_ex(ctx, out, &out_len);
	EVP_MD_CTX_free(ctx);
	return 0;
}

static void resolve_path(client *c, const char *name, char *out) {
	if (name[0] == '/') {
		strncpy(out, name, PATH_MAX - 1);
		out[PATH_MAX - 1] = '\0';
	} else {
		snprintf(out, PATH_MAX, "%s/%s", c->cwd, name);
	}
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
	char resolved[PATH_MAX];

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

	if (realpath(new_path, resolved) == NULL) {
		resp.payload_size = 0;
		send_exact(c->socket, &resp, sizeof(resp));
		return -1;
	}

	struct stat st;
	if (stat(resolved, &st) != 0 || !S_ISDIR(st.st_mode)) {
		resp.payload_size = 0;
		send_exact(c->socket, &resp, sizeof(resp));
		return -1;
	}

	strncpy(c->cwd, resolved, PATH_MAX - 1);
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
	if (!fp)
		return -1;

	char buf[8192] = {0};
	size_t n = fread(buf, 1, sizeof(buf), fp);
	pclose(fp);

	message_header_t resp = {{MAGIC_1, MAGIC_2}, CMD_LS, htonl(n)};
	send_exact(client_sock, &resp, sizeof(resp));
	if (n > 0)
		send_exact(client_sock, buf, n);
	return 0;
}

int command_ls_detail(client *c, int client_sock) {
	DIR *d = opendir(c->cwd);
	message_header_t empty = {{MAGIC_1, MAGIC_2}, CMD_LS_DETAIL, 0};

	if (!d) {
		send_exact(client_sock, &empty, sizeof(empty));
		return -1;
	}

	size_t cap = 65536;
	uint8_t *buf = malloc(cap);
	if (!buf) {
		closedir(d);
		send_exact(client_sock, &empty, sizeof(empty));
		return -1;
	}

	size_t pos = 0;
	struct dirent *entry;

	while ((entry = readdir(d)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;

		char full[PATH_MAX];
		if (snprintf(full, PATH_MAX, "%s/%s", c->cwd, entry->d_name) >= PATH_MAX)
			continue;

		struct stat st;
		if (stat(full, &st) != 0)
			continue;

		uint8_t type = S_ISDIR(st.st_mode) ? 'd' : 'f';
		uint64_t size = S_ISREG(st.st_mode) ? (uint64_t)st.st_size : 0;
		uint16_t nl = (uint16_t)strlen(entry->d_name);
		size_t esz = 11 + nl;

		if (pos + esz > cap) {
			cap *= 2;
			uint8_t *nb = realloc(buf, cap);
			if (!nb)
				break;
			buf = nb;
		}

		buf[pos] = type;
		write_uint64_be(buf + pos + 1, size);
		buf[pos + 9] = (nl >> 8) & 0xFF;
		buf[pos + 10] = nl & 0xFF;
		memcpy(buf + pos + 11, entry->d_name, nl);
		pos += esz;
	}
	closedir(d);

	message_header_t resp = {{MAGIC_1, MAGIC_2}, CMD_LS_DETAIL, htonl(pos)};
	send_exact(client_sock, &resp, sizeof(resp));
	if (pos > 0)
		send_exact(client_sock, buf, pos);
	free(buf);
	return 0;
}

int command_read_file(client *c, const char *filename, int client_sock) {
	message_header_t empty = {{MAGIC_1, MAGIC_2}, CMD_READ_FILE, 0};

	char full[PATH_MAX];
	resolve_path(c, filename, full);

	struct stat st;
	if (stat(full, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > MAX_VIEW_SIZE) {
		send_exact(client_sock, &empty, sizeof(empty));
		return -1;
	}

	FILE *f = fopen(full, "rb");
	if (!f) {
		send_exact(client_sock, &empty, sizeof(empty));
		return -1;
	}

	uint8_t *content = malloc((size_t)st.st_size);
	if (!content) {
		fclose(f);
		send_exact(client_sock, &empty, sizeof(empty));
		return -1;
	}

	size_t n = fread(content, 1, (size_t)st.st_size, f);
	fclose(f);

	message_header_t resp = {{MAGIC_1, MAGIC_2}, CMD_READ_FILE, htonl((uint32_t)n)};
	send_exact(client_sock, &resp, sizeof(resp));
	if (n > 0)
		send_exact(client_sock, content, n);
	free(content);
	return 0;
}

int command_file_info(client *c, const char *filename, int client_sock) {
	message_header_t empty = {{MAGIC_1, MAGIC_2}, CMD_FILE_INFO, 0};

	char full[PATH_MAX];
	resolve_path(c, filename, full);

	struct stat st;
	if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) {
		send_exact(client_sock, &empty, sizeof(empty));
		return -1;
	}

	uint8_t sha256[32];
	if (compute_sha256(full, sha256) < 0) {
		send_exact(client_sock, &empty, sizeof(empty));
		return -1;
	}

	uint8_t payload[40];
	write_uint64_be(payload, (uint64_t)st.st_size);
	memcpy(payload + 8, sha256, 32);

	message_header_t resp = {{MAGIC_1, MAGIC_2}, CMD_FILE_INFO, htonl(40)};
	send_exact(client_sock, &resp, sizeof(resp));
	send_exact(client_sock, payload, 40);
	return 0;
}

int command_download(client *c, int client_sock, uint64_t offset, const char *filename) {
	message_header_t empty = {{MAGIC_1, MAGIC_2}, CMD_DOWNLOAD, 0};

	char full[PATH_MAX];
	resolve_path(c, filename, full);

	struct stat st;
	if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) {
		send_exact(client_sock, &empty, sizeof(empty));
		return -1;
	}

	uint64_t fsz = (uint64_t)st.st_size;
	if (offset >= fsz) {
		send_exact(client_sock, &empty, sizeof(empty));
		return 0;
	}

	uint64_t remaining = fsz - offset;
	if (remaining > (uint64_t)UINT32_MAX)
		remaining = (uint64_t)UINT32_MAX;

	FILE *f = fopen(full, "rb");
	if (!f) {
		send_exact(client_sock, &empty, sizeof(empty));
		return -1;
	}

	if (fseeko(f, (off_t)offset, SEEK_SET) != 0) {
		fclose(f);
		send_exact(client_sock, &empty, sizeof(empty));
		return -1;
	}

	uint8_t *data = malloc((size_t)remaining);
	if (!data) {
		fclose(f);
		send_exact(client_sock, &empty, sizeof(empty));
		return -1;
	}

	size_t n = fread(data, 1, (size_t)remaining, f);
	fclose(f);

	message_header_t resp = {{MAGIC_1, MAGIC_2}, CMD_DOWNLOAD, htonl((uint32_t)n)};
	send_exact(client_sock, &resp, sizeof(resp));
	if (n > 0)
		send_exact(client_sock, data, n);
	free(data);
	return 0;
}

int command_upload(client *c, int client_sock, const uint8_t *payload, uint32_t plen) {
	uint8_t status = 0x00;

	do {
		if (plen < 10)
			break;

		uint64_t offset = read_uint64_be(payload);
		uint16_t nl = ((uint16_t)payload[8] << 8) | payload[9];
		if (plen < (uint32_t)(10 + nl) || nl >= PATH_MAX)
			break;

		char filename[PATH_MAX];
		memcpy(filename, payload + 10, nl);
		filename[nl] = '\0';

		const uint8_t *data = payload + 10 + nl;
		uint32_t dlen = plen - 10 - nl;

		char full[PATH_MAX];
		resolve_path(c, filename, full);

		const char *mode = (offset == 0) ? "wb" : "r+b";
		FILE *f = fopen(full, mode);
		if (!f)
			break;

		if (offset > 0 && fseeko(f, (off_t)offset, SEEK_SET) != 0) {
			fclose(f);
			break;
		}

		if (dlen == 0 || fwrite(data, 1, dlen, f) == dlen) {
			status = 0x01;
		}
		fclose(f);
	} while (0);

	message_header_t resp = {{MAGIC_1, MAGIC_2}, CMD_UPLOAD, htonl(1)};
	send_exact(client_sock, &resp, sizeof(resp));
	send_exact(client_sock, &status, 1);
	return (status == 0x01) ? 0 : -1;
}

void *handle_client(void *arg) {
	client *c = (client *)arg;
	int sock = c->socket;

	log_printf("client connected socket:%d\n", sock);

	if (auth_server_handshake(sock) < 0) {
		log_printf("auth failed socket:%d\n", sock);
		close(sock);
		free(c);
		return NULL;
	}

	message_header_t header;

	while (recv_exact(sock, &header, sizeof(header)) > 0) {
		if (!validate_magic(header.magic)) {
			log_printf("invalid magic from socket:%d\n", sock);
			break;
		}

		switch (header.command_id) {
		case CMD_PING:
			log_printf("[PING] socket:%d\n", sock);
			command_ping(sock);
			break;

		case CMD_LS:
			log_printf("[LS] socket:%d\n", sock);
			command_ls(sock, c->cwd);
			break;

		case CMD_CD: {
			uint32_t plen = ntohl(header.payload_size);
			if (plen == 0 || plen >= PATH_MAX)
				break;
			char path[PATH_MAX];
			if (recv_exact(sock, path, plen) <= 0)
				goto done;
			path[plen] = '\0';
			log_printf("[CD] '%s' socket:%d\n", path, sock);
			command_cd(c, path);
			break;
		}

		case CMD_LS_DETAIL:
			log_printf("[LS_DETAIL] socket:%d\n", sock);
			command_ls_detail(c, sock);
			break;

		case CMD_READ_FILE: {
			uint32_t plen = ntohl(header.payload_size);
			if (plen == 0 || plen >= PATH_MAX)
				break;
			char name[PATH_MAX];
			if (recv_exact(sock, name, plen) <= 0)
				goto done;
			name[plen] = '\0';
			log_printf("[READ_FILE] '%s' socket:%d\n", name, sock);
			command_read_file(c, name, sock);
			break;
		}

		case CMD_FILE_INFO: {
			uint32_t plen = ntohl(header.payload_size);
			if (plen == 0 || plen >= PATH_MAX)
				break;
			char name[PATH_MAX];
			if (recv_exact(sock, name, plen) <= 0)
				goto done;
			name[plen] = '\0';
			log_printf("[FILE_INFO] '%s' socket:%d\n", name, sock);
			command_file_info(c, name, sock);
			break;
		}

		case CMD_DOWNLOAD: {
			uint32_t plen = ntohl(header.payload_size);
			if (plen < 9)
				break;
			uint8_t *payload = malloc(plen);
			if (!payload)
				break;
			if (recv_exact(sock, payload, plen) <= 0) {
				free(payload);
				goto done;
			}

			uint64_t offset = read_uint64_be(payload);
			uint32_t nlen = plen - 8;
			if (nlen >= PATH_MAX) {
				free(payload);
				break;
			}
			char name[PATH_MAX];
			memcpy(name, payload + 8, nlen);
			name[nlen] = '\0';
			free(payload);

			log_printf("[DOWNLOAD] '%s' offset=%llu socket:%d\n", name, (unsigned long long)offset, sock);
			command_download(c, sock, offset, name);
			break;
		}

		case CMD_UPLOAD: {
			uint32_t plen = ntohl(header.payload_size);
			if (plen < 10)
				break;
			uint8_t *payload = malloc(plen);
			if (!payload)
				break;
			if (recv_exact(sock, payload, plen) <= 0) {
				free(payload);
				goto done;
			}
			log_printf("[UPLOAD] socket:%d\n", sock);
			command_upload(c, sock, payload, plen);
			free(payload);
			break;
		}

		default:
			log_printf("[UNKNOWN] cmd=0x%02x socket:%d\n", header.command_id, sock);
			break;
		}
	}

done:
	log_printf("disconnected socket:%d\n", sock);
	close(sock);
	free(c);
	return NULL;
}

int handle(int server_sock) {
	while (1) {
		int client_sock = accept(server_sock, NULL, NULL);
		if (client_sock == -1) {
			perror("accept error");
			continue;
		}

		client *c = malloc(sizeof(client));
		if (!c) {
			perror("malloc error");
			close(client_sock);
			continue;
		}

		c->socket = client_sock;
		const char *home = getenv("HOME");
		strncpy(c->cwd, home ? home : "/", PATH_MAX - 1);
		c->cwd[PATH_MAX - 1] = '\0';

		pthread_t t;
		if (pthread_create(&t, NULL, handle_client, c) != 0) {
			perror("thread creation error");
			close(client_sock);
			free(c);
			continue;
		}
		pthread_detach(t);
	}
	return 0;
}

int main() {
	int server_sock = socket(AF_INET, SOCK_STREAM, 0);

	int opt = 1;
	setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	struct sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(DEFAULT_PORT);
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		perror("bind error");
		close(server_sock);
		return -1;
	}

	if (listen(server_sock, 10) == -1) {
		perror("listen error");
		close(server_sock);
		return -1;
	}

	printf("daemon listening on port %d\n", DEFAULT_PORT);

	handle(server_sock);
	return 0;
}
