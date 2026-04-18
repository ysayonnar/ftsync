#include "../../include/auth.h"
#include "../../include/common.h"
#include "../../include/protocol.h"
#include <arpa/inet.h>
#include <ncurses.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 8080
#define MAX_FILE_VIEW_SIZE (1024 * 1024)
#define MAX_PATH 4096
#define MAX_NAME 256

typedef struct {
	char name[MAX_NAME];
	int is_dir;
	uint64_t size;
} entry_t;

typedef struct {
	entry_t *entries;
	int count;
	int selected;
	int scroll;
	char cwd[MAX_PATH];
	char status[512];
} browser_t;

static int connect_to_daemon(const char *host, int port) {
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		perror("socket creation error");
		return -1;
	}

	struct sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
		perror("invalid address");
		close(sock);
		return -1;
	}

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		perror("connection failed");
		close(sock);
		return -1;
	}

	return sock;
}

static int send_cd_get_path(int sock, const char *path, char *out, int out_size) {
	uint32_t path_len = strlen(path);

	message_header_t req;
	req.magic[0] = MAGIC_1;
	req.magic[1] = MAGIC_2;
	req.command_id = CMD_CD;
	req.payload_size = htonl(path_len);

	if (send_exact(sock, &req, sizeof(req)) <= 0) return -1;
	if (send_exact(sock, path, path_len) <= 0) return -1;

	message_header_t resp;
	if (recv_exact(sock, &resp, sizeof(resp)) <= 0) return -1;
	if (!validate_magic(resp.magic)) return -1;

	uint32_t size = ntohl(resp.payload_size);
	if (size == 0 || (int)size >= out_size) return -1;

	if (recv_exact(sock, out, size) <= 0) return -1;
	out[size] = '\0';

	return 0;
}

static int send_ls_detail(int sock, browser_t *br) {
	message_header_t req;
	req.magic[0] = MAGIC_1;
	req.magic[1] = MAGIC_2;
	req.command_id = CMD_LS_DETAIL;
	req.payload_size = 0;

	free(br->entries);
	br->entries = malloc(sizeof(entry_t));
	if (!br->entries) return -1;

	strcpy(br->entries[0].name, "..");
	br->entries[0].is_dir = 1;
	br->entries[0].size = 0;
	br->count = 1;

	if (send_exact(sock, &req, sizeof(req)) <= 0) return -1;

	message_header_t resp;
	if (recv_exact(sock, &resp, sizeof(resp)) <= 0) return -1;
	if (!validate_magic(resp.magic)) return -1;

	uint32_t total_size = ntohl(resp.payload_size);
	if (total_size == 0) return 0;

	uint8_t *buf = malloc(total_size);
	if (!buf) return -1;

	if (recv_exact(sock, buf, total_size) <= 0) {
		free(buf);
		return -1;
	}

	int extra = 0;
	size_t pos = 0;
	while (pos + 11 <= total_size) {
		uint16_t nl = ((uint16_t)buf[pos + 9] << 8) | buf[pos + 10];
		if (pos + 11 + nl > total_size) break;
		pos += 11 + nl;
		extra++;
	}

	entry_t *new_entries = realloc(br->entries, sizeof(entry_t) * (1 + extra));
	if (!new_entries) {
		free(buf);
		return 0;
	}
	br->entries = new_entries;

	int idx = 1;
	pos = 0;
	while (pos + 11 <= total_size && idx <= extra) {
		uint8_t type = buf[pos];
		uint64_t sz = ((uint64_t)buf[pos + 1] << 56) | ((uint64_t)buf[pos + 2] << 48) |
		              ((uint64_t)buf[pos + 3] << 40) | ((uint64_t)buf[pos + 4] << 32) |
		              ((uint64_t)buf[pos + 5] << 24) | ((uint64_t)buf[pos + 6] << 16) |
		              ((uint64_t)buf[pos + 7] << 8) | (uint64_t)buf[pos + 8];
		uint16_t nl = ((uint16_t)buf[pos + 9] << 8) | buf[pos + 10];

		if (pos + 11 + nl > total_size) break;

		if (nl > 0 && nl < MAX_NAME) {
			memcpy(br->entries[idx].name, buf + pos + 11, nl);
			br->entries[idx].name[nl] = '\0';
			br->entries[idx].is_dir = (type == 'd');
			br->entries[idx].size = sz;
			idx++;
		}
		pos += 11 + nl;
	}

	br->count = idx;
	free(buf);
	return 0;
}

static int send_read_file(int sock, const char *filename, char **out, uint32_t *out_size) {
	uint32_t name_len = strlen(filename);

	message_header_t req;
	req.magic[0] = MAGIC_1;
	req.magic[1] = MAGIC_2;
	req.command_id = CMD_READ_FILE;
	req.payload_size = htonl(name_len);

	if (send_exact(sock, &req, sizeof(req)) <= 0) return -1;
	if (send_exact(sock, filename, name_len) <= 0) return -1;

	message_header_t resp;
	if (recv_exact(sock, &resp, sizeof(resp)) <= 0) return -1;
	if (!validate_magic(resp.magic)) return -1;

	uint32_t size = ntohl(resp.payload_size);
	if (size == 0) return -1;

	char *content = malloc(size + 1);
	if (!content) return -1;

	if (recv_exact(sock, content, size) <= 0) {
		free(content);
		return -1;
	}
	content[size] = '\0';

	*out = content;
	*out_size = size;
	return 0;
}

static int cmp_entry(const void *a, const void *b) {
	const entry_t *ea = (const entry_t *)a;
	const entry_t *eb = (const entry_t *)b;
	if (strcmp(ea->name, "..") == 0) return -1;
	if (strcmp(eb->name, "..") == 0) return 1;
	if (ea->is_dir != eb->is_dir) return eb->is_dir - ea->is_dir;
	return strcasecmp(ea->name, eb->name);
}

static void sort_entries(browser_t *br) {
	if (br->count > 0) {
		qsort(br->entries, br->count, sizeof(entry_t), cmp_entry);
	}
}

static void format_size(uint64_t size, char *buf, int len) {
	if (size < 1024) {
		snprintf(buf, len, "%llu B", (unsigned long long)size);
	} else if (size < 1024 * 1024) {
		snprintf(buf, len, "%.1f KB", size / 1024.0);
	} else if (size < (uint64_t)1024 * 1024 * 1024) {
		snprintf(buf, len, "%.1f MB", size / (1024.0 * 1024.0));
	} else {
		snprintf(buf, len, "%.1f GB", size / (1024.0 * 1024.0 * 1024.0));
	}
}

static void draw_browser(browser_t *br) {
	int rows, cols;
	getmaxyx(stdscr, rows, cols);

	erase();

	attron(COLOR_PAIR(3) | A_BOLD);
	mvprintw(0, 0, "%-*.*s", cols, cols, br->cwd);
	attroff(COLOR_PAIR(3) | A_BOLD);

	int visible = rows - 2;
	if (visible < 1) visible = 1;

	for (int i = 0; i < visible; i++) {
		int idx = br->scroll + i;
		if (idx >= br->count) break;

		entry_t *e = &br->entries[idx];
		int selected = (idx == br->selected);

		if (selected) {
			attron(COLOR_PAIR(2) | A_BOLD);
		} else if (e->is_dir) {
			attron(COLOR_PAIR(1) | A_BOLD);
		}

		char line[4096];
		if (e->is_dir) {
			snprintf(line, sizeof(line), " %s/", e->name);
		} else {
			char size_str[32];
			format_size(e->size, size_str, sizeof(size_str));
			int name_w = cols - 16;
			if (name_w < 4) name_w = 4;
			snprintf(line, sizeof(line), " %-*s %12s", name_w, e->name, size_str);
		}
		mvprintw(i + 1, 0, "%-*.*s", cols, cols, line);

		if (selected) {
			attroff(COLOR_PAIR(2) | A_BOLD);
		} else if (e->is_dir) {
			attroff(COLOR_PAIR(1) | A_BOLD);
		}
	}

	attron(COLOR_PAIR(3));
	char footer[512];
	if (br->status[0]) {
		snprintf(footer, sizeof(footer), " %s", br->status);
	} else {
		snprintf(footer, sizeof(footer),
		         " Enter:open  Backspace/Left:parent  q:quit  [%d/%d]",
		         br->selected + 1, br->count);
	}
	mvprintw(rows - 1, 0, "%-*.*s", cols, cols, footer);
	attroff(COLOR_PAIR(3));

	refresh();
}

static void view_content(const char *title, const char *content, uint32_t size) {
	int line_cap = 64;
	char **lines = malloc(sizeof(char *) * line_cap);
	if (!lines) return;

	char *buf = malloc(size + 1);
	if (!buf) {
		free(lines);
		return;
	}
	memcpy(buf, content, size);
	buf[size] = '\0';

	int line_count = 0;
	lines[line_count++] = buf;

	for (uint32_t i = 0; i < size; i++) {
		if (buf[i] == '\n') {
			buf[i] = '\0';
			if (i + 1 < size) {
				if (line_count >= line_cap) {
					line_cap *= 2;
					char **nl = realloc(lines, sizeof(char *) * line_cap);
					if (!nl) break;
					lines = nl;
				}
				lines[line_count++] = buf + i + 1;
			}
		}
	}

	int scroll = 0;
	int running = 1;

	while (running) {
		int rows, cols;
		getmaxyx(stdscr, rows, cols);
		int visible = rows - 2;
		if (visible < 1) visible = 1;

		erase();

		attron(COLOR_PAIR(3) | A_BOLD);
		mvprintw(0, 0, "%-*.*s", cols, cols, title);
		attroff(COLOR_PAIR(3) | A_BOLD);

		for (int i = 0; i < visible && (scroll + i) < line_count; i++) {
			const char *src = lines[scroll + i];
			char line_buf[4096];
			int j = 0;
			while (*src && j < (int)sizeof(line_buf) - 1) {
				unsigned char ch = (unsigned char)*src++;
				line_buf[j++] = (ch < 32 && ch != '\t') ? '.' : (char)ch;
			}
			line_buf[j] = '\0';
			mvprintw(i + 1, 0, "%.*s", cols, line_buf);
		}

		attron(COLOR_PAIR(3));
		char footer[256];
		snprintf(footer, sizeof(footer),
		         " q/ESC:back  Up/Down:scroll  PgUp/PgDn:page  line %d/%d",
		         scroll + 1, line_count);
		mvprintw(rows - 1, 0, "%-*.*s", cols, cols, footer);
		attroff(COLOR_PAIR(3));

		refresh();

		int ch = getch();
		switch (ch) {
		case KEY_UP:
			if (scroll > 0) scroll--;
			break;
		case KEY_DOWN:
			if (scroll + visible < line_count) scroll++;
			break;
		case KEY_PPAGE:
			scroll -= visible;
			if (scroll < 0) scroll = 0;
			break;
		case KEY_NPAGE:
			scroll += visible;
			if (scroll + visible > line_count) scroll = line_count - visible;
			if (scroll < 0) scroll = 0;
			break;
		case KEY_RESIZE:
			break;
		case 'q':
		case 'Q':
		case 27:
			running = 0;
			break;
		}
	}

	free(lines);
	free(buf);
}

static void navigate_up(int sock, browser_t *br) {
	char came_from[MAX_NAME] = {0};
	char *slash = strrchr(br->cwd, '/');
	if (slash && slash != br->cwd) {
		strncpy(came_from, slash + 1, MAX_NAME - 1);
	}

	char new_cwd[MAX_PATH];
	if (send_cd_get_path(sock, "..", new_cwd, sizeof(new_cwd)) != 0) return;

	strncpy(br->cwd, new_cwd, MAX_PATH - 1);
	send_ls_detail(sock, br);
	sort_entries(br);
	br->selected = 0;
	br->scroll = 0;

	if (came_from[0]) {
		int rows, cols;
		getmaxyx(stdscr, rows, cols);
		int visible = rows - 2;
		if (visible < 1) visible = 1;
		for (int i = 0; i < br->count; i++) {
			if (strcmp(br->entries[i].name, came_from) == 0) {
				br->selected = i;
				if (br->selected >= br->scroll + visible) {
					br->scroll = br->selected - visible + 1;
				}
				break;
			}
		}
	}
}

static void run_browser(int sock) {
	browser_t br = {0};

	char initial_cwd[MAX_PATH];
	if (send_cd_get_path(sock, ".", initial_cwd, sizeof(initial_cwd)) < 0) {
		fprintf(stderr, "failed to get initial working directory\n");
		return;
	}
	strncpy(br.cwd, initial_cwd, MAX_PATH - 1);

	send_ls_detail(sock, &br);
	sort_entries(&br);

	initscr();
	raw();
	noecho();
	keypad(stdscr, TRUE);
	curs_set(0);
	start_color();
	use_default_colors();
	init_pair(1, COLOR_GREEN, -1);
	init_pair(2, COLOR_BLACK, COLOR_GREEN);
	init_pair(3, COLOR_BLACK, COLOR_WHITE);

	int running = 1;
	while (running) {
		draw_browser(&br);
		int ch = getch();
		br.status[0] = '\0';

		int rows, cols;
		getmaxyx(stdscr, rows, cols);
		int visible = rows - 2;
		if (visible < 1) visible = 1;

		switch (ch) {
		case KEY_UP:
			if (br.selected > 0) {
				br.selected--;
				if (br.selected < br.scroll) br.scroll = br.selected;
			}
			break;

		case KEY_DOWN:
			if (br.selected < br.count - 1) {
				br.selected++;
				if (br.selected >= br.scroll + visible) {
					br.scroll = br.selected - visible + 1;
				}
			}
			break;

		case '\n':
		case '\r':
		case KEY_ENTER: {
			if (br.count == 0) break;
			entry_t *e = &br.entries[br.selected];
			if (e->is_dir) {
				if (strcmp(e->name, "..") == 0) {
					navigate_up(sock, &br);
					break;
				}
				char new_cwd[MAX_PATH];
				char came_from[MAX_NAME] = {0};
				if (send_cd_get_path(sock, e->name, new_cwd, sizeof(new_cwd)) == 0) {
					strncpy(br.cwd, new_cwd, MAX_PATH - 1);
					send_ls_detail(sock, &br);
					sort_entries(&br);
					br.selected = 0;
					br.scroll = 0;
				} else {
					snprintf(br.status, sizeof(br.status), "Cannot open: %s", e->name);
					(void)came_from;
				}
			} else {
				if (e->size > MAX_FILE_VIEW_SIZE) {
					char sz[32];
					format_size(e->size, sz, sizeof(sz));
					snprintf(br.status, sizeof(br.status), "File too large to view: %s", sz);
				} else {
					char *content = NULL;
					uint32_t content_size = 0;
					if (send_read_file(sock, e->name, &content, &content_size) == 0) {
						char title[MAX_PATH + MAX_NAME];
						snprintf(title, sizeof(title), " %s/%s", br.cwd, e->name);
						view_content(title, content, content_size);
						free(content);
					} else {
						snprintf(br.status, sizeof(br.status), "Cannot read: %s", e->name);
					}
				}
			}
			break;
		}

		case KEY_BACKSPACE:
		case KEY_LEFT:
		case 127:
		case 8:
			navigate_up(sock, &br);
			break;

		case KEY_RESIZE:
			break;

		case 'q':
		case 'Q':
		case 27:
			running = 0;
			break;
		}
	}

	endwin();
	free(br.entries);
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
				printf("invalid format, using default values\n");
			}
		}
	}

	int sock = connect_to_daemon(daemon_host, daemon_port);
	if (sock == -1) {
		return -1;
	}
	printf("connected\n");

	if (auth_client_handshake(sock) < 0) {
		fprintf(stderr, "authentication failed\n");
		close(sock);
		return -1;
	}
	printf("authenticated\n");

	run_browser(sock);

	close(sock);
	return 0;
}
