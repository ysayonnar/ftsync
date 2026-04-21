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
		perror("socket error");
		return -1;
	}

	struct sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
		close(sock);
		return -1;
	}

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		close(sock);
		return -1;
	}

	return sock;
}

static int send_cd_get_path(int sock, const char *path, char *out, int out_size) {
	uint32_t plen = strlen(path);

	message_header_t req;
	req.magic[0] = MAGIC_1;
	req.magic[1] = MAGIC_2;
	req.command_id = CMD_CD;
	req.payload_size = htonl(plen);

	if (send_exact(sock, &req, sizeof(req)) <= 0)
		return -1;
	if (send_exact(sock, path, plen) <= 0)
		return -1;

	message_header_t resp;
	if (recv_exact(sock, &resp, sizeof(resp)) <= 0)
		return -1;
	if (!validate_magic(resp.magic))
		return -1;

	uint32_t size = ntohl(resp.payload_size);
	if (size == 0 || (int)size >= out_size)
		return -1;

	if (recv_exact(sock, out, size) <= 0)
		return -1;
	out[size] = '\0';
	return 0;
}

static int send_ls_detail(int sock, browser_t *br) {
	message_header_t req = {{MAGIC_1, MAGIC_2}, CMD_LS_DETAIL, 0};

	free(br->entries);
	br->entries = malloc(sizeof(entry_t));
	if (!br->entries)
		return -1;

	strcpy(br->entries[0].name, "..");
	br->entries[0].is_dir = 1;
	br->entries[0].size = 0;
	br->count = 1;

	if (send_exact(sock, &req, sizeof(req)) <= 0)
		return -1;

	message_header_t resp;
	if (recv_exact(sock, &resp, sizeof(resp)) <= 0)
		return -1;
	if (!validate_magic(resp.magic))
		return -1;

	uint32_t total = ntohl(resp.payload_size);
	if (total == 0)
		return 0;

	uint8_t *buf = malloc(total);
	if (!buf)
		return -1;

	if (recv_exact(sock, buf, total) <= 0) {
		free(buf);
		return -1;
	}

	int extra = 0;
	size_t pos = 0;
	while (pos + 11 <= total) {
		uint16_t nl = ((uint16_t)buf[pos + 9] << 8) | buf[pos + 10];
		if (pos + 11 + nl > total)
			break;
		pos += 11 + nl;
		extra++;
	}

	entry_t *ne = realloc(br->entries, sizeof(entry_t) * (1 + extra));
	if (!ne) {
		free(buf);
		return 0;
	}
	br->entries = ne;

	int idx = 1;
	pos = 0;
	while (pos + 11 <= total && idx <= extra) {
		uint8_t type = buf[pos];
		uint64_t sz = 0;
		for (int i = 1; i <= 8; i++)
			sz = (sz << 8) | buf[pos + i];
		uint16_t nl = ((uint16_t)buf[pos + 9] << 8) | buf[pos + 10];
		if (pos + 11 + nl > total)
			break;
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
	uint32_t nlen = strlen(filename);
	message_header_t req = {{MAGIC_1, MAGIC_2}, CMD_READ_FILE, htonl(nlen)};

	if (send_exact(sock, &req, sizeof(req)) <= 0)
		return -1;
	if (send_exact(sock, filename, nlen) <= 0)
		return -1;

	message_header_t resp;
	if (recv_exact(sock, &resp, sizeof(resp)) <= 0)
		return -1;
	if (!validate_magic(resp.magic))
		return -1;

	uint32_t size = ntohl(resp.payload_size);
	if (size == 0)
		return -1;

	char *content = malloc(size + 1);
	if (!content)
		return -1;

	if (recv_exact(sock, content, size) <= 0) {
		free(content);
		return -1;
	}
	content[size] = '\0';
	*out = content;
	*out_size = size;
	return 0;
}

static int send_file_info(int sock, const char *path, uint64_t *out_size, uint8_t sha256[32]) {
	uint32_t plen = strlen(path);
	message_header_t req = {{MAGIC_1, MAGIC_2}, CMD_FILE_INFO, htonl(plen)};

	if (send_exact(sock, &req, sizeof(req)) <= 0)
		return -1;
	if (send_exact(sock, path, plen) <= 0)
		return -1;

	message_header_t resp;
	if (recv_exact(sock, &resp, sizeof(resp)) <= 0)
		return -1;
	if (!validate_magic(resp.magic))
		return -1;

	if (ntohl(resp.payload_size) != 40)
		return -1;

	uint8_t payload[40];
	if (recv_exact(sock, payload, 40) <= 0)
		return -1;

	uint64_t sz = 0;
	for (int i = 0; i < 8; i++)
		sz = (sz << 8) | payload[i];
	*out_size = sz;
	memcpy(sha256, payload + 8, 32);
	return 0;
}

static int download_from_daemon(int sock, const char *path, uint64_t offset,
								uint8_t **out_data, uint32_t *out_size) {
	uint32_t plen = strlen(path);
	uint32_t payload_len = 8 + plen;

	message_header_t req = {{MAGIC_1, MAGIC_2}, CMD_DOWNLOAD, htonl(payload_len)};
	if (send_exact(sock, &req, sizeof(req)) <= 0)
		return -1;

	uint8_t off_buf[8];
	uint64_t tmp = offset;
	for (int i = 7; i >= 0; i--) {
		off_buf[i] = tmp & 0xFF;
		tmp >>= 8;
	}
	if (send_exact(sock, off_buf, 8) <= 0)
		return -1;
	if (send_exact(sock, path, plen) <= 0)
		return -1;

	message_header_t resp;
	if (recv_exact(sock, &resp, sizeof(resp)) <= 0)
		return -1;
	if (!validate_magic(resp.magic))
		return -1;

	uint32_t size = ntohl(resp.payload_size);
	if (size == 0)
		return -1;

	uint8_t *data = malloc(size);
	if (!data)
		return -1;

	if (recv_exact(sock, data, size) <= 0) {
		free(data);
		return -1;
	}
	*out_data = data;
	*out_size = size;
	return 0;
}

static int upload_to_daemon(int sock, const char *dest_path, uint64_t offset,
							const uint8_t *data, uint32_t data_size) {
	uint16_t plen = (uint16_t)strlen(dest_path);
	uint32_t payload_len = 8 + 2 + plen + data_size;

	message_header_t req = {{MAGIC_1, MAGIC_2}, CMD_UPLOAD, htonl(payload_len)};
	if (send_exact(sock, &req, sizeof(req)) <= 0)
		return -1;

	uint8_t off_buf[8];
	uint64_t tmp = offset;
	for (int i = 7; i >= 0; i--) {
		off_buf[i] = tmp & 0xFF;
		tmp >>= 8;
	}
	if (send_exact(sock, off_buf, 8) <= 0)
		return -1;

	uint8_t nl_buf[2] = {(plen >> 8) & 0xFF, plen & 0xFF};
	if (send_exact(sock, nl_buf, 2) <= 0)
		return -1;
	if (send_exact(sock, dest_path, plen) <= 0)
		return -1;
	if (data_size > 0 && send_exact(sock, data, data_size) <= 0)
		return -1;

	message_header_t resp;
	if (recv_exact(sock, &resp, sizeof(resp)) <= 0)
		return -1;
	if (!validate_magic(resp.magic))
		return -1;
	if (ntohl(resp.payload_size) == 0)
		return -1;

	uint8_t status;
	if (recv_exact(sock, &status, 1) <= 0)
		return -1;
	return (status == 0x01) ? 0 : -1;
}

static int cmp_entry(const void *a, const void *b) {
	const entry_t *ea = (const entry_t *)a;
	const entry_t *eb = (const entry_t *)b;
	if (strcmp(ea->name, "..") == 0)
		return -1;
	if (strcmp(eb->name, "..") == 0)
		return 1;
	if (ea->is_dir != eb->is_dir)
		return eb->is_dir - ea->is_dir;
	return strcasecmp(ea->name, eb->name);
}

static void sort_entries(browser_t *br) {
	if (br->count > 0)
		qsort(br->entries, br->count, sizeof(entry_t), cmp_entry);
}

static void format_size(uint64_t size, char *buf, int len) {
	if (size < 1024)
		snprintf(buf, len, "%llu B", (unsigned long long)size);
	else if (size < 1024 * 1024)
		snprintf(buf, len, "%.1f KB", size / 1024.0);
	else if (size < (uint64_t)1024 * 1024 * 1024)
		snprintf(buf, len, "%.1f MB", size / (1024.0 * 1024.0));
	else
		snprintf(buf, len, "%.1f GB", size / (1024.0 * 1024.0 * 1024.0));
}

static void draw_browser(browser_t *br) {
	int rows, cols;
	getmaxyx(stdscr, rows, cols);
	erase();

	attron(COLOR_PAIR(3) | A_BOLD);
	mvprintw(0, 0, "%-*.*s", cols, cols, br->cwd);
	attroff(COLOR_PAIR(3) | A_BOLD);

	int visible = rows - 2;
	if (visible < 1)
		visible = 1;

	for (int i = 0; i < visible; i++) {
		int idx = br->scroll + i;
		if (idx >= br->count)
			break;
		entry_t *e = &br->entries[idx];
		int sel = (idx == br->selected);

		if (sel)
			attron(COLOR_PAIR(2) | A_BOLD);
		else if (e->is_dir)
			attron(COLOR_PAIR(1) | A_BOLD);

		char line[4096];
		if (e->is_dir) {
			snprintf(line, sizeof(line), " %s/", e->name);
		} else {
			char sz[32];
			format_size(e->size, sz, sizeof(sz));
			int nw = cols - 16;
			if (nw < 4)
				nw = 4;
			snprintf(line, sizeof(line), " %-*s %12s", nw, e->name, sz);
		}
		mvprintw(i + 1, 0, "%-*.*s", cols, cols, line);

		if (sel)
			attroff(COLOR_PAIR(2) | A_BOLD);
		else if (e->is_dir)
			attroff(COLOR_PAIR(1) | A_BOLD);
	}

	attron(COLOR_PAIR(3));
	char footer[512];
	if (br->status[0]) {
		snprintf(footer, sizeof(footer), " %s", br->status);
	} else {
		snprintf(footer, sizeof(footer),
				 " Enter:open  Bksp:parent  c:copy  q:quit  [%d/%d]",
				 br->selected + 1, br->count);
	}
	mvprintw(rows - 1, 0, "%-*.*s", cols, cols, footer);
	attroff(COLOR_PAIR(3));

	refresh();
}

static void view_content(const char *title, const char *content, uint32_t size) {
	int lc = 0, lcap = 64;
	char **lines = malloc(sizeof(char *) * lcap);
	if (!lines)
		return;

	char *buf = malloc(size + 1);
	if (!buf) {
		free(lines);
		return;
	}
	memcpy(buf, content, size);
	buf[size] = '\0';

	lines[lc++] = buf;
	for (uint32_t i = 0; i < size; i++) {
		if (buf[i] == '\n') {
			buf[i] = '\0';
			if (i + 1 < size) {
				if (lc >= lcap) {
					lcap *= 2;
					char **nl = realloc(lines, sizeof(char *) * lcap);
					if (!nl)
						break;
					lines = nl;
				}
				lines[lc++] = buf + i + 1;
			}
		}
	}

	int scroll = 0, running = 1;
	while (running) {
		int rows, cols;
		getmaxyx(stdscr, rows, cols);
		int visible = rows - 2;
		if (visible < 1)
			visible = 1;
		erase();

		attron(COLOR_PAIR(3) | A_BOLD);
		mvprintw(0, 0, "%-*.*s", cols, cols, title);
		attroff(COLOR_PAIR(3) | A_BOLD);

		for (int i = 0; i < visible && (scroll + i) < lc; i++) {
			const char *src = lines[scroll + i];
			char lb[4096];
			int j = 0;
			while (*src && j < (int)sizeof(lb) - 1) {
				unsigned char ch = (unsigned char)*src++;
				lb[j++] = (ch < 32 && ch != '\t') ? '.' : (char)ch;
			}
			lb[j] = '\0';
			mvprintw(i + 1, 0, "%.*s", cols, lb);
		}

		attron(COLOR_PAIR(3));
		char footer[256];
		snprintf(footer, sizeof(footer), " q/ESC:back  Up/Down:scroll  PgUp/PgDn:page  %d/%d", scroll + 1, lc);
		mvprintw(rows - 1, 0, "%-*.*s", cols, cols, footer);
		attroff(COLOR_PAIR(3));
		refresh();

		int ch = getch();
		switch (ch) {
		case KEY_UP:
			if (scroll > 0)
				scroll--;
			break;
		case KEY_DOWN:
			if (scroll + visible < lc)
				scroll++;
			break;
		case KEY_PPAGE:
			scroll -= visible;
			if (scroll < 0)
				scroll = 0;
			break;
		case KEY_NPAGE:
			scroll += visible;
			if (scroll + visible > lc)
				scroll = lc - visible;
			if (scroll < 0)
				scroll = 0;
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
	if (slash && slash != br->cwd)
		strncpy(came_from, slash + 1, MAX_NAME - 1);

	char new_cwd[MAX_PATH];
	if (send_cd_get_path(sock, "..", new_cwd, sizeof(new_cwd)) != 0)
		return;

	strncpy(br->cwd, new_cwd, MAX_PATH - 1);
	send_ls_detail(sock, br);
	sort_entries(br);
	br->selected = 0;
	br->scroll = 0;

	if (came_from[0]) {
		int rows, cols;
		getmaxyx(stdscr, rows, cols);
		int visible = rows - 2;
		if (visible < 1)
			visible = 1;
		for (int i = 0; i < br->count; i++) {
			if (strcmp(br->entries[i].name, came_from) == 0) {
				br->selected = i;
				if (br->selected >= br->scroll + visible)
					br->scroll = br->selected - visible + 1;
				break;
			}
		}
	}
}

static void show_step(const char *file, const char *dest, int step, int total, const char *msg) {
	int rows, cols;
	getmaxyx(stdscr, rows, cols);
	erase();

	attron(COLOR_PAIR(3) | A_BOLD);
	mvprintw(0, 0, "%-*.*s", cols, cols, " File Transfer");
	attroff(COLOR_PAIR(3) | A_BOLD);

	mvprintw(2, 2, "File: %s", file);
	mvprintw(3, 2, "To:   %s", dest);
	mvprintw(5, 2, "[%d/%d] %s", step, total, msg);

	attron(COLOR_PAIR(3));
	mvprintw(rows - 1, 0, "%-*.*s", cols, cols, " Please wait...");
	attroff(COLOR_PAIR(3));
	refresh();
}

static void show_result(const char *file, const char *dest, const char *msg) {
	int rows, cols;
	getmaxyx(stdscr, rows, cols);
	erase();

	attron(COLOR_PAIR(3) | A_BOLD);
	mvprintw(0, 0, "%-*.*s", cols, cols, " File Transfer");
	attroff(COLOR_PAIR(3) | A_BOLD);

	mvprintw(2, 2, "File: %s", file);
	mvprintw(3, 2, "To:   %s", dest);
	mvprintw(5, 2, "%s", msg);

	attron(COLOR_PAIR(3));
	mvprintw(rows - 1, 0, "%-*.*s", cols, cols, " Press any key to continue...");
	attroff(COLOR_PAIR(3));
	refresh();
}

static int copy_dialog(const char *filename, char *dest_host, int *dest_port, char *dest_path) {
	int rows __attribute__((unused)), cols;
	getmaxyx(stdscr, rows, cols);
	erase();

	attron(COLOR_PAIR(3) | A_BOLD);
	mvprintw(0, 0, "%-*.*s", cols, cols, " Copy File");
	attroff(COLOR_PAIR(3) | A_BOLD);

	mvprintw(2, 2, "File: %s", filename);
	mvprintw(4, 2, "Destination daemon [host:port]:");
	mvprintw(5, 4, "> ");
	refresh();

	char addr_buf[256] = "";
	curs_set(1);
	echo();
	nocbreak();
	mvgetnstr(5, 6, addr_buf, sizeof(addr_buf) - 1);
	raw();
	noecho();
	curs_set(0);

	if (addr_buf[0] == '\0')
		return -1;

	char host[256] = DEFAULT_HOST;
	int port = DEFAULT_PORT;
	sscanf(addr_buf, "%255[^:]:%d", host, &port);
	strncpy(dest_host, host, 255);
	dest_host[255] = '\0';
	*dest_port = port;

	mvprintw(7, 2, "Destination path (e.g. /tmp/ or /tmp/file.txt):");
	mvprintw(8, 4, "> ");
	refresh();

	char path_buf[MAX_PATH] = "";
	curs_set(1);
	echo();
	nocbreak();
	mvgetnstr(8, 6, path_buf, MAX_PATH - 1);
	raw();
	noecho();
	curs_set(0);

	if (path_buf[0] == '\0')
		return -1;

	int plen = strlen(path_buf);
	if (path_buf[plen - 1] == '/') {
		snprintf(dest_path, MAX_PATH, "%s%s", path_buf, filename);
	} else {
		strncpy(dest_path, path_buf, MAX_PATH - 1);
		dest_path[MAX_PATH - 1] = '\0';
	}

	return 0;
}

static void handle_copy(int sock, browser_t *br) {
	if (br->count == 0)
		return;
	entry_t *e = &br->entries[br->selected];

	if (e->is_dir) {
		snprintf(br->status, sizeof(br->status), "Directory copy is not supported");
		return;
	}

	char dest_host[256];
	int dest_port;
	char dest_path[MAX_PATH];

	if (copy_dialog(e->name, dest_host, &dest_port, dest_path) < 0)
		return;

	char dest_display[512];
	snprintf(dest_display, sizeof(dest_display), "%s:%d:%s", dest_host, dest_port, dest_path);

	show_step(e->name, dest_display, 1, 5, "Getting source file info...");
	uint8_t src_sha256[32];
	uint64_t src_size;
	if (send_file_info(sock, e->name, &src_size, src_sha256) < 0) {
		show_result(e->name, dest_display, "FAILED: Cannot get source file info");
		getch();
		return;
	}

	show_step(e->name, dest_display, 2, 5, "Connecting to destination daemon...");
	int dst_sock = connect_to_daemon(dest_host, dest_port);
	if (dst_sock < 0) {
		show_result(e->name, dest_display, "FAILED: Cannot connect to destination daemon");
		getch();
		return;
	}

	if (auth_client_handshake(dst_sock) < 0) {
		close(dst_sock);
		show_result(e->name, dest_display, "FAILED: Authentication failed at destination");
		getch();
		return;
	}

	show_step(e->name, dest_display, 3, 5, "Checking for partial file (resume support)...");
	uint8_t dst_sha256_prev[32];
	uint64_t dst_size = 0;
	uint64_t offset = 0;

	if (send_file_info(dst_sock, dest_path, &dst_size, dst_sha256_prev) == 0) {
		if (dst_size == src_size && memcmp(dst_sha256_prev, src_sha256, 32) == 0) {
			close(dst_sock);
			show_result(e->name, dest_display, "File already exists at destination and is identical. Nothing to do.");
			getch();
			return;
		}
		if (dst_size < src_size) {
			offset = dst_size;
		}
	}

	char dl_msg[256];
	if (offset > 0) {
		char off_str[32], tot_str[32];
		format_size(offset, off_str, sizeof(off_str));
		format_size(src_size, tot_str, sizeof(tot_str));
		snprintf(dl_msg, sizeof(dl_msg), "Downloading %s (resuming from %s)...", tot_str, off_str);
	} else {
		char tot_str[32];
		format_size(src_size, tot_str, sizeof(tot_str));
		snprintf(dl_msg, sizeof(dl_msg), "Downloading %s...", tot_str);
	}

	show_step(e->name, dest_display, 4, 5, dl_msg);
	uint8_t *data = NULL;
	uint32_t data_size = 0;
	if (download_from_daemon(sock, e->name, offset, &data, &data_size) < 0) {
		close(dst_sock);
		show_result(e->name, dest_display, "FAILED: Cannot download from source");
		getch();
		return;
	}

	show_step(e->name, dest_display, 5, 5, "Uploading to destination...");
	if (upload_to_daemon(dst_sock, dest_path, offset, data, data_size) < 0) {
		free(data);
		close(dst_sock);
		show_result(e->name, dest_display, "FAILED: Cannot upload to destination");
		getch();
		return;
	}
	free(data);

	show_step(e->name, dest_display, 5, 5, "Verifying integrity (SHA256)...");
	uint8_t final_sha256[32];
	uint64_t final_size;
	if (send_file_info(dst_sock, dest_path, &final_size, final_sha256) < 0) {
		close(dst_sock);
		show_result(e->name, dest_display, "FAILED: Cannot verify destination file");
		getch();
		return;
	}
	close(dst_sock);

	if (final_size != src_size || memcmp(final_sha256, src_sha256, 32) != 0) {
		show_result(e->name, dest_display, "FAILED: Integrity check failed - SHA256 mismatch");
	} else {
		char result[256];
		char sz[32];
		format_size(src_size, sz, sizeof(sz));
		snprintf(result, sizeof(result), "SUCCESS: %s transferred (%s). SHA256 verified.", e->name, sz);
		show_result(e->name, dest_display, result);
	}
	getch();
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
		if (visible < 1)
			visible = 1;

		switch (ch) {
		case KEY_UP:
			if (br.selected > 0) {
				br.selected--;
				if (br.selected < br.scroll)
					br.scroll = br.selected;
			}
			break;

		case KEY_DOWN:
			if (br.selected < br.count - 1) {
				br.selected++;
				if (br.selected >= br.scroll + visible)
					br.scroll = br.selected - visible + 1;
			}
			break;

		case '\n':
		case '\r':
		case KEY_ENTER: {
			if (br.count == 0)
				break;
			entry_t *e = &br.entries[br.selected];
			if (e->is_dir) {
				if (strcmp(e->name, "..") == 0) {
					navigate_up(sock, &br);
					break;
				}
				char new_cwd[MAX_PATH];
				if (send_cd_get_path(sock, e->name, new_cwd, sizeof(new_cwd)) == 0) {
					strncpy(br.cwd, new_cwd, MAX_PATH - 1);
					send_ls_detail(sock, &br);
					sort_entries(&br);
					br.selected = 0;
					br.scroll = 0;
				} else {
					snprintf(br.status, sizeof(br.status), "Cannot open: %s", e->name);
				}
			} else {
				if (e->size > MAX_FILE_VIEW_SIZE) {
					char sz[32];
					format_size(e->size, sz, sizeof(sz));
					snprintf(br.status, sizeof(br.status), "File too large to view: %s", sz);
				} else {
					char *content = NULL;
					uint32_t csz = 0;
					if (send_read_file(sock, e->name, &content, &csz) == 0) {
						char title[MAX_PATH + MAX_NAME];
						snprintf(title, sizeof(title), " %s/%s", br.cwd, e->name);
						view_content(title, content, csz);
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

		case 'c':
		case 'C':
		case KEY_F(5):
			handle_copy(sock, &br);
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

int main(void) {
	char daemon_host[256] = DEFAULT_HOST;
	int daemon_port = DEFAULT_PORT;
	char buffer[256];

	printf("enter daemon address [host:port] => ");

	if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
		if (buffer[0] != '\n') {
			int parsed = sscanf(buffer, "%255[^:]:%d", daemon_host, &daemon_port);
			if (parsed < 2)
				printf("invalid format, using default values\n");
		}
	}

	int sock = connect_to_daemon(daemon_host, daemon_port);
	if (sock == -1) {
		fprintf(stderr, "connection failed\n");
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
