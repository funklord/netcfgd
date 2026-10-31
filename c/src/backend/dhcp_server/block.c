/*
 * block.c -- the names a DHCP server's forwarder refuses (decision 0305).
 *
 * WHAT THIS WRITES
 *   `<run>/dhcp-server/<iface>.block`, which the server's configuration reads
 *   with `conf-file=`: one `address=/name/` line per blocked name, which
 *   dnsmasq answers NXDOMAIN for the name and everything under it, then one
 *   `server=/name/#` per allowed name, which sends it back to the upstream
 *   even under a blocked parent. Both measured against 2.91.
 *
 * WHY NETCFGD READS THE LISTS RATHER THAN DNSMASQ
 *   A list is downloaded from somebody else. Given to dnsmasq as
 *   configuration, a line of `dhcp-script=` in it would run as root, so each
 *   line is reduced to one name by `ncfg_block_list_name_of_line`, which
 *   refuses every character that could make a name into more, and the file
 *   dnsmasq reads is netcfgd's own.
 *
 * WHY FETCHING IS NOT THE DAEMON'S
 *   `ncfg_block_list_fetch` runs curl for `ncfg block fetch`, which an
 *   operator or a timer runs: the daemon holds no HTTP client, and what it
 *   applies never depends on a remote at apply time. A download lands beside
 *   the file and replaces it only once it holds at least one name, so a
 *   failed or empty fetch keeps the list that was there.
 *
 * WHY A LIST THAT CANNOT BE READ IS LEFT OUT
 *   A file not fetched yet, or past the bound, leaves its names out and the
 *   server starts without them -- with a plan warning, from
 *   `ncfg_block_list_file_usable` -- because a LAN with no DNS is a worse
 *   failure than a LAN whose ads are not blocked yet.
 */
#include "ncfg/dhcp_server.h"
#include "../backend_internal.h"
#include "ncfg/base.h"
#include "ncfg/buf.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Firefox's switch (0305): a resolver that answers this name NXDOMAIN tells
 * Firefox not to turn DNS over HTTPS on by itself, which would ask past the
 * router and block nothing. Pi-hole answers it the same way.
 */
#define BLOCK_CANARY "use-application-dns.net"

/* A line longer than a name could be, with its address column, is not one. */
#define BLOCK_LINE_MAX 1024u

/* The generated file's own bound: every name at its longest. */
#define BLOCK_FILE_MAX ((size_t)NCFG_BLOCK_NAMES_MAX * 300u)

static const ncfg_block_list_t *find_list(const ncfg_document_t *document, const char *name)
{
	size_t at;

	for (at = 0; document && at < document->block_list_count; at++) {
		if (strcmp(document->block_lists[at].name, name) == 0) {
			return &document->block_lists[at];
		}
	}
	return NULL;
}

int ncfg_block_list_file_usable(const char *path)
{
	struct stat status;

	return path && stat(path, &status) == 0 && S_ISREG(status.st_mode) &&
	    (unsigned long long)status.st_size <= (unsigned long long)NCFG_BLOCK_FILE_MAX;
}

/* FNV-1a, with a separator, as the summary's other digests. */
static uint32_t digest_bytes(uint32_t digest, const void *bytes, size_t length)
{
	const unsigned char *at = bytes;
	size_t               one;

	for (one = 0; one < length; one++) {
		digest = (digest ^ at[one]) * 16777619u;
	}
	return digest;
}

static uint32_t digest_word(uint32_t digest, const char *text)
{
	digest = digest_bytes(digest, text ? text : "", text ? strlen(text) : 0u);
	return (digest ^ 0u) * 16777619u;
}

/*
 * A file's contents into the digest, so a refreshed list is a changed summary
 * and a restart -- and a refresh that fetched the same list is not. One that
 * cannot be read digests as the word "absent", so its arrival is a change.
 */
static uint32_t digest_file(uint32_t digest, const char *path)
{
	unsigned char chunk[8192];
	FILE         *file;
	size_t        got;

	if (!ncfg_block_list_file_usable(path) || !(file = fopen(path, "rb"))) {
		return digest_word(digest, "absent");
	}
	while ((got = fread(chunk, 1u, sizeof(chunk), file)) > 0u) {
		digest = digest_bytes(digest, chunk, got);
	}
	(void)fclose(file);
	return digest_word(digest, "");
}

size_t ncfg_dhcp_server_block_digest(const ncfg_document_t *document,
    const ncfg_dhcp_server_t *server, uint32_t *out)
{
	uint32_t digest = 2166136261u;
	size_t   at;
	size_t   one;

	if (!server || !server->dns_forward || !server->block_count) {
		return 0;
	}
	for (at = 0; at < server->block_count; at++) {
		const ncfg_block_list_t *list = find_list(document, server->block[at]);

		digest = digest_word(digest, server->block[at]);
		if (!list) {
			continue;
		}
		for (one = 0; one < list->domain_count; one++) {
			digest = digest_word(digest, list->domain[one]);
		}
		digest = digest_word(digest, "|");
		for (one = 0; one < list->allow_count; one++) {
			digest = digest_word(digest, list->allow[one]);
		}
		digest = digest_word(digest, "|");
		for (one = 0; one < list->file_count; one++) {
			digest = digest_file(digest_word(digest, list->file[one]), list->file[one]);
		}
	}
	*out = digest;
	return server->block_count;
}

typedef struct {
	char **names;
	size_t count;
	size_t capacity;
} names_t;

/* 0 only for memory; a name past the bound is dropped, and the file says so. */
static int names_add(names_t *names, const char *name, int *full)
{
	if (names->count >= (size_t)NCFG_BLOCK_NAMES_MAX) {
		*full = 1;
		return 1;
	}
	if (names->count == names->capacity) {
		size_t capacity = names->capacity ? names->capacity * 2u : 1024u;
		char **grown = realloc(names->names, capacity * sizeof(*grown));

		if (!grown) {
			return 0;
		}
		names->names = grown;
		names->capacity = capacity;
	}
	names->names[names->count] = strdup(name);
	return names->names[names->count++] != NULL;
}

static void names_free(names_t *names)
{
	size_t at;

	for (at = 0; at < names->count; at++) {
		free(names->names[at]);
	}
	free(names->names);
}

static int compare_names(const void *left, const void *right)
{
	return strcmp(*(char *const *)left, *(char *const *)right);
}

/* Every name a file holds; 0 only for memory. */
static int read_list(const char *path, names_t *names, int *full)
{
	char  line[BLOCK_LINE_MAX];
	char  name[256];
	FILE *file;
	int   ok = 1;

	if (!ncfg_block_list_file_usable(path) || !(file = fopen(path, "rb"))) {
		return 1;
	}
	while (ok && fgets(line, sizeof(line), file)) {
		size_t length = strlen(line);

		if (length && line[length - 1u] != '\n' && !feof(file)) {
			int c;

			/* Longer than any name: skipped whole, not read in pieces. */
			while ((c = fgetc(file)) != EOF && c != '\n') {
			}
			continue;
		}
		if (length && line[length - 1u] == '\n') {
			length--;
		}
		if (ncfg_block_list_name_of_line(line, length, name, sizeof(name))) {
			ok = names_add(names, name, full);
		}
	}
	(void)fclose(file);
	return ok;
}

static int allowed(const ncfg_document_t *document, const ncfg_dhcp_server_t *server,
    const char *name)
{
	size_t at;
	size_t one;

	for (at = 0; at < server->block_count; at++) {
		const ncfg_block_list_t *list = find_list(document, server->block[at]);

		for (one = 0; list && one < list->allow_count; one++) {
			if (strcmp(list->allow[one], name) == 0) {
				return 1;
			}
		}
	}
	return 0;
}

int ncfg_dhcp_server_block_write(const ncfg_document_t *document,
    const ncfg_dhcp_server_t *server, const char *path, char *err, size_t err_size)
{
	names_t    names = { NULL, 0, 0 };
	ncfg_buf_t buf;
	size_t     written = 0;
	size_t     at;
	size_t     one;
	int        full = 0;
	int        ok = 1;
	char      *text;
	size_t     length;

	ok = names_add(&names, BLOCK_CANARY, &full);
	for (at = 0; ok && at < server->block_count; at++) {
		const ncfg_block_list_t *list = find_list(document, server->block[at]);

		for (one = 0; ok && list && one < list->domain_count; one++) {
			ok = names_add(&names, list->domain[one], &full);
		}
		for (one = 0; ok && list && one < list->file_count; one++) {
			ok = read_list(list->file[one], &names, &full);
		}
	}
	if (!ok) {
		names_free(&names);
		ncfg_error_set(err, err_size, "out of memory reading the block lists");
		return 0;
	}
	/* Sorted and each name once: lists overlap, and dnsmasq keeps every line
	 * it is given. */
	qsort(names.names, names.count, sizeof(*names.names), compare_names);
	ncfg_buf_init(&buf, BLOCK_FILE_MAX);
	ncfg_buf_add_text(&buf,
	    "# Written by netcfgd from the block lists (decision 0305). Do not edit; it is "
	    "rewritten on apply.\n");
	if (full) {
		ncfg_buf_addf(&buf, "# The lists hold more than %d names; the rest are left out.\n",
		    NCFG_BLOCK_NAMES_MAX);
	}
	for (at = 0; at < names.count; at++) {
		if ((at && strcmp(names.names[at], names.names[at - 1u]) == 0) ||
		    allowed(document, server, names.names[at])) {
			continue;
		}
		ncfg_buf_addf(&buf, "address=/%s/\n", names.names[at]);
		written++;
	}
	for (at = 0; at < server->block_count; at++) {
		const ncfg_block_list_t *list = find_list(document, server->block[at]);

		for (one = 0; list && one < list->allow_count; one++) {
			ncfg_buf_addf(&buf, "server=/%s/#\n", list->allow[one]);
		}
	}
	ncfg_buf_addf(&buf, "# %zu names blocked\n", written);
	names_free(&names);
	if (ncfg_buf_failed(&buf)) {
		ncfg_buf_free(&buf);
		ncfg_error_set(err, err_size, "out of memory writing the block lists");
		return 0;
	}
	text = ncfg_buf_take(&buf, &length);
	ncfg_buf_free(&buf);
	ok = ncfg_backend_write_file(path, text, length, 0644, err, err_size);
	free(text);
	return ok;
}

/* What curl says when it fails, for the sentence a failed fetch carries. */
static const char *const FETCH_MARKERS[] = { "curl:", "error", "failed", "could not" };

/* The names a downloaded file holds, counted as `read_list` would read them. */
static size_t count_names(const char *path)
{
	names_t names = { NULL, 0, 0 };
	size_t  count;
	int     full = 0;

	if (!read_list(path, &names, &full)) {
		names_free(&names);
		return 0;
	}
	count = names.count;
	names_free(&names);
	return count;
}

int ncfg_block_list_fetch(const char *url, const char *path, const char *program,
    size_t *names_out, char *err, size_t err_size)
{
	char        dir[NCFG_DHCP_SERVER_PATH_MAX];
	char        part[NCFG_DHCP_SERVER_PATH_MAX + 8];
	char        log[NCFG_DHCP_SERVER_PATH_MAX + 8];
	char        said[NCFG_ERROR_MAX];
	char        most[32];
	char       *found = NULL;
	char       *slash;
	const char *argv[17];
	size_t      names;
	int         exited_ok = 0;
	int         status = 0;

	if (!url || !path || strlen(path) >= sizeof(dir)) {
		ncfg_error_set(err, err_size, "a fetch needs a url and a file to put it in");
		return 0;
	}
	strcpy(dir, path);
	slash = strrchr(dir, '/');
	if (slash && slash != dir) {
		*slash = '\0';
		if (!ncfg_backend_make_dir(dir, 0755, err, err_size)) {
			return 0;
		}
	}
	(void)snprintf(part, sizeof(part), "%s.part", path);
	(void)snprintf(log, sizeof(log), "%s.log", path);
	(void)snprintf(most, sizeof(most), "%llu", (unsigned long long)NCFG_BLOCK_FILE_MAX);
	if (!program) {
		found = ncfg_backend_find_program("curl");
		if (!found) {
			ncfg_error_set(err, err_size, "no curl found; fetching a block list needs it");
			return 0;
		}
		program = found;
	}
	/*
	 * **Bounded on every side curl offers**: the web schemes only, redirects
	 * included, so a list cannot send it to `file://`; five minutes; and the
	 * size `read_list` would read, refused before it is written rather than
	 * truncated into a list missing its tail. `--fail` makes an error page
	 * an exit status rather than a file of HTML.
	 */
	argv[0] = program;
	argv[1] = "--fail";
	argv[2] = "--silent";
	argv[3] = "--show-error";
	argv[4] = "--location";
	argv[5] = "--proto";
	argv[6] = "=https,http";
	argv[7] = "--proto-redir";
	argv[8] = "=https,http";
	argv[9] = "--max-time";
	argv[10] = "300";
	argv[11] = "--max-filesize";
	argv[12] = most;
	argv[13] = "--output";
	argv[14] = part;
	/* Its own argument, and checked by `ncfg_block_list_check` to start
	 * with a scheme, so curl never reads it as an option. */
	argv[15] = url;
	argv[16] = NULL;
	if (!ncfg_backend_run(program, argv, log, &exited_ok, &status, err, err_size)) {
		free(found);
		(void)unlink(log);
		(void)unlink(part);
		return 0;
	}
	free(found);
	if (!exited_ok) {
		if (ncfg_backend_complaints(log, FETCH_MARKERS,
		        sizeof(FETCH_MARKERS) / sizeof(FETCH_MARKERS[0]), NULL, 0u, 2u, said,
		        sizeof(said))) {
			ncfg_error_set(err, err_size, "could not fetch %s: %s; %s is kept as it was", url,
			    said, path);
		} else {
			ncfg_error_set(err, err_size, "could not fetch %s: curl exited with status %d; %s "
			    "is kept as it was", url, status, path);
		}
		/* Read into the sentence above, so nothing is left beside the list. */
		(void)unlink(log);
		(void)unlink(part);
		return 0;
	}
	(void)unlink(log);
	names = count_names(part);
	if (names == 0u) {
		ncfg_error_set(err, err_size, "%s holds no names a block list can use, so %s is kept "
		    "as it was", url, path);
		(void)unlink(part);
		return 0;
	}
	if (chmod(part, 0644) != 0 || rename(part, path) != 0) {
		ncfg_error_set(err, err_size, "could not put the list fetched from %s in %s", url,
		    path);
		(void)unlink(part);
		return 0;
	}
	if (names_out) {
		*names_out = names;
	}
	return 1;
}
