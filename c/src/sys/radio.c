/*
 * radio.c -- the one existence test that says an interface is a radio.
 *
 * Two attributes, asked in the order radio.h gives, and a name check in front
 * of both. Nothing here opens a socket or needs a privilege: it is `stat` and
 * `readdir` on `/sys`, which is what lets `ncfg wifi add` answer the question
 * on a machine with no network and nothing running.
 */
#include "ncfg/radio.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

/* `IFNAMSIZ`, written out rather than included: `linux/if.h` and `net/if.h`
 * redefine each other's structures, and this file's callers are entitled to
 * either. A name longer than this cannot be an interface's, so it is refused
 * before a path is built out of it. */
#define RADIO_NAME_MAX 16u

/* Room for a root, a name, a separator and the longer of the two attribute
 * names. */
#define RADIO_PATH_MAX (NCFG_RADIO_ROOT_MAX + RADIO_NAME_MAX + 16u)

/*
 * Whether `<root>/<name>/<attribute>` is there.
 *
 * `stat` rather than `lstat`, because both attributes are symlinks into the
 * device tree and a reader that refused to follow them would answer "not a
 * radio" for every cfg80211 device on the machine. A dangling one is absent,
 * which is the same answer the Rust's `Path::exists` gives.
 */
static int attribute_exists(const char *root, const char *name, const char *attribute)
{
	char        path[RADIO_PATH_MAX];
	struct stat found;
	int         written;

	written = snprintf(path, sizeof(path), "%s/%s/%s", root, name, attribute);
	if (written < 0 || (size_t)written >= sizeof(path)) {
		/* A path that did not fit names some other file, not a longer
		 * version of this one. */
		return 0;
	}
	return stat(path, &found) == 0;
}

/* A name that could leave the directory it is meant to be inside, or that
 * names the directory itself. `.` is not a separator and carries no `..`, so it
 * passes both of those tests and would ask whether `<root>/./phy80211` exists
 * -- a question about the class directory rather than about an interface. */
static int name_escapes(const char *name)
{
	return name[0] == '\0' || strcmp(name, ".") == 0 || strchr(name, '/') != NULL ||
	    strstr(name, "..") != NULL;
}

int ncfg_radio_class_net(char *out, size_t out_size, char *err, size_t err_size)
{
	const char *set;
	size_t      length;

	if (!out || out_size < NCFG_RADIO_ROOT_MAX) {
		ncfg_error_set(err, err_size, "a sysfs root needs %u bytes to be written into",
		    (unsigned)NCFG_RADIO_ROOT_MAX);
		return 0;
	}
	out[0] = '\0';
	set = getenv(NCFG_RADIO_CLASS_NET_ENV);
	if (!set || set[0] == '\0') {
		/* An empty value is the variable not being set. A root of ""
		 * would make every path relative to the working directory,
		 * which is a different machine's worth of answers. */
		(void)snprintf(out, out_size, "%s", NCFG_RADIO_CLASS_NET);
		return 1;
	}
	length = strlen(set);
	if (length >= out_size) {
		ncfg_error_set(err, err_size,
		    "%s is %zu bytes, which is longer than a path this reads",
		    NCFG_RADIO_CLASS_NET_ENV, length);
		return 0;
	}
	memcpy(out, set, length + 1u);
	return 1;
}

int ncfg_radio_is_wireless(const char *root, const char *name)
{
	if (!root || !name || name_escapes(name) || strlen(name) >= RADIO_NAME_MAX) {
		return 0;
	}
	/* `phy80211` first and `wireless` second, which is the order 0231
	 * settles: the second exists only where the kernel was built with the
	 * Wireless Extensions compatibility layer, and asking it alone reported
	 * a working radio as not one. */
	if (attribute_exists(root, name, "phy80211")) {
		return 1;
	}
	return attribute_exists(root, name, "wireless");
}

static int compare_names(const void *left, const void *right)
{
	const char *const *one = (const char *const *)left;
	const char *const *two = (const char *const *)right;

	return strcmp(*one, *two);
}

static int links_add(ncfg_radio_links_t *links, const char *name, char *err, size_t err_size)
{
	char *copy;

	if (links->count == links->capacity) {
		size_t wanted = links->capacity ? links->capacity * 2u : 8u;
		char **grown = realloc(links->items, wanted * sizeof(*grown));

		if (!grown) {
			ncfg_error_set(err, err_size, "out of memory listing radios");
			return 0;
		}
		links->items = grown;
		links->capacity = wanted;
	}
	copy = strdup(name);
	if (!copy) {
		ncfg_error_set(err, err_size, "out of memory listing radios");
		return 0;
	}
	links->items[links->count++] = copy;
	return 1;
}

void ncfg_radio_links_free(ncfg_radio_links_t *links)
{
	size_t at;

	if (!links) {
		return;
	}
	for (at = 0; at < links->count; at++) {
		free(links->items[at]);
	}
	free(links->items);
	links->items = NULL;
	links->count = 0;
	links->capacity = 0;
}

int ncfg_radio_links(const char *root, ncfg_radio_links_t *out, char *err, size_t err_size)
{
	DIR           *directory;
	struct dirent *entry;

	if (!out) {
		ncfg_error_set(err, err_size, "a radio list needs somewhere to go");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!root) {
		ncfg_error_set(err, err_size, "listing radios needs a directory to list");
		return 0;
	}
	directory = opendir(root);
	if (!directory) {
		/* Not a refusal: see radio.h. A machine with no `/sys` mounted
		 * and a machine with no radio are the same answer to every
		 * caller here. */
		return 1;
	}
	while ((entry = readdir(directory)) != NULL) {
		if (!ncfg_radio_is_wireless(root, entry->d_name)) {
			continue;
		}
		if (!links_add(out, entry->d_name, err, err_size)) {
			(void)closedir(directory);
			ncfg_radio_links_free(out);
			return 0;
		}
	}
	(void)closedir(directory);
	if (out->count > 1u) {
		qsort(out->items, out->count, sizeof(*out->items), compare_names);
	}
	return 1;
}
