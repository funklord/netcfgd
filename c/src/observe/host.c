/*
 * host.c -- the parts of an observation that are not rtnetlink.
 *
 * Four things netcfgd configures cannot be read from a link dump: the
 * forwarding, privacy and `accept_ra` sysctls, which live in `/proc/sys`; the
 * hostname, which is another file under it; a radio's kill switch, which is in
 * `/sys`; and the Bluetooth adapters, which are not links at all. They are read
 * here so that `ncfg_observe_build` stays a function of a snapshot -- the
 * ownership rules are then testable without a kernel, which is the whole reason
 * the split exists.
 *
 * NOTHING HERE FAILS AN OBSERVATION
 *   A container with no writable `/proc/sys`, an IPv6-disabled kernel, a
 *   machine with no radio and no Bluetooth are all ordinary. The honest reading
 *   in each case is "netcfgd cannot tell" or "there is nothing to ask", which
 *   is what an absent optional and an empty list say. What must not happen is a
 *   daemon that refuses to start on a kernel that simply does not have a
 *   feature nobody asked for. The only failures reported from here are out of
 *   memory.
 *
 * EVERY ROOT IS A PARAMETER
 *   `ncfg_observe_roots_default` reads the environment once and every reader
 *   below takes the answer. A reader that looked the variable up for itself
 *   would be one whose answer depends on hidden global state, and two tests
 *   setting one variable while running in parallel is a race -- which is
 *   radio.h's argument, and this module is the reason that argument was made.
 */
#include "ncfg/observe.h"

#include "observe_internal.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

/* A root, a subdirectory, an interface name and the longest leaf any of this
 * joins on. Generous rather than exact: a path that did not fit names some
 * other file, not a longer version of this one, so every join below checks. */
#define HOST_PATH_MAX (NCFG_OBSERVE_ROOT_MAX + 256u)

/* Longer than any value read here: a sysctl is a number and a hostname is
 * bounded by `HOST_NAME_MAX`. A longer file is read truncated, which for every
 * caller below reads as a value that does not parse. */
#define HOST_VALUE_MAX 256u

/* ------------------------------------------------------------------------ *
 * Reading one small file
 * ------------------------------------------------------------------------ */

/* Join, refusing a result that did not fit. */
static int join(char *out, size_t out_size, const char *format, const char *one, const char *two)
{
	int written = snprintf(out, out_size, format, one, two);

	return written >= 0 && (size_t)written < out_size;
}

/*
 * The contents of a small file, trimmed of surrounding whitespace.
 *
 * The kernel's files end in a newline and the values they are compared against
 * do not. 0 where the file is not there, cannot be read, or is longer than
 * anything this reads -- and every caller treats all three the same, because
 * each of them means netcfgd cannot tell.
 */
static int read_value(const char *path, char *out, size_t out_size)
{
	FILE  *file = fopen(path, "rb");
	size_t got;
	size_t start = 0;
	size_t end;

	if (!file) {
		return 0;
	}
	got = fread(out, 1u, out_size - 1u, file);
	(void)fclose(file);
	out[got] = '\0';
	end = got;
	while (end > start && (unsigned char)out[end - 1u] <= ' ') {
		end--;
	}
	while (start < end && (unsigned char)out[start] <= ' ') {
		start++;
	}
	memmove(out, out + start, end - start);
	out[end - start] = '\0';
	return 1;
}

/* The same, joined from a root and two parts. */
static int read_joined(char *out, size_t out_size, const char *format, const char *one,
    const char *two)
{
	char path[HOST_PATH_MAX];

	if (!join(path, sizeof(path), format, one, two)) {
		return 0;
	}
	return read_value(path, out, out_size);
}

static ncfg_optbool_t some_bool(int value)
{
	ncfg_optbool_t result;

	result.has = 1;
	result.value = value ? 1 : 0;
	return result;
}

static ncfg_optbool_t no_bool(void)
{
	ncfg_optbool_t result;

	result.has = 0;
	result.value = 0;
	return result;
}

/* ------------------------------------------------------------------------ *
 * The roots
 * ------------------------------------------------------------------------ */

static int root_from_env(const char *variable, const char *fallback, char *out, size_t out_size,
    char *err, size_t err_size)
{
	const char *set = getenv(variable);
	size_t      length;

	if (!set || set[0] == '\0') {
		/* An empty value is the variable not being set. A root of ""
		 * would make every path relative to the working directory,
		 * which is a different machine's worth of answers. */
		(void)snprintf(out, out_size, "%s", fallback);
		return 1;
	}
	length = strlen(set);
	if (length >= out_size) {
		ncfg_error_set(err, err_size,
		    "%s is %zu bytes, which is longer than a path this reads", variable, length);
		return 0;
	}
	memcpy(out, set, length + 1u);
	return 1;
}

int ncfg_observe_roots_default(ncfg_observe_roots_t *out, char *err, size_t err_size)
{
	if (!out) {
		ncfg_error_set(err, err_size, "there is nowhere to put the roots");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	/* radio.h's, because "is this a radio" is its question: a second reading
	 * of `NCFG_SYS_CLASS_NET` here would be a second answer to it. */
	if (!ncfg_radio_class_net(out->class_net, sizeof(out->class_net), err, err_size)) {
		return 0;
	}
	if (!root_from_env(NCFG_OBSERVE_PROC_ROOT_ENV, NCFG_OBSERVE_PROC_ROOT_DEFAULT, out->proc,
	    sizeof(out->proc), err, err_size)) {
		return 0;
	}
	return root_from_env(NCFG_OBSERVE_SYS_ROOT_ENV, NCFG_OBSERVE_SYS_ROOT_DEFAULT, out->sys,
	    sizeof(out->sys), err, err_size);
}

/* ------------------------------------------------------------------------ *
 * The sysctls
 * ------------------------------------------------------------------------ */

/* One family's forwarding flag. `!= "0"` rather than `== "1"`, which is what
 * the kernel's own semantics are: anything non-zero forwards. */
static int family_forwards(const char *proc_root, const char *family, const char *name,
    int *value_out)
{
	char path[HOST_PATH_MAX];
	char value[HOST_VALUE_MAX];
	int  written;

	written = snprintf(path, sizeof(path), "%s/sys/net/%s/conf/%s/forwarding", proc_root,
	    family, name);
	if (written < 0 || (size_t)written >= sizeof(path)) {
		return 0;
	}
	if (!read_value(path, value, sizeof(value))) {
		return 0;
	}
	*value_out = strcmp(value, "0") != 0;
	return 1;
}

ncfg_optbool_t ncfg_observe_forwarding(const char *proc_root, const char *name)
{
	int four = 0;
	int six = 0;

	if (!proc_root || !name) {
		return no_bool();
	}
	/* **Both must be readable.** One family present and the other missing
	 * means an IPv6-disabled kernel, where reporting the IPv4 answer alone
	 * would have the planner satisfied by half a change it can never
	 * complete. */
	if (!family_forwards(proc_root, "ipv4", name, &four) ||
	    !family_forwards(proc_root, "ipv6", name, &six)) {
		return no_bool();
	}
	return some_bool(four && six);
}

ncfg_optbool_t ncfg_observe_privacy(const char *proc_root, const char *name)
{
	char value[HOST_VALUE_MAX];

	if (!proc_root || !name ||
	    !read_joined(value, sizeof(value), "%s/sys/net/ipv6/conf/%s/use_tempaddr", proc_root,
	    name)) {
		return no_bool();
	}
	/* `2` is the only value the document can ask for, so it is the only one
	 * that reads as true -- `1` generates a temporary address and prefers
	 * the stable one, which is a state nothing here can request and netcfgd
	 * therefore does not claim as its own. */
	return some_bool(strcmp(value, "2") == 0);
}

int ncfg_observe_accept_ra(const char *proc_root, const char *name,
    ncfg_observed_accept_ra_t *out)
{
	char          value[HOST_VALUE_MAX];
	char          forwarding[HOST_VALUE_MAX];
	char         *end;
	unsigned long number;
	int           forwards;

	if (!out) {
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!proc_root || !name ||
	    !read_joined(value, sizeof(value), "%s/sys/net/ipv6/conf/%s/accept_ra", proc_root,
	    name)) {
		return 0;
	}
	number = strtoul(value, &end, 10);
	if (end == value || *end != '\0' || number > 255u) {
		return 0;
	}
	/* **The IPv6 forwarding file alone**, not a link's `forwarding`, which
	 * is true only when both families forward and is the right answer to a
	 * different question: a machine with IPv6 forwarding on and IPv4 off
	 * ignores advertisements while that field says false.
	 *
	 * One that cannot be read is treated as off, which is the kernel's own
	 * default for an interface: the value that is *there* is `accept_ra`,
	 * and refusing to answer at all because its neighbour is missing would
	 * report "netcfgd cannot tell" on a machine where it plainly can. */
	forwards = read_joined(forwarding, sizeof(forwarding),
	    "%s/sys/net/ipv6/conf/%s/forwarding", proc_root, name) &&
	    strcmp(forwarding, "1") == 0;
	out->value = (int64_t)number;
	out->effective = number == 2u || (number == 1u && !forwards);
	return 1;
}

char *ncfg_observe_hostname(const char *proc_root)
{
	char value[HOST_VALUE_MAX];
	char path[HOST_PATH_MAX];
	int  written;

	if (!proc_root) {
		return NULL;
	}
	written = snprintf(path, sizeof(path), "%s/sys/kernel/hostname", proc_root);
	if (written < 0 || (size_t)written >= sizeof(path)) {
		return NULL;
	}
	if (!read_value(path, value, sizeof(value))) {
		return NULL;
	}
	return observe_dup(value);
}

/* ------------------------------------------------------------------------ *
 * The kill switches
 * ------------------------------------------------------------------------ */

/*
 * The entries of a directory, sorted.
 *
 * Sorted because `readdir` order is the filesystem's, and a laptop has two
 * `wlan` switches: whichever comes first is luck, and a test that depends on
 * that luck proves nothing about the search. Deleting the name match left the
 * Rust's unit test passing until its sort was there.
 *
 * `prefix` narrows the listing where a caller wants only one family of names.
 * An unreadable directory is an empty listing rather than a failure.
 */
static int entries_of(const char *path, const char *prefix, char ***out, size_t *out_count)
{
	DIR                 *open_dir = opendir(path);
	const struct dirent *found;

	if (!open_dir) {
		return 1;
	}
	while ((found = readdir(open_dir)) != NULL) {
		if (strcmp(found->d_name, ".") == 0 || strcmp(found->d_name, "..") == 0) {
			continue;
		}
		if (prefix && strncmp(found->d_name, prefix, strlen(prefix)) != 0) {
			continue;
		}
		if (!observe_list_add(out, out_count, found->d_name)) {
			(void)closedir(open_dir);
			return 0;
		}
	}
	(void)closedir(open_dir);
	observe_list_sort(*out, *out_count);
	return 1;
}

/* One flag file. **A flag that cannot be read is not a flag that is clear**, so
 * this reports whether it could be read at all and the caller refuses to build
 * a switch out of half an answer. */
static int read_flag(const char *directory, const char *file, int *out)
{
	char value[HOST_VALUE_MAX];

	if (!read_joined(value, sizeof(value), "%s/%s", directory, file)) {
		return 0;
	}
	*out = strcmp(value, "1") == 0;
	return 1;
}

/*
 * A switch from one `rfkill` directory, where all three files are readable.
 *
 * `switch_` is the name read from *this* entry rather than the phy name a
 * search started from. They are equal by the search's own check -- which is the
 * point: a field describing where the flags came from must be able to disagree,
 * or it cannot be wrong when the search is.
 */
static int switch_at(const char *directory, ncfg_observed_rfkill_t **out, char *err,
    size_t err_size)
{
	char name[HOST_VALUE_MAX];
	int  soft;
	int  hard;

	*out = NULL;
	if (!read_joined(name, sizeof(name), "%s/%s", directory, "name") ||
	    !read_flag(directory, "soft", &soft) || !read_flag(directory, "hard", &hard)) {
		return 1;
	}
	*out = calloc(1, sizeof(**out));
	if (!*out) {
		ncfg_error_set(err, err_size, "out of memory recording a kill switch");
		return 0;
	}
	(*out)->switch_ = observe_dup(name);
	if (!(*out)->switch_) {
		free(*out);
		*out = NULL;
		ncfg_error_set(err, err_size, "out of memory recording a kill switch");
		return 0;
	}
	(*out)->soft = soft;
	(*out)->hard = hard;
	return 1;
}

int ncfg_observe_rfkill(const char *sys_root, const char *iface, ncfg_observed_rfkill_t **out,
    char *err, size_t err_size)
{
	char    phy[HOST_VALUE_MAX];
	char    listing[HOST_PATH_MAX];
	char  **entries = NULL;
	size_t  count = 0;
	size_t  at;
	int     built = 1;

	if (!out) {
		ncfg_error_set(err, err_size, "there is nowhere to put a kill switch");
		return 0;
	}
	*out = NULL;
	if (!sys_root || !iface) {
		return 1;
	}
	/* Exists only for a radio, so anything wired answers here with no
	 * special case. */
	if (!read_joined(phy, sizeof(phy), "%s/class/net/%s/phy80211/name", sys_root, iface)) {
		return 1;
	}
	if (!join(listing, sizeof(listing), "%s/class/%s", sys_root, "rfkill")) {
		return 1;
	}
	if (!entries_of(listing, NULL, &entries, &count)) {
		observe_names_free(entries, count);
		ncfg_error_set(err, err_size, "out of memory listing the kill switches");
		return 0;
	}
	for (at = 0; at < count; at++) {
		char directory[HOST_PATH_MAX];
		char name[HOST_VALUE_MAX];

		if (!join(directory, sizeof(directory), "%s/%s", listing, entries[at])) {
			continue;
		}
		/*
		 * **Skip, do not return.** The Rust's `?` here returned from the
		 * whole function, so one unreadable `name` on an unrelated entry
		 * abandoned the search -- and the listing is sorted, so an entry
		 * sorting before the phy's own decided for every entry after it.
		 * A laptop's `rfkill0` is typically the platform button or a
		 * Bluetooth switch, and a USB dongle being unplugged tears its
		 * directory down between the listing and this read.
		 *
		 * Skipping is right rather than fail-closed here: an entry whose
		 * name cannot be read is one we cannot show is ours, and a later
		 * entry still can be. The fail-closed reasoning applies to the
		 * flags of the entry that *is* ours, which is a different
		 * question and is `switch_at`'s.
		 */
		if (!read_joined(name, sizeof(name), "%s/%s", directory, "name")) {
			continue;
		}
		if (strcmp(name, phy) != 0) {
			continue;
		}
		built = switch_at(directory, out, err, err_size);
		/* The matching entry decides. A phy whose flags cannot be read
		 * reports nothing rather than falling through to some other
		 * entry that happens to carry the same name. */
		break;
	}
	observe_names_free(entries, count);
	return built;
}

/* ------------------------------------------------------------------------ *
 * The Bluetooth adapters
 * ------------------------------------------------------------------------ */

/*
 * The rfkill switch inside one adapter's own directory.
 *
 * Sorted for the reason the wifi search sorts: `readdir` order is the
 * filesystem's, and a directory that ever held two would make the answer luck.
 * One is expected here, so this is cheap insurance rather than a case anybody
 * has seen.
 */
static int adapter_switch(const char *adapter, ncfg_observed_rfkill_t **out, char *err,
    size_t err_size)
{
	char  **entries = NULL;
	size_t  count = 0;
	char    directory[HOST_PATH_MAX];
	int     built = 1;

	*out = NULL;
	if (!entries_of(adapter, "rfkill", &entries, &count)) {
		observe_names_free(entries, count);
		ncfg_error_set(err, err_size, "out of memory listing an adapter's switches");
		return 0;
	}
	if (count > 0 && join(directory, sizeof(directory), "%s/%s", adapter, entries[0])) {
		built = switch_at(directory, out, err, err_size);
	}
	observe_names_free(entries, count);
	return built;
}

int ncfg_observe_bluetooth(const char *sys_root, ncfg_observed_bluetooth_t **out,
    size_t *count_out, char *err, size_t err_size)
{
	char    listing[HOST_PATH_MAX];
	char  **entries = NULL;
	size_t  count = 0;
	size_t  at;

	if (!out || !count_out) {
		ncfg_error_set(err, err_size, "there is nowhere to put the adapters");
		return 0;
	}
	*out = NULL;
	*count_out = 0;
	if (!sys_root || !join(listing, sizeof(listing), "%s/class/%s", sys_root, "bluetooth")) {
		return 1;
	}
	if (!entries_of(listing, NULL, &entries, &count)) {
		observe_names_free(entries, count);
		ncfg_error_set(err, err_size, "out of memory listing the Bluetooth adapters");
		return 0;
	}
	if (count == 0) {
		/* No Bluetooth, or a kernel without the subsystem. An empty list
		 * is the honest answer and is what a machine with no adapter
		 * has. */
		observe_names_free(entries, count);
		return 1;
	}
	*out = calloc(count, sizeof(**out));
	if (!*out) {
		observe_names_free(entries, count);
		ncfg_error_set(err, err_size, "out of memory recording the Bluetooth adapters");
		return 0;
	}
	for (at = 0; at < count; at++) {
		char adapter[HOST_PATH_MAX];

		(*count_out)++;
		(*out)[at].name = observe_dup(entries[at]);
		if (!(*out)[at].name) {
			observe_names_free(entries, count);
			ncfg_error_set(err, err_size,
			    "out of memory recording the Bluetooth adapters");
			return 0;
		}
		if (!join(adapter, sizeof(adapter), "%s/%s", listing, entries[at])) {
			continue;
		}
		if (!adapter_switch(adapter, &(*out)[at].rfkill, err, err_size)) {
			observe_names_free(entries, count);
			return 0;
		}
	}
	observe_names_free(entries, count);
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Everything the snapshot could not supply
 * ------------------------------------------------------------------------ */

int ncfg_observe_augment_host(ncfg_observed_t *observed, const ncfg_observe_roots_t *roots,
    char *err, size_t err_size)
{
	size_t at;

	if (!observed || !roots) {
		ncfg_error_set(err, err_size, "there is no observation to augment");
		return 0;
	}
	for (at = 0; at < observed->link_count; at++) {
		ncfg_observed_link_t     *link = &observed->links[at];
		ncfg_observed_accept_ra_t accept_ra;

		link->forwarding = ncfg_observe_forwarding(roots->proc, link->name);
		link->privacy = ncfg_observe_privacy(roots->proc, link->name);
		/* Replaced rather than added to, so that a second pass over one
		 * observation says what the machine says now. */
		free(link->accept_ra);
		link->accept_ra = NULL;
		if (ncfg_observe_accept_ra(roots->proc, link->name, &accept_ra)) {
			link->accept_ra = calloc(1, sizeof(*link->accept_ra));
			if (!link->accept_ra) {
				ncfg_error_set(err, err_size,
				    "out of memory recording accept_ra");
				return 0;
			}
			*link->accept_ra = accept_ra;
		}
	}
	free(observed->hostname);
	observed->hostname = ncfg_observe_hostname(roots->proc);
	for (at = 0; at < observed->link_count; at++) {
		ncfg_observed_link_t *link = &observed->links[at];

		if (link->rfkill) {
			free(link->rfkill->switch_);
			free(link->rfkill);
			link->rfkill = NULL;
		}
		if (!ncfg_observe_rfkill(roots->sys, link->name, &link->rfkill, err, err_size)) {
			return 0;
		}
	}
	for (at = 0; at < observed->bluetooth_count; at++) {
		free(observed->bluetooth[at].name);
		if (observed->bluetooth[at].rfkill) {
			free(observed->bluetooth[at].rfkill->switch_);
			free(observed->bluetooth[at].rfkill);
		}
	}
	free(observed->bluetooth);
	observed->bluetooth = NULL;
	observed->bluetooth_count = 0;
	return ncfg_observe_bluetooth(roots->sys, &observed->bluetooth,
	    &observed->bluetooth_count, err, err_size);
}
