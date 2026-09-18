/*
 * peer.c -- who is on the other end of a unix socket.
 *
 * The interesting part is what `SO_PEERCRED` does not tell you. It reports the
 * peer's pid, uid and *primary* gid, and a user's primary group is usually
 * their own -- so checking `group:netdev` against it alone would deny nearly
 * everybody the rule is meant to allow, while looking configured. The
 * supplementary set comes from `/proc`, with the uid cross-check below.
 *
 * WHY THE PATHS ARE ARGUMENTS
 *   `/proc`, `/etc/group` and `/etc/passwd` arrive from the caller. The Rust
 *   reads all three from constants and pays for it in its own tests, which say
 *   twice that resolving a group asks this machine's `/etc/group` and check
 *   something else instead. Here a test hands over a fixture directory and the
 *   rule itself gets exercised.
 */
/*
 * `struct ucred` and `SO_PEERCRED` are Linux's, and the tree's floor of
 * `-D_DEFAULT_SOURCE` does not publish the struct -- `sys/socket.h` guards it
 * on `__USE_GNU`. This is the only file in the module that wants more, so the
 * request is here rather than in the Makefile where it would apply to every
 * file that does not need it. It must precede every header.
 */
#define _GNU_SOURCE

#include "ncfg/daemon.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

int ncfg_peer_is_root(const ncfg_peer_t *peer)
{
	return peer && peer->uid == 0;
}

int ncfg_peer_in_group(const ncfg_peer_t *peer, gid_t gid)
{
	size_t at;

	if (!peer) {
		return 0;
	}
	if (peer->gid == gid) {
		return 1;
	}
	for (at = 0; at < peer->group_count; at++) {
		if (peer->groups[at] == gid) {
			return 1;
		}
	}
	return 0;
}

ncfg_authz_roots_t ncfg_authz_roots_default(void)
{
	ncfg_authz_roots_t roots;

	roots.proc_root = "/proc";
	roots.group_file = "/etc/group";
	roots.passwd_file = "/etc/passwd";
	return roots;
}

/* The caller's, or the machine's where the caller said nothing. */
static const char *or_default(const char *given, const char *fallback)
{
	return (given && given[0]) ? given : fallback;
}

/*
 * One unsigned id out of a field, refusing anything that is not all digits.
 *
 * `strtoul` alone would read `1000junk` as 1000 and `-1` as a very large id,
 * and a `/etc/group` line that is not what it looks like should resolve to
 * nothing rather than to something surprising.
 */
static int parse_id(const char *text, size_t length, unsigned long *out)
{
	unsigned long value = 0;
	size_t        at;

	if (length == 0 || length > 10) {
		return 0;
	}
	for (at = 0; at < length; at++) {
		if (text[at] < '0' || text[at] > '9') {
			return 0;
		}
		value = value * 10u + (unsigned long)(text[at] - '0');
	}
	*out = value;
	return 1;
}

/* The `n`th colon-separated field of `line`, as a pointer and a length. */
static int field_at(const char *line, size_t wanted, const char **out, size_t *length_out)
{
	size_t index = 0;
	const char *start = line;

	for (;;) {
		const char *stop = strchr(start, ':');
		size_t      length = stop ? (size_t)(stop - start) : strlen(start);

		if (index == wanted) {
			*out = start;
			*length_out = length;
			return 1;
		}
		if (!stop) {
			return 0;
		}
		start = stop + 1;
		index++;
	}
}

/*
 * Field 0 of every line in a colon-separated database, matched by name, with
 * field `id_field` returned as a number.
 *
 * `/etc/group` and `/etc/passwd` are read as files rather than through
 * `getgrnam`/`getpwnam`, which would pull in NSS and with it whatever modules
 * the host has configured -- LDAP, SSSD, a network round trip inside an
 * accept. A network configuration daemon resolving a group over the network to
 * decide who may configure the network is a dependency loop whose failure only
 * shows up on the machine whose network is broken.
 */
static int lookup_id(const char *path, const char *name, size_t id_field, unsigned long *out)
{
	FILE *file;
	char  line[4096];
	int   found = 0;

	if (!path || !name || !name[0]) {
		return 0;
	}
	file = fopen(path, "r");
	if (!file) {
		return 0;
	}
	while (!found && fgets(line, sizeof(line), file)) {
		const char *field;
		size_t      length;
		size_t      end = strcspn(line, "\r\n");

		line[end] = '\0';
		if (!field_at(line, 0, &field, &length)) {
			continue;
		}
		if (length != strlen(name) || memcmp(field, name, length) != 0) {
			continue;
		}
		if (field_at(line, id_field, &field, &length) && parse_id(field, length, out)) {
			found = 1;
		}
		/* A matching name whose id does not parse is not a reason to go on
		 * looking: the entry exists and is broken, and the next line that
		 * happened to carry the same name would be a different answer. */
		break;
	}
	(void)fclose(file);
	return found;
}

int ncfg_peer_group_id(const char *group_file, const char *name, gid_t *out)
{
	unsigned long value;

	if (!out) {
		return 0;
	}
	/* name:passwd:gid:members */
	if (!lookup_id(or_default(group_file, "/etc/group"), name, 2u, &value)) {
		return 0;
	}
	*out = (gid_t)value;
	return 1;
}

int ncfg_peer_user_id(const char *passwd_file, const char *name, uid_t *out)
{
	unsigned long value;

	if (!out) {
		return 0;
	}
	/* name:passwd:uid:gid:... */
	if (!lookup_id(or_default(passwd_file, "/etc/passwd"), name, 2u, &value)) {
		return 0;
	}
	*out = (uid_t)value;
	return 1;
}

/* The first whitespace-separated field after a `Key:` prefix. */
static const char *after_prefix(const char *line, const char *prefix)
{
	size_t length = strlen(prefix);

	if (strncmp(line, prefix, length) != 0) {
		return NULL;
	}
	return line + length;
}

int ncfg_peer_groups_from(const char *proc_root, pid_t pid, uid_t expected, ncfg_peer_t *out)
{
	char        path[256];
	FILE       *file;
	char        line[8192];
	int         uid_matches = 0;
	int         saw_groups = 0;
	const char *rest;

	if (!out) {
		return 0;
	}
	out->group_count = 0;
	out->group_total = 0;
	out->groups_known = 0;

	(void)snprintf(path, sizeof(path), "%s/%ld/status", or_default(proc_root, "/proc"),
	    (long)pid);
	file = fopen(path, "r");
	if (!file) {
		return 0;
	}
	/*
	 * Two passes in one, because the file is small and the order of its lines
	 * is not this module's to assume: `Uid:` precedes `Groups:` on every
	 * kernel anybody runs, and a reader that depended on it would be a reader
	 * that silently stopped checking the uid the day it did not.
	 *
	 * The real uid is the first field of `Uid:`. A mismatch means the pid is
	 * not the process that connected -- it was recycled between `SO_PEERCRED`
	 * returning and this file being opened -- and on any doubt this fills in
	 * nothing, which denies.
	 */
	while (fgets(line, sizeof(line), file)) {
		size_t end = strcspn(line, "\r\n");

		line[end] = '\0';
		rest = after_prefix(line, "Uid:");
		if (rest) {
			unsigned long value;
			size_t        length;

			while (*rest == ' ' || *rest == '\t') {
				rest++;
			}
			length = strcspn(rest, " \t");
			if (parse_id(rest, length, &value) && (uid_t)value == expected) {
				uid_matches = 1;
			}
			continue;
		}
		rest = after_prefix(line, "Groups:");
		if (!rest) {
			continue;
		}
		saw_groups = 1;
		while (*rest) {
			unsigned long value;
			size_t        length;

			while (*rest == ' ' || *rest == '\t') {
				rest++;
			}
			if (!*rest) {
				break;
			}
			length = strcspn(rest, " \t");
			if (parse_id(rest, length, &value)) {
				out->group_total++;
				if (out->group_count < NCFG_PEER_GROUPS_MAX) {
					out->groups[out->group_count] = (gid_t)value;
					out->group_count++;
				}
			}
			rest += length;
		}
	}
	(void)fclose(file);

	if (!uid_matches) {
		/* Not the process that connected, or a file with no `Uid:` line at
		 * all. Everything read is discarded rather than half-trusted. */
		out->group_count = 0;
		out->group_total = 0;
		return 0;
	}
	/* A process genuinely in no supplementary group still has the line, with
	 * nothing after it. That is a known set, and an empty one. */
	out->groups_known = saw_groups;
	if (!saw_groups) {
		out->group_count = 0;
		out->group_total = 0;
	}
	return out->groups_known;
}

int ncfg_peer_credentials(int socket, const ncfg_authz_roots_t *roots, ncfg_peer_t *out,
    char *err, size_t err_size)
{
	struct ucred      credentials;
	socklen_t         length = (socklen_t)sizeof(credentials);
	ncfg_authz_roots_t where = roots ? *roots : ncfg_authz_roots_default();

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the peer's credentials");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	memset(&credentials, 0, sizeof(credentials));
	if (getsockopt(socket, SOL_SOCKET, SO_PEERCRED, &credentials, &length) < 0) {
		/* On a unix socket this means the connection has already gone. */
		ncfg_error_set(err, err_size, "the peer's credentials could not be read: %s",
		    strerror(errno));
		return 0;
	}
	out->pid = credentials.pid;
	out->uid = credentials.uid;
	out->gid = credentials.gid;
	/*
	 * A supplementary set that could not be read is **not** a failure of this
	 * call. The peer is still identified by uid and primary gid, and every
	 * `group:` rule then denies -- which is the answer a security control
	 * should give when it cannot tell, and is why this return value is
	 * ignored rather than propagated.
	 */
	(void)ncfg_peer_groups_from(where.proc_root, out->pid, out->uid, out);
	return 1;
}
