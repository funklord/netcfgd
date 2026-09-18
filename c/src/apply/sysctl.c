/*
 * sysctl.c -- the four ops that change a machine by writing a file.
 *
 * WHY A PLAIN `write` AND NOT `ncfg_write_atomically`
 *   Nothing here is under `/run` or `/etc`. A `procfs` file is a handle on a
 *   kernel variable rather than a file: it cannot be renamed into place, a
 *   staging file beside it cannot be created, and the write is already atomic
 *   in the only sense that matters -- one `write` of one value is one
 *   assignment. Reaching for the atomic writer would fail on every machine
 *   this runs on, at the `rename`.
 *
 * WHY THE ROOT IS THE FIRST ARGUMENT OF EVERY ONE OF THEM
 *   `testdir.h`'s rule, and this is the module it exists for. These four calls
 *   are the ones that would otherwise write the developer's forwarding state,
 *   the developer's temporary-address policy and the developer's hostname --
 *   on a workstation whose network is live. A test that forgot to set an
 *   environment variable would do exactly that; a test that forgets an
 *   argument does not compile.
 *
 * WHY NOTHING HERE READS BEFORE IT WRITES
 *   Writing a value that is already there is the same write, so these are
 *   idempotent without asking. They are also cheap, and a read-then-write
 *   would be a check whose answer can change between the two.
 */
#include "ncfg/service.h"

#include "ncfg/base.h"
#include "ncfg/log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Long enough for any root a caller may hand over plus the longest of the
 * four tails, which is `sys/net/ipv6/conf/<iface>/use_tempaddr`. A path that
 * does not fit is a failure rather than a shorter one: a truncated path names
 * a different file, and this is about to write to it. */
#define SYSCTL_PATH_MAX 4352u

/*
 * The root, checked once.
 *
 * NULL and empty are refused **by name** rather than defaulted, which is the
 * whole of this module's safety: `""` joined to a tail is a relative path, so
 * a missing root would write `sys/kernel/hostname` into whatever directory the
 * process happens to be in -- which is a file nobody reads, reported as a
 * hostname that was set.
 */
static int root_is_usable(const char *proc_root, const char *doing, char *err, size_t err_size)
{
	if (!proc_root || proc_root[0] == '\0') {
		ncfg_error_set(err, err_size,
		    "%s needs to be told where /proc is; this build has no default for it, "
		    "because a default is how a test comes to write the machine's own", doing);
		return 0;
	}
	return 1;
}

/*
 * An interface name that can safely become a path component.
 *
 * `radio.h`'s rule, applied to a write rather than to a question: a name
 * carrying a separator or `..` would escape `sys/net/ipv4/conf` and set a
 * sysctl on something else entirely -- and unlike a read, the answer is not
 * "0, it is not a radio" but a machine that changed somewhere nobody asked
 * about. Everything here has been through the compiler, which accepts no such
 * name; this is the backstop that makes that a property rather than a
 * coincidence.
 */
static int name_is_a_component(const char *name, const char *doing, char *err, size_t err_size)
{
	size_t i;

	if (!name || name[0] == '\0') {
		ncfg_error_set(err, err_size, "%s names no interface to act on", doing);
		return 0;
	}
	if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
		ncfg_error_set(err, err_size, "`%s` is not an interface name", name);
		return 0;
	}
	for (i = 0; name[i] != '\0'; i++) {
		if (name[i] == '/') {
			ncfg_error_set(err, err_size,
			    "`%s` carries a path separator, so it is not an interface this "
			    "may set a sysctl on", name);
			return 0;
		}
	}
	return 1;
}

/*
 * Write one value to one file under the root.
 *
 * `O_WRONLY | O_TRUNC` and no `O_CREAT`: every one of these files exists or
 * the feature is not in this kernel, and creating one would leave an ordinary
 * file where a sysctl was expected -- which reads back correctly for ever and
 * changes nothing. `errno` is in the sentence because the two ways this fails
 * on a real machine are a missing IPv6 stack and a container without a
 * writable `/proc/sys`, and the operator has to be able to tell them apart.
 */
static int write_value(const char *path, const char *value, char *err, size_t err_size)
{
	size_t  length = strlen(value);
	ssize_t put;
	int     handle = open(path, O_WRONLY | O_TRUNC);

	if (handle < 0) {
		ncfg_error_set(err, err_size, "cannot open %s: %s", path, strerror(errno));
		return 0;
	}
	put = write(handle, value, length);
	if (put < 0 || (size_t)put != length) {
		int failed = errno;

		(void)close(handle);
		ncfg_error_set(err, err_size, "cannot write `%s` to %s: %s", value, path,
		    put < 0 ? strerror(failed) : "the kernel took only part of it");
		return 0;
	}
	if (close(handle) != 0) {
		/* A `procfs` write is checked at `write` rather than at `close`, but a
		 * close that fails is still a write nobody can vouch for, and
		 * reporting success for one is how a machine comes to disagree with
		 * the journal that describes it. */
		ncfg_error_set(err, err_size, "cannot finish writing %s: %s", path, strerror(errno));
		return 0;
	}
	return 1;
}

/* `<root>/sys/net/<family>/conf/<iface>/<leaf>`, or `<root>/sys/<tail>` where
 * `family` is NULL. 1 on success; truncation is a failure. */
static int sysctl_path(char *out, size_t out_size, const char *root, const char *family,
    const char *iface, const char *leaf, char *err, size_t err_size)
{
	int written;

	if (family) {
		written = snprintf(out, out_size, "%s/sys/net/%s/conf/%s/%s", root, family, iface,
		    leaf);
	} else {
		written = snprintf(out, out_size, "%s/sys/%s", root, leaf);
	}
	if (written < 0 || (size_t)written >= out_size) {
		ncfg_error_set(err, err_size,
		    "the path to %s under %s does not fit in %zu bytes", leaf, root, out_size);
		return 0;
	}
	return 1;
}

int ncfg_service_set_forwarding(const char *proc_root, const char *iface, int enabled, char *err,
    size_t err_size)
{
	char        path[SYSCTL_PATH_MAX];
	char        detail[NCFG_ERROR_MAX];
	const char *value = enabled ? "1" : "0";

	if (!root_is_usable(proc_root, "sysctl.set_forwarding", err, err_size) ||
	    !name_is_a_component(iface, "sysctl.set_forwarding", err, err_size)) {
		return 0;
	}
	if (!sysctl_path(path, sizeof(path), proc_root, "ipv4", iface, "forwarding", err,
	    err_size)) {
		return 0;
	}
	if (!write_value(path, value, detail, sizeof(detail))) {
		ncfg_error_set(err, err_size, "cannot set IPv4 forwarding on %s: %s", iface, detail);
		return 0;
	}
	/*
	 * And the other family, whose failure is a warning rather than the end of
	 * the apply. A kernel built with `ipv6.disable=1` has no IPv6 sysctl at
	 * all, and refusing there would make netcfgd unable to configure an IPv4
	 * router at all. What the warning adds over the Rust's is the consequence:
	 * a reader of a log line that says only "cannot set IPv6 forwarding" does
	 * not know whether anything was routed.
	 */
	if (!sysctl_path(path, sizeof(path), proc_root, "ipv6", iface, "forwarding", detail,
	    sizeof(detail)) || !write_value(path, value, detail, sizeof(detail))) {
		ncfg_log_emitf("forwarding", NCFG_LOG_WARNING,
		    "cannot set IPv6 forwarding on %s: %s; IPv4 is set and IPv6 traffic will "
		    "not be routed", iface, detail);
	}
	return 1;
}

int ncfg_service_set_privacy(const char *proc_root, const char *iface, int prefer_temporary,
    char *err, size_t err_size)
{
	char path[SYSCTL_PATH_MAX];
	char detail[NCFG_ERROR_MAX];

	if (!root_is_usable(proc_root, "sysctl.set_privacy", err, err_size) ||
	    !name_is_a_component(iface, "sysctl.set_privacy", err, err_size)) {
		return 0;
	}
	if (!sysctl_path(path, sizeof(path), proc_root, "ipv6", iface, "use_tempaddr", err,
	    err_size)) {
		return 0;
	}
	/*
	 * Fatal on failure, unlike the IPv6 half of `set_forwarding`. There is no
	 * IPv4 equivalent to fall back to -- a kernel with no IPv6 has no
	 * temporary addresses to configure -- and the planner never asks, because
	 * the observation of an absent sysctl is absent and nothing is planned on
	 * one. So reaching this means the file was there when it was read.
	 */
	if (!write_value(path, prefer_temporary ? "2" : "0", detail, sizeof(detail))) {
		ncfg_error_set(err, err_size, "cannot set temporary addresses on %s: %s", iface,
		    detail);
		return 0;
	}
	return 1;
}

int ncfg_service_set_accept_ra(const char *proc_root, const char *iface, int64_t value, char *err,
    size_t err_size)
{
	char path[SYSCTL_PATH_MAX];
	char detail[NCFG_ERROR_MAX];
	char written[2];

	if (!root_is_usable(proc_root, "sysctl.set_accept_ra", err, err_size) ||
	    !name_is_a_component(iface, "sysctl.set_accept_ra", err, err_size)) {
		return 0;
	}
	/*
	 * 0073: netcfgd writes `2` -- accept even while forwarding -- and `1`,
	 * which is the kernel's own default and is what an interface that stops
	 * asking for SLAAC gets back. It never writes `0`, because switching
	 * advertisements off is a thing an operator may have chosen and no
	 * document here asks for.
	 */
	if (value != 1 && value != 2) {
		ncfg_error_set(err, err_size,
		    "sysctl.set_accept_ra on %s asks for %lld; netcfgd writes 1 or 2 and "
		    "never 0, since switching advertisements off is a choice no document "
		    "here makes", iface, (long long)value);
		return 0;
	}
	if (!sysctl_path(path, sizeof(path), proc_root, "ipv6", iface, "accept_ra", err,
	    err_size)) {
		return 0;
	}
	written[0] = (char)('0' + (int)value);
	written[1] = '\0';
	if (!write_value(path, written, detail, sizeof(detail))) {
		ncfg_error_set(err, err_size, "cannot set accept_ra on %s: %s", iface, detail);
		return 0;
	}
	return 1;
}

int ncfg_service_set_hostname(const char *proc_root, const char *name, char *err, size_t err_size)
{
	char   path[SYSCTL_PATH_MAX];
	char   detail[NCFG_ERROR_MAX];
	size_t i;

	if (!root_is_usable(proc_root, "hostname.set", err, err_size)) {
		return 0;
	}
	if (!name || name[0] == '\0') {
		ncfg_error_set(err, err_size, "hostname.set carries no name to set");
		return 0;
	}
	/*
	 * The file is a line. A value carrying a newline would set the hostname to
	 * the part before it while the document, the plan and the journal all say
	 * the whole thing -- and every comparison afterwards would plan the same
	 * change again. Refused rather than trimmed, because a name somebody typed
	 * that is not the name they get is the kind of quiet disagreement this
	 * project exists to refuse.
	 */
	for (i = 0; name[i] != '\0'; i++) {
		if ((unsigned char)name[i] < 0x20u || (unsigned char)name[i] == 0x7fu) {
			ncfg_error_set(err, err_size,
			    "the hostname carries a control character at byte %zu, and the "
			    "kernel's own file is one line", i);
			return 0;
		}
	}
	if (!sysctl_path(path, sizeof(path), proc_root, NULL, NULL, "kernel/hostname", err,
	    err_size)) {
		return 0;
	}
	if (!write_value(path, name, detail, sizeof(detail))) {
		ncfg_error_set(err, err_size, "cannot set the hostname to `%s`: %s", name, detail);
		return 0;
	}
	return 1;
}
