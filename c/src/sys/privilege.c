/*
 * privilege.c -- giving away what this process holds, permanently.
 *
 * **It is deliberately one direction and has no inverse**: everything here is
 * irreversible for the process that calls it, which is the property that makes
 * it worth having. process.h carries the reasoning; this file is the four steps
 * and the verification that they happened.
 */
/*
 * `getresuid` is a GNU extension, and all three uids are what this file needs:
 * a saved-set uid of 0 is a way back, so a check that reads only the real and
 * effective ones would call a process disarmed that can `seteuid` straight back
 * to root. The tree's floor is `-D_DEFAULT_SOURCE`, which does not publish it,
 * and this is the only file that wants more -- so the request is here rather
 * than in the Makefile, where it would apply to every module that does not need
 * it. It must precede every header.
 */
#define _GNU_SOURCE

#include "ncfg/process.h"

#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/*
 * `_LINUX_CAPABILITY_VERSION_3`, from `linux/capability.h`.
 *
 * Version 3 is two 32-bit words per set. Passing version 1 to a kernel that
 * speaks 3 makes `capset` rewrite the header and fail, which reads as a
 * mysterious `EINVAL` rather than as "ask again".
 */
#define CAPABILITY_VERSION_3 0x20080522u

/*
 * The highest capability number worth trying to drop.
 *
 * `/proc/sys/kernel/cap_last_cap` is the honest answer and this does not read
 * it: dropping a capability the kernel does not have returns `EINVAL`, which
 * costs a failed syscall and nothing else, so the loop runs to a number
 * comfortably above any kernel's and ignores the refusals. One fewer file to be
 * unable to open in a child that is giving up the ability to open files.
 */
#define CAPABILITY_CEILING 63

/*
 * The `prctl` numbers, where a build host's headers are older than its kernel.
 *
 * These are ABI and cannot change: a value defined here differently from the
 * kernel's would drop the wrong thing silently. They are spelled only where the
 * header did not.
 */
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef PR_CAPBSET_DROP
#define PR_CAPBSET_DROP 24
#endif
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#endif
#ifndef PR_CAP_AMBIENT_CLEAR_ALL
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

/* The layout `capset` reads. Named here because libcap owns the header and
 * this does not link against it -- the syscall is what libcap would issue. */
struct cap_header {
	uint32_t version;
	int      pid;
};

struct cap_data {
	uint32_t effective;
	uint32_t permitted;
	uint32_t inheritable;
};

/* Status text is read whole, for the reason process.c gives; the `Cap*` lines
 * sit further into the file than `Uid:` does, so this buffer is a page. */
#define STATUS_TEXT_MAX 8192

/* One `Cap...:` field of `/proc/thread-self/status`, as a 64-bit mask. */
static int capability_field(const char *status, const char *name, uint64_t *out)
{
	const char *at = status;
	size_t length = strlen(name);

	while (*at != '\0') {
		if (strncmp(at, name, length) == 0) {
			char *end;
			unsigned long long value;

			at += length;
			while (*at == ' ' || *at == '\t') {
				at++;
			}
			errno = 0;
			value = strtoull(at, &end, 16);
			if (end == at || errno != 0) {
				return 0;
			}
			*out = (uint64_t)value;
			return 1;
		}
		at = strchr(at, '\n');
		if (!at) {
			break;
		}
		at++;
	}
	return 0;
}

/*
 * The calling thread's status file.
 *
 * **`/proc/thread-self`, not `/proc/self`.** Capabilities are per-thread and
 * `/proc/self/status` reports the thread group leader, so a caller that has
 * just shed on a worker thread would read back the set it did not change --
 * measured, and it reported a full set after a successful shed.
 */
static int read_thread_status(char *out, size_t out_size)
{
	FILE *file = fopen("/proc/thread-self/status", "re");
	size_t filled;

	if (!file) {
		return 0;
	}
	filled = fread(out, 1, out_size - 1, file);
	(void)fclose(file);
	out[filled] = '\0';
	return filled > 0;
}

int ncfg_privilege_held_capabilities(uint64_t *effective, uint64_t *permitted, uint64_t *inheritable)
{
	char status[STATUS_TEXT_MAX];
	uint64_t eff = 0;
	uint64_t prm = 0;
	uint64_t inh = 0;

	if (!read_thread_status(status, sizeof(status))) {
		return 0;
	}
	if (!capability_field(status, "CapEff:", &eff) ||
	    !capability_field(status, "CapPrm:", &prm) ||
	    !capability_field(status, "CapInh:", &inh)) {
		return 0;
	}
	if (effective) {
		*effective = eff;
	}
	if (permitted) {
		*permitted = prm;
	}
	if (inheritable) {
		*inheritable = inh;
	}
	return 1;
}

int ncfg_privilege_effective_capabilities(uint64_t *effective)
{
	return ncfg_privilege_held_capabilities(effective, NULL, NULL);
}

int ncfg_privilege_is_root(void)
{
	uid_t real = (uid_t)-1;
	uid_t effective = (uid_t)-1;
	uid_t saved = (uid_t)-1;

	if (getresuid(&real, &effective, &saved) != 0) {
		/* Unknowable is treated as root, because the caller uses this to
		 * decide whether to drop and the safe answer to "am I
		 * privileged" is yes. */
		return 1;
	}
	return real == 0 || effective == 0 || saved == 0;
}

uid_t ncfg_privilege_unprivileged_id(void)
{
	FILE *file = fopen("/proc/sys/kernel/overflowuid", "re");
	char text[32];
	unsigned long value;
	char *end;

	if (!file) {
		return 65534;
	}
	if (!fgets(text, sizeof(text), file)) {
		(void)fclose(file);
		return 65534;
	}
	(void)fclose(file);
	errno = 0;
	value = strtoul(text, &end, 10);
	if (end == text || errno != 0 || value == 0 || value > 0xffffffffUL) {
		return 65534;
	}
	return (uid_t)value;
}

const char *ncfg_shed_describe(ncfg_shed_t reached)
{
	if (reached == NCFG_SHED_CAPABILITIES_ONLY) {
		return "no capabilities, still uid 0: no unprivileged id to become";
	}
	return "no capabilities and not root";
}

int ncfg_privilege_shed(ncfg_shed_t *reached, char *err, size_t err_size)
{
	struct cap_header header;
	struct cap_data data[2];
	ncfg_shed_t got = NCFG_SHED_FULLY;
	uint64_t effective = 0;
	uint64_t permitted = 0;
	uint64_t inheritable = 0;
	int capability;

	/* 1. Nothing after this point can be undone by executing something with
	 *    a setuid bit. First, so that the steps below need not be ordered
	 *    against that hazard as well as against each other. */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		ncfg_error_set(err, err_size, "cannot set no_new_privs: %s", strerror(errno));
		return 0;
	}

	/* 2. Ambient capabilities survive `execve`, which is exactly why
	 *    netcfgd's unit grants three of them and exactly why a child that has
	 *    just been `exec`ed still holds them. `EINVAL` is a kernel with no
	 *    ambient set, which is a kernel with nothing to clear. */
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 && errno != EINVAL) {
		ncfg_error_set(err, err_size, "cannot clear the ambient set: %s", strerror(errno));
		return 0;
	}

	/* 3. **Before the capabilities, because it needs two of them.** Clearing
	 *    the supplementary groups and setting the gid want `CAP_SETGID`, and
	 *    the uid wants `CAP_SETUID` -- both of which the bounding-set loop
	 *    below is about to make unavailable. netcfgd's unit grants both, for
	 *    dhcpcd's privsep, so they are there to be spent. */
	if (ncfg_privilege_is_root()) {
		uid_t id = ncfg_privilege_unprivileged_id();

		if (!ncfg_process_become(id, (gid_t)id, NULL, 0)) {
			/* **There is no id to become, and that is a real place to
			 * be.** A user namespace with one mapping -- `unshare -r`,
			 * and every rootless container -- maps uid 0 and nothing
			 * else, so 65534 does not exist to move to and the kernel
			 * refuses. Being uid 0 there is not being the machine's
			 * root: it is a mapped id with no authority outside the
			 * namespace, so capabilities-only is the whole of what
			 * privilege there was.
			 *
			 * Reported rather than swallowed. A caller that needs the
			 * stronger answer can insist on it; the portal probe does
			 * not, because the weaker one is already everything that
			 * namespace had to give. */
			got = NCFG_SHED_CAPABILITIES_ONLY;
		}
	}

	/* 4a. The ceiling: once a capability leaves the bounding set, no
	 *     `execve` in this process or any descendant can bring it back.
	 *
	 *     **Dropping from the bounding set needs `CAP_SETPCAP`, and the
	 *     caller usually does not have it.** netcfgd's own unit lists six
	 *     capabilities and that is not one of them, so a first version of
	 *     this returned `EPERM` here and the helper refused to run -- on
	 *     precisely the packaged install it was written for. `EPERM` is
	 *     tolerated because `NO_NEW_PRIVS` is already set, which is what a
	 *     full bounding set would otherwise be a route around, and because
	 *     the *outcome* is verified below rather than each step trusted.
	 *     `EINVAL` is the ceiling being generous about capability numbers
	 *     this kernel does not have. */
	for (capability = 0; capability <= CAPABILITY_CEILING; capability++) {
		if (prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) != 0 &&
		    errno != EINVAL && errno != EPERM) {
			ncfg_error_set(err, err_size, "cannot drop capability %d from the bounding set: %s",
			    capability, strerror(errno));
			return 0;
		}
	}

	/* 4b. Effective, permitted and inheritable, zeroed in one call. Doing
	 *     this before the bounding set would leave the bounding set full
	 *     with nothing permitted, which a setuid binary could climb back
	 *     through. */
	header.version = CAPABILITY_VERSION_3;
	/* Zero is "this thread", which is the only one this is ever called for:
	 * it runs in a freshly `exec`ed child before anything spawns. */
	header.pid = 0;
	memset(data, 0, sizeof(data));
	if (syscall(SYS_capset, &header, data) != 0) {
		ncfg_error_set(err, err_size, "cannot empty the capability sets: %s", strerror(errno));
		return 0;
	}

	/* **The outcome, not the steps.** Two of the calls above are allowed to
	 * fail on a machine that had nothing to give up, so what the caller needs
	 * promised is the end state: this thread holds nothing effective, nothing
	 * permitted, and can inherit nothing. Anything else and the caller must
	 * not go on -- which is the difference between a guard and a gesture. */
	if (!ncfg_privilege_held_capabilities(&effective, &permitted, &inheritable)) {
		ncfg_error_set(err, err_size,
		    "/proc is not mounted, so what this thread holds cannot be confirmed");
		return 0;
	}
	if (effective != 0 || permitted != 0 || inheritable != 0) {
		ncfg_error_set(err, err_size,
		    "capabilities survived: effective %llx, permitted %llx, inheritable %llx",
		    (unsigned long long)effective, (unsigned long long)permitted,
		    (unsigned long long)inheritable);
		return 0;
	}
	if (got == NCFG_SHED_FULLY && ncfg_privilege_is_root()) {
		ncfg_error_set(err, err_size, "still uid 0 after a drop that reported success");
		return 0;
	}
	if (reached) {
		*reached = got;
	}
	return 1;
}

void ncfg_privilege_die_after(unsigned int seconds)
{
	(void)alarm(seconds);
}
