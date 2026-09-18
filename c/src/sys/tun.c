/*
 * tun.c -- the four ioctls that make a persistent tun or tap.
 *
 * The whole of the ordering argument is in tun.h and in decision 0254. What is
 * here is the two halves that argument needs kept apart: `ncfg_tun_plan`, which
 * decides what to do and touches nothing, and `ncfg_tun_create`, which opens
 * one descriptor and performs the plan without deciding anything.
 *
 * That split is the same one `wire.c` and `socket.c` have, and it is what lets
 * the order be asserted on a machine that must not have a device made on it.
 */
#include "ncfg/tun.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/if_tun.h>
#include <net/if.h>

/*
 * The request this module builds is the libc's `struct ifreq`, and these are
 * what keep that claim honest. `net/if.h` is included for exactly this -- not
 * for the type, which tun.h declares for the reason given there.
 */
_Static_assert(sizeof(struct ifreq) == NCFG_TUN_REQUEST_LEN,
    "a tun request is forty bytes and this libc's ifreq is not");
_Static_assert(sizeof(ncfg_tun_request_t) == NCFG_TUN_REQUEST_LEN,
    "and the one built here is not forty bytes");
_Static_assert(offsetof(ncfg_tun_request_t, flags) == NCFG_TUN_NAME_MAX,
    "the flags must sit where the kernel reads ifr_flags");
_Static_assert(offsetof(struct ifreq, ifr_flags) == NCFG_TUN_NAME_MAX,
    "and that is not where this libc keeps them");
_Static_assert(IFNAMSIZ == NCFG_TUN_NAME_MAX,
    "an interface name is sixteen bytes and this libc says otherwise");

const char *ncfg_tun_mode_name(ncfg_tun_mode_t mode)
{
	switch (mode) {
	case NCFG_TUN_MODE_TUN:
		return "tun";
	case NCFG_TUN_MODE_TAP:
		return "tap";
	}
	return NULL;
}

int ncfg_tun_mode_from_name(const char *text, ncfg_tun_mode_t *out)
{
	if (!text || !out) {
		return 0;
	}
	if (strcmp(text, "tun") == 0) {
		*out = NCFG_TUN_MODE_TUN;
		return 1;
	}
	if (strcmp(text, "tap") == 0) {
		*out = NCFG_TUN_MODE_TAP;
		return 1;
	}
	return 0;
}

int16_t ncfg_tun_flags(ncfg_tun_mode_t mode)
{
	switch (mode) {
	case NCFG_TUN_MODE_TUN:
		return (int16_t)(IFF_TUN | IFF_NO_PI);
	case NCFG_TUN_MODE_TAP:
		return (int16_t)(IFF_TAP | IFF_NO_PI);
	}
	return 0;
}

int ncfg_tun_request(const ncfg_tun_spec_t *spec, ncfg_tun_request_t *out,
    char *err, size_t err_size)
{
	size_t length;

	if (!out) {
		ncfg_error_set(err, err_size, "a tun request needs somewhere to go");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!spec || !spec->name) {
		ncfg_error_set(err, err_size, "making a tun device needs a name");
		return 0;
	}
	length = strlen(spec->name);
	/* `>=`, not `>`: the kernel's field is sixteen bytes *including* the
	 * terminator, and a name that filled it would come back as whatever the
	 * next field happens to hold. */
	if (length == 0 || length >= NCFG_TUN_NAME_MAX) {
		ncfg_error_set(err, err_size,
		    "`%s` is not a name the kernel would take for a link", spec->name);
		return 0;
	}
	out->flags = ncfg_tun_flags(spec->mode);
	if (out->flags == 0) {
		ncfg_error_set(err, err_size, "a tun device is either a tun or a tap");
		return 0;
	}
	/* Into a zeroed array, so the name is NUL-terminated by construction
	 * rather than by a terminator somebody remembered to write. */
	memcpy(out->name, spec->name, length);
	return 1;
}

int ncfg_tun_plan(const ncfg_tun_spec_t *spec, ncfg_tun_step_t *out, size_t max,
    size_t *count, char *err, size_t err_size)
{
	ncfg_tun_request_t request;
	size_t             at = 0;

	if (count) {
		*count = 0;
	}
	if (!out || !count || max < NCFG_TUN_STEPS_MAX) {
		ncfg_error_set(err, err_size, "a tun plan needs room for %u steps",
		    (unsigned)NCFG_TUN_STEPS_MAX);
		return 0;
	}
	memset(out, 0, max * sizeof(*out));
	/* Built and thrown away: what is wanted here is the refusal for a name
	 * the kernel would not take, before a descriptor is opened for it. */
	if (!ncfg_tun_request(spec, &request, err, err_size)) {
		return 0;
	}

	out[at].what = "TUNSETIFF";
	out[at].request = TUNSETIFF;
	out[at].is_request_struct = 1;
	at++;

	/* Before persistence, so a device that cannot be given its owner is not
	 * left behind for somebody to find: closing the descriptor at that point
	 * removes it. See tun.h. */
	if (spec->has_owner) {
		out[at].what = "TUNSETOWNER";
		out[at].request = TUNSETOWNER;
		out[at].value = (unsigned long)spec->owner;
		at++;
	}
	if (spec->has_group) {
		out[at].what = "TUNSETGROUP";
		out[at].request = TUNSETGROUP;
		out[at].value = (unsigned long)spec->group;
		at++;
	}

	/* **Last, and the reason the device survives this call.** A tun device
	 * exists only while something holds its descriptor; without this the
	 * close would delete what was just made, and the call would report
	 * success over a machine with no such link. */
	out[at].what = "TUNSETPERSIST";
	out[at].request = TUNSETPERSIST;
	out[at].value = 1u;
	at++;

	*count = at;
	return 1;
}

int ncfg_tun_create(const char *clone_device, const ncfg_tun_spec_t *spec,
    char *err, size_t err_size)
{
	ncfg_tun_request_t request;
	ncfg_tun_step_t    steps[NCFG_TUN_STEPS_MAX];
	size_t             count = 0;
	size_t             at;
	int                fd;

	if (!clone_device) {
		ncfg_error_set(err, err_size, "making a tun device needs the clone device");
		return 0;
	}
	/* The name is refused here, before anything is opened: a refusal that
	 * arrives after the open is a refusal that had a descriptor to leak. */
	if (!ncfg_tun_request(spec, &request, err, err_size)) {
		return 0;
	}
	if (!ncfg_tun_plan(spec, steps, NCFG_TUN_STEPS_MAX, &count, err, err_size)) {
		return 0;
	}

	/* Read and write, because `TUNSETIFF` wants a writable descriptor, and
	 * `O_CLOEXEC` because netcfgd spawns children and a descriptor on this
	 * device outliving the call would keep an unpersisted device alive in
	 * something that knows nothing about it. */
	fd = open(clone_device, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		ncfg_error_set(err, err_size, "cannot open %s: %s%s", clone_device,
		    strerror(errno),
		    errno == ENOENT ? "; is the `tun` module loaded?" : "");
		return 0;
	}
	for (at = 0; at < count; at++) {
		int done;

		if (steps[at].is_request_struct) {
			done = ioctl(fd, steps[at].request, &request);
		} else {
			done = ioctl(fd, steps[at].request, steps[at].value);
		}
		if (done < 0) {
			int failed = errno;

			/* Closed before the message is built, and this is the
			 * close that removes a half-made device: nothing has
			 * persisted yet unless the last step succeeded, and the
			 * last step is the only one after which this loop does
			 * not run again. */
			(void)close(fd);
			ncfg_error_set(err, err_size, "%s for %s: %s", steps[at].what,
			    spec->name, strerror(failed));
			return 0;
		}
	}
	(void)close(fd);
	return 1;
}
