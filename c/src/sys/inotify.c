/*
 * inotify.c -- the descriptor, and the walk over what it returns.
 *
 * The syscalls are here and the parsing is safe arithmetic over bytes the
 * kernel wrote, which is the same split `socket.c` and `wire.c` have. The walk
 * carries the same two obligations as the netlink ones -- it terminates, and it
 * does not read past the end -- and watch.h says why they are the same two.
 */
#include "ncfg/watch.h"

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

/* The header this file skips past is the system's own length, not a second
 * opinion. */
_Static_assert(sizeof(struct inotify_event) == NCFG_INOTIFY_EVENT_HDR_LEN,
    "an inotify event header is sixteen bytes and this system's is not");

int ncfg_inotify_event_overflowed(const ncfg_inotify_event_t *event)
{
	return event && (event->mask & (uint32_t)IN_Q_OVERFLOW) != 0;
}

void ncfg_inotify_walk_start(ncfg_inotify_walk_t *walk, const void *bytes, size_t length)
{
	if (!walk) {
		return;
	}
	walk->rest = (const uint8_t *)bytes;
	walk->remaining = bytes ? length : 0;
}

ncfg_wire_step_t ncfg_inotify_walk_next(ncfg_inotify_walk_t *walk, ncfg_inotify_event_t *out,
    char *err, size_t err_size)
{
	uint32_t claimed = 0;
	int32_t  wd = 0;
	uint32_t mask = 0;
	size_t   total;

	if (!walk || !out) {
		ncfg_error_set(err, err_size, "walking inotify events needs somewhere to go");
		return NCFG_WIRE_BAD;
	}
	memset(out, 0, sizeof(*out));
	if (walk->remaining == 0) {
		return NCFG_WIRE_END;
	}
	if (walk->remaining < NCFG_INOTIFY_EVENT_HDR_LEN) {
		size_t left = walk->remaining;

		/* Exhausted, so a loop that ignores this still terminates. */
		walk->remaining = 0;
		ncfg_error_set(err, err_size,
		    "an inotify event is at least %u bytes and this one is %zu",
		    (unsigned)NCFG_INOTIFY_EVENT_HDR_LEN, left);
		return NCFG_WIRE_BAD;
	}
	/* Native order, by copying the host representation: these are the
	 * kernel's own integers written into a buffer, and a shift-based read
	 * would be right here and wrong on a big-endian machine that nothing
	 * would ever run this on to notice. */
	memcpy(&wd, walk->rest, sizeof(wd));
	memcpy(&mask, walk->rest + 4, sizeof(mask));
	/* Bytes 8 to 11 are the cookie, which pairs a `MOVED_FROM` with its
	 * `MOVED_TO`. Nothing here needs it: this watcher reports that something
	 * moved and the caller re-reads everything. */
	memcpy(&claimed, walk->rest + 12, sizeof(claimed));

	total = NCFG_INOTIFY_EVENT_HDR_LEN + (size_t)claimed;
	if (total < NCFG_INOTIFY_EVENT_HDR_LEN || total > walk->remaining) {
		walk->remaining = 0;
		ncfg_error_set(err, err_size,
		    "an inotify event claims %u bytes of name and there is not room for it",
		    (unsigned)claimed);
		return NCFG_WIRE_BAD;
	}

	out->wd = wd;
	out->mask = mask;
	if (claimed > 0) {
		const uint8_t *raw = walk->rest + NCFG_INOTIFY_EVENT_HDR_LEN;
		size_t         end = 0;

		/* The name is NUL-padded to an alignment boundary, so it ends at
		 * the first NUL rather than at `len` -- which is the padded
		 * length and not the string's. */
		while (end < (size_t)claimed && raw[end] != '\0') {
			end++;
		}
		if (end < sizeof(out->name)) {
			memcpy(out->name, raw, end);
			out->name[end] = '\0';
			out->has_name = 1;
		}
		/* A name that would not fit is absent rather than truncated: a
		 * truncated name is a name, just somebody else's -- and this one
		 * is used to decide which file changed. `NAME_MAX` says the
		 * kernel cannot produce one, so this is the unreachable arm
		 * being made harmless rather than a case being handled. */
	}
	walk->rest += total;
	walk->remaining -= total;
	return NCFG_WIRE_OK;
}

void ncfg_inotify_init(ncfg_inotify_t *inotify)
{
	if (!inotify) {
		return;
	}
	inotify->fd = -1;
}

int ncfg_inotify_open(ncfg_inotify_t *inotify, char *err, size_t err_size)
{
	int opened;

	if (!inotify) {
		ncfg_error_set(err, err_size, "an inotify descriptor needs somewhere to go");
		return 0;
	}
	ncfg_inotify_init(inotify);
	/* Non-blocking, so the read after a `poll` cannot park: a watcher that
	 * blocked in `read` would be a watcher whose timeout does not
	 * exist. Close-on-exec because netcfgd spawns children. */
	opened = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
	if (opened < 0) {
		ncfg_error_set(err, err_size, "cannot watch for configuration changes: %s%s",
		    strerror(errno),
		    errno == EMFILE ? "; fs.inotify.max_user_instances is exhausted" : "");
		return 0;
	}
	inotify->fd = opened;
	return 1;
}

void ncfg_inotify_close(ncfg_inotify_t *inotify)
{
	if (!inotify || inotify->fd < 0) {
		return;
	}
	(void)close(inotify->fd);
	inotify->fd = -1;
}

int ncfg_inotify_watch(const ncfg_inotify_t *inotify, const char *path, uint32_t mask,
    int *wd, char *err, size_t err_size)
{
	int taken;

	if (wd) {
		*wd = -1;
	}
	if (!inotify || inotify->fd < 0 || !path) {
		ncfg_error_set(err, err_size, "watching a directory needs an open descriptor");
		return 0;
	}
	taken = inotify_add_watch(inotify->fd, path, mask);
	if (taken < 0) {
		ncfg_error_set(err, err_size, "cannot watch %s: %s", path, strerror(errno));
		return 0;
	}
	if (wd) {
		*wd = taken;
	}
	return 1;
}

int ncfg_inotify_wait(const ncfg_inotify_t *inotify, int timeout_ms,
    ncfg_inotify_batch_t *out, char *err, size_t err_size)
{
	struct pollfd waiting;
	ssize_t       taken;
	int           ready;

	if (!out) {
		ncfg_error_set(err, err_size, "waiting for events needs somewhere to put them");
		return 0;
	}
	out->length = 0;
	if (!inotify || inotify->fd < 0) {
		ncfg_error_set(err, err_size, "waiting for events needs an open descriptor");
		return 0;
	}
	waiting.fd = inotify->fd;
	waiting.events = POLLIN;
	waiting.revents = 0;
	ready = poll(&waiting, 1, timeout_ms);
	if (ready < 0) {
		/* A signal during the wait is not a failure to watch. Reported
		 * as a timeout, which is what the caller's loop already handles
		 * -- and it cannot spin, because every one of them is a signal
		 * that really arrived. */
		if (errno == EINTR) {
			return 1;
		}
		ncfg_error_set(err, err_size, "waiting for configuration changes: %s",
		    strerror(errno));
		return 0;
	}
	if (ready == 0) {
		return 1;
	}
	taken = read(inotify->fd, out->bytes, sizeof(out->bytes));
	if (taken < 0) {
		/* Nothing there after all, or a signal: both are "no events",
		 * which is what a timeout is. */
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			return 1;
		}
		ncfg_error_set(err, err_size, "reading configuration changes: %s",
		    strerror(errno));
		return 0;
	}
	out->length = (size_t)taken;
	return 1;
}
