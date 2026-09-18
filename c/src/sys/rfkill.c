/*
 * rfkill.c -- reading the kernel's kill-switch events.
 *
 * A file with a fixed record format, which is `read` plus arithmetic. It lives
 * beside the netlink code because it is a kernel interface, not because it
 * needs anything special: there is no ioctl here and nothing that writes.
 *
 * The parse is split from the read for the reason the whole `sys` layer is
 * split that way -- `ncfg_rfkill_parse` takes bytes a caller already has, so
 * the record format is testable with no device, no radio and no privilege, and
 * the only thing left in the reading is the loop.
 */
#include "ncfg/rfkill.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

/* The length this module reads is the kernel's own, not a second opinion. */
_Static_assert(RFKILL_EVENT_SIZE_V1 == NCFG_RFKILL_RECORD,
    "a rfkill record is eight bytes and this kernel's is not");

/*
 * Bigger than any record the kernel has, so the whole of one arrives whatever
 * version it is and the surplus is ignored. See rfkill.h: the surplus is the
 * defect this shape exists to refuse.
 */
#define RFKILL_BUFFER 64u

void ncfg_rfkill_init(ncfg_rfkill_t *rfkill)
{
	if (!rfkill) {
		return;
	}
	rfkill->fd = -1;
}

int ncfg_rfkill_open(ncfg_rfkill_t *rfkill, const char *path, char *err, size_t err_size)
{
	int opened;

	if (!rfkill || !path) {
		ncfg_error_set(err, err_size, "opening a kill switch reader needs a path");
		return 0;
	}
	ncfg_rfkill_init(rfkill);
	/* Read-only, and `O_CLOEXEC` because this descriptor must not reach a
	 * hook or a supplicant: netcfgd spawns children, and a descriptor on
	 * this device is a descriptor that can block every radio. */
	opened = open(path, O_RDONLY | O_CLOEXEC);
	if (opened < 0) {
		ncfg_error_set(err, err_size, "cannot open %s: %s%s", path, strerror(errno),
		    errno == ENOENT ? "; this machine has no radio" : "");
		return 0;
	}
	rfkill->fd = opened;
	return 1;
}

void ncfg_rfkill_close(ncfg_rfkill_t *rfkill)
{
	if (!rfkill || rfkill->fd < 0) {
		return;
	}
	(void)close(rfkill->fd);
	rfkill->fd = -1;
}

int ncfg_rfkill_descriptor(const ncfg_rfkill_t *rfkill)
{
	return rfkill ? rfkill->fd : -1;
}

int ncfg_rfkill_parse(const void *record, size_t length, ncfg_rfkill_event_t *out,
    char *err, size_t err_size)
{
	const uint8_t *bytes = (const uint8_t *)record;
	uint32_t       index = 0;

	if (!out) {
		ncfg_error_set(err, err_size, "a kill switch event needs somewhere to go");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!bytes || length < NCFG_RFKILL_RECORD) {
		ncfg_error_set(err, err_size,
		    "a kill switch record is %u bytes and this one is %zu",
		    (unsigned)NCFG_RFKILL_RECORD, bytes ? length : (size_t)0);
		return 0;
	}
	/* Host order, by copying the host representation rather than by
	 * shifting bytes into place: the shift version is correct on this
	 * machine and silently wrong on a big-endian one, where nothing here
	 * would ever be run to notice. */
	memcpy(&index, bytes, sizeof(index));
	out->index = index;
	out->kind = bytes[4];
	out->op = bytes[5];
	out->soft = bytes[6] != 0;
	out->hard = bytes[7] != 0;
	return 1;
}

int ncfg_rfkill_next(ncfg_rfkill_t *rfkill, ncfg_rfkill_event_t *out, int *got,
    char *err, size_t err_size)
{
	uint8_t buffer[RFKILL_BUFFER];

	if (got) {
		*got = 0;
	}
	if (!rfkill || rfkill->fd < 0 || !out || !got) {
		ncfg_error_set(err, err_size, "reading a kill switch event needs an open device");
		return 0;
	}
	for (;;) {
		ssize_t taken = read(rfkill->fd, buffer, sizeof(buffer));

		if (taken < 0) {
			/* A signal arriving mid-read is not the device going
			 * away. Retried here rather than reported, because
			 * this call blocks and a caller cannot tell the two
			 * apart from the outside -- netlink's `EINTR` note in
			 * netlink.h is the same case and cost fifty-two
			 * minutes of a machine's network configuration. */
			if (errno == EINTR) {
				continue;
			}
			ncfg_error_set(err, err_size, "reading a kill switch event: %s",
			    strerror(errno));
			return 0;
		}
		if (taken == 0) {
			/* End of file on this device means it went away. Not a
			 * failure, and the caller stops asking. */
			return 1;
		}
		if ((size_t)taken >= NCFG_RFKILL_RECORD) {
			if (!ncfg_rfkill_parse(buffer, (size_t)taken, out, err, err_size)) {
				return 0;
			}
			*got = 1;
			return 1;
		}
		/* Shorter than the eight bytes every version of this record
		 * has. Nothing sensible to do with it and nothing to join it
		 * to, so it is dropped rather than buffered into the next
		 * one -- which is the reassembly defect rfkill.h describes. */
	}
}
