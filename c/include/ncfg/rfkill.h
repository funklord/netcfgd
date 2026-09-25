/*
 * rfkill.h -- `/dev/rfkill`: the switch being flipped, as it happens.
 *
 * WHY A SECOND SOURCE OF THE SAME FACT
 *   0062 made netcfgd *report* a blocked radio, read out of `/sys` during an
 *   observation. What it could not do is notice one being flipped: an
 *   observation runs on a netlink event or on the loop's five-second backstop,
 *   and a kill switch produces neither reliably -- blocking a radio usually
 *   takes the interface down and so shows up on netlink, but unblocking one
 *   produces nothing until something else happens.
 *
 *   This is the kernel's own notification for it. Opening the device queues
 *   one `ADD` per switch that already exists, so a reader learns the current
 *   state without asking `/sys` for it, and then gets a record per change.
 *
 * READ-ONLY, ALWAYS
 *   The same device accepts writes that block or unblock every radio on the
 *   machine, and netcfgd does not do that -- 0062 decided that a switch an
 *   operator flipped is a decision netcfgd reports rather than overrules.
 *   Nothing here opens the device for writing, which makes that a property of
 *   the code rather than of the intent: `ncfg_rfkill_open` passes `O_RDONLY`
 *   and there is no call that writes.
 *
 * ONE READ IS ONE RECORD, AND THE SURPLUS IS IGNORED
 *   The kernel dequeues a single event per read and copies `min(what you asked
 *   for, the struct it has)`, so a generous buffer gets one whole record and
 *   never two. The Rust's first version assumed a byte stream and carried a
 *   reassembly buffer: on a kernel writing the longer `rfkill_event_ext` that
 *   buffer would have kept the extra byte and shifted every following record by
 *   one -- a fault that appears only on kernels newer than the one it was
 *   written against. So `ncfg_rfkill_parse` takes a length, reads the eight
 *   bytes every version has, and ignores whatever follows them.
 *
 * THE NUMBERS ARE THE KERNEL'S
 *   `RFKILL_TYPE_*` and `RFKILL_OP_*` come from <linux/rfkill.h>, for the
 *   reason wire.h gives: a port that copied them across would be inventing a
 *   second place for them to be wrong.
 */
#ifndef NCFG_RFKILL_H
#define NCFG_RFKILL_H

#include <stddef.h>
#include <stdint.h>

#include <linux/rfkill.h>

#include "ncfg/base.h"

/*
 * The kernel's `struct rfkill_event`, which is packed and eight bytes.
 *
 * Newer kernels have `rfkill_event_ext`, which appends `hard_block_reasons`.
 * The kernel's own rule for userspace is to read at least the eight it knows
 * and ignore anything past them, so that a reader built today keeps working on
 * a kernel that grows the record -- which is what this does. Checked against
 * `RFKILL_EVENT_SIZE_V1` in rfkill.c.
 */
#define NCFG_RFKILL_RECORD 8u

/* Where the kernel publishes it. A parameter everywhere below, so that a test
 * can be handed something else, but this is the only path netcfgd uses. */
#define NCFG_RFKILL_DEVICE "/dev/rfkill"

/*
 * What a test puts in front of it.
 *
 * **The name only. Nothing in this module reads it**, which is the rule the
 * line above states: every path here is a parameter. The daemon reads this
 * when it builds the set of descriptors it watches, exactly as it reads
 * `NCFG_WPA_SUPPLICANT`.
 *
 * **Overridable for the reason the supplicant's directory is**, and the Rust's
 * own comment says it: a network namespace is not a device namespace, so
 * `unshare -rn` is no protection and a test that could not move this would be
 * reading -- and a test that wrote would be flipping -- the switches on the
 * machine it runs on.
 */
#define NCFG_RFKILL_DEVICE_ENV "NCFG_RFKILL_DEV"

/* What happened to a switch. */
typedef struct {
	/* The kernel's index for this switch. */
	uint32_t index;
	/* `RFKILL_TYPE_*`: which kind of radio it governs. */
	uint8_t  kind;
	/* `RFKILL_OP_*`: added, removed, or changed. */
	uint8_t  op;
	/* Blocked in software, which is what `rfkill block` sets. */
	int      soft;
	/* Blocked by a physical switch, which software cannot clear. */
	int      hard;
} ncfg_rfkill_event_t;

/* An open reader. Treat the field as private; `fd` is -1 when nothing is
 * open. */
typedef struct {
	int fd;
} ncfg_rfkill_t;

/* Leave a reader closed and unopened. `ncfg_rfkill_close` on one that has been
 * through this is nothing, which is what makes a failure path cheap. */
void ncfg_rfkill_init(ncfg_rfkill_t *rfkill);

/*
 * Open the device.
 *
 * Opening queues one `ADD` per switch that already exists, so the first few
 * reads describe the machine as it stands before anything is flipped. Measured
 * on a laptop with four switches: four `ADD` records, then nothing until
 * something changes.
 *
 * A machine with no radio has no `/dev/rfkill`, which is `ENOENT` -- a refusal
 * here, and not a failure worth propagating past the caller that knows whether
 * it wanted one. The sentence says as much.
 */
int ncfg_rfkill_open(ncfg_rfkill_t *rfkill, const char *path, char *err, size_t err_size);

/* Close it. Nothing where it was never opened. */
void ncfg_rfkill_close(ncfg_rfkill_t *rfkill);

/*
 * The descriptor, for a caller that multiplexes several of them.
 *
 * -1 where nothing is open. `ncfg_rfkill_next` blocks, which is right for a
 * reader whose whole job is this device and wrong for a daemon watching five
 * things at once -- so the loop in `src/main/` waits on this integer with the
 * others and calls `ncfg_rfkill_next` only once `poll` has said a record is
 * there, which is the one arrangement in which that call cannot block.
 */
int ncfg_rfkill_descriptor(const ncfg_rfkill_t *rfkill);

/*
 * The next event, blocking until one arrives.
 *
 * `*got` is 1 where an event came out and 0 at end of file, which for this
 * device means it went away. The return value is the usual 1-or-0: a real
 * failure. A read shorter than a record is discarded and the read is made
 * again rather than the bytes being kept -- there is nothing to join them to.
 */
int ncfg_rfkill_next(ncfg_rfkill_t *rfkill, ncfg_rfkill_event_t *out, int *got,
    char *err, size_t err_size);

/*
 * One record's bytes as an event.
 *
 * `length` may be longer than a record and anything past the first
 * `NCFG_RFKILL_RECORD` bytes is ignored; shorter is a refusal.
 *
 * Little-endian for the index because the kernel writes it in host order and
 * every machine this runs on is little-endian -- read through `memcpy` of the
 * host representation rather than through shifts, so that a big-endian port
 * gets the kernel's answer rather than a swapped one. wire.h has the long
 * version of this note.
 */
int ncfg_rfkill_parse(const void *record, size_t length, ncfg_rfkill_event_t *out,
    char *err, size_t err_size);

#endif /* NCFG_RFKILL_H */
