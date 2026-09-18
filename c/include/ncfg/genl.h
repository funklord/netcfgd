/*
 * genl.h -- generic netlink: asking the controller what a family's id is.
 *
 * WHY THIS MODULE EXISTS
 *   rtnetlink's message types are compiled into the kernel headers, so
 *   `wire.h` can send an `RTM_NEWLINK` with a number that was fixed years
 *   ago. Generic netlink has no such numbers: a family registers at runtime,
 *   is given whichever id was free at the time, and a client has to ask the
 *   controller what that id is before it can send the family anything. The id
 *   is not stable across a reboot, not stable across a module unload and
 *   reload, and caching it on disk would be a defect rather than an
 *   optimisation.
 *
 *   That indirection is the whole cost decision 0016 identified for `nl80211`
 *   and it is the same cost for `wireguard`. Paying it once, here, is the
 *   point of the module.
 *
 * BYTES IN, STRUCTURES OUT -- THE SAME SPLIT AS wire.h
 *   Nothing here opens a socket. A caller sends what `ncfg_genl_*_request`
 *   builds and hands the replies back to `ncfg_genl_family_parse`; the
 *   syscalls live next door in `sys/socket.c`, where there is no parsing. So
 *   the encoding and the reply handling -- which is the half that can be
 *   silently wrong -- is testable on a machine with no such family loaded.
 *
 * THE NUMBERS ARE THE KERNEL'S
 *   `GENL_ID_CTRL`, `CTRL_CMD_GETFAMILY`, `CTRL_ATTR_*` and `GENL_NAMSIZ`
 *   come from <linux/genetlink.h>. The Rust spells them out because `libc`
 *   exports almost none of them; a C port that copied the numbers across
 *   would be inventing a second place for them to be wrong, which is
 *   `wire.h`'s reasoning applied to the family next door.
 */
#ifndef NCFG_GENL_H
#define NCFG_GENL_H

#include <stddef.h>
#include <stdint.h>

#include <linux/genetlink.h>

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/wire.h"

/*
 * How long a `genlmsghdr` is on the wire.
 *
 * Four bytes -- a command, a version and two the kernel ignores -- and small
 * enough that it could be written out at every call site. It is a type
 * instead because forgetting it produces a message whose attributes start
 * four bytes early, and the kernel's refusal names neither the command nor
 * the field. Checked against the kernel's own `GENL_HDRLEN` in genl.c.
 */
#define NCFG_GENL_HDR_LEN 4u

/*
 * `GENL_NAMSIZ`, the terminator included.
 *
 * A longer name cannot name a family that exists, and the kernel answers
 * `EINVAL` for the length rather than `ENOENT` for the lookup -- so a typo in
 * a long name reports as "netcfgd sent a broken request" unless the length is
 * checked before the request goes out. It is checked in
 * `ncfg_genl_getfamily_request`.
 */
#define NCFG_GENL_NAME_MAX GENL_NAMSIZ

/* The `genlmsghdr` that sits between the netlink header and the attributes. */
typedef struct {
	/* The family-specific command. */
	uint8_t cmd;
	/* The family-specific interface version. */
	uint8_t version;
} ncfg_genl_header_t;

/* One multicast group a family publishes. */
typedef struct {
	/* What a caller knows the group by. */
	char     name[NCFG_GENL_NAME_MAX];
	/* Its runtime id, which is what a socket subscribes to. */
	uint32_t id;
} ncfg_genl_group_t;

/*
 * What the controller knows about a family.
 *
 * `groups` is allocated; `ncfg_genl_family_free` releases it, and freeing a
 * family that was never filled in is nothing.
 */
typedef struct {
	char               name[NCFG_GENL_NAME_MAX];
	/* The runtime message type to send to. */
	uint16_t           id;
	ncfg_genl_group_t *groups;
	size_t             group_count;
} ncfg_genl_family_t;

/* Append the encoded header. Failure is the buffer's, and it is sticky. */
void ncfg_genl_header_encode(const ncfg_genl_header_t *header, ncfg_buf_t *out);

/* Read one from the front of a message payload, or refuse a payload too
 * short to hold one. */
int ncfg_genl_header_decode(const void *bytes, size_t length, ncfg_genl_header_t *out,
    char *err, size_t err_size);

/*
 * The attribute area of a generic netlink payload, past its header.
 *
 * A payload with no room for the header is a refusal rather than an empty
 * area. The Rust returns an empty iterator for it, which reads downstream as
 * "the controller answered without a family id" -- an honest sentence about
 * the wrong thing. Divergence, and `wire.h`'s reasoning: truncation is a
 * refusal, never a partial answer.
 */
int ncfg_genl_payload_attrs(const void *payload, size_t length, ncfg_wire_attrs_t *out,
    char *err, size_t err_size);

/*
 * Build a controller `GETFAMILY` request for `name`.
 *
 * Refuses a name that cannot fit `GENL_NAMSIZ` before anything is sent, for
 * the reason `NCFG_GENL_NAME_MAX` gives.
 */
int ncfg_genl_getfamily_request(ncfg_buf_t *out, const char *name, uint32_t seq,
    char *err, size_t err_size);

/*
 * Build a request to a family whose id has already been resolved.
 *
 * `NLM_F_REQUEST` is set here rather than by the caller: every one of these is
 * a request, and a caller that forgot it would get a message the kernel drops
 * without answering -- a timeout rather than an error.
 */
int ncfg_genl_build_request(ncfg_buf_t *out, uint16_t family_id,
    const ncfg_genl_header_t *header, uint16_t flags, uint32_t seq,
    const ncfg_buf_t *attrs, char *err, size_t err_size);

/*
 * Pull a family out of one controller reply payload.
 *
 * `name` is what was asked for. Where the reply names a family itself, the two
 * must agree: a generic netlink socket that has subscribed to the controller's
 * `notify` group receives `NEWFAMILY` announcements about *other* families on
 * the same socket, and a parser that took the id out of whichever reply
 * arrived would resolve `wireguard` to whatever module loaded last. The Rust
 * takes the caller's word for it. Divergence, and the check is two lines.
 */
int ncfg_genl_family_parse(const char *name, const void *payload, size_t length,
    ncfg_genl_family_t *out, char *err, size_t err_size);

/* Release what a family holds, and leave it usable and empty. */
void ncfg_genl_family_free(ncfg_genl_family_t *family);

/* The id of a named multicast group, or a refusal naming the family. */
int ncfg_genl_family_group(const ncfg_genl_family_t *family, const char *name, uint32_t *out,
    char *err, size_t err_size);

/*
 * The sentence for a lookup the kernel refused, from the errno it refused
 * with.
 *
 * **Always returns 0**, so a caller writes `return ncfg_genl_lookup_failed(
 * name, errno, err, err_size);` and cannot accidentally report success. It is
 * the one call in this header that cannot succeed, and the convention is kept
 * rather than bent so that every failure path still ends in a `return 0` with
 * a sentence beside it.
 *
 * `ENOENT` is the ordinary answer for a module that is not loaded, and it is
 * worth telling from a protocol failure: an operator reading "no such family"
 * has no idea what to do, and one reading "the module providing it is probably
 * not loaded" runs `modprobe`.
 */
int ncfg_genl_lookup_failed(const char *name, int error_number, char *err, size_t err_size);

#endif /* NCFG_GENL_H */
