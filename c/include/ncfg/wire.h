/*
 * wire.h -- netlink framing: headers, attributes, and the payloads rtnetlink
 * uses.
 *
 * **Bytes in, structures out, and no socket anywhere.** Everything here takes
 * a pointer and a length that came off a socket -- which is to say, input this
 * process does not control -- and the whole point of the split is that the
 * part which handles hostile bytes does no I/O and holds no descriptor. The
 * syscalls live next door in `sys/socket.c`, where there is no parsing.
 *
 * Two properties every walk here must have, because a malformed message is the
 * expected case rather than the exceptional one:
 *
 *   * **It terminates.** A length field of zero must not produce an infinite
 *     loop. This is the classic netlink parser bug and there is a test for it.
 *   * **It does not read past the end.** Truncation is a refusal with a
 *     sentence, never a partial answer and never an index past the buffer.
 *     The Rust this replaces got the second half for free from slicing; C does
 *     not, so every read here is bounds-checked by hand and the tests run
 *     under ASan for the ones that are not.
 *
 * WHY A WALK DOES NOT USE THE 1-FOR-SUCCESS CONVENTION
 *   `base.h`'s two outcomes cannot say "there is nothing more", which is the
 *   one thing an iterator says most often, and folding it in with failure is
 *   how a caller ends up treating a truncated buffer as a finished one -- the
 *   exact confusion this module exists to refuse. So the two `_next` calls and
 *   `ncfg_wire_attrs_find` return `ncfg_wire_step_t`, and everything else in
 *   this header keeps the convention exactly.
 *
 * ENDIANNESS, WHICH IS TWO DIFFERENT ANSWERS IN ONE MESSAGE
 *   Netlink's own fields -- `nlmsg_len`, an attribute's length and type, and
 *   every integer *value* an attribute carries -- are in the **host's** byte
 *   order. The kernel writes its own representation and expects to read it
 *   back; there is no `ntohl` anywhere in this file and one would be a bug.
 *   The addresses inside the payloads -- `IFA_ADDRESS`, `RTA_GATEWAY`,
 *   `RTA_DST` -- are **network order**, which is to say they are byte strings
 *   and not integers at all, and they are copied rather than converted.
 *
 *   The way to get this wrong is to encode a native field by hand, low byte
 *   first: it is correct on x86 and silently wrong on any big-endian machine,
 *   where it will never be noticed because nothing here is tested there. So
 *   the native fields go through `memcpy` of the host representation, never
 *   through shifts, and `ncfg_wire_ip_t` holds wire bytes that are never
 *   swapped in either direction.
 */
#ifndef NCFG_WIRE_H
#define NCFG_WIRE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "ncfg/base.h"
#include "ncfg/buf.h"

/*
 * The message and attribute types come from the kernel's own headers above --
 * `RTM_NEWLINK`, `NLM_F_DUMP`, `IFLA_IFNAME`, `IFA_PROTO`, `RTA_TABLE`,
 * `NLA_F_NESTED`, and `RTM_NEWLINKPROP` and `IFLA_ALT_IFNAME` with them. The
 * Rust spells those out because `libc` exports almost none of them; a C port
 * that copied the numbers across would be inventing a second place for them to
 * be wrong. What follows is only what the kernel headers do not give us here.
 */

/*
 * `ALTIFNAMSIZ` from `linux/if.h`, written out rather than included.
 *
 * Eight times `IFNAMSIZ`, which is what makes a prefixed marker fit
 * comfortably where a second interface name would not. The header is not
 * included because `linux/if.h` and `net/if.h` redefine each other's `struct
 * ifreq` and `struct ifmap`, and a caller of this file is very likely to want
 * the second one -- so pulling in the first would decide that for them.
 */
#define NCFG_WIRE_ALT_IFNAME_MAX 128u

/*
 * The `rtm_protocol` value netcfgd stamps on routes it installs.
 *
 * Duplicated from the model rather than depended on, because this file must
 * stay free of anything but libc and the kernel. Decision 0002 fixes the value
 * at 110.
 */
#define NCFG_WIRE_RTPROT_NETCFGD 110u

/* Lengths of the four wire structures. Each is checked against the kernel's
 * own `sizeof` at compile time in wire.c, so these are a convenience and not a
 * second opinion. */
#define NCFG_WIRE_NLMSG_HDR_LEN 16u
#define NCFG_WIRE_RTATTR_HDR_LEN 4u
#define NCFG_WIRE_IFINFO_LEN 16u
#define NCFG_WIRE_IFADDR_LEN 8u
#define NCFG_WIRE_RTMSG_LEN 12u

/* "11:22:33:44:55:66" and its terminator. */
#define NCFG_WIRE_MAC_TEXT_MAX 18u
/* `INET6_ADDRSTRLEN`, including room for a scope suffix this never writes. */
#define NCFG_WIRE_IP_TEXT_MAX 46u

/* How far a walk got. See the header comment for why this is not 1-or-0. */
typedef enum {
	/* The buffer ended cleanly, on an attribute or message boundary. */
	NCFG_WIRE_END = 0,
	/* One message or attribute came out. */
	NCFG_WIRE_OK = 1,
	/* The bytes do not make sense; `err` says how. The walk is left
	 * exhausted, so a loop that ignores this still terminates. */
	NCFG_WIRE_BAD = -1
} ncfg_wire_step_t;

/* A netlink message header, `struct nlmsghdr` with names this port uses. */
typedef struct {
	/* Total message length including this header. */
	uint32_t len;
	/* Message type. */
	uint16_t kind;
	/* Flags. */
	uint16_t flags;
	/* Sequence number. */
	uint32_t seq;
	/* Sending port id. */
	uint32_t pid;
} ncfg_wire_header_t;

/* One message from a netlink buffer. The payload points into the caller's
 * bytes and does not outlive them. */
typedef struct {
	ncfg_wire_header_t header;
	/* Everything after the header, up to `header.len`. */
	const uint8_t     *payload;
	size_t             payload_length;
} ncfg_wire_message_t;

/* One attribute. The value points into the caller's bytes. */
typedef struct {
	/* Attribute type, with the nested and byte-order bits masked off. */
	uint16_t       kind;
	const uint8_t *value;
	size_t         length;
} ncfg_wire_attr_t;

/* A walk over a buffer of messages. Start it with `ncfg_wire_messages_start`
 * and treat the fields as private. */
typedef struct {
	const uint8_t *rest;
	size_t         remaining;
} ncfg_wire_messages_t;

/* A walk over an attribute area -- a message's tail, or a nest's value. */
typedef struct {
	const uint8_t *rest;
	size_t         remaining;
} ncfg_wire_attrs_t;

/*
 * An address exactly as the wire carries it: 4 or 16 bytes, network order.
 *
 * Not a `struct in_addr` or a `uint32_t`, because either invites somebody to
 * apply `ntohl` to it on the way past. `family` is `AF_INET` or `AF_INET6` and
 * says how many of `bytes` mean anything.
 */
typedef struct {
	int     family;
	uint8_t bytes[16];
} ncfg_wire_ip_t;

/* `struct ifinfomsg`. */
typedef struct {
	uint8_t  family;
	/* ARPHRD type. */
	uint16_t kind;
	/* Interface index. Signed, as the kernel declares it. */
	int32_t  index;
	uint32_t flags;
	/* Which flag bits this message changes. */
	uint32_t change;
} ncfg_wire_ifinfo_t;

/* `struct ifaddrmsg`. */
typedef struct {
	uint8_t  family;
	uint8_t  prefix_len;
	uint8_t  flags;
	uint8_t  scope;
	uint32_t index;
} ncfg_wire_ifaddr_t;

/* `struct rtmsg`. */
typedef struct {
	uint8_t  family;
	uint8_t  dst_len;
	uint8_t  src_len;
	uint8_t  tos;
	/* Table id, for tables below 256; above that it is in `RTA_TABLE`. */
	uint8_t  table;
	/* Routing protocol. netcfgd stamps `NCFG_WIRE_RTPROT_NETCFGD` here. */
	uint8_t  protocol;
	uint8_t  scope;
	/* Route type. */
	uint8_t  kind;
	uint32_t flags;
} ncfg_wire_rtmsg_t;

/*
 * Round up to the 4-byte boundary netlink aligns everything to.
 *
 * The caller has already bounded `length` by a buffer it holds; a length
 * within four of `SIZE_MAX` is returned unchanged rather than wrapping to
 * zero, which would turn "no room" into "no bytes needed".
 */
size_t ncfg_wire_align4(size_t length);

/* Decode a header, or refuse a buffer too short to hold one. */
int ncfg_wire_header_decode(const void *bytes, size_t length, ncfg_wire_header_t *out,
    char *err, size_t err_size);
/* Append the encoded header. Failure is the buffer's, and it is sticky. */
void ncfg_wire_header_encode(const ncfg_wire_header_t *header, ncfg_buf_t *out);

int ncfg_wire_ifinfo_decode(const void *bytes, size_t length, ncfg_wire_ifinfo_t *out,
    char *err, size_t err_size);
void ncfg_wire_ifinfo_encode(const ncfg_wire_ifinfo_t *info, ncfg_buf_t *out);

int ncfg_wire_ifaddr_decode(const void *bytes, size_t length, ncfg_wire_ifaddr_t *out,
    char *err, size_t err_size);
void ncfg_wire_ifaddr_encode(const ncfg_wire_ifaddr_t *addr, ncfg_buf_t *out);

int ncfg_wire_rtmsg_decode(const void *bytes, size_t length, ncfg_wire_rtmsg_t *out,
    char *err, size_t err_size);
void ncfg_wire_rtmsg_encode(const ncfg_wire_rtmsg_t *route, ncfg_buf_t *out);

/* Start walking a buffer that begins at a message header. */
void ncfg_wire_messages_start(ncfg_wire_messages_t *walk, const void *bytes, size_t length);
/* The next message, the end of the buffer, or a refusal. */
ncfg_wire_step_t ncfg_wire_messages_next(ncfg_wire_messages_t *walk, ncfg_wire_message_t *out,
    char *err, size_t err_size);

/*
 * The attribute area of a message whose family struct is `body_length` long.
 *
 * Refuses a payload too short for the struct it claims to carry, which is the
 * check that keeps a caller from walking attributes that begin past the end of
 * the message. The body is skipped aligned, as the kernel writes it.
 */
int ncfg_wire_message_attrs(const ncfg_wire_message_t *message, size_t body_length,
    ncfg_wire_attrs_t *out, char *err, size_t err_size);

/* Start walking an attribute area: a message tail, or a nest's value. */
void ncfg_wire_attrs_start(ncfg_wire_attrs_t *walk, const void *bytes, size_t length);
ncfg_wire_step_t ncfg_wire_attrs_next(ncfg_wire_attrs_t *walk, ncfg_wire_attr_t *out,
    char *err, size_t err_size);
/*
 * The first attribute of this type, from where `area` stands.
 *
 * `NCFG_WIRE_END` where the area is well-formed and has no such attribute,
 * which is a different thing from `NCFG_WIRE_BAD` and callers act differently
 * on it: a missing `IFA_PROTO` is a kernel older than 5.18, a malformed area
 * is a message to throw away.
 *
 * `area` is not consumed -- a caller may search the same one repeatedly, which
 * is what reading a link record is.
 */
ncfg_wire_step_t ncfg_wire_attrs_find(const ncfg_wire_attrs_t *area, uint16_t kind,
    ncfg_wire_attr_t *out, char *err, size_t err_size);

/*
 * Read an attribute's value.
 *
 * Each refuses a value of the wrong size rather than padding or truncating
 * one: netlink is not consistent about integer widths and the header gives no
 * hint -- `CTRL_ATTR_FAMILY_ID` is two bytes where everything around it is
 * four -- so reading one with the wrong accessor has to fail loudly, or it
 * returns a number that is merely wrong.
 */
int ncfg_wire_attr_u8(const ncfg_wire_attr_t *attr, uint8_t *out, char *err, size_t err_size);
int ncfg_wire_attr_u16(const ncfg_wire_attr_t *attr, uint16_t *out, char *err, size_t err_size);
int ncfg_wire_attr_u32(const ncfg_wire_attr_t *attr, uint32_t *out, char *err, size_t err_size);
/*
 * The value as a NUL-terminated string, refused where it does not fit.
 *
 * A name that would not fit the caller's buffer is a refusal and not a short
 * name, because a truncated interface name is a name -- just somebody else's.
 */
int ncfg_wire_attr_string(const ncfg_wire_attr_t *attr, char *out, size_t out_size,
    char *err, size_t err_size);
/* The value as a MAC address in the usual colon notation. `out_size` must be
 * at least `NCFG_WIRE_MAC_TEXT_MAX`. */
int ncfg_wire_attr_mac(const ncfg_wire_attr_t *attr, char *out, size_t out_size,
    char *err, size_t err_size);
/* The value as an address, IPv4 or IPv6 decided by its length. */
int ncfg_wire_attr_ip(const ncfg_wire_attr_t *attr, ncfg_wire_ip_t *out,
    char *err, size_t err_size);

/* Text to wire bytes and back, the only two places an address changes form.
 * Neither swaps anything: presentation form is already big-endian. */
int ncfg_wire_ip_parse(const char *text, ncfg_wire_ip_t *out, char *err, size_t err_size);
int ncfg_wire_ip_text(const ncfg_wire_ip_t *ip, char *out, size_t out_size,
    char *err, size_t err_size);

/*
 * Append an attribute, padded to alignment.
 *
 * These are `void` for the reason `ncfg_buf_add` is: a caller writes a dozen
 * of them and checks `ncfg_buf_failed` once. A value too long for the 16-bit
 * length field fails the buffer rather than being appended short -- see the
 * note in wire.c, which is a defect the Rust still has.
 */
void ncfg_wire_attr_put(ncfg_buf_t *out, uint16_t kind, const void *value, size_t length);
void ncfg_wire_attr_put_u8(ncfg_buf_t *out, uint16_t kind, uint8_t value);
void ncfg_wire_attr_put_u32(ncfg_buf_t *out, uint16_t kind, uint32_t value);
/* A NUL-terminated string attribute; the NUL is part of the value, as the
 * kernel expects. */
void ncfg_wire_attr_put_str(ncfg_buf_t *out, uint16_t kind, const char *value);
void ncfg_wire_attr_put_ip(ncfg_buf_t *out, uint16_t kind, const ncfg_wire_ip_t *value);
/*
 * A nest, with `NLA_F_NESTED` set.
 *
 * Old rtnetlink parsers ignore the flag; the strict ones reject a nest without
 * it with `EINVAL`. `IFLA_LINKINFO` on `RTM_NEWLINK` goes through the lenient
 * path and works either way, which is why netcfgd sent nests unflagged for a
 * long time and only met this on `RTM_NEWLINKPROP` -- a newer message type,
 * parsed strictly. The error says nothing about nesting, so this sets the flag
 * on every nest rather than discovering it per message type.
 */
void ncfg_wire_attr_put_nested(ncfg_buf_t *out, uint16_t kind, const ncfg_buf_t *nest);

/*
 * Assemble a complete request: header, family struct, attributes.
 *
 * `body` and `attrs` may be NULL for none. A buffer that has already failed is
 * refused here rather than encoded as the empty string it hands out, because a
 * request whose attributes silently went missing is one the kernel will act
 * on.
 */
int ncfg_wire_build_request(ncfg_buf_t *out, uint16_t kind, uint16_t flags, uint32_t seq,
    const ncfg_buf_t *body, const ncfg_buf_t *attrs, char *err, size_t err_size);

/*
 * The error code in an `NLMSG_ERROR` payload, negated into a positive errno.
 *
 * Zero means this was an acknowledgement rather than a failure, which is
 * netlink's least obvious convention.
 *
 * A payload with no readable code is a refusal, and that includes `INT32_MIN`
 * -- the one value with no positive counterpart. In Rust plain `-raw` panicked
 * on it under overflow checks and wrapped back to `INT32_MIN` without them, so
 * the daemon either died or reported a nonsense errno depending on the profile
 * it was built with; in C the same expression is signed overflow, which is
 * undefined behaviour and which UBSan traps. Found by `cargo fuzz` on the
 * `netlink_wire` target, from a nine-byte input. No errno is anywhere near
 * that magnitude, so a payload carrying it is malformed.
 */
int ncfg_wire_error_code(const void *payload, size_t length, int32_t *out,
    char *err, size_t err_size);

#endif /* NCFG_WIRE_H */
