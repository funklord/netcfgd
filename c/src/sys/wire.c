/*
 * wire.c -- the framing described in wire.h.
 *
 * Nothing in this file opens, reads or writes a descriptor. Every function
 * takes bytes the caller already has, and the ones that decode treat those
 * bytes as hostile, because a message that arrived from the kernel arrived
 * through a socket anything on this machine with `CAP_NET_ADMIN` can also
 * write to.
 */
#include "ncfg/wire.h"

#include <arpa/inet.h>
#include <string.h>

/*
 * The lengths wire.h publishes are the kernel's, and here is the proof.
 *
 * A port that wrote `16` because the Rust wrote `16` would carry a number
 * nobody had checked against the machine it runs on. These fail the build
 * instead, which is the only kind of check that cannot be skipped.
 */
_Static_assert(sizeof(struct nlmsghdr) == NCFG_WIRE_NLMSG_HDR_LEN, "nlmsghdr is 16 bytes");
_Static_assert(sizeof(struct rtattr) == NCFG_WIRE_RTATTR_HDR_LEN, "rtattr is 4 bytes");
_Static_assert(sizeof(struct ifinfomsg) == NCFG_WIRE_IFINFO_LEN, "ifinfomsg is 16 bytes");
_Static_assert(sizeof(struct ifaddrmsg) == NCFG_WIRE_IFADDR_LEN, "ifaddrmsg is 8 bytes");
_Static_assert(sizeof(struct rtmsg) == NCFG_WIRE_RTMSG_LEN, "rtmsg is 12 bytes");

/*
 * And these are why the encoders may write field offsets rather than the
 * struct itself.
 *
 * The one that matters is `ifi_type` at 2: `struct ifinfomsg` has a pad byte
 * after `ifi_family` that nothing names, and a port that encoded the fields in
 * declaration order with no gap would put the ARPHRD type one byte early and
 * every interface would come back the wrong kind.
 */
_Static_assert(offsetof(struct ifinfomsg, ifi_type) == 2, "ifinfomsg pads after the family");
_Static_assert(offsetof(struct ifinfomsg, ifi_index) == 4, "ifi_index sits at 4");
_Static_assert(offsetof(struct ifinfomsg, ifi_flags) == 8, "ifi_flags sits at 8");
_Static_assert(offsetof(struct ifinfomsg, ifi_change) == 12, "ifi_change sits at 12");
_Static_assert(offsetof(struct ifaddrmsg, ifa_index) == 4, "ifa_index sits at 4");
_Static_assert(offsetof(struct rtmsg, rtm_flags) == 8, "rtm_flags sits at 8");

/*
 * Native-endian reads and writes, which is every netlink field that is not an
 * address.
 *
 * `memcpy` rather than a cast for two reasons that are both real: a buffer
 * that came off a socket is only guaranteed 4-byte aligned by convention, and
 * a cast to `uint32_t *` on an odd offset is undefined behaviour that UBSan
 * traps and older ARM faults on. And `memcpy` of the host representation is
 * what makes "native" true on a machine this was never built on -- shifts
 * would hardcode x86's answer. See the endianness note in wire.h.
 */
static uint16_t read_u16(const uint8_t *bytes)
{
	uint16_t value;

	memcpy(&value, bytes, sizeof(value));
	return value;
}

static uint32_t read_u32(const uint8_t *bytes)
{
	uint32_t value;

	memcpy(&value, bytes, sizeof(value));
	return value;
}

static void put_u16(ncfg_buf_t *out, uint16_t value)
{
	ncfg_buf_add(out, &value, sizeof(value));
}

static void put_u32(ncfg_buf_t *out, uint32_t value)
{
	ncfg_buf_add(out, &value, sizeof(value));
}

/* Pad the buffer out to the next 4-byte boundary. An attribute area is
 * measured from the start of the buffer it is built in, which is what makes
 * this the same alignment the kernel sees. */
static void pad_to_align(ncfg_buf_t *out)
{
	static const uint8_t zeros[4] = { 0, 0, 0, 0 };
	size_t padding;

	if (!out || out->failed) {
		return;
	}
	padding = ncfg_wire_align4(out->length) - out->length;
	if (padding) {
		ncfg_buf_add(out, zeros, padding);
	}
}

size_t ncfg_wire_align4(size_t length)
{
	if (length > SIZE_MAX - 3u) {
		/* Cannot happen from a real buffer -- but wrapping here would turn
		 * a length that does not fit into one that needs no room at all,
		 * and every bounds check downstream would then agree with it. */
		return length;
	}
	return (length + 3u) & ~(size_t)3u;
}

int ncfg_wire_header_decode(const void *bytes, size_t length, ncfg_wire_header_t *out,
    char *err, size_t err_size)
{
	const uint8_t *raw = bytes;

	if (!raw || !out) {
		ncfg_error_set(err, err_size,
		    "a netlink header needs somewhere to come from and go");
		return 0;
	}
	if (length < NCFG_WIRE_NLMSG_HDR_LEN) {
		ncfg_error_set(err, err_size,
		    "a netlink header needs %u bytes and this message has %zu",
		    (unsigned)NCFG_WIRE_NLMSG_HDR_LEN, length);
		return 0;
	}
	out->len = read_u32(raw);
	out->kind = read_u16(raw + 4);
	out->flags = read_u16(raw + 6);
	/* `seq` is four bytes at offset 8. The Rust had this reading a two-byte
	 * slice once, which made every decode fail and the daemon see a kernel
	 * with no interfaces on it. */
	out->seq = read_u32(raw + 8);
	out->pid = read_u32(raw + 12);
	return 1;
}

void ncfg_wire_header_encode(const ncfg_wire_header_t *header, ncfg_buf_t *out)
{
	if (!header || !out) {
		return;
	}
	put_u32(out, header->len);
	put_u16(out, header->kind);
	put_u16(out, header->flags);
	put_u32(out, header->seq);
	put_u32(out, header->pid);
}

int ncfg_wire_ifinfo_decode(const void *bytes, size_t length, ncfg_wire_ifinfo_t *out,
    char *err, size_t err_size)
{
	const uint8_t *raw = bytes;
	uint32_t index;

	if (!raw || !out) {
		ncfg_error_set(err, err_size, "an ifinfomsg needs somewhere to come from and go");
		return 0;
	}
	if (length < NCFG_WIRE_IFINFO_LEN) {
		ncfg_error_set(err, err_size,
		    "a link message carries %u bytes of ifinfomsg and this one has %zu",
		    (unsigned)NCFG_WIRE_IFINFO_LEN, length);
		return 0;
	}
	out->family = raw[0];
	/* raw[1] is the pad byte; see the static assertion above. */
	out->kind = read_u16(raw + 2);
	index = read_u32(raw + 4);
	/* The kernel declares `ifi_index` signed and this port keeps that, so the
	 * conversion is stated here rather than left to a compiler flag. Every
	 * real index is small and positive; a negative one is the kernel's to
	 * explain, not ours to hide. */
	memcpy(&out->index, &index, sizeof(out->index));
	out->flags = read_u32(raw + 8);
	out->change = read_u32(raw + 12);
	return 1;
}

void ncfg_wire_ifinfo_encode(const ncfg_wire_ifinfo_t *info, ncfg_buf_t *out)
{
	uint32_t index;

	if (!info || !out) {
		return;
	}
	ncfg_buf_add(out, &info->family, 1u);
	ncfg_buf_add_char(out, '\0');
	put_u16(out, info->kind);
	memcpy(&index, &info->index, sizeof(index));
	put_u32(out, index);
	put_u32(out, info->flags);
	put_u32(out, info->change);
}

int ncfg_wire_ifaddr_decode(const void *bytes, size_t length, ncfg_wire_ifaddr_t *out,
    char *err, size_t err_size)
{
	const uint8_t *raw = bytes;

	if (!raw || !out) {
		ncfg_error_set(err, err_size, "an ifaddrmsg needs somewhere to come from and go");
		return 0;
	}
	if (length < NCFG_WIRE_IFADDR_LEN) {
		ncfg_error_set(err, err_size,
		    "an address message carries %u bytes of ifaddrmsg and this one has %zu",
		    (unsigned)NCFG_WIRE_IFADDR_LEN, length);
		return 0;
	}
	out->family = raw[0];
	out->prefix_len = raw[1];
	out->flags = raw[2];
	out->scope = raw[3];
	out->index = read_u32(raw + 4);
	return 1;
}

void ncfg_wire_ifaddr_encode(const ncfg_wire_ifaddr_t *addr, ncfg_buf_t *out)
{
	uint8_t head[4];

	if (!addr || !out) {
		return;
	}
	head[0] = addr->family;
	head[1] = addr->prefix_len;
	head[2] = addr->flags;
	head[3] = addr->scope;
	ncfg_buf_add(out, head, sizeof(head));
	put_u32(out, addr->index);
}

int ncfg_wire_rtmsg_decode(const void *bytes, size_t length, ncfg_wire_rtmsg_t *out,
    char *err, size_t err_size)
{
	const uint8_t *raw = bytes;

	if (!raw || !out) {
		ncfg_error_set(err, err_size, "an rtmsg needs somewhere to come from and go");
		return 0;
	}
	if (length < NCFG_WIRE_RTMSG_LEN) {
		ncfg_error_set(err, err_size,
		    "a route message carries %u bytes of rtmsg and this one has %zu",
		    (unsigned)NCFG_WIRE_RTMSG_LEN, length);
		return 0;
	}
	out->family = raw[0];
	out->dst_len = raw[1];
	out->src_len = raw[2];
	out->tos = raw[3];
	out->table = raw[4];
	out->protocol = raw[5];
	out->scope = raw[6];
	out->kind = raw[7];
	out->flags = read_u32(raw + 8);
	return 1;
}

void ncfg_wire_rtmsg_encode(const ncfg_wire_rtmsg_t *route, ncfg_buf_t *out)
{
	uint8_t head[8];

	if (!route || !out) {
		return;
	}
	head[0] = route->family;
	head[1] = route->dst_len;
	head[2] = route->src_len;
	head[3] = route->tos;
	head[4] = route->table;
	head[5] = route->protocol;
	head[6] = route->scope;
	head[7] = route->kind;
	ncfg_buf_add(out, head, sizeof(head));
	put_u32(out, route->flags);
}

void ncfg_wire_messages_start(ncfg_wire_messages_t *walk, const void *bytes, size_t length)
{
	if (!walk) {
		return;
	}
	walk->rest = bytes;
	/* A NULL buffer is an empty one rather than a special case, so that a
	 * caller which read zero bytes need not test before walking. */
	walk->remaining = bytes ? length : 0;
}

/* Leave a walk finished. Every refusal does this, which is what makes a loop
 * that ignores `NCFG_WIRE_BAD` terminate anyway -- the failure mode this
 * module exists to prevent does not look like a crash, it looks like a hang in
 * a privileged daemon. */
static void stop_messages(ncfg_wire_messages_t *walk)
{
	walk->rest = NULL;
	walk->remaining = 0;
}

ncfg_wire_step_t ncfg_wire_messages_next(ncfg_wire_messages_t *walk, ncfg_wire_message_t *out,
    char *err, size_t err_size)
{
	ncfg_wire_header_t header;
	size_t len;
	size_t advance;

	if (!walk || !out) {
		ncfg_error_set(err, err_size,
		    "a message walk needs somewhere to come from and go");
		return NCFG_WIRE_BAD;
	}
	if (walk->remaining == 0) {
		return NCFG_WIRE_END;
	}
	if (walk->remaining < NCFG_WIRE_NLMSG_HDR_LEN) {
		/* A short read that stopped mid-header is a refusal and not an
		 * end: the difference is whether the caller has seen everything
		 * the kernel sent, and guessing costs it a message it will never
		 * know was there. */
		ncfg_error_set(err, err_size,
		    "a netlink buffer ends %zu bytes into a %u-byte header",
		    walk->remaining, (unsigned)NCFG_WIRE_NLMSG_HDR_LEN);
		stop_messages(walk);
		return NCFG_WIRE_BAD;
	}
	if (!ncfg_wire_header_decode(walk->rest, walk->remaining, &header, err, err_size)) {
		stop_messages(walk);
		return NCFG_WIRE_BAD;
	}
	len = (size_t)header.len;
	if (len < NCFG_WIRE_NLMSG_HDR_LEN) {
		/* A message shorter than its own header would advance the walk by
		 * zero, and the loop would never end. This is *the* netlink parser
		 * bug, and refusing here is the whole fix. */
		ncfg_error_set(err, err_size,
		    "a netlink message says it is %zu bytes long, shorter than the %u-byte header "
		    "it sits in", len, (unsigned)NCFG_WIRE_NLMSG_HDR_LEN);
		stop_messages(walk);
		return NCFG_WIRE_BAD;
	}
	if (len > walk->remaining) {
		ncfg_error_set(err, err_size,
		    "a netlink message claims %zu bytes and the buffer holds %zu",
		    len, walk->remaining);
		stop_messages(walk);
		return NCFG_WIRE_BAD;
	}
	out->header = header;
	out->payload = walk->rest + NCFG_WIRE_NLMSG_HDR_LEN;
	out->payload_length = len - NCFG_WIRE_NLMSG_HDR_LEN;
	/* The last message of a read may be unaligned, in which case the padding
	 * the next one would start after was never sent. Clamping rather than
	 * refusing keeps that message, which is well-formed. */
	advance = ncfg_wire_align4(len);
	if (advance > walk->remaining) {
		advance = walk->remaining;
	}
	walk->rest += advance;
	walk->remaining -= advance;
	return NCFG_WIRE_OK;
}

int ncfg_wire_message_attrs(const ncfg_wire_message_t *message, size_t body_length,
    ncfg_wire_attrs_t *out, char *err, size_t err_size)
{
	size_t skip;

	if (!message || !out) {
		ncfg_error_set(err, err_size, "an attribute area needs a message to come from");
		return 0;
	}
	skip = ncfg_wire_align4(body_length);
	if (skip > message->payload_length) {
		/* The attributes would begin past the end of the message. Reported
		 * rather than clamped, because a clamp here reads whatever follows
		 * the message in the read buffer as this message's attributes. */
		ncfg_error_set(err, err_size,
		    "a message payload of %zu bytes cannot hold a %zu-byte family struct",
		    message->payload_length, body_length);
		return 0;
	}
	ncfg_wire_attrs_start(out, message->payload + skip, message->payload_length - skip);
	return 1;
}

void ncfg_wire_attrs_start(ncfg_wire_attrs_t *walk, const void *bytes, size_t length)
{
	if (!walk) {
		return;
	}
	walk->rest = bytes;
	walk->remaining = bytes ? length : 0;
}

static void stop_attrs(ncfg_wire_attrs_t *walk)
{
	walk->rest = NULL;
	walk->remaining = 0;
}

ncfg_wire_step_t ncfg_wire_attrs_next(ncfg_wire_attrs_t *walk, ncfg_wire_attr_t *out,
    char *err, size_t err_size)
{
	size_t len;
	size_t advance;
	uint16_t kind;

	if (!walk || !out) {
		ncfg_error_set(err, err_size,
		    "an attribute walk needs somewhere to come from and go");
		return NCFG_WIRE_BAD;
	}
	if (walk->remaining == 0) {
		return NCFG_WIRE_END;
	}
	if (walk->remaining < NCFG_WIRE_RTATTR_HDR_LEN) {
		/* Up to three bytes of alignment padding may follow the last
		 * attribute of an area, and they are not the start of another one.
		 * A kernel that padded correctly never lands here, since the area
		 * itself is a multiple of four; anything else is a refusal. */
		ncfg_error_set(err, err_size,
		    "an attribute area ends %zu bytes into a %u-byte header",
		    walk->remaining, (unsigned)NCFG_WIRE_RTATTR_HDR_LEN);
		stop_attrs(walk);
		return NCFG_WIRE_BAD;
	}
	len = (size_t)read_u16(walk->rest);
	kind = read_u16(walk->rest + 2);
	if (len < NCFG_WIRE_RTATTR_HDR_LEN) {
		/* The same termination hazard as messages, one level down: a
		 * length below the header size makes no progress. */
		ncfg_error_set(err, err_size,
		    "an attribute says it is %zu bytes long, shorter than the %u-byte header "
		    "it sits in", len, (unsigned)NCFG_WIRE_RTATTR_HDR_LEN);
		stop_attrs(walk);
		return NCFG_WIRE_BAD;
	}
	if (len > walk->remaining) {
		ncfg_error_set(err, err_size,
		    "an attribute of type %u claims %zu bytes and the message holds %zu",
		    (unsigned)(kind & 0x3fffu), len, walk->remaining);
		stop_attrs(walk);
		return NCFG_WIRE_BAD;
	}
	/* The top two bits mark nested and network-byte-order attributes and are
	 * not part of the type. A reader that kept them looks up `IFLA_LINKINFO`
	 * and finds nothing, because the kernel set `NLA_F_NESTED` on it. */
	out->kind = (uint16_t)(kind & 0x3fffu);
	out->value = walk->rest + NCFG_WIRE_RTATTR_HDR_LEN;
	out->length = len - NCFG_WIRE_RTATTR_HDR_LEN;
	advance = ncfg_wire_align4(len);
	if (advance > walk->remaining) {
		advance = walk->remaining;
	}
	walk->rest += advance;
	walk->remaining -= advance;
	return NCFG_WIRE_OK;
}

ncfg_wire_step_t ncfg_wire_attrs_find(const ncfg_wire_attrs_t *area, uint16_t kind,
    ncfg_wire_attr_t *out, char *err, size_t err_size)
{
	ncfg_wire_attrs_t walk;
	ncfg_wire_attr_t attr;
	ncfg_wire_step_t step;

	if (!area) {
		ncfg_error_set(err, err_size, "an attribute search needs an area to search");
		return NCFG_WIRE_BAD;
	}
	/* Searched on a copy, so the caller's walk is where it was. A link
	 * record reads half a dozen attributes out of one area and each search
	 * has to start at the beginning. */
	walk = *area;
	for (;;) {
		step = ncfg_wire_attrs_next(&walk, &attr, err, err_size);
		if (step != NCFG_WIRE_OK) {
			return step;
		}
		if (attr.kind == kind) {
			if (out) {
				*out = attr;
			}
			return NCFG_WIRE_OK;
		}
	}
}

int ncfg_wire_attr_u8(const ncfg_wire_attr_t *attr, uint8_t *out, char *err, size_t err_size)
{
	if (!attr || !out || !attr->value || attr->length < 1u) {
		ncfg_error_set(err, err_size, "an attribute with no bytes is not a number");
		return 0;
	}
	*out = attr->value[0];
	return 1;
}

int ncfg_wire_attr_u16(const ncfg_wire_attr_t *attr, uint16_t *out, char *err, size_t err_size)
{
	if (!attr || !out || !attr->value || attr->length < 2u) {
		ncfg_error_set(err, err_size,
		    "a 16-bit attribute needs 2 bytes and this one has %zu",
		    attr && attr->value ? attr->length : (size_t)0);
		return 0;
	}
	*out = read_u16(attr->value);
	return 1;
}

int ncfg_wire_attr_u32(const ncfg_wire_attr_t *attr, uint32_t *out, char *err, size_t err_size)
{
	if (!attr || !out || !attr->value || attr->length < 4u) {
		ncfg_error_set(err, err_size,
		    "a 32-bit attribute needs 4 bytes and this one has %zu",
		    attr && attr->value ? attr->length : (size_t)0);
		return 0;
	}
	*out = read_u32(attr->value);
	return 1;
}

/*
 * Whether `text` is valid UTF-8, which an interface name from the kernel is
 * not guaranteed to be.
 *
 * The Rust refused invalid UTF-8 because `String` could not hold it. Here
 * nothing would stop the bytes, so the refusal is written out: a name read off
 * netlink ends up in a JSON document and in a rendered configuration block,
 * and a lone continuation byte in either is a file that a reader downstream
 * rejects with no idea which interface it came from. Overlong forms, surrogate
 * halves and anything above U+10FFFF are all rejected, because each is a way
 * to smuggle a byte past a validator that only counts lengths.
 */
static int is_utf8(const uint8_t *bytes, size_t length)
{
	size_t at = 0;

	while (at < length) {
		uint8_t lead = bytes[at];
		size_t extra;
		uint32_t code;
		size_t step;

		if (lead < 0x80u) {
			at++;
			continue;
		}
		if (lead >= 0xc2u && lead <= 0xdfu) {
			extra = 1;
			code = lead & 0x1fu;
		} else if (lead >= 0xe0u && lead <= 0xefu) {
			extra = 2;
			code = lead & 0x0fu;
		} else if (lead >= 0xf0u && lead <= 0xf4u) {
			extra = 3;
			code = lead & 0x07u;
		} else {
			/* A continuation byte with no lead, or 0xc0/0xc1, which
			 * only ever encode an overlong ASCII character. */
			return 0;
		}
		if (extra >= length - at) {
			return 0;
		}
		for (step = 1; step <= extra; step++) {
			uint8_t next = bytes[at + step];

			if ((next & 0xc0u) != 0x80u) {
				return 0;
			}
			code = (code << 6) | (next & 0x3fu);
		}
		if (extra == 2 && code < 0x800u) {
			return 0;
		}
		if (extra == 3 && code < 0x10000u) {
			return 0;
		}
		if (code > 0x10ffffu || (code >= 0xd800u && code <= 0xdfffu)) {
			return 0;
		}
		at += extra + 1u;
	}
	return 1;
}

int ncfg_wire_attr_string(const ncfg_wire_attr_t *attr, char *out, size_t out_size,
    char *err, size_t err_size)
{
	size_t end = 0;

	if (!attr || !out || out_size == 0) {
		ncfg_error_set(err, err_size, "a string attribute needs somewhere to go");
		return 0;
	}
	out[0] = '\0';
	if (!attr->value && attr->length) {
		ncfg_error_set(err, err_size, "a string attribute with no bytes behind it");
		return 0;
	}
	/* The kernel NUL-terminates these, but the terminator is inside the
	 * value rather than implied by it, and a value that never reaches one is
	 * not an error -- it is the whole value. */
	while (end < attr->length && attr->value[end] != '\0') {
		end++;
	}
	if (end >= out_size) {
		/* Refused, not truncated: a truncated interface name is still a
		 * name, just somebody else's, and a caller that acted on it would
		 * reconfigure the wrong link. */
		ncfg_error_set(err, err_size,
		    "a %zu-byte string attribute does not fit a %zu-byte buffer",
		    end, out_size - 1u);
		return 0;
	}
	if (!is_utf8(attr->value, end)) {
		ncfg_error_set(err, err_size, "a string attribute that is not valid UTF-8");
		return 0;
	}
	if (end) {
		memcpy(out, attr->value, end);
	}
	out[end] = '\0';
	return 1;
}

int ncfg_wire_attr_mac(const ncfg_wire_attr_t *attr, char *out, size_t out_size,
    char *err, size_t err_size)
{
	static const char digits[] = "0123456789abcdef";
	size_t at;
	char *write = out;

	if (!attr || !out || out_size < NCFG_WIRE_MAC_TEXT_MAX) {
		ncfg_error_set(err, err_size, "a MAC address needs %u bytes to be written into",
		    (unsigned)NCFG_WIRE_MAC_TEXT_MAX);
		return 0;
	}
	out[0] = '\0';
	if (!attr->value || attr->length != 6u) {
		/* Not every `IFLA_ADDRESS` is six bytes: an InfiniBand link carries
		 * twenty and a tunnel four. Refusing is what keeps those out of a
		 * field the rest of the port treats as a MAC. */
		ncfg_error_set(err, err_size,
		    "a MAC address is 6 bytes and this attribute has %zu",
		    attr->value ? attr->length : (size_t)0);
		return 0;
	}
	/* Written out rather than formatted: seventeen characters and a
	 * terminator is exactly `NCFG_WIRE_MAC_TEXT_MAX`, and a `snprintf` per
	 * octet is where an off-by-one in the colon offset would hide. */
	for (at = 0; at < 6u; at++) {
		if (at) {
			*write++ = ':';
		}
		*write++ = digits[attr->value[at] >> 4];
		*write++ = digits[attr->value[at] & 0x0fu];
	}
	*write = '\0';
	return 1;
}

int ncfg_wire_attr_ip(const ncfg_wire_attr_t *attr, ncfg_wire_ip_t *out,
    char *err, size_t err_size)
{
	if (!attr || !out || !attr->value) {
		ncfg_error_set(err, err_size, "an address attribute needs somewhere to come from");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	/* Length decides the family, as it does everywhere in rtnetlink: the
	 * `ifa_family` beside it agrees, but an attribute is read here without
	 * the struct it came with. The bytes are network order and stay that
	 * way; nothing is swapped. */
	if (attr->length == 4u) {
		out->family = AF_INET;
	} else if (attr->length == 16u) {
		out->family = AF_INET6;
	} else {
		ncfg_error_set(err, err_size,
		    "an address is 4 or 16 bytes and this attribute has %zu", attr->length);
		return 0;
	}
	memcpy(out->bytes, attr->value, attr->length);
	return 1;
}

int ncfg_wire_ip_parse(const char *text, ncfg_wire_ip_t *out, char *err, size_t err_size)
{
	if (!text || !out) {
		ncfg_error_set(err, err_size, "an address needs somewhere to come from and go");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	/* `inet_pton` and not `inet_aton`: the second accepts `10.1` and octal
	 * octets, so `010.0.0.1` would parse as 8.0.0.1 and a configuration file
	 * would mean something other than it reads. */
	if (inet_pton(AF_INET, text, out->bytes) == 1) {
		out->family = AF_INET;
		return 1;
	}
	if (inet_pton(AF_INET6, text, out->bytes) == 1) {
		out->family = AF_INET6;
		return 1;
	}
	memset(out, 0, sizeof(*out));
	ncfg_error_set(err, err_size, "`%s` is not an address", text);
	return 0;
}

int ncfg_wire_ip_text(const ncfg_wire_ip_t *ip, char *out, size_t out_size,
    char *err, size_t err_size)
{
	if (!ip || !out || out_size < NCFG_WIRE_IP_TEXT_MAX) {
		ncfg_error_set(err, err_size, "an address needs %u bytes to be written into",
		    (unsigned)NCFG_WIRE_IP_TEXT_MAX);
		return 0;
	}
	out[0] = '\0';
	if (ip->family != AF_INET && ip->family != AF_INET6) {
		ncfg_error_set(err, err_size, "an address of no family cannot be written");
		return 0;
	}
	if (!inet_ntop(ip->family, ip->bytes, out, (socklen_t)out_size)) {
		ncfg_error_set(err, err_size, "this address cannot be written as text");
		return 0;
	}
	return 1;
}

void ncfg_wire_attr_put(ncfg_buf_t *out, uint16_t kind, const void *value, size_t length)
{
	if (!out || out->failed) {
		return;
	}
	/*
	 * An attribute's length field is 16 bits, and a value that does not fit
	 * it has no wire form at all.
	 *
	 * The Rust casts the sum to `u16` and appends whatever is left, so a
	 * value of 65532 bytes becomes an attribute claiming zero and the kernel
	 * reads the next attribute out of the middle of this one's value. It has
	 * never happened because nothing netcfgd sends is near that size -- which
	 * is an argument about today's callers, not about the encoder. Here it
	 * fails the buffer, so a caller's single `ncfg_buf_failed` catches it.
	 */
	if (length > 0xffffu - NCFG_WIRE_RTATTR_HDR_LEN) {
		out->failed = 1;
		return;
	}
	if (length && !value) {
		out->failed = 1;
		return;
	}
	put_u16(out, (uint16_t)(NCFG_WIRE_RTATTR_HDR_LEN + length));
	put_u16(out, kind);
	if (length) {
		ncfg_buf_add(out, value, length);
	}
	pad_to_align(out);
}

void ncfg_wire_attr_put_u8(ncfg_buf_t *out, uint16_t kind, uint8_t value)
{
	ncfg_wire_attr_put(out, kind, &value, sizeof(value));
}

void ncfg_wire_attr_put_u32(ncfg_buf_t *out, uint16_t kind, uint32_t value)
{
	/* Native order, like every other netlink integer. See wire.h. */
	ncfg_wire_attr_put(out, kind, &value, sizeof(value));
}

void ncfg_wire_attr_put_str(ncfg_buf_t *out, uint16_t kind, const char *value)
{
	if (!out || out->failed) {
		return;
	}
	if (!value) {
		out->failed = 1;
		return;
	}
	/* The NUL is part of the value: the kernel's `nla_strcmp` reads to the
	 * terminator and a name sent without one matches the name beside it. */
	ncfg_wire_attr_put(out, kind, value, strlen(value) + 1u);
}

void ncfg_wire_attr_put_ip(ncfg_buf_t *out, uint16_t kind, const ncfg_wire_ip_t *value)
{
	if (!out || out->failed) {
		return;
	}
	if (!value || (value->family != AF_INET && value->family != AF_INET6)) {
		out->failed = 1;
		return;
	}
	ncfg_wire_attr_put(out, kind, value->bytes, value->family == AF_INET ? 4u : 16u);
}

void ncfg_wire_attr_put_nested(ncfg_buf_t *out, uint16_t kind, const ncfg_buf_t *nest)
{
	if (!out || out->failed) {
		return;
	}
	if (!nest || ncfg_buf_failed(nest)) {
		/* A nest that failed to build is not an empty nest. Appending one
		 * would send a link with no kind and let the kernel decide. */
		out->failed = 1;
		return;
	}
	ncfg_wire_attr_put(out, (uint16_t)(kind | NLA_F_NESTED), nest->data, nest->length);
}

int ncfg_wire_build_request(ncfg_buf_t *out, uint16_t kind, uint16_t flags, uint32_t seq,
    const ncfg_buf_t *body, const ncfg_buf_t *attrs, char *err, size_t err_size)
{
	ncfg_wire_header_t header;
	size_t body_length = 0;
	size_t attrs_length = 0;
	size_t total;

	if (!out) {
		ncfg_error_set(err, err_size, "a request needs somewhere to be built");
		return 0;
	}
	if (body) {
		if (ncfg_buf_failed(body)) {
			ncfg_error_set(err, err_size, "the body of this request was never built");
			return 0;
		}
		body_length = body->length;
	}
	if (attrs) {
		/*
		 * A failed buffer hands out the empty string, which here would be
		 * a request with every attribute quietly missing -- and the kernel
		 * acts on that: an `RTM_NEWLINK` with no `IFLA_IFNAME` is not a
		 * refusal, it is a link named by the kernel. So the failure is
		 * carried out rather than read through.
		 */
		if (ncfg_buf_failed(attrs)) {
			ncfg_error_set(err, err_size,
			    "the attributes of this request were never built");
			return 0;
		}
		attrs_length = attrs->length;
	}
	total = NCFG_WIRE_NLMSG_HDR_LEN + ncfg_wire_align4(body_length) + attrs_length;
	if (total > 0xffffffffu || total < attrs_length) {
		ncfg_error_set(err, err_size,
		    "a netlink message length is 32 bits and this request needs %zu bytes", total);
		return 0;
	}
	header.len = (uint32_t)total;
	header.kind = kind;
	header.flags = flags;
	header.seq = seq;
	/* Zero: the kernel fills in the sending port id, and a request that
	 * states one is a request claiming to be from somebody. */
	header.pid = 0;
	ncfg_wire_header_encode(&header, out);
	if (body_length) {
		ncfg_buf_add(out, body->data, body_length);
		pad_to_align(out);
	}
	if (attrs_length) {
		ncfg_buf_add(out, attrs->data, attrs_length);
	}
	if (ncfg_buf_failed(out)) {
		ncfg_error_set(err, err_size, "a %zu-byte request did not fit its buffer", total);
		return 0;
	}
	return 1;
}

int ncfg_wire_error_code(const void *payload, size_t length, int32_t *out,
    char *err, size_t err_size)
{
	const uint8_t *raw = payload;
	uint32_t bits;
	int32_t code;

	if (!raw || !out) {
		ncfg_error_set(err, err_size,
		    "an error payload needs somewhere to come from and go");
		return 0;
	}
	if (length < 4u) {
		ncfg_error_set(err, err_size,
		    "an NLMSG_ERROR payload carries 4 bytes of errno and this one has %zu",
		    length);
		return 0;
	}
	bits = read_u32(raw);
	memcpy(&code, &bits, sizeof(code));
	if (code == INT32_MIN) {
		/* The one value with no positive counterpart. `-code` here is
		 * signed overflow -- undefined behaviour, which UBSan traps and an
		 * optimizer is entitled to assume cannot happen; in Rust the same
		 * expression panicked under overflow checks and wrapped back to
		 * INT32_MIN without them, so one nine-byte message either killed
		 * the daemon or gave it a nonsense errno depending on the profile
		 * it was built with. No real errno is within nine digits of this,
		 * so the payload is malformed and says so. */
		ncfg_error_set(err, err_size,
		    "an errno with no positive counterpart is a malformed payload, not a code");
		return 0;
	}
	/* Netlink sends errno negated, and zero means acknowledgement rather
	 * than failure -- its least obvious convention. */
	*out = -code;
	return 1;
}
