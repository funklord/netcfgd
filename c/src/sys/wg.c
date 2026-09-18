/*
 * wg.c -- the WireGuard encoding and decoding described in wg.h.
 *
 * No socket, no ioctl, no name lookup. Everything here turns a document into
 * bytes or bytes into an observation, which is what makes the part that can be
 * silently wrong -- the nesting, the attribute numbering, the endianness of a
 * port -- testable on a machine with no `wireguard` module at all.
 *
 * Nothing in this file renders a key, quotes one in a diagnostic, or hands one
 * back to a caller that did not already have it. Errors name interfaces,
 * peers by their local label, sizes and counts.
 */
#include "ncfg/wg.h"

#include "ncfg/value.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(NCFG_WG_KEY_LEN == 32u, "a WireGuard key is 32 octets");
/*
 * The document's peer key and the kernel's are the same 32 octets, proved
 * rather than assumed. A model that held a base64 string here would compile
 * against this file and send 44 bytes where the kernel declares `NLA_EXACT_LEN`
 * -- an `ERANGE` naming neither the attribute nor the length.
 */
_Static_assert(sizeof(((ncfg_wg_peer_t *)0)->public_key) == NCFG_WG_KEY_LEN,
    "the document carries a peer key as the kernel's 32 octets");

/*
 * And these are why `endpoint_bytes` may write the fields out by hand.
 *
 * The kernel copies an endpoint attribute straight into a `sockaddr`, so the
 * layout is the ABI's rather than this file's opinion. Written out rather than
 * memcpy'd from a libc struct because the port is big-endian while the family
 * is native, and writing them separately makes both facts visible instead of
 * hiding them behind a cast. These assertions are what make that safe.
 */
_Static_assert(sizeof(struct sockaddr_in) == 16u, "sockaddr_in is 16 bytes");
_Static_assert(sizeof(struct sockaddr_in6) == 28u, "sockaddr_in6 is 28 bytes");
_Static_assert(offsetof(struct sockaddr_in, sin_port) == 2u, "the port follows the family");
_Static_assert(offsetof(struct sockaddr_in, sin_addr) == 4u, "then the address");
_Static_assert(offsetof(struct sockaddr_in6, sin6_port) == 2u, "the v6 port follows too");
_Static_assert(offsetof(struct sockaddr_in6, sin6_flowinfo) == 4u, "then the flow label");
_Static_assert(offsetof(struct sockaddr_in6, sin6_addr) == 8u, "then the address");
_Static_assert(offsetof(struct sockaddr_in6, sin6_scope_id) == 24u, "then the scope");

/*
 * `IFNAMSIZ`, written out rather than included.
 *
 * `linux/if.h` and `net/if.h` redefine each other's `struct ifreq`, and a
 * caller of this file is very likely to want one of them -- so pulling in
 * either here would decide that for them. The same reasoning as `wire.h`'s
 * `NCFG_WIRE_ALT_IFNAME_MAX`.
 */
#define IFNAME_MAX 16u

/*
 * The largest attribute *type* that survives a round trip.
 *
 * The top two bits of the type field mark a nested attribute and a
 * network-byte-order one; the kind is the low fourteen. An array slot is the
 * index, so an index past this would set one of those bits and the reader
 * would see a different attribute entirely. The byte bound below is reached
 * long first, which is why this is a guard rather than a limit anybody meets.
 */
#define ARRAY_SLOT_MAX 0x3fffu

/* How many peers or allowed IPs an array holds before it grows. A device with
 * one peer is the common case and a hub has hundreds; this keeps the first to
 * one allocation and the second to a handful. */
#define ARRAY_FIRST 4u

static size_t array_capacity(size_t count)
{
	size_t capacity = ARRAY_FIRST;

	while (capacity < count && capacity <= SIZE_MAX / 2u) {
		capacity *= 2u;
	}
	return capacity;
}

/*
 * Room for one more entry: the array to use, or NULL with a sentence.
 *
 * `size` is one entry. One helper for the three arrays here rather than three
 * copies of the same doubling, because the interesting half is the overflow
 * check and it is the half a copy loses.
 *
 * It returns the array rather than taking a `void **`, which would mean
 * casting an `ncfg_wg_peer_state_t **` at every call site -- an aliasing
 * violation that happens to work. NULL is unambiguously failure: an array that
 * needed no growth is returned as it was, and one that was NULL always grows.
 */
static void *array_room(void *items, size_t count, size_t size, const char *what,
    char *err, size_t err_size)
{
	size_t want;
	void *bigger;

	if (items && count != array_capacity(count)) {
		return items;
	}
	want = array_capacity(count + 1u);
	if (want <= count || want > SIZE_MAX / size) {
		ncfg_error_set(err, err_size, "too many %s to hold", what);
		return NULL;
	}
	bigger = realloc(items, want * size);
	if (!bigger) {
		ncfg_error_set(err, err_size, "out of memory for %s", what);
		return NULL;
	}
	return bigger;
}

/* An array index as an attribute type. See `ARRAY_SLOT_MAX`. */
static int array_slot(size_t index, uint16_t *out, const char *what, char *err, size_t err_size)
{
	if (index > ARRAY_SLOT_MAX) {
		ncfg_error_set(err, err_size,
		    "%s past %u cannot be numbered in an attribute type", what,
		    (unsigned)ARRAY_SLOT_MAX);
		return 0;
	}
	*out = (uint16_t)index;
	return 1;
}

static int ifname_fits(const char *name, char *err, size_t err_size)
{
	size_t length = name ? strlen(name) : 0;

	if (length == 0 || length >= IFNAME_MAX) {
		ncfg_error_set(err, err_size,
		    "`%s` is not a name the kernel would take for a link: %u characters at most",
		    name ? name : "", (unsigned)(IFNAME_MAX - 1u));
		return 0;
	}
	return 1;
}

/* A peer's local label, for a diagnostic. The document makes it the sorting
 * key and never leaves it empty; this is what keeps a hand-built peer from
 * turning a refusal into a crash. */
static const char *peer_label(const ncfg_wg_peer_t *peer)
{
	return peer->name ? peer->name : "(unnamed)";
}

/* ------------------------------------------------------------------------ *
 * Endpoints
 * ------------------------------------------------------------------------ */

/*
 * An endpoint as the `sockaddr` the kernel copies into place.
 *
 * `out` must hold `sizeof(struct sockaddr_in6)`. The family is native order,
 * like every other netlink integer; the port is big-endian, like every port on
 * every wire. Getting either wrong produces an endpoint the kernel accepts and
 * sends nothing to, which is a tunnel that comes up and carries no traffic.
 */
static int endpoint_bytes(const ncfg_wire_ip_t *address, uint16_t port, unsigned char *out,
    size_t *length, char *err, size_t err_size)
{
	uint16_t family;

	memset(out, 0, sizeof(struct sockaddr_in6));
	if (address->family == AF_INET) {
		family = AF_INET;
		*length = sizeof(struct sockaddr_in);
	} else if (address->family == AF_INET6) {
		family = AF_INET6;
		*length = sizeof(struct sockaddr_in6);
	} else {
		ncfg_error_set(err, err_size, "an endpoint of no address family");
		return 0;
	}
	/* Native, by copying the host's representation rather than by shifts:
	 * a hand-rolled low-byte-first encoding is correct on x86 and silently
	 * wrong everywhere else. wire.h has the long version. */
	memcpy(out, &family, sizeof(family));
	/* And the port is the opposite case: big-endian by shifts, which is
	 * correct on every host precisely because it names the byte order. */
	out[2] = (unsigned char)(port >> 8);
	out[3] = (unsigned char)(port & 0xffu);
	if (family == AF_INET) {
		memcpy(out + 4, address->bytes, 4);
	} else {
		/* `sin6_flowinfo` stays zero; the address sits after it. */
		memcpy(out + 8, address->bytes, 16);
	}
	return 1;
}

/* The inverse. A value that is not one of the two `sockaddr`s is a refusal. */
static int endpoint_parse(const unsigned char *bytes, size_t length, ncfg_wire_ip_t *address,
    uint16_t *port, char *err, size_t err_size)
{
	uint16_t family;

	memset(address, 0, sizeof(*address));
	if (length < 4u) {
		ncfg_error_set(err, err_size,
		    "an endpoint needs at least 4 bytes and this one has %zu", length);
		return 0;
	}
	memcpy(&family, bytes, sizeof(family));
	*port = (uint16_t)(((uint16_t)bytes[2] << 8) | (uint16_t)bytes[3]);
	if (family == AF_INET && length >= sizeof(struct sockaddr_in)) {
		address->family = AF_INET;
		memcpy(address->bytes, bytes + 4, 4);
		return 1;
	}
	if (family == AF_INET6 && length >= sizeof(struct sockaddr_in6)) {
		address->family = AF_INET6;
		memcpy(address->bytes, bytes + 8, 16);
		return 1;
	}
	ncfg_error_set(err, err_size,
	    "an endpoint of family %u in %zu bytes is neither a sockaddr_in nor a sockaddr_in6",
	    (unsigned)family, length);
	return 0;
}

int ncfg_wg_endpoint_parse(const char *text, ncfg_wire_ip_t *address, uint16_t *port,
    char *err, size_t err_size)
{
	char host[NCFG_WIRE_IP_TEXT_MAX];
	const char *host_at;
	const char *colon;
	size_t host_length;
	unsigned long value;
	char *end;

	if (!text || !address || !port) {
		ncfg_error_set(err, err_size, "an endpoint needs text and somewhere to go");
		return 0;
	}
	if (text[0] == '[') {
		const char *close = strchr(text, ']');

		if (!close || close[1] != ':') {
			ncfg_error_set(err, err_size,
			    "`%s` is not `[address]:port`", text);
			return 0;
		}
		host_at = text + 1;
		host_length = (size_t)(close - host_at);
		colon = close + 1;
	} else {
		colon = strrchr(text, ':');
		if (!colon) {
			ncfg_error_set(err, err_size, "`%s` names no port", text);
			return 0;
		}
		host_at = text;
		host_length = (size_t)(colon - text);
		if (memchr(host_at, ':', host_length)) {
			/*
			 * `fd00::1:51820` is a perfectly good IPv6 address and
			 * also reads as an address and a port, and the two
			 * readings name different machines. The brackets exist
			 * to settle it, so an unbracketed address with a colon
			 * in it is refused rather than guessed at.
			 */
			ncfg_error_set(err, err_size,
			    "`%s` is ambiguous; an IPv6 endpoint is written `[address]:port`",
			    text);
			return 0;
		}
	}
	if (host_length == 0 || host_length >= sizeof(host)) {
		ncfg_error_set(err, err_size, "`%s` names no address", text);
		return 0;
	}
	memcpy(host, host_at, host_length);
	host[host_length] = '\0';
	if (!ncfg_wire_ip_parse(host, address, err, err_size)) {
		return 0;
	}
	errno = 0;
	value = strtoul(colon + 1, &end, 10);
	if (end == colon + 1 || *end != '\0' || errno != 0 || value == 0 || value > 65535u) {
		/* Zero is refused with the rest: a peer endpoint on port zero is
		 * a peer nothing can be sent to, and it is what an empty field
		 * parses to. */
		ncfg_error_set(err, err_size, "`%s` has no usable port", text);
		return 0;
	}
	*port = (uint16_t)value;
	return 1;
}

int ncfg_wg_endpoint_text(const ncfg_wire_ip_t *address, uint16_t port, char *out,
    size_t out_size, char *err, size_t err_size)
{
	char host[NCFG_WIRE_IP_TEXT_MAX];
	int written;

	if (!out || out_size < NCFG_WG_ENDPOINT_TEXT_MAX) {
		ncfg_error_set(err, err_size, "an endpoint needs %u bytes to be written into",
		    (unsigned)NCFG_WG_ENDPOINT_TEXT_MAX);
		return 0;
	}
	out[0] = '\0';
	if (!address || !ncfg_wire_ip_text(address, host, sizeof(host), err, err_size)) {
		return 0;
	}
	written = address->family == AF_INET6
	    ? snprintf(out, out_size, "[%s]:%u", host, (unsigned)port)
	    : snprintf(out, out_size, "%s:%u", host, (unsigned)port);
	if (written < 0 || (size_t)written >= out_size) {
		out[0] = '\0';
		ncfg_error_set(err, err_size, "this endpoint does not fit its buffer");
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Building a SET_DEVICE
 * ------------------------------------------------------------------------ */

/* One allowed IP: family, address, prefix, in a nest of its own. */
static int allowed_ip_entry(ncfg_buf_t *entry, const char *text, const char *peer_name,
    char *err, size_t err_size)
{
	ncfg_address_t parsed;
	ncfg_wire_ip_t address;
	uint16_t family;
	unsigned prefix;

	/* Parsed with no error buffer, because the sentence this file wants names
	 * the peer: "`10.9.0.0/33` is not an address" leaves an operator with a
	 * document to search and no idea which peer to search it for. */
	if (!ncfg_address_parse(text, &parsed, NULL, 0)) {
		ncfg_error_set(err, err_size,
		    "peer `%s` allows `%s`, which is not an address and a prefix",
		    peer_name, text);
		return 0;
	}
	memset(&address, 0, sizeof(address));
	address.family = parsed.is_ipv6 ? AF_INET6 : AF_INET;
	memcpy(address.bytes, parsed.bytes, sizeof(address.bytes));
	/* A bare address routes only itself, which is what `wg(8)` does with
	 * one: the kernel has no "no mask" and a missing one would otherwise be
	 * sent as a zero prefix, which is the default route. */
	prefix = parsed.has_prefix ? parsed.prefix : (parsed.is_ipv6 ? 128u : 32u);
	family = (uint16_t)address.family;
	/* Native order, and two bytes: `WGALLOWEDIP_A_FAMILY` is an `NLA_U16`
	 * where the flags beside it are 32-bit. */
	ncfg_wire_attr_put(entry, WGALLOWEDIP_A_FAMILY, &family, sizeof(family));
	ncfg_wire_attr_put_ip(entry, WGALLOWEDIP_A_IPADDR, &address);
	ncfg_wire_attr_put_u8(entry, WGALLOWEDIP_A_CIDR_MASK, (uint8_t)prefix);
	if (ncfg_buf_failed(entry)) {
		ncfg_error_set(err, err_size,
		    "peer `%s` could not be given `%s`", peer_name, text);
		return 0;
	}
	return 1;
}

static int allowed_ips_nest(ncfg_buf_t *nest, const ncfg_wg_peer_t *peer, char *err,
    size_t err_size)
{
	size_t index;

	for (index = 0; index < peer->allowed_ip_count; index++) {
		ncfg_buf_t entry;
		uint16_t slot;
		int ok;

		if (!array_slot(index, &slot, "allowed IPs", err, err_size)) {
			return 0;
		}
		ncfg_buf_init(&entry, 0);
		ok = allowed_ip_entry(&entry, peer->allowed_ips[index], peer_label(peer),
		    err, err_size);
		if (ok) {
			/*
			 * The slot is the index, because this nest is an array:
			 * the attribute *type* is a position and not a meaning.
			 * Numbering them all the same is a list the kernel reads
			 * as one entry repeated.
			 */
			ncfg_wire_attr_put_nested(nest, slot, &entry);
		}
		ncfg_buf_free(&entry);
		if (!ok) {
			return 0;
		}
		if (nest->length > NCFG_WG_ATTR_VALUE_MAX) {
			ncfg_error_set(err, err_size,
			    "peer `%s` allows %zu addresses, which is more than one netlink "
			    "attribute carries", peer_label(peer), peer->allowed_ip_count);
			return 0;
		}
	}
	if (ncfg_buf_failed(nest)) {
		ncfg_error_set(err, err_size, "peer `%s` could not be given its allowed IPs",
		    peer_label(peer));
		return 0;
	}
	return 1;
}

/* One peer: its identity, its keys, where it is, and what routes to it. */
static int peer_entry(ncfg_buf_t *entry, const ncfg_wg_peer_t *peer,
    const ncfg_wg_peer_material_t *material, char *err, size_t err_size)
{
	ncfg_buf_t allowed;
	int ok;

	ncfg_wire_attr_put(entry, WGPEER_A_PUBLIC_KEY, peer->public_key, NCFG_WG_KEY_LEN);
	if (material && material->preshared_key) {
		ncfg_wire_attr_put(entry, WGPEER_A_PRESHARED_KEY, material->preshared_key,
		    NCFG_WG_KEY_LEN);
	}
	/* Replace rather than merge, for the reason the device flag does: an
	 * allowed IP the document has removed must stop routing to this peer,
	 * and without this it keeps doing so until the device is torn down. */
	ncfg_wire_attr_put_u32(entry, WGPEER_A_FLAGS, WGPEER_F_REPLACE_ALLOWEDIPS);
	if (material && material->has_endpoint) {
		unsigned char sockaddr[sizeof(struct sockaddr_in6)];
		size_t length;

		if (!endpoint_bytes(&material->endpoint, material->endpoint_port, sockaddr,
		    &length, err, err_size)) {
			return 0;
		}
		ncfg_wire_attr_put(entry, WGPEER_A_ENDPOINT, sockaddr, length);
	}
	if (peer->keepalive.has) {
		uint16_t seconds;

		if (peer->keepalive.value < 0 || peer->keepalive.value > 65535) {
			ncfg_error_set(err, err_size,
			    "peer `%s` asks for a keepalive of %lld seconds; the kernel's "
			    "field holds 0 to 65535", peer_label(peer),
			    (long long)peer->keepalive.value);
			return 0;
		}
		seconds = (uint16_t)peer->keepalive.value;
		/* Two bytes, native order: an `NLA_U16` like the listen port. */
		ncfg_wire_attr_put(entry, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, &seconds,
		    sizeof(seconds));
	}
	ncfg_buf_init(&allowed, 0);
	ok = allowed_ips_nest(&allowed, peer, err, err_size);
	if (ok) {
		ncfg_wire_attr_put_nested(entry, WGPEER_A_ALLOWEDIPS, &allowed);
	}
	ncfg_buf_free(&allowed);
	if (!ok) {
		return 0;
	}
	if (ncfg_buf_failed(entry)) {
		ncfg_error_set(err, err_size, "peer `%s` could not be encoded", peer_label(peer));
		return 0;
	}
	return 1;
}

/*
 * The device's own attributes.
 *
 * `first` is what keeps a fragment from repeating them. The flags in
 * particular: a second message carrying `WGDEVICE_F_REPLACE_PEERS` would clear
 * the peers the first one installed, and the device would end up holding only
 * whatever the last fragment carried. <linux/wireguard.h> warns about exactly
 * this, and it is the failure mode that looks like "most of my peers vanished"
 * rather than like an error.
 */
static int device_attrs(ncfg_buf_t *attrs, const ncfg_wg_request_t *request, int first,
    char *err, size_t err_size)
{
	const ncfg_wireguard_config_t *config = request->config;

	ncfg_wire_attr_put_str(attrs, WGDEVICE_A_IFNAME, request->name);
	if (!first) {
		return 1;
	}
	if (request->replace_peers) {
		ncfg_wire_attr_put_u32(attrs, WGDEVICE_A_FLAGS, WGDEVICE_F_REPLACE_PEERS);
	}
	if (request->private_key) {
		ncfg_wire_attr_put(attrs, WGDEVICE_A_PRIVATE_KEY, request->private_key,
		    NCFG_WG_KEY_LEN);
	}
	if (config->listen_port.has) {
		uint16_t port;

		if (config->listen_port.value < 0 || config->listen_port.value > 65535) {
			ncfg_error_set(err, err_size,
			    "`%s` asks to listen on port %lld", request->name,
			    (long long)config->listen_port.value);
			return 0;
		}
		port = (uint16_t)config->listen_port.value;
		ncfg_wire_attr_put(attrs, WGDEVICE_A_LISTEN_PORT, &port, sizeof(port));
	}
	if (config->fwmark.has) {
		if (config->fwmark.value < 0 || config->fwmark.value > 0xffffffffLL) {
			ncfg_error_set(err, err_size,
			    "`%s` asks for a firewall mark of %lld", request->name,
			    (long long)config->fwmark.value);
			return 0;
		}
		ncfg_wire_attr_put_u32(attrs, WGDEVICE_A_FWMARK,
		    (uint32_t)config->fwmark.value);
	}
	return 1;
}

static int messages_append(ncfg_wg_messages_t *out, ncfg_buf_t *message, char *err,
    size_t err_size)
{
	size_t length = 0;
	char *bytes;
	void *grown;

	grown = array_room(out->message, out->count, sizeof(*out->message),
	    "netlink messages", err, err_size);
	if (!grown) {
		return 0;
	}
	out->message = grown;
	bytes = ncfg_buf_take(message, &length);
	if (!bytes) {
		ncfg_error_set(err, err_size, "a WireGuard message was never built");
		return 0;
	}
	out->message[out->count].bytes = (uint8_t *)bytes;
	out->message[out->count].length = length;
	out->count++;
	return 1;
}

/* One fragment: the device attributes this fragment owes, plus the peers
 * gathered so far. */
static int emit(ncfg_wg_messages_t *out, const ncfg_genl_family_t *family, uint32_t seq,
    const ncfg_wg_request_t *request, const ncfg_buf_t *peers, char *err, size_t err_size)
{
	ncfg_genl_header_t header;
	ncfg_buf_t attrs;
	ncfg_buf_t message;
	int first = out->count == 0;
	int ok;

	header.cmd = WG_CMD_SET_DEVICE;
	header.version = WG_GENL_VERSION;
	ncfg_buf_init(&attrs, 0);
	ok = device_attrs(&attrs, request, first, err, err_size);
	if (ok && request->replace_peers) {
		/*
		 * Written whenever the peer list is meant, empty list included --
		 * that is how the last peer is removed. It is not written at all
		 * otherwise: "and here are the peers: none" is a sentence worth
		 * not sending when the intent was to change a port.
		 */
		ncfg_wire_attr_put_nested(&attrs, WGDEVICE_A_PEERS, peers);
	}
	if (ok && ncfg_buf_failed(&attrs)) {
		ncfg_error_set(err, err_size, "the attributes for `%s` could not be built",
		    request->name);
		ok = 0;
	}
	if (ok) {
		ncfg_buf_init(&message, 0);
		/* `NLM_F_ACK`, because the kernel says nothing at all about a
		 * `SET_DEVICE` that worked, and a caller that did not ask for the
		 * acknowledgement cannot tell that from one it never read. */
		ok = ncfg_genl_build_request(&message, family->id, &header, NLM_F_ACK,
		    seq + (uint32_t)out->count, &attrs, err, err_size);
		if (ok) {
			ok = messages_append(out, &message, err, err_size);
		}
		ncfg_buf_free(&message);
	}
	ncfg_buf_free(&attrs);
	return ok;
}

int ncfg_wg_set_device_build(ncfg_wg_messages_t *out, const ncfg_genl_family_t *family,
    uint32_t seq, const ncfg_wg_request_t *request, char *err, size_t err_size)
{
	ncfg_buf_t peers;
	size_t index;
	size_t slot_index = 0;
	int ok = 1;

	if (!out) {
		ncfg_error_set(err, err_size, "a request needs somewhere to be built");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!family || !request || !request->config) {
		ncfg_error_set(err, err_size,
		    "a WireGuard request needs a resolved family and a configuration");
		return 0;
	}
	if (!ifname_fits(request->name, err, err_size)) {
		return 0;
	}

	ncfg_buf_init(&peers, 0);
	if (request->replace_peers) {
		for (index = 0; index < request->config->peer_count; index++) {
			const ncfg_wg_peer_t *peer = &request->config->peers[index];
			ncfg_buf_t entry;
			uint16_t slot;
			size_t need = 0;

			ncfg_buf_init(&entry, 0);
			ok = peer_entry(&entry, peer,
			    request->material ? &request->material[index] : NULL, err, err_size);
			if (ok) {
				/* What this peer costs the nest it goes into: its own
				 * bytes, an attribute header, and the padding after. */
				need = ncfg_wire_align4(NCFG_WIRE_RTATTR_HDR_LEN + entry.length);
				if (need > NCFG_WG_ATTR_VALUE_MAX) {
					/* No wire form at all, at any peer count: this
					 * one peer does not fit one attribute. Splitting
					 * a peer's allowed IPs across messages is a
					 * second mechanism the kernel allows and this
					 * does not implement; it is refused with the
					 * size instead of sent malformed. */
					ncfg_error_set(err, err_size,
					    "peer `%s` needs %zu bytes and one netlink "
					    "attribute carries %u", peer_label(peer), need,
					    (unsigned)NCFG_WG_ATTR_VALUE_MAX);
					ok = 0;
				}
			}
			if (ok && peers.length > 0
			    && peers.length + need > NCFG_WG_ATTR_VALUE_MAX) {
				/* The peer set has outgrown one message. Close this
				 * fragment and start another carrying only the name and
				 * more peers -- see wg.h for why the flags must not come
				 * with it. */
				ok = emit(out, family, seq, request, &peers, err, err_size);
				if (ok) {
					ncfg_buf_free(&peers);
					ncfg_buf_init(&peers, 0);
					slot_index = 0;
				}
			}
			if (ok) {
				ok = array_slot(slot_index, &slot, "peers", err, err_size);
			}
			if (ok) {
				ncfg_wire_attr_put_nested(&peers, slot, &entry);
				slot_index++;
			}
			ncfg_buf_free(&entry);
			if (!ok) {
				break;
			}
		}
	}
	if (ok) {
		ok = emit(out, family, seq, request, &peers, err, err_size);
	}
	ncfg_buf_free(&peers);
	if (!ok) {
		/* Half a configuration is worse than none: a caller that sent the
		 * fragments built before the failure would clear the device's peers
		 * and install some of them. */
		ncfg_wg_messages_free(out);
	}
	return ok;
}

void ncfg_wg_messages_free(ncfg_wg_messages_t *messages)
{
	size_t index;

	if (!messages) {
		return;
	}
	for (index = 0; index < messages->count; index++) {
		if (messages->message[index].bytes) {
			/*
			 * Scrubbed rather than merely freed: a `SET_DEVICE` carries
			 * the device's private key and a peer's preshared key in the
			 * clear, and freed heap is handed to whoever allocates next.
			 * `explicit_bzero` because a plain `memset` on memory about
			 * to be freed is exactly what a compiler is allowed to
			 * delete.
			 */
			explicit_bzero(messages->message[index].bytes,
			    messages->message[index].length);
			free(messages->message[index].bytes);
		}
	}
	free(messages->message);
	memset(messages, 0, sizeof(*messages));
}

int ncfg_wg_get_device_request(ncfg_buf_t *out, const ncfg_genl_family_t *family,
    uint32_t seq, const char *name, char *err, size_t err_size)
{
	ncfg_genl_header_t header;
	ncfg_buf_t attrs;
	int ok;

	if (!out || !family) {
		ncfg_error_set(err, err_size, "a request needs somewhere to be built");
		return 0;
	}
	if (!ifname_fits(name, err, err_size)) {
		return 0;
	}
	header.cmd = WG_CMD_GET_DEVICE;
	header.version = WG_GENL_VERSION;
	ncfg_buf_init(&attrs, 0);
	ncfg_wire_attr_put_str(&attrs, WGDEVICE_A_IFNAME, name);
	/* A dump, because one device's peers may need more than one reply --
	 * which is the same bound that splits the request going out. */
	ok = ncfg_genl_build_request(out, family->id, &header, NLM_F_DUMP, seq, &attrs,
	    err, err_size);
	ncfg_buf_free(&attrs);
	return ok;
}

/* ------------------------------------------------------------------------ *
 * Reading a GET_DEVICE reply
 * ------------------------------------------------------------------------ */

/*
 * A 32-octet key attribute.
 *
 * Exactly 32, where the Rust takes the first 32 of whatever arrived. The
 * kernel declares these `NLA_EXACT_LEN`, so anything else is a reply to throw
 * away rather than a key to read out of the front of one. The error says the
 * length and never the bytes.
 */
static int key_attr(const ncfg_wire_attr_t *attr, unsigned char *out, const char *what,
    char *err, size_t err_size)
{
	if (attr->length != NCFG_WG_KEY_LEN || !attr->value) {
		ncfg_error_set(err, err_size, "a %s is %u octets and this one has %zu", what,
		    (unsigned)NCFG_WG_KEY_LEN, attr->length);
		return 0;
	}
	memcpy(out, attr->value, NCFG_WG_KEY_LEN);
	return 1;
}

static int allowed_ip_parse(const ncfg_wire_attr_t *entry, ncfg_wg_allowed_ip_t *out,
    char *err, size_t err_size)
{
	ncfg_wire_attrs_t inside;
	ncfg_wire_attr_t attr;
	uint16_t family;

	memset(out, 0, sizeof(*out));
	ncfg_wire_attrs_start(&inside, entry->value, entry->length);
	if (ncfg_wire_attrs_find(&inside, WGALLOWEDIP_A_IPADDR, &attr, err, err_size)
	    != NCFG_WIRE_OK) {
		ncfg_error_set(err, err_size, "an allowed IP with no address");
		return 0;
	}
	if (!ncfg_wire_attr_ip(&attr, &out->address, err, err_size)) {
		return 0;
	}
	if (ncfg_wire_attrs_find(&inside, WGALLOWEDIP_A_FAMILY, &attr, NULL, 0)
	    == NCFG_WIRE_OK && ncfg_wire_attr_u16(&attr, &family, NULL, 0)) {
		/* The family is sent beside an address whose length already says
		 * which it is. They must agree: a reply where they do not is one
		 * this port does not understand, and picking either would be a
		 * guess about a route. */
		if ((int)family != out->address.family) {
			ncfg_error_set(err, err_size,
			    "an allowed IP says family %u and carries %zu bytes",
			    (unsigned)family, attr.length);
			return 0;
		}
	}
	if (ncfg_wire_attrs_find(&inside, WGALLOWEDIP_A_CIDR_MASK, &attr, err, err_size)
	    != NCFG_WIRE_OK) {
		ncfg_error_set(err, err_size, "an allowed IP with no prefix length");
		return 0;
	}
	return ncfg_wire_attr_u8(&attr, &out->prefix, err, err_size);
}

static int allowed_ips_parse(ncfg_wg_peer_state_t *peer, const ncfg_wire_attr_t *nest,
    char *err, size_t err_size)
{
	ncfg_wire_attrs_t walk;
	ncfg_wire_attr_t entry;
	void *grown;

	ncfg_wire_attrs_start(&walk, nest->value, nest->length);
	for (;;) {
		ncfg_wire_step_t step = ncfg_wire_attrs_next(&walk, &entry, err, err_size);

		if (step == NCFG_WIRE_END) {
			return 1;
		}
		if (step == NCFG_WIRE_BAD) {
			return 0;
		}
		grown = array_room(peer->allowed_ips, peer->allowed_ip_count,
		    sizeof(*peer->allowed_ips), "allowed IPs", err, err_size);
		if (!grown) {
			return 0;
		}
		peer->allowed_ips = grown;
		if (!allowed_ip_parse(&entry, &peer->allowed_ips[peer->allowed_ip_count],
		    err, err_size)) {
			return 0;
		}
		peer->allowed_ip_count++;
	}
}

static void peer_state_free(ncfg_wg_peer_state_t *peer)
{
	free(peer->allowed_ips);
	memset(peer, 0, sizeof(*peer));
}

static int peer_parse(ncfg_wg_peer_state_t *out, const ncfg_wire_attr_t *entry, char *err,
    size_t err_size)
{
	ncfg_wire_attrs_t inside;
	ncfg_wire_attr_t attr;
	ncfg_wire_step_t step;

	memset(out, 0, sizeof(*out));
	ncfg_wire_attrs_start(&inside, entry->value, entry->length);
	if (ncfg_wire_attrs_find(&inside, WGPEER_A_PUBLIC_KEY, &attr, err, err_size)
	    != NCFG_WIRE_OK) {
		ncfg_error_set(err, err_size, "a peer with no public key");
		return 0;
	}
	if (!key_attr(&attr, out->public_key, "public key", err, err_size)) {
		return 0;
	}

	step = ncfg_wire_attrs_find(&inside, WGPEER_A_PRESHARED_KEY, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step == NCFG_WIRE_OK) {
		unsigned char reported[NCFG_WG_KEY_LEN];
		unsigned char any = 0;
		size_t byte;

		if (!key_attr(&attr, reported, "preshared key", err, err_size)) {
			return 0;
		}
		/*
		 * An unset preshared key is reported as 32 zero octets, which is
		 * the kernel saying "none" rather than "the key is zero" -- an
		 * all-zero preshared key is not usable. The value goes no further
		 * than this block: what is kept is the flag.
		 */
		for (byte = 0; byte < sizeof(reported); byte++) {
			any |= reported[byte];
		}
		out->has_preshared_key = any != 0;
		explicit_bzero(reported, sizeof(reported));
	}

	step = ncfg_wire_attrs_find(&inside, WGPEER_A_ENDPOINT, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step == NCFG_WIRE_OK) {
		if (!endpoint_parse(attr.value, attr.length, &out->endpoint, &out->endpoint_port,
		    err, err_size)) {
			return 0;
		}
		out->has_endpoint = 1;
	}

	step = ncfg_wire_attrs_find(&inside, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, &attr,
	    err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step == NCFG_WIRE_OK && !ncfg_wire_attr_u16(&attr, &out->keepalive, err, err_size)) {
		return 0;
	}

	step = ncfg_wire_attrs_find(&inside, WGPEER_A_ALLOWEDIPS, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD
	    || (step == NCFG_WIRE_OK && !allowed_ips_parse(out, &attr, err, err_size))) {
		/* Half a peer is not a peer. The allowed IPs are allocated as they
		 * are read, so a refusal partway through has already taken memory
		 * -- released here rather than left for a caller that is about to
		 * return a failure and forget this ever existed. */
		peer_state_free(out);
		return 0;
	}
	return 1;
}

/*
 * Fold one peer into the state, coalescing a continuation.
 *
 * See wg.h: the kernel may write one peer across two messages, the second
 * carrying only its public key and the rest of its allowed IPs. Appending that
 * as a peer of its own reports one peer twice, each holding half a routing
 * table -- which a reconciler reads as a duplicate to remove.
 */
static int state_add_peer(ncfg_wg_state_t *state, ncfg_wg_peer_state_t *peer, char *err,
    size_t err_size)
{
	ncfg_wg_peer_state_t *last;
	void *grown;

	if (state->peer_count > 0) {
		last = &state->peers[state->peer_count - 1u];
		if (memcmp(last->public_key, peer->public_key, NCFG_WG_KEY_LEN) == 0) {
			size_t index;

			for (index = 0; index < peer->allowed_ip_count; index++) {
				grown = array_room(last->allowed_ips, last->allowed_ip_count,
				    sizeof(*last->allowed_ips), "allowed IPs", err, err_size);
				if (!grown) {
					return 0;
				}
				last->allowed_ips = grown;
				last->allowed_ips[last->allowed_ip_count] = peer->allowed_ips[index];
				last->allowed_ip_count++;
			}
			peer_state_free(peer);
			return 1;
		}
	}
	grown = array_room(state->peers, state->peer_count, sizeof(*state->peers), "peers",
	    err, err_size);
	if (!grown) {
		return 0;
	}
	state->peers = grown;
	state->peers[state->peer_count] = *peer;
	state->peer_count++;
	return 1;
}

int ncfg_wg_state_merge(ncfg_wg_state_t *state, const void *payload, size_t length,
    char *err, size_t err_size)
{
	ncfg_wire_attrs_t attrs;
	ncfg_wire_attrs_t walk;
	ncfg_wire_attr_t attr;
	ncfg_wire_step_t step;

	if (!state) {
		ncfg_error_set(err, err_size, "a device state needs somewhere to go");
		return 0;
	}
	if (!ncfg_genl_payload_attrs(payload, length, &attrs, err, err_size)) {
		return 0;
	}

	step = ncfg_wire_attrs_find(&attrs, WGDEVICE_A_PUBLIC_KEY, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step == NCFG_WIRE_OK) {
		/* The public key the kernel derived from the private one. The
		 * private key is never reported back, which is what makes an
		 * observation of a device safe to keep. */
		if (!key_attr(&attr, state->public_key, "public key", err, err_size)) {
			return 0;
		}
		state->has_public_key = 1;
	}

	step = ncfg_wire_attrs_find(&attrs, WGDEVICE_A_LISTEN_PORT, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step == NCFG_WIRE_OK) {
		if (!ncfg_wire_attr_u16(&attr, &state->listen_port, err, err_size)) {
			return 0;
		}
		state->has_listen_port = 1;
	}

	step = ncfg_wire_attrs_find(&attrs, WGDEVICE_A_FWMARK, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step == NCFG_WIRE_OK) {
		if (!ncfg_wire_attr_u32(&attr, &state->fwmark, err, err_size)) {
			return 0;
		}
		state->has_fwmark = 1;
	}

	step = ncfg_wire_attrs_find(&attrs, WGDEVICE_A_PEERS, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step == NCFG_WIRE_END) {
		return 1;
	}
	ncfg_wire_attrs_start(&walk, attr.value, attr.length);
	for (;;) {
		ncfg_wire_attr_t entry;
		ncfg_wg_peer_state_t peer;

		step = ncfg_wire_attrs_next(&walk, &entry, err, err_size);
		if (step == NCFG_WIRE_END) {
			return 1;
		}
		if (step == NCFG_WIRE_BAD) {
			return 0;
		}
		if (!peer_parse(&peer, &entry, err, err_size)) {
			return 0;
		}
		if (!state_add_peer(state, &peer, err, err_size)) {
			peer_state_free(&peer);
			return 0;
		}
	}
}

void ncfg_wg_state_free(ncfg_wg_state_t *state)
{
	size_t index;

	if (!state) {
		return;
	}
	for (index = 0; index < state->peer_count; index++) {
		free(state->peers[index].allowed_ips);
	}
	free(state->peers);
	memset(state, 0, sizeof(*state));
}
