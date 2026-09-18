/*
 * netlink_test.c -- the socket and the dumps, without a kernel.
 *
 * WHY THERE IS NO SOCKET IN HERE BY DEFAULT
 *   This suite runs on the machine netcfgd configures. A test that binds a
 *   multicast group and waits is a test that hangs on somebody's desk, and a
 *   test that dumps the running kernel asserts against whatever that machine
 *   happens to be doing at the time. So the decoding is driven by bytes this
 *   file wrote, and the receive loop is driven by a fake datagram source --
 *   which can do the two things a kernel will not do on demand: hand back a
 *   datagram larger than the buffer, and hand back one past the ceiling.
 *
 *   There is one live check, at the bottom, behind `NCFG_NETLINK_LIVE=1`. It
 *   opens a route socket with no groups, dumps links twice into buffers of two
 *   sizes and compares, which is the Rust's own growth test. It is opt-in
 *   because reading is safe in principle and a hang is not, and it says
 *   loudly that it was skipped rather than passing silently.
 *
 * WHAT THE FAKE SOURCE BUYS, PRECISELY
 *   The defect this module exists to keep fixed is a reply too big for its
 *   buffer (0183). The first fix doubled the buffer and re-sent the request,
 *   which left the truncated reply's datagrams queued to be read against the
 *   new sequence number; it passed once and returned an empty dump on the next
 *   run. Driving the loop with a queue of datagrams makes both halves
 *   checkable without privilege: the same dump must come back whatever size
 *   buffer it was read into, and the source must be asked for exactly the
 *   datagrams that were queued -- a re-send would show up as a second read of
 *   the first one.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/netlink.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The two kernel headers `netlink.h` deliberately does not pull in: this file
 * builds the bytes a kernel would send, so it needs the attribute numbers for
 * tunnels and bridge VLANs that `dump.c` reads. */
#include <linux/if_bridge.h>
#include <linux/if_tunnel.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-58s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* A walk that will not run for ever even if the code under test would. The
 * failure this file is mostly about does not look like a crash, it looks like
 * a hang in a privileged daemon, and a test that hangs reports nothing. */
#define WALK_CAP 10000u

/* ------------------------------------------------------------------------ */
/* Building the bytes a kernel would send.                                  */
/* ------------------------------------------------------------------------ */

/* One complete message, appended to `out`. `attrs` and `body` may be NULL. */
static void append_message(ncfg_buf_t *out, uint16_t kind, uint32_t seq, const ncfg_buf_t *body,
    const ncfg_buf_t *attrs)
{
	ncfg_buf_t one;

	ncfg_buf_init(&one, 0);
	if (!ncfg_wire_build_request(&one, kind, 0, seq, body, attrs, NULL, 0)) {
		out->failed = 1;
	} else {
		ncfg_buf_add(out, one.data, one.length);
	}
	ncfg_buf_free(&one);
}

static void append_ifinfo(ncfg_buf_t *body, uint8_t family, int32_t index, uint32_t flags)
{
	ncfg_wire_ifinfo_t info;

	memset(&info, 0, sizeof(info));
	info.family = family;
	info.index = index;
	info.flags = flags;
	ncfg_wire_ifinfo_encode(&info, body);
}

/* A link message with a name and whatever else the caller put in `attrs`. */
static void append_link(ncfg_buf_t *out, uint32_t seq, int32_t index, uint32_t flags,
    const ncfg_buf_t *attrs)
{
	ncfg_buf_t body;

	ncfg_buf_init(&body, 0);
	append_ifinfo(&body, 0, index, flags);
	append_message(out, RTM_NEWLINK, seq, &body, attrs);
	ncfg_buf_free(&body);
}

static void append_done(ncfg_buf_t *out, uint32_t seq)
{
	append_message(out, NLMSG_DONE, seq, NULL, NULL);
}

/*
 * An `NLMSG_ERROR`: the negated errno, and then the header of the request that
 * caused it -- which is where the failure sentence learns what was refused.
 */
static void append_error(ncfg_buf_t *out, uint32_t seq, int32_t code, uint16_t refused)
{
	ncfg_buf_t         body;
	ncfg_wire_header_t original;
	uint32_t           bits;
	int32_t            negated = -code;

	ncfg_buf_init(&body, 0);
	memcpy(&bits, &negated, sizeof(bits));
	ncfg_buf_add(&body, &bits, sizeof(bits));
	memset(&original, 0, sizeof(original));
	original.len = NCFG_WIRE_NLMSG_HDR_LEN;
	original.kind = refused;
	original.seq = seq;
	ncfg_wire_header_encode(&original, &body);
	append_message(out, NLMSG_ERROR, seq, &body, NULL);
	ncfg_buf_free(&body);
}

/* The first message of a buffer, decoded far enough to hand its payload to a
 * dump. */
static int first_payload(const ncfg_buf_t *buffer, ncfg_wire_message_t *out)
{
	ncfg_wire_messages_t walk;

	ncfg_wire_messages_start(&walk, buffer->data, buffer->length);
	return ncfg_wire_messages_next(&walk, out, NULL, 0) == NCFG_WIRE_OK;
}

/* Decode the first link message in `buffer`. */
static int decode_first_link(const ncfg_buf_t *buffer, ncfg_link_record_t *out, char *err,
    size_t err_size)
{
	ncfg_wire_message_t message;

	if (!first_payload(buffer, &message)) {
		ncfg_error_set(err, err_size, "the test built a buffer with no message in it");
		return 0;
	}
	return ncfg_dump_link(message.payload, message.payload_length, out, err, err_size);
}

/* ------------------------------------------------------------------------ */
/* The fake datagram source.                                                */
/* ------------------------------------------------------------------------ */

#define FAKE_MAX 8u

typedef struct {
	const uint8_t *bytes;
	size_t         length;
	/* Who sent it: 0 for the kernel, anything else for a process on this
	 * machine -- which is a thing any local user can be, since
	 * `/proc/net/netlink` is world-readable and lists the port id. */
	uint32_t       from;
	/* What the peek claims instead of the truth, for the two cases a kernel
	 * will not produce: a reply past the ceiling, and a datagram that grew
	 * between the peek and the read. 0 means tell the truth. */
	size_t         peek_says;
	/* Make the peek claim the kernel and the read tell the truth, so that
	 * the check on the call which actually delivers the bytes is reachable
	 * on its own rather than always shadowed by the peek's. */
	int            quiet_on_peek;
} datagram_t;

typedef struct {
	datagram_t datagrams[FAKE_MAX];
	size_t     count;
	size_t     at;
	/* How many times each half of the protocol was asked. A re-send would
	 * show up here as a second read of a datagram already consumed. */
	size_t     peeks;
	size_t     reads;
	/* The errno once the queue is empty. A real socket answers a receive
	 * with no reply by timing out. */
	int        code;
} fake_t;

static ssize_t fake_recv(void *context, void *bytes, size_t length, int peek, uint32_t *from)
{
	fake_t           *fake = context;
	const datagram_t *one;
	size_t            copy;

	/* Not the kernel until the queue says so, which is what the real source
	 * does on every path including the failing one. */
	*from = UINT32_MAX;
	if (fake->at >= fake->count) {
		errno = fake->code ? fake->code : EAGAIN;
		return -1;
	}
	one = &fake->datagrams[fake->at];
	*from = one->from;
	copy = one->length < length ? one->length : length;
	if (copy) {
		memcpy(bytes, one->bytes, copy);
	}
	if (peek) {
		fake->peeks++;
		if (one->quiet_on_peek) {
			*from = 0;
		}
		return (ssize_t)(one->peek_says ? one->peek_says : one->length);
	}
	fake->reads++;
	fake->at++;
	return (ssize_t)one->length;
}

/* Queue a datagram from a given sender. The kernel's port id is 0. */
static void queue_from(fake_t *fake, const ncfg_buf_t *buffer, uint32_t from)
{
	if (fake->count >= FAKE_MAX) {
		return;
	}
	fake->datagrams[fake->count].bytes = (const uint8_t *)buffer->data;
	fake->datagrams[fake->count].length = buffer->length;
	fake->datagrams[fake->count].from = from;
	fake->datagrams[fake->count].peek_says = 0;
	fake->datagrams[fake->count].quiet_on_peek = 0;
	fake->count++;
}

static void queue(fake_t *fake, const ncfg_buf_t *buffer)
{
	queue_from(fake, buffer, 0);
}

/* ------------------------------------------------------------------------ */

int main(void)
{
	char err[NCFG_ERROR_MAX];

	/* --- a link message, the ordinary case ---------------------------- */
	{
		ncfg_buf_t         attrs;
		ncfg_buf_t         buffer;
		ncfg_link_record_t link;
		static const uint8_t mac[6] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 };

		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0");
		ncfg_wire_attr_put_u32(&attrs, IFLA_MTU, 1500);
		ncfg_wire_attr_put(&attrs, IFLA_ADDRESS, mac, sizeof(mac));
		ncfg_wire_attr_put_u8(&attrs, IFLA_CARRIER, 1);
		/* IFF_UP | IFF_RUNNING */
		append_link(&buffer, 1, 3, 0x41u, &attrs);

		check(decode_first_link(&buffer, &link, err, sizeof(err)), "a link message decodes");
		check(strcmp(link.name, "eth0") == 0, "and carries its name");
		check(link.index == 3u, "and its index");
		check(link.mtu == 1500u, "and its mtu");
		check(link.up && link.carrier, "and is up with carrier");
		check(link.has_mac && strcmp(link.mac, "de:ad:be:ef:00:01") == 0,
		    "and its hardware address");
		check(link.kind[0] == '\0', "and no kind, which a plain device has");
		check(link.altname_count == 0, "and no alternative names");
		ncfg_link_record_free(&link);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&buffer);
	}

	/* --- the kind lives one level down -------------------------------- */
	{
		ncfg_buf_t         nest;
		ncfg_buf_t         attrs;
		ncfg_buf_t         buffer;
		ncfg_link_record_t link;

		ncfg_buf_init(&nest, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_str(&nest, IFLA_INFO_KIND, "bridge");
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "br0");
		ncfg_wire_attr_put_nested(&attrs, IFLA_LINKINFO, &nest);
		append_link(&buffer, 1, 4, 0, &attrs);

		check(decode_first_link(&buffer, &link, err, sizeof(err)) &&
		    strcmp(link.kind, "bridge") == 0, "a nested link kind decodes");
		ncfg_link_record_free(&link);
		ncfg_buf_free(&nest);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&buffer);
	}

	/*
	 * --- carrier and admin state are different questions ---------------
	 *
	 * Conflating them is how a plan decides to reconfigure a perfectly good
	 * interface whose cable is out, or ignores one that is administratively
	 * down. The third case is the one with no attribute at all, which is an
	 * older kernel and not a machine with every cable pulled.
	 */
	{
		ncfg_buf_t         attrs;
		ncfg_buf_t         buffer;
		ncfg_link_record_t link;

		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0");
		ncfg_wire_attr_put_u8(&attrs, IFLA_CARRIER, 0);
		append_link(&buffer, 1, 5, 0x1u, &attrs);
		check(decode_first_link(&buffer, &link, err, sizeof(err)) && link.up &&
		    !link.carrier, "up with no carrier is up, and has no carrier");
		ncfg_link_record_free(&link);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&buffer);

		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0");
		append_link(&buffer, 1, 5, 0, &attrs);
		check(decode_first_link(&buffer, &link, err, sizeof(err)) && !link.up &&
		    link.carrier, "and a link that reports no carrier at all has one");
		ncfg_link_record_free(&link);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&buffer);
	}

	/*
	 * --- every alternative name, not the first -------------------------
	 *
	 * netcfgd stamps one on every link it creates, which is how ownership
	 * survives losing `/run` (0136). A search stops at the first match and
	 * would read a device with three names as a device with one -- and
	 * netcfgd's own is not guaranteed to be first.
	 */
	{
		ncfg_buf_t         nest;
		ncfg_buf_t         attrs;
		ncfg_buf_t         buffer;
		ncfg_link_record_t link;

		ncfg_buf_init(&nest, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_str(&nest, IFLA_ALT_IFNAME, "enp0s31f6");
		ncfg_wire_attr_put_str(&nest, IFLA_ALT_IFNAME, "netcfgd:uplink");
		ncfg_wire_attr_put_str(&nest, IFLA_ALT_IFNAME, "wired");
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0");
		ncfg_wire_attr_put_nested(&attrs, IFLA_PROP_LIST, &nest);
		append_link(&buffer, 1, 6, 0, &attrs);

		check(decode_first_link(&buffer, &link, err, sizeof(err)), "a link with three names");
		check(link.altname_count == 3u, "keeps all three, not the first");
		check(link.altname_count == 3u && strcmp(link.altnames[1], "netcfgd:uplink") == 0,
		    "and netcfgd's own marker is among them");
		ncfg_link_record_free(&link);
		check(link.altname_count == 0 && link.altnames == NULL,
		    "and freeing a record leaves it empty");
		ncfg_link_record_free(&link);
		check(1, "and freeing it twice is nothing");
		ncfg_buf_free(&nest);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&buffer);
	}

	/*
	 * --- a bridge's priority is two bytes ------------------------------
	 *
	 * `IFLA_BR_PRIORITY` is a `__u16`, and a 32-bit read of it returns
	 * nothing -- so this field read as absent on every kernel, always.
	 * Nothing noticed because the planner did not compare it; the moment it
	 * did, an apply set the priority and the observation still said absent,
	 * so the plan asked for it again for ever. The `ageing_time` beside it
	 * is the control: a genuine `u32` in the same blob, so a test that read
	 * both at one width would fail on whichever it chose.
	 */
	{
		ncfg_buf_t         data;
		ncfg_buf_t         nest;
		ncfg_buf_t         attrs;
		ncfg_buf_t         buffer;
		ncfg_link_record_t link;
		uint16_t           priority = 200;

		ncfg_buf_init(&data, 0);
		ncfg_buf_init(&nest, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_u32(&data, IFLA_BR_AGEING_TIME, 30000);
		ncfg_wire_attr_put(&data, IFLA_BR_PRIORITY, &priority, sizeof(priority));
		ncfg_wire_attr_put_u32(&data, IFLA_BR_STP_STATE, 1);
		ncfg_wire_attr_put_u8(&data, IFLA_BR_VLAN_FILTERING, 1);
		ncfg_wire_attr_put_str(&nest, IFLA_INFO_KIND, "bridge");
		ncfg_wire_attr_put_nested(&nest, IFLA_INFO_DATA, &data);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "br0");
		ncfg_wire_attr_put_nested(&attrs, IFLA_LINKINFO, &nest);
		append_link(&buffer, 1, 7, 0, &attrs);

		check(decode_first_link(&buffer, &link, err, sizeof(err)) && link.has_bridge,
		    "a bridge reports its own settings");
		check(link.bridge.has_priority && link.bridge.priority == 200,
		    "and a two-byte priority is read");
		check(link.bridge.has_ageing_time && link.bridge.ageing_time == 30000u,
		    "and the u32 control beside it still reads");
		check(link.bridge.stp && link.bridge.vlan_filtering,
		    "and stp state and vlan filtering are booleans");
		check(!link.has_vlan && !link.has_vxlan && !link.has_bond,
		    "and no other kind's nest was decoded out of it");
		ncfg_link_record_free(&link);
		ncfg_buf_free(&data);
		ncfg_buf_free(&nest);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&buffer);
	}

	/*
	 * --- a VXLAN's underlay is in its nest and nowhere else ------------
	 *
	 * Every other kind reports it in the outer `IFLA_LINK`, and the two
	 * disagreeing is how a parent came to be sent to the wrong place for
	 * years.
	 */
	{
		ncfg_buf_t         data;
		ncfg_buf_t         nest;
		ncfg_buf_t         attrs;
		ncfg_buf_t         buffer;
		ncfg_link_record_t link;
		uint16_t           port = 0x12b5; /* 4789, big-endian on the wire */
		uint8_t            wire_port[2] = { 0x12, 0xb5 };
		ncfg_wire_ip_t     group;
		ncfg_wire_ip_t     zero;

		(void)port;
		memset(&zero, 0, sizeof(zero));
		zero.family = AF_INET;
		check(ncfg_wire_ip_parse("239.1.1.1", &group, err, sizeof(err)),
		    "a multicast group parses");

		ncfg_buf_init(&data, 0);
		ncfg_buf_init(&nest, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_u32(&data, IFLA_VXLAN_ID, 42);
		ncfg_wire_attr_put_u32(&data, IFLA_VXLAN_LINK, 9);
		ncfg_wire_attr_put_ip(&data, IFLA_VXLAN_GROUP, &group);
		/* An all-zero local endpoint is how the kernel spells "none", and
		 * it sends one for a VXLAN that was given neither. */
		ncfg_wire_attr_put_ip(&data, IFLA_VXLAN_LOCAL, &zero);
		ncfg_wire_attr_put(&data, IFLA_VXLAN_PORT, wire_port, sizeof(wire_port));
		ncfg_wire_attr_put_str(&nest, IFLA_INFO_KIND, "vxlan");
		ncfg_wire_attr_put_nested(&nest, IFLA_INFO_DATA, &data);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "vx0");
		ncfg_wire_attr_put_nested(&attrs, IFLA_LINKINFO, &nest);
		append_link(&buffer, 1, 8, 0, &attrs);

		check(decode_first_link(&buffer, &link, err, sizeof(err)) && link.has_vxlan,
		    "a vxlan reports its own settings");
		check(link.vxlan.has_id && link.vxlan.id == 42u, "and its network identifier");
		check(link.has_parent && link.parent == 9u,
		    "and its underlay becomes the parent, from the nest");
		check(link.vxlan.remote.family == AF_INET, "and its group is read");
		check(link.vxlan.local.family == AF_UNSPEC,
		    "while an all-zero endpoint is absence, not 0.0.0.0");
		check(link.vxlan.has_port && link.vxlan.port == 4789u,
		    "and the port is big-endian, like every port on the wire");
		ncfg_link_record_free(&link);

		/* And the outer attribute wins where a kind reports both. */
		ncfg_wire_attr_put_u32(&attrs, IFLA_LINK, 3);
		ncfg_buf_free(&buffer);
		ncfg_buf_init(&buffer, 0);
		append_link(&buffer, 1, 8, 0, &attrs);
		check(decode_first_link(&buffer, &link, err, sizeof(err)) && link.has_parent &&
		    link.parent == 3u, "and the outer IFLA_LINK wins where there is one");
		ncfg_link_record_free(&link);
		ncfg_buf_free(&data);
		ncfg_buf_free(&nest);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&buffer);
	}

	/*
	 * --- a geneve tunnel's TTL is attribute 3 --------------------------
	 *
	 * The Rust wrote 4 here, which is `IFLA_GENEVE_TOS` -- and the writer
	 * said the same, so the two agreed with each other and with nothing
	 * else, and the plan converged on a tunnel whose TTL had never been
	 * set. The second half of this case is the proof: a TOS attribute alone
	 * must leave the TTL absent.
	 */
	{
		ncfg_buf_t         data;
		ncfg_buf_t         nest;
		ncfg_buf_t         attrs;
		ncfg_buf_t         buffer;
		ncfg_link_record_t link;
		ncfg_wire_ip_t     remote;

		check(ncfg_wire_ip_parse("192.0.2.7", &remote, err, sizeof(err)),
		    "a tunnel endpoint parses");
		ncfg_buf_init(&data, 0);
		ncfg_buf_init(&nest, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_u32(&data, IFLA_GENEVE_ID, 5000);
		ncfg_wire_attr_put_ip(&data, IFLA_GENEVE_REMOTE, &remote);
		ncfg_wire_attr_put_u8(&data, IFLA_GENEVE_TTL, 64);
		ncfg_wire_attr_put_str(&nest, IFLA_INFO_KIND, "geneve");
		ncfg_wire_attr_put_nested(&nest, IFLA_INFO_DATA, &data);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "gnv0");
		ncfg_wire_attr_put_nested(&attrs, IFLA_LINKINFO, &nest);
		append_link(&buffer, 1, 9, 0, &attrs);

		check(decode_first_link(&buffer, &link, err, sizeof(err)) && link.has_tunnel,
		    "a geneve tunnel reports its endpoints");
		check(link.tunnel.has_ttl && link.tunnel.ttl == 64u, "and its TTL, from attribute 3");
		check(link.tunnel.has_key && link.tunnel.key == 5000u,
		    "and its VNI, which the model spells as the key");
		check(link.tunnel.remote.family == AF_INET, "and its remote endpoint");
		check(link.tunnel.local.family == AF_UNSPEC, "and has no local one to set");
		ncfg_link_record_free(&link);

		ncfg_buf_free(&data);
		ncfg_buf_free(&buffer);
		ncfg_buf_free(&nest);
		ncfg_buf_init(&data, 0);
		ncfg_buf_init(&nest, 0);
		ncfg_buf_init(&buffer, 0);
		/* IFLA_GENEVE_TOS is 4, which is what the Rust read as the TTL. */
		ncfg_wire_attr_put_u8(&data, IFLA_GENEVE_TOS, 64);
		ncfg_wire_attr_put_str(&nest, IFLA_INFO_KIND, "geneve");
		ncfg_wire_attr_put_nested(&nest, IFLA_INFO_DATA, &data);
		ncfg_buf_free(&attrs);
		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "gnv1");
		ncfg_wire_attr_put_nested(&attrs, IFLA_LINKINFO, &nest);
		append_link(&buffer, 1, 9, 0, &attrs);
		check(decode_first_link(&buffer, &link, err, sizeof(err)) && link.has_tunnel &&
		    !link.tunnel.has_ttl, "and a TOS attribute is not a TTL");
		ncfg_link_record_free(&link);
		ncfg_buf_free(&data);
		ncfg_buf_free(&nest);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&buffer);
	}

	/*
	 * --- a GRE key means nothing without its flag ----------------------
	 *
	 * The kernel emits `IKEY` whether or not the tunnel has a key, so a zero
	 * there is either no key or the key `0` -- which a document may
	 * legitimately ask for. Reading the flag is what keeps `key = 0` from
	 * differing from itself for ever.
	 */
	{
		ncfg_buf_t         data;
		ncfg_buf_t         nest;
		ncfg_buf_t         attrs;
		ncfg_buf_t         buffer;
		ncfg_link_record_t link;
		uint8_t            no_flags[2] = { 0x00, 0x00 };
		uint8_t            key_flag[2] = { 0x20, 0x00 };
		uint8_t            key[4] = { 0x00, 0x00, 0x00, 0x00 };

		ncfg_buf_init(&data, 0);
		ncfg_buf_init(&nest, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put(&data, IFLA_GRE_IFLAGS, no_flags, sizeof(no_flags));
		ncfg_wire_attr_put(&data, IFLA_GRE_IKEY, key, sizeof(key));
		ncfg_wire_attr_put_u8(&data, IFLA_GRE_TTL, 255);
		ncfg_wire_attr_put_str(&nest, IFLA_INFO_KIND, "gre");
		ncfg_wire_attr_put_nested(&nest, IFLA_INFO_DATA, &data);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "gre0");
		ncfg_wire_attr_put_nested(&attrs, IFLA_LINKINFO, &nest);
		append_link(&buffer, 1, 10, 0, &attrs);
		check(decode_first_link(&buffer, &link, err, sizeof(err)) && link.has_tunnel &&
		    !link.tunnel.has_key, "a GRE key with no flag set is no key");
		check(link.tunnel.has_ttl && link.tunnel.ttl == 255u, "while its TTL still reads");
		ncfg_link_record_free(&link);

		ncfg_buf_free(&data);
		ncfg_buf_free(&nest);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&buffer);
		ncfg_buf_init(&data, 0);
		ncfg_buf_init(&nest, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put(&data, IFLA_GRE_IFLAGS, key_flag, sizeof(key_flag));
		ncfg_wire_attr_put(&data, IFLA_GRE_IKEY, key, sizeof(key));
		ncfg_wire_attr_put_str(&nest, IFLA_INFO_KIND, "gre");
		ncfg_wire_attr_put_nested(&nest, IFLA_INFO_DATA, &data);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "gre0");
		ncfg_wire_attr_put_nested(&attrs, IFLA_LINKINFO, &nest);
		append_link(&buffer, 1, 10, 0, &attrs);
		check(decode_first_link(&buffer, &link, err, sizeof(err)) && link.has_tunnel &&
		    link.tunnel.has_key && link.tunnel.key == 0u,
		    "and the key 0 with the flag set is the key 0");
		ncfg_link_record_free(&link);
		ncfg_buf_free(&data);
		ncfg_buf_free(&nest);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&buffer);
	}

	/*
	 * --- which numbering a tunnel kind is read with --------------------
	 *
	 * Matched exactly and not by substring: the kind comes from the kernel
	 * and could be any link kind on this machine, and reading one family's
	 * nest with another's constants is how a tunnel comes to report somebody
	 * else's field.
	 */
	{
		check(ncfg_tunnel_family("gre") == NCFG_TUNNEL_GRE &&
		    ncfg_tunnel_family("gretap") == NCFG_TUNNEL_GRE &&
		    ncfg_tunnel_family("ip6gre") == NCFG_TUNNEL_GRE, "the three GRE kinds");
		check(ncfg_tunnel_family("ipip") == NCFG_TUNNEL_IP &&
		    ncfg_tunnel_family("sit") == NCFG_TUNNEL_IP &&
		    ncfg_tunnel_family("ip6tnl") == NCFG_TUNNEL_IP, "the three ip tunnel kinds");
		check(ncfg_tunnel_family("geneve") == NCFG_TUNNEL_GENEVE, "and geneve on its own");
		check(ncfg_tunnel_family("wireguard") == NCFG_TUNNEL_NONE &&
		    ncfg_tunnel_family("gre0") == NCFG_TUNNEL_NONE &&
		    ncfg_tunnel_family("") == NCFG_TUNNEL_NONE &&
		    ncfg_tunnel_family(NULL) == NCFG_TUNNEL_NONE,
		    "and a kind this does not know is nothing, not a near miss");
	}

	/* --- a VLAN's tag protocol is an ethertype ------------------------- */
	{
		ncfg_buf_t         data;
		ncfg_buf_t         nest;
		ncfg_buf_t         attrs;
		ncfg_buf_t         buffer;
		ncfg_link_record_t link;
		uint16_t           id = 42;
		uint8_t            protocol[2] = { 0x88, 0xa8 };

		ncfg_buf_init(&data, 0);
		ncfg_buf_init(&nest, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put(&data, IFLA_VLAN_ID, &id, sizeof(id));
		ncfg_wire_attr_put(&data, IFLA_VLAN_PROTOCOL, protocol, sizeof(protocol));
		ncfg_wire_attr_put_str(&nest, IFLA_INFO_KIND, "vlan");
		ncfg_wire_attr_put_nested(&nest, IFLA_INFO_DATA, &data);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0.42");
		ncfg_wire_attr_put_u32(&attrs, IFLA_LINK, 3);
		ncfg_wire_attr_put_nested(&attrs, IFLA_LINKINFO, &nest);
		append_link(&buffer, 1, 11, 0, &attrs);

		check(decode_first_link(&buffer, &link, err, sizeof(err)) && link.has_vlan &&
		    link.vlan.has_id && link.vlan.id == 42u, "a vlan reports its id");
		check(link.vlan.has_protocol && link.vlan.protocol == 0x88a8u,
		    "and its tag protocol big-endian, as an ethertype");
		check(link.has_parent && link.parent == 3u, "and rides on the outer IFLA_LINK");
		ncfg_link_record_free(&link);
		ncfg_buf_free(&data);
		ncfg_buf_free(&nest);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&buffer);
	}

	/* --- a bond, and a macvlan, each with its own numbering ------------ */
	{
		ncfg_buf_t         data;
		ncfg_buf_t         nest;
		ncfg_buf_t         attrs;
		ncfg_buf_t         buffer;
		ncfg_link_record_t link;

		ncfg_buf_init(&data, 0);
		ncfg_buf_init(&nest, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_u8(&data, IFLA_BOND_MODE, 4);
		ncfg_wire_attr_put_u32(&data, IFLA_BOND_MIIMON, 100);
		ncfg_wire_attr_put_str(&nest, IFLA_INFO_KIND, "bond");
		ncfg_wire_attr_put_nested(&nest, IFLA_INFO_DATA, &data);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "bond0");
		ncfg_wire_attr_put_nested(&attrs, IFLA_LINKINFO, &nest);
		append_link(&buffer, 1, 12, 0, &attrs);
		check(decode_first_link(&buffer, &link, err, sizeof(err)) && link.has_bond &&
		    link.bond.has_mode && link.bond.mode == 4u && link.bond.has_miimon &&
		    link.bond.miimon == 100u, "a bond reports the two settings netcfgd sets");
		check(!link.has_bridge, "and a bond's nest is not read as a bridge's");
		ncfg_link_record_free(&link);
		ncfg_buf_free(&data);
		ncfg_buf_free(&nest);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&buffer);

		ncfg_buf_init(&data, 0);
		ncfg_buf_init(&nest, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_u32(&data, IFLA_MACVLAN_MODE, 16);
		ncfg_wire_attr_put_str(&nest, IFLA_INFO_KIND, "macvlan");
		ncfg_wire_attr_put_nested(&nest, IFLA_INFO_DATA, &data);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "mv0");
		ncfg_wire_attr_put_nested(&attrs, IFLA_LINKINFO, &nest);
		append_link(&buffer, 1, 13, 0, &attrs);
		check(decode_first_link(&buffer, &link, err, sizeof(err)) && link.has_macvlan &&
		    link.macvlan.has_mode && link.macvlan.mode == 16u,
		    "a macvlan's mode is a flag value, kept as the number");
		ncfg_link_record_free(&link);
		ncfg_buf_free(&data);
		ncfg_buf_free(&nest);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&buffer);
	}

	/*
	 * --- an IPv6 token, two levels down --------------------------------
	 *
	 * All-zero is how the kernel spells "no token", and reading that as an
	 * address would make every interface look as though it had one.
	 */
	{
		ncfg_buf_t         inet6;
		ncfg_buf_t         spec;
		ncfg_buf_t         attrs;
		ncfg_buf_t         buffer;
		ncfg_link_record_t link;
		ncfg_wire_ip_t     token;
		ncfg_wire_ip_t     none;
		char               text[NCFG_WIRE_IP_TEXT_MAX];

		check(ncfg_wire_ip_parse("::5", &token, err, sizeof(err)), "a token parses");
		check(ncfg_wire_ip_parse("::", &none, err, sizeof(err)), "and so does the empty one");

		ncfg_buf_init(&inet6, 0);
		ncfg_buf_init(&spec, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_ip(&inet6, IFLA_INET6_TOKEN, &token);
		ncfg_wire_attr_put_nested(&spec, 10, &inet6);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0");
		ncfg_wire_attr_put_nested(&attrs, IFLA_AF_SPEC, &spec);
		append_link(&buffer, 1, 14, 0, &attrs);
		check(decode_first_link(&buffer, &link, err, sizeof(err)) &&
		    link.ipv6_token.family == AF_INET6 &&
		    ncfg_wire_ip_text(&link.ipv6_token, text, sizeof(text), NULL, 0) &&
		    strcmp(text, "::5") == 0, "an ip token is read out of AF_SPEC");
		ncfg_link_record_free(&link);
		ncfg_buf_free(&inet6);
		ncfg_buf_free(&spec);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&buffer);

		ncfg_buf_init(&inet6, 0);
		ncfg_buf_init(&spec, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_ip(&inet6, IFLA_INET6_TOKEN, &none);
		ncfg_wire_attr_put_nested(&spec, 10, &inet6);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0");
		ncfg_wire_attr_put_nested(&attrs, IFLA_AF_SPEC, &spec);
		append_link(&buffer, 1, 14, 0, &attrs);
		check(decode_first_link(&buffer, &link, err, sizeof(err)) &&
		    link.ipv6_token.family == AF_UNSPEC, "and `::` is no token, not the address ::");
		ncfg_link_record_free(&link);
		ncfg_buf_free(&inet6);
		ncfg_buf_free(&spec);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&buffer);
	}

	/* --- a hardware address that is not a MAC ------------------------- */
	{
		ncfg_buf_t         attrs;
		ncfg_buf_t         buffer;
		ncfg_link_record_t link;
		uint8_t            infiniband[20];

		memset(infiniband, 0x11, sizeof(infiniband));
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "ib0");
		ncfg_wire_attr_put(&attrs, IFLA_ADDRESS, infiniband, sizeof(infiniband));
		append_link(&buffer, 1, 15, 0, &attrs);
		check(decode_first_link(&buffer, &link, err, sizeof(err)) && !link.has_mac &&
		    link.mac[0] == '\0',
		    "a 20-byte link address is not reported as a MAC");
		ncfg_link_record_free(&link);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&buffer);
	}

	/* --- a link message with no name is refused ----------------------- */
	{
		ncfg_buf_t         attrs;
		ncfg_buf_t         buffer;
		ncfg_link_record_t link;

		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_u32(&attrs, IFLA_MTU, 1500);
		append_link(&buffer, 1, 16, 0, &attrs);
		err[0] = '\0';
		check(!decode_first_link(&buffer, &link, err, sizeof(err)) && err[0] != '\0',
		    "a link message with no name is refused, with a sentence");
		ncfg_link_record_free(&link);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&buffer);
	}

	/* --- addresses ---------------------------------------------------- */
	{
		ncfg_buf_t            attrs;
		ncfg_buf_t            body;
		ncfg_buf_t            buffer;
		ncfg_wire_ifaddr_t    info;
		ncfg_wire_message_t   message;
		ncfg_address_record_t address;
		ncfg_wire_ip_t        local;
		ncfg_wire_ip_t        peer;
		char                  text[NCFG_CIDR_TEXT_MAX];

		check(ncfg_wire_ip_parse("192.168.1.10", &local, err, sizeof(err)),
		    "an address parses");
		memset(&info, 0, sizeof(info));
		info.family = AF_INET;
		info.prefix_len = 24;
		info.index = 3;

		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&body, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_ip(&attrs, IFA_LOCAL, &local);
		ncfg_wire_attr_put_u8(&attrs, IFA_PROTO, NCFG_WIRE_RTPROT_NETCFGD);
		ncfg_wire_ifaddr_encode(&info, &body);
		append_message(&buffer, RTM_NEWADDR, 1, &body, &attrs);
		check(first_payload(&buffer, &message) &&
		    ncfg_dump_address(message.payload, message.payload_length, &address, err,
		    sizeof(err)), "an address message decodes");
		check(ncfg_address_record_cidr(&address, text, sizeof(text), err, sizeof(err)) &&
		    strcmp(text, "192.168.1.10/24") == 0, "and renders as CIDR");
		check(address.has_proto && address.proto == 110u, "and carries IFA_PROTO");
		check(address.index == 3u, "and the index of its interface");
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&body);
		ncfg_buf_free(&buffer);

		/* On a kernel before 5.18 there is no IFA_PROTO, and the record
		 * has to say so rather than inventing a value -- decision 0002
		 * turns on the difference. */
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&body, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_ip(&attrs, IFA_LOCAL, &local);
		ncfg_wire_ifaddr_encode(&info, &body);
		append_message(&buffer, RTM_NEWADDR, 1, &body, &attrs);
		check(first_payload(&buffer, &message) &&
		    ncfg_dump_address(message.payload, message.payload_length, &address, err,
		    sizeof(err)) && !address.has_proto,
		    "an address with no IFA_PROTO reports absence, not zero");
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&body);
		ncfg_buf_free(&buffer);

		/* IFA_LOCAL is this host's address; IFA_ADDRESS is the peer on a
		 * point-to-point link. Preferring LOCAL is what stops a PPP
		 * interface reporting the far end as its own. */
		check(ncfg_wire_ip_parse("10.9.0.1", &peer, err, sizeof(err)), "a peer parses");
		check(ncfg_wire_ip_parse("10.9.0.2", &local, err, sizeof(err)), "and our end");
		info.prefix_len = 32;
		info.index = 5;
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&body, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_ip(&attrs, IFA_ADDRESS, &peer);
		ncfg_wire_attr_put_ip(&attrs, IFA_LOCAL, &local);
		ncfg_wire_ifaddr_encode(&info, &body);
		append_message(&buffer, RTM_NEWADDR, 1, &body, &attrs);
		check(first_payload(&buffer, &message) &&
		    ncfg_dump_address(message.payload, message.payload_length, &address, err,
		    sizeof(err)) &&
		    ncfg_address_record_cidr(&address, text, sizeof(text), NULL, 0) &&
		    strcmp(text, "10.9.0.2/32") == 0,
		    "LOCAL wins over ADDRESS on a point-to-point link");
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&body);
		ncfg_buf_free(&buffer);

		/* And a message with neither is not an address. */
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&body, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_u8(&attrs, IFA_PROTO, 2);
		ncfg_wire_ifaddr_encode(&info, &body);
		append_message(&buffer, RTM_NEWADDR, 1, &body, &attrs);
		check(first_payload(&buffer, &message) &&
		    !ncfg_dump_address(message.payload, message.payload_length, &address, err,
		    sizeof(err)), "and a message with no address at all is refused");
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&body);
		ncfg_buf_free(&buffer);
	}

	/* --- routes ------------------------------------------------------- */
	{
		ncfg_buf_t          attrs;
		ncfg_buf_t          body;
		ncfg_buf_t          buffer;
		ncfg_wire_rtmsg_t   info;
		ncfg_wire_message_t message;
		ncfg_route_record_t route;
		ncfg_wire_ip_t      gateway;
		char                text[NCFG_CIDR_TEXT_MAX];

		check(ncfg_wire_ip_parse("192.168.1.1", &gateway, err, sizeof(err)),
		    "a gateway parses");
		memset(&info, 0, sizeof(info));
		info.family = AF_INET;
		info.table = RT_TABLE_MAIN;
		info.protocol = NCFG_WIRE_RTPROT_NETCFGD;
		info.kind = RTN_UNICAST;

		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&body, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_ip(&attrs, RTA_GATEWAY, &gateway);
		ncfg_wire_attr_put_u32(&attrs, RTA_OIF, 3);
		ncfg_wire_attr_put_u32(&attrs, RTA_PRIORITY, 100);
		ncfg_wire_rtmsg_encode(&info, &body);
		append_message(&buffer, RTM_NEWROUTE, 1, &body, &attrs);
		check(first_payload(&buffer, &message) &&
		    ncfg_dump_route(message.payload, message.payload_length, &route, err,
		    sizeof(err)), "a default route decodes");
		check(ncfg_route_record_destination(&route, text, sizeof(text), err, sizeof(err)) &&
		    strcmp(text, "default") == 0, "and a route with no destination is `default`");
		check(route.gateway.family == AF_INET && route.has_index && route.index == 3u,
		    "and carries its gateway and interface");
		check(route.has_metric && route.metric == 100u, "and its metric");
		check(route.protocol == 110u, "and the protocol netcfgd stamps on its own routes");
		check(route.table == 254u, "and the main table from the byte-wide field");
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&body);
		ncfg_buf_free(&buffer);

		/*
		 * A table id above 255 does not fit `rtm_table` and arrives in
		 * `RTA_TABLE` instead. Reading only the byte would report table
		 * 5000 as 252 -- `RT_TABLE_COMPAT`, which is a real table and not
		 * that one.
		 */
		info.table = RT_TABLE_COMPAT;
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&body, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_u32(&attrs, RTA_TABLE, 5000);
		ncfg_wire_rtmsg_encode(&info, &body);
		append_message(&buffer, RTM_NEWROUTE, 1, &body, &attrs);
		check(first_payload(&buffer, &message) &&
		    ncfg_dump_route(message.payload, message.payload_length, &route, err,
		    sizeof(err)) && route.table == 5000u,
		    "a table id that does not fit the byte comes from RTA_TABLE");
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&body);
		ncfg_buf_free(&buffer);

		/* And a route with a destination renders as CIDR. */
		{
			ncfg_wire_ip_t destination;

			check(ncfg_wire_ip_parse("10.0.0.0", &destination, err, sizeof(err)),
			    "a destination parses");
			info.table = RT_TABLE_MAIN;
			info.dst_len = 8;
			ncfg_buf_init(&attrs, 0);
			ncfg_buf_init(&body, 0);
			ncfg_buf_init(&buffer, 0);
			ncfg_wire_attr_put_ip(&attrs, RTA_DST, &destination);
			ncfg_wire_rtmsg_encode(&info, &body);
			append_message(&buffer, RTM_NEWROUTE, 1, &body, &attrs);
			check(first_payload(&buffer, &message) &&
			    ncfg_dump_route(message.payload, message.payload_length, &route,
			    err, sizeof(err)) &&
			    ncfg_route_record_destination(&route, text, sizeof(text), NULL, 0) &&
			    strcmp(text, "10.0.0.0/8") == 0, "and a destination renders as CIDR");
			ncfg_buf_free(&attrs);
			ncfg_buf_free(&body);
			ncfg_buf_free(&buffer);
		}
	}

	/* --- bridge VLANs, including the kernel's ranges ------------------- */
	{
		ncfg_buf_t          spec;
		ncfg_buf_t          attrs;
		ncfg_buf_t          body;
		ncfg_buf_t          buffer;
		ncfg_wire_message_t message;
		ncfg_bridge_vlans_t vlans;
		struct bridge_vlan_info one;
		struct bridge_vlan_info begin;
		struct bridge_vlan_info end;

		memset(&one, 0, sizeof(one));
		one.flags = BRIDGE_VLAN_INFO_PVID | BRIDGE_VLAN_INFO_UNTAGGED;
		one.vid = 1;
		memset(&begin, 0, sizeof(begin));
		begin.flags = BRIDGE_VLAN_INFO_RANGE_BEGIN;
		begin.vid = 10;
		memset(&end, 0, sizeof(end));
		end.flags = BRIDGE_VLAN_INFO_RANGE_END;
		end.vid = 13;

		ncfg_buf_init(&spec, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&body, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put(&spec, IFLA_BRIDGE_VLAN_INFO, &begin, sizeof(begin));
		ncfg_wire_attr_put(&spec, IFLA_BRIDGE_VLAN_INFO, &end, sizeof(end));
		ncfg_wire_attr_put(&spec, IFLA_BRIDGE_VLAN_INFO, &one, sizeof(one));
		ncfg_wire_attr_put_nested(&attrs, IFLA_AF_SPEC, &spec);
		append_ifinfo(&body, AF_BRIDGE, 7, 0);
		append_message(&buffer, RTM_NEWLINK, 1, &body, &attrs);

		check(first_payload(&buffer, &message) &&
		    ncfg_dump_bridge_vlans(message.payload, message.payload_length, &vlans, err,
		    sizeof(err)), "a bridge port's VLANs decode");
		check(vlans.count == 5u, "and a range of four becomes four entries, plus the one");
		check(vlans.count == 5u && vlans.items[0].vid == 1u && vlans.items[0].pvid &&
		    vlans.items[0].untagged, "sorted, with the pvid and untagged flags read");
		check(vlans.count == 5u && vlans.items[1].vid == 10u && vlans.items[4].vid == 13u,
		    "and the range expanded from its ends");
		check(vlans.count == 5u && vlans.items[4].index == 7u,
		    "each carrying the interface it is on");
		ncfg_bridge_vlans_free(&vlans);
		ncfg_bridge_vlans_free(&vlans);
		check(vlans.count == 0 && vlans.items == NULL, "and freeing it twice is nothing");
		ncfg_buf_free(&spec);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&body);
		ncfg_buf_free(&buffer);

		/* A range that never ended is a truncated message rather than a
		 * range to the end of the space: inventing 4094 VLANs would have
		 * netcfgd delete them. */
		ncfg_buf_init(&spec, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&body, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put(&spec, IFLA_BRIDGE_VLAN_INFO, &begin, sizeof(begin));
		ncfg_wire_attr_put_nested(&attrs, IFLA_AF_SPEC, &spec);
		append_ifinfo(&body, AF_BRIDGE, 7, 0);
		append_message(&buffer, RTM_NEWLINK, 1, &body, &attrs);
		check(first_payload(&buffer, &message) &&
		    ncfg_dump_bridge_vlans(message.payload, message.payload_length, &vlans, err,
		    sizeof(err)) && vlans.count == 1u && vlans.items[0].vid == 10u,
		    "a range that never ended is its first entry alone");
		ncfg_bridge_vlans_free(&vlans);
		ncfg_buf_free(&spec);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&body);
		ncfg_buf_free(&buffer);

		/* An ordinary link dump arrives on the same socket, and a link
		 * with no AF_SPEC has no VLANs rather than being a failure. */
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&body, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0");
		append_ifinfo(&body, 0, 3, 0);
		append_message(&buffer, RTM_NEWLINK, 1, &body, &attrs);
		check(first_payload(&buffer, &message) &&
		    ncfg_dump_bridge_vlans(message.payload, message.payload_length, &vlans, err,
		    sizeof(err)) && vlans.count == 0u,
		    "and a link with no AF_SPEC has no VLANs, which is not a failure");
		ncfg_bridge_vlans_free(&vlans);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&body);
		ncfg_buf_free(&buffer);
	}

	/* --- the dump requests -------------------------------------------- */
	{
		ncfg_buf_t body;
		ncfg_buf_t attrs;

		ncfg_buf_init(&body, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_dump_link_request(&body, &attrs);
		check(body.length == NCFG_WIRE_IFINFO_LEN && attrs.length == 0,
		    "a link dump asks with an empty ifinfomsg");
		ncfg_buf_free(&body);
		ncfg_buf_free(&attrs);

		ncfg_buf_init(&body, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_dump_address_request(&body, &attrs);
		check(body.length == NCFG_WIRE_IFADDR_LEN && body.data[0] == 0,
		    "an address dump asks for every family at once");
		ncfg_buf_free(&body);
		ncfg_buf_free(&attrs);

		ncfg_buf_init(&body, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_dump_route_request(&body, &attrs);
		check(body.length == NCFG_WIRE_RTMSG_LEN, "a route dump asks with an empty rtmsg");
		ncfg_buf_free(&body);
		ncfg_buf_free(&attrs);

		ncfg_buf_init(&body, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_dump_bridge_vlan_request(&body, &attrs);
		check(body.length == NCFG_WIRE_IFINFO_LEN && (unsigned char)body.data[0] == AF_BRIDGE,
		    "a bridge VLAN dump asks under AF_BRIDGE");
		check(attrs.length == 8u,
		    "and carries the filter without which it reports no VLANs");
		ncfg_buf_free(&body);
		ncfg_buf_free(&attrs);

		check(ncfg_dump_flags() == (NLM_F_REQUEST | NLM_F_DUMP), "and a dump asks to dump");
		/*
		 * `bind` takes a bitmask and `linux/rtnetlink.h` numbers the
		 * groups from 1, so every one of these is `1 << (group - 1)` --
		 * the numbers are 1, 5, 7, 9 and 11 and the bits are 0x1, 0x10,
		 * 0x40, 0x100 and 0x400, which look nothing like each other. A
		 * mask written out by hand is how a watcher comes to subscribe to
		 * the wrong thing and see nothing for ever.
		 */
		check(NCFG_NETLINK_GROUP_LINK == 0x1u &&
		    NCFG_NETLINK_GROUP_IPV4_IFADDR == 0x10u &&
		    NCFG_NETLINK_GROUP_IPV4_ROUTE == 0x40u &&
		    NCFG_NETLINK_GROUP_IPV6_IFADDR == 0x100u &&
		    NCFG_NETLINK_GROUP_IPV6_ROUTE == 0x400u,
		    "a multicast group is a bit, not the number of the group");
		check(NCFG_NETLINK_GROUPS_OBSERVED == 0x551u,
		    "and the observed model is built from all five");
		check(NCFG_DUMP_LINK == NCFG_DUMP_BRIDGE_VLAN,
		    "the bridge dump is a link dump, which is why it is named");
	}

	/* --- several messages in one read are all seen -------------------- */
	{
		ncfg_buf_t           attrs;
		ncfg_buf_t           buffer;
		ncfg_wire_messages_t walk;
		ncfg_wire_message_t  message;
		ncfg_link_record_t   link;
		size_t               seen = 0;
		int                  ordered = 1;

		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0");
		append_link(&buffer, 1, 3, 0, &attrs);
		ncfg_buf_free(&attrs);
		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth1");
		append_link(&buffer, 1, 4, 0, &attrs);

		ncfg_wire_messages_start(&walk, buffer.data, buffer.length);
		while (seen < WALK_CAP &&
		    ncfg_wire_messages_next(&walk, &message, NULL, 0) == NCFG_WIRE_OK) {
			if (!ncfg_dump_link(message.payload, message.payload_length, &link, NULL,
			    0)) {
				ordered = 0;
				break;
			}
			if (strcmp(link.name, seen == 0 ? "eth0" : "eth1") != 0) {
				ordered = 0;
			}
			ncfg_link_record_free(&link);
			seen++;
		}
		check(seen == 2u && ordered, "two messages in one read decode as two links");
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&buffer);
	}

	/*
	 * --- adversarial bytes ---------------------------------------------
	 *
	 * The decoders take bytes from a socket, which is input this process
	 * does not control. Nothing here may read past the end or fail to
	 * terminate, whatever arrives. Run under ASan: the difference between
	 * "refused" and "read four bytes past the end and then refused" is
	 * invisible without it, and it is the whole difference.
	 */
	{
		static const uint8_t ones[64] = {
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
		};
		static const uint8_t zeros[16] = { 0 };
		static const uint8_t counted[16] = {
			0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		};
		size_t at;

		for (at = 0; at <= sizeof(ones); at++) {
			uint8_t              *copy = at ? malloc(at) : NULL;
			ncfg_link_record_t    link;
			ncfg_address_record_t address;
			ncfg_route_record_t   route;
			ncfg_bridge_vlans_t   vlans;

			if (at) {
				memcpy(copy, ones, at);
			}
			/* Every entry point, on a buffer whose end is the end of
			 * an allocation -- a short read tested as the prefix of a
			 * longer buffer is not tested at all. */
			if (ncfg_dump_link(copy, at, &link, NULL, 0)) {
				ncfg_link_record_free(&link);
			}
			(void)ncfg_dump_address(copy, at, &address, NULL, 0);
			(void)ncfg_dump_route(copy, at, &route, NULL, 0);
			if (ncfg_dump_bridge_vlans(copy, at, &vlans, NULL, 0)) {
				ncfg_bridge_vlans_free(&vlans);
			}
			free(copy);
		}
		check(1, "0xff bytes at every length decode or refuse, and never read past");

		{
			ncfg_link_record_t  link;
			ncfg_bridge_vlans_t vlans;

			(void)ncfg_dump_link(zeros, sizeof(zeros), &link, NULL, 0);
			ncfg_link_record_free(&link);
			(void)ncfg_dump_link(counted, sizeof(counted), &link, NULL, 0);
			ncfg_link_record_free(&link);
			if (ncfg_dump_bridge_vlans(zeros, sizeof(zeros), &vlans, NULL, 0)) {
				ncfg_bridge_vlans_free(&vlans);
			}
			check(1, "and so do an all-zero message and a self-describing one");
		}
	}

	/*
	 * --- every truncation of a well-formed link message ----------------
	 *
	 * The shape a short read actually produces. Each cut is copied to its
	 * own allocation so that one byte past the input is a report rather than
	 * a byte of the rest of the buffer.
	 */
	{
		ncfg_buf_t attrs;
		ncfg_buf_t buffer;
		size_t     cut;
		int        named = 0;

		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0");
		ncfg_wire_attr_put_u32(&attrs, IFLA_MTU, 1500);
		append_link(&buffer, 1, 3, 0, &attrs);

		for (cut = 0; cut < buffer.length; cut++) {
			uint8_t           *partial = cut ? malloc(cut) : NULL;
			ncfg_link_record_t link;

			if (cut) {
				memcpy(partial, buffer.data, cut);
			}
			/* The payload begins after the header, which is what a
			 * caller hands the decoder. */
			if (cut > NCFG_WIRE_NLMSG_HDR_LEN &&
			    ncfg_dump_link(partial + NCFG_WIRE_NLMSG_HDR_LEN,
			    cut - NCFG_WIRE_NLMSG_HDR_LEN, &link, NULL, 0)) {
				/* A name only ever comes back whole: a truncated
				 * interface name is a name, just somebody
				 * else's. */
				if (strcmp(link.name, "eth0") != 0) {
					named = 1;
				}
				ncfg_link_record_free(&link);
			}
			free(partial);
		}
		check(named == 0, "no cut of a link message yields a piece of a name");
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&buffer);
	}

	/*
	 * --- a malformed attribute area refuses the record -----------------
	 *
	 * The Rust's iterator stops and the caller keeps what it had, which
	 * reads a truncated message as a finished one. This port refuses it,
	 * which is the divergence the wire layer's three outcomes exist for.
	 */
	{
		ncfg_buf_t         attrs;
		ncfg_buf_t         buffer;
		ncfg_link_record_t link;
		uint8_t           *bytes;
		uint16_t           overlong = 0xff00;
		size_t             tail;

		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&buffer, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0");
		ncfg_wire_attr_put_u32(&attrs, IFLA_MTU, 1500);
		append_link(&buffer, 1, 3, 0, &attrs);
		/* The MTU attribute's length field, made longer than the message
		 * that holds it. */
		tail = buffer.length - 8u;
		bytes = (uint8_t *)buffer.data;
		memcpy(bytes + tail, &overlong, sizeof(overlong));
		err[0] = '\0';
		check(!decode_first_link(&buffer, &link, err, sizeof(err)) && err[0] != '\0',
		    "an attribute claiming more than the message refuses the record");
		ncfg_link_record_free(&link);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&buffer);
	}

	/* ------------------------------------------------------------------ */
	/* The socket half.                                                   */
	/* ------------------------------------------------------------------ */

	/*
	 * --- which receive outcomes are failures, and which four are not ---
	 *
	 * `EINTR` was, and it cost a machine its network configuration for
	 * fifty-two minutes (0233). A signal arriving while the socket is
	 * blocked means "call it again"; netcfgd spawns children, so `SIGCHLD`
	 * can land on that syscall at any time, and on the reporting machine one
	 * did two seconds before a network change. The watcher thread treated it
	 * as fatal and returned, taking the daemon's reconcile loop with it.
	 */
	{
		int changed = 0;

		check(ncfg_netlink_change_from(120, 0, &changed, err, sizeof(err)) && changed,
		    "something arrived is a change");
		check(ncfg_netlink_change_from(0, 0, &changed, err, sizeof(err)) && changed,
		    "and a zero-length message is still a message");
		check(ncfg_netlink_change_from(-1, EAGAIN, &changed, err, sizeof(err)) && !changed,
		    "a receive timeout is the caller's tick, not a failure");
		check(ncfg_netlink_change_from(-1, EWOULDBLOCK, &changed, err, sizeof(err)) &&
		    !changed, "and so is the other spelling of it");
		check(ncfg_netlink_change_from(-1, ETIMEDOUT, &changed, err, sizeof(err)) &&
		    !changed, "and the third");
		check(ncfg_netlink_change_from(-1, EINTR, &changed, err, sizeof(err)) && !changed,
		    "a signal means call it again, not give up");
		check(ncfg_netlink_change_from(-1, ENOBUFS, &changed, err, sizeof(err)) && changed,
		    "a dropped message is a change, not a quiet moment");
		err[0] = '\0';
		check(!ncfg_netlink_change_from(-1, EBADF, &changed, err, sizeof(err)) &&
		    strstr(err, "EBADF") != NULL,
		    "and a bad descriptor is a failure that names itself");
	}

	/* --- the sentence a netlink error becomes ------------------------- */
	{
		err[0] = '\0';
		check(ncfg_netlink_fail(err, sizeof(err), "the link dump", EPERM) == 0,
		    "a failure sentence returns 0, so the message and the answer agree");
		check(strstr(err, "the link dump") != NULL && strstr(err, "EPERM") != NULL,
		    "and names what failed and which errno it was");
		check(strstr(err, "CAP_NET_ADMIN") != NULL,
		    "and says the thing an operator can act on");
		err[0] = '\0';
		(void)ncfg_netlink_fail(err, sizeof(err), "a request", EINVAL);
		check(strstr(err, "NLA_F_NESTED") != NULL,
		    "EINVAL on this socket gets the explanation strerror cannot give");
		err[0] = '\0';
		(void)ncfg_netlink_fail(err, sizeof(err), NULL, 0x7fff);
		check(strstr(err, "a netlink operation") != NULL && strstr(err, "32767") != NULL,
		    "and an errno nobody has a sentence for still reports its number");
		check(ncfg_netlink_errno_text(0x7fff) == NULL, "with nothing invented for it");
		check(strcmp(ncfg_netlink_kind_text(RTM_NEWLINK), "RTM_NEWLINK") == 0 &&
		    strcmp(ncfg_netlink_kind_text(NLMSG_DONE), "NLMSG_DONE") == 0,
		    "and a message type has the kernel's own name");
		check(ncfg_netlink_kind_text(0x7ff0) == NULL,
		    "and a type this port has no name for says so");
	}

	/* --- sequence numbers --------------------------------------------- */
	{
		ncfg_netlink_t netlink;

		ncfg_netlink_init(&netlink);
		check(netlink.fd == -1, "an initialised socket holds no descriptor");
		check(ncfg_netlink_take_seq(&netlink) == 2u &&
		    ncfg_netlink_take_seq(&netlink) == 3u, "sequence numbers start at 2 and rise");
		netlink.seq = 0xffffffffu;
		check(ncfg_netlink_take_seq(&netlink) == 1u,
		    "and a counter that wraps skips 0, which means unsolicited");
		ncfg_netlink_close(&netlink);
		ncfg_netlink_close(&netlink);
		check(1, "and closing one that was never opened is nothing");
	}

	/*
	 * --- a dump too big for its buffer is read again -------------------
	 *
	 * The assertion is equality with the same dump read into a roomy buffer,
	 * so this fails both if the growth loses messages and if it invents any
	 * -- and the source's own counters fail it if the datagram is asked for
	 * twice, which is what re-sending the request would look like.
	 */
	{
		ncfg_buf_t           dump;
		ncfg_buf_t           attrs;
		fake_t               fake;
		ncfg_netlink_reply_t cramped;
		ncfg_netlink_reply_t roomy;
		size_t               at;
		int                  same = 1;

		ncfg_buf_init(&dump, 0);
		for (at = 0; at < 12u; at++) {
			char name[NCFG_LINK_NAME_MAX];

			(void)snprintf(name, sizeof(name), "eth%zu", at);
			ncfg_buf_init(&attrs, 0);
			ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, name);
			ncfg_wire_attr_put_u32(&attrs, IFLA_MTU, 1500);
			append_link(&dump, 2, (int32_t)at + 1, 0x1u, &attrs);
			ncfg_buf_free(&attrs);
		}
		append_done(&dump, 2);
		check(!ncfg_buf_failed(&dump) && dump.length > 128u,
		    "a dump of twelve links is larger than a small buffer");

		memset(&fake, 0, sizeof(fake));
		queue(&fake, &dump);
		check(ncfg_netlink_collect(fake_recv, &fake, 2, ncfg_dump_flags(), 128u, &cramped,
		    err, sizeof(err)), "a reply too big for its buffer is read whole");
		check(fake.peeks == 1u && fake.reads == 1u,
		    "asked once and read once -- never re-sent, which 0183 is about");

		memset(&fake, 0, sizeof(fake));
		queue(&fake, &dump);
		check(ncfg_netlink_collect(fake_recv, &fake, 2, ncfg_dump_flags(),
		    NCFG_NETLINK_REPLY_INITIAL, &roomy, err, sizeof(err)),
		    "and the same dump read into a roomy buffer");
		if (cramped.count != roomy.count) {
			same = 0;
		} else {
			for (at = 0; at < cramped.count; at++) {
				if (cramped.items[at].length != roomy.items[at].length ||
				    memcmp(cramped.items[at].bytes, roomy.items[at].bytes,
				    roomy.items[at].length) != 0) {
					same = 0;
				}
			}
		}
		check(roomy.count == 12u, "collects every message of the dump");
		check(same, "and the two are the same dump, byte for byte");
		ncfg_netlink_reply_free(&cramped);
		ncfg_netlink_reply_free(&roomy);
		ncfg_netlink_reply_free(&roomy);
		check(1, "and freeing a reply twice is nothing");

		/* Several datagrams, which is what a real dump is. */
		{
			ncfg_buf_t           first;
			ncfg_buf_t           second;
			ncfg_netlink_reply_t reply;

			ncfg_buf_init(&first, 0);
			ncfg_buf_init(&second, 0);
			ncfg_buf_init(&attrs, 0);
			ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0");
			append_link(&first, 2, 1, 0, &attrs);
			append_link(&second, 2, 2, 0, &attrs);
			append_done(&second, 2);
			memset(&fake, 0, sizeof(fake));
			queue(&fake, &first);
			queue(&fake, &second);
			check(ncfg_netlink_collect(fake_recv, &fake, 2, ncfg_dump_flags(), 128u,
			    &reply, err, sizeof(err)) && reply.count == 2u && fake.reads == 2u,
			    "a multipart reply spanning two datagrams is one answer");
			ncfg_netlink_reply_free(&reply);
			ncfg_buf_free(&first);
			ncfg_buf_free(&second);
			ncfg_buf_free(&attrs);
		}
		ncfg_buf_free(&dump);
	}

	/* --- a reply past the ceiling is refused with its size ------------- */
	{
		ncfg_buf_t           dump;
		fake_t               fake;
		ncfg_netlink_reply_t reply;

		ncfg_buf_init(&dump, 0);
		append_done(&dump, 2);
		memset(&fake, 0, sizeof(fake));
		queue(&fake, &dump);
		/* The kernel will not make a reply this large on demand, which is
		 * the whole reason the source is a fake. */
		fake.datagrams[0].peek_says = (size_t)NCFG_NETLINK_MAX_REPLY + 1u;
		err[0] = '\0';
		check(!ncfg_netlink_collect(fake_recv, &fake, 2, ncfg_dump_flags(), 128u, &reply,
		    err, sizeof(err)), "a reply past the ceiling is refused");
		check(strstr(err, "1048577") != NULL,
		    "and reported with the size whoever raises it needs");
		check(fake.reads == 0u, "and is not read into a buffer it does not fit");
		ncfg_netlink_reply_free(&reply);
		ncfg_buf_free(&dump);
	}

	/* --- a datagram larger than the peek promised is refused ----------- */
	{
		ncfg_buf_t           dump;
		ncfg_buf_t           attrs;
		fake_t               fake;
		ncfg_netlink_reply_t reply;

		ncfg_buf_init(&dump, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0");
		append_link(&dump, 2, 1, 0, &attrs);
		append_done(&dump, 2);
		memset(&fake, 0, sizeof(fake));
		queue(&fake, &dump);
		/* The buffer is not grown, and the read then reports more bytes
		 * than were written into it. Clamping would read a piece of a
		 * dump as a whole one. */
		fake.datagrams[0].peek_says = 16u;
		err[0] = '\0';
		check(!ncfg_netlink_collect(fake_recv, &fake, 2, ncfg_dump_flags(), 16u, &reply,
		    err, sizeof(err)) && strstr(err, "arrived in a") != NULL,
		    "a datagram bigger than the buffer it landed in is refused");
		ncfg_netlink_reply_free(&reply);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&dump);
	}

	/* --- sequence handling in the reply loop --------------------------- */
	{
		ncfg_buf_t           reply_bytes;
		ncfg_buf_t           attrs;
		fake_t               fake;
		ncfg_netlink_reply_t reply;

		ncfg_buf_init(&reply_bytes, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0");
		/* Somebody else's reply, an unsolicited message, and ours. */
		append_link(&reply_bytes, 99, 1, 0, &attrs);
		append_link(&reply_bytes, 0, 2, 0, &attrs);
		append_link(&reply_bytes, 2, 3, 0, &attrs);
		append_done(&reply_bytes, 2);
		memset(&fake, 0, sizeof(fake));
		queue(&fake, &reply_bytes);
		check(ncfg_netlink_collect(fake_recv, &fake, 2, ncfg_dump_flags(), 4096u, &reply,
		    err, sizeof(err)) && reply.count == 2u,
		    "a message for another sequence number is skipped");
		{
			ncfg_link_record_t kept;
			int                unsolicited = 0;
			int                ours = 0;

			if (reply.count == 2u &&
			    ncfg_dump_link(reply.items[0].bytes, reply.items[0].length, &kept,
			    NULL, 0)) {
				unsolicited = (kept.index == 2u);
				ncfg_link_record_free(&kept);
			}
			if (reply.count == 2u &&
			    ncfg_dump_link(reply.items[1].bytes, reply.items[1].length, &kept,
			    NULL, 0)) {
				ours = (kept.index == 3u);
				ncfg_link_record_free(&kept);
			}
			check(unsolicited && ours,
			    "while sequence 0 -- unsolicited -- is kept beside ours");
		}
		ncfg_netlink_reply_free(&reply);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&reply_bytes);
	}

	/* --- an error reply, and the acknowledgement that looks like one --- */
	{
		ncfg_buf_t           reply_bytes;
		fake_t               fake;
		ncfg_netlink_reply_t reply;

		ncfg_buf_init(&reply_bytes, 0);
		append_error(&reply_bytes, 2, EPERM, RTM_NEWLINK);
		memset(&fake, 0, sizeof(fake));
		queue(&fake, &reply_bytes);
		err[0] = '\0';
		check(!ncfg_netlink_collect(fake_recv, &fake, 2, NLM_F_REQUEST, 4096u, &reply, err,
		    sizeof(err)), "an NLMSG_ERROR with a code is a failure");
		check(strstr(err, "EPERM") != NULL && strstr(err, "RTM_NEWLINK") != NULL,
		    "naming the errno and the request the kernel echoed back");
		ncfg_netlink_reply_free(&reply);
		ncfg_buf_free(&reply_bytes);

		ncfg_buf_init(&reply_bytes, 0);
		append_error(&reply_bytes, 2, 0, RTM_NEWLINK);
		memset(&fake, 0, sizeof(fake));
		queue(&fake, &reply_bytes);
		check(ncfg_netlink_collect(fake_recv, &fake, 2, NLM_F_REQUEST, 4096u, &reply, err,
		    sizeof(err)) && reply.count == 0u,
		    "and a zero code is an acknowledgement, which ends the request");
		ncfg_netlink_reply_free(&reply);
		ncfg_buf_free(&reply_bytes);
	}

	/* --- a single-shot reply is complete without an acknowledgement ---- */
	{
		ncfg_buf_t           reply_bytes;
		ncfg_buf_t           body;
		ncfg_buf_t           attrs;
		fake_t               fake;
		ncfg_netlink_reply_t reply;
		ncfg_wire_ifaddr_t   info;

		memset(&info, 0, sizeof(info));
		ncfg_buf_init(&reply_bytes, 0);
		ncfg_buf_init(&body, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_wire_ifaddr_encode(&info, &body);
		append_message(&reply_bytes, RTM_NEWADDR, 2, &body, &attrs);
		memset(&fake, 0, sizeof(fake));
		queue(&fake, &reply_bytes);
		/* The source answers a second read with a timeout, which is what
		 * a socket does -- so this fails if the loop asks again. */
		fake.code = EAGAIN;
		check(ncfg_netlink_collect(fake_recv, &fake, 2, NLM_F_REQUEST, 4096u, &reply, err,
		    sizeof(err)) && reply.count == 1u && fake.reads == 1u,
		    "a reply without NLM_F_MULTI is complete on its own");
		ncfg_netlink_reply_free(&reply);
		ncfg_buf_free(&reply_bytes);
		ncfg_buf_free(&body);
		ncfg_buf_free(&attrs);
	}

	/* --- a malformed datagram, and an empty one ----------------------- */
	{
		ncfg_buf_t           reply_bytes;
		fake_t               fake;
		ncfg_netlink_reply_t reply;
		uint32_t             nothing = 0;

		/* nlmsg_len = 0, which is shorter than the header it sits in and
		 * would advance a walk by nothing at all. */
		ncfg_buf_init(&reply_bytes, 0);
		ncfg_buf_add(&reply_bytes, &nothing, sizeof(nothing));
		ncfg_buf_add(&reply_bytes, &nothing, sizeof(nothing));
		ncfg_buf_add(&reply_bytes, &nothing, sizeof(nothing));
		ncfg_buf_add(&reply_bytes, &nothing, sizeof(nothing));
		memset(&fake, 0, sizeof(fake));
		queue(&fake, &reply_bytes);
		err[0] = '\0';
		check(!ncfg_netlink_collect(fake_recv, &fake, 2, ncfg_dump_flags(), 4096u, &reply,
		    err, sizeof(err)) && err[0] != '\0',
		    "a message shorter than its own header refuses the reply");
		ncfg_netlink_reply_free(&reply);
		ncfg_buf_free(&reply_bytes);

		ncfg_buf_init(&reply_bytes, 0);
		memset(&fake, 0, sizeof(fake));
		queue(&fake, &reply_bytes);
		err[0] = '\0';
		check(!ncfg_netlink_collect(fake_recv, &fake, 2, ncfg_dump_flags(), 4096u, &reply,
		    err, sizeof(err)) && strstr(err, "no bytes") != NULL,
		    "and a datagram with no bytes is refused rather than looped on");
		ncfg_netlink_reply_free(&reply);
		ncfg_buf_free(&reply_bytes);
	}

	/* --- the receive failing outright --------------------------------- */
	{
		fake_t               fake;
		ncfg_netlink_reply_t reply;

		memset(&fake, 0, sizeof(fake));
		fake.code = EAGAIN;
		err[0] = '\0';
		check(!ncfg_netlink_collect(fake_recv, &fake, 2, ncfg_dump_flags(), 4096u, &reply,
		    err, sizeof(err)) && strstr(err, "EAGAIN") != NULL,
		    "a kernel that never answers is the socket's timeout, reported");
		ncfg_netlink_reply_free(&reply);
	}

	/*
	 * --- a batch ends on the acknowledgement it was told to wait for ----
	 *
	 * `last_acked` is the last message that asked for an acknowledgement and
	 * not the batch-end marker: the kernel acknowledges the messages inside
	 * the transaction and says nothing about the end, so waiting for that
	 * one waits until the socket times out.
	 */
	{
		ncfg_buf_t           reply_bytes;
		fake_t               fake;
		ncfg_netlink_reply_t reply;

		ncfg_buf_init(&reply_bytes, 0);
		append_error(&reply_bytes, 4, 0, RTM_NEWLINK);
		append_error(&reply_bytes, 5, 0, RTM_NEWLINK);
		memset(&fake, 0, sizeof(fake));
		queue(&fake, &reply_bytes);
		fake.code = EAGAIN;
		check(ncfg_netlink_collect_batch(fake_recv, &fake, 5, 4096u, &reply, err,
		    sizeof(err)), "a batch ends when its last message is acknowledged");
		ncfg_netlink_reply_free(&reply);
		ncfg_buf_free(&reply_bytes);

		ncfg_buf_init(&reply_bytes, 0);
		append_error(&reply_bytes, 4, 0, RTM_NEWLINK);
		append_error(&reply_bytes, 5, EEXIST, RTM_NEWLINK);
		memset(&fake, 0, sizeof(fake));
		queue(&fake, &reply_bytes);
		err[0] = '\0';
		check(!ncfg_netlink_collect_batch(fake_recv, &fake, 9, 4096u, &reply, err,
		    sizeof(err)) && strstr(err, "EEXIST") != NULL,
		    "and one failure in a transaction is the whole transaction's");
		ncfg_netlink_reply_free(&reply);
		ncfg_buf_free(&reply_bytes);
	}

	/*
	 * --- a datagram that did not come from the kernel -------------------
	 *
	 * A netlink socket is not a private channel to the kernel: any local
	 * process may unicast to one, and `/proc/net/netlink` is world-readable
	 * and lists netcfgd's socket with its port id, so nobody has to guess
	 * where to aim. Sequence numbers are small consecutive integers, so the
	 * forgeries below carry the *right* one -- which is the whole point,
	 * since the sequence filter is not what stops them.
	 *
	 * Each case checks the same two things: the forgery reaches nothing, and
	 * it is not allowed to break anything either. Refusing would have closed
	 * the first half and opened the second, handing any local user a way to
	 * end a dump on a root daemon with one packet.
	 */
	{
		ncfg_buf_t           forged;
		ncfg_buf_t           genuine;
		ncfg_buf_t           attrs;
		fake_t               fake;
		ncfg_netlink_reply_t reply;

		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "evil0");
		ncfg_buf_init(&forged, 0);
		append_link(&forged, 2, 66, 0, &attrs);
		ncfg_buf_free(&attrs);
		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0");
		ncfg_buf_init(&genuine, 0);
		append_link(&genuine, 2, 3, 0, &attrs);
		append_done(&genuine, 2);

		/* A forged link record, with the sequence number of the dump in
		 * flight, queued in front of the kernel's own answer. */
		memset(&fake, 0, sizeof(fake));
		queue_from(&fake, &forged, 4242);
		queue(&fake, &genuine);
		check(ncfg_netlink_collect(fake_recv, &fake, 2, ncfg_dump_flags(), 4096u, &reply,
		    err, sizeof(err)),
		    "a forged reply does not fail the dump it was aimed at");
		check(reply.count == 1u, "and does not join it either");
		check(reply.dropped == 1u, "the drop is counted rather than silent");
		check(fake.reads == 2u, "and the forgery was consumed, not left queued");
		{
			ncfg_link_record_t kept;

			check(reply.count == 1u &&
			    ncfg_dump_link(reply.items[0].bytes, reply.items[0].length, &kept,
			    NULL, 0) && strcmp(kept.name, "eth0") == 0,
			    "while the kernel's own message goes through untouched");
			if (reply.count == 1u) {
				ncfg_link_record_free(&kept);
			}
		}
		ncfg_netlink_reply_free(&reply);
		ncfg_buf_free(&forged);
		ncfg_buf_free(&genuine);
		ncfg_buf_free(&attrs);
	}
	{
		ncfg_buf_t           forged;
		ncfg_buf_t           genuine;
		fake_t               fake;
		ncfg_netlink_reply_t reply;

		/* The one that costs the most if it lands: an operation the
		 * kernel was about to acknowledge, failed by somebody else. */
		ncfg_buf_init(&forged, 0);
		append_error(&forged, 2, EPERM, RTM_NEWLINK);
		ncfg_buf_init(&genuine, 0);
		append_error(&genuine, 2, 0, RTM_NEWLINK);

		memset(&fake, 0, sizeof(fake));
		queue_from(&fake, &forged, 4242);
		queue(&fake, &genuine);
		err[0] = '\0';
		check(ncfg_netlink_collect(fake_recv, &fake, 2, NLM_F_REQUEST, 4096u, &reply, err,
		    sizeof(err)) && reply.dropped == 1u,
		    "a forged NLMSG_ERROR does not fail the operation");
		check(err[0] == '\0', "and leaves no sentence claiming the kernel refused");
		ncfg_netlink_reply_free(&reply);
		ncfg_buf_free(&forged);
		ncfg_buf_free(&genuine);

		/* Caught on the call that delivered the bytes, not only on the
		 * peek before it. */
		memset(&fake, 0, sizeof(fake));
		ncfg_buf_init(&forged, 0);
		append_error(&forged, 2, EPERM, RTM_NEWLINK);
		ncfg_buf_init(&genuine, 0);
		append_error(&genuine, 2, 0, RTM_NEWLINK);
		queue_from(&fake, &forged, 4242);
		fake.datagrams[0].quiet_on_peek = 1;
		queue(&fake, &genuine);
		check(ncfg_netlink_collect(fake_recv, &fake, 2, NLM_F_REQUEST, 4096u, &reply, err,
		    sizeof(err)) && reply.dropped == 1u,
		    "and a sender that only shows on the read is caught there");
		ncfg_netlink_reply_free(&reply);
		ncfg_buf_free(&forged);
		ncfg_buf_free(&genuine);
	}
	{
		ncfg_buf_t           forged;
		ncfg_buf_t           genuine;
		fake_t               fake;
		ncfg_netlink_reply_t reply;

		/*
		 * The denial-of-service half, which is why the drop happens
		 * before the buffer is grown: a forged datagram claiming more
		 * than the ceiling would otherwise end the dump with the refusal
		 * meant for a kernel that sent too much.
		 */
		ncfg_buf_init(&forged, 0);
		append_done(&forged, 2);
		ncfg_buf_init(&genuine, 0);
		append_done(&genuine, 2);
		memset(&fake, 0, sizeof(fake));
		queue_from(&fake, &forged, 4242);
		fake.datagrams[0].peek_says = (size_t)NCFG_NETLINK_MAX_REPLY + 1u;
		queue(&fake, &genuine);
		err[0] = '\0';
		check(ncfg_netlink_collect(fake_recv, &fake, 2, ncfg_dump_flags(), 128u, &reply,
		    err, sizeof(err)) && reply.dropped == 1u,
		    "a forged datagram past the ceiling is dropped, not refused");
		ncfg_netlink_reply_free(&reply);
		ncfg_buf_free(&forged);
		ncfg_buf_free(&genuine);
	}
	{
		fake_t               fake;
		ncfg_netlink_reply_t reply;
		ncfg_buf_t           forged;
		ncfg_netlink_t       netlink;

		/* The count outlives a refusal, because the forgery may be the
		 * reason there is one: here nothing genuine ever arrives and the
		 * socket times out, and the answer still says what it discarded
		 * on the way. */
		ncfg_buf_init(&forged, 0);
		append_done(&forged, 2);
		memset(&fake, 0, sizeof(fake));
		queue_from(&fake, &forged, 4242);
		queue_from(&fake, &forged, 4243);
		fake.code = EAGAIN;
		check(!ncfg_netlink_collect(fake_recv, &fake, 2, ncfg_dump_flags(), 4096u, &reply,
		    err, sizeof(err)) && reply.dropped == 2u,
		    "and a refusal still reports what it discarded first");
		check(reply.count == 0 && reply.items == NULL,
		    "with the payloads released all the same");
		ncfg_netlink_reply_free(&reply);
		ncfg_buf_free(&forged);

		ncfg_netlink_init(&netlink);
		check(netlink.dropped == 0u, "a fresh socket has discarded nothing");
	}

	/*
	 * --- the live check, which is opt-in -------------------------------
	 *
	 * This suite runs on the machine netcfgd configures. A link dump reads
	 * nothing and changes nothing, but a socket is still a socket: set
	 * `NCFG_NETLINK_LIVE=1` to run it, and it says so rather than passing
	 * quietly when it does not.
	 */
	if (getenv("NCFG_NETLINK_LIVE")) {
		ncfg_netlink_t       netlink;
		ncfg_buf_t           body;
		ncfg_buf_t           attrs;
		ncfg_netlink_reply_t cramped;
		ncfg_netlink_reply_t roomy;

		if (!ncfg_netlink_open(&netlink, err, sizeof(err))) {
			printf("live: no netlink socket here: %s\n", err);
		} else {
			check(ncfg_netlink_set_timeout(&netlink, 2, err, sizeof(err)),
			    "live: a timeout is settable");
			ncfg_buf_init(&body, 0);
			ncfg_buf_init(&attrs, 0);
			ncfg_dump_link_request(&body, &attrs);
			check(ncfg_netlink_request_from(&netlink, NCFG_DUMP_LINK,
			    ncfg_dump_flags(), &body, &attrs, NCFG_NETLINK_REPLY_INITIAL, &roomy,
			    err, sizeof(err)), "live: a link dump is readable without privilege");
			check(ncfg_netlink_request_from(&netlink, NCFG_DUMP_LINK,
			    ncfg_dump_flags(), &body, &attrs, 128u, &cramped, err, sizeof(err)),
			    "live: and again into a buffer too small for it");
			check(roomy.count > 0 && cramped.count == roomy.count,
			    "live: the same dump, whatever it was read into");
			ncfg_netlink_reply_free(&roomy);
			ncfg_netlink_reply_free(&cramped);
			ncfg_buf_free(&body);
			ncfg_buf_free(&attrs);
			ncfg_netlink_close(&netlink);
		}
	} else {
		printf("%-58s %s\n", "the live socket check", "SKIPPED (NCFG_NETLINK_LIVE)");
	}

	if (failures == 0) {
		printf("netlink_test: all checks passed\n");
	} else {
		printf("netlink_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
