/*
 * observe_wireguard_test.c -- the two WireGuard observation passes.
 *
 * WHAT THESE ARE FOR
 *   `plan/wireguard.c` has been able to correct an edited listen port, an
 *   edited mark, a rotated key and a deleted peer since decision 0054 was
 *   written, and it did none of those things on any machine: it returns
 *   without planning anything for a link whose `wireguard` observation is
 *   absent, and nothing filled one in. So these cases are the input that pass
 *   was waiting for, and the last of them is the check that it now converges
 *   -- in both directions, because a comparison that noticed too much would
 *   replace a working tunnel's peer list on every reconcile.
 *
 * THE ONE THING THAT WOULD BE WORSE THAN NO OBSERVATION
 *   Reporting a device netcfgd **could not read** as a device with no peers.
 *   `netfilter.c` is right to read a socket it could not open as "no NAT is
 *   installed", because a kernel with no `nf_tables` has none; the same
 *   reading here hands the planner an empty peer list, which it corrects by
 *   sending the document's with `WGDEVICE_F_REPLACE_PEERS` -- a working tunnel
 *   rebuilt from a guess. Half the cases below drive a way the read can fail
 *   and assert the link stays at NULL, which is what the model already means
 *   by "not observed".
 *
 * WHY THE CANARY, AND WHY IT IS ASSERTED TO BE REACHABLE FIRST
 *   The currency question is the one pass in this module that touches the
 *   secret store, and 10.163 records a passphrase reaching a diagnostic in the
 *   Rust. A private key is worse. So a secret whose value nothing may repeat is
 *   put in the store, driven through every failure this pass has, and looked
 *   for afterwards in every `err` buffer, in everything the process said on
 *   standard error, and in the observation as it would be written to `/run`.
 *
 *   **A sweep that could not have found anything passes exactly as loudly as a
 *   real one.** So `ncfg_secret_expose` is asserted to hand the canary back
 *   before the sweep runs, the stderr capture is asserted to be non-empty, and
 *   the serialized observation is asserted to mention the device -- three ways
 *   of saying that each surface was genuinely looked at.
 *
 * NO KERNEL IN HERE
 *   `collect_test.c`'s reason, unchanged: this suite runs on the machine
 *   netcfgd configures, and a generic netlink round trip aimed at the real
 *   `wireguard` family would read that machine's tunnels. Every exchange below
 *   is a replay over bytes this file wrote.
 */
#include "planfix.h"

#include "ncfg/genl.h"
#include "ncfg/hooks.h"
#include "ncfg/log.h"
#include "ncfg/netlink.h"
#include "ncfg/observe.h"
#include "ncfg/secrets.h"
#include "ncfg/wg.h"
#include "ncfg/wire.h"

#include "testdir.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/wireguard.h>

static int failures;
static int checks;

static int check(int condition, const char *what)
{
	checks++;
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
	return condition;
}

static void detail(const char *what, const char *value)
{
	printf("  %s: %s\n", what, value ? value : "(none)");
}

/* ------------------------------------------------------------------------ *
 * The keys, which are not secret and are spelled out so nothing derives one
 * ------------------------------------------------------------------------ */

/*
 * Thirty-two octets of one repeated byte, and the base64 each spells.
 *
 * A public key identifies a peer and is the thing handed to the other end, so
 * these are literals. The two digests below are **computed outside this
 * program** -- `python3 -c "import hashlib; hashlib.sha256(bytes([4])*32)"` --
 * rather than by calling `ncfg_sha256_hex` here, because a record written by
 * the same function the comparison uses would agree with itself whatever
 * either of them did. `hooks_test.c` is where SHA-256 is checked against the
 * published vectors; this is where the comparison is checked against an
 * independent witness.
 */
#define PEER_ONE_TEXT "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
#define PEER_TWO_TEXT "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
/* The same 32 octets as PEER_TWO_TEXT, spelled with the other setting of the
 * two bits base64 does not use in a 32-octet key's last character. */
#define PEER_TWO_OTHER_SPELLING "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ="
#define DEVICE_KEY_TEXT "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="

/* What the store holds for `wg0`, and what a digest of it looks like. */
#define STORED_PRIVATE_TEXT "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ="
#define STORED_PRIVATE_DIGEST "9f4fb68f3e1dac82202f9aa581ce0bbf1f765df0e9ac3c8c57e20f685abab8ed"
/* A digest of some other key entirely, which is what a rotated one looks like
 * from here. */
#define SOME_OTHER_DIGEST "f849d67325facf04177bc663b2dc544051831c589ef581d412f2eba44834e77c"

/* The preshared key peer two was given, and its digest, computed the same way. */
#define STORED_PRESET_TEXT PEER_ONE_TEXT
#define STORED_PRESET_DIGEST "72cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793"

/* The value nothing in netcfgd may repeat. Not a key and not base64, which is
 * deliberate: it drives the fallback `digest_of` takes for a store holding
 * something `ncfg_key_parse` refuses, and it is greppable. */
#define CANARY "NCFGCANARY-not-a-key-and-not-base64"
/* SHA-256 of exactly the bytes above, computed outside this program like the
 * others. **A digest that did not correspond to the canary would make half
 * this sweep vacuous**, which is how it was written the first time: the
 * constant was carried over from an earlier spelling of the value and the
 * sabotage that emits a digest to a log went unnoticed. */
#define CANARY_DIGEST "cc093aa159ee95cf8ab80ccd4a8aa36fc358b2b608272946efc4a68d283938f3"

static void fill_key(unsigned char *out, unsigned char byte)
{
	memset(out, byte, NCFG_WG_KEY_LEN);
}

/* ------------------------------------------------------------------------ *
 * The bytes a generic netlink kernel would send
 * ------------------------------------------------------------------------ */

static void append_message(ncfg_buf_t *out, uint16_t kind, const ncfg_buf_t *body)
{
	ncfg_buf_t one;

	ncfg_buf_init(&one, 0);
	if (!ncfg_wire_build_request(&one, kind, 0, 0, body, NULL, NULL, 0)) {
		out->failed = 1;
	} else {
		ncfg_buf_add(out, one.data, one.length);
	}
	ncfg_buf_free(&one);
}

static void append_done(ncfg_buf_t *out)
{
	append_message(out, NLMSG_DONE, NULL);
}

/* What the controller answers a `GETFAMILY` for `name` with. `id` is two bytes
 * on the wire, which is the whole reason `genl.h` has a `u16` accessor. */
static void append_family(ncfg_buf_t *out, const char *name, uint16_t id)
{
	ncfg_genl_header_t header;
	ncfg_buf_t         payload;

	header.cmd = CTRL_CMD_NEWFAMILY;
	header.version = 2;
	ncfg_buf_init(&payload, 0);
	ncfg_genl_header_encode(&header, &payload);
	ncfg_wire_attr_put(&payload, CTRL_ATTR_FAMILY_ID, &id, sizeof(id));
	ncfg_wire_attr_put_str(&payload, CTRL_ATTR_FAMILY_NAME, name);
	append_message(out, GENL_ID_CTRL, &payload);
	ncfg_buf_free(&payload);
}

/* One peer as the kernel reports it. `preshared` writes the 32 zero octets the
 * kernel sends for a peer that has none and 32 of 0xff for one that has: the
 * value is never reported either way, which is the asymmetry the boolean
 * exists for. */
static void put_peer(ncfg_buf_t *array, uint16_t index, const unsigned char *public_key,
    int preshared, const char *endpoint, uint16_t keepalive, const char *const *allowed,
    size_t allowed_count)
{
	ncfg_buf_t peer;
	ncfg_buf_t nest;
	size_t     at;

	ncfg_buf_init(&peer, 0);
	ncfg_buf_init(&nest, 0);
	ncfg_wire_attr_put(&peer, WGPEER_A_PUBLIC_KEY, public_key, NCFG_WG_KEY_LEN);
	{
		unsigned char reported[NCFG_WG_KEY_LEN];

		memset(reported, preshared ? 0xff : 0x00, sizeof(reported));
		ncfg_wire_attr_put(&peer, WGPEER_A_PRESHARED_KEY, reported, sizeof(reported));
	}
	if (endpoint) {
		ncfg_wire_ip_t address;
		uint16_t       port = 0;

		if (ncfg_wg_endpoint_parse(endpoint, &address, &port, NULL, 0)) {
			/* `sockaddr_in` on the wire: family, port in network order, the
			 * address, and the pad the kernel sends. `sys/wg.c` reads it. */
			unsigned char bytes[16];

			memset(bytes, 0, sizeof(bytes));
			bytes[0] = (unsigned char)(AF_INET & 0xff);
			bytes[1] = (unsigned char)((AF_INET >> 8) & 0xff);
			bytes[2] = (unsigned char)((port >> 8) & 0xff);
			bytes[3] = (unsigned char)(port & 0xff);
			memcpy(bytes + 4, address.bytes, 4u);
			ncfg_wire_attr_put(&peer, WGPEER_A_ENDPOINT, bytes, sizeof(bytes));
		}
	}
	ncfg_wire_attr_put(&peer, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, &keepalive,
	    sizeof(keepalive));
	for (at = 0; at < allowed_count; at++) {
		ncfg_buf_t     entry;
		ncfg_wire_ip_t address;
		uint16_t       family;
		const char    *slash = strchr(allowed[at], '/');
		char           head[64];

		if (!slash || (size_t)(slash - allowed[at]) >= sizeof(head)) {
			continue;
		}
		memcpy(head, allowed[at], (size_t)(slash - allowed[at]));
		head[slash - allowed[at]] = '\0';
		if (!ncfg_wire_ip_parse(head, &address, NULL, 0)) {
			continue;
		}
		family = (uint16_t)address.family;
		ncfg_buf_init(&entry, 0);
		ncfg_wire_attr_put(&entry, WGALLOWEDIP_A_FAMILY, &family, sizeof(family));
		ncfg_wire_attr_put_ip(&entry, WGALLOWEDIP_A_IPADDR, &address);
		ncfg_wire_attr_put_u8(&entry, WGALLOWEDIP_A_CIDR_MASK,
		    (uint8_t)atoi(slash + 1));
		ncfg_wire_attr_put_nested(&nest, (uint16_t)at, &entry);
		ncfg_buf_free(&entry);
	}
	ncfg_wire_attr_put_nested(&peer, WGPEER_A_ALLOWEDIPS, &nest);
	ncfg_wire_attr_put_nested(array, index, &peer);
	ncfg_buf_free(&peer);
	ncfg_buf_free(&nest);
}

/* The device half of a `GET_DEVICE` reply: the key it derived, the port it
 * holds and a mark of zero, which is how the kernel spells "none". */
static void append_device(ncfg_buf_t *out, uint16_t family_id, int with_device,
    const ncfg_buf_t *peers)
{
	ncfg_genl_header_t header;
	ncfg_buf_t         payload;

	header.cmd = WG_CMD_GET_DEVICE;
	header.version = WG_GENL_VERSION;
	ncfg_buf_init(&payload, 0);
	ncfg_genl_header_encode(&header, &payload);
	ncfg_wire_attr_put_str(&payload, WGDEVICE_A_IFNAME, "wg0");
	if (with_device) {
		unsigned char key[NCFG_WG_KEY_LEN];
		uint16_t      port = 51820;
		uint32_t      fwmark = 0;

		fill_key(key, 0x03);
		ncfg_wire_attr_put(&payload, WGDEVICE_A_PUBLIC_KEY, key, sizeof(key));
		ncfg_wire_attr_put(&payload, WGDEVICE_A_LISTEN_PORT, &port, sizeof(port));
		ncfg_wire_attr_put_u32(&payload, WGDEVICE_A_FWMARK, fwmark);
	}
	if (peers) {
		ncfg_wire_attr_put_nested(&payload, WGDEVICE_A_PEERS, peers);
	}
	append_message(out, family_id, &payload);
	ncfg_buf_free(&payload);
}

/* ------------------------------------------------------------------------ *
 * The fake datagram source
 * ------------------------------------------------------------------------ */

#define QUEUED_MAX 8u

typedef struct {
	const uint8_t *bytes;
	size_t         length;
	int            fails;
	int            code;
} queued_t;

typedef struct {
	queued_t at[QUEUED_MAX];
	size_t   count;
	size_t   next;
} script_t;

static ssize_t script_recv(void *context, void *bytes, size_t length, int peek, uint32_t *from)
{
	script_t       *script = context;
	const queued_t *one;
	size_t          copy;

	*from = UINT32_MAX;
	if (script->next >= script->count) {
		errno = EAGAIN;
		return -1;
	}
	one = &script->at[script->next];
	if (one->fails) {
		if (!peek) {
			script->next++;
		}
		errno = one->code;
		return -1;
	}
	*from = 0u;
	copy = one->length < length ? one->length : length;
	if (copy) {
		memcpy(bytes, one->bytes, copy);
	}
	if (peek) {
		return (ssize_t)one->length;
	}
	script->next++;
	return (ssize_t)one->length;
}

static void queue(script_t *script, const ncfg_buf_t *buffer)
{
	if (script->count < QUEUED_MAX) {
		script->at[script->count].bytes = (const uint8_t *)buffer->data;
		script->at[script->count].length = buffer->length;
		script->at[script->count].fails = 0;
		script->at[script->count].code = 0;
		script->count++;
	}
}

static void queue_failure(script_t *script, int code)
{
	if (script->count < QUEUED_MAX) {
		memset(&script->at[script->count], 0, sizeof(script->at[script->count]));
		script->at[script->count].fails = 1;
		script->at[script->count].code = code;
		script->count++;
	}
}

static void kernel_of(ncfg_observe_kernel_t *kernel, ncfg_observe_replay_t *replay,
    script_t *script)
{
	memset(replay, 0, sizeof(*replay));
	replay->recv = script_recv;
	replay->context = script;
	memset(kernel, 0, sizeof(*kernel));
	kernel->exchange = ncfg_observe_exchange_replay;
	kernel->context = replay;
}

/* ------------------------------------------------------------------------ *
 * One machine: a WireGuard device and an ethernet beside it
 * ------------------------------------------------------------------------ */

#define MACHINE \
	"\"links\":[" \
	PLANFIX_LINK("wg0", ",\"kind\":\"wireguard\"") "," \
	PLANFIX_LINK("eth0", ",\"kind\":\"\"") "]"

/*
 * The reply a device with two peers sends, **as two messages**.
 *
 * The kernel splits a device across messages when its peers do not fit one,
 * and taking only the first reports a truncated configuration as the whole of
 * it -- which a reconciler reads as "these peers are missing" and reinstalls on
 * every pass. The peers are also given in the order the kernel happens to hold
 * them, which is the other half: the observation has to come back sorted by
 * public key or the planner's ordered comparison differs from a device that is
 * already right.
 */
static void two_message_reply(ncfg_buf_t *out, uint16_t family_id)
{
	static const char *const allowed[] = { "192.168.1.0/24", "10.0.0.0/8" };
	unsigned char            two[NCFG_WG_KEY_LEN];
	unsigned char            one[NCFG_WG_KEY_LEN];
	ncfg_buf_t               array;

	fill_key(two, 0x02);
	fill_key(one, 0x01);
	ncfg_buf_init(out, 0);

	ncfg_buf_init(&array, 0);
	put_peer(&array, 0, two, 1, "192.0.2.1:51820", 0, allowed, 2u);
	append_device(out, family_id, 1, &array);
	ncfg_buf_free(&array);

	ncfg_buf_init(&array, 0);
	put_peer(&array, 0, one, 0, NULL, 25, NULL, 0u);
	append_device(out, family_id, 0, &array);
	ncfg_buf_free(&array);

	append_done(out);
}

/* The observation, with the pass run over it. `script` and its buffers must
 * outlive the call, which is why they are the caller's. */
static ncfg_observed_t *observed_through(script_t *script, char *err, size_t err_size)
{
	ncfg_observe_replay_t replay;
	ncfg_observe_kernel_t kernel;
	ncfg_observed_t      *observed = planfix_observed(MACHINE);

	if (!observed) {
		return NULL;
	}
	kernel_of(&kernel, &replay, script);
	if (!ncfg_observe_wireguard_from(&kernel, observed, err, err_size)) {
		ncfg_observed_free(observed);
		return NULL;
	}
	return observed;
}

/* ------------------------------------------------------------------------ *
 * What the kernel holds
 * ------------------------------------------------------------------------ */

static void the_device_the_kernel_holds(void)
{
	script_t                         script;
	ncfg_buf_t                       family;
	ncfg_buf_t                       device;
	ncfg_observed_t                 *observed;
	const ncfg_observed_link_t      *link;
	const ncfg_observed_wireguard_t *wireguard;
	unsigned char                    expected[NCFG_WG_KEY_LEN];
	char                             err[NCFG_ERROR_MAX];

	memset(&script, 0, sizeof(script));
	ncfg_buf_init(&family, 0);
	append_family(&family, "wireguard", 27u);
	two_message_reply(&device, 27u);
	queue(&script, &family);
	queue(&script, &device);

	err[0] = '\0';
	observed = observed_through(&script, err, sizeof(err));
	if (!check(observed != NULL, "a WireGuard device is read over the generic netlink seam")) {
		detail("it said", err);
		ncfg_buf_free(&family);
		ncfg_buf_free(&device);
		return;
	}
	link = ncfg_observed_link(observed, "wg0");
	wireguard = link ? link->wireguard : NULL;
	if (!check(wireguard != NULL, "and the link carries what the device holds")) {
		ncfg_observed_free(observed);
		ncfg_buf_free(&family);
		ncfg_buf_free(&device);
		return;
	}
	fill_key(expected, 0x03);
	check(wireguard->public_key.has &&
	    memcmp(wireguard->public_key.bytes, expected, sizeof(expected)) == 0,
	    "the public key the kernel derived, which is the one a peer is given");
	check(link->private_key_loaded == 1,
	    "and `private_key_loaded` is that presence and never a request for the key");
	check(wireguard->listen_port.has && wireguard->listen_port.value == 51820,
	    "the listen port the kernel holds");
	check(!wireguard->fwmark.has,
	    "a mark of zero is absent, because zero is how the kernel spells none");

	if (check(wireguard->peer_count == 2u, "both messages' peers, not just the first's")) {
		fill_key(expected, 0x01);
		check(memcmp(wireguard->peers[0].public_key, expected, sizeof(expected)) == 0,
		    "sorted by public key, which is the one name both sides have");
		check(!wireguard->peers[0].preshared_key,
		    "a peer the kernel reports 32 zero octets for has no preshared key");
		check(wireguard->peers[0].keepalive.has &&
		    wireguard->peers[0].keepalive.value == 25,
		    "and its keepalive is carried");
		check(!wireguard->peers[0].preshared_matches.has,
		    "and no currency has been asked of it yet");
		check(wireguard->peers[1].preshared_key,
		    "a peer the kernel reports 32 non-zero octets for has one");
		check(!wireguard->peers[1].keepalive.has,
		    "a keepalive of zero is absent, for the mark's reason");
		check(wireguard->peers[1].endpoint &&
		    strcmp(wireguard->peers[1].endpoint, "192.0.2.1:51820") == 0,
		    "and the endpoint it is talking to, rendered as the document spells one");
		check(wireguard->peers[1].allowed_ip_count == 2u &&
		    strcmp(wireguard->peers[1].allowed_ips[0], "10.0.0.0/8") == 0 &&
		    strcmp(wireguard->peers[1].allowed_ips[1], "192.168.1.0/24") == 0,
		    "with its allowed IPs sorted rather than in the kernel's own order");
	}
	check(!wireguard->key_matches.has,
	    "and nothing about the private key, which this half cannot answer");

	link = ncfg_observed_link(observed, "eth0");
	check(link && !link->wireguard && !link->private_key_loaded,
	    "a link that is not WireGuard is not asked about and claims nothing");

	ncfg_observed_free(observed);
	ncfg_buf_free(&family);
	ncfg_buf_free(&device);
}

/*
 * A machine with no WireGuard asks the controller nothing.
 *
 * The Rust's guard, and it is not a micro-optimisation: the daemon reobserves
 * on every tick, so without it every machine netcfgd manages sends a generic
 * netlink round trip for ever to find out there is nothing to ask about.
 */
static void a_machine_with_no_wireguard_asks_nothing(void)
{
	script_t              script;
	ncfg_buf_t            family;
	ncfg_observe_replay_t replay;
	ncfg_observe_kernel_t kernel;
	ncfg_observed_t      *observed = planfix_observed(
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"kind\":\"\"") "]");
	char                  err[NCFG_ERROR_MAX];

	if (!observed) {
		return;
	}
	memset(&script, 0, sizeof(script));
	ncfg_buf_init(&family, 0);
	append_family(&family, "wireguard", 27u);
	queue(&script, &family);
	kernel_of(&kernel, &replay, &script);
	err[0] = '\0';
	check(ncfg_observe_wireguard_from(&kernel, observed, err, sizeof(err)),
	    "a machine with no WireGuard link observes successfully");
	check(script.next == 0u,
	    "and asks the generic netlink controller nothing at all");
	ncfg_observed_free(observed);
	ncfg_buf_free(&family);
}

/* ------------------------------------------------------------------------ *
 * Absence is not emptiness
 * ------------------------------------------------------------------------ */

/* What a link says about itself after a round that could not read it. */
static int says_nothing(const ncfg_observed_t *observed, const char *name)
{
	const ncfg_observed_link_t *link = ncfg_observed_link(observed, name);

	return link && link->wireguard == NULL && link->private_key_loaded == 0;
}

static void a_device_that_cannot_be_read_is_not_a_device_with_no_peers(void)
{
	ncfg_buf_t       family;
	ncfg_buf_t       device;
	ncfg_observed_t *observed;
	char             err[NCFG_ERROR_MAX];

	ncfg_buf_init(&family, 0);
	append_family(&family, "wireguard", 27u);

	/* The seam left out. */
	observed = planfix_observed(MACHINE);
	if (observed) {
		err[0] = '\0';
		check(ncfg_observe_wireguard_from(NULL, observed, err, sizeof(err)) &&
		    says_nothing(observed, "wg0"),
		    "no generic netlink seam leaves the device unobserved, not empty");
		ncfg_observed_free(observed);
	}

	/* A family that will not resolve: a container whose netlink is denied. */
	{
		script_t script;

		memset(&script, 0, sizeof(script));
		queue_failure(&script, EPERM);
		observed = observed_through(&script, err, sizeof(err));
		check(observed && says_nothing(observed, "wg0"),
		    "a family lookup this process may not make says nothing about the device");
		ncfg_observed_free(observed);
	}

	/* A device the kernel will not answer for: one that went away between the
	 * link dump and this request. */
	{
		script_t script;

		memset(&script, 0, sizeof(script));
		queue(&script, &family);
		queue_failure(&script, ENODEV);
		observed = observed_through(&script, err, sizeof(err));
		check(observed && says_nothing(observed, "wg0"),
		    "a device the kernel will not answer for says nothing either");
		ncfg_observed_free(observed);
	}

	/* A reply this port does not understand: a public key of the wrong
	 * length, which `sys/wg.c` refuses rather than reading a key out of the
	 * front of. Half a device is not a device. */
	{
		script_t           script;
		ncfg_genl_header_t header;
		ncfg_buf_t         payload;
		unsigned char      stub[8];

		ncfg_buf_init(&device, 0);
		ncfg_buf_init(&payload, 0);
		header.cmd = WG_CMD_GET_DEVICE;
		header.version = WG_GENL_VERSION;
		ncfg_genl_header_encode(&header, &payload);
		memset(stub, 0x09, sizeof(stub));
		ncfg_wire_attr_put(&payload, WGDEVICE_A_PUBLIC_KEY, stub, sizeof(stub));
		append_message(&device, 27u, &payload);
		append_done(&device);
		ncfg_buf_free(&payload);

		memset(&script, 0, sizeof(script));
		queue(&script, &family);
		queue(&script, &device);
		observed = observed_through(&script, err, sizeof(err));
		check(observed && says_nothing(observed, "wg0"),
		    "and a reply that will not read is not a device with no peers");
		ncfg_observed_free(observed);
		ncfg_buf_free(&device);
	}

	/* And a second pass through a seam that is absent does not leave the
	 * first one's answer behind. */
	{
		script_t script;

		memset(&script, 0, sizeof(script));
		two_message_reply(&device, 27u);
		queue(&script, &family);
		queue(&script, &device);
		observed = observed_through(&script, err, sizeof(err));
		if (check(observed && !says_nothing(observed, "wg0"),
		    "a device that was read once is there")) {
			err[0] = '\0';
			check(ncfg_observe_wireguard_from(NULL, observed, err, sizeof(err)) &&
			    says_nothing(observed, "wg0"),
			    "and a second observation through no seam forgets it");
		}
		ncfg_observed_free(observed);
		ncfg_buf_free(&device);
	}

	check(!ncfg_observe_wireguard_from(NULL, NULL, err, sizeof(err)),
	    "and there being no observation to write into is refused with a sentence");
	ncfg_buf_free(&family);
}

/* ------------------------------------------------------------------------ *
 * The fixture the currency question needs
 * ------------------------------------------------------------------------ */

static char fixture[256];
static char run_dir[320];
static char config_dir[320];
static char secrets_dir[384];

static void make_dir(const char *path)
{
	if (mkdir(path, 0700) != 0) {
		printf("observe_wireguard_test: could not make %s\n", path);
		exit(1);
	}
}

static void put(const char *path, const char *contents)
{
	if (!testdir_write(path, contents, strlen(contents))) {
		printf("observe_wireguard_test: could not write %s\n", path);
		exit(1);
	}
}

static void remove_file(const char *path)
{
	(void)unlink(path);
}

static void store(const char *name, const char *value)
{
	char err[NCFG_ERROR_MAX];

	err[0] = '\0';
	if (!ncfg_secret_store_put(config_dir, name, value, 1, NULL, err, sizeof(err))) {
		printf("observe_wireguard_test: could not store `%s`: %s\n", name, err);
		exit(1);
	}
}

static void make_the_fixture(void)
{
	char wireguard[384];

	(void)snprintf(fixture, sizeof(fixture), "%s", testdir_make("observe-wireguard"));
	(void)snprintf(run_dir, sizeof(run_dir), "%s/run", fixture);
	(void)snprintf(config_dir, sizeof(config_dir), "%s/etc", fixture);
	(void)snprintf(secrets_dir, sizeof(secrets_dir), "%s/secrets", config_dir);
	make_dir(run_dir);
	make_dir(config_dir);
	(void)snprintf(wireguard, sizeof(wireguard), "%s/wireguard", run_dir);
	make_dir(wireguard);
	/* Written by the store rather than by this file, so the 0600 the resolver
	 * insists on is the store's own answer rather than a fixture's guess. */
	store("wg0-private", STORED_PRIVATE_TEXT);
	store("psk-two", STORED_PRESET_TEXT);
	store("canary", CANARY);
}

static const char *key_record(void)
{
	static char path[NCFG_OBSERVE_WG_RECORD_PATH_MAX];

	if (!ncfg_observe_wg_key_record_path(run_dir, "wg0", path, sizeof(path), NULL, 0)) {
		path[0] = '\0';
	}
	return path;
}

static const char *preset_record(void)
{
	static char path[NCFG_OBSERVE_WG_RECORD_PATH_MAX];

	if (!ncfg_observe_wg_preset_record_path(run_dir, "wg0", path, sizeof(path), NULL, 0)) {
		path[0] = '\0';
	}
	return path;
}

/* The document that describes `wg0`, with `key` naming the private key's entry
 * and `peers` whatever a case needs. */
#define DOC_DEVICE(key, peers) \
	"{\"name\":\"wg0\",\"kind\":{\"kind\":\"wire_guard\"," \
	"\"private_key\":{\"provider\":\"file\",\"name\":\"" key "\"}," \
	"\"listen_port\":51820,\"peers\":[" peers "]}}"

#define DOC_PEER_TWO \
	"{\"name\":\"hub\",\"public_key\":\"" PEER_TWO_TEXT "\"," \
	"\"preshared_key\":{\"provider\":\"file\",\"name\":\"psk-two\"}," \
	"\"allowed_ips\":[\"10.0.0.0/8\",\"192.168.1.0/24\"]}"
#define DOC_PEER_ONE \
	"{\"name\":\"spoke\",\"public_key\":\"" PEER_ONE_TEXT "\"," \
	"\"keepalive\":25,\"allowed_ips\":[]}"

static ncfg_document_t *the_document(const char *key)
{
	char devices[2048];

	(void)snprintf(devices, sizeof(devices), DOC_DEVICE("%s", "%s,%s"), key, DOC_PEER_TWO,
	    DOC_PEER_ONE);
	return planfix_document(devices, "", "", "");
}

/*
 * An observation with the netlink half already run over it.
 *
 * **The two buffers are released before they are rebuilt**, because a case
 * asks for several observations of one machine and `two_message_reply` starts
 * by initialising what it is handed. The caller initialises them once and
 * frees them at the end; everything between is this. ASan is what says so: the
 * first version of this file leaked twelve of them.
 */
static ncfg_observed_t *the_observation(script_t *script, ncfg_buf_t *family,
    ncfg_buf_t *device)
{
	char err[NCFG_ERROR_MAX];

	memset(script, 0, sizeof(*script));
	ncfg_buf_free(family);
	ncfg_buf_free(device);
	ncfg_buf_init(family, 0);
	append_family(family, "wireguard", 27u);
	two_message_reply(device, 27u);
	queue(script, family);
	queue(script, device);
	err[0] = '\0';
	return observed_through(script, err, sizeof(err));
}

static ncfg_optbool_t key_answer(const ncfg_observed_t *observed)
{
	const ncfg_observed_link_t *link = ncfg_observed_link(observed, "wg0");
	ncfg_optbool_t              none = { 0, 0 };

	return (link && link->wireguard) ? link->wireguard->key_matches : none;
}

/* ------------------------------------------------------------------------ *
 * Is what is running what was asked for
 * ------------------------------------------------------------------------ */

static void the_currency_question(void)
{
	script_t               script;
	ncfg_buf_t             family;
	ncfg_buf_t             device;
	ncfg_secret_resolver_t resolver;
	ncfg_document_t       *document = the_document("wg0-private");
	ncfg_observed_t       *observed;
	char                   err[NCFG_ERROR_MAX];

	ncfg_buf_init(&family, 0);
	ncfg_buf_init(&device, 0);

	memset(&resolver, 0, sizeof(resolver));
	resolver.secrets_dir = secrets_dir;
	if (!document) {
		return;
	}

	put(key_record(), STORED_PRIVATE_DIGEST "\n");
	put(preset_record(), PEER_TWO_TEXT " " STORED_PRESET_DIGEST "\n");

	observed = the_observation(&script, &family, &device);
	if (check(observed != NULL, "an observation to ask the currency question of")) {
		const ncfg_observed_link_t *link;

		err[0] = '\0';
		check(ncfg_observe_wireguard_currency(observed, run_dir, &resolver, document,
		    err, sizeof(err)), "the currency question is asked");
		check(key_answer(observed).has && key_answer(observed).value,
		    "a device running the key the store holds reports it current");
		link = ncfg_observed_link(observed, "wg0");
		check(link && link->wireguard && link->wireguard->peer_count == 2u &&
		    link->wireguard->peers[1].preshared_matches.has &&
		    link->wireguard->peers[1].preshared_matches.value,
		    "and so does a peer whose preshared key is the one it was given");
		check(link && link->wireguard &&
		    !link->wireguard->peers[0].preshared_matches.has,
		    "a peer with no preshared key has nothing to be out of date");
		ncfg_observed_free(observed);
	}

	/* The whole point of the record: the operator rotates the secret and the
	 * kernel goes on using what it was handed. */
	put(key_record(), SOME_OTHER_DIGEST "\n");
	observed = the_observation(&script, &family, &device);
	if (observed) {
		err[0] = '\0';
		(void)ncfg_observe_wireguard_currency(observed, run_dir, &resolver, document,
		    err, sizeof(err));
		check(key_answer(observed).has && !key_answer(observed).value,
		    "a key the store has rotated under a running device reports stale");
		ncfg_observed_free(observed);
	}
	put(key_record(), STORED_PRIVATE_DIGEST "\n");

	/*
	 * The same 32 octets, spelled with the other setting of the two bits
	 * base64 does not use. The record is parsed rather than compared as text,
	 * so this is the same peer -- the Rust compares the rendered strings and
	 * would call this a peer it has no record of.
	 */
	put(preset_record(), PEER_TWO_OTHER_SPELLING " " STORED_PRESET_DIGEST "\n");
	observed = the_observation(&script, &family, &device);
	if (observed) {
		const ncfg_observed_link_t *link;

		err[0] = '\0';
		(void)ncfg_observe_wireguard_currency(observed, run_dir, &resolver, document,
		    err, sizeof(err));
		link = ncfg_observed_link(observed, "wg0");
		check(link && link->wireguard && link->wireguard->peer_count == 2u &&
		    link->wireguard->peers[1].preshared_matches.has,
		    "a record written in the other spelling of one key is the same peer");
		ncfg_observed_free(observed);
	}
	put(preset_record(), PEER_TWO_TEXT " " STORED_PRESET_DIGEST "\n");

	/* Four ways to be asked nothing, and none of them is `false`. */
	remove_file(key_record());
	observed = the_observation(&script, &family, &device);
	if (observed) {
		err[0] = '\0';
		(void)ncfg_observe_wireguard_currency(observed, run_dir, &resolver, document,
		    err, sizeof(err));
		check(!key_answer(observed).has,
		    "a device netcfgd has no record for leaves the question unanswered");
		ncfg_observed_free(observed);
	}
	put(key_record(), STORED_PRIVATE_DIGEST "\n");

	observed = the_observation(&script, &family, &device);
	if (observed) {
		err[0] = '\0';
		(void)ncfg_observe_wireguard_currency(observed, run_dir, NULL, document, err,
		    sizeof(err));
		check(!key_answer(observed).has,
		    "no store named asks nothing, rather than reaching for the machine's");
		(void)ncfg_observe_wireguard_currency(observed, run_dir, &resolver, NULL, err,
		    sizeof(err));
		check(!key_answer(observed).has,
		    "and a configuration that does not compile leaves it unanswered too");
		ncfg_observed_free(observed);
	}

	{
		ncfg_document_t *elsewhere = the_document("no-such-entry");

		observed = the_observation(&script, &family, &device);
		if (observed && elsewhere) {
			err[0] = '\0';
			(void)ncfg_observe_wireguard_currency(observed, run_dir, &resolver,
			    elsewhere, err, sizeof(err));
			check(!key_answer(observed).has,
			    "a secret the store cannot resolve is not a rotated key");
		}
		ncfg_observed_free(observed);
		ncfg_document_free(elsewhere);
	}

	check(!ncfg_observe_wireguard_currency(NULL, run_dir, &resolver, document, err,
	    sizeof(err)),
	    "and there being no observation to write into is refused with a sentence");

	ncfg_document_free(document);
	ncfg_buf_free(&family);
	ncfg_buf_free(&device);
}

/* ------------------------------------------------------------------------ *
 * Nothing that identifies a key leaves this pass
 * ------------------------------------------------------------------------ */

/*
 * Every `err` this pass fills, everything it says on standard error, and the
 * observation as `/run` would hold it, swept for a value nothing may repeat
 * and for the digest of it.
 *
 * **The digest is swept for as well as the value.** A digest of a WireGuard
 * key is not a way back to one, which is why writing it to a 0600 file under
 * `/run` is defensible -- but it identifies the key it was taken of, so a log
 * line carrying one would let anyone reading the journal tell which key a
 * device is running. Neither may appear.
 */
static void nothing_that_identifies_a_key_leaves_this_pass(void)
{
	script_t               script;
	ncfg_buf_t             family;
	ncfg_buf_t             device;
	ncfg_buf_t             written;
	ncfg_secret_resolver_t resolver;
	ncfg_document_t       *document = the_document("canary");
	ncfg_observed_t       *observed;
	ncfg_secret_t         *reachable;
	ncfg_secret_ref_t      reference;
	char                   log_path[384];
	char                  *said;
	size_t                 said_length = 0;
	char                   err[NCFG_ERROR_MAX];
	int                    saved_stderr;
	int                    wrote = 0;
	int                    log;

	ncfg_buf_init(&family, 0);
	ncfg_buf_init(&device, 0);

	memset(&resolver, 0, sizeof(resolver));
	resolver.secrets_dir = secrets_dir;
	if (!document) {
		return;
	}

	/*
	 * **The sweep is proved reachable before it is run.** A store that
	 * silently held nothing would pass this whole case exactly as loudly as
	 * one that held the canary and kept quiet about it.
	 */
	memset(&reference, 0, sizeof(reference));
	reference.provider = NCFG_SECRET_PROVIDER_FILE;
	reference.name = (char *)(uintptr_t)"canary";
	err[0] = '\0';
	reachable = ncfg_secret_resolve(&resolver, &reference, NULL, err, sizeof(err));
	if (!check(reachable != NULL && strcmp(ncfg_secret_expose(reachable), CANARY) == 0,
	    "the canary is in the store and this test can reach it")) {
		detail("it said", err);
		ncfg_secret_free(reachable);
		ncfg_document_free(document);
		return;
	}
	ncfg_secret_free(reachable);

	/* A record naming the canary's own digest, so that the comparison runs to
	 * the end rather than stopping at a mismatch, and a peer record too. */
	put(key_record(), CANARY_DIGEST "\n");
	put(preset_record(), PEER_TWO_TEXT " " CANARY_DIGEST "\n");

	(void)snprintf(log_path, sizeof(log_path), "%s/said.log", fixture);
	saved_stderr = dup(STDERR_FILENO);
	log = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (log >= 0) {
		(void)dup2(log, STDERR_FILENO);
		(void)close(log);
	}

	ncfg_buf_init(&written, 0);
	observed = the_observation(&script, &family, &device);
	err[0] = '\0';
	if (observed) {
		(void)ncfg_observe_wireguard_currency(observed, run_dir, &resolver, document,
		    err, sizeof(err));
		/* Serialized here, between the two calls, because the second is about
		 * a store that cannot answer and leaves the question unanswered --
		 * and an unanswered question omits itself, so the observation to
		 * sweep is the one that carries an answer. */
		wrote = ncfg_observed_write(observed, &written, err, sizeof(err));
		/* And once more against a store that cannot answer, which is the
		 * path that writes a note carrying the store's own sentence. */
		{
			ncfg_document_t *missing = the_document("no-such-entry");

			(void)ncfg_observe_wireguard_currency(observed, run_dir, &resolver,
			    missing, err, sizeof(err));
			ncfg_document_free(missing);
		}
	}
	(void)fflush(stderr);
	if (saved_stderr >= 0) {
		(void)dup2(saved_stderr, STDERR_FILENO);
		(void)close(saved_stderr);
	}

	said = testdir_read(log_path, &said_length);
	check(said != NULL && said_length > 0,
	    "this pass said something on standard error, so the sweep is not vacuous");
	check(!said || strstr(said, CANARY) == NULL,
	    "and nothing it said carries the material");
	check(!said || strstr(said, CANARY_DIGEST) == NULL,
	    "nor a digest of it, which would identify the key just as well");
	free(said);
	check(strstr(err, CANARY) == NULL && strstr(err, CANARY_DIGEST) == NULL,
	    "the error buffer this pass was handed carries neither");

	if (observed && check(wrote, "the observation serializes as `/run` would hold it")) {
		const char *text = ncfg_buf_text(&written);

		check(strstr(text, "wg0") != NULL,
		    "and it does describe the device, so this sweep looked at something");
		check(strstr(text, CANARY) == NULL && strstr(text, CANARY_DIGEST) == NULL,
		    "and carries neither the material nor a digest of it");
		check(strstr(text, "key_matches") != NULL,
		    "what it does carry about the key is the answer, which is a boolean");
	}
	ncfg_buf_free(&written);

	ncfg_observed_free(observed);
	ncfg_document_free(document);
	ncfg_buf_free(&family);
	ncfg_buf_free(&device);
	put(key_record(), STORED_PRIVATE_DIGEST "\n");
	put(preset_record(), PEER_TWO_TEXT " " STORED_PRESET_DIGEST "\n");
}

/* ------------------------------------------------------------------------ *
 * What the observation buys the planner
 * ------------------------------------------------------------------------ */

static int quiet(const ncfg_plan_t *plan)
{
	char names[512];

	if (ncfg_plan_is_empty(plan)) {
		return 1;
	}
	planfix_names(plan, names, sizeof(names));
	printf("  expected nothing to do; the plan is [%s]\n", names);
	return 0;
}

/*
 * The convergence check, in both directions and with the third case that says
 * what the missing pass actually cost.
 *
 * **It is not the non-convergence NAT and the offloads had.** Those two filled
 * a list the planner compared against, so an empty one planned the same op for
 * ever. `ncfg_plan_wireguard` returns without planning anything for a link with
 * no `wireguard` observation, so the cost of this pass being missing was the
 * opposite: an edited port, a rotated key and a deleted peer each planned
 * nothing whatever, for as long as WireGuard has existed here.
 */
static void what_the_observation_buys_the_planner(void)
{
	script_t               script;
	ncfg_buf_t             family;
	ncfg_buf_t             device;
	ncfg_secret_resolver_t resolver;
	ncfg_document_t       *document = the_document("wg0-private");
	ncfg_observed_t       *observed;
	ncfg_plan_t           *plan;
	char                   err[NCFG_ERROR_MAX];

	ncfg_buf_init(&family, 0);
	ncfg_buf_init(&device, 0);

	memset(&resolver, 0, sizeof(resolver));
	resolver.secrets_dir = secrets_dir;
	if (!document) {
		return;
	}
	put(key_record(), STORED_PRIVATE_DIGEST "\n");
	put(preset_record(), PEER_TWO_TEXT " " STORED_PRESET_DIGEST "\n");

	observed = the_observation(&script, &family, &device);
	if (check(observed != NULL, "a device observed exactly as the document describes it")) {
		err[0] = '\0';
		(void)ncfg_observe_wireguard_currency(observed, run_dir, &resolver, document,
		    err, sizeof(err));
		plan = ncfg_plan_build(document, observed, NULL, err, sizeof(err));
		if (check(plan != NULL, "and a plan built from the two")) {
			check(quiet(plan),
			    "a device already carrying the right key plans no wg.set_device");
		}
		ncfg_plan_free(plan);
		ncfg_observed_free(observed);
	}

	/* The same observation against a document that wants another port. */
	{
		ncfg_document_t *moved;
		char             devices[2048];

		(void)snprintf(devices, sizeof(devices),
		    "{\"name\":\"wg0\",\"kind\":{\"kind\":\"wire_guard\","
		    "\"private_key\":{\"provider\":\"file\",\"name\":\"wg0-private\"},"
		    "\"listen_port\":51821,\"peers\":[%s,%s]}}", DOC_PEER_TWO, DOC_PEER_ONE);
		moved = planfix_document(devices, "", "", "");
		observed = the_observation(&script, &family, &device);
		if (moved && observed) {
			const ncfg_action_t *action;

			err[0] = '\0';
			plan = ncfg_plan_build(moved, observed, NULL, err, sizeof(err));
			action = plan ? planfix_for_field(plan, "wg.set_device",
			    "wireguard.listen_port") : NULL;
			check(action != NULL,
			    "and an edited listen port is now noticed, which it never was");
			ncfg_plan_free(plan);
		}
		ncfg_observed_free(observed);
		ncfg_document_free(moved);
	}

	/* And what it was like before this pass: an observation with the device
	 * unobserved plans nothing at all, whatever the document says. */
	{
		ncfg_document_t *moved;
		char             devices[2048];

		(void)snprintf(devices, sizeof(devices),
		    "{\"name\":\"wg0\",\"kind\":{\"kind\":\"wire_guard\","
		    "\"private_key\":{\"provider\":\"file\",\"name\":\"wg0-private\"},"
		    "\"listen_port\":51821,\"peers\":[]}}");
		moved = planfix_document(devices, "", "", "");
		observed = planfix_observed(MACHINE);
		if (moved && observed) {
			err[0] = '\0';
			plan = ncfg_plan_build(moved, observed, NULL, err, sizeof(err));
			check(plan && quiet(plan),
			    "and with no observation of the device, nothing was planned at all");
			ncfg_plan_free(plan);
		}
		ncfg_observed_free(observed);
		ncfg_document_free(moved);
	}

	ncfg_document_free(document);
	ncfg_buf_free(&family);
	ncfg_buf_free(&device);
}

/* ------------------------------------------------------------------------ *
 * The record paths
 * ------------------------------------------------------------------------ */

static void the_record_paths(void)
{
	char path[NCFG_OBSERVE_WG_RECORD_PATH_MAX];
	char small[8];
	char err[NCFG_ERROR_MAX];

	check(ncfg_observe_wg_key_record_path("/run/netcfgd", "wg0", path, sizeof(path), NULL,
	    0) && strcmp(path, "/run/netcfgd/wireguard/wg0.key.sha256") == 0,
	    "the key record is named where the Rust names it");
	check(ncfg_observe_wg_preset_record_path("/run/netcfgd", "wg0", path, sizeof(path),
	    NULL, 0) && strcmp(path, "/run/netcfgd/wireguard/wg0.psk.sha256") == 0,
	    "and so is the preshared-key record");
	err[0] = '\0';
	check(!ncfg_observe_wg_key_record_path("/run/netcfgd", "wg0", small, sizeof(small), err,
	    sizeof(err)) && small[0] == '\0',
	    "a path that does not fit is refused rather than truncated into another file");
	check(!ncfg_observe_wg_key_record_path(NULL, "wg0", path, sizeof(path), NULL, 0) &&
	    !ncfg_observe_wg_key_record_path("/run", NULL, path, sizeof(path), NULL, 0),
	    "and a record needs both halves of its name");
}

int main(void)
{
	ncfg_log_accept(NCFG_LOG_NOTE);
	make_the_fixture();

	the_device_the_kernel_holds();
	a_machine_with_no_wireguard_asks_nothing();
	a_device_that_cannot_be_read_is_not_a_device_with_no_peers();
	the_record_paths();
	the_currency_question();
	nothing_that_identifies_a_key_leaves_this_pass();
	what_the_observation_buys_the_planner();

	testdir_remove(fixture);
	printf("observe_wireguard_test: %d check(s)\n", checks);
	if (failures) {
		printf("observe_wireguard_test: %d FAILED\n", failures);
		return 1;
	}
	printf("observe_wireguard_test: all checks passed\n");
	return 0;
}
