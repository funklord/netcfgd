/*
 * kernel_genl.c -- the three ops that are generic netlink: a WireGuard
 * device, its peers, and a driver's offloads.
 *
 * WHY EACH OF THESE OPENS A SOCKET OF ITS OWN
 *   The executor holds an **rtnetlink** socket. Generic netlink is a second
 *   protocol on the same socket family with its own message layout, and
 *   `netlink.h` says what that means: a family id resolved on one socket is
 *   meaningless on the other, so these cannot share the executor's. The
 *   alternative -- two more descriptors and two cached family ids on every
 *   executor, opened whether or not a plan has a WireGuard device in it -- is
 *   `ncfg_contenders_find`'s mistake pointed the other way, and 0263 already
 *   records it: netcfgd used to open an executor every five seconds on every
 *   machine it managed to discover there was nothing to do.
 *
 *   So the socket and the family lookup are the op's, and they last exactly as
 *   long as the op does. What it costs is one extra round trip per op, on a
 *   plan that has at most a handful of them; what it buys is that a machine
 *   with no WireGuard and no offloads to set never asks the controller
 *   anything, and that nothing outlives the call.
 *
 * WHY A `GETFAMILY` IS TAKEN APART RATHER THAN SENT
 *   `ncfg_genl_getfamily_request` builds a complete message, and `netlink.h`
 *   has no call that sends a prepared one and reads a reply that is neither a
 *   dump nor an acknowledgement -- `ncfg_netlink_send_batch` waits for an ack
 *   the controller never sends, which is a five-second timeout rather than an
 *   answer. `src/observe/collect.c` met the same gap with the two traffic
 *   control requests and answered it the same way: build the message with the
 *   module that owns it, walk it with the wire layer, and hand
 *   `ncfg_netlink_request` the kind, the flags and the body found there.
 *   Nothing about the request is spelled a second time -- not the command, not
 *   the controller's id, not the name length check.
 *
 * KEY MATERIAL, AND THE THREE PLACES IT EXISTS
 *   The document carries a *reference*; the store hands back text; this file
 *   turns it into 32 octets and puts them in the request. Every one of the
 *   three is scrubbed before it is released -- `ncfg_secret_free` wipes,
 *   `ncfg_wg_messages_free` wipes, and the octets in between are wiped here.
 *   Nothing in this file renders a key, quotes one in a refusal, or logs one.
 */
#include "kernel_internal.h"

#include "ncfg/base.h"
#include "ncfg/wire.h"

#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/* ------------------------------------------------------------------------ *
 * A socket, and a family on it
 * ------------------------------------------------------------------------ */

/* The same five seconds `kernel.c` gives an rtnetlink request, and for its
 * reason: a daemon holding CAP_NET_ADMIN wedged on a lost message is worse
 * than one that reports an error. */
#define REQUEST_SECONDS 5

/*
 * The kind, the flags and the payload of a message this port built.
 *
 * `collect.c` has the same three lines for the same reason and says why: the
 * alternative is spelling the request again, which is how a request comes to
 * be aimed at the wrong thing in the one module that does not own it.
 */
static int request_parts(const ncfg_buf_t *message, uint16_t *kind, uint16_t *flags,
    ncfg_buf_t *body, char *err, size_t err_size)
{
	ncfg_wire_messages_t walk;
	ncfg_wire_message_t  parsed;

	ncfg_wire_messages_start(&walk, message->data, message->length);
	if (ncfg_wire_messages_next(&walk, &parsed, err, err_size) != NCFG_WIRE_OK) {
		ncfg_error_set(err, err_size,
		    "a generic netlink request this port built is not a netlink message");
		return 0;
	}
	*kind = parsed.header.kind;
	*flags = parsed.header.flags;
	ncfg_buf_add(body, parsed.payload, parsed.payload_length);
	if (ncfg_buf_failed(body)) {
		ncfg_error_set(err, err_size, "no room for a generic netlink request");
		return 0;
	}
	return 1;
}

/*
 * Open a generic netlink socket and resolve one family on it.
 *
 * On success the caller owns both and closes the socket with
 * `ncfg_netlink_close` and the family with `ncfg_genl_family_free`. On failure
 * neither is left open.
 */
static int family_open(const char *name, ncfg_netlink_t *socket, ncfg_genl_family_t *family,
    char *err, size_t err_size)
{
	ncfg_buf_t           message;
	ncfg_buf_t           body;
	ncfg_netlink_reply_t reply;
	uint16_t             kind = 0;
	uint16_t             flags = 0;
	uint32_t             seq;
	int                  ok;

	memset(family, 0, sizeof(*family));
	ncfg_netlink_init(socket);
	if (!ncfg_netlink_open_protocol(socket, NETLINK_GENERIC, 0, err, err_size)) {
		return 0;
	}
	if (!ncfg_netlink_set_timeout(socket, REQUEST_SECONDS, err, err_size)) {
		ncfg_netlink_close(socket);
		return 0;
	}
	seq = ncfg_netlink_take_seq(socket);
	ncfg_buf_init(&message, 0);
	ncfg_buf_init(&body, 0);
	memset(&reply, 0, sizeof(reply));
	ok = ncfg_genl_getfamily_request(&message, name, seq, err, err_size) &&
	    request_parts(&message, &kind, &flags, &body, err, err_size);
	if (ok) {
		ok = ncfg_netlink_request(socket, kind, flags, &body, NULL, &reply, err, err_size);
	}
	ncfg_buf_free(&message);
	ncfg_buf_free(&body);
	if (ok && reply.count == 0) {
		/*
		 * The controller answered and named no family. `ncfg_genl_lookup_
		 * failed` is for a kernel that refused; this is a reply that arrived
		 * and said nothing, which reads downstream as a family with id zero
		 * -- and `ncfg_genl_build_request` refuses that, five seconds later
		 * and about the wrong thing.
		 */
		ncfg_error_set(err, err_size,
		    "the generic netlink controller answered about `%s` without naming a "
		    "family", name);
		ok = 0;
	}
	if (ok) {
		ok = ncfg_genl_family_parse(name, reply.items[0].bytes, reply.items[0].length,
		    family, err, err_size);
	}
	ncfg_netlink_reply_free(&reply);
	if (!ok) {
		ncfg_netlink_close(socket);
	}
	return ok;
}

/* ------------------------------------------------------------------------ *
 * Endpoints
 * ------------------------------------------------------------------------ */

int ncfg_kernel_endpoint(const char *text, ncfg_wire_ip_t *address, uint16_t *port, char *err,
    size_t err_size)
{
	struct addrinfo  hints;
	struct addrinfo *answers = NULL;
	char             host[NCFG_ERROR_MAX];
	const char      *colon;
	int              looked;

	if (!text || !address || !port) {
		ncfg_error_set(err, err_size, "there is no endpoint to resolve");
		return 0;
	}
	/* A literal costs nothing and is most of them. It also settles the
	 * bracketed IPv6 form, which `ncfg_wg_endpoint_parse` requires for the
	 * reason brackets exist at all: `fd00::1:51820` is a perfectly good
	 * address, and reading a port off the end of one would silently
	 * reconfigure a peer to talk to somewhere else. */
	if (ncfg_wg_endpoint_parse(text, address, port, NULL, 0)) {
		return 1;
	}
	colon = strrchr(text, ':');
	if (!colon || colon == text || colon[1] == '\0') {
		ncfg_error_set(err, err_size,
		    "`%s` is not an endpoint: a peer's endpoint is a host and a port, and an "
		    "IPv6 literal carries brackets around the address", text);
		return 0;
	}
	if (memchr(text, ':', (size_t)(colon - text)) != NULL) {
		/* More than one colon and the literal parser refused it, so this is
		 * a bare IPv6 address or a malformed bracketed one. Either way the
		 * part before the last colon is not a host name. */
		ncfg_error_set(err, err_size,
		    "`%s` is not an endpoint: an IPv6 literal needs brackets around the "
		    "address, as `[2001:db8::1]:51820` does", text);
		return 0;
	}
	if ((size_t)(colon - text) >= sizeof(host)) {
		ncfg_error_set(err, err_size, "an endpoint's host name is too long to resolve");
		return 0;
	}
	memcpy(host, text, (size_t)(colon - text));
	host[colon - text] = '\0';

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	looked = getaddrinfo(host, colon + 1, &hints, &answers);
	if (looked != 0 || !answers) {
		ncfg_error_set(err, err_size, "cannot resolve endpoint `%s`: %s", text,
		    gai_strerror(looked));
		if (answers) {
			freeaddrinfo(answers);
		}
		return 0;
	}
	/* The first answer, which is what `to_socket_addrs().next()` takes on the
	 * other side. A peer has one endpoint, and choosing among several would be
	 * netcfgd deciding a routing question the resolver already answered. */
	memset(address, 0, sizeof(*address));
	if (answers->ai_family == AF_INET && answers->ai_addrlen >= sizeof(struct sockaddr_in)) {
		const struct sockaddr_in *in = (const struct sockaddr_in *)(const void *)
		    answers->ai_addr;

		address->family = AF_INET;
		memcpy(address->bytes, &in->sin_addr, 4u);
		*port = ntohs(in->sin_port);
	} else if (answers->ai_family == AF_INET6 &&
	    answers->ai_addrlen >= sizeof(struct sockaddr_in6)) {
		const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)(const void *)
		    answers->ai_addr;

		address->family = AF_INET6;
		memcpy(address->bytes, &in6->sin6_addr, 16u);
		*port = ntohs(in6->sin6_port);
	} else {
		freeaddrinfo(answers);
		ncfg_error_set(err, err_size,
		    "`%s` resolved to an address of a family WireGuard cannot send to", text);
		return 0;
	}
	freeaddrinfo(answers);
	return 1;
}

/* ------------------------------------------------------------------------ *
 * WireGuard
 * ------------------------------------------------------------------------ */

/* The 32 octets a secret reference names. `out` is scrubbed on a refusal, and
 * the text is wiped by `ncfg_secret_free` whichever way this goes. */
static int key_of(const ncfg_secret_resolver_t *resolver, const ncfg_secret_ref_t *reference,
    const char *about, unsigned char out[NCFG_KEY_LEN], char *err, size_t err_size)
{
	ncfg_secret_resolver_t machine;
	ncfg_secret_t         *secret;
	char                   why[NCFG_ERROR_MAX];
	int                    parsed;

	memset(out, 0, NCFG_KEY_LEN);
	if (!reference) {
		ncfg_error_set(err, err_size, "%s: there is no key reference to resolve", about);
		return 0;
	}
	if (!resolver) {
		/* The machine's own secrets directory, which is what a NULL
		 * `secrets_dir` means to `secrets.h`. Written as a value here so that
		 * the path itself appears in exactly one place, which is that
		 * header. */
		memset(&machine, 0, sizeof(machine));
		resolver = &machine;
	}
	secret = ncfg_secret_resolve(resolver, reference, NULL, why, sizeof(why));
	if (!secret) {
		ncfg_error_set(err, err_size, "%s: %s", about, why);
		return 0;
	}
	/* The refusal never quotes the value: a private key that failed to parse
	 * is still a private key. `ncfg_key_parse` is written to that rule. */
	parsed = ncfg_key_parse(ncfg_secret_expose(secret), ncfg_secret_length(secret), out, why,
	    sizeof(why));
	ncfg_secret_free(secret);
	if (!parsed) {
		ncfg_error_set(err, err_size, "%s: %s", about, why);
		return 0;
	}
	return 1;
}

/* What the document refers to and cannot carry, one entry per peer. */
typedef struct {
	ncfg_wg_peer_material_t *at;
	unsigned char           *keys; /* `count` blocks of NCFG_KEY_LEN */
	size_t                   count;
} material_t;

static void material_free(material_t *material)
{
	if (material->keys) {
		/* Wiped before release: freed heap is handed to the next caller, and
		 * a preshared key is as much a secret as the private one. */
		memset(material->keys, 0, material->count * NCFG_KEY_LEN);
		free(material->keys);
	}
	free(material->at);
	memset(material, 0, sizeof(*material));
}

static int material_build(material_t *material, const ncfg_wg_peer_t *peers, size_t count,
    const char *iface, const ncfg_secret_resolver_t *resolver, char *err, size_t err_size)
{
	size_t i;

	memset(material, 0, sizeof(*material));
	if (count == 0) {
		return 1;
	}
	material->at = calloc(count, sizeof(*material->at));
	material->keys = calloc(count, NCFG_KEY_LEN);
	material->count = count;
	if (!material->at || !material->keys) {
		ncfg_error_set(err, err_size, "there was not enough memory for %zu peers", count);
		material_free(material);
		return 0;
	}
	for (i = 0; i < count; i++) {
		const ncfg_wg_peer_t *peer = &peers[i];
		char                  about[NCFG_ERROR_MAX];

		(void)snprintf(about, sizeof(about), "%s: peer `%s`", iface ? iface : "?",
		    peer->name ? peer->name : "?");
		if (peer->preshared_key) {
			unsigned char *slot = material->keys + i * NCFG_KEY_LEN;

			if (!key_of(resolver, peer->preshared_key, about, slot, err, err_size)) {
				material_free(material);
				return 0;
			}
			material->at[i].preshared_key = slot;
		}
		if (peer->endpoint) {
			char why[NCFG_ERROR_MAX];

			if (!ncfg_kernel_endpoint(peer->endpoint, &material->at[i].endpoint,
			    &material->at[i].endpoint_port, why, sizeof(why))) {
				ncfg_error_set(err, err_size, "%s: %s", about, why);
				material_free(material);
				return 0;
			}
			material->at[i].has_endpoint = 1;
		}
	}
	return 1;
}

/*
 * The document's private key reference for one device.
 *
 * The op carries the reference's *name* and the document carries its provider,
 * so both are needed and both must agree. A document whose reference has
 * another name is a plan built from another document, and the key it would
 * load is not the key that was planned -- which for a WireGuard device means
 * a tunnel that comes up to the wrong peer rather than one that fails.
 */
static const ncfg_secret_ref_t *private_key_ref(const ncfg_document_t *document,
    const char *iface, const char *named, char *err, size_t err_size)
{
	const ncfg_interface_kind_t *kind = ncfg_kernel_kind_of(document, iface,
	    NCFG_KIND_WIREGUARD, err, err_size);

	if (!kind) {
		return NULL;
	}
	if (named && kind->wireguard.private_key.name &&
	    strcmp(named, kind->wireguard.private_key.name) != 0) {
		ncfg_error_set(err, err_size,
		    "%s: the plan asks for the key named `%s` and the document being applied "
		    "names `%s`; the plan was built from a different document", iface, named,
		    kind->wireguard.private_key.name);
		return NULL;
	}
	return &kind->wireguard.private_key;
}

int ncfg_kernel_wg_build(ncfg_wg_messages_t *out, const ncfg_genl_family_t *family,
    uint32_t seq, const ncfg_op_t *op, const ncfg_document_t *document,
    const ncfg_secret_resolver_t *resolver, char *err, size_t err_size)
{
	ncfg_wireguard_config_t config;
	ncfg_wg_request_t       request;
	material_t              material;
	unsigned char           private[NCFG_KEY_LEN];
	int                     built;

	if (!out || !op) {
		ncfg_error_set(err, err_size, "there is no WireGuard action to carry out");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	memset(&config, 0, sizeof(config));
	memset(&request, 0, sizeof(request));
	memset(&material, 0, sizeof(material));
	memset(private, 0, sizeof(private));
	request.config = &config;

	if (op->kind == NCFG_OP_WG_SET_DEVICE) {
		const ncfg_secret_ref_t *reference;
		char                     about[NCFG_ERROR_MAX];

		request.name = op->u.wg_device.iface;
		/*
		 * The device's own fields and **no peer list at all**: a
		 * `wg.set_device` says nothing about peers, so it sends no list and
		 * does not set the replace flag, and the kernel leaves what it has.
		 * That is the whole of what decision 0054 split the two ops for.
		 */
		config.listen_port = op->u.wg_device.listen_port;
		config.fwmark = op->u.wg_device.fwmark;
		reference = private_key_ref(document, op->u.wg_device.iface,
		    op->u.wg_device.private_key_ref, err, err_size);
		if (!reference) {
			return 0;
		}
		(void)snprintf(about, sizeof(about), "%s: private key",
		    op->u.wg_device.iface ? op->u.wg_device.iface : "?");
		if (!key_of(resolver, reference, about, private, err, err_size)) {
			return 0;
		}
		request.private_key = private;
		built = ncfg_wg_set_device_build(out, family, seq, &request, err, err_size);
		memset(private, 0, sizeof(private));
		return built;
	}
	if (op->kind != NCFG_OP_WG_SET_PEERS) {
		ncfg_error_set(err, err_size,
		    "%s is not a WireGuard action; that is a defect in the executor, not in "
		    "the plan", ncfg_op_name(op));
		return 0;
	}

	request.name = op->u.wg_peers.iface;
	/*
	 * Cast because `ncfg_wireguard_config_t` is the *document's* type and owns
	 * its peers, while a plan borrows the list and hands it out `const`. The
	 * request takes the config `const` and `wg.c` only reads it, so nothing
	 * here writes through the cast -- and building a second peer type to avoid
	 * it is the parallel model `wg.h` refuses by name.
	 */
	config.peers = (ncfg_wg_peer_t *)(uintptr_t)(const void *)op->u.wg_peers.peers;
	config.peer_count = op->u.wg_peers.peer_count;
	/*
	 * **True even with an empty list, and that is the point.** True and no
	 * peers is how the last peer is removed; without the flag a `SET_DEVICE`
	 * merges, and a peer the document has removed goes on accepting traffic.
	 * The list is the op's, which the planner filled from the document, so an
	 * empty one here means the document has no peers rather than that a
	 * caller forgot to fill it.
	 */
	request.replace_peers = 1;
	if (config.peer_count > 0 && !config.peers) {
		ncfg_error_set(err, err_size,
		    "%s: the plan says this device has %zu peers and carries none",
		    request.name ? request.name : "?", config.peer_count);
		return 0;
	}
	if (!material_build(&material, config.peers, config.peer_count, request.name, resolver,
	    err, err_size)) {
		return 0;
	}
	request.material = material.at;
	built = ncfg_wg_set_device_build(out, family, seq, &request, err, err_size);
	material_free(&material);
	return built;
}

/* ------------------------------------------------------------------------ *
 * The offloads
 * ------------------------------------------------------------------------ */

int ncfg_kernel_build_offloads(ncfg_buf_t *out, const ncfg_genl_family_t *family, uint32_t seq,
    const ncfg_op_t *op, char *err, size_t err_size)
{
	ncfg_ethtool_feature_t *wanted;
	size_t                  count;
	size_t                  i;
	int                     built;

	if (!op) {
		ncfg_error_set(err, err_size, "there is no offload action to carry out");
		return 0;
	}
	count = op->u.set_offloads.feature_count;
	if (count == 0) {
		/*
		 * A request naming no feature is a mask bitset with nothing in it,
		 * which the kernel accepts and which changes nothing -- so it would
		 * report a successful apply for work nobody did. The planner does not
		 * emit one; this refuses it rather than sending it.
		 */
		ncfg_error_set(err, err_size,
		    "link.set_offloads on %s names no feature to change",
		    op->u.set_offloads.name ? op->u.set_offloads.name : "?");
		return 0;
	}
	/* A count with no list behind it is `ncfg_ethtool_features_set_request`'s
	 * refusal and is not repeated here -- but the `calloc` below has to be
	 * reached with a list to walk, so the count is what bounds it and the
	 * pointer is checked by the loop's own bound rather than by a second
	 * sentence. */
	if (!op->u.set_offloads.features) {
		return ncfg_ethtool_features_set_request(out, family, op->u.set_offloads.name,
		    NULL, count, seq, err, err_size);
	}
	wanted = calloc(count, sizeof(*wanted));
	if (!wanted) {
		ncfg_error_set(err, err_size, "there was not enough memory for %zu features",
		    count);
		return 0;
	}
	for (i = 0; i < count; i++) {
		wanted[i].name = op->u.set_offloads.features[i].name;
		wanted[i].on = op->u.set_offloads.features[i].wanted;
	}
	built = ncfg_ethtool_features_set_request(out, family, op->u.set_offloads.name, wanted,
	    count, seq, err, err_size);
	free(wanted);
	return built;
}

/* ------------------------------------------------------------------------ *
 * The arms
 * ------------------------------------------------------------------------ */

int ncfg_kernel_wg_op(const ncfg_kernel_world_t *world, const ncfg_op_t *op, char *err,
    size_t err_size)
{
	ncfg_netlink_t     socket;
	ncfg_genl_family_t family;
	ncfg_wg_messages_t messages;
	const char        *iface;
	uint32_t           seq;
	size_t             i;
	int                ok;

	iface = op->kind == NCFG_OP_WG_SET_DEVICE ? op->u.wg_device.iface : op->u.wg_peers.iface;
	if (!family_open(NCFG_WG_FAMILY, &socket, &family, err, err_size)) {
		return 0;
	}
	/*
	 * `ncfg_wg_set_device_build` numbers the nth message `seq + n` and
	 * `wg.h` says a caller must not reuse those numbers for anything else.
	 * Nothing here does: the socket was opened a few lines above, is this
	 * op's alone, and is closed before the arm returns -- so the run from
	 * `seq` upwards belongs to this request and to nothing.
	 */
	seq = ncfg_netlink_take_seq(&socket);
	memset(&messages, 0, sizeof(messages));
	ok = ncfg_kernel_wg_build(&messages, &family, seq, op, world->document, world->secrets,
	    err, err_size);
	for (i = 0; ok && i < messages.count; i++) {
		char doing[NCFG_ERROR_MAX];

		(void)snprintf(doing, sizeof(doing), "configure %s", iface ? iface : "?");
		/*
		 * **Every message, in order, and stopping after the first is not an
		 * option**: the first carries the replace flag, so a device left
		 * holding only the peers that fitted one attribute is a device whose
		 * remaining peers were cleared and never put back. So the loop runs
		 * to the end of a successful run and stops at the first failure,
		 * which is the rule the plan itself runs under -- and the journal
		 * then says which action stopped it.
		 *
		 * Sent as bytes rather than wrapped in a `ncfg_buf_t`: these are
		 * `ncfg_wg_messages_free`'s to own and to scrub, and a copy would be
		 * a second allocation holding a private key that nothing wipes.
		 */
		ok = ncfg_kernel_send_bytes(&socket, messages.message[i].bytes,
		    messages.message[i].length, seq + (uint32_t)i, op->kind, doing, err,
		    err_size);
	}
	ncfg_wg_messages_free(&messages);
	ncfg_genl_family_free(&family);
	ncfg_netlink_close(&socket);
	return ok;
}

int ncfg_kernel_offloads_op(const ncfg_kernel_world_t *world, const ncfg_op_t *op, char *err,
    size_t err_size)
{
	ncfg_netlink_t     socket;
	ncfg_genl_family_t family;
	ncfg_buf_t         message;
	char               doing[NCFG_ERROR_MAX];
	uint32_t           seq;
	int                ok;

	(void)world;
	if (!family_open(NCFG_ETHTOOL_FAMILY, &socket, &family, err, err_size)) {
		/* `ENOENT` from the lookup is a kernel older than 5.6, which
		 * `ncfg_genl_lookup_failed` already says in the sentence `family_open`
		 * carried up. */
		return 0;
	}
	seq = ncfg_netlink_take_seq(&socket);
	ncfg_buf_init(&message, 0);
	ok = ncfg_kernel_build_offloads(&message, &family, seq, op, err, err_size);
	if (ok) {
		(void)snprintf(doing, sizeof(doing), "set the offloads on %s",
		    op->u.set_offloads.name ? op->u.set_offloads.name : "?");
		ok = ncfg_kernel_send(&socket, &message, seq, op->kind, doing, err, err_size);
	}
	ncfg_buf_free(&message);
	ncfg_genl_family_free(&family);
	ncfg_netlink_close(&socket);
	return ok;
}
