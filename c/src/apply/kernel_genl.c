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
#include "ncfg/log.h"
#include "ncfg/observe.h"
#include "ncfg/state.h"
#include "ncfg/wire.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

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
	    ncfg_wire_request_parts(&message, "generic netlink", &kind, &flags, &body, err, err_size);
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

/*
 * The record line for one peer that was given a preshared key.
 *
 * `<public key in base64> <digest>`, which is `observe.h`'s format and the
 * public key is the only name the kernel and the document share -- a peer's
 * `name` is the document's alone and a kernel dump has no idea of it.
 */
static void record_peer(ncfg_buf_t *record, const unsigned char *public_key,
    const unsigned char *preshared)
{
	char rendered[NCFG_KEY_TEXT_SIZE];
	char digest[NCFG_SHA256_HEX_SIZE];

	if (!record || !public_key || !preshared) {
		return;
	}
	if (!ncfg_key_render(public_key, rendered, sizeof(rendered), NULL, 0)) {
		return;
	}
	/* The octet door, for the reason `observe.h` gives at length: a preshared
	 * key is 32 octets from `wg genpsk` and not text, so the text door's trim
	 * would take an end byte of `0x1f` for whitespace and record the digest of
	 * thirty-one of them. */
	ncfg_observe_wg_digest_key(preshared, digest);
	ncfg_buf_add_text(record, rendered);
	ncfg_buf_add_char(record, ' ');
	ncfg_buf_add_text(record, digest);
	ncfg_buf_add_char(record, '\n');
}

int ncfg_kernel_wg_build(ncfg_wg_messages_t *out, ncfg_buf_t *record,
    const ncfg_genl_family_t *family, uint32_t seq, const ncfg_op_t *op,
    const ncfg_document_t *document, const ncfg_secret_resolver_t *resolver, char *err,
    size_t err_size)
{
	ncfg_wireguard_config_t config;
	ncfg_wg_request_t       request;
	material_t              material;
	unsigned char           private[NCFG_KEY_LEN];
	size_t                  i;
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
		/*
		 * Digested from the octets that are about to be sent, before they are
		 * wiped -- which is the whole reason this is here and not in the
		 * caller. `kernel_internal.h` has the argument: a record built from a
		 * second resolution describes whatever the store held a moment later.
		 */
		if (built && record) {
			char digest[NCFG_SHA256_HEX_SIZE];

			ncfg_observe_wg_digest_key(private, digest);
			ncfg_buf_add_text(record, digest);
			ncfg_buf_add_char(record, '\n');
		}
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
	/*
	 * One line per peer that was given a key, out of the material that was
	 * built for the message rather than out of a second resolution -- and
	 * before `material_free` scrubs it.
	 *
	 * A peer with no preshared key contributes no line, which is what the
	 * reader wants: `preshared_matches` is absent for a peer that has none,
	 * and that is a different answer from one whose key netcfgd cannot check.
	 */
	for (i = 0; built && record && i < config.peer_count; i++) {
		record_peer(record, config.peers[i].public_key, material.at[i].preshared_key);
	}
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

/*
 * Leave the record the observer reads back.
 *
 * `<run>/wireguard/<iface>.key.sha256` and `.psk.sha256`, named through
 * `observe.h`'s own path functions rather than composed here -- which is what
 * those functions were declared for, before there was a writer: two spellings
 * of one path is a reader looking where nothing was written.
 *
 * **An empty record removes the file rather than writing nothing into it.** A
 * `wg.set_peers` that left every peer without a preshared key, or removed the
 * last peer that had one, must not leave yesterday's digests behind: the
 * reader would go on answering `preshared_matches` about keys no peer holds.
 * Removing something that is not there is success, which is `process.h`'s rule
 * for `ESRCH` applied to a file.
 *
 * Nothing here can fail the op -- see the caller -- so every failure is a log
 * line naming the file. The record holds digests and no material, so the mode
 * is the run directory's ordinary one rather than a credential's.
 */
void ncfg_kernel_wg_write_record(const char *run_dir, const char *iface, int kind,
    const ncfg_buf_t *record)
{
	char        path[NCFG_OBSERVE_WG_RECORD_PATH_MAX];
	char        dir[NCFG_OBSERVE_WG_RECORD_PATH_MAX];
	char        why[NCFG_ERROR_MAX];
	const char *text;
	int         named;

	named = kind == NCFG_OP_WG_SET_DEVICE ?
	    ncfg_observe_wg_key_record_path(run_dir, iface, path, sizeof(path), NULL, 0) :
	    ncfg_observe_wg_preset_record_path(run_dir, iface, path, sizeof(path), NULL, 0);
	if (!named) {
		return;
	}
	if (ncfg_buf_failed(record)) {
		/* A buffer that ran out hands back the empty string, so writing it
		 * would record "no peer has a preshared key" about a device where
		 * several do. Saying nothing leaves the reader with no record, which
		 * is the answer it already knows how to hold. */
		ncfg_log_emitf("wireguard", NCFG_LOG_WARNING,
		    "%s: the WireGuard record could not be built, so %s is left as it was and "
		    "the next observation will say nothing about the keys in use",
		    iface ? iface : "?", path);
		return;
	}
	text = ncfg_buf_text(record);
	if (!text || !text[0]) {
		if (unlink(path) != 0 && errno != ENOENT) {
			ncfg_log_emitf("wireguard", NCFG_LOG_WARNING,
			    "%s: %s could not be removed (%s), so it goes on describing keys "
			    "that are no longer in use", iface ? iface : "?", path,
			    strerror(errno));
		}
		return;
	}
	(void)snprintf(dir, sizeof(dir), "%s/wireguard", run_dir);
	if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
		ncfg_log_emitf("wireguard", NCFG_LOG_WARNING,
		    "%s: %s could not be made (%s), so no WireGuard record is kept",
		    iface ? iface : "?", dir, strerror(errno));
		return;
	}
	why[0] = '\0';
	if (!ncfg_write_atomically(path, text, strlen(text), 0600, why, sizeof(why))) {
		ncfg_log_emitf("wireguard", NCFG_LOG_WARNING,
		    "%s: the WireGuard record could not be written (%s), so the next "
		    "observation will say nothing about the keys in use", iface ? iface : "?",
		    why);
	}
}

int ncfg_kernel_wg_configure_new(const ncfg_kernel_world_t *world, const char *iface,
    const ncfg_interface_kind_t *kind, char *err, size_t err_size)
{
	const ncfg_wireguard_config_t *config;
	ncfg_op_t                      op;

	/* Every other kind configures itself in the `RTM_NEWLINK` that created it,
	 * so this is a question rather than a caller's duty to ask. */
	if (!kind || kind->kind != (int)NCFG_KIND_WIREGUARD) {
		return 1;
	}
	config = &kind->wireguard;
	/*
	 * The device's own fields first, because they carry the private key: a
	 * device with peers and no key answers nothing, and the record written
	 * here is what lets the next observation notice a rotated one.
	 */
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_WG_SET_DEVICE;
	op.u.wg_device.iface = iface;
	/* The document's own, by name. A synthesized action has no plan to have
	 * been built from a different document than, which is the disagreement
	 * `private_key_ref` exists to catch. */
	op.u.wg_device.private_key_ref = NULL;
	op.u.wg_device.listen_port = config->listen_port;
	op.u.wg_device.fwmark = config->fwmark;
	if (!ncfg_kernel_wg_op(world, &op, err, err_size)) {
		return 0;
	}
	/*
	 * Then the peers, **and unconditionally**. A brand-new device has none to
	 * replace, so an empty list costs one transaction and says the true thing;
	 * asking first would put a second rule about when peers are sent beside
	 * the one `wg.set_peers` already has, and the two would drift.
	 */
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_WG_SET_PEERS;
	op.u.wg_peers.iface = iface;
	op.u.wg_peers.peers = config->peers;
	op.u.wg_peers.peer_count = config->peer_count;
	return ncfg_kernel_wg_op(world, &op, err, err_size);
}

void ncfg_kernel_wg_forget_records(const char *run_dir, const char *iface)
{
	char   path[NCFG_OBSERVE_WG_RECORD_PATH_MAX];
	size_t at;

	if (!run_dir || !run_dir[0] || !iface || !iface[0]) {
		return;
	}
	/* The two, by name, through the same path functions the reader and the
	 * writer use -- a third spelling here would remove some other file and
	 * leave the record standing. */
	for (at = 0; at < 2; at++) {
		int named = at == 0 ?
		    ncfg_observe_wg_key_record_path(run_dir, iface, path, sizeof(path), NULL, 0) :
		    ncfg_observe_wg_preset_record_path(run_dir, iface, path, sizeof(path), NULL,
		        0);

		if (!named) {
			continue;
		}
		if (unlink(path) != 0 && errno != ENOENT) {
			ncfg_log_emitf("wireguard", NCFG_LOG_WARNING,
			    "%s: %s outlived the link it describes and could not be removed "
			    "(%s), so the next observation will answer about a device that is "
			    "no longer there", iface, path, strerror(errno));
		}
	}
}

int ncfg_kernel_wg_op(const ncfg_kernel_world_t *world, const ncfg_op_t *op, char *err,
    size_t err_size)
{
	ncfg_netlink_t     socket;
	ncfg_genl_family_t family;
	ncfg_wg_messages_t messages;
	ncfg_buf_t         record;
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
	ncfg_buf_init(&record, 0);
	ok = ncfg_kernel_wg_build(&messages, world->run_dir ? &record : NULL, &family, seq, op,
	    world->document, world->secrets, err, err_size);
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
	/*
	 * **After the kernel accepted it, and never instead of it.** The record
	 * says what netcfgd handed over; writing one for a request that failed
	 * would tell the next observation that a key is in use which the device
	 * never took, and `key_matches` would answer true about a device holding
	 * the old one -- a plan that then does nothing, for ever.
	 *
	 * A write that fails does **not** fail the op. The machine has already
	 * changed; the observer reads a missing record as "not a device netcfgd
	 * configured", which is the one shape the planner is built to do nothing
	 * about, and failing here would report an op that succeeded as an op that
	 * did not.
	 */
	if (ok && world->run_dir) {
		ncfg_kernel_wg_write_record(world->run_dir, iface, op->kind, &record);
	}
	ncfg_buf_free(&record);
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
