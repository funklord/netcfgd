/*
 * wireguard.c -- what a WireGuard device is running, and whether the key it is
 * running is the one the configuration names.
 *
 * WHY THIS IS A ROUND OF ITS OWN, AND THE SECOND ONE
 *   `collect.c` takes seven dumps over one rtnetlink socket and `netfilter.c`
 *   takes two over `NETLINK_NETFILTER`. A WireGuard device's configuration is
 *   neither: the device is an ordinary link, but its keys, its port and its
 *   peers go through the `wireguard` generic netlink family, which is a third
 *   protocol on a third socket -- `ncfg_netlink_open_protocol`'s own comment
 *   says a family id resolved on one socket is meaningless on another. So this
 *   is `netfilter.c`'s shape again, one protocol further along, and 10.182
 *   judged the pair a wave for that reason.
 *
 * WHAT AN ABSENT SEAM MEANS HERE, WHICH IS NOT WHAT IT MEANS FOR NAT
 *   `netfilter.c` reads a socket it could not open as "no NAT is installed",
 *   because a kernel with no `nf_tables` genuinely has none and a planner does
 *   the same thing with either. **That reading would be wrong here, and
 *   dangerous.** A WireGuard device netcfgd cannot read is not a device with no
 *   peers: report it as one and the planner compares the document's peer list
 *   against an empty one, finds every peer missing, and sends a
 *   `wg.set_peers` with `WGDEVICE_F_REPLACE_PEERS` -- which on a device it
 *   could not read is a working tunnel rebuilt from a guess.
 *
 *   The model already tells the two apart and this file keeps them apart:
 *   `link->wireguard == NULL` is **not observed**, and an observed device with
 *   no key is `wireguard` present with `public_key.has == 0`. So a missing
 *   socket, a missing family, a device the kernel would not answer for and a
 *   reply that would not read all leave the link at NULL -- and
 *   `ncfg_plan_wireguard` returns without planning anything for a device with
 *   no observation, which is the safe direction and the one the Rust takes
 *   (`host.rs:311`, which `continue`s). Nothing is refused: a machine with no
 *   WireGuard, a kernel without the module and a container whose netlink is
 *   denied are all ordinary, and each is a note.
 *
 * NOTHING HERE OBSERVES A SECRET, AND THE ASYMMETRY IS THE KERNEL'S
 *   A `GET_DEVICE` reports the **public** key -- the one the kernel derived
 *   and the one a peer is handed -- and never the private one; a peer's
 *   preshared key comes back as 32 zero octets, which `sys/wg.c` turns into a
 *   boolean and drops. So the whole of what leaves the netlink half is public.
 *
 *   The currency half is the one that touches the store, and what it produces
 *   is **a boolean and nothing else**: netcfgd hashes the key it loaded when
 *   the kernel accepted it, this hashes what the store holds now, and the two
 *   digests are compared. No key, no digest and nothing derived from either
 *   reaches an error buffer, a log line or the observation written to `/run`
 *   -- `observe_wireguard_test.c` drives a canary through every `err` this
 *   file fills and through the process' standard error to prove it, rather
 *   than asserting it here. Decision 0052's shape, which 0053 and 0055 already
 *   use for a passphrase and a tunnel's configuration: the comparison happens
 *   where both halves are already in hand, and a boolean travels.
 *
 *   `NULL` is not `false` in either answer. A device netcfgd did not
 *   configure, a `/run` cleared under a running daemon and a secret that will
 *   not resolve all leave the question unanswered -- and an unanswered
 *   question is not a reason to rekey a working tunnel. `plan/wireguard.c`
 *   reads `key_matches.has` before `key_matches.value` for that reason.
 *
 * EVERY PATH IS A PARAMETER
 *   The run directory the two records are read out of is an argument, and so
 *   is the store: `secrets` of NULL is "do not ask", never "look where the
 *   machine keeps its keys". An observer that reached
 *   `NCFG_SECRETS_DIR_DEFAULT` for itself would be one that reads the
 *   developer's real credentials the first time a test forgot to override it,
 *   which is `observe.h`'s rule about the three roots pointed at the one
 *   directory where it matters most.
 */
#include "ncfg/observe.h"

#include "observe_internal.h"

#include "ncfg/genl.h"
#include "ncfg/hooks.h"
#include "ncfg/log.h"
#include "ncfg/secrets.h"
#include "ncfg/value.h"
#include "ncfg/wg.h"
#include "ncfg/wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The kernel's word for the link kind, which is the one the document does not
 * use: the language spells it `wireguard` and this project has twice shipped
 * the model's spelling instead (`wire_guard`), each time compiling into a
 * block with the feature silently missing. `model/observed_link.c` matches the
 * same literal for the same reason. */
#define WG_LINK_KIND "wireguard"

/*
 * The most of either record this will read.
 *
 * The key record is 64 hex digits. The preshared record is one line per peer
 * that has one -- 44 characters of base64, a space and 64 hex digits -- so
 * this holds some two thousand peers' worth, which is past what one attribute
 * can carry a peer list in (`wg.h`) and far past what a record nobody has
 * written by hand should be. A longer file is read as no record rather than
 * truncated into one, because half a record answers the currency question for
 * the peers that fitted and stays silent about the rest, which is a worse
 * answer than silence.
 */
#define WG_RECORD_MAX 262144u

/* ------------------------------------------------------------------------ *
 * Where the two records live
 * ------------------------------------------------------------------------ */

static int record_path(const char *run_dir, const char *iface, const char *suffix, char *out,
    size_t out_size, char *err, size_t err_size)
{
	int written;

	if (!out || out_size == 0) {
		ncfg_error_set(err, err_size, "there is nowhere to build a record path");
		return 0;
	}
	out[0] = '\0';
	if (!run_dir || !run_dir[0] || !iface || !iface[0]) {
		ncfg_error_set(err, err_size,
		    "a WireGuard record is named by a run directory and an interface, and "
		    "one of the two was not given");
		return 0;
	}
	written = snprintf(out, out_size, "%s/wireguard/%s%s", run_dir, iface, suffix);
	if (written < 0 || (size_t)written >= out_size) {
		out[0] = '\0';
		ncfg_error_set(err, err_size,
		    "the record path for `%s` under this run directory is too long", iface);
		return 0;
	}
	return 1;
}

int ncfg_observe_wg_key_record_path(const char *run_dir, const char *iface, char *out,
    size_t out_size, char *err, size_t err_size)
{
	return record_path(run_dir, iface, ".key.sha256", out, out_size, err, err_size);
}

int ncfg_observe_wg_preset_record_path(const char *run_dir, const char *iface, char *out,
    size_t out_size, char *err, size_t err_size)
{
	return record_path(run_dir, iface, ".psk.sha256", out, out_size, err, err_size);
}

/*
 * A record, or NULL.
 *
 * Absent, unreadable and past the ceiling are one answer and it is not a
 * failure: a device netcfgd never configured has no record, and a `/run`
 * cleared under a running daemon has none either. Neither is a statement about
 * a key.
 */
static char *read_record(const char *path)
{
	FILE  *file = fopen(path, "rb");
	char  *body;
	size_t got;

	if (!file) {
		return NULL;
	}
	body = malloc((size_t)WG_RECORD_MAX + 1u);
	if (!body) {
		(void)fclose(file);
		return NULL;
	}
	got = fread(body, 1u, (size_t)WG_RECORD_MAX, file);
	if (!feof(file) || ferror(file)) {
		/* More than the ceiling holds, or a read that failed partway. Both
		 * are "no record": see the ceiling's comment. */
		(void)fclose(file);
		free(body);
		return NULL;
	}
	(void)fclose(file);
	body[got] = '\0';
	return body;
}

/* One line's worth, trimmed of surrounding whitespace in place. */
static char *trim(char *text)
{
	size_t end;

	while (*text && (unsigned char)*text <= ' ') {
		text++;
	}
	end = strlen(text);
	while (end > 0 && (unsigned char)text[end - 1u] <= ' ') {
		end--;
	}
	text[end] = '\0';
	return text;
}

/* ------------------------------------------------------------------------ *
 * One request, through whatever the caller's exchange is
 * ------------------------------------------------------------------------ */

/*
 * The kind, the flags and the payload of a message this port built.
 *
 * `collect.c`, `netfilter.c` and `apply/kernel_genl.c` all have these three
 * lines and each says why: the exchange writes a header of its own, so what it
 * takes is what is inside one -- and spelling the command, the family id or
 * the dump flag again here is how a request comes to be aimed at something
 * other than what the module that owns it built. The sequence number goes with
 * the discarded header, which is why the callers below build with zero.
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
 * Send what `build` produced and collect the replies.
 *
 * 1 with a reply, which the caller frees; 0 with a sentence in `why`, which
 * covers both a request this port could not build and a kernel that would not
 * answer. The two are told apart by the caller only where it matters, which is
 * nowhere here: a family that will not resolve and a device that will not
 * answer are both "this observation does not describe that device".
 */
static int ask(const ncfg_observe_kernel_t *kernel, const ncfg_buf_t *message,
    ncfg_netlink_reply_t *reply, char *why, size_t why_size)
{
	ncfg_buf_t body;
	uint16_t   kind = 0;
	uint16_t   flags = 0;
	int        answered;

	memset(reply, 0, sizeof(*reply));
	ncfg_buf_init(&body, 0);
	if (!request_parts(message, &kind, &flags, &body, why, why_size)) {
		ncfg_buf_free(&body);
		return 0;
	}
	answered = kernel->exchange(kernel->context, kind, flags, &body, NULL, reply, why,
	    why_size);
	ncfg_buf_free(&body);
	if (!answered) {
		ncfg_netlink_reply_free(reply);
		memset(reply, 0, sizeof(*reply));
		return 0;
	}
	return 1;
}

/*
 * The `wireguard` family's runtime id.
 *
 * Asked once per observation rather than once per device: a controller round
 * trip per WireGuard interface is a request per tick per tunnel for an answer
 * that cannot change between two of them.
 */
static int family_of(const ncfg_observe_kernel_t *kernel, ncfg_genl_family_t *family,
    char *why, size_t why_size)
{
	ncfg_buf_t           message;
	ncfg_netlink_reply_t reply;
	int                  ok;

	memset(family, 0, sizeof(*family));
	ncfg_buf_init(&message, 0);
	why[0] = '\0';
	ok = ncfg_genl_getfamily_request(&message, NCFG_WG_FAMILY, 0, why, why_size) &&
	    ask(kernel, &message, &reply, why, why_size);
	ncfg_buf_free(&message);
	if (!ok) {
		return 0;
	}
	if (reply.count == 0) {
		/*
		 * The controller answered and named no family, which reads
		 * downstream as a family with id zero -- and a request built with one
		 * is refused five seconds later and about the wrong thing.
		 * `apply/kernel_genl.c` refuses the same reply for the same reason.
		 */
		ncfg_error_set(why, why_size,
		    "the generic netlink controller answered about `%s` without naming a "
		    "family", NCFG_WG_FAMILY);
		ncfg_netlink_reply_free(&reply);
		return 0;
	}
	ok = ncfg_genl_family_parse(NCFG_WG_FAMILY, reply.items[0].bytes, reply.items[0].length,
	    family, why, why_size);
	ncfg_netlink_reply_free(&reply);
	return ok;
}

/* ------------------------------------------------------------------------ *
 * What the kernel holds, in the model's shape
 * ------------------------------------------------------------------------ */

static void wg_peer_free(ncfg_observed_wg_peer_t *peer)
{
	size_t at;

	free(peer->endpoint);
	for (at = 0; at < peer->allowed_ip_count; at++) {
		free(peer->allowed_ips[at]);
	}
	free(peer->allowed_ips);
	memset(peer, 0, sizeof(*peer));
}

/*
 * Release one device's observation.
 *
 * Written out here rather than reached through the model, which drives its
 * frees from a field table this file cannot see. `host.c` frees an
 * `ncfg_observed_rfkill_t` by hand for the same reason and it is the same
 * bargain: the cost is that a field added to `ncfg_observed_wireguard_t`
 * without a line here leaks, which is what `make -C c SANITIZE=1` is for.
 */
static void wireguard_free(ncfg_observed_wireguard_t *wireguard)
{
	size_t at;

	if (!wireguard) {
		return;
	}
	for (at = 0; at < wireguard->peer_count; at++) {
		wg_peer_free(&wireguard->peers[at]);
	}
	free(wireguard->peers);
	free(wireguard);
}

static ncfg_optint_t some_int(int64_t value)
{
	ncfg_optint_t result;

	result.has = 1;
	result.value = value;
	return result;
}

static ncfg_optint_t no_int(void)
{
	ncfg_optint_t result;

	result.has = 0;
	result.value = 0;
	return result;
}

/*
 * Zero read as absent.
 *
 * The kernel spells "no mark" and "no keepalive" as zero and the model spells
 * both as absent, which is the distinction an optional exists for. A zero
 * surviving into the model differs from a document that says nothing, every
 * time and for ever -- which is `plan/wireguard.c`'s `without_zero` on the
 * other side of the same comparison, and 0052's `band` trap in a third place.
 */
static ncfg_optint_t without_zero(uint64_t value)
{
	return value ? some_int((int64_t)value) : no_int();
}

static int compare_peer_keys(const void *left, const void *right)
{
	const ncfg_observed_wg_peer_t *a = left;
	const ncfg_observed_wg_peer_t *b = right;

	return memcmp(a->public_key, b->public_key, sizeof(a->public_key));
}

static int compare_text(const void *left, const void *right)
{
	return strcmp(*(char *const *)left, *(char *const *)right);
}

/* One peer's allowed IPs, in the kernel's spelling and in a stable order. */
static int carry_allowed_ips(ncfg_observed_wg_peer_t *out, const ncfg_wg_peer_state_t *peer,
    char *err, size_t err_size)
{
	size_t at;

	if (peer->allowed_ip_count == 0) {
		return 1;
	}
	out->allowed_ips = calloc(peer->allowed_ip_count, sizeof(*out->allowed_ips));
	if (!out->allowed_ips) {
		ncfg_error_set(err, err_size, "out of memory recording a peer's allowed IPs");
		return 0;
	}
	for (at = 0; at < peer->allowed_ip_count; at++) {
		char address[NCFG_ADDRESS_MAX];
		char text[NCFG_ADDRESS_MAX + 8u];

		if (!ncfg_wire_ip_text(&peer->allowed_ips[at].address, address, sizeof(address),
		    err, err_size)) {
			return 0;
		}
		(void)snprintf(text, sizeof(text), "%s/%u", address,
		    (unsigned)peer->allowed_ips[at].prefix);
		out->allowed_ips[out->allowed_ip_count] = observe_dup(text);
		if (!out->allowed_ips[out->allowed_ip_count]) {
			ncfg_error_set(err, err_size,
			    "out of memory recording a peer's allowed IPs");
			return 0;
		}
		out->allowed_ip_count++;
	}
	/* Sorted, because the kernel's order is the order it happens to hold them
	 * in. The planner sorts both sides itself, so this is for whoever reads
	 * `ncfg status` twice running and expects the same list. */
	qsort(out->allowed_ips, out->allowed_ip_count, sizeof(*out->allowed_ips), compare_text);
	return 1;
}

static int carry_peer(ncfg_observed_wg_peer_t *out, const ncfg_wg_peer_state_t *peer,
    char *err, size_t err_size)
{
	memset(out, 0, sizeof(*out));
	memcpy(out->public_key, peer->public_key, sizeof(out->public_key));
	/* A boolean, which is the whole of what the kernel reports: the value
	 * comes back zeroed. `preshared_matches` is the currency pass' to fill and
	 * cannot be answered from a netlink reply alone. */
	out->preshared_key = peer->has_preshared_key;
	out->keepalive = without_zero(peer->keepalive);
	if (peer->has_endpoint) {
		char text[NCFG_WG_ENDPOINT_TEXT_MAX];

		if (!ncfg_wg_endpoint_text(&peer->endpoint, peer->endpoint_port, text,
		    sizeof(text), err, err_size)) {
			return 0;
		}
		out->endpoint = observe_dup(text);
		if (!out->endpoint) {
			ncfg_error_set(err, err_size, "out of memory recording a peer's endpoint");
			return 0;
		}
	}
	return carry_allowed_ips(out, peer, err, err_size);
}

/*
 * What of a device's state travels, which is everything the kernel offered.
 *
 * The same request already answers `private_key_loaded` and the Rust dropped
 * the rest on the floor for as long as WireGuard existed there, so an edited
 * listen port and a **deleted peer** reached a planner with nothing to compare
 * (0054). None of it is secret: the device's public key is derived by the
 * kernel and is what a peer is given, and a preshared key arrived zeroed and
 * has already become a boolean.
 */
static ncfg_observed_wireguard_t *carried(const ncfg_wg_state_t *state, char *err,
    size_t err_size)
{
	ncfg_observed_wireguard_t *out = calloc(1u, sizeof(*out));
	size_t                     at;

	if (!out) {
		ncfg_error_set(err, err_size, "out of memory recording a WireGuard device");
		return NULL;
	}
	if (state->has_public_key) {
		out->public_key.has = 1;
		memcpy(out->public_key.bytes, state->public_key, sizeof(out->public_key.bytes));
	}
	out->listen_port = state->has_listen_port ? some_int(state->listen_port) : no_int();
	out->fwmark = state->has_fwmark ? without_zero(state->fwmark) : no_int();
	if (state->peer_count == 0) {
		return out;
	}
	out->peers = calloc(state->peer_count, sizeof(*out->peers));
	if (!out->peers) {
		ncfg_error_set(err, err_size, "out of memory recording %zu WireGuard peer(s)",
		    state->peer_count);
		wireguard_free(out);
		return NULL;
	}
	for (at = 0; at < state->peer_count; at++) {
		if (!carry_peer(&out->peers[at], &state->peers[at], err, err_size)) {
			out->peer_count = at + 1u;
			wireguard_free(out);
			return NULL;
		}
	}
	out->peer_count = state->peer_count;
	/* **Sorted by public key**, which is the one field the kernel and the
	 * document share: the document sorts by the operator's label, which the
	 * kernel has never heard of. `plan/wireguard.c` compares the two lists in
	 * order, so an observation in the kernel's arbitrary order would differ
	 * from a device that is already right. */
	qsort(out->peers, out->peer_count, sizeof(*out->peers), compare_peer_keys);
	return out;
}

/* ------------------------------------------------------------------------ *
 * The pass that reads the kernel
 * ------------------------------------------------------------------------ */

static int is_wireguard(const ncfg_observed_link_t *link)
{
	return link->kind && strcmp(link->kind, WG_LINK_KIND) == 0;
}

/* Forget whatever a previous source said, so that an observation taken through
 * a seam that is absent does not carry an earlier one's answer. `netfilter.c`
 * clears its two lists for the same reason. */
static void forget(ncfg_observed_t *observed)
{
	size_t at;

	for (at = 0; at < observed->link_count; at++) {
		wireguard_free(observed->links[at].wireguard);
		observed->links[at].wireguard = NULL;
		observed->links[at].private_key_loaded = 0;
	}
}

/*
 * One device, or nothing said about it.
 *
 * 1 whether or not the device was read: what a kernel that will not answer for
 * one interface costs is that interface's observation and not the round.
 * 0 is out of memory, which is netcfgd's fault rather than the machine's.
 */
static int read_device(const ncfg_observe_kernel_t *kernel, const ncfg_genl_family_t *family,
    ncfg_observed_link_t *link, char *err, size_t err_size)
{
	ncfg_buf_t                 message;
	ncfg_netlink_reply_t       reply;
	ncfg_wg_state_t            state;
	ncfg_observed_wireguard_t *carry;
	char                       why[NCFG_ERROR_MAX];
	size_t                     at;
	int                        ok;

	ncfg_buf_init(&message, 0);
	memset(&state, 0, sizeof(state));
	why[0] = '\0';
	ok = ncfg_wg_get_device_request(&message, family, 0, link->name, why, sizeof(why)) &&
	    ask(kernel, &message, &reply, why, sizeof(why));
	ncfg_buf_free(&message);
	if (!ok) {
		/*
		 * `ENODEV` is a device that went away between the link dump and this
		 * request, `EPERM` is a netlink this process may not ask, and a
		 * refusal from the wire layer is a reply this port does not
		 * understand. All three mean the same thing to a planner -- nothing
		 * is known about this device -- and none of them may be reported as
		 * a device with no peers. `why` carries no key: `wg.h` says in as
		 * many words that nothing in that module renders one.
		 */
		ncfg_log_emitf("observe", NCFG_LOG_NOTE,
		    "the WireGuard device `%s` could not be read (%s), so this observation "
		    "says nothing about its keys, its port or its peers", link->name,
		    why[0] ? why : "no sentence was given");
		return 1;
	}
	for (at = 0; at < reply.count; at++) {
		/*
		 * **Every reply, not just the first.** A device with many peers
		 * arrives as several messages, each carrying a slice of the list,
		 * and taking only the first reports a truncated configuration as the
		 * whole of it -- which a reconciler reads as "these peers are
		 * missing" and reinstalls on every pass. `ncfg_wg_state_merge` also
		 * coalesces a peer the kernel split across two of them.
		 */
		if (!ncfg_wg_state_merge(&state, reply.items[at].bytes, reply.items[at].length,
		    why, sizeof(why))) {
			ncfg_netlink_reply_free(&reply);
			ncfg_wg_state_free(&state);
			ncfg_log_emitf("observe", NCFG_LOG_NOTE,
			    "a reply about the WireGuard device `%s` could not be read (%s), "
			    "so this observation says nothing about it", link->name, why);
			return 1;
		}
	}
	ncfg_netlink_reply_free(&reply);
	carry = carried(&state, err, err_size);
	ncfg_wg_state_free(&state);
	if (!carry) {
		return 0;
	}
	wireguard_free(link->wireguard);
	link->wireguard = carry;
	/*
	 * Asked as "does the kernel report a public key", which it derives from
	 * the private one and reports for no other reason. Nothing here asks for
	 * the private key and `ncfg_wg_state_t` has no field that could return
	 * one -- that is deliberate in `wg.h` and this must not be the reason it
	 * changes.
	 */
	link->private_key_loaded = carry->public_key.has;
	return 1;
}

int ncfg_observe_wireguard_from(const ncfg_observe_kernel_t *kernel, ncfg_observed_t *observed,
    char *err, size_t err_size)
{
	ncfg_genl_family_t family;
	char               why[NCFG_ERROR_MAX];
	size_t             at;
	size_t             wanted = 0;

	if (!observed) {
		ncfg_error_set(err, err_size,
		    "there is no observation to read the WireGuard devices into");
		return 0;
	}
	forget(observed);
	if (!kernel || !kernel->exchange) {
		/* The seam left out: nothing is asked and nothing is claimed. See the
		 * header comment for why that is not the same answer `netfilter.c`
		 * gives to the same shape. */
		return 1;
	}
	for (at = 0; at < observed->link_count; at++) {
		wanted += is_wireguard(&observed->links[at]) ? 1u : 0u;
	}
	if (wanted == 0) {
		/*
		 * **No controller request at all on a machine with no WireGuard**,
		 * which is most of them and every reconcile tick on each. A kernel
		 * without the module has no such links either, so the one check
		 * covers both.
		 */
		return 1;
	}
	why[0] = '\0';
	if (!family_of(kernel, &family, why, sizeof(why))) {
		/*
		 * A link the kernel calls `wireguard` and a family that will not
		 * resolve is the odd pair: the module is loaded or the device could
		 * not exist. So this is a container whose netlink is denied, or a
		 * controller this port could not read -- and it is reported as
		 * nothing known rather than as a set of devices with no keys.
		 */
		ncfg_log_emitf("observe", NCFG_LOG_NOTE,
		    "the `%s` generic netlink family could not be resolved (%s), so this "
		    "observation says nothing about %zu WireGuard device(s)", NCFG_WG_FAMILY,
		    why[0] ? why : "no sentence was given", wanted);
		return 1;
	}
	for (at = 0; at < observed->link_count; at++) {
		if (!is_wireguard(&observed->links[at])) {
			continue;
		}
		if (!read_device(kernel, &family, &observed->links[at], err, err_size)) {
			ncfg_genl_family_free(&family);
			return 0;
		}
	}
	ncfg_genl_family_free(&family);
	return 1;
}

int ncfg_observe_wireguard(ncfg_observed_t *observed, char *err, size_t err_size)
{
	ncfg_netlink_t        netlink;
	ncfg_observe_kernel_t kernel;
	int                   read;

	/*
	 * **The offloads round's socket, not a fourth one.** One generic netlink
	 * socket carries every family, and `observe_genl_open` is named for the
	 * protocol rather than for a family precisely so that this pass asks over
	 * it -- which is what `observe_internal.h` says where it is declared.
	 */
	if (!observe_genl_open(&netlink, &kernel)) {
		return ncfg_observe_wireguard_from(NULL, observed, err, err_size);
	}
	read = ncfg_observe_wireguard_from(&kernel, observed, err, err_size);
	ncfg_netlink_close(&netlink);
	return read;
}

/* ------------------------------------------------------------------------ *
 * Is what is running what was asked for
 * ------------------------------------------------------------------------ */

/*
 * The digest of the 32 octets a stored key spells.
 *
 * **The decode has to match the one the executor did**, or every device would
 * report a rotated key for ever: `apply/kernel_genl.c` hands the kernel what
 * `ncfg_key_parse` produced, and what was hashed when the kernel accepted it
 * is that. A store holding something this cannot parse falls back to the raw
 * text, which keeps the two sides hashing the same unparseable thing rather
 * than making one of them refuse -- the Rust's `decoded_key`, and its reason.
 *
 * `out` is `NCFG_SHA256_HEX_SIZE`. Both the octets and the text are the
 * caller's to wipe; the octets here are wiped before this returns.
 */
static void digest_of(const ncfg_secret_t *secret, char *out)
{
	unsigned char octets[NCFG_KEY_LEN];
	const char   *text = ncfg_secret_expose(secret);
	size_t        length = ncfg_secret_length(secret);
	size_t        start = 0;

	while (start < length && (unsigned char)text[start] <= ' ') {
		start++;
	}
	while (length > start && (unsigned char)text[length - 1u] <= ' ') {
		length--;
	}
	if (ncfg_key_parse(text + start, length - start, octets, NULL, 0)) {
		ncfg_sha256_hex(octets, sizeof(octets), out);
		explicit_bzero(octets, sizeof(octets));
		return;
	}
	ncfg_sha256_hex(text + start, length - start, out);
}

/*
 * Whether the material a reference names hashes to `recorded`.
 *
 * `NULL` in `*answer`'s `has` where the store could not answer, which is the
 * distinction that matters: "netcfgd cannot tell" is not "it changed", and the
 * second would replace a whole peer list over an unreadable file.
 *
 * **The digest never leaves this function and never reaches a buffer.** It
 * identifies the key it was taken of, which is enough to be worth keeping out
 * of a log, and the one thing a caller needs from it is the comparison.
 */
static ncfg_optbool_t currency_of(const ncfg_secret_resolver_t *secrets,
    const ncfg_secret_ref_t *reference, const char *recorded, const char *about)
{
	ncfg_optbool_t answer = { 0, 0 };
	ncfg_secret_t *secret;
	char           digest[NCFG_SHA256_HEX_SIZE];
	char           why[NCFG_ERROR_MAX];

	if (!reference || !recorded || !recorded[0]) {
		return answer;
	}
	why[0] = '\0';
	secret = ncfg_secret_resolve(secrets, reference, NULL, why, sizeof(why));
	if (!secret) {
		/*
		 * The store's sentence, which `secrets.h` guarantees names the
		 * reference, the provider and the reason and nothing else -- so this
		 * is the one place a note about a secret is safe to write, and the
		 * test sweeps this line for a canary rather than taking the
		 * guarantee's word for it.
		 */
		ncfg_log_emitf("observe", NCFG_LOG_NOTE,
		    "%s: the secret store could not answer (%s), so this observation says "
		    "nothing about whether the key in use is current", about, why);
		return answer;
	}
	digest_of(secret, digest);
	ncfg_secret_free(secret);
	answer.has = 1;
	answer.value = strcmp(digest, recorded) == 0;
	explicit_bzero(digest, sizeof(digest));
	return answer;
}

/* The device the document describes, or NULL where it describes none. */
static const ncfg_wireguard_config_t *configured(const ncfg_document_t *desired,
    const char *name)
{
	size_t at;

	for (at = 0; at < desired->device_count; at++) {
		const ncfg_device_t *device = &desired->devices[at];

		if (device->kind.kind == NCFG_KIND_WIREGUARD && device->name &&
		    strcmp(device->name, name) == 0) {
			return &device->kind.wireguard;
		}
	}
	return NULL;
}

/*
 * The digest one line of the preshared record holds for a peer.
 *
 * `<key> <digest>` per line, keyed by public key because that is the only name
 * the kernel and the document share. **The key is parsed rather than the
 * peer's rendered**, which is the divergence: base64 has more than one
 * spelling of one key -- the last significant character carries four bits and
 * two of them are not used -- so comparing the text would make a record
 * written in one spelling miss a peer reported in the other. `document.h`
 * keeps keys as octets and re-renders them for this reason; the Rust compares
 * the rendered strings.
 *
 * **Nothing is written into the record**, which is what lets one read serve
 * every peer: a walk that terminated each line in place would need a copy per
 * peer, and a hub's record is one line per peer. `out` is
 * `NCFG_SHA256_HEX_SIZE` and is filled only on a match.
 */
static int preset_digest(const char *record, const unsigned char *public_key, char *out)
{
	const char *line = record;

	while (line && *line) {
		const char   *end = strchr(line, '\n');
		const char   *stop = end ? end : line + strlen(line);
		const char   *space = memchr(line, ' ', (size_t)(stop - line));
		unsigned char octets[NCFG_KEY_LEN];

		if (space && ncfg_key_parse(line, (size_t)(space - line), octets, NULL, 0) &&
		    memcmp(octets, public_key, sizeof(octets)) == 0) {
			size_t at = 0;

			space++;
			while (space < stop && (unsigned char)*space <= ' ') {
				space++;
			}
			while (space < stop && (unsigned char)*space > ' ' &&
			    at + 1u < (size_t)NCFG_SHA256_HEX_SIZE) {
				out[at++] = *space++;
			}
			out[at] = '\0';
			return at != 0;
		}
		if (!end) {
			return 0;
		}
		line = end + 1;
	}
	return 0;
}

/* The document's reference for one peer, found by the key the kernel reports. */
static const ncfg_secret_ref_t *peer_preshared(const ncfg_wireguard_config_t *config,
    const unsigned char *public_key)
{
	size_t at;

	for (at = 0; at < config->peer_count; at++) {
		if (memcmp(config->peers[at].public_key, public_key,
		    sizeof(config->peers[at].public_key)) == 0) {
			return config->peers[at].preshared_key;
		}
	}
	return NULL;
}

/* Whether each peer's preshared key is still the one the store holds. */
static void preset_currency(ncfg_observed_wireguard_t *wireguard, const char *run_dir,
    const char *iface, const ncfg_wireguard_config_t *config,
    const ncfg_secret_resolver_t *secrets)
{
	char  path[NCFG_OBSERVE_WG_RECORD_PATH_MAX];
	char *record;
	size_t at;

	if (!ncfg_observe_wg_preset_record_path(run_dir, iface, path, sizeof(path), NULL, 0)) {
		return;
	}
	record = read_record(path);
	if (!record) {
		return;
	}
	for (at = 0; at < wireguard->peer_count; at++) {
		ncfg_observed_wg_peer_t *peer = &wireguard->peers[at];
		char                     digest[NCFG_SHA256_HEX_SIZE];
		char                     about[NCFG_ERROR_MAX];

		if (!peer->preshared_key) {
			/* A peer that has none has nothing to be out of date, which is
			 * not the same as one whose key netcfgd cannot check. */
			continue;
		}
		if (!preset_digest(record, peer->public_key, digest)) {
			/* No line for this peer: netcfgd did not give it the key it is
			 * holding, or the record predates it. Not a statement either. */
			continue;
		}
		/* Named by the interface and the peer's position, never by the key:
		 * a rendered public key in a log is not a disclosure, but it is the
		 * one identifier this file has no reason to print. */
		(void)snprintf(about, sizeof(about), "%s: peer %zu's preshared key", iface,
		    at + 1u);
		peer->preshared_matches = currency_of(secrets, peer_preshared(config,
		    peer->public_key), digest, about);
	}
	free(record);
}

int ncfg_observe_wireguard_currency(ncfg_observed_t *observed, const char *run_dir,
    const ncfg_secret_resolver_t *secrets, const ncfg_document_t *desired, char *err,
    size_t err_size)
{
	size_t at;

	if (!observed) {
		ncfg_error_set(err, err_size,
		    "there is no observation to read the key currency into");
		return 0;
	}
	/*
	 * Three ways to be asked nothing, and each is ordinary. No store named is
	 * the seam left out; no document is `ncfg status` on a machine whose
	 * configuration has stopped compiling, which is exactly when somebody
	 * runs it; no run directory is nowhere to have recorded anything.
	 */
	if (!secrets || !desired || !run_dir || !run_dir[0]) {
		return 1;
	}
	for (at = 0; at < observed->link_count; at++) {
		ncfg_observed_link_t          *link = &observed->links[at];
		const ncfg_wireguard_config_t *config;
		char                           path[NCFG_OBSERVE_WG_RECORD_PATH_MAX];
		char                           about[NCFG_ERROR_MAX];
		char                          *record;

		if (!link->wireguard || !link->name) {
			continue;
		}
		config = configured(desired, link->name);
		if (!config) {
			/* A device the document does not describe -- one somebody else
			 * made, or one whose block has been deleted while the device
			 * lives on. There is nothing to be current with. */
			continue;
		}
		if (!ncfg_observe_wg_key_record_path(run_dir, link->name, path, sizeof(path),
		    NULL, 0)) {
			continue;
		}
		record = read_record(path);
		if (!record) {
			/* A device netcfgd did not configure, or a `/run` cleared under a
			 * running one. Neither is a statement about the key. */
			continue;
		}
		(void)snprintf(about, sizeof(about), "%s: private key", link->name);
		link->wireguard->key_matches = currency_of(secrets, &config->private_key,
		    trim(record), about);
		free(record);
		preset_currency(link->wireguard, run_dir, link->name, config, secrets);
	}
	return 1;
}
