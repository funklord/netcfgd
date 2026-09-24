/*
 * wireguard.c -- the device's own settings and its peer list.
 *
 * WHAT WAS THROWN AWAY, AND FOR HOW LONG
 *   The kernel reports the listen port, the mark and every peer for free on
 *   the same request that answers "is a private key loaded", and netcfgd
 *   discarded all of it for as long as WireGuard has existed here. So an
 *   edited listen port, an edited mark and a **deleted peer** each planned
 *   nothing at all, on a tunnel that looked configured (0054). The
 *   observation carries them now and this is what reads them.
 *
 * NOTHING SECRET PASSES THROUGH HERE
 *   A plan goes to `/run/netcfgd/plan.last.json` and over the control socket,
 *   so constraint 5 holds for it exactly as it does for the document. What the
 *   op carries is the secret *reference* the document names, never a key. And
 *   the two comparisons that are about secrets are not comparisons at all:
 *   `key_matches` and `preshared_matches` are answers the **observer**
 *   computed where both halves were already in hand, exactly as an access
 *   point's passphrase is (0052, 0055, 0056).
 *
 *   `NULL` is not `false` in either of them. A device netcfgd did not
 *   configure, and a secret that will not resolve, both leave the question
 *   unanswered -- and an unanswered question is not a reason to rekey a
 *   working tunnel.
 *
 * WHAT PARTICIPATES IN THE PEER COMPARISON
 *   Both sides go through the same two steps, and that is the whole design:
 *   the Rust's first version normalised only the document's side and left the
 *   observation's endpoint in place, which made every peer that has ever
 *   handshaken differ for ever -- and its live test could not see it, because
 *   its peers have no endpoint and so agreed for the wrong reason.
 *
 *     * **The endpoint is left out.** A peer roams, the kernel rewrites the
 *       endpoint from the packets it receives, and the document's endpoint is
 *       where to look *first* rather than where a peer must stay. It stays in
 *       the observation, which is what `ncfg status` shows.
 *     * **`allowed_ips` are canonicalised and sorted.** The kernel prints its
 *       own spelling and the operator writes theirs; comparing the two as
 *       written is 10.169's defect in a second place, and the order is the
 *       kernel's arbitrary one on one side and the operator's on the other.
 *     * **A zero keepalive is absent.** A peer with none reports 0, and a
 *       document saying 0 means the same thing.
 *     * **The peers themselves are sorted by public key**, which is the one
 *       field both sides have: the document sorts by the operator's label,
 *       which the kernel has never heard of.
 */
#include "plan_internal.h"

#include "ncfg/base.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ *
 * The comparable form of a peer
 * ------------------------------------------------------------------------ */

/*
 * A peer with everything the comparison does not own taken out.
 *
 * One type for both sides, so that what participates is decided once. The
 * prefixes are pointers into `prefix_text`, which is why this is a value the
 * caller owns rather than something a plan holds: nothing here outlives the
 * comparison.
 */
typedef struct {
	const unsigned char *public_key; /* 32 octets, borrowed */
	int                  preshared_key;
	char               **allowed_ips; /* canonical, sorted */
	size_t               allowed_ip_count;
	ncfg_optint_t        keepalive;
} ncfg_wg_comparable_t;

typedef struct {
	ncfg_wg_comparable_t *peers;
	size_t                count;
	/* Set where anything could not be allocated. A comparison that ran out of
	 * memory must not answer "the same", which would silently skip the one
	 * action this pass exists to plan. */
	int                   failed;
} ncfg_wg_peers_t;

static int compare_text(const void *left, const void *right)
{
	return strcmp(*(char *const *)left, *(char *const *)right);
}

static int compare_peers(const void *left, const void *right)
{
	const ncfg_wg_comparable_t *a = left;
	const ncfg_wg_comparable_t *b = right;

	return memcmp(a->public_key, b->public_key, 32u);
}

/*
 * One peer's prefixes, in the kernel's spelling and in sorted order.
 *
 * A prefix neither side can parse is kept as written rather than dropped: the
 * Rust's `filter_map` drops it, so a peer whose `allowed_ips` hold something
 * unparsable compares equal to one that holds nothing -- which is a route into
 * a tunnel silently not being narrowed.
 */
static int fill_prefixes(ncfg_wg_comparable_t *out, char *const *prefixes, size_t count)
{
	char   message[NCFG_ERROR_MAX];
	size_t i;

	out->allowed_ips = NULL;
	out->allowed_ip_count = 0;
	if (count == 0u) {
		return 1;
	}
	out->allowed_ips = calloc(count, sizeof(*out->allowed_ips));
	if (!out->allowed_ips) {
		return 0;
	}
	for (i = 0; i < count; i++) {
		char canonical[NCFG_ADDRESS_MAX];

		if (!prefixes[i]) {
			continue;
		}
		if (!ncfg_address_canonical(prefixes[i], canonical, sizeof(canonical), message,
		    sizeof(message))) {
			out->allowed_ips[out->allowed_ip_count] = strdup(prefixes[i]);
		} else {
			out->allowed_ips[out->allowed_ip_count] = strdup(canonical);
		}
		if (!out->allowed_ips[out->allowed_ip_count]) {
			return 0;
		}
		out->allowed_ip_count++;
	}
	qsort(out->allowed_ips, out->allowed_ip_count, sizeof(*out->allowed_ips), compare_text);
	return 1;
}

static void comparable_free(ncfg_wg_peers_t *peers)
{
	size_t i;
	size_t j;

	for (i = 0; i < peers->count; i++) {
		for (j = 0; j < peers->peers[i].allowed_ip_count; j++) {
			free(peers->peers[i].allowed_ips[j]);
		}
		free(peers->peers[i].allowed_ips);
	}
	free(peers->peers);
	peers->peers = NULL;
	peers->count = 0;
}

/* A stated keepalive, with zero read as none. */
static ncfg_optint_t without_zero(ncfg_optint_t value)
{
	ncfg_optint_t none = { 0, 0 };

	return (value.has && value.value != 0) ? value : none;
}

static void wanted_peers(ncfg_wg_peers_t *out, const ncfg_wireguard_config_t *config)
{
	size_t i;

	memset(out, 0, sizeof(*out));
	if (config->peer_count == 0u) {
		return;
	}
	out->peers = calloc(config->peer_count, sizeof(*out->peers));
	if (!out->peers) {
		out->failed = 1;
		return;
	}
	out->count = config->peer_count;
	for (i = 0; i < config->peer_count; i++) {
		const ncfg_wg_peer_t *peer = &config->peers[i];

		out->peers[i].public_key = peer->public_key;
		out->peers[i].preshared_key = peer->preshared_key != NULL;
		out->peers[i].keepalive = without_zero(peer->keepalive);
		if (!fill_prefixes(&out->peers[i], peer->allowed_ips, peer->allowed_ip_count)) {
			out->failed = 1;
			return;
		}
	}
	qsort(out->peers, out->count, sizeof(*out->peers), compare_peers);
}

static void running_peers(ncfg_wg_peers_t *out, const ncfg_observed_wireguard_t *running)
{
	size_t i;

	memset(out, 0, sizeof(*out));
	if (running->peer_count == 0u) {
		return;
	}
	out->peers = calloc(running->peer_count, sizeof(*out->peers));
	if (!out->peers) {
		out->failed = 1;
		return;
	}
	out->count = running->peer_count;
	for (i = 0; i < running->peer_count; i++) {
		const ncfg_observed_wg_peer_t *peer = &running->peers[i];

		out->peers[i].public_key = peer->public_key;
		out->peers[i].preshared_key = peer->preshared_key;
		out->peers[i].keepalive = peer->keepalive;
		if (!fill_prefixes(&out->peers[i], peer->allowed_ips, peer->allowed_ip_count)) {
			out->failed = 1;
			return;
		}
	}
	qsort(out->peers, out->count, sizeof(*out->peers), compare_peers);
}

static int peers_differ(const ncfg_wg_peers_t *left, const ncfg_wg_peers_t *right)
{
	size_t i;
	size_t j;

	if (left->failed || right->failed) {
		/* Not "the same": see the comment on the field. */
		return 1;
	}
	if (left->count != right->count) {
		return 1;
	}
	for (i = 0; i < left->count; i++) {
		if (memcmp(left->peers[i].public_key, right->peers[i].public_key, 32u) != 0 ||
		    left->peers[i].preshared_key != right->peers[i].preshared_key ||
		    left->peers[i].allowed_ip_count != right->peers[i].allowed_ip_count) {
			return 1;
		}
		if (left->peers[i].keepalive.has != right->peers[i].keepalive.has ||
		    (left->peers[i].keepalive.has &&
		    left->peers[i].keepalive.value != right->peers[i].keepalive.value)) {
			return 1;
		}
		for (j = 0; j < left->peers[i].allowed_ip_count; j++) {
			if (strcmp(left->peers[i].allowed_ips[j],
			    right->peers[i].allowed_ips[j]) != 0) {
				return 1;
			}
		}
	}
	return 0;
}

/*
 * A peer list as a plan's reason renders it.
 *
 * Public keys and nothing else. They are what identifies a peer, they are not
 * secret -- a public key is the thing handed to the other end -- and an
 * operator reading "the peer list changed" wants to see *which*.
 */
static const char *render_peers(ncfg_plan_t *plan, const ncfg_wg_peers_t *peers)
{
	ncfg_buf_t  buf;
	const char *text;
	size_t      i;

	if (peers->count == 0u) {
		return "<none>";
	}
	ncfg_buf_init(&buf, 0);
	for (i = 0; i < peers->count; i++) {
		char rendered[NCFG_KEY_TEXT_SIZE];

		(void)ncfg_key_render(peers->peers[i].public_key, rendered, sizeof(rendered),
		    NULL, 0);
		ncfg_buf_addf(&buf, "%s%s", i ? " " : "", rendered);
	}
	text = ncfg_plan_intern(plan, ncfg_buf_text(&buf));
	ncfg_buf_free(&buf);
	return text ? text : "<none>";
}

/* ------------------------------------------------------------------------ *
 * The pass
 * ------------------------------------------------------------------------ */

/* A stated port or mark, with zero read as "let the kernel choose". */
static ncfg_optint_t stated(ncfg_optint_t value)
{
	return without_zero(value);
}

/*
 * Whether a value the document states differs from what the kernel holds.
 *
 * A port or a mark the document does not state is the kernel's to choose, and
 * a silence against whatever it chose is agreement. The same trap 0052's
 * `band` fell into, which restarted an access point on every reconcile until
 * the document's silence was read as silence.
 */
static int device_differs(ncfg_optint_t desired, ncfg_optint_t seen)
{
	return desired.has && (!seen.has || desired.value != seen.value);
}

static const char *rendered(ncfg_plan_t *plan, ncfg_optint_t value)
{
	if (!value.has) {
		return "<absent>";
	}
	return ncfg_plan_internf(plan, "%lld", (long long)value.value);
}

void ncfg_plan_wireguard(ncfg_builder_t *builder, const ncfg_device_t *device)
{
	const ncfg_observed_link_t      *link;
	const ncfg_observed_wireguard_t *running;
	const ncfg_wireguard_config_t   *config;
	ncfg_plan_ids_t                  gate = { NULL, 0, 0 };
	ncfg_wg_peers_t                  wanted;
	ncfg_wg_peers_t                  held;
	ncfg_op_t                        op;
	ncfg_op_t                        inverse;
	ncfg_reason_t                    reason;
	const char                      *field = NULL;
	const char                      *desired_text = NULL;
	const char                      *observed_text = NULL;
	const ncfg_observed_wg_peer_t   *rotated = NULL;
	size_t                           i;

	if (device->kind.kind != NCFG_KIND_WIREGUARD) {
		return;
	}
	link = ncfg_observed_link(builder->observed, device->name);
	if (!link || !link->wireguard) {
		return;
	}
	running = link->wireguard;
	config = &device->kind.wireguard;
	ncfg_builder_gate(builder, device->name, &gate);

	if (device_differs(stated(config->listen_port), running->listen_port)) {
		field = "wireguard.listen_port";
		desired_text = rendered(builder->plan, stated(config->listen_port));
		observed_text = rendered(builder->plan, running->listen_port);
	} else if (device_differs(stated(config->fwmark), running->fwmark)) {
		field = "wireguard.fwmark";
		desired_text = rendered(builder->plan, stated(config->fwmark));
		observed_text = rendered(builder->plan, running->fwmark);
	} else if (running->key_matches.has && !running->key_matches.value) {
		/*
		 * A rotated private key. The value is in neither the document nor the
		 * observation and must be in neither: what arrives here is the
		 * answer, computed in the observer where both halves were already in
		 * hand. So the reason names the field and says which way it went, and
		 * nothing in this plan can print a key.
		 */
		field = "wireguard.private_key";
		desired_text = "the secret store's";
		observed_text = "the one the device was given";
	}

	if (field) {
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_WG_SET_DEVICE;
		op.u.wg_device.iface = device->name;
		/* A reference, never a value. */
		op.u.wg_device.private_key_ref = config->private_key.name;
		op.u.wg_device.listen_port = config->listen_port;
		op.u.wg_device.fwmark = config->fwmark;
		/*
		 * Reversible, and worth saying so: commit-confirm can put the port
		 * and the mark back, because what they were is exactly what the
		 * observation was just read from. The peer list below gets no such
		 * offer -- an observed peer has no name and no secret reference for a
		 * preshared key, so there is nothing to build a `wg.set_peers` out of,
		 * and claiming otherwise would revert a revocation into something that
		 * is not what was there.
		 */
		memset(&inverse, 0, sizeof(inverse));
		inverse.kind = NCFG_OP_WG_SET_DEVICE;
		inverse.u.wg_device.iface = device->name;
		inverse.u.wg_device.private_key_ref = config->private_key.name;
		inverse.u.wg_device.listen_port = running->listen_port;
		inverse.u.wg_device.fwmark = running->fwmark;
		reason = ncfg_plan_reason_differs(device->name, field, desired_text,
		    observed_text);
		(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count, &inverse);
	}

	/*
	 * A rotated preshared key is not a difference between the two lists --
	 * both say "this peer has one" -- so it is asked separately, and the
	 * answer is the observer's for the reason the private key's is. What it
	 * produces is the same op: the kernel takes a peer list, so replacing one
	 * peer means sending the list.
	 */
	for (i = 0; i < running->peer_count; i++) {
		if (running->peers[i].preshared_matches.has &&
		    !running->peers[i].preshared_matches.value) {
			rotated = &running->peers[i];
			break;
		}
	}

	wanted_peers(&wanted, config);
	running_peers(&held, running);
	if (rotated) {
		char rendered_key[NCFG_KEY_TEXT_SIZE];

		(void)ncfg_key_render(rotated->public_key, rendered_key, sizeof(rendered_key),
		    NULL, 0);
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_WG_SET_PEERS;
		op.u.wg_peers.iface = device->name;
		op.u.wg_peers.peers = config->peers;
		op.u.wg_peers.peer_count = config->peer_count;
		reason = ncfg_plan_reason_differs(device->name, "wireguard.peers.preshared_key",
		    "the secret store's",
		    ncfg_plan_internf(builder->plan, "the one %s was given", rendered_key));
		(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count, NULL);
	} else if (peers_differ(&wanted, &held)) {
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_WG_SET_PEERS;
		op.u.wg_peers.iface = device->name;
		op.u.wg_peers.peers = config->peers;
		op.u.wg_peers.peer_count = config->peer_count;
		reason = ncfg_plan_reason_differs(device->name, "wireguard.peers",
		    render_peers(builder->plan, &wanted), render_peers(builder->plan, &held));
		(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count, NULL);
	}
	if (wanted.failed || held.failed) {
		builder->plan->failed = 1;
	}
	comparable_free(&wanted);
	comparable_free(&held);
	ncfg_plan_ids_free(&gate);
}
