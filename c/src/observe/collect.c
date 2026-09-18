/*
 * collect.c -- the seven dumps, and the arrays a snapshot borrows.
 *
 * WHAT WAS MISSING, AND WHY IT SHOWED UP AS SILENCE
 *   `build.c` turns a snapshot into an observation and the decoders turn
 *   payloads into records, but nothing performed the dumps -- so every verb
 *   that begins with "look at the machine" answered that it was not in this
 *   wave, and the daemon had no way to see anything. This is that step and
 *   nothing else: ask, decode, and hand back the storage.
 *
 * WHY THERE IS AN AGGREGATE AND NOT JUST A SNAPSHOT
 *   `ncfg_observe_snapshot_t` borrows every field and has no free beside it,
 *   which its own comment says in as many words. Something has to own seven
 *   arrays and the alternative names hanging off each link record, so
 *   `ncfg_observe_capture_t` does, and 0263's rule about an aggregate having
 *   an `ncfg_x_free` lands there rather than on a type this file may not
 *   change.
 *
 * WHY THE SOCKET IS BEHIND A SEAM
 *   This suite runs on the machine netcfgd configures. A dump of the running
 *   kernel asserts against whatever that machine is doing at the time, and the
 *   cases worth having are the ones a kernel will not produce on demand: a
 *   dump ending in `NLMSG_ERROR`, a truncated final message, a message longer
 *   than the datagram that carried it, `ENOBUFS` mid-dump, and a machine with
 *   one more interface than an observation will hold.
 *   `ncfg_observe_exchange_t` is the whole of what changes between the live
 *   path and a replayed one, and `ncfg_observe_exchange_replay` is the same
 *   round with the send taken out -- which is `ncfg_netlink_change_from`'s
 *   split, one layer up.
 *
 * WHAT THIS FILE DOES NOT DECIDE
 *   Ownership, origin, and every judgement 0002 is about: those are
 *   `ownership.c`'s and `build.c`'s, and this file must stay ignorant of them
 *   or the policy becomes something that can only be tested against a kernel
 *   again. It reads no file and no environment variable either -- the roots
 *   are `augment`'s argument and nothing here has a path in it.
 */
#include "ncfg/observe.h"

#include "observe_internal.h"

#include <stdlib.h>
#include <string.h>

#include <linux/rtnetlink.h>

/* ------------------------------------------------------------------------ *
 * What a round of dumps is building
 * ------------------------------------------------------------------------ */

/*
 * The capacities behind the capture's counts.
 *
 * Deliberately not in the capture. A reader of an observation wants to know
 * how many links there are; a capacity beside that count is a second number
 * that looks like an answer to the same question, and the exactly-grown lists
 * in `observe_internal.h` make the same choice for the same reason.
 */
typedef struct {
	size_t links;
	size_t addresses;
	size_t routes;
	size_t bridge_vlans;
	size_t qdisc_roots;
	size_t redirects;
	size_t rules;
	size_t ingress_hooks;
} capacities_t;

typedef struct {
	const ncfg_observe_kernel_t *kernel;
	ncfg_observe_capture_t      *capture;
	/* `kernel->records_max`, resolved once so that the default is not read
	 * in eight places. */
	size_t                       max;
	capacities_t                 room;
} round_t;

/* The first thing that went wrong without stopping the round. One buffer and
 * not one per event; see the field's comment. */
static void note(ncfg_observe_capture_t *capture, const char *why)
{
	if (capture->note[0] != '\0' || !why || why[0] == '\0') {
		return;
	}
	ncfg_error_set(capture->note, sizeof(capture->note), "%s", why);
}

/* A payload a decoder refused. Counted, because a truncated dump and a quiet
 * machine look the same afterwards. */
static void skip(ncfg_observe_capture_t *capture, const char *why)
{
	capture->skipped++;
	note(capture, why);
}

/* An interface whose filter dump could not be read. */
static void unreadable(ncfg_observe_capture_t *capture, const char *why)
{
	capture->redirects_unreadable++;
	note(capture, why);
}

/* ------------------------------------------------------------------------ *
 * Growing the arrays
 * ------------------------------------------------------------------------ */

/*
 * Room for one more record, handing back the array -- which may have moved.
 *
 * The array is returned rather than written through a `void **` because the
 * caller's pointer is typed and a pointer to it is not a `void **`; casting one
 * to the other is a pun this port has no reason to make. `*ok` is the answer,
 * and on a refusal the caller's own pointer is still the valid one, since
 * `realloc` leaves it alone when it fails.
 */
static void *with_room(void *items, size_t count, size_t *capacity, size_t item_size,
    size_t max, const char *what, int *ok, char *err, size_t err_size)
{
	size_t wanted;
	void  *grown;

	*ok = 0;
	if (count >= max) {
		/*
		 * Refused naming the kind and the number, which is the pair
		 * whoever raises this needs. Not truncated: an observation
		 * quietly missing routes is a plan that installs them all again.
		 */
		ncfg_error_set(err, err_size,
		    "this machine reports more than %zu %s, which is past what one observation holds",
		    max, what);
		return items;
	}
	if (count < *capacity) {
		*ok = 1;
		return items;
	}
	/* Sixteen, then doubling, with the ceiling as the last step -- so the
	 * final allocation is the bound itself rather than twice it. */
	wanted = *capacity ? *capacity * 2u : 16u;
	if (*capacity > max / 2u || wanted > max) {
		wanted = max;
	}
	/*
	 * **The growth does not lean on the refusal above it.** Clamping to the
	 * ceiling is only safe while `count < max` holds, and an edit to that
	 * one comparison would turn a refusal into a write one past the array
	 * -- a boundary mistake becoming a heap overflow, which is the failure
	 * mode a bound is supposed to prevent. Asking for one more than is held
	 * costs nothing and cannot be undone by an edit somewhere else.
	 */
	if (wanted <= count) {
		wanted = count + 1u;
	}
	grown = realloc(items, wanted * item_size);
	if (!grown) {
		ncfg_error_set(err, err_size, "no memory for %zu %s", wanted, what);
		return items;
	}
	*capacity = wanted;
	*ok = 1;
	return grown;
}

static int push_link(round_t *round, const ncfg_link_record_t *record, char *err,
    size_t err_size)
{
	ncfg_observe_capture_t *capture = round->capture;
	int                     ok = 0;
	void                   *grown;

	grown = with_room(capture->links, capture->link_count, &round->room.links,
	    sizeof(*capture->links), round->max, "links", &ok, err, err_size);
	if (!ok) {
		return 0;
	}
	capture->links = grown;
	/* The record's alternative names move with it: a link record owns them
	 * and this is the hand-over, which is why the caller frees the record
	 * only where this refused. */
	capture->links[capture->link_count] = *record;
	capture->link_count++;
	return 1;
}

static int push_address(round_t *round, const ncfg_address_record_t *record, char *err,
    size_t err_size)
{
	ncfg_observe_capture_t *capture = round->capture;
	int                     ok = 0;
	void                   *grown;

	grown = with_room(capture->addresses, capture->address_count, &round->room.addresses,
	    sizeof(*capture->addresses), round->max, "addresses", &ok, err, err_size);
	if (!ok) {
		return 0;
	}
	capture->addresses = grown;
	capture->addresses[capture->address_count] = *record;
	capture->address_count++;
	return 1;
}

static int push_route(round_t *round, const ncfg_route_record_t *record, char *err,
    size_t err_size)
{
	ncfg_observe_capture_t *capture = round->capture;
	int                     ok = 0;
	void                   *grown;

	grown = with_room(capture->routes, capture->route_count, &round->room.routes,
	    sizeof(*capture->routes), round->max, "routes", &ok, err, err_size);
	if (!ok) {
		return 0;
	}
	capture->routes = grown;
	capture->routes[capture->route_count] = *record;
	capture->route_count++;
	return 1;
}

static int push_bridge_vlan(round_t *round, const ncfg_bridge_vlan_record_t *record, char *err,
    size_t err_size)
{
	ncfg_observe_capture_t *capture = round->capture;
	int                     ok = 0;
	void                   *grown;

	grown = with_room(capture->bridge_vlans, capture->bridge_vlan_count,
	    &round->room.bridge_vlans, sizeof(*capture->bridge_vlans), round->max, "bridge VLANs",
	    &ok, err, err_size);
	if (!ok) {
		return 0;
	}
	capture->bridge_vlans = grown;
	capture->bridge_vlans[capture->bridge_vlan_count] = *record;
	capture->bridge_vlan_count++;
	return 1;
}

static int push_qdisc_root(round_t *round, const ncfg_qdisc_record_t *record, char *err,
    size_t err_size)
{
	ncfg_observe_capture_t *capture = round->capture;
	int                     ok = 0;
	void                   *grown;

	grown = with_room(capture->qdisc_roots, capture->qdisc_root_count,
	    &round->room.qdisc_roots, sizeof(*capture->qdisc_roots), round->max, "root qdiscs",
	    &ok, err, err_size);
	if (!ok) {
		return 0;
	}
	capture->qdisc_roots = grown;
	capture->qdisc_roots[capture->qdisc_root_count] = *record;
	capture->qdisc_root_count++;
	return 1;
}

static int push_redirect(round_t *round, const ncfg_observe_redirect_t *record, char *err,
    size_t err_size)
{
	ncfg_observe_capture_t *capture = round->capture;
	int                     ok = 0;
	void                   *grown;

	grown = with_room(capture->redirects, capture->redirect_count, &round->room.redirects,
	    sizeof(*capture->redirects), round->max, "ingress redirects", &ok, err, err_size);
	if (!ok) {
		return 0;
	}
	capture->redirects = grown;
	capture->redirects[capture->redirect_count] = *record;
	capture->redirect_count++;
	return 1;
}

static int push_rule(round_t *round, const ncfg_rule_record_t *record, char *err,
    size_t err_size)
{
	ncfg_observe_capture_t *capture = round->capture;
	int                     ok = 0;
	void                   *grown;

	grown = with_room(capture->rules, capture->rule_count, &round->room.rules,
	    sizeof(*capture->rules), round->max, "routing rules", &ok, err, err_size);
	if (!ok) {
		return 0;
	}
	capture->rules = grown;
	capture->rules[capture->rule_count] = *record;
	capture->rule_count++;
	return 1;
}

static int push_ingress_hook(round_t *round, uint32_t index, char *err, size_t err_size)
{
	ncfg_observe_capture_t *capture = round->capture;
	int                     ok = 0;
	void                   *grown;

	grown = with_room(capture->ingress_hooks, capture->ingress_hook_count,
	    &round->room.ingress_hooks, sizeof(*capture->ingress_hooks), round->max,
	    "ingress hooks", &ok, err, err_size);
	if (!ok) {
		return 0;
	}
	capture->ingress_hooks = grown;
	capture->ingress_hooks[capture->ingress_hook_count] = index;
	capture->ingress_hook_count++;
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Order, so that one machine reads the same twice running
 * ------------------------------------------------------------------------ */

/*
 * Total orders, every field of them.
 *
 * `qsort` is not stable, so a comparator that calls two different records equal
 * lets the library decide which comes first -- which is how a list that ought
 * to compare equal between two observations of one unchanged machine comes back
 * in a different order. The Rust sorts these two lists by deriving `Ord`, which
 * is every field in declaration order; these say the same thing out loud.
 */
static int compare_u32(const void *left, const void *right)
{
	uint32_t first;
	uint32_t second;

	memcpy(&first, left, sizeof(first));
	memcpy(&second, right, sizeof(second));
	if (first != second) {
		return first < second ? -1 : 1;
	}
	return 0;
}

static int compare_bridge_vlan(const void *left, const void *right)
{
	const ncfg_bridge_vlan_record_t *first = left;
	const ncfg_bridge_vlan_record_t *second = right;

	if (first->index != second->index) {
		return first->index < second->index ? -1 : 1;
	}
	if (first->vid != second->vid) {
		return first->vid < second->vid ? -1 : 1;
	}
	if (first->pvid != second->pvid) {
		return first->pvid < second->pvid ? -1 : 1;
	}
	if (first->untagged != second->untagged) {
		return first->untagged < second->untagged ? -1 : 1;
	}
	return 0;
}

static int compare_redirect(const void *left, const void *right)
{
	const ncfg_observe_redirect_t *first = left;
	const ncfg_observe_redirect_t *second = right;

	if (first->index != second->index) {
		return first->index < second->index ? -1 : 1;
	}
	if (first->target != second->target) {
		return first->target < second->target ? -1 : 1;
	}
	if (first->ours != second->ours) {
		return first->ours < second->ours ? -1 : 1;
	}
	return 0;
}

/*
 * Sort, where there is something to sort.
 *
 * `qsort` on a null pointer is undefined even with a count of zero -- UBSan
 * says so in as many words -- and an observation of a quiet machine has three
 * empty arrays in it before it has anything else.
 */
static void sort(void *items, size_t count, size_t item_size,
    int (*compare)(const void *, const void *))
{
	if (items && count > 1u) {
		qsort(items, count, item_size, compare);
	}
}

/* Drop adjacent equals from a sorted array, in place. */
static size_t dedup(void *items, size_t count, size_t item_size,
    int (*compare)(const void *, const void *))
{
	uint8_t *bytes = items;
	size_t   kept = 0;
	size_t   at;

	if (count == 0) {
		return 0;
	}
	kept = 1;
	for (at = 1; at < count; at++) {
		if (compare(bytes + ((kept - 1u) * item_size), bytes + (at * item_size)) == 0) {
			continue;
		}
		if (kept != at) {
			memcpy(bytes + (kept * item_size), bytes + (at * item_size), item_size);
		}
		kept++;
	}
	return kept;
}

/* ------------------------------------------------------------------------ *
 * Asking
 * ------------------------------------------------------------------------ */

/*
 * One request, with the forgery count carried up whatever the answer was.
 *
 * The count survives a refusal for the reason `ncfg_netlink_collect` keeps it:
 * a dump that came back empty having discarded three datagrams from a local
 * process is a different fact from one that came back empty.
 */
static int ask(const round_t *round, uint16_t kind, uint16_t flags, const ncfg_buf_t *body,
    const ncfg_buf_t *attrs, ncfg_netlink_reply_t *out, char *err, size_t err_size)
{
	int answered;

	memset(out, 0, sizeof(*out));
	answered = round->kernel->exchange(round->kernel->context, kind, flags, body, attrs, out,
	    err, err_size);
	round->capture->dropped += out->dropped;
	return answered;
}

/*
 * A complete request message, taken apart into what the exchange takes.
 *
 * The two traffic-control dumps are built by `qdisc.h`, which writes a whole
 * message with its own header because that is what its other callers send; the
 * exchange writes a header itself, so what it needs is the body. Taking the
 * kind, the flags and the body **out of the message qdisc.c built** is what
 * keeps the ingress parent, the dump flags and the refusal of a zero index in
 * the one module that owns them -- spelling any of the three again here is how
 * a filter dump comes to be aimed at the wrong parent and report a machine with
 * no redirects on it.
 *
 * `body` is the caller's to have initialised and to free on either answer. The
 * sequence number the message carries is discarded with its header, which is
 * why every caller passes zero for it.
 */
static int request_parts(const ncfg_buf_t *message, uint16_t *kind, uint16_t *flags,
    ncfg_buf_t *body, char *err, size_t err_size)
{
	ncfg_wire_messages_t walk;
	ncfg_wire_message_t  parsed;

	ncfg_wire_messages_start(&walk, message->data, message->length);
	if (ncfg_wire_messages_next(&walk, &parsed, err, err_size) != NCFG_WIRE_OK) {
		ncfg_error_set(err, err_size,
		    "a traffic control request this port built is not a netlink message");
		return 0;
	}
	*kind = parsed.header.kind;
	*flags = parsed.header.flags;
	ncfg_buf_add(body, parsed.payload, parsed.payload_length);
	if (ncfg_buf_failed(body)) {
		ncfg_error_set(err, err_size, "no room for a traffic control request");
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * The dumps
 * ------------------------------------------------------------------------ */

static int dump_links(round_t *round, char *err, size_t err_size)
{
	ncfg_buf_t           body;
	ncfg_buf_t           attrs;
	ncfg_netlink_reply_t reply;
	size_t               at;
	int                  answered;

	ncfg_buf_init(&body, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_dump_link_request(&body, &attrs);
	if (ncfg_buf_failed(&body) || ncfg_buf_failed(&attrs)) {
		ncfg_error_set(err, err_size, "no room for a link dump request");
		ncfg_buf_free(&body);
		ncfg_buf_free(&attrs);
		return 0;
	}
	answered = ask(round, NCFG_DUMP_LINK, ncfg_dump_flags(), &body, &attrs, &reply, err,
	    err_size);
	ncfg_buf_free(&body);
	ncfg_buf_free(&attrs);
	if (!answered) {
		ncfg_netlink_reply_free(&reply);
		return 0;
	}
	for (at = 0; at < reply.count; at++) {
		ncfg_link_record_t record;
		char               why[NCFG_ERROR_MAX];

		if (!ncfg_dump_link(reply.items[at].bytes, reply.items[at].length, &record, why,
		    sizeof(why))) {
			skip(round->capture, why);
			continue;
		}
		if (!push_link(round, &record, err, err_size)) {
			ncfg_link_record_free(&record);
			ncfg_netlink_reply_free(&reply);
			return 0;
		}
	}
	ncfg_netlink_reply_free(&reply);
	return 1;
}

static int dump_addresses(round_t *round, char *err, size_t err_size)
{
	ncfg_buf_t           body;
	ncfg_buf_t           attrs;
	ncfg_netlink_reply_t reply;
	size_t               at;
	int                  answered;

	ncfg_buf_init(&body, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_dump_address_request(&body, &attrs);
	if (ncfg_buf_failed(&body) || ncfg_buf_failed(&attrs)) {
		ncfg_error_set(err, err_size, "no room for an address dump request");
		ncfg_buf_free(&body);
		ncfg_buf_free(&attrs);
		return 0;
	}
	answered = ask(round, NCFG_DUMP_ADDRESS, ncfg_dump_flags(), &body, &attrs, &reply, err,
	    err_size);
	ncfg_buf_free(&body);
	ncfg_buf_free(&attrs);
	if (!answered) {
		ncfg_netlink_reply_free(&reply);
		return 0;
	}
	for (at = 0; at < reply.count; at++) {
		ncfg_address_record_t record;
		char                  why[NCFG_ERROR_MAX];

		if (!ncfg_dump_address(reply.items[at].bytes, reply.items[at].length, &record, why,
		    sizeof(why))) {
			skip(round->capture, why);
			continue;
		}
		if (!push_address(round, &record, err, err_size)) {
			ncfg_netlink_reply_free(&reply);
			return 0;
		}
	}
	ncfg_netlink_reply_free(&reply);
	return 1;
}

static int dump_routes(round_t *round, char *err, size_t err_size)
{
	ncfg_buf_t           body;
	ncfg_buf_t           attrs;
	ncfg_netlink_reply_t reply;
	size_t               at;
	int                  answered;

	ncfg_buf_init(&body, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_dump_route_request(&body, &attrs);
	if (ncfg_buf_failed(&body) || ncfg_buf_failed(&attrs)) {
		ncfg_error_set(err, err_size, "no room for a route dump request");
		ncfg_buf_free(&body);
		ncfg_buf_free(&attrs);
		return 0;
	}
	answered = ask(round, NCFG_DUMP_ROUTE, ncfg_dump_flags(), &body, &attrs, &reply, err,
	    err_size);
	ncfg_buf_free(&body);
	ncfg_buf_free(&attrs);
	if (!answered) {
		ncfg_netlink_reply_free(&reply);
		return 0;
	}
	for (at = 0; at < reply.count; at++) {
		ncfg_route_record_t record;
		char                why[NCFG_ERROR_MAX];

		if (!ncfg_dump_route(reply.items[at].bytes, reply.items[at].length, &record, why,
		    sizeof(why))) {
			skip(round->capture, why);
			continue;
		}
		if (!push_route(round, &record, err, err_size)) {
			ncfg_netlink_reply_free(&reply);
			return 0;
		}
	}
	ncfg_netlink_reply_free(&reply);
	return 1;
}

/*
 * The second link dump, under `AF_BRIDGE`.
 *
 * It cannot be folded into the first: without `RTEXT_FILTER_BRVLAN` a bridge
 * arrives with its VLAN configuration *omitted* rather than empty, which reads
 * as "this bridge has none" rather than "you did not ask". Several records come
 * out of one message, because a port carrying four VLANs is one link with four
 * attributes.
 */
static int dump_bridge_vlans(round_t *round, char *err, size_t err_size)
{
	ncfg_buf_t           body;
	ncfg_buf_t           attrs;
	ncfg_netlink_reply_t reply;
	size_t               at;
	int                  answered;

	ncfg_buf_init(&body, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_dump_bridge_vlan_request(&body, &attrs);
	if (ncfg_buf_failed(&body) || ncfg_buf_failed(&attrs)) {
		ncfg_error_set(err, err_size, "no room for a bridge VLAN dump request");
		ncfg_buf_free(&body);
		ncfg_buf_free(&attrs);
		return 0;
	}
	answered = ask(round, NCFG_DUMP_BRIDGE_VLAN, ncfg_dump_flags(), &body, &attrs, &reply,
	    err, err_size);
	ncfg_buf_free(&body);
	ncfg_buf_free(&attrs);
	if (!answered) {
		ncfg_netlink_reply_free(&reply);
		return 0;
	}
	for (at = 0; at < reply.count; at++) {
		ncfg_bridge_vlan_records_t vlans;
		char                       why[NCFG_ERROR_MAX];
		size_t                     one;

		memset(&vlans, 0, sizeof(vlans));
		if (!ncfg_dump_bridge_vlans(reply.items[at].bytes, reply.items[at].length, &vlans,
		    why, sizeof(why))) {
			/*
			 * Ordinary rather than alarming: this dump and the
			 * ordinary link dump are the same message type, and a
			 * bridge is the only kind of link that answers it with
			 * VLANs.
			 */
			skip(round->capture, why);
			ncfg_bridge_vlan_records_free(&vlans);
			continue;
		}
		for (one = 0; one < vlans.count; one++) {
			if (!push_bridge_vlan(round, &vlans.items[one], err, err_size)) {
				ncfg_bridge_vlan_records_free(&vlans);
				ncfg_netlink_reply_free(&reply);
				return 0;
			}
		}
		ncfg_bridge_vlan_records_free(&vlans);
	}
	ncfg_netlink_reply_free(&reply);
	sort(round->capture->bridge_vlans, round->capture->bridge_vlan_count,
	    sizeof(*round->capture->bridge_vlans), compare_bridge_vlan);
	return 1;
}

/*
 * Every qdisc on the machine, which is where the ingress hooks come from too.
 *
 * They are in this dump, and knowing which interfaces carry one is what makes
 * the filter dump affordable -- that has to be asked per interface, and on a
 * machine doing no ingress shaping the answer is that it is asked zero times.
 */
static int dump_qdiscs(round_t *round, char *err, size_t err_size)
{
	ncfg_buf_t           message;
	ncfg_buf_t           body;
	ncfg_netlink_reply_t reply;
	uint16_t             kind = 0;
	uint16_t             flags = 0;
	size_t               at;
	int                  answered;

	ncfg_buf_init(&message, 0);
	ncfg_buf_init(&body, 0);
	if (!ncfg_qdisc_build_dump(&message, 0, err, err_size) ||
	    !request_parts(&message, &kind, &flags, &body, err, err_size)) {
		ncfg_buf_free(&message);
		ncfg_buf_free(&body);
		return 0;
	}
	answered = ask(round, kind, flags, &body, NULL, &reply, err, err_size);
	ncfg_buf_free(&message);
	ncfg_buf_free(&body);
	if (!answered) {
		ncfg_netlink_reply_free(&reply);
		return 0;
	}
	for (at = 0; at < reply.count; at++) {
		ncfg_qdisc_entry_t  what;
		ncfg_qdisc_record_t record;
		char                why[NCFG_ERROR_MAX];

		if (!ncfg_qdisc_entry_read(reply.items[at].bytes, reply.items[at].length, &what,
		    &record, why, sizeof(why))) {
			skip(round->capture, why);
			continue;
		}
		if (what == NCFG_QDISC_ENTRY_ROOT) {
			if (!push_qdisc_root(round, &record, err, err_size)) {
				ncfg_netlink_reply_free(&reply);
				return 0;
			}
		} else if (what == NCFG_QDISC_ENTRY_INGRESS) {
			if (!push_ingress_hook(round, record.index, err, err_size)) {
				ncfg_netlink_reply_free(&reply);
				return 0;
			}
		}
		/* `NCFG_QDISC_ENTRY_OTHER` is a child of somebody's class tree,
		 * which is outside 0023's scope and is not a skip: it was read
		 * perfectly well and is not ours to hold. */
	}
	ncfg_netlink_reply_free(&reply);
	sort(round->capture->ingress_hooks, round->capture->ingress_hook_count,
	    sizeof(*round->capture->ingress_hooks), compare_u32);
	round->capture->ingress_hook_count = dedup(round->capture->ingress_hooks,
	    round->capture->ingress_hook_count, sizeof(*round->capture->ingress_hooks),
	    compare_u32);
	return 1;
}

/*
 * The redirects on one interface's ingress hook.
 *
 * **A failure here is counted rather than fatal**, which is this file's one
 * deliberate softness and the argument is the window it lives in: the interface
 * was reported as carrying a hook by a dump taken a moment ago, so a request
 * that fails now is a machine that moved between two of the seven. A USB device
 * being unplugged is exactly that, and it is also what generates the event the
 * observation is running on -- observe.h records the same coincidence about the
 * rfkill search. Denying the whole observation over it would withhold the
 * answer at the moment somebody is asking why the device went.
 *
 * Returns 0 only where the round itself cannot continue.
 */
static int dump_redirects_on(round_t *round, uint32_t index, char *err, size_t err_size)
{
	ncfg_buf_t           message;
	ncfg_buf_t           body;
	ncfg_netlink_reply_t reply;
	uint16_t             kind = 0;
	uint16_t             flags = 0;
	char                 why[NCFG_ERROR_MAX];
	size_t               at;

	ncfg_buf_init(&message, 0);
	ncfg_buf_init(&body, 0);
	/*
	 * A zero index is refused in there rather than sent, because
	 * `RTM_GETTFILTER` answers one with an empty dump that looks exactly
	 * like a machine with no redirects installed. It cannot arrive from a
	 * qdisc dump, and it is handled rather than asserted for the reason a
	 * library never asserts.
	 */
	if (!ncfg_qdisc_build_filter_dump(&message, 0, index, why, sizeof(why)) ||
	    !request_parts(&message, &kind, &flags, &body, why, sizeof(why))) {
		unreadable(round->capture, why);
		ncfg_buf_free(&message);
		ncfg_buf_free(&body);
		return 1;
	}
	if (!ask(round, kind, flags, &body, NULL, &reply, why, sizeof(why))) {
		unreadable(round->capture, why);
		ncfg_netlink_reply_free(&reply);
		ncfg_buf_free(&message);
		ncfg_buf_free(&body);
		return 1;
	}
	ncfg_buf_free(&message);
	ncfg_buf_free(&body);
	for (at = 0; at < reply.count; at++) {
		ncfg_qdisc_redirect_t   found;
		ncfg_observe_redirect_t one;

		/*
		 * Not counted as a skip. This answers 0 for every filter that is
		 * not the exact shape netcfgd writes -- somebody's `u32`
		 * classifier is a perfectly good filter and reporting it as a
		 * redirect would produce a plan that removed it -- so a 0 here
		 * is much more often "not ours" than "malformed", and counting
		 * the two together would make the count mean nothing.
		 */
		if (!ncfg_qdisc_redirect_read(reply.items[at].bytes, reply.items[at].length,
		    &found, why, sizeof(why))) {
			continue;
		}
		memset(&one, 0, sizeof(one));
		one.index = index;
		one.target = found.target;
		one.ours = found.ours;
		if (!push_redirect(round, &one, err, err_size)) {
			ncfg_netlink_reply_free(&reply);
			return 0;
		}
	}
	ncfg_netlink_reply_free(&reply);
	return 1;
}

static int dump_redirects(round_t *round, char *err, size_t err_size)
{
	size_t at;

	for (at = 0; at < round->capture->ingress_hook_count; at++) {
		if (!dump_redirects_on(round, round->capture->ingress_hooks[at], err, err_size)) {
			return 0;
		}
	}
	sort(round->capture->redirects, round->capture->redirect_count,
	    sizeof(*round->capture->redirects), compare_redirect);
	round->capture->redirect_count = dedup(round->capture->redirects,
	    round->capture->redirect_count, sizeof(*round->capture->redirects), compare_redirect);
	return 1;
}

static int dump_rules(round_t *round, char *err, size_t err_size)
{
	ncfg_buf_t           body;
	ncfg_buf_t           attrs;
	ncfg_netlink_reply_t reply;
	size_t               at;
	int                  answered;

	ncfg_buf_init(&body, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_dump_rule_request(&body, &attrs);
	if (ncfg_buf_failed(&body) || ncfg_buf_failed(&attrs)) {
		ncfg_error_set(err, err_size, "no room for a routing rule dump request");
		ncfg_buf_free(&body);
		ncfg_buf_free(&attrs);
		return 0;
	}
	answered = ask(round, NCFG_DUMP_RULE, ncfg_dump_flags(), &body, &attrs, &reply, err,
	    err_size);
	ncfg_buf_free(&body);
	ncfg_buf_free(&attrs);
	if (!answered) {
		ncfg_netlink_reply_free(&reply);
		return 0;
	}
	for (at = 0; at < reply.count; at++) {
		ncfg_rule_record_t record;
		char               why[NCFG_ERROR_MAX];

		if (!ncfg_dump_rule(reply.items[at].bytes, reply.items[at].length, &record, why,
		    sizeof(why))) {
			skip(round->capture, why);
			continue;
		}
		if (!push_rule(round, &record, err, err_size)) {
			ncfg_netlink_reply_free(&reply);
			return 0;
		}
	}
	ncfg_netlink_reply_free(&reply);
	return 1;
}

/* ------------------------------------------------------------------------ *
 * The snapshot the capture hands out
 * ------------------------------------------------------------------------ */

/*
 * Point the snapshot at the arrays beside it.
 *
 * `address_proto_supported` is computed here and is **a lower bound**: it says
 * that an address in this dump carried `IFA_PROTO`, never that the kernel can
 * report one. A live 6.12 kernel tags none of its own, so a fresh machine
 * starts weak and calibrates the moment netcfgd owns its first address; the
 * field's own comment in this header is the long version.
 */
static void bind_snapshot(ncfg_observe_capture_t *capture)
{
	size_t at;

	memset(&capture->snapshot, 0, sizeof(capture->snapshot));
	capture->snapshot.links = capture->links;
	capture->snapshot.link_count = capture->link_count;
	capture->snapshot.addresses = capture->addresses;
	capture->snapshot.address_count = capture->address_count;
	capture->snapshot.routes = capture->routes;
	capture->snapshot.route_count = capture->route_count;
	capture->snapshot.bridge_vlans = capture->bridge_vlans;
	capture->snapshot.bridge_vlan_count = capture->bridge_vlan_count;
	capture->snapshot.qdisc_roots = capture->qdisc_roots;
	capture->snapshot.qdisc_root_count = capture->qdisc_root_count;
	capture->snapshot.redirects = capture->redirects;
	capture->snapshot.redirect_count = capture->redirect_count;
	capture->snapshot.rules = capture->rules;
	capture->snapshot.rule_count = capture->rule_count;
	for (at = 0; at < capture->address_count; at++) {
		if (capture->addresses[at].has_proto) {
			capture->snapshot.address_proto_supported = 1;
			break;
		}
	}
}

void ncfg_observe_capture_free(ncfg_observe_capture_t *capture)
{
	size_t at;

	if (!capture) {
		return;
	}
	/* The alternative names are the only thing a record owns, and they are
	 * the reason this aggregate exists rather than a bag of `free` calls. */
	for (at = 0; at < capture->link_count; at++) {
		ncfg_link_record_free(&capture->links[at]);
	}
	free(capture->links);
	free(capture->addresses);
	free(capture->routes);
	free(capture->bridge_vlans);
	free(capture->qdisc_roots);
	free(capture->redirects);
	free(capture->rules);
	free(capture->ingress_hooks);
	memset(capture, 0, sizeof(*capture));
}

/* ------------------------------------------------------------------------ *
 * The two exchanges
 * ------------------------------------------------------------------------ */

int ncfg_observe_exchange_socket(void *context, uint16_t kind, uint16_t flags,
    const ncfg_buf_t *body, const ncfg_buf_t *attrs, ncfg_netlink_reply_t *out, char *err,
    size_t err_size)
{
	ncfg_netlink_t *netlink = context;

	if (!netlink) {
		ncfg_error_set(err, err_size, "a netlink request needs an open socket");
		return 0;
	}
	return ncfg_netlink_request(netlink, kind, flags, body, attrs, out, err, err_size);
}

int ncfg_observe_exchange_replay(void *context, uint16_t kind, uint16_t flags,
    const ncfg_buf_t *body, const ncfg_buf_t *attrs, ncfg_netlink_reply_t *out, char *err,
    size_t err_size)
{
	ncfg_observe_replay_t *replay = context;
	ncfg_buf_t             message;
	uint32_t               seq;
	int                    built;

	if (!replay || !replay->recv || !out) {
		ncfg_error_set(err, err_size, "a replayed request needs a source and somewhere to go");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	seq = replay->seq;
	/*
	 * Built and then thrown away, rather than skipped.
	 *
	 * A request that would not assemble is one the socket form refuses
	 * before it sends anything, and a seam that left the step out would test
	 * less than the thing it stands in for -- which is the whole of what a
	 * seam is worth. The bytes are discarded because nothing here has
	 * anywhere to send them.
	 */
	ncfg_buf_init(&message, 0);
	built = ncfg_wire_build_request(&message, kind, flags, seq, body, attrs, err, err_size);
	ncfg_buf_free(&message);
	if (!built) {
		return 0;
	}
	replay->seq++;
	return ncfg_netlink_collect(replay->recv, replay->context, seq, flags,
	    replay->initial ? replay->initial : NCFG_NETLINK_REPLY_INITIAL, out, err, err_size);
}

/* ------------------------------------------------------------------------ *
 * The round
 * ------------------------------------------------------------------------ */

int ncfg_observe_collect_from(const ncfg_observe_kernel_t *kernel, ncfg_observe_capture_t *out,
    char *err, size_t err_size)
{
	round_t round;

	if (!kernel || !kernel->exchange || !out) {
		ncfg_error_set(err, err_size,
		    "a round of dumps needs a kernel to ask and somewhere to put the answer");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	memset(&round, 0, sizeof(round));
	round.kernel = kernel;
	round.capture = out;
	round.max = kernel->records_max ? kernel->records_max : NCFG_OBSERVE_RECORDS_MAX;

	/*
	 * The Rust's order, kept because the fifth decides how many the sixth
	 * is. Nothing between them re-reads anything, so a machine that changes
	 * mid-round is reported as it was at each dump -- which is inherent to
	 * asking seven questions and is why an address whose interface is not in
	 * the link table is dropped by `build` rather than guessed at.
	 */
	if (!dump_links(&round, err, err_size) || !dump_addresses(&round, err, err_size) ||
	    !dump_routes(&round, err, err_size) || !dump_bridge_vlans(&round, err, err_size) ||
	    !dump_qdiscs(&round, err, err_size) || !dump_redirects(&round, err, err_size) ||
	    !dump_rules(&round, err, err_size)) {
		ncfg_observe_capture_free(out);
		return 0;
	}
	bind_snapshot(out);
	return 1;
}

int ncfg_observe_collect_on(ncfg_netlink_t *netlink, ncfg_observe_capture_t *out, char *err,
    size_t err_size)
{
	ncfg_observe_kernel_t kernel;

	if (!netlink) {
		ncfg_error_set(err, err_size, "a round of dumps needs an open socket");
		return 0;
	}
	memset(&kernel, 0, sizeof(kernel));
	kernel.exchange = ncfg_observe_exchange_socket;
	kernel.context = netlink;
	return ncfg_observe_collect_from(&kernel, out, err, err_size);
}

int ncfg_observe_collect(ncfg_observe_capture_t *out, char *err, size_t err_size)
{
	ncfg_netlink_t netlink;
	int            collected;

	ncfg_netlink_init(&netlink);
	if (!ncfg_netlink_open(&netlink, err, err_size)) {
		return 0;
	}
	/* Without a timeout a lost message wedges the caller for ever, which on
	 * a daemon holding `CAP_NET_ADMIN` is worse than an error. A caller with
	 * its own socket has already decided this; one that reached here has
	 * not. */
	if (!ncfg_netlink_set_timeout(&netlink, NCFG_OBSERVE_TIMEOUT_SECONDS, err, err_size)) {
		ncfg_netlink_close(&netlink);
		return 0;
	}
	collected = ncfg_observe_collect_on(&netlink, out, err, err_size);
	ncfg_netlink_close(&netlink);
	return collected;
}
