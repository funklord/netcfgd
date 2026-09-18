/*
 * offloads.c -- which of the driver offloads netcfgd manages are on, per link.
 *
 * WHY THIS IS A ROUND OF ITS OWN, AND ITS OWN SEAM
 *   `collect.c` takes seven dumps over `NETLINK_ROUTE` and `netfilter.c` two
 *   over `NETLINK_NETFILTER`. ethtool is neither: it is a generic netlink
 *   family, which is a third protocol on a third socket -- `netlink.h` says a
 *   family id resolved on one socket is meaningless on another -- so this is a
 *   third `ncfg_observe_kernel_t` rather than an eighth dump or a third
 *   nftables question.
 *
 *   **The seam is named for the protocol and not for the family.** A generic
 *   netlink socket carries every family on the machine, and the two WireGuard
 *   passes `observe.h` still defers are the same protocol asked a different
 *   family. Calling it `ethtool` would be naming a socket after one of the
 *   questions it can be asked, and would be a fourth seam the day the second
 *   question lands.
 *
 * ONE REQUEST PER LINK, BECAUSE ETHTOOL HAS NO DUMP
 *   Its messages are per-device by construction: there is no `NLM_F_DUMP` form
 *   of `FEATURES_GET` that answers for every interface at once. So this is a
 *   handful of round trips on a laptop and a few dozen on a router, each
 *   costing microseconds -- which is the Rust's arithmetic and its conclusion.
 *
 * WHAT ITS ABSENCE COST, WHICH IS THE NAT PASS'S COST AGAIN
 *   `link.set_offloads` is planned by comparing the document's `ethtool` block
 *   against `ncfg_observed_link_t.offloads`, and with nothing filling that
 *   list the comparison was against an empty one: a machine whose offloads
 *   were already right was planned a `link.set_offloads` on every pass and
 *   never converged, and the op's *inverse* -- which is built out of the same
 *   list -- would have turned every named feature off rather than putting back
 *   what was there. `netfilter.c` has the identical paragraph about `nat`, and
 *   it is identical because it is the same defect one field along.
 *
 * NOTHING HERE FAILS AN OBSERVATION BECAUSE A DEVICE WOULD NOT ANSWER
 *   A kernel older than 5.6 has no `ethtool` family at all; a device with no
 *   ethtool operations answers `EOPNOTSUPP`, which is most virtual interfaces;
 *   a container's netlink may be denied outright. All three are ordinary, and
 *   `observed.h` already says what an absent name means where the field is
 *   declared -- off, or unsupported, which the kernel does not distinguish
 *   either. So each of them leaves a link's list empty and says so in a note,
 *   and none of them costs the operator the rest of the observation.
 *
 *   **A device that answered partly is not read partly.** Where a payload will
 *   not decode, what was gathered for that device is thrown away rather than
 *   stored, because a short list is not a smaller answer to the same question:
 *   it is a feature the planner believes is off and sets on every pass. That
 *   is `collect.c`'s argument about a truncated dump, applied to the one list
 *   here that is input to a planner.
 *
 * WHAT `ACTIVE` DOES NOT SAY, MEASURED RATHER THAN ASSUMED
 *   A `FEATURES_GET` reply carries four bitsets -- `HW`, `WANTED`, `ACTIVE`
 *   and `NOCHANGE` -- and this reads one of them, which is the Rust's shape.
 *   The gap is real and both languages have it: the executor writes `WANTED`
 *   and this reads `ACTIVE`, and a feature the device forces on cannot be
 *   moved by the first and goes on being reported by the second. On this
 *   machine `rx-checksum` is in `ACTIVE` and absent from `WANTED` on the
 *   loopback, on `docker0` and on both WireGuard devices -- the state a refused
 *   set leaves behind, sitting there with nothing having been applied -- so a
 *   document naming it `off` there plans `link.set_offloads` on every pass for
 *   ever. Reading the third fact needs somewhere to put it, and `offloads` is a
 *   list of names with no room for "asked for and refused"; project.md 10.185
 *   has the measurement and 0263 the entry.
 *
 * WHERE THE NAMES COME FROM
 *   `document.h`, and nowhere else. `ncfg_offload_field_names` is the table the
 *   planner writes from, and this is the reader that has to agree with it --
 *   which is the whole reason it is in the model rather than in either module.
 *   Nothing in this file spells a feature name.
 */
#include "ncfg/observe.h"

#include "observe_internal.h"

#include "ncfg/document.h"
#include "ncfg/ethtool.h"
#include "ncfg/genl.h"
#include "ncfg/log.h"
#include "ncfg/wire.h"

#include <stdlib.h>
#include <string.h>

/*
 * A complete request message, taken apart into what the exchange takes.
 *
 * `genl.h` and `ethtool.h` build whole messages because that is what their
 * other callers send, and the exchange writes a header of its own. Taking the
 * kind, the flags and the body out of what they built is what keeps the
 * controller's id, the family id, the command number and the device header in
 * the modules that own them; spelling any of them again here is how a request
 * comes to be aimed at another family and read as this one's. `collect.c` does
 * this to the two traffic-control requests and `netfilter.c` to the two
 * nftables ones -- three copies of a line that differs only in the noun in its
 * refusal, which is a tidy-up for whoever next touches all three rather than
 * one to make in a file two of them are being written in.
 *
 * `body` is the caller's to have initialised and to free on either answer. The
 * sequence number is discarded with the header, which is why every caller here
 * builds with zero.
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
 * Whether a kernel feature name is one the model can express.
 *
 * Derived from `ncfg_offload_field_names` rather than kept beside it, so this
 * is not a second list: a feature added to the model is in this answer the
 * moment it is in that table. A device reports dozens of features and storing
 * all of them would put a page of driver detail in `/run` for five fields,
 * which is what `observed.h` says where the field is declared.
 */
static int managed(const char *name)
{
	size_t field;

	if (!name) {
		return 0;
	}
	for (field = 0; field < NCFG_OFFLOAD_FIELD_COUNT; field++) {
		const char *const *names;
		size_t             count = 0;
		size_t             at;

		names = ncfg_offload_field_names((int)field, &count);
		for (at = 0; names && at < count; at++) {
			if (strcmp(names[at], name) == 0) {
				return 1;
			}
		}
	}
	return 0;
}

/*
 * The `ethtool` family, resolved over the caller's exchange.
 *
 * 0 is a machine this port cannot ask -- a kernel that predates the family, a
 * netlink this process may not open, a controller that answered about nothing
 * -- and the sentence comes back in `why` for a note rather than for a
 * refusal. It is deliberately not told apart from a controller that refused:
 * `ncfg_genl_lookup_failed` already distinguishes them inside the sentence,
 * and to this pass all of them mean the same thing, which is that no device's
 * offloads can be read.
 */
static int family_of(const ncfg_observe_kernel_t *genl, ncfg_genl_family_t *family, char *why,
    size_t why_size)
{
	ncfg_buf_t           message;
	ncfg_buf_t           body;
	ncfg_netlink_reply_t reply;
	uint16_t             kind = 0;
	uint16_t             flags = 0;
	int                  ok;

	memset(family, 0, sizeof(*family));
	memset(&reply, 0, sizeof(reply));
	ncfg_buf_init(&message, 0);
	ncfg_buf_init(&body, 0);
	ok = ncfg_genl_getfamily_request(&message, NCFG_ETHTOOL_FAMILY, 0, why, why_size) &&
	    request_parts(&message, &kind, &flags, &body, why, why_size);
	ncfg_buf_free(&message);
	if (ok) {
		ok = genl->exchange(genl->context, kind, flags, &body, NULL, &reply, why,
		    why_size);
	}
	ncfg_buf_free(&body);
	if (ok && reply.count == 0) {
		/*
		 * The controller answered and named no family. `kernel_genl.c`
		 * refuses this for the same reason and says it: a reply that
		 * arrived and said nothing reads downstream as a family with id
		 * zero, and the refusal then arrives from the wrong call and is
		 * about the wrong thing.
		 */
		ncfg_error_set(why, why_size,
		    "the generic netlink controller answered about `%s` without naming a "
		    "family", NCFG_ETHTOOL_FAMILY);
		ok = 0;
	}
	if (ok) {
		ok = ncfg_genl_family_parse(NCFG_ETHTOOL_FAMILY, reply.items[0].bytes,
		    reply.items[0].length, family, why, why_size);
	}
	ncfg_netlink_reply_free(&reply);
	return ok;
}

/*
 * Every feature one device has on, whatever their names.
 *
 * 1 with `out` filled in, 0 with a sentence for a device that could not be
 * asked or whose answer would not decode. `out` is the caller's to free on
 * either answer -- a partial set is exactly what must not be stored, and
 * leaving it owned by one side keeps the failure path one line.
 */
static int active_of(const ncfg_observe_kernel_t *genl, const ncfg_genl_family_t *family,
    const char *device, ncfg_ethtool_names_t *out, char *why, size_t why_size)
{
	ncfg_buf_t           message;
	ncfg_buf_t           body;
	ncfg_netlink_reply_t reply;
	uint16_t             kind = 0;
	uint16_t             flags = 0;
	size_t               at;
	int                  ok;

	memset(out, 0, sizeof(*out));
	memset(&reply, 0, sizeof(reply));
	ncfg_buf_init(&message, 0);
	ncfg_buf_init(&body, 0);
	ok = ncfg_ethtool_features_get_request(&message, family, device, 0, why, why_size) &&
	    request_parts(&message, &kind, &flags, &body, why, why_size);
	ncfg_buf_free(&message);
	if (ok) {
		ok = genl->exchange(genl->context, kind, flags, &body, NULL, &reply, why,
		    why_size);
	}
	ncfg_buf_free(&body);
	for (at = 0; ok && at < reply.count; at++) {
		/*
		 * Every payload, because the kernel answers about some devices in
		 * more than one message and only one of them carries the active
		 * set -- which is why a payload without one adds nothing and is
		 * not a failure. `ncfg_ethtool_active_merge` says so, and folds
		 * them in sorted and deduplicated.
		 */
		ok = ncfg_ethtool_active_merge(out, reply.items[at].bytes,
		    reply.items[at].length, why, why_size);
	}
	ncfg_netlink_reply_free(&reply);
	return ok;
}

/* Everything the model can express out of one device's active set, in the
 * order the set is already in -- which is sorted and without repeats, so two
 * observations of one machine compare equal. */
static int keep_managed(const ncfg_ethtool_names_t *active, ncfg_observed_link_t *link,
    char *err, size_t err_size)
{
	char **kept = NULL;
	size_t count = 0;
	size_t at;

	for (at = 0; at < active->count; at++) {
		if (!managed(active->items[at])) {
			continue;
		}
		if (!observe_list_add(&kept, &count, active->items[at])) {
			ncfg_error_set(err, err_size,
			    "out of memory recording the offloads %s has on",
			    link->name ? link->name : "?");
			observe_names_free(kept, count);
			return 0;
		}
	}
	observe_names_free(link->offloads, link->offload_count);
	link->offloads = kept;
	link->offload_count = count;
	return 1;
}

/* Nothing is known about any device's offloads. Cleared rather than left, so a
 * second observation through a source without this seam does not carry the
 * first one's answer -- `netfilter.c`'s rule, for its reason. */
static void nothing_is_known(ncfg_observed_t *observed)
{
	size_t at;

	for (at = 0; at < observed->link_count; at++) {
		observe_names_free(observed->links[at].offloads,
		    observed->links[at].offload_count);
		observed->links[at].offloads = NULL;
		observed->links[at].offload_count = 0;
	}
}

int ncfg_observe_offloads_from(const ncfg_observe_kernel_t *genl, ncfg_observed_t *observed,
    char *err, size_t err_size)
{
	ncfg_genl_family_t family;
	char               why[NCFG_ERROR_MAX];
	char               note[NCFG_ERROR_MAX];
	size_t             unreadable = 0;
	size_t             at;

	if (!observed) {
		ncfg_error_set(err, err_size,
		    "there is no observation to read the offloads into");
		return 0;
	}
	nothing_is_known(observed);
	if (!genl || !genl->exchange) {
		/*
		 * **A seam that is absent costs exactly what it says.** A caller
		 * with no generic netlink exchange observes everything else and
		 * reports no offload on, which is `ncfg_reconcile_world_t`'s
		 * bargain and is what lets a test install only the seam its case
		 * is about.
		 */
		return 1;
	}
	why[0] = '\0';
	if (!family_of(genl, &family, why, sizeof(why))) {
		ncfg_log_emitf("observe", NCFG_LOG_NOTE,
		    "the ethtool generic netlink family could not be resolved (%s), so this "
		    "observation reports no driver offload on any interface",
		    why[0] ? why : "no sentence was given");
		ncfg_genl_family_free(&family);
		return 1;
	}

	note[0] = '\0';
	for (at = 0; at < observed->link_count; at++) {
		ncfg_observed_link_t *link = &observed->links[at];
		ncfg_ethtool_names_t  active;
		int                   read;

		why[0] = '\0';
		read = active_of(genl, &family, link->name, &active, why, sizeof(why));
		if (!read) {
			/*
			 * Counted rather than fatal, and the whole device's answer
			 * dropped rather than half-stored. A device with no ethtool
			 * operations is the commonest reason and is most virtual
			 * interfaces; a name this port would not put in a request is
			 * the other, and neither is a machine an operator should be
			 * refused an observation of.
			 */
			if (note[0] == '\0') {
				ncfg_error_set(note, sizeof(note), "%s", why);
			}
			unreadable++;
			ncfg_ethtool_names_free(&active);
			continue;
		}
		if (!keep_managed(&active, link, err, err_size)) {
			ncfg_ethtool_names_free(&active);
			ncfg_genl_family_free(&family);
			return 0;
		}
		ncfg_ethtool_names_free(&active);
	}
	ncfg_genl_family_free(&family);
	if (unreadable != 0) {
		ncfg_log_emitf("observe", NCFG_LOG_NOTE,
		    "%zu interface(s) could not be asked which offloads they have on, so "
		    "this observation reports none for them: %s", unreadable,
		    note[0] ? note : "no sentence was kept");
	}
	return 1;
}

int observe_genl_open(ncfg_netlink_t *socket, ncfg_observe_kernel_t *out)
{
	char why[NCFG_ERROR_MAX];

	ncfg_netlink_init(socket);
	memset(out, 0, sizeof(*out));
	why[0] = '\0';
	if (!ncfg_netlink_open_protocol(socket, NETLINK_GENERIC, 0, why, sizeof(why)) ||
	    !ncfg_netlink_set_timeout(socket, NCFG_OBSERVE_TIMEOUT_SECONDS, why, sizeof(why))) {
		/*
		 * A container whose netlink is denied has no socket to open, and
		 * that is the commonest reason this fails. It is the same "nothing
		 * is known about any device's offloads" the family lookup answers
		 * with, so it is a note rather than a refusal -- and the
		 * observation goes on being taken.
		 */
		ncfg_netlink_close(socket);
		ncfg_log_emitf("observe", NCFG_LOG_NOTE,
		    "no generic netlink socket could be opened (%s), so this observation "
		    "reports no driver offload on any interface", why);
		return 0;
	}
	/* Without a timeout a lost message wedges the caller for ever, which is
	 * `ncfg_observe_collect`'s argument and is asked above rather than here so
	 * that a socket which opened and could not be timed out is closed with the
	 * one that never opened. */
	out->exchange = ncfg_observe_exchange_socket;
	out->context = socket;
	return 1;
}

int ncfg_observe_offloads(ncfg_observed_t *observed, char *err, size_t err_size)
{
	ncfg_netlink_t        netlink;
	ncfg_observe_kernel_t kernel;
	int                   read;

	if (!observe_genl_open(&netlink, &kernel)) {
		return ncfg_observe_offloads_from(NULL, observed, err, err_size);
	}
	read = ncfg_observe_offloads_from(&kernel, observed, err, err_size);
	ncfg_netlink_close(&netlink);
	return read;
}
