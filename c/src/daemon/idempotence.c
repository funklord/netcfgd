/*
 * idempotence.c -- whether a queued order may be run twice.
 *
 * `daemon.h` carries the decision and the criterion. This carries the table
 * and the judgement per verb, which is the part somebody has to disagree with
 * in specifics rather than in principle.
 *
 * **Its own file rather than beside `ncfg_tier_of` in `authorize.c`.** The two
 * are the same shape -- a pure function from request kind to a property of the
 * verb, over a designated-initialiser table -- and they are not the same
 * subject. One decides who may ask; this decides what happens when an answer
 * is lost. Putting them together would make `authorize.c` a place where
 * per-verb facts accumulate, which is how a security-critical file stops being
 * about one thing.
 */
#include "ncfg/daemon.h"

/*
 * WHY SO MANY VERBS ARE IDEMPOTENT, AND IT IS NOT GENEROSITY
 *
 * netcfgd is declarative. A client says what it wants to be true -- this
 * drop-in holds this text, this radio is on, the machine matches its document
 * -- and the daemon converges the machine onto it. **A verb whose argument is
 * an end state is idempotent by construction**, which is why the interesting
 * column here is the short one.
 *
 * The three that are not share one shape: their effect depends on what is
 * ambient at the moment they run rather than on what the order says.
 *
 *   `confirm`        confirms THE OPEN WINDOW. Which window that is, is
 *                    ambient. A retry after a window closed and another opened
 *                    confirms a change nobody confirmed -- which is the exact
 *                    failure commit-confirm exists to prevent, arriving
 *                    through the mechanism meant to make orders reliable.
 *   `revert`         reverts to what was current before. Same ambience, and
 *                    the same way round: a retry can undo an operator's later,
 *                    deliberate change.
 *   `profile_save`   `profile_save.c` writes "what the machine is running"
 *                    into a profile, so a retry a minute later files something
 *                    else under the same name.
 *
 * **`wifi_connect` and `wifi_disconnect` are deliberately NOT in that list**,
 * and they are the ones worth arguing about. Retrying either looks dangerous
 * -- the operator may have moved to another network since. That is staleness,
 * and an order's freshness bounds it; this table answers the narrower
 * question, which is whether running a still-valid order twice does what
 * running it once did. `wifi_connect(network)` asks for an end state and
 * reaching it twice reaches it once. Conflating the two questions here would
 * make the table a second, worse expiry.
 */
static const ncfg_order_class_t order_table[NCFG_PROTO_REQ_COUNT] = {
	/* Observational. They change nothing, so running them again changes
	 * nothing again. */
	[NCFG_PROTO_REQ_HELLO] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_STATUS] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_PLAN] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_SHOW] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_EXPLAIN] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_MONITOR] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_CONFIG_LIST] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_SECRET_LIST] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_PROFILE_LIST] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_PROBE_LIST] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_HOOK_LIST] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_MODEM_LIST] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_RADIOS] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_WIFI_STATUS] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_AP_STATIONS] = NCFG_ORDER_IDEMPOTENT,

	/* Writes whose argument is the end state. The file holds that text, the
	 * secret holds that value, the block is present or it is not -- however
	 * many times the order arrives. `config_delete` and `wifi_forget` are
	 * idempotent in the direction people find surprising: deleting twice
	 * leaves it deleted, which is the same result as deleting once. */
	[NCFG_PROTO_REQ_CONFIG_PUT] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_CONFIG_DELETE] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_SECRET_PUT] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_SECRET_DELETE] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_PROBE_PUT] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_WIFI_ADD] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_WIFI_FORGET] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_PROFILE_SET] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_RADIO_SET] = NCFG_ORDER_IDEMPOTENT,

	/* The two that make the machine match what is already written down.
	 * `apply` is the declarative case at its purest -- it is convergence, so
	 * converging twice converges -- and `reload` re-reads a directory that
	 * says the same thing when read again. */
	[NCFG_PROTO_REQ_APPLY] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_RELOAD] = NCFG_ORDER_IDEMPOTENT,

	/* End states on a radio. See the header comment for why these are here
	 * and not below: what makes a late one dangerous is its age, not its
	 * repetition, and age is the freshness bound's question. */
	[NCFG_PROTO_REQ_WIFI_CONNECT] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_WIFI_DISCONNECT] = NCFG_ORDER_IDEMPOTENT,
	[NCFG_PROTO_REQ_WIFI_SCAN] = NCFG_ORDER_IDEMPOTENT,

	/* Ambient, and therefore at most once. Written out rather than left to
	 * the zero default: the default is what catches a verb somebody FORGOT,
	 * and these three were decided rather than forgotten. A reader should be
	 * able to see the judgement, not infer it from an absence. */
	[NCFG_PROTO_REQ_CONFIRM] = NCFG_ORDER_AT_MOST_ONCE,
	[NCFG_PROTO_REQ_REVERT] = NCFG_ORDER_AT_MOST_ONCE,
	[NCFG_PROTO_REQ_PROFILE_SAVE] = NCFG_ORDER_AT_MOST_ONCE
};

ncfg_order_class_t ncfg_order_class_of(ncfg_proto_request_kind_t kind)
{
	if ((int)kind < 0 || (int)kind >= (int)NCFG_PROTO_REQ_COUNT) {
		/* A kind outside the enum is not a request this build knows, and the
		 * direction that refuses to retry is the one to take -- the same
		 * reasoning `ncfg_tier_of` gives for answering `admin`. */
		return NCFG_ORDER_AT_MOST_ONCE;
	}
	return order_table[kind];
}
