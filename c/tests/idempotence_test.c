/*
 * idempotence_test.c -- every verb's order class, and the two properties the
 * table cannot supply itself.
 *
 * WHY THE LIST BELOW IS WRITTEN OUT BY HAND
 *   **A table compared against itself proves nothing.** That sentence is
 *   `authorize_test.c`'s, about the tier table, and it applies here for the
 *   same reason: reading `order_table` back and checking it equals
 *   `order_table` is one witness twice. So this list is spelled out from the
 *   criterion in `daemon.h` -- does the order fully determine the effect it
 *   asks for -- and disagreeing with `idempotence.c` is the point of it.
 *
 *   The Rust would get exhaustiveness from a match arm per kind and a build
 *   failure when one is missed. C cannot, so the exhaustiveness is an
 *   assertion: every kind from 0 to `NCFG_PROTO_REQ_COUNT` must appear here
 *   exactly once, and a verb added to the protocol and forgotten by the table
 *   fails here rather than being quietly classified by whoever chose the
 *   enum's first value.
 *
 * AND THE PROPERTY THAT SURVIVES THIS TEST BEING DELETED
 *   The last case pins `NCFG_ORDER_AT_MOST_ONCE == 0`. That is not a spelling
 *   detail: it is what makes a FORGOTTEN verb stall instead of being leased,
 *   so the table's silent default and the assertion above point the same way.
 *   `NCFG_TIER_OBSERVE` is 0 and points the other way, which is why this is
 *   worth a check of its own rather than a comment.
 */
#include "ncfg/daemon.h"
#include "ncfg/proto.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check(int condition, const char *what)
{
	checks++;
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/*
 * Every request kind with the class the criterion gives it, written from the
 * criterion rather than read from the table under test.
 */
static const struct {
	ncfg_proto_request_kind_t kind;
	ncfg_order_class_t        class_;
	const char               *why;
} expected[] = {
	/* Observational: they change nothing. */
	{ NCFG_PROTO_REQ_HELLO, NCFG_ORDER_IDEMPOTENT, "reads" },
	{ NCFG_PROTO_REQ_STATUS, NCFG_ORDER_IDEMPOTENT, "reads" },
	{ NCFG_PROTO_REQ_PLAN, NCFG_ORDER_IDEMPOTENT, "reads" },
	{ NCFG_PROTO_REQ_SHOW, NCFG_ORDER_IDEMPOTENT, "reads" },
	{ NCFG_PROTO_REQ_EXPLAIN, NCFG_ORDER_IDEMPOTENT, "reads" },
	{ NCFG_PROTO_REQ_MONITOR, NCFG_ORDER_IDEMPOTENT, "reads" },
	{ NCFG_PROTO_REQ_CONFIG_LIST, NCFG_ORDER_IDEMPOTENT, "reads" },
	{ NCFG_PROTO_REQ_SECRET_LIST, NCFG_ORDER_IDEMPOTENT, "reads" },
	{ NCFG_PROTO_REQ_PROFILE_LIST, NCFG_ORDER_IDEMPOTENT, "reads" },
	{ NCFG_PROTO_REQ_PROBE_LIST, NCFG_ORDER_IDEMPOTENT, "reads" },
	{ NCFG_PROTO_REQ_HOOK_LIST, NCFG_ORDER_IDEMPOTENT, "reads" },
	{ NCFG_PROTO_REQ_MODEM_LIST, NCFG_ORDER_IDEMPOTENT, "reads" },
	{ NCFG_PROTO_REQ_RADIOS, NCFG_ORDER_IDEMPOTENT, "reads" },
	{ NCFG_PROTO_REQ_WIFI_STATUS, NCFG_ORDER_IDEMPOTENT, "reads" },
	{ NCFG_PROTO_REQ_AP_STATIONS, NCFG_ORDER_IDEMPOTENT, "reads" },

	/* The argument IS the end state. */
	{ NCFG_PROTO_REQ_CONFIG_PUT, NCFG_ORDER_IDEMPOTENT, "the file holds that text" },
	{ NCFG_PROTO_REQ_CONFIG_DELETE, NCFG_ORDER_IDEMPOTENT, "deleted twice is deleted" },
	{ NCFG_PROTO_REQ_SECRET_PUT, NCFG_ORDER_IDEMPOTENT, "the secret holds that value" },
	{ NCFG_PROTO_REQ_SECRET_DELETE, NCFG_ORDER_IDEMPOTENT, "deleted twice is deleted" },
	{ NCFG_PROTO_REQ_PROBE_PUT, NCFG_ORDER_IDEMPOTENT, "the probe holds that text" },
	{ NCFG_PROTO_REQ_WIFI_ADD, NCFG_ORDER_IDEMPOTENT, "the block is present" },
	{ NCFG_PROTO_REQ_WIFI_FORGET, NCFG_ORDER_IDEMPOTENT, "the block is absent" },
	{ NCFG_PROTO_REQ_PROFILE_SET, NCFG_ORDER_IDEMPOTENT, "that profile is selected" },
	{ NCFG_PROTO_REQ_RADIO_SET, NCFG_ORDER_IDEMPOTENT, "the radio is in that state" },
	{ NCFG_PROTO_REQ_APPLY, NCFG_ORDER_IDEMPOTENT, "convergence converges" },
	{ NCFG_PROTO_REQ_RELOAD, NCFG_ORDER_IDEMPOTENT, "re-reading reads the same" },
	{ NCFG_PROTO_REQ_WIFI_CONNECT, NCFG_ORDER_IDEMPOTENT, "associated to that network" },
	{ NCFG_PROTO_REQ_WIFI_DISCONNECT, NCFG_ORDER_IDEMPOTENT, "not associated" },
	{ NCFG_PROTO_REQ_WIFI_SCAN, NCFG_ORDER_IDEMPOTENT, "leaves nothing behind" },

	/* Ambient: the effect depends on the moment, not on the order. */
	{ NCFG_PROTO_REQ_CONFIRM, NCFG_ORDER_AT_MOST_ONCE, "confirms whichever window is open" },
	{ NCFG_PROTO_REQ_REVERT, NCFG_ORDER_AT_MOST_ONCE, "undoes whatever is current" },
	{ NCFG_PROTO_REQ_PROFILE_SAVE, NCFG_ORDER_AT_MOST_ONCE, "files what is running now" }
};

#define EXPECTED_COUNT (sizeof(expected) / sizeof(expected[0]))

static void every_verb_has_the_class_the_criterion_gives_it(void)
{
	size_t at;
	int    wrong = 0;

	for (at = 0u; at < EXPECTED_COUNT; at++) {
		if (ncfg_order_class_of(expected[at].kind) != expected[at].class_) {
			printf("       %s: expected %s (%s)\n",
			    ncfg_proto_request_name(expected[at].kind),
			    expected[at].class_ == NCFG_ORDER_IDEMPOTENT ? "idempotent"
			                                                 : "at-most-once",
			    expected[at].why);
			wrong++;
		}
	}
	check(wrong == 0, "every verb carries the class the criterion gives it");
}

/*
 * **The exhaustiveness, which is what C has instead of a match.** Counted over
 * the enum rather than over the list, so a kind the list forgot is a gap here
 * rather than a shorter loop nobody notices.
 */
static void every_kind_is_classified_exactly_once(void)
{
	static int seen[NCFG_PROTO_REQ_COUNT];
	size_t     at;
	int        missing = 0;
	int        twice = 0;
	int        kind;

	memset(seen, 0, sizeof(seen));
	for (at = 0u; at < EXPECTED_COUNT; at++) {
		int which = (int)expected[at].kind;

		if (which >= 0 && which < (int)NCFG_PROTO_REQ_COUNT) {
			seen[which]++;
		}
	}
	for (kind = 0; kind < (int)NCFG_PROTO_REQ_COUNT; kind++) {
		if (seen[kind] == 0) {
			printf("       %s is in no row: a verb was added and not classified\n",
			    ncfg_proto_request_name((ncfg_proto_request_kind_t)kind));
			missing++;
		} else if (seen[kind] > 1) {
			twice++;
		}
	}
	check(missing == 0, "every request kind in the protocol is classified");
	check(twice == 0, "and none is classified twice");
}

/*
 * The property that outlives this file: a verb nobody classified must stall,
 * not be leased. `NCFG_TIER_OBSERVE` is 0 and defaults the other way, which is
 * what makes this worth pinning rather than trusting.
 */
static void the_unclassified_direction_is_the_refusing_one(void)
{
	check(NCFG_ORDER_AT_MOST_ONCE == 0,
	    "the stalling class is zero, so a forgotten verb is not leased");
	check(ncfg_order_class_of((ncfg_proto_request_kind_t)NCFG_PROTO_REQ_COUNT) ==
	        NCFG_ORDER_AT_MOST_ONCE,
	    "and a kind outside the enum refuses to be retried");
	check(ncfg_order_class_of((ncfg_proto_request_kind_t)-1) == NCFG_ORDER_AT_MOST_ONCE,
	    "in both directions out of range");
}

int main(void)
{
	every_verb_has_the_class_the_criterion_gives_it();
	every_kind_is_classified_exactly_once();
	the_unclassified_direction_is_the_refusing_one();

	printf("idempotence_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("idempotence_test: all checks passed\n");
	} else {
		printf("idempotence_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
