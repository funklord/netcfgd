/*
 * scope_test.c -- how far a key travels, and the two properties the table
 * cannot state about itself.
 *
 * WHAT IS WORTH CHECKING
 *   Not that a lookup returns something. What separates a right table from a
 *   wrong one:
 *
 *     * **every block has a default**, because an unlisted one would take the
 *       enum's first value silently and C has no match arm to refuse it;
 *     * **the narrow direction is the default**, so a key nobody classified is
 *       not published. Widening a scope offers configuration its author never
 *       offered anybody; narrowing one only fails to share;
 *     * **`prefix` and `address` differ**, which is the pair a local/network
 *       boolean could not express and the reason scopes exist at all;
 *     * **paths never travel**, which is the brief's rule rather than a
 *       preference -- a document that can carry shell is remote code
 *       execution with extra steps.
 */
#include "ncfg/scope.h"

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
 * Every block, with the default the rule gives it, written out here rather
 * than read from the table under test -- a table compared against itself is
 * one witness twice.
 */
static const struct {
	const char  *block;
	ncfg_scope_t scope;
} EXPECTED[] = {
	{ "global", NCFG_SCOPE_HOST_PRIVATE },
	{ "device", NCFG_SCOPE_HOST_PRIVATE },
	{ "bluetooth", NCFG_SCOPE_HOST_PRIVATE },
	{ "interface", NCFG_SCOPE_HOST },
	{ "linkset", NCFG_SCOPE_HOST },
	{ "rule", NCFG_SCOPE_GROUP },
	{ "network", NCFG_SCOPE_ESTATE },
	{ "access_point", NCFG_SCOPE_ESTATE }
};

#define EXPECTED_COUNT (sizeof(EXPECTED) / sizeof(EXPECTED[0]))

static ncfg_scope_t scope_in(const char *block, const char *key)
{
	ncfg_block_t which;

	if (!ncfg_block_from_name(block, &which)) {
		return NCFG_SCOPE_COUNT; /* cannot happen for the names below */
	}
	return ncfg_scope_of(which, key);
}

static void every_block_has_the_default_the_rule_gives_it(void)
{
	size_t at;
	int    wrong = 0;

	for (at = 0u; at < EXPECTED_COUNT; at++) {
		if (scope_in(EXPECTED[at].block, NULL) != EXPECTED[at].scope) {
			printf("       %s: default is not what the rule gives it\n",
			    EXPECTED[at].block);
			wrong++;
		}
	}
	check(wrong == 0, "every block's default is the one the rule gives it");
}

/* The exhaustiveness C has instead of a match: counted over the enum, so a
 * block added and not classified is a gap here rather than a shorter loop. */
static void every_block_is_classified_exactly_once(void)
{
	static int seen[NCFG_BLOCK_COUNT];
	size_t     at;
	int        which;
	int        missing = 0;
	int        twice = 0;

	memset(seen, 0, sizeof(seen));
	for (at = 0u; at < EXPECTED_COUNT; at++) {
		ncfg_block_t block;

		if (ncfg_block_from_name(EXPECTED[at].block, &block)) {
			seen[block]++;
		}
	}
	for (which = 0; which < (int)NCFG_BLOCK_COUNT; which++) {
		if (seen[which] == 0) {
			printf("       %s is in no row: a block was added and not scoped\n",
			    ncfg_block_name((ncfg_block_t)which));
			missing++;
		} else if (seen[which] > 1) {
			twice++;
		}
	}
	check(missing == 0, "every block in the language has a scope");
	check(twice == 0, "and none has two");
}

/*
 * **The pair the whole design turns on.** A subnet is the zone's and an
 * address within it is this machine's, and a table that gave them one answer
 * would be the boolean scopes replaced.
 */
static void a_subnet_and_an_address_are_different_scopes(void)
{
	check(scope_in("interface", "prefix") == NCFG_SCOPE_GROUP,
	    "a subnet is the zone's, not this machine's");
	check(scope_in("interface", "address") == NCFG_SCOPE_HOST,
	    "while the address within it is this machine's, and replicated");
	check(scope_in("interface", "prefix") != scope_in("interface", "address"),
	    "so the two do not collapse into one answer");
}

/* Paths and hardware never travel, whatever block they sit in. */
static void paths_and_hardware_stay_on_the_machine(void)
{
	check(scope_in("interface", "mac") == NCFG_SCOPE_HOST_PRIVATE, "a MAC stays");
	check(scope_in("interface", "command") == NCFG_SCOPE_HOST_PRIVATE, "a command stays");
	check(scope_in("interface", "config") == NCFG_SCOPE_HOST_PRIVATE, "a config path stays");
	/* And the one exception that points downward out of an estate-wide block:
	 * a network's hooks are paths on whoever runs them. */
	check(scope_in("network", "hooks") == NCFG_SCOPE_HOST_PRIVATE,
	    "and a network's hooks stay, although the block around them travels");
	check(scope_in("network", "ssid") == NCFG_SCOPE_ESTATE,
	    "while the network itself does travel, so the exception is not the rule");
}

/*
 * The property that outlives this file: an unknown block, and an unclassified
 * key, must not publish anything.
 */
static void the_unknown_direction_is_the_narrow_one(void)
{
	ncfg_block_t unused;

	check(NCFG_SCOPE_HOST_PRIVATE == 0,
	    "the narrowest scope is zero, so an omission is not published");
	check(ncfg_scope_of((ncfg_block_t)NCFG_BLOCK_COUNT, "anything") ==
	        NCFG_SCOPE_HOST_PRIVATE,
	    "a block this build does not know publishes nothing");
	check(ncfg_scope_of((ncfg_block_t)-1, NULL) == NCFG_SCOPE_HOST_PRIVATE,
	    "in both directions out of range");
	check(!ncfg_block_from_name("not_a_block", &unused),
	    "and a name that is not a block is refused rather than guessed");
}

int main(void)
{
	every_block_has_the_default_the_rule_gives_it();
	every_block_is_classified_exactly_once();
	a_subnet_and_an_address_are_different_scopes();
	paths_and_hardware_stay_on_the_machine();
	the_unknown_direction_is_the_narrow_one();

	printf("scope_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("scope_test: all checks passed\n");
	} else {
		printf("scope_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
