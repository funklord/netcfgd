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

/* ------------------------------------------------------------------------ *
 * The kind registry
 * ------------------------------------------------------------------------ */

/*
 * **The cross-check between the two tables, which is the one that matters.**
 * A number on a host-private key means something that must never leave the
 * machine has been given a way to travel. Neither table can catch that alone.
 */
static void nothing_host_private_has_a_kind(void)
{
	static const struct {
		const char *block;
		const char *key;
	} PRIVATE[] = { { "interface", "mac" }, { "interface", "command" },
		{ "interface", "args" }, { "interface", "config" },
		{ "interface", "backend" }, { "interface", "kind" },
		{ "interface", "master" }, { "interface", "ethtool" },
		{ "interface", "qdisc" }, { "network", "hooks" }, { "device", "mac" },
		{ "bluetooth", "address" } };
	size_t at;
	int    leaked = 0;

	for (at = 0u; at < sizeof(PRIVATE) / sizeof(PRIVATE[0]); at++) {
		ncfg_block_t block;

		if (!ncfg_block_from_name(PRIVATE[at].block, &block)) {
			continue;
		}
		if (ncfg_scope_of(block, PRIVATE[at].key) != NCFG_SCOPE_HOST_PRIVATE) {
			printf("       %s.%s is not host-private any more\n", PRIVATE[at].block,
			    PRIVATE[at].key);
			leaked++;
		} else if (ncfg_kind_of(block, PRIVATE[at].key) != NCFG_KIND_NONE) {
			printf("       %s.%s is host-private and has a wire number\n",
			    PRIVATE[at].block, PRIVATE[at].key);
			leaked++;
		}
	}
	check(leaked == 0, "no host-private key carries a number it could travel under");
}

/* A number used twice gives two keys one meaning, and every signature still
 * verifies. Checked over the registry by asking it about itself, which is the
 * one question a table may be asked about itself honestly: not what a number
 * means, but whether it is unique. */
static void no_number_is_used_twice(void)
{
	static const struct {
		const char *block;
		const char *key;
	} REGISTERED[] = { { "global", "dns" }, { "global", "dns_mode" },
		{ "global", "dns_search" }, { "global", "dns_domains" },
		{ "global", "connectivity" }, { "interface", "address" },
		{ "interface", "prefix" }, { "interface", "prefixes" },
		{ "interface", "routes" }, { "interface", "mtu" }, { "interface", "vlans" },
		{ "interface", "nat" }, { "interface", "dns" }, { "interface", "mtu" } };
	size_t at;
	size_t other;
	int    collisions = 0;

	for (at = 0u; at < sizeof(REGISTERED) / sizeof(REGISTERED[0]); at++) {
		ncfg_block_t a;
		unsigned     ka;

		if (!ncfg_block_from_name(REGISTERED[at].block, &a)) {
			continue;
		}
		ka = ncfg_kind_of(a, REGISTERED[at].key);
		if (ka == NCFG_KIND_NONE) {
			continue;
		}
		for (other = at + 1u; other < sizeof(REGISTERED) / sizeof(REGISTERED[0]);
		    other++) {
			ncfg_block_t b;

			if (!ncfg_block_from_name(REGISTERED[other].block, &b)) {
				continue;
			}
			if (ncfg_kind_of(b, REGISTERED[other].key) != ka) {
				continue;
			}
			/* The same key twice in the list above is not a collision. */
			if (a == b && strcmp(REGISTERED[at].key, REGISTERED[other].key) == 0) {
				continue;
			}
			printf("       %s.%s and %s.%s share a number\n", REGISTERED[at].block,
			    REGISTERED[at].key, REGISTERED[other].block, REGISTERED[other].key);
			collisions++;
		}
	}
	check(collisions == 0, "no two keys carry the same wire number");
}

static void zero_is_reserved_and_an_unknown_key_gets_it(void)
{
	ncfg_block_t interface;

	check(ncfg_block_from_name("interface", &interface), "the interface block resolves");
	check(ncfg_kind_of(interface, "a_key_that_does_not_exist") == NCFG_KIND_NONE,
	    "an unregistered key has no number, so it cannot be written wrongly");
	check(ncfg_kind_is_taken(NCFG_KIND_NONE),
	    "zero is permanently taken, so nothing allocates it");
	check(ncfg_kind_is_taken(ncfg_kind_of(interface, "address")),
	    "and a number in use reads as taken");
	check(!ncfg_kind_is_taken(0x00FFFFFFu), "while a free one does not");
}

int main(void)
{
	every_block_has_the_default_the_rule_gives_it();
	every_block_is_classified_exactly_once();
	a_subnet_and_an_address_are_different_scopes();
	paths_and_hardware_stay_on_the_machine();
	the_unknown_direction_is_the_narrow_one();
	nothing_host_private_has_a_kind();
	no_number_is_used_twice();
	zero_is_reserved_and_an_unknown_key_gets_it();

	printf("scope_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("scope_test: all checks passed\n");
	} else {
		printf("scope_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
