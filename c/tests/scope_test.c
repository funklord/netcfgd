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
 *     * **`advertise.prefix` and `config` differ**, which is the pair a
 *       local/network boolean could not express and the reason scopes exist
 *       at all;
 *     * **a program's path never travels**, which is the brief's rule rather
 *       than a preference -- a document that can carry shell is remote code
 *       execution with extra steps;
 *     * **an exception covers what is under it**, so a sub-block settles its
 *       keys in one row and a key nobody named takes the block's answer
 *       rather than inventing one;
 *     * **an alias is resolved, not registered**, so two spellings of one
 *       field cannot acquire two numbers.
 *
 * WHAT THIS FILE CANNOT CHECK, AND WHAT DOES
 *   That a registered path names a key the language actually has. Nothing in
 *   C connects these strings to `compile/lower_*.c`, and the first version of
 *   the registry carried six rows that were not keys -- `tool/registry_gate.py`
 *   reads the lowering's own `strcmp` chains and is what catches that class.
 *   project.md 10.326.
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
 * **The pair the whole design turns on**, with the keys read rather than
 * remembered. A prefix this link ANNOUNCES is a fact about the segment; the
 * addressing this machine takes within it is `config`, and a table that gave
 * them one answer would be the boolean scopes replaced.
 */
static void a_subnet_and_an_address_are_different_scopes(void)
{
	check(scope_in("interface", "advertise.prefix") == NCFG_SCOPE_GROUP,
	    "a prefix a link announces is the segment's, not this machine's");
	check(scope_in("interface", "config") == NCFG_SCOPE_HOST,
	    "while the addressing within it is this machine's, and replicated");
	check(scope_in("interface", "advertise.prefix") != scope_in("interface", "config"),
	    "so the two do not collapse into one answer");
}

/* Programs, paths and hardware never travel, whatever block they sit in. */
static void paths_and_hardware_stay_on_the_machine(void)
{
	check(scope_in("interface", "mac") == NCFG_SCOPE_HOST_PRIVATE, "a MAC stays");
	check(scope_in("interface", "probe.command") == NCFG_SCOPE_HOST_PRIVATE,
	    "a probe's command stays");
	check(scope_in("interface", "probe.args") == NCFG_SCOPE_HOST_PRIVATE,
	    "and its argument vector with it");
	/* And the one exception that points downward out of an estate-wide block:
	 * a network's hooks are paths on whoever runs them. */
	check(scope_in("network", "hooks") == NCFG_SCOPE_HOST_PRIVATE,
	    "and a network's hooks stay, although the block around them travels");
	check(scope_in("network", "ssid") == NCFG_SCOPE_ESTATE,
	    "while the network itself does travel, so the exception is not the rule");
	/* An access point's radio is this machine's; what it offers is not. */
	check(scope_in("access_point", "device") == NCFG_SCOPE_HOST_PRIVATE,
	    "which radio offers a network is this machine's business");
	check(scope_in("access_point", "ssid") == NCFG_SCOPE_ESTATE,
	    "while what it offers is the estate's");
}

/*
 * **An exception covers what is under it.** `interface.kind` is one row and
 * settles thirteen link types; a fixture asserting only the row would pass
 * against a lookup that had no inheritance at all.
 */
static void a_sub_block_settles_what_is_under_it(void)
{
	check(scope_in("interface", "kind") == NCFG_SCOPE_HOST_PRIVATE,
	    "an interface's link type is this machine's topology");
	check(scope_in("interface", "kind.bridge.members") == NCFG_SCOPE_HOST_PRIVATE,
	    "and so is every key under it, without a row of its own");
	check(scope_in("interface", "kind.wireguard.peer.public_key") == NCFG_SCOPE_HOST_PRIVATE,
	    "however deep it goes");
	/* The other direction: inheriting must not reach past a nearer answer. */
	check(scope_in("interface", "advertise.dns") == NCFG_SCOPE_ESTATE,
	    "a key's own row wins over the sub-block it sits in");
	check(scope_in("interface", "advertise.prefix") == NCFG_SCOPE_GROUP,
	    "and two keys in one sub-block may differ");
	/* And an unclassified sub-block takes the block, not an invention. */
	check(scope_in("interface", "probe.timeout") == NCFG_SCOPE_HOST,
	    "a key nobody named takes its block's answer");
}

/*
 * **An alias is one field with two spellings**, so it must resolve rather than
 * be registered: a second number for `lookup` would make two meanings of one.
 */
static void a_second_spelling_is_the_same_key(void)
{
	ncfg_block_t rule;
	ncfg_block_t global;

	check(ncfg_block_from_name("rule", &rule) && ncfg_block_from_name("global", &global),
	    "the rule and global blocks resolve");
	check(ncfg_kind_of(rule, "lookup") == ncfg_kind_of(rule, "table"),
	    "`lookup` and `table` are one field, so they carry one number");
	check(ncfg_kind_of(rule, "table") != NCFG_KIND_NONE, "and it is a real one");
	check(ncfg_kind_of(global, "dns.servers") == ncfg_kind_of(global, "dns"),
	    "a dns key written inside the sub-block is the same key");
	check(scope_in("global", "dns.search") == NCFG_SCOPE_ESTATE,
	    "and it inherits the scope of the spelling it resolves to");
	check(strcmp(ncfg_key_canonical(rule, "lookup"), "table") == 0,
	    "which the caller can ask about directly");
	check(strcmp(ncfg_key_canonical(rule, "from"), "from") == 0,
	    "a key that is already canonical is returned unchanged");
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
	} PRIVATE[] = { { "interface", "mac" }, { "interface", "probe.command" },
		{ "interface", "probe.args" }, { "interface", "advertise.backend" },
		{ "interface", "kind" }, { "interface", "kind.bridge.members" },
		{ "interface", "master" }, { "interface", "ethtool" },
		{ "interface", "ethtool.gro" }, { "interface", "qdisc" },
		{ "interface", "qdisc.bandwidth" }, { "network", "hooks" },
		{ "device", "mac" }, { "device", "mtu" }, { "bluetooth", "address" },
		{ "global", "hostname" }, { "global", "control.admin" },
		{ "global", "remote.agent" }, { "access_point", "device" } };
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
		{ "global", "connectivity.requires" }, { "global", "connectivity.ignore" },
		{ "interface", "config" }, { "interface", "routes" }, { "interface", "mtu" },
		{ "interface", "vlans" }, { "interface", "nat" }, { "interface", "dns" },
		{ "interface", "advertise.prefix" }, { "interface", "advertise.dns" },
		{ "interface", "probe.timeout" }, { "interface", "dot1x.identity" },
		{ "network", "ssid" }, { "network", "config" }, { "network", "wifi.psk" },
		{ "network", "wifi.roam.signal" }, { "network", "dns.dns" },
		{ "access_point", "ssid" }, { "access_point", "channel" },
		{ "access_point", "wifi.psk" }, { "access_point", "access_control.allow" },
		{ "rule", "from" }, { "rule", "to" }, { "rule", "table" }, { "rule", "action" },
		{ "linkset", "members" },
		/* The same key twice, which is not a collision. */
		{ "interface", "mtu" } };
	size_t at;
	size_t other;
	int    collisions = 0;
	int    numbered = 0;

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
		numbered++;
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
	/* **The liveness half.** Every row here is registered, so a run that
	 * skipped most of them would be comparing nothing and saying so in the
	 * same words. This caught exactly that, when the list still named keys a
	 * rewrite had moved. */
	check(numbered == (int)(sizeof(REGISTERED) / sizeof(REGISTERED[0])),
	    "every row in the list above has a number, so the comparison ran");
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
	check(ncfg_kind_is_taken(ncfg_kind_of(interface, "config")),
	    "and a number in use reads as taken");
	check(!ncfg_kind_is_taken(0x00FFFFFFu), "while a free one does not");
}

/*
 * **A deliberate absence, pinned.** These three are estate-wide by scope and
 * carry no number, because one spelling accepts either a stored secret or a
 * PATH -- and a path is an instruction to open a file as root. A scope is a
 * property of a key and cannot say "in one of its two forms", so the registry
 * declines to carry them at all.
 *
 * Without this case, completing the registry looks like tidying: the keys are
 * right there in the block, everything around them has a number, and nothing
 * would say why they do not.
 */
static void the_three_cert_keys_are_unregistered_on_purpose(void)
{
	static const char *const CERTS[] = { "dot1x.ca_cert", "dot1x.client_cert",
		"dot1x.private_key" };
	ncfg_block_t interface;
	size_t       at;
	int          numbered = 0;
	int          narrowed = 0;

	if (!ncfg_block_from_name("interface", &interface)) {
		check(0, "the interface block resolves");
		return;
	}
	for (at = 0u; at < sizeof(CERTS) / sizeof(CERTS[0]); at++) {
		if (ncfg_kind_of(interface, CERTS[at]) != NCFG_KIND_NONE) {
			printf("       %s has a number: a path form can now travel\n", CERTS[at]);
			numbered++;
		}
		if (ncfg_scope_of(interface, CERTS[at]) == NCFG_SCOPE_HOST_PRIVATE) {
			narrowed++;
		}
	}
	check(numbered == 0, "a key that accepts a root-readable path carries no wire number");
	check(narrowed == 0,
	    "and the reason is the value's two forms, not the key being host-private");
	/* The neighbour that does travel, so the absence is about these three
	 * rather than about `dot1x` being unreachable. */
	check(ncfg_kind_of(interface, "dot1x.identity") != NCFG_KIND_NONE,
	    "while the rest of the block is registered, so this is not a gap in reach");
}

int main(void)
{
	every_block_has_the_default_the_rule_gives_it();
	every_block_is_classified_exactly_once();
	a_subnet_and_an_address_are_different_scopes();
	paths_and_hardware_stay_on_the_machine();
	the_unknown_direction_is_the_narrow_one();
	a_sub_block_settles_what_is_under_it();
	a_second_spelling_is_the_same_key();
	nothing_host_private_has_a_kind();
	the_three_cert_keys_are_unregistered_on_purpose();
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
