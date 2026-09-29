/*
 * scope.c -- the block defaults and the keys that depart from them.
 *
 * `scope.h` carries why there are scopes and why this is a rule with
 * exceptions rather than a table of every key. This carries the judgements,
 * which is the part to disagree with in specifics.
 *
 * **In `compile/` because a key is the language's, not the document's.** The
 * model holds what a configuration means; this holds how far one of its
 * spellings travels, which is a fact about the file somebody writes.
 */
#include "ncfg/scope.h"

#include <string.h>

static const char *const BLOCK_NAMES[NCFG_BLOCK_COUNT] = { "global", "device", "interface",
	"network", "access_point", "bluetooth", "rule", "linkset" };

const char *ncfg_block_name(ncfg_block_t block)
{
	if ((int)block < 0 || (int)block >= (int)NCFG_BLOCK_COUNT) {
		return "";
	}
	return BLOCK_NAMES[block];
}

int ncfg_block_from_name(const char *name, ncfg_block_t *out)
{
	int at;

	if (!name || !out) {
		return 0;
	}
	for (at = 0; at < (int)NCFG_BLOCK_COUNT; at++) {
		if (strcmp(name, BLOCK_NAMES[at]) == 0) {
			*out = (ncfg_block_t)at;
			return 1;
		}
	}
	return 0;
}

/*
 * THE BLOCK DEFAULTS
 *
 *   global        host-private. `control`, `remote`, `networking`, `hostname`,
 *                 `profile` and `confirm` are this machine's policy about
 *                 itself, and 0128 already settles who may ask it what.
 *   device        host-private, entire. A NIC's name, its MAC, its offloads:
 *                 nothing here is true of another box, and no exception is
 *                 plausible.
 *   interface     host. It describes THIS machine's participation, which the
 *                 estate should see -- and it carries most of the exceptions
 *                 in both directions, being the only genuinely mixed block.
 *   network       estate. An `ssid`, its security, its EAP identity: every
 *                 machine joining holds the same value and is correct.
 *   access_point  estate. Describing a network being offered is describing the
 *                 network.
 *   bluetooth     host-private. A paired device belongs to the machine it was
 *                 paired with, and pairing is not estate business.
 *   rule          group. Routing policy is a property of a zone rather than of
 *                 one machine, and rarely of every machine at once.
 *   linkset       host. Which of this machine's links are bonded is about this
 *                 machine, and an estate managing it wants to see it.
 */
static const ncfg_scope_t BLOCK_DEFAULT[NCFG_BLOCK_COUNT] = {
	[NCFG_BLOCK_GLOBAL] = NCFG_SCOPE_HOST_PRIVATE,
	[NCFG_BLOCK_DEVICE] = NCFG_SCOPE_HOST_PRIVATE,
	[NCFG_BLOCK_INTERFACE] = NCFG_SCOPE_HOST,
	[NCFG_BLOCK_NETWORK] = NCFG_SCOPE_ESTATE,
	[NCFG_BLOCK_ACCESS_POINT] = NCFG_SCOPE_ESTATE,
	[NCFG_BLOCK_BLUETOOTH] = NCFG_SCOPE_HOST_PRIVATE,
	[NCFG_BLOCK_RULE] = NCFG_SCOPE_GROUP,
	[NCFG_BLOCK_LINKSET] = NCFG_SCOPE_HOST
};

ncfg_scope_t ncfg_block_default_scope(ncfg_block_t block)
{
	if ((int)block < 0 || (int)block >= (int)NCFG_BLOCK_COUNT) {
		return NCFG_SCOPE_HOST_PRIVATE;
	}
	return BLOCK_DEFAULT[block];
}

/*
 * THE EXCEPTIONS, WHICH ARE THE DESIGN
 *
 * Read as: within this block, this key departs from the default. Everything
 * not named here takes its block's answer, which is what keeps the list short
 * enough to argue with.
 */
static const struct {
	ncfg_block_t block;
	const char  *key;
	ncfg_scope_t scope;
} EXCEPTIONS[] = {
	/*
	 * `global`'s resolver and reachability answers are the estate's. What
	 * counts as being online, and which resolvers to ask, are the same
	 * question for every machine in a deployment and a different one per
	 * deployment -- which is the test in `scope.h` exactly.
	 */
	{ NCFG_BLOCK_GLOBAL, "dns", NCFG_SCOPE_ESTATE },
	{ NCFG_BLOCK_GLOBAL, "dns_mode", NCFG_SCOPE_ESTATE },
	{ NCFG_BLOCK_GLOBAL, "dns_search", NCFG_SCOPE_ESTATE },
	{ NCFG_BLOCK_GLOBAL, "dns_domains", NCFG_SCOPE_ESTATE },
	{ NCFG_BLOCK_GLOBAL, "connectivity", NCFG_SCOPE_ESTATE },

	/*
	 * **`interface`'s hardware and path keys go the other way**, down to
	 * host-private from the block's host.
	 *
	 * `mac`, `kind` and `master` name this machine's own hardware and
	 * topology. `backend`, `command`, `args` and `config` name paths on this
	 * filesystem, and those are host-private **by the brief's rule rather
	 * than by preference**: a non-local document may reference only paths
	 * that already exist on the device, because "a document that can carry
	 * shell is remote code execution with extra steps".
	 */
	{ NCFG_BLOCK_INTERFACE, "mac", NCFG_SCOPE_HOST_PRIVATE },
	{ NCFG_BLOCK_INTERFACE, "kind", NCFG_SCOPE_HOST_PRIVATE },
	{ NCFG_BLOCK_INTERFACE, "master", NCFG_SCOPE_HOST_PRIVATE },
	{ NCFG_BLOCK_INTERFACE, "backend", NCFG_SCOPE_HOST_PRIVATE },
	{ NCFG_BLOCK_INTERFACE, "command", NCFG_SCOPE_HOST_PRIVATE },
	{ NCFG_BLOCK_INTERFACE, "args", NCFG_SCOPE_HOST_PRIVATE },
	{ NCFG_BLOCK_INTERFACE, "config", NCFG_SCOPE_HOST_PRIVATE },
	{ NCFG_BLOCK_INTERFACE, "ethtool", NCFG_SCOPE_HOST_PRIVATE },
	{ NCFG_BLOCK_INTERFACE, "qdisc", NCFG_SCOPE_HOST_PRIVATE },

	/*
	 * And its network-describing keys go up.
	 *
	 * **`prefix` and `prefixes` are the pair 10.322 turned on.** A subnet is
	 * a fact about a VLAN or a zone that every machine in it shares, while
	 * `address` -- which stays at the block's `host` -- is which address this
	 * machine holds within it. Those two being different scopes is what a
	 * local/network boolean could not express, and the derivation between
	 * them is the link rather than the problem.
	 */
	{ NCFG_BLOCK_INTERFACE, "prefix", NCFG_SCOPE_GROUP },
	{ NCFG_BLOCK_INTERFACE, "prefixes", NCFG_SCOPE_GROUP },
	{ NCFG_BLOCK_INTERFACE, "vlans", NCFG_SCOPE_GROUP },
	{ NCFG_BLOCK_INTERFACE, "nat", NCFG_SCOPE_GROUP },
	{ NCFG_BLOCK_INTERFACE, "guard", NCFG_SCOPE_GROUP },
	{ NCFG_BLOCK_INTERFACE, "advertise", NCFG_SCOPE_GROUP },
	{ NCFG_BLOCK_INTERFACE, "radvd", NCFG_SCOPE_GROUP },
	{ NCFG_BLOCK_INTERFACE, "odhcpd", NCFG_SCOPE_GROUP },
	{ NCFG_BLOCK_INTERFACE, "lifetime", NCFG_SCOPE_GROUP },
	{ NCFG_BLOCK_INTERFACE, "preference", NCFG_SCOPE_GROUP },
	{ NCFG_BLOCK_INTERFACE, "dns", NCFG_SCOPE_ESTATE },
	{ NCFG_BLOCK_INTERFACE, "dns_mode", NCFG_SCOPE_ESTATE },
	{ NCFG_BLOCK_INTERFACE, "dns_search", NCFG_SCOPE_ESTATE },
	{ NCFG_BLOCK_INTERFACE, "dns_domains", NCFG_SCOPE_ESTATE },

	/*
	 * A `network`'s hooks are paths on the machine that runs them, so they
	 * cannot travel even though the block around them does. Same rule as the
	 * interface path keys, and it is the one exception that goes downward out
	 * of an estate-wide block.
	 */
	{ NCFG_BLOCK_NETWORK, "hook", NCFG_SCOPE_HOST_PRIVATE },
	{ NCFG_BLOCK_NETWORK, "hooks", NCFG_SCOPE_HOST_PRIVATE }
};

#define EXCEPTION_COUNT (sizeof(EXCEPTIONS) / sizeof(EXCEPTIONS[0]))

ncfg_scope_t ncfg_scope_of(ncfg_block_t block, const char *key)
{
	size_t at;

	if ((int)block < 0 || (int)block >= (int)NCFG_BLOCK_COUNT) {
		/* Not a block this build knows, so nothing about it may be
		 * published. The narrow direction, as `scope.h` argues. */
		return NCFG_SCOPE_HOST_PRIVATE;
	}
	if (!key) {
		return BLOCK_DEFAULT[block];
	}
	for (at = 0u; at < EXCEPTION_COUNT; at++) {
		if (EXCEPTIONS[at].block == block && strcmp(EXCEPTIONS[at].key, key) == 0) {
			return EXCEPTIONS[at].scope;
		}
	}
	return BLOCK_DEFAULT[block];
}
