/*
 * scope.c -- the block defaults, the keys that depart from them, and the wire
 * numbers the travelling ones are carried under.
 *
 * `scope.h` carries why there are scopes, why a key is identified by its PATH
 * rather than by its name, and the rules the kind registry is kept under. This
 * carries the judgements, which is the part to disagree with in specifics.
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
 *   global        host-private. `hostname`, `networking`, `profile`,
 *                 `confirm`, `control` and `remote` are this machine's policy
 *                 about itself, and 0128 already settles who may ask it what.
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
 * THE SPELLINGS THAT MEAN ONE THING
 *
 * The language accepts a second spelling in two places, and a record carries a
 * meaning rather than a spelling -- so an alias resolves to its canonical path
 * before either table is consulted, and does not get a number of its own.
 *
 * **The canonical spelling is the unambiguous one**: the `dns`/`dns_*` family,
 * at the shallowest nesting its block offers. Inside a `dns { }` block the
 * prefix is redundant and the language lets it be dropped; outside one it is
 * the whole name.
 */
static const struct {
	ncfg_block_t block;
	const char  *alias;
	const char  *canonical;
} ALIASES[] = {
	/* `global` and `interface` both offer the four dns keys at the top level
	 * and inside a `dns` block; the top-level spelling is canonical. */
	{ NCFG_BLOCK_GLOBAL, "dns.dns", "dns" },
	{ NCFG_BLOCK_GLOBAL, "dns.servers", "dns" },
	{ NCFG_BLOCK_GLOBAL, "dns.dns_search", "dns_search" },
	{ NCFG_BLOCK_GLOBAL, "dns.search", "dns_search" },
	{ NCFG_BLOCK_GLOBAL, "dns.dns_mode", "dns_mode" },
	{ NCFG_BLOCK_GLOBAL, "dns.mode", "dns_mode" },
	{ NCFG_BLOCK_GLOBAL, "dns.dns_domains", "dns_domains" },
	{ NCFG_BLOCK_GLOBAL, "dns.domains", "dns_domains" },
	{ NCFG_BLOCK_INTERFACE, "dns.dns", "dns" },
	{ NCFG_BLOCK_INTERFACE, "dns.servers", "dns" },
	{ NCFG_BLOCK_INTERFACE, "dns.dns_search", "dns_search" },
	{ NCFG_BLOCK_INTERFACE, "dns.search", "dns_search" },
	{ NCFG_BLOCK_INTERFACE, "dns.dns_mode", "dns_mode" },
	{ NCFG_BLOCK_INTERFACE, "dns.mode", "dns_mode" },
	{ NCFG_BLOCK_INTERFACE, "dns.dns_domains", "dns_domains" },
	{ NCFG_BLOCK_INTERFACE, "dns.domains", "dns_domains" },
	/* A `network` has the sub-block and no top-level spelling, so the
	 * canonical path keeps the prefix. */
	{ NCFG_BLOCK_NETWORK, "dns.servers", "dns.dns" },
	{ NCFG_BLOCK_NETWORK, "dns.search", "dns.dns_search" },
	{ NCFG_BLOCK_NETWORK, "dns.mode", "dns.dns_mode" },
	{ NCFG_BLOCK_NETWORK, "dns.domains", "dns.dns_domains" },
	/* `lookup` and `table` are one field in `ncfg_lower_rule`. */
	{ NCFG_BLOCK_RULE, "lookup", "table" }
};

#define ALIAS_COUNT (sizeof(ALIASES) / sizeof(ALIASES[0]))

const char *ncfg_key_canonical(ncfg_block_t block, const char *path)
{
	size_t at;

	if (!path) {
		return NULL;
	}
	for (at = 0u; at < ALIAS_COUNT; at++) {
		if (ALIASES[at].block == block && strcmp(ALIASES[at].alias, path) == 0) {
			return ALIASES[at].canonical;
		}
	}
	return path;
}

/*
 * THE EXCEPTIONS, WHICH ARE THE DESIGN
 *
 * Read as: within this block, this path departs from the default. Everything
 * not named here takes its block's answer, which is what keeps the list short
 * enough to argue with.
 *
 * **A path covers what is under it**, so naming a sub-block host-private
 * settles every key inside it without listing them. Inheritance runs in the
 * narrow direction by construction: a key is looked up, then its parent, then
 * the block -- so widening something requires naming it, and nothing widens by
 * accident.
 */
static const struct {
	ncfg_block_t block;
	const char  *path;
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
	 * **`interface`'s hardware, program and topology keys go the other way**,
	 * down to host-private from the block's host.
	 *
	 * `mac`, `kind` and `master` name this machine's own hardware and
	 * topology -- and `kind` covers the whole sub-tree under it, which is
	 * where a bridge's members and a tunnel's endpoints live.
	 *
	 * `probe.command` and `probe.args` are a program and its argument vector,
	 * and those are host-private **by the brief's rule rather than by
	 * preference**: a non-local document may reference only paths that
	 * already exist on the device, because "a document that can carry shell
	 * is remote code execution with extra steps".
	 *
	 * `advertise.backend` names which router-advertisement daemon is
	 * installed here, `ethtool` this NIC's offloads and `qdisc` its queueing
	 * discipline. None of the three is true of another box.
	 */
	{ NCFG_BLOCK_INTERFACE, "mac", NCFG_SCOPE_HOST_PRIVATE },
	{ NCFG_BLOCK_INTERFACE, "kind", NCFG_SCOPE_HOST_PRIVATE },
	{ NCFG_BLOCK_INTERFACE, "master", NCFG_SCOPE_HOST_PRIVATE },
	{ NCFG_BLOCK_INTERFACE, "qdisc", NCFG_SCOPE_HOST_PRIVATE },
	{ NCFG_BLOCK_INTERFACE, "ethtool", NCFG_SCOPE_HOST_PRIVATE },
	{ NCFG_BLOCK_INTERFACE, "probe.command", NCFG_SCOPE_HOST_PRIVATE },
	{ NCFG_BLOCK_INTERFACE, "probe.args", NCFG_SCOPE_HOST_PRIVATE },
	{ NCFG_BLOCK_INTERFACE, "advertise.backend", NCFG_SCOPE_HOST_PRIVATE },

	/*
	 * And its network-describing keys go up.
	 *
	 * **`advertise.prefix` and `config` are the pair 10.353 turned on**, once
	 * the keys were read rather than remembered -- 10.326. A prefix this link
	 * ANNOUNCES is a fact about the segment that every router on it must
	 * agree about, while `config` is which address this machine takes within
	 * it, and stays at the block's `host`: about this machine, and replicated
	 * so the estate can see and manage it. Those two being different scopes
	 * is what a local/network boolean could not express.
	 */
	{ NCFG_BLOCK_INTERFACE, "vlans", NCFG_SCOPE_GROUP },
	{ NCFG_BLOCK_INTERFACE, "nat", NCFG_SCOPE_GROUP },
	{ NCFG_BLOCK_INTERFACE, "advertise.prefix", NCFG_SCOPE_GROUP },
	{ NCFG_BLOCK_INTERFACE, "advertise.prefixes", NCFG_SCOPE_GROUP },
	{ NCFG_BLOCK_INTERFACE, "advertise.lifetime", NCFG_SCOPE_GROUP },
	{ NCFG_BLOCK_INTERFACE, "advertise.managed", NCFG_SCOPE_GROUP },
	{ NCFG_BLOCK_INTERFACE, "advertise.other", NCFG_SCOPE_GROUP },
	{ NCFG_BLOCK_INTERFACE, "advertise.other_config", NCFG_SCOPE_GROUP },
	{ NCFG_BLOCK_INTERFACE, "dns", NCFG_SCOPE_ESTATE },
	{ NCFG_BLOCK_INTERFACE, "dns_mode", NCFG_SCOPE_ESTATE },
	{ NCFG_BLOCK_INTERFACE, "dns_search", NCFG_SCOPE_ESTATE },
	{ NCFG_BLOCK_INTERFACE, "dns_domains", NCFG_SCOPE_ESTATE },
	{ NCFG_BLOCK_INTERFACE, "advertise.dns", NCFG_SCOPE_ESTATE },

	/*
	 * A hook is a path on the machine that runs them, so it cannot travel
	 * even though the block around it does. Same rule as `probe.command`, and
	 * these are the exceptions that go downward out of an estate-wide block.
	 *
	 * **`hooks` is not an assignment key**: it is its own item in the
	 * grammar, which is why the registry gate exempts it by name rather than
	 * failing to find it among the key strings.
	 */
	{ NCFG_BLOCK_NETWORK, "hooks", NCFG_SCOPE_HOST_PRIVATE },

	/*
	 * An `access_point`'s `device` names which of THIS machine's radios
	 * offers the network. The network being offered is the estate's; which
	 * box offers it is not, and an estate holding this would tell every host
	 * to use one radio name.
	 */
	{ NCFG_BLOCK_ACCESS_POINT, "device", NCFG_SCOPE_HOST_PRIVATE }
};

#define EXCEPTION_COUNT (sizeof(EXCEPTIONS) / sizeof(EXCEPTIONS[0]))

/*
 * THE KIND REGISTRY -- see `scope.h` for the rules this table is kept under.
 *
 * **Numbers are grouped by block for a reader's sake and are not computed from
 * one.** A structured number would make the block taxonomy part of the wire
 * format, so renaming or splitting a block later would move every key under
 * it. The grouping is a convention for whoever allocates the next number; the
 * number itself is written out.
 *
 *     0x0001xxxx  global        0x0004xxxx  access_point
 *     0x0002xxxx  interface     0x0005xxxx  rule
 *     0x0003xxxx  network       0x0006xxxx  linkset
 *
 * `device` and `bluetooth` have no range because they are host-private
 * entire: nothing in them travels, so nothing in them has a number.
 */
static const struct {
	ncfg_block_t block;
	const char  *path;
	unsigned     kind;
} KINDS[] = {
	/* global -- only the keys that travel, which are the resolver and
	 * reachability answers. The rest of the block is this machine's policy
	 * about itself. */
	{ NCFG_BLOCK_GLOBAL, "dns", 0x00010001u },
	{ NCFG_BLOCK_GLOBAL, "dns_mode", 0x00010002u },
	{ NCFG_BLOCK_GLOBAL, "dns_search", 0x00010003u },
	{ NCFG_BLOCK_GLOBAL, "dns_domains", 0x00010004u },
	{ NCFG_BLOCK_GLOBAL, "connectivity.requires", 0x00010005u },
	{ NCFG_BLOCK_GLOBAL, "connectivity.ignore", 0x00010006u },

	/* interface -- the block travels by default, so this is everything
	 * except the host-private exceptions above. `config` and
	 * `advertise.prefix` are the pair the whole design turns on. */
	{ NCFG_BLOCK_INTERFACE, "config", 0x00020001u },
	{ NCFG_BLOCK_INTERFACE, "routes", 0x00020002u },
	{ NCFG_BLOCK_INTERFACE, "mtu", 0x00020003u },
	{ NCFG_BLOCK_INTERFACE, "vlans", 0x00020004u },
	{ NCFG_BLOCK_INTERFACE, "nat", 0x00020005u },
	{ NCFG_BLOCK_INTERFACE, "guard", 0x00020006u },
	{ NCFG_BLOCK_INTERFACE, "preference", 0x00020007u },
	{ NCFG_BLOCK_INTERFACE, "ipv6_token", 0x00020008u },
	{ NCFG_BLOCK_INTERFACE, "enabled", 0x00020009u },
	{ NCFG_BLOCK_INTERFACE, "forwarding", 0x0002000au },
	{ NCFG_BLOCK_INTERFACE, "on_drift", 0x0002000bu },
	{ NCFG_BLOCK_INTERFACE, "dns", 0x0002000cu },
	{ NCFG_BLOCK_INTERFACE, "dns_mode", 0x0002000du },
	{ NCFG_BLOCK_INTERFACE, "dns_search", 0x0002000eu },
	{ NCFG_BLOCK_INTERFACE, "dns_domains", 0x0002000fu },
	{ NCFG_BLOCK_INTERFACE, "advertise.prefix", 0x00020010u },
	{ NCFG_BLOCK_INTERFACE, "advertise.prefixes", 0x00020011u },
	{ NCFG_BLOCK_INTERFACE, "advertise.lifetime", 0x00020012u },
	{ NCFG_BLOCK_INTERFACE, "advertise.managed", 0x00020013u },
	{ NCFG_BLOCK_INTERFACE, "advertise.other", 0x00020014u },
	{ NCFG_BLOCK_INTERFACE, "advertise.other_config", 0x00020015u },
	{ NCFG_BLOCK_INTERFACE, "advertise.dns", 0x00020016u },
	{ NCFG_BLOCK_INTERFACE, "probe.interval", 0x00020017u },
	{ NCFG_BLOCK_INTERFACE, "probe.timeout", 0x00020018u },
	{ NCFG_BLOCK_INTERFACE, "probe.up_after", 0x00020019u },
	{ NCFG_BLOCK_INTERFACE, "probe.down_after", 0x0002001au },
	{ NCFG_BLOCK_INTERFACE, "probe.hold_down", 0x0002001bu },
	{ NCFG_BLOCK_INTERFACE, "probe.require_lease", 0x0002001cu },
	/* Wired 802.1X. `ca_cert`, `client_cert` and `private_key` are absent on
	 * purpose -- see THE THREE KEYS THAT HAVE NO NUMBER YET, below. */
	{ NCFG_BLOCK_INTERFACE, "dot1x.eap", 0x0002001du },
	{ NCFG_BLOCK_INTERFACE, "dot1x.identity", 0x0002001eu },
	{ NCFG_BLOCK_INTERFACE, "dot1x.anonymous_identity", 0x0002001fu },
	{ NCFG_BLOCK_INTERFACE, "dot1x.password", 0x00020020u },
	{ NCFG_BLOCK_INTERFACE, "dot1x.phase2", 0x00020021u },
	{ NCFG_BLOCK_INTERFACE, "dot1x.domain_suffix_match", 0x00020022u },

	/*
	 * network -- estate-wide entire but for its hooks, so everything the
	 * grammar accepts has a number.
	 *
	 * **A credential travels as a reference and never as a value.**
	 * `ncfg_as_secret` refuses a bare string and takes only `@secret:NAME`,
	 * whose value lives in /etc/netcfgd/secrets/NAME at 0600 on each machine.
	 * So `wifi.psk` carries a name the estate agrees on and the passphrase
	 * stays where it was put -- which is what makes an estate-wide `network`
	 * block safe to replicate at all.
	 */
	{ NCFG_BLOCK_NETWORK, "ssid", 0x00030001u },
	{ NCFG_BLOCK_NETWORK, "bssid", 0x00030002u },
	{ NCFG_BLOCK_NETWORK, "hidden", 0x00030003u },
	{ NCFG_BLOCK_NETWORK, "metered", 0x00030004u },
	{ NCFG_BLOCK_NETWORK, "metric", 0x00030005u },
	{ NCFG_BLOCK_NETWORK, "config", 0x00030006u },
	{ NCFG_BLOCK_NETWORK, "routes", 0x00030007u },
	{ NCFG_BLOCK_NETWORK, "dns.dns", 0x00030008u },
	{ NCFG_BLOCK_NETWORK, "dns.dns_mode", 0x00030009u },
	{ NCFG_BLOCK_NETWORK, "dns.dns_search", 0x0003000au },
	{ NCFG_BLOCK_NETWORK, "dns.dns_domains", 0x0003000bu },
	{ NCFG_BLOCK_NETWORK, "wifi.proto", 0x0003000cu },
	{ NCFG_BLOCK_NETWORK, "wifi.open", 0x0003000du },
	{ NCFG_BLOCK_NETWORK, "wifi.owe", 0x0003000eu },
	{ NCFG_BLOCK_NETWORK, "wifi.psk", 0x0003000fu },
	{ NCFG_BLOCK_NETWORK, "wifi.eap", 0x00030010u },
	{ NCFG_BLOCK_NETWORK, "wifi.identity", 0x00030011u },
	{ NCFG_BLOCK_NETWORK, "wifi.anonymous_identity", 0x00030012u },
	{ NCFG_BLOCK_NETWORK, "wifi.password", 0x00030013u },
	{ NCFG_BLOCK_NETWORK, "wifi.phase2", 0x00030014u },
	{ NCFG_BLOCK_NETWORK, "wifi.domain_suffix_match", 0x00030015u },
	{ NCFG_BLOCK_NETWORK, "wifi.autoconnect", 0x00030016u },
	{ NCFG_BLOCK_NETWORK, "wifi.roam.signal", 0x00030017u },
	{ NCFG_BLOCK_NETWORK, "wifi.roam.interval", 0x00030018u },
	{ NCFG_BLOCK_NETWORK, "wifi.roam.slow_interval", 0x00030019u },

	/*
	 * access_point -- what is offered, not who offers it. `device` is
	 * host-private above and has no number.
	 *
	 * **Only the security keys an AP actually configures get one.**
	 * `ncfg_build_security` is shared with `network`, so the grammar accepts
	 * an `identity` here and it means nothing on the offering side. A number
	 * for it would be wire surface for a key with no behaviour behind it.
	 */
	{ NCFG_BLOCK_ACCESS_POINT, "ssid", 0x00040001u },
	{ NCFG_BLOCK_ACCESS_POINT, "hidden", 0x00040002u },
	{ NCFG_BLOCK_ACCESS_POINT, "channel", 0x00040003u },
	{ NCFG_BLOCK_ACCESS_POINT, "band", 0x00040004u },
	{ NCFG_BLOCK_ACCESS_POINT, "regdom", 0x00040005u },
	{ NCFG_BLOCK_ACCESS_POINT, "wifi.proto", 0x00040006u },
	{ NCFG_BLOCK_ACCESS_POINT, "wifi.open", 0x00040007u },
	{ NCFG_BLOCK_ACCESS_POINT, "wifi.owe", 0x00040008u },
	{ NCFG_BLOCK_ACCESS_POINT, "wifi.psk", 0x00040009u },
	{ NCFG_BLOCK_ACCESS_POINT, "access_control.allow", 0x0004000au },
	{ NCFG_BLOCK_ACCESS_POINT, "access_control.deny", 0x0004000bu },

	/*
	 * rule -- a policy expression, group-wide entire.
	 *
	 * **`iif` and `oif` name links and still travel**, which is the line
	 * `scope.h` draws rather than a lapse: two machines in a zone can hold
	 * `iif wan0` identically and mean the same thing, where `interface.master`
	 * says that THIS link is enslaved to THAT one and cannot be held by two
	 * machines at once.
	 */
	{ NCFG_BLOCK_RULE, "family", 0x00050001u },
	{ NCFG_BLOCK_RULE, "priority", 0x00050002u },
	{ NCFG_BLOCK_RULE, "from", 0x00050003u },
	{ NCFG_BLOCK_RULE, "to", 0x00050004u },
	{ NCFG_BLOCK_RULE, "iif", 0x00050005u },
	{ NCFG_BLOCK_RULE, "oif", 0x00050006u },
	{ NCFG_BLOCK_RULE, "fwmark", 0x00050007u },
	{ NCFG_BLOCK_RULE, "fwmask", 0x00050008u },
	{ NCFG_BLOCK_RULE, "table", 0x00050009u },
	{ NCFG_BLOCK_RULE, "suppress_prefixlength", 0x0005000au },
	{ NCFG_BLOCK_RULE, "l3mdev", 0x0005000bu },
	{ NCFG_BLOCK_RULE, "action", 0x0005000cu },

	/* linkset -- `members` and nothing else, which the lowering says in as
	 * many words when it refuses anything else. */
	{ NCFG_BLOCK_LINKSET, "members", 0x00060001u }
};

#define KIND_COUNT (sizeof(KINDS) / sizeof(KINDS[0]))

/*
 * THE THREE KEYS THAT HAVE NO NUMBER YET, AND WHY THAT IS THE ANSWER
 *
 * `dot1x.ca_cert`, `dot1x.client_cert` and `dot1x.private_key` are estate-wide
 * by scope and deliberately unregistered, which is the zero rule doing its job
 * rather than an omission.
 *
 * `ncfg_as_cert_source` accepts EITHER form under one spelling: `@secret:NAME`
 * is content netcfgd already holds and grants nothing, while a bare string is
 * a PATH -- "an instruction to open it *as root*; a caller who is not root
 * cannot send one" (`document.h`). A scope is a property of a key and cannot
 * say "this key may travel in one of its two forms", so a number here would
 * let a replicated record carry the privileged form under a key the table
 * calls safe.
 *
 * What closes it is a record encoder that refuses `NCFG_CERT_SOURCE_PATH`,
 * at which point the three get numbers in the interface range. Until then
 * they answer `NCFG_KIND_NONE`, which is exactly true: they cannot be carried
 * yet.
 */

/*
 * **Numbers that have been used and must never be used again.**
 *
 * Empty today and kept anyway, because the moment it is needed is the moment
 * somebody is removing a key and is least likely to invent the list. A record
 * signed under a retired number outlives the key it described, so reissuing
 * that number gives an old record a new meaning -- with a valid signature.
 *
 * **The numbering was rewritten once, on 2026-09-29, and nothing is retired
 * from it.** The first table was keyed on a bare name rather than a path and
 * carried six entries that were not keys at all (10.357). Nothing had written
 * a record under any of those numbers, on this machine or anywhere else, so
 * they were corrected rather than retired -- which was the last moment that
 * was free, and is why the rule binds from here.
 */
static const unsigned RETIRED[] = { 0u };
#define RETIRED_COUNT (sizeof(RETIRED) / sizeof(RETIRED[0]))

unsigned ncfg_kind_of(ncfg_block_t block, const char *path)
{
	size_t at;

	if (!path || (int)block < 0 || (int)block >= (int)NCFG_BLOCK_COUNT) {
		return NCFG_KIND_NONE;
	}
	path = ncfg_key_canonical(block, path);
	for (at = 0u; at < KIND_COUNT; at++) {
		if (KINDS[at].block == block && strcmp(KINDS[at].path, path) == 0) {
			return KINDS[at].kind;
		}
	}
	/* Not registered. Zero means "cannot be a record yet", which fails at the
	 * point of writing rather than acquiring a neighbour's meaning. **No
	 * inheritance here**, unlike a scope: a parent's number is the parent's,
	 * and handing it to a child would put two meanings under one number. */
	return NCFG_KIND_NONE;
}

int ncfg_kind_is_taken(unsigned kind)
{
	size_t at;

	if (kind == NCFG_KIND_NONE) {
		return 1; /* reserved, so never allocatable */
	}
	for (at = 0u; at < KIND_COUNT; at++) {
		if (KINDS[at].kind == kind) {
			return 1;
		}
	}
	for (at = 0u; at < RETIRED_COUNT; at++) {
		if (RETIRED[at] == kind) {
			return 1;
		}
	}
	return 0;
}

/* One exact lookup, with no walking. */
static int exception_for(ncfg_block_t block, const char *path, size_t length, ncfg_scope_t *out)
{
	size_t at;

	for (at = 0u; at < EXCEPTION_COUNT; at++) {
		if (EXCEPTIONS[at].block != block) {
			continue;
		}
		if (strncmp(EXCEPTIONS[at].path, path, length) != 0) {
			continue;
		}
		if (EXCEPTIONS[at].path[length] != '\0') {
			continue;
		}
		*out = EXCEPTIONS[at].scope;
		return 1;
	}
	return 0;
}

ncfg_scope_t ncfg_scope_of(ncfg_block_t block, const char *path)
{
	ncfg_scope_t found;
	size_t       length;

	if ((int)block < 0 || (int)block >= (int)NCFG_BLOCK_COUNT) {
		/* Not a block this build knows, so nothing about it may be
		 * published. The narrow direction, as `scope.h` argues. */
		return NCFG_SCOPE_HOST_PRIVATE;
	}
	if (!path) {
		return BLOCK_DEFAULT[block];
	}
	path = ncfg_key_canonical(block, path);

	/*
	 * The key, then each enclosing sub-block, then the block. A parent's
	 * answer covers what is under it, so `interface.kind` settles every key
	 * of every link type without thirteen more rows -- and a sub-block that
	 * nobody classified takes the block's answer rather than inventing one.
	 */
	length = strlen(path);
	while (length > 0u) {
		if (exception_for(block, path, length, &found)) {
			return found;
		}
		/* Step back to the enclosing sub-block, or stop at the block itself. */
		while (length > 0u && path[length - 1u] != '.') {
			length--;
		}
		if (length > 0u) {
			length--; /* drop the separator, leaving the parent's path */
		}
	}
	return BLOCK_DEFAULT[block];
}
