/*
 * The kernel's other byte streams, and the payloads inside netlink messages.
 *
 * WHY `netlink_wire` IS NOT ENOUGH
 *   That target walks messages and attributes. These are the decoders ABOVE
 *   and BESIDE it, each with its own idea of what a record looks like:
 *
 *     inotify   a run of variable-length records in one `read`, where the
 *               length of each comes out of the record itself -- the exact
 *               shape that makes a walk fail to terminate
 *     rfkill    fixed-size records from `/dev/rfkill`, whose size is a
 *               kernel ABI that has grown twice
 *     nft       tables, chains and rules out of a netfilter payload, which is
 *               nested attributes with a different vocabulary
 *     fib rule  a routing-rule dump record
 *     genl      a family's groups, which is how every generic-netlink family
 *               gets found
 *     nl80211   the regulatory domain's country, which `ncfg status` prints
 *
 *   All of them read a length from the bytes and trust it to bound a read,
 *   which is the one sentence this target exists for.
 *
 * TERMINATION IS ASSERTED, NOT HOPED FOR
 *   `netlink_wire` makes this argument and it is the same here: a length that
 *   makes no progress is an infinite loop that looks like a slow input from
 *   outside, and no sanitizer sees it. The walk is counted and the bound
 *   aborts.
 */
#include "fuzz.h"

#include "ncfg/devlink.h"
#include "ncfg/regdom.h"
#include "ncfg/base.h"
#include "ncfg/rule.h"
#include "ncfg/genl.h"
#include "ncfg/nft.h"
#include "ncfg/rfkill.h"
#include "ncfg/watch.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define WALK_MAX 10000u

int ncfg_fuzz_one(const unsigned char *data, size_t length)
{
	ncfg_inotify_walk_t   walk;
	ncfg_inotify_event_t  event;
	ncfg_rfkill_event_t   radio;
	ncfg_rule_record_t    rule;
	ncfg_nft_table_t      table;
	ncfg_nft_chain_t      chain;
	ncfg_genl_family_t    family;
	char                  text[256];
	char                  err[NCFG_ERROR_MAX];
	size_t                seen = 0u;

	/* One `read` from an inotify descriptor: a run of records whose names are
	 * counted by a field inside each. */
	ncfg_inotify_walk_start(&walk, data, length);
	while (ncfg_inotify_walk_next(&walk, &event, err, sizeof(err)) == NCFG_WIRE_OK) {
		(void)ncfg_inotify_event_overflowed(&event);
		if (++seen >= WALK_MAX) {
			abort(); /* a walk that does not terminate */
		}
	}

	/* One record from `/dev/rfkill`, whose size is an ABI rather than a
	 * constant this program chose. */
	(void)ncfg_rfkill_parse(data, length, &radio, err, sizeof(err));

	/* A routing rule, as a dump hands one over. */
	(void)ncfg_dump_rule(data, length, &rule, err, sizeof(err));

	/* netfilter: the three shapes, plus the question the apply path asks
	 * before it writes anything -- whether a payload touches only our own
	 * table, which is a refusal that protects somebody else's firewall. */
	memset(&table, 0, sizeof(table));
	memset(&chain, 0, sizeof(chain));
	(void)ncfg_nft_table_read(data, length, &table, err, sizeof(err));
	(void)ncfg_nft_chain_read(data, length, &chain, err, sizeof(err));
	(void)ncfg_nft_rule_uplink(data, length, text, sizeof(text), err, sizeof(err));
	(void)ncfg_nft_writes_only_our_table(data, length, err, sizeof(err));

	/* Generic netlink's family lookup, which every family added after
	 * nl80211 will go through. The name is the fuzzer's too, since a reply
	 * naming a different family is exactly what must not be believed. */
	memset(&family, 0, sizeof(family));
	if (ncfg_genl_family_parse("nl80211", data, length, &family, err, sizeof(err))) {
		uint32_t group = 0u;

		(void)ncfg_genl_family_group(&family, "mlme", &group, err, sizeof(err));
	}
	ncfg_genl_family_free(&family);

	/* nl80211's answer about the regulatory domain, which `ncfg status`
	 * prints as a sentence about where the machine is. */
	{
		char code[NCFG_REGDOM_TEXT_MAX];

		(void)ncfg_regdom_parse(data, length, code, sizeof(code), err, sizeof(err));
	}

	/* And the notification of who changed it, which the daemon reads off the
	 * `regulatory` group whole -- several messages to a datagram -- and keeps.
	 * The family id is one a real kernel hands out, so the walk reaches the
	 * attribute reads rather than passing every message over. */
	{
		ncfg_regdom_change_t change;
		int                  found = 0;

		(void)ncfg_regdom_change_parse(data, length, 35u, &found, &change, err, sizeof(err));
	}

	/* One port out of devlink's dump, which `ncfg status` prints as what a
	 * card's port is running as. */
	{
		ncfg_devlink_port_t port;

		(void)ncfg_devlink_port_parse(data, length, &port, err, sizeof(err));
	}
	return 0;
}
