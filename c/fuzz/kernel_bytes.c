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
 *     nl80211   the regulatory domain's country, which `ncfg status` prints,
 *               an interface's type, and a mesh point's stations
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
#include "ncfg/mesh_peer.h"
#include "ncfg/netlink.h"
#include "ncfg/qdisc.h"
#include "ncfg/regdom.h"
#include "ncfg/base.h"
#include "ncfg/rule.h"
#include "ncfg/genl.h"
#include "ncfg/nft.h"
#include "ncfg/rfkill.h"
#include "ncfg/watch.h"
#include "ncfg/wds.h"
#include "ncfg/wiphy.h"

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

	/* And every reader of what netcfgd's own table holds, which takes a rule
	 * somebody may have edited by hand: the firewall's rules, a forward's,
	 * the MSS clamp and flow offload, a flowtable and the generation. The
	 * firewall rule reader is the largest parser in nft.c and was reached by
	 * nothing here until 2026-11-22 (10.907). */
	{
		ncfg_nft_kernel_rule_t    kernel_rule;
		ncfg_nft_kernel_forward_t forward;
		ncfg_nft_flowtable_t      flowtable;
		char                      time[NCFG_NFT_TIME_TEXT];
		int                       leaving = 0;
		uint32_t                  generation = 0u;

		if (ncfg_nft_firewall_rule_read(data, length, &kernel_rule, err, sizeof(err))) {
			ncfg_nft_kernel_rule_time(&kernel_rule, time, sizeof(time));
			(void)ncfg_nft_kernel_rule_action_word(&kernel_rule);
		}
		(void)ncfg_nft_forward_read(data, length, &forward, err, sizeof(err));
		(void)ncfg_nft_rule_mss(data, length, text, sizeof(text), &leaving);
		(void)ncfg_nft_rule_is_offload(data, length);
		(void)ncfg_nft_flowtable_read(data, length, &flowtable, err, sizeof(err));
		(void)ncfg_nft_gen_read(data, length, &generation, err, sizeof(err));
	}

	/* A slot's rule and a slot's members (0340): the first read on every
	 * observation, the second before every replacement and on every pass
	 * that lists members. */
	{
		ncfg_nft_kernel_slot_t  opened;
		ncfg_nft_slot_member_t *members = NULL;
		size_t                  count = 0u;

		(void)ncfg_nft_rule_slot(data, length, &opened);
		(void)ncfg_nft_slot_members_read(data, length, &members, &count, err, sizeof(err));
		for (size_t one = 0u; one < count; one++) {
			ncfg_nft_slot_member_text(&members[one], text, sizeof(text));
		}
		free(members);
	}

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

	/* rtnetlink's dumps, which every observation reads: a link (its kind's
	 * nest, its alternative names -- the one part allocated), an address, a
	 * route and a bridge port's VLANs; tc's qdiscs and their redirect; and
	 * nl80211's description of a radio. None was reached by any target until
	 * 2026-11-22 (10.907). Each record is freed on either answer, as its
	 * header says a caller may. */
	{
		ncfg_link_record_t         link;
		ncfg_address_record_t      address;
		ncfg_route_record_t        route;
		ncfg_bridge_vlan_records_t vlans;
		ncfg_qdisc_entry_t         entry;
		ncfg_qdisc_record_t        qdisc;
		ncfg_qdisc_redirect_t      redirect;
		ncfg_qdisc_tcmsg_t         tcmsg;
		ncfg_wiphy_t               wiphy;

		(void)ncfg_dump_link(data, length, &link, err, sizeof(err));
		ncfg_link_record_free(&link);
		(void)ncfg_dump_address(data, length, &address, err, sizeof(err));
		(void)ncfg_dump_route(data, length, &route, err, sizeof(err));
		(void)ncfg_dump_bridge_vlans(data, length, &vlans, err, sizeof(err));
		ncfg_bridge_vlan_records_free(&vlans);
		(void)ncfg_qdisc_entry_read(data, length, &entry, &qdisc, err, sizeof(err));
		(void)ncfg_qdisc_redirect_read(data, length, &redirect, err, sizeof(err));
		(void)ncfg_qdisc_tcmsg_decode(data, length, &tcmsg, err, sizeof(err));
		(void)ncfg_wiphy_parse(data, length, &wiphy, err, sizeof(err));
	}

	/* One interface out of nl80211's dump -- its type and four-address mode
	 * -- and one station of a mesh point, whose peer link state sits in a nest
	 * (10.686). The station's address must come back terminated, and its
	 * state is only claimed where a byte was read for it. */
	{
		ncfg_wds_interface_t wireless;
		ncfg_mesh_peer_t     peer;

		(void)ncfg_wds_interface_parse(data, length, &wireless, err, sizeof(err));
		if (ncfg_mesh_peer_parse(data, length, &peer, err, sizeof(err)) &&
		    memchr(peer.mac, '\0', sizeof(peer.mac)) == NULL) {
			abort(); /* an address handed back without its end */
		}
	}
	return 0;
}
