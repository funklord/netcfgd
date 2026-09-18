/*
 * lower_kind.c -- what netcfgd creates, and therefore what a device is.
 *
 * One file per question rather than per type: every block here answers "what
 * kind of link is this", they share the same shape -- collect keys, then
 * refuse the combinations the kernel would refuse with an errno naming
 * nothing -- and 0155 pass 1b moved the whole question from `interface` to
 * `device` in one go.
 *
 * The refusals are the substance. A `geneve` tunnel with a `parent`, an
 * `ipip` with a v6 endpoint, a bond with no mode, two WireGuard peers sharing
 * a public key: each of those is accepted by this language and rejected by the
 * kernel at apply time, with an error that names neither the key nor the line.
 */
#include <stdlib.h>
#include <string.h>

#include "lower_internal.h"

#include "ncfg/base.h"
#include "ncfg/value.h"

/*
 * Every assignment of a block, for the kinds that hold nothing else.
 *
 * A macro rather than twelve copies of the same three lines. It reads `at`,
 * which every user declares, because a loop variable hidden inside a macro is
 * the kind of thing that shadows one somebody adds later -- and `-Wshadow` is
 * on.
 */
#define FOR_ASSIGNMENTS(block, item, assignment)                                                 \
	for (at = 0; at < (block)->items.count; at++)                                                \
		if (((item) = (block)->items.at[at])->kind == NCFG_AST_ITEM_ASSIGNMENT &&                \
		    ((assignment) = &(item)->as.assignment, 1))

/* ------------------------------------------------------------------------ *
 * Members
 * ------------------------------------------------------------------------ */

/*
 * Each word of a `members` list is a link name. Every bad one is reported and
 * dropped rather than stopping at the first, so an operator fixing typos is
 * told about all of them at once.
 */
static void lower_members(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value, char ***members,
    size_t *count)
{
	ncfg_words_t words;
	size_t       i;

	if (!ncfg_as_words(ctx, value, &words)) {
		ncfg_words_free(&words);
		return;
	}
	for (i = 0; i < words.count; i++) {
		if (!ncfg_name_ok(ctx, words.at[i].text, words.at[i].span, ncfg_link_name_help)) {
			continue;
		}
		(void)ncfg_push_string(ctx, members, count, words.at[i].text);
	}
	ncfg_words_free(&words);
}

/* ------------------------------------------------------------------------ *
 * bridge, bond, vlan, veth
 * ------------------------------------------------------------------------ */

static void lower_bridge(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_interface_kind_t *out)
{
	ncfg_bridge_config_t        *config = &out->bridge;
	const ncfg_ast_item_t       *item;
	const ncfg_ast_assignment_t *assignment;
	size_t                       at;
	int                          flag;

	out->kind = NCFG_KIND_BRIDGE;
	FOR_ASSIGNMENTS(block, item, assignment) {
		const char *key = assignment->key;

		if (strcmp(key, "members") == 0) {
			lower_members(ctx, assignment->value, &config->members, &config->member_count);
		} else if (strcmp(key, "stp") == 0) {
			if (ncfg_as_bool(ctx, assignment->value, &flag)) {
				config->stp = flag;
			}
		} else if (strcmp(key, "forward_delay") == 0) {
			ncfg_as_u32_opt(ctx, assignment->value, &config->forward_delay);
		} else if (strcmp(key, "hello_time") == 0) {
			ncfg_as_u32_opt(ctx, assignment->value, &config->hello_time);
		} else if (strcmp(key, "ageing_time") == 0) {
			ncfg_as_u32_opt(ctx, assignment->value, &config->ageing_time);
		} else if (strcmp(key, "priority") == 0) {
			ncfg_as_narrow_opt(ctx, assignment->value, 65535, &config->priority);
		} else if (strcmp(key, "vlan_filtering") == 0) {
			/* Off by default, as in the kernel. Never inferred from the
			 * presence of VLAN interfaces elsewhere: a bridge quietly becoming
			 * VLAN-aware would drop untagged traffic that used to pass. */
			if (ncfg_as_bool(ctx, assignment->value, &flag)) {
				config->vlan_filtering = flag;
			}
		} else {
			ncfg_diag(ctx, assignment->span, "unknown bridge key `%s`", key);
		}
	}
}

/* `iproute2`'s spellings, which is why this is neither snake nor kebab all
 * through: `802.3ad` is what every piece of bonding documentation calls LACP,
 * and a tidier word would be a bond the kernel refuses. */
static int bond_mode(const char *text, int *out)
{
	static const char *const names[] = { "balance-rr", "active-backup", "balance-xor",
		"broadcast", "802.3ad", "balance-tlb", "balance-alb" };
	size_t i;

	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		if (strcmp(names[i], text) == 0) {
			*out = (int)i;
			return 1;
		}
	}
	return 0;
}

static int lower_bond(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_interface_kind_t *out)
{
	ncfg_bond_config_t           config;
	const ncfg_ast_item_t       *item;
	const ncfg_ast_assignment_t *assignment;
	size_t                       at;
	int                          mode_seen = 0;

	memset(&config, 0, sizeof(config));
	FOR_ASSIGNMENTS(block, item, assignment) {
		const char *key = assignment->key;

		if (strcmp(key, "members") == 0) {
			lower_members(ctx, assignment->value, &config.members, &config.member_count);
		} else if (strcmp(key, "mode") == 0) {
			char *text = ncfg_as_string(ctx, assignment->value);

			if (!text) {
				continue;
			}
			if (bond_mode(text, &config.mode)) {
				mode_seen = 1;
			} else {
				ncfg_diag(ctx, assignment->span,
				    "`%s` is not a bonding mode: one of balance-rr, active-backup, "
				    "balance-xor, broadcast, 802.3ad, balance-tlb, balance-alb", text);
			}
			free(text);
		} else if (strcmp(key, "miimon") == 0) {
			ncfg_as_u32_opt(ctx, assignment->value, &config.miimon);
		} else {
			ncfg_diag(ctx, assignment->span, "unknown bond key `%s`", key);
		}
	}
	if (!mode_seen) {
		size_t i;

		ncfg_diag(ctx, block->span,
		    "a bond needs a `mode`: `active-backup` needs nothing of the switch; the others "
		    "need a cooperating one");
		for (i = 0; i < config.member_count; i++) {
			free(config.members[i]);
		}
		free(config.members);
		return 0;
	}
	out->kind = NCFG_KIND_BOND;
	out->bond = config;
	return 1;
}

static int lower_vlan(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_interface_kind_t *out)
{
	const ncfg_ast_item_t       *item;
	const ncfg_ast_assignment_t *assignment;
	char                        *parent = NULL;
	ncfg_optint_t                id;
	int                          protocol = NCFG_VLAN_PROTOCOL_DOT1Q;
	size_t                       at;

	memset(&id, 0, sizeof(id));
	FOR_ASSIGNMENTS(block, item, assignment) {
		const char *key = assignment->key;

		if (strcmp(key, "parent") == 0) {
			free(parent);
			parent = ncfg_as_interface_name(ctx, assignment->value);
		} else if (strcmp(key, "id") == 0) {
			ncfg_as_narrow_opt(ctx, assignment->value, 65535, &id);
			if (!id.has) {
				ncfg_diag(ctx, assignment->value->span,
				    "vlan id must be between 0 and 4095");
			}
		} else if (strcmp(key, "protocol") == 0) {
			char *name = ncfg_as_string(ctx, assignment->value);

			if (!name) {
				continue;
			}
			if (strcmp(name, "dot1q") == 0 || strcmp(name, "802.1q") == 0) {
				protocol = NCFG_VLAN_PROTOCOL_DOT1Q;
			} else if (strcmp(name, "dot1ad") == 0 || strcmp(name, "802.1ad") == 0) {
				protocol = NCFG_VLAN_PROTOCOL_DOT1AD;
			} else {
				ncfg_diag(ctx, assignment->value->span, "unknown vlan protocol `%s`", name);
			}
			free(name);
		} else {
			ncfg_diag(ctx, assignment->span, "unknown vlan key `%s`", key);
		}
	}
	if (!parent || !id.has) {
		ncfg_diag(ctx, block->span,
		    "a vlan needs both `parent` and `id`: for example: vlan { parent = \"eth0\"; "
		    "id = 10 }");
		free(parent);
		return 0;
	}
	out->kind = NCFG_KIND_VLAN;
	out->vlan.parent = parent;
	out->vlan.id = id.value;
	out->vlan.protocol = protocol;
	return 1;
}

static int lower_veth(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_interface_kind_t *out)
{
	const ncfg_ast_item_t       *item;
	const ncfg_ast_assignment_t *assignment;
	char                        *peer = NULL;
	size_t                       at;

	FOR_ASSIGNMENTS(block, item, assignment) {
		if (strcmp(assignment->key, "peer") == 0) {
			free(peer);
			peer = ncfg_as_interface_name(ctx, assignment->value);
		} else {
			ncfg_diag(ctx, assignment->span, "unknown veth key `%s`", assignment->key);
		}
	}
	if (!peer) {
		ncfg_diag(ctx, block->span,
		    "a veth needs a `peer`: a veth is a pair, and both ends are named at creation");
		return 0;
	}
	out->kind = NCFG_KIND_VETH;
	out->veth.peer = peer;
	return 1;
}

/* ------------------------------------------------------------------------ *
 * vxlan, vrf, macvlan, tunnel, tun
 * ------------------------------------------------------------------------ */

/* An address key in a link block: a bare address, canonicalised. */
static char *lower_address_key(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value)
{
	char *text = ncfg_as_string(ctx, value);
	char *canonical;

	if (!text) {
		return NULL;
	}
	if (!ncfg_is_bare_address(text)) {
		ncfg_diag(ctx, value->span, "`%s` is not an IP address", text);
		free(text);
		return NULL;
	}
	canonical = ncfg_canonical_address(ctx, text);
	free(text);
	return canonical;
}

static int lower_vxlan(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_interface_kind_t *out)
{
	ncfg_vxlan_config_t          config;
	const ncfg_ast_item_t       *item;
	const ncfg_ast_assignment_t *assignment;
	size_t                       at;
	int                          id_seen = 0;

	memset(&config, 0, sizeof(config));
	FOR_ASSIGNMENTS(block, item, assignment) {
		const char *key = assignment->key;

		if (strcmp(key, "id") == 0 || strcmp(key, "vni") == 0) {
			int64_t value;

			if (!ncfg_as_u32(ctx, assignment->value, &value)) {
				continue;
			}
			/* 24 bits. A VNI above that is silently truncated by the kernel,
			 * so two tunnels that look distinct in the config become one. */
			if (value < (1LL << 24)) {
				config.id = value;
				id_seen = 1;
			} else {
				ncfg_diag(ctx, assignment->value->span,
				    "a VNI is 24 bits, so at most 16777215");
			}
		} else if (strcmp(key, "parent") == 0 || strcmp(key, "dev") == 0) {
			free(config.parent);
			config.parent = ncfg_as_interface_name(ctx, assignment->value);
		} else if (strcmp(key, "local") == 0) {
			free(config.local);
			config.local = lower_address_key(ctx, assignment->value);
		} else if (strcmp(key, "remote") == 0 || strcmp(key, "group") == 0) {
			free(config.remote);
			config.remote = lower_address_key(ctx, assignment->value);
		} else if (strcmp(key, "port") == 0) {
			ncfg_as_narrow_opt(ctx, assignment->value, 65535, &config.port);
		} else {
			ncfg_diag(ctx, assignment->span, "unknown vxlan key `%s`", key);
		}
	}

	if (!id_seen) {
		ncfg_diag(ctx, block->span,
		    "a vxlan needs an `id`: the VNI, which identifies the overlay: `id = 100`");
		goto drop;
	}
	/* Both families in one tunnel is not a thing the kernel will build, and
	 * the error it gives says nothing about which end was wrong. */
	if (config.local && config.remote &&
	    (strchr(config.local, ':') == NULL) != (strchr(config.remote, ':') == NULL)) {
		ncfg_diag(ctx, block->span, "`local` and `remote` must be the same address family");
		goto drop;
	}
	out->kind = NCFG_KIND_VXLAN;
	out->vxlan = config;
	return 1;

drop:
	free(config.parent);
	free(config.local);
	free(config.remote);
	return 0;
}

static int lower_vrf(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_interface_kind_t *out)
{
	const ncfg_ast_item_t       *item;
	const ncfg_ast_assignment_t *assignment;
	ncfg_optint_t                table;
	size_t                       at;

	memset(&table, 0, sizeof(table));
	FOR_ASSIGNMENTS(block, item, assignment) {
		if (strcmp(assignment->key, "table") == 0) {
			ncfg_as_u32_opt(ctx, assignment->value, &table);
		} else {
			ncfg_diag(ctx, assignment->span, "unknown vrf key `%s`", assignment->key);
		}
	}
	if (!table.has) {
		ncfg_diag(ctx, block->span,
		    "a vrf needs a `table`: enslaving an interface moves its routes into that table; "
		    "a vrf without one isolates traffic into nowhere");
		return 0;
	}
	out->kind = NCFG_KIND_VRF;
	out->vrf.table = table.value;
	return 1;
}

static int lower_macvlan(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_interface_kind_t *out)
{
	const ncfg_ast_item_t       *item;
	const ncfg_ast_assignment_t *assignment;
	char                        *parent = NULL;
	int                          mode = NCFG_MACVLAN_MODE_PRIVATE;
	size_t                       at;

	FOR_ASSIGNMENTS(block, item, assignment) {
		const char *key = assignment->key;

		if (strcmp(key, "parent") == 0 || strcmp(key, "dev") == 0) {
			free(parent);
			parent = ncfg_as_interface_name(ctx, assignment->value);
		} else if (strcmp(key, "mode") == 0) {
			char *name = ncfg_as_string(ctx, assignment->value);

			if (!name) {
				continue;
			}
			if (strcmp(name, "private") == 0) {
				mode = NCFG_MACVLAN_MODE_PRIVATE;
			} else if (strcmp(name, "vepa") == 0) {
				mode = NCFG_MACVLAN_MODE_VEPA;
			} else if (strcmp(name, "bridge") == 0) {
				mode = NCFG_MACVLAN_MODE_BRIDGE;
			} else if (strcmp(name, "passthru") == 0) {
				mode = NCFG_MACVLAN_MODE_PASSTHRU;
			} else {
				ncfg_diag(ctx, assignment->span,
				    "`%s` is not a macvlan mode: one of private, vepa, bridge, passthru",
				    name);
			}
			free(name);
		} else {
			ncfg_diag(ctx, assignment->span, "unknown macvlan key `%s`", key);
		}
	}
	if (!parent) {
		ncfg_diag(ctx, block->span, "a macvlan needs a `parent` to sit on");
		return 0;
	}
	out->kind = NCFG_KIND_MACVLAN;
	out->macvlan.parent = parent;
	out->macvlan.mode = mode;
	return 1;
}

static int tunnel_kind(const char *text, int *out)
{
	static const char *const names[] = { "gre", "gretap", "ip6gre", "ipip", "sit", "ip6tnl",
		"geneve" };
	size_t i;

	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		if (strcmp(names[i], text) == 0) {
			*out = (int)i;
			return 1;
		}
	}
	return 0;
}

static int tunnel_is_v6(int kind)
{
	return kind == NCFG_TUNNEL_KIND_IP6GRE || kind == NCFG_TUNNEL_KIND_IP6TNL;
}

static const char *tunnel_name(int kind)
{
	static const char *const names[] = { "gre", "gretap", "ip6gre", "ipip", "sit", "ip6tnl",
		"geneve" };

	return names[kind];
}

static int lower_tunnel(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_interface_kind_t *out)
{
	ncfg_tunnel_config_t         config;
	const ncfg_ast_item_t       *item;
	const ncfg_ast_assignment_t *assignment;
	size_t                       at;
	int                          kind = 0;
	int                          kind_seen = 0;
	int                          end;

	memset(&config, 0, sizeof(config));
	FOR_ASSIGNMENTS(block, item, assignment) {
		const char *key = assignment->key;

		if (strcmp(key, "mode") == 0 || strcmp(key, "kind") == 0) {
			char *name = ncfg_as_string(ctx, assignment->value);

			if (!name) {
				continue;
			}
			if (tunnel_kind(name, &kind)) {
				kind_seen = 1;
			} else {
				ncfg_diag(ctx, assignment->span,
				    "`%s` is not a tunnel mode: one of gre, gretap, ip6gre, ipip, sit, "
				    "ip6tnl, geneve", name);
				kind_seen = 0;
			}
			free(name);
		} else if (strcmp(key, "local") == 0) {
			free(config.local);
			config.local = lower_address_key(ctx, assignment->value);
		} else if (strcmp(key, "remote") == 0) {
			free(config.remote);
			config.remote = lower_address_key(ctx, assignment->value);
		} else if (strcmp(key, "parent") == 0 || strcmp(key, "dev") == 0) {
			free(config.parent);
			config.parent = ncfg_as_interface_name(ctx, assignment->value);
		} else if (strcmp(key, "ttl") == 0) {
			ncfg_as_narrow_opt(ctx, assignment->value, 255, &config.ttl);
		} else if (strcmp(key, "key") == 0 || strcmp(key, "vni") == 0) {
			ncfg_as_u32_opt(ctx, assignment->value, &config.key);
		} else {
			ncfg_diag(ctx, assignment->span, "unknown tunnel key `%s`", key);
		}
	}

	if (!kind_seen) {
		ncfg_diag(ctx, block->span,
		    "a tunnel needs a `mode`: one of gre, gretap, ip6gre, ipip, sit, ip6tnl, geneve");
		goto drop;
	}
	config.mode = kind;
	/*
	 * A geneve tunnel has no underlay device. There is no attribute for one in
	 * its netlink family and `ip` offers no `dev` for it either, so a `parent`
	 * here could only ever be dropped -- and it was, silently, until somebody
	 * asked the kernel what it does with one.
	 */
	if (kind == NCFG_TUNNEL_KIND_GENEVE && config.parent) {
		ncfg_diag(ctx, block->span,
		    "a `geneve` tunnel has no underlay interface, so `parent` means nothing to it: "
		    "remove `parent`; geneve sends its outer packets through the routing table");
		goto drop;
	}
	/* The endpoints have to agree with each other and with the encapsulation.
	 * A v6 remote on an `ipip` produces a link the kernel refuses to build,
	 * with an error naming neither. */
	for (end = 0; end < 2; end++) {
		const char *label = end ? "remote" : "local";
		const char *address = end ? config.remote : config.local;
		int         is_v6;

		if (!address) {
			continue;
		}
		is_v6 = strchr(address, ':') != NULL;
		if (is_v6 != tunnel_is_v6(kind)) {
			ncfg_diag(ctx, block->span,
			    "a `%s` tunnel carries an IPv%d outer header, and `%s` is IPv%d",
			    tunnel_name(kind), tunnel_is_v6(kind) ? 6 : 4, label, is_v6 ? 6 : 4);
			goto drop;
		}
	}
	out->kind = NCFG_KIND_TUNNEL;
	out->tunnel = config;
	return 1;

drop:
	free(config.local);
	free(config.remote);
	free(config.parent);
	return 0;
}

static void lower_tun(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block, int tap,
    ncfg_interface_kind_t *out)
{
	const ncfg_ast_item_t       *item;
	const ncfg_ast_assignment_t *assignment;
	size_t                       at;

	out->kind = NCFG_KIND_TUN;
	out->tun.mode = tap ? NCFG_TUN_MODE_TAP : NCFG_TUN_MODE_TUN;
	FOR_ASSIGNMENTS(block, item, assignment) {
		if (strcmp(assignment->key, "owner") == 0) {
			free(out->tun.owner);
			out->tun.owner = ncfg_as_string(ctx, assignment->value);
		} else if (strcmp(assignment->key, "group") == 0) {
			free(out->tun.group);
			out->tun.group = ncfg_as_string(ctx, assignment->value);
		} else {
			ncfg_diag(ctx, assignment->span, "unknown tun key `%s`", assignment->key);
		}
	}
}

/* ------------------------------------------------------------------------ *
 * wireguard
 * ------------------------------------------------------------------------ */

static void wg_peer_free(ncfg_wg_peer_t *peer)
{
	size_t i;

	free(peer->name);
	if (peer->preshared_key) {
		free(peer->preshared_key->name);
		free(peer->preshared_key);
	}
	free(peer->endpoint);
	for (i = 0; i < peer->allowed_ip_count; i++) {
		free(peer->allowed_ips[i]);
	}
	free(peer->allowed_ips);
	memset(peer, 0, sizeof(*peer));
}

static int lower_wg_peer(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_wg_peer_t *out)
{
	ncfg_wg_peer_t               peer;
	const ncfg_ast_item_t       *item;
	const ncfg_ast_assignment_t *assignment;
	size_t                       at;
	int                          key_seen = 0;

	memset(&peer, 0, sizeof(peer));
	peer.name = ncfg_require_label(ctx, block);
	if (!peer.name) {
		return 0;
	}
	FOR_ASSIGNMENTS(block, item, assignment) {
		const char *key = assignment->key;

		if (strcmp(key, "public_key") == 0) {
			char       *text = ncfg_as_string(ctx, assignment->value);
			const char *why = NULL;

			if (!text) {
				continue;
			}
			if (ncfg_public_key_parse(text, peer.public_key, &why)) {
				key_seen = 1;
			} else {
				ncfg_diag(ctx, assignment->value->span, "`%s` is not a public key: %s", text,
				    why);
			}
			free(text);
		} else if (strcmp(key, "preshared_key") == 0) {
			ncfg_secret_ref_t secret;

			memset(&secret, 0, sizeof(secret));
			if (!ncfg_as_secret(ctx, assignment->value, &secret)) {
				continue;
			}
			if (!peer.preshared_key) {
				peer.preshared_key = calloc(1, sizeof(*peer.preshared_key));
				if (!peer.preshared_key) {
					ncfg_lower_oom(ctx);
					free(secret.name);
					continue;
				}
			}
			free(peer.preshared_key->name);
			*peer.preshared_key = secret;
		} else if (strcmp(key, "endpoint") == 0) {
			free(peer.endpoint);
			peer.endpoint = ncfg_as_string(ctx, assignment->value);
		} else if (strcmp(key, "allowed_ips") == 0) {
			ncfg_words_t words;
			size_t       i;

			if (!ncfg_as_words(ctx, assignment->value, &words)) {
				ncfg_words_free(&words);
				continue;
			}
			for (i = 0; i < peer.allowed_ip_count; i++) {
				free(peer.allowed_ips[i]);
			}
			free(peer.allowed_ips);
			peer.allowed_ips = NULL;
			peer.allowed_ip_count = 0;
			for (i = 0; i < words.count; i++) {
				if (!ncfg_is_prefix(words.at[i].text)) {
					ncfg_diag(ctx, words.at[i].span, "`%s` is not a CIDR prefix",
					    words.at[i].text);
					continue;
				}
				(void)ncfg_push_string(ctx, &peer.allowed_ips, &peer.allowed_ip_count,
				    words.at[i].text);
			}
			ncfg_words_free(&words);
		} else if (strcmp(key, "keepalive") == 0) {
			ncfg_as_narrow_opt(ctx, assignment->value, 65535, &peer.keepalive);
		} else {
			ncfg_diag(ctx, assignment->span, "unknown peer key `%s`", key);
		}
	}

	if (!key_seen) {
		ncfg_diag(ctx, block->span, "peer `%s` needs a `public_key`", peer.name);
		wg_peer_free(&peer);
		return 0;
	}
	/* A peer with no allowed IPs receives nothing and is routed nothing. It is
	 * legal to the kernel and never what anybody meant. */
	if (peer.allowed_ip_count == 0) {
		ncfg_diag(ctx, block->span,
		    "peer `%s` has no `allowed_ips`, so nothing would route to it: "
		    "`allowed_ips = \"0.0.0.0/0\"` sends everything; a prefix sends some", peer.name);
		wg_peer_free(&peer);
		return 0;
	}
	*out = peer;
	return 1;
}

static int lower_wireguard(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_interface_kind_t *out)
{
	ncfg_wireguard_config_t config;
	size_t                  at;
	size_t                  i;
	size_t                  j;
	int                     key_seen = 0;

	memset(&config, 0, sizeof(config));
	for (at = 0; at < block->items.count; at++) {
		const ncfg_ast_item_t *item = block->items.at[at];

		if (item->kind == NCFG_AST_ITEM_ASSIGNMENT) {
			const ncfg_ast_assignment_t *assignment = &item->as.assignment;
			const char                  *key = assignment->key;

			if (strcmp(key, "private_key") == 0) {
				if (ncfg_as_secret(ctx, assignment->value, &config.private_key)) {
					key_seen = 1;
				}
			} else if (strcmp(key, "listen_port") == 0) {
				ncfg_as_narrow_opt(ctx, assignment->value, 65535, &config.listen_port);
			} else if (strcmp(key, "fwmark") == 0) {
				ncfg_as_u32_opt(ctx, assignment->value, &config.fwmark);
			} else {
				ncfg_diag(ctx, assignment->span, "unknown wireguard key `%s`", key);
			}
			continue;
		}
		if (item->kind != NCFG_AST_ITEM_BLOCK) {
			continue;
		}
		if (strcmp(item->as.block.head, "peer") == 0) {
			ncfg_wg_peer_t peer;

			if (!lower_wg_peer(ctx, &item->as.block, &peer)) {
				continue;
			}
			{
				ncfg_wg_peer_t *slot = ncfg_push(ctx, &config.peers, &config.peer_count,
				    sizeof(*slot));

				if (!slot) {
					wg_peer_free(&peer);
					break;
				}
				*slot = peer;
			}
			continue;
		}
		ncfg_diag(ctx, item->as.block.span, "`%s` is not valid inside `wireguard`",
		    item->as.block.head);
	}

	if (!key_seen) {
		ncfg_diag(ctx, block->span,
		    "a wireguard device needs a `private_key`: `private_key = \"@secret:NAME\"`; "
		    "`wg genkey` produces one and it never belongs in the config");
		goto drop;
	}
	/* Two peers with one public key is two halves of one entry: the key is the
	 * peer's identity, so the kernel would keep whichever came last and the
	 * other's allowed IPs would silently vanish. */
	for (i = 0; i < config.peer_count; i++) {
		for (j = 0; j < i; j++) {
			if (memcmp(config.peers[j].public_key, config.peers[i].public_key, 32u) != 0) {
				continue;
			}
			ncfg_diag(ctx, block->span,
			    "two peers share the public key of `%s`: a public key is a peer's identity; "
			    "merge the two blocks", config.peers[i].name);
			goto drop;
		}
	}
	out->kind = NCFG_KIND_WIREGUARD;
	out->wireguard = config;
	return 1;

drop:
	free(config.private_key.name);
	for (i = 0; i < config.peer_count; i++) {
		wg_peer_free(&config.peers[i]);
	}
	free(config.peers);
	return 0;
}

/* ------------------------------------------------------------------------ *
 * pppoe and openvpn
 * ------------------------------------------------------------------------ */

static int lower_pppoe(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_interface_kind_t *out)
{
	ncfg_pppoe_config_t          config;
	const ncfg_ast_item_t       *item;
	const ncfg_ast_assignment_t *assignment;
	size_t                       at;
	int                          password_seen = 0;

	memset(&config, 0, sizeof(config));
	FOR_ASSIGNMENTS(block, item, assignment) {
		const char *key = assignment->key;

		if (strcmp(key, "parent") == 0 || strcmp(key, "dev") == 0) {
			free(config.parent);
			config.parent = ncfg_as_interface_name(ctx, assignment->value);
		} else if (strcmp(key, "username") == 0 || strcmp(key, "user") == 0) {
			free(config.username);
			config.username = ncfg_as_string(ctx, assignment->value);
		} else if (strcmp(key, "password") == 0) {
			if (ncfg_as_secret(ctx, assignment->value, &config.password)) {
				password_seen = 1;
			}
		} else if (strcmp(key, "service") == 0) {
			free(config.service);
			config.service = ncfg_as_string(ctx, assignment->value);
		} else if (strcmp(key, "ac") == 0) {
			free(config.ac);
			config.ac = ncfg_as_string(ctx, assignment->value);
		} else {
			ncfg_diag(ctx, assignment->span, "unknown pppoe key `%s`", key);
		}
	}

	if (!config.parent) {
		ncfg_diag(ctx, block->span,
		    "a pppoe session needs a `parent`: the ethernet interface the session runs over, "
		    "such as `eth0`");
		goto drop;
	}
	if (!config.username || !password_seen) {
		ncfg_diag(ctx, block->span,
		    "a pppoe session needs a `username` and a `password`: "
		    "`password = \"@secret:NAME\"`; a DSL password never belongs in config");
		goto drop;
	}
	out->kind = NCFG_KIND_PPPOE;
	out->pppoe = config;
	return 1;

drop:
	free(config.parent);
	free(config.username);
	free(config.password.name);
	free(config.service);
	free(config.ac);
	return 0;
}

/*
 * An `openvpn { }` block, which is a path and nothing else.
 *
 * Deliberately one key. Decision 0046: `openvpn --help` lists 253 top-level
 * options, so netcfgd expressing the surface would be a second OpenVPN
 * configuration language permanently behind the first. Every option somebody
 * might want here already has a home in the `.ovpn`, and a second place to say
 * the same thing is how the two come to disagree.
 */
static int lower_openvpn(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_interface_kind_t *out)
{
	ncfg_openvpn_config_t        config;
	const ncfg_ast_item_t       *item;
	const ncfg_ast_assignment_t *assignment;
	size_t                       at;

	memset(&config, 0, sizeof(config));
	FOR_ASSIGNMENTS(block, item, assignment) {
		const char *key = assignment->key;

		if (strcmp(key, "config") == 0 || strcmp(key, "file") == 0) {
			free(config.config);
			config.config = ncfg_as_string(ctx, assignment->value);
		} else if (strcmp(key, "username") == 0 || strcmp(key, "user") == 0) {
			free(config.username);
			config.username = ncfg_as_string(ctx, assignment->value);
		} else if (strcmp(key, "password") == 0) {
			ncfg_secret_ref_t secret;

			memset(&secret, 0, sizeof(secret));
			if (!ncfg_as_secret(ctx, assignment->value, &secret)) {
				continue;
			}
			if (!config.password) {
				config.password = calloc(1, sizeof(*config.password));
				if (!config.password) {
					ncfg_lower_oom(ctx);
					free(secret.name);
					continue;
				}
			}
			free(config.password->name);
			*config.password = secret;
		} else {
			ncfg_diag(ctx, assignment->span,
			    "unknown openvpn key `%s`: an openvpn tunnel takes only `config`, the path "
			    "to the .ovpn file; everything else belongs in that file "
			    "(doc/decision/0046)", key);
		}
	}

	if (!config.config) {
		ncfg_diag(ctx, block->span,
		    "an openvpn tunnel needs a `config`: the path to the .ovpn file, such as "
		    "`/etc/openvpn/work.ovpn`; netcfgd hands it to openvpn and does not read it");
		goto drop;
	}
	/* Absolute, because netcfgd's working directory is not the operator's and
	 * a relative path here would resolve somewhere nobody chose. */
	if (config.config[0] != '/') {
		ncfg_diag(ctx, block->span,
		    "`%s` is not an absolute path: netcfgd runs from no particular directory, so the "
		    ".ovpn needs a full path", config.config);
		goto drop;
	}
	/* One without the other is a configuration that cannot work: OpenVPN
	 * prompts on the console for whatever is missing, and there is no console
	 * behind a daemon netcfgd started. */
	if ((config.username != NULL) != (config.password != NULL)) {
		ncfg_diag(ctx, block->span,
		    "an openvpn tunnel needs both `username` and `password`, or neither: openvpn "
		    "prompts on the console for whichever is missing, and a daemon netcfgd started "
		    "has no console to prompt on");
		goto drop;
	}
	out->kind = NCFG_KIND_OPENVPN;
	out->openvpn = config;
	return 1;

drop:
	free(config.config);
	free(config.username);
	if (config.password) {
		free(config.password->name);
		free(config.password);
	}
	return 0;
}

/* ------------------------------------------------------------------------ *
 * The dispatcher
 * ------------------------------------------------------------------------ */

int ncfg_is_kind_block(const char *head)
{
	static const char *const heads[] = { "bridge", "bond", "vlan", "veth", "vxlan", "vrf",
		"macvlan", "tunnel", "tun", "tap", "wireguard", "pppoe", "openvpn" };
	size_t i;

	for (i = 0; i < sizeof(heads) / sizeof(heads[0]); i++) {
		if (strcmp(heads[i], head) == 0) {
			return 1;
		}
	}
	return 0;
}

int ncfg_lower_kind_block(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *inner,
    ncfg_interface_kind_t *out)
{
	const char *head = inner->head;

	if (strcmp(head, "bridge") == 0) {
		lower_bridge(ctx, inner, out);
		return 1;
	}
	if (strcmp(head, "bond") == 0) {
		return lower_bond(ctx, inner, out);
	}
	if (strcmp(head, "vlan") == 0) {
		return lower_vlan(ctx, inner, out);
	}
	if (strcmp(head, "veth") == 0) {
		return lower_veth(ctx, inner, out);
	}
	if (strcmp(head, "vxlan") == 0) {
		return lower_vxlan(ctx, inner, out);
	}
	if (strcmp(head, "vrf") == 0) {
		return lower_vrf(ctx, inner, out);
	}
	if (strcmp(head, "macvlan") == 0) {
		return lower_macvlan(ctx, inner, out);
	}
	if (strcmp(head, "tunnel") == 0) {
		return lower_tunnel(ctx, inner, out);
	}
	if (strcmp(head, "tun") == 0 || strcmp(head, "tap") == 0) {
		lower_tun(ctx, inner, strcmp(head, "tap") == 0, out);
		return 1;
	}
	if (strcmp(head, "wireguard") == 0) {
		return lower_wireguard(ctx, inner, out);
	}
	if (strcmp(head, "pppoe") == 0) {
		return lower_pppoe(ctx, inner, out);
	}
	if (strcmp(head, "openvpn") == 0) {
		return lower_openvpn(ctx, inner, out);
	}
	return 0;
}
