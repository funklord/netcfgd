/*
 * model_json.c -- the model values a plan embeds, written the way the model
 * writes them.
 *
 * A `route.add` carries a whole `Route`, a `rule.add` a whole `RoutingRule`, a
 * `link.create` an `InterfaceKind`, a `dns.apply` a `DnsPolicy` and a
 * `wg.set_peers` a list of peers. Each has to appear on the wire exactly as
 * `ncfg_document_write` would write it, or a client reading a plan and a client
 * reading a document would need two readers for one type.
 *
 * `plan_internal.h` says why this is a second copy rather than a call into the
 * model, and names the test that stops the two drifting.
 *
 * WHAT "EXACTLY" MEANS HERE
 *   Member order is declaration order, an absent optional member is written
 *   not at all rather than as null, and a list is always written even when it
 *   is empty -- those are serde's rules as the model's tables spell them, and
 *   the last one is the one that looks wrong: `"domains": []` stays because a
 *   document that has always written it goes on writing it, and an upgrade
 *   must not look like a configuration change.
 */
#include "plan_internal.h"

#include "ncfg/json_write.h"
#include "ncfg/value.h"

#include <stddef.h>

/* ------------------------------------------------------------------------ *
 * The word sets
 * ------------------------------------------------------------------------ */

/*
 * The sets neither `value.h` nor `document.h` publishes a name for.
 *
 * Every other closed set in this file is asked of the module that owns it --
 * `ncfg_interface_kind_name`, `ncfg_dns_mode_name`, `ncfg_backend_kind_name`,
 * `ncfg_hook_phase_name`, `ncfg_rule_action_name`, `ncfg_rule_family_name`.
 * A second table for a set somebody else owns is how this project twice
 * compiled a block whose feature was silently missing, so there are no tables
 * here that could be asked for instead.
 */
static const char *const secret_provider_words[] = { "file", "keyring", "pass", "exec" };
static const char *const route_scope_words[] = { "global", "link", "host" };
static const char *const dnssec_words[] = { "no", "allow", "yes" };
static const char *const dns_transport_words[] = { "plain", "tls", "https" };
static const char *const vlan_protocol_words[] = { "dot1q", "dot1ad" };
/* `iproute2`'s spellings, and the one set here that is neither snake nor kebab
 * all through: `802.3ad` is what every piece of bonding documentation calls
 * LACP, and a tidier word would be a bond the kernel refuses. */
static const char *const bond_mode_words[] = { "balance-rr", "active-backup", "balance-xor",
	"broadcast", "802.3ad", "balance-tlb", "balance-alb" };
static const char *const macvlan_mode_words[] = { "private", "vepa", "bridge", "passthru" };
static const char *const tunnel_kind_words[] = { "gre", "gretap", "ip6gre", "ipip", "sit",
	"ip6tnl", "geneve" };
static const char *const tun_mode_words[] = { "tun", "tap" };
static const char *const acl_policy_words[] = { "deny", "allow" };
/* The kernel's own scheduler names, which is why a `qdisc.set` carries the
 * word rather than the number: `tc` and `/proc/net` both spell them this
 * way, and the executor sends `IFLA_INFO_KIND` as text. */
static const char *const qdisc_kind_words[] = { "fq_codel", "cake", "fq", "pfifo_fast",
	"noqueue" };

#define COUNT(array) (sizeof(array) / sizeof((array)[0]))

static const char *word_of(const char *const *words, size_t count, int value)
{
	if (value < 0 || (size_t)value >= count) {
		return NULL;
	}
	return words[(size_t)value];
}

const char *ncfg_plan_acl_policy_word(int policy)
{
	return word_of(acl_policy_words, COUNT(acl_policy_words), policy);
}

/*
 * Three more of this file's sets, read rather than written.
 *
 * They are here rather than in the passes that compare against them for the
 * reason the paragraph above gives: a second table for a set somebody else
 * owns is how this project twice compiled a block whose feature was silently
 * missing. The planner's kind passes compare a document's mode against the
 * observer's word for the kernel's, and the qdisc pass puts the document's
 * scheduler in an op as a string -- so all three need the word and none of
 * them may spell it.
 */
const char *ncfg_plan_bond_mode_word(int mode)
{
	return word_of(bond_mode_words, COUNT(bond_mode_words), mode);
}

const char *ncfg_plan_macvlan_mode_word(int mode)
{
	return word_of(macvlan_mode_words, COUNT(macvlan_mode_words), mode);
}

const char *ncfg_plan_qdisc_kind_word(int kind)
{
	return word_of(qdisc_kind_words, COUNT(qdisc_kind_words), kind);
}

/* ------------------------------------------------------------------------ *
 * The pieces every writer here needs
 * ------------------------------------------------------------------------ */

/* A string member, written only where there is one. An absent optional member
 * and a member whose value is the empty string are different answers. */
static void member_text(ncfg_json_writer_t *writer, const char *name, const char *text)
{
	if (text) {
		ncfg_json_write_member_string(writer, name, text);
	}
}

static void member_optint(ncfg_json_writer_t *writer, const char *name, ncfg_optint_t value)
{
	if (value.has) {
		ncfg_json_write_member_int(writer, name, value.value);
	}
}

static void member_optenum(ncfg_json_writer_t *writer, const char *name, ncfg_optint_t value,
    const char *const *words, size_t count)
{
	const char *word;

	if (!value.has) {
		return;
	}
	word = word_of(words, count, (int)value.value);
	if (word) {
		ncfg_json_write_member_string(writer, name, word);
	}
}

static void member_enum(ncfg_json_writer_t *writer, const char *name, int value,
    const char *const *words, size_t count)
{
	const char *word = word_of(words, count, value);

	if (word) {
		ncfg_json_write_member_string(writer, name, word);
	}
}

static void member_strings(ncfg_json_writer_t *writer, const char *name, char *const *list,
    size_t count)
{
	size_t i;

	ncfg_json_write_key(writer, name);
	ncfg_json_write_array_begin(writer);
	for (i = 0; i < count; i++) {
		ncfg_json_write_string(writer, list[i]);
	}
	ncfg_json_write_array_end(writer);
}


static void write_key(ncfg_json_writer_t *writer, const unsigned char *key)
{
	char text[NCFG_KEY_TEXT_SIZE];

	(void)ncfg_key_render(key, text, sizeof(text), NULL, 0);
	ncfg_json_write_string(writer, text);
}

static void write_secret_ref(ncfg_json_writer_t *writer, const ncfg_secret_ref_t *ref)
{
	ncfg_json_write_object_begin(writer);
	member_enum(writer, "provider", ref->provider, secret_provider_words,
	    COUNT(secret_provider_words));
	member_text(writer, "name", ref->name);
	ncfg_json_write_object_end(writer);
}

/* ------------------------------------------------------------------------ *
 * Route, rule, DNS policy, peer
 * ------------------------------------------------------------------------ */

void ncfg_plan_write_route(ncfg_json_writer_t *writer, const ncfg_route_t *route)
{
	ncfg_json_write_object_begin(writer);
	member_text(writer, "destination", route->destination);
	member_text(writer, "via", route->via);
	member_optint(writer, "metric", route->metric);
	member_optint(writer, "table", route->table);
	member_text(writer, "src", route->src);
	member_optenum(writer, "scope", route->scope, route_scope_words,
	    COUNT(route_scope_words));
	/* Always written: a plain `bool` in the model, and the ordering rule reads
	 * it, so a reader that had to guess would be guessing about whether a
	 * route waits for an address. */
	ncfg_json_write_member_bool(writer, "onlink", route->onlink);
	member_optint(writer, "proto", route->proto);
	ncfg_json_write_object_end(writer);
}

void ncfg_plan_write_rule(ncfg_json_writer_t *writer, const ncfg_routing_rule_t *rule)
{
	ncfg_json_write_object_begin(writer);
	member_text(writer, "id", rule->id);
	ncfg_json_write_member_int(writer, "priority", rule->priority);
	ncfg_json_write_member_string(writer, "family", ncfg_rule_family_name(rule->family));
	member_text(writer, "from", rule->from);
	member_text(writer, "to", rule->to);
	member_text(writer, "iif", rule->iif);
	member_text(writer, "oif", rule->oif);
	member_optint(writer, "fwmark", rule->fwmark);
	member_optint(writer, "fwmask", rule->fwmask);
	member_optint(writer, "table", rule->table);
	ncfg_json_write_member_string(writer, "action", ncfg_rule_action_name(rule->action));
	member_optint(writer, "suppress_prefixlength", rule->suppress_prefixlength);
	ncfg_json_write_member_bool(writer, "l3mdev", rule->l3mdev);
	ncfg_json_write_member_bool(writer, "invert", rule->invert);
	ncfg_json_write_object_end(writer);
}

/*
 * A DNS mode, which is a word except for `exec`.
 *
 * `exec` carries the command it runs, so it is the one arm serde writes as an
 * object -- `{"exec": "..."}` -- and a writer that spelled it as a bare word
 * would produce a policy with the command silently gone.
 */
static void write_dns_mode(ncfg_json_writer_t *writer, const ncfg_dns_mode_value_t *mode)
{
	const char *word;

	ncfg_json_write_key(writer, "mode");
	if (mode->mode == NCFG_DNS_MODE_EXEC) {
		ncfg_json_write_object_begin(writer);
		member_text(writer, "exec", mode->command);
		ncfg_json_write_object_end(writer);
		return;
	}
	word = ncfg_dns_mode_name(mode->mode);
	if (word) {
		ncfg_json_write_string(writer, word);
	}
}

void ncfg_plan_write_dns_policy(ncfg_json_writer_t *writer, const ncfg_dns_policy_t *policy)
{
	size_t i;

	ncfg_json_write_object_begin(writer);
	write_dns_mode(writer, &policy->mode);

	ncfg_json_write_key(writer, "servers");
	ncfg_json_write_array_begin(writer);
	for (i = 0; i < policy->server_count; i++) {
		ncfg_json_write_object_begin(writer);
		member_text(writer, "addr", policy->servers[i].addr);
		member_optint(writer, "port", policy->servers[i].port);
		member_text(writer, "sni", policy->servers[i].sni);
		ncfg_json_write_object_end(writer);
	}
	ncfg_json_write_array_end(writer);

	member_strings(writer, "search", policy->search, policy->search_count);

	ncfg_json_write_key(writer, "domains");
	ncfg_json_write_array_begin(writer);
	for (i = 0; i < policy->domain_count; i++) {
		ncfg_json_write_object_begin(writer);
		member_text(writer, "suffix", policy->domains[i].suffix);
		ncfg_json_write_member_bool(writer, "exclusive", policy->domains[i].exclusive);
		ncfg_json_write_object_end(writer);
	}
	ncfg_json_write_array_end(writer);

	member_strings(writer, "options", policy->options, policy->option_count);
	member_optenum(writer, "dnssec", policy->dnssec, dnssec_words, COUNT(dnssec_words));
	member_optenum(writer, "transport", policy->transport, dns_transport_words,
	    COUNT(dns_transport_words));
	ncfg_json_write_object_end(writer);
}

void ncfg_plan_write_wg_peer(ncfg_json_writer_t *writer, const ncfg_wg_peer_t *peer)
{
	ncfg_json_write_object_begin(writer);
	member_text(writer, "name", peer->name);
	ncfg_json_write_key(writer, "public_key");
	write_key(writer, peer->public_key);
	if (peer->preshared_key) {
		ncfg_json_write_key(writer, "preshared_key");
		write_secret_ref(writer, peer->preshared_key);
	}
	member_text(writer, "endpoint", peer->endpoint);
	member_strings(writer, "allowed_ips", peer->allowed_ips, peer->allowed_ip_count);
	member_optint(writer, "keepalive", peer->keepalive);
	ncfg_json_write_object_end(writer);
}

/* ------------------------------------------------------------------------ *
 * The interface kind
 * ------------------------------------------------------------------------ */

/*
 * An internally tagged union: `kind` leads, the arm's members follow.
 *
 * Three of the fifteen carry nothing at all -- `physical`, `dummy` and `ifb` --
 * and writing them as a bare tag is what the model does. A reader that got an
 * object with no `kind` could not tell which arm it was holding, so the tag is
 * written even for the arms that have nothing to follow it.
 */
void ncfg_plan_write_interface_kind(ncfg_json_writer_t *writer, const ncfg_interface_kind_t *kind)
{
	const char *word = ncfg_interface_kind_name(kind->kind);
	size_t      i;

	ncfg_json_write_object_begin(writer);
	if (word) {
		ncfg_json_write_member_string(writer, "kind", word);
	}
	switch (kind->kind) {
	case NCFG_KIND_BRIDGE:
		member_strings(writer, "members", kind->bridge.members,
		    kind->bridge.member_count);
		ncfg_json_write_member_bool(writer, "stp", kind->bridge.stp);
		member_optint(writer, "forward_delay", kind->bridge.forward_delay);
		member_optint(writer, "hello_time", kind->bridge.hello_time);
		member_optint(writer, "ageing_time", kind->bridge.ageing_time);
		member_optint(writer, "priority", kind->bridge.priority);
		ncfg_json_write_member_bool(writer, "vlan_filtering",
		    kind->bridge.vlan_filtering);
		break;
	case NCFG_KIND_BOND:
		member_strings(writer, "members", kind->bond.members, kind->bond.member_count);
		member_enum(writer, "mode", kind->bond.mode, bond_mode_words,
		    COUNT(bond_mode_words));
		member_optint(writer, "miimon", kind->bond.miimon);
		break;
	case NCFG_KIND_VLAN:
		member_text(writer, "parent", kind->vlan.parent);
		ncfg_json_write_member_int(writer, "id", kind->vlan.id);
		member_enum(writer, "protocol", kind->vlan.protocol, vlan_protocol_words,
		    COUNT(vlan_protocol_words));
		break;
	case NCFG_KIND_VXLAN:
		ncfg_json_write_member_int(writer, "id", kind->vxlan.id);
		member_text(writer, "parent", kind->vxlan.parent);
		member_text(writer, "local", kind->vxlan.local);
		member_text(writer, "remote", kind->vxlan.remote);
		member_optint(writer, "port", kind->vxlan.port);
		break;
	case NCFG_KIND_WIREGUARD:
		ncfg_json_write_key(writer, "private_key");
		write_secret_ref(writer, &kind->wireguard.private_key);
		member_optint(writer, "listen_port", kind->wireguard.listen_port);
		member_optint(writer, "fwmark", kind->wireguard.fwmark);
		ncfg_json_write_key(writer, "peers");
		ncfg_json_write_array_begin(writer);
		for (i = 0; i < kind->wireguard.peer_count; i++) {
			ncfg_plan_write_wg_peer(writer, &kind->wireguard.peers[i]);
		}
		ncfg_json_write_array_end(writer);
		break;
	case NCFG_KIND_PPPOE:
		member_text(writer, "parent", kind->pppoe.parent);
		member_text(writer, "username", kind->pppoe.username);
		ncfg_json_write_key(writer, "password");
		write_secret_ref(writer, &kind->pppoe.password);
		member_text(writer, "service", kind->pppoe.service);
		member_text(writer, "ac", kind->pppoe.ac);
		break;
	case NCFG_KIND_OPENVPN:
		member_text(writer, "config", kind->openvpn.config);
		member_text(writer, "username", kind->openvpn.username);
		if (kind->openvpn.password) {
			ncfg_json_write_key(writer, "password");
			write_secret_ref(writer, kind->openvpn.password);
		}
		break;
	case NCFG_KIND_VETH:
		member_text(writer, "peer", kind->veth.peer);
		break;
	case NCFG_KIND_VRF:
		ncfg_json_write_member_int(writer, "table", kind->vrf.table);
		break;
	case NCFG_KIND_MACVLAN:
		member_text(writer, "parent", kind->macvlan.parent);
		member_enum(writer, "mode", kind->macvlan.mode, macvlan_mode_words,
		    COUNT(macvlan_mode_words));
		break;
	case NCFG_KIND_TUNNEL:
		member_enum(writer, "mode", kind->tunnel.mode, tunnel_kind_words,
		    COUNT(tunnel_kind_words));
		member_text(writer, "local", kind->tunnel.local);
		member_text(writer, "remote", kind->tunnel.remote);
		member_text(writer, "parent", kind->tunnel.parent);
		member_optint(writer, "ttl", kind->tunnel.ttl);
		member_optint(writer, "key", kind->tunnel.key);
		break;
	case NCFG_KIND_TUN:
		member_enum(writer, "mode", kind->tun.mode, tun_mode_words,
		    COUNT(tun_mode_words));
		member_text(writer, "owner", kind->tun.owner);
		member_text(writer, "group", kind->tun.group);
		break;
	case NCFG_KIND_PHYSICAL:
	case NCFG_KIND_DUMMY:
	case NCFG_KIND_IFB:
	default:
		break;
	}
	ncfg_json_write_object_end(writer);
}
