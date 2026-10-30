/*
 * nat.c -- netcfgd's one nftables table, replaced whole.
 *
 * WHY THERE IS NO PER-RULE DIFF
 *   Decision 0022 gives netcfgd exactly one table and one thing to say with
 *   it: these interfaces are uplinks and traffic leaving them is
 *   masqueraded. So the comparison is between two sorted lists of interface
 *   names, and that is the entire diff -- there is no per-rule
 *   reconciliation because there is no per-rule change.
 *
 *   **That is the floor and not the scope.** 0022 also said netcfgd would
 *   never model which packets may pass; 0283 supersedes it on the holder's
 *   instruction -- filtering and queuing are netcfgd's, in full -- so this
 *   file's one-boolean diff is what exists today rather than what is
 *   intended, and a per-rule reconciliation is coming.
 *
 * THE TWO WARNINGS, AND WHY NEITHER IS A REFUSAL
 *   A second source-NAT chain translates the same packets twice, which breaks
 *   return paths in ways that look like packet loss. netcfgd will not delete
 *   somebody else's table -- it cannot evaluate the filtering in there -- so
 *   the operator is told and the operator decides. And NAT with nothing
 *   forwarded translates packets the kernel already dropped, which is a router
 *   that silently does nothing; both halves are set independently and that is
 *   the mistake worth naming.
 */
#include "plan_internal.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/nft.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int by_name(const void *left, const void *right)
{
	const char *const *one = left;
	const char *const *other = right;

	if (!*one || !*other) {
		return *one ? 1 : (*other ? -1 : 0);
	}
	return strcmp(*one, *other);
}

/* `eth0, wwan0`, or the word for having none, for a plan's reason line. */
static const char *describe(ncfg_plan_t *plan, const char *const *names, size_t count)
{
	ncfg_buf_t  buf;
	const char *text;
	size_t      i;

	if (count == 0u) {
		return "<none>";
	}
	ncfg_buf_init(&buf, 0);
	for (i = 0; i < count; i++) {
		ncfg_buf_addf(&buf, "%s%s", i ? ", " : "", names[i] ? names[i] : "");
	}
	text = ncfg_plan_intern(plan, ncfg_buf_text(&buf));
	ncfg_buf_free(&buf);
	return text ? text : "<none>";
}

/* Whether two name lists are the same list in the same order. */
static int same_uplinks(const char *const *left, size_t left_count, const char *const *right,
    size_t right_count)
{
	size_t i;

	if (left_count != right_count) {
		return 0;
	}
	for (i = 0; i < left_count; i++) {
		if (by_name(&left[i], &right[i]) != 0) {
			return 0;
		}
	}
	return 1;
}

static void warn_conflicts(ncfg_builder_t *builder, size_t wanted_count)
{
	const ncfg_observed_t *observed = builder->observed;
	ncfg_buf_t             buf;
	size_t                 i;

	/*
	 * Reported whenever netcfgd has an opinion about NAT, **including when its
	 * opinion is "none"** -- an operator who has just removed `nat` from their
	 * configuration is exactly the person who needs to know something else is
	 * still translating.
	 */
	if (observed->nat_conflict_count == 0u ||
	    (wanted_count == 0u && observed->nat_count == 0u)) {
		return;
	}
	ncfg_buf_init(&buf, 0);
	for (i = 0; i < observed->nat_conflict_count; i++) {
		ncfg_buf_addf(&buf, "%s%s", i ? "`, `" : "",
		    observed->nat_conflicts[i] ? observed->nat_conflicts[i] : "");
	}
	ncfg_plan_warnf(builder->plan, NULL,
	    "nftables table(s) `%s` also translate source addresses. Traffic matching both is "
	    "translated twice, which breaks return paths in ways that look like packet loss. "
	    "netcfgd will not delete another table -- it cannot tell what filtering is in there "
	    "-- so remove the duplicate rule yourself, or drop `nat` here.",
	    ncfg_buf_text(&buf));
	ncfg_buf_free(&buf);
}

/* ------------------------------------------------------------------------ *
 * The firewall half of the table (10.592)
 * ------------------------------------------------------------------------ */

static const char *policy_word(int policy)
{
	return policy == NCFG_FIREWALL_POLICY_DROP ? "drop" : "accept";
}

/* One word back to its enum, for the inverse. */
static int action_of(const char *word)
{
	if (word && strcmp(word, "drop") == 0) {
		return NCFG_FIREWALL_DROP;
	}
	if (word && strcmp(word, "reject") == 0) {
		return NCFG_FIREWALL_REJECT;
	}
	return NCFG_FIREWALL_ACCEPT;
}

static int protocol_of(const char *word)
{
	static const struct {
		const char *word;
		int         protocol;
	} words[] = { { "tcp", NCFG_FIREWALL_PROTO_TCP }, { "udp", NCFG_FIREWALL_PROTO_UDP },
		{ "icmp", NCFG_FIREWALL_PROTO_ICMP }, { "icmpv6", NCFG_FIREWALL_PROTO_ICMPV6 } };
	size_t at;

	for (at = 0; word && at < sizeof(words) / sizeof(words[0]); at++) {
		if (strcmp(word, words[at].word) == 0) {
			return words[at].protocol;
		}
	}
	return NCFG_FIREWALL_PROTO_ANY;
}

static int add_text(char ***list, size_t *count, const char *text)
{
	char **grown;
	size_t at;

	if (!text) {
		return 1;
	}
	for (at = 0; at < *count; at++) {
		if (strcmp((*list)[at], text) == 0) {
			return 1;
		}
	}
	grown = realloc(*list, (*count + 1u) * sizeof(**list));
	if (!grown) {
		return 0;
	}
	*list = grown;
	(*list)[*count] = strdup(text);
	if (!(*list)[*count]) {
		return 0;
	}
	(*count)++;
	return 1;
}

/*
 * The installed firewall as a document's, for the op's inverse: the rules of
 * one chain that share a name in a row are one written rule, each match the
 * values its kernel rules carried, in the order they first appear -- which is
 * the order the builder expanded them in. A rule the decoder refused is not
 * restorable and is not in it. NULL on out of memory.
 */
static ncfg_firewall_t *installed(const ncfg_observed_firewall_t *observed)
{
	ncfg_firewall_t       *firewall = calloc(1u, sizeof(*firewall));
	ncfg_firewall_chain_t *chains[3];
	const char            *names[3] = { "input", "forward", "output" };
	const char            *policies[3];
	size_t                 c;
	size_t                 at;

	if (!firewall) {
		return NULL;
	}
	chains[0] = &firewall->input;
	chains[1] = &firewall->forward;
	chains[2] = &firewall->output;
	policies[0] = observed->input;
	policies[1] = observed->forward;
	policies[2] = observed->output;
	for (c = 0; c < 3u; c++) {
		chains[c]->policy = policies[c] && strcmp(policies[c], "drop") == 0
		    ? NCFG_FIREWALL_POLICY_DROP : NCFG_FIREWALL_POLICY_ACCEPT;
	}
	for (at = 0; at < observed->rule_count; at++) {
		const ncfg_observed_firewall_rule_t *one = &observed->rules[at];
		ncfg_firewall_chain_t               *chain = NULL;
		ncfg_firewall_rule_t                *rule;

		for (c = 0; c < 3u; c++) {
			if (strcmp(one->chain, names[c]) == 0) {
				chain = chains[c];
			}
		}
		if (!chain) {
			continue;
		}
		if (chain->rule_count == 0u ||
		    strcmp(chain->rules[chain->rule_count - 1u].name, one->name) != 0) {
			ncfg_firewall_rule_t *grown = realloc(chain->rules,
			    (chain->rule_count + 1u) * sizeof(*chain->rules));

			if (!grown) {
				ncfg_firewall_free(firewall);
				return NULL;
			}
			chain->rules = grown;
			rule = &chain->rules[chain->rule_count++];
			memset(rule, 0, sizeof(*rule));
			rule->name = strdup(one->name);
			rule->action = action_of(one->action);
			rule->protocol = protocol_of(one->protocol);
			rule->interface = one->interface ? strdup(one->interface) : NULL;
			rule->out_interface = one->out_interface ? strdup(one->out_interface) : NULL;
			if (!rule->name || (one->interface && !rule->interface) ||
			    (one->out_interface && !rule->out_interface)) {
				ncfg_firewall_free(firewall);
				return NULL;
			}
			for (c = 0; c < one->state_count; c++) {
				if (!add_text(&rule->states, &rule->state_count, one->states[c])) {
					ncfg_firewall_free(firewall);
					return NULL;
				}
			}
		}
		rule = &chain->rules[chain->rule_count - 1u];
		if (one->port.has) {
			size_t p;
			int    seen = 0;

			for (p = 0; p < rule->port_count; p++) {
				seen = seen || rule->ports[p] == one->port.value;
			}
			if (!seen) {
				int64_t *grown = realloc(rule->ports, (rule->port_count + 1u) *
				    sizeof(*rule->ports));

				if (!grown) {
					ncfg_firewall_free(firewall);
					return NULL;
				}
				rule->ports = grown;
				rule->ports[rule->port_count++] = one->port.value;
			}
		}
		if (!add_text(&rule->from, &rule->from_count, one->from) ||
		    !add_text(&rule->to, &rule->to_count, one->to) ||
		    !add_text(&rule->mac, &rule->mac_count, one->mac)) {
			ncfg_firewall_free(firewall);
			return NULL;
		}
	}
	return firewall;
}

/* What the reason says about a firewall: each chain's policy and rule count. */
static const char *describe_firewall(ncfg_plan_t *plan, const char *input, size_t in_rules,
    const char *forward, size_t forward_rules, const char *output, size_t out_rules)
{
	ncfg_buf_t  buf;
	const char *text;

	ncfg_buf_init(&buf, 0);
	ncfg_buf_addf(&buf, "input %s, %zu rule(s); forward %s, %zu; output %s, %zu",
	    input ? input : "absent", in_rules, forward ? forward : "absent", forward_rules,
	    output ? output : "absent", out_rules);
	text = ncfg_plan_intern(plan, ncfg_buf_text(&buf));
	ncfg_buf_free(&buf);
	return text ? text : "<firewall>";
}

static size_t observed_in(const ncfg_observed_firewall_t *observed, const char *chain)
{
	size_t at;
	size_t count = 0;

	for (at = 0; observed && at < observed->rule_count; at++) {
		count += strcmp(observed->rules[at].chain, chain) == 0;
	}
	return count;
}

/* ------------------------------------------------------------------------ *
 * Port forwards (0298)
 * ------------------------------------------------------------------------ */

/* A bare IPv4 address out of a CIDR, interned in the plan; NULL for one that
 * is not IPv4. */
static const char *bare_ipv4(ncfg_plan_t *plan, const char *cidr)
{
	ncfg_address_t address;
	char           text[NCFG_ADDRESS_MAX];

	if (!cidr || !ncfg_address_parse(cidr, &address, NULL, 0) || address.is_ipv6) {
		return NULL;
	}
	(void)snprintf(text, sizeof(text), "%u.%u.%u.%u", address.bytes[0], address.bytes[1],
	    address.bytes[2], address.bytes[3]);
	return ncfg_plan_intern(plan, text);
}

/*
 * The interface whose static IPv4 network holds `host`, and that network as a
 * CIDR, interned: where a return path for a hairpinned connection leaves
 * (0299). 0 where no interface in the document holds it.
 */
static int network_of(ncfg_plan_t *plan, const ncfg_document_t *desired, const char *host,
    const char **via, const char **network)
{
	ncfg_address_t target;
	size_t         i;
	size_t         at;

	if (!host || !ncfg_address_parse(host, &target, NULL, 0) || target.is_ipv6) {
		return 0;
	}
	for (i = 0; i < desired->interface_count; i++) {
		const ncfg_interface_t *interface = &desired->interfaces[i];

		for (at = 0; at < interface->addressing_count; at++) {
			const ncfg_address_source_t *source = &interface->addressing[at];
			ncfg_address_t               own;
			uint32_t                     mask;
			uint32_t                     mine;
			uint32_t                     theirs;
			char                         text[NCFG_ADDRESS_MAX];

			if (source->kind != NCFG_ADDRESS_SOURCE_STATIC || !source->static_address.address ||
			    !ncfg_address_parse(source->static_address.address, &own, NULL, 0) ||
			    own.is_ipv6 || !own.has_prefix || own.prefix == 0u || own.prefix > 30u) {
				continue;
			}
			mask = 0xffffffffu << (32u - own.prefix);
			mine = ((uint32_t)own.bytes[0] << 24) | ((uint32_t)own.bytes[1] << 16) |
			    ((uint32_t)own.bytes[2] << 8) | own.bytes[3];
			theirs = ((uint32_t)target.bytes[0] << 24) | ((uint32_t)target.bytes[1] << 16) |
			    ((uint32_t)target.bytes[2] << 8) | target.bytes[3];
			if ((mine & mask) != (theirs & mask)) {
				continue;
			}
			mine &= mask;
			(void)snprintf(text, sizeof(text), "%u.%u.%u.%u/%u", (unsigned)(mine >> 24),
			    (unsigned)(mine >> 16) & 255u, (unsigned)(mine >> 8) & 255u,
			    (unsigned)mine & 255u, own.prefix);
			*via = interface->name;
			*network = ncfg_plan_intern(plan, text);
			return *network != NULL;
		}
	}
	return 0;
}

/* Append one rule to a growing list. 0 on out of memory. */
static int add_rule(ncfg_forward_rule_t **rules, size_t *count, size_t *room,
    const ncfg_forward_rule_t *rule)
{
	if (*count == *room) {
		size_t               more = *room ? *room * 2u : 8u;
		ncfg_forward_rule_t *grown = realloc(*rules, more * sizeof(*grown));

		if (!grown) {
			return 0;
		}
		*rules = grown;
		*room = more;
	}
	(*rules)[(*count)++] = *rule;
	return 1;
}

static int text_order(const char *one, const char *other)
{
	return strcmp(one ? one : "", other ? other : "");
}

/* The order both sides are compared in: by forward, then kind, then what
 * tells two of one kind apart. The kernel's order is per chain, which is not
 * the document's, so neither side's order is the comparison's. */
static int rule_order(const void *left, const void *right)
{
	const ncfg_forward_rule_t *one = left;
	const ncfg_forward_rule_t *other = right;
	int                        by;

	if ((by = text_order(one->interface, other->interface)) != 0 ||
	    (by = text_order(one->name, other->name)) != 0) {
		return by;
	}
	if (one->kind != other->kind) {
		return one->kind < other->kind ? -1 : 1;
	}
	if ((by = text_order(one->address, other->address)) != 0) {
		return by;
	}
	return text_order(one->network, other->network);
}

/*
 * The kernel rules the document's forwards become (0298, 0299): each forward,
 * its reflection at every IPv4 address the uplink has -- the document's static
 * ones and the observed ones, a lease's included -- and the return path where
 * an interface holds the host's network, unless the forward says `hairpin =
 * false`. Sorted by `rule_order`. Strings borrowed from the document or
 * interned in the plan; the array is the caller's.
 */
static ncfg_forward_rule_t *wanted_forwards(ncfg_builder_t *builder, size_t *count, int *failed)
{
	const ncfg_document_t *desired = builder->desired;
	const ncfg_observed_t *observed = builder->observed;
	ncfg_forward_rule_t   *rules = NULL;
	size_t                 room = 0;
	size_t                 i;
	size_t                 at;

	*count = 0;
	for (i = 0; i < desired->interface_count; i++) {
		const ncfg_interface_t *interface = &desired->interfaces[i];

		for (at = 0; at < interface->port_forward_count; at++) {
			const ncfg_port_forward_t *forward = &interface->port_forwards[at];
			ncfg_forward_rule_t        rule;
			const char                *via = NULL;
			const char                *network = NULL;
			size_t                     a;

			memset(&rule, 0, sizeof(rule));
			rule.kind = NCFG_FORWARD_RULE_FORWARD;
			rule.interface = interface->name;
			rule.name = forward->name;
			rule.protocol = forward->protocol;
			rule.port = (uint16_t)forward->port;
			rule.to = forward->to;
			rule.to_port = (uint16_t)(forward->to_port.has ? forward->to_port.value
			                                               : forward->port);
			if (!add_rule(&rules, count, &room, &rule)) {
				goto oom;
			}
			if (forward->hairpin.has && !forward->hairpin.value) {
				continue;
			}
			rule.kind = NCFG_FORWARD_RULE_REFLECT;
			for (a = 0; a < interface->addressing_count; a++) {
				const ncfg_address_source_t *source = &interface->addressing[a];

				if (source->kind == NCFG_ADDRESS_SOURCE_STATIC &&
				    (rule.address = bare_ipv4(builder->plan, source->static_address.address)) &&
				    !add_rule(&rules, count, &room, &rule)) {
					goto oom;
				}
			}
			for (a = 0; a < observed->address_count; a++) {
				const ncfg_observed_address_t *seen = &observed->addresses[a];

				if (seen->interface && strcmp(seen->interface, interface->name) == 0 &&
				    (rule.address = bare_ipv4(builder->plan, seen->address)) &&
				    !add_rule(&rules, count, &room, &rule)) {
					goto oom;
				}
			}
			rule.address = NULL;
			if (network_of(builder->plan, desired, forward->to, &via, &network)) {
				rule.kind = NCFG_FORWARD_RULE_HAIRPIN;
				rule.port = rule.to_port;
				rule.network = network;
				rule.via = via;
				if (!add_rule(&rules, count, &room, &rule)) {
					goto oom;
				}
			}
		}
	}
	if (*count > 1u) {
		size_t kept = 1;

		qsort(rules, *count, sizeof(*rules), rule_order);
		/* A static address is observed once it is applied, so it arrives from
		 * both sides: one reflection per address. */
		for (at = 1; at < *count; at++) {
			if (rule_order(&rules[at], &rules[kept - 1u]) != 0) {
				rules[kept++] = rules[at];
			}
		}
		*count = kept;
	}
	return rules;
oom:
	free(rules);
	*count = 0;
	*failed = 1;
	return NULL;
}

/* The installed rules as the op's inverse and the comparison want them,
 * borrowing the observation's strings, sorted by `rule_order`. */
static ncfg_forward_rule_t *installed_forwards(const ncfg_observed_t *observed, int *failed)
{
	ncfg_forward_rule_t *rules;
	size_t               at;

	if (observed->port_forward_count == 0u) {
		return NULL;
	}
	rules = calloc(observed->port_forward_count, sizeof(*rules));
	if (!rules) {
		*failed = 1;
		return NULL;
	}
	for (at = 0; at < observed->port_forward_count; at++) {
		const ncfg_observed_forward_t *seen = &observed->port_forwards[at];

		rules[at].kind = seen->kind && strcmp(seen->kind, "reflect") == 0
		    ? NCFG_FORWARD_RULE_REFLECT
		    : seen->kind && strcmp(seen->kind, "hairpin") == 0 ? NCFG_FORWARD_RULE_HAIRPIN
		                                                       : NCFG_FORWARD_RULE_FORWARD;
		rules[at].interface = seen->interface;
		rules[at].name = seen->name;
		rules[at].protocol = seen->protocol && strcmp(seen->protocol, "udp") == 0
		    ? NCFG_PORT_FORWARD_UDP : NCFG_PORT_FORWARD_TCP;
		rules[at].port = (uint16_t)seen->port;
		rules[at].to = seen->to;
		rules[at].to_port = (uint16_t)seen->to_port;
		rules[at].address = seen->address;
		rules[at].network = seen->network;
		rules[at].via = seen->via;
	}
	qsort(rules, observed->port_forward_count, sizeof(*rules), rule_order);
	return rules;
}

/* Whether the installed rules are the document's, with nothing the decoder
 * refused beside them. Both sorted by `rule_order`. */
static int same_forwards(const ncfg_forward_rule_t *wanted, size_t count,
    const ncfg_forward_rule_t *installed, const ncfg_observed_t *observed)
{
	size_t at;

	if (observed->port_forward_unread_count != 0u || observed->port_forward_count != count) {
		return 0;
	}
	for (at = 0; at < count; at++) {
		if (rule_order(&wanted[at], &installed[at]) != 0 ||
		    wanted[at].protocol != installed[at].protocol ||
		    wanted[at].port != installed[at].port || wanted[at].to_port != installed[at].to_port ||
		    text_order(wanted[at].to, installed[at].to) != 0 ||
		    text_order(wanted[at].via, installed[at].via) != 0) {
			return 0;
		}
	}
	return 1;
}

/* `wan0/web tcp 443 -> 192.168.1.10:8443, reflected at 203.0.113.1, hairpin
 * via lan0; ...`, for a plan's reason line. */
static const char *describe_forwards(ncfg_plan_t *plan, const ncfg_forward_rule_t *rules,
    size_t count)
{
	ncfg_buf_t  buf;
	const char *text;
	size_t      at;
	int         first = 1;

	if (count == 0u) {
		return "<none>";
	}
	ncfg_buf_init(&buf, 0);
	for (at = 0; at < count; at++) {
		const ncfg_forward_rule_t *rule = &rules[at];

		if (rule->kind == NCFG_FORWARD_RULE_FORWARD) {
			ncfg_buf_addf(&buf, "%s%s/%s %s %u -> %s:%u", first ? "" : "; ",
			    rule->interface ? rule->interface : "", rule->name ? rule->name : "",
			    rule->protocol == NCFG_PORT_FORWARD_UDP ? "udp" : "tcp", (unsigned)rule->port,
			    rule->to ? rule->to : "", (unsigned)rule->to_port);
			first = 0;
		} else if (rule->kind == NCFG_FORWARD_RULE_REFLECT) {
			ncfg_buf_addf(&buf, ", reflected at %s", rule->address ? rule->address : "");
		} else {
			ncfg_buf_addf(&buf, ", hairpin via %s", rule->via ? rule->via : "");
		}
	}
	text = ncfg_plan_intern(plan, ncfg_buf_text(&buf));
	ncfg_buf_free(&buf);
	return text ? text : "<port forwards>";
}

/*
 * What a forward needs that the forward itself does not set (0298), said
 * before the apply: IPv4 forwards by the setting of the interface a packet
 * arrives on, and a forward chain that drops by default drops the translated
 * traffic like any other unless a rule accepts it.
 */
static void warn_forwards(ncfg_builder_t *builder)
{
	const ncfg_document_t *desired = builder->desired;
	size_t                 i;
	size_t                 at;

	for (i = 0; i < desired->interface_count; i++) {
		const ncfg_interface_t *interface = &desired->interfaces[i];

		if (interface->port_forward_count == 0u) {
			continue;
		}
		if (!interface->forwarding.has || !interface->forwarding.value) {
			ncfg_plan_warnf(builder->plan, interface->name,
			    "`%s` forwards ports but does not have `forwarding = true`: IPv4 forwards a "
			    "packet by the setting of the interface it arrives on, so the translated "
			    "traffic would be dropped there. Set it on `%s`", interface->name,
			    interface->name);
		}
		/* 0299: a reflected forward whose host is on no network the document
		 * holds has no return path to write, so a client beside the host is
		 * answered from the wrong address. */
		for (at = 0; at < interface->port_forward_count; at++) {
			const ncfg_port_forward_t *forward = &interface->port_forwards[at];
			const char                *via = NULL;
			const char                *network = NULL;

			if ((!forward->hairpin.has || forward->hairpin.value) &&
			    !network_of(builder->plan, desired, forward->to, &via, &network)) {
				ncfg_plan_warnf(builder->plan, interface->name,
				    "port forward `%s/%s` is reflected for clients inside, but no interface "
				    "here has a static address on %s's network, so there is no return path "
				    "and a client beside that host is answered from the wrong address. Give "
				    "the interface towards it a static address, or set `hairpin = false`",
				    interface->name, forward->name, forward->to);
			}
		}
		if (!desired->firewall || desired->firewall->forward.policy != NCFG_FIREWALL_POLICY_DROP) {
			continue;
		}
		for (at = 0; at < interface->port_forward_count; at++) {
			const ncfg_port_forward_t   *forward = &interface->port_forwards[at];
			const ncfg_firewall_chain_t *chain = &desired->firewall->forward;
			int                          accepted = 0;
			size_t                       r;
			size_t                       t;

			for (r = 0; !accepted && r < chain->rule_count; r++) {
				if (chain->rules[r].action != NCFG_FIREWALL_ACCEPT) {
					continue;
				}
				for (t = 0; t < chain->rules[r].to_count; t++) {
					accepted = accepted || strcmp(chain->rules[r].to[t], forward->to) == 0;
				}
			}
			if (!accepted) {
				ncfg_plan_warnf(builder->plan, interface->name,
				    "port forward `%s/%s` sends to %s, and the firewall's forward chain drops "
				    "by default with no accept rule naming that address, so the translated "
				    "traffic is dropped. Add `accept \"%s\" { protocol = \"%s\"; port = "
				    "[%lld]; to = [\"%s\"] }` to `forward`", interface->name, forward->name,
				    forward->to, forward->name,
				    forward->protocol == NCFG_PORT_FORWARD_UDP ? "udp" : "tcp",
				    (long long)(forward->to_port.has ? forward->to_port.value : forward->port),
				    forward->to);
			}
		}
	}
}

void ncfg_plan_nat(ncfg_builder_t *builder)
{
	const ncfg_document_t *desired = builder->desired;
	const char           **wanted;
	size_t                 count = 0;
	int                    forwarding = 0;
	ncfg_op_t              op;
	ncfg_op_t              inverse;
	ncfg_reason_t          reason;
	ncfg_firewall_t       *was = NULL;
	char                   refusal[NCFG_ERROR_MAX];
	int                    uplinks_same;
	int                    firewall_same;
	int                    forwards_same;
	ncfg_forward_rule_t   *forwards;
	ncfg_forward_rule_t   *forwards_was;
	size_t                 forward_count = 0;
	int                    failed = 0;
	size_t                 i;

	if (desired->interface_count != 0u) {
		wanted = calloc(desired->interface_count, sizeof(*wanted));
		if (!wanted) {
			builder->plan->failed = 1;
			return;
		}
	} else {
		wanted = NULL;
	}
	for (i = 0; i < desired->interface_count; i++) {
		const ncfg_interface_t *interface = &desired->interfaces[i];

		if (interface->nat.has && interface->nat.value) {
			wanted[count++] = interface->name;
		}
		if (interface->forwarding.has && interface->forwarding.value) {
			forwarding = 1;
		}
	}
	if (count != 0u) {
		qsort(wanted, count, sizeof(*wanted), by_name);
	}

	warn_conflicts(builder, count);
	/*
	 * Forwarding is what makes NAT do anything, and the two are set
	 * independently, so this is the mistake that produces a router which
	 * translates nothing because nothing was forwarded to it.
	 */
	if (count != 0u && !forwarding) {
		ncfg_plan_warn(builder->plan, NULL,
		    "`nat` is set but no interface has `forwarding = true`, so nothing will "
		    "reach the translation. Set it on the interface the traffic arrives on -- "
		    "the LAN side, not the uplink.");
	}

	warn_forwards(builder);
	forwards = wanted_forwards(builder, &forward_count, &failed);
	forwards_was = installed_forwards(builder->observed, &failed);
	if (failed) {
		builder->plan->failed = 1;
		free(forwards_was);
		free(forwards);
		free(wanted);
		return;
	}
	forwards_same = same_forwards(forwards, forward_count, forwards_was, builder->observed);
	uplinks_same = same_uplinks((const char *const *)wanted, count,
	    (const char *const *)builder->observed->nat, builder->observed->nat_count);
	firewall_same = ncfg_nft_firewall_matches(desired->firewall, builder->observed->firewall,
	    refusal, sizeof(refusal));
	if (refusal[0] != '\0') {
		ncfg_plan_warnf(builder->plan, NULL,
		    "the firewall cannot be written to nftables: %s. The table is replaced in one "
		    "transaction, so applying this changes neither the firewall nor NAT until it is "
		    "fixed", refusal);
	}
	/* 0294: another table's filter chain at netcfgd's hooks sees every packet
	 * too, and the strictest verdict wins -- so a `drop` here can drop what a
	 * container runtime forwards. Said before the apply, and not fought. */
	if (desired->firewall && builder->observed->filter_neighbour_count) {
		ncfg_buf_t buf;

		ncfg_buf_init(&buf, 0);
		for (i = 0; i < builder->observed->filter_neighbour_count; i++) {
			ncfg_buf_addf(&buf, "%s%s", i ? "`, `" : "", builder->observed->filter_neighbours[i]);
		}
		ncfg_plan_warnf(builder->plan, NULL,
		    "other nftables tables filter at the firewall's hooks too: `%s`. Both see "
		    "every packet and the strictest verdict wins, so a `drop` in netcfgd's firewall "
		    "can drop traffic those tables accept -- a container runtime's forwarding, for "
		    "one. netcfgd does not touch them", ncfg_buf_text(&buf));
		ncfg_buf_free(&buf);
	}
	if (uplinks_same && firewall_same && forwards_same) {
		free(forwards_was);
		free(forwards);
		free(wanted);
		return;
	}
	/*
	 * **A firewall change can cut the connection it is applied over** -- an
	 * `input` that drops the operator's ssh -- and 10.546 is the holder's
	 * word that the control path is part of what is configured. A confirm
	 * window is what brings a machine back from that, so a change with none
	 * says so before it runs rather than after the machine is out of reach.
	 */
	if (!firewall_same && desired->firewall &&
	    !ncfg_plan_confirm_window(desired, builder->options).has) {
		ncfg_plan_warn(builder->plan, NULL,
		    "this changes the firewall with no confirm window armed: a rule or policy that "
		    "drops the connection this is applied over would leave the machine out of reach "
		    "with nothing to put it back. Apply with `--confirm-within 60`, or set "
		    "`global { confirm = 60 }` so every change carries one");
	}
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_NFTABLES_REPLACE;
	op.u.nftables.uplinks = (const char *const *)wanted;
	op.u.nftables.uplink_count = count;
	op.u.nftables.firewall = desired->firewall;
	op.u.nftables.forwards = forwards;
	op.u.nftables.forward_count = forward_count;
	memset(&inverse, 0, sizeof(inverse));
	inverse.kind = NCFG_OP_NFTABLES_REPLACE;
	/* The table as it stands, which is a real revert rather than a guess: an
	 * empty list and no firewall removes the table, and that is what a
	 * machine with no table had. The firewall is the installed one put back
	 * together, so undoing this op does not leave the host unprotected. */
	inverse.u.nftables.uplinks = (const char *const *)builder->observed->nat;
	inverse.u.nftables.uplink_count = builder->observed->nat_count;
	inverse.u.nftables.forwards = forwards_was;
	inverse.u.nftables.forward_count = forwards_was ? builder->observed->port_forward_count : 0u;
	if (builder->observed->firewall) {
		was = installed(builder->observed->firewall);
		if (!was) {
			failed = 1;
		}
	}
	if (failed) {
		builder->plan->failed = 1;
		ncfg_firewall_free(was);
		free(forwards_was);
		free(forwards);
		free(wanted);
		return;
	}
	inverse.u.nftables.firewall = was;
	if (uplinks_same && firewall_same) {
		reason = ncfg_plan_reason_differs(NULL, "port_forwards",
		    describe_forwards(builder->plan, forwards, forward_count),
		    describe_forwards(builder->plan, forwards_was, inverse.u.nftables.forward_count));
	} else if (!uplinks_same) {
		reason = ncfg_plan_reason_differs(NULL, "nat",
		    describe(builder->plan, (const char *const *)wanted, count),
		    describe(builder->plan, (const char *const *)builder->observed->nat,
		        builder->observed->nat_count));
	} else {
		const ncfg_firewall_t          *fw = desired->firewall;
		const ncfg_observed_firewall_t *seen = builder->observed->firewall;

		reason = ncfg_plan_reason_differs(NULL, "firewall",
		    fw ? describe_firewall(builder->plan, policy_word(fw->input.policy),
		        fw->input.rule_count, policy_word(fw->forward.policy), fw->forward.rule_count,
		        policy_word(fw->output.policy), fw->output.rule_count) : "<none>",
		    seen ? describe_firewall(builder->plan, seen->input, observed_in(seen, "input"),
		        seen->forward, observed_in(seen, "forward"), seen->output,
		        observed_in(seen, "output")) : "<none>");
	}
	(void)ncfg_builder_push(builder, &op, &reason, NULL, 0, &inverse);
	/* `ncfg_plan_add` copies the list and the firewall into the plan, so these
	 * are the caller's to give back -- the same bargain every string an op
	 * names is under. */
	ncfg_firewall_free(was);
	free(forwards_was);
	free(forwards);
	free(wanted);
}
