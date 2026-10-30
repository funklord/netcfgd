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
			if (!rule->name || (one->interface && !rule->interface)) {
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

/*
 * The document's forwards in the order the table writes them -- interfaces in
 * the document's order, each one's forwards by name -- with `to_port`
 * resolved. Borrowed strings; the array is the caller's. NULL with a count of
 * 0 where there are none, and on out of memory with `failed` set.
 */
static ncfg_forward_rule_t *wanted_forwards(const ncfg_document_t *desired, size_t *count,
    int *failed)
{
	ncfg_forward_rule_t *rules;
	size_t               total = 0;
	size_t               i;
	size_t               at;

	*count = 0;
	for (i = 0; i < desired->interface_count; i++) {
		total += desired->interfaces[i].port_forward_count;
	}
	if (total == 0u) {
		return NULL;
	}
	rules = calloc(total, sizeof(*rules));
	if (!rules) {
		*failed = 1;
		return NULL;
	}
	for (i = 0; i < desired->interface_count; i++) {
		const ncfg_interface_t *interface = &desired->interfaces[i];

		for (at = 0; at < interface->port_forward_count; at++) {
			const ncfg_port_forward_t *forward = &interface->port_forwards[at];
			ncfg_forward_rule_t       *rule = &rules[(*count)++];

			rule->interface = interface->name;
			rule->name = forward->name;
			rule->protocol = forward->protocol;
			rule->port = (uint16_t)forward->port;
			rule->to = forward->to;
			rule->to_port = (uint16_t)(forward->to_port.has ? forward->to_port.value
			                                                : forward->port);
		}
	}
	return rules;
}

/* Whether the installed forwards are the document's, in order, with nothing
 * the decoder refused beside them. */
static int same_forwards(const ncfg_forward_rule_t *wanted, size_t count,
    const ncfg_observed_t *observed)
{
	size_t at;

	if (observed->port_forward_unread_count != 0u || observed->port_forward_count != count) {
		return 0;
	}
	for (at = 0; at < count; at++) {
		const ncfg_observed_forward_t *seen = &observed->port_forwards[at];
		const char *protocol = wanted[at].protocol == NCFG_PORT_FORWARD_UDP ? "udp" : "tcp";

		if (!seen->interface || !seen->name || !seen->protocol || !seen->to ||
		    strcmp(seen->interface, wanted[at].interface) != 0 ||
		    strcmp(seen->name, wanted[at].name) != 0 || strcmp(seen->protocol, protocol) != 0 ||
		    seen->port != wanted[at].port || strcmp(seen->to, wanted[at].to) != 0 ||
		    seen->to_port != wanted[at].to_port) {
			return 0;
		}
	}
	return 1;
}

/* The installed forwards as the op's inverse wants them, borrowing the
 * observation's strings. NULL with a count of 0 where there are none. */
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

		rules[at].interface = seen->interface;
		rules[at].name = seen->name;
		rules[at].protocol = seen->protocol && strcmp(seen->protocol, "udp") == 0
		    ? NCFG_PORT_FORWARD_UDP : NCFG_PORT_FORWARD_TCP;
		rules[at].port = (uint16_t)seen->port;
		rules[at].to = seen->to;
		rules[at].to_port = (uint16_t)seen->to_port;
	}
	return rules;
}

/* `wan0/web tcp 443 -> 192.168.1.10:8443; ...`, for a plan's reason line. */
static const char *describe_forwards(ncfg_plan_t *plan, const ncfg_forward_rule_t *rules,
    size_t count)
{
	ncfg_buf_t  buf;
	const char *text;
	size_t      at;

	if (count == 0u) {
		return "<none>";
	}
	ncfg_buf_init(&buf, 0);
	for (at = 0; at < count; at++) {
		ncfg_buf_addf(&buf, "%s%s/%s %s %u -> %s:%u", at ? "; " : "",
		    rules[at].interface ? rules[at].interface : "", rules[at].name ? rules[at].name : "",
		    rules[at].protocol == NCFG_PORT_FORWARD_UDP ? "udp" : "tcp",
		    (unsigned)rules[at].port, rules[at].to ? rules[at].to : "",
		    (unsigned)rules[at].to_port);
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
	forwards = wanted_forwards(desired, &forward_count, &failed);
	if (failed) {
		builder->plan->failed = 1;
		free(wanted);
		return;
	}
	forwards_same = same_forwards(forwards, forward_count, builder->observed);
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
	forwards_was = installed_forwards(builder->observed, &failed);
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
