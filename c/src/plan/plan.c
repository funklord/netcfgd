/*
 * plan.c -- the container: what a plan owns, and how an action gets into it.
 *
 * WHY THERE IS AN ARENA AND NOT A `free` PER OP
 *   An op is a union of thirty arms. A `ncfg_op_free` walking it would be a
 *   third list to keep in step with the enum and with the writer, and the one
 *   this project has already got wrong twice is the list maintained by hand.
 *   So an action copies what it names into the plan's own array of
 *   allocations, and `ncfg_plan_free` is one loop. The cost is a pointer per
 *   string; the benefit is that "who frees this?" has one answer.
 *
 *   Four things are deliberately **not** copied -- an interface kind, a DNS
 *   policy, a peer list and a routing rule. plan.h says why and says what the
 *   caller owes in return.
 *
 * THE STICKY FAILURE
 *   `ncfg_buf_t`'s discipline, for the same reason: a planner makes several
 *   hundred calls and checks once, which is what makes the check get written.
 *   A plan that failed writes nothing rather than half a plan -- half a plan
 *   that looks whole is the one that gets applied.
 */
#include "ncfg/plan.h"

#include "plan_internal.h"

#include "ncfg/base.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ *
 * The arena
 * ------------------------------------------------------------------------ */

/* Record one allocation as the plan's, or free it and fail. */
static void *keep(ncfg_plan_t *plan, void *block)
{
	void **grown;
	size_t wanted;

	if (!block) {
		plan->failed = 1;
		return NULL;
	}
	if (plan->owned_count == plan->owned_capacity) {
		wanted = plan->owned_capacity ? plan->owned_capacity * 2u : 64u;
		grown = realloc(plan->owned, wanted * sizeof(*grown));
		if (!grown) {
			free(block);
			plan->failed = 1;
			return NULL;
		}
		plan->owned = grown;
		plan->owned_capacity = wanted;
	}
	plan->owned[plan->owned_count++] = block;
	return block;
}

int ncfg_plan_adopt(ncfg_plan_t *plan, void *owned, void (*release)(void *owned))
{
	ncfg_plan_adopted_t *grown;
	size_t               wanted;

	if (!plan || !owned || !release) {
		/* Nothing to record, and nothing that could be released either: a
		 * caller with no release has handed over something this cannot free,
		 * which is the one case where refusing without freeing is right. */
		if (plan) {
			plan->failed = 1;
		}
		return 0;
	}
	if (plan->adopted_count == plan->adopted_capacity) {
		wanted = plan->adopted_capacity ? plan->adopted_capacity * 2u : 4u;
		grown = realloc(plan->adopted, wanted * sizeof(*grown));
		if (!grown) {
			/* The caller stopped owning it at the call, so this owns it now
			 * and there is nowhere to put it. Freeing here is what keeps that
			 * one sentence true on both paths. */
			release(owned);
			plan->failed = 1;
			return 0;
		}
		plan->adopted = grown;
		plan->adopted_capacity = wanted;
	}
	plan->adopted[plan->adopted_count].owned = owned;
	plan->adopted[plan->adopted_count].release = release;
	plan->adopted_count++;
	return 1;
}

/*
 * Room for one more element of `*array`, which the plan owns.
 *
 * Growing in place would leave the old block in the arena and the new one
 * outside it, so the arena entry is rewritten -- and it is found **before**
 * the `realloc`, not after. Doing it the other way round means that a block
 * which somehow was not the plan's has already been freed by the time that is
 * discovered, leaving a stale pointer in the arena for `ncfg_plan_free` to
 * free a second time. Every caller passes a list head this function itself
 * allocated, so the search always succeeds; the order is what makes that a
 * fact rather than a hope.
 */
static void *grow(ncfg_plan_t *plan, void *array, size_t count, size_t element)
{
	void  *grown;
	size_t slot = 0;
	int    found = 0;
	size_t i;

	if (plan->failed) {
		return NULL;
	}
	if (array) {
		for (i = plan->owned_count; i-- > 0;) {
			if (plan->owned[i] == array) {
				slot = i;
				found = 1;
				break;
			}
		}
		if (!found) {
			plan->failed = 1;
			return NULL;
		}
	}
	grown = realloc(array, (count + 1u) * element);
	if (!grown) {
		plan->failed = 1;
		return NULL;
	}
	if (array) {
		plan->owned[slot] = grown;
		return grown;
	}
	return keep(plan, grown);
}

const char *ncfg_plan_intern(ncfg_plan_t *plan, const char *text)
{
	size_t length;
	char  *copy;

	if (!text || plan->failed) {
		return NULL;
	}
	length = strlen(text);
	copy = malloc(length + 1u);
	if (copy) {
		memcpy(copy, text, length + 1u);
	}
	return keep(plan, copy);
}

const char *ncfg_plan_internf(ncfg_plan_t *plan, const char *format, ...)
{
	char    text[NCFG_ERROR_MAX];
	va_list args;

	va_start(args, format);
	(void)vsnprintf(text, sizeof(text), format, args);
	va_end(args);
	return ncfg_plan_intern(plan, text);
}

const ncfg_route_t *ncfg_plan_intern_route(ncfg_plan_t *plan, const ncfg_route_t *route)
{
	ncfg_route_t *copy;

	if (!route || plan->failed) {
		return NULL;
	}
	copy = calloc(1u, sizeof(*copy));
	if (!keep(plan, copy)) {
		return NULL;
	}
	*copy = *route;
	/* The three strings a route carries. Cast away const on the way in
	 * because the model's own type owns them; the plan's copy owns its own. */
	copy->destination = (char *)(uintptr_t)ncfg_plan_intern(plan, route->destination);
	copy->via = (char *)(uintptr_t)ncfg_plan_intern(plan, route->via);
	copy->src = (char *)(uintptr_t)ncfg_plan_intern(plan, route->src);
	return copy;
}

const ncfg_routing_rule_t *ncfg_plan_intern_rule(ncfg_plan_t *plan, const ncfg_routing_rule_t *rule)
{
	ncfg_routing_rule_t *copy;

	if (!rule || plan->failed) {
		return NULL;
	}
	copy = calloc(1u, sizeof(*copy));
	if (!keep(plan, copy)) {
		return NULL;
	}
	*copy = *rule;
	/* The five strings a rule carries. Cast away const on the way in because
	 * the model's own type owns them; the plan's copy owns its own. */
	copy->id = (char *)(uintptr_t)ncfg_plan_intern(plan, rule->id);
	copy->from = (char *)(uintptr_t)ncfg_plan_intern(plan, rule->from);
	copy->to = (char *)(uintptr_t)ncfg_plan_intern(plan, rule->to);
	copy->iif = (char *)(uintptr_t)ncfg_plan_intern(plan, rule->iif);
	copy->oif = (char *)(uintptr_t)ncfg_plan_intern(plan, rule->oif);
	return copy;
}

ncfg_dns_policy_t *ncfg_plan_intern_dns_policy(ncfg_plan_t *plan, const ncfg_dns_policy_t *policy,
    size_t extra_servers, size_t extra_search)
{
	ncfg_dns_policy_t *copy;
	size_t             servers;
	size_t             search;

	if (plan->failed) {
		return NULL;
	}
	copy = calloc(1u, sizeof(*copy));
	if (!keep(plan, copy)) {
		return NULL;
	}
	if (policy) {
		*copy = *policy;
	}
	/*
	 * Only the two lists a merge appends to are re-allocated; everything else
	 * stays exactly the borrow it was. A scope whose servers came straight off
	 * the document never reaches here at all -- `build_scope` hands the
	 * document's policy back -- so the copy exists precisely because these two
	 * lists are about to be something neither the document nor the observation
	 * holds.
	 */
	servers = copy->server_count + extra_servers;
	search = copy->search_count + extra_search;
	if (servers != 0u) {
		ncfg_dns_server_t *room = calloc(servers, sizeof(*room));

		if (!keep(plan, room)) {
			return NULL;
		}
		if (copy->server_count != 0u) {
			memcpy(room, copy->servers, copy->server_count * sizeof(*room));
		}
		copy->servers = room;
	}
	if (search != 0u) {
		char **room = calloc(search, sizeof(*room));

		if (!keep(plan, room)) {
			return NULL;
		}
		if (copy->search_count != 0u) {
			memcpy(room, copy->search, copy->search_count * sizeof(*room));
		}
		copy->search = room;
	}
	return copy;
}

/* A counted array of strings, copied into the plan. */
static const char *const *intern_strings(ncfg_plan_t *plan, const char *const *list, size_t count)
{
	const char **copy;
	size_t       i;

	if (plan->failed) {
		return NULL;
	}
	if (count == 0u) {
		/* An empty list is a list, and `nat.replace` with none is how a
		 * document that stops asking for NAT is honoured. */
		return NULL;
	}
	copy = calloc(count, sizeof(*copy));
	if (!keep(plan, copy)) {
		return NULL;
	}
	for (i = 0; i < count; i++) {
		copy[i] = ncfg_plan_intern(plan, list[i]);
	}
	return copy;
}

/* ------------------------------------------------------------------------ *
 * Copying one op
 * ------------------------------------------------------------------------ */

/*
 * Take a copy of `in` whose strings are the plan's.
 *
 * One arm per op, in the enum's order, and no `default:` -- see action.c for
 * why every switch over this enum is exhaustive.
 */
static void intern_op(ncfg_plan_t *plan, const ncfg_op_t *in, ncfg_op_t *out)
{
	ncfg_offload_t *features;
	size_t          i;

	*out = *in;
	switch ((ncfg_op_kind_t)in->kind) {
	case NCFG_OP_LINK_CREATE:
		out->u.link_create.name = ncfg_plan_intern(plan, in->u.link_create.name);
		return;
	case NCFG_OP_LINK_DELETE:
	case NCFG_OP_LINK_UNSET_MASTER:
	case NCFG_OP_LINK_UP:
	case NCFG_OP_LINK_DOWN:
	case NCFG_OP_LINK_SET_BRIDGE:
	case NCFG_OP_LINK_SET_MACVLAN:
	case NCFG_OP_LINK_SET_TUNNEL:
	case NCFG_OP_LINK_SET_VXLAN:
	case NCFG_OP_HOSTNAME_SET:
		out->u.named.name = ncfg_plan_intern(plan, in->u.named.name);
		return;
	case NCFG_OP_LINK_SET_MTU:
		out->u.set_mtu.name = ncfg_plan_intern(plan, in->u.set_mtu.name);
		return;
	case NCFG_OP_LINK_SET_MAC:
		out->u.set_mac.name = ncfg_plan_intern(plan, in->u.set_mac.name);
		out->u.set_mac.mac = ncfg_plan_intern(plan, in->u.set_mac.mac);
		return;
	case NCFG_OP_LINK_SET_MASTER:
		out->u.set_master.name = ncfg_plan_intern(plan, in->u.set_master.name);
		out->u.set_master.master = ncfg_plan_intern(plan, in->u.set_master.master);
		return;
	case NCFG_OP_LINK_SET_BOND:
		out->u.set_bond.name = ncfg_plan_intern(plan, in->u.set_bond.name);
		return;
	case NCFG_OP_LINK_SET_IPV6_TOKEN:
		out->u.set_ipv6_token.name = ncfg_plan_intern(plan, in->u.set_ipv6_token.name);
		out->u.set_ipv6_token.token = ncfg_plan_intern(plan, in->u.set_ipv6_token.token);
		return;
	case NCFG_OP_LINK_SET_OFFLOADS:
		out->u.set_offloads.name = ncfg_plan_intern(plan, in->u.set_offloads.name);
		if (in->u.set_offloads.feature_count == 0u || plan->failed) {
			out->u.set_offloads.features = NULL;
			out->u.set_offloads.feature_count = 0u;
			return;
		}
		features = calloc(in->u.set_offloads.feature_count, sizeof(*features));
		if (!keep(plan, features)) {
			out->u.set_offloads.features = NULL;
			out->u.set_offloads.feature_count = 0u;
			return;
		}
		for (i = 0; i < in->u.set_offloads.feature_count; i++) {
			features[i].name =
			    ncfg_plan_intern(plan, in->u.set_offloads.features[i].name);
			features[i].wanted = in->u.set_offloads.features[i].wanted;
		}
		out->u.set_offloads.features = features;
		return;
	case NCFG_OP_ADDR_ADD:
		out->u.addr_add.iface = ncfg_plan_intern(plan, in->u.addr_add.iface);
		out->u.addr_add.addr = ncfg_plan_intern(plan, in->u.addr_add.addr);
		return;
	case NCFG_OP_ADDR_DEL:
		out->u.addr_del.iface = ncfg_plan_intern(plan, in->u.addr_del.iface);
		out->u.addr_del.addr = ncfg_plan_intern(plan, in->u.addr_del.addr);
		return;
	case NCFG_OP_ROUTE_ADD:
	case NCFG_OP_ROUTE_DEL:
		out->u.route.iface = ncfg_plan_intern(plan, in->u.route.iface);
		out->u.route.route = ncfg_plan_intern_route(plan, in->u.route.route);
		return;
	case NCFG_OP_BACKEND_START:
	case NCFG_OP_BACKEND_STOP:
	case NCFG_OP_BACKEND_RELOAD:
		out->u.backend.iface = ncfg_plan_intern(plan, in->u.backend.iface);
		return;
	case NCFG_OP_BRIDGE_VLAN_ADD:
	case NCFG_OP_BRIDGE_VLAN_DEL:
		out->u.bridge_vlan.iface = ncfg_plan_intern(plan, in->u.bridge_vlan.iface);
		return;
	case NCFG_OP_WIFI_SET_PROFILES:
		out->u.set_profiles.device = ncfg_plan_intern(plan, in->u.set_profiles.device);
		out->u.set_profiles.profiles = intern_strings(plan, in->u.set_profiles.profiles,
		    in->u.set_profiles.profile_count);
		return;
	case NCFG_OP_WIFI_ASSOCIATE:
		out->u.associate.device = ncfg_plan_intern(plan, in->u.associate.device);
		out->u.associate.network_id = ncfg_plan_intern(plan, in->u.associate.network_id);
		return;
	case NCFG_OP_WIFI_DISASSOCIATE:
		out->u.device.device = ncfg_plan_intern(plan, in->u.device.device);
		return;
	case NCFG_OP_WIFI_SET_REGDOM:
		out->u.regdom.device = ncfg_plan_intern(plan, in->u.regdom.device);
		out->u.regdom.country = ncfg_plan_intern(plan, in->u.regdom.country);
		return;
	case NCFG_OP_ACCESS_CONTROL_ADD:
	case NCFG_OP_ACCESS_CONTROL_DEL:
		out->u.access_control.iface = ncfg_plan_intern(plan, in->u.access_control.iface);
		out->u.access_control.station = ncfg_plan_intern(plan, in->u.access_control.station);
		return;
	case NCFG_OP_WG_SET_DEVICE:
		out->u.wg_device.iface = ncfg_plan_intern(plan, in->u.wg_device.iface);
		out->u.wg_device.private_key_ref =
		    ncfg_plan_intern(plan, in->u.wg_device.private_key_ref);
		return;
	case NCFG_OP_WG_SET_PEERS:
		out->u.wg_peers.iface = ncfg_plan_intern(plan, in->u.wg_peers.iface);
		return;
	case NCFG_OP_DNS_APPLY:
		out->u.dns.scope = ncfg_plan_intern(plan, in->u.dns.scope);
		return;
	case NCFG_OP_RULE_ADD:
	case NCFG_OP_RULE_DEL:
		return;
	case NCFG_OP_QDISC_SET:
		out->u.qdisc.iface = ncfg_plan_intern(plan, in->u.qdisc.iface);
		out->u.qdisc.kind = ncfg_plan_intern(plan, in->u.qdisc.kind);
		return;
	case NCFG_OP_QDISC_RESET:
	case NCFG_OP_INGRESS_REDIRECT_CLEAR:
		out->u.iface.iface = ncfg_plan_intern(plan, in->u.iface.iface);
		return;
	case NCFG_OP_INGRESS_REDIRECT:
		out->u.redirect.iface = ncfg_plan_intern(plan, in->u.redirect.iface);
		out->u.redirect.target = ncfg_plan_intern(plan, in->u.redirect.target);
		return;
	case NCFG_OP_SYSCTL_SET_FORWARDING:
		out->u.forwarding.iface = ncfg_plan_intern(plan, in->u.forwarding.iface);
		return;
	case NCFG_OP_SYSCTL_SET_PRIVACY:
		out->u.privacy.iface = ncfg_plan_intern(plan, in->u.privacy.iface);
		return;
	case NCFG_OP_SYSCTL_SET_ACCEPT_RA:
		out->u.accept_ra.iface = ncfg_plan_intern(plan, in->u.accept_ra.iface);
		return;
	case NCFG_OP_NAT_REPLACE:
		out->u.nat.uplinks =
		    intern_strings(plan, in->u.nat.uplinks, in->u.nat.uplink_count);
		return;
	case NCFG_OP_HOOK_RUN:
		out->u.hook.iface = ncfg_plan_intern(plan, in->u.hook.iface);
		out->u.hook.path = ncfg_plan_intern(plan, in->u.hook.path);
		out->u.hook.value = ncfg_plan_intern(plan, in->u.hook.value);
		return;
	case NCFG_OP_COMMIT_ARM:
	case NCFG_OP_COMMIT_CONFIRM:
		return;
	case NCFG_OP_COMMIT_REVERT:
		out->u.commit_revert.to_document_hash =
		    ncfg_plan_intern(plan, in->u.commit_revert.to_document_hash);
		return;
	}
}

static void intern_reason(ncfg_plan_t *plan, const ncfg_reason_t *in, ncfg_reason_t *out)
{
	out->interface = ncfg_plan_intern(plan, in->interface);
	out->field = ncfg_plan_intern(plan, in->field);
	out->desired = ncfg_plan_intern(plan, in->desired);
	out->observed = ncfg_plan_intern(plan, in->observed);
}

/* ------------------------------------------------------------------------ *
 * The plan itself
 * ------------------------------------------------------------------------ */

ncfg_plan_t *ncfg_plan_new(char *err, size_t err_size)
{
	ncfg_plan_t *plan = calloc(1u, sizeof(*plan));

	if (!plan) {
		ncfg_error_set(err, err_size, "out of memory making a plan");
		return NULL;
	}
	return plan;
}

void ncfg_plan_free(ncfg_plan_t *plan)
{
	size_t i;

	if (!plan) {
		return;
	}
	/*
	 * The adopted before the arena, and in reverse: an aggregate's release
	 * walks its own memory, and the arena holds nothing it points at -- but
	 * the order costs nothing and the other one is the order in which a
	 * dependency between two adopted things would go wrong silently.
	 */
	for (i = plan->adopted_count; i-- > 0;) {
		plan->adopted[i].release(plan->adopted[i].owned);
	}
	free(plan->adopted);
	for (i = 0; i < plan->owned_count; i++) {
		free(plan->owned[i]);
	}
	free(plan->owned);
	free(plan);
}

int ncfg_plan_failed(const ncfg_plan_t *plan)
{
	return plan->failed;
}

int ncfg_plan_is_empty(const ncfg_plan_t *plan)
{
	return plan->action_count == 0u;
}

int ncfg_plan_was_refused(const ncfg_plan_t *plan)
{
	return plan->refusal_count != 0u;
}

int ncfg_plan_strands_credentials(const ncfg_plan_t *plan)
{
	return plan->stranded_count != 0u;
}

uint32_t ncfg_plan_add(ncfg_plan_t *plan, const ncfg_op_t *op, const ncfg_reason_t *reason,
    const uint32_t *depends_on, size_t depends_count, const ncfg_op_t *inverse)
{
	ncfg_action_t *actions;
	ncfg_action_t *action;
	uint32_t      *edges = NULL;
	size_t         kept = 0;
	size_t         i;

	if (plan->failed) {
		return NCFG_PLAN_NO_ACTION;
	}
	/*
	 * The sentinel is dropped here rather than at each call site, because a
	 * site added later would not know to ask -- and because dropping it is
	 * what the edge *means*: an action that was not emitted is not something
	 * to wait for, so the dependency is vacuous rather than unsatisfied. The
	 * refusal beside it is what says why (0097).
	 */
	if (depends_count != 0u) {
		edges = calloc(depends_count, sizeof(*edges));
		if (!keep(plan, edges)) {
			return NCFG_PLAN_NO_ACTION;
		}
		for (i = 0; i < depends_count; i++) {
			if (depends_on[i] != NCFG_PLAN_NO_ACTION) {
				edges[kept++] = depends_on[i];
			}
		}
	}

	actions = grow(plan, plan->actions, plan->action_count, sizeof(*plan->actions));
	if (!actions) {
		return NCFG_PLAN_NO_ACTION;
	}
	plan->actions = actions;
	action = &plan->actions[plan->action_count];
	memset(action, 0, sizeof(*action));
	action->id = (uint32_t)plan->action_count;
	intern_op(plan, op, &action->op);
	intern_reason(plan, reason, &action->reason);
	action->depends_on = edges;
	action->depends_count = kept;
	if (inverse) {
		action->has_inverse = 1;
		intern_op(plan, inverse, &action->inverse);
	}
	plan->action_count++;

	/*
	 * An action with no inverse is one commit-confirm cannot undo, and saying
	 * so is not optional: the window arms, the operator believes the change is
	 * revertible, and the one action that is not is the one that deleted a
	 * link.
	 */
	if (!inverse) {
		ncfg_plan_warnf(plan, ncfg_op_interface(op),
		    "%s cannot be undone; commit-confirm will not revert it", ncfg_op_name(op));
	}
	return action->id;
}

void ncfg_plan_warn(ncfg_plan_t *plan, const char *interface, const char *message)
{
	ncfg_warning_t *warnings =
	    grow(plan, plan->warnings, plan->warning_count, sizeof(*plan->warnings));

	if (!warnings) {
		return;
	}
	plan->warnings = warnings;
	plan->warnings[plan->warning_count].interface = ncfg_plan_intern(plan, interface);
	plan->warnings[plan->warning_count].message = ncfg_plan_intern(plan, message);
	plan->warning_count++;
}

/*
 * A warning that did not fit says so, rather than stopping mid-word.
 *
 * **`vsnprintf` truncates in silence, and a test cannot see it.** A warning
 * written past `NCFG_ERROR_MAX` reaches an operator cut at 511 characters --
 * measured, one reached one as "...still means t" -- and every check on it
 * passed, because each fragment asserted sat before the cut. A sabotage that
 * should have turned those checks red turned none, which is how it was found.
 *
 * So the last thing an over-long warning carries is a marker saying it was
 * cut. That is worse than a warning that fits and much better than one that
 * looks whole: a reader who sees the marker knows to go and look, where a
 * reader of a sentence ending mid-word does not know whether netcfgd stopped
 * or the terminal did.
 *
 * Not a refusal, because a warning is what a plan says when it cannot act and
 * dropping it would lose the only notice there is. Not a bigger buffer,
 * because the next sentence would grow into that one too.
 */
void ncfg_plan_warnf(ncfg_plan_t *plan, const char *interface, const char *format, ...)
{
	static const char cut[] = " [cut: this warning is longer than netcfgd prints]";
	char    message[NCFG_ERROR_MAX];
	va_list args;
	int     wanted;

	va_start(args, format);
	wanted = vsnprintf(message, sizeof(message), format, args);
	va_end(args);
	if (wanted >= (int)sizeof(message)) {
		/* Room for the marker is taken from the end of what did fit, which is
		 * the half a reader is least likely to need -- the subject is at the
		 * front of every sentence this file writes. */
		(void)memcpy(&message[sizeof(message) - sizeof(cut)], cut, sizeof(cut));
	}
	ncfg_plan_warn(plan, interface, message);
}

void ncfg_plan_refuse(ncfg_plan_t *plan, const ncfg_refusal_t *refusal)
{
	ncfg_refusal_t *list =
	    grow(plan, plan->refusals, plan->refusal_count, sizeof(*plan->refusals));
	ncfg_refusal_t *slot;

	if (!list) {
		return;
	}
	plan->refusals = list;
	slot = &plan->refusals[plan->refusal_count];
	slot->interface = ncfg_plan_intern(plan, refusal->interface);
	slot->op = ncfg_plan_intern(plan, refusal->op);
	slot->guard = ncfg_plan_intern(plan, refusal->guard);
	intern_reason(plan, &refusal->reason, &slot->reason);
	slot->override_with = ncfg_plan_intern(plan, refusal->override_with);
	plan->refusal_count++;
}

void ncfg_plan_strand(ncfg_plan_t *plan, const ncfg_stranded_t *stranded)
{
	ncfg_stranded_t *list =
	    grow(plan, plan->stranded, plan->stranded_count, sizeof(*plan->stranded));
	ncfg_stranded_t *slot;

	if (!list) {
		return;
	}
	plan->stranded = list;
	slot = &plan->stranded[plan->stranded_count];
	slot->interface = ncfg_plan_intern(plan, stranded->interface);
	slot->credential = ncfg_plan_intern(plan, stranded->credential);
	slot->irrevocable = ncfg_plan_intern(plan, stranded->irrevocable);
	slot->remove_with = ncfg_plan_intern(plan, stranded->remove_with);
	slot->consent_with = ncfg_plan_intern(plan, stranded->consent_with);
	plan->stranded_count++;
}
