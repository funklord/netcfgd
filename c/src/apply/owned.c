/*
 * owned.c -- what an apply did, folded into `/run/netcfgd/owned.json`.
 *
 * WHY THIS FILE IS IN `src/apply/` AND NOT IN `src/host/`
 *   `state.h` names it: the record's *rules* are that module's and are tested
 *   there -- `ncfg_owned_remember`, `ncfg_owned_note_hook_state` -- while the
 *   fold's argument is what an apply did, which is this module's. The Rust
 *   splits the same pair the same way, `OwnedState::absorb` taking
 *   `netcfgd-apply`'s `Effects`.
 *
 * WHAT THE RECORD IS FOR, SAID ONCE
 *   It is not a log. Every entry in it is an answer to "may netcfgd take this
 *   away?", and the safety property `plan.h` puts above every other one --
 *   nothing foreign is ever removed -- is decided from it and from the marks in
 *   the kernel, and from nothing else. So the direction a mistake goes in
 *   matters: a record that lost an entry makes netcfgd leave something of its
 *   own behind, and a record that gained one makes it delete somebody else's.
 *   Every rule below prefers the first.
 *
 * WHY AN ACTION AND NOT AN EFFECT
 *   `apply.h` argues it where the call is declared. In short: every member of
 *   the Rust's `Effects` that this record can carry is a pure function of the
 *   op that produced it, so the op is the effect and the fold is checkable
 *   against the recorder rather than against a kernel.
 *
 *   `dns.apply` is the one op that is **not** its own effect: the executor
 *   delivers every scope its context carries whatever the op names. So the
 *   delivered set arrives as an argument to `ncfg_apply_record` instead, and
 *   the case below says what that costs and what leaving it out cost.
 */
#include "ncfg/apply.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/json_write.h"
#include "ncfg/lock.h"
#include "ncfg/state.h"
#include "ncfg_json.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Long enough for a run directory and the two leaf names below.
 *
 * A fixed buffer rather than an allocation, because the only thing that can
 * overflow it is a run directory somebody set by hand, and a refusal naming the
 * ceiling is a better answer than a `malloc` on a path that is already wrong.
 */
#define RUN_PATH_MAX 512

/* ------------------------------------------------------------------------ *
 * The two object lists
 * ------------------------------------------------------------------------ */

/* Where this object sits in the list, or the count where it is not there. */
static size_t object_at(const ncfg_owned_object_t *list, size_t count, const char *interface,
    const char *key)
{
	size_t at;

	for (at = 0; at < count; at++) {
		if (list[at].interface && list[at].key &&
		    strcmp(list[at].interface, interface) == 0 && strcmp(list[at].key, key) == 0) {
			return at;
		}
	}
	return count;
}

/* Take one out, keeping the order of the rest: the file is read by people, and
 * a record that reshuffled itself on every apply would make `diff` useless. */
static void object_drop(ncfg_owned_object_t **list, size_t *count, const char *interface,
    const char *key)
{
	size_t at = object_at(*list, *count, interface, key);

	if (at == *count) {
		return;
	}
	free((*list)[at].interface);
	free((*list)[at].key);
	memmove(&(*list)[at], &(*list)[at + 1u], (*count - at - 1u) * sizeof(**list));
	(*count)--;
}

/*
 * Put one in, replacing whatever was there for the same interface and key.
 *
 * Replace rather than append, because the key is the identity: an address
 * reinstalled with a different origin is one address, and two records of it
 * would make `ncfg explain` answer twice about one thing.
 */
static int object_put(ncfg_owned_object_t **list, size_t *count, const char *interface,
    const char *key, int origin)
{
	ncfg_owned_object_t *grown;
	char                *name;
	char                *text;

	if (!interface || !key) {
		return 0;
	}
	object_drop(list, count, interface, key);
	name = strdup(interface);
	text = strdup(key);
	grown = realloc(*list, (*count + 1u) * sizeof(**list));
	if (grown) {
		/* The old array is gone whichever way this goes, so the record takes
		 * the new one before anything can return -- `ncfg_owned_note_hook_
		 * state`'s arrangement, and for its reason: a failure that left the
		 * list pointing at the freed one would be a use-after-free in the
		 * caller's cleanup rather than here. */
		*list = grown;
	}
	if (!name || !text || !grown) {
		free(name);
		free(text);
		return 0;
	}
	(*list)[*count].interface = name;
	(*list)[*count].key = text;
	(*list)[*count].origin = origin;
	(*count)++;
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Backends that will not stay up
 * ------------------------------------------------------------------------ */

/*
 * The backend netcfgd started, remembered -- or the one it stopped, forgotten.
 *
 * **`running` is set and is a memory rather than an observation**, which is
 * 0078's distinction and the whole reason `answering` is a separate field: what
 * this records is that netcfgd started the daemon and has not stopped it. A
 * process being there is a different question, and nothing in this build asks
 * it yet -- see `ncfg_owned_absorb`.
 *
 * Everything else about the entry is absent, which is the Rust's `absorb`
 * exactly: an access point's station lists, a client's metric, a tunnel's
 * digest and a daemon's prefixes are read live by observation passes, never
 * recorded, and `observed.h`'s field tables leave every one of them out of the
 * file when it is absent. So what goes to disk is `{kind, interface, running}`,
 * which is what a Rust netcfgd writes for a backend it has just started.
 */
static size_t backend_at(const ncfg_owned_state_t *owned, int kind, const char *interface)
{
	size_t at;

	for (at = 0; at < owned->backend_count; at++) {
		if (owned->backends[at].kind == kind && owned->backends[at].interface && interface &&
		    strcmp(owned->backends[at].interface, interface) == 0) {
			return at;
		}
	}
	return owned->backend_count;
}

static int backend_started(ncfg_owned_state_t *owned, int kind, const char *interface)
{
	ncfg_observed_backend_t *grown;
	char                    *name;

	if (!interface) {
		return 0;
	}
	if (backend_at(owned, kind, interface) != owned->backend_count) {
		/* Already recorded, which is the ordinary case for a start that
		 * adopted the daemon already there. Folding the same journal twice
		 * must write the same file, so this is not an append. */
		return 1;
	}
	name = strdup(interface);
	grown = realloc(owned->backends, (owned->backend_count + 1u) * sizeof(*owned->backends));
	if (grown) {
		/* `ncfg_owned_note_hook_state`'s arrangement and for its reason: the
		 * old array is gone whichever way this goes, so the record takes the
		 * new one before anything can return. */
		owned->backends = grown;
	}
	if (!name || !grown) {
		free(name);
		return 0;
	}
	memset(&owned->backends[owned->backend_count], 0, sizeof(*owned->backends));
	owned->backends[owned->backend_count].kind = kind;
	owned->backends[owned->backend_count].interface = name;
	owned->backends[owned->backend_count].running = 1;
	owned->backend_count++;
	return 1;
}

/*
 * A stop takes the entry out, and its **absence** is what the record says.
 *
 * The same rule `link.delete` follows: a record that outlived the thing it
 * describes is a claim on whatever next takes that name, and here the name is
 * one interface and one kind of daemon.
 */
static void backend_stopped(ncfg_owned_state_t *owned, int kind, const char *interface)
{
	size_t at = backend_at(owned, kind, interface);

	if (at == owned->backend_count) {
		return;
	}
	ncfg_observed_backend_free(&owned->backends[at]);
	memmove(&owned->backends[at], &owned->backends[at + 1u],
	    (owned->backend_count - at - 1u) * sizeof(*owned->backends));
	owned->backend_count--;
}

/*
 * A start that has not yet been seen to work, counted (0079).
 *
 * The clearing half -- a backend observed running -- is not here, because it is
 * not something an apply did. `apply.h` says where it went.
 */
static int restart_counted(ncfg_owned_state_t *owned, int kind, const char *interface)
{
	ncfg_backend_restart_t *grown;
	char                   *name;
	size_t                  at;

	if (!interface) {
		return 0;
	}
	for (at = 0; at < owned->backend_restart_count; at++) {
		if (owned->backend_restarts[at].kind == kind &&
		    owned->backend_restarts[at].interface &&
		    strcmp(owned->backend_restarts[at].interface, interface) == 0) {
			owned->backend_restarts[at].count++;
			return 1;
		}
	}
	name = strdup(interface);
	grown = realloc(owned->backend_restarts,
	    (owned->backend_restart_count + 1u) * sizeof(*owned->backend_restarts));
	if (grown) {
		owned->backend_restarts = grown;
	}
	if (!name || !grown) {
		free(name);
		return 0;
	}
	owned->backend_restarts[owned->backend_restart_count].kind = kind;
	owned->backend_restarts[owned->backend_restart_count].interface = name;
	owned->backend_restarts[owned->backend_restart_count].count = 1;
	owned->backend_restart_count++;
	return 1;
}

/* A deliberate stop clears the count: the document stopped asking, so whatever
 * the daemon was doing before is no longer being attempted. */
static void restart_cleared(ncfg_owned_state_t *owned, int kind, const char *interface)
{
	size_t at;

	for (at = 0; at < owned->backend_restart_count; at++) {
		if (owned->backend_restarts[at].kind != kind ||
		    !owned->backend_restarts[at].interface || !interface ||
		    strcmp(owned->backend_restarts[at].interface, interface) != 0) {
			continue;
		}
		free(owned->backend_restarts[at].interface);
		memmove(&owned->backend_restarts[at], &owned->backend_restarts[at + 1u],
		    (owned->backend_restart_count - at - 1u) * sizeof(*owned->backend_restarts));
		owned->backend_restart_count--;
		return;
	}
}

/* ------------------------------------------------------------------------ *
 * One action
 * ------------------------------------------------------------------------ */

/*
 * **No `default:` arm**, which is `ncfg_apply_supported`'s rule and for its
 * reason: an op added to the taxonomy makes this fail to compile rather than
 * falling silently into "records nothing", which is the half that loses an
 * object netcfgd has installed.
 */
int ncfg_owned_absorb(ncfg_owned_state_t *owned, const ncfg_op_t *op)
{
	if (!owned || !op) {
		return 0;
	}
	switch ((ncfg_op_kind_t)op->kind) {
	case NCFG_OP_LINK_CREATE:
		return ncfg_owned_remember(&owned->created_links, &owned->created_link_count,
		    op->u.link_create.name, 1);
	case NCFG_OP_LINK_DELETE:
		/*
		 * The record goes with the link, and its **absence** is load-bearing:
		 * a record that outlived the device it describes is a claim on
		 * whatever next takes that name.
		 */
		return ncfg_owned_remember(&owned->created_links, &owned->created_link_count,
		    op->u.named.name, 0);
	case NCFG_OP_ADDR_ADD:
		/*
		 * `static` because netcfgd installs an address from the document and
		 * from nowhere else -- a lease's address belongs to the DHCP client,
		 * which installs it under its own protocol number. `observed.h` makes
		 * the same argument about the tag, and the two must agree: every
		 * teardown path gates on `origin == static` before it gates on
		 * anything else.
		 */
		return object_put(&owned->addresses, &owned->address_count, op->u.addr_add.iface,
		    op->u.addr_add.addr, (int)NCFG_ORIGIN_STATIC);
	case NCFG_OP_ADDR_DEL:
		object_drop(&owned->addresses, &owned->address_count, op->u.addr_del.iface,
		    op->u.addr_del.addr);
		return 1;
	case NCFG_OP_ROUTE_ADD:
		if (!op->u.route.route) {
			return 0;
		}
		return object_put(&owned->routes, &owned->route_count, op->u.route.iface,
		    op->u.route.route->destination, (int)NCFG_ORIGIN_STATIC);
	case NCFG_OP_ROUTE_DEL:
		if (!op->u.route.route) {
			return 0;
		}
		object_drop(&owned->routes, &owned->route_count, op->u.route.iface,
		    op->u.route.route->destination);
		return 1;
	case NCFG_OP_SYSCTL_SET_FORWARDING:
		return ncfg_owned_remember(&owned->forwarding, &owned->forwarding_count,
		    op->u.forwarding.iface, op->u.forwarding.enabled);
	case NCFG_OP_SYSCTL_SET_PRIVACY:
		return ncfg_owned_remember(&owned->privacy, &owned->privacy_count,
		    op->u.privacy.iface, op->u.privacy.prefer_temporary);
	case NCFG_OP_SYSCTL_SET_ACCEPT_RA:
		/*
		 * The one list whose "off" is not false. The value netcfgd writes to
		 * give an interface back is 1, the kernel's own default, so that is
		 * what drops the record (0073) -- and `state.h` says the comparison is
		 * the caller's rather than `ncfg_owned_remember`'s, which is here.
		 */
		return ncfg_owned_remember(&owned->accept_ra, &owned->accept_ra_count,
		    op->u.accept_ra.iface, op->u.accept_ra.value != 1);
	case NCFG_OP_QDISC_SET:
		return ncfg_owned_remember(&owned->qdisc, &owned->qdisc_count, op->u.qdisc.iface,
		    1);
	case NCFG_OP_QDISC_RESET:
		return ncfg_owned_remember(&owned->qdisc, &owned->qdisc_count, op->u.iface.iface,
		    0);
	case NCFG_OP_INGRESS_REDIRECT:
		return ncfg_owned_remember(&owned->ingress, &owned->ingress_count,
		    op->u.redirect.iface, 1);
	case NCFG_OP_INGRESS_REDIRECT_CLEAR:
		return ncfg_owned_remember(&owned->ingress, &owned->ingress_count,
		    op->u.iface.iface, 0);
	case NCFG_OP_HOOK_RUN:
		/*
		 * Only the two phases that carry a value. `lease` and `carrier` are
		 * events, and what this remembers is what the script was last told, so
		 * that the next reconcile can tell a new event from the same one
		 * again (0064). A lifecycle phase has no value and nothing to compare.
		 *
		 * **Recorded because the hook ran, which is a divergence and is the
		 * safer half.** The Rust pushes the effect *before* running the hook,
		 * so a script it refused to run -- a content hash that did not match
		 * the approved one -- is recorded as having been told. Here a refusal
		 * is a failed action and folds nothing, so the event is still waiting.
		 * A hook that ran and exited non-zero is `NCFG_HOOK_NOTED`, which is a
		 * successful action, so the case the Rust's comment is actually about
		 * -- an event hook retried on every reconcile for ever -- is closed
		 * here too.
		 */
		if (!op->u.hook.value ||
		    (op->u.hook.phase != (int)NCFG_HOOK_PHASE_LEASE &&
		    op->u.hook.phase != (int)NCFG_HOOK_PHASE_CARRIER)) {
			return 1;
		}
		return ncfg_owned_note_hook_state(owned, op->u.hook.iface, op->u.hook.phase,
		    op->u.hook.value);
	case NCFG_OP_BACKEND_START:
		/* The tally first, so that a start which cannot be recorded does not
		 * leave a backend in the record with no count beside it. */
		if (!restart_counted(owned, op->u.backend.kind, op->u.backend.iface)) {
			return 0;
		}
		return backend_started(owned, op->u.backend.kind, op->u.backend.iface);
	case NCFG_OP_BACKEND_STOP:
		restart_cleared(owned, op->u.backend.kind, op->u.backend.iface);
		backend_stopped(owned, op->u.backend.kind, op->u.backend.iface);
		return 1;
	/*
	 * The rest change the machine and leave nothing this record answers a
	 * question about. Written out rather than swept into a `default`, because
	 * the whole value of the switch above is that an op nobody decided about
	 * cannot compile -- and three of these are worth naming:
	 *
	 *   * `backend.reload` neither starts nor stops anything, so it neither
	 *     counts a restart nor clears one;
	 *   * `dns.apply` is recorded, and not from here: the op names one scope
	 *     and `ncfg_service_dns_apply` delivers every scope its context
	 *     carries, so folding the op's own scope would strand a departed one
	 *     in the record for ever. `ncfg_apply_record` takes the delivered set
	 *     and replaces the record's with it; `apply.h` has the argument;
	 *   * the three commit ops are markers in the plan rather than changes to
	 *     the machine, which is why the executor does nothing for them either.
	 */
	case NCFG_OP_LINK_SET_MTU:
	case NCFG_OP_LINK_SET_MAC:
	case NCFG_OP_LINK_SET_MASTER:
	case NCFG_OP_LINK_UNSET_MASTER:
	case NCFG_OP_LINK_UP:
	case NCFG_OP_LINK_DOWN:
	case NCFG_OP_BACKEND_RELOAD:
	case NCFG_OP_BRIDGE_VLAN_ADD:
	case NCFG_OP_BRIDGE_VLAN_DEL:
	case NCFG_OP_WIFI_SET_PROFILES:
	case NCFG_OP_WIFI_ASSOCIATE:
	case NCFG_OP_WIFI_DISASSOCIATE:
	case NCFG_OP_WIFI_SET_REGDOM:
	case NCFG_OP_ACCESS_CONTROL_ADD:
	case NCFG_OP_ACCESS_CONTROL_DEL:
	case NCFG_OP_LINK_SET_BOND:
	case NCFG_OP_LINK_SET_BRIDGE:
	case NCFG_OP_LINK_SET_MACVLAN:
	case NCFG_OP_LINK_SET_TUNNEL:
	case NCFG_OP_LINK_SET_VXLAN:
	case NCFG_OP_WG_SET_DEVICE:
	case NCFG_OP_WG_SET_PEERS:
	case NCFG_OP_DNS_APPLY:
	case NCFG_OP_LINK_SET_OFFLOADS:
	case NCFG_OP_LINK_SET_IPV6_TOKEN:
	case NCFG_OP_RULE_ADD:
	case NCFG_OP_RULE_DEL:
	case NCFG_OP_HOSTNAME_SET:
	case NCFG_OP_NAT_REPLACE:
	case NCFG_OP_COMMIT_ARM:
	case NCFG_OP_COMMIT_CONFIRM:
	case NCFG_OP_COMMIT_REVERT:
		return 1;
	}
	/* An op outside the taxonomy altogether, which is a value nothing in this
	 * project builds. Refused rather than ignored: a record that quietly
	 * absorbed a number it did not recognise would report having folded it. */
	return 0;
}

/* ------------------------------------------------------------------------ *
 * A whole journal
 * ------------------------------------------------------------------------ */

/* What `ncfg_owned_update` is handed, so that the walk happens under the lock
 * rather than either side of it. */
typedef struct {
	const ncfg_plan_t      *plan;
	const ncfg_journal_t   *journal;
	/* What a `dns.apply` in this journal delivered, or NULL from a caller that
	 * has no scope list -- which leaves the record's alone. */
	const ncfg_dns_scope_t *delivered;
	size_t                  delivered_count;
} fold_t;

/*
 * Replace the delivered DNS scopes with what this apply delivered.
 *
 * **Published and read back rather than copied field by field.** The record
 * holds `ncfg_applied_dns_t`, whose policy is a value with seven owned lists
 * inside it, and a hand-written deep copy of that is a function somebody has to
 * remember to extend the next time `ncfg_dns_policy_t` gains a field -- the
 * quiet half of a drift, since a field that is not copied reads back absent and
 * the planner calls the scope different for ever. The model's own field tables
 * already write a policy and read one, so the copy is one render and one parse
 * through them and cannot fall behind a field they gain.
 *
 * The scopes are borrowed into the writer's own element type, which is a
 * struct copy of a policy nobody frees: `ncfg_applied_dns_write` reads it and
 * nothing else, and the copies the caller keeps are the reader's.
 *
 * **Replaced rather than merged**, which is `state.h`'s rule for this member
 * and the delivery's shape: a scope absent from a delivery is absent from the
 * resolver file it wrote whole, so a record saying otherwise is simply wrong.
 */
static int note_dns(ncfg_owned_state_t *owned, const ncfg_dns_scope_t *scopes, size_t count)
{
	ncfg_applied_dns_t *borrowed = NULL;
	ncfg_applied_dns_t *copied = NULL;
	size_t              copied_count = 0;
	size_t              borrowed_count = 0;
	size_t              at;
	ncfg_buf_t          rendered;
	ncfg_json_writer_t  writer;
	ncfg_json_doc_t    *doc;
	int                 ok;

	if (count != 0u) {
		borrowed = calloc(count, sizeof(*borrowed));
		if (!borrowed) {
			return 0;
		}
		for (at = 0u; at < count; at++) {
			/* A scope with no name or no policy is one nothing could look up
			 * afterwards, and `ncfg_dns_scopes_of` produces neither. Dropped
			 * rather than written as an empty entry, which would read back as
			 * a scope netcfgd delivered nothing to. */
			if (!scopes[at].name || !scopes[at].policy) {
				continue;
			}
			borrowed[borrowed_count].scope = (char *)(uintptr_t)scopes[at].name;
			borrowed[borrowed_count].policy = *scopes[at].policy;
			borrowed_count++;
		}
	}
	ncfg_buf_init(&rendered, 0u);
	ncfg_json_write_init(&writer, &rendered);
	ncfg_applied_dns_write(&writer, borrowed, borrowed_count);
	free(borrowed);
	if (ncfg_buf_failed(&rendered)) {
		ncfg_buf_free(&rendered);
		return 0;
	}
	doc = ncfg_json_parse(ncfg_buf_text(&rendered), strlen(ncfg_buf_text(&rendered)), NULL, 0u);
	ncfg_buf_free(&rendered);
	if (!doc) {
		return 0;
	}
	ok = borrowed_count == 0u ||
	    ncfg_applied_dns_read(doc, ncfg_json_root(doc), &copied, &copied_count, NULL, 0u);
	ncfg_json_free(doc);
	if (!ok) {
		ncfg_applied_dns_free(copied, copied_count);
		return 0;
	}
	ncfg_applied_dns_free(owned->dns, owned->dns_count);
	owned->dns = copied;
	owned->dns_count = copied_count;
	return 1;
}

/* The action a record came from, by id rather than by position -- a journal may
 * be assembled from more than one apply, and a position that happened to line
 * up would be a coincidence this relied on. `apply.c` matches the same way. */
static const ncfg_action_t *action_with_id(const ncfg_plan_t *plan, uint32_t id)
{
	size_t at;

	for (at = 0; at < plan->action_count; at++) {
		if (plan->actions[at].id == id) {
			return &plan->actions[at];
		}
	}
	return NULL;
}

static int fold(ncfg_owned_state_t *owned, void *context)
{
	const fold_t *what = context;
	int           delivered_dns = 0;
	size_t        at;

	for (at = 0; at < what->journal->record_count; at++) {
		const ncfg_record_t *record = &what->journal->records[at];
		const ncfg_action_t *action = action_with_id(what->plan, record->id);

		if (!action) {
			continue;
		}
		/*
		 * A `dns.apply` that reached the machine, whichever way round. Its
		 * inverse is a `dns.apply` too, and with a scope list the executor
		 * delivers that list either way -- so what is in force after a revert
		 * is what is in force after the action, and one flag covers both.
		 */
		if ((record->outcome == NCFG_OUTCOME_DONE ||
		        record->outcome == NCFG_OUTCOME_REVERTED) &&
		    action->op.kind == NCFG_OP_DNS_APPLY) {
			delivered_dns = 1;
		}
		if (record->outcome == NCFG_OUTCOME_DONE) {
			if (!ncfg_owned_absorb(owned, &action->op)) {
				return 0;
			}
		} else if (record->outcome == NCFG_OUTCOME_REVERTED && action->has_inverse) {
			/* What is in effect now is the inverse, so that is what the
			 * record says. Without this the file would go on claiming every
			 * object a window that closed unconfirmed has just given back. */
			if (!ncfg_owned_absorb(owned, &action->inverse)) {
				return 0;
			}
		}
		/* `failed` and `skipped` changed nothing, and a `reverted` action with
		 * no declared inverse is one the revert could not put back -- so the
		 * original op is still in effect and the record it wrote stands. */
	}
	/* And the one member no op is. A caller with no list leaves it alone,
	 * which costs one re-delivery on the next pass; `apply.h` has why that is
	 * the right direction and what the absence of any writer at all cost. */
	if (delivered_dns && what->delivered) {
		return note_dns(owned, what->delivered, what->delivered_count);
	}
	return 1;
}

int ncfg_apply_record(const char *run_dir, const ncfg_plan_t *plan,
    const ncfg_journal_t *journal, const ncfg_dns_scope_t *delivered, size_t delivered_count,
    char *err, size_t err_size)
{
	fold_t what;

	if (!run_dir || !run_dir[0] || !plan || !journal) {
		ncfg_error_set(err, err_size,
		    "recording what an apply did needs a run directory, the plan and its "
		    "journal");
		return 0;
	}
	if (journal->record_count == 0u) {
		/* Nothing ran, so nothing is written -- not even the read and the
		 * rewrite, which on an already-correct machine is every tick. */
		return 1;
	}
	what.plan = plan;
	what.journal = journal;
	what.delivered = delivered;
	what.delivered_count = delivered ? delivered_count : 0u;
	if (ncfg_owned_update(run_dir, fold, &what, err, err_size)) {
		return 1;
	}
	/*
	 * `ncfg_owned_update` leaves `err` alone when the *change* is what refused,
	 * because a caller returning 0 from it is ordinarily saying "nothing to
	 * record after all". Here it can only be an allocation failure or an op
	 * carrying no interface, and a refusal with no sentence in it is one the
	 * caller logs as an empty pair of brackets.
	 */
	if (err && err_size && err[0] == '\0') {
		ncfg_error_set(err, err_size,
		    "the record of what this apply did could not be built");
	}
	return 0;
}

/* ------------------------------------------------------------------------ *
 * The journal of the last apply
 * ------------------------------------------------------------------------ */

/* `<run_dir>/<leaf>`, or 0 with a sentence where it would not fit. */
static int run_path(char *out, size_t out_size, const char *run_dir, const char *leaf,
    char *err, size_t err_size)
{
	int written = snprintf(out, out_size, "%s/%s", run_dir, leaf);

	if (written < 0 || (size_t)written >= out_size) {
		out[0] = '\0';
		ncfg_error_set(err, err_size,
		    "this run directory's path for %s is longer than the %u bytes netcfgd "
		    "builds one in", leaf, (unsigned)out_size);
		return 0;
	}
	return 1;
}

int ncfg_apply_write_journal(const char *run_dir, const ncfg_journal_t *journal, char *err,
    size_t err_size)
{
	char        path[RUN_PATH_MAX];
	char        lock_path[RUN_PATH_MAX];
	ncfg_lock_t lock;
	ncfg_buf_t  text;
	int         ok;

	if (!run_dir || !run_dir[0] || !journal) {
		ncfg_error_set(err, err_size,
		    "writing the journal of the last apply needs a run directory and the "
		    "journal");
		return 0;
	}
	if (!run_path(path, sizeof(path), run_dir, "plan.last.json", err, err_size) ||
	    !run_path(lock_path, sizeof(lock_path), run_dir, "owned.lock", err, err_size)) {
		return 0;
	}
	/*
	 * Rendered before the lock is taken, so that what is held is a rename and
	 * nothing else. A journal is at most a plan's worth of records and the
	 * buffer has a ceiling of its own, so this cannot grow with how long
	 * somebody else waits.
	 */
	ncfg_buf_init(&text, 0);
	if (!ncfg_journal_write(journal, &text, err, err_size) || ncfg_buf_failed(&text)) {
		if (err && err_size && err[0] == '\0') {
			ncfg_error_set(err, err_size,
			    "the journal of this apply could not be rendered");
		}
		ncfg_buf_free(&text);
		return 0;
	}
	/*
	 * `owned.lock`, which is the fold's, for the reason `apply.h` gives: these
	 * two files are the two halves of one statement about one apply, and two
	 * processes write both. **A failure to take it is returned rather than
	 * swallowed**, which is `ncfg_owned_update`'s rule -- writing anyway is the
	 * behaviour the lock replaces.
	 */
	ncfg_lock_init(&lock);
	if (!ncfg_lock_take(&lock, lock_path, err, err_size)) {
		ncfg_buf_free(&text);
		return 0;
	}
	/* 0644: `state.h` says everything under the run directory answers a
	 * question without netcfgd running, and this is the file an operator is
	 * sent to when an apply stopped somewhere. Nothing in it is a secret --
	 * `apply.h` is why the six ops that would carry one take the device's name
	 * instead. */
	ok = ncfg_write_atomically(path, ncfg_buf_text(&text), text.length, 0644u, err, err_size);
	ncfg_lock_release(&lock);
	ncfg_buf_free(&text);
	return ok;
}
