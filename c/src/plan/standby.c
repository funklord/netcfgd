/*
 * standby.c -- which links a `linkset` is not using, and what that withholds.
 *
 * WHAT A SET MEANS TO A PLANNER
 *   `linkset.h` decides which member of a group carries traffic; this turns
 *   that decision into the one thing a planner can do about it -- withhold the
 *   routes of everything else in the set. A set's whole meaning is that one
 *   member is in use at a time, and a spare that keeps a default route at a
 *   worse metric is not a spare: it is a second path the kernel falls back to
 *   without anything having decided that it works.
 *
 *   Being in a set is the opt-in, exactly as `preference` is for the carrier
 *   and probe rules beside it. A machine with no `linkset` block collects
 *   nothing here and is not touched by any of it.
 *
 * WHY IT IS COLLECTED ONCE AND NOT ASKED PER ROUTE
 *   `ncfg_linkset_choose` walks the set, its nested sets, the link table and
 *   the probe verdicts. Asking it per route would make the cost of planning
 *   scale with the number of routes an operator wrote, for an answer that
 *   cannot change inside one plan -- and it allocates, so a route path that
 *   asked would have to carry a failure it has nowhere to put.
 *
 *   **An interface any set chose is in none of these.** A link may be in two
 *   sets -- the modem that is the uplink's last resort and the out-of-band
 *   set's only member -- and one of them wanting it is enough for it to be
 *   carrying traffic.
 *
 * WHERE THIS DIFFERS FROM `standby_interfaces` IN THE RUST
 *   The Rust collects into a `HashMap<String, (String, Option<String>)>` and
 *   filters the chosen out at the end. This keeps a counted array and replaces
 *   in place, which is the same "last set wins" a `collect` into a map gives,
 *   and interns the three strings into the plan: the choice is freed before
 *   the first route is planned, and a borrowed name would be read afterwards.
 */
#include "plan_internal.h"

#include "ncfg/base.h"
#include "ncfg/linkset.h"

#include <stdlib.h>
#include <string.h>

/* Record that this interface is a spare of this set, replacing what an earlier
 * set said about it -- which is what collecting into a map does. */
static void reserve(ncfg_builder_t *builder, const char *interface, const char *set,
    const char *instead)
{
	ncfg_plan_standby_t *grown;
	size_t               i;

	for (i = 0; i < builder->standby_count; i++) {
		if (strcmp(builder->standby[i].interface, interface) == 0) {
			builder->standby[i].set = set;
			builder->standby[i].instead = instead;
			return;
		}
	}
	grown = realloc(builder->standby, (builder->standby_count + 1u) * sizeof(*grown));
	if (!grown) {
		builder->plan->failed = 1;
		return;
	}
	builder->standby = grown;
	grown[builder->standby_count].interface = interface;
	grown[builder->standby_count].set = set;
	grown[builder->standby_count].instead = instead;
	builder->standby_count++;
}

/* Drop every entry naming an interface some set is actually using. */
static void drop_the_chosen(ncfg_builder_t *builder, const char *const *chosen,
    size_t chosen_count)
{
	size_t kept = 0;
	size_t i;

	for (i = 0; i < builder->standby_count; i++) {
		if (ncfg_plan_names(chosen, chosen_count, builder->standby[i].interface)) {
			continue;
		}
		builder->standby[kept++] = builder->standby[i];
	}
	builder->standby_count = kept;
}

void ncfg_plan_standby_collect(ncfg_builder_t *builder)
{
	const char **chosen = NULL;
	size_t       chosen_count = 0;
	size_t       i;
	size_t       j;

	for (i = 0; i < builder->desired->linkset_count; i++) {
		const ncfg_linkset_t *set = &builder->desired->linksets[i];
		ncfg_chosen_t        *decision = NULL;
		char                  message[NCFG_ERROR_MAX];
		const char           *set_name;
		const char           *instead = NULL;

		if (!set->name) {
			continue;
		}
		message[0] = '\0';
		if (!ncfg_linkset_choose(builder->desired, builder->observed, set->name, &decision,
		    message, sizeof(message))) {
			/*
			 * The only way this answers no is an allocation, which is the
			 * plan's own failure and is reported as one. Warning instead would
			 * put a sentence about memory in front of an operator and then go
			 * on to install routes the set says are not wanted.
			 */
			builder->plan->failed = 1;
			break;
		}
		if (!decision) {
			continue;
		}
		set_name = ncfg_plan_intern(builder->plan, set->name);
		if (decision->active) {
			instead = ncfg_plan_intern(builder->plan, decision->active);
		}
		if (!set_name || (decision->active && !instead)) {
			builder->plan->failed = 1;
			ncfg_chosen_free(decision);
			break;
		}
		if (decision->interface) {
			const char *winner = ncfg_plan_intern(builder->plan, decision->interface);

			if (!winner) {
				builder->plan->failed = 1;
				ncfg_chosen_free(decision);
				break;
			}
			ncfg_builder_note_string(builder, &chosen, &chosen_count, winner);
		}
		for (j = 0; j < decision->member_count; j++) {
			const char *member;

			/* A member with nothing carrying it has no route to withhold: an
			 * absent interface, a saved network no radio is on. */
			if (!decision->members[j].interface) {
				continue;
			}
			member = ncfg_plan_intern(builder->plan, decision->members[j].interface);
			if (!member) {
				builder->plan->failed = 1;
				break;
			}
			reserve(builder, member, set_name, instead);
		}
		ncfg_chosen_free(decision);
	}
	drop_the_chosen(builder, chosen, chosen_count);
	free(chosen);
}

void ncfg_plan_standby_free(ncfg_builder_t *builder)
{
	free(builder->standby);
	builder->standby = NULL;
	builder->standby_count = 0;
}

int ncfg_plan_standby_of(const ncfg_builder_t *builder, const char *name, const char **set_out,
    const char **instead_out)
{
	size_t i;

	if (!name) {
		return 0;
	}
	for (i = 0; i < builder->standby_count; i++) {
		if (strcmp(builder->standby[i].interface, name) != 0) {
			continue;
		}
		if (set_out) {
			*set_out = builder->standby[i].set;
		}
		if (instead_out) {
			*instead_out = builder->standby[i].instead;
		}
		return 1;
	}
	return 0;
}

void ncfg_plan_standby_warn(ncfg_builder_t *builder, const char *name)
{
	const char *set = NULL;
	const char *instead = NULL;

	if (!ncfg_plan_standby_of(builder, name, &set, &instead)) {
		return;
	}
	if (instead) {
		ncfg_plan_warnf(builder->plan, name,
		    "`%s` is using %s, so %s's routes are not installed", set, instead, name);
		return;
	}
	ncfg_plan_warnf(builder->plan, name,
	    "`%s` has nothing it can use, so %s's routes are not installed", set, name);
}
