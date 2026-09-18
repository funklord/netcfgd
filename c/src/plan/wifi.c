/*
 * wifi.c -- the networks a supplicant is given, the station lists an access
 * point enforces, and the radio settings this build stores and does not act
 * on.
 *
 * WHAT A RUNNING SUPPLICANT IS NOT
 *   **Running is not the same as holding what the document says.** The Rust
 *   returned from its backend pass as soon as a supplicant was up, and the
 *   call that hands the networks over had one caller -- the `backend.start`
 *   arm -- so a supplicant that was already running was never given anything
 *   again. Measured there: changing a passphrase, pinning a `bssid`, adding a
 *   network and deleting one each planned `nothing to do`, and the supplicant
 *   kept the original credentials indefinitely. 0015 says netcfgd's next
 *   reconcile removes a network the document does not contain; this is that
 *   reconcile.
 *
 *   The question is asked of the observation rather than of the document:
 *   `networks_match` is the answer the observer computed, and absent is not
 *   false -- not a supplicant, no record of what netcfgd handed over, or a
 *   network that names access points instead of an SSID all leave it
 *   unanswered, and an unanswered question is not a reason to re-send.
 *
 * WHY BOTH STATION LISTS, ALWAYS
 *   hostapd's `hostapd_check_acl` consults the accept list *first* and the
 *   deny list second, whatever `macaddr_acl` says -- that value decides only
 *   what happens to an address in neither. So a station left on the accept
 *   list overrides the deny list that is supposed to be refusing it, and
 *   leaving the unused list alone would be leaving the failure this feature
 *   exists to remove.
 *
 * AND WHY A POLICY THAT MOVED IS NOT CONVERGED
 *   `macaddr_acl` cannot be changed over hostapd's control socket, so a
 *   document that went from `deny` to `allow` needs the access point
 *   restarted. Converging the lists without that would enforce the new list
 *   under the old default -- every unlisted station accepted, reported as
 *   applied. **This build plans no backend actions**, so it says so and
 *   converges nothing, which is the same answer `unknown` gets and for the
 *   same reason: emptying a list without knowing which one hostapd reads
 *   either opens a network or closes it.
 *
 * THE THREE RADIO SETTINGS THAT REACH NOTHING
 *   `regdom` and `powersave` on a `device`'s `wifi` block have no consumer
 *   anywhere -- no planner reads them, no executor writes them, and
 *   `wifi.set_regdom` is an op nothing constructs. They are parsed, kept in
 *   the document and rendered back by `ncfg profile save`, which is the shape
 *   0061 exists to prevent. Said only where the document states them: a radio
 *   at its defaults is not asking for anything.
 */
#include "plan_internal.h"

#include "ncfg/base.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ------------------------------------------------------------------------ *
 * What this build holds and does not act on
 * ------------------------------------------------------------------------ */

/*
 * Say which radio settings this build stores and does not act on.
 *
 * **The clause used to be fixed -- "nothing sets the regulatory domain or the
 * power-saving mode" -- and the first half was false.** hostapd's own
 * documentation calls `country_code` the way a regulatory domain is set, and
 * netcfgd writes that from an *access point's* `regdom`, so a plan could warn
 * that nothing sets the domain in the same breath as starting the thing that
 * sets it (0221). So the reason is gathered beside the name, and the sentence
 * says it about the settings that were actually written.
 */
static void warn_device_policy(ncfg_builder_t *builder, const ncfg_device_t *device)
{
	const ncfg_wifi_device_policy_t *wifi = device->wifi;
	const char                      *stated[2];
	const char                      *because[2];
	size_t                           count = 0;
	ncfg_buf_t                       names;
	ncfg_buf_t                       reasons;
	size_t                           i;

	if (wifi->regdom) {
		stated[count] = "`regdom`";
		because[count] = "a radio's `regdom` reaches nothing, and an access point's is "
		    "the only one this build writes -- as hostapd's `country_code`";
		count++;
	}
	if (wifi->powersave != NCFG_POWERSAVE_DEFAULT) {
		stated[count] = "`powersave`";
		because[count] = "nothing sets the power-saving mode";
		count++;
	}
	/* `scan_randomization` is deliberately not here: it sets the supplicant's
	 * `preassoc_mac_addr`, which is the address in probe requests (0220). */
	if (count == 0u) {
		return;
	}
	ncfg_buf_init(&names, 0);
	ncfg_buf_init(&reasons, 0);
	for (i = 0; i < count; i++) {
		ncfg_buf_addf(&names, "%s%s", i ? " and " : "", stated[i]);
		ncfg_buf_addf(&reasons, "%s%s", i ? "; and " : "", because[i]);
	}
	ncfg_plan_warnf(builder->plan, device->name,
	    "%s on %s %s understood and not acted on by this build: %s. The setting is kept, "
	    "so a configuration written now still means this when the code arrives",
	    ncfg_buf_text(&names), device->name, count == 1u ? "is" : "are",
	    ncfg_buf_text(&reasons));
	ncfg_buf_free(&names);
	ncfg_buf_free(&reasons);
}

/*
 * Say where a regulatory domain was written and will not arrive.
 *
 * **The language spells `regdom` twice and only one of them does anything.** A
 * radio's is stored and not acted on, and the warning above says so; an access
 * point's becomes hostapd's `country_code`. So the setting that looks like it
 * belongs to the radio is the inert one, and the one an operator adds almost
 * as an afterthought to an access point is the one that takes effect.
 *
 * Warned only where a *radio* names one, which is what keeps this quiet: an
 * access point with a `regdom` and a radio with none is the ordinary
 * arrangement and asks nothing, and an access point with neither is a machine
 * that has not been told about regulatory domains.
 *
 * Compared case-insensitively, because the compiler uppercases both and a
 * document can reach the planner without passing through it.
 */
static void warn_regdom(ncfg_builder_t *builder)
{
	size_t i;

	for (i = 0; i < builder->desired->access_point_count; i++) {
		const ncfg_access_point_t *point = &builder->desired->access_points[i];
		const ncfg_device_t       *device =
		    ncfg_plan_device(builder->desired, point->device);
		const char                *radio =
		    (device && device->wifi) ? device->wifi->regdom : NULL;

		if (!radio) {
			continue;
		}
		if (point->regdom && strcasecmp(point->regdom, radio) == 0) {
			continue;
		}
		if (point->regdom) {
			ncfg_plan_warnf(builder->plan, point->device,
			    "`%s` and the access point `%s` running on it name different "
			    "regulatory domains -- the radio says `%s` and the access point "
			    "says `%s` -- and the access point's is the one netcfgd writes, as "
			    "hostapd's `country_code`. The radio's is stored and not acted on, "
			    "so this machine gets `%s`",
			    point->device, point->id, radio, point->regdom, point->regdom);
			continue;
		}
		ncfg_plan_warnf(builder->plan, point->device,
		    "`%s` names `regdom = \"%s\"` and the access point `%s` running on it names "
		    "none, so nothing carries it to hostapd: a radio's `regdom` is stored and "
		    "not acted on by this build, and an access point's is the only one that "
		    "becomes a `country_code`. Write `regdom = \"%s\"` in the access point as "
		    "well",
		    point->device, radio, point->id, radio);
	}
}

/*
 * The half of the wireless configuration no pass here reads.
 *
 * `build.c`'s `warn_unported` carried one sentence per block and this is what
 * three of its arms became: the passes below act on part of each, so a blanket
 * "nothing in the plan above is about it" would now be false, and deleting the
 * arms outright would make a plan quieter than the configuration it was given
 * -- which is the hazard that function exists for.
 */
static void warn_held(ncfg_builder_t *builder)
{
	size_t i;

	for (i = 0; i < builder->desired->device_count; i++) {
		const ncfg_device_t *device = &builder->desired->devices[i];

		if (!device->wifi) {
			continue;
		}
		warn_device_policy(builder, device);
		ncfg_plan_warnf(builder->plan, device->name,
		    "the supplicant that would serve `%s` is not started by this build of the "
		    "planner, which plans no backend actions at all: the configured networks "
		    "are handed to one that is already running and to nothing else",
		    device->name);
	}
	warn_regdom(builder);
	if (builder->desired->network_count != 0u) {
		ncfg_plan_warn(builder->plan, NULL,
		    "a `network` block's addressing, routes, `dns` policy, hooks and metric are "
		    "carried in the document and this build of the planner does not act on "
		    "them; only the set of network ids is handed to a running supplicant");
	}
	if (builder->desired->access_point_count != 0u) {
		ncfg_plan_warn(builder->plan, NULL,
		    "an `access_point` block's ssid, band, channel, security and `regdom` are "
		    "carried in the document and this build of the planner does not act on "
		    "them -- nothing here starts, configures or restarts hostapd, so an edited "
		    "identity is not noticed and only the station lists of an access point that "
		    "is already running are converged");
	}
}

/* ------------------------------------------------------------------------ *
 * The networks a supplicant holds
 * ------------------------------------------------------------------------ */

/* The running backend of this kind on this interface, or NULL. */
static const ncfg_observed_backend_t *backend_of(const ncfg_observed_t *observed, int kind,
    const char *interface)
{
	size_t i;

	for (i = 0; i < observed->backend_count; i++) {
		const ncfg_observed_backend_t *backend = &observed->backends[i];

		if (backend->kind == kind && backend->running && backend->interface &&
		    strcmp(backend->interface, interface) == 0) {
			return backend;
		}
	}
	return NULL;
}

/*
 * Hand the document's networks to every supplicant that is holding something
 * else.
 *
 * Driven from the observation's backend list rather than from the devices,
 * because what makes this actionable is a supplicant that is *running*: a
 * radio with none gets one from the backend pass, which is not in this build,
 * and a wired 802.1X port reaches the same supplicant by the same route
 * (0008). `ncfg_builder_push` drops anything on an unmanaged device, so the
 * `managed = false` rule is honoured without asking here.
 */
static void plan_profiles(ncfg_builder_t *builder)
{
	const char    **profiles;
	ncfg_plan_ids_t gate = { NULL, 0, 0 };
	ncfg_op_t       op;
	ncfg_reason_t   reason;
	size_t          i;

	profiles = NULL;
	if (builder->desired->network_count != 0u) {
		profiles = calloc(builder->desired->network_count, sizeof(*profiles));
		if (!profiles) {
			builder->plan->failed = 1;
			return;
		}
		for (i = 0; i < builder->desired->network_count; i++) {
			profiles[i] = builder->desired->networks[i].id;
		}
	}
	for (i = 0; i < builder->observed->backend_count; i++) {
		const ncfg_observed_backend_t *backend = &builder->observed->backends[i];

		if (backend->kind != NCFG_BACKEND_SUPPLICANT || !backend->running ||
		    !backend->interface) {
			continue;
		}
		/* Absent is not false: see the header. */
		if (!backend->networks_match.has || backend->networks_match.value) {
			continue;
		}
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_WIFI_SET_PROFILES;
		op.u.set_profiles.device = backend->interface;
		op.u.set_profiles.profiles = profiles;
		op.u.set_profiles.profile_count = builder->desired->network_count;
		reason = ncfg_plan_reason_differs(backend->interface, "networks",
		    "the document's", "what the supplicant was given");
		ncfg_builder_gate(builder, backend->interface, &gate);
		/*
		 * No inverse: what it replaced is not recorded anywhere a revert
		 * could read, and 0015's whole point is that the supplicant holds
		 * nothing netcfgd is not the author of. A revert re-plans against the
		 * last-good document and hands them over again.
		 */
		(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count, NULL);
		ncfg_plan_ids_free(&gate);
	}
	free(profiles);
}

void ncfg_plan_wifi(ncfg_builder_t *builder)
{
	warn_held(builder);
	plan_profiles(builder);
}

/* ------------------------------------------------------------------------ *
 * The station lists an access point enforces
 * ------------------------------------------------------------------------ */

static int lists(char *const *list, size_t count, const char *station)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (list[i] && strcmp(list[i], station) == 0) {
			return 1;
		}
	}
	return 0;
}

/* Add and remove until one of hostapd's lists holds what the document says. */
static void converge_list(ncfg_builder_t *builder, const char *device, int list,
    char *const *want, size_t want_count, char *const *live, size_t live_count)
{
	static const char *const field = "access_point.access_control.stations";
	ncfg_op_t                op;
	ncfg_op_t                inverse;
	ncfg_reason_t            reason;
	size_t                   i;

	for (i = 0; i < want_count; i++) {
		if (lists(live, live_count, want[i])) {
			continue;
		}
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_ACCESS_CONTROL_ADD;
		op.u.access_control.iface = device;
		op.u.access_control.list = list;
		op.u.access_control.station = want[i];
		memset(&inverse, 0, sizeof(inverse));
		inverse.kind = NCFG_OP_ACCESS_CONTROL_DEL;
		inverse.u.access_control.iface = device;
		inverse.u.access_control.list = list;
		inverse.u.access_control.station = want[i];
		reason = ncfg_plan_reason_absent(device, field,
		    ncfg_plan_internf(builder->plan, "%s (%s)", want[i],
		    ncfg_plan_acl_policy_word(list)));
		(void)ncfg_builder_push(builder, &op, &reason, NULL, 0, &inverse);
	}
	for (i = 0; i < live_count; i++) {
		if (lists(want, want_count, live[i])) {
			continue;
		}
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_ACCESS_CONTROL_DEL;
		op.u.access_control.iface = device;
		op.u.access_control.list = list;
		op.u.access_control.station = live[i];
		memset(&inverse, 0, sizeof(inverse));
		inverse.kind = NCFG_OP_ACCESS_CONTROL_ADD;
		inverse.u.access_control.iface = device;
		inverse.u.access_control.list = list;
		inverse.u.access_control.station = live[i];
		reason = ncfg_plan_reason_unwanted(device, field,
		    ncfg_plan_internf(builder->plan, "%s (%s)", live[i],
		    ncfg_plan_acl_policy_word(list)));
		(void)ncfg_builder_push(builder, &op, &reason, NULL, 0, &inverse);
	}
}

void ncfg_plan_access_control(ncfg_builder_t *builder)
{
	size_t at;

	for (at = 0; at < builder->desired->access_point_count; at++) {
		const ncfg_access_point_t            *point =
		    &builder->desired->access_points[at];
		const char                           *device = point->device;
		const ncfg_observed_backend_t        *running;
		const ncfg_observed_access_control_t *live;
		const ncfg_access_control_t          *wanted;
		int                                   policy = 0;
		int                                   has_policy = 0;
		size_t                                i;

		/*
		 * One radio is one BSS in this build, and the one that runs is the
		 * first by id -- the same answer the executor gives. Without this the
		 * *second* access point on a radio compares its own identity against
		 * what the first started with, finds a difference that is not one,
		 * and converges for ever. `access_points` is sorted by id, so "the
		 * first" is a stable answer.
		 */
		for (i = 0; i < builder->desired->access_point_count; i++) {
			if (strcmp(builder->desired->access_points[i].device, device) == 0) {
				break;
			}
		}
		if (i != at) {
			continue;
		}
		running = backend_of(builder->observed, NCFG_BACKEND_ACCESS_POINT, device);
		if (!running || !running->access_control) {
			continue;
		}
		live = running->access_control;
		wanted = point->access_control;

		if (live->policy.kind == NCFG_OBSERVED_POLICY_UNKNOWN) {
			/*
			 * No record, so netcfgd does not know which list this hostapd
			 * consults by default. Nothing may be converged from here: under
			 * `deny` an empty accept list is nothing, and under `allow` it is
			 * a network nobody can join. Converging against a guess is how an
			 * access point ends up closed at three in the morning.
			 */
			ncfg_plan_warnf(builder->plan, device,
			    "netcfgd has no record of which access control policy the access "
			    "point running on %s was started with, so its station list is left "
			    "alone. Restarting it writes the record",
			    device);
			continue;
		}
		if (live->policy.kind == NCFG_OBSERVED_POLICY_SET && wanted &&
		    live->policy.policy == wanted->policy) {
			/* Running what the document asks for: the ordinary case, and the
			 * one the whole feature is for. */
			policy = wanted->policy;
			has_policy = 1;
		} else if (live->policy.kind == NCFG_OBSERVED_POLICY_UNSET && !wanted) {
			has_policy = 0;
		} else {
			/*
			 * A policy change, which hostapd will not take over the control
			 * socket. The Rust restarts the access point here; this build
			 * plans no backend actions, so it says what is wrong and
			 * converges nothing -- enforcing the new list under the old
			 * default is the one outcome worse than doing nothing.
			 */
			ncfg_plan_warnf(builder->plan, device,
			    "the access control policy on %s is `%s` in the config and `%s` in "
			    "the access point that is running, and hostapd only reads it at "
			    "startup -- so its station lists are left alone. Restarting the "
			    "access point is what applies it, and this build of the planner "
			    "does not start, stop or restart a backend",
			    device,
			    wanted ? ncfg_plan_acl_policy_word(wanted->policy) : "<absent>",
			    live->policy.kind == NCFG_OBSERVED_POLICY_SET ?
			    ncfg_plan_acl_policy_word(live->policy.policy) : "<absent>");
			continue;
		}

		/* Both lists, always. See the header. */
		{
			static const int both[] = { NCFG_ACL_POLICY_DENY, NCFG_ACL_POLICY_ALLOW };

			for (i = 0; i < sizeof(both) / sizeof(both[0]); i++) {
				size_t       live_count = 0;
				char *const *held = ncfg_observed_access_control_list(live,
				    both[i], &live_count);
				int          mine = has_policy && policy == both[i];

				converge_list(builder, device, both[i],
				    mine && wanted ? wanted->stations : NULL,
				    mine && wanted ? wanted->station_count : 0u, held,
				    live_count);
			}
		}
	}
}
