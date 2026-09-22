/*
 * wedged.c -- a backend that is running and will not answer.
 *
 * WHY THIS IS A WARNING AND NOT A RESTART
 *   **netcfgd cannot tell a wedged daemon from a slow answer on a loaded
 *   machine.** The round trip behind `answering` has a one-second deadline on
 *   purpose, so that a wedged daemon cannot stall the reconcile loop -- and a
 *   healthy fake has already missed it under load in the Rust's own live
 *   tests. Acting on that reading would kill working access points on busy
 *   machines, which is a worse failure than the one being reported.
 *
 *   So 0141's rule: **a wedged backend fails loudly and is restarted only when
 *   asked.** The operator is told, the refusal names the exact invocation that
 *   consents, and `--restart-wedged <iface>` is what turns the report into two
 *   actions.
 *
 * WHY THE CONSENT IS STILL BOUNDED
 *   By 0079's counter, the same one an ordinary start is bounded by. Consent
 *   to restarting a wedged backend is not consent to an endless loop, and a
 *   machine that is merely slow would otherwise be restarted for ever by a
 *   single `--restart-wedged`.
 *
 * WHY `answering` ABSENT IS NOT "NOT ANSWERING"
 *   0074's rule, and it is why the filter below is `has && !value` rather than
 *   `!value`: absent means the kind has no control socket or nothing asked,
 *   and reading it as a wedge would put this warning on every DHCP client on
 *   the machine.
 */
#include "plan_internal.h"

#include "ncfg/base.h"

#include <stdio.h>
#include <string.h>

/*
 * The noun an operator would use.
 *
 * Named arms rather than a table of every kind, which is the Rust's shape and
 * its reason: only a round trip sets `answering`, so each kind that gains one
 * gains its noun here in the same change. The fallback is not a guess about a
 * kind nobody asked.
 */
static const char *noun_of(int kind)
{
	if (kind == NCFG_BACKEND_ACCESS_POINT) {
		return "access point";
	}
	if (kind == NCFG_BACKEND_SUPPLICANT) {
		return "supplicant";
	}
	return "backend";
}

/* What the reason says, which is the same for the warning, the refusal and the
 * restart: this is one finding with three possible answers. */
static ncfg_reason_t why(const char *interface)
{
	return ncfg_plan_reason_differs(interface, "backend.answering",
	    "answering its control socket", "running and silent");
}

/* Stop and start again, as two actions, each the inverse of the other. */
static void restart(ncfg_builder_t *builder, int kind, const char *interface)
{
	ncfg_op_t     stop;
	ncfg_op_t     start;
	ncfg_reason_t reason = why(interface);
	uint32_t      id;

	if (ncfg_observed_backend_restarts(builder->observed, kind, interface) >=
	    NCFG_PLAN_RESTART_LIMIT) {
		/* Said by `ncfg_plan_backend`'s own limit for an ordinary start; here
		 * the plan simply stops short, because the warning above has already
		 * told the operator what is wrong and a second sentence about the
		 * counter would be about netcfgd rather than about the daemon. */
		return;
	}
	memset(&stop, 0, sizeof(stop));
	stop.kind = NCFG_OP_BACKEND_STOP;
	stop.u.backend.kind = kind;
	stop.u.backend.iface = interface;
	memset(&start, 0, sizeof(start));
	start.kind = NCFG_OP_BACKEND_START;
	start.u.backend.kind = kind;
	start.u.backend.iface = interface;

	id = ncfg_builder_push(builder, &stop, &reason, NULL, 0u, &start);
	if (id == NCFG_PLAN_NO_ACTION) {
		/* A guard stopped it, or the device is unmanaged. Starting what was
		 * never stopped would leave two of them. */
		return;
	}
	(void)ncfg_builder_push(builder, &start, &reason, &id, 1u, &stop);
}

void ncfg_plan_wedged_backends(ncfg_builder_t *builder)
{
	size_t at;

	for (at = 0; at < builder->observed->backend_count; at++) {
		const ncfg_observed_backend_t *backend = &builder->observed->backends[at];
		const char                    *what;
		ncfg_refusal_t                 refusal;
		char                           consent[NCFG_ERROR_MAX];

		if (!backend->running || !backend->answering.has || backend->answering.value) {
			continue;
		}
		if (!backend->interface) {
			continue;
		}
		what = noun_of(backend->kind);
		ncfg_plan_warnf(builder->plan, backend->interface,
		    "the %s on %s is running and did not answer its control socket. netcfgd "
		    "cannot configure it while it is like this, and does not restart it by "
		    "default -- a busy machine can miss the deadline too, and killing a "
		    "healthy daemon is worse than saying so",
		    what, backend->interface);

		(void)snprintf(consent, sizeof(consent), "ncfg apply --restart-wedged %s",
		    backend->interface);
		if (builder->options &&
		    ncfg_plan_names(builder->options->restart_wedged,
		        builder->options->restart_wedged_count, backend->interface)) {
			restart(builder, backend->kind, backend->interface);
			continue;
		}
		/*
		 * **First-class rather than a second warning line**, because "what did
		 * netcfgd decline, and how do I consent?" is a question a script has
		 * to answer as well as a person (0010) -- and because a restart that
		 * drops an association is exactly the kind of act this type exists to
		 * make deliberate.
		 */
		memset(&refusal, 0, sizeof(refusal));
		refusal.interface = backend->interface;
		refusal.op = "backend.restart";
		refusal.guard = "the backend is running and silent, and netcfgd will not kill a "
		                "daemon that may only be busy";
		refusal.reason = why(backend->interface);
		refusal.override_with = consent;
		ncfg_plan_refuse(builder->plan, &refusal);
	}
}
