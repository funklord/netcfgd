/*
 * session.c -- the daemon that brings a ppp link or a tunnel into existence.
 *
 * WHY THIS IS A PASS OF ITS OWN
 *   Every other backend is started for an interface that already exists: a
 *   DHCP client needs a link to lease on, a supplicant a radio to associate
 *   with, an access point a device to put into AP mode. A PPPoE session and an
 *   OpenVPN tunnel are the other way round -- **the daemon is what creates the
 *   interface**. `pppd` makes `ppp0` when the session comes up and `openvpn`
 *   makes `tun0` when the handshake finishes, so there is no `link.create` to
 *   plan and nothing to address until the daemon has run.
 *
 * WHY IT IS DRIVEN FROM THE DEVICE WALK
 *   Two reasons, and the Rust paid for both.
 *
 *   **The link is absent, which is where every other pass gives up.**
 *   `ncfg_plan_link_is_plannable` answers no for a pppoe or an openvpn device
 *   whose link is not there -- correctly, for addresses and routes, which have
 *   nothing to be attached to -- and the device loop in `build.c` skips such a
 *   device entirely. So this call sits *before* that guard: the one action
 *   that would make the link exist cannot be gated on the link existing.
 *
 *   **And a tunnel need not have an `interface` block at all.** It has nothing
 *   to address until the daemon reports something, so a document may carry the
 *   `device` and no interface -- and a pass driven from the interface walk
 *   would never see it (0155 pass 1b).
 *
 * WHY IT IS NOT ALSO IN THE INTERFACE WALK
 *   Because it was, in the Rust, at the same time as being here: two
 *   `backend.start` actions for one session, so every apply ran `pppd` twice.
 *   Nothing caught it because the fixture asserted the action was *present*
 *   rather than how many there were -- which is why `plan_session_test.c`
 *   counts them.
 *
 * WHY A RUNNING DAEMON IS NOT RE-PLANNED, AND A DEAD ONE IS
 *   `ncfg_plan_backend` returns at once for a backend the observation says is
 *   running, so a converged machine plans nothing. The reverse case is why
 *   this is not inside an "is the link absent" branch: a tunnel whose daemon
 *   had died while its device lingered would never be restarted.
 */
#include "plan_internal.h"

#include <string.h>

/* Which backend a device's kind asks for, or 0 where it asks for none. */
static int session_kind_of(const ncfg_device_t *device, const char **field)
{
	if (!device) {
		return 0;
	}
	if (device->kind.kind == NCFG_KIND_PPPOE) {
		*field = "pppoe";
		return NCFG_BACKEND_PPPOE;
	}
	if (device->kind.kind == NCFG_KIND_OPENVPN) {
		*field = "openvpn";
		return NCFG_BACKEND_OPENVPN;
	}
	return 0;
}

void ncfg_plan_session(ncfg_builder_t *builder, const ncfg_device_t *device)
{
	ncfg_plan_ids_t base = { NULL, 0, 0 };
	ncfg_plan_ids_t started = { NULL, 0, 0 };
	const char     *field = NULL;
	int             kind = session_kind_of(device, &field);

	if (kind == 0) {
		return;
	}
	/* The same gate every other pass takes, so a guard on this interface stops
	 * the dial as it stops everything else. */
	ncfg_builder_gate(builder, device->name, &base);
	ncfg_plan_backend(builder, device->name, kind, field, &base, &started);
	if (!ncfg_observed_link(builder->observed, device->name)) {
		/*
		 * **Said once, here, rather than by the creation pass.** That pass
		 * used to warn that nothing would bring the device into existence,
		 * which stopped being true the moment this one landed -- `build.c`'s
		 * rule is that a pass landing takes its warning out in the same
		 * commit. What is left to say is the thing an operator reading a plan
		 * for a DSL line actually needs: the addressing is not missing, it is
		 * waiting.
		 */
		ncfg_plan_warnf(builder->plan, device->name,
		    "%s is not up yet; addressing and routes are planned once its %s daemon "
		    "has brought it into existence",
		    device->name, field);
	}
	ncfg_plan_ids_free(&started);
	ncfg_plan_ids_free(&base);
}

int ncfg_plan_session_wanted(const ncfg_document_t *desired, const char *name, int kind)
{
	const ncfg_device_t *device = ncfg_plan_device(desired, name);
	const char          *field = NULL;

	/*
	 * **The device, not the interface.** A tunnel need not have an interface
	 * block at all, so asking the interface list whether anything wants this
	 * backend answers no and stops a working tunnel (0155 pass 1b).
	 *
	 * The session *is* the interface here, so the whole question is whether
	 * the document still declares one of this kind under this name -- which is
	 * what makes deleting the block hang the line up. Until the Rust had this,
	 * removing a `pppoe` device left `pppd` holding the line with `persist`
	 * and `maxfail 0` in the options netcfgd had written it: for ever.
	 */
	return session_kind_of(device, &field) == kind;
}
