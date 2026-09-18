/*
 * dot1x.c -- the supplicant a wired 802.1X port needs before it has an address.
 *
 * WHY THIS IS A PREREQUISITE AND NOT AN ADDRESSING ACTION
 *   A port that has not authenticated drops everything. A DHCP client started
 *   first would spend its whole backoff sequence talking to a switch that is
 *   not listening, and then report a failure whose real cause is two steps
 *   earlier. So the supplicant is planned before any address and the addressing
 *   waits on it.
 *
 *   Decision 0008 puts wired 802.1X on the same supplicant as wifi, so this is
 *   the same op either way -- which is what makes the teardown question below
 *   one question rather than two.
 *
 * WHY THE TEARDOWN'S RULE LIVES HERE TOO
 *   **The conditions that start a supplicant and the conditions that keep one
 *   have to stay the same.** Wrong in the permissive direction leaves a
 *   supplicant nobody owns; wrong in the other direction makes netcfgd start
 *   one and kill it on the next reconcile, for ever -- which is what the Rust's
 *   idempotence gate caught the day `supplicant_wanted` did not know a kind
 *   existed. Keeping both halves in one file is what makes "the same
 *   conditions" checkable by reading rather than by remembering.
 *
 *   **The radio arm used to be the half this build did not start**, so the
 *   rule answered "wanted" about a supplicant nothing here would have brought
 *   up -- the permissive direction, deliberately, since answering the other
 *   way would have stopped one netcfgd never started. `radio.c` starts it now,
 *   and the arm has become ordinary: it is a call to that file's half of this
 *   rule, so the pass that starts a radio's supplicant and the rule that keeps
 *   one are the same line of code rather than two that agree today.
 */
#include "plan_internal.h"

void ncfg_plan_dot1x(ncfg_builder_t *builder, const ncfg_interface_t *interface,
    const ncfg_plan_ids_t *base, ncfg_plan_ids_t *out)
{
	if (!interface->dot1x) {
		return;
	}
	ncfg_plan_backend(builder, interface->name, NCFG_BACKEND_SUPPLICANT, "dot1x", base, out);
}

int ncfg_plan_supplicant_wanted(const ncfg_document_t *desired, const ncfg_observed_t *observed,
    const char *name)
{
	const ncfg_interface_t *interface = ncfg_plan_interface(desired, name);

	if (interface && interface->dot1x) {
		return 1;
	}
	/*
	 * And the other reason one process is kept, asked of the file that starts
	 * a supplicant for it rather than spelled again here. The access point's
	 * arm is inside that answer, which is where it belongs: "this radio is
	 * running hostapd instead" is a statement about the radio and not about
	 * 802.1X.
	 */
	return ncfg_plan_radio_supplicant_wanted(desired, observed, name);
}
