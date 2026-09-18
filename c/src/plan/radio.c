/*
 * radio.c -- the supplicant a wireless radio needs before it can join
 * anything, and whether a running one is still asked for.
 *
 * WHY THIS IS A PREREQUISITE AND NOT AN ADDRESSING ACTION
 *   `dot1x.c`'s reason, unchanged: a radio that has not associated carries
 *   nothing, so a DHCP client started first spends its whole backoff sequence
 *   talking to a network it has not joined and then reports a failure whose
 *   real cause is two steps earlier. Decision 0008 puts wired 802.1X and wifi
 *   on the same supplicant, so this is the same op as `dot1x.c`'s and the same
 *   place in the order.
 *
 * WHY IT IS THE LAST PREREQUISITE, AND WHY THAT IS NOT AN ORDERING OF
 * CONVENIENCE
 *   The Rust plans all of them from one function and returns at the first that
 *   applies, which is what makes "one prerequisite per interface" true rather
 *   than a hope. This port has three of its five arms, and this is the last of
 *   them for the reason the Rust gives at each:
 *
 *     * **`dot1x` first**, because an interface carrying that block has said
 *       what its supplicant is for, and starting a second one for the radio
 *       would be two `backend.start` actions for one process.
 *     * **the access point before this one**, because a radio running hostapd
 *       does not also join networks with the same interface -- one radio does
 *       both only with a second virtual interface on the phy, which netcfgd
 *       does not create.
 *
 *   So the guard below is not a tidy-up: without it a radio with an
 *   `access_point` block gets a supplicant *and* a hostapd on one phy, and
 *   nothing downstream would notice, because each pass would be doing exactly
 *   what it was asked.
 *
 * WHAT MAKES AN INTERFACE A RADIO
 *   **Two facts from two places, and neither is enough alone.**
 *
 *   The `device` block supplies the first -- `managed`, and a `wifi { }`
 *   section saying there is radio policy here at all. It cannot supply the
 *   second, because that section is not a statement that the interface *is* a
 *   radio: `portal_check` lives in it and is meaningful on anything, and
 *   `tests/live/portal.sh` puts exactly that on a dummy interface.
 *
 *   The kernel supplies the second, through `ncfg_observed_link_t::wireless`,
 *   which `observed.h` says is carried for this question and no other. The
 *   Rust records what dropping it cost: netcfgd tried to start a supplicant on
 *   a dummy, and only the live suite caught it, the mistake being invisible to
 *   every unit test that had no kernel in it.
 *
 * WHY THE TEARDOWN'S RULE LIVES HERE TOO
 *   `dot1x.c`'s and `access_point.c`'s arrangement, for their reason: the
 *   conditions that start a backend and the conditions that keep one have to
 *   stay the same, and a rule in two files is one that eventually disagrees
 *   with itself. Wrong in the permissive direction leaves a supplicant nobody
 *   owns; wrong in the other direction is netcfgd starting one and killing it
 *   on every reconcile, for ever.
 *
 *   `ncfg_plan_supplicant_wanted` is the whole rule and is in `dot1x.c`,
 *   because one process serves both blocks and cannot be half wanted. This is
 *   its radio half, and the two callers are that function and the pass below
 *   -- which is what the "same conditions" sentence above means here: not two
 *   rules kept in step, one rule asked twice.
 */
#include "plan_internal.h"

#include <string.h>

int ncfg_plan_radio_supplicant_wanted(const ncfg_document_t *desired,
    const ncfg_observed_t *observed, const char *name)
{
	const ncfg_device_t        *device = ncfg_plan_device(desired, name);
	const ncfg_observed_link_t *link;

	if (!device || !device->managed || !device->wifi) {
		return 0;
	}
	/*
	 * A radio that has been given an access point is not a station, so a
	 * supplicant left over from before the `access_point` block was written is
	 * unwanted -- and one is not started for a radio that is about to run
	 * hostapd. Both directions of that are this line: without it the two
	 * backends would each be started by the pass that wants it and stopped by
	 * the pass that does not.
	 */
	if (ncfg_plan_access_point_wanted(desired, name)) {
		return 0;
	}
	link = ncfg_observed_link(observed, name);
	return link && link->wireless;
}

void ncfg_plan_radio_supplicant(ncfg_builder_t *builder, const ncfg_interface_t *interface,
    const ncfg_plan_ids_t *base, ncfg_plan_ids_t *out)
{
	/* One prerequisite per interface, and this is the last of them. See the
	 * header: the `dot1x` supplicant is the same process under another name,
	 * and the access point's arm is inside the rule below. */
	if (interface->dot1x) {
		return;
	}
	if (!ncfg_plan_radio_supplicant_wanted(builder->desired, builder->observed,
	    interface->name)) {
		return;
	}
	/*
	 * Through the same function the DHCP client and the access point are
	 * started by, which carries 0079's restart limit and rule 3's wait for
	 * `link.up` without a second copy of either. **The field is the `device`
	 * block's `wifi`, not the interface's**, because that is where somebody
	 * would go to turn this off.
	 */
	ncfg_plan_backend(builder, interface->name, NCFG_BACKEND_SUPPLICANT, "wifi", base, out);
}

/*
 * A radio the document declares and states no `interface` block for.
 *
 * **This is what the blanket sentence that used to stand in `wifi.c` narrowed
 * to.** That one said the supplicant serving a radio was not started by this
 * build at all, which the pass above makes untrue; what survives is the one
 * arrangement in which nothing still happens, and it is silent otherwise.
 *
 * A supplicant is started as an interface's prerequisite and an interface that
 * is not in the document is never walked, so a `device` block with a `wifi`
 * section and no `interface` block produces no supplicant, no `link.up` and no
 * explanation -- which is the failure a warning pass exists to prevent,
 * arrived at by deleting a warning. `access_point.c` says the same thing about
 * hostapd for the same reason, and a radio in both states is left to that one
 * rather than told twice about one missing block.
 *
 * Said only where the kernel agrees the interface is a radio, which is what
 * keeps this quiet: a `wifi { portal_check = ... }` on a dummy is the
 * arrangement `tests/live/portal.sh` uses and is not asking for a supplicant.
 */
void ncfg_plan_radio_warn(ncfg_builder_t *builder)
{
	size_t i;

	for (i = 0; i < builder->desired->device_count; i++) {
		const ncfg_device_t        *device = &builder->desired->devices[i];
		const ncfg_observed_link_t *link;

		if (!device->managed || !device->wifi) {
			continue;
		}
		if (ncfg_plan_interface(builder->desired, device->name)) {
			continue;
		}
		if (ncfg_plan_access_point_wanted(builder->desired, device->name)) {
			continue;
		}
		link = ncfg_observed_link(builder->observed, device->name);
		if (!link || !link->wireless) {
			continue;
		}
		ncfg_plan_warnf(builder->plan, device->name,
		    "`%s` is a radio with no `interface` block, so nothing brings it up and "
		    "nothing starts the supplicant that would join the configured networks on "
		    "it. Adding `interface %s { }` is enough",
		    device->name, device->name);
	}
}
