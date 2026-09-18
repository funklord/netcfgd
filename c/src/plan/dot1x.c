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
 *   The radio arm is the half this build does not start: nothing here brings a
 *   station's supplicant up, and answering "unwanted" about one would stop a
 *   radio netcfgd never started. It is the Rust's rule unchanged, and it
 *   becomes ordinary the day the wifi half of the backend pass lands.
 */
#include "plan_internal.h"

#include <string.h>

void ncfg_plan_dot1x(ncfg_builder_t *builder, const ncfg_interface_t *interface,
    const ncfg_plan_ids_t *base, ncfg_plan_ids_t *out)
{
	if (!interface->dot1x) {
		return;
	}
	ncfg_plan_backend(builder, interface->name, NCFG_BACKEND_SUPPLICANT, "dot1x", base, out);
}

int ncfg_plan_supplicant_wanted(const ncfg_document_t *desired, const char *name)
{
	const ncfg_interface_t *interface = ncfg_plan_interface(desired, name);
	const ncfg_device_t    *device;
	size_t                  i;

	if (interface && interface->dot1x) {
		return 1;
	}
	/*
	 * A radio that has been given an access point is not a station, so a
	 * supplicant left over from before the `access_point` block was written is
	 * unwanted. Without this arm the two backends would each be started by the
	 * pass that wants it and stopped by the pass that does not.
	 */
	for (i = 0; i < desired->access_point_count; i++) {
		if (desired->access_points[i].device && name &&
		    strcmp(desired->access_points[i].device, name) == 0) {
			return 0;
		}
	}
	device = ncfg_plan_device(desired, name);
	return device && device->managed && device->wifi;
}
