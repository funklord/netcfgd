/*
 * service_internal.h -- the one question `wifi_ops.c` and `backend_ops.c` both
 * have to answer the same way.
 *
 * WHY THIS EXISTS, AND IT IS ONE RULE RATHER THAN THREE FUNCTIONS
 *   A supplicant is started with `-Dwired` or `-Dnl80211,wext`, and it is then
 *   filled either with one `IEEE8021X` profile or with every network in the
 *   document. **Those are the same decision made twice**, and the cost of
 *   making it twice is the failure `supplicant.h` names as the worst
 *   available: a supplicant the daemon accepts, that comes up, and that never
 *   authenticates -- everything looks configured and the port stays blocked.
 *   Nothing downstream can tell, because each half would be doing exactly what
 *   it was asked.
 *
 *   So the document is read once, here, and `ncfg_service_supplicant_driver`
 *   is built out of the same two lookups `ncfg_service_set_profiles` branches
 *   on. The Rust cannot make this promise: it reads the driver from sysfs --
 *   `radio::is_wireless` -- and the population from the document, so the two
 *   disagree exactly when a `dot1x` block is written on a radio, or when sysfs
 *   answers about an interface the document describes differently. See 0263.
 *
 * WHY NOT `kernel_internal.h`
 *   That header says in its first sentence what it is -- the kernel-side ops
 *   as messages rather than as sends -- and none of this is a message. A
 *   second small header beats widening one whose scope is stated.
 */
#ifndef NCFG_SERVICE_INTERNAL_H
#define NCFG_SERVICE_INTERNAL_H

#include <stddef.h>

#include "ncfg/document.h"

/*
 * The wired 802.1X block on one interface, or NULL.
 *
 * Decision 0008 puts wired 802.1X on the same supplicant as wifi, so this
 * block is what says the process on this interface is for a port rather than
 * for a radio -- and it is asked before the radio question, because an
 * interface carrying it has already said what its supplicant is for.
 */
const ncfg_eap_config_t *ncfg_service_dot1x_on(const ncfg_document_t *document,
    const char *iface);

/*
 * The `wifi` section of one device, or NULL.
 *
 * **Not a statement that the interface is a radio**, which is why the planner
 * needs the kernel's own answer beside it: `portal_check` lives in this
 * section and is meaningful on anything, and `tests/live/portal.sh` puts
 * exactly that on a dummy. What it is here is the document's radio policy --
 * the address policy, the scanning policy and whether the radio joins by
 * itself -- and its absence is a device asking for none of them.
 */
const ncfg_wifi_device_policy_t *ncfg_service_wifi_on(const ncfg_document_t *document,
    const char *device);

/*
 * Which `wpa_supplicant` driver serves this interface.
 *
 * `NCFG_SUPPLICANT_DRIVER_WIRED` for an interface with a `dot1x` block and
 * `NCFG_SUPPLICANT_DRIVER_RADIO` for a device with a `wifi` section, in that
 * order -- which is `ncfg_plan_radio_supplicant`'s order and is the same rule
 * from the other end: an interface carrying `dot1x` never reaches the radio
 * arm there either.
 *
 * **An interface the document describes as neither is refused by name.** The
 * planner emits a supplicant from those two passes and from nowhere else, so
 * an op naming a third kind of interface did not come from this build's
 * planner, and the honest answer is a sentence rather than a driver picked by
 * elimination. `*out` is left alone on a refusal.
 */
int ncfg_service_supplicant_driver(const ncfg_document_t *document, const char *iface,
    const char **out, char *err, size_t err_size);

#endif /* NCFG_SERVICE_INTERNAL_H */
