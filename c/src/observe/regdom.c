/*
 * regdom.c -- the wireless regulatory domain, as one more question asked of
 * generic netlink in the same round as the offloads and WireGuard.
 *
 * WHY IT IS OBSERVED, AND NOT ASKED BY A CLIENT
 *   Decision 0296: what the domain is gets reported, because the failure it
 *   is about is invisible -- project.md 10.585 measured a country set by hand
 *   stranding a machine in that country's gaps, and the world domain having
 *   no 6 GHz, and either way the access point is simply not there. The daemon
 *   takes this observation on every tick and every client is answered from
 *   it, so this is where a fact about the machine is read once.
 *
 * ONLY WHERE THERE IS A RADIO
 *   A wired machine has a domain too, and asking for it is a round trip per
 *   tick about nothing the machine uses. The links are already in the
 *   observation by the time this runs, and they say which are radios.
 *
 * A KERNEL THAT WILL NOT SAY IS NOT A FAILURE
 *   No nl80211 family, a reply that names no country: the field stays empty,
 *   a note says why, and the rest of the observation stands -- the offloads
 *   round's bargain, for the same reason.
 *
 * WHAT IT CANNOT SAY
 *   Who set the domain. `GET_REG` carries the country and its rules; the
 *   initiator travels only in the `REG_CHANGE` notification, at the moment of
 *   change, and a round of questions cannot see one.
 */
#include "ncfg/observe.h"

#include "observe_internal.h"

#include "ncfg/genl.h"
#include "ncfg/log.h"
#include "ncfg/regdom.h"

#include <stdlib.h>
#include <string.h>

#include <linux/nl80211.h>

static int has_radio(const ncfg_observed_t *observed)
{
	size_t at;

	for (at = 0; at < observed->link_count; at++) {
		if (observed->links[at].wireless) {
			return 1;
		}
	}
	return 0;
}

int ncfg_observe_regdom_from(const ncfg_observe_kernel_t *genl, ncfg_observed_t *observed,
    char *err, size_t err_size)
{
	ncfg_genl_family_t   family;
	ncfg_netlink_reply_t reply;
	ncfg_buf_t           message;
	char                 code[NCFG_REGDOM_TEXT_MAX];
	char                 why[NCFG_ERROR_MAX];
	int                  ok;

	if (!observed) {
		ncfg_error_set(err, err_size,
		    "there is no observation to read the regulatory domain into");
		return 0;
	}
	free(observed->regdom);
	observed->regdom = NULL;
	if (!genl || !genl->exchange || !has_radio(observed)) {
		return 1;
	}
	why[0] = '\0';
	if (!observe_genl_family(genl, NL80211_GENL_NAME, &family, why, sizeof(why))) {
		ncfg_log_emitf("observe", NCFG_LOG_NOTE,
		    "nl80211 could not be resolved (%s), so this observation names no wireless "
		    "regulatory domain", why[0] ? why : "no sentence was given");
		ncfg_genl_family_free(&family);
		return 1;
	}
	memset(&reply, 0, sizeof(reply));
	ncfg_buf_init(&message, 0);
	ok = ncfg_regdom_request(&message, &family, 0, why, sizeof(why)) &&
	    observe_genl_ask(genl, &message, &reply, why, sizeof(why));
	ncfg_buf_free(&message);
	ncfg_genl_family_free(&family);
	if (ok && reply.count == 0) {
		ncfg_error_set(why, sizeof(why),
		    "the kernel answered the regulatory domain request with nothing");
		ok = 0;
	}
	if (ok) {
		ok = ncfg_regdom_parse(reply.items[0].bytes, reply.items[0].length, code,
		    sizeof(code), why, sizeof(why));
	}
	ncfg_netlink_reply_free(&reply);
	if (!ok) {
		ncfg_log_emitf("observe", NCFG_LOG_NOTE,
		    "the wireless regulatory domain could not be read: %s", why);
		return 1;
	}
	observed->regdom = strdup(code);
	if (!observed->regdom) {
		ncfg_error_set(err, err_size, "out of memory recording the regulatory domain");
		return 0;
	}
	return 1;
}
