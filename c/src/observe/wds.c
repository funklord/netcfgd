/*
 * wds.c -- whether each station radio is in four-address (WDS) mode, in the
 * same generic netlink round as the regulatory domain and the card ports.
 *
 * Asked only where the observation has a radio, for `regdom.c`'s reason: a
 * wired machine has nothing to ask about. One `GET_INTERFACE` dump answers for
 * every radio. A kernel that will not say leaves every `wds` false with a
 * note, and the rest of the observation stands.
 */
#include "ncfg/observe.h"

#include "observe_internal.h"

#include "ncfg/genl.h"
#include "ncfg/log.h"
#include "ncfg/wds.h"

#include <string.h>

#include <linux/nl80211.h>

int ncfg_observe_wds_from(const ncfg_observe_kernel_t *genl, ncfg_observed_t *observed,
    char *err, size_t err_size)
{
	ncfg_genl_family_t   family;
	ncfg_netlink_reply_t reply;
	ncfg_buf_t           message;
	char                 why[NCFG_ERROR_MAX];
	size_t               at;
	size_t               link;
	int                  radios = 0;
	int                  ok;

	if (!observed) {
		ncfg_error_set(err, err_size, "there is no observation to read four-address mode into");
		return 0;
	}
	for (link = 0; link < observed->link_count; link++) {
		observed->links[link].wds = 0;
		radios |= observed->links[link].wireless;
	}
	if (!genl || !genl->exchange || !radios) {
		return 1;
	}
	why[0] = '\0';
	if (!observe_genl_family(genl, NL80211_GENL_NAME, &family, why, sizeof(why))) {
		ncfg_genl_family_free(&family);
		return 1;
	}
	memset(&reply, 0, sizeof(reply));
	ncfg_buf_init(&message, 0);
	ok = ncfg_wds_interfaces_request(&message, &family, 0, why, sizeof(why)) &&
	    observe_genl_ask(genl, &message, &reply, why, sizeof(why));
	ncfg_buf_free(&message);
	ncfg_genl_family_free(&family);
	if (!ok) {
		ncfg_log_emitf("observe", NCFG_LOG_NOTE,
		    "the radios' four-address mode could not be read: %s", why);
		return 1;
	}
	for (at = 0; at < reply.count; at++) {
		ncfg_wds_interface_t radio;

		if (!ncfg_wds_interface_parse(reply.items[at].bytes, reply.items[at].length, &radio,
		    why, sizeof(why)) || !radio.has_four_address) {
			continue;
		}
		for (link = 0; link < observed->link_count; link++) {
			if (observed->links[link].name &&
			    strcmp(observed->links[link].name, radio.name) == 0) {
				observed->links[link].wds = radio.four_address;
			}
		}
	}
	ncfg_netlink_reply_free(&reply);
	return 1;
}
