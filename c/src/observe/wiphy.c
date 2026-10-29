/*
 * wiphy.c -- whether each radio has 802.11n (HT), in the same generic netlink
 * round as four-address mode (project.md 10.596).
 *
 * Two dumps: `GET_INTERFACE` says which radio each interface is on, and a
 * split `GET_WIPHY` says what each radio can do. Asked only where the
 * observation has a radio, for `regdom.c`'s reason. A kernel that will not say
 * leaves every `high_throughput` unanswered with a note: an access point not
 * yet started then runs at 802.11a/g rates, as every one did before this, one
 * already running is left as it is, and the rest of the observation stands.
 */
#include "ncfg/observe.h"

#include "observe_internal.h"

#include "ncfg/genl.h"
#include "ncfg/log.h"
#include "ncfg/wds.h"
#include "ncfg/wiphy.h"

#include <string.h>

#include <linux/nl80211.h>

/* Radios a machine has, at most, for the per-radio answer; one beyond is
 * read as having no HT, which is the cautious direction. */
#define WIPHY_MAX 32u

static int dump(const ncfg_observe_kernel_t *genl, const ncfg_genl_family_t *family, int radios,
    ncfg_netlink_reply_t *reply, char *why, size_t why_size)
{
	ncfg_buf_t message;
	int        ok;

	memset(reply, 0, sizeof(*reply));
	ncfg_buf_init(&message, 0);
	ok = (radios ? ncfg_wiphy_request(&message, family, 0, why, why_size)
	             : ncfg_wds_interfaces_request(&message, family, 0, why, why_size)) &&
	    observe_genl_ask(genl, &message, reply, why, why_size);
	ncfg_buf_free(&message);
	return ok;
}

int ncfg_observe_high_throughput_from(const ncfg_observe_kernel_t *genl,
    ncfg_observed_t *observed, char *err, size_t err_size)
{
	ncfg_genl_family_t   family;
	ncfg_netlink_reply_t interfaces;
	ncfg_netlink_reply_t phys;
	char                 why[NCFG_ERROR_MAX];
	unsigned char        has_ht[WIPHY_MAX];
	size_t               at;
	size_t               link;
	int                  radios = 0;

	if (!observed) {
		ncfg_error_set(err, err_size, "there is no observation to read 802.11n into");
		return 0;
	}
	for (link = 0; link < observed->link_count; link++) {
		observed->links[link].high_throughput.has = 0;
		observed->links[link].high_throughput.value = 0;
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
	if (!dump(genl, &family, 1, &phys, why, sizeof(why))) {
		ncfg_genl_family_free(&family);
		ncfg_log_emitf("observe", NCFG_LOG_NOTE,
		    "whether the radios have 802.11n could not be read: %s", why);
		return 1;
	}
	if (!dump(genl, &family, 0, &interfaces, why, sizeof(why))) {
		ncfg_netlink_reply_free(&phys);
		ncfg_genl_family_free(&family);
		ncfg_log_emitf("observe", NCFG_LOG_NOTE,
		    "which radio each interface is on could not be read: %s", why);
		return 1;
	}
	ncfg_genl_family_free(&family);
	memset(has_ht, 0, sizeof(has_ht));
	for (at = 0; at < phys.count; at++) {
		ncfg_wiphy_t part;

		if (ncfg_wiphy_parse(phys.items[at].bytes, phys.items[at].length, &part, why,
		        sizeof(why)) && part.index < WIPHY_MAX && part.high_throughput) {
			has_ht[part.index] = 1;
		}
	}
	/* Answered for every interface the kernel placed on a radio, yes or no;
	 * one it did not place stays unanswered. */
	for (at = 0; at < interfaces.count; at++) {
		ncfg_wds_interface_t radio;

		if (!ncfg_wds_interface_parse(interfaces.items[at].bytes,
		        interfaces.items[at].length, &radio, why, sizeof(why)) ||
		    !radio.has_wiphy || radio.wiphy >= WIPHY_MAX) {
			continue;
		}
		for (link = 0; link < observed->link_count; link++) {
			if (observed->links[link].name &&
			    strcmp(observed->links[link].name, radio.name) == 0) {
				observed->links[link].high_throughput.has = 1;
				observed->links[link].high_throughput.value = has_ht[radio.wiphy];
			}
		}
	}
	ncfg_netlink_reply_free(&interfaces);
	ncfg_netlink_reply_free(&phys);
	return 1;
}
