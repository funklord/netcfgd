/*
 * wiphy.h -- what a radio can do, asked of nl80211: for now, whether it has
 * 802.11n (HT) in any band.
 *
 * WHY IT IS HERE
 *   hostapd runs an access point at 802.11a/g rates unless told
 *   `ieee80211n=1`, and 10.116 left it unwritten because whether a radio has
 *   HT is something the radio reports and netcfgd did not read. A radio that
 *   has it is given it; one that does not is not, so no document needs to say
 *   either way. The capability is `NL80211_BAND_ATTR_HT_CAPA` in a band of
 *   `NL80211_ATTR_WIPHY_BANDS` (project.md 10.596).
 *
 * THE DUMP IS SPLIT
 *   `NL80211_ATTR_SPLIT_WIPHY_DUMP` asks for each radio in several messages,
 *   which every kernel since 3.10 does and which a radio with many channels
 *   needs -- unsplit, its description can exceed one message. So a reply names
 *   its radio in each part, and the caller ORs the parts of one radio.
 *
 * THE NUMBERS ARE THE KERNEL'S
 *   From <linux/nl80211.h>, for `genl.h`'s reason.
 */
#ifndef NCFG_WIPHY_H
#define NCFG_WIPHY_H

#include <stddef.h>
#include <stdint.h>

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/genl.h"

/* One part of one radio's description. */
typedef struct {
	uint32_t index;
	/* Whether this part carried a band with an HT capability. */
	int      high_throughput;
	/* And, per band, whether that capability says 20/40 MHz -- bit 1 of
	 * `HT_CAPA`, "supported channel width set" (10.597). Per band because a
	 * radio can differ between them, and hostapd refuses to start with an
	 * `[HT40+]` the band cannot do. */
	int      forty_mhz_24;
	int      forty_mhz_5;
	/* And 802.11ac (VHT) on 5 GHz: the band carries `VHT_CAPA` (10.598).
	 * 80 MHz is mandatory for VHT, so this is also "can do 80". */
	int      vht_5;
	/* And 160 MHz there: bits 2-3 of `VHT_CAPA`, the supported channel
	 * width set, non-zero (10.599). hwsim reports 0x038004fa. */
	int      vht160_5;
	/* And 802.11ax (HE) for an access point, per band (10.600): an entry
	 * of the band's `IFTYPE_DATA` naming `NL80211_IFTYPE_AP` among its
	 * interface types and carrying `HE_CAP_PHY`. Per interface type because
	 * the kernel says it that way -- measured, hwsim lists one entry for
	 * stations and one for access points. */
	int      he_24;
	int      he_5;
} ncfg_wiphy_t;

/* A split dump of every radio, to a family resolved. */
int ncfg_wiphy_request(ncfg_buf_t *out, const ncfg_genl_family_t *family, uint32_t seq,
    char *err, size_t err_size);

/* One part out of a reply payload, the generic netlink header first. Refused
 * without the radio's index or with a malformed band list. */
int ncfg_wiphy_parse(const void *payload, size_t length, ncfg_wiphy_t *out, char *err,
    size_t err_size);

#endif /* NCFG_WIPHY_H */
