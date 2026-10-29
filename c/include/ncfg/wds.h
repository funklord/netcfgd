/*
 * wds.h -- a station radio's four-address (WDS) mode, asked and set over
 * nl80211.
 *
 * WHY IT IS HERE
 *   A repeater bridges a second LAN through somebody else's access point, and
 *   the kernel will not put a three-address station in a bridge at all --
 *   measured, `ip link set wlan1 master br` left the bridge without it and
 *   nothing crossed. Four-address mode is the radio's own setting, `4addr` in
 *   `iw`, and it is read and written here: `NL80211_ATTR_4ADDR` on an
 *   interface (project.md 10.587 item 4). It can be changed while the station
 *   is up and associated, which a vm measured, so it needs no link cycle; what
 *   it must precede is the radio joining its bridge.
 *
 * THE NUMBERS ARE THE KERNEL'S
 *   From <linux/nl80211.h>, for `genl.h`'s reason.
 */
#ifndef NCFG_WDS_H
#define NCFG_WDS_H

#include <stddef.h>
#include <stdint.h>

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/genl.h"

/* An interface name and its NUL. */
#define NCFG_WDS_NAME_MAX 16

/* One interface as `GET_INTERFACE` describes it. */
typedef struct {
	uint32_t index;
	char     name[NCFG_WDS_NAME_MAX];
	/* Whether the reply carried `4ADDR` at all, and what it said. */
	int      has_four_address;
	int      four_address;
} ncfg_wds_interface_t;

/* A dump of every wireless interface, to a family resolved. */
int ncfg_wds_interfaces_request(ncfg_buf_t *out, const ncfg_genl_family_t *family, uint32_t seq,
    char *err, size_t err_size);

/* One interface out of a reply payload, the generic netlink header first.
 * Refused without an index or a name. */
int ncfg_wds_interface_parse(const void *payload, size_t length, ncfg_wds_interface_t *out,
    char *err, size_t err_size);

/*
 * `SET_INTERFACE` turning four-address mode on or off on a station.
 *
 * The type is sent as a station's, which `SET_INTERFACE` requires and which is
 * the only mode four-address applies to here: an access point takes
 * four-address stations through hostapd's `wds_sta` instead.
 */
int ncfg_wds_set_request(ncfg_buf_t *out, const ncfg_genl_family_t *family, uint32_t index,
    int on, uint32_t seq, char *err, size_t err_size);

#endif /* NCFG_WDS_H */
