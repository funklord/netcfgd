/*
 * mesh_peer.h -- a mesh point's peers, asked of nl80211 (project.md 10.686).
 *
 * WHY IT IS HERE
 *   netcfgd joins an 802.11s mesh through wpa_supplicant (10.588), and until
 *   now nothing it reported said who the node was meshed with: `iw dev wlan0
 *   station dump` does, and `ncfg status` did not. The kernel keeps the peers
 *   as stations of the mesh interface, each with its peer link's state
 *   (`NL80211_STA_INFO_PLINK_STATE`), so one `GET_STATION` dump of that
 *   interface answers it.
 *
 * THE NUMBERS ARE THE KERNEL'S
 *   From <linux/nl80211.h>, for `genl.h`'s reason.
 */
#ifndef NCFG_MESH_PEER_H
#define NCFG_MESH_PEER_H

#include <stddef.h>
#include <stdint.h>

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/genl.h"
#include "ncfg/wire.h"

/* `NL80211_PLINK_ESTAB`: the one state in which the peer carries traffic. */
#define NCFG_MESH_PLINK_ESTAB 4u

/* One station of a mesh interface as `GET_STATION` describes it. */
typedef struct {
	char    mac[NCFG_WIRE_MAC_TEXT_MAX];
	/* Whether the reply carried the peer link's state, and which it was. */
	int     has_plink_state;
	uint8_t plink_state;
} ncfg_mesh_peer_t;

/* A dump of the stations of interface `index`. */
int ncfg_mesh_peers_request(ncfg_buf_t *out, const ncfg_genl_family_t *family, uint32_t index,
    uint32_t seq, char *err, size_t err_size);

/* One reply of that dump. 0 with a sentence where it is not a station with an
 * address -- the kernel's bytes, read as hostile, for `wire.c`'s reason. */
int ncfg_mesh_peer_parse(const void *payload, size_t length, ncfg_mesh_peer_t *out, char *err,
    size_t err_size);

#endif /* NCFG_MESH_PEER_H */
