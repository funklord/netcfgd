/*
 * mesh_peer.c -- the request and the reply described in mesh_peer.h.
 *
 * The reply is the kernel's and read as hostile all the same, for `wire.c`'s
 * reason: a nest's length is a length nobody here chose.
 */
#include "ncfg/mesh_peer.h"

#include <string.h>

#include <linux/netlink.h>
#include <linux/nl80211.h>

int ncfg_mesh_peers_request(ncfg_buf_t *out, const ncfg_genl_family_t *family, uint32_t index,
    uint32_t seq, char *err, size_t err_size)
{
	ncfg_genl_header_t header;
	ncfg_buf_t         attrs;
	int                ok;

	if (!family || index == 0u) {
		ncfg_error_set(err, err_size, "a station dump needs nl80211 and an interface");
		return 0;
	}
	header.cmd = NL80211_CMD_GET_STATION;
	header.version = 0;
	ncfg_buf_init(&attrs, 0);
	ncfg_wire_attr_put_u32(&attrs, NL80211_ATTR_IFINDEX, index);
	ok = ncfg_genl_build_request(out, family->id, &header, NLM_F_DUMP, seq, &attrs, err,
	    err_size);
	ncfg_buf_free(&attrs);
	return ok;
}

int ncfg_mesh_peer_parse(const void *payload, size_t length, ncfg_mesh_peer_t *out, char *err,
    size_t err_size)
{
	ncfg_wire_attrs_t attrs;
	ncfg_wire_attrs_t info;
	ncfg_wire_attr_t  attr;
	ncfg_wire_attr_t  state;
	ncfg_wire_step_t  step;

	if (!out) {
		ncfg_error_set(err, err_size, "a station needs somewhere to be written");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!ncfg_genl_payload_attrs(payload, length, &attrs, err, err_size)) {
		return 0;
	}
	step = ncfg_wire_attrs_find(&attrs, NL80211_ATTR_MAC, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step != NCFG_WIRE_OK || !ncfg_wire_attr_mac(&attr, out->mac, sizeof(out->mac), err,
	        err_size)) {
		ncfg_error_set(err, err_size, "nl80211 described a station without its address");
		return 0;
	}
	step = ncfg_wire_attrs_find(&attrs, NL80211_ATTR_STA_INFO, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step != NCFG_WIRE_OK) {
		return 1; /* a station with no information is still one, with no state */
	}
	ncfg_wire_attrs_start(&info, attr.value, attr.length);
	step = ncfg_wire_attrs_find(&info, NL80211_STA_INFO_PLINK_STATE, &state, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step == NCFG_WIRE_OK) {
		if (!ncfg_wire_attr_u8(&state, &out->plink_state, err, err_size)) {
			return 0;
		}
		out->has_plink_state = 1;
	}
	return 1;
}

void ncfg_mesh_point_address(const uint8_t parent[6], uint8_t out[6])
{
	memcpy(out, parent, 6u);
	out[0] |= 0x02u;
	if (memcmp(out, parent, 6u) == 0) {
		out[5] ^= 0x01u;
	}
}

int ncfg_mesh_point_add_request(ncfg_buf_t *out, const ncfg_genl_family_t *family,
    uint32_t parent, const char *name, const uint8_t mac[6], uint32_t seq, char *err,
    size_t err_size)
{
	ncfg_genl_header_t header;
	ncfg_buf_t         attrs;
	int                ok;

	if (!family || parent == 0u || !name || !name[0]) {
		ncfg_error_set(err, err_size, "a mesh point needs nl80211, its radio and a name");
		return 0;
	}
	header.cmd = NL80211_CMD_NEW_INTERFACE;
	header.version = 0;
	ncfg_buf_init(&attrs, 0);
	ncfg_wire_attr_put_u32(&attrs, NL80211_ATTR_IFINDEX, parent);
	ncfg_wire_attr_put_str(&attrs, NL80211_ATTR_IFNAME, name);
	ncfg_wire_attr_put_u32(&attrs, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MESH_POINT);
	if (mac) {
		ncfg_wire_attr_put(&attrs, NL80211_ATTR_MAC, mac, 6u);
	}
	ok = ncfg_genl_build_request(out, family->id, &header, NLM_F_ACK, seq, &attrs, err,
	    err_size);
	ncfg_buf_free(&attrs);
	return ok;
}

int ncfg_mesh_point_delete_request(ncfg_buf_t *out, const ncfg_genl_family_t *family,
    uint32_t index, uint32_t seq, char *err, size_t err_size)
{
	ncfg_genl_header_t header;
	ncfg_buf_t         attrs;
	int                ok;

	if (!family || index == 0u) {
		ncfg_error_set(err, err_size, "taking a mesh point away needs nl80211 and its index");
		return 0;
	}
	header.cmd = NL80211_CMD_DEL_INTERFACE;
	header.version = 0;
	ncfg_buf_init(&attrs, 0);
	ncfg_wire_attr_put_u32(&attrs, NL80211_ATTR_IFINDEX, index);
	ok = ncfg_genl_build_request(out, family->id, &header, NLM_F_ACK, seq, &attrs, err,
	    err_size);
	ncfg_buf_free(&attrs);
	return ok;
}
