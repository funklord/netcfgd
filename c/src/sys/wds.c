/*
 * wds.c -- the requests and the reply described in wds.h.
 *
 * The reply is the kernel's and read as hostile all the same, for `wire.c`'s
 * reason.
 */
#include "ncfg/wds.h"

#include "ncfg/wire.h"

#include <string.h>

#include <linux/netlink.h>
#include <linux/nl80211.h>

int ncfg_wds_interfaces_request(ncfg_buf_t *out, const ncfg_genl_family_t *family, uint32_t seq,
    char *err, size_t err_size)
{
	ncfg_genl_header_t header;

	if (!family) {
		ncfg_error_set(err, err_size, "an interface dump needs nl80211 resolved");
		return 0;
	}
	header.cmd = NL80211_CMD_GET_INTERFACE;
	header.version = 0;
	return ncfg_genl_build_request(out, family->id, &header, NLM_F_DUMP, seq, NULL, err,
	    err_size);
}

int ncfg_wds_interface_parse(const void *payload, size_t length, ncfg_wds_interface_t *out,
    char *err, size_t err_size)
{
	ncfg_wire_attrs_t attrs;
	ncfg_wire_attr_t  attr;
	ncfg_wire_step_t  step;
	uint8_t           flag = 0;

	if (!out) {
		ncfg_error_set(err, err_size, "an interface needs somewhere to be written");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!ncfg_genl_payload_attrs(payload, length, &attrs, err, err_size)) {
		return 0;
	}
	step = ncfg_wire_attrs_find(&attrs, NL80211_ATTR_IFINDEX, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step != NCFG_WIRE_OK || !ncfg_wire_attr_u32(&attr, &out->index, err, err_size)) {
		ncfg_error_set(err, err_size, "nl80211 described an interface without its index");
		return 0;
	}
	step = ncfg_wire_attrs_find(&attrs, NL80211_ATTR_IFNAME, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step != NCFG_WIRE_OK ||
	    !ncfg_wire_attr_string(&attr, out->name, sizeof(out->name), err, err_size) ||
	    out->name[0] == '\0') {
		ncfg_error_set(err, err_size, "nl80211 described interface %u without its name",
		    (unsigned)out->index);
		return 0;
	}
	step = ncfg_wire_attrs_find(&attrs, NL80211_ATTR_WIPHY, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step == NCFG_WIRE_OK) {
		if (!ncfg_wire_attr_u32(&attr, &out->wiphy, err, err_size)) {
			return 0;
		}
		out->has_wiphy = 1;
	}
	step = ncfg_wire_attrs_find(&attrs, NL80211_ATTR_4ADDR, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step == NCFG_WIRE_OK) {
		if (!ncfg_wire_attr_u8(&attr, &flag, err, err_size)) {
			return 0;
		}
		out->has_four_address = 1;
		out->four_address = flag != 0;
	}
	return 1;
}

int ncfg_wds_set_request(ncfg_buf_t *out, const ncfg_genl_family_t *family, uint32_t index,
    int on, uint32_t seq, char *err, size_t err_size)
{
	ncfg_genl_header_t header;
	ncfg_buf_t         attrs;
	int                ok;

	if (!family || index == 0u) {
		ncfg_error_set(err, err_size, "setting four-address mode needs nl80211 and an index");
		return 0;
	}
	header.cmd = NL80211_CMD_SET_INTERFACE;
	header.version = 0;
	ncfg_buf_init(&attrs, 0);
	ncfg_wire_attr_put_u32(&attrs, NL80211_ATTR_IFINDEX, index);
	ncfg_wire_attr_put_u32(&attrs, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_STATION);
	ncfg_wire_attr_put_u8(&attrs, NL80211_ATTR_4ADDR, on ? 1u : 0u);
	ok = ncfg_genl_build_request(out, family->id, &header, NLM_F_ACK, seq, &attrs, err,
	    err_size);
	ncfg_buf_free(&attrs);
	return ok;
}
