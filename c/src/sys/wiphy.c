/*
 * wiphy.c -- the request and the reply described in wiphy.h.
 *
 * The reply is the kernel's and read as hostile all the same, for `wire.c`'s
 * reason.
 */
#include "ncfg/wiphy.h"

#include "ncfg/wire.h"

#include <string.h>

#include <linux/netlink.h>
#include <linux/nl80211.h>

int ncfg_wiphy_request(ncfg_buf_t *out, const ncfg_genl_family_t *family, uint32_t seq,
    char *err, size_t err_size)
{
	ncfg_genl_header_t header;
	ncfg_buf_t         attrs;
	int                ok;

	if (!family) {
		ncfg_error_set(err, err_size, "a radio dump needs nl80211 resolved");
		return 0;
	}
	header.cmd = NL80211_CMD_GET_WIPHY;
	header.version = 0;
	ncfg_buf_init(&attrs, 0);
	/* A flag: present and empty. */
	ncfg_wire_attr_put(&attrs, NL80211_ATTR_SPLIT_WIPHY_DUMP, NULL, 0u);
	ok = ncfg_genl_build_request(out, family->id, &header, NLM_F_DUMP, seq, &attrs, err,
	    err_size);
	ncfg_buf_free(&attrs);
	return ok;
}

int ncfg_wiphy_parse(const void *payload, size_t length, ncfg_wiphy_t *out, char *err,
    size_t err_size)
{
	ncfg_wire_attrs_t attrs;
	ncfg_wire_attrs_t bands;
	ncfg_wire_attr_t  attr;
	ncfg_wire_attr_t  band;
	ncfg_wire_step_t  step;

	if (!out) {
		ncfg_error_set(err, err_size, "a radio needs somewhere to be written");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!ncfg_genl_payload_attrs(payload, length, &attrs, err, err_size)) {
		return 0;
	}
	step = ncfg_wire_attrs_find(&attrs, NL80211_ATTR_WIPHY, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step != NCFG_WIRE_OK || !ncfg_wire_attr_u32(&attr, &out->index, err, err_size)) {
		ncfg_error_set(err, err_size, "nl80211 described a radio without its index");
		return 0;
	}
	step = ncfg_wire_attrs_find(&attrs, NL80211_ATTR_WIPHY_BANDS, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step != NCFG_WIRE_OK) {
		/* A part about something else: the split dump sends many. */
		return 1;
	}
	ncfg_wire_attrs_start(&bands, attr.value, attr.length);
	while ((step = ncfg_wire_attrs_next(&bands, &band, err, err_size)) == NCFG_WIRE_OK) {
		ncfg_wire_attrs_t inside;
		ncfg_wire_attr_t  capability;
		ncfg_wire_step_t  found;

		ncfg_wire_attrs_start(&inside, band.value, band.length);
		found = ncfg_wire_attrs_find(&inside, NL80211_BAND_ATTR_HT_CAPA, &capability, err,
		    err_size);
		if (found == NCFG_WIRE_BAD) {
			return 0;
		}
		if (found == NCFG_WIRE_OK) {
			uint16_t bits = 0;

			out->high_throughput = 1;
			if (!ncfg_wire_attr_u16(&capability, &bits, err, err_size)) {
				return 0;
			}
			if ((bits & 0x0002u) != 0u && band.kind == NL80211_BAND_2GHZ) {
				out->forty_mhz_24 = 1;
			}
			if ((bits & 0x0002u) != 0u && band.kind == NL80211_BAND_5GHZ) {
				out->forty_mhz_5 = 1;
			}
		}
	}
	return step != NCFG_WIRE_BAD;
}
