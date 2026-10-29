/*
 * wiphy_test.c -- what a radio can do, asked of nl80211, against bytes
 * rather than against a radio.
 *
 * WHAT IS CHECKED
 *   That the request is a `GET_WIPHY` dump asking to be split, which is what
 *   lets a radio with many channels be described at all; that a part is read
 *   only when it names its radio; that HT is any band's `HT_CAPA`, and a part
 *   carrying no bands is a part about something else rather than "no HT"
 *   (project.md 10.596).
 */
#include "ncfg/wiphy.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/genl.h"
#include "ncfg/wire.h"

#include <stdio.h>
#include <string.h>

#include <linux/netlink.h>
#include <linux/nl80211.h>

static int failures;

static int check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
	return condition;
}

/* A part of radio `index` (0 leaves the index out) with `bands` bands, of
 * which the last carries HT where `ht` is set. */
static void part(ncfg_buf_t *out, uint32_t index, int bands, int ht)
{
	ncfg_genl_header_t header = { NL80211_CMD_NEW_WIPHY, 1 };
	ncfg_buf_t         list;
	uint16_t           capability = 0x017e;
	int                at;

	ncfg_buf_init(out, 0);
	ncfg_buf_init(&list, 0);
	ncfg_genl_header_encode(&header, out);
	if (index) {
		ncfg_wire_attr_put_u32(out, NL80211_ATTR_WIPHY, index);
	}
	for (at = 0; at < bands; at++) {
		ncfg_buf_t band;

		ncfg_buf_init(&band, 0);
		ncfg_wire_attr_put_u32(&band, NL80211_BAND_ATTR_HT_AMPDU_FACTOR, 3);
		if (ht && at == bands - 1) {
			uint32_t vht = 0x038004fau;

			ncfg_wire_attr_put(&band, NL80211_BAND_ATTR_HT_CAPA, &capability,
			    sizeof(capability));
			ncfg_wire_attr_put(&band, NL80211_BAND_ATTR_VHT_CAPA, &vht, sizeof(vht));
		}
		ncfg_wire_attr_put_nested(&list, (uint16_t)at, &band);
		ncfg_buf_free(&band);
	}
	if (bands) {
		ncfg_wire_attr_put_nested(out, NL80211_ATTR_WIPHY_BANDS, &list);
	}
	ncfg_buf_free(&list);
}

/* Radio 3, one 2.4 GHz band with HT and no 20/40 bit. */
static void part20(ncfg_buf_t *out)
{
	ncfg_genl_header_t header = { NL80211_CMD_NEW_WIPHY, 1 };
	ncfg_buf_t         list;
	ncfg_buf_t         band;
	uint16_t           capability = 0x017c;

	ncfg_buf_init(out, 0);
	ncfg_buf_init(&list, 0);
	ncfg_buf_init(&band, 0);
	ncfg_genl_header_encode(&header, out);
	ncfg_wire_attr_put_u32(out, NL80211_ATTR_WIPHY, 3u);
	ncfg_wire_attr_put(&band, NL80211_BAND_ATTR_HT_CAPA, &capability, sizeof(capability));
	ncfg_wire_attr_put_nested(&list, NL80211_BAND_2GHZ, &band);
	ncfg_wire_attr_put_nested(out, NL80211_ATTR_WIPHY_BANDS, &list);
	ncfg_buf_free(&band);
	ncfg_buf_free(&list);
}

static void the_request(void)
{
	ncfg_genl_family_t family;
	ncfg_buf_t         message;
	ncfg_buf_t         body;
	ncfg_wire_attrs_t  attrs;
	ncfg_wire_attr_t   attr;
	uint16_t           kind = 0;
	uint16_t           flags = 0;
	char               err[NCFG_ERROR_MAX];

	memset(&family, 0, sizeof(family));
	family.id = 38;
	ncfg_buf_init(&message, 0);
	ncfg_buf_init(&body, 0);
	check(ncfg_wiphy_request(&message, &family, 1, err, sizeof(err)) &&
	        ncfg_wire_request_parts(&message, "nl80211", &kind, &flags, &body, err,
	        sizeof(err)) &&
	        (flags & NLM_F_DUMP) == NLM_F_DUMP &&
	        (unsigned char)body.data[0] == NL80211_CMD_GET_WIPHY,
	    "the radio request is a GET_WIPHY dump");
	check(ncfg_genl_payload_attrs(body.data, body.length, &attrs, err, sizeof(err)) &&
	        ncfg_wire_attrs_find(&attrs, NL80211_ATTR_SPLIT_WIPHY_DUMP, &attr, err,
	        sizeof(err)) == NCFG_WIRE_OK && attr.length == 0u,
	    "  asking to be split, as a flag with no value");
	ncfg_buf_free(&message);
	ncfg_buf_free(&body);
	ncfg_buf_init(&message, 0);
	check(!ncfg_wiphy_request(&message, NULL, 1, err, sizeof(err)),
	    "and refused without nl80211 resolved");
	ncfg_buf_free(&message);
}

static void the_reply(void)
{
	ncfg_buf_t   payload;
	ncfg_wiphy_t radio;
	char         err[NCFG_ERROR_MAX];

	part(&payload, 2u, 2, 1);
	check(ncfg_wiphy_parse(payload.data, payload.length, &radio, err, sizeof(err)) &&
	        radio.index == 2u && radio.high_throughput,
	    "a radio with HT in its second band has it");
	check(radio.forty_mhz_5 && !radio.forty_mhz_24,
	    "  and 40 MHz in that band alone, the second being 5 GHz, by the capability's bit 1");
	check(radio.vht_5, "  and 802.11ac, the band carrying VHT_CAPA (hwsim's, measured)");
	ncfg_buf_free(&payload);
	part20(&payload);
	check(ncfg_wiphy_parse(payload.data, payload.length, &radio, err, sizeof(err)) &&
	        radio.high_throughput && !radio.forty_mhz_24 && !radio.forty_mhz_5 &&
	        !radio.vht_5,
	    "a band whose capability lacks bit 1 has HT at 20 MHz only, and no 802.11ac");
	ncfg_buf_free(&payload);
	part(&payload, 2u, 2, 0);
	check(ncfg_wiphy_parse(payload.data, payload.length, &radio, err, sizeof(err)) &&
	        !radio.high_throughput,
	    "  and one with HT in neither has not");
	ncfg_buf_free(&payload);
	part(&payload, 2u, 0, 0);
	check(ncfg_wiphy_parse(payload.data, payload.length, &radio, err, sizeof(err)) &&
	        radio.index == 2u && !radio.high_throughput,
	    "a part with no bands is read, and is a part about something else");
	ncfg_buf_free(&payload);
	part(&payload, 0u, 1, 1);
	check(!ncfg_wiphy_parse(payload.data, payload.length, &radio, err, sizeof(err)),
	    "a part that does not name its radio is refused");
	ncfg_buf_free(&payload);
}

int main(void)
{
	the_request();
	the_reply();
	if (failures) {
		printf("%d check(s) failed\n", failures);
		return 1;
	}
	printf("wiphy_test: all checks passed\n");
	return 0;
}
