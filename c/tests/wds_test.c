/*
 * wds_test.c -- four-address mode's requests and reply, against bytes rather
 * than against a radio.
 *
 * WHAT IS CHECKED
 *   That the dump asks every interface, that the set names the interface,
 *   says it is a station's -- which `SET_INTERFACE` requires -- and carries the
 *   mode, and that a reply is read only when it names an interface by index
 *   and by name. A reply with no `4ADDR` says nothing either way, which is
 *   kept apart from "off" (10.587 item 4).
 */
#include "ncfg/wds.h"

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

/* A `GET_INTERFACE` reply. `four` of -1 leaves `4ADDR` out. */
static void reply(ncfg_buf_t *out, uint32_t index, const char *name, int four)
{
	ncfg_genl_header_t header = { NL80211_CMD_NEW_INTERFACE, 1 };

	ncfg_buf_init(out, 0);
	ncfg_genl_header_encode(&header, out);
	if (index) {
		ncfg_wire_attr_put_u32(out, NL80211_ATTR_IFINDEX, index);
	}
	if (name) {
		ncfg_wire_attr_put_str(out, NL80211_ATTR_IFNAME, name);
	}
	ncfg_wire_attr_put_u32(out, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_STATION);
	if (four >= 0) {
		ncfg_wire_attr_put_u8(out, NL80211_ATTR_4ADDR, (uint8_t)four);
	}
}

static void the_requests(void)
{
	ncfg_genl_family_t family;
	ncfg_buf_t         message;
	ncfg_buf_t         body;
	ncfg_wire_attrs_t  attrs;
	ncfg_wire_attr_t   attr;
	uint16_t           kind = 0;
	uint16_t           flags = 0;
	uint32_t           value = 0;
	uint8_t            flag = 0;
	char               err[NCFG_ERROR_MAX];

	memset(&family, 0, sizeof(family));
	family.id = 38;
	ncfg_buf_init(&message, 0);
	ncfg_buf_init(&body, 0);
	check(ncfg_wds_interfaces_request(&message, &family, 1, err, sizeof(err)) &&
	        ncfg_wire_request_parts(&message, "nl80211", &kind, &flags, &body, err,
	        sizeof(err)) &&
	        (flags & NLM_F_DUMP) == NLM_F_DUMP &&
	        (unsigned char)body.data[0] == NL80211_CMD_GET_INTERFACE,
	    "the interface request is a GET_INTERFACE dump");
	ncfg_buf_free(&message);
	ncfg_buf_free(&body);

	ncfg_buf_init(&message, 0);
	ncfg_buf_init(&body, 0);
	check(ncfg_wds_set_request(&message, &family, 7u, 1, 2, err, sizeof(err)) &&
	        ncfg_wire_request_parts(&message, "nl80211", &kind, &flags, &body, err,
	        sizeof(err)) &&
	        (unsigned char)body.data[0] == NL80211_CMD_SET_INTERFACE,
	    "turning it on is a SET_INTERFACE");
	check(ncfg_genl_payload_attrs(body.data, body.length, &attrs, err, sizeof(err)) &&
	        ncfg_wire_attrs_find(&attrs, NL80211_ATTR_IFINDEX, &attr, err, sizeof(err)) ==
	        NCFG_WIRE_OK && ncfg_wire_attr_u32(&attr, &value, err, sizeof(err)) && value == 7u,
	    "  naming the interface by its index");
	check(ncfg_wire_attrs_find(&attrs, NL80211_ATTR_IFTYPE, &attr, err, sizeof(err)) ==
	        NCFG_WIRE_OK && ncfg_wire_attr_u32(&attr, &value, err, sizeof(err)) &&
	        value == NL80211_IFTYPE_STATION,
	    "  as a station, which SET_INTERFACE requires");
	check(ncfg_wire_attrs_find(&attrs, NL80211_ATTR_4ADDR, &attr, err, sizeof(err)) ==
	        NCFG_WIRE_OK && ncfg_wire_attr_u8(&attr, &flag, err, sizeof(err)) && flag == 1u,
	    "  and carrying the mode");
	ncfg_buf_free(&message);
	ncfg_buf_free(&body);
	ncfg_buf_init(&message, 0);
	check(!ncfg_wds_set_request(&message, &family, 0u, 1, 2, err, sizeof(err)),
	    "a set with no interface index is refused");
	ncfg_buf_free(&message);
}

static void the_reply(void)
{
	ncfg_buf_t           payload;
	ncfg_wds_interface_t radio;
	char                 err[NCFG_ERROR_MAX];

	reply(&payload, 4u, "wlan1", 1);
	check(ncfg_wds_interface_parse(payload.data, payload.length, &radio, err, sizeof(err)) &&
	        radio.index == 4u && strcmp(radio.name, "wlan1") == 0 && radio.has_four_address &&
	        radio.four_address,
	    "a radio in four-address mode reads as on");
	ncfg_buf_free(&payload);
	reply(&payload, 4u, "wlan1", -1);
	check(ncfg_wds_interface_parse(payload.data, payload.length, &radio, err, sizeof(err)) &&
	        !radio.has_four_address,
	    "one whose reply carries no 4ADDR says nothing, which is not the same as off");
	ncfg_buf_free(&payload);
	reply(&payload, 0u, "wlan1", 0);
	check(!ncfg_wds_interface_parse(payload.data, payload.length, &radio, err, sizeof(err)),
	    "a reply with no index is refused");
	ncfg_buf_free(&payload);
	reply(&payload, 4u, NULL, 0);
	check(!ncfg_wds_interface_parse(payload.data, payload.length, &radio, err, sizeof(err)),
	    "and so is one with no name");
	ncfg_buf_free(&payload);
}

int main(void)
{
	the_requests();
	the_reply();
	if (failures) {
		printf("%d check(s) failed\n", failures);
		return 1;
	}
	printf("wds_test: all checks passed\n");
	return 0;
}
