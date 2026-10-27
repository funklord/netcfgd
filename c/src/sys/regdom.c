/*
 * regdom.c -- the request and reply described in regdom.h, and the one round
 * trip that sends one.
 *
 * The reply is the kernel's, which is the more trustworthy end of netcfgd's
 * boundaries, and it is still read as hostile for `wire.c`'s reason: it came
 * through a socket, and a length in it is a length nobody here chose.
 */
#include "ncfg/regdom.h"

#include "ncfg/genl_socket.h"
#include "ncfg/netlink.h"
#include "ncfg/wire.h"

#include <ctype.h>
#include <string.h>

#include <linux/nl80211.h>

int ncfg_regdom_request(ncfg_buf_t *out, const ncfg_genl_family_t *family, uint32_t seq,
    char *err, size_t err_size)
{
	ncfg_genl_header_t header;

	if (!family) {
		ncfg_error_set(err, err_size, "a regulatory domain request needs nl80211 resolved");
		return 0;
	}
	/* Version 0, which is what `iw` sends: nl80211 has never refused a request
	 * for the version it carries, and naming a later one would be a claim
	 * about message layouts this request does not use. */
	header.cmd = NL80211_CMD_GET_REG;
	header.version = 0;
	/* No attributes: without `NL80211_ATTR_WIPHY` the kernel answers for the
	 * global domain, which is the one every radio without a private domain of
	 * its own is held to. */
	return ncfg_genl_build_request(out, family->id, &header, 0, seq, NULL, err, err_size);
}

int ncfg_regdom_parse(const void *payload, size_t length, char *out, size_t out_size,
    char *err, size_t err_size)
{
	ncfg_wire_attrs_t attrs;
	ncfg_wire_attr_t  attr;
	ncfg_wire_step_t  step;
	char              code[8];

	if (!out || out_size < NCFG_REGDOM_TEXT_MAX) {
		ncfg_error_set(err, err_size, "a regulatory domain needs three bytes to be written");
		return 0;
	}
	out[0] = '\0';
	if (!ncfg_genl_payload_attrs(payload, length, &attrs, err, err_size)) {
		return 0;
	}
	step = ncfg_wire_attrs_find(&attrs, NL80211_ATTR_REG_ALPHA2, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step != NCFG_WIRE_OK) {
		ncfg_error_set(err, err_size,
		    "the kernel answered for the regulatory domain without naming a country");
		return 0;
	}
	if (!ncfg_wire_attr_string(&attr, code, sizeof(code), err, err_size)) {
		return 0;
	}
	/* Two characters, letters or digits: a country, or the kernel's `00`,
	 * `98` and `99`. Anything else printed as a domain would be a country
	 * nobody is in. */
	if (strlen(code) != 2u || !isalnum((unsigned char)code[0]) ||
	    !isalnum((unsigned char)code[1])) {
		ncfg_error_set(err, err_size,
		    "the kernel named a regulatory domain that is not two letters or digits");
		return 0;
	}
	out[0] = code[0];
	out[1] = code[1];
	out[2] = '\0';
	return 1;
}

int ncfg_regdom_read(char *out, size_t out_size, char *err, size_t err_size)
{
	ncfg_netlink_t       socket;
	ncfg_genl_family_t   family;
	ncfg_netlink_reply_t reply;
	ncfg_buf_t           message;
	ncfg_buf_t           body;
	uint16_t             kind = 0;
	uint16_t             flags = 0;
	int                  ok;

	if (!ncfg_genl_family_open(NL80211_GENL_NAME, &socket, &family, err, err_size)) {
		return 0;
	}
	memset(&reply, 0, sizeof(reply));
	ncfg_buf_init(&message, 0);
	ncfg_buf_init(&body, 0);
	/* Taken apart and handed to `ncfg_netlink_request`, for the reason
	 * `kernel_genl.c` gives: the request is spelled once, by the module that
	 * owns it. */
	ok = ncfg_regdom_request(&message, &family, ncfg_netlink_take_seq(&socket), err,
	         err_size) &&
	    ncfg_wire_request_parts(&message, "nl80211", &kind, &flags, &body, err, err_size);
	ncfg_buf_free(&message);
	if (ok) {
		ok = ncfg_netlink_request(&socket, kind, flags, &body, NULL, &reply, err, err_size);
	}
	ncfg_buf_free(&body);
	if (ok && reply.count == 0) {
		ncfg_error_set(err, err_size,
		    "the kernel answered the regulatory domain request with nothing");
		ok = 0;
	}
	if (ok) {
		ok = ncfg_regdom_parse(reply.items[0].bytes, reply.items[0].length, out, out_size,
		    err, err_size);
	}
	ncfg_netlink_reply_free(&reply);
	ncfg_genl_family_free(&family);
	ncfg_netlink_close(&socket);
	return ok;
}
