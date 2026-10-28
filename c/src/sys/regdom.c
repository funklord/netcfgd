/*
 * regdom.c -- the request and reply described in regdom.h.
 *
 * The reply is the kernel's, which is the more trustworthy end of netcfgd's
 * boundaries, and it is still read as hostile for `wire.c`'s reason: it came
 * through a socket, and a length in it is a length nobody here chose.
 */
#include "ncfg/regdom.h"

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

/* Two characters, letters or digits: a country, or the kernel's `00`, `98`
 * and `99`. Anything else printed as a domain would be a country nobody is
 * in. */
static int country_of(const ncfg_wire_attr_t *attr, char *out, char *err, size_t err_size)
{
	char code[8];

	if (!ncfg_wire_attr_string(attr, code, sizeof(code), err, err_size)) {
		return 0;
	}
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

int ncfg_regdom_parse(const void *payload, size_t length, char *out, size_t out_size,
    char *err, size_t err_size)
{
	ncfg_wire_attrs_t attrs;
	ncfg_wire_attr_t  attr;
	ncfg_wire_step_t  step;

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
	return country_of(&attr, out, err, err_size);
}

const char *ncfg_regdom_setter_name(ncfg_regdom_setter_t set_by)
{
	switch (set_by) {
	case NCFG_REGDOM_SET_BY_KERNEL:
		return "kernel";
	case NCFG_REGDOM_SET_BY_USER:
		return "user";
	case NCFG_REGDOM_SET_BY_DRIVER:
		return "driver";
	case NCFG_REGDOM_SET_BY_ACCESS_POINT:
		return "access_point";
	default:
		break;
	}
	return "unknown";
}

/* One `REG_CHANGE` payload, after the generic netlink header. */
static int change_of(const void *payload, size_t length, ncfg_regdom_change_t *out, char *err,
    size_t err_size)
{
	ncfg_wire_attrs_t attrs;
	ncfg_wire_attr_t  attr;
	ncfg_wire_step_t  step;
	uint8_t           initiator;
	uint8_t           type;

	if (!ncfg_genl_payload_attrs(payload, length, &attrs, err, err_size)) {
		return 0;
	}
	step = ncfg_wire_attrs_find(&attrs, NL80211_ATTR_REG_INITIATOR, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step != NCFG_WIRE_OK || !ncfg_wire_attr_u8(&attr, &initiator, err, err_size)) {
		ncfg_error_set(err, err_size,
		    "the kernel announced a regulatory change without saying who made it");
		return 0;
	}
	switch (initiator) {
	case NL80211_REGDOM_SET_BY_CORE:
		out->set_by = NCFG_REGDOM_SET_BY_KERNEL;
		break;
	case NL80211_REGDOM_SET_BY_USER:
		out->set_by = NCFG_REGDOM_SET_BY_USER;
		break;
	case NL80211_REGDOM_SET_BY_DRIVER:
		out->set_by = NCFG_REGDOM_SET_BY_DRIVER;
		break;
	case NL80211_REGDOM_SET_BY_COUNTRY_IE:
		out->set_by = NCFG_REGDOM_SET_BY_ACCESS_POINT;
		break;
	default:
		ncfg_error_set(err, err_size,
		    "the kernel announced a regulatory change made by initiator %u, which this "
		    "build has no word for", (unsigned)initiator);
		return 0;
	}
	step = ncfg_wire_attrs_find(&attrs, NL80211_ATTR_REG_TYPE, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step != NCFG_WIRE_OK || !ncfg_wire_attr_u8(&attr, &type, err, err_size)) {
		ncfg_error_set(err, err_size,
		    "the kernel announced a regulatory change without saying what kind");
		return 0;
	}
	switch (type) {
	case NL80211_REGDOM_TYPE_WORLD:
		(void)memcpy(out->code, "00", 3u);
		return 1;
	case NL80211_REGDOM_TYPE_CUSTOM_WORLD:
		(void)memcpy(out->code, "99", 3u);
		return 1;
	case NL80211_REGDOM_TYPE_INTERSECTION:
		(void)memcpy(out->code, "98", 3u);
		return 1;
	case NL80211_REGDOM_TYPE_COUNTRY:
		break;
	default:
		ncfg_error_set(err, err_size,
		    "the kernel announced a regulatory domain of type %u, which this build has "
		    "no word for", (unsigned)type);
		return 0;
	}
	step = ncfg_wire_attrs_find(&attrs, NL80211_ATTR_REG_ALPHA2, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step != NCFG_WIRE_OK) {
		ncfg_error_set(err, err_size,
		    "the kernel announced a country's regulatory domain without naming it");
		return 0;
	}
	return country_of(&attr, out->code, err, err_size);
}

int ncfg_regdom_change_parse(const void *bytes, size_t length, uint16_t family, int *found,
    ncfg_regdom_change_t *out, char *err, size_t err_size)
{
	ncfg_wire_messages_t walk;
	ncfg_wire_message_t  message;
	ncfg_wire_step_t     step;

	if (!found || !out) {
		ncfg_error_set(err, err_size, "a regulatory change needs somewhere to be written");
		return 0;
	}
	*found = 0;
	ncfg_wire_messages_start(&walk, bytes, length);
	while ((step = ncfg_wire_messages_next(&walk, &message, err, err_size)) == NCFG_WIRE_OK) {
		ncfg_genl_header_t   header;
		ncfg_regdom_change_t change;

		if (message.header.kind != family) {
			continue;
		}
		if (!ncfg_genl_header_decode(message.payload, message.payload_length, &header, err,
		    err_size)) {
			return 0;
		}
		/* `WIPHY_REG_CHANGE` is a radio with a domain of its own, which is
		 * not the global one the observation reports. */
		if (header.cmd != NL80211_CMD_REG_CHANGE) {
			continue;
		}
		memset(&change, 0, sizeof(change));
		if (!change_of(message.payload, message.payload_length, &change, err, err_size)) {
			return 0;
		}
		*out = change;
		*found = 1;
	}
	return step == NCFG_WIRE_END;
}
