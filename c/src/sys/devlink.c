/*
 * devlink.c -- the request and reply described in devlink.h.
 *
 * The reply is the kernel's and is read as hostile all the same, for
 * `wire.c`'s reason: a length in it is a length nobody here chose.
 */
#include "ncfg/devlink.h"

#include "ncfg/wire.h"

#include <stdio.h>
#include <string.h>

#include <linux/devlink.h>
#include <linux/netlink.h>

const char *ncfg_devlink_port_type_name(ncfg_devlink_port_type_t type)
{
	switch (type) {
	case NCFG_DEVLINK_PORT_NOTSET:
		return "notset";
	case NCFG_DEVLINK_PORT_AUTO:
		return "auto";
	case NCFG_DEVLINK_PORT_ETH:
		return "eth";
	case NCFG_DEVLINK_PORT_IB:
		return "ib";
	default:
		break;
	}
	return "unknown";
}

int ncfg_devlink_ports_request(ncfg_buf_t *out, const ncfg_genl_family_t *family, uint32_t seq,
    char *err, size_t err_size)
{
	ncfg_genl_header_t header;

	if (!family) {
		ncfg_error_set(err, err_size, "a devlink request needs the family resolved");
		return 0;
	}
	header.cmd = DEVLINK_CMD_PORT_GET;
	header.version = DEVLINK_GENL_VERSION;
	/* No attributes and a dump: every port of every device, which is one
	 * message where asking per device would be one per card. */
	return ncfg_genl_build_request(out, family->id, &header, NLM_F_DUMP, seq, NULL, err,
	    err_size);
}

/* A string attribute into a fixed buffer, or empty where it is absent. */
static int text_of(const ncfg_wire_attrs_t *attrs, uint16_t kind, char *out, size_t out_size,
    char *err, size_t err_size)
{
	ncfg_wire_attr_t attr;
	ncfg_wire_step_t step;

	out[0] = '\0';
	step = ncfg_wire_attrs_find(attrs, kind, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step != NCFG_WIRE_OK) {
		return 1;
	}
	return ncfg_wire_attr_string(&attr, out, out_size, err, err_size);
}

/* A u16 attribute, and whether it was there. */
static int u16_of(const ncfg_wire_attrs_t *attrs, uint16_t kind, uint16_t *out, int *present,
    char *err, size_t err_size)
{
	ncfg_wire_attr_t attr;
	ncfg_wire_step_t step;

	*present = 0;
	step = ncfg_wire_attrs_find(attrs, kind, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step != NCFG_WIRE_OK) {
		return 1;
	}
	*present = 1;
	return ncfg_wire_attr_u16(&attr, out, err, err_size);
}

int ncfg_devlink_port_parse(const void *payload, size_t length, ncfg_devlink_port_t *out,
    char *err, size_t err_size)
{
	ncfg_wire_attrs_t attrs;
	ncfg_wire_attr_t  attr;
	ncfg_wire_step_t  step;
	char              bus[NCFG_DEVLINK_DEVICE_MAX];
	char              name[NCFG_DEVLINK_DEVICE_MAX];
	uint16_t          type = 0;
	uint16_t          flavour = 0;
	int               present = 0;

	if (!out) {
		ncfg_error_set(err, err_size, "a devlink port needs somewhere to be written");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!ncfg_genl_payload_attrs(payload, length, &attrs, err, err_size) ||
	    !text_of(&attrs, DEVLINK_ATTR_BUS_NAME, bus, sizeof(bus), err, err_size) ||
	    !text_of(&attrs, DEVLINK_ATTR_DEV_NAME, name, sizeof(name), err, err_size)) {
		return 0;
	}
	if (bus[0] == '\0' || name[0] == '\0') {
		ncfg_error_set(err, err_size, "the kernel described a devlink port without its device");
		return 0;
	}
	if ((size_t)snprintf(out->device, sizeof(out->device), "%s/%s", bus, name) >=
	    sizeof(out->device)) {
		ncfg_error_set(err, err_size, "a devlink device name is longer than this build holds");
		return 0;
	}
	step = ncfg_wire_attrs_find(&attrs, DEVLINK_ATTR_PORT_INDEX, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step != NCFG_WIRE_OK || !ncfg_wire_attr_u32(&attr, &out->index, err, err_size)) {
		ncfg_error_set(err, err_size, "the kernel described a port of %s without its number",
		    out->device);
		return 0;
	}
	if (!u16_of(&attrs, DEVLINK_ATTR_PORT_TYPE, &type, &present, err, err_size)) {
		return 0;
	}
	switch (type) {
	case DEVLINK_PORT_TYPE_NOTSET:
		out->type = NCFG_DEVLINK_PORT_NOTSET;
		break;
	case DEVLINK_PORT_TYPE_AUTO:
		out->type = NCFG_DEVLINK_PORT_AUTO;
		break;
	case DEVLINK_PORT_TYPE_ETH:
		out->type = NCFG_DEVLINK_PORT_ETH;
		break;
	case DEVLINK_PORT_TYPE_IB:
		out->type = NCFG_DEVLINK_PORT_IB;
		break;
	default:
		ncfg_error_set(err, err_size,
		    "port %u of %s runs as devlink type %u, which this build has no word for",
		    (unsigned)out->index, out->device, (unsigned)type);
		return 0;
	}
	/* No flavour is a kernel from before flavours (4.18), whose ports were all
	 * physical ones. */
	if (!u16_of(&attrs, DEVLINK_ATTR_PORT_FLAVOUR, &flavour, &present, err, err_size)) {
		return 0;
	}
	out->physical = !present || flavour == DEVLINK_PORT_FLAVOUR_PHYSICAL;
	return text_of(&attrs, DEVLINK_ATTR_PORT_NETDEV_NAME, out->netdev, sizeof(out->netdev), err,
	    err_size) &&
	    text_of(&attrs, DEVLINK_ATTR_PORT_IBDEV_NAME, out->ibdev, sizeof(out->ibdev), err,
	    err_size);
}
