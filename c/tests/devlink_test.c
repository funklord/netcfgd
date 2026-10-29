/*
 * devlink_test.c -- the port dump request and one port's reply, against bytes
 * rather than against a card.
 *
 * WHAT IS CHECKED
 *   That the request is a dump of every port, and that a reply is read as a
 *   port only when it can be named: a missing device or a type this build has
 *   no word for is refused, because `ncfg status` prints the answer as what a
 *   card's port is running as, and a guessed mode is the thing it exists to
 *   stop. `current_test.c` takes the same bytes through the observation; this
 *   is the half that needs no seam.
 */
#include "ncfg/devlink.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/genl.h"
#include "ncfg/wire.h"

#include <stdio.h>
#include <string.h>

#include <linux/devlink.h>
#include <linux/netlink.h>

static int failures;

static int check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
	return condition;
}

static void detail(const char *what, const char *value)
{
	printf("  %s: %s\n", what, value ? value : "(none)");
}

/* A `PORT_GET` reply payload. `bus` of NULL leaves the device unnamed. */
static void reply(ncfg_buf_t *out, const char *bus, uint16_t type, const char *netdev)
{
	ncfg_genl_header_t header = { DEVLINK_CMD_PORT_NEW, 1 };

	ncfg_buf_init(out, 0);
	ncfg_genl_header_encode(&header, out);
	if (bus) {
		ncfg_wire_attr_put_str(out, DEVLINK_ATTR_BUS_NAME, bus);
	}
	ncfg_wire_attr_put_str(out, DEVLINK_ATTR_DEV_NAME, "0000:05:00.0");
	ncfg_wire_attr_put_u32(out, DEVLINK_ATTR_PORT_INDEX, 1u);
	ncfg_wire_attr_put(out, DEVLINK_ATTR_PORT_TYPE, &type, sizeof(type));
	if (netdev) {
		ncfg_wire_attr_put_str(out, DEVLINK_ATTR_PORT_NETDEV_NAME, netdev);
	}
}

static void the_request_is_a_dump_of_every_port(void)
{
	ncfg_genl_family_t family;
	ncfg_buf_t         message;
	ncfg_buf_t         body;
	uint16_t           kind = 0;
	uint16_t           flags = 0;
	char               err[NCFG_ERROR_MAX];

	memset(&family, 0, sizeof(family));
	family.id = 21;
	ncfg_buf_init(&message, 0);
	ncfg_buf_init(&body, 0);
	check(ncfg_devlink_ports_request(&message, &family, 3, err, sizeof(err)) &&
	        ncfg_wire_request_parts(&message, "devlink", &kind, &flags, &body, err,
	        sizeof(err)),
	    "a PORT_GET request builds and decodes");
	check(kind == 21 && (flags & NLM_F_DUMP) == NLM_F_DUMP,
	    "addressed to the family, as a dump");
	check(body.length == NCFG_GENL_HDR_LEN && (unsigned char)body.data[0] == DEVLINK_CMD_PORT_GET,
	    "asking PORT_GET with no attributes, so every port of every device");
	ncfg_buf_free(&message);
	ncfg_buf_free(&body);
}

static void a_port_is_read_only_when_it_can_be_named(void)
{
	ncfg_buf_t          payload;
	ncfg_devlink_port_t port;
	char                err[NCFG_ERROR_MAX];

	reply(&payload, "pci", DEVLINK_PORT_TYPE_ETH, "eth2");
	check(ncfg_devlink_port_parse(payload.data, payload.length, &port, err, sizeof(err)) &&
	        strcmp(port.device, "pci/0000:05:00.0") == 0 && port.index == 1u &&
	        port.type == NCFG_DEVLINK_PORT_ETH && strcmp(port.netdev, "eth2") == 0,
	    "an Ethernet port reads with its device, number and interface");
	check(port.physical, "  and no flavour is a physical port, as before flavours existed");
	check(strcmp(ncfg_devlink_port_type_name(port.type), "eth") == 0,
	    "  and its type is written `eth`");
	ncfg_buf_free(&payload);

	reply(&payload, "pci", 7u, NULL);
	check(!ncfg_devlink_port_parse(payload.data, payload.length, &port, err, sizeof(err)),
	    "a type this build has no word for is refused, not guessed");
	detail("said", err);
	ncfg_buf_free(&payload);

	reply(&payload, NULL, DEVLINK_PORT_TYPE_IB, NULL);
	check(!ncfg_devlink_port_parse(payload.data, payload.length, &port, err, sizeof(err)),
	    "a port whose device is not named is refused");
	ncfg_buf_free(&payload);

	reply(&payload, "pci", DEVLINK_PORT_TYPE_ETH, NULL);
	check(!ncfg_devlink_port_parse(payload.data, 2u, &port, err, sizeof(err)),
	    "and so is a payload too short for its own header");
	ncfg_buf_free(&payload);
}

int main(void)
{
	the_request_is_a_dump_of_every_port();
	a_port_is_read_only_when_it_can_be_named();

	if (failures) {
		printf("%d check(s) failed\n", failures);
		return 1;
	}
	printf("devlink_test: all checks passed\n");
	return 0;
}
