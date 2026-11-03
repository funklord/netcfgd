/*
 * mesh_peer_test.c -- a mesh point's peers and its making, against bytes
 * rather than against a radio (`src/sys/mesh_peer.c`, project.md 10.686 and
 * 10.687).
 *
 * WHAT IS CHECKED
 *   That the station dump asks the one interface; that a reply is read only
 *   with an address, keeps the peer link's state apart from its absence, and
 *   refuses a state attribute too short to hold one; that the mesh point is
 *   made on the parent's index as a mesh point with its name and address, and
 *   taken away by index; and that its address differs from the radio's --
 *   mac80211 refuses a second interface up on the same one (ENOTUNIQ,
 *   measured in hull-mesh) -- and is the same on every start.
 */
#include "ncfg/mesh_peer.h"

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

/* A `GET_STATION` reply: `mac` NULL leaves the address out; `state` of -1
 * leaves the peer link's state out, -2 the station information as well, and
 * -3 writes a state attribute with no byte in it. */
static void reply(ncfg_buf_t *out, const uint8_t *mac, int state)
{
	ncfg_genl_header_t header = { NL80211_CMD_NEW_STATION, 1 };
	ncfg_buf_t         info;

	ncfg_buf_init(out, 0);
	ncfg_genl_header_encode(&header, out);
	ncfg_wire_attr_put_u32(out, NL80211_ATTR_IFINDEX, 7u);
	if (mac) {
		ncfg_wire_attr_put(out, NL80211_ATTR_MAC, mac, 6u);
	}
	if (state == -2) {
		return;
	}
	ncfg_buf_init(&info, 0);
	ncfg_wire_attr_put_u32(&info, NL80211_STA_INFO_INACTIVE_TIME, 40u);
	if (state >= 0) {
		ncfg_wire_attr_put_u8(&info, NL80211_STA_INFO_PLINK_STATE, (uint8_t)state);
	} else if (state == -3) {
		ncfg_wire_attr_put(&info, NL80211_STA_INFO_PLINK_STATE, NULL, 0u);
	}
	ncfg_wire_attr_put(out, NL80211_ATTR_STA_INFO, info.data, info.length);
	ncfg_buf_free(&info);
}

/* The request's command and attributes, its flags into `flags`. */
static int parts(const ncfg_buf_t *message, uint16_t *flags, uint8_t *cmd,
    ncfg_wire_attrs_t *attrs, ncfg_buf_t *body)
{
	uint16_t kind = 0;
	char     err[NCFG_ERROR_MAX];

	if (!ncfg_wire_request_parts(message, "nl80211", &kind, flags, body, err, sizeof(err)) ||
	    kind != 38u || body->length < 4u) {
		return 0;
	}
	*cmd = (uint8_t)body->data[0];
	return ncfg_genl_payload_attrs(body->data, body->length, attrs, err, sizeof(err));
}

static uint32_t u32_of(ncfg_wire_attrs_t *attrs, uint16_t type)
{
	ncfg_wire_attr_t attr;
	uint32_t         value = 0;
	char             err[NCFG_ERROR_MAX];

	if (ncfg_wire_attrs_find(attrs, type, &attr, err, sizeof(err)) != NCFG_WIRE_OK ||
	    !ncfg_wire_attr_u32(&attr, &value, err, sizeof(err))) {
		return 0u;
	}
	return value;
}

static void the_requests(void)
{
	static const uint8_t mac[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
	ncfg_genl_family_t   family;
	ncfg_buf_t           message;
	ncfg_buf_t           body;
	ncfg_wire_attrs_t    attrs;
	ncfg_wire_attrs_t    again;
	ncfg_wire_attr_t     attr;
	uint16_t             flags = 0;
	uint8_t              cmd = 0;
	char                 err[NCFG_ERROR_MAX];

	memset(&family, 0, sizeof(family));
	family.id = 38;

	ncfg_buf_init(&message, 0);
	ncfg_buf_init(&body, 0);
	check(ncfg_mesh_peers_request(&message, &family, 7u, 1, err, sizeof(err)) &&
	        parts(&message, &flags, &cmd, &attrs, &body) && cmd == NL80211_CMD_GET_STATION &&
	        (flags & NLM_F_DUMP) == NLM_F_DUMP && u32_of(&attrs, NL80211_ATTR_IFINDEX) == 7u,
	    "the peers request is a GET_STATION dump of the one interface");
	ncfg_buf_free(&message);
	ncfg_buf_free(&body);

	ncfg_buf_init(&message, 0);
	ncfg_buf_init(&body, 0);
	check(ncfg_mesh_point_add_request(&message, &family, 3u, "mesh0", mac, 2, err,
	          sizeof(err)) &&
	        parts(&message, &flags, &cmd, &attrs, &body) && cmd == NL80211_CMD_NEW_INTERFACE &&
	        (flags & NLM_F_ACK) == NLM_F_ACK && u32_of(&attrs, NL80211_ATTR_IFINDEX) == 3u &&
	        (again = attrs, u32_of(&again, NL80211_ATTR_IFTYPE)) == NL80211_IFTYPE_MESH_POINT &&
	        ncfg_wire_attrs_find(&attrs, NL80211_ATTR_IFNAME, &attr, err, sizeof(err)) ==
	            NCFG_WIRE_OK &&
	        attr.length >= 5u && memcmp(attr.value, "mesh0", 5u) == 0 &&
	        ncfg_wire_attrs_find(&attrs, NL80211_ATTR_MAC, &attr, err, sizeof(err)) ==
	            NCFG_WIRE_OK &&
	        attr.length == 6u && memcmp(attr.value, mac, 6u) == 0,
	    "the mesh point is made on the parent's index, a mesh point, named, addressed");
	ncfg_buf_free(&message);
	ncfg_buf_free(&body);

	ncfg_buf_init(&message, 0);
	check(!ncfg_mesh_point_add_request(&message, &family, 0u, "mesh0", mac, 2, err,
	          sizeof(err)) &&
	        !ncfg_mesh_point_add_request(&message, &family, 3u, "", mac, 2, err, sizeof(err)),
	    "  and is refused without a radio or a name");
	ncfg_buf_free(&message);

	ncfg_buf_init(&message, 0);
	ncfg_buf_init(&body, 0);
	check(ncfg_mesh_point_delete_request(&message, &family, 9u, 3, err, sizeof(err)) &&
	        parts(&message, &flags, &cmd, &attrs, &body) && cmd == NL80211_CMD_DEL_INTERFACE &&
	        u32_of(&attrs, NL80211_ATTR_IFINDEX) == 9u,
	    "and taken away by its index, DEL_INTERFACE");
	ncfg_buf_free(&message);
	ncfg_buf_free(&body);
}

static void the_replies(void)
{
	static const uint8_t mac[6] = { 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x07 };
	ncfg_mesh_peer_t     peer;
	ncfg_buf_t           message;
	char                 err[NCFG_ERROR_MAX];

	reply(&message, mac, NCFG_MESH_PLINK_ESTAB);
	check(ncfg_mesh_peer_parse(message.data, message.length, &peer, err, sizeof(err)) &&
	        strcmp(peer.mac, "aa:bb:cc:00:00:07") == 0 && peer.has_plink_state &&
	        peer.plink_state == NCFG_MESH_PLINK_ESTAB,
	    "a peer is read with its address and its link established");
	ncfg_buf_free(&message);

	reply(&message, mac, -1);
	check(ncfg_mesh_peer_parse(message.data, message.length, &peer, err, sizeof(err)) &&
	        !peer.has_plink_state,
	    "  a reply with no link state says nothing of it, rather than a state");
	ncfg_buf_free(&message);

	reply(&message, mac, -2);
	check(ncfg_mesh_peer_parse(message.data, message.length, &peer, err, sizeof(err)) &&
	        !peer.has_plink_state,
	    "  and one with no station information at all is still a station");
	ncfg_buf_free(&message);

	reply(&message, NULL, NCFG_MESH_PLINK_ESTAB);
	check(!ncfg_mesh_peer_parse(message.data, message.length, &peer, err, sizeof(err)),
	    "a station without its address is refused");
	ncfg_buf_free(&message);

	reply(&message, mac, -3);
	check(!ncfg_mesh_peer_parse(message.data, message.length, &peer, err, sizeof(err)),
	    "a link state with no byte in it is refused, not read past");
	ncfg_buf_free(&message);

	check(!ncfg_mesh_peer_parse("\x13", 1u, &peer, err, sizeof(err)),
	    "a payload too short for its header is refused");
}

static void the_address(void)
{
	static const uint8_t global[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
	static const uint8_t local[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
	uint8_t              out[6];
	uint8_t              twice[6];

	ncfg_mesh_point_address(global, out);
	ncfg_mesh_point_address(global, twice);
	check(memcmp(out, global, 6u) != 0 && out[0] == 0x02u && memcmp(out + 1, global + 1, 5u) == 0 &&
	        memcmp(out, twice, 6u) == 0,
	    "a mesh point's address is the radio's, locally administered, every time");
	ncfg_mesh_point_address(local, out);
	check(memcmp(out, local, 6u) != 0 && out[0] == 0x02u && out[5] == 0x54u,
	    "  and where the radio's is local already, it still differs");
}

int main(void)
{
	the_requests();
	the_replies();
	the_address();
	if (failures) {
		printf("\nmesh_peer_test: %d check(s) FAILED\n", failures);
		return 1;
	}
	printf("\nmesh_peer_test: all checks passed\n");
	return 0;
}
