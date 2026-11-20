/*
 * link_modes_test.c -- autonegotiation, speed and duplex: the messages, the
 * record of what was forced, and the plan (project.md 10.877); and the ring
 * sizes beside them, built the same way (10.881).
 *
 * WHAT THESE CASES ARE FOR
 *   * **The two messages carry exactly what was asked.** A field left alone
 *     is absent from the set, not zero: `DUPLEX_HALF` is 0, so a zero sent for
 *     "leave it" would halve a link's duplex.
 *   * **A reply is read for all three or not at all**, and the kernel's
 *     unknowns -- `SPEED_UNKNOWN`, `DUPLEX_UNKNOWN` -- are absences.
 *   * **The record stands in only where the kernel cannot say**: a forced
 *     link with no carrier. A kernel answer always wins.
 *   * **The planner compares what the setting is**: speed and duplex with
 *     autonegotiation off, autonegotiation alone with it on, and nothing on
 *     a link that reports no link modes -- each of which, got wrong, plans
 *     a carrier-dropping set on every pass for ever.
 *
 *   The kernel half is `tests/hull/link-modes`, against virtio-net.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/ethtool.h"
#include "ncfg/genl.h"
#include "ncfg/observe.h"
#include "ncfg/wire.h"

#include "planfix.h"
#include "testdir.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static void resolved_family(ncfg_genl_family_t *family)
{
	memset(family, 0, sizeof(*family));
	(void)snprintf(family->name, sizeof(family->name), "%s", NCFG_ETHTOOL_FAMILY);
	family->id = 22;
}

static int request_attrs(const ncfg_buf_t *message, ncfg_wire_attrs_t *out)
{
	if (message->length <= NCFG_WIRE_NLMSG_HDR_LEN + NCFG_GENL_HDR_LEN) {
		return 0;
	}
	return ncfg_genl_payload_attrs(message->data + NCFG_WIRE_NLMSG_HDR_LEN,
	    message->length - NCFG_WIRE_NLMSG_HDR_LEN, out, NULL, 0);
}

static int has_attr(const ncfg_buf_t *message, uint16_t kind, ncfg_wire_attr_t *out)
{
	ncfg_wire_attrs_t attrs;

	return request_attrs(message, &attrs) &&
	    ncfg_wire_attrs_find(&attrs, kind, out, NULL, 0) == NCFG_WIRE_OK;
}

static void test_messages(void)
{
	ncfg_genl_family_t            family;
	ncfg_buf_t                    message;
	ncfg_wire_attr_t              attr;
	ncfg_genl_header_t            header;
	ncfg_wire_header_t            outer;
	ncfg_ethtool_link_modes_set_t wanted;
	uint8_t                       byte = 0;
	uint32_t                      word = 0;

	resolved_family(&family);
	check(ETHTOOL_MSG_LINKMODES_GET == 4 && ETHTOOL_MSG_LINKMODES_SET == 5,
	    "LINKMODES_GET and _SET are commands four and five");

	ncfg_buf_init(&message, 0);
	check(ncfg_ethtool_link_modes_get_request(&message, &family, "eth0", 3, NULL, 0),
	    "a get request is built");
	check(ncfg_genl_header_decode(message.data + NCFG_WIRE_NLMSG_HDR_LEN,
	    message.length - NCFG_WIRE_NLMSG_HDR_LEN, &header, NULL, 0) &&
	    header.cmd == ETHTOOL_MSG_LINKMODES_GET, "as LINKMODES_GET");
	check(has_attr(&message, ETHTOOL_A_LINKMODES_HEADER, &attr), "naming the device in its header");
	ncfg_buf_free(&message);

	wanted.autoneg = 0;
	wanted.speed = 100;
	wanted.duplex = DUPLEX_FULL;
	ncfg_buf_init(&message, 0);
	check(ncfg_ethtool_link_modes_set_request(&message, &family, "eth0", &wanted, 9, NULL, 0),
	    "a set request is built");
	check(ncfg_wire_header_decode(message.data, message.length, &outer, NULL, 0) &&
	    (outer.flags & NLM_F_ACK) != 0, "asking to be acknowledged");
	check(has_attr(&message, ETHTOOL_A_LINKMODES_AUTONEG, &attr) &&
	    ncfg_wire_attr_u8(&attr, &byte, NULL, 0) && byte == AUTONEG_DISABLE, "autoneg off");
	check(has_attr(&message, ETHTOOL_A_LINKMODES_SPEED, &attr) &&
	    ncfg_wire_attr_u32(&attr, &word, NULL, 0) && word == 100u, "speed 100");
	check(has_attr(&message, ETHTOOL_A_LINKMODES_DUPLEX, &attr) &&
	    ncfg_wire_attr_u8(&attr, &byte, NULL, 0) && byte == DUPLEX_FULL, "duplex full");
	ncfg_buf_free(&message);

	wanted.autoneg = 1;
	wanted.speed = 0;
	wanted.duplex = -1;
	ncfg_buf_init(&message, 0);
	check(ncfg_ethtool_link_modes_set_request(&message, &family, "eth0", &wanted, 9, NULL, 0),
	    "negotiating alone is built");
	check(has_attr(&message, ETHTOOL_A_LINKMODES_AUTONEG, &attr) &&
	    !has_attr(&message, ETHTOOL_A_LINKMODES_SPEED, &attr) &&
	    !has_attr(&message, ETHTOOL_A_LINKMODES_DUPLEX, &attr),
	    "and leaves speed and duplex out rather than sending zero, which is half duplex");
	ncfg_buf_free(&message);

	wanted.autoneg = -1;
	ncfg_buf_init(&message, 0);
	check(!ncfg_ethtool_link_modes_set_request(&message, &family, "eth0", &wanted, 9, NULL, 0),
	    "a set naming nothing is refused");
	ncfg_buf_free(&message);
	wanted.autoneg = 0;
	wanted.duplex = 7;
	ncfg_buf_init(&message, 0);
	check(!ncfg_ethtool_link_modes_set_request(&message, &family, "eth0", &wanted, 9, NULL, 0),
	    "and so is a duplex that does not exist");
	ncfg_buf_free(&message);
}

static void reply(ncfg_buf_t *out, int with_speed, uint8_t autoneg, uint32_t speed, uint8_t duplex)
{
	ncfg_genl_header_t header;

	header.cmd = ETHTOOL_MSG_LINKMODES_GET_REPLY;
	header.version = 1;
	ncfg_buf_init(out, 0);
	ncfg_genl_header_encode(&header, out);
	ncfg_wire_attr_put_u8(out, ETHTOOL_A_LINKMODES_AUTONEG, autoneg);
	if (with_speed) {
		ncfg_wire_attr_put_u32(out, ETHTOOL_A_LINKMODES_SPEED, speed);
	}
	ncfg_wire_attr_put_u8(out, ETHTOOL_A_LINKMODES_DUPLEX, duplex);
}

static void test_merge(void)
{
	ncfg_ethtool_link_modes_t modes;
	ncfg_buf_t                payload;
	ncfg_genl_header_t        header;

	memset(&modes, 0, sizeof(modes));
	reply(&payload, 1, AUTONEG_DISABLE, 1000, DUPLEX_FULL);
	check(ncfg_ethtool_link_modes_merge(&modes, payload.data, payload.length, NULL, 0) &&
	    modes.known && !modes.autoneg && modes.speed == 1000u && modes.duplex == DUPLEX_FULL,
	    "a reply is read: autoneg off, 1000, full");
	ncfg_buf_free(&payload);

	memset(&modes, 0, sizeof(modes));
	reply(&payload, 1, AUTONEG_ENABLE, (uint32_t)SPEED_UNKNOWN, DUPLEX_UNKNOWN);
	check(ncfg_ethtool_link_modes_merge(&modes, payload.data, payload.length, NULL, 0) &&
	    modes.known && modes.autoneg && modes.speed == 0u && modes.duplex == -1,
	    "a link with no carrier: the unknowns are absences");
	ncfg_buf_free(&payload);

	memset(&modes, 0, sizeof(modes));
	reply(&payload, 0, AUTONEG_ENABLE, 0, DUPLEX_FULL);
	check(!ncfg_ethtool_link_modes_merge(&modes, payload.data, payload.length, NULL, 0) &&
	    !modes.known, "a reply with autoneg and no speed is refused, not half read");
	ncfg_buf_free(&payload);

	memset(&modes, 0, sizeof(modes));
	header.cmd = ETHTOOL_MSG_LINKMODES_GET_REPLY;
	header.version = 1;
	ncfg_buf_init(&payload, 0);
	ncfg_genl_header_encode(&header, &payload);
	check(ncfg_ethtool_link_modes_merge(&modes, payload.data, payload.length, NULL, 0) &&
	    !modes.known, "a message without them adds nothing and is not a failure");
	ncfg_buf_free(&payload);
}

static const ncfg_observed_link_t *eth0(const ncfg_observed_t *observed)
{
	return ncfg_observed_link(observed, "eth0");
}

static void test_record(const char *run)
{
	char             path[512];
	char             dir[512];
	ncfg_observed_t *observed;

	(void)snprintf(dir, sizeof(dir), "%s/link_modes", run);
	testdir_mkdirp(dir);
	check(ncfg_observe_link_modes_record_path(run, "eth0", path, sizeof(path), NULL, 0),
	    "the record has a path");
	(void)testdir_write(path, "speed 100\nduplex full\n", 22);
	check(!ncfg_observe_link_modes_record_path(run, "../x", path, sizeof(path), NULL, 0),
	    "a name with a slash has none");

	observed = planfix_observed(
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"autoneg\":false") "]");
	check(observed && ncfg_observe_link_modes_recorded(observed, run, NULL, 0) &&
	    eth0(observed)->speed.has && eth0(observed)->speed.value == 100 &&
	    eth0(observed)->duplex && strcmp(eth0(observed)->duplex, "full") == 0,
	    "forced, with no carrier: the record says 100/full");
	ncfg_observed_free(observed);

	observed = planfix_observed(
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"autoneg\":false,\"speed\":1000,\"duplex\":\"full\"") "]");
	check(observed && ncfg_observe_link_modes_recorded(observed, run, NULL, 0) &&
	    eth0(observed)->speed.value == 1000, "a kernel answer wins over the record");
	ncfg_observed_free(observed);

	observed = planfix_observed(
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"autoneg\":true") "]");
	check(observed && ncfg_observe_link_modes_recorded(observed, run, NULL, 0) &&
	    !eth0(observed)->speed.has, "a negotiating link is not given the record's speed");
	ncfg_observed_free(observed);
}

#define DEVICE(body) \
	"{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"},\"link_settings\":{" body "}}"

static ncfg_plan_t *plan_for(const char *device, const char *link, ncfg_document_t **document,
    ncfg_observed_t **observed)
{
	char links[512];

	(void)snprintf(links, sizeof(links), "\"links\":[%s]", link);
	return planfix_plan(device, "", "", "", links, document, observed);
}

static void test_plan(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan;
	const ncfg_action_t *action;

	plan = plan_for(DEVICE("\"autoneg\":\"off\",\"speed\":100,\"duplex\":\"full\""),
	    PLANFIX_LINK("eth0", ",\"autoneg\":true,\"speed\":1000,\"duplex\":\"full\""),
	    &document, &observed);
	action = plan ? planfix_action(plan, "link.set_link_modes") : NULL;
	check(action && action->op.u.set_link_modes.autoneg == 0 &&
	    action->op.u.set_link_modes.speed == 100u && action->op.u.set_link_modes.duplex == 1,
	    "a negotiating link is forced to 100/full");
	check(action && action->has_inverse && action->inverse.u.set_link_modes.autoneg == 1 &&
	    action->inverse.u.set_link_modes.speed == 0u,
	    "and the inverse asks it to negotiate again");
	planfix_release(plan, document, observed);

	plan = plan_for(DEVICE("\"autoneg\":\"off\",\"speed\":100,\"duplex\":\"full\""),
	    PLANFIX_LINK("eth0", ",\"autoneg\":false,\"speed\":100,\"duplex\":\"full\""),
	    &document, &observed);
	check(plan && !planfix_action(plan, "link.set_link_modes"), "a link already forced so is left");
	planfix_release(plan, document, observed);

	plan = plan_for(DEVICE("\"autoneg\":\"off\",\"speed\":100,\"duplex\":\"full\""),
	    PLANFIX_LINK("eth0", ",\"autoneg\":false,\"speed\":1000,\"duplex\":\"full\""),
	    &document, &observed);
	action = plan ? planfix_action(plan, "link.set_link_modes") : NULL;
	check(action && action->inverse.u.set_link_modes.autoneg == 0 &&
	    action->inverse.u.set_link_modes.speed == 1000u,
	    "forced at another speed: set, with the old speed as the inverse");
	planfix_release(plan, document, observed);

	plan = plan_for(DEVICE("\"autoneg\":\"on\",\"speed\":1000,\"duplex\":\"full\""),
	    PLANFIX_LINK("eth0", ",\"autoneg\":true,\"speed\":100,\"duplex\":\"half\""),
	    &document, &observed);
	check(plan && !planfix_action(plan, "link.set_link_modes"),
	    "negotiating, at whatever it agreed: nothing, since that speed is not a setting");
	planfix_release(plan, document, observed);

	plan = plan_for(DEVICE("\"autoneg\":\"off\",\"speed\":100"),
	    PLANFIX_LINK("eth0", ""), &document, &observed);
	check(plan && !planfix_action(plan, "link.set_link_modes") &&
	    planfix_warned(plan, "does not report autonegotiation"),
	    "a link with no link modes is warned about, not planned for");
	planfix_release(plan, document, observed);

	plan = plan_for(DEVICE("\"autoneg\":\"off\",\"speed\":100"),
	    PLANFIX_LINK("eth0", ",\"autoneg\":false,\"speed\":100,\"duplex\":\"full\""),
	    &document, &observed);
	check(plan && !planfix_warned(plan, "recognised and applied by nothing"),
	    "and the old warning that nothing applies them is gone");
	planfix_release(plan, document, observed);
}

static void test_rings(void)
{
	ncfg_genl_family_t   family;
	ncfg_buf_t           message, payload;
	ncfg_wire_attr_t     attr;
	ncfg_genl_header_t   header;
	ncfg_ethtool_rings_t rings;
	uint32_t             word = 0;
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan;
	const ncfg_action_t *action;

	resolved_family(&family);
	ncfg_buf_init(&message, 0);
	check(ncfg_ethtool_rings_set_request(&message, &family, "eth0", 1024, 0, 4, NULL, 0),
	    "a ring set for the receive ring alone is built");
	check(has_attr(&message, ETHTOOL_A_RINGS_RX, &attr) &&
	    ncfg_wire_attr_u32(&attr, &word, NULL, 0) && word == 1024u &&
	    !has_attr(&message, ETHTOOL_A_RINGS_TX, &attr),
	    "carrying rx 1024 and leaving tx out rather than sending zero");
	ncfg_buf_free(&message);
	ncfg_buf_init(&message, 0);
	check(!ncfg_ethtool_rings_set_request(&message, &family, "eth0", 0, 0, 4, NULL, 0),
	    "a ring set naming no ring is refused");
	ncfg_buf_free(&message);

	header.cmd = ETHTOOL_MSG_RINGS_GET_REPLY;
	header.version = 1;
	ncfg_buf_init(&payload, 0);
	ncfg_genl_header_encode(&header, &payload);
	ncfg_wire_attr_put_u32(&payload, ETHTOOL_A_RINGS_RX_MAX, 4096);
	ncfg_wire_attr_put_u32(&payload, ETHTOOL_A_RINGS_TX_MAX, 4096);
	ncfg_wire_attr_put_u32(&payload, ETHTOOL_A_RINGS_RX, 256);
	ncfg_wire_attr_put_u32(&payload, ETHTOOL_A_RINGS_TX, 256);
	memset(&rings, 0, sizeof(rings));
	check(ncfg_ethtool_rings_merge(&rings, payload.data, payload.length, NULL, 0) && rings.known &&
	    rings.rx == 256u && rings.tx == 256u && rings.rx_max == 4096u,
	    "a reply is read: 256 each, at most 4096");
	ncfg_buf_free(&payload);

	plan = planfix_plan(DEVICE("\"rx_ring\":1024,\"tx_ring\":256"), "", "", "",
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"rx_ring\":256,\"tx_ring\":256,\"rx_ring_max\":4096,"
	    "\"tx_ring_max\":4096") "]", &document, &observed);
	action = plan ? planfix_action(plan, "link.set_rings") : NULL;
	check(action && action->op.u.set_rings.rx == 1024u && action->op.u.set_rings.tx == 0u,
	    "the receive ring is grown and the transmit ring, already right, left out");
	check(action && action->has_inverse && action->inverse.u.set_rings.rx == 256u,
	    "and the inverse puts back what it was");
	planfix_release(plan, document, observed);

	plan = planfix_plan(DEVICE("\"rx_ring\":8192"), "", "", "",
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"rx_ring\":256,\"tx_ring\":256,\"rx_ring_max\":4096,"
	    "\"tx_ring_max\":4096") "]", &document, &observed);
	check(plan && !planfix_action(plan, "link.set_rings") && planfix_warned(plan, "at most 4096"),
	    "past the maximum is warned about, not asked for on every pass");
	planfix_release(plan, document, observed);

	plan = planfix_plan(DEVICE("\"rx_ring\":256"), "", "", "",
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"rx_ring\":256,\"tx_ring\":512") "]", &document,
	    &observed);
	check(plan && !planfix_action(plan, "link.set_rings"), "a ring already that size is left");
	planfix_release(plan, document, observed);

	plan = planfix_plan(DEVICE("\"rx_ring\":256"), "", "", "",
	    "\"links\":[" PLANFIX_LINK("eth0", "") "]", &document, &observed);
	check(plan && !planfix_action(plan, "link.set_rings") &&
	    planfix_warned(plan, "does not report its ring sizes"),
	    "a link with no rings is warned about, not planned for");
	planfix_release(plan, document, observed);
}

int main(void)
{
	const char *run = testdir_make("link-modes");

	if (!run) {
		return 1;
	}
	test_messages();
	test_merge();
	test_record(run);
	test_plan();
	test_rings();
	testdir_remove(run);
	printf("%s\n", failures ? "link_modes_test: FAILED" : "link_modes_test: all passed");
	return failures ? 1 : 0;
}
