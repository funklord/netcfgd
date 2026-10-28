/*
 * regdom_test.c -- the regulatory domain request and reply, against bytes
 * rather than against a radio.
 *
 * WHAT IS CHECKED
 *   The half that can be silently wrong: that the request asks nl80211 for the
 *   global domain and nothing else, and that a reply is read as a country only
 *   when it names one. A reply with no country, a code that is not two letters
 *   or digits, and a payload too short for its own header are each refused --
 *   because `ncfg status` prints the answer as a sentence about where the
 *   machine is, and an empty or truncated code printed there is a country
 *   nobody is in.
 *
 * THE ONE CHECK THAT OPENS A SOCKET
 *   Behind `NCFG_OBSERVE_LIVE=1`, as `current_test.c` does it, and for its
 *   reason: this suite runs on the machine netcfgd configures. It sends two
 *   `GET`s -- a family lookup and `GET_REG` -- and changes nothing. A family
 *   that does not exist is asked for too, through `genl_socket.h`, because
 *   "no such family" is the answer on a machine with no wireless at all and
 *   the sentence it comes back as is the one an operator reads.
 */
#include "ncfg/regdom.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/genl.h"
#include "ncfg/genl_socket.h"
#include "ncfg/netlink.h"
#include "ncfg/wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static void detail(const char *what, const char *value)
{
	printf("  %s: %s\n", what, value ? value : "(none)");
}

/* A `GET_REG` reply payload: the generic netlink header, then whatever
 * attribute `code` makes -- none at all where it is NULL. */
static void reply(ncfg_buf_t *out, const char *code)
{
	ncfg_genl_header_t header = { NL80211_CMD_GET_REG, 1 };

	ncfg_buf_init(out, 0);
	ncfg_genl_header_encode(&header, out);
	/* The other attributes a real reply carries, before the country, so the
	 * parse is a search and not a read of the first attribute. */
	ncfg_wire_attr_put_u8(out, NL80211_ATTR_DFS_REGION, 1);
	if (code) {
		ncfg_wire_attr_put_str(out, NL80211_ATTR_REG_ALPHA2, code);
	}
}

static void the_request_asks_for_the_global_domain(void)
{
	ncfg_genl_family_t family;
	ncfg_buf_t         message;
	ncfg_buf_t         body;
	uint16_t           kind = 0;
	uint16_t           flags = 0;
	char               err[NCFG_ERROR_MAX];
	int                built;

	memset(&family, 0, sizeof(family));
	family.id = 35;
	ncfg_buf_init(&message, 0);
	ncfg_buf_init(&body, 0);
	built = ncfg_regdom_request(&message, &family, 7, err, sizeof(err)) &&
	    ncfg_wire_request_parts(&message, "nl80211", &kind, &flags, &body, err, sizeof(err));
	check(built, "a GET_REG request builds and decodes");
	check(kind == 35, "addressed to the family id it was given");
	check(body.length == NCFG_GENL_HDR_LEN,
	    "and carries the header alone: no wiphy, so the global domain");
	check(body.length >= 1 && (unsigned char)body.data[0] == NL80211_CMD_GET_REG,
	    "asking GET_REG");
	ncfg_buf_free(&message);
	ncfg_buf_free(&body);

	ncfg_buf_init(&message, 0);
	check(!ncfg_regdom_request(&message, NULL, 1, err, sizeof(err)),
	    "a request with no family resolved is refused");
	ncfg_buf_free(&message);
}

static void a_reply_is_a_country_only_when_it_names_one(void)
{
	ncfg_buf_t payload;
	char       code[NCFG_REGDOM_TEXT_MAX];
	char       err[NCFG_ERROR_MAX];

	reply(&payload, "DE");
	check(ncfg_regdom_parse(payload.data, payload.length, code,
	          sizeof(code), err, sizeof(err)) &&
	        strcmp(code, "DE") == 0,
	    "a reply naming DE reads as DE");
	ncfg_buf_free(&payload);

	reply(&payload, "00");
	check(ncfg_regdom_parse(payload.data, payload.length, code,
	          sizeof(code), err, sizeof(err)) &&
	        strcmp(code, "00") == 0,
	    "the world domain reads as 00");
	ncfg_buf_free(&payload);

	reply(&payload, NULL);
	check(!ncfg_regdom_parse(payload.data, payload.length, code,
	          sizeof(code), err, sizeof(err)),
	    "a reply naming no country is refused");
	detail("said", err);
	check(code[0] == '\0', "and leaves no code behind to be printed");
	ncfg_buf_free(&payload);

	reply(&payload, "D");
	check(!ncfg_regdom_parse(payload.data, payload.length, code,
	          sizeof(code), err, sizeof(err)),
	    "a one-character code is refused");
	ncfg_buf_free(&payload);

	reply(&payload, "DEU");
	check(!ncfg_regdom_parse(payload.data, payload.length, code,
	          sizeof(code), err, sizeof(err)),
	    "a three-character code is refused, not cut to two");
	ncfg_buf_free(&payload);

	reply(&payload, "D!");
	check(!ncfg_regdom_parse(payload.data, payload.length, code,
	          sizeof(code), err, sizeof(err)),
	    "a code that is not letters or digits is refused");
	ncfg_buf_free(&payload);

	reply(&payload, "DE");
	check(!ncfg_regdom_parse(payload.data, 2, code, sizeof(code), err,
	          sizeof(err)),
	    "a payload too short for its own header is refused");
	check(!ncfg_regdom_parse(payload.data, payload.length, code, 2, err,
	          sizeof(err)),
	    "and so is a buffer with no room for the code and its NUL");
	ncfg_buf_free(&payload);
}

/* The id the notifications below come from. Any number serves; one that is not
 * nl80211's is the case `a_foreign_family_is_passed_over` needs. */
#define NL80211_ID 35

/*
 * One whole netlink message of a family, as the `regulatory` group delivers
 * it: the netlink header, the generic netlink one, then the attributes --
 * `initiator` and `type` left out where negative, the country where NULL.
 */
static void notification(ncfg_buf_t *out, uint16_t family, uint8_t cmd, int initiator,
    int type, const char *code)
{
	ncfg_genl_header_t header = { 0, 1 };
	ncfg_wire_header_t outer;
	ncfg_buf_t         payload;

	header.cmd = cmd;
	ncfg_buf_init(&payload, 0);
	ncfg_genl_header_encode(&header, &payload);
	if (initiator >= 0) {
		ncfg_wire_attr_put_u8(&payload, NL80211_ATTR_REG_INITIATOR, (uint8_t)initiator);
	}
	if (type >= 0) {
		ncfg_wire_attr_put_u8(&payload, NL80211_ATTR_REG_TYPE, (uint8_t)type);
	}
	if (code) {
		ncfg_wire_attr_put_str(&payload, NL80211_ATTR_REG_ALPHA2, code);
	}
	/* A wiphy, as a driver's or a beacon's hint carries one: the change is
	 * still the global domain's, and this must not be read as a radio's. */
	ncfg_wire_attr_put_u32(&payload, NL80211_ATTR_WIPHY, 0);
	memset(&outer, 0, sizeof(outer));
	outer.len = (uint32_t)(NCFG_WIRE_NLMSG_HDR_LEN + payload.length);
	outer.kind = family;
	ncfg_wire_header_encode(&outer, out);
	ncfg_buf_add(out, payload.data, payload.length);
	ncfg_buf_free(&payload);
}

static void a_change_says_who_set_the_domain(void)
{
	ncfg_buf_t           bytes;
	ncfg_regdom_change_t change;
	char                 err[NCFG_ERROR_MAX];
	int                  found = 0;
	int                  read;

	ncfg_buf_init(&bytes, 0);
	notification(&bytes, NL80211_ID, NL80211_CMD_REG_CHANGE, NL80211_REGDOM_SET_BY_COUNTRY_IE,
	    NL80211_REGDOM_TYPE_COUNTRY, "DE");
	memset(&change, 0, sizeof(change));
	read = ncfg_regdom_change_parse(bytes.data, bytes.length, NL80211_ID, &found, &change, err,
	    sizeof(err));
	check(read && found && strcmp(change.code, "DE") == 0 &&
	        change.set_by == NCFG_REGDOM_SET_BY_ACCESS_POINT,
	    "a beacon's country is DE, set by the access point");
	check(strcmp(ncfg_regdom_setter_name(change.set_by), "access_point") == 0,
	    "and the setter is written `access_point`");
	ncfg_buf_free(&bytes);

	/* The revert when the station leaves: the kernel, and no country in the
	 * message at all -- the code comes from the type. */
	ncfg_buf_init(&bytes, 0);
	notification(&bytes, NL80211_ID, NL80211_CMD_REG_CHANGE, NL80211_REGDOM_SET_BY_CORE,
	    NL80211_REGDOM_TYPE_WORLD, NULL);
	read = ncfg_regdom_change_parse(bytes.data, bytes.length, NL80211_ID, &found, &change, err,
	    sizeof(err));
	check(read && found && strcmp(change.code, "00") == 0 &&
	        change.set_by == NCFG_REGDOM_SET_BY_KERNEL,
	    "the world domain is 00, set by the kernel, from the type alone");
	ncfg_buf_free(&bytes);

	ncfg_buf_init(&bytes, 0);
	notification(&bytes, NL80211_ID, NL80211_CMD_REG_CHANGE, NL80211_REGDOM_SET_BY_USER,
	    NL80211_REGDOM_TYPE_INTERSECTION, NULL);
	read = ncfg_regdom_change_parse(bytes.data, bytes.length, NL80211_ID, &found, &change, err,
	    sizeof(err));
	check(read && found && strcmp(change.code, "98") == 0 &&
	        change.set_by == NCFG_REGDOM_SET_BY_USER,
	    "an intersection is 98, the name GET_REG gives it");
	ncfg_buf_free(&bytes);

	/* Two in one datagram: the later is the domain now. */
	ncfg_buf_init(&bytes, 0);
	notification(&bytes, NL80211_ID, NL80211_CMD_REG_CHANGE, NL80211_REGDOM_SET_BY_USER,
	    NL80211_REGDOM_TYPE_COUNTRY, "SE");
	notification(&bytes, NL80211_ID, NL80211_CMD_REG_CHANGE, NL80211_REGDOM_SET_BY_DRIVER,
	    NL80211_REGDOM_TYPE_COUNTRY, "JP");
	read = ncfg_regdom_change_parse(bytes.data, bytes.length, NL80211_ID, &found, &change, err,
	    sizeof(err));
	check(read && found && strcmp(change.code, "JP") == 0 &&
	        change.set_by == NCFG_REGDOM_SET_BY_DRIVER,
	    "of two changes in one datagram, the later is the one kept");
	ncfg_buf_free(&bytes);
}

static void what_is_not_a_global_change_is_passed_over(void)
{
	ncfg_buf_t           bytes;
	ncfg_regdom_change_t change;
	char                 err[NCFG_ERROR_MAX];
	int                  found = 1;

	ncfg_buf_init(&bytes, 0);
	notification(&bytes, NL80211_ID, NL80211_CMD_WIPHY_REG_CHANGE, NL80211_REGDOM_SET_BY_DRIVER,
	    NL80211_REGDOM_TYPE_COUNTRY, "US");
	memset(&change, 0, sizeof(change));
	check(ncfg_regdom_change_parse(bytes.data, bytes.length, NL80211_ID, &found, &change, err,
	          sizeof(err)) && !found,
	    "a radio's own domain changing is not the global domain changing");
	ncfg_buf_free(&bytes);

	ncfg_buf_init(&bytes, 0);
	notification(&bytes, NL80211_ID + 1, NL80211_CMD_REG_CHANGE, NL80211_REGDOM_SET_BY_USER,
	    NL80211_REGDOM_TYPE_COUNTRY, "US");
	found = 1;
	check(ncfg_regdom_change_parse(bytes.data, bytes.length, NL80211_ID, &found, &change, err,
	          sizeof(err)) && !found,
	    "nor is a message from another family with the same command number");
	ncfg_buf_free(&bytes);
}

static void a_change_that_does_not_read_is_refused(void)
{
	ncfg_buf_t           bytes;
	ncfg_regdom_change_t change;
	char                 err[NCFG_ERROR_MAX];
	int                  found = 0;

	ncfg_buf_init(&bytes, 0);
	notification(&bytes, NL80211_ID, NL80211_CMD_REG_CHANGE, 9, NL80211_REGDOM_TYPE_COUNTRY,
	    "DE");
	check(!ncfg_regdom_change_parse(bytes.data, bytes.length, NL80211_ID, &found, &change,
	          err, sizeof(err)) && !found,
	    "an initiator this build has no word for is refused, not guessed");
	detail("said", err);
	ncfg_buf_free(&bytes);

	ncfg_buf_init(&bytes, 0);
	notification(&bytes, NL80211_ID, NL80211_CMD_REG_CHANGE, -1, NL80211_REGDOM_TYPE_COUNTRY,
	    "DE");
	check(!ncfg_regdom_change_parse(bytes.data, bytes.length, NL80211_ID, &found, &change,
	          err, sizeof(err)),
	    "so is a change that does not say who made it");
	ncfg_buf_free(&bytes);

	ncfg_buf_init(&bytes, 0);
	notification(&bytes, NL80211_ID, NL80211_CMD_REG_CHANGE, NL80211_REGDOM_SET_BY_USER,
	    NL80211_REGDOM_TYPE_COUNTRY, NULL);
	check(!ncfg_regdom_change_parse(bytes.data, bytes.length, NL80211_ID, &found, &change,
	          err, sizeof(err)),
	    "and a country's change that names no country");
	ncfg_buf_free(&bytes);

	ncfg_buf_init(&bytes, 0);
	notification(&bytes, NL80211_ID, NL80211_CMD_REG_CHANGE, NL80211_REGDOM_SET_BY_USER,
	    NL80211_REGDOM_TYPE_COUNTRY, "DE");
	check(!ncfg_regdom_change_parse(bytes.data, bytes.length - 4u, NL80211_ID, &found,
	          &change, err, sizeof(err)),
	    "and a datagram cut short of its own length");
	ncfg_buf_free(&bytes);
}

static void the_live_check(void)
{
	const char        *live = getenv("NCFG_OBSERVE_LIVE");
	char               code[NCFG_REGDOM_TEXT_MAX];
	char               err[NCFG_ERROR_MAX];
	ncfg_netlink_t     socket;
	ncfg_genl_family_t family;

	if (!live || strcmp(live, "1") != 0) {
		printf("%-72s %s\n", "the kernel answers (NCFG_OBSERVE_LIVE=1 to ask it)",
		    "skipped");
		return;
	}
	/* The request and the parse against the real kernel, through the same
	 * socket helper the executor uses. No nl80211 is a machine with no
	 * wireless, and the check is then that the answer is a sentence. */
	if (ncfg_genl_family_open(NL80211_GENL_NAME, &socket, &family, err, sizeof(err))) {
		ncfg_buf_t           message;
		ncfg_buf_t           body;
		ncfg_netlink_reply_t answer;
		uint16_t             kind = 0;
		uint16_t             flags = 0;
		int                  read;

		memset(&answer, 0, sizeof(answer));
		ncfg_buf_init(&message, 0);
		ncfg_buf_init(&body, 0);
		read = ncfg_regdom_request(&message, &family, ncfg_netlink_take_seq(&socket), err,
		           sizeof(err)) &&
		    ncfg_wire_request_parts(&message, "nl80211", &kind, &flags, &body, err,
		        sizeof(err)) &&
		    ncfg_netlink_request(&socket, kind, flags, &body, NULL, &answer, err,
		        sizeof(err)) &&
		    answer.count > 0 &&
		    ncfg_regdom_parse(answer.items[0].bytes, answer.items[0].length, code,
		        sizeof(code), err, sizeof(err));
		check(read && strlen(code) == 2u, "the kernel names a two-character domain");
		detail("domain", read ? code : err);
		ncfg_netlink_reply_free(&answer);
		ncfg_buf_free(&message);
		ncfg_buf_free(&body);
		ncfg_genl_family_free(&family);
		ncfg_netlink_close(&socket);
	} else {
		check(err[0] != '\0', "a machine with no nl80211 says why");
		detail("said", err);
	}
	check(!ncfg_genl_family_open("ncfg-nofamily", &socket, &family, err, sizeof(err)),
	    "a family the kernel does not have is refused, and nothing is left open");
	detail("said", err);
	/* **As a lookup, naming the module.** It used to read "RTM_NEWLINK
	 * failed": the controller's message type is 16, which is that number in
	 * rtnetlink, and the request path named the failure by type. */
	check(strstr(err, "not loaded") != NULL && strstr(err, "RTM_") == NULL,
	    "and the sentence says the module is probably not loaded");

	/* **A request the family refuses, named without rtnetlink's words.** A
	 * `GET_REG` for a radio that does not exist is refused by nl80211; its
	 * message type is the family id, which the reply reader would otherwise
	 * name as whichever `RTM_` message shares the number -- 38 was
	 * `RTM_GETQDISC` on the machine this was written on. */
	if (ncfg_genl_family_open(NL80211_GENL_NAME, &socket, &family, err, sizeof(err))) {
		ncfg_genl_header_t   header = { NL80211_CMD_GET_REG, 0 };
		ncfg_buf_t           attrs;
		ncfg_buf_t           message;
		ncfg_buf_t           body;
		ncfg_netlink_reply_t answer;
		uint16_t             kind = 0;
		uint16_t             flags = 0;
		int                  refused;

		memset(&answer, 0, sizeof(answer));
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&message, 0);
		ncfg_buf_init(&body, 0);
		ncfg_wire_attr_put_u32(&attrs, NL80211_ATTR_WIPHY, 99999u);
		refused = ncfg_genl_build_request(&message, family.id, &header, 0,
		              ncfg_netlink_take_seq(&socket), &attrs, err, sizeof(err)) &&
		    ncfg_wire_request_parts(&message, "nl80211", &kind, &flags, &body, err,
		        sizeof(err)) &&
		    !ncfg_netlink_request(&socket, kind, flags, &body, NULL, &answer, err,
		        sizeof(err));
		check(refused, "a GET_REG for a radio that does not exist is refused");
		detail("said", err);
		check(strstr(err, "RTM_") == NULL && strstr(err, "generic netlink") != NULL,
		    "and the refusal is not named after an rtnetlink message");
		ncfg_netlink_reply_free(&answer);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&message);
		ncfg_buf_free(&body);
		ncfg_genl_family_free(&family);
		ncfg_netlink_close(&socket);
	}
}

int main(void)
{
	the_request_asks_for_the_global_domain();
	a_reply_is_a_country_only_when_it_names_one();
	a_change_says_who_set_the_domain();
	what_is_not_a_global_change_is_passed_over();
	a_change_that_does_not_read_is_refused();
	the_live_check();

	if (failures) {
		printf("%d check(s) failed\n", failures);
		return 1;
	}
	printf("regdom_test: all checks passed\n");
	return 0;
}
