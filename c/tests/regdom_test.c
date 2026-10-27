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
	if (ncfg_regdom_read(code, sizeof(code), err, sizeof(err))) {
		check(strlen(code) == 2u, "the kernel names a two-character domain");
		detail("domain", code);
	} else {
		/* No nl80211 is a machine with no wireless; the check is that the
		 * answer is a sentence, not that there is a radio. */
		check(err[0] != '\0', "a machine that cannot answer says why");
		detail("said", err);
	}
	check(!ncfg_genl_family_open("ncfg-nofamily", &socket, &family, err, sizeof(err)),
	    "a family the kernel does not have is refused, and nothing is left open");
	detail("said", err);
}

int main(void)
{
	the_request_asks_for_the_global_domain();
	a_reply_is_a_country_only_when_it_names_one();
	the_live_check();

	if (failures) {
		printf("%d check(s) failed\n", failures);
		return 1;
	}
	printf("regdom_test: all checks passed\n");
	return 0;
}
