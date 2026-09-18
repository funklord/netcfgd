/*
 * ethtool_test.c -- the features messages, against bytes rather than against a
 * network card.
 *
 * WHY THIS EXISTS
 *   Nothing here opens a socket, resolves a family or touches a device. What is
 *   checked is the half that can be silently wrong, and for this family that
 *   half is entirely about which bitset is which:
 *
 *     * a set request must **not** carry `NOMASK`, or it means "this is the
 *       complete set of enabled features" and turns off every offload the
 *       document does not mention;
 *     * a get reply must be read as a list, because `ACTIVE` is a no-mask
 *       bitset -- reading it as a mask one and looking for `BIT_VALUE` finds
 *       nothing and reports every feature disabled;
 *     * `BIT_VALUE` is a flag, so "off" is its absence and a zero written there
 *       would read as on.
 *
 *   None of the three fails loudly on a real card. All three are bytes.
 *
 * WHAT IS ASSERTED, AND HOW
 *   The bytes are walked back with the wire layer rather than compared against
 *   a hand-written blob, which is wg_test.c's reasoning: a blob pins the
 *   encoder to whatever it did on the day it was written and says nothing about
 *   what the kernel would make of it. The one exception is `NLA_F_NESTED`,
 *   which the ordinary reader masks off, so `raw_find` below walks the same
 *   bytes with the type bits intact.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/ethtool.h"
#include "ncfg/genl.h"
#include "ncfg/wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-58s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static uint8_t *exact_copy(const void *bytes, size_t length)
{
	uint8_t *copy;

	if (!bytes || length == 0) {
		return NULL;
	}
	copy = malloc(length);
	if (!copy) {
		return NULL;
	}
	memcpy(copy, bytes, length);
	return copy;
}

/* A family as the controller would have answered, without asking it. */
static void resolved_family(ncfg_genl_family_t *family)
{
	memset(family, 0, sizeof(*family));
	(void)snprintf(family->name, sizeof(family->name), "%s", NCFG_ETHTOOL_FAMILY);
	family->id = 27;
}

/* The attribute area of a built request: past the netlink header and past the
 * generic netlink one. */
static int request_attrs(const ncfg_buf_t *message, ncfg_wire_attrs_t *out)
{
	if (message->length <= NCFG_WIRE_NLMSG_HDR_LEN + NCFG_GENL_HDR_LEN) {
		return 0;
	}
	return ncfg_genl_payload_attrs(message->data + NCFG_WIRE_NLMSG_HDR_LEN,
	    message->length - NCFG_WIRE_NLMSG_HDR_LEN, out, NULL, 0);
}

/*
 * Find an attribute keeping the type bits, which the ordinary reader masks off.
 *
 * `NLA_F_NESTED` is the one thing this file has to assert that the masked
 * reader cannot see: the ethtool family's parsers require it, and the error for
 * its absence is a bare `EINVAL` that says nothing about nesting.
 */
static int raw_find(const void *bytes, size_t length, uint16_t kind, uint16_t *flags_out)
{
	const uint8_t *at = (const uint8_t *)bytes;
	size_t         rest = length;

	while (rest >= NCFG_WIRE_RTATTR_HDR_LEN) {
		uint16_t claimed;
		uint16_t raw;
		size_t   step;

		memcpy(&claimed, at, sizeof(claimed));
		memcpy(&raw, at + 2, sizeof(raw));
		if (claimed < NCFG_WIRE_RTATTR_HDR_LEN || (size_t)claimed > rest) {
			return 0;
		}
		if ((raw & (uint16_t)~(uint16_t)NLA_F_NESTED) == kind) {
			*flags_out = raw;
			return 1;
		}
		step = ncfg_wire_align4(claimed);
		if (step == 0 || step > rest) {
			return 0;
		}
		at += step;
		rest -= step;
	}
	return 0;
}

/* The one attribute of this type in an area, or zero. */
static int find_in(const ncfg_wire_attrs_t *area, uint16_t kind, ncfg_wire_attr_t *out)
{
	return ncfg_wire_attrs_find(area, kind, out, NULL, 0) == NCFG_WIRE_OK;
}

/* A `FEATURES_GET` reply as the kernel would send one: a no-mask bitset listing
 * the features that are on. `nomask` says whether to mark it as one. */
static void active_reply(ncfg_buf_t *out, const char *const *names, size_t count, int nomask)
{
	ncfg_genl_header_t header;
	ncfg_buf_t         bits;
	ncfg_buf_t         bitset;
	size_t             at;

	header.cmd = ETHTOOL_MSG_FEATURES_GET;
	header.version = 1;
	ncfg_genl_header_encode(&header, out);

	ncfg_buf_init(&bits, 0);
	for (at = 0; at < count; at++) {
		ncfg_buf_t bit;

		ncfg_buf_init(&bit, 0);
		ncfg_wire_attr_put_str(&bit, ETHTOOL_A_BITSET_BIT_NAME, names[at]);
		ncfg_wire_attr_put_nested(&bits, ETHTOOL_A_BITSET_BITS_BIT, &bit);
		ncfg_buf_free(&bit);
	}
	ncfg_buf_init(&bitset, 0);
	if (nomask) {
		/* A flag, exactly as the kernel sends it. */
		ncfg_wire_attr_put(&bitset, ETHTOOL_A_BITSET_NOMASK, NULL, 0);
	}
	ncfg_wire_attr_put_nested(&bitset, ETHTOOL_A_BITSET_BITS, &bits);
	ncfg_wire_attr_put_nested(out, ETHTOOL_A_FEATURES_ACTIVE, &bitset);
	ncfg_buf_free(&bits);
	ncfg_buf_free(&bitset);
}

int main(void)
{
	ncfg_genl_family_t family;

	resolved_family(&family);

	/*
	 * The two commands, against the numbers the Rust's comment was bought
	 * with: twelve, not ten. Ten is `ETHTOOL_MSG_WOL_SET`, and a features
	 * payload sent there is a bare `EINVAL` that reads exactly like a
	 * malformed bitset.
	 */
	{
		check(ETHTOOL_MSG_FEATURES_GET == 11, "FEATURES_GET is command eleven");
		check(ETHTOOL_MSG_FEATURES_SET == 12, "and FEATURES_SET is twelve, not ten");
	}

	/* The get request. */
	{
		ncfg_buf_t        message;
		ncfg_wire_attrs_t attrs;
		ncfg_wire_attrs_t inside;
		ncfg_wire_attr_t  attr;
		ncfg_genl_header_t header;
		ncfg_wire_header_t outer;
		char              name[NCFG_ETHTOOL_DEVICE_MAX];
		uint16_t          flags = 0;

		ncfg_buf_init(&message, 0);
		check(ncfg_ethtool_features_get_request(&message, &family, "eth0", 7, NULL, 0),
		    "a features get request is built");
		check(ncfg_wire_header_decode(message.data, message.length, &outer, NULL, 0) &&
		    outer.kind == family.id,
		    "addressed to the family id the controller answered with");
		check((outer.flags & NLM_F_REQUEST) != 0,
		    "and marked as a request, without which the kernel never answers");
		check(outer.seq == 7u, "carrying the sequence number it was given");
		check(ncfg_genl_header_decode(message.data + NCFG_WIRE_NLMSG_HDR_LEN,
		    message.length - NCFG_WIRE_NLMSG_HDR_LEN, &header, NULL, 0) &&
		    header.cmd == ETHTOOL_MSG_FEATURES_GET && header.version == 1,
		    "and the features get command at version one");

		check(request_attrs(&message, &attrs), "its attributes read back");
		check(find_in(&attrs, ETHTOOL_A_FEATURES_HEADER, &attr),
		    "it carries the header nest every ethtool message begins with");
		check(raw_find(message.data + NCFG_WIRE_NLMSG_HDR_LEN + NCFG_GENL_HDR_LEN,
		    message.length - NCFG_WIRE_NLMSG_HDR_LEN - NCFG_GENL_HDR_LEN,
		    ETHTOOL_A_FEATURES_HEADER, &flags) && (flags & NLA_F_NESTED) != 0,
		    "flagged as a nest, which this family's parsers require");
		ncfg_wire_attrs_start(&inside, attr.value, attr.length);
		check(find_in(&inside, ETHTOOL_A_HEADER_DEV_NAME, &attr) &&
		    ncfg_wire_attr_string(&attr, name, sizeof(name), NULL, 0) &&
		    strcmp(name, "eth0") == 0, "and names the device inside it");
		ncfg_buf_free(&message);
	}

	/*
	 * The set request, which is where the two bitsets have to be told apart.
	 */
	{
		ncfg_buf_t        message;
		ncfg_wire_attrs_t attrs;
		ncfg_wire_attrs_t bitset;
		ncfg_wire_attrs_t bits;
		ncfg_wire_attr_t  attr;
		ncfg_wire_attr_t  bit;
		char              name[NCFG_ETHTOOL_NAME_MAX];
		uint16_t          flags = 0;
		int               seen_on = 0;
		int               seen_off = 0;
		int               on_has_value = 0;
		int               off_has_value = 1;
		const ncfg_ethtool_feature_t wanted[] = {
			{ "rx-checksum", 1 },
			{ "tx-tcp-segmentation", 0 }
		};

		ncfg_buf_init(&message, 0);
		check(ncfg_ethtool_features_set_request(&message, &family, "eth0", wanted, 2u,
		    9, NULL, 0), "a features set request is built");
		check(request_attrs(&message, &attrs), "its attributes read back");
		check(find_in(&attrs, ETHTOOL_A_FEATURES_WANTED, &attr),
		    "it carries the wanted bitset");
		check(raw_find(message.data + NCFG_WIRE_NLMSG_HDR_LEN + NCFG_GENL_HDR_LEN,
		    message.length - NCFG_WIRE_NLMSG_HDR_LEN - NCFG_GENL_HDR_LEN,
		    ETHTOOL_A_FEATURES_WANTED, &flags) && (flags & NLA_F_NESTED) != 0,
		    "flagged as a nest");

		ncfg_wire_attrs_start(&bitset, attr.value, attr.length);
		check(!find_in(&bitset, ETHTOOL_A_BITSET_NOMASK, &bit),
		    "and it is a mask bitset: no NOMASK, or it would mean 'and nothing else'");
		check(find_in(&bitset, ETHTOOL_A_BITSET_BITS, &attr), "it carries the bits");

		ncfg_wire_attrs_start(&bits, attr.value, attr.length);
		for (;;) {
			ncfg_wire_attrs_t inside;
			ncfg_wire_attr_t  named;

			if (ncfg_wire_attrs_next(&bits, &bit, NULL, 0) != NCFG_WIRE_OK) {
				break;
			}
			if (bit.kind != ETHTOOL_A_BITSET_BITS_BIT) {
				continue;
			}
			ncfg_wire_attrs_start(&inside, bit.value, bit.length);
			if (!find_in(&inside, ETHTOOL_A_BITSET_BIT_NAME, &named) ||
			    !ncfg_wire_attr_string(&named, name, sizeof(name), NULL, 0)) {
				continue;
			}
			if (strcmp(name, "rx-checksum") == 0) {
				seen_on = 1;
				on_has_value = find_in(&inside, ETHTOOL_A_BITSET_BIT_VALUE,
				    &named);
			}
			if (strcmp(name, "tx-tcp-segmentation") == 0) {
				seen_off = 1;
				off_has_value = find_in(&inside, ETHTOOL_A_BITSET_BIT_VALUE,
				    &named);
			}
		}
		check(seen_on && seen_off, "both features are named rather than numbered");
		check(on_has_value, "the one turned on carries the value flag");
		check(!off_has_value,
		    "and the one turned off carries nothing, since a zero would read as on");
		ncfg_buf_free(&message);
	}

	/* What a request refuses before it is sent. */
	{
		ncfg_buf_t message;
		char       err[NCFG_ERROR_MAX];
		char       long_name[NCFG_ETHTOOL_NAME_MAX + 4u];
		ncfg_ethtool_feature_t too_long;

		ncfg_buf_init(&message, 0);
		err[0] = '\0';
		check(!ncfg_ethtool_features_get_request(&message, &family, "", 1, err,
		    sizeof(err)), "an empty device name is refused");
		check(err[0] != '\0', "and says so");
		ncfg_buf_free(&message);

		ncfg_buf_init(&message, 0);
		err[0] = '\0';
		check(!ncfg_ethtool_features_get_request(&message, &family,
		    "a-device-name-far-too-long", 1, err, sizeof(err)),
		    "as is one longer than an interface name");
		check(strstr(err, "not a name") != NULL, "and the refusal says why");
		ncfg_buf_free(&message);

		ncfg_buf_init(&message, 0);
		check(!ncfg_ethtool_features_get_request(&message, NULL, "eth0", 1, NULL, 0),
		    "a request with no resolved family is refused");
		ncfg_buf_free(&message);

		memset(long_name, 'x', sizeof(long_name) - 1u);
		long_name[sizeof(long_name) - 1u] = '\0';
		too_long.name = long_name;
		too_long.on = 1;
		ncfg_buf_init(&message, 0);
		err[0] = '\0';
		check(!ncfg_ethtool_features_set_request(&message, &family, "eth0", &too_long,
		    1u, 1, err, sizeof(err)),
		    "a feature name longer than the kernel's is refused rather than sent");
		check(strstr(err, "too long") != NULL,
		    "with a sentence, rather than the EINVAL a malformed bitset gives");
		ncfg_buf_free(&message);
	}

	/* Reading the reply: a no-mask bitset is a list of what is on. */
	{
		ncfg_buf_t           reply;
		ncfg_ethtool_names_t names;
		const char *const    on[] = { "tx-tcp-segmentation", "rx-checksum" };

		memset(&names, 0, sizeof(names));
		ncfg_buf_init(&reply, 0);
		active_reply(&reply, on, 2u, 1);
		check(ncfg_ethtool_active_merge(&names, reply.data, reply.length, NULL, 0),
		    "an active features reply folds in");
		check(names.count == 2u, "with both features in it");
		check(ncfg_ethtool_names_has(&names, "rx-checksum") &&
		    ncfg_ethtool_names_has(&names, "tx-tcp-segmentation"),
		    "and each one is found by name");
		check(names.count == 2u && strcmp(names.items[0], "rx-checksum") == 0,
		    "sorted, so a message listing them reads the same twice running");

		/* The kernel describes one device in more than one message, and
		 * a feature named twice is one feature. */
		check(ncfg_ethtool_active_merge(&names, reply.data, reply.length, NULL, 0) &&
		    names.count == 2u, "the same reply folded in twice adds nothing");
		ncfg_ethtool_names_free(&names);
		check(names.count == 0u && names.items == NULL,
		    "freeing the set leaves it usable and empty");
		ncfg_ethtool_names_free(&names);
		ncfg_buf_free(&reply);
	}

	/*
	 * A bitset that is not a no-mask one lists nothing.
	 *
	 * In a mask bitset a listed bit means "this bit is being talked about",
	 * not "this bit is on". Nothing netcfgd sends is one, so reading it as a
	 * list would be wrong rather than merely useless.
	 */
	{
		ncfg_buf_t           reply;
		ncfg_ethtool_names_t names;
		const char *const    on[] = { "rx-checksum" };

		memset(&names, 0, sizeof(names));
		ncfg_buf_init(&reply, 0);
		active_reply(&reply, on, 1u, 0);
		check(ncfg_ethtool_active_merge(&names, reply.data, reply.length, NULL, 0),
		    "a mask bitset is not a failure");
		check(names.count == 0u, "but nothing in it counts as a feature that is on");
		ncfg_ethtool_names_free(&names);
		ncfg_buf_free(&reply);
	}

	/* A message about the device that carries no active set adds nothing and
	 * is not a refusal. */
	{
		ncfg_buf_t           reply;
		ncfg_genl_header_t   header;
		ncfg_ethtool_names_t names;

		memset(&names, 0, sizeof(names));
		ncfg_buf_init(&reply, 0);
		header.cmd = ETHTOOL_MSG_FEATURES_GET;
		header.version = 1;
		ncfg_genl_header_encode(&header, &reply);
		check(ncfg_ethtool_active_merge(&names, reply.data, reply.length, NULL, 0),
		    "a reply with no active set is not a failure");
		check(names.count == 0u, "and adds nothing");
		ncfg_ethtool_names_free(&names);
		ncfg_buf_free(&reply);
	}

	/* Truncation is a refusal rather than an empty answer, which is the
	 * divergence genl.h records: an empty iterator reads downstream as "the
	 * kernel answered without the thing we asked for". */
	{
		ncfg_buf_t           reply;
		ncfg_ethtool_names_t names;
		uint8_t             *exact;
		const char *const    on[] = { "rx-checksum" };

		memset(&names, 0, sizeof(names));
		ncfg_buf_init(&reply, 0);
		active_reply(&reply, on, 1u, 1);

		exact = exact_copy(reply.data, 2u);
		if (exact) {
			check(!ncfg_ethtool_active_merge(&names, exact, 2u, NULL, 0),
			    "a payload too short for a generic netlink header is refused");
			free(exact);
		}
		/* And a message whose attribute area is cut mid-attribute. */
		exact = exact_copy(reply.data, reply.length - 3u);
		if (exact) {
			check(!ncfg_ethtool_active_merge(&names, exact, reply.length - 3u,
			    NULL, 0), "as is one cut in the middle of an attribute");
			free(exact);
		}
		check(names.count == 0u, "and neither leaves half a feature set behind");
		check(!ncfg_ethtool_active_merge(NULL, reply.data, reply.length, NULL, 0),
		    "a fold with nowhere to go is refused");
		ncfg_ethtool_names_free(&names);
		ncfg_buf_free(&reply);
	}

	if (failures == 0) {
		printf("ethtool_test: all checks passed\n");
	} else {
		printf("ethtool_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
