/*
 * ethtool.c -- the two features messages, and the one bitset that is a list.
 *
 * Bytes in, structures out, and no socket anywhere: the requests are built into
 * a buffer the caller sends and the replies are folded in as payloads the
 * caller already has. That is genl.h's split and wg.c's, and it is what lets
 * every case here be checked on a machine whose only interface is a veth.
 */
#include "ncfg/ethtool.h"

#include <stdlib.h>
#include <string.h>

#include "ncfg/wire.h"

/* The header nest every ethtool message begins with: the device it is about. */
static int ethtool_header(ncfg_buf_t *out, const char *device, char *err, size_t err_size)
{
	ncfg_buf_t inner;

	if (!device || device[0] == '\0' || strlen(device) >= NCFG_ETHTOOL_DEVICE_MAX) {
		ncfg_error_set(err, err_size,
		    "`%s` is not a name the kernel would take for a link",
		    device ? device : "");
		return 0;
	}
	ncfg_buf_init(&inner, 0);
	ncfg_wire_attr_put_str(&inner, ETHTOOL_A_HEADER_DEV_NAME, device);
	ncfg_wire_attr_put_nested(out, ETHTOOL_A_FEATURES_HEADER, &inner);
	ncfg_buf_free(&inner);
	return 1;
}

int ncfg_ethtool_features_get_request(ncfg_buf_t *out, const ncfg_genl_family_t *family,
    const char *device, uint32_t seq, char *err, size_t err_size)
{
	ncfg_genl_header_t header;
	ncfg_buf_t         attrs;
	int                built;

	if (!out || !family) {
		ncfg_error_set(err, err_size, "an ethtool request needs the resolved family");
		return 0;
	}
	ncfg_buf_init(&attrs, 0);
	if (!ethtool_header(&attrs, device, err, err_size)) {
		ncfg_buf_free(&attrs);
		return 0;
	}
	header.cmd = ETHTOOL_MSG_FEATURES_GET;
	header.version = 1;
	/* No `NLM_F_DUMP`: this asks about one device and the kernel answers
	 * with that device's messages. */
	built = ncfg_genl_build_request(out, family->id, &header, 0, seq, &attrs, err, err_size);
	ncfg_buf_free(&attrs);
	return built;
}

int ncfg_ethtool_features_set_request(ncfg_buf_t *out, const ncfg_genl_family_t *family,
    const char *device, const ncfg_ethtool_feature_t *wanted, size_t count, uint32_t seq,
    char *err, size_t err_size)
{
	ncfg_genl_header_t header;
	ncfg_buf_t         attrs;
	ncfg_buf_t         bitset;
	ncfg_buf_t         bits;
	size_t             at;
	int                built;

	if (!out || !family || (count > 0 && !wanted)) {
		ncfg_error_set(err, err_size, "an ethtool request needs the resolved family");
		return 0;
	}
	ncfg_buf_init(&attrs, 0);
	if (!ethtool_header(&attrs, device, err, err_size)) {
		ncfg_buf_free(&attrs);
		return 0;
	}

	ncfg_buf_init(&bits, 0);
	for (at = 0; at < count; at++) {
		ncfg_buf_t bit;

		if (!wanted[at].name || wanted[at].name[0] == '\0' ||
		    strlen(wanted[at].name) >= NCFG_ETHTOOL_NAME_MAX) {
			ncfg_error_set(err, err_size,
			    "`%s` is too long to be a feature this kernel has",
			    wanted[at].name ? wanted[at].name : "");
			ncfg_buf_free(&bits);
			ncfg_buf_free(&attrs);
			return 0;
		}
		ncfg_buf_init(&bit, 0);
		ncfg_wire_attr_put_str(&bit, ETHTOOL_A_BITSET_BIT_NAME, wanted[at].name);
		if (wanted[at].on) {
			/* A flag: present means on, absent means off. There is
			 * no "false" encoding, so writing a zero here would read
			 * as on. */
			ncfg_wire_attr_put(&bit, ETHTOOL_A_BITSET_BIT_VALUE, NULL, 0);
		}
		ncfg_wire_attr_put_nested(&bits, ETHTOOL_A_BITSET_BITS_BIT, &bit);
		ncfg_buf_free(&bit);
	}

	/* A mask bitset, deliberately without `NOMASK`: it says "change exactly
	 * these and leave everything else alone". The no-mask form would mean
	 * "this is the complete set of enabled features", which would turn off
	 * every offload the document does not mention. */
	ncfg_buf_init(&bitset, 0);
	ncfg_wire_attr_put_nested(&bitset, ETHTOOL_A_BITSET_BITS, &bits);
	ncfg_wire_attr_put_nested(&attrs, ETHTOOL_A_FEATURES_WANTED, &bitset);

	header.cmd = ETHTOOL_MSG_FEATURES_SET;
	header.version = 1;
	/* `NLM_F_ACK`, because a set that is not acknowledged is a set whose
	 * failure and whose success are the same bytes from this side. */
	built = ncfg_genl_build_request(out, family->id, &header, NLM_F_ACK, seq, &attrs,
	    err, err_size);
	ncfg_buf_free(&bits);
	ncfg_buf_free(&bitset);
	ncfg_buf_free(&attrs);
	return built;
}

void ncfg_ethtool_names_free(ncfg_ethtool_names_t *names)
{
	size_t at;

	if (!names) {
		return;
	}
	for (at = 0; at < names->count; at++) {
		free(names->items[at]);
	}
	free(names->items);
	names->items = NULL;
	names->count = 0;
	names->capacity = 0;
}

int ncfg_ethtool_names_has(const ncfg_ethtool_names_t *names, const char *name)
{
	size_t at;

	if (!names || !name) {
		return 0;
	}
	for (at = 0; at < names->count; at++) {
		if (strcmp(names->items[at], name) == 0) {
			return 1;
		}
	}
	return 0;
}

/* Insert in order, dropping a name already there. */
static int names_add(ncfg_ethtool_names_t *names, const char *name, char *err, size_t err_size)
{
	char  *copy;
	size_t at = 0;
	size_t back;

	while (at < names->count) {
		int order = strcmp(names->items[at], name);

		if (order == 0) {
			return 1;
		}
		if (order > 0) {
			break;
		}
		at++;
	}
	if (names->count == names->capacity) {
		size_t wanted = names->capacity ? names->capacity * 2u : 8u;
		char **grown = realloc(names->items, wanted * sizeof(*grown));

		if (!grown) {
			ncfg_error_set(err, err_size, "out of memory reading ethtool features");
			return 0;
		}
		names->items = grown;
		names->capacity = wanted;
	}
	copy = strdup(name);
	if (!copy) {
		ncfg_error_set(err, err_size, "out of memory reading ethtool features");
		return 0;
	}
	for (back = names->count; back > at; back--) {
		names->items[back] = names->items[back - 1u];
	}
	names->items[at] = copy;
	names->count++;
	return 1;
}

/*
 * The names listed in a no-mask bitset.
 *
 * Without `NOMASK` this is a mask bitset and a listed bit means "this bit is
 * being talked about", not "this bit is on". Nothing here sends one, so reading
 * it as a list would be wrong rather than merely useless -- and the kernel does
 * send mask bitsets in other messages, so the check is not theoretical.
 */
static int listed_names(ncfg_ethtool_names_t *out, const ncfg_wire_attr_t *bitset,
    char *err, size_t err_size)
{
	ncfg_wire_attrs_t area;
	ncfg_wire_attrs_t bits;
	ncfg_wire_attr_t  attr;
	ncfg_wire_step_t  step;

	ncfg_wire_attrs_start(&area, bitset->value, bitset->length);
	step = ncfg_wire_attrs_find(&area, ETHTOOL_A_BITSET_NOMASK, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step == NCFG_WIRE_END) {
		return 1;
	}
	step = ncfg_wire_attrs_find(&area, ETHTOOL_A_BITSET_BITS, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step == NCFG_WIRE_END) {
		return 1;
	}

	ncfg_wire_attrs_start(&bits, attr.value, attr.length);
	for (;;) {
		ncfg_wire_attr_t bit;
		ncfg_wire_attrs_t inside;
		ncfg_wire_attr_t named;
		char             name[NCFG_ETHTOOL_NAME_MAX];

		step = ncfg_wire_attrs_next(&bits, &bit, err, err_size);
		if (step == NCFG_WIRE_END) {
			return 1;
		}
		if (step == NCFG_WIRE_BAD) {
			return 0;
		}
		if (bit.kind != ETHTOOL_A_BITSET_BITS_BIT) {
			continue;
		}
		ncfg_wire_attrs_start(&inside, bit.value, bit.length);
		step = ncfg_wire_attrs_find(&inside, ETHTOOL_A_BITSET_BIT_NAME, &named,
		    err, err_size);
		if (step == NCFG_WIRE_BAD) {
			return 0;
		}
		/* A bit with an index and no name is one this kernel numbered
		 * rather than named. Nothing here can do anything with a number
		 * -- see ethtool.h on why the names are the contract -- so it is
		 * skipped rather than guessed at. */
		if (step == NCFG_WIRE_END) {
			continue;
		}
		if (!ncfg_wire_attr_string(&named, name, sizeof(name), NULL, 0)) {
			continue;
		}
		if (!names_add(out, name, err, err_size)) {
			return 0;
		}
	}
}

int ncfg_ethtool_active_merge(ncfg_ethtool_names_t *out, const void *payload, size_t length,
    char *err, size_t err_size)
{
	ncfg_wire_attrs_t area;
	ncfg_wire_attr_t  active;
	ncfg_wire_step_t  step;

	if (!out) {
		ncfg_error_set(err, err_size, "a feature set needs somewhere to go");
		return 0;
	}
	if (!ncfg_genl_payload_attrs(payload, length, &area, err, err_size)) {
		return 0;
	}
	step = ncfg_wire_attrs_find(&area, ETHTOOL_A_FEATURES_ACTIVE, &active, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	/* A message about this device that does not carry the active set adds
	 * nothing. It is not a refusal: the kernel answers with more than one
	 * message for some devices and only one of them has it. */
	if (step == NCFG_WIRE_END) {
		return 1;
	}
	return listed_names(out, &active, err, err_size);
}
