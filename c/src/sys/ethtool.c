/*
 * ethtool.c -- the features messages, the one bitset that is a list, and the
 * link modes.
 *
 * Bytes in, structures out, and no socket anywhere: the requests are built into
 * a buffer the caller sends and the replies are folded in as payloads the
 * caller already has. That is genl.h's split and wg.c's, and it is what lets
 * every case here be checked on a machine whose only interface is a veth.
 */
#include "ncfg/ethtool.h"

#include <stdlib.h>
#include <string.h>

#include "ncfg/document.h"
#include "ncfg/wire.h"

/* The header nest every ethtool message begins with: the device it is about. */
/* Every message's header attribute is number 1 (`ETHTOOL_A_FEATURES_HEADER`,
 * `ETHTOOL_A_LINKMODES_HEADER`, ...): the kernel's convention, so one function
 * serves both. */
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

int ncfg_ethtool_bitset_merge(ncfg_ethtool_names_t *out, const void *payload, size_t length,
    ncfg_ethtool_bitset_t which, char *err, size_t err_size)
{
	ncfg_wire_attrs_t area;
	ncfg_wire_attr_t  set;
	ncfg_wire_step_t  step;
	/* Initialised to the active set rather than left for the switch to fill,
	 * so a value outside the enum reads the set every caller before the second
	 * one wanted instead of whatever was on the stack. */
	uint16_t          kind = (uint16_t)ETHTOOL_A_FEATURES_ACTIVE;

	if (!out) {
		ncfg_error_set(err, err_size, "a feature set needs somewhere to go");
		return 0;
	}
	if (which == NCFG_ETHTOOL_BITSET_WANTED) {
		kind = (uint16_t)ETHTOOL_A_FEATURES_WANTED;
	}
	if (!ncfg_genl_payload_attrs(payload, length, &area, err, err_size)) {
		return 0;
	}
	step = ncfg_wire_attrs_find(&area, kind, &set, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	/* A message about this device that does not carry this set adds nothing.
	 * It is not a refusal: the kernel answers with more than one message for
	 * some devices and only one of them has it. */
	if (step == NCFG_WIRE_END) {
		return 1;
	}
	return listed_names(out, &set, err, err_size);
}

int ncfg_ethtool_active_merge(ncfg_ethtool_names_t *out, const void *payload, size_t length,
    char *err, size_t err_size)
{
	return ncfg_ethtool_bitset_merge(out, payload, length, NCFG_ETHTOOL_BITSET_ACTIVE, err,
	    err_size);
}

/* ---------------------------------------------------------------- link modes */

int ncfg_ethtool_link_modes_get_request(ncfg_buf_t *out, const ncfg_genl_family_t *family,
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
	header.cmd = ETHTOOL_MSG_LINKMODES_GET;
	header.version = 1;
	built = ncfg_genl_build_request(out, family->id, &header, 0, seq, &attrs, err, err_size);
	ncfg_buf_free(&attrs);
	return built;
}

int ncfg_ethtool_link_modes_set_request(ncfg_buf_t *out, const ncfg_genl_family_t *family,
    const char *device, const ncfg_ethtool_link_modes_set_t *wanted, uint32_t seq, char *err,
    size_t err_size)
{
	ncfg_genl_header_t header;
	ncfg_buf_t         attrs;
	int                built;

	if (!out || !family || !wanted) {
		ncfg_error_set(err, err_size, "an ethtool request needs the resolved family");
		return 0;
	}
	if (wanted->autoneg < 0 && wanted->speed == 0u && wanted->duplex < 0) {
		ncfg_error_set(err, err_size, "a link-modes request on %s names nothing to change",
		    device ? device : "?");
		return 0;
	}
	if (wanted->autoneg > 1 || (wanted->duplex >= 0 && wanted->duplex != DUPLEX_HALF &&
	    wanted->duplex != DUPLEX_FULL)) {
		ncfg_error_set(err, err_size, "a link-modes request on %s asks for a mode that does "
		    "not exist", device ? device : "?");
		return 0;
	}
	ncfg_buf_init(&attrs, 0);
	if (!ethtool_header(&attrs, device, err, err_size)) {
		ncfg_buf_free(&attrs);
		return 0;
	}
	if (wanted->autoneg >= 0) {
		ncfg_wire_attr_put_u8(&attrs, ETHTOOL_A_LINKMODES_AUTONEG, (uint8_t)wanted->autoneg);
	}
	if (wanted->speed != 0u) {
		ncfg_wire_attr_put_u32(&attrs, ETHTOOL_A_LINKMODES_SPEED, wanted->speed);
	}
	if (wanted->duplex >= 0) {
		ncfg_wire_attr_put_u8(&attrs, ETHTOOL_A_LINKMODES_DUPLEX, (uint8_t)wanted->duplex);
	}
	header.cmd = ETHTOOL_MSG_LINKMODES_SET;
	header.version = 1;
	built = ncfg_genl_build_request(out, family->id, &header, NLM_F_ACK, seq, &attrs,
	    err, err_size);
	ncfg_buf_free(&attrs);
	return built;
}

int ncfg_ethtool_link_modes_merge(ncfg_ethtool_link_modes_t *out, const void *payload,
    size_t length, char *err, size_t err_size)
{
	ncfg_wire_attrs_t area;
	ncfg_wire_attr_t  attr;
	ncfg_wire_step_t  step;
	uint8_t           autoneg, duplex;
	uint32_t          speed;

	if (!out) {
		ncfg_error_set(err, err_size, "link modes need somewhere to go");
		return 0;
	}
	if (!ncfg_genl_payload_attrs(payload, length, &area, err, err_size)) {
		return 0;
	}
	step = ncfg_wire_attrs_find(&area, ETHTOOL_A_LINKMODES_AUTONEG, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step == NCFG_WIRE_END) {
		return 1;
	}
	if (!ncfg_wire_attr_u8(&attr, &autoneg, err, err_size)) {
		return 0;
	}
	if (!ncfg_genl_payload_attrs(payload, length, &area, err, err_size)) {
		return 0;
	}
	step = ncfg_wire_attrs_find(&area, ETHTOOL_A_LINKMODES_SPEED, &attr, err, err_size);
	if (step != NCFG_WIRE_OK || !ncfg_wire_attr_u32(&attr, &speed, err, err_size)) {
		if (step == NCFG_WIRE_END) {
			ncfg_error_set(err, err_size, "a link-modes reply said autonegotiation and no speed");
		}
		return 0;
	}
	if (!ncfg_genl_payload_attrs(payload, length, &area, err, err_size)) {
		return 0;
	}
	step = ncfg_wire_attrs_find(&area, ETHTOOL_A_LINKMODES_DUPLEX, &attr, err, err_size);
	if (step != NCFG_WIRE_OK || !ncfg_wire_attr_u8(&attr, &duplex, err, err_size)) {
		if (step == NCFG_WIRE_END) {
			ncfg_error_set(err, err_size, "a link-modes reply said autonegotiation and no duplex");
		}
		return 0;
	}
	out->known = 1;
	out->autoneg = autoneg == AUTONEG_ENABLE;
	out->speed = speed == (uint32_t)SPEED_UNKNOWN ? 0u : speed;
	out->duplex = duplex == DUPLEX_HALF ? DUPLEX_HALF : duplex == DUPLEX_FULL ? DUPLEX_FULL : -1;
	return 1;
}

/* ---------------------------------------------------------------- rings */

int ncfg_ethtool_rings_get_request(ncfg_buf_t *out, const ncfg_genl_family_t *family,
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
	header.cmd = ETHTOOL_MSG_RINGS_GET;
	header.version = 1;
	built = ncfg_genl_build_request(out, family->id, &header, 0, seq, &attrs, err, err_size);
	ncfg_buf_free(&attrs);
	return built;
}

int ncfg_ethtool_rings_set_request(ncfg_buf_t *out, const ncfg_genl_family_t *family,
    const char *device, uint32_t rx, uint32_t tx, uint32_t seq, char *err, size_t err_size)
{
	ncfg_genl_header_t header;
	ncfg_buf_t         attrs;
	int                built;

	if (!out || !family) {
		ncfg_error_set(err, err_size, "an ethtool request needs the resolved family");
		return 0;
	}
	if (rx == 0u && tx == 0u) {
		ncfg_error_set(err, err_size, "a ring-size request on %s names no ring to change",
		    device ? device : "?");
		return 0;
	}
	ncfg_buf_init(&attrs, 0);
	if (!ethtool_header(&attrs, device, err, err_size)) {
		ncfg_buf_free(&attrs);
		return 0;
	}
	if (rx != 0u) {
		ncfg_wire_attr_put_u32(&attrs, ETHTOOL_A_RINGS_RX, rx);
	}
	if (tx != 0u) {
		ncfg_wire_attr_put_u32(&attrs, ETHTOOL_A_RINGS_TX, tx);
	}
	header.cmd = ETHTOOL_MSG_RINGS_SET;
	header.version = 1;
	built = ncfg_genl_build_request(out, family->id, &header, NLM_F_ACK, seq, &attrs,
	    err, err_size);
	ncfg_buf_free(&attrs);
	return built;
}

/* One optional u32 out of a reply; 1 with it, 1 with `*has` 0 where absent, 0
 * where it will not decode. */
static int optional_u32(const void *payload, size_t length, uint16_t kind, uint32_t *out,
    int *has, char *err, size_t err_size)
{
	ncfg_wire_attrs_t area;
	ncfg_wire_attr_t  attr;
	ncfg_wire_step_t  step;

	*has = 0;
	if (!ncfg_genl_payload_attrs(payload, length, &area, err, err_size)) {
		return 0;
	}
	step = ncfg_wire_attrs_find(&area, kind, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step == NCFG_WIRE_END) {
		return 1;
	}
	if (!ncfg_wire_attr_u32(&attr, out, err, err_size)) {
		return 0;
	}
	*has = 1;
	return 1;
}

int ncfg_ethtool_rings_merge(ncfg_ethtool_rings_t *out, const void *payload, size_t length,
    char *err, size_t err_size)
{
	uint32_t rx = 0, tx = 0, rx_max = 0, tx_max = 0;
	int      has_rx, has_tx, has_rx_max, has_tx_max;

	if (!out) {
		ncfg_error_set(err, err_size, "ring sizes need somewhere to go");
		return 0;
	}
	if (!optional_u32(payload, length, ETHTOOL_A_RINGS_RX, &rx, &has_rx, err, err_size) ||
	    !optional_u32(payload, length, ETHTOOL_A_RINGS_TX, &tx, &has_tx, err, err_size) ||
	    !optional_u32(payload, length, ETHTOOL_A_RINGS_RX_MAX, &rx_max, &has_rx_max, err,
	        err_size) ||
	    !optional_u32(payload, length, ETHTOOL_A_RINGS_TX_MAX, &tx_max, &has_tx_max, err,
	        err_size)) {
		return 0;
	}
	if (!has_rx && !has_tx) {
		return 1;
	}
	if (!has_rx || !has_tx) {
		ncfg_error_set(err, err_size, "a ring-size reply gave one ring and not the other");
		return 0;
	}
	out->known = 1;
	out->rx = rx;
	out->tx = tx;
	out->rx_max = has_rx_max ? rx_max : 0u;
	out->tx_max = has_tx_max ? tx_max : 0u;
	return 1;
}

/* ---------------------------------------------------------- wake-on-LAN */

/* The kernel's names for the wake-on-LAN modes, by `WAKE_*` bit
 * (`wol_mode_names` in net/ethtool/common.c). The names are what goes on the
 * wire, as for the features; the letters are the language's, in document.h. */
static const struct {
	const char *name;
} wol_modes[] = {
	{ "phy" }, { "ucast" }, { "mcast" }, { "bcast" },
	{ "arp" }, { "magic" }, { "magicsecure" }, { "filter" },
};

#define WOL_MODE_NAMES (sizeof(wol_modes) / sizeof(wol_modes[0]))

int ncfg_ethtool_wol_get_request(ncfg_buf_t *out, const ncfg_genl_family_t *family,
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
	header.cmd = ETHTOOL_MSG_WOL_GET;
	header.version = 1;
	built = ncfg_genl_build_request(out, family->id, &header, 0, seq, &attrs, err, err_size);
	ncfg_buf_free(&attrs);
	return built;
}

int ncfg_ethtool_wol_set_request(ncfg_buf_t *out, const ncfg_genl_family_t *family,
    const char *device, uint32_t modes, uint32_t seq, char *err, size_t err_size)
{
	ncfg_genl_header_t header;
	ncfg_buf_t         attrs;
	ncfg_buf_t         bitset;
	ncfg_buf_t         bits;
	size_t             at;
	int                built;

	if (!out || !family) {
		ncfg_error_set(err, err_size, "an ethtool request needs the resolved family");
		return 0;
	}
	if (modes & ~NCFG_WOL_MANAGED) {
		ncfg_error_set(err, err_size,
		    "a wake-on-LAN request on %s names a mode netcfgd does not manage",
		    device ? device : "?");
		return 0;
	}
	ncfg_buf_init(&attrs, 0);
	if (!ethtool_header(&attrs, device, err, err_size)) {
		ncfg_buf_free(&attrs);
		return 0;
	}
	/*
	 * **A mask bitset naming every mode netcfgd manages**, each on or off:
	 * "these six are exactly so, and the rest are not mine". The no-mask form
	 * would also clear `magicsecure` and `filter`, which need a password or a
	 * filter table this language has no word for, and which somebody else may
	 * have set on purpose.
	 */
	ncfg_buf_init(&bits, 0);
	for (at = 0; at < WOL_MODE_NAMES; at++) {
		ncfg_buf_t bit;

		if (!((1u << at) & NCFG_WOL_MANAGED)) {
			continue;
		}
		ncfg_buf_init(&bit, 0);
		ncfg_wire_attr_put_str(&bit, ETHTOOL_A_BITSET_BIT_NAME, wol_modes[at].name);
		if (modes & (1u << at)) {
			ncfg_wire_attr_put(&bit, ETHTOOL_A_BITSET_BIT_VALUE, NULL, 0);
		}
		ncfg_wire_attr_put_nested(&bits, ETHTOOL_A_BITSET_BITS_BIT, &bit);
		ncfg_buf_free(&bit);
	}
	ncfg_buf_init(&bitset, 0);
	ncfg_wire_attr_put_nested(&bitset, ETHTOOL_A_BITSET_BITS, &bits);
	ncfg_wire_attr_put_nested(&attrs, ETHTOOL_A_WOL_MODES, &bitset);

	header.cmd = ETHTOOL_MSG_WOL_SET;
	header.version = 1;
	built = ncfg_genl_build_request(out, family->id, &header, NLM_F_ACK, seq, &attrs,
	    err, err_size);
	ncfg_buf_free(&bits);
	ncfg_buf_free(&bitset);
	ncfg_buf_free(&attrs);
	return built;
}

/*
 * A `WOL_GET` reply's modes: a mask bitset, the mask the modes the device
 * supports and the value the ones on (`ethnl_put_bitset32` with
 * `wol.supported` as the mask). Read by name, as the features are; a bit the
 * kernel sends with an index and no name, or a name not in the table, is
 * skipped. A compact bitset is not asked for, so one is refused rather than
 * misread.
 */
int ncfg_ethtool_wol_merge(ncfg_ethtool_wol_t *out, const void *payload, size_t length,
    char *err, size_t err_size)
{
	ncfg_wire_attrs_t area;
	ncfg_wire_attrs_t inside;
	ncfg_wire_attrs_t bits;
	ncfg_wire_attr_t  modes;
	ncfg_wire_attr_t  attr;
	ncfg_wire_step_t  step;
	uint32_t          supported = 0;
	uint32_t          active = 0;

	if (!out) {
		ncfg_error_set(err, err_size, "wake-on-LAN modes need somewhere to go");
		return 0;
	}
	if (!ncfg_genl_payload_attrs(payload, length, &area, err, err_size)) {
		return 0;
	}
	step = ncfg_wire_attrs_find(&area, ETHTOOL_A_WOL_MODES, &modes, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step == NCFG_WIRE_END) {
		return 1;
	}
	ncfg_wire_attrs_start(&inside, modes.value, modes.length);
	step = ncfg_wire_attrs_find(&inside, ETHTOOL_A_BITSET_VALUE, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step != NCFG_WIRE_END) {
		ncfg_error_set(err, err_size,
		    "a wake-on-LAN reply came as a compact bitset, which was not asked for");
		return 0;
	}
	ncfg_wire_attrs_start(&inside, modes.value, modes.length);
	step = ncfg_wire_attrs_find(&inside, ETHTOOL_A_BITSET_BITS, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step != NCFG_WIRE_END) {
		ncfg_wire_attrs_start(&bits, attr.value, attr.length);
		for (;;) {
			ncfg_wire_attr_t  bit;
			ncfg_wire_attrs_t one;
			ncfg_wire_attr_t  named;
			ncfg_wire_attr_t  value;
			char              name[NCFG_ETHTOOL_NAME_MAX];
			size_t            at;

			step = ncfg_wire_attrs_next(&bits, &bit, err, err_size);
			if (step == NCFG_WIRE_END) {
				break;
			}
			if (step == NCFG_WIRE_BAD) {
				return 0;
			}
			if (bit.kind != ETHTOOL_A_BITSET_BITS_BIT) {
				continue;
			}
			ncfg_wire_attrs_start(&one, bit.value, bit.length);
			step = ncfg_wire_attrs_find(&one, ETHTOOL_A_BITSET_BIT_NAME, &named, err,
			    err_size);
			if (step == NCFG_WIRE_BAD) {
				return 0;
			}
			if (step == NCFG_WIRE_END ||
			    !ncfg_wire_attr_string(&named, name, sizeof(name), NULL, 0)) {
				continue;
			}
			for (at = 0; at < WOL_MODE_NAMES; at++) {
				if (strcmp(wol_modes[at].name, name) == 0) {
					break;
				}
			}
			if (at == WOL_MODE_NAMES) {
				continue;
			}
			supported |= 1u << at;
			ncfg_wire_attrs_start(&one, bit.value, bit.length);
			step = ncfg_wire_attrs_find(&one, ETHTOOL_A_BITSET_BIT_VALUE, &value, err,
			    err_size);
			if (step == NCFG_WIRE_BAD) {
				return 0;
			}
			if (step != NCFG_WIRE_END) {
				active |= 1u << at;
			}
		}
	}
	out->known = 1;
	out->supported = supported;
	out->active = active;
	return 1;
}
