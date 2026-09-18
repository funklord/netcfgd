/*
 * rule.c -- one `RTM_GETRULE` reply, as a rule.
 *
 * No descriptor is opened, read or closed in this file, which is dump.c's
 * property and for the same reason: everything here takes bytes the caller
 * already has, so every case is testable against a request this port itself
 * encoded, with no kernel, no privilege and no policy routing on the machine.
 *
 * The attribute helpers below are this file's own rather than dump.c's. They
 * are the same four lines -- find an attribute, and let "not there" be absence
 * while a malformed area refuses the record -- and dump.c's are `static` in a
 * file this worker did not write. Sharing them means changing that file, which
 * is not a change a rule decoder gets to make; the alternative was to widen
 * `wire.h`, which is landed. Said here so that whoever reconciles the two later
 * knows this was a choice rather than an oversight.
 */
#include "ncfg/rule.h"

#include <string.h>

#include <linux/fib_rules.h>

/* The length this file decodes is the kernel's own, not a second opinion. */
_Static_assert(sizeof(struct fib_rule_hdr) == NCFG_RULE_HDR_LEN,
    "a rule header is twelve bytes and this one is not");

/*
 * Find an attribute, distinguishing "not there" from "the area is nonsense".
 *
 * Returns 0 only for the second, with `err` set: a missing `FRA_PROTOCOL` is a
 * kernel older than 4.17, while a malformed area is a message nothing should be
 * decoded out of.
 */
static int area_find(const ncfg_wire_attrs_t *area, uint16_t kind, ncfg_wire_attr_t *out,
    int *found, char *err, size_t err_size)
{
	ncfg_wire_step_t step = ncfg_wire_attrs_find(area, kind, out, err, err_size);

	*found = (step == NCFG_WIRE_OK);
	return step != NCFG_WIRE_BAD;
}

static int area_u8(const ncfg_wire_attrs_t *area, uint16_t kind, uint8_t *value, int *found,
    char *err, size_t err_size)
{
	ncfg_wire_attr_t attr;
	int              present = 0;

	*found = 0;
	if (!area_find(area, kind, &attr, &present, err, err_size)) {
		return 0;
	}
	/* An attribute of the wrong width is absent, deliberately: `wire.c`
	 * refuses a value of the wrong size rather than truncating it, and
	 * reading one with the wrong accessor would return a number that is
	 * merely wrong. */
	if (!present || !ncfg_wire_attr_u8(&attr, value, NULL, 0)) {
		return 1;
	}
	*found = 1;
	return 1;
}

static int area_u32(const ncfg_wire_attrs_t *area, uint16_t kind, uint32_t *value, int *found,
    char *err, size_t err_size)
{
	ncfg_wire_attr_t attr;
	int              present = 0;

	*found = 0;
	if (!area_find(area, kind, &attr, &present, err, err_size)) {
		return 0;
	}
	if (!present || !ncfg_wire_attr_u32(&attr, value, NULL, 0)) {
		return 1;
	}
	*found = 1;
	return 1;
}

static int area_string(const ncfg_wire_attrs_t *area, uint16_t kind, char *out, size_t out_size,
    int *found, char *err, size_t err_size)
{
	ncfg_wire_attr_t attr;
	int              present = 0;

	*found = 0;
	if (!area_find(area, kind, &attr, &present, err, err_size)) {
		return 0;
	}
	/* A name that would not fit is absent rather than truncated: a
	 * truncated interface name is a name, just somebody else's. */
	if (!present || !ncfg_wire_attr_string(&attr, out, out_size, NULL, 0)) {
		return 1;
	}
	*found = 1;
	return 1;
}

static int area_ip(const ncfg_wire_attrs_t *area, uint16_t kind, ncfg_wire_ip_t *value,
    int *found, char *err, size_t err_size)
{
	ncfg_wire_attr_t attr;
	int              present = 0;

	*found = 0;
	if (!area_find(area, kind, &attr, &present, err, err_size)) {
		return 0;
	}
	if (!present || !ncfg_wire_attr_ip(&attr, value, NULL, 0)) {
		return 1;
	}
	*found = 1;
	return 1;
}

void ncfg_dump_rule_request(ncfg_buf_t *body, ncfg_buf_t *attrs)
{
	uint8_t header[NCFG_RULE_HDR_LEN];

	(void)attrs;
	/* An all-zero header: family `AF_UNSPEC` asks for both families in one
	 * dump. Written as bytes rather than through a struct so that a
	 * compiler's padding rules are not part of what goes on the wire, which
	 * is what ops_route.c does on the way out. */
	memset(header, 0, sizeof(header));
	ncfg_buf_add(body, header, sizeof(header));
}

int ncfg_dump_rule(const void *payload, size_t length, ncfg_rule_record_t *out,
    char *err, size_t err_size)
{
	const uint8_t    *bytes = (const uint8_t *)payload;
	ncfg_wire_attrs_t area;
	uint32_t          flags = 0;
	uint32_t          table = 0;
	uint8_t           table_byte;
	uint8_t           l3mdev = 0;
	int               found = 0;

	if (!out) {
		ncfg_error_set(err, err_size, "a rule record needs somewhere to go");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!bytes || length < NCFG_RULE_HDR_LEN) {
		ncfg_error_set(err, err_size,
		    "a rule message is at least %u bytes and this one is %zu",
		    (unsigned)NCFG_RULE_HDR_LEN, bytes ? length : (size_t)0);
		return 0;
	}
	out->family = bytes[0];
	out->to_len = bytes[1];
	out->from_len = bytes[2];
	/* bytes[3] is `tos`, which netcfgd does not carry: it is deprecated in
	 * the kernel and `ip rule` has not offered it for years. */
	table_byte = bytes[4];
	/* bytes[5] and bytes[6] are `res1` and `res2`. The action is seventh,
	 * which is where a route message keeps its type -- see rule.h. */
	out->action = bytes[7];
	memcpy(&flags, bytes + 8, sizeof(flags));
	out->invert = (flags & FIB_RULE_INVERT) != 0;

	ncfg_wire_attrs_start(&area, bytes + NCFG_RULE_HDR_LEN, length - NCFG_RULE_HDR_LEN);

	if (!area_u32(&area, FRA_PRIORITY, &out->priority, &found, err, err_size)) {
		return 0;
	}
	/* `FRA_TABLE` carries the table id when it does not fit the byte-wide
	 * field in the header, which is every table above 255. Reading only the
	 * byte reports table 1000 as table 232, and 232 is a real table
	 * belonging to somebody else. */
	if (!area_u32(&area, FRA_TABLE, &table, &found, err, err_size)) {
		return 0;
	}
	out->table = found ? table : (uint32_t)table_byte;

	if (!area_ip(&area, FRA_SRC, &out->from, &found, err, err_size)) {
		return 0;
	}
	/* A prefix length means nothing without the selector it belongs to, so
	 * it is kept only where the address arrived -- which is the reading side
	 * of what ops_route.c does when it sends one. */
	if (!found) {
		out->from_len = 0;
	}
	if (!area_ip(&area, FRA_DST, &out->to, &found, err, err_size)) {
		return 0;
	}
	if (!found) {
		out->to_len = 0;
	}

	if (!area_string(&area, FRA_IIFNAME, out->iif, sizeof(out->iif), &out->has_iif,
	    err, err_size)) {
		return 0;
	}
	if (!area_string(&area, FRA_OIFNAME, out->oif, sizeof(out->oif), &out->has_oif,
	    err, err_size)) {
		return 0;
	}
	if (!area_u32(&area, FRA_FWMARK, &out->fwmark, &out->has_fwmark, err, err_size)) {
		return 0;
	}
	if (!area_u32(&area, FRA_FWMASK, &out->fwmask, &out->has_fwmask, err, err_size)) {
		return 0;
	}
	if (!area_u32(&area, FRA_SUPPRESS_PREFIXLEN, &out->suppress_prefixlength,
	    &out->has_suppress_prefixlength, err, err_size)) {
		return 0;
	}
	/* The suppressor is dumped as all-ones when unset, which is not a prefix
	 * length. Reading it literally would make every ordinary rule look as
	 * though it suppressed prefixes shorter than four billion -- and a plan
	 * comparing that against a document that asked for nothing would rewrite
	 * every rule on the machine, for ever. */
	if (out->has_suppress_prefixlength && out->suppress_prefixlength == UINT32_MAX) {
		out->has_suppress_prefixlength = 0;
		out->suppress_prefixlength = 0;
	}
	if (!area_u8(&area, FRA_L3MDEV, &l3mdev, &found, err, err_size)) {
		return 0;
	}
	out->l3mdev = found && l3mdev == 1;
	if (!area_u8(&area, FRA_PROTOCOL, &out->protocol, &found, err, err_size)) {
		return 0;
	}
	if (!found) {
		/* Not netcfgd's, which is what a kernel older than 4.17 makes
		 * every rule on the machine look like. Installs go on working
		 * and removals stop, which is the safe direction. */
		out->protocol = 0;
	}
	return 1;
}

void ncfg_rule_record_spec(const ncfg_rule_record_t *record, ncfg_ops_rule_t *out)
{
	if (!out) {
		return;
	}
	memset(out, 0, sizeof(*out));
	if (!record) {
		return;
	}
	out->family = record->family;
	out->priority = record->priority;
	out->table = record->table;
	out->action = record->action;
	out->from = record->from;
	out->from_len = record->from_len;
	out->to = record->to;
	out->to_len = record->to_len;
	/* Borrowed, not copied. See rule.h: the spec must not outlive the
	 * record, which is the same arrangement it has with a parsed document on
	 * the other side. */
	out->iif = record->has_iif ? record->iif : NULL;
	out->oif = record->has_oif ? record->oif : NULL;
	out->fwmark.has = record->has_fwmark;
	out->fwmark.value = (int64_t)record->fwmark;
	out->fwmask.has = record->has_fwmask;
	out->fwmask.value = (int64_t)record->fwmask;
	out->suppress_prefixlength.has = record->has_suppress_prefixlength;
	out->suppress_prefixlength.value = (int64_t)record->suppress_prefixlength;
	out->l3mdev = record->l3mdev;
	out->invert = record->invert;
	/* Present, always. A record states what the kernel reported, including
	 * that it reported nothing -- while an absent protocol on the way *out*
	 * means netcfgd's own 110. Leaving this absent would turn a rule
	 * somebody else installed into one this port would claim. */
	out->protocol.has = 1;
	out->protocol.value = record->protocol;
}
