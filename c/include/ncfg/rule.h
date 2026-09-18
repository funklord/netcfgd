/*
 * rule.h -- reading the policy routing rules the kernel holds.
 *
 * WHY THIS IS NOT IN netlink.h WITH THE OTHER FOUR DUMPS
 *   It is the fifth dump and it is named like them -- `ncfg_dump_rule_request`,
 *   `NCFG_DUMP_RULE`, `ncfg_dump_rule` -- because a caller writing an
 *   observation should not have to learn a second spelling for the same thing.
 *   It is here rather than there because the rule itself belongs to ops.h,
 *   which already carries `ncfg_ops_rule_t` and the two messages that install
 *   and remove one; a decoder in netlink.h would make netlink.h depend on the
 *   model's idea of a rule, which is the one thing that header says it does
 *   not do. It also could not be there today: netlink.h and document.h declare
 *   one type name between them, so a header that needs ops.h cannot include
 *   netlink.h at all -- see `NCFG_RULE_NAME_MAX` below.
 *
 * WHY A RECORD AND A SPEC, WHEN THE RUST HAS ONE TYPE
 *   `rule.rs` uses `RuleRecord` in both directions deliberately: a rule netcfgd
 *   installs and a rule it reads have to be comparable field by field, and a
 *   separate spec and record pair is two places for the comparison to drift.
 *
 *   C cannot quite have that. `ncfg_ops_rule_t` borrows its interface names
 *   from the document that is being applied -- they are `const char *` into a
 *   parsed document, and nothing owns them -- while a record comes off a socket
 *   and has to own its own. So there are two shapes, and
 *   `ncfg_rule_record_spec` is the one place the mapping between them lives:
 *   it builds the spec a planner compares against, pointing at the record's own
 *   names. A comparison is therefore still between two values of one type, and
 *   there is exactly one function to get wrong rather than a field list copied
 *   at every call site.
 *
 * OWNERSHIP COMES FROM `FRA_PROTOCOL`
 *   Exactly as it does for routes. Decision 0002 stamps 110 on everything
 *   netcfgd installs and refuses to delete anything not carrying it. Without it
 *   a rule would be indistinguishable from one an operator added by hand, and
 *   reconciliation would either remove theirs or never remove its own.
 *
 *   `FRA_PROTOCOL` arrived in Linux 4.17. On anything older the attribute is
 *   ignored on the way in and absent on the way out, so every rule reads as
 *   unowned and netcfgd installs but never removes. That is the safe direction,
 *   and it is stated rather than discovered.
 */
#ifndef NCFG_RULE_H
#define NCFG_RULE_H

#include <stddef.h>
#include <stdint.h>

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/ops.h"
#include "ncfg/wire.h"

/*
 * `IFNAMSIZ`, which netlink.h already spells `NCFG_LINK_NAME_MAX`.
 *
 * Written out again rather than borrowed, and not by choice: netlink.h and
 * document.h cannot both be included, because each declares a type called
 * `ncfg_bridge_vlan_t` -- the kernel's observed VLAN in one and the document's
 * desired VLAN in the other -- and this header needs ops.h, which brings
 * document.h. The collision is reported rather than worked around anywhere but
 * here; when it is settled, this constant should become netlink.h's.
 */
#define NCFG_RULE_NAME_MAX 16u

/*
 * Length of `struct fib_rule_hdr`.
 *
 * Byte-for-byte the same shape as `rtmsg` and deliberately not that type:
 * bytes five, six and seven are `res1`, `res2` and `action` here against
 * `protocol`, `scope` and `type` there. Decoding one with
 * `ncfg_wire_rtmsg_decode` would compile and would read the action as a route
 * type. Checked against the kernel's own `sizeof` in rule.c.
 */
#define NCFG_RULE_HDR_LEN 12u

/* The message a rule dump asks for. Named rather than assumed, as the bridge
 * VLAN dump is. */
#define NCFG_DUMP_RULE RTM_GETRULE

/*
 * The dump request: an all-zero header in `body`, nothing in `attrs`.
 *
 * Family `AF_UNSPEC` asks for both families in one dump, which is what
 * `ip rule show` does -- asking for `AF_INET` and then for `AF_INET6` is two
 * dumps and a window between them in which the machine changed.
 *
 * `void`, for the reason the other four are: failure is the buffer's and it is
 * sticky, so a caller builds a request and checks `ncfg_buf_failed` once.
 */
void ncfg_dump_rule_request(ncfg_buf_t *body, ncfg_buf_t *attrs);

/*
 * One rule, as the kernel reports it.
 *
 * Owns nothing: the two interface names are arrays inside the record, which is
 * what the link, address and route records do and why none of them has a free
 * beside it. `ncfg_rule_record_t` has none either, and that is said here so a
 * reader can find it out without reading the decoder.
 */
typedef struct {
	/* `AF_INET` or `AF_INET6`. */
	uint8_t        family;
	/* Consulted in ascending order. */
	uint32_t       priority;
	/* Which table to look up, for `FR_ACT_TO_TBL`. Above 255 it does not
	 * fit the header's byte and arrives in `FRA_TABLE` instead, which is
	 * why this is 32 bits wide. */
	uint32_t       table;
	/* What to do on a match: `FR_ACT_TO_TBL` and the three drop actions. */
	uint8_t        action;
	/* Source selector, with its prefix length. `AF_UNSPEC` for absent. */
	ncfg_wire_ip_t from;
	uint8_t        from_len;
	/* Destination selector. */
	ncfg_wire_ip_t to;
	uint8_t        to_len;
	int            has_iif;
	char           iif[NCFG_RULE_NAME_MAX];
	int            has_oif;
	char           oif[NCFG_RULE_NAME_MAX];
	int            has_fwmark;
	uint32_t       fwmark;
	int            has_fwmask;
	uint32_t       fwmask;
	/*
	 * Ignore routes shorter than this.
	 *
	 * Absent and zero are different answers: `suppress_prefixlength 0` is
	 * the whole `ip rule` trick, and the kernel dumps the attribute as
	 * all-ones when it is unset. Reading that literally would make every
	 * ordinary rule look as though it suppressed prefixes shorter than four
	 * billion, so all-ones is read as absence.
	 */
	int            has_suppress_prefixlength;
	uint32_t       suppress_prefixlength;
	/* Match packets belonging to an l3mdev master. */
	int            l3mdev;
	/* Invert the selectors. */
	int            invert;
	/* `FRA_PROTOCOL`, or 0 on a kernel that does not send it -- which reads
	 * as "not netcfgd's", and see the header comment for why that is the
	 * safe direction. */
	uint8_t        protocol;
} ncfg_rule_record_t;

/*
 * Decode one payload into a record.
 *
 * A payload too short for the header, or whose attributes do not make sense, is
 * a refusal with a sentence -- and a refusal is ordinary rather than alarming,
 * since a caller that dumps skips what it cannot read and says how many.
 *
 * `out` is left zeroed on a refusal.
 */
int ncfg_dump_rule(const void *payload, size_t length, ncfg_rule_record_t *out,
    char *err, size_t err_size);

/*
 * The record as the type that installs and removes rules.
 *
 * **The spec borrows the record**: its `iif` and `oif` point into `record`, so
 * it must not outlive it and neither may be freed. That is the same arrangement
 * `ncfg_ops_rule_t` already has with a parsed document, which is where its
 * names come from on the other side.
 *
 * An absent optional field comes back with `has` clear, which is what makes a
 * field-by-field comparison against a rule built from a document meaningful:
 * absent and zero are different answers throughout, and `suppress_prefixlength`
 * is the one where the difference is the feature.
 */
void ncfg_rule_record_spec(const ncfg_rule_record_t *record, ncfg_ops_rule_t *out);

#endif /* NCFG_RULE_H */
