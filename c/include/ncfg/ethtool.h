/*
 * ethtool.h -- the offloads, over ethtool's generic netlink family.
 *
 * WHY THERE IS NO IOCTL HERE
 *   Decision 0016 said this needed "an `unsafe` ioctl outside `netcfgd-sys` or
 *   generic netlink family resolution". The second was built for WireGuard at
 *   M4, so the cost is already paid and `SIOCETHTOOL` is not needed: the
 *   `ethtool` family has existed since Linux 5.6 and does everything the ioctl
 *   does. In this port that means genl.h resolves the family and this module
 *   only builds messages -- there is no descriptor in this file at all.
 *
 * ONLY THE OFFLOADS
 *   The model also carries ring sizes, link modes and wake-on-LAN, and those
 *   are not here. The reason is verification, not effort: a veth accepts a
 *   features set and refuses a link-modes set with a bare `EINVAL`; ring and
 *   wake-on-LAN messages are `EOPNOTSUPP` on anything that is not a physical
 *   NIC. Every netlink defect this project has shipped -- the WireGuard flags
 *   attribute, the nftables meta key, the qdisc rate unit -- was found by
 *   writing to a real kernel and reading it back, and none of them would have
 *   been found by writing an encoder carefully. So the settings that can only
 *   be exercised against hardware this build cannot safely write to stay
 *   unimplemented and stay warned about.
 *
 * FEATURES ARE NAMED, NOT NUMBERED
 *   The kernel's bit indices are not stable across versions and are not a wire
 *   contract; the names are. Sending `ETHTOOL_A_BITSET_BIT_NAME` lets the
 *   kernel do the lookup, which also makes a feature the driver has never heard
 *   of a clean failure rather than the wrong bit being set.
 *
 * TWO BITSETS, AND THEY MEAN OPPOSITE THINGS
 *   This is the part that goes wrong, and it goes wrong silently in both
 *   directions:
 *
 *     * `ACTIVE` comes back as a **no-mask** bitset, which is a *list*: a bit
 *       that appears is on, and one that does not is off. Reading it as a mask
 *       bitset and looking for `BIT_VALUE` finds nothing and reports every
 *       feature disabled.
 *     * What goes out is a **mask** bitset, deliberately without `NOMASK`: it
 *       says "change exactly these and leave everything else alone". The
 *       no-mask form would mean "this is the complete set of enabled
 *       features", which would turn off every offload the document does not
 *       mention.
 *
 *   And within a mask bitset there is no "false" encoding: `BIT_VALUE` is a
 *   flag, so present means on and absent means off. Writing a zero-valued
 *   `BIT_VALUE` would read as on.
 *
 * THE NUMBERS ARE THE KERNEL'S
 *   `ETHTOOL_MSG_FEATURES_GET`, the `ETHTOOL_A_*` attributes and
 *   `ETH_GSTRING_LEN` come from <linux/ethtool_netlink.h>. The Rust spells the
 *   command out with a warning beside it -- twelve, not ten, because ten is
 *   `ETHTOOL_MSG_WOL_SET` and a features payload sent there is a bare `EINVAL`
 *   that reads exactly like a malformed bitset, which is where an hour went.
 *   Taking the enum removes the possibility rather than warning about it, and
 *   `ethtool_test.c` checks the two commands against the numbers that hour
 *   produced.
 */
#ifndef NCFG_ETHTOOL_H
#define NCFG_ETHTOOL_H

#include <stddef.h>
#include <stdint.h>

#include <linux/ethtool.h>
#include <linux/ethtool_netlink.h>

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/genl.h"

/* The family to resolve through genl.h before anything here can be sent. */
#define NCFG_ETHTOOL_FAMILY "ethtool"

/* `ETH_GSTRING_LEN`, the terminator included: the kernel's own bound on a
 * feature name. A longer one cannot name a feature that exists. */
#define NCFG_ETHTOOL_NAME_MAX ETH_GSTRING_LEN

/* `IFNAMSIZ`, written out for the reason wire.h gives about `linux/if.h`. */
#define NCFG_ETHTOOL_DEVICE_MAX 16u

/* One feature, and whether it is wanted on. */
typedef struct {
	const char *name;
	int         on;
} ncfg_ethtool_feature_t;

/*
 * Feature names, sorted and without duplicates.
 *
 * Sorted on insertion rather than at the end, because a reply is folded in one
 * payload at a time and there is no point at which a caller could be relied on
 * to say "that was the last one". Duplicates are dropped for the same reason
 * the Rust's `dedup` exists: the kernel may describe one device in more than
 * one message.
 */
typedef struct {
	char **items;
	size_t count;
	size_t capacity;
} ncfg_ethtool_names_t;

/* Release what it holds, and leave it usable and empty. Freeing one that was
 * never filled in is nothing. */
void ncfg_ethtool_names_free(ncfg_ethtool_names_t *names);

/* Whether a name is in the set. */
int ncfg_ethtool_names_has(const ncfg_ethtool_names_t *names, const char *name);

/*
 * Ask which features a device has on.
 *
 * `family` is what genl.h resolved for `NCFG_ETHTOOL_FAMILY`; `ENOENT` from
 * that lookup means this kernel predates the netlink interface, which is Linux
 * 5.6.
 */
int ncfg_ethtool_features_get_request(ncfg_buf_t *out, const ncfg_genl_family_t *family,
    const char *device, uint32_t seq, char *err, size_t err_size);

/*
 * Turn features on or off by name.
 *
 * Every name in `wanted` is sent, on ones with a `BIT_VALUE` flag and off ones
 * without -- see the header comment, where absent means off and there is no
 * other spelling for it.
 *
 * A name longer than `NCFG_ETHTOOL_NAME_MAX` is refused here rather than sent.
 * That is a divergence from the Rust, which sends it and lets the kernel answer
 * `EINVAL`: the errno is the same one a malformed bitset produces, and "the
 * name `...` is too long to be a feature" is a sentence an operator can act on.
 */
int ncfg_ethtool_features_set_request(ncfg_buf_t *out, const ncfg_genl_family_t *family,
    const char *device, const ncfg_ethtool_feature_t *wanted, size_t count, uint32_t seq,
    char *err, size_t err_size);

/*
 * Fold one `FEATURES_GET` reply payload into the set of active features.
 *
 * A payload with no `ACTIVE` bitset adds nothing and is not a failure: the
 * kernel answers with more than one message for some devices, and only one of
 * them carries it. A payload that is not a generic netlink message at all, or
 * whose attributes do not make sense, is a refusal with a sentence.
 *
 * A bitset that is not a no-mask one adds nothing either, and that is the check
 * the Rust makes for the same reason: in a mask bitset a listed bit means "this
 * bit is being talked about", not "this bit is on". Nothing here sends one, so
 * reading it as a list would be wrong rather than merely useless.
 */
/*
 * Which of a `FEATURES_GET` reply's bitsets to read.
 *
 * The reply carries four -- `HW`, `WANTED`, `ACTIVE` and `NOCHANGE` -- and
 * netcfgd reads two. `ACTIVE` is what the device is doing; `WANTED` is what it
 * was last asked for, which is the bitset a `set_features` writes. **Where the
 * two disagree, a request did not take**, and that is the one thing an
 * observation cannot learn from either on its own.
 *
 * `HW` and `NOCHANGE` are deliberately not here. They say *why* a feature
 * cannot move -- the device does not support it, or the kernel never changes
 * it -- and the planner's question is only *whether*, which the two above
 * answer between them. A reader that added them would be keeping two facts to
 * decide one.
 */
typedef enum {
	NCFG_ETHTOOL_BITSET_ACTIVE,
	NCFG_ETHTOOL_BITSET_WANTED
} ncfg_ethtool_bitset_t;

int ncfg_ethtool_bitset_merge(ncfg_ethtool_names_t *out, const void *payload, size_t length,
    ncfg_ethtool_bitset_t which, char *err, size_t err_size);

/* `ncfg_ethtool_bitset_merge` for the active set, which is every caller that
 * predates there being a second one. */
int ncfg_ethtool_active_merge(ncfg_ethtool_names_t *out, const void *payload, size_t length,
    char *err, size_t err_size);

#endif /* NCFG_ETHTOOL_H */
