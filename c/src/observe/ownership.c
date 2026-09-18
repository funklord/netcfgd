/*
 * ownership.c -- the three judgements that decide what netcfgd may delete.
 *
 * A file of their own, and each with a name of its own, because these are the
 * decisions in this module that can strand somebody's address or remove it.
 * The Rust splits `address_ownership` out for exactly that reason -- "it should
 * be reviewable on its own" -- and the other two are the same question asked of
 * the object kinds that have no protocol field and of the origin a tag implies.
 *
 * Decision 0002 is the whole of the policy, and its asymmetry is the thing to
 * keep in mind while reading: under-claiming costs a little convenience,
 * over-claiming deletes somebody's manual change.
 */
#include "ncfg/observe.h"

#include "observe_internal.h"

#include <string.h>

int ncfg_observe_link_ownership(char *const *altnames, size_t altname_count, int recorded)
{
	const size_t prefix = sizeof(NCFG_OBSERVE_ALTNAME_PREFIX) - 1u;
	size_t       at;

	for (at = 0; at < altname_count; at++) {
		/* **By prefix, not by the whole name.** The marker carries what
		 * the link was called when netcfgd made it, and a link can be
		 * renamed afterwards -- so the two disagree and the answer must
		 * not. */
		if (altnames[at] &&
		    strncmp(altnames[at], NCFG_OBSERVE_ALTNAME_PREFIX, prefix) == 0) {
			return NCFG_OWNERSHIP_OURS;
		}
	}
	if (recorded) {
		/* Additive: a link an older netcfgd created carries no
		 * alternative name, and a kernel that refused `RTM_NEWLINKPROP`
		 * left one unmarked on purpose. Neither should stop being
		 * netcfgd's on the day 0136 ships. */
		return NCFG_OWNERSHIP_OURS;
	}
	/* netcfgd did not make `eth0`, and saying so positively would be a claim
	 * about every physical device on the machine. */
	return NCFG_OWNERSHIP_UNKNOWN;
}

int ncfg_observe_address_ownership(int has_proto, uint8_t proto, int proto_supported,
    int recorded)
{
	if (proto_supported) {
		/* The kernel is authoritative here. An address with somebody
		 * else's tag, or none, is theirs whatever netcfgd wrote down --
		 * a stale record must not be able to claim an address back. */
		if (has_proto && proto == NCFG_WIRE_RTPROT_NETCFGD) {
			return NCFG_OWNERSHIP_OURS;
		}
		return NCFG_OWNERSHIP_FOREIGN;
	}
	/* Pre-5.18: no tag to read, so recorded state is all there is. It cannot
	 * distinguish netcfgd's address from an identical one added by hand, so
	 * a match is `unknown` rather than `ours` and nothing is removed on the
	 * strength of it. */
	return recorded ? NCFG_OWNERSHIP_UNKNOWN : NCFG_OWNERSHIP_FOREIGN;
}

ncfg_optint_t ncfg_observe_tagged_origin(int has_proto, uint8_t proto)
{
	ncfg_optint_t origin = { 0, 0 };

	if (has_proto && proto == NCFG_WIRE_RTPROT_NETCFGD) {
		origin.has = 1;
		origin.value = NCFG_ORIGIN_STATIC;
	}
	return origin;
}
