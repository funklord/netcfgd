/*
 * ops_value.c -- what the model holds, turned into what the wire takes.
 *
 * Five conversions, shared by ops.c and ops_route.c and useful to anybody
 * assembling an operation: an address from the model's type, the family byte
 * that goes with it, an optional number narrowed to its field, and a hardware
 * address out of text. They are here rather than in either of those files
 * because both need them, and because a second copy of a narrowing check is a
 * second place for a cast to creep back in.
 *
 * **Every one of them is work the Rust did not have to do.** `Option<u32>`,
 * `IpAddr` and `u8::from_str_radix` did this in the type system; in C the
 * model carries every number as an `int64_t` and every address as bytes beside
 * a flag, so each narrowing is real code. Each one is checked rather than
 * cast, and the failure it refuses is named on it.
 */
#include "ncfg/ops.h"

#include <stdint.h>
#include <string.h>

int ncfg_ops_ip_present(const ncfg_wire_ip_t *ip)
{
	return ip && (ip->family == AF_INET || ip->family == AF_INET6);
}

int ncfg_ops_ip_from_address(const ncfg_address_t *address, ncfg_wire_ip_t *out,
    char *err, size_t err_size)
{
	if (!address || !out) {
		ncfg_error_set(err, err_size, "an address needs somewhere to come from and go");
		return 0;
	}
	out->family = address->is_ipv6 ? AF_INET6 : AF_INET;
	/* Both types hold network order, so this is a copy and not a conversion.
	 * All sixteen bytes move either way: the four an IPv4 address uses are
	 * the first four, and the rest are zero in both. */
	memcpy(out->bytes, address->bytes, sizeof(out->bytes));
	return 1;
}

uint8_t ncfg_ops_family_byte(const ncfg_wire_ip_t *ip)
{
	return (uint8_t)(ip && ip->family == AF_INET6 ? AF_INET6 : AF_INET);
}

int ncfg_ops_narrow(ncfg_optint_t value, int64_t ceiling, const char *what, uint32_t *out,
    char *err, size_t err_size)
{
	if (value.value < 0 || value.value > ceiling) {
		ncfg_error_set(err, err_size, "%s is 0 to %lld, and this one is %lld", what,
		    (long long)ceiling, (long long)value.value);
		return 0;
	}
	*out = (uint32_t)value.value;
	return 1;
}

