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

static int hex_digit(char one, uint8_t *out)
{
	if (one >= '0' && one <= '9') {
		*out = (uint8_t)(one - '0');
		return 1;
	}
	if (one >= 'a' && one <= 'f') {
		*out = (uint8_t)(one - 'a' + 10);
		return 1;
	}
	if (one >= 'A' && one <= 'F') {
		*out = (uint8_t)(one - 'A' + 10);
		return 1;
	}
	return 0;
}

int ncfg_ops_parse_mac(const char *text, uint8_t out[6], char *err, size_t err_size)
{
	size_t at = 0;
	int octet;

	if (!text || !out) {
		ncfg_error_set(err, err_size, "a hardware address needs somewhere to go");
		return 0;
	}
	for (octet = 0; octet < 6; octet++) {
		uint8_t high;
		uint8_t low;

		if (octet > 0) {
			if (text[at] != ':') {
				ncfg_error_set(err, err_size,
				    "a hardware address is six colon-separated octets and `%s` is not",
				    text);
				return 0;
			}
			at++;
		}
		/*
		 * Exactly two digits, where `u8::from_str_radix` takes one or
		 * three-that-overflow and the Rust's `split(':')` would accept
		 * `1:2:3:4:5:6`. Two is what the kernel prints and what every other
		 * reader in this project writes, and a length that varies per octet
		 * is a spelling nothing downstream compares equal.
		 */
		if (!hex_digit(text[at], &high) || !hex_digit(text[at + 1u], &low)) {
			ncfg_error_set(err, err_size,
			    "`%s` has an octet that is not two hex digits", text);
			return 0;
		}
		out[octet] = (uint8_t)((high << 4) | low);
		at += 2u;
	}
	if (text[at] != '\0') {
		ncfg_error_set(err, err_size, "`%s` is longer than a hardware address", text);
		return 0;
	}
	return 1;
}
