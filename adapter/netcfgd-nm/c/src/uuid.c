/*
 * uuid.c -- the connection UUIDs, derived rather than stored.
 *
 * WHY DERIVED
 *   Design section 9.3, and constraint 1 behind it: a stored UUID is state
 *   outside netcfgd's configuration files. Derived as `UUIDv5` over a fixed
 *   namespace and the profile's identity, the same configuration produces the
 *   same UUIDs on another machine, and a client's stored reference survives a
 *   restart because nothing generated it in the first place.
 *
 * WHY A SHA-1 IS IN HERE
 *   UUIDv5 is defined as a SHA-1, and nothing this adapter links provides one:
 *   libdbus has no digest and netcfgd's C client has no need of one. So it is
 *   written here, 70 lines, used for exactly this.
 *
 *   **It is not a general-purpose hash and must not be used as one.** SHA-1 is
 *   broken for anything that needs collision resistance. A UUIDv5 does not: it
 *   is a naming function whose only requirement is that the same name gives the
 *   same answer everywhere, and the standard says to use SHA-1 for it. Anything
 *   that needs a real digest asks fuzznet, which has one.
 *
 * HOW IT IS CHECKED
 *   Two ways, and the second is the one that matters. The SHA-1 is checked
 *   against FIPS 180's own published vectors, taken from the standard rather
 *   than from this implementation -- a vector produced by running this code
 *   would be one witness twice. And the UUIDs are checked against the values
 *   the Rust shim's `uuid` crate produces for this project's own namespace,
 *   which is an independent implementation of the same standard reached by a
 *   different route.
 */
#include "nmc/uuid.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ SHA-1 */

typedef struct {
	unsigned long  state[5];
	unsigned char  block[64];
	size_t         held;
	unsigned long  length; /* in bits, and 32 bits of it is plenty here */
} sha1_t;

static unsigned long rotate(unsigned long value, int by)
{
	/* Masked, because `unsigned long` is wider than 32 bits on this platform
	 * and a rotate that let the high bits live would not be a SHA-1. */
	value &= 0xffffffffUL;
	return ((value << by) | (value >> (32 - by))) & 0xffffffffUL;
}

static void absorb(sha1_t *hash, const unsigned char *block)
{
	unsigned long words[80];
	unsigned long a = hash->state[0];
	unsigned long b = hash->state[1];
	unsigned long c = hash->state[2];
	unsigned long d = hash->state[3];
	unsigned long e = hash->state[4];
	int           at;

	for (at = 0; at < 16; at++) {
		words[at] = ((unsigned long)block[at * 4] << 24) |
		    ((unsigned long)block[at * 4 + 1] << 16) |
		    ((unsigned long)block[at * 4 + 2] << 8) | (unsigned long)block[at * 4 + 3];
	}
	for (at = 16; at < 80; at++) {
		words[at] = rotate(words[at - 3] ^ words[at - 8] ^ words[at - 14] ^ words[at - 16],
		    1);
	}
	for (at = 0; at < 80; at++) {
		unsigned long mixed;
		unsigned long constant;

		if (at < 20) {
			mixed = (b & c) | (~b & d);
			constant = 0x5a827999UL;
		} else if (at < 40) {
			mixed = b ^ c ^ d;
			constant = 0x6ed9eba1UL;
		} else if (at < 60) {
			mixed = (b & c) | (b & d) | (c & d);
			constant = 0x8f1bbcdcUL;
		} else {
			mixed = b ^ c ^ d;
			constant = 0xca62c1d6UL;
		}
		mixed = (rotate(a, 5) + (mixed & 0xffffffffUL) + e + constant + words[at]) &
		    0xffffffffUL;
		e = d;
		d = c;
		c = rotate(b, 30);
		b = a;
		a = mixed;
	}
	hash->state[0] = (hash->state[0] + a) & 0xffffffffUL;
	hash->state[1] = (hash->state[1] + b) & 0xffffffffUL;
	hash->state[2] = (hash->state[2] + c) & 0xffffffffUL;
	hash->state[3] = (hash->state[3] + d) & 0xffffffffUL;
	hash->state[4] = (hash->state[4] + e) & 0xffffffffUL;
}

static void sha1_begin(sha1_t *hash)
{
	hash->state[0] = 0x67452301UL;
	hash->state[1] = 0xefcdab89UL;
	hash->state[2] = 0x98badcfeUL;
	hash->state[3] = 0x10325476UL;
	hash->state[4] = 0xc3d2e1f0UL;
	hash->held = 0u;
	hash->length = 0u;
}

static void sha1_add(sha1_t *hash, const unsigned char *bytes, size_t count)
{
	size_t at;

	for (at = 0u; at < count; at++) {
		hash->block[hash->held++] = bytes[at];
		hash->length += 8u;
		if (hash->held == sizeof(hash->block)) {
			absorb(hash, hash->block);
			hash->held = 0u;
		}
	}
}

static void sha1_end(sha1_t *hash, unsigned char out[20])
{
	unsigned long bits = hash->length;
	unsigned char tail[8];
	unsigned char pad = 0x80u;
	unsigned char zero = 0x00u;
	int           at;

	for (at = 0; at < 8; at++) {
		/* The length is 64 bits big-endian; the top four bytes are zero for
		 * anything this ever hashes, which is a name of a few dozen bytes. */
		tail[at] = at < 4 ? 0u : (unsigned char)((bits >> ((7 - at) * 8)) & 0xffu);
	}
	sha1_add(hash, &pad, 1u);
	/* The length is counted inside `sha1_add`, so padding to 56 has to be
	 * measured against the count as it grows rather than against a remembered
	 * one -- the first version subtracted from a stale `held`. */
	while (hash->held != 56u) {
		sha1_add(hash, &zero, 1u);
	}
	/* Appending the length must not advance it, so it goes in by hand. */
	for (at = 0; at < 8; at++) {
		hash->block[hash->held++] = tail[at];
	}
	absorb(hash, hash->block);
	hash->held = 0u;
	for (at = 0; at < 20; at++) {
		out[at] = (unsigned char)((hash->state[at / 4] >> ((3 - (at % 4)) * 8)) & 0xffu);
	}
}

void nmc_sha1(const void *bytes, size_t count, unsigned char out[20])
{
	sha1_t hash;

	sha1_begin(&hash);
	sha1_add(&hash, bytes, count);
	sha1_end(&hash, out);
}

/* ------------------------------------------------------------- the UUIDs */

/*
 * The namespace this project derives connection UUIDs in.
 *
 * An ordinary random v4 UUID, generated once and written down. It has no
 * meaning beyond being ours and never changing: **changing it renames every
 * profile every client has ever seen.** It is the same constant `settings.rs`
 * carries, and the two agreeing is what makes a client's stored reference
 * survive the port.
 */
static const unsigned char NAMESPACE[16] = { 0x4e, 0xd6, 0x29, 0x0d, 0x37, 0x61, 0x40, 0x5c,
	0x8a, 0xd8, 0x0d, 0x40, 0xf2, 0x58, 0xee, 0x63 };

void nmc_uuid_of(const char *identity, char *out, size_t out_size)
{
	unsigned char digest[20];
	sha1_t        hash;

	if (!out || out_size == 0u) {
		return;
	}
	out[0] = '\0';
	if (!identity) {
		return;
	}
	sha1_begin(&hash);
	sha1_add(&hash, NAMESPACE, sizeof(NAMESPACE));
	sha1_add(&hash, (const unsigned char *)identity, strlen(identity));
	sha1_end(&hash, digest);
	/*
	 * The version and variant bits, which are what make this a v5 rather than
	 * twenty bytes of hash: the top nibble of octet 6 is the version, and the
	 * top two bits of octet 8 are the RFC 4122 variant.
	 */
	digest[6] = (unsigned char)((digest[6] & 0x0fu) | 0x50u);
	digest[8] = (unsigned char)((digest[8] & 0x3fu) | 0x80u);
	(void)snprintf(out, out_size,
	    "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", digest[0],
	    digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
	    digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14],
	    digest[15]);
}
