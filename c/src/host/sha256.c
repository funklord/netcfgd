/*
 * sha256.c -- the one digest in the C port.
 *
 * WHY IT IS HERE
 *   The Rust keeps this in `netcfgd-model` so that the hash a hook is written
 *   with and the hash checked before it is executed cannot disagree.
 *   `document.h` is final and carries no hash, so the port's one copy lives
 *   beside the module that needs it first and every other caller uses this
 *   one. Two implementations of a digest is a hook refused at execution time
 *   for a difference nobody can see.
 *
 * WHY NOT A LIBRARY
 *   netcfgd links libc and the kernel and nothing else; taking OpenSSL for
 *   sixty lines of arithmetic would put a package on every machine that runs
 *   this daemon. The published vectors are in `hooks_test.c`, including the
 *   55/56/64-byte padding boundaries, because an implementation that is nearly
 *   right is worth nothing and looks fine.
 */
#include "ncfg/hooks.h"

#include <stdint.h>
#include <string.h>

/* FIPS 180-4, the first thirty-two bits of the fractional parts of the cube
 * roots of the first sixty-four primes. */
static const uint32_t K[64] = {
	0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
	0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
	0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
	0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
	0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
	0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
	0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
	0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
	0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
	0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
	0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static uint32_t rotate_right(uint32_t value, unsigned int bits)
{
	return (value >> bits) | (value << (32u - bits));
}

/* One 64-byte block into the eight words of state. */
static void compress(uint32_t state[8], const unsigned char block[64])
{
	uint32_t w[64];
	uint32_t a, b, c, d, e, f, g, h;
	unsigned int i;

	for (i = 0; i < 16u; i++) {
		w[i] = ((uint32_t)block[i * 4u] << 24) | ((uint32_t)block[i * 4u + 1u] << 16) |
		    ((uint32_t)block[i * 4u + 2u] << 8) | (uint32_t)block[i * 4u + 3u];
	}
	for (i = 16u; i < 64u; i++) {
		uint32_t s0 = rotate_right(w[i - 15u], 7u) ^ rotate_right(w[i - 15u], 18u) ^
		    (w[i - 15u] >> 3);
		uint32_t s1 = rotate_right(w[i - 2u], 17u) ^ rotate_right(w[i - 2u], 19u) ^
		    (w[i - 2u] >> 10);
		w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
	}

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];

	for (i = 0; i < 64u; i++) {
		uint32_t s1 = rotate_right(e, 6u) ^ rotate_right(e, 11u) ^ rotate_right(e, 25u);
		uint32_t choose = (e & f) ^ ((~e) & g);
		uint32_t temp1 = h + s1 + choose + K[i] + w[i];
		uint32_t s0 = rotate_right(a, 2u) ^ rotate_right(a, 13u) ^ rotate_right(a, 22u);
		uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
		uint32_t temp2 = s0 + majority;

		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}

void ncfg_sha256_hex(const void *bytes, size_t length, char *out)
{
	static const char digits[] = "0123456789abcdef";
	uint32_t state[8] = { 0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
		0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u };
	const unsigned char *input = bytes;
	unsigned char tail[128];
	size_t whole = length / 64u;
	size_t rest = length % 64u;
	size_t tail_length;
	uint64_t bits = (uint64_t)length * 8u;
	size_t i;

	if (!out) {
		return;
	}
	for (i = 0; i < whole; i++) {
		compress(state, input + i * 64u);
	}

	/*
	 * The padding, in one buffer rather than a streaming state machine: the
	 * longest tail is 55 bytes of message, the 0x80, up to 63 zeros and the
	 * eight length bytes, which is two blocks. 55, 56 and 64 take different
	 * paths through this and an off-by-one here is invisible on short input,
	 * which is why the test pins all three.
	 */
	memset(tail, 0, sizeof(tail));
	if (rest) {
		memcpy(tail, input + whole * 64u, rest);
	}
	tail[rest] = 0x80u;
	tail_length = (rest < 56u) ? 64u : 128u;
	for (i = 0; i < 8u; i++) {
		tail[tail_length - 1u - i] = (unsigned char)((bits >> (8u * (unsigned int)i)) & 0xffu);
	}
	compress(state, tail);
	if (tail_length == 128u) {
		compress(state, tail + 64u);
	}

	for (i = 0; i < 8u; i++) {
		unsigned int shift;

		for (shift = 4u; shift-- > 0u;) {
			unsigned int nibble = (unsigned int)(state[i] >> (shift * 8u + 4u)) & 0xfu;

			out[i * 8u + (3u - shift) * 2u] = digits[nibble];
			nibble = (unsigned int)(state[i] >> (shift * 8u)) & 0xfu;
			out[i * 8u + (3u - shift) * 2u + 1u] = digits[nibble];
		}
	}
	out[64] = '\0';
}
