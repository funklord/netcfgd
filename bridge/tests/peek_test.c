/*
 * peek_test.c -- the bridge's read path, against a frame this file builds.
 *
 * WHY THIS EXISTS AT ALL
 *   Everything `netcfgd-remote --peek` had been shown doing was *refusing*: a
 *   zeroed frame comes back `FZN_SEAL_ERR_SHAPE`, empty stdin is told apart
 *   from it, and both are correct. **A program that can only refuse looks
 *   exactly like one that refuses everything.** Until a frame that verifies
 *   goes in and the right fields come out, the read path is unmeasured.
 *
 *   That control was impossible before the crypto backend was chosen, which is
 *   the whole reason 0269 named it as the next decision: fuzznet's crypto is a
 *   vtable, `wire/seal.o` carries no undefined AEAD symbol, and a frame that
 *   verifies cannot be produced without one.
 *
 * WHAT THIS IS NOT
 *   **Not a copy of fuzznet's golden vector.** That array has provenance --
 *   produced by a different tree's build and reproduced byte for byte before
 *   being committed -- and it answers "do two independently written builds
 *   agree". Copying it here would put a second copy of somebody else's fixture
 *   in this tree and answer a question netcfgd is not asking.
 *
 *   This asks the narrower thing netcfgd actually needs: **a frame built by
 *   the library reads back through the bridge's own path with its fields
 *   intact.** It freezes nothing and would notice `fzn_seal_peek` being
 *   miswired, a field being read from the wrong offset, or the bridge
 *   compiling against headers whose objects it is not linking.
 */
#include "session/aead.h"
#include "session/aead_monocypher.h"
#include "session/hash_monocypher.h"
#include "session/random.h"
#include "wire/seal.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check(int condition, const char *what)
{
	checks++;
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* Fixed bytes where the library asks for entropy, so the frame is the same on
 * every run. This replaces the SOURCE the library draws a nonce from and not
 * the nonce itself -- `fzn_seal_build` refuses a caller-supplied nonce, and
 * `session/random.h` says what repeating one under XChaCha20-Poly1305 costs. */
static int fixed_fill(void *ctx, uint8_t *out, size_t len)
{
	size_t i;

	(void)ctx;
	for (i = 0u; i < len; i++) {
		out[i] = (uint8_t)(0xa0u + i);
	}
	return 1;
}

#define PAYLOAD_LEN 24u

static const uint8_t KEY[FZN_AEAD_KEY_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8 };
static const uint8_t COMMITMENT_KEY[FZN_COMMITMENT_KEY_LEN] = { 9, 10, 11, 12 };
static const uint8_t SENDER[32] = { 0x55, 0xaa };
static const uint8_t CAPABILITY[32] = { 0x77, 0xff };
static const uint8_t PAYLOAD[PAYLOAD_LEN] = "netcfgd reads this frame";

int main(void)
{
	fzn_aead_ops_t   aead;
	fzn_hash_ops_t   hash;
	fzn_random_ops_t rng = { fixed_fill, NULL };
	fzn_send_t       what;
	fzn_peek_t       peek;
	uint8_t          frame[FZN_SEAL_OVERHEAD + PAYLOAD_LEN];
	uint8_t          frame_kept[FZN_SEAL_OVERHEAD + PAYLOAD_LEN];
	size_t           frame_len = 0u;
	fzn_seal_err_t   verdict;

	fzn_aead_monocypher_init(&aead);
	fzn_hash_monocypher_init(&hash);
	/* **The control's own control.** A binding that left a null op would make
	 * every check below pass or fail for a reason that has nothing to do with
	 * the read path. */
	check(aead.seal != NULL && aead.open != NULL && hash.hash != NULL,
	    "the Monocypher bindings are wired, so the rest is about the real algorithm");

	memset(&what, 0, sizeof(what));
	what.sender = SENDER;
	what.capability = CAPABILITY;
	what.payload = PAYLOAD;
	what.payload_len = PAYLOAD_LEN;
	what.expires_at = 1790000000u;
	what.msg = 0x11223344u;
	what.index = 2;
	what.chunks = 5;
	what.kind = 1;
	what.hops = 3;

	verdict = fzn_seal_build(frame, sizeof(frame), &frame_len, &what, KEY, COMMITMENT_KEY,
	    &hash, &rng, &aead);
	check(verdict == FZN_SEAL_OK, "a frame can be built at all, so there is something to read");

	memset(&peek, 0, sizeof(peek));
	verdict = fzn_seal_peek(frame, frame_len, &peek);
	check(verdict == FZN_SEAL_OK, "and the bridge's own read accepts it");

	/* Each field separately: a peek that returned OK and filled nothing would
	 * satisfy the line above on its own. */
	check(peek.kind == 1u, "the kind survives the round trip");
	check(peek.msg == 0x11223344u, "and the message id");
	check(peek.index == 2u && peek.chunks == 5u, "and which chunk of how many");
	check(peek.expires_at == 1790000000u, "and when it expires");

	/* Kept before the zeroing below, because the program needs the real one. */
	memcpy(frame_kept, frame, frame_len);

	/* And the refusal that was all this program could previously show, kept
	 * beside the acceptance so the pair discriminates rather than either one
	 * alone. */
	memset(frame, 0, sizeof(frame));
	check(fzn_seal_peek(frame, sizeof(frame), &peek) != FZN_SEAL_OK,
	    "while a zeroed frame of the same length is still refused");

	/*
	 * **And the program, because everything above tests fuzznet.**
	 *
	 * The checks so far call `fzn_seal_peek` directly, so they would pass
	 * unchanged against a `netcfgd-remote` that read the wrong descriptor,
	 * printed the wrong field, or was linked against objects it was not
	 * compiled for. That is `a correct function is not a working feature`,
	 * and the seam this whole program exists to hold is the one they skip.
	 *
	 * So the frame goes through the actual binary, on its actual stdin.
	 */
	{
		FILE *out;
		char  line[512] = "";
		char  command[256];
		int   status;

		out = fopen("tests/frame.bin", "wb");
		if (out && fwrite(frame_kept, 1u, frame_len, out) == frame_len) {
			(void)fclose(out);
			(void)snprintf(command, sizeof(command),
			    "./netcfgd-remote --peek < tests/frame.bin");
			out = popen(command, "r");
			if (out) {
				if (!fgets(line, sizeof(line), out)) {
					line[0] = '\0';
				}
				status = pclose(out);
				check(status == 0,
				    "the program accepts a real frame on stdin and exits 0");
				check(strstr(line, "kind 1") != NULL &&
				        strstr(line, "msg 287454020") != NULL,
				    "and prints the fields it read, not a default");
				check(strstr(line, "chunk 2 of 5") != NULL,
				    "including which chunk of how many");
			} else {
				check(0, "the program could be run");
			}
		} else {
			check(0, "a frame could be written for the program to read");
		}
		(void)remove("tests/frame.bin");
	}

	printf("peek_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("peek_test: all checks passed\n");
	} else {
		printf("peek_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
