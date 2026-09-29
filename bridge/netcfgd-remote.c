/*
 * netcfgd-remote.c -- the unprivileged side of netcfgd's remote access.
 *
 * WHY THIS IS A SEPARATE PROGRAM AND NOT PART OF THE DAEMON
 *   `doc/shared-protocol-brief.md` section 3 fixes it, and design section 11.3
 *   before that: **the daemon never grows a network listener.** Whatever
 *   speaks UDP is a separate process holding an ordinary local socket
 *   connection, exactly as the NetworkManager shim does for D-Bus. So fuzznet
 *   is linked here and never by the process holding `CAP_NET_ADMIN`, and a
 *   fault in framing, signing or reassembly reaches an unprivileged program
 *   rather than the one that configures the machine.
 *
 * WHAT IS BUILT, AND WHAT IS DELIBERATELY NOT
 *   Built: reading a frame and asking fuzznet what it is. That is the first
 *   step of receiving one, it needs no policy, and it proves the seam --
 *   netcfgd's build linking fuzznet's wire layer and getting a real answer out
 *   of it.
 *
 *   **Not built, and not stubbed either: the UDP socket, the local connection
 *   to netcfgd, and the capability-to-tier mapping.** The last is the one to
 *   be careful about. The brief says a remote capability must map onto
 *   `observe`, `wifi` and `admin` (0013) rather than introduce a parallel
 *   vocabulary, and those tiers are independent rather than a ladder (0092).
 *   *How* a `fzn_cap_id_t` names one of them -- fixed ids, a policy file, a
 *   grant carried in the chain -- is a design decision, and inventing one here
 *   because it was the next thing to write is how a security boundary acquires
 *   a shape nobody chose.
 *
 *   A program that refuses what it has not built says so; it does not open a
 *   socket that does nothing.
 */
#include "wire/seal.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* A datagram this is willing to read. fuzznet chunks anything longer, and the
 * reassembly that undoes it is not wired here yet. */
#define REMOTE_FRAME_MAX 65536u

static int peek_from_stdin(void)
{
	static unsigned char frame[REMOTE_FRAME_MAX];
	size_t               got;
	fzn_peek_t           peek;
	fzn_seal_err_t       err;

	got = fread(frame, 1u, sizeof(frame), stdin);
	if (got == 0u) {
		(void)fprintf(stderr, "netcfgd-remote: nothing to read on stdin\n");
		return 2;
	}
	memset(&peek, 0, sizeof(peek));
	err = fzn_seal_peek(frame, got, &peek);
	if (err != FZN_SEAL_OK) {
		/* fuzznet's own number, not a sentence of this program's. The
		 * vocabulary is the library's and a translation here would be a
		 * second, partial copy of it. */
		(void)fprintf(stderr, "netcfgd-remote: fuzznet refused the frame (%d)\n",
		    (int)err);
		return 1;
	}
	(void)printf("kind %u  msg %u  chunk %u of %u  expires_at %llu\n", (unsigned)peek.kind,
	    (unsigned)peek.msg, (unsigned)peek.index, (unsigned)peek.chunks,
	    (unsigned long long)peek.expires_at);
	return 0;
}

static void usage(void)
{
	(void)printf("netcfgd-remote --peek   read one frame on stdin and say what it is\n");
	(void)printf("netcfgd-remote --version\n");
	(void)printf("\n");
	(void)printf("The UDP listener, the connection to netcfgd and the mapping from a\n");
	(void)printf("capability to netcfgd's observe/wifi/admin tiers are not built yet.\n");
}

int main(int argc, char **argv)
{
	if (argc == 2 && strcmp(argv[1], "--peek") == 0) {
		return peek_from_stdin();
	}
	if (argc == 2 && strcmp(argv[1], "--version") == 0) {
		(void)printf("netcfgd-remote -- Copyright (C) 2026 Nabeel Sowan "
		             "<nabeel@vibes.se>\n");
		return 0;
	}
	usage();
	return argc == 2 && strcmp(argv[1], "--help") == 0 ? 0 : 2;
}
