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

#include "ncfg_client.h"

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

/*
 * Ask the daemon what this connection may do.
 *
 * **This is the whole of 0128 from the agent's side, and it had never been
 * asked.** That record splits remote access in two: the agent decides who the
 * caller is, because it terminates fuzznet's protocol and the daemon sees only
 * a unix socket; and the daemon decides what remote can *ever* do, whoever it
 * is, because origin is which socket you arrived on and there is no field to
 * forge. The second half is the property worth having -- a compromised agent
 * reaches what the remote policy allows and not the machine.
 *
 * `ncfg_client_tiers` is the daemon answering exactly that question about the
 * caller in front of it, so pointing it at the remote socket is the bound
 * being read back rather than inferred. `control_exposure.sh` already checks
 * who may *open* that socket; nothing has ever connected to it and been told
 * what it may do.
 *
 * Read-only, and it sends no configuration. An agent that could not ask this
 * would have to discover the bound by being refused.
 */
static int tiers_of(const char *socket_path)
{
	char            message[512] = "";
	ncfg_client_t  *client;
	ncfg_tiers_t    tiers;
	int             ok;

	client = ncfg_client_open(socket_path, message, sizeof(message));
	if (!client) {
		(void)fprintf(stderr, "netcfgd-remote: %s\n", message);
		return 1;
	}
	memset(&tiers, 0, sizeof(tiers));
	ok = ncfg_client_tiers(client, &tiers, message, sizeof(message));
	ncfg_client_close(client);
	if (!ok) {
		(void)fprintf(stderr, "netcfgd-remote: %s\n", message);
		return 1;
	}
	(void)printf("observe %d  wifi %d  admin %d\n", tiers.observe, tiers.wifi, tiers.admin);
	return 0;
}

static void usage(void)
{
	(void)printf("netcfgd-remote --peek            read one frame on stdin, say what it is\n");
	(void)printf("netcfgd-remote --tiers [socket]  ask the daemon what this connection may do\n");
	(void)printf("netcfgd-remote --version\n");
	(void)printf("\n");
	(void)printf("The UDP listener and forwarding a received frame's request are not\n");
	(void)printf("built yet. There is no capability-to-tier mapping to build: 0128 makes\n");
	(void)printf("the remote policy a set of tiers rather than principals, and the daemon\n");
	(void)printf("enforces it by which socket a connection arrived on.\n");
}

int main(int argc, char **argv)
{
	if (argc == 2 && strcmp(argv[1], "--peek") == 0) {
		return peek_from_stdin();
	}
	if (argc >= 2 && strcmp(argv[1], "--tiers") == 0) {
		/* NULL is the client library's own default path, which is the local
		 * socket. Naming the remote one is the case this exists for. */
		return tiers_of(argc > 2 ? argv[2] : NULL);
	}
	if (argc == 2 && strcmp(argv[1], "--version") == 0) {
		(void)printf("netcfgd-remote -- Copyright (C) 2026 Nabeel Sowan "
		             "<nabeel@vibes.se>\n");
		return 0;
	}
	usage();
	return argc == 2 && strcmp(argv[1], "--help") == 0 ? 0 : 2;
}
