/*
 * user_node.c -- `ncfg node`: this user's node (project.md 10.734).
 *
 * WHAT IT IS
 *   fuzznet's node, which is a call, with netcfgd's numbers written in. A
 *   client and a node are the same thing with different code around the core:
 *   the daemon is the machine's, with the network code around it, and this is
 *   the person's, with nothing around it. `--at`, `ncfg nodes`, the fleet view
 *   and the phone all reach other hosts through one, and nothing installs
 *   fuzznetd, which is only here to be shown to coexist.
 *
 * COEXISTING
 *   The user's store is fuzznet's default, shared with every other fuzznet
 *   program of this person's. The first to start is the face and the rest
 *   follow. The extension is what makes this one follow rather than exit:
 *   fuzznet ends a follower with none, having nothing for it to do.
 *
 * THE PORT
 *   Any free one. The host's daemon holds netcfgd's own, a machine has both,
 *   and this node starts every conversation it has.
 */
#include "ncfg/node.h"

#include <stdio.h>
#include <string.h>

#include "chain/service.h"
#include "node/daemon.h"

#define ARGS_MAX 32

static int given(int argc, char **argv, const char *option)
{
	const size_t length = strlen(option);
	int          at;

	for (at = 1; at < argc; at++) {
		if (strncmp(argv[at], option, length) == 0) {
			return 1;
		}
	}
	return 0;
}

int ncfg_node_user_main(int argc, char **argv, int skip)
{
	static fzn_daemon_ext_t ext;
	static char            *args[ARGS_MAX + 4];
	static char             service[32];
	static char             product[32];
	int                     count = 0;
	int                     at;

	if (argc > ARGS_MAX) {
		fprintf(stderr, "ncfg node: more than %d arguments\n", ARGS_MAX);
		return 2;
	}
	args[count++] = argv[0];
	for (at = 1 + skip; at < argc; at++) {
		args[count++] = argv[at];
	}
	if (!given(argc, argv, "--fuzznet-service")) {
		(void)snprintf(service, sizeof(service), "--fuzznet-service=%u", FZN_SERVICE_NODE);
		args[count++] = service;
	}
	if (!given(argc, argv, "--fuzznet-product")) {
		(void)snprintf(product, sizeof(product), "--fuzznet-product=%u", FZN_PRODUCT_NETCFGD);
		args[count++] = product;
	}
	if (!given(argc, argv, "--udp-port")) {
		args[count++] = (char *)"--udp-port=0";
	}
	args[count] = NULL;
	/* Taking the claim starts the process again: as it was typed, or `ncfg`
	 * would be handed fuzznet's options with no `node` before them. */
	ext.restart_argv = argv;
	return fzn_daemon_main(count, args, &ext);
}
