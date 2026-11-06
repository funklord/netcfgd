/*
 * user_host.c -- `ncfg host`: this user's host (project.md 10.734).
 *
 * WHAT IT IS
 *   fuzznet's node, which is a call, with netcfgd's numbers written in. A
 *   client and a node are the same thing with different code around the core:
 *   the daemon is the machine's, with the network code around it, and this is
 *   the person's, with nothing around it. `--at`, `ncfg hosts`, the fleet view
 *   and the phone all reach other hosts through one, and nothing installs
 *   fuzznetd, which is only here to be shown to coexist.
 *
 * COEXISTING
 *   The user's store is fuzznet's default, shared with every other fuzznet
 *   program of this person's. The first to start is the face and the rest
 *   follow. The extension is what makes this one follow rather than exit:
 *   fuzznet ends a follower with none, having nothing for it to do.
 *
 * ITS LIFE (0314)
 *   `--while-held` is how a client starts it: it stops within a second of no client
 *   holding the lock beside its socket, so nothing of this person's outlives what
 *   they are doing (0315). The lock it takes to stop is kept to the exit, so a client
 *   arriving then waits and starts another. Typed by hand it stays up until stopped.
 *
 *   A phone's is the app's child, so none of that is built there.
 *
 * THE PORT
 *   Any free one. The host's daemon holds netcfgd's own, a machine has both,
 *   and this node starts every conversation it has.
 */
#include "ncfg/node.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#include "chain/service.h"
#include "ncfg_fuzznet.h"
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

#ifndef __ANDROID__
/* From `tick`, which runs after every pass: a look a second, and it stops the
 * first time nobody holds it. A client coming in as it goes waits for the lock and
 * then starts another, which costs about 15 ms, so nothing is gained by lingering. */
static void held_tick(void *context, uint64_t now)
{
	static uint64_t last;
	static int      fd = -1;
	char            path[1100];

	(void)context;
	if (now == last) {
		return;
	}
	last = now;
	if (fd < 0) {
		if (!ncfg_fuzznet_user_lock(path, sizeof(path))) {
			return;
		}
		fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
		if (fd < 0) {
			return;
		}
	}
	if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
		fzn_daemon_stop(); /* and the lock is kept to the exit */
	}
}
#endif

int ncfg_host_user_main(int argc, char **argv, int skip)
{
	static fzn_daemon_ext_t ext;
	static char            *args[ARGS_MAX + 4];
	static char             service[32];
	static char             product[32];
	int                     count = 0;
	int                     at;

	if (argc > ARGS_MAX) {
		fprintf(stderr, "ncfg host: more than %d arguments\n", ARGS_MAX);
		return 2;
	}
	args[count++] = argv[0];
	for (at = 1 + skip; at < argc; at++) {
#ifndef __ANDROID__
		if (strcmp(argv[at], "--while-held") == 0) {
			ext.tick = held_tick;
			continue;
		}
#endif
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
