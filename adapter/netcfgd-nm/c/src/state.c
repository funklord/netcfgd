/* state.c -- the client handle, opened late and reopened after a break. */
#include "nmc/state.h"

#include <stdio.h>
#include <string.h>

void nmc_state_init(nmc_state_t *state, const char *socket_path)
{
	memset(state, 0, sizeof(*state));
	state->socket_path = socket_path;
}

void nmc_state_free(nmc_state_t *state)
{
	if (state->client) {
		ncfg_client_close(state->client);
		state->client = NULL;
	}
}

void nmc_state_broke(nmc_state_t *state)
{
	if (state->client) {
		ncfg_client_close(state->client);
		state->client = NULL;
	}
}

ncfg_client_t *nmc_state_client(nmc_state_t *state)
{
	char err[256];

	if (!state) {
		return NULL;
	}
	/*
	 * **A broken client is dropped here rather than at the call that broke
	 * it.** `ncfg_client_broken` is the library's own answer and every
	 * caller would otherwise have to remember to ask; asking once, on the
	 * way in, means a daemon restart costs one failed property and not a
	 * shim that never reconnects.
	 */
	if (state->client && ncfg_client_broken(state->client)) {
		nmc_state_broke(state);
	}
	if (!state->client) {
		err[0] = '\0';
		state->client = ncfg_client_open(state->socket_path, err, sizeof(err));
	}
	return state->client;
}
