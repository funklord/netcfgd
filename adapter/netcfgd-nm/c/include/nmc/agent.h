/*
 * nmc/agent.h -- `AgentManager`: who has offered to be asked for a secret.
 *
 * Design section 9.3: clients register a secret agent and expect to be asked
 * for a passphrase. **It runs in one direction only** -- an agent supplies a
 * credential, netcfgd's provider stores it, and the configuration keeps a
 * `@secret:` reference. Nothing travels the other way, and `GetSecrets` on a
 * profile still refuses (0029, and `settings.c` where it does).
 *
 * THREE THINGS THIS GETS RIGHT ON PURPOSE
 *   **The bus name is the SENDER's, never an argument.** An agent is identified
 *   by the connection it registered from, which the bus reports and the client
 *   cannot choose -- the same property `authorize.h` rests on. A registry keyed
 *   on something a caller supplied would let one process register as another.
 *
 *   **`Unregister` removes only the caller's own.** NM's method takes no
 *   argument precisely because the caller is the subject; implementing it as
 *   "remove the name you were given" would let any local process unregister a
 *   desktop's agent and quietly take over answering for secrets.
 *
 *   **An agent whose connection goes away is dropped.** Without that the
 *   registry only grows, and the shim would ask a dead name for a passphrase
 *   and wait. `NameOwnerChanged` is what says so, which is why this needs a
 *   message filter rather than only a method table.
 */
#ifndef NMC_AGENT_H
#define NMC_AGENT_H

#include "nmc/bus.h"
#include "nmc/settings.h"

#include <stddef.h>

typedef struct {
	char bus_name[64];   /* `:1.42`, as the bus reports it */
	char identifier[96]; /* what the agent called itself */
	int  capabilities;
} nmc_agent_t;

typedef struct {
	nmc_agent_t *at;
	size_t       count;
	size_t       capacity;
} nmc_agents_t;

void nmc_agents_init(nmc_agents_t *agents);
void nmc_agents_free(nmc_agents_t *agents);

/* Remember, or update, the agent on `bus_name`. 0 only out of memory. */
int nmc_agents_add(nmc_agents_t *agents, const char *bus_name, const char *identifier,
    int capabilities);

/* Forget the agent on `bus_name`. Answers whether one was there. */
int nmc_agents_drop(nmc_agents_t *agents, const char *bus_name);

size_t nmc_agents_count(const nmc_agents_t *agents);

/*
 * Ask a registered agent for a network's passphrase and store it through
 * netcfgd.
 *
 * `asker` is the bus name that asked for the activation, and is never asked
 * itself: it is blocked on the call this runs inside and cannot answer. `name`
 * is the credential netcfgd is missing, which `nmc_agents_credential_wanted`
 * answers.
 *
 * Answers 1 where a credential was stored, 0 where there was nobody to ask --
 * the ordinary state of a machine with no desktop, and the caller then lets
 * the activation fail on netcfgd's own terms rather than inventing a complaint
 * about agents -- and -1 where an agent was asked and refused, with `err`
 * carrying the sentence a person pressing cancel produces.
 *
 * **The caller has already authorized**, which is why no uid is passed:
 * storing a credential is an `admin` write and `ActivateConnection` requires
 * the same tier before it reaches this. Asking twice would be one question
 * with two answers that can come to disagree.
 */
int nmc_agents_supply(nmc_agents_t *agents, DBusConnection *connection, nmc_state_t *state,
    const char *asker, nmc_connection_slot_t *slot, const char *name, char *err,
    size_t err_size);

/*
 * The credential a network refers to and netcfgd does not hold, or "" where
 * there is nothing to ask for.
 */
void nmc_agents_credential_wanted(nmc_state_t *state, const char *id, char *out, size_t cap);

/* Watch for agents whose connection goes away, and drop them. */
int nmc_agents_watch(nmc_agents_t *agents, DBusConnection *connection, char *err,
    size_t err_size);
void nmc_agents_unwatch(nmc_agents_t *agents, DBusConnection *connection);

/* Its object data is an `nmc_agents_t *`. */
extern const nmc_interface_t nmc_agentmanager_interface;

#endif /* NMC_AGENT_H */
