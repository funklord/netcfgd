/* agent.c -- the agent registry, keyed on the connection the bus reports. */
#include "nmc/agent.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static nmc_agent_t *found(nmc_agents_t *agents, const char *bus_name)
{
	size_t at;

	for (at = 0u; at < agents->count; at++) {
		if (strcmp(agents->at[at].bus_name, bus_name) == 0) {
			return &agents->at[at];
		}
	}
	return NULL;
}

void nmc_agents_init(nmc_agents_t *agents)
{
	memset(agents, 0, sizeof(*agents));
}

void nmc_agents_free(nmc_agents_t *agents)
{
	free(agents->at);
	memset(agents, 0, sizeof(*agents));
}

size_t nmc_agents_count(const nmc_agents_t *agents)
{
	return agents ? agents->count : 0u;
}

int nmc_agents_add(nmc_agents_t *agents, const char *bus_name, const char *identifier,
    int capabilities)
{
	nmc_agent_t *slot = found(agents, bus_name);

	if (!slot) {
		if (agents->count == agents->capacity) {
			size_t       bigger = agents->capacity ? agents->capacity * 2u : 8u;
			nmc_agent_t *grown = realloc(agents->at, bigger * sizeof(*grown));

			if (!grown) {
				return 0;
			}
			agents->at = grown;
			agents->capacity = bigger;
		}
		slot = &agents->at[agents->count++];
		memset(slot, 0, sizeof(*slot));
		(void)snprintf(slot->bus_name, sizeof(slot->bus_name), "%s", bus_name);
	}
	/*
	 * A second `Register` from one connection REPLACES rather than adds: NM
	 * allows an agent to re-register, and two entries for one connection would
	 * mean asking it twice for one secret.
	 */
	(void)snprintf(slot->identifier, sizeof(slot->identifier), "%s",
	    identifier ? identifier : "");
	slot->capabilities = capabilities;
	return 1;
}

int nmc_agents_drop(nmc_agents_t *agents, const char *bus_name)
{
	nmc_agent_t *slot = found(agents, bus_name);

	if (!slot) {
		return 0;
	}
	/* Swapped with the last rather than shifted: the order means nothing. */
	*slot = agents->at[agents->count - 1u];
	agents->count--;
	return 1;
}

/* -------------------------------------------------- agents that go away */

/*
 * `NameOwnerChanged` for a name we hold an agent under, which means it died.
 *
 * **A filter and not a method, because nobody calls this.** The bus sends it
 * and the shim has to be listening; without it the registry only grows, and the
 * shim would eventually ask a dead name for a passphrase and wait for a reply
 * that cannot come.
 *
 * `new_owner` empty is the case that matters: a name that changed hands is not
 * the agent going away, and dropping on any change would unregister an agent
 * that is still there.
 */
static DBusHandlerResult watch_names(DBusConnection *connection, DBusMessage *message,
    void *user)
{
	nmc_agents_t *agents = user;
	const char   *name = NULL;
	const char   *was = NULL;
	const char   *now = NULL;

	(void)connection;
	if (!dbus_message_is_signal(message, DBUS_INTERFACE_DBUS, "NameOwnerChanged")) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	if (!dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_STRING, &was,
	        DBUS_TYPE_STRING, &now, DBUS_TYPE_INVALID)) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	if (now && now[0] == '\0' && name) {
		if (nmc_agents_drop(agents, name)) {
			(void)fprintf(stderr,
			    "netcfgd-nm: the secret agent on %s went away; %zu left\n", name,
			    nmc_agents_count(agents));
		}
	}
	/* Not handled: a signal is for everyone, and claiming it would stop
	 * anything else that wanted to see it. */
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

int nmc_agents_watch(nmc_agents_t *agents, DBusConnection *connection, char *err,
    size_t err_size)
{
	DBusError problem;

	if (!dbus_connection_add_filter(connection, watch_names, agents, NULL)) {
		(void)snprintf(err, err_size, "no memory to watch for agents going away");
		return 0;
	}
	dbus_error_init(&problem);
	/*
	 * Narrowed to the signal wanted. A broad match would hand this process
	 * every name change on the bus, which on a desktop is a steady stream --
	 * and the filter above would do nothing with all of it.
	 */
	dbus_bus_add_match(connection,
	    "type='signal',sender='org.freedesktop.DBus',"
	    "interface='org.freedesktop.DBus',member='NameOwnerChanged'",
	    &problem);
	if (dbus_error_is_set(&problem)) {
		(void)snprintf(err, err_size, "cannot watch for agents going away: %s",
		    problem.message);
		dbus_error_free(&problem);
		dbus_connection_remove_filter(connection, watch_names, agents);
		return 0;
	}
	dbus_error_free(&problem);
	return 1;
}

void nmc_agents_unwatch(nmc_agents_t *agents, DBusConnection *connection)
{
	dbus_connection_remove_filter(connection, watch_names, agents);
}

/* ------------------------------------------------------- the interface */

/*
 * The caller's own bus name.
 *
 * **From the message's sender, which the bus fills in and a client cannot
 * forge.** This is the identity the whole registry is keyed on, so it is the
 * one place a mistake would let one process register or unregister as another.
 */
static const char *caller_of(DBusMessage *call, char *err, size_t err_size)
{
	const char *sender = dbus_message_get_sender(call);

	if (!sender || sender[0] == '\0') {
		(void)snprintf(err, err_size,
		    "the bus did not say who is calling, so there is no agent to register");
		return NULL;
	}
	return sender;
}

static int register_agent(DBusConnection *connection, DBusMessage *call, DBusMessage *reply,
    void *object, char *err, size_t err_size)
{
	const char *identifier = NULL;
	const char *sender;

	(void)connection;
	(void)reply;
	if (!dbus_message_get_args(call, NULL, DBUS_TYPE_STRING, &identifier, DBUS_TYPE_INVALID)) {
		(void)snprintf(err, err_size, "Register takes an identifier");
		return 0;
	}
	sender = caller_of(call, err, err_size);
	if (!sender) {
		return 0;
	}
	if (!nmc_agents_add(object, sender, identifier, 0)) {
		(void)snprintf(err, err_size, "no memory to remember this agent");
		return 0;
	}
	return 1;
}

static int register_with_capabilities(DBusConnection *connection, DBusMessage *call,
    DBusMessage *reply, void *object, char *err, size_t err_size)
{
	const char   *identifier = NULL;
	dbus_uint32_t capabilities = 0u;
	const char   *sender;

	(void)connection;
	(void)reply;
	if (!dbus_message_get_args(call, NULL, DBUS_TYPE_STRING, &identifier, DBUS_TYPE_UINT32,
	        &capabilities, DBUS_TYPE_INVALID)) {
		(void)snprintf(err, err_size,
		    "RegisterWithCapabilities takes an identifier and a capability mask");
		return 0;
	}
	sender = caller_of(call, err, err_size);
	if (!sender) {
		return 0;
	}
	/*
	 * The capability mask is remembered and not acted on. Its one flag is
	 * "this agent can show a VPN hint", and netcfgd has no VPN secrets to
	 * ask for -- so storing it keeps the agent's own statement without this
	 * build pretending to honour it.
	 */
	if (!nmc_agents_add(object, sender, identifier, (int)capabilities)) {
		(void)snprintf(err, err_size, "no memory to remember this agent");
		return 0;
	}
	return 1;
}

/*
 * `Unregister` takes no argument, and that is the security of it.
 *
 * NM's method is about the caller, so the subject is the sender and nothing
 * else. **Implementing it as "remove the name you were given" would let any
 * local process unregister a desktop's agent** and quietly become the thing
 * that answers for secrets. An unregister for a connection that registered
 * nothing succeeds silently, as NM's does: it is idempotent, and saying "you
 * had none" tells a caller about the registry rather than about itself.
 */
static int unregister_agent(DBusConnection *connection, DBusMessage *call, DBusMessage *reply,
    void *object, char *err, size_t err_size)
{
	const char *sender;

	(void)connection;
	(void)reply;
	sender = caller_of(call, err, err_size);
	if (!sender) {
		return 0;
	}
	(void)nmc_agents_drop(object, sender);
	return 1;
}

static const nmc_method_t METHODS[] = {
	{ "Register", "s", "", register_agent },
	{ "RegisterWithCapabilities", "su", "", register_with_capabilities },
	{ "Unregister", "", "", unregister_agent }
};

const nmc_interface_t nmc_agentmanager_interface = {
	.name = "org.freedesktop.NetworkManager.AgentManager",
	.methods = METHODS,
	.method_count = sizeof(METHODS) / sizeof(METHODS[0])
};
