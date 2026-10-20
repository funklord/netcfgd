/* agent.c -- the agent registry, keyed on the connection the bus reports. */
#include "nmc/agent.h"
#include "nmc/block.h"
#include "nmc/settings.h"

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

/* ------------------------------------------------- asking one of them */

/*
 * Where a secret agent answers, and the flags that say a person is waiting.
 *
 * `ALLOW_INTERACTION` and `USER_REQUESTED`, which is what lets an agent put a
 * dialog on the screen instead of failing quietly -- a desktop asked without
 * them answers only from what it has already stored.
 */
#define NMC_AGENT_PATH      "/org/freedesktop/NetworkManager/SecretAgent"
#define NMC_AGENT_INTERFACE "org.freedesktop.NetworkManager.SecretAgent"
#define NMC_SECRET_GROUP    "802-11-wireless-security"
#define NMC_AGENT_FLAGS     0x5u

/*
 * How long to wait for an answer.
 *
 * **A person is being asked, so this is a dialog's lifetime rather than a
 * round trip.** libdbus's own default is 25 seconds, which is also GDBus's --
 * and two parties timing out at the same number is how 0107's circular wait
 * came to depend on which one noticed first. 90 seconds is long enough that
 * the agent is the one that gives up, and bounded so a dead agent cannot
 * wedge the shim for ever.
 *
 * **The shim answers nothing while this is outstanding**, which is the cost of
 * a blocking call in a single-threaded loop and is why the caller's own agent
 * is never asked. It is also why the activation should become asynchronous:
 * until it does, a dialog left open stops every other client being served.
 */
#define NMC_AGENT_TIMEOUT_MS 90000

/* Whether the bus still has an owner for that name. */
static int still_there(DBusConnection *connection, const char *name)
{
	DBusMessage *ask = dbus_message_new_method_call("org.freedesktop.DBus",
	    "/org/freedesktop/DBus", "org.freedesktop.DBus", "NameHasOwner");
	DBusMessage *reply;
	DBusError    problem;
	dbus_bool_t  owned = FALSE;

	if (!ask) {
		return 0;
	}
	if (!dbus_message_append_args(ask, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID)) {
		dbus_message_unref(ask);
		return 0;
	}
	dbus_error_init(&problem);
	reply = dbus_connection_send_with_reply_and_block(connection, ask, 5000, &problem);
	dbus_message_unref(ask);
	if (!reply) {
		dbus_error_free(&problem);
		return 0;
	}
	if (!dbus_message_get_args(reply, NULL, DBUS_TYPE_BOOLEAN, &owned, DBUS_TYPE_INVALID)) {
		owned = FALSE;
	}
	dbus_message_unref(reply);
	dbus_error_free(&problem);
	return owned ? 1 : 0;
}

/*
 * Ask one agent for the passphrase of the profile `slot` describes.
 *
 * Answers 1 with `out` filled, 0 where the agent could not be reached at all,
 * and -1 where it was reached and refused -- which is a person pressing cancel
 * and is not a fault to report as one, so the message says what happened
 * rather than naming an internal failure.
 */
static int ask_one(DBusConnection *connection, const char *name,
    nmc_connection_slot_t *slot, const char *path, char *out, size_t cap, char *err,
    size_t err_size)
{
	DBusMessage    *ask;
	DBusMessage    *reply;
	DBusMessageIter args;
	DBusMessageIter hints;
	DBusError       problem;
	const char     *group = NMC_SECRET_GROUP;
	dbus_uint32_t   flags = NMC_AGENT_FLAGS;
	int             answered;

	ask = dbus_message_new_method_call(name, NMC_AGENT_PATH, NMC_AGENT_INTERFACE,
	    "GetSecrets");
	if (!ask) {
		return 0;
	}
	/* `a{sa{sv}}osasu`: the profile, its path, the setting being asked about,
	 * the hints, and the flags. The dictionary is the one `GetSettings`
	 * answers with, appended by the same code. */
	if (!nmc_settings_append(ask, slot, err, err_size)) {
		dbus_message_unref(ask);
		return 0;
	}
	dbus_message_iter_init_append(ask, &args);
	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_OBJECT_PATH, &path) ||
	    !dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &group) ||
	    !dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "s", &hints)) {
		dbus_message_unref(ask);
		return 0;
	}
	/* No hints. NM uses them to name the one key it wants; the group is
	 * already that narrow here, and an invented hint would be a key this
	 * shim does not read back. */
	(void)dbus_message_iter_close_container(&args, &hints);
	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_UINT32, &flags)) {
		dbus_message_unref(ask);
		return 0;
	}

	dbus_error_init(&problem);
	reply = dbus_connection_send_with_reply_and_block(connection, ask,
	    NMC_AGENT_TIMEOUT_MS, &problem);
	dbus_message_unref(ask);
	if (!reply) {
		(void)snprintf(err, err_size,
		    "the secret agent `%s` did not supply a passphrase: %s", name,
		    dbus_error_is_set(&problem) ? problem.message : "no answer");
		dbus_error_free(&problem);
		return -1;
	}
	dbus_error_free(&problem);
	answered = nmc_block_passphrase_in(reply, out, cap);
	dbus_message_unref(reply);
	if (!answered) {
		(void)snprintf(err, err_size,
		    "the secret agent `%s` answered without a passphrase in it", name);
		return -1;
	}
	return 1;
}

int nmc_agents_supply(nmc_agents_t *agents, DBusConnection *connection, nmc_state_t *state,
    const char *asker, nmc_connection_slot_t *slot, const char *name, char *err,
    size_t err_size)
{
	char           passphrase[128] = "";
	char           path[96];
	ncfg_client_t *client = nmc_state_client(state);
	size_t         at;
	int            asked = 0;

	if (!agents || !connection || !slot || !name || !client) {
		return 0;
	}
	(void)snprintf(path, sizeof(path), "%s/%u", NMC_SETTINGS_PATH, slot->number);
	for (at = 0u; at < agents->count && asked == 0; at++) {
		const char *who = agents->at[at].bus_name;

		/*
		 * **Never the caller, and this is not an optimisation.** A secret is
		 * asked for from inside `ActivateConnection`, before it returns, so a
		 * client that registered an agent of its own and then activated a
		 * profile is sitting on a blocking call waiting for this very reply
		 * and cannot answer a question. `nmcli` does exactly that -- it
		 * registers an agent for `connection up` -- and asking it is a
		 * circular wait that unwinds at whichever side times out first,
		 * intermittently (0107).
		 *
		 * Real NetworkManager avoids it by returning the activation path and
		 * asking during the asynchronous activation that follows, with the
		 * caller free by then. Until this shim's activation is asynchronous
		 * too, the caller is the one party that provably cannot answer, and
		 * skipping it costs nothing: any other agent is still asked.
		 */
		if (asker && strcmp(asker, who) == 0) {
			continue;
		}
		/*
		 * An agent whose process has gone leaves its registration behind
		 * until `NameOwnerChanged` arrives. Asking the bus at the moment it
		 * matters gets the same answer with no window in which a stale entry
		 * is believed -- and drops it, so the next activation does not ask
		 * again.
		 */
		if (!still_there(connection, who)) {
			(void)nmc_agents_drop(agents, who);
			at--;
			continue;
		}
		asked = ask_one(connection, who, slot, path, passphrase, sizeof(passphrase), err,
		    err_size);
	}
	if (asked != 1) {
		/* Nothing to ask, or an agent that refused. The refusal's sentence is
		 * already in `err`; with nobody to ask there is no sentence, because
		 * netcfgd's own "secret was not found" is better than one about
		 * agents on a machine that has no desktop. */
		explicit_bzero(passphrase, sizeof(passphrase));
		return asked;
	}
	/*
	 * **Stored through netcfgd, and never replaced.** 0031's bridge is an
	 * agent answering a request for a credential, so a value already on disk
	 * means the request should not have been made -- and overwriting a
	 * credential is the one thing 0042 says nobody can undo. The caller
	 * authorized for `admin` before this was reached, which is the same
	 * permission storing it needs: a desktop that may not change the
	 * configuration may not fill in its secrets either, and the second is how
	 * you would work around the first.
	 */
	if (!ncfg_client_secret_put(client, name, passphrase, 0, err, err_size)) {
		explicit_bzero(passphrase, sizeof(passphrase));
		return -1;
	}
	explicit_bzero(passphrase, sizeof(passphrase));
	return 1;
}

/*
 * The credential this network needs and netcfgd does not hold, or "" .
 *
 * **Asked of netcfgd rather than of the filesystem**, which is the rule `ours`
 * follows in `settings.c`: the daemon owns `/etc/netcfgd` and is therefore the
 * authority on what is in it. `ncfg_client_secrets` answers with the union of
 * what the store holds and what the configuration refers to, and `stored` is
 * the half that says which -- a referenced name with no file is exactly this
 * case, and it is the one the daemon's own listing already names as a fault.
 */
void nmc_agents_credential_wanted(nmc_state_t *state, const char *id, char *out, size_t cap)
{
	const ncfg_saved_networks_t *saved = nmc_state_saved(state);
	ncfg_client_t               *client = nmc_state_client(state);
	ncfg_secrets_t               secrets;
	char                         problem[NMC_ERROR_MAX] = "";
	const char                  *wanted = NULL;
	size_t                       at;

	if (cap > 0u) {
		out[0] = '\0';
	}
	if (!saved || !client || !id) {
		return;
	}
	for (at = 0u; at < saved->count; at++) {
		if (saved->items[at].id && strcmp(saved->items[at].id, id) == 0) {
			wanted = saved->items[at].credential;
			break;
		}
	}
	if (!wanted || wanted[0] == '\0') {
		/* An open or OWE network refers to no credential, and an agent has
		 * nothing to be asked for. */
		return;
	}
	memset(&secrets, 0, sizeof(secrets));
	if (!ncfg_client_secrets(client, &secrets, problem, sizeof(problem))) {
		/* Cannot tell. Saying nothing is wanted leaves the activation to fail
		 * on netcfgd's own terms, which is the better of the two wrong
		 * answers: the other invents a prompt for a credential that may
		 * already be there. */
		return;
	}
	for (at = 0u; at < secrets.count; at++) {
		if (secrets.items[at].name && strcmp(secrets.items[at].name, wanted) == 0 &&
		    secrets.items[at].stored) {
			ncfg_secrets_free(&secrets);
			return;
		}
	}
	ncfg_secrets_free(&secrets);
	(void)snprintf(out, cap, "%s", wanted);
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
