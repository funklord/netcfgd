/*
 * main.c -- claim the name and answer.
 *
 * `main.rs`'s shape: the system bus by default, `--session` for a test, and
 * the name claimed with DO_NOT_QUEUE so that a second shim fails loudly
 * instead of waiting behind the first.
 */
#include "nmc/bus.h"
#include "nmc/compat.h"
#include "nmc/manager.h"
#include "nmc/device.h"
#include "nmc/store.h"
#include "nmc/subtypes.h"
#include "nmc/emit.h"
#include "nmc/settings.h"
#include "nmc/ipconfig.h"
#include "nmc/active.h"
#include "nmc/accesspoint.h"
#include "nmc/agent.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

#define NMC_BUS_NAME     "org.freedesktop.NetworkManager"
#define NMC_MANAGER_PATH "/org/freedesktop/NetworkManager"
#define NMC_DEVICES_PATH "/org/freedesktop/NetworkManager/Devices"
#define NMC_SETTINGS_PATH "/org/freedesktop/NetworkManager/Settings"
#define NMC_IP4_PATH      "/org/freedesktop/NetworkManager/IP4Config"
#define NMC_IP6_PATH      "/org/freedesktop/NetworkManager/IP6Config"
#define NMC_ACTIVE_PATH   "/org/freedesktop/NetworkManager/ActiveConnection"
#define NMC_AP_PATH       "/org/freedesktop/NetworkManager/AccessPoint"
#define NMC_AGENT_PATH    "/org/freedesktop/NetworkManager/AgentManager"

static void asked_to_stop(int signal_number)
{
	(void)signal_number;
	nmc_bus_stop();
}

/* What the tick needs: the connection to send on, and what to look at. */
typedef struct {
	DBusConnection     *connection;
	nmc_watch_t        *watch;
	nmc_store_t        *store;
	nmc_connections_t  *connections;
	nmc_aps_t          *aps;
	const nmc_object_t *manager;
	/* Which object this tick looks at. See `beat`. */
	size_t              cursor;
} heartbeat_t;

/*
 * **One object per tick, round-robin, and that is a defect fix rather than a
 * refinement.**
 *
 * This used to sweep everything every wake. With no cache, every property is
 * socket round trips -- and as the interfaces landed, one sweep grew past ten
 * devices times thirty-one properties times three calls each. A sweep then took
 * longer than the tick, `dbus_connection_read_write_dispatch` never ran, and
 * **the shim answered nothing at all**: a `Register` call sat until its client
 * gave up, and so did every property read.
 *
 * It was latent from the day the poll was added and became visible only when
 * enough interfaces existed to cross one second. It also means the measurement
 * that said "no signals in eight seconds on a converged machine" (10.359) was
 * taken on a loop that may already have been starving, which is why the
 * detector has a direct test and not only that observation.
 *
 * So a tick looks at ONE object and moves on. A full sweep takes as many
 * seconds as there are objects, which is the right trade for change
 * notification: a client learns within N seconds instead of never.
 *
 * The real fix is one fetch per tick shared by every getter, which is the cache
 * `emit.rs` keeps -- and it belongs with the next slice rather than inside a
 * bisect.
 */
/*
 * The membership signals: what appeared and what went.
 *
 * **Every tick rather than round-robin**, because each is one windowed fetch and
 * because a device appearing is the event a client most wants promptly -- a
 * cable going in should not wait for the cursor to come round.
 *
 * NM emits these on the manager and the settings object, and the access point
 * ones on the radio whose scan they came from. The path matters: a client
 * subscribes per object.
 */
static void announce_membership(heartbeat_t *beat_on)
{
	const char *names[256];
	const char *added[64];
	const char *gone[64];
	size_t      count;
	size_t      added_count = 0u;
	size_t      gone_count = 0u;
	size_t      at;
	char        path[96];

	count = nmc_store_enumerate_for_bus(names, sizeof(names) / sizeof(names[0]),
	    beat_on->store);
	if (nmc_watch_set(beat_on->watch, "devices", names, count, added, &added_count, gone,
	        &gone_count, sizeof(added) / sizeof(added[0]))) {
		for (at = 0u; at < added_count; at++) {
			(void)snprintf(path, sizeof(path),
			    "/org/freedesktop/NetworkManager/Devices/%s", added[at]);
			nmc_emit_path(beat_on->connection, NMC_MANAGER_PATH,
			    "org.freedesktop.NetworkManager", "DeviceAdded", path);
		}
		for (at = 0u; at < gone_count; at++) {
			(void)snprintf(path, sizeof(path),
			    "/org/freedesktop/NetworkManager/Devices/%s", gone[at]);
			nmc_emit_path(beat_on->connection, NMC_MANAGER_PATH,
			    "org.freedesktop.NetworkManager", "DeviceRemoved", path);
		}
	}

	count = nmc_connections_enumerate_for_bus(names, sizeof(names) / sizeof(names[0]),
	    beat_on->connections);
	if (nmc_watch_set(beat_on->watch, "connections", names, count, added, &added_count, gone,
	        &gone_count, sizeof(added) / sizeof(added[0]))) {
		for (at = 0u; at < added_count; at++) {
			(void)snprintf(path, sizeof(path), "%s/%s", NMC_SETTINGS_PATH, added[at]);
			nmc_emit_path(beat_on->connection, NMC_SETTINGS_PATH,
			    "org.freedesktop.NetworkManager.Settings", "NewConnection", path);
		}
		for (at = 0u; at < gone_count; at++) {
			(void)snprintf(path, sizeof(path), "%s/%s", NMC_SETTINGS_PATH, gone[at]);
			nmc_emit_path(beat_on->connection, NMC_SETTINGS_PATH,
			    "org.freedesktop.NetworkManager.Settings", "ConnectionRemoved",
			    path);
		}
	}

	/*
	 * The access point signals go on the RADIO's path and not the manager's,
	 * and the radio is found rather than assumed: a machine with no wifi has
	 * none, and emitting on a device that is not a radio would be a signal on
	 * an interface that device does not serve.
	 */
	count = nmc_aps_enumerate_for_bus(names, sizeof(names) / sizeof(names[0]),
	    beat_on->aps);
	if (nmc_watch_set(beat_on->watch, "aps", names, count, added, &added_count, gone,
	        &gone_count, sizeof(added) / sizeof(added[0]))) {
		/*
		 * Found by lookup rather than assumed: the scan store already
		 * records which radio it asked, and the store already knows that
		 * name's path. Building one here would be a second answer to a
		 * question something else owns.
		 */
		const char *radio = nmc_store_path_for(beat_on->store,
		    beat_on->aps->interface);

		if (radio) {
			for (at = 0u; at < added_count; at++) {
				(void)snprintf(path, sizeof(path),
				    "/org/freedesktop/NetworkManager/AccessPoint/%s", added[at]);
				nmc_emit_path(beat_on->connection, radio,
				    "org.freedesktop.NetworkManager.Device.Wireless",
				    "AccessPointAdded", path);
			}
			for (at = 0u; at < gone_count; at++) {
				(void)snprintf(path, sizeof(path),
				    "/org/freedesktop/NetworkManager/AccessPoint/%s", gone[at]);
				nmc_emit_path(beat_on->connection, radio,
				    "org.freedesktop.NetworkManager.Device.Wireless",
				    "AccessPointRemoved", path);
			}
		}
	}
}

/*
 * `StateChanged`, which carries what the state WAS.
 *
 * A `PropertiesChanged` on `State` says only where it got to, and "went to
 * disconnected" and "has been disconnected" are then the same message. NM's
 * signal carries both, so the old value is kept for it -- which the property
 * detector cannot supply, since it overwrites what it remembered.
 *
 * The reason is 0, `NM_DEVICE_STATE_REASON_NONE`: netcfgd gives none, and
 * guessing which of NM's forty applied would be worse than saying nothing.
 */
static void announce_state(heartbeat_t *beat_on, const char *path, const char *interface,
    const char *key, unsigned long now, int with_reason)
{
	unsigned long was = 0u;
	dbus_uint32_t values[3];

	if (!nmc_watch_number(beat_on->watch, key, now, &was)) {
		return;
	}
	values[0] = (dbus_uint32_t)now;
	values[1] = (dbus_uint32_t)was;
	values[2] = 0u;
	nmc_emit_numbers(beat_on->connection, path, interface, "StateChanged", values,
	    with_reason ? 3u : 1u);
}

static void beat(void *context)
{
	heartbeat_t *beat_on = context;
	const char  *names[256];
	size_t       count;
	size_t       which;

	/* The poll reads the same properties a dispatch does, so it wants the
	 * same window -- otherwise one tick would be the sixty-two fetches that
	 * starved this loop in the first place. */
	nmc_window_begin();
	count = nmc_store_enumerate_for_bus(names, sizeof(names) / sizeof(names[0]),
	    beat_on->store);
	/* The manager is index 0 and each device follows it. */
	if (beat_on->cursor > count) {
		beat_on->cursor = 0u;
	}
	announce_membership(beat_on);
	which = beat_on->cursor++;
	if (which == 0u) {
		(void)nmc_watch_poll(beat_on->watch, beat_on->connection, beat_on->manager);
		/* The manager's own state, which NM emits as one `u`. */
		announce_state(beat_on, NMC_MANAGER_PATH, "org.freedesktop.NetworkManager",
		    "manager.state", nmc_manager_state_now(beat_on->manager->data), 0);
		nmc_window_end();
		return;
	}
	which--;
	if (which < count) {
		char               path[96];
		nmc_device_slot_t *slot = nmc_store_resolve(beat_on->store, names[which]);
		nmc_object_t       device;

		if (!slot) {
			nmc_window_end();
			return;
		}
		(void)snprintf(path, sizeof(path), "/org/freedesktop/NetworkManager/Devices/%s",
		    names[which]);
		device.path = path;
		device.interfaces = nmc_device_interfaces_for(slot);
		device.data = slot;
		if (device.interfaces) {
			char key[160];

			(void)nmc_watch_poll(beat_on->watch, beat_on->connection, &device);
			/* This device's own transition, keyed on its path so two
			 * devices cannot share a remembered state. */
			(void)snprintf(key, sizeof(key), "%s.state", path);
			announce_state(beat_on, path,
			    "org.freedesktop.NetworkManager.Device", key,
			    nmc_device_state_now(slot), 1);
		}
	}
	nmc_window_end();
}

static void usage(void)
{
	printf("netcfgd-nm -- serve org.freedesktop.NetworkManager from netcfgd\n"
	    "\n"
	    "  netcfgd-nm [--session]\n"
	    "\n"
	    "  --session   claim the name on the session bus instead (for testing)\n"
	    "  --version   print the version and exit\n");
}

int main(int argc, char **argv)
{
	int                    session = 0;
	DBusError              problem;
	DBusConnection        *connection;
	int                    claimed;
	char                   err[NMC_ERROR_MAX] = "";
	nmc_state_t            state;
	nmc_store_t            store;
	nmc_connections_t      connections;
	nmc_aps_t              aps;
	nmc_agents_t           agents;
	nmc_watch_t           *watch;
	heartbeat_t            heartbeat;
	const nmc_interface_t *device_interfaces[] = { &nmc_device_interface, NULL };
	const nmc_interface_t *settings_interfaces[] = { &nmc_settings_interface, NULL };
	const nmc_interface_t *connection_interfaces[] = { &nmc_connection_interface, NULL };
	const nmc_interface_t *ip4_interfaces[] = { &nmc_ip4config_interface, NULL };
	const nmc_interface_t *ip6_interfaces[] = { &nmc_ip6config_interface, NULL };
	const nmc_interface_t *active_interfaces[] = { &nmc_active_interface, NULL };
	const nmc_interface_t *ap_interfaces[] = { &nmc_accesspoint_interface, NULL };
	const nmc_interface_t *agent_interfaces[] = { &nmc_agentmanager_interface, NULL };
	/* Both at the manager path, which is where NM serves its own and where
	 * 0264's policy gate expects to find `org.netcfgd.Compat`. */
	const nmc_interface_t *manager_interfaces[] = { &nmc_manager_interface,
		&nmc_compat_interface, NULL };
	const nmc_object_t     objects[] = {
		{ NMC_MANAGER_PATH, manager_interfaces, &state },
		/* Its own path, as NM serves it, and its data is the registry
		 * rather than the state: nothing else reads the agents yet. */
		{ NMC_AGENT_PATH, agent_interfaces, &agents }
	};

	nmc_state_init(&state, NULL);
	nmc_store_init(&store, &state);
	nmc_connections_init(&connections, &state);
	nmc_aps_init(&aps, &state);
	nmc_agents_init(&agents);
	state.store = (struct nmc_store *)&store;
	state.connections = (struct nmc_connections *)&connections;
	state.access_points = &aps;
	watch = nmc_watch_new();
	if (!watch) {
		fprintf(stderr, "netcfgd-nm: no memory to watch for changes\n");
		return 1;
	}

	if (argc > 1) {
		if (strcmp(argv[1], "--session") == 0) {
			session = 1;
		} else if (strcmp(argv[1], "--help") == 0) {
			usage();
			return 0;
		} else if (strcmp(argv[1], "--version") == 0) {
			printf("netcfgd-nm 0.1.0\n");
			return 0;
		} else {
			fprintf(stderr, "netcfgd-nm: unknown option `%s`\n", argv[1]);
			usage();
			return 2;
		}
	}

	/* So a stop is a stop and not a kill: the loop unregisters its paths. */
	(void)signal(SIGINT, asked_to_stop);
	(void)signal(SIGTERM, asked_to_stop);

	dbus_error_init(&problem);
	connection = dbus_bus_get(session ? DBUS_BUS_SESSION : DBUS_BUS_SYSTEM, &problem);
	if (!connection) {
		fprintf(stderr, "netcfgd-nm: cannot reach the %s bus: %s\n",
		    session ? "session" : "system",
		    dbus_error_is_set(&problem) ? problem.message : "no reason given");
		dbus_error_free(&problem);
		return 1;
	}
	/*
	 * **Not `dbus_connection_set_exit_on_disconnect`'s default.** libdbus
	 * calls `exit()` on a disconnect unless told otherwise, which would
	 * take the shim down past its own cleanup -- and the loop already
	 * treats a lost bus as an orderly end.
	 */
	dbus_connection_set_exit_on_disconnect(connection, FALSE);

	/*
	 * Before the name is claimed, so no agent can register into a registry
	 * that is not yet watching for it going away.
	 */
	if (!nmc_agents_watch(&agents, connection, err, sizeof(err))) {
		fprintf(stderr, "netcfgd-nm: %s\n", err);
		return 1;
	}

	claimed = dbus_bus_request_name(connection, NMC_BUS_NAME, DBUS_NAME_FLAG_DO_NOT_QUEUE,
	    &problem);
	if (claimed != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		fprintf(stderr,
		    "netcfgd-nm: cannot claim %s: %s\n"
		    "netcfgd-nm:   something already owns it -- NetworkManager itself, or "
		    "another shim.\n",
		    NMC_BUS_NAME,
		    dbus_error_is_set(&problem) ? problem.message : "the name is taken");
		dbus_error_free(&problem);
		return 1;
	}
	dbus_error_free(&problem);

	{
		/* Designated, so a member added to `nmc_subtree_t` cannot
		 * silently shift what these mean -- which it just did. */
		const nmc_subtree_t subtrees[] = {
			{ .prefix = NMC_DEVICES_PATH,
			    .interfaces = device_interfaces,
			    .interfaces_for = nmc_device_interfaces_for,
			    .resolve = nmc_store_resolve_for_bus,
			    .enumerate = nmc_store_enumerate_for_bus,
			    .context = &store },
			/* One interface for every connection, so no
			 * `interfaces_for`: a saved network is a saved network. */
			{ .prefix = NMC_SETTINGS_PATH,
			    /* The prefix serves `...Settings` and each child a
			     * `...Settings.Connection`, which is NM's shape and
			     * is why one path cannot be both an object and a
			     * fallback. */
			    .root_interfaces = settings_interfaces,
			    .root_data = &state,
			    .interfaces = connection_interfaces,
			    .resolve = nmc_connections_resolve_for_bus,
			    .enumerate = nmc_connections_enumerate_for_bus,
			    .context = &connections },
			/*
			 * All three keyed by the DEVICE's number and resolving
			 * through its store, because netcfgd has one addressing
			 * and one active thing per interface -- so a second
			 * numbering would be a second thing able to disagree
			 * about which config belongs to which device.
			 */
			{ .prefix = NMC_IP4_PATH,
			    .interfaces = ip4_interfaces,
			    .resolve = nmc_store_resolve_for_bus,
			    .enumerate = nmc_store_enumerate_for_bus,
			    .context = &store },
			{ .prefix = NMC_IP6_PATH,
			    .interfaces = ip6_interfaces,
			    .resolve = nmc_store_resolve_for_bus,
			    .enumerate = nmc_store_enumerate_for_bus,
			    .context = &store },
			{ .prefix = NMC_ACTIVE_PATH,
			    .interfaces = active_interfaces,
			    .resolve = nmc_store_resolve_for_bus,
			    .enumerate = nmc_store_enumerate_for_bus,
			    .context = &store },
			/* The one family NOT keyed by a device: a scan result's
			 * identity is its BSSID, so it has a store of its own. */
			{ .prefix = NMC_AP_PATH,
			    .interfaces = ap_interfaces,
			    .resolve = nmc_aps_resolve_for_bus,
			    .enumerate = nmc_aps_enumerate_for_bus,
			    .context = &aps }
		};

		heartbeat.connection = connection;
		heartbeat.watch = watch;
		heartbeat.store = &store;
		heartbeat.connections = &connections;
		heartbeat.aps = &aps;
		heartbeat.manager = &objects[0];
		heartbeat.cursor = 0u;
		if (!nmc_bus_serve(connection, objects, sizeof(objects) / sizeof(objects[0]),
		        subtrees, sizeof(subtrees) / sizeof(subtrees[0]), beat, &heartbeat, err,
		        sizeof(err))) {
			fprintf(stderr, "netcfgd-nm: %s\n", err);
			nmc_watch_free(watch);
			nmc_agents_unwatch(&agents, connection);
			nmc_agents_free(&agents);
			nmc_aps_free(&aps);
			nmc_connections_free(&connections);
			nmc_store_free(&store);
			nmc_state_free(&state);
			return 1;
		}
	}
	nmc_watch_free(watch);
	nmc_agents_unwatch(&agents, connection);
	nmc_agents_free(&agents);
	nmc_aps_free(&aps);
	nmc_connections_free(&connections);
	nmc_store_free(&store);
	nmc_state_free(&state);
	return 0;
}
