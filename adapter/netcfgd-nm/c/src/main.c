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
#include "nmc/subtypes.h"
#include "nmc/emit.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

#define NMC_BUS_NAME     "org.freedesktop.NetworkManager"
#define NMC_MANAGER_PATH "/org/freedesktop/NetworkManager"
#define NMC_DEVICES_PATH "/org/freedesktop/NetworkManager/Devices"

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
	const nmc_object_t *manager;
} heartbeat_t;

/*
 * One pass over everything that has properties, emitting what moved.
 *
 * **Every wake, which is once a second.** NM pushes a signal the moment it
 * acts; this polls, because netcfgd offers no change notification to the
 * adapter and the alternative is a client that never learns. One second is the
 * loop's existing wake and costs one sweep of the properties -- which is a
 * socket round trip each, and is the cost `state.h` records as wrong for a
 * tray and right for being correct first.
 */
static void beat(void *context)
{
	heartbeat_t *beat_on = context;
	const char  *names[256];
	size_t       count;
	size_t       at;

	(void)nmc_watch_poll(beat_on->watch, beat_on->connection, beat_on->manager);
	count = nmc_store_enumerate_for_bus(names, sizeof(names) / sizeof(names[0]),
	    beat_on->store);
	for (at = 0u; at < count; at++) {
		char               path[96];
		nmc_device_slot_t *slot = nmc_store_resolve(beat_on->store, names[at]);
		nmc_object_t       device;

		if (!slot) {
			continue;
		}
		(void)snprintf(path, sizeof(path), "/org/freedesktop/NetworkManager/Devices/%s",
		    names[at]);
		device.path = path;
		device.interfaces = nmc_device_interfaces_for(slot);
		device.data = slot;
		if (device.interfaces) {
			(void)nmc_watch_poll(beat_on->watch, beat_on->connection, &device);
		}
	}
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
	nmc_watch_t           *watch;
	heartbeat_t            heartbeat;
	const nmc_interface_t *device_interfaces[] = { &nmc_device_interface, NULL };
	/* Both at the manager path, which is where NM serves its own and where
	 * 0264's policy gate expects to find `org.netcfgd.Compat`. */
	const nmc_interface_t *manager_interfaces[] = { &nmc_manager_interface,
		&nmc_compat_interface, NULL };
	const nmc_object_t     objects[] = {
		{ NMC_MANAGER_PATH, manager_interfaces, &state }
	};

	nmc_state_init(&state, NULL);
	nmc_store_init(&store, &state);
	state.store = (struct nmc_store *)&store;
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
			    .context = &store }
		};

		heartbeat.connection = connection;
		heartbeat.watch = watch;
		heartbeat.store = &store;
		heartbeat.manager = &objects[0];
		if (!nmc_bus_serve(connection, objects, sizeof(objects) / sizeof(objects[0]),
		        subtrees, sizeof(subtrees) / sizeof(subtrees[0]), beat, &heartbeat, err,
		        sizeof(err))) {
			fprintf(stderr, "netcfgd-nm: %s\n", err);
			nmc_watch_free(watch);
			nmc_store_free(&store);
			nmc_state_free(&state);
			return 1;
		}
	}
	nmc_watch_free(watch);
	nmc_store_free(&store);
	nmc_state_free(&state);
	return 0;
}
