/*
 * main.c -- claim the name and answer.
 *
 * `main.rs`'s shape: the system bus by default, `--session` for a test, and
 * the name claimed with DO_NOT_QUEUE so that a second shim fails loudly
 * instead of waiting behind the first.
 */
#include "nmc/bus.h"
#include "nmc/compat.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

#define NMC_BUS_NAME     "org.freedesktop.NetworkManager"
#define NMC_MANAGER_PATH "/org/freedesktop/NetworkManager"

static void asked_to_stop(int signal_number)
{
	(void)signal_number;
	nmc_bus_stop();
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
	const nmc_interface_t *manager_interfaces[] = { &nmc_compat_interface, NULL };
	const nmc_object_t     objects[] = {
		{ NMC_MANAGER_PATH, manager_interfaces, NULL }
	};

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

	if (!nmc_bus_serve(connection, objects, sizeof(objects) / sizeof(objects[0]), err,
	        sizeof(err))) {
		fprintf(stderr, "netcfgd-nm: %s\n", err);
		return 1;
	}
	return 0;
}
