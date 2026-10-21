/*
 * What netcfgd answers, as the three programs that link this library read it.
 *
 * WHY THIS IS THE LIBRARY'S OWN TARGET AND NOT THE DAEMON'S
 *   `libncfg_client.a` is linked by `ncfg`, by the Qt client and by the
 *   NetworkManager shim, and every one of them learns what the machine is
 *   doing by calling a reader here. A reader takes a socket's reply and builds
 *   C structures with allocated strings and counted arrays -- framing, then
 *   JSON, then a typed walk -- and the JSON layer is the only one of the three
 *   that was fuzzed, from the daemon's side (`c/fuzz/document_json` reaches
 *   `ncfg_json_parse` through `ncfg_document_read`). The typed walk above it
 *   had nothing.
 *
 * IS THE DAEMON NOT TRUSTED?
 *   The socket is `root:netcfgd` and netcfgd is what answers on it, so this is
 *   not the hostile boundary that netlink or a D-Bus client is. It is a
 *   boundary all the same, and for two reasons worth stating rather than
 *   assuming: the path is settable -- `$NCFG_RUN_DIR`, and
 *   `ncfg_client_open(path)` takes one -- so a client can be pointed at a
 *   socket somebody else owns; and a daemon one version ahead of the library
 *   answers with fields this build has never seen, which is the ordinary case
 *   on a machine mid-upgrade and is exactly what a typed walk gets wrong.
 *
 * HOW A REPLY IS DELIVERED WITHOUT A DAEMON, AND WITHOUT FORKING
 *   One listening unix socket, made once for the whole process. Per input:
 *   connect a client to it, accept the other end, **write the reply before
 *   calling the reader**, then shut the writing half down so the reader sees
 *   an end of stream rather than waiting for one.
 *
 *   The order is what makes this work in a single thread. A reader writes its
 *   request and then blocks reading the answer, so a target that called it
 *   first would have nobody to answer. Queued first, the bytes are already in
 *   the socket when the reader looks, and the request it writes lands in a
 *   buffer nobody reads -- which is fine, because it is one short line.
 *
 * TERMINATION AND WHAT IT LEAVES BEHIND
 *   No loop over anything but the reader table's one entry, nothing spawned,
 *   two descriptors opened and closed per input. The socket file is named for
 *   the process and unlinked by `atexit`, so a killed run leaves one empty
 *   socket in the temporary directory and nothing else.
 */
#include "fuzz.h"

#include "ncfg_client.h"

#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* `ncfg_tiers_t` holds three ints and owns nothing, so it has no free of its
 * own; the switch below needs something to call, and nothing is what it needs. */
static void free_nothing(const void *answer)
{
	(void)answer;
}

/*
 * ONE READER PER CASE, AND WHY THIS IS NOT A TABLE
 *   It was a table of twenty-one `{reader, free}` pairs with the `out`
 *   pointer cast to `void *`, which is four lines instead of eighty and is
 *   **undefined behaviour**: calling a function through a pointer of a
 *   different type is UB whatever the ABI does, and
 *   `-fsanitize=function` says so. It said so within seconds of the first
 *   run -- in the harness built to find other people's bugs, which is the
 *   joke and also the argument for pointing the sanitizers at a target and
 *   not only at what it drives.
 *
 *   So the dispatch is a macro over a switch: each case names the real type,
 *   calls the real function and frees with the real free, with no cast
 *   anywhere and the compiler checking all three against each other.
 */
#define DRIVE(type, call, release)                                                            \
	{                                                                                     \
		type answer;                                                                  \
		memset(&answer, 0, sizeof(answer));                                           \
		(void)call(client, &answer, err, sizeof(err));                                \
		/* Freed on BOTH outcomes, which is half of what this target is              \
		 * for: a walk that allocated four strings and then met a field it            \
		 * could not read must not leak them, and the caller cannot know how          \
		 * far it got. `ncfg_client.h` says freeing something never filled            \
		 * in is nothing, so every refusal exercises that contract. */                \
		release(&answer);                                                             \
	}

/* How many cases the switch has. Asserted against the switch by its own
 * `default`, which cannot be reached while this number is right. */
#define READER_COUNT 21u
/* What will be written into a socket nobody is draining. Well inside the
 * default unix buffer, so the write cannot block. */
#define REPLY_MAX 32768u

static int listener = -1;
/* Sized to `sun_path` rather than to taste: a path that does not fit there
 * cannot be bound, and truncating one would bind something else. */
static char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];

static void stop_listening(void)
{
	if (listener >= 0) {
		(void)close(listener);
		listener = -1;
	}
	if (socket_path[0] != '\0') {
		(void)unlink(socket_path);
		socket_path[0] = '\0';
	}
}

/* Once per process. 0 and a sentence on stderr where the socket cannot be
 * made, because a target that quietly stopped delivering replies would report
 * every input as handled. */
static int start_listening(void)
{
	struct sockaddr_un address;
	const char        *dir = getenv("TMPDIR");

	if (listener >= 0) {
		return 1;
	}
	if (snprintf(socket_path, sizeof(socket_path), "%s/ncfg-fuzz-%ld.sock",
	        dir ? dir : "/tmp", (long)getpid()) >= (int)sizeof(socket_path)) {
		fprintf(stderr, "replies: $TMPDIR makes a path longer than sun_path\n");
		socket_path[0] = '\0';
		return 0;
	}
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listener < 0) {
		fprintf(stderr, "replies: no socket: %s\n", strerror(errno));
		return 0;
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	memcpy(address.sun_path, socket_path, strlen(socket_path));
	(void)unlink(socket_path);
	if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
	    listen(listener, 16) != 0) {
		fprintf(stderr, "replies: cannot listen on %s: %s\n", socket_path,
		    strerror(errno));
		stop_listening();
		return 0;
	}
	(void)atexit(stop_listening);
	return 1;
}

int ncfg_fuzz_one(const unsigned char *data, size_t length)
{
	unsigned char  which;
	ncfg_client_t *client;
	char           err[NCFG_ERROR_MAX];
	int            served;
	size_t         reply_length;

	if (!length || !start_listening()) {
		return 0;
	}
	/* The first byte picks the reader, so that one mutation moves the input
	 * from one typed walk to another. */
	which = (unsigned char)(data[0] % READER_COUNT);
	data++;
	length--;

	client = ncfg_client_open(socket_path, err, sizeof(err));
	if (!client) {
		return 0;
	}
	served = accept(listener, NULL, NULL);
	if (served < 0) {
		ncfg_client_close(client);
		return 0;
	}
	(void)fcntl(served, F_SETFL, O_NONBLOCK);
	reply_length = length > REPLY_MAX ? REPLY_MAX : length;
	if (reply_length) {
		(void)write(served, data, reply_length);
	}
	/* A reply is a line. The fuzzer's bytes may hold any number of newlines,
	 * including none -- which is the end-of-stream-mid-line case the framing
	 * has to refuse rather than half-read. */
	(void)write(served, "\n", 1u);
	(void)shutdown(served, SHUT_WR);

	switch (which) {
	case 0:
		DRIVE(ncfg_tiers_t, ncfg_client_tiers, free_nothing)
		break;
	case 1:
		DRIVE(ncfg_links_t, ncfg_client_links, ncfg_links_free)
		break;
	case 2:
		DRIVE(ncfg_linksets_t, ncfg_client_linksets, ncfg_linksets_free)
		break;
	case 3:
		DRIVE(ncfg_inventory_t, ncfg_client_inventory, ncfg_inventory_free)
		break;
	case 4:
		DRIVE(ncfg_connectivity_t, ncfg_client_connectivity, ncfg_connectivity_free)
		break;
	case 5:
		DRIVE(ncfg_plan_t, ncfg_client_plan_of, ncfg_client_plan_free)
		break;
	case 6:
		DRIVE(ncfg_rules_t, ncfg_client_rules, ncfg_rules_free)
		break;
	case 7:
		DRIVE(ncfg_bluetooths_t, ncfg_client_bluetooth, ncfg_bluetooths_free)
		break;
	case 8:
		DRIVE(ncfg_devices_t, ncfg_client_devices, ncfg_devices_free)
		break;
	case 9:
		DRIVE(ncfg_secrets_t, ncfg_client_secrets, ncfg_secrets_free)
		break;
	case 10:
		DRIVE(ncfg_configs_t, ncfg_client_configs, ncfg_configs_free)
		break;
	case 11:
		DRIVE(ncfg_globals_t, ncfg_client_globals, ncfg_globals_free)
		break;
	case 12:
		DRIVE(ncfg_hooks_t, ncfg_client_hooks, ncfg_client_hooks_free)
		break;
	case 13:
		DRIVE(ncfg_hook_scripts_t, ncfg_client_hook_scripts,
		    ncfg_client_hook_scripts_free)
		break;
	case 14:
		DRIVE(ncfg_modems_t, ncfg_client_modems, ncfg_modems_free)
		break;
	case 15:
		DRIVE(ncfg_profiles_t, ncfg_client_profiles, ncfg_profiles_free)
		break;
	case 16:
		DRIVE(ncfg_probes_t, ncfg_client_probes, ncfg_client_probes_free)
		break;
	case 17:
		DRIVE(ncfg_radios_t, ncfg_client_radios, ncfg_radios_free)
		break;
	case 18:
		DRIVE(ncfg_access_points_t, ncfg_client_access_points, ncfg_access_points_free)
		break;
	case 19:
		DRIVE(ncfg_saved_networks_t, ncfg_client_saved_networks, ncfg_saved_networks_free)
		break;
	case 20:
		DRIVE(ncfg_dns_t, ncfg_client_dns, ncfg_dns_free)
		break;
	default:
		abort(); /* READER_COUNT disagrees with this switch */
	}

	ncfg_client_close(client);
	(void)close(served);
	return 0;
}
