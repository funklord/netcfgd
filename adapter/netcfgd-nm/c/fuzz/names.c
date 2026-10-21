/*
 * The names and paths a client chooses, and what the shim turns them into.
 *
 * WHAT THESE READERS ARE
 *   Every object a client holds is a path, and the tail of that path came from
 *   the client: `/org/freedesktop/NetworkManager/Devices/<tail>`,
 *   `/Settings/<tail>`, `/AccessPoint/<tail>`. A client may send any string
 *   there -- D-Bus validates the path's SHAPE, nothing validates its meaning
 *   -- and the resolvers parse it. One of them parses with `sscanf("%u%c")`,
 *   which is the sort of thing worth pointing a fuzzer at.
 *
 *   The other half is a profile's id, which arrives in a settings dictionary
 *   and becomes two things that leave the program: a UUID a client reads back,
 *   and **a filename under `/etc/netcfgd/conf.d`**. The invariants below are
 *   about those two, because a crash is not the only way either can go wrong.
 *
 * WHY THE SOCKET PATH CANNOT EXIST
 *   The `_for_bus` resolvers refresh from netcfgd on the way in, by design:
 *   the subtree stores nothing, so a path for a device that appeared since the
 *   last message has to resolve. A fuzz target cannot have that reaching a
 *   real daemon -- it would send a running netcfgd thousands of requests a
 *   second -- so the state is pointed at a socket under a directory that does
 *   not exist. Every refresh then fails fast and the stores stay empty, which
 *   is both deterministic and a real condition: it is the state of a shim
 *   whose daemon has stopped, where these functions must still behave.
 *
 *   What that costs is the hit path: a tail that matches a device cannot be
 *   reached here, only the parse and the miss. The hit is what `bus_test` and
 *   the live scripts cover, with a daemon that exists.
 */
#include "fuzz.h"

#include "nmc/accesspoint.h"
#include "nmc/active.h"
#include "nmc/block.h"
#include "nmc/settings.h"
#include "nmc/state.h"
#include "nmc/store.h"
#include "nmc/uuid.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * A UUID is 36 characters, `8-4-4-4-12`, hex and dashes -- **and libnm parses
 * it**, which is what makes this an invariant rather than a nicety: `nmcli`
 * merges an activation into its profile's row by matching the uuid, so one
 * that does not parse makes a profile and its activation two unrelated rows
 * (the defect `active.c` records).
 */
static void check_uuid(const char *identity)
{
	char   uuid[64] = "";
	size_t at;

	nmc_uuid_of(identity, uuid, sizeof(uuid));
	if (strlen(uuid) != 36u) {
		fprintf(stderr, "names: a uuid of %zu characters for [%s]\n", strlen(uuid),
		    identity);
		abort();
	}
	for (at = 0u; at < 36u; at++) {
		int dash = (at == 8u || at == 13u || at == 18u || at == 23u);

		if (dash) {
			if (uuid[at] != '-') {
				abort(); /* the shape libnm parses */
			}
		} else if (!isxdigit((unsigned char)uuid[at])) {
			abort(); /* a character that is not hex */
		}
	}
}

/*
 * A stem names a FILE under `/etc/netcfgd/conf.d`, so the characters in it are
 * a security property and not a matter of taste: a `/` would write outside the
 * directory, and a leading `.` or a bare `..` would write something nobody
 * meant. The `nm-` prefix is what says the shim owns the file, so `Delete`
 * removing it is not removing somebody's hand-written configuration.
 */
static void check_stem(const char *id)
{
	char   stem[96] = "";
	size_t at;

	nmc_block_stem(id, stem, sizeof(stem));
	if (strncmp(stem, "nm-", 3u) != 0) {
		fprintf(stderr, "names: a stem that is not the shim's: [%s]\n", stem);
		abort();
	}
	for (at = 0u; stem[at] != '\0'; at++) {
		unsigned char c = (unsigned char)stem[at];

		if (!isalnum(c) && c != '-' && c != '_' && c != '.') {
			fprintf(stderr, "names: [%c] in a filename: [%s]\n", (char)c, stem);
			abort();
		}
	}
	/*
	 * **`..` is deliberately not refused, and the first version of this
	 * refused it.** `../../etc/passwd` becomes `nm-.._.._etc_passwd`, which
	 * looks alarming and is a flat filename: the separators are gone, so
	 * there is nothing for `..` to climb through, and the `nm-` prefix means
	 * the name can never BE `.` or `..` either. The character class above is
	 * what makes that true, and it is the check worth having.
	 *
	 * The assertion fired on the seed written to test it, before any fuzzing
	 * -- which is the argument for seeding a target with the cases you are
	 * worried about rather than only with the ones that work.
	 */
}

int ncfg_fuzz_one(const unsigned char *data, size_t length)
{
	nmc_state_t       state;
	nmc_store_t       store;
	nmc_connections_t connections;
	nmc_aps_t         aps;
	char             *tail = ncfg_fuzz_text(data, length);

	if (!tail) {
		return 0;
	}
	/* Pure functions of the text first: they need no store at all, and they
	 * are the two whose answers leave the program. */
	check_uuid(tail);
	check_stem(tail);

	nmc_state_init(&state, "/nonexistent-netcfgd-fuzz/netcfgd.sock");
	nmc_store_init(&store, &state);
	nmc_connections_init(&connections, &state);
	nmc_aps_init(&aps, &state);

	/* Every family's path tail, as a client may send it. */
	(void)nmc_store_resolve(&store, tail);
	(void)nmc_store_resolve_for_bus(tail, &store);
	(void)nmc_connections_resolve_for_bus(tail, &connections);
	(void)nmc_active_resolve_for_bus(tail, &store);
	(void)nmc_aps_resolve_for_bus(tail, &aps);

	/* And the other direction: a name into a path. `path_of` takes both kinds
	 * because an `interface wlan0` and a `network "wlan0"` are two profiles,
	 * and asking for one must not answer with the other's path. */
	(void)nmc_store_path_for(&store, tail);
	(void)nmc_connections_path_of(&connections, NMC_PROFILE_NETWORK, tail);
	(void)nmc_connections_path_of(&connections, NMC_PROFILE_INTERFACE, tail);
	(void)nmc_connections_slot_of(&connections, NMC_PROFILE_NETWORK, tail);
	(void)nmc_connections_slot_of(&connections, NMC_PROFILE_INTERFACE, tail);

	nmc_aps_free(&aps);
	nmc_connections_free(&connections);
	nmc_store_free(&store);
	nmc_state_free(&state);
	free(tail);
	return 0;
}
