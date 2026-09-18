/*
 * contention_test.c -- what else on the machine is touching the network.
 *
 * WHY EVERY PATH HERE IS MADE UP
 *   **This machine runs `NetworkManager`.** A liveness check read off the real
 *   `/proc` would make every case below pass without testing anything -- and
 *   fail for the opposite reason on a machine that does not run it. The Rust
 *   says the same thing about its own fixture and points `NCFG_RUN_ROOT` and
 *   `NCFG_PROC` at one; here the two roots are arguments, so a case that
 *   forgot to supply them would not compile rather than reading the
 *   developer's `/run`.
 *
 *   Nothing here reads `/run`, `/proc` or `/etc`. The only thing outside this
 *   test's own directory that it opens is `crates/netcfgd-host/tests/networkd/`,
 *   read-only: three link state files copied verbatim from a running
 *   `systemd-networkd`. They are read from where they already are rather than
 *   copied in, because a second copy of a fixture is a second thing that can
 *   drift from what networkd really writes -- and what is being matched is
 *   exactly that.
 *
 * WHAT THE CASES CARRY ACROSS
 *   Each is one of `crates/netcfgd-host/tests/contention.rs`'s, and three of
 *   them name a failure that shipped:
 *
 *     * **A stopped daemon leaves its claim behind.**
 *       `NetworkManager.service` has no `RuntimeDirectory=` and no
 *       `ExecStop=`, so its device files outlive it with `managed=true` still
 *       in them. Composed with the `netcfgd-exclusive.conf` drop-in that is a
 *       machine with no network at all: netcfgd stops NM, reads NM's abandoned
 *       files, believes NM still holds the radio, and declines to start a
 *       supplicant. The reported symptom was "when I start netcfgd, ping stops
 *       working" (0145).
 *     * **`pending` is not a claim.** A running networkd produced a third
 *       state the documentation does not mention, and it persisted for the
 *       whole run rather than flickering past. Warning about a contest there
 *       is the false alarm that gets a warning ignored.
 *     * **State written in another network namespace is about other
 *       interfaces.** `tests/live/hwsim.sh` put two simulated radios in a
 *       private namespace where the station was index 3; on the host, index 3
 *       was the operator's real `wlp0s20f3` with `managed=true`, so netcfgd
 *       refused to start a supplicant on a radio `NetworkManager` had never
 *       heard of. The Rust has no case for this at all -- its escape hatch is
 *       the same environment variable its tests use, so the check is skipped
 *       in every one of them. Here the namespace links are part of the fixture.
 *
 *   The dhcpcd control reply is here rather than in a file of its own because
 *   it is the same subject from the other side: which of the daemons on this
 *   machine is netcfgd's own.
 *
 * NOTHING OUTSIDE ITS OWN DIRECTORY, AND NOTHING BY PATTERN
 *   Every file and directory this makes is recorded as it is made and removed
 *   by the path that was recorded. `testdir.h`'s sweep goes three levels deep
 *   and `systemd/netif/links/<index>` is four, so the removal here is by name
 *   rather than by a walk.
 */
#include "ncfg/apply.h"
#include "ncfg/base.h"

#include "testdir.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static int holds(const char *text, const char *wanted)
{
	return text && strstr(text, wanted) != NULL;
}

/* ------------------------------------------------------------------------ *
 * What this test made, so that it can take it away by name
 * ------------------------------------------------------------------------ */

#define MADE_MAX 64
#define PATH_BYTES 512

/* A root this test makes: wide enough for whatever `testdir.h` hands back and
 * narrow enough that everything composed under it still fits in `PATH_BYTES`.
 * The compiler checks both ends of that and says so. */
#define ROOT_BYTES 320

static char   made_files[MADE_MAX][PATH_BYTES];
static size_t made_file_count;
static char   made_dirs[MADE_MAX][PATH_BYTES];
static size_t made_dir_count;

static void record(char store[MADE_MAX][PATH_BYTES], size_t *count, const char *path)
{
	if (*count >= (size_t)MADE_MAX) {
		check(0, "this test made more paths than it can remember");
		return;
	}
	(void)snprintf(store[*count], PATH_BYTES, "%s", path);
	(*count)++;
}

/* `mkdir -p` over a path under the test's own directory, recording each
 * component so that it can be removed again. */
static void make_directories(const char *path)
{
	char   partial[PATH_BYTES];
	size_t at;

	(void)snprintf(partial, sizeof(partial), "%s", path);
	for (at = 1u; partial[at] != '\0'; at++) {
		if (partial[at] != '/') {
			continue;
		}
		partial[at] = '\0';
		if (mkdir(partial, 0755) == 0) {
			record(made_dirs, &made_dir_count, partial);
		}
		partial[at] = '/';
	}
	if (mkdir(partial, 0755) == 0) {
		record(made_dirs, &made_dir_count, partial);
	}
}

/* Write a fixture file, making the directories above it. */
static void put(const char *path, const char *body)
{
	char   holding[PATH_BYTES];
	char  *last;

	(void)snprintf(holding, sizeof(holding), "%s", path);
	last = strrchr(holding, '/');
	if (last) {
		*last = '\0';
		make_directories(holding);
	}
	if (!testdir_write(path, body, strlen(body))) {
		check(0, "a fixture file could be written");
		return;
	}
	record(made_files, &made_file_count, path);
}

static void forget(const char *path)
{
	size_t at;

	(void)unlink(path);
	for (at = 0u; at < made_file_count; at++) {
		if (strcmp(made_files[at], path) == 0) {
			made_files[at][0] = '\0';
		}
	}
}

/* Everything back, deepest first, each by the path that was recorded. */
static void unmake_everything(void)
{
	size_t at;

	for (at = made_file_count; at > 0u; at--) {
		if (made_files[at - 1u][0]) {
			(void)unlink(made_files[at - 1u]);
		}
	}
	for (at = made_dir_count; at > 0u; at--) {
		(void)rmdir(made_dirs[at - 1u]);
	}
	made_file_count = 0u;
	made_dir_count = 0u;
}

/* ------------------------------------------------------------------------ *
 * The fixture
 * ------------------------------------------------------------------------ */

static char run_root[ROOT_BYTES];
static char proc_root[ROOT_BYTES];

static void nm_device(unsigned index, const char *body)
{
	char path[PATH_BYTES];

	(void)snprintf(path, sizeof(path), "%s/NetworkManager/devices/%u", run_root, index);
	put(path, body);
}

static void networkd_link(unsigned index, const char *body)
{
	char path[PATH_BYTES];

	(void)snprintf(path, sizeof(path), "%s/systemd/netif/links/%u", run_root, index);
	put(path, body);
}

/* The captured samples, read from where they already live in this tree. */
static char *captured(const char *sample)
{
	char path[PATH_BYTES];

	(void)snprintf(path, sizeof(path), "../crates/netcfgd-host/tests/networkd/%s", sample);
	return testdir_read(path, NULL);
}

static void networkd_link_as_written(unsigned index, const char *sample)
{
	char *body = captured(sample);

	if (!body) {
		check(0, "the captured networkd sample is in the tree, beside the Rust test");
		return;
	}
	networkd_link(index, body);
	free(body);
}

static void process(unsigned pid, const char *comm)
{
	char path[PATH_BYTES];
	char body[64];

	(void)snprintf(path, sizeof(path), "%s/%u/comm", proc_root, pid);
	(void)snprintf(body, sizeof(body), "%s\n", comm);
	put(path, body);
}

static void stop_process(unsigned pid)
{
	char path[PATH_BYTES];

	(void)snprintf(path, sizeof(path), "%s/%u/comm", proc_root, pid);
	forget(path);
}

/* Where the ordinary cases read from: a fake `/run`, a fake `/proc`, and no
 * namespace question, because the caller pointed this at a tree on purpose. */
static void here(ncfg_contention_where_t *where)
{
	where->run_root = run_root;
	where->proc_root = proc_root;
	where->run_root_is_the_machines = 0;
}

/* The contender with this name, or NULL. */
static const ncfg_contender_t *by_name(const ncfg_contenders_t *found, const char *name)
{
	size_t at;

	for (at = 0u; at < found->count; at++) {
		if (strcmp(found->at[at].name, name) == 0) {
			return &found->at[at];
		}
	}
	return NULL;
}

/* ------------------------------------------------------------------------ *
 * The claims
 * ------------------------------------------------------------------------ */

/*
 * **The state file exists for every device NM knows about, so its presence
 * proves nothing.** `managed=true` is the claim -- and reporting on presence
 * alone would announce a contest with a daemon that has already stepped aside,
 * which is the sort of false alarm that gets a warning ignored.
 */
static void only_a_managed_device_is_a_claim(void)
{
	static const ncfg_interface_claim_t claims[] = {
		{ "wlan0", 3u }, { "eth0", 2u }, { "eth1", 4u }
	};
	ncfg_contention_where_t where;
	ncfg_contenders_t       found;
	char                    err[NCFG_ERROR_MAX];

	nm_device(3u, "[device]\nmanaged=true\nconnection-uuid=abc\n");
	/* A device NM knows about and does not manage: the exact shape a real
	 * `NetworkManager` wrote for an ethernet port with the cable out. */
	nm_device(2u, "[device]\nperm-hw-addr-fake=00:00:00:00:00:00\n");
	/* And one it was explicitly told to leave alone. */
	nm_device(4u, "[device]\nmanaged=false\n");

	here(&where);
	check(ncfg_contenders_find(&where, claims, 3u, &found, err, sizeof(err)),
	    "a contention check over three devices answers");
	check(found.count == 1u && strcmp(found.at[0].name, "NetworkManager") == 0 &&
	    found.at[0].interface_count == 1u &&
	    strcmp(found.at[0].interfaces[0], "wlan0") == 0,
	    "and only the managed one is a claim");
	ncfg_contenders_free(&found);
}

/*
 * An interface netcfgd does not claim is not a conflict. The two daemons can
 * share a machine perfectly well as long as they do not share a device, and
 * warning otherwise would make the message noise.
 */
static void an_interface_netcfgd_does_not_claim_is_not_reported(void)
{
	static const ncfg_interface_claim_t claims[] = { { "eth0", 2u } };
	ncfg_contention_where_t             where;
	ncfg_contenders_t                   found;
	char                                err[NCFG_ERROR_MAX];

	here(&where);
	check(ncfg_contenders_find(&where, claims, 1u, &found, err, sizeof(err)) &&
	    found.count == 0u,
	    "a device NM manages that netcfgd does not claim is not reported");
	ncfg_contenders_free(&found);
}

/* A machine with neither daemon reports nothing, and does not mind that the
 * directories are absent. */
static void a_clean_machine_reports_nothing(void)
{
	static const ncfg_interface_claim_t claims[] = { { "eth9", 90u } };
	ncfg_contention_where_t             where;
	ncfg_contenders_t                   found;
	char                                err[NCFG_ERROR_MAX];

	here(&where);
	check(ncfg_contenders_find(&where, claims, 1u, &found, err, sizeof(err)) &&
	    found.count == 0u,
	    "an interface nobody has written a file about reports nothing");
	ncfg_contenders_free(&found);
}

/* `networkd`, from its documented layout. */
static void networkd_is_detected_from_its_link_state(void)
{
	static const ncfg_interface_claim_t claims[] = { { "eth0", 10u }, { "wlan0", 11u } };
	ncfg_contention_where_t             where;
	ncfg_contenders_t                   found;
	char                                err[NCFG_ERROR_MAX];

	networkd_link(10u, "ADMIN_STATE=configured\nOPER_STATE=routable\n");
	networkd_link(11u, "ADMIN_STATE=unmanaged\n");

	here(&where);
	check(ncfg_contenders_find(&where, claims, 2u, &found, err, sizeof(err)) &&
	    found.count == 1u && strcmp(found.at[0].name, "systemd-networkd") == 0 &&
	    found.at[0].interface_count == 1u &&
	    strcmp(found.at[0].interfaces[0], "eth0") == 0,
	    "a configured link is a claim and an unmanaged one is not");
	ncfg_contenders_free(&found);
}

/*
 * **The three states a running networkd actually produced, against the
 * detector.**
 *
 * The documented two are right, and there is a third. `pending` is a link
 * networkd has seen and not yet decided about; it is deliberately not a claim,
 * because networkd has configured nothing on such a link.
 */
static void the_three_states_a_real_networkd_writes(void)
{
	static const ncfg_interface_claim_t claims[] = {
		{ "nd0", 7u }, { "nd1", 8u }, { "lo", 1u }
	};
	ncfg_contention_where_t where;
	ncfg_contenders_t       found;
	char                    err[NCFG_ERROR_MAX];

	networkd_link_as_written(7u, "configured");
	networkd_link_as_written(8u, "unmanaged");
	networkd_link_as_written(1u, "pending");

	here(&where);
	check(ncfg_contenders_find(&where, claims, 3u, &found, err, sizeof(err)) &&
	    found.count == 1u && strcmp(found.at[0].name, "systemd-networkd") == 0,
	    "only networkd is reported for its own link files");
	check(found.count == 1u && found.at[0].interface_count == 1u &&
	    strcmp(found.at[0].interfaces[0], "nd0") == 0,
	    "the configured link is the claim; unmanaged and pending are not");
	ncfg_contenders_free(&found);
}

/*
 * **The header line is part of what is parsed, and it says not to.**
 *
 * `# This is private data. Do not parse.` is the first line of every one of
 * these files. netcfgd parses them anyway, and that is a decision rather than
 * an oversight. Asserted so the assumption is visible rather than implied by a
 * fixture.
 */
static void the_link_file_is_private_data_and_says_so(void)
{
	static const char header[] = "# This is private data. Do not parse.";
	char             *body = captured("configured");

	check(body && strncmp(body, header, sizeof(header) - 1u) == 0,
	    "systemd still marks these files private, and the detector reads them anyway");
	free(body);
}

/* ------------------------------------------------------------------------ *
 * The message
 * ------------------------------------------------------------------------ */

/*
 * The message has to be actionable, which means naming the device rather than
 * a placeholder the operator has to interpret -- and naming the whole-machine
 * remedy as well, which shipped as documentation that the refusal never
 * mentioned (0125).
 */
static void the_message_names_the_device_and_the_command(void)
{
	/* Given in the order that makes the sort load-bearing: an answer that
	 * simply echoed the caller's list would come back the other way round. */
	static const ncfg_interface_claim_t claims[] = { { "wlan1", 5u }, { "wlan0", 3u } };
	ncfg_contention_where_t             where;
	ncfg_contenders_t                   found;
	ncfg_buf_t                          text;
	char                                err[NCFG_ERROR_MAX];
	const char                         *message;

	nm_device(5u, "[device]\nmanaged=true\n");
	here(&where);
	if (!ncfg_contenders_find(&where, claims, 2u, &found, err, sizeof(err)) ||
	    found.count != 1u) {
		check(0, "two managed devices are one contender with two interfaces");
		ncfg_contenders_free(&found);
		return;
	}
	check(found.at[0].interface_count == 2u &&
	    strcmp(found.at[0].interfaces[0], "wlan0") == 0 &&
	    strcmp(found.at[0].interfaces[1], "wlan1") == 0,
	    "two managed devices are one contender, with its interfaces sorted");

	ncfg_buf_init(&text, 0u);
	check(ncfg_contender_describe(&found.at[0], &text, err, sizeof(err)),
	    "the contender describes itself");
	message = ncfg_buf_text(&text);

	check(holds(message, "nmcli device set wlan0 managed no") &&
	    holds(message, "nmcli device set wlan1 managed no"),
	    "and names the command for each device");
	check(!holds(message, "DEV") && !holds(message, "{}"),
	    "with no placeholder left for the operator to interpret");
	/* And it says what goes wrong, not just that something might. */
	check(holds(message, "intermittently"), "and says what the fight actually looks like");

	/* The whole-machine remedy, whose path is asserted literally because it is
	 * where `debian/rules` installs the file -- a message naming a path that is
	 * not there is worse than one naming no path at all. */
	check(holds(message, "/usr/share/doc/netcfgd/netcfgd-exclusive.conf") &&
	    holds(message, "/etc/systemd/system/netcfgd.service.d"),
	    "the whole-machine remedy names the drop-in and where it goes");
	/* And who stops them, because netcfgd killing daemons itself is the thing
	 * 0125 declined to do. */
	check(holds(message, "init system"), "and says who stops the other daemons");

	ncfg_buf_free(&text);
	ncfg_contenders_free(&found);
}

/* The remedy for networkd is the other one, and it fills in the same way. */
static void each_contender_has_its_own_remedy(void)
{
	static const ncfg_interface_claim_t claims[] = { { "eth0", 10u } };
	ncfg_contention_where_t             where;
	ncfg_contenders_t                   found;
	char                                command[NCFG_REMEDY_MAX];
	char                                err[NCFG_ERROR_MAX];
	char                                tiny[8];

	here(&where);
	if (!ncfg_contenders_find(&where, claims, 1u, &found, err, sizeof(err)) ||
	    found.count != 1u) {
		check(0, "networkd is the contender for a configured link");
		ncfg_contenders_free(&found);
		return;
	}
	check(ncfg_contender_remedy_for(&found.at[0], "eth0", command, sizeof(command)) &&
	    strcmp(command, "remove the .network file matching eth0, or set Unmanaged=yes "
	    "for it") == 0,
	    "networkd's remedy names the file to remove and the key to set");
	check(!ncfg_contender_remedy_for(&found.at[0], "eth0", tiny, sizeof(tiny)) &&
	    tiny[0] == '\0',
	    "and a remedy that would not fit leaves nothing rather than half a command");
	ncfg_contenders_free(&found);
}

/* ------------------------------------------------------------------------ *
 * Liveness
 * ------------------------------------------------------------------------ */

/*
 * **A stopped daemon leaves its claim behind, and this is the machine's whole
 * wireless failure.**
 *
 * The file says *which* interfaces. Only a live process says the claim is
 * *current*. Neither is sufficient alone, which is why this checks both rather
 * than replacing one with the other -- and why the first half of this case is
 * the control: without it the assertion below would pass just as happily
 * against a reader that found nothing at all.
 */
static void a_stopped_daemon_has_no_claim_however_much_state_it_left(void)
{
	static const ncfg_interface_claim_t claims[] = { { "wlan0", 3u } };
	ncfg_contention_where_t             where;
	ncfg_contenders_t                   found;
	char                                err[NCFG_ERROR_MAX];

	here(&where);
	check(ncfg_contenders_find(&where, claims, 1u, &found, err, sizeof(err)) &&
	    by_name(&found, "NetworkManager") != NULL,
	    "a running NetworkManager still claims the radio it wrote a file about");
	ncfg_contenders_free(&found);

	/* Exactly what a real NetworkManager leaves behind when it is stopped:
	 * the same files, and no process. */
	stop_process(100u);
	check(ncfg_contenders_find(&where, claims, 1u, &found, err, sizeof(err)) &&
	    found.count == 0u,
	    "a stopped one must not hold it, however much state it left");
	ncfg_contenders_free(&found);
	process(100u, "NetworkManager");
}

/*
 * **An unreadable `/proc` believes the files.**
 *
 * The direction that keeps the guard, rather than the one that starts a second
 * supplicant on somebody else's radio.
 */
static void a_proc_that_cannot_be_read_keeps_the_guard(void)
{
	static const ncfg_interface_claim_t claims[] = { { "wlan0", 3u } };
	ncfg_contention_where_t             where;
	ncfg_contenders_t                   found;
	char                                err[NCFG_ERROR_MAX];

	here(&where);
	where.proc_root = "/nonexistent/netcfgd-contention-test";
	check(ncfg_contenders_find(&where, claims, 1u, &found, err, sizeof(err)) &&
	    by_name(&found, "NetworkManager") != NULL,
	    "a `/proc` that will not answer leaves the claim standing");
	ncfg_contenders_free(&found);
}

/* ------------------------------------------------------------------------ *
 * Whose namespace wrote the files
 * ------------------------------------------------------------------------ */

/* Two namespace links under a `/proc` of this test's own making. */
static void namespace_fixture(const char *root, const char *ours, const char *init)
{
	char path[PATH_BYTES];

	(void)snprintf(path, sizeof(path), "%s/self/ns", root);
	make_directories(path);
	(void)snprintf(path, sizeof(path), "%s/self/ns/net", root);
	(void)unlink(path);
	if (symlink(ours, path) == 0) {
		record(made_files, &made_file_count, path);
	}
	(void)snprintf(path, sizeof(path), "%s/1/ns", root);
	make_directories(path);
	(void)snprintf(path, sizeof(path), "%s/1/ns/net", root);
	(void)unlink(path);
	if (symlink(init, path) == 0) {
		record(made_files, &made_file_count, path);
	}
	/* A live NetworkManager, so that the only thing deciding these two cases
	 * is the namespace. */
	(void)snprintf(path, sizeof(path), "%s/100/comm", root);
	put(path, "NetworkManager\n");
}

/*
 * **An index means nothing outside the network namespace that issued it.**
 *
 * `/run` is a mount rather than a namespace, so a netcfgd in a private network
 * namespace that can still see the host's `/run` reads the host's files and
 * matches them against its own indices -- which collide immediately, both
 * numberings starting at 1. The guard against two daemons fighting over one
 * radio was, measured, the only thing preventing the association it was
 * protecting.
 */
static void state_from_another_namespace_claims_nothing(const char *dir)
{
	static const ncfg_interface_claim_t claims[] = { { "wlan0", 3u } };
	ncfg_contention_where_t             where;
	ncfg_contenders_t                   found;
	char                                err[NCFG_ERROR_MAX];
	char                                same[ROOT_BYTES];
	char                                other[ROOT_BYTES];

	(void)testdir_in(dir, "proc-same", same, sizeof(same));
	(void)testdir_in(dir, "proc-other", other, sizeof(other));
	namespace_fixture(same, "net:[4026531840]", "net:[4026531840]");
	namespace_fixture(other, "net:[4026532999]", "net:[4026531840]");

	/*
	 * The control, and it is the whole of what makes the second half mean
	 * anything: the same files, the same live daemon, and the only difference
	 * is whose namespace wrote them.
	 */
	where.run_root = run_root;
	where.proc_root = same;
	where.run_root_is_the_machines = 1;
	check(ncfg_contenders_find(&where, claims, 1u, &found, err, sizeof(err)) &&
	    by_name(&found, "NetworkManager") != NULL,
	    "state written from this namespace is about this machine's interfaces");
	ncfg_contenders_free(&found);

	where.proc_root = other;
	check(ncfg_contenders_find(&where, claims, 1u, &found, err, sizeof(err)) &&
	    found.count == 0u,
	    "and state written from another one claims nothing here");
	ncfg_contenders_free(&found);

	/*
	 * A tree somebody pointed netcfgd at on purpose is exempt, which is what
	 * lets every other case in this file use one.
	 */
	where.run_root_is_the_machines = 0;
	check(ncfg_contenders_find(&where, claims, 1u, &found, err, sizeof(err)) &&
	    by_name(&found, "NetworkManager") != NULL,
	    "a run root the caller named is not asked whose namespace wrote it");
	ncfg_contenders_free(&found);
}

/* Where the daemon reads when nobody has said otherwise, asserted by reading
 * it rather than by letting anything go near it. */
static void the_machine_is_run_and_proc(void)
{
	ncfg_contention_where_t where;

	memset(&where, 0, sizeof(where));
	ncfg_contention_machine(&where);
	check(strcmp(where.run_root, "/run") == 0 && strcmp(where.proc_root, "/proc") == 0 &&
	    where.run_root_is_the_machines,
	    "the machine's own roots are `/run` and `/proc`, and its namespace is asked about");
}

/* ------------------------------------------------------------------------ *
 * The dhcpcd control reply
 * ------------------------------------------------------------------------ */

/* The exact bytes dhcpcd 10.1.0 sent, measured in a namespace, and the
 * narrower prefix a 32-bit platform sends. */
static void the_measured_reply_parses(void)
{
	static const unsigned char measured[] = {
		0x22, 0, 0, 0, 0, 0, 0, 0,
		'/', 'r', 'u', 'n', '/', 'n', 'e', 't', 'c', 'f', 'g', 'd', '/', 'd', 'h', 'c',
		'p', 'c', 'd', '/', 'p', 'r', 'o', 'b', 'e', '0', '-', '4', '.', 'c', 'o', 'n',
		'f', 0
	};
	static const unsigned char wide[] = {
		0x11, 0, 0, 0, 0, 0, 0, 0,
		'/', 'e', 't', 'c', '/', 'd', 'h', 'c', 'p', 'c', 'd', '.', 'c', 'o', 'n', 'f', 0
	};
	static const unsigned char narrow[] = {
		0x11, 0, 0, 0,
		'/', 'e', 't', 'c', '/', 'd', 'h', 'c', 'p', 'c', 'd', '.', 'c', 'o', 'n', 'f', 0
	};
	static const unsigned char nothing[] = { 0, 0, 0, 0 };
	char                       out[NCFG_DHCPCD_REPLY_MAX];

	check(ncfg_dhcpcd_control_payload(measured, sizeof(measured), out, sizeof(out)) &&
	    strcmp(out, "/run/netcfgd/dhcpcd/probe0-4.conf") == 0,
	    "the reply dhcpcd measurably sent parses to the path netcfgd gave it");

	/* **The bug this replaced.** Reading to the first NUL stops after the
	 * length prefix's low byte, which is printable for any ordinary path. */
	check(ncfg_dhcpcd_control_payload(wide, sizeof(wide), out, sizeof(out)) &&
	    strcmp(out, "/etc/dhcpcd.conf") == 0,
	    "the printable length byte is not the answer");
	check(ncfg_dhcpcd_control_payload(narrow, sizeof(narrow), out, sizeof(out)) &&
	    strcmp(out, "/etc/dhcpcd.conf") == 0,
	    "and a four-byte prefix parses the same, which is what 32-bit sends");

	check(!ncfg_dhcpcd_control_payload(nothing, sizeof(nothing), out, sizeof(out)) &&
	    !ncfg_dhcpcd_control_payload(nothing, 0u, out, sizeof(out)),
	    "nothing printable is no answer");
}

/*
 * **The length prefix alone is not a path, and the Rust says it is.**
 *
 * These are the first eight bytes of the reply above, which is what one read
 * returns when the frame arrives split between its two parts. `payload` there
 * answers `Some("\"")` -- measured against a transcription of it -- and a
 * caller comparing that against netcfgd's own `-f` reads it as somebody else's
 * dhcpcd: a stop reports a client gone that is still running, and a start
 * spawns beside one that is already there.
 */
static void a_reply_that_is_only_its_length_prefix_is_no_answer(void)
{
	static const unsigned char prefix_only[] = { 0x22, 0, 0, 0, 0, 0, 0, 0 };
	char                       out[NCFG_DHCPCD_REPLY_MAX];

	check(!ncfg_dhcpcd_control_payload(prefix_only, sizeof(prefix_only), out, sizeof(out)) &&
	    out[0] == '\0',
	    "a reply that is only its length prefix is not a path");
}

/* Answer one `--getconfigfile`, in a child of this test. */
static void serve_dhcpcd(int listener, const unsigned char *reply, size_t length, size_t split_at)
{
	char    asked[64];
	ssize_t got;
	int     talking;

	alarm(10);
	talking = accept(listener, NULL, NULL);
	if (talking < 0) {
		_exit(1);
	}
	got = read(talking, asked, sizeof(asked));
	if (got <= 0 || strncmp(asked, "--getconfigfile", 15u) != 0) {
		(void)close(talking);
		_exit(2);
	}
	(void)write(talking, reply, split_at);
	if (split_at < length) {
		struct timespec rest;

		rest.tv_sec = 0;
		rest.tv_nsec = 50L * 1000000L;
		(void)nanosleep(&rest, NULL);
		(void)write(talking, reply + split_at, length - split_at);
	}
	/* dhcpcd does not close either; the caller's deadline is what ends this.
	 * Long enough to outlive the answer, short enough not to be a sleep in a
	 * test suite. */
	{
		struct timespec linger;

		linger.tv_sec = 0;
		linger.tv_nsec = 100L * 1000000L;
		(void)nanosleep(&linger, NULL);
	}
	(void)close(talking);
	(void)close(listener);
	_exit(0);
}

/*
 * A real control socket, in this test's own directory, answering the bytes a
 * real dhcpcd answered.
 *
 * `split_at` is where the reply is cut in two, which is the case the Rust's
 * single `read` cannot survive: the first half is the length prefix, and its
 * printable low byte is what that reader returns as a path.
 */
static char *round_trip(const char *dir, size_t split_at)
{
	static const unsigned char reply[] = {
		0x22, 0, 0, 0, 0, 0, 0, 0,
		'/', 'r', 'u', 'n', '/', 'n', 'e', 't', 'c', 'f', 'g', 'd', '/', 'd', 'h', 'c',
		'p', 'c', 'd', '/', 'p', 'r', 'o', 'b', 'e', '0', '-', '4', '.', 'c', 'o', 'n',
		'f', 0
	};
	struct sockaddr_un where;
	char               run_dir[ROOT_BYTES];
	char               path[PATH_BYTES];
	int                listener;
	pid_t              server;
	char              *answer;

	(void)testdir_in(dir, "dhcpcd", run_dir, sizeof(run_dir));
	make_directories(run_dir);
	(void)snprintf(path, sizeof(path), "%s/probe0-4.sock", run_dir);
	(void)unlink(path);

	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listener < 0) {
		return NULL;
	}
	memset(&where, 0, sizeof(where));
	where.sun_family = AF_UNIX;
	if (strlen(path) >= sizeof(where.sun_path)) {
		(void)close(listener);
		return NULL;
	}
	memcpy(where.sun_path, path, strlen(path) + 1u);
	if (bind(listener, (const struct sockaddr *)&where, (socklen_t)sizeof(where)) != 0 ||
	    listen(listener, 1) != 0) {
		(void)close(listener);
		return NULL;
	}
	record(made_files, &made_file_count, path);

	server = fork();
	if (server < 0) {
		(void)close(listener);
		return NULL;
	}
	if (server == 0) {
		serve_dhcpcd(listener, reply, sizeof(reply), split_at);
	}
	(void)close(listener);
	answer = ncfg_dhcpcd_config_file_of(run_dir, "probe0", "4");
	while (waitpid(server, NULL, 0) < 0 && errno == EINTR) {
		continue;
	}
	(void)unlink(path);
	return answer;
}

static void a_running_dhcpcd_recites_its_config_file(const char *dir)
{
	char *whole = round_trip(dir, 42u);
	char *split = round_trip(dir, 8u);
	char *nothing;
	char  empty[ROOT_BYTES];

	check(whole && strcmp(whole, "/run/netcfgd/dhcpcd/probe0-4.conf") == 0,
	    "a running dhcpcd recites the config file netcfgd started it with");
	free(whole);

	/* **The divergence, over a real socket.** A reply cut between its length
	 * prefix and its string is read again rather than believed, so the two
	 * halves answer the same thing. */
	check(split && strcmp(split, "/run/netcfgd/dhcpcd/probe0-4.conf") == 0,
	    "and a reply that arrives in two pieces answers the same, not its prefix");
	free(split);

	(void)testdir_in(dir, "empty", empty, sizeof(empty));
	make_directories(empty);
	nothing = ncfg_dhcpcd_config_file_of(empty, "probe0", "4");
	check(nothing == NULL, "a run directory with no socket in it is `could not tell`");
	free(nothing);
}

int main(void)
{
	const char *dir = testdir_make("contention");

	/* A ceiling on the whole binary. Several cases fork and one waits on a
	 * socket deadline; nothing else in this suite has a timeout. */
	alarm(120);

	printf("== contention_test in %s\n", dir);
	(void)testdir_in(dir, "run", run_root, sizeof(run_root));
	(void)testdir_in(dir, "proc", proc_root, sizeof(proc_root));
	make_directories(run_root);
	make_directories(proc_root);

	/*
	 * Both daemons are alive unless a case says otherwise, which is what every
	 * case written before liveness mattered assumed. The fixture also holds
	 * the two shapes a `/proc` scan trips over: a non-numeric entry, and a
	 * numeric one with no `comm` at all, which is what a process exiting
	 * mid-scan looks like.
	 */
	process(100u, "NetworkManager");
	process(101u, "systemd-network");
	{
		char path[PATH_BYTES];

		(void)snprintf(path, sizeof(path), "%s/uptime", proc_root);
		put(path, "10000.00 40000.00\n");
		(void)snprintf(path, sizeof(path), "%s/999", proc_root);
		make_directories(path);
	}

	only_a_managed_device_is_a_claim();
	an_interface_netcfgd_does_not_claim_is_not_reported();
	a_clean_machine_reports_nothing();
	networkd_is_detected_from_its_link_state();
	the_three_states_a_real_networkd_writes();
	the_link_file_is_private_data_and_says_so();
	the_message_names_the_device_and_the_command();
	each_contender_has_its_own_remedy();
	a_stopped_daemon_has_no_claim_however_much_state_it_left();
	a_proc_that_cannot_be_read_keeps_the_guard();
	state_from_another_namespace_claims_nothing(dir);
	the_machine_is_run_and_proc();
	the_measured_reply_parses();
	a_reply_that_is_only_its_length_prefix_is_no_answer();
	a_running_dhcpcd_recites_its_config_file(dir);

	unmake_everything();
	testdir_remove(dir);

	if (failures == 0) {
		printf("contention_test: all checks passed\n");
	} else {
		printf("contention_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
