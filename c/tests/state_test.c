/*
 * state_test.c -- the run directory, and the four defects that shaped it.
 *
 * WHAT THESE CASES ARE FOR
 *   * **A record from another boot is discarded, and one with no boot is
 *     kept.** Every object a stale record names is gone, and anything that has
 *     taken the same name since would be adopted by a claim that never applied
 *     to it (0138). The round trip matters as much as the discard: the write
 *     stamps the boot itself, so a caller cannot forget to -- and a record that
 *     forgot would be one the read cannot judge, failing open. An *unstamped*
 *     record is from a netcfgd that predates the field, and discarding it would
 *     throw ownership away for a reason unrelated to a reboot.
 *   * **A record that will not parse is discarded and said out loud** (0189).
 *     This is a downgrade's most likely shape. Measured before it: the daemon
 *     started, stayed configured, and said nothing at all.
 *   * **Two writers of one file must not share a temporary.** `owned.json` is
 *     written by `ncfg apply` and by the daemon, and every temporary used to be
 *     `<name>.tmp` -- one path for everyone. Interleaved, the second writer's
 *     bytes land under the first writer's rename and the loser renames a file
 *     that is no longer there. **Processes rather than threads here**, because
 *     that is the arrangement the defect actually has.
 *   * **Two updaters must not lose each other's changes.** Worse than "one
 *     change does not stick": a fold adds only what *this* apply did, so a pass
 *     with nothing of its own writes back everything it read, and a stale read
 *     therefore **restores** a record the other process had just dropped.
 *     Ownership is what decides whether netcfgd may reset a qdisc or delete a
 *     link, so a restored record is the unsafe direction. Deterministic: both
 *     sides hold their change open long enough that an unlocked implementation
 *     must interleave.
 *
 *   The report cases are the contract's own, and `THE_DOCUMENTED_EXAMPLE` is
 *   verbatim from `doc/interface-report.md`. **If this file and that document
 *   ever disagree, the document is right**: it is what somebody else wrote
 *   their helper against.
 *
 * NOTHING OUTSIDE ITS OWN DIRECTORY
 *   The real daemon is running on this machine with `/run/netcfgd` full of its
 *   real state. Every path here is under one `mkdtemp` directory, the run
 *   directory is passed explicitly everywhere, and the default is checked by
 *   reading the constant rather than by writing to it.
 */
#include "ncfg/base.h"
#include "ncfg/document.h"
#include "ncfg/observed.h"
#include "ncfg/state.h"

#include "testdir.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-64s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static char *join(const char *dir, const char *leaf)
{
	static char out[512];

	(void)snprintf(out, sizeof(out), "%s/%s", dir, leaf);
	return out;
}

static void sleep_ms(long milliseconds)
{
	struct timespec wanted;

	wanted.tv_sec = milliseconds / 1000;
	wanted.tv_nsec = (milliseconds % 1000) * 1000000L;
	(void)nanosleep(&wanted, NULL);
}

/* Wait for one child, with a ceiling: nothing here takes more than a second
 * when it works, and a blocking wait on a child that wedged would hold the
 * whole suite. */
static int wait_for(pid_t child)
{
	int rounds;

	for (rounds = 0; rounds < 300; rounds++) {
		int status = 0;
		pid_t got = waitpid(child, &status, WNOHANG);

		if (got == child) {
			return WIFEXITED(status) && WEXITSTATUS(status) == 0;
		}
		if (got < 0 && errno != EINTR) {
			return 0;
		}
		sleep_ms(20);
	}
	(void)kill(child, SIGKILL);
	(void)waitpid(child, NULL, 0);
	return 0;
}

/* ----------------------------------------------------------- the run directory */

static void the_run_directory_is_chosen_in_one_order(void)
{
	char out[256];

	(void)unsetenv(NCFG_RUN_DIR_ENV);
	check(strcmp(ncfg_state_resolve_dir(NULL, out, sizeof(out)), NCFG_RUN_DIR_DEFAULT) == 0,
	    "with nothing said, the run directory is the default");
	(void)setenv(NCFG_RUN_DIR_ENV, "/tmp/netcfgd-not-written-to", 1);
	check(strcmp(ncfg_state_resolve_dir(NULL, out, sizeof(out)),
	    "/tmp/netcfgd-not-written-to") == 0,
	    "the environment overrides it, which is what a second netcfgd needs");
	check(strcmp(ncfg_state_resolve_dir("/tmp/netcfgd-asked-for", out, sizeof(out)),
	    "/tmp/netcfgd-asked-for") == 0,
	    "and an explicit one overrides both");
	(void)unsetenv(NCFG_RUN_DIR_ENV);
	/* Nothing above wrote anywhere: the names are resolved, not used. */
}

/* --------------------------------------------------------------- the record */

static void the_record_round_trips(const char *run_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	ncfg_owned_state_t owned;
	ncfg_owned_state_t back;
	size_t capacity = 0;
	char *now = ncfg_state_boot_id();

	memset(&owned, 0, sizeof(owned));
	memset(&back, 0, sizeof(back));
	check(ncfg_owned_remember(&owned.forwarding, &owned.forwarding_count, "eth0", 1),
	    "an interface netcfgd switched forwarding on for is remembered");
	check(ncfg_owned_remember(&owned.forwarding, &owned.forwarding_count, "eth1", 1) &&
	    owned.forwarding_count == 2u, "and so is a second");
	/* **Switching one off drops the record rather than storing false**: the
	 * question is "is this ours to undo later", and once it has been undone
	 * the answer is no. */
	check(ncfg_owned_remember(&owned.forwarding, &owned.forwarding_count, "eth0", 0) &&
	    owned.forwarding_count == 1u && strcmp(owned.forwarding[0], "eth1") == 0,
	    "switching one off drops its record rather than storing a false");

	owned.addresses = calloc(1u, sizeof(*owned.addresses));
	owned.addresses[0].interface = strdup("eth1");
	owned.addresses[0].key = strdup("10.0.0.5/24");
	owned.addresses[0].origin = NCFG_ORIGIN_DHCP4;
	owned.address_count = 1u;
	(void)capacity;
	check(ncfg_owned_note_hook_state(&owned, "eth1", NCFG_HOOK_PHASE_LEASE, "10.0.0.5/24") &&
	    ncfg_owned_note_hook_state(&owned, "eth1", NCFG_HOOK_PHASE_LEASE, "10.0.0.6/24") &&
	    owned.hook_state_count == 1u &&
	    strcmp(owned.hook_state[0].value, "10.0.0.6/24") == 0,
	    "a hook's last word replaces the one before it rather than joining it");

	check(ncfg_owned_write(run_dir, &owned, message, sizeof(message)),
	    "the record is written");
	check(ncfg_owned_read(run_dir, &back, message, sizeof(message)) &&
	    back.forwarding_count == 1u && strcmp(back.forwarding[0], "eth1") == 0 &&
	    back.address_count == 1u && back.addresses[0].origin == NCFG_ORIGIN_DHCP4 &&
	    strcmp(back.addresses[0].key, "10.0.0.5/24") == 0 &&
	    back.hook_state_count == 1u && back.hook_state[0].phase == NCFG_HOOK_PHASE_LEASE,
	    "and comes back as itself");
	check(!now || (back.boot && strcmp(back.boot, now) == 0),
	    "stamped with this boot by the write, so no caller can forget to");
	free(now);
	ncfg_owned_free(&owned);
	ncfg_owned_free(&back);
}

static void a_record_from_another_boot_is_discarded(const char *run_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	ncfg_owned_state_t owned;
	char *now = ncfg_state_boot_id();
	static const char forged[] = "{\"boot\":\"00000000-0000-0000-0000-000000000000\","
	    "\"forwarding\":[\"eth0\"]}";

	if (!now) {
		/* Saying so beats a green result that inspected nothing. */
		printf("no boot id on this kernel; the discard was not exercised\n");
		return;
	}
	free(now);
	check(testdir_write(join(run_dir, "owned.json"), forged, sizeof(forged) - 1u),
	    "a record that says it was written during another boot");
	check(ncfg_owned_read(run_dir, &owned, message, sizeof(message)) &&
	    owned.forwarding_count == 0u,
	    "names objects that no longer exist, so it is discarded whole");
	ncfg_owned_free(&owned);
}

static void a_record_with_no_boot_recorded_is_kept(const char *run_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	ncfg_owned_state_t owned;
	static const char old[] = "{\"forwarding\":[\"eth0\"],\"created_links\":[],"
	    "\"addresses\":[],\"routes\":[],\"privacy\":[],\"qdisc\":[],\"ingress\":[]}";

	check(testdir_write(join(run_dir, "owned.json"), old, sizeof(old) - 1u),
	    "a record from a netcfgd that predates the boot field");
	check(ncfg_owned_read(run_dir, &owned, message, sizeof(message)) &&
	    owned.forwarding_count == 1u && strcmp(owned.forwarding[0], "eth0") == 0,
	    "is kept: an unknown boot means do not judge, never discard");
	ncfg_owned_free(&owned);
}

static int push_qdisc(ncfg_owned_state_t *owned, void *context)
{
	size_t capacity = owned->qdisc_count;

	(void)capacity;
	return ncfg_owned_remember(&owned->qdisc, &owned->qdisc_count, (const char *)context, 1);
}

static void a_record_that_will_not_parse_is_discarded_rather_than_fatal(const char *run_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	ncfg_owned_state_t owned;

	check(testdir_write(join(run_dir, "owned.json"), "this is not json\n", 17u),
	    "a record a newer netcfgd wrote and this one cannot read");
	check(ncfg_owned_read(run_dir, &owned, message, sizeof(message)) &&
	    owned.address_count == 0u,
	    "is the empty default rather than a refusal to start");
	ncfg_owned_free(&owned);

	/* Which is what stops a bad file being permanent: the next apply writes a
	 * good one. */
	check(ncfg_owned_update(run_dir, push_qdisc, (void *)"eth0", message, sizeof(message)),
	    "and an update over it still writes one");
	check(ncfg_owned_read(run_dir, &owned, message, sizeof(message)) &&
	    owned.qdisc_count == 1u && strcmp(owned.qdisc[0], "eth0") == 0,
	    "which reads back");
	ncfg_owned_free(&owned);

	/* A member this build has never heard of is the same case: guessing at it
	 * is how a downgrade adopts an object it cannot describe. */
	check(testdir_write(join(run_dir, "owned.json"),
	    "{\"forwarding\":[\"eth0\"],\"something_new\":[1]}", 41u),
	    "a record carrying a member this build does not know");
	check(ncfg_owned_read(run_dir, &owned, message, sizeof(message)) &&
	    owned.forwarding_count == 0u,
	    "is discarded rather than half-read");
	ncfg_owned_free(&owned);
	(void)unlink(join(run_dir, "owned.json"));
}

/* ------------------------------------------------- backends and dns scopes */

/*
 * The witness, and it is this machine's own.
 *
 * `/run/netcfgd/owned.json` on the workstation this port is written on is
 * written by the Rust netcfgd that is actually running here, and what is below
 * is its shape with the names changed: member for member, in the order serde's
 * derive emits them, with a backend as `{kind, interface, running}` and a scope
 * as `{scope, policy}`. **The two members in the middle are the ones this build
 * used to drop.** It read them as "known but unrepresentable", warned, and
 * wrote the record back without them -- so a C netcfgd taking over from a Rust
 * one forgot which daemons were up and which resolver policy had been
 * delivered, and the planner re-delivered every scope on every pass for ever
 * (project.md 10.183).
 */
static const char THE_RECORD_A_RUST_NETCFGD_WROTE[] =
    "{\n"
    "  \"boot\": \"\",\n"
    "  \"created_links\": [],\n"
    "  \"addresses\": [],\n"
    "  \"routes\": [],\n"
    "  \"backends\": [\n"
    "    {\n"
    "      \"kind\": \"supplicant\",\n"
    "      \"interface\": \"wlan9\",\n"
    "      \"running\": true\n"
    "    },\n"
    "    {\n"
    "      \"kind\": \"dhcp4\",\n"
    "      \"interface\": \"wlan9\",\n"
    "      \"running\": true\n"
    "    }\n"
    "  ],\n"
    "  \"backend_restarts\": [],\n"
    "  \"dns\": [\n"
    "    {\n"
    "      \"scope\": \"globals\",\n"
    "      \"policy\": {\n"
    "        \"mode\": \"write_resolv_conf\",\n"
    "        \"servers\": [],\n"
    "        \"search\": [],\n"
    "        \"domains\": [],\n"
    "        \"options\": []\n"
    "      }\n"
    "    },\n"
    "    {\n"
    "      \"scope\": \"wlan9\",\n"
    "      \"policy\": {\n"
    "        \"mode\": \"write_resolv_conf\",\n"
    "        \"servers\": [\n"
    "          {\n"
    "            \"addr\": \"192.0.2.1\"\n"
    "          }\n"
    "        ],\n"
    "        \"search\": [\n"
    "          \"example.test\"\n"
    "        ],\n"
    "        \"domains\": [],\n"
    "        \"options\": []\n"
    "      }\n"
    "    }\n"
    "  ],\n"
    "  \"forwarding\": [],\n"
    "  \"privacy\": [],\n"
    "  \"accept_ra\": [],\n"
    "  \"hook_state\": [],\n"
    "  \"qdisc\": [],\n"
    "  \"ingress\": []\n"
    "}\n";

static void the_backends_and_scopes_a_rust_netcfgd_recorded(const char *run_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	ncfg_owned_state_t owned;
	ncfg_owned_state_t back;
	char *written;
	size_t length = 0;

	memset(&owned, 0, sizeof(owned));
	memset(&back, 0, sizeof(back));
	check(testdir_write(join(run_dir, "owned.json"), THE_RECORD_A_RUST_NETCFGD_WROTE,
	    sizeof(THE_RECORD_A_RUST_NETCFGD_WROTE) - 1u),
	    "a record in the shape this machine's own netcfgd writes");
	check(ncfg_owned_read(run_dir, &owned, message, sizeof(message)) &&
	    owned.backend_count == 2u,
	    "is read with both the backends it names");
	check(owned.backend_count == 2u && owned.backends[0].kind == NCFG_BACKEND_SUPPLICANT &&
	    strcmp(owned.backends[0].interface, "wlan9") == 0 && owned.backends[0].running &&
	    owned.backends[1].kind == NCFG_BACKEND_DHCP4,
	    "in the order the file holds them, kind, interface and running each");
	/* **Absent is not false**, and the file is what says so: `answering` has
	 * no place in this record at all, and reading it as `false` would put a
	 * warning on every daemon netcfgd has ever started. */
	check(owned.backend_count == 2u && !owned.backends[0].answering.has,
	    "and a question the record does not answer is left unanswered, not answered no");
	check(owned.dns_count == 2u && strcmp(owned.dns[0].scope, "globals") == 0 &&
	    strcmp(owned.dns[1].scope, "wlan9") == 0,
	    "and both delivered scopes, in the order the file holds them");
	check(owned.dns_count == 2u && owned.dns[1].policy.server_count == 1u &&
	    strcmp(owned.dns[1].policy.servers[0].addr, "192.0.2.1") == 0 &&
	    owned.dns[1].policy.search_count == 1u &&
	    strcmp(owned.dns[1].policy.search[0], "example.test") == 0,
	    "with the whole policy under each, through the model's own table");

	/*
	 * And back out. This is the half that mattered: a read-modify-write is
	 * what every apply does, so a member read and not written is a member the
	 * first apply after a version change deletes.
	 */
	check(ncfg_owned_write(run_dir, &owned, message, sizeof(message)),
	    "the record is written back");
	written = testdir_read(join(run_dir, "owned.json"), &length);
	check(written && strstr(written, "\"supplicant\"") && strstr(written, "\"192.0.2.1\"") &&
	    strstr(written, "\"example.test\""),
	    "and what went to disk still carries the backends and the scopes");
	/*
	 * **In the place serde's derive puts them**, which is the witness this
	 * fixture was taken from: `backends` after `routes`, `dns` after
	 * `backend_restarts`. Nothing reading JSON depends on the order -- what
	 * does is the person running `diff` between a Rust netcfgd's record and a
	 * C one's, which is the only instrument that has ever caught a member
	 * this port put in the wrong place.
	 */
	check(written && strstr(written, "\"routes\"") && strstr(written, "\"backends\"") &&
	    strstr(written, "\"backend_restarts\"") && strstr(written, "\"dns\"") &&
	    strstr(written, "\"forwarding\"") &&
	    strstr(written, "\"routes\"") < strstr(written, "\"backends\"") &&
	    strstr(written, "\"backends\"") < strstr(written, "\"backend_restarts\"") &&
	    strstr(written, "\"backend_restarts\"") < strstr(written, "\"dns\"") &&
	    strstr(written, "\"dns\"") < strstr(written, "\"forwarding\""),
	    "each in the place the Rust's derive writes it, so the two files diff");
	free(written);
	check(ncfg_owned_read(run_dir, &back, message, sizeof(message)) &&
	    back.backend_count == 2u && back.dns_count == 2u &&
	    back.dns[1].policy.server_count == 1u,
	    "which reads back as itself, so a round trip loses nothing");
	ncfg_owned_free(&owned);
	ncfg_owned_free(&back);
	(void)unlink(join(run_dir, "owned.json"));
}

static void a_backend_this_build_cannot_describe_is_refused(const char *run_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	ncfg_owned_state_t owned;
	static const char stranger[] = "{\"forwarding\":[\"eth0\"],\"backends\":[{\"kind\":"
	    "\"dhcp4\",\"interface\":\"eth0\",\"running\":true,\"something_new\":1}]}";
	static const char bad_kind[] = "{\"forwarding\":[\"eth0\"],\"backends\":[{\"kind\":"
	    "\"teleport\",\"interface\":\"eth0\",\"running\":true}]}";
	static const char half_a_list[] = "{\"dns\":[{\"scope\":\"globals\",\"policy\":"
	    "{\"mode\":\"write_resolv_conf\"}},{\"scope\":\"eth0\"}]}";

	/* `deny_unknown_fields`, one level down, and it comes from the model's
	 * table rather than from a second list here -- which is the whole reason
	 * the table is what this module reads through. */
	check(testdir_write(join(run_dir, "owned.json"), stranger, sizeof(stranger) - 1u),
	    "a backend carrying a member this build has never heard of");
	check(ncfg_owned_read(run_dir, &owned, message, sizeof(message)) &&
	    owned.forwarding_count == 0u && owned.backend_count == 0u,
	    "discards the whole record rather than adopting a daemon it cannot describe");
	ncfg_owned_free(&owned);

	check(testdir_write(join(run_dir, "owned.json"), bad_kind, sizeof(bad_kind) - 1u),
	    "and a kind outside the set is the same answer");
	check(ncfg_owned_read(run_dir, &owned, message, sizeof(message)) &&
	    owned.forwarding_count == 0u && owned.backend_count == 0u,
	    "rather than a backend of some kind netcfgd would then try to stop");
	ncfg_owned_free(&owned);

	/*
	 * **A list that failed half way is still a list**, which is what the
	 * reader promises and what the free below has to be able to take apart:
	 * the first scope here reads, the second does not, and the array was
	 * allocated for both. Under the sanitizer this is the case that says so.
	 */
	check(testdir_write(join(run_dir, "owned.json"), half_a_list,
	    sizeof(half_a_list) - 1u),
	    "a dns list whose second scope is not a scope at all");
	check(ncfg_owned_read(run_dir, &owned, message, sizeof(message)) &&
	    owned.dns_count == 0u,
	    "is discarded whole, and what had been read is freed rather than stranded");
	ncfg_owned_free(&owned);
	(void)unlink(join(run_dir, "owned.json"));
}

static void two_writers_of_one_file_do_not_share_a_temporary(const char *run_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	const char *path = join(run_dir, "contended.json");
	char *own_path = strdup(path);
	char *body = malloc(64u * 1024u);
	pid_t children[2];
	int which;
	int all = 1;
	char *final_text;
	size_t length = 0;

	if (!body || !own_path) {
		check(0, "the fixture could be allocated");
		free(body);
		free(own_path);
		return;
	}
	for (which = 0; which < 2; which++) {
		fflush(NULL);
		children[which] = fork();
		if (children[which] == 0) {
			int round;

			memset(body, which ? 'b' : 'a', 64u * 1024u);
			for (round = 0; round < 200; round++) {
				char mine[NCFG_ERROR_MAX] = "";

				if (!ncfg_write_atomically(own_path, body, 64u * 1024u, 0666u, mine,
				    sizeof(mine))) {
					_exit(1);
				}
			}
			_exit(0);
		}
		if (children[which] < 0) {
			check(0, "the writers could be started");
			free(body);
			free(own_path);
			return;
		}
	}
	for (which = 0; which < 2; which++) {
		all = wait_for(children[which]) && all;
	}
	check(all, "two processes writing one file never fail each other");

	final_text = testdir_read(own_path, &length);
	/* And the survivor is one of them whole, never a mixture. */
	check(final_text && length == 64u * 1024u &&
	    (final_text[0] == 'a' || final_text[0] == 'b') &&
	    final_text[length - 1u] == final_text[0],
	    "and what is left is one writer's content, never a mixture");
	free(final_text);
	free(body);
	(void)unlink(own_path);
	free(own_path);
	(void)message;
}

static int push_slowly(ncfg_owned_state_t *owned, void *context)
{
	if (!ncfg_owned_remember(&owned->qdisc, &owned->qdisc_count, (const char *)context, 1)) {
		return 0;
	}
	/* Long enough that an unlocked reader has certainly read, and short enough
	 * that a person waits for it. */
	sleep_ms(150);
	return 1;
}

static void two_updaters_do_not_lose_each_others_records(const char *run_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	static const char *const names[2] = { "veth0", "veth1" };
	ncfg_owned_state_t owned;
	pid_t children[2];
	int which;
	int all = 1;

	(void)unlink(join(run_dir, "owned.json"));
	for (which = 0; which < 2; which++) {
		fflush(NULL);
		children[which] = fork();
		if (children[which] == 0) {
			char mine[NCFG_ERROR_MAX] = "";

			_exit(ncfg_owned_update(run_dir, push_slowly, (void *)names[which], mine,
			    sizeof(mine)) ? 0 : 1);
		}
		if (children[which] < 0) {
			check(0, "the updaters could be started");
			return;
		}
	}
	for (which = 0; which < 2; which++) {
		all = wait_for(children[which]) && all;
	}
	check(all, "two processes updating the record both succeed");
	check(ncfg_owned_read(run_dir, &owned, message, sizeof(message)) &&
	    owned.qdisc_count == 2u,
	    "and neither loses the other's: an update was not put back over");
	ncfg_owned_free(&owned);
	(void)unlink(join(run_dir, "owned.json"));
	(void)unlink(join(run_dir, "owned.lock"));
}

/* ------------------------------------------------------------- provenance */

static void provenance_round_trips(const char *run_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	ncfg_provenance_t provenance;
	ncfg_provenance_t back;
	char where[256];

	memset(&provenance, 0, sizeof(provenance));
	memset(&back, 0, sizeof(back));
	check(ncfg_state_read_provenance(run_dir, &back, message, sizeof(message)) &&
	    back.count == 0u,
	    "an absent provenance table is empty, not a failure");
	ncfg_provenance_free(&back);

	(void)ncfg_provenance_record(&provenance, "interfaces[eth0].mtu",
	    "/etc/netcfgd/conf.d/10-lan.conf", 4, 2, message, sizeof(message));
	(void)ncfg_provenance_record(&provenance, "globals.on_drift",
	    "/etc/netcfgd/netcfgd.conf", 9, 1, message, sizeof(message));
	/* The first entry for a path wins: an explanation naming the later one
	 * would send a reader to the override rather than to what produced the
	 * value. */
	(void)ncfg_provenance_record(&provenance, "globals.on_drift", "/etc/netcfgd/later.conf",
	    99, 1, message, sizeof(message));
	check(ncfg_state_write_provenance(run_dir, &provenance, message, sizeof(message)),
	    "the provenance table is written");
	check(provenance.count == 2u &&
	    strcmp(provenance.entries[0].path, "globals.on_drift") == 0,
	    "sorted by path and with one entry per path, so the file is stable");
	/*
	 * **Which one survived, which the check above cannot see.** Counting the
	 * entries proves a duplicate went; it says nothing about whether the one
	 * kept is the one the rule names, and the rule is the whole reason this
	 * function does not simply keep the last. `qsort` is not stable, so
	 * before the comparator learned to break ties by arrival this was left to
	 * the libc.
	 *
	 * **And this check passes against the version that leaves it to the
	 * libc**, measured: glibc's `qsort` is a merge sort and happens to keep
	 * these two in order, so the old code was right here by luck and would
	 * have been wrong on a libc that chose differently. What turns it red is a
	 * comparator that reverses ties, which is what an unstable sort is
	 * entitled to do. A check that only fails against a deliberately hostile
	 * sort is still worth having: it is the rule written down where the next
	 * reader of this function will see it.
	 */
	ncfg_provenance_location(ncfg_provenance_lookup(&provenance, "globals.on_drift"), where,
	    sizeof(where));
	check(strcmp(where, "/etc/netcfgd/netcfgd.conf:9:1") == 0,
	    "and the entry kept is the one recorded first, not the override at line 99");
	check(ncfg_state_read_provenance(run_dir, &back, message, sizeof(message)) &&
	    back.count == 2u,
	    "and read back");
	ncfg_provenance_location(ncfg_provenance_lookup(&back, "interfaces[eth0].mtu"), where,
	    sizeof(where));
	check(strcmp(where, "/etc/netcfgd/conf.d/10-lan.conf:4:2") == 0,
	    "`ncfg explain` can name a file and a line without recompiling");
	ncfg_provenance_free(&provenance);
	ncfg_provenance_free(&back);
}

/* ------------------------------------------------------- the desired document */

static ncfg_document_t *two_interfaces(void)
{
	char message[NCFG_ERROR_MAX];
	ncfg_document_t *document = ncfg_document_new(message, sizeof(message));

	if (!document) {
		printf("could not make a document: %s\n", message);
		exit(1);
	}
	document->interfaces = calloc(2u, sizeof(*document->interfaces));
	if (!document->interfaces) {
		exit(1);
	}
	document->interface_count = 2u;
	/* Deliberately out of order, so that the canonicalisation the write does
	 * is what the projections are named from. */
	document->interfaces[0].name = strdup("wlan0");
	document->interfaces[0].enabled = 1;
	document->interfaces[1].name = strdup("eth0");
	document->interfaces[1].enabled = 1;
	return document;
}

static void the_desired_document_and_its_projections(const char *run_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	ncfg_document_t *document = two_interfaces();
	char *whole;
	char *one;
	size_t length = 0;
	char *desired_dir = strdup(join(run_dir, "desired"));
	char *stale = strdup(join(desired_dir, "gone.json"));

	check(mkdir(desired_dir, 0755) == 0 && testdir_write(stale, "{}", 2u),
	    "a projection for an interface the configuration no longer has");

	check(ncfg_state_write_desired(run_dir, document, message, sizeof(message)),
	    "the desired document is written");
	whole = testdir_read(join(run_dir, "desired.json"), &length);
	check(whole && strstr(whole, "\"eth0\"") && strstr(whole, "\"wlan0\""),
	    "and carries both interfaces");
	free(whole);

	one = testdir_read(join(desired_dir, "eth0.json"), &length);
	/* `cat /run/netcfgd/desired/eth0.json` answers a question about one
	 * interface without a reader having to find it inside the whole file --
	 * and the slice is proved to be that interface before it is written. */
	check(one && strstr(one, "\"name\":\"eth0\"") && !strstr(one, "wlan0"),
	    "each interface has a file of its own, carrying itself and nothing else");
	free(one);
	one = testdir_read(join(desired_dir, "wlan0.json"), &length);
	check(one && strstr(one, "\"name\":\"wlan0\"") && !strstr(one, "eth0"),
	    "for every interface, not only the first");
	free(one);

	check(!testdir_exists(stale),
	    "and a projection the configuration dropped is removed, not left claiming");
	ncfg_document_free(document);

	/* No interfaces, no directory: the filesystem reflects use, not
	 * capability. */
	document = ncfg_document_new(message, sizeof(message));
	check(ncfg_state_write_desired(run_dir, document, message, sizeof(message)) &&
	    !testdir_exists(join(desired_dir, "eth0.json")),
	    "a document with no interfaces leaves no projections behind");
	ncfg_document_free(document);
	(void)rmdir(desired_dir);
	free(stale);
	free(desired_dir);
}

/* An observation with two links, an address on each and one route, read from
 * JSON so that the fixture is the shape the model reads rather than a struct
 * built by hand. */
static ncfg_observed_t *two_links(void)
{
	static const char text[] =
	    "{\"links\":[{\"name\":\"eth0\",\"index\":2,\"mtu\":1500,\"up\":true,"
	    "\"carrier\":true,\"ownership\":\"ours\"},"
	    "{\"name\":\"wlan0\",\"index\":3,\"mtu\":1500,\"up\":false,"
	    "\"carrier\":false,\"wireless\":true,\"ownership\":\"unknown\"}],"
	    "\"addresses\":[{\"interface\":\"eth0\",\"address\":\"10.0.0.1/24\","
	    "\"ownership\":\"ours\"},"
	    "{\"interface\":\"wlan0\",\"address\":\"10.9.9.9/24\","
	    "\"ownership\":\"unknown\"}],"
	    "\"routes\":[{\"interface\":\"eth0\",\"destination\":\"default\","
	    "\"via\":\"10.0.0.254\",\"ownership\":\"ours\"}]}";
	char             message[NCFG_ERROR_MAX] = "";
	ncfg_observed_t *observed = ncfg_observed_read(text, sizeof(text) - 1u, message,
	    sizeof(message));

	if (!observed) {
		printf("could not read the observation fixture: %s\n", message);
		exit(1);
	}
	return observed;
}

static void the_observation_is_written_whole(const char *run_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	ncfg_observed_t *observed = ncfg_observed_new(message, sizeof(message));
	char *whole;
	char *one;
	char *observed_dir = strdup(join(run_dir, "observed"));
	char *stale = strdup(join(observed_dir, "gone.json"));

	check(observed && ncfg_state_write_observed(run_dir, observed, message, sizeof(message)),
	    "the observation is written whole");
	whole = testdir_read(join(run_dir, "observed.json"), NULL);
	check(whole && whole[0] == '{', "and is a document a reader can `cat`");
	free(whole);
	check(!testdir_exists(observed_dir),
	    "a machine with no links leaves no per-link directory behind");
	ncfg_observed_free(observed);

	/* And the per-link views, which are what a reader asking about one
	 * interface uses instead of filtering the whole-host file. */
	check(mkdir(observed_dir, 0755) == 0 && testdir_write(stale, "{}", 2u),
	    "a per-link view for a link this machine no longer has");
	observed = two_links();
	check(ncfg_state_write_observed(run_dir, observed, message, sizeof(message)),
	    "an observation with two links is written");
	one = testdir_read(join(observed_dir, "eth0.json"), NULL);
	/*
	 * The link, the addresses on it and the routes on it -- and nothing
	 * belonging to the other link. A projection that carried the whole-host
	 * lists would be the file it exists to save a reader from.
	 */
	check(one && strstr(one, "\"link\":{\"name\":\"eth0\"") != NULL &&
	        strstr(one, "10.0.0.1/24") != NULL && strstr(one, "10.0.0.254") != NULL,
	    "each link has a file carrying itself, its addresses and its routes");
	check(one && strstr(one, "wlan0") == NULL && strstr(one, "10.9.9.9") == NULL,
	    "  and nothing belonging to another link");
	free(one);
	one = testdir_read(join(observed_dir, "wlan0.json"), NULL);
	check(one && strstr(one, "10.9.9.9/24") != NULL && strstr(one, "\"routes\":[]") != NULL,
	    "for every link, and a link with no routes says so with an empty list");
	free(one);
	check(!testdir_exists(stale),
	    "and a view of a link that has gone is removed, not left claiming it is there");
	ncfg_observed_free(observed);

	/*
	 * And a name that could not be a filename, which is reachable rather than
	 * defensive: a link list is read back out of `observed.json` as well as
	 * taken from the kernel, and a file somebody edited can carry any string
	 * at all. `../` in it would put a per-link view outside the directory.
	 */
	{
		static const char escape[] =
		    "{\"links\":[{\"name\":\"../escaped\",\"index\":9,\"mtu\":1500,"
		    "\"up\":false,\"carrier\":false,\"ownership\":\"unknown\"}]}";
		ncfg_observed_t *bad = ncfg_observed_read(escape, sizeof(escape) - 1u, message,
		    sizeof(message));

		if (bad) {
			message[0] = '\0';
			check(!ncfg_state_write_observed(run_dir, bad, message, sizeof(message)) &&
			        strstr(message, "cannot be a filename") != NULL,
			    "a link whose name could not be a filename is refused by name");
			check(!testdir_exists(join(run_dir, "escaped.json")),
			    "  and nothing was written outside the directory");
			ncfg_observed_free(bad);
		} else {
			check(0, "the escaping fixture reads");
		}
	}

	(void)unlink(join(observed_dir, "eth0.json"));
	(void)unlink(join(observed_dir, "wlan0.json"));
	(void)rmdir(observed_dir);
	free(stale);
	free(observed_dir);
	(void)unlink(join(run_dir, "observed.json"));
}

/* ----------------------------------------------------------- the reports */

/* Verbatim from `doc/interface-report.md`. If the two disagree, the document
 * is right. */
static const char THE_DOCUMENTED_EXAMPLE[] =
    "# wwan0, connected 2026-07-31T14:02:11Z via three.co.uk\n"
    "address=10.64.1.23/30\n"
    "gateway=10.64.1.24\n"
    "dns=8.8.8.8\n"
    "dns=2001:4860:4860::8888\n";

static int parsed(const char *body, ncfg_observed_report_t *out)
{
	char message[NCFG_ERROR_MAX] = "";

	return ncfg_state_parse_report("wwan0", body, strlen(body), out, message,
	    sizeof(message));
}

static void the_report_format_is_the_contract(void)
{
	ncfg_observed_report_t report;

	check(parsed(THE_DOCUMENTED_EXAMPLE, &report) &&
	    report.address_count == 1u && strcmp(report.addresses[0], "10.64.1.23/30") == 0 &&
	    report.gateway_count == 1u && strcmp(report.gateways[0], "10.64.1.24") == 0 &&
	    report.nameserver_count == 2u && strcmp(report.nameservers[0], "8.8.8.8") == 0 &&
	    strcmp(report.nameservers[1], "2001:4860:4860::8888") == 0,
	    "the documented example parses to what it says");
	ncfg_state_report_free(&report);

	/* **Unknown keys are ignored, and that is a promise the contract makes.**
	 * A reader that refused here would break every helper the day it learned a
	 * new field. */
	check(parsed("mtu=1428\noperator=three.co.uk\naddress=10.0.0.1/32\nsignal=-71\n",
	    &report) && report.address_count == 1u && report.gateway_count == 0u,
	    "a key netcfgd does not know yet does not cost the rest of the report");
	ncfg_state_report_free(&report);

	/* A bearer that came up with a usable v4 address and a mangled v6 one
	 * should still get the v4. Losing the file over one line is the failure
	 * that leaves somebody with no connectivity and no explanation. */
	check(parsed("address=10.0.0.1/32\nthis is not a key=value line at all\n"
	    "gateway=\naddress=\n\ndns=1.1.1.1\n", &report) &&
	    report.address_count == 1u && report.gateway_count == 0u &&
	    report.nameserver_count == 1u,
	    "a bad line does not discard the good ones, and an empty value is not one");
	ncfg_state_report_free(&report);

	check(parsed("  # a comment, indented\n\t address = 10.0.0.1/32 \t\n\n#dns=8.8.8.8\n",
	    &report) && report.address_count == 1u &&
	    strcmp(report.addresses[0], "10.0.0.1/32") == 0 && report.nameserver_count == 0u,
	    "comments and whitespace are what the document says they are");
	ncfg_state_report_free(&report);

	/* Distinct from no file at all only in that somebody said so, which is
	 * exactly the distinction the contract asks helpers to make. */
	check(parsed("", &report) && strcmp(report.interface, "wwan0") == 0 &&
	    report.address_count == 0u,
	    "an empty report is a bearer that is down");
	ncfg_state_report_free(&report);

	check(parsed("dns=9.9.9.9\ndns=1.1.1.1\ndns=8.8.8.8\n", &report) &&
	    report.nameserver_count == 3u && strcmp(report.nameservers[0], "9.9.9.9") == 0 &&
	    strcmp(report.nameservers[2], "8.8.8.8") == 0,
	    "repeats keep the order they were written in");
	ncfg_state_report_free(&report);

	check(parsed("route=10.0.0.0/8 via 10.8.0.1\nroute=192.168.5.0/24\n", &report) &&
	    report.route_count == 2u &&
	    strcmp(report.routes[0].destination, "10.0.0.0/8") == 0 &&
	    report.routes[0].via && strcmp(report.routes[0].via, "10.8.0.1") == 0 &&
	    report.routes[1].via == NULL,
	    "a route is read the way a config file spells one");
	ncfg_state_report_free(&report);

	/* Not refused: `metric 50` silently ignored would be a route with a metric
	 * netcfgd chose and an operator thought they had. */
	check(parsed("route=10.0.0.0/8 metric 50\nroute=10.1.0.0/16 via 10.8.0.1 metric 50\n"
	    "route=10.2.0.0/16 via\nroute=10.3.0.0/16 via 10.8.0.1\n", &report) &&
	    report.route_count == 1u &&
	    strcmp(report.routes[0].destination, "10.3.0.0/16") == 0,
	    "a route line the contract does not define is skipped, not half-applied");
	ncfg_state_report_free(&report);

	/* One card and one source rather than a list: a second line is a writer
	 * correcting itself within one file. */
	check(parsed("iccid=8944\nsim=first\niccid=8945\n", &report) &&
	    report.iccid && strcmp(report.iccid, "8945") == 0 &&
	    report.sim && strcmp(report.sim, "first") == 0,
	    "the card and its source take the last word, where every other key adds");
	ncfg_state_report_free(&report);
}

static void two_clients_on_one_interface_keep_both_their_answers(const char *run_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	ncfg_observed_report_t *reports = NULL;
	size_t count = 0;
	char *fragments = strdup(join(run_dir, "reported.d/wan0"));

	check(ncfg_state_read_reports("/nonexistent/netcfgd-test-run-dir", &reports, &count,
	    message, sizeof(message)) && count == 0u,
	    "a machine with nothing reporting reports nothing");

	check(mkdir(join(run_dir, "reported"), 0755) == 0 &&
	    mkdir(join(run_dir, "reported.d"), 0755) == 0 && mkdir(fragments, 0755) == 0,
	    "a v4 client's single file and a v6 client's fragment");
	(void)testdir_write(join(run_dir, "reported/wan0"),
	    "address=192.0.2.10/24\ndns=8.8.8.8\n", 34u);
	/* The contract tells every writer to stage in the same directory and
	 * rename over the target, so the half-written file it exists to hide is
	 * sitting right here -- and it was read as a report for an interface named
	 * after the temporary file (0113). */
	(void)testdir_write(join(run_dir, "reported/.wan0.tmp"), "address=10.9.9.9/32\n", 20u);
	(void)testdir_write(join(fragments, "dhcpcd6"),
	    "dns=2001:4860:4860::8888\nsearch=example.net\n", 43u);
	(void)testdir_write(join(fragments, ".dhcpcd6.tmp"), "dns=9.9.9.9\n", 12u);

	check(ncfg_state_read_reports(run_dir, &reports, &count, message, sizeof(message)) &&
	    count == 1u,
	    "one interface, one report, whichever files it was assembled from");
	check(count == 1u && reports[0].nameserver_count == 2u &&
	    strcmp(reports[0].nameservers[0], "8.8.8.8") == 0 &&
	    strcmp(reports[0].nameservers[1], "2001:4860:4860::8888") == 0,
	    "the single file first and the fragments after, so v4 precedes v6 every boot");
	check(count == 1u && reports[0].address_count == 1u && reports[0].search_count == 1u,
	    "and everything else merges rather than the last writer winning");
	ncfg_state_reports_free(reports, count);

	/* `readdir` order is the filesystem's. A nameserver list that came back
	 * differently between boots would make a plan differ from the last one for
	 * a reason nobody could see. */
	(void)unlink(join(run_dir, "reported/wan0"));
	(void)unlink(join(fragments, "dhcpcd6"));
	(void)testdir_write(join(fragments, "zzz"), "dns=3.3.3.3\n", 12u);
	(void)testdir_write(join(fragments, "aaa"), "dns=1.1.1.1\n", 12u);
	(void)testdir_write(join(fragments, "mmm"), "dns=2.2.2.2\n", 12u);
	reports = NULL;
	count = 0;
	check(ncfg_state_read_reports(run_dir, &reports, &count, message, sizeof(message)) &&
	    count == 1u && reports[0].nameserver_count == 3u &&
	    strcmp(reports[0].nameservers[0], "1.1.1.1") == 0 &&
	    strcmp(reports[0].nameservers[2], "3.3.3.3") == 0,
	    "fragments are read in name order, whatever order the directory holds");
	/* A v6-only network has no DHCPv4 client, so nothing writes the single
	 * file -- and a reader that walked `reported/` and decorated what it found
	 * would report nothing at all for exactly that machine (0086). */
	check(count == 1u && strcmp(reports[0].interface, "wan0") == 0,
	    "an interface with only fragments is still an interface");
	ncfg_state_reports_free(reports, count);

	(void)unlink(join(fragments, "zzz"));
	(void)unlink(join(fragments, "aaa"));
	(void)unlink(join(fragments, "mmm"));
	(void)unlink(join(fragments, ".dhcpcd6.tmp"));
	(void)unlink(join(run_dir, "reported/.wan0.tmp"));
	(void)rmdir(fragments);
	(void)rmdir(join(run_dir, "reported.d"));
	(void)rmdir(join(run_dir, "reported"));
	free(fragments);
}

static void the_delegations_a_client_reported(const char *run_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	ncfg_delegation_t *delegations = NULL;
	size_t count = 0;
	char *dir = strdup(join(run_dir, "prefixes"));

	check(ncfg_state_read_delegations(run_dir, &delegations, &count, message,
	    sizeof(message)) && count == 0u,
	    "a machine that is not a router has no delegations and that is not an error");

	(void)mkdir(dir, 0755);
	(void)testdir_write(join(dir, "wan0"),
	    "# what the lease said\n2001:db8:1::/64\n\n2001:db8:2::/64\n", 55u);
	/* An empty file means the lease expired and the hook recorded that, which
	 * differs from no file at all only in that it says so deliberately. */
	(void)testdir_write(join(dir, "wan1"), "", 0u);
	(void)testdir_write(join(dir, ".wan2.tmp"), "2001:db8:9::/64\n", 16u);

	check(ncfg_state_read_delegations(run_dir, &delegations, &count, message,
	    sizeof(message)) && count == 2u,
	    "one delegation per interface, and a staging file is not one");
	check(count == 2u && strcmp(delegations[0].interface, "wan0") == 0 &&
	    delegations[0].prefix_count == 2u &&
	    strcmp(delegations[0].prefixes[0], "2001:db8:1::/64") == 0,
	    "comments and blank lines are ignored, and the order is the lease's");
	check(count == 2u && delegations[1].prefix_count == 0u,
	    "and an expired lease is an interface with no prefixes");
	ncfg_state_delegations_free(delegations, count);

	(void)unlink(join(dir, "wan0"));
	(void)unlink(join(dir, "wan1"));
	(void)unlink(join(dir, ".wan2.tmp"));
	(void)rmdir(dir);
	free(dir);
}

/*
 * **What a file written under `/run` ends up being readable by.**
 *
 * The rule every comment about these files already states: the mode passed in
 * is what the file is opened with, and **the umask decides the rest**. 0666 on
 * an ordinary record means "as open as this machine's umask allows"; 0600 on a
 * credential means 0600, because a umask can only clear bits that are already
 * set and those two are the owner's.
 *
 * It stopped being true and nothing noticed. The atomic write set the mode on
 * the descriptor as well as the open -- for a good reason, a credential must
 * not inherit the mode of a temporary an earlier run left -- and `fchmod`
 * ignores the umask. So every record netcfgd wrote under `/run` came out 0666
 * rather than 0644: `owned.json` among them, which is the record deciding what
 * netcfgd will remove, world-writable on a machine where any local user could
 * edit it. Found by comparing the two implementations' output file by file.
 *
 * `O_EXCL` answers both: there is no file to inherit from, so the open's mode
 * is the whole of it.
 */
static void what_a_written_file_is_readable_by(const char *dir)
{
	static const unsigned modes[] = { 0666u, 0644u, 0600u };
	static const mode_t   masks[] = { 0000, 0022, 0077 };
	char                  err[NCFG_ERROR_MAX];
	size_t                at;
	size_t                mask_at;
	unsigned              agreed = 0;
	unsigned              tried = 0;
	mode_t                kept;

	printf("\n-- what a written file is readable by\n");
	kept = umask(0);
	for (mask_at = 0; mask_at < sizeof(masks) / sizeof(masks[0]); mask_at++) {
		(void)umask(masks[mask_at]);
		for (at = 0; at < sizeof(modes) / sizeof(modes[0]); at++) {
			char        path[512];
			struct stat found;
			unsigned    wanted = modes[at] & (unsigned)~masks[mask_at];

			(void)snprintf(path, sizeof(path), "%s/mode-%zu-%zu", dir, mask_at, at);
			err[0] = '\0';
			tried++;
			if (!ncfg_write_atomically(path, "x", 1u, modes[at], err, sizeof(err))) {
				printf("       could not write: %s\n", err);
				continue;
			}
			if (stat(path, &found) != 0) {
				printf("       could not stat what was written\n");
				continue;
			}
			if ((found.st_mode & 0777u) == wanted) {
				agreed++;
			} else {
				printf("       umask %03o, asked %04o, got %04o, wanted %04o\n",
				    (unsigned)masks[mask_at], modes[at],
				    (unsigned)(found.st_mode & 0777u), wanted);
			}
			(void)unlink(path);
		}
	}
	(void)umask(kept);
	check(tried == 9u, "nine combinations of mode and umask were tried");
	check(agreed == tried,
	    "  and every file came out at the mode asked for with the umask applied, "
	    "which is what keeps a record out of a stranger's reach");

	/* And the half that must not follow the umask down to nothing: a
	 * credential is 0600 whatever the umask, because those are the owner's
	 * bits and a umask only clears what is already set elsewhere. */
	kept = umask(0);
	{
		char        path[512];
		struct stat found;

		(void)snprintf(path, sizeof(path), "%s/credential", dir);
		err[0] = '\0';
		check(ncfg_write_atomically(path, "secret", 6u, 0600u, err, sizeof(err)) &&
		    stat(path, &found) == 0 && (found.st_mode & 0777u) == 0600u,
		    "and a credential is 0600 even where the umask would allow more");
		(void)unlink(path);
	}
	(void)umask(kept);

	/*
	 * **And the hazard `O_EXCL` is actually for.**
	 *
	 * A run that died between creating the temporary and renaming it leaves
	 * one behind. Opening that with `O_TRUNC` writes a credential into a file
	 * whose mode is whatever the dead run left -- which is the reason the
	 * `fchmod` was there, and dropping it without `O_EXCL` would bring the
	 * hazard back in silence. The umask checks above do not notice: with no
	 * leftover, truncating and creating exclusively do the same thing, and a
	 * sabotage that swapped them passed every one of them.
	 *
	 * The temporary is `.<name>.<pid>.<counter>` and the counter is a static
	 * this test cannot read. So a leftover is laid at every plausible counter
	 * instead: whichever one the write picks, it finds a world-readable file
	 * in its way.
	 */
	{
		char        path[512];
		char        leftover[512];
		struct stat found;
		unsigned    at_seq;

		(void)snprintf(path, sizeof(path), "%s/after-a-crash", dir);
		for (at_seq = 0; at_seq < 64u; at_seq++) {
			int fd;

			(void)snprintf(leftover, sizeof(leftover), "%s/.after-a-crash.%ld.%u",
			    dir, (long)getpid(), at_seq);
			fd = open(leftover, O_WRONLY | O_CREAT | O_TRUNC, 0666);
			if (fd >= 0) {
				(void)chmod(leftover, 0666);
				(void)close(fd);
			}
		}
		err[0] = '\0';
		check(ncfg_write_atomically(path, "secret", 6u, 0600u, err, sizeof(err)) &&
		    stat(path, &found) == 0 && (found.st_mode & 0777u) == 0600u,
		    "and a credential written over a temporary a dead run left is still 0600");
		(void)unlink(path);
		for (at_seq = 0; at_seq < 64u; at_seq++) {
			(void)snprintf(leftover, sizeof(leftover), "%s/.after-a-crash.%ld.%u",
			    dir, (long)getpid(), at_seq);
			(void)unlink(leftover);
		}
	}
}

/*
 * **And what a record ends up as, whatever the umask is.**
 *
 * The case above is about the mechanism: a mode asked for, reduced by the
 * umask, which is what an `open` does. This is about what the callers ask
 * *for*, and it is a different question with a different answer.
 *
 * These files used to be opened `0666` with a comment saying the umask would
 * decide. True, and not enough: a daemon started with a umask of zero -- from
 * a container entrypoint, or an init script that cleared it -- then wrote
 * every record world-writable, `owned.json` among them, which is the record
 * deciding what netcfgd will remove. `NCFG_RUN_FILE_MODE` is `0644` stated
 * rather than hoped for, and this is the check that says the writers use it.
 *
 * Driven under a umask of zero deliberately: with an ordinary one the wrong
 * answer and the right answer are the same file.
 */
static void a_record_is_never_world_writable(const char *dir)
{
	char             message[NCFG_ERROR_MAX];
	char             path[512];
	ncfg_observed_t *observed;
	struct stat      found;
	mode_t           kept;

	printf("\n-- what a record is, whatever the umask\n");
	observed = ncfg_observed_read("{\"links\":[]}", 12u, message, sizeof(message));
	if (!observed) {
		check(0, "an observation to write");
		return;
	}
	kept = umask(0);
	message[0] = '\0';
	check(ncfg_state_write_observed(dir, observed, message, sizeof(message)),
	    "an observation is written under a umask of zero");
	if (message[0]) { printf("       %s\n", message); }
	(void)snprintf(path, sizeof(path), "%s/observed.json", dir);
	/* **The number, not the constant.** Comparing against
	 * `NCFG_RUN_FILE_MODE` makes the assertion move with the thing it is
	 * asserting: a sabotage that set the constant to `0666` passed, because
	 * the file was then 0666 and so was what it was compared to. */
	check(stat(path, &found) == 0 && (found.st_mode & 0777u) == 0644u,
	    "  and it is 0644, not whatever the umask happened to allow");
	check((found.st_mode & 0022u) == 0u,
	    "  so no group and no stranger can write the record netcfgd reads back");
	(void)umask(kept);
	ncfg_observed_free(observed);
}

int main(void)
{
	const char *run_dir = testdir_make("state");

	what_a_written_file_is_readable_by(run_dir);
	a_record_is_never_world_writable(run_dir);

	printf("== state_test in %s\n", run_dir);
	the_run_directory_is_chosen_in_one_order();
	the_record_round_trips(run_dir);
	a_record_from_another_boot_is_discarded(run_dir);
	a_record_with_no_boot_recorded_is_kept(run_dir);
	a_record_that_will_not_parse_is_discarded_rather_than_fatal(run_dir);
	the_backends_and_scopes_a_rust_netcfgd_recorded(run_dir);
	a_backend_this_build_cannot_describe_is_refused(run_dir);
	two_writers_of_one_file_do_not_share_a_temporary(run_dir);
	two_updaters_do_not_lose_each_others_records(run_dir);
	provenance_round_trips(run_dir);
	the_desired_document_and_its_projections(run_dir);
	the_observation_is_written_whole(run_dir);
	the_report_format_is_the_contract();
	two_clients_on_one_interface_keep_both_their_answers(run_dir);
	the_delegations_a_client_reported(run_dir);
	testdir_remove(run_dir);

	if (failures == 0) {
		printf("state_test: all checks passed\n");
	} else {
		printf("state_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
