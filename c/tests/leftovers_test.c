/*
 * leftovers_test.c -- classifying what netcfgd inherited in its control group.
 *
 * NOTHING HERE READS THE MACHINE
 *   `ncfg_leftovers_classify` takes the process table and the recorded pids as
 *   arguments, so every case below is a table this file wrote. The gathering
 *   halves that do read `/proc` and the run directory are separate functions
 *   for exactly that reason, and the run-directory half is checked against a
 *   directory `mkdtemp` made.
 *
 * WHAT IS WORTH CHECKING HERE
 *   Not that a recorded pid is recorded, which every version of this gets
 *   right including the wrong ones. What separates them:
 *
 *     * **the helper chain**, because it is the whole reason the walk exists.
 *       dhcpcd forks a privileged proxy, a control proxy and a BPF helper, and
 *       none of them is in any record -- so a classifier without the walk
 *       reports four unaccounted processes on a healthy machine and trains
 *       whoever reads it to ignore the line;
 *     * **that the walk stops at the edge of the control group**, since init
 *       reparents an orphan and every orphan's chain therefore reaches pid 1.
 *       A walk that followed it would judge a process by whatever pid 1 is;
 *     * **that a cycle terminates**, because the parent numbers come from
 *       `/proc` and two reads can catch the table mid-change. This runs at
 *       daemon startup and an unbounded loop there is a daemon that never
 *       starts;
 *     * **that the classifier can say UNACCOUNTED at all.** The sabotage is at
 *       the end: the same healthy table with the anchor's record removed must
 *       turn every one of its helpers unaccounted. Without it these cases pass
 *       just as loudly against a function that returns RECORDED for
 *       everything.
 */
#include "ncfg/leftovers.h"

#include "testdir.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
static int checks;

static void check(int condition, const char *what)
{
	checks++;
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* One row of a process table, spelled so the cases below read as tables. */
static ncfg_leftover_process_t row(pid_t pid, pid_t parent, const char *program,
    const char *command)
{
	ncfg_leftover_process_t out;

	memset(&out, 0, sizeof(out));
	out.pid = pid;
	out.parent = parent;
	(void)snprintf(out.program, sizeof(out.program), "%s", program);
	(void)snprintf(out.command, sizeof(out.command), "%s", command ? command : "");
	return out;
}

/* The verdict this classifier reached for `pid`, or -1 if it said nothing. */
static int verdict_of(const ncfg_leftover_finding_t *found, size_t count, pid_t pid)
{
	size_t at;

	for (at = 0u; at < count; at++) {
		if (found[at].process.pid == pid) {
			return (int)found[at].verdict;
		}
	}
	return -1;
}

static pid_t anchor_of(const ncfg_leftover_finding_t *found, size_t count, pid_t pid)
{
	size_t at;

	for (at = 0u; at < count; at++) {
		if (found[at].process.pid == pid) {
			return found[at].anchor;
		}
	}
	return -1;
}

/* ------------------------------------------------------------------------ *
 * The machine this was written on, as a table
 *
 * Taken from `debian-nabbe` on 2026-09-28, where a restart of the C daemon
 * left six processes in netcfgd's control group and systemd reported every one
 * of them as evidence of an unclean stop. The supplicant is recorded in
 * `/run/netcfgd/supplicant/wlp0s20f3.pid`; the dhcpcd family is one client and
 * three helpers, and only the client is anything netcfgd wrote down.
 * ------------------------------------------------------------------------ */

#define REAL_COUNT 5u

static void real_table(ncfg_leftover_process_t *out)
{
	out[0] = row(1256, 1, "wpa_supplicant",
	    "/usr/sbin/wpa_supplicant -B -Dnl80211,wext -s -i wlp0s20f3");
	/* The titles are `setproctitle`'s, copied from `ps` on the machine: the
	 * client names the interface and two of its three helpers do not. */
	out[1] = row(3061114, 1, "dhcpcd", "dhcpcd: wlp0s20f3 [ip4]");
	out[2] = row(3061115, 3061114, "dhcpcd", "dhcpcd: [privileged proxy] wlp0s20f3 [ip4]");
	out[3] = row(3061116, 3061114, "dhcpcd", "dhcpcd: [control proxy] wlp0s20f3 [ip4]");
	out[4] = row(975891, 3061115, "dhcpcd", "dhcpcd: [BPF ARP] 10.0.125.56");
}

static void the_machine_that_prompted_this_is_all_accounted_for(void)
{
	ncfg_leftover_process_t found[REAL_COUNT];
	ncfg_leftover_finding_t out[REAL_COUNT];
	const pid_t             recorded[] = {1256, 3061114};
	size_t                  count;

	real_table(found);
	count = ncfg_leftovers_classify(found, REAL_COUNT, recorded, 2u, NULL, 0u, out,
	    REAL_COUNT);
	check(count == REAL_COUNT, "every process in the group gets a verdict");
	check(verdict_of(out, count, 1256) == NCFG_LEFTOVER_RECORDED,
	    "the supplicant is recorded, by the pid file netcfgd wrote");
	check(verdict_of(out, count, 3061114) == NCFG_LEFTOVER_RECORDED,
	    "the dhcp client is recorded although init has reparented it");
	check(verdict_of(out, count, 3061115) == NCFG_LEFTOVER_HELPER,
	    "dhcpcd's privileged proxy is a helper, and is in no record anywhere");
	check(verdict_of(out, count, 975891) == NCFG_LEFTOVER_HELPER,
	    "and so is the BPF helper, which is two levels down");
	check(anchor_of(out, count, 975891) == 3061114,
	    "a helper names the recorded process it hangs off, not its parent");
}

/*
 * **The sabotage, and it is the only case here that can fail for the right
 * reason.** Same table, same walk, one pid missing from the record -- which is
 * what a run that died between forking a client and writing its pid file
 * leaves behind. Four processes must change verdict.
 */
static void with_the_anchor_unrecorded_its_helpers_are_unaccounted(void)
{
	ncfg_leftover_process_t found[REAL_COUNT];
	ncfg_leftover_finding_t out[REAL_COUNT];
	const pid_t             recorded[] = {1256};
	size_t                  count;
	size_t                  at;
	size_t                  unaccounted = 0u;

	real_table(found);
	count = ncfg_leftovers_classify(found, REAL_COUNT, recorded, 1u, NULL, 0u, out,
	    REAL_COUNT);
	for (at = 0u; at < count; at++) {
		if (out[at].verdict == NCFG_LEFTOVER_UNACCOUNTED) {
			unaccounted++;
		}
	}
	check(unaccounted == 4u, "dropping one pid from the record unaccounts it and its three "
	                         "helpers");
	check(verdict_of(out, count, 1256) == NCFG_LEFTOVER_RECORDED,
	    "and leaves the supplicant alone, so the change is the record and not the walk");
}

/*
 * **The case this machine actually presents, and the one that nearly shipped
 * wrong.**
 *
 * netcfgd writes a pid file for udhcpc and odhcp6c because it starts them with
 * `-p`. It writes none for dhcpcd, which destroys its argv with `setproctitle`
 * and is identified by asking its control socket which config file it was
 * started with (0143). So on a dhcpcd machine -- the default -- nothing under
 * the run directory names the client, and a classifier that knew only about
 * pid files reported the whole healthy family as evidence of an unclean stop.
 *
 * That was measured before it was fixed: `/run/netcfgd/dhcpcd/` held one config
 * symlink and no `.pid` after four days of correct running, while `owned.json`
 * said `dhcp4` on `wlp0s20f3` was running.
 */
static void a_dhcpcd_family_with_no_pid_file_is_not_an_alarm(void)
{
	ncfg_leftover_process_t found[REAL_COUNT];
	ncfg_leftover_finding_t out[REAL_COUNT];
	const pid_t             recorded[] = {1256}; /* the supplicant, and nothing else */
	const char             *claimed[] = {"wlp0s20f3"};
	size_t                  count;
	size_t                  at;
	size_t                  unaccounted = 0u;

	real_table(found);
	count = ncfg_leftovers_classify(found, REAL_COUNT, recorded, 1u, claimed, 1u, out,
	    REAL_COUNT);
	for (at = 0u; at < count; at++) {
		if (out[at].verdict == NCFG_LEFTOVER_UNACCOUNTED) {
			unaccounted++;
		}
	}
	check(unaccounted == 0u, "a dhcpcd family netcfgd cannot name by pid raises no alarm");
	check(verdict_of(out, count, 3061114) == NCFG_LEFTOVER_CLAIMED,
	    "the client is claimed, by the interface the record says it is running on");
	check(verdict_of(out, count, 975891) == NCFG_LEFTOVER_HELPER,
	    "and its BPF helper, whose own title names no interface, is a helper of it");
	/*
	 * **These two said 3061115 until 2026-10-01, and the old answer is what
	 * misled a reader.**
	 *
	 * The privileged proxy's own title carries the interface, so it was
	 * claimed in its own right and the walk stopped on it: the BPF helper
	 * reported the proxy, and the proxy reported the record. Nothing was
	 * hidden -- every verdict was an accounted-for one -- but the log then read
	 * as several backends the record claims with no pid written down, where
	 * there is one client and its helpers. A session reading that journal on
	 * the holder's machine reported it as processes accumulating across
	 * restarts. It was dhcpcd's privilege separation: one client, a privileged
	 * proxy, a control proxy and two per-address helpers.
	 *
	 * So a claimed process whose parent is also accounted for is now a helper
	 * of it, and the walk runs past a helper rather than stopping on one --
	 * which keeps the recorded case's property that a helper names the thing
	 * netcfgd recorded and not the intermediate. Both halves are needed: the
	 * first without the second anchors a grandchild on a proxy.
	 */
	check(anchor_of(out, count, 975891) == 3061114,
	    "anchored on the client rather than on the proxy between them");
	check(verdict_of(out, count, 3061115) == NCFG_LEFTOVER_HELPER,
	    "and the proxy is a helper of that client, not a backend of its own");
}

/*
 * And the claim is a whole word, because interface names nest.
 *
 * A record claiming `wlan0` must not quieten a process on `wlan01`. This is the
 * one place a weak marker could withhold an alarm about the wrong thing.
 */
static void a_claim_on_one_interface_does_not_cover_another(void)
{
	ncfg_leftover_process_t found[2];
	ncfg_leftover_finding_t out[2];
	const char             *claimed[] = {"wlan0"};
	size_t                  count;

	found[0] = row(70, 1, "dhcpcd", "dhcpcd: wlan01 [ip4]");
	found[1] = row(71, 1, "dhcpcd", "dhcpcd: wlan0 [ip4]");
	count = ncfg_leftovers_classify(found, 2u, NULL, 0u, claimed, 1u, out, 2u);
	check(verdict_of(out, count, 70) == NCFG_LEFTOVER_UNACCOUNTED,
	    "a claim on wlan0 does not cover a process on wlan01");
	check(verdict_of(out, count, 71) == NCFG_LEFTOVER_CLAIMED,
	    "while the interface actually claimed is covered");
}

/*
 * A parent outside the control group ends the walk.
 *
 * Without this every orphan reaches pid 1, and a classifier that kept walking
 * would ask whether pid 1 is one of netcfgd's recorded backends -- which it
 * would answer correctly today and wrongly the moment a recorded pid was
 * recycled as something's ancestor.
 */
static void a_chain_that_leaves_the_group_stops_there(void)
{
	ncfg_leftover_process_t found[2];
	ncfg_leftover_finding_t out[2];
	size_t                  count;
	/*
	 * pid 1 is put in the record deliberately, which is absurd and is the
	 * point: if the walk ever leaves the control group it arrives here, and
	 * the only thing stopping it is that 999 is not a member.
	 */
	const pid_t recorded[] = {1, 500};

	found[0] = row(4242, 999, "udhcpc", "udhcpc -i wlan9"); /* 999 is not a member */
	found[1] = row(600, 500, "openvpn", "openvpn --config x"); /* 500 is recorded */
	count = ncfg_leftovers_classify(found, 2u, recorded, 2u, NULL, 0u, out, 2u);
	check(verdict_of(out, count, 4242) == NCFG_LEFTOVER_UNACCOUNTED,
	    "a chain through a non-member stops there rather than reaching pid 1");
	check(verdict_of(out, count, 600) == NCFG_LEFTOVER_HELPER,
	    "while a chain that does reach a recorded pid still resolves");
}

/* A cycle terminates rather than hanging the daemon at startup. */
static void a_parent_cycle_terminates(void)
{
	ncfg_leftover_process_t found[2];
	ncfg_leftover_finding_t out[2];
	const pid_t             recorded[] = {7};
	size_t                  count;

	found[0] = row(10, 11, "a", "a");
	found[1] = row(11, 10, "b", "b");
	count = ncfg_leftovers_classify(found, 2u, recorded, 1u, NULL, 0u, out, 2u);
	check(count == 2u, "a cycle in the parent chain returns rather than looping");
	check(verdict_of(out, count, 10) == NCFG_LEFTOVER_UNACCOUNTED,
	    "and reaches no conclusion it has not earned");
}

/* An empty group and an empty record are the ordinary first start. */
static void nothing_in_the_group_is_not_a_finding(void)
{
	ncfg_leftover_finding_t out[1];

	check(ncfg_leftovers_classify(NULL, 0u, NULL, 0u, NULL, 0u, out, 1u) == 0u,
	    "no processes means no findings");
}

/* ------------------------------------------------------------------------ *
 * The run-directory half, over a directory this file made
 * ------------------------------------------------------------------------ */

static void the_recorded_pids_come_out_of_the_run_directory(void)
{
	const char *base;
	char        path[1024];
	pid_t       pids[8];
	size_t      count;
	FILE       *file;

	/* `testdir_make` leaves with a sentence rather than returning a failure,
	 * for the reason its own comment gives: a suite that carried on would run
	 * the rest of this case against the working directory. */
	base = testdir_make("leftovers");
	(void)snprintf(path, sizeof(path), "%s/supplicant", base);
	(void)mkdir(path, 0700);
	(void)snprintf(path, sizeof(path), "%s/supplicant/wlan0.pid", base);
	file = fopen(path, "we");
	if (file) {
		(void)fprintf(file, "1256\n");
		(void)fclose(file);
	}
	/* A file that is not a pid file, beside one that is: the run directory
	 * holds config symlinks and sockets in the same places. */
	(void)snprintf(path, sizeof(path), "%s/supplicant/wlan0.networks.sha256", base);
	file = fopen(path, "we");
	if (file) {
		(void)fprintf(file, "deadbeef\n");
		(void)fclose(file);
	}
	/* And one that will not parse, which must be skipped rather than counted
	 * as pid 0. */
	(void)snprintf(path, sizeof(path), "%s/openvpn", base);
	(void)mkdir(path, 0700);
	(void)snprintf(path, sizeof(path), "%s/openvpn/tun0.pid", base);
	file = fopen(path, "we");
	if (file) {
		(void)fprintf(file, "not a number\n");
		(void)fclose(file);
	}

	count = ncfg_leftovers_recorded_pids(base, pids, 8u);
	check(count == 1u, "only the readable pid file counts");
	check(count == 1u && pids[0] == 1256, "and it yields the pid the previous run wrote");
	check(ncfg_leftovers_recorded_pids("/nonexistent-ncfg-leftovers", pids, 8u) == 0u,
	    "an absent run directory reads as no record rather than as a failure");
	testdir_remove(base);
}

int main(void)
{
	the_machine_that_prompted_this_is_all_accounted_for();
	a_dhcpcd_family_with_no_pid_file_is_not_an_alarm();
	a_claim_on_one_interface_does_not_cover_another();
	with_the_anchor_unrecorded_its_helpers_are_unaccounted();
	a_chain_that_leaves_the_group_stops_there();
	a_parent_cycle_terminates();
	nothing_in_the_group_is_not_a_finding();
	the_recorded_pids_come_out_of_the_run_directory();

	printf("leftovers_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("leftovers_test: all checks passed\n");
	} else {
		printf("leftovers_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
