/*
 * leftovers.h -- what netcfgd inherited in its own control group, and whether
 * it can account for it.
 *
 * WHY THIS EXISTS
 *   `KillMode=process` in the packaged unit is deliberate (0134, 0142): a stop
 *   leaves the supplicant, the DHCP client and the tunnels running, so an
 *   upgrade does not take the network down. systemd reports that arrangement
 *   on every single start:
 *
 *       Found left-over process 3061114 (dhcpcd) in control group while
 *       starting unit. Ignoring.
 *       This usually indicates unclean termination of a previous run, or
 *       service implementation deficiencies.
 *
 *   Both sentences are systemd's honest reading and neither is true here. The
 *   cost is not the noise, it is that **the same two lines are what a real
 *   unclean stop looks like**. 0177 paid for that once: netcfgd started beside
 *   an orphan of its own, systemd logged exactly that line, and the orphan and
 *   the new supplicant deauthenticated each other until the association went.
 *   The message was the available signal and it is indistinguishable from the
 *   message printed every ordinary restart.
 *
 *   Measured on systemd 257 with four throwaway units: no directive suppresses
 *   it. `Delegate=yes` does not, and neither does moving the survivor into a
 *   delegated sub-cgroup, because the check recurses. The only arrangement
 *   that silences it is one where nothing of netcfgd's remains in the unit's
 *   cgroup at all -- which is the thing `KillMode=process` exists to prevent.
 *
 * SO NETCFGD ANSWERS IT INSTEAD
 *   systemd names a pid and cannot say whose it is. netcfgd can: it knows
 *   which backends it started, it wrote their pid files, and 0177 turns on
 *   exactly that distinction -- *"does netcfgd still have a record of it"*.
 *   So this reads the control group at startup and says, of each process it
 *   finds, whether the previous run accounted for it.
 *
 * WHEN IT RUNS, AND WHY THAT IS BEFORE THE FIRST PASS
 *   At startup, before anything is adopted or applied. The question is what
 *   netcfgd *inherited*, and adoption is what makes an inherited process into
 *   netcfgd's again -- run afterwards this would report every survivor as
 *   accounted for and could never see the case it exists for.
 *
 * WHAT IT DOES NOT DO
 *   It signals nothing and stops nothing. 0177 decides when an orphan is
 *   terminated, and it decides that per backend with a marker and a
 *   reachability test; this is a narrower instrument that reports and leaves.
 *   A process it calls unaccounted may still be adopted moments later by a
 *   pass that knows more, and the report says so rather than implying a fault.
 */
#ifndef NCFG_LEFTOVERS_H
#define NCFG_LEFTOVERS_H

#include "ncfg/process.h"

#include <stddef.h>
#include <sys/types.h>

/*
 * How many processes a report will describe.
 *
 * A bound rather than an allocation, because this runs at startup on a machine
 * whose state is by definition not understood yet. Four backends and a DHCP
 * client's three helpers is eight; anything approaching this many is itself
 * the finding, and the reporter says how many it could not list rather than
 * growing to fit.
 */
#define NCFG_LEFTOVER_MAX 64u

/*
 * How far up a parent chain a helper may sit.
 *
 * `/proc` is data from outside this process, so a chain that loops is a thing
 * to survive rather than to assume away. Real chains here are two deep --
 * dhcpcd's BPF helper under its privileged proxy under the client.
 */
#define NCFG_LEFTOVER_WALK_MAX 16u

/*
 * How much of a process' command line is kept.
 *
 * Enough for dhcpcd's renamed self -- `dhcpcd: [BPF ARP] wlp0s20f3 10.0.125.56`
 * is 41 -- and for a supplicant's real argv. It is read to look for an
 * interface name and printed nowhere, so a truncated tail costs nothing but a
 * missed match on a pathological command line.
 */
#define NCFG_LEFTOVER_COMMAND_MAX 256u

/* An interface name, `IFNAMSIZ` without pulling in a kernel header. */
#define NCFG_LEFTOVER_IFACE_MAX 16u

typedef enum {
	/* A pid the previous run wrote down: the backends netcfgd started. */
	NCFG_LEFTOVER_RECORDED = 0,
	/*
	 * The record claims a backend on an interface this process names, and
	 * carries no pid for it.
	 *
	 * **dhcpcd is why this verdict exists and it is not an edge case.**
	 * netcfgd writes a pid file for udhcpc and odhcp6c because it starts them
	 * with `-p`; dhcpcd is told nothing of the sort, destroys its argv with
	 * `setproctitle`, and is identified by asking its control socket which
	 * config file it was started with (0143). So on any machine using dhcpcd
	 * -- which is the default -- netcfgd's record says `dhcp4 running` on an
	 * interface and names no process.
	 *
	 * Without this verdict the healthy case reports four unaccounted
	 * processes, which is the noise this file exists to remove, rebuilt one
	 * layer up and in netcfgd's own voice.
	 *
	 * **The match is an interface name in a command line, which `dhcp.h` calls
	 * the weakest marker netcfgd uses -- and this is the right place for a
	 * weak one.** It is only ever used to *withhold* an alarm, never to
	 * license an action. Being wrong means staying quiet about a process that
	 * deserved a mention, in a report nothing acts on automatically.
	 */
	NCFG_LEFTOVER_CLAIMED,
	/* Reached from a recorded or claimed pid by its parent chain. dhcpcd's
	 * privileged, control and BPF helpers are this and are in no record
	 * anywhere. */
	NCFG_LEFTOVER_HELPER,
	/* Neither, which is what a run that did not stop cleanly leaves. */
	NCFG_LEFTOVER_UNACCOUNTED
} ncfg_leftover_verdict_t;

typedef struct {
	pid_t pid;
	pid_t parent;
	char  program[NCFG_PROGRAM_MAX];
	/* The command line with its NULs turned into spaces, or empty where it
	 * could not be read. Only ever searched for an interface name. */
	char  command[NCFG_LEFTOVER_COMMAND_MAX];
} ncfg_leftover_process_t;

typedef struct {
	ncfg_leftover_process_t process;
	ncfg_leftover_verdict_t verdict;
	/* The recorded pid this one belongs to, or 0. Set for a helper so the
	 * report can name what it hangs off rather than listing four pids with no
	 * relationship between them. */
	pid_t anchor;
} ncfg_leftover_finding_t;

/*
 * The decision, with no filesystem in it, so that it can be checked.
 *
 * `found` is every process in netcfgd's control group except netcfgd itself;
 * `recorded` is every pid the previous run wrote into a pid file under its run
 * directory. Both are the caller's to gather. Returns how many findings were
 * written, which is `found_count` clamped to `out_max`.
 *
 * **A parent chain is followed only through processes in `found`.** A parent
 * outside the control group cannot be a backend of netcfgd's, and following
 * one would walk into the rest of the machine -- init reparents an orphan, so
 * every orphan's chain reaches pid 1 and would otherwise be judged by whatever
 * pid 1 happened to be.
 */
size_t ncfg_leftovers_classify(const ncfg_leftover_process_t *found, size_t found_count,
    const pid_t *recorded, size_t recorded_count, const char *const *claimed,
    size_t claimed_count, ncfg_leftover_finding_t *out, size_t out_max);

/*
 * The interfaces `owned.json` says netcfgd has a backend running on.
 *
 * What turns "a dhcpcd nobody wrote a pid for" into "the dhcp4 backend the
 * record claims on this interface". Returns how many were found, which may
 * exceed `out_max`; each is at most `NCFG_LEFTOVER_IFACE_MAX` bytes including
 * its NUL, and a longer one is skipped rather than truncated -- a truncated
 * name would match the wrong interface by prefix.
 */
size_t ncfg_leftovers_claimed_interfaces(const char *run_dir,
    char out[][NCFG_LEFTOVER_IFACE_MAX], size_t out_max);

/*
 * Every pid the run directory records, from `<run>/<backend>/<name>.pid`.
 *
 * **A pid file is read as a claim and never as proof.** It may name a process
 * that has gone, and pids are recycled -- so a stale file could name something
 * else entirely. That does not matter here and it is worth saying why: a pid
 * only ever reaches a verdict if it is also in the control group, and a
 * recycled pid that is in netcfgd's control group is netcfgd's own child. The
 * failure this could produce is under-reporting, which is the safe direction
 * for a thing that exists to raise an alarm.
 *
 * Returns how many were found, which may exceed `out_max`.
 */
size_t ncfg_leftovers_recorded_pids(const char *run_dir, pid_t *out, size_t out_max);

/*
 * Every process in this process' own service, except this one.
 *
 * Empty where netcfgd is not under a service manager -- run from a shell, or
 * under `unshare` as the live suite does -- which is `ncfg_process_in_our_service`
 * answering false rather than a failure. There is no control group to inherit
 * in those cases and nothing to report.
 */
size_t ncfg_leftovers_in_our_service(ncfg_leftover_process_t *out, size_t out_max);

/*
 * Read the control group, classify it, and say so in the log.
 *
 * Silent where it finds nothing, which is the ordinary first start of a
 * machine. Otherwise one line naming the total and a line per process, at
 * `NOTE` when everything is accounted for and `ERROR` for each process that is
 * not -- because an unaccounted process in netcfgd's control group is the one
 * thing in this file somebody has to act on.
 */
void ncfg_leftovers_report(const char *run_dir);

#endif /* NCFG_LEFTOVERS_H */
