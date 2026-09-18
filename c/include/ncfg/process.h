/*
 * process.h -- this process, and the ones netcfgd starts: finding them,
 * stopping them, and giving up what this one holds.
 *
 * **Every other daemon netcfgd runs has a control socket to be stopped
 * through** -- `wpa_supplicant`, `hostapd` and `OpenVPN` all do, and decision
 * 0014's reason for preferring one holds for each: an operator's own daemons
 * are common, and a process found *by name* would be reached along with
 * netcfgd's. So finding a process by name is forbidden here, and nothing in
 * this header does it.
 *
 * `pppd` has no socket. What it has is a pid file it writes itself, named for
 * the interface, which is a record of *this* session rather than a search for
 * something that looks like one. That is what makes signalling it defensible.
 *
 * TWO RULES, AND THEY ARE THE WHOLE DEFENSIBILITY OF THIS FILE
 *   * **The marker is a whole argument, never a substring.** It is an absolute
 *     path netcfgd composed from its own run directory and one interface, and
 *     `/proc/<pid>/cmdline` is read NUL-separated so that a proper prefix of an
 *     argument, or a longer string containing it, matches nothing. Loosen that
 *     to a substring or to a program name and the exception this file makes to
 *     the rule above is gone -- netcfgd would adopt another manager's
 *     supplicant. `process_test.c` asserts both refusals.
 *   * **The process must belong to the right user.** A marker in `argv` says
 *     nothing about who put it there: the path is composed from public parts,
 *     so any local user can type it into their own command line. Measured --
 *     `sh -c 'sleep 300' /run/netcfgd/openvpn/vpn0.sock`, run as an ordinary
 *     user, was adopted as netcfgd's `OpenVPN` backend; netcfgd recorded the
 *     start as done, started no openvpn, and reported the tunnel up. What the
 *     impostor cannot forge is privilege, so ownership is what says whether
 *     the claim is worth anything.
 *
 * WHERE THIS DIVERGES FROM THE RUST
 *   * **The privilege half lives here too**, in `ncfg_privilege_*`. The Rust
 *     splits `process.rs` from `privilege.rs`; the C port gives this module one
 *     public header because the two halves are one subject -- what this process
 *     is allowed to do, and what it does to the processes it started -- and a
 *     second header would be a second place to look for one rule.
 *   * **A lookup that finds nothing returns 0 rather than a failure with a
 *     sentence.** `base.h`'s convention is for failures an operator reads, and
 *     "no such pid file" is the ordinary answer here rather than an error: a
 *     pid file outlives the process it names, a `/proc` entry vanishes between
 *     the scan and the read, and none of that is worth a sentence. The calls
 *     that can genuinely fail -- the signals, the shed -- keep the convention
 *     exactly.
 *   * **`ncfg_process_pids_of_programs` reports how many it found and writes
 *     as many as fit**, for `0263`'s reason about the parser's 64 diagnostics:
 *     an unbounded answer to a question about `/proc` is a buffer sized by
 *     whatever is running on the machine.
 *   * **`ESRCH` is success for every signal that asks a process to stop**, and
 *     in the Rust it is success only for `terminate`. The other three say in
 *     their own doc comments that a group already gone "is the outcome that was
 *     wanted" and then return the errno anyway, so this is the documented
 *     intent being followed rather than a new rule: a caller told to stop
 *     something that has already stopped got what it asked for, and a kill in a
 *     teardown path that reports failure for the ordinary case is a caller that
 *     learns to ignore its return value. `ncfg_process_hangup` keeps `ESRCH` as
 *     a failure, and that difference is the point of it.
 *   * **`ncfg_process_kill` refuses a pid of 0 or -1**, which the Rust's `kill`
 *     is alone in not doing while `terminate`, `hangup` and both group calls
 *     do. There is no reading of that omission that makes it deliberate:
 *     `kill_group` is how a group is spelled here, so a caller reaching this
 *     one with 0 has made the mistake the other three refuse.
 */
#ifndef NCFG_PROCESS_H
#define NCFG_PROCESS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "ncfg/base.h"

/*
 * A buffer an executable's name fits in.
 *
 * `/proc/<pid>/comm` is **truncated to 15 characters** by the kernel, which is
 * why a caller's list carries `systemd-resolve` rather than `systemd-resolved`
 * -- a name that is one character too long simply never matches and the sweep
 * reports nothing. Worth knowing where the list is written.
 */
#define NCFG_PROGRAM_MAX 16

/* A `*.service` unit name, which systemd bounds well below this. */
#define NCFG_UNIT_MAX 128

/* One answer from `ncfg_process_pids_of_programs`. */
typedef struct {
	pid_t pid;
	char  program[NCFG_PROGRAM_MAX];
} ncfg_process_ref_t;

/*
 * The real and effective uids of a process, from `/proc/<pid>/status`.
 *
 * **The real uid is the one that answers "who started this", and it is not the
 * one the obvious instrument reports.** `stat` on `/proc/<pid>` gives the
 * *effective* uid, and for a setuid binary the kernel reports that directory
 * as root's -- so a process an unprivileged user launched to be mistaken for
 * netcfgd's stats as root. Measured, with a marker netcfgd composes in its own
 * argv:
 *
 *     $ sudo -k -S -p '' /run/netcfgd/openvpn/vpn0.sock < pipe &
 *     stat -c %u /proc/<pid>          ->  0
 *     grep ^Uid: /proc/<pid>/status   ->  Uid:  1000  0  0  0
 *
 * sudo will refuse the command, but the attacker chooses how long it sits at
 * the password prompt, and adoption needs to happen once. So this reads the
 * `Uid:` line and takes the first field.
 *
 * 1 where both were read, 0 where the process is gone or `/proc` will not
 * answer. Either output pointer may be NULL.
 */
int ncfg_process_uids(pid_t pid, uid_t *real_out, uid_t *effective_out);

/*
 * Whether a process could be one netcfgd started, as asked by `asking`.
 *
 * **Root, or whoever is asking** -- and the second half is not slack. netcfgd
 * applying is root, so it collapses to "root" in the case that matters. It is
 * there because `ncfg diff` and `ncfg status` observe locally and may be run by
 * anybody: a rule of "root only" would be read by an unprivileged observer as
 * every backend having stopped, and it would then plan to start them all. A
 * rule of "mine only" would refuse a root backend for the same reader. The pair
 * is the rule that is safe from both ends, and it is also what lets the tests
 * run as an ordinary user against their own children.
 */
int ncfg_process_ours(pid_t pid, uid_t asking);

/*
 * The pid in a file, if the process it names is alive and is the one expected.
 *
 * **A pid file outlives the process it names, and pids are recycled.** So the
 * pid is only half an answer: the other half is `/proc/<pid>/cmdline`, read
 * NUL-separated so that `marker` has to be a whole argument, and
 * `/proc/<pid>/status` for who started it. 0 covers every way of not knowing --
 * no file, no number in it, no such process, or a process that is somebody
 * else's.
 *
 * The marker should be as specific as the caller can make it. A path netcfgd
 * chose -- an options file, a management socket, a generated configuration --
 * is unique to one daemon on one machine; an interface name is a short string
 * an unrelated command line could contain, and is what to use only when there
 * is nothing better.
 *
 * One function because this rule was written four times: `pppd`'s pid, radvd's,
 * the `DHCP` clients' and a tunnel's. Four copies of a rule is how two of them
 * come to disagree about what counts as ownership -- and this one is a security
 * property, not a convenience.
 */
pid_t ncfg_process_pid_of(const char *path, const char *marker);

/*
 * The pid of a process carrying `marker` as a whole argument, if any.
 *
 * **`ncfg_process_pid_of`'s recovery path, and it exists because the pid file
 * is an index into a fact rather than the fact itself.** netcfgd starts its
 * supplicant with `-P <run>/supplicant/<iface>.pid`, so the process carries
 * netcfgd's mark in its own `argv` for as long as it lives. The file that holds
 * the pid does not: `RuntimeDirectory=netcfgd` means systemd deletes
 * `/run/netcfgd` on a real stop, while the supplicant -- which netcfgd
 * deliberately does not stop (0134) -- keeps running. netcfgd then cannot
 * recognise its own child, and the guard against taking another manager's radio
 * refuses it for ever, naming `NetworkManager` for a process netcfgd started
 * itself. Decision 0140.
 *
 * **This is a scan of `/proc`, which the header above forbids -- and the
 * exception is the marker, not the need.** That rule is about finding a process
 * by *name*. This matches an absolute path netcfgd composed, as a whole `argv`
 * element, by exactly the test `ncfg_process_pid_of` applies.
 *
 * The lowest matching pid, so that the answer is stable across calls when a
 * caller has somehow produced two.
 */
pid_t ncfg_process_pid_by_marker(const char *marker);

/*
 * The two above, told who is asking.
 *
 * Public, where the Rust keeps them private and reaches them from a unit test
 * in the same module: a C test links against the library and can see only what
 * the header publishes. A caller with a reason to ask on somebody else's behalf
 * -- and a test that supplies a uid its own children do not have, to watch the
 * answer be refused -- is the whole of the intended use.
 */
pid_t ncfg_process_pid_of_as(const char *path, const char *marker, uid_t asking);
pid_t ncfg_process_pid_by_marker_as(const char *marker, uid_t asking);

/*
 * The program a pid is running, from `/proc/<pid>/comm`.
 *
 * `comm` rather than `cmdline[0]`: a daemon re-executed under a path, a symlink
 * or a wrapper has whatever argv it was given, while `comm` is the kernel's own
 * name for the executable. See `NCFG_PROGRAM_MAX` for the truncation, which is
 * a fact callers have to write their lists around.
 */
int ncfg_process_program_of(pid_t pid, char *name, size_t name_size);

/*
 * Every pid whose program name is one of `names`, lowest first.
 *
 * The scan `ncfg_process_pid_by_marker` does, asked a different question: that
 * one looks for an argument netcfgd put there, and this one for programs
 * netcfgd did not start at all.
 *
 * Returns how many were found; writes the `out_max` lowest of them. A caller
 * that got back more than it had room for has the count to say so, which is
 * better than an answer silently short.
 */
size_t ncfg_process_pids_of_programs(const char *const *names, size_t name_count,
    ncfg_process_ref_t *out, size_t out_max);

/*
 * Whether a service manager is holding this process up.
 *
 * **A killed service comes straight back**, so this is the difference between
 * removing an interference and starting a fight that cannot be won:
 * `systemd-resolved.service` carries `Restart=`, and signalling it buys
 * seconds. The answer for those is `Conflicts=` in a unit, not a signal.
 *
 * **It answers false where it cannot tell**, which is the direction that
 * matches the caller: an unreadable cgroup on a kernel without the controller
 * is not evidence of supervision, and treating it as such would make the sweep
 * do nothing on exactly the machines it is wanted on.
 *
 * **The question is whose service, and it used to be "any service".** Every
 * process netcfgd spawns inherits netcfgd's own cgroup, so a dhcpcd that
 * netcfgd started is in `/system.slice/netcfgd.service` -- which contains
 * `.service`, so the old test answered yes about netcfgd's own child. Measured
 * on the reporting machine:
 *
 *     dhcpcd (pid 2538344) keeps rewriting resolv.conf and is run by a service
 *     manager, so netcfgd is not signalling it
 *     resolv.conf has been taken back 3 times and netcfgd found nothing it
 *     could signal
 *
 * -- netcfgd declining to signal a process it had started itself. So compare
 * the unit rather than look for the word.
 */
int ncfg_process_is_service_supervised(pid_t pid);

/*
 * Whether a process is in *this* process' own service.
 *
 * **The other half of the cgroup question, and the load-bearing one.** A
 * process netcfgd started inherits netcfgd's cgroup, so this is a positive
 * identification of netcfgd's own children -- including the ones netcfgd has no
 * record of. dhcpcd writes its pid file to `/run/dhcpcd/<iface>-4.pid`, where
 * netcfgd does not look, and forks a privileged proxy, a control proxy and a
 * BPF helper that appear in no pid file at all. All of them inherit the cgroup.
 *
 * **False where netcfgd is not under a service manager at all** -- run from a
 * shell, or under `unshare` as the live suite does.
 */
int ncfg_process_in_our_service(pid_t pid);

/*
 * The `*.service` unit a process belongs to, if any.
 *
 * A cgroup line is `0::/system.slice/netcfgd.service`, and a delegated child
 * may sit below it -- `.../netcfgd.service/something.scope` -- so this takes
 * the nearest `.service` component rather than the last one. `pid` of -1 asks
 * about this process, which is what `self` spells in `/proc`.
 */
int ncfg_process_service_of(pid_t pid, char *unit, size_t unit_size);

/*
 * The decision behind `ncfg_process_is_service_supervised`, without the
 * filesystem, so that it can be checked.
 *
 * NULL for `theirs` is a process in no service at all: killable. Equal units
 * mean it is one of ours. NULL for `ours` -- netcfgd not under systemd, or a
 * `/proc` that will not answer about this process -- leaves the conservative
 * answer, since a service netcfgd cannot prove is its own is one that may come
 * straight back.
 */
int ncfg_process_supervised_by_another(const char *theirs, const char *ours);

/*
 * Whether a process is in the same network namespace as this one.
 *
 * **A daemon in another network namespace is not configuring netcfgd's
 * interfaces**, so it cannot be interfering with netcfgd whatever its name is.
 * That is not a nicety: netcfgd's own live suite runs each script under
 * `unshare -rn`, where `/proc` still lists every process on the machine, so
 * without this a test that reached the sweep would terminate the developer's
 * real `dhclient` or `NetworkManager`. It is equally the right answer for a
 * container, where the host's daemons are visible and are somebody else's.
 *
 * **It fails closed, and that is the opposite of
 * `ncfg_process_is_service_supervised`.** The two defaults point opposite ways
 * because the costs do: mistaking a supervised process for an unsupervised one
 * wastes a signal, while mistaking another namespace's process for ours kills
 * something outside the world netcfgd manages.
 */
int ncfg_process_shares_network_namespace(pid_t pid);

/*
 * Ask a process to terminate.
 *
 * `SIGTERM` rather than `SIGKILL`, always: `pppd` on a `SIGTERM` hangs up the
 * link, runs its `ip-down` script and takes the interface away. A `SIGKILL`
 * leaves the session up at the far end and the report on disk, which is the
 * state this exists to avoid.
 *
 * `ESRCH` -- no such process -- is the state the caller asked for, so it is
 * reported as success. A pid of 0 or -1 is refused rather than passed through:
 * those mean process groups, and "stop every process I may signal" is not a
 * thing this should be able to express by accident.
 */
int ncfg_process_terminate(pid_t pid, char *err, size_t err_size);

/*
 * Kill a process outright, when asking has not worked.
 *
 * The last resort and never the first: `ncfg_process_terminate` says why
 * `SIGTERM` is the right signal for anything netcfgd starts, and a `SIGKILL`
 * that arrives before a process has had its chance to clean up is the state
 * that rule exists to avoid. This is here for the one case where the chance has
 * been given and refused -- a hook that has ignored a `SIGTERM` through its
 * grace period, which cannot be waited on for ever because the reconcile loop
 * is behind it.
 */
int ncfg_process_kill(pid_t pid, char *err, size_t err_size);

/*
 * Ask a whole process group to terminate, and kill one outright.
 *
 * **A hook is a script, and a script that runs `sleep 300` has forked it**: the
 * shell is the child netcfgd spawned, and the work is a grandchild. Signalling
 * the child kills the shell and leaves the grandchild running, reparented to
 * init -- so the daemon stops waiting and the thing it was waiting for carries
 * on. Measured, not supposed: two `sleep 300` processes outlived a run that
 * believed it had killed them.
 *
 * The caller must have put the child in its own group -- `setpgid(0, 0)` in the
 * child between `fork` and `exec` -- or this signals netcfgd's own group, which
 * includes the daemon. A `pgid` of 0 or -1 is refused for that reason, and the
 * negation that makes this a group signal is this function's job rather than
 * the caller's.
 *
 * `ESRCH` means the group is already gone, which is the outcome that was
 * wanted.
 */
int ncfg_process_terminate_group(pid_t pgid, char *err, size_t err_size);
int ncfg_process_kill_group(pid_t pgid, char *err, size_t err_size);

/*
 * Ask a process to re-read its configuration.
 *
 * `SIGHUP` is the convention and radvd honours it -- `radvd.c` handles it by
 * calling `reload_config`, which re-reads the file it was started with. That is
 * what makes a changed prefix free: the daemon keeps running and nothing on the
 * wire is disturbed.
 *
 * Unlike `ncfg_process_terminate`, `ESRCH` is *not* success: a reload asked of a
 * process that is gone did not happen, and the caller has a document that no
 * longer matches anything.
 */
int ncfg_process_hangup(pid_t pid, char *err, size_t err_size);

/*
 * Become somebody else, in a child between `fork` and `exec`.
 *
 * Three calls in one order, and the order is the whole of it:
 *
 *   1. `setgroups` -- **first, because it needs the privilege being dropped**.
 *      After `setuid` it fails, so a version that did it last would leave the
 *      process in root's supplementary groups while looking like it had
 *      dropped. That is the classic incomplete drop: no longer uid 0, still in
 *      every group root belongs to.
 *   2. `setgid` -- before `setuid`, for the same reason.
 *   3. `setuid` -- last, because it is the door that only opens outward.
 *
 * **Any failure must fail the exec.** This returns 0 and the caller must
 * `_exit` rather than go on -- so a hook that asked to be unprivileged never
 * runs privileged instead. That is the whole security property.
 *
 * A `group_count` of 0 is meaningful rather than a no-op: `setgroups(0, ...)`
 * clears the inherited set, which is what a user in no supplementary groups
 * must get.
 *
 * **Async-signal-safe, because of where it runs.** Three syscalls, no
 * allocation and no error buffer: between `fork` and `exec` in a process that
 * may have been threaded, `snprintf` into a caller's buffer is not something to
 * do. The caller reports `errno`, which is left set by whichever call refused.
 */
int ncfg_process_become(uid_t uid, gid_t gid, const gid_t *groups, size_t group_count);

/*
 * Why a program would not run, when the kernel said `EACCES`.
 *
 * **`Permission denied` on an exec has two causes and they need different
 * repairs**, and the message the standard library gives is the same four words
 * for both: the file is not executable, or it is executable and sits on a
 * filesystem mounted `noexec`. Decision 0178 is the second one costing an
 * afternoon -- systemd has mounted `/run` `noexec` by default since v256,
 * netcfgd wrote a hook there, and dhcpcd's `script_runreason: Permission
 * denied` appeared 1,350 times in a journal while netcfgd reported success.
 *
 * So this answers the question the operator has next: **is the mode wrong, or
 * is the mount?** It looks the program up the way an exec does -- an absolute
 * path as given, a bare name along `PATH` -- and reports the first candidate
 * that exists. A file that is there with an executable bit set, refused anyway,
 * is the mount, and nothing else it could be.
 *
 * `error_number` is the `errno` the exec failed with. Returns 0, leaving `text`
 * empty, where there is nothing useful to add: another errno, a program that is
 * not there at all (the caller's own "not installed" message is better), or a
 * `PATH` this cannot read.
 */
int ncfg_process_exec_refusal(const char *program, int error_number, char *text, size_t text_size);

/*
 * How far `ncfg_privilege_shed` got.
 *
 * Two answers rather than a boolean success, because the weaker one is
 * legitimate and the difference matters to whoever reads it.
 */
typedef enum {
	/* No capabilities, and no longer uid 0. */
	NCFG_SHED_FULLY = 0,
	/*
	 * No capabilities, still uid 0 -- there was no unprivileged id to
	 * become. A user namespace with a single mapping is the case that
	 * produces this.
	 */
	NCFG_SHED_CAPABILITIES_ONLY = 1
} ncfg_shed_t;

/* A sentence for a diagnostic. Never NULL. */
const char *ncfg_shed_describe(ncfg_shed_t reached);

/*
 * Give up every capability, the ability to regain one, and uid 0.
 *
 * **For a child that is about to touch something hostile.** netcfgd runs as
 * root and holds `CAP_NET_ADMIN`; a captive-portal probe resolves a name and
 * reads a reply from the network it has just joined. Those two facts should not
 * be true of one process, and decision 0162 says why: `getaddrinfo` is glibc's,
 * it loads NSS modules, and it parses a DNS response chosen by the network
 * under test. CVE-2015-7547 is that shape. **This is deliberately one direction
 * and has no inverse.**
 *
 * Four steps, and the order matters:
 *
 *   1. `PR_SET_NO_NEW_PRIVS`, first, so that nothing after this point can be
 *      undone by executing something with a setuid bit.
 *   2. The ambient set, cleared. Ambient capabilities survive `execve`, which
 *      is exactly why netcfgd's unit grants three of them, and exactly why a
 *      child that has just been `exec`ed still holds them.
 *   3. The ids, **before** the bounding set, because clearing the supplementary
 *      groups and setting the gid want `CAP_SETGID` and the uid wants
 *      `CAP_SETUID` -- both of which step 4 is about to make unavailable.
 *   4. The bounding set, dropped capability by capability, then effective,
 *      permitted and inheritable zeroed in one `capset`. Doing the zeroing
 *      before the bounding set would leave the bounding set full with nothing
 *      permitted, which a setuid binary could climb back through -- so
 *      `NO_NEW_PRIVS` is not belt and braces here, it is what makes the order
 *      forgiving.
 *
 * **It stops being root too, and the id comes from the kernel rather than from
 * a convention.** Capabilities alone leave uid 0, which can still read what uid
 * 0 *owns* -- `/etc/netcfgd/secrets` is 0600 and root's, so a compromise in the
 * resolver could read every wifi passphrase and 802.1X credential on the
 * machine. `CAP_DAC_OVERRIDE` being gone does not help: an owner needs no
 * override. The id is `ncfg_privilege_unprivileged_id`.
 *
 * **Capabilities are per-thread on Linux and credentials are not, so how much
 * of a threaded process this disarms depends on which outcome it reaches.**
 * `capset` with a pid of 0, `PR_CAPBSET_DROP` and `PR_SET_NO_NEW_PRIVS` all act
 * on the calling thread alone. The uid change does not: POSIX makes credentials
 * a property of the process, so glibc's `setuid` signals every other thread to
 * make the same change -- nptl calls it setxid -- and a thread that never
 * called it comes out at the new uid with its capabilities gone. Measured: a
 * worker calling `setuid(65534)` took the main thread from `uid 0 CapEff
 * 000001ffffffffff` to `uid 65534 CapEff 0`.
 *
 * So `NCFG_SHED_FULLY` disarms the whole process and
 * `NCFG_SHED_CAPABILITIES_ONLY` disarms one thread, and **the weaker of those
 * is the one to design around**: where there is no id to become -- `unshare
 * -r`, every rootless container -- a worker that sheds leaves every other
 * thread holding what it held, which looks like shedding and is not. Call this
 * from `main` in a freshly `exec`ed image that has not spawned anything.
 *
 * **What it promises is the outcome, not the steps.** Two of the calls are
 * allowed to fail on a machine that had nothing to give up -- dropping from the
 * bounding set needs `CAP_SETPCAP`, which netcfgd's own unit does not list --
 * so the end state is read back from `/proc` and a caller that gets a failure
 * must not go on to do the thing it was dropping privilege for. That is the
 * difference between a guard and a gesture.
 *
 * `reached` may be NULL for a caller that does not care which of the two it
 * got; it is written only on success.
 */
int ncfg_privilege_shed(ncfg_shed_t *reached, char *err, size_t err_size);

/*
 * The id to become: the kernel's own substitute for one it cannot map.
 *
 * `/proc/sys/kernel/overflowuid`, and 65534 where it cannot be read or reads as
 * 0 -- which is the kernel's compiled-in default and what `nobody` is on a
 * Debian or an Alpine machine. Read rather than assumed, because it is tunable,
 * and read rather than resolved by name: `getpwnam` means NSS, which is the C
 * library this whole exercise exists to keep away from the privileged process.
 *
 * **Not a dedicated `netcfgd` user**, which is deliberate rather than lazy: the
 * packaging creates a *group* for the control socket and no user, so requiring
 * one would be a change to four init systems and two package formats for a
 * child that owns nothing, opens nothing and lives for milliseconds.
 */
uid_t ncfg_privilege_unprivileged_id(void);

/*
 * The effective, permitted and inheritable capability sets of the calling
 * thread, and the effective set alone.
 *
 * **`/proc/thread-self`, not `/proc/self`.** Capabilities are per-thread and
 * `/proc/self/status` reports the thread group leader, so a caller that has
 * just shed on a worker thread would read back the set it did not change --
 * measured, and it reported a full set after a successful shed. On a
 * single-threaded process the two are the same file.
 *
 * Read from `/proc` rather than through `capget`, because the question is "what
 * does the kernel say this thread holds" and the file is the kernel saying it.
 * 0 where `/proc` is not mounted, which is a machine where this cannot be
 * checked rather than one where the answer is no capabilities.
 */
int ncfg_privilege_held_capabilities(uint64_t *effective, uint64_t *permitted, uint64_t *inheritable);
int ncfg_privilege_effective_capabilities(uint64_t *effective);

/* Whether this process is root by any of its three uids.
 *
 * All three, because a saved-set uid of 0 is a way back: a process that has
 * only `seteuid`ed away can `seteuid` back. The check that matters after a shed
 * is that none of them is 0.
 */
int ncfg_privilege_is_root(void);

/*
 * Die after `seconds`, whatever is happening.
 *
 * **A ceiling the parent does not have to enforce.** The parent reads the
 * child's output to end of file, and end of file is the child exiting -- so a
 * child that cannot outlive its alarm is a parent that cannot block. The
 * alternative is a timer in the parent and a kill, which is two mechanisms
 * where one will do.
 *
 * `SIGALRM`'s default action terminates, and this deliberately installs no
 * handler: a handler is a thing that could fail to run.
 */
void ncfg_privilege_die_after(unsigned int seconds);

#endif /* NCFG_PROCESS_H */
