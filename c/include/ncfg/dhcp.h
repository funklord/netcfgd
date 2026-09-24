/*
 * dhcp.h -- the DHCP client netcfgd runs, and does not implement.
 *
 * WHAT THIS IS
 *   Decision 0004 delegates DHCP rather than speaking it: a `config = "dhcp"`
 *   interface is a client process, and what netcfgd decides is *which* client,
 *   *with what arguments*, and *whether one is already running*. Nothing here
 *   sends or parses a DHCP packet. That is the same split 0026 made for
 *   hostapd and `ra.h` made for radvd, and it is why this module looks like
 *   its three siblings under `src/backend/`.
 *
 * WHICH CLIENTS
 *   dhcpcd first, then busybox udhcpc -- by the name `udhcpc`, and then by the
 *   name `busybox` with `udhcpc` as its first argument, because Debian
 *   packages busybox as one binary with no `udhcpc` symlink beside it. Three
 *   candidates, not two: the fallback was unreachable on exactly the machines
 *   most likely to want it.
 *
 *   **The two clients are not interchangeable and one difference is in the
 *   document.** busybox udhcpc has no metric option -- its script does the
 *   routing -- so a `preference` or a network's `metric` reaches dhcpcd as
 *   `-m` and reaches udhcpc not at all. See `ncfg_dhcp_record_metric`.
 *
 * WHERE THE FILES GO
 *   Under netcfgd's own run directory, which is **a parameter of every call**
 *   -- the same rule `ra.h` states and for its reason: a check has to be able
 *   to run on a machine whose real netcfgd is managing its real network.
 *
 *   The one directory that is *not* netcfgd's is dhcpcd's own: it is compiled
 *   into dhcpcd as `RUNDIR` and it survives a netcfgd stop, which is exactly
 *   why the control socket is still reachable when everything under
 *   `/run/netcfgd` has gone. It is a member of `ncfg_dhcp_machine_t` rather
 *   than a constant read here, so nothing in this module can reach the
 *   machine's own by default.
 *
 * MARKING AND ADOPTION, WHICH IS THE WHOLE OF THIS MODULE
 *   A client netcfgd started and then forgot is an orphan holding a lease on
 *   an interface netcfgd believes it owns. `RuntimeDirectory=netcfgd` deletes
 *   `/run/netcfgd` when the daemon stops and `KillMode=process` deliberately
 *   leaves the client running (0134, 0142), so **forgetting is the ordinary
 *   case rather than the exceptional one**: it happens on every restart.
 *
 *   The rule is `process.h`'s, unchanged, and it is the one
 *   `ncfg_ra_running_pid` and `ncfg_openvpn_running_pid` already apply: a
 *   process is netcfgd's when it carries, **as a whole `argv` element**, an
 *   absolute path netcfgd composed out of its own run directory and one
 *   interface -- and when it belongs to root or to whoever is asking. radvd's
 *   marker is its generated configuration, a tunnel's is its management
 *   socket. What differs here is only *where the mark is read*:
 *
 *     * **udhcpc keeps it in its own command line.** netcfgd starts it with
 *       `-p <run>/udhcpc/<iface>.pid` and busybox does not call
 *       `setproctitle`, so that path is in `/proc/<pid>/cmdline` for as long
 *       as the client lives. `ncfg_dhcp_running_pid` is `ncfg_ra_running_pid`
 *       with that marker, and `ncfg_dhcp_adopt` is the recovery when the pid
 *       *file* has gone with the run directory while the process has not.
 *       Adopting writes the pid back down, which is all "adopted" means: the
 *       record netcfgd lost is rebuilt from the mark the client still carries.
 *
 *       **The pid file's path rather than the script's**, though both are
 *       netcfgd's and absolute: the script path is also in the environment of
 *       every hook the client forks, and `-p` is carried by the client alone.
 *
 *     * **dhcpcd keeps nothing in its command line at all.** It calls
 *       `setproctitle` and destroys argv and environment alike -- it reads
 *       back as `dhcpcd: wlp0s20f3 [ip4]` -- so it is the one backend whose
 *       ownership cannot be read out of the process image. What it does keep
 *       is its own memory of `-f`, which it recites on its control socket, so
 *       netcfgd starts it with a `-f` under netcfgd's run directory and asks
 *       later. That is 0143, and `ncfg_dhcpcd_whose` is the question.
 *
 *   Adopting matters more for dhcpcd than anywhere: **a second `dhcpcd -b`
 *   against a running one is a silent no-op** -- it prints "sending commands
 *   to dhcpcd process" and exits 0 having started nothing -- so an executor
 *   that did not ask would report success on every reconcile while an orphan
 *   held the lease and netcfgd held no handle on it.
 *
 * WHY THE `-f` IS A SYMLINK TO THE OPERATOR'S FILE
 *   dhcpcd's `-f` *replaces* `/etc/dhcpcd.conf` outright and dhcpcd has no
 *   `include` directive, so a file of netcfgd's own there would silently drop
 *   whatever the operator had -- `duid`, `persistent`,
 *   `require dhcp_server_identifier` and the rest of a stock Debian file.
 *   Pointing at theirs keeps it: dhcpcd reads the target's options through the
 *   symlink and recites the *symlink* path when asked, which is exactly the
 *   pair of properties a mark needs. A dangling symlink is not a failure --
 *   dhcpcd prints `read_config: ...: No such file or directory`, takes a
 *   normal lease and applies its defaults, which is what it already does on a
 *   machine with no `/etc/dhcpcd.conf`.
 *
 * WHY THE HOOK IS SHIPPED AND NOT GENERATED
 *   netcfgd used to write a script per interface into `/run/netcfgd/dhcpcd/`
 *   and pass it with `-c`. systemd mounts `/run` `nosuid,nodev,noexec` -- its
 *   own default since v256 -- so dhcpcd could not exec it and said so, once
 *   per lease event, in its own log and nowhere netcfgd could see. The hook is
 *   the only route a lease's nameservers have into netcfgd, so the resolver
 *   was written empty: 1,350 of those messages on the machine that reported
 *   it. Decision 0178. The path is checked before dhcpcd is run, because a
 *   missing hook and an unexecutable one have the same silent outcome.
 *
 * ERRORS
 *   `base.h`'s convention throughout: 1 or 0, and a sentence an operator
 *   reads. Nothing here exits, asserts or prints.
 */
#ifndef NCFG_DHCP_H
#define NCFG_DHCP_H

#include <stddef.h>
#include <sys/types.h>

#include "ncfg/document.h"

/* Long enough for a run directory, a subdirectory and `<iface>-<family>.conf`. */
#define NCFG_DHCP_PATH_MAX 512

/*
 * Room for the longest vector below, which is busybox's: the program, the
 * applet name, and udhcpc's ten arguments, and the NULL.
 */
#define NCFG_DHCP_ARGV_MAX 16

/*
 * The machine's own answers, published so that a caller fills them in and a
 * check reads them rather than letting anything write there.
 *
 * `NCFG_PORTAL_OWN_IMAGE`'s arrangement, and `ncfg_contention_machine`'s: the
 * value a daemon passes is written down once, and a test asserts it by reading
 * the constant instead of by running against the machine.
 */
#define NCFG_DHCP_HOOK_DEFAULT "/usr/libexec/netcfgd/dhcpcd-hook"
#define NCFG_DHCPCD_RUN_DIR_DEFAULT "/run/dhcpcd"
#define NCFG_DHCPCD_CONFIG_DEFAULT "/etc/dhcpcd.conf"

/*
 * How long `dhcpcd -k` is given to take effect before the stop is a failure.
 *
 * A `-k` returns as soon as it has sent the signal, so an immediate look would
 * call every successful stop a failure. Three seconds is the shape of the
 * other patience constants here and long enough for a client that is releasing
 * its lease on the way out.
 */
#define NCFG_DHCP_STOP_PATIENCE_MS 3000

/* dhcpcd's spelling of the two families, which is also the second half of
 * every pid file, socket and configuration name it writes. */
#define NCFG_DHCP_FAMILY_V4 "4"
#define NCFG_DHCP_FAMILY_V6 "6"

/*
 * What this module needs from the machine and will not assume.
 *
 * `ncfg_service_t`'s bargain, taken for its reason: **nothing here has a
 * default and nothing here reads the environment**, because the machine these
 * tests are built on is a workstation whose network is live and a default is
 * how the difference between a check and an outage becomes a variable somebody
 * remembered to set. The Rust reads `NCFG_DHCPCD_HOOK` and
 * `NCFG_DHCPCD_RUN_DIR`; here they are members, and a member left NULL refuses
 * by name what needs it.
 *
 * The three programs are the one exception and it is `ncfg_ra_start`'s: NULL
 * means "find the conventional name", which is what a daemon wants and what a
 * test never uses -- `backend_internal.h` records that 20 of 45 checks in the
 * Rust's live openvpn script were silently exercising the machine's own
 * openvpn because the search reached it first.
 */
typedef struct {
	/* `dhcpcd`, `udhcpc` and `busybox`. NULL searches for the name. */
	const char *dhcpcd_program;
	const char *udhcpc_program;
	const char *busybox_program;
	/*
	 * odhcp6c, which is the only client that can report a delegated prefix
	 * (0050). NULL searches for the name; a path that is not there is a
	 * machine without one, which is what makes `ncfg_dhcp6_client`'s refusing
	 * branch reachable from a test.
	 */
	const char *odhcp6c_program;
	/*
	 * The hook dhcpcd is pointed at with `-c`. NULL, or a path that is not
	 * there, refuses a dhcpcd start by name -- see the header above for what
	 * a missing one costs.
	 */
	const char *hook;
	/*
	 * Where dhcpcd keeps its own control sockets. **dhcpcd's run directory,
	 * not netcfgd's**, and that is the point: it survives a netcfgd stop,
	 * which is why the mark is still readable when `/run/netcfgd` has gone.
	 * NULL means netcfgd cannot ask, which is `NCFG_DHCPCD_SILENT`.
	 */
	const char *dhcpcd_run_dir;
	/*
	 * What `-f` is pointed at. NULL is `NCFG_DHCPCD_CONFIG_DEFAULT`'s file,
	 * and a target that is not there is not a failure.
	 */
	const char *dhcpcd_config;
	/* How long a stop waits for `dhcpcd -k`. 0 is
	 * `NCFG_DHCP_STOP_PATIENCE_MS`. */
	int patience_ms;
} ncfg_dhcp_machine_t;

/*
 * This machine's own, in one place.
 *
 * Fills `hook`, `dhcpcd_run_dir` and `dhcpcd_config`; leaves the three
 * programs NULL, since "find the conventional name" is what a daemon means and
 * there is no machine-wide answer for a path a test would pass. **Nothing in
 * this project calls it from a check in order to write anything.**
 */
void ncfg_dhcp_machine(ncfg_dhcp_machine_t *out);

/* ------------------------------------------------------------------------ *
 * The paths, which are the marks
 * ------------------------------------------------------------------------ */

/*
 * Written into a caller's buffer rather than allocated, which is
 * `ncfg_ra_config_path`'s convention: one buffer and no ownership question. A
 * path that would not fit is a failure and not a shorter one, because every
 * caller is about to write to it or compare against it.
 */

/* `<run>/udhcpc`, and `<run>/<program>` for a client that records a pid. */
int ncfg_dhcp_client_dir(const char *run, const char *program, char *out, size_t out_size,
    char *err, size_t err_size);

/*
 * `<run>/<program>/<iface>.pid` -- where a client that has no control socket
 * records its pid, and the mark it carries in its own `argv`.
 *
 * One function for both clients, because the writer, the reader and the
 * `-p` argument are three views of one path: netcfgd makes the directory,
 * names the file on the command line, and reads it back. Three spellings is
 * how two of them come to disagree, and a disagreement here is silent -- every
 * lookup answers "not running" and netcfgd starts a second client beside the
 * first.
 */
int ncfg_dhcp_pid_path(const char *run, const char *program, const char *iface, char *out,
    size_t out_size, char *err, size_t err_size);

/* `<run>/udhcpc/<iface>.script` -- what udhcpc runs on every lease event, and
 * `<run>/udhcpc/<iface>.address`, the one address that script installed. */
int ncfg_dhcp_script_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size);
int ncfg_dhcp_address_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size);

/* `<run>/dhcpcd/<iface>-<family>.conf` -- the symlink netcfgd points `-f` at,
 * which is the mark a running dhcpcd recites. */
int ncfg_dhcp_config_path(const char *run, const char *iface, const char *family, char *out,
    size_t out_size, char *err, size_t err_size);

/* `<run>/dhcpcd/<iface>.metric` -- netcfgd's account of the `-m` it started a
 * client with. See `ncfg_dhcp_record_metric`. */
int ncfg_dhcp_metric_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size);

/* `<run>/dhcp/<iface>-<family>.log` -- where a client's two output streams go,
 * so the reason one would not start is readable after the fact on a machine
 * with no syslog at all. */
int ncfg_dhcp_log_path(const char *run, const char *iface, const char *family, char *out,
    size_t out_size, char *err, size_t err_size);

/*
 * `<run>/reported/<iface>` -- where a v4 lease's nameservers are reported.
 *
 * The single file rather than a fragment under `reported.d/`, because both
 * DHCPv4 clients write it and a dual-stack interface's second writer is the
 * DHCPv6 one (0086). `packaging/hooks/dhcpcd-hook` composes the same two paths
 * in shell and is the other half of this: `*6` on dhcpcd's reason picks the
 * fragment, anything else picks this.
 */
int ncfg_dhcp_report_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * What udhcpc is given to run
 * ------------------------------------------------------------------------ */

/*
 * The script odhcp6c runs, which reports the prefixes it was delegated.
 *
 * One prefix per line into `target`, written to a temporary beside it and
 * renamed -- `doc/interface-report.md`'s rule, because the observer may read
 * at any moment and a half-written file reads as a shorter list rather than as
 * an error. An empty file means the lease is gone.
 *
 * **The reader end of this file already existed and the writer did not.**
 * `ncfg_state_read_reports` walks `<run>/prefixes/` and has since the host
 * module landed; nothing wrote into it, because the C refused to start a
 * DHCPv6 client at all (project.md 10.259).
 *
 * Allocated; free it. NULL with a sentence.
 */
char *ncfg_dhcp_pd_script(const char *iface, const char *target, char *err, size_t err_size);

/*
 * The script udhcpc runs when a lease changes.
 *
 * **Without one udhcpc obtains a lease and configures nothing at all** --
 * there is no configuration step of its own -- which is decision 0065. Pure,
 * so what a lease does to an interface can be read without taking one.
 *
 * Three things it deliberately leaves alone, and each is a contention this
 * project exists to avoid:
 *
 *   * **The MTU**, which the document owns. A lease that lowered it would have
 *     netcfgd fighting its own `mtu` field on every renewal.
 *   * **`/etc/resolv.conf`**, which netcfgd's DNS backend owns. What to do
 *     with a lease's nameservers is one decision for both clients, and it is
 *     made by reading the report this writes rather than by the client.
 *   * **Every address it did not add itself.** A stock `deconfig` flushes the
 *     interface, which would delete a static address netcfgd had installed
 *     beside the lease. This one records what it added in `state` and removes
 *     exactly that.
 *
 * `$mask` is a prefix length and `$subnet` is the same thing dotted; `ip` takes
 * only the first, so a client that sets only `subnet` is refused by name
 * rather than guessed at.
 *
 * Allocated; free it with `free`. NULL with a sentence on failure.
 */
char *ncfg_dhcp_udhcpc_script(const char *iface, const char *state, const char *report,
    char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * The argument vectors
 * ------------------------------------------------------------------------ */

/*
 * A command line, built rather than written out at the call site.
 *
 * The Rust builds each of these in a function of its own "so the argument list
 * has somewhere to be asserted", and names the one that nothing could have
 * caught otherwise: `-O search`. That reason is stronger in C, where the
 * alternative is an `argv[12]` filled by index inside a function that also
 * forks.
 *
 * **`argv` borrows every string but the metric.** The paths point at the
 * caller's buffers and must outlive the run; the `-m` value is formatted into
 * this struct, which is why it is a struct rather than an array.
 */
typedef struct {
	const char *argv[NCFG_DHCP_ARGV_MAX];
	size_t      count;
	/* What `-m` points at. Room for any `int64_t` and a sign. */
	char metric[24];
} ncfg_dhcp_args_t;

/*
 * The `-P` argument odhcp6c is given for a delegated prefix.
 *
 * `<hint>/<length>` where the document named a hint, the length alone
 * otherwise, and `0` for a length it did not state -- which asks for whatever
 * the server offers. 1 with the text, 0 with `out` emptied where there is no
 * request or it would not fit.
 */
int ncfg_dhcp_prefix_request(const ncfg_pd_request_t *request, char *out, size_t out_size);

/*
 * Which DHCPv6 client can serve what the document asked for, or NULL with the
 * reason.
 *
 * **Pure and separate, which is the Rust's arrangement and its reason**: the
 * refusing case needs a machine with no odhcp6c, and a branch no test can make
 * fire is untested code however defensive it looks. Asked this way a test
 * makes all four combinations fire without the machine having to be any of
 * them.
 *
 * **Prefix delegation is odhcp6c's.** Measured in the Rust against a real
 * `kea-dhcp6` over a veth pair, with 0050 carrying the whole of it: dhcpcd
 * exposes a delegated prefix to a script only as
 * `$new_delegated_dhcp6_prefix`, which carries **the addresses dhcpcd itself
 * derived** from the prefix, on an interface it delegated to. netcfgd does the
 * deriving (0009 makes a prefix reference an indirection the document
 * resolves), so there is no interface for dhcpcd to delegate to and the
 * variable is always empty. A document that asks for a prefix on a machine
 * with only dhcpcd is therefore refused, rather than served by a client that
 * would take a lease from the ISP and report nothing.
 */
const char *ncfg_dhcp6_client(int delegating, int has_odhcp6c, const char *iface, char *err,
    size_t err_size);

/*
 * odhcp6c's command line.
 *
 * `-d` to daemonise, `-p` for the pid file that is the only handle there is,
 * `-s` for the script netcfgd generated, and `-P` **only where the document
 * asked for a prefix** -- see `ncfg_dhcp_odhcp6c_args` for what an
 * unconditional one cost. `request` may be NULL or empty for no delegation.
 *
 * Borrows every string, exactly as `ncfg_dhcp_udhcpc_args` does.
 */
int ncfg_dhcp_odhcp6c_args(const char *program, const char *iface, const char *script,
    const char *pid_path, const char *request, ncfg_dhcp_args_t *out, char *err,
    size_t err_size);

/*
 * What netcfgd starts udhcpc with.
 *
 * `-R` releases the lease on the way out, which is also what makes the script
 * run `deconfig` on a `SIGTERM`. Without it a stopped client leaves its
 * address on the interface -- measured -- where `dhcpcd -k` takes it away, and
 * two clients that disagree about what stopping means is two behaviours for
 * one `backend.stop`.
 *
 * `-O search` asks for the search list. **udhcpc does not request option 119
 * by default**: its list is 1, 3, 6, 12, 15, 28, 42, so a server that honours
 * the request list never sends one. 0067's search suffixes reached netcfgd
 * only because the live test's server was `busybox udhcpd`, which pushes every
 * configured option whether it was asked for or not; against dnsmasq, ISC
 * dhcpd or a domestic router the client asked for nothing and got nothing.
 * Found by porting that test to a second server, not by reading the code.
 * Option 15 (`domain`) is in the default list and is a single name; 119 is the
 * list, and is what an operator writing `dns { }` on a DHCP interface expects.
 *
 * `applet` is `udhcpc` where the program is the busybox multi-call binary, and
 * NULL where it is the client itself.
 */
int ncfg_dhcp_udhcpc_args(const char *program, const char *applet, const char *iface,
    const char *script, const char *pid_path, ncfg_dhcp_args_t *out, char *err, size_t err_size);

/*
 * What netcfgd starts dhcpcd with.
 *
 * One family at a time and never both, because netcfgd decides per address
 * source what each family does: a dhcpcd left to itself would do DHCPv4,
 * DHCPv6 and SLAAC on one interface, which is three things configuring one
 * link and only one of them written down.
 *
 * `-c` and `-f` come before the interface because dhcpcd parses options first,
 * and **every dhcpcd netcfgd starts gets `-c`**: "leave dhcpcd's own hooks
 * alone" meant a lease rewriting `/etc/resolv.conf` on a machine where
 * netcfgd's DNS mode owns that file (0072).
 *
 * `metric` may be NULL or absent, which is a client started with no `-m` --
 * dhcpcd's own default, and the only honest answer for a document that named
 * no preference.
 */
int ncfg_dhcp_dhcpcd_args(const char *program, const char *family, const char *iface,
    const ncfg_optint_t *metric, const char *hook, const char *config, ncfg_dhcp_args_t *out,
    char *err, size_t err_size);

/*
 * What stops it, which has to name the same family the start did.
 *
 * **dhcpcd's pid file carries the family in its name.** A client started with
 * `-4` writes `<rundir>/<iface>-4.pid`, and `dhcpcd -k <iface>` looks for
 * `<iface>.pid`, finds nothing, prints "dhcpcd is not running" and exits 1 --
 * which netcfgd ignored, because that is also what a machine with no dhcpcd at
 * all says. So dropping `config = "dhcp"` from a document reported a stopped
 * backend while a real dhcpcd kept renewing the lease and holding the address.
 * Measured against dhcpcd 10.1.0. Decision 0070.
 */
int ncfg_dhcp_dhcpcd_stop_args(const char *program, const char *family, const char *iface,
    ncfg_dhcp_args_t *out, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * Whose client is this
 * ------------------------------------------------------------------------ */

/*
 * The three answers a dhcpcd control socket gives, which is deliberately not
 * two.
 *
 * "Somebody else's" and "netcfgd could not tell" have different consequences
 * and 0141 is the difference: a stranger's daemon is a fact to report and a
 * person's decision, while silence is the ordinary state of every machine
 * whose client is udhcpc and of every machine with no dhcpcd installed.
 * Folding them would either fail every stop on a busybox machine or adopt a
 * daemon nobody identified.
 */
typedef enum {
	/* Nothing answered: no socket, no dhcpcd, or one netcfgd may not read. */
	NCFG_DHCPCD_SILENT = 0,
	/* One answered, reciting the `-f` netcfgd would have started it with. */
	NCFG_DHCPCD_OURS = 1,
	/* One answered, reciting somebody else's. */
	NCFG_DHCPCD_THEIRS = 2
} ncfg_dhcpcd_whose_t;

/*
 * Ask a running dhcpcd whose it is.
 *
 * `ncfg_dhcpcd_config_file_of` is the socket and the parsing;
 * `ncfg_dhcp_config_path` is the mark; this is the comparison, in one place,
 * because the start and the stop both ask it and a second spelling is how they
 * come to disagree about the same client.
 *
 * `recited` is filled with what the client answered where there was one, so a
 * caller can name it. It may be NULL.
 */
ncfg_dhcpcd_whose_t ncfg_dhcpcd_whose(const char *run, const char *iface, const char *family,
    const ncfg_dhcp_machine_t *machine, char *recited, size_t recited_size);

/*
 * The pid of a client of netcfgd's that records one, if it is still there.
 *
 * `ncfg_ra_running_pid`'s rule with this module's marker: the pid file netcfgd
 * named on the command line, and `/proc/<pid>/cmdline` checked for that same
 * path as a whole argument. 0 covers every way of not knowing -- no file, no
 * number in it, no such process, or a process that is somebody else's.
 *
 * **dhcpcd is not one of these and cannot be**: it has no pid file of
 * netcfgd's and no mark in its process image. Ask `ncfg_dhcpcd_whose`.
 */
pid_t ncfg_dhcp_running_pid(const char *run, const char *program, const char *iface);

/*
 * Take back a client netcfgd started and lost the record of.
 *
 * The recovery path, and it exists because **the pid file is an index into a
 * fact rather than the fact itself**: `RuntimeDirectory=netcfgd` deletes
 * `/run/netcfgd` when the daemon stops while the client -- which netcfgd
 * deliberately does not stop (0134) -- keeps running. The mark survives in the
 * client's own `argv`, so `ncfg_process_pid_by_marker` finds it and this
 * writes the pid back down.
 *
 * **Without it netcfgd starts a second client**, and unlike dhcpcd, udhcpc has
 * no instance lock to refuse one. Measured: both run, both take the same lease
 * -- same MAC, same client id, the server re-offers -- and the second
 * overwrites the pid file, so the first becomes permanently unreachable. A
 * later `backend.stop` then signals only the second, and with `-R` that
 * RELEASEs the lease and the script removes the address, leaving the interface
 * bare while a live client still believes it holds the lease and will not
 * re-add it until T1.
 *
 * 1 with `*pid_out` set to the pid adopted, 1 with `*pid_out` 0 where there
 * was nothing to adopt -- which is not a failure and is the ordinary answer --
 * and 0 with a sentence where the record could not be written.
 */
int ncfg_dhcp_adopt(const char *run, const char *program, const char *iface, pid_t *pid_out,
    char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * The metric netcfgd started a client with
 * ------------------------------------------------------------------------ */

/*
 * Write down the `-m` a client was just started with, or clear the record.
 *
 * **Beside the pid file and written only where a client was actually spawned,
 * which is the whole point.** The metric reaches the client once, so a radio
 * that moves to a network asking for a different one keeps the old metric on
 * its lease's default route and the client has to be replaced. Noticing that
 * by comparing the *installed route* means waiting out the entire exchange
 * that installs it -- eight seconds on the reporting machine -- and then
 * throwing the result away (0241).
 *
 * **The client cannot be asked.** dhcpcd rewrites its command line to
 * `dhcpcd: <iface> [ip4]` as soon as it starts, so nothing netcfgd passed
 * survives in `/proc/<pid>/cmdline`. Measured: no dhcpcd process carries `-m`
 * in its `argv` at all.
 *
 * An absent metric **removes** the record rather than leaving it, and that is
 * not tidiness: a network that asks for no metric starts a client with no
 * `-m`, and a record left over from the previous network would say the running
 * client carries one it was never given -- a restart on every pass until the
 * restart limit gives up.
 *
 * Best effort in both directions, and it answers 0 with a sentence so a caller
 * can say what it cost rather than fail a start that worked. A record netcfgd
 * could not write leaves the planner reading "cannot tell", which is what it
 * read before this existed.
 */
int ncfg_dhcp_record_metric(const char *run, const char *iface, const ncfg_optint_t *metric,
    char *err, size_t err_size);

/*
 * Read back what a client on this interface was started with.
 *
 * Absent where netcfgd cannot tell: no file, an unreadable one, something that
 * is not a number, or a client started before this record existed. **Not a
 * metric of zero**, which is a legitimate value and the strongest one.
 *
 * The writer and the reader share `ncfg_dhcp_metric_path` rather than
 * composing it apart, because a disagreement between them is invisible: every
 * client would read "cannot tell", the planner would fall back to the route
 * comparison, and nothing would look wrong. That silent absence is this
 * record's failure mode.
 */
ncfg_optint_t ncfg_dhcp_started_metric(const char *run, const char *iface);

/* ------------------------------------------------------------------------ *
 * The lifecycle
 * ------------------------------------------------------------------------ */

/*
 * Start a DHCPv4 client on one interface, or adopt the one already there.
 *
 * The order is the module, and each step is a thing that has gone wrong:
 *
 *   1. **A client netcfgd's own records already name** is running, and
 *      starting a second is what this exists to prevent. Success, nothing
 *      started.
 *   2. The script and the `-f` symlink are (re)written, because both carry the
 *      interface name and both are what an adopted client is still using.
 *   3. **A udhcpc whose pid file went with the run directory** is adopted.
 *   4. **A dhcpcd reciting netcfgd's own `-f`** is adopted.
 *   5. A dhcpcd reciting somebody else's is **refused by name**, rather than
 *      spawned beside. See the divergence note in 0263: a second `dhcpcd -b`
 *      exits 0 having started nothing, so spawning beside one would report a
 *      start netcfgd did not make and could never stop.
 *   6. dhcpcd, then udhcpc, then busybox. The first that is installed and runs
 *      is the answer; one that is installed and refuses fails the start,
 *      quoting what it said.
 *
 * `metric` may be NULL or absent. It reaches dhcpcd as `-m` and udhcpc not at
 * all, and the record written at the end says which of those happened.
 */
int ncfg_dhcp_start(const char *run, const char *iface, const ncfg_optint_t *metric,
    const ncfg_dhcp_machine_t *machine, char *err, size_t err_size);

/*
 * Start a DHCPv6 client on one interface, or adopt the one already there.
 *
 * `ncfg_dhcp_start`'s order, with two differences that are the v6 half's own:
 *
 *   * **Which client can serve this document is decided first**, by
 *     `ncfg_dhcp6_client`, because it is a refusal rather than a fallback: a
 *     machine with only dhcpcd cannot serve an interface that asked for a
 *     delegated prefix, and starting one would take a lease from the ISP and
 *     report nothing (0050). The v4 half has no such case -- its three
 *     candidates are interchangeable.
 *   * **The hook is netcfgd's own generated script**, written here and passed
 *     to odhcp6c with `-s`, rather than the shipped dhcpcd hook. It is the
 *     writer of `<run>/prefixes/<iface>`, whose reader
 *     (`ncfg_state_read_reports`) existed for several waves with nothing
 *     writing into it because this function did not exist (project.md 10.259).
 *
 * `request` is the `-P` argument `ncfg_dhcp_prefix_request` built, or NULL
 * where the document asked for no prefix -- and an absent one means no `-P` at
 * all rather than `-P 0`, which is the difference between soliciting a
 * delegation and not.
 */
int ncfg_dhcp6_start(const char *run, const char *iface, const char *request,
    const ncfg_dhcp_machine_t *machine, char *err, size_t err_size);

/*
 * Stop the DHCP client of netcfgd's on one interface, in one family.
 *
 * Both shapes are asked, because **which client is running is a property of
 * the machine rather than of the document**: a dhcpcd is stopped through its
 * own `-k`, and a udhcpc or an odhcp6c by the pid it was told to record.
 *
 * **Whose it is decides whether anything is signalled**, which is this port's
 * divergence and 0014's rule applied where the Rust does not apply it: the
 * ownership question is asked *before* `dhcpcd -k` rather than after, so a
 * stranger's client on this interface is left alone and named instead of being
 * signalled by a command that finds it by convention.
 *
 * **The exit status of `-k` cannot answer whether it worked and the socket
 * can.** `dhcpcd -k` exits 1 both for "there was no dhcpcd" -- the ordinary
 * answer on a udhcpc machine -- and for "it is running and I was not allowed
 * to signal it". The second was reached for a month on the reporting machine:
 * dhcpcd's main process runs as its own user under privsep, signalling across
 * uids needs `CAP_KILL`, and the unit did not grant it. Every `backend.stop`
 * returned success having stopped nothing, and what that cost was not a lost
 * stop but a loop -- the start that follows adopts the client that is still
 * running, the observation says the backend is up, the restart counter clears
 * as "stayed up" (0079), and the same plan is made again five seconds later,
 * indefinitely, with nothing saying anything had failed.
 *
 * Nothing running is the state this was asked to produce, so that is success.
 */
int ncfg_dhcp_stop(const char *run, const char *iface, const char *family,
    const ncfg_dhcp_machine_t *machine, char *err, size_t err_size);

/* Find `dhcpcd`, `udhcpc` or `busybox`, `/usr/sbin` first. Allocated, or NULL
 * where nothing is installed under that name. */
char *ncfg_dhcp_binary(const char *name);

#endif /* NCFG_DHCP_H */
