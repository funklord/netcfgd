/*
 * autoip.h -- IPv4 link-local addressing, by a client netcfgd supervises.
 *
 * WHAT THIS IS FOR
 *   `config = "link-local"` has been accepted by the language since the model
 *   was written and applied by nothing, in either implementation: the plan said
 *   so out loud through `warn_unbuilt` rather than pretending otherwise. This
 *   is the pass that applies it.
 *
 * WHY A CLIENT RATHER THAN NETCFGD ITSELF
 *   RFC 3927 is a protocol: probe a candidate with ARP, defend it, and pick
 *   again on a conflict. That is a daemon's work, and this tree's settled
 *   answer for anything needing one is to delegate and supervise --
 *   dhcpcd/udhcpc/busybox, pppd, wpa_supplicant, radvd. Writing the protocol
 *   into netcfgd would be the first time it did otherwise.
 *
 *   **`dhcpcd` can speak IPv4LL and is excluded anyway.** It reaches it only as
 *   a fallback from the discover phase and has no IPv4LL-only switch, so an
 *   explicit `link-local` request would broadcast DHCPDISCOVER first and take a
 *   lease if one answered. `document.h` rules that out in as many words beside
 *   the enum value: link-local "coexists with routable addresses rather than
 *   being a fallback, because a timeout-triggered fallback would be state
 *   hidden in the reconciler that no config explains".
 *
 * WHY `--force-bind` IS NOT OPTIONAL
 *   It is the same sentence from the other side. Without it the client declines
 *   when a routable address is already configured, which is exactly the
 *   fallback behaviour the document forbids -- so netcfgd passes it on
 *   correctness grounds, not for convenience.
 *
 * HOW OWNERSHIP IS ESTABLISHED, AND HOW STRONG THE CLAIM IS
 *   `avahi-autoipd` offers `--kill <iface>` and `--check <iface>`, and both act
 *   on **whichever** client is on that interface. It writes no pid file and
 *   takes no option to put one where netcfgd chooses. So neither verb can be
 *   used: `--kill` would stop an operator's IPv4LL client as readily as
 *   netcfgd's, which is what 0141 and `ncfg_dhcpcd_whose` exist to prevent.
 *
 *   What is left is the pid netcfgd recorded when it started one, re-checked
 *   against `/proc/<pid>/cmdline` before anything is signalled. The marker is
 *   `--force-bind` beside the interface name.
 *
 *   **That is weaker than `ra.h`'s and saying so is the point.** A radvd is
 *   identified by a configuration path under `/run/netcfgd`, which an
 *   operator's cannot match; an operator who passes `--force-bind` themselves
 *   is indistinguishable from netcfgd here. It is the strength of the udhcpc
 *   adoption this tree already accepts -- "by the `-p` it was started with and
 *   the privilege it runs with" -- and it is strictly better than `--kill`,
 *   which asserts nothing at all.
 *
 * WHAT IS DELIBERATELY NOT HERE
 *   The action script. `avahi-autoipd` runs `/etc/avahi/avahi-autoipd.action`
 *   at a fixed path and takes no option to point elsewhere, so there is no
 *   per-interface hook for netcfgd to install and nothing here pretends there
 *   is. A lease's nameservers are 0178's subject and a link-local address
 *   carries none, so nothing is lost by it.
 */
#ifndef NCFG_AUTOIP_H
#define NCFG_AUTOIP_H

#include <stddef.h>
#include <sys/types.h>

/* Every path this module builds, which is `ra.h`'s number for the same shape:
 * `<run>/autoip/<iface>.pid` on a run directory a test may put anywhere. */
#define NCFG_AUTOIP_PATH_MAX 512

/* The conventional name, searched for when a caller passes no program. */
#define NCFG_AUTOIP_PROGRAM "avahi-autoipd"

/*
 * What to run instead, for a test and for a machine that keeps its client
 * somewhere else. The same arrangement `NCFG_SUPPLICANT_PROGRAM_ENV` and
 * `NCFG_OPENVPN_PROGRAM_ENV` have, and named consistently with them.
 *
 * **An explicit path that is not a regular file reads as "not installed"**
 * rather than being run and failing, which is `dhcp.c`'s `program_for` rule.
 * That is what lets a check say "this machine has no IPv4LL client" by naming
 * a path in its own directory, which is the only way to say it on a machine
 * that does have one.
 */
#define NCFG_AUTOIP_PROGRAM_ENV "NCFG_AVAHI_AUTOIPD"

/* The argument that makes the client obey `document.h`'s rule, and the marker
 * ownership is read from. One string, used for both, so the two cannot drift. */
#define NCFG_AUTOIP_FORCE_BIND "--force-bind"

/* `<run>/autoip`, which netcfgd creates: the client keeps nothing of its own. */
int ncfg_autoip_run_dir(const char *run, char *out, size_t out_size, char *err, size_t err_size);

/* `<run>/autoip/<iface>.pid`, written by netcfgd rather than by the client. */
int ncfg_autoip_pid_path(const char *run, const char *iface, char *out, size_t out_size, char *err,
    size_t err_size);

/* `<run>/autoip/<iface>.log`, which is what a failed start is quoted from. */
int ncfg_autoip_log_path(const char *run, const char *iface, char *out, size_t out_size, char *err,
    size_t err_size);

/*
 * Start one on this interface.
 *
 * `program` is the client to run; NULL searches for `NCFG_AUTOIP_PROGRAM` on
 * `PATH`, which is what the daemon means and what a test never uses -- a test
 * passes a path to a stub, for `backend_internal.h`'s reason.
 *
 * **The start is synchronous**, which is `-w`'s doing: the client stays in the
 * foreground until it has acquired an address and only then detaches, so the
 * exit status says whether link-local addressing actually happened rather than
 * whether a process was spawned.
 *
 * One already running and netcfgd's own is success and starts nothing, which is
 * the state this was asked to produce. One running that netcfgd cannot claim
 * fails by name rather than being signalled or spawned beside.
 *
 * Returns 0 with a message naming what failed: no client installed, one
 * installed that cannot be executed, a client that refused -- quoting what it
 * said -- or a client that acquired nothing.
 */
int ncfg_autoip_start(const char *run, const char *iface, const char *program, char *err,
    size_t err_size);

/*
 * Stop the one netcfgd started on this interface.
 *
 * Nothing running is the state this was asked to produce, so that is success.
 * A pid whose `cmdline` no longer carries the marker is somebody else's by now
 * -- a pid is a moment, not an artifact -- and is left alone rather than
 * signalled.
 */
int ncfg_autoip_stop(const char *run, const char *iface, char *err, size_t err_size);

/*
 * The pid of netcfgd's own client on this interface, or 0.
 *
 * Re-read from `/proc` every time rather than trusted from the file: the pid
 * file outlives the process it names, and pids are recycled.
 */
pid_t ncfg_autoip_running_pid(const char *run, const char *iface);

#endif /* NCFG_AUTOIP_H */
