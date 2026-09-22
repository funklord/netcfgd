/*
 * pppoe.h -- dialling a DSL line, and hanging it up again.
 *
 * WHAT NETCFGD OWNS HERE
 *   pppd's options file, the two scripts it runs when a session comes up and
 *   goes down, and the lifecycle around them. The *session* is pppd's: netcfgd
 *   writes what to dial with, starts it, and later identifies the process it
 *   started well enough to stop that one and nothing else.
 *
 * WHY A FILE RATHER THAN ARGUMENTS
 *   The password. pppd takes a `password` option and **anything on a command
 *   line is readable by every process on the machine** through `/proc`, so the
 *   credential goes in a file at mode 0600 under the run directory -- which is
 *   tmpfs, so it does not survive a reboot, and which is not `/etc/ppp`, so it
 *   cannot collide with whatever else on the host dials.
 *
 *   The mode goes on the open rather than after it. A create-then-chmod leaves
 *   the file world-readable for an instant, and a local process that opens it
 *   in that instant holds a readable descriptor the later chmod does not
 *   revoke -- measured in the Rust: an fd opened at 0644 returns the content
 *   written after a chmod to 0600. `ncfg_backend_write_file` is what settles
 *   it here, and it also tightens a file that already existed at a wider mode.
 *
 * WHY PPPD IS TOLD TO INSTALL NEITHER A ROUTE NOR A RESOLVER
 *   Both would be somebody else configuring the network behind netcfgd's back,
 *   which constraint 1 exists to prevent -- and the drift report would be
 *   right and useless, since the operator did not ask for either. What a DSL
 *   user needs instead is `routes = "default"` on the ppp interface: a
 *   point-to-point link needs no gateway, so that is a device route netcfgd
 *   owns and can explain rather than a dynamic one nobody wrote down.
 *
 *   The one thing only pppd can learn is the ISP's resolvers, and those come
 *   back through `doc/interface-report.md` -- the same contract a modem helper
 *   and an OpenVPN tunnel write.
 *
 * WHY TWO SCRIPTS AND NOT ONE
 *   pppd hands `ip-up` and `ip-down` the same argv and **does not unset
 *   `IPLOCAL`, `DNS1` or `DNS2` on the way down**; it unsets `OLDIPLOCAL` and
 *   `CONNECT_TIME` and leaves the rest standing. A single script testing its
 *   environment for "is this a teardown" would therefore rewrite the same
 *   nameservers as the session went away, and netcfgd would hold an ISP's
 *   resolvers for a line that is down. Which script pppd invoked is the only
 *   thing that differs between the two calls, so that has to be the answer.
 *
 * STOPPED BY A PID THAT HAS TO PROVE WHOSE IT IS
 *   **pppd has no control socket**, which is what every other daemon here is
 *   stopped through (0014). What it has is a pid file it writes itself, named
 *   for the interface -- and a pid file outlives the process it names while
 *   pids are recycled. So the pid is checked against `/proc/<pid>/cmdline` by
 *   `ncfg_process_pid_of`, with **the options file netcfgd generated** as the
 *   marker: a path netcfgd chose, unique to this session on this machine. An
 *   operator's own pppd cannot match it.
 *
 *   Where pppd writes that file is not fixed -- Debian's pppd 2.5.2 writes
 *   `/run/<iface>.pid` and upstream's default is `${runstatedir}/pppd/` -- so
 *   the directories are a list rather than one guess, and a wrong guess here
 *   would silently stop nothing.
 *
 * EVERY PATH IS A PARAMETER
 *   `openvpn.h`'s rule, for its reason: the run directory, the report file,
 *   the program and the directories pppd's own pid file may be in. A test
 *   passes a program it wrote and cannot dial a real line by accident.
 */
#ifndef NCFG_PPPOE_H
#define NCFG_PPPOE_H

#include "ncfg/document.h"

#include <stddef.h>
#include <sys/types.h>

/* Long enough for a run directory, `ppp/` and `<iface>.down`. */
#define NCFG_PPPOE_PATH_MAX 512

/* Where pppd's own pid file may be, on the machines this runs on. The list is
 * `ncfg_pppoe_machine`'s and is here so a reader can see it without running
 * anything. */
#define NCFG_PPPOE_PID_DIRS_DEFAULT "/run", "/run/pppd", "/var/run", "/var/run/pppd"

/*
 * What a session needs from the machine, with no defaults taken silently.
 *
 * `dhcp.h`'s arrangement and for its reason: the Rust reaches for a fixed list
 * of directories and a fixed program search, and a test cannot get in front of
 * either. Here they are members, and `ncfg_pppoe_machine` is the one place
 * this machine's answers are written down.
 */
typedef struct {
	/* The pppd to run. NULL searches `/usr/sbin` first, then `PATH`. */
	const char *program;
	/* Where pppd's own pid file is looked for. NULL is the list above. */
	const char *const *pid_dirs;
	size_t             pid_dir_count;
} ncfg_pppoe_machine_t;

/* This machine's own. Fills both members with the defaults above. */
void ncfg_pppoe_machine(ncfg_pppoe_machine_t *out);

/* ------------------------------------------------------------ the paths */

/* `<run>/ppp`, made by a start. */
int ncfg_pppoe_run_dir(const char *run, char *out, size_t out_size, char *err, size_t err_size);
/* `<run>/ppp/<iface>`: the options file, and the marker a stop identifies
 * netcfgd's own pppd by. */
int ncfg_pppoe_options_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size);
/* `<run>/ppp/<iface>.up` and `<iface>.down`. */
int ncfg_pppoe_script_path(const char *run, const char *iface, int going_up, char *out,
    size_t out_size, char *err, size_t err_size);
/* `<run>/ppp/<iface>.log`, where pppd's own complaint about a dial that did
 * not start is kept. */
int ncfg_pppoe_log_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size);

/* --------------------------------------------------- what pppd is told */

/*
 * The options file's text, allocated.
 *
 * Pure, so what pppd is handed can be read without a DSL line -- and the two
 * things most worth reading are that the password survives quoting and that
 * pppd is told to leave routes and resolvers alone.
 *
 * `password` is the already-resolved credential; the document carries only a
 * reference to one. `up` and `down` are the two scripts' paths, passed in
 * rather than derived, because the layout of the run directory belongs to the
 * caller.
 */
char *ncfg_pppoe_options(const char *iface, const ncfg_pppoe_config_t *config,
    const char *password, const char *up, const char *down, char *err, size_t err_size);

/*
 * One of the two scripts, allocated.
 *
 * Pure, for `ncfg_openvpn_report_script`'s reason: what a session reports can
 * then be checked without dialling one. `report` is the file to write.
 *
 * **Only the nameservers are reported.** The address is IPCP's and the routes
 * are the document's, so a report carrying either would be netcfgd claiming
 * something it did not decide.
 */
char *ncfg_pppoe_script(const char *iface, const char *report, int going_up, char *err,
    size_t err_size);

/* ------------------------------------------------------- the lifecycle */

/*
 * Dial the session `config` describes.
 *
 * Writes the two scripts and the options file, then runs `pppd file <options>`
 * -- which returns as soon as pppd has detached, so success here is a dial
 * that started rather than a line that came up. The report arrives later,
 * through the `ip-up` script.
 *
 * **A failed dial deliberately leaves the options file behind.** It is 0600
 * and netcfgd runs as root, so the only reader is somebody who can already
 * read `/etc/netcfgd/secrets` -- there is no exposure to remove -- and what
 * removing it costs is the only way this project can check what it hands pppd
 * on a machine with no DSL line. A session that genuinely ran has its files
 * taken back by `ncfg_pppoe_stop`.
 *
 * 0 with a message naming what failed: no pppd installed, a file that could
 * not be written, or pppd refusing to dial -- quoting what it said rather than
 * its exit status.
 */
int ncfg_pppoe_start(const char *run, const char *iface, const ncfg_pppoe_config_t *config,
    const char *password, const ncfg_pppoe_machine_t *machine, char *err, size_t err_size);

/*
 * Hang up the session on one interface, and take its files back.
 *
 * The report goes first and whether or not anything is running: it is a claim
 * about resolvers a session is providing, and the session is going either way.
 *
 * **Nothing netcfgd can identify as its own is success**, not a failure: an
 * apply run twice, and a session that died on its own, both land there -- and
 * the second is the case that matters most for the files, because a dead pppd
 * leaves its options file, with the password in it, behind.
 *
 * The files go *after* the signal, never before: the options file is what
 * identifies the process, so a stop that failed must leave the evidence for
 * the next attempt to find.
 */
int ncfg_pppoe_stop(const char *run, const char *iface, const char *report,
    const ncfg_pppoe_machine_t *machine, char *err, size_t err_size);

/*
 * The pid of netcfgd's own pppd on this interface, or 0.
 *
 * Every directory in `machine` is looked in, and the options file this build
 * wrote is the marker. See the header above for why both halves are needed.
 */
pid_t ncfg_pppoe_running_pid(const char *run, const char *iface,
    const ncfg_pppoe_machine_t *machine);

/* Find `pppd`, `/usr/sbin` first. Allocated, or NULL. */
char *ncfg_pppoe_binary(void);

#endif /* NCFG_PPPOE_H */
