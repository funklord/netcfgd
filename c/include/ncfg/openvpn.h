/*
 * openvpn.h -- running a tunnel whose configuration netcfgd does not own.
 *
 * THE ONE THING THAT DECIDES EVERYTHING ELSE HERE
 *   netcfgd generates hostapd's configuration and `pppd`'s options file; it
 *   generates none of OpenVPN's. `openvpn --help` lists **253 top-level
 *   options**, against a couple of dozen expressible keys for hostapd, and a
 *   `.ovpn` is something an operator is *given* rather than a rendering of an
 *   intent netcfgd holds. Decision 0046 has the argument; the consequence for
 *   this module is that **it never reads the file for meaning**.
 *
 * WHICH IS ALSO WHY NAMING ONE IS PRIVILEGED
 *   `openvpn.config` is the `ForeignConfig` production in
 *   `netcfgd-compile`'s privilege table, and the sentence that table gives is
 *   the sentence this module is built around: "that names another program's
 *   configuration file, which netcfgd hands to it as root and which may itself
 *   name scripts to run". A `.ovpn` carries `up` and `down` directives. So a
 *   caller who is not root cannot send one, and **this module treats the path
 *   as opaque**: it is passed to `--config` and never opened for content.
 *
 *   Two things here do touch the bytes, and both are deliberate and neither
 *   interprets them:
 *
 *   * `ncfg_openvpn_start` checks that a file is *there*, only because the
 *     error is so much better -- netcfgd knows the path came from a document
 *     and can say so, where openvpn says "Options error" against a file the
 *     operator may not realise netcfgd chose.
 *   * `ncfg_openvpn_hash_of` digests it, which is the same thing a hook's
 *     `sha256` does for a script netcfgd equally does not interpret (section
 *     2.2). It is what makes an *edited* `.ovpn` something a later reconcile
 *     can notice at all (0053).
 *
 *   Nothing else may open it. A future that wanted to read an option out of
 *   that file is a future that has made netcfgd a second OpenVPN configuration
 *   language, permanently behind the first.
 *
 * WHAT IT DOES OWN
 *   The lifecycle: start the daemon, stop the one it started, and say what the
 *   daemon said when it will not run. Plus the report script, which is
 *   netcfgd's whole side of `--route-up`: openvpn is told `--route-noexec` so
 *   the routes stay netcfgd's (0047), and the script hands back what the server
 *   pushed through `doc/interface-report.md` -- the same contract a modem
 *   helper writes (0048).
 *
 * STOPPED THROUGH THE MANAGEMENT SOCKET, AND BY PID WHEN IT WILL NOT ANSWER
 *   `--management <path> unix` gives OpenVPN a line-oriented text protocol on a
 *   unix **stream** socket, and `signal SIGTERM` over it stops the daemon --
 *   which beats killing a process found by name, because an operator's own
 *   OpenVPN tunnels are common (0014).
 *
 *   **But nothing listening is not nothing running.** `--daemon` returns as
 *   soon as openvpn forks, and the child binds its socket a moment later, so a
 *   stop arriving inside that window found nothing, reported the tunnel
 *   stopped, and left a daemon netcfgd would never speak to again. Measured:
 *   with a three-second gap, `ncfg apply` printed `ok backend.stop vpn0` and
 *   then `nothing to do`, with the tunnel still up (0074). So `--writepid`
 *   gives a second handle, and only a daemon that is neither reachable nor
 *   running counts as already stopped.
 *
 * EVERY PATH IS A PARAMETER
 *   The run directory, the report file and the program. The Rust reads
 *   `NCFG_OPENVPN` out of the environment and its own comment says what the
 *   absence of one cost: `tests/live/openvpn.sh` faked the daemon on `PATH` to
 *   check the command line netcfgd builds, the `/usr/sbin` search reached the
 *   real one first, and 20 of its 45 checks were silently exercising the
 *   machine's openvpn (0101).
 */
#ifndef NCFG_OPENVPN_H
#define NCFG_OPENVPN_H

/*
 * What a test puts in front of the conventional `openvpn`.
 *
 * **The name only. Nothing in this module reads it** -- every path here is a
 * parameter, for the reason the header comment gives: 20 of 45 checks in the
 * Rust's live script were silently exercising the machine's own openvpn
 * because the search had no other seam. The daemon and `ncfg` read this when
 * they build the world they hand to an executor.
 */
#define NCFG_OPENVPN_PROGRAM_ENV "NCFG_OPENVPN"

#include <stddef.h>
#include <sys/types.h>

/* Long enough for a run directory, a subdirectory and `<iface>.ovpn.sha256`. */
#define NCFG_OPENVPN_PATH_MAX 512

/*
 * The six paths one tunnel has, under `<run>/openvpn/`.
 *
 * Under netcfgd's own run directory rather than `/run/openvpn`, for the reason
 * hostapd's are: a socket in the distribution's location would be found by that
 * distribution's tooling, which would then be managing a tunnel netcfgd owns.
 */
int ncfg_openvpn_run_dir(const char *run, char *out, size_t out_size, char *err, size_t err_size);
int ncfg_openvpn_socket_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size);
int ncfg_openvpn_log_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size);
/*
 * Where the daemon writes its own pid, and the only handle netcfgd has when the
 * management socket is not answering.
 *
 * `--writepid` is openvpn's own option for this, so the file is the daemon's
 * claim about itself rather than netcfgd's guess -- which matters because the
 * pid netcfgd could observe is the parent that exits.
 */
int ncfg_openvpn_pid_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size);
/*
 * Where the credentials for one tunnel go, when the server wants any.
 *
 * Mode 0600 and under the run directory, which is the same trade the generated
 * hostapd configuration and the `pppd` options file already make, with the same
 * mitigations: the run directory is tmpfs so it does not survive a reboot, and
 * the document itself still carries only a secret reference (constraint 5).
 * OpenVPN has no indirection for a password either -- `--auth-user-pass` takes
 * a file with the username on the first line and the password on the second,
 * and there is no other way in.
 */
int ncfg_openvpn_auth_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size);
int ncfg_openvpn_script_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size);
/*
 * Where netcfgd records the `.ovpn` it started this tunnel from.
 *
 * **A hash, not a copy.** The file is the operator's and netcfgd does not read
 * it for meaning (0046) -- but it can notice that it changed, which is the same
 * thing a hook's `sha256` does for a script netcfgd equally does not interpret
 * (0053).
 */
int ncfg_openvpn_config_hash_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size);

/*
 * The hash of a `.ovpn`, as netcfgd records and compares it.
 *
 * `out` holds at least `NCFG_SHA256_HEX_SIZE` bytes. 0 where the file cannot be
 * read at all, which is the honest answer: "the operator's file is not there"
 * is a different statement from "it changed", and only one of them is a reason
 * to restart a working tunnel.
 */
int ncfg_openvpn_hash_of(const char *config, char *out, size_t out_size);

/*
 * Record which `.ovpn` the running tunnel was started from.
 *
 * **A call with a return value rather than three lines and an ignored result,
 * because its failure is a silence with consequences.** This hash is the only
 * thing that makes an edited config visible to a later reconcile (0053), so a
 * record that could not be written means the operator edits the file and
 * netcfgd never restarts the tunnel. Until 0180 it said nothing about that.
 *
 * Success where the file cannot be hashed at all: that is not a write failing,
 * it is there being nothing to write.
 */
int ncfg_openvpn_record_started_from(const char *run, const char *iface, const char *config,
    char *err, size_t err_size);

/*
 * The script's text, which is the whole of netcfgd's side of `--route-up`.
 *
 * Pure, so that what a tunnel is told to do can be read without running one.
 * `report` is the file to write and is passed in rather than derived: the
 * layout of the run directory belongs to the caller, and a second module
 * spelling `reported` for itself is how two spellings start.
 *
 * WHAT THE ENVIRONMENT HOLDS, MEASURED RATHER THAN ASSUMED
 *   Against a real openvpn 2.6.14 in a network namespace, with a real `tun`:
 *
 *   * `route_network_N`, `route_netmask_N`, `route_gateway_N` for IPv4, with
 *     the netmask **dotted** rather than a prefix length. The gateway is filled
 *     in even for a route the config gave none -- it becomes the tunnel's own
 *     endpoint.
 *   * `route_ipv6_network_N` already in CIDR, with `route_ipv6_gateway_N`.
 *   * `foreign_option_N` for everything the server said about resolvers.
 *     **2.6's newer `--dns server` syntax arrives in the same list**: on
 *     anything that is not Windows, `foreign_options_copy_dns` rewrites it into
 *     `dhcp-option` form, so reading one spelling reads both.
 *   * Both **survive `--route-noexec`**, because the environment is filled in
 *     when the route list is built and the flag only skips installing it.
 *   * **`N` is not guaranteed contiguous**: `setenv_route` skips a route that
 *     is not fully defined and the counter moves on regardless, so the script
 *     scans a range rather than stopping at the first gap.
 *
 * THE ONE THING THAT DOES NOT SURVIVE
 *   **`redirect-gateway` for IPv4 leaves no trace in the environment.** The
 *   `0.0.0.0/1` pair it installs is added inside `add_routes`, which
 *   `--route-noexec` skips entirely, and the `redirect_gateway` variable is set
 *   in the same skipped branch. The IPv6 half *does* survive, because those
 *   four prefixes join the option list before the route list is built. Measured
 *   both ways; 0048 says the local answer is `routes = "default"` in the
 *   document.
 *
 * WHAT A SERVER DOES NOT GET TO DECIDE
 *   `DOMAIN` and `DOMAIN-SEARCH` are reported as **search suffixes**, which is
 *   0067 splitting 0049 in two: what to append to a bare name travels under the
 *   same gate as a nameserver, while *which names go through this tunnel* is a
 *   routing domain, is the operator's to say in the document, and has no report
 *   key at all. Everything else the server suggested becomes a comment:
 *   declined, and visible to whoever reads the file rather than silently
 *   dropped.
 */
char *ncfg_openvpn_report_script(const char *iface, const char *report, char *err,
    size_t err_size);

/*
 * Start the tunnel described by `config`, which is a path netcfgd hands over
 * unread.
 *
 * `username` and `password` are the already-resolved credentials, or NULL for a
 * `.ovpn` that authenticates without any -- in which case a credentials file
 * from an earlier configuration is removed, so a password does not outlive the
 * document that asked for it. **The path is passed to openvpn, never the
 * values**: a password on a command line is readable by every process on the
 * machine through `/proc`.
 *
 * `program` is the openvpn to run; NULL searches `/usr/sbin` first, then
 * `PATH`.
 *
 * 0 with a message naming what failed: no openvpn installed, a configuration
 * file that is not there, or the daemon refusing to start -- quoting what it
 * said rather than its exit status.
 */
int ncfg_openvpn_start(const char *run, const char *iface, const char *config,
    const char *username, const char *password, const char *report, const char *program,
    char *err, size_t err_size);

/*
 * Stop the tunnel on one interface.
 *
 * The report is removed **before the signal and outside the "is anything
 * listening" question**: a report is a claim that routes exist, and the tunnel
 * they belong to is going either way -- a daemon that already died is exactly
 * the case where nobody comes back to tidy up, which is the lesson a stopped
 * access point's passphrase paid for.
 *
 * The generated script itself stays. It is regenerated on every start, it does
 * nothing unless openvpn runs it, and removing it here would pull it out from
 * under the `--down` call that has not happened yet.
 *
 * Nothing listening and nothing running is the state this was asked to produce,
 * so that is success.
 */
int ncfg_openvpn_stop(const char *run, const char *iface, const char *report, char *err,
    size_t err_size);

/*
 * Whether netcfgd's own openvpn is running on this interface, and its pid.
 *
 * The pid is checked against `/proc/<pid>/cmdline` and against **this
 * interface's own socket path** rather than the interface name alone: `vpn0` is
 * a short string that a wholly unrelated command line could contain, where the
 * socket path is unique to this tunnel on this machine. That is the same
 * reasoning `pppd_pid` and the DHCP clients use, one notch stricter because the
 * argument here is a path netcfgd chose.
 */
pid_t ncfg_openvpn_running_pid(const char *run, const char *iface);

/* Find `openvpn`, `/usr/sbin` first. Allocated, or NULL. */
char *ncfg_openvpn_binary(void);

/* --------------------------------------------- the management connection */

typedef struct ncfg_openvpn_management ncfg_openvpn_management_t;

/*
 * Open one tunnel's management socket.
 *
 * NULL where nothing is listening, which is the ordinary case for a tunnel that
 * is not running. The deadline is short and for the reason hostapd's ACL read
 * is: this runs where an apply is waiting, and the daemon is answering from
 * memory, so a tunnel that has wedged should not hold the executor.
 */
ncfg_openvpn_management_t *ncfg_openvpn_connect(const char *socket_path, char *err,
    size_t err_size);

void ncfg_openvpn_disconnect(ncfg_openvpn_management_t *management);

/*
 * Send one command and read until the daemon answers it.
 *
 * **OpenVPN greets a new client with `>INFO:` before it is asked anything**,
 * and emits further `>`-prefixed notifications whenever it likes, interleaved
 * with replies. Reading the first line as the answer is the classic bug in a
 * management client and produces a stop that silently did nothing -- the same
 * failure the supplicant's client documents for `wpa_ctrl` events, arrived at
 * independently because both protocols made the same choice.
 *
 * Skipping them needs no test for `>`: **reading until a line *is* an answer
 * passes over anything that is not one**, and a `>` branch on top would be a
 * guard clause no input could make fire.
 *
 * `reply` receives what followed `SUCCESS: `. 0 on a socket failure, a timeout,
 * or an `ERROR:` reply -- which is quoted.
 */
int ncfg_openvpn_command(ncfg_openvpn_management_t *management, const char *command, char *reply,
    size_t reply_size, char *err, size_t err_size);

#endif /* NCFG_OPENVPN_H */
