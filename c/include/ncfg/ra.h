/*
 * ra.h -- router advertisement, which netcfgd configures and does not send.
 *
 * WHAT THIS IS
 *   Design section 1.5 keeps netcfgd off the wire: it does not speak DHCP, it
 *   does not speak EAP, and it does not send router advertisements either.
 *   What it does is decide *what* should be advertised and hand that to a
 *   daemon -- the same split 0026 made for hostapd and for the same reason. An
 *   RA is a packet a host on the LAN acts on without asking, and a program
 *   that composes those is a program with a parser and a timer loop facing a
 *   network, which is the surface this project is arranged to avoid.
 *
 * WHICH DAEMON
 *   radvd. `odhcpd` is the OpenWrt one and is not implemented in this build --
 *   it is **refused by name rather than silently substituted**, because the two
 *   take entirely different configuration and a document that names one and
 *   gets the other is a document that stopped describing the system.
 *
 * WHERE THE PREFIX COMES FROM
 *   Never from here. `ncfg_ra_policy_t::prefixes` is a list of
 *   `ncfg_prefix_ref_t`, and 0009 makes that an indirection the *document*
 *   resolves: a router advertising the /64 it carved out of an ISP's
 *   delegation is advertising something no config file could have contained.
 *   The caller resolves the references and passes the prefixes it derived, so
 *   this renders values and looks nothing up.
 *
 * WHERE THE FILES GO
 *   Under netcfgd's own run directory rather than `/etc/radvd.conf`, for the
 *   reason hostapd's are: a file in the distribution's location would be found
 *   by that distribution's tooling, which would then be managing an
 *   advertisement netcfgd owns. **The run directory is a parameter of every
 *   call**, which is what lets a check run on a machine whose real netcfgd is
 *   managing its real network.
 *
 * RELOAD IS NOT RESTART, AND THAT IS THE POINT OF HAVING ONE
 *   radvd handles `SIGHUP` by re-reading the file it was started with, checked
 *   in radvd 2.20's own `radvd.c` rather than taken from the manual page,
 *   which does not mention it. So a changed prefix costs nothing on the wire.
 *   That is the opposite of an access point, where the same question means a
 *   restart and every client is deauthenticated (0026), and it is worth
 *   knowing which of the two a backend is.
 */
#ifndef NCFG_RA_H
#define NCFG_RA_H

#include <stddef.h>
#include <sys/types.h>

#include "ncfg/document.h"

/* Long enough for a run directory, a subdirectory and `<iface>.conf`. */
#define NCFG_RA_PATH_MAX 512

/*
 * The four paths one advertising interface has, under `<run>/radvd/`.
 *
 * Written into a caller's buffer and returning it rather than allocating, which
 * is `ncfg_state_resolve_dir`'s convention: one buffer, no ownership question.
 * 1 on success; a path that would not fit is a failure rather than a shorter
 * one, because the caller is about to write to it.
 */
int ncfg_ra_run_dir(const char *run, char *out, size_t out_size, char *err, size_t err_size);
int ncfg_ra_config_path(const char *run, const char *iface, char *out, size_t out_size, char *err,
    size_t err_size);
int ncfg_ra_pid_path(const char *run, const char *iface, char *out, size_t out_size, char *err,
    size_t err_size);
int ncfg_ra_log_path(const char *run, const char *iface, char *out, size_t out_size, char *err,
    size_t err_size);

/*
 * The configuration radvd reads, from a policy and the prefixes it names.
 *
 * Pure, so what is advertised can be checked without sending anything -- and
 * `radvd --configtest` parses this same text, which is the check that matters
 * most (`tests/live/advertise.sh`).
 *
 * `AdvSendAdvert on` is the whole point of the file and is not a knob: an
 * interface netcfgd was told to advertise on is one it advertises on. What the
 * document controls is the two flags that send hosts to a DHCPv6 server
 * (`managed`, `other_config`), the lifetime, and whether the nameservers the
 * LAN's own DNS scope carries go out as `RDNSS`.
 *
 * A prefix is advertised `AdvOnLink on; AdvAutonomous on;` -- the combination
 * that makes a host both treat it as local and configure an address from it,
 * which is the only combination that makes a delegated prefix useful to the
 * hosts behind the router. Anything narrower would be a knob nobody asked for.
 *
 * Allocated; free it with `free`. NULL with a sentence on failure.
 */
char *ncfg_ra_render(const char *iface, const ncfg_ra_policy_t *policy,
    const char *const *prefixes, size_t prefix_count, const char *const *servers,
    size_t server_count, char *err, size_t err_size);

/*
 * Start advertising on one interface.
 *
 * `program` is the radvd to run. NULL searches for one the way
 * `ncfg_ra_binary` does; a caller that passes a path is the reason a check can
 * exercise the whole start path without a radvd on the machine.
 *
 * Returns 0 with a message naming what failed: a backend this build does not
 * implement, no radvd installed, a policy with no prefix to advertise, or
 * radvd refusing the configuration -- quoting what it said.
 */
int ncfg_ra_start(const char *run, const char *iface, const ncfg_ra_policy_t *policy,
    const char *const *prefixes, size_t prefix_count, const char *const *servers,
    size_t server_count, const char *program, char *err, size_t err_size);

/*
 * Rewrite the configuration and tell a running radvd to re-read it.
 *
 * **Rewriting before signalling is the order that matters**: radvd reads the
 * file when it is told to, so a signal sent first would reload the old
 * contents.
 *
 * A daemon that is not running is *not* success here: `ncfg_ra_start` is what a
 * stopped daemon needs, and quietly doing nothing would leave the document and
 * the wire disagreeing with nothing to say so.
 */
int ncfg_ra_reload(const char *run, const char *iface, const ncfg_ra_policy_t *policy,
    const char *const *prefixes, size_t prefix_count, const char *const *servers,
    size_t server_count, char *err, size_t err_size);

/*
 * Stop advertising on one interface.
 *
 * radvd has no control socket, so this is the `pppd` shape: read the pid file
 * radvd wrote for this interface, check `/proc/<pid>/cmdline` names the
 * configuration netcfgd generated, and only then signal it. An operator's own
 * radvd cannot match that, which is a stronger claim than "not by name".
 *
 * Nothing running is the state this was asked to produce, so that is success.
 */
int ncfg_ra_stop(const char *run, const char *iface, char *err, size_t err_size);

/*
 * Whether netcfgd's own radvd is running on this interface, and its pid.
 *
 * 0 where none is. The generated configuration is the marker: it is a path
 * netcfgd chose, so it is unique to this daemon on this machine. The ownership
 * rule itself lives in `ncfg_process_pid_of`, which is where it is written once
 * rather than in each of the four places that needed it.
 */
pid_t ncfg_ra_running_pid(const char *run, const char *iface);

/* Find `radvd`, `/usr/sbin` first. Allocated, or NULL. */
char *ncfg_ra_binary(void);

#endif /* NCFG_RA_H */
