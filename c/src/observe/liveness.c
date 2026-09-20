/*
 * liveness.c -- whether the daemons netcfgd started are still there.
 *
 * WHAT THIS CLOSES
 *   `ncfg_observed_backend_t::running` says of itself that it is *a fact about
 *   a process: something is there under that pid*. Until this pass it was not:
 *   the backend list is filled from the prior state and from nowhere else, so
 *   `running: true` was netcfgd's memory of having started something. A daemon
 *   that crashed an hour ago stayed `running` for ever, and 0079's restart
 *   could not fire for it -- the cap counts starts of something the record
 *   already says is up, so "never started again" became "started for ever" the
 *   moment anyone tried to clear it on `running` instead (project.md 10.183).
 *
 * WHY IT ONLY EVER CLEARS
 *   The record is netcfgd's account of what *it* started. A process netcfgd did
 *   not start is not netcfgd's, whatever its command line looks like, and
 *   `process.h` spends its header on that rule. So this asks "is what I
 *   recorded still there", and the only answer it writes is *no*. Inventing a
 *   backend from a matching process would make the observation a scan of the
 *   machine rather than a reconciliation of netcfgd's own state, and the
 *   planner would then stop a daemon it never started.
 *
 * WHY EVERY ANSWER IS SOMEBODY ELSE'S FUNCTION
 *   Six modules already answer "is mine running on this interface", each with
 *   the marker it chose -- a pid file `-P` names, a generated configuration, a
 *   management socket. The Rust has `backend_pid_file`, seven kinds in one
 *   function, which is a seventh spelling of six rules. This calls the six.
 *   The one thing written here is the *mapping*, and it is a switch with no
 *   `default:` so that a kind added to the taxonomy fails to compile rather
 *   than falling quietly into "cannot answer".
 *
 * WHAT ELSE A DHCP CLIENT IS ASKED WHILE IT IS UP
 *   `started_metric`: the route metric the running client was started with, and
 *   the reason it is read *here* is the reason the Rust reads it here too -- a
 *   record read for a process that has exited is not an observation of
 *   anything. It is the input to `ncfg_plan_metric_restart`'s first half, which
 *   answers before any route exists; the installed route answers the second
 *   half and cannot, because a client that has not finished its first exchange
 *   has installed nothing. Until this pass wrote it the field had no producer
 *   at all, so that first half never fired on any machine (project.md 10.206).
 *
 *   **Read for a client this pass could not ask about, as well as one it
 *   found.** That is not sloppiness and it is where this differs from the
 *   Rust's, which reads it only behind a pid: the record is written for dhcpcd
 *   alone -- `dhcp.h` says busybox udhcpc has no `-m` to be given -- and
 *   dhcpcd is precisely the client this pass cannot ask about. Reading it only
 *   where a pid was found would fill the field exactly for the clients that
 *   never have a metric, which is a producer that cannot produce. What it is
 *   never read for is a backend this pass has just declared dead.
 *
 * THE TWO CLIENTS A DHCP KIND COULD BE
 *   `ncfg_dhcp_running_pid` takes the program, because the pid file lives in a
 *   directory named after the client. The record does not carry which one was
 *   started, so both netcfgd can start are tried -- and either answering is
 *   enough. **dhcpcd is neither**: `dhcp.h` says in as many words that it has
 *   no pid file of netcfgd's and no mark in its process image, so a dhcpcd
 *   machine's clients are left alone here and `ncfg_dhcpcd_whose` is the
 *   question to ask about one.
 *
 *   What separates the two is **whether the file is there**, not whether it
 *   answered. No file for either program is dhcpcd, or a client from before
 *   this build, and neither may be buried on that. A file netcfgd wrote that
 *   names nothing is netcfgd's own record of a client that has gone, and is
 *   the one case here that may clear.
 */
#include "ncfg/observe.h"

#include "ncfg/base.h"
#include "ncfg/dhcp.h"
#include "ncfg/hostapd.h"
#include "ncfg/openvpn.h"
#include "ncfg/ra.h"
#include "ncfg/supplicant.h"

#include <unistd.h>

/*
 * Whether netcfgd's own pid file for this client is there at all.
 *
 * Separate from reading it, because the two answer different questions: the
 * pid says whether the client is alive, and the file says whether netcfgd is
 * in a position to ask. `ncfg_dhcp_pid_path` composes it rather than this
 * file, so a directory layout change cannot make the check and the read
 * disagree -- which would be invisible, every client reading "cannot tell".
 */
static int dhcp_pid_file(const char *run_dir, const char *program, const char *iface)
{
	char path[512];

	if (!ncfg_dhcp_pid_path(run_dir, program, iface, path, sizeof(path), NULL, 0)) {
		return 0;
	}
	return access(path, F_OK) == 0;
}

/*
 * Whether this kind can be asked at all, and the answer if it can.
 *
 * `*answerable` separates "netcfgd asked and it is gone" from "netcfgd has no
 * way to ask", which are the two things a single pid of 0 would run together.
 * Only the first may clear `running`.
 */
static pid_t pid_of_backend(const ncfg_observed_backend_t *backend, const char *run_dir,
    int *answerable)
{
	pid_t pid;

	*answerable = 1;
	switch ((ncfg_backend_kind_t)backend->kind) {
	case NCFG_BACKEND_SUPPLICANT:
		return ncfg_supplicant_running_pid(run_dir, backend->interface);
	case NCFG_BACKEND_ACCESS_POINT:
		return ncfg_hostapd_running_pid(run_dir, backend->interface);
	case NCFG_BACKEND_ROUTER_ADVERT:
		return ncfg_ra_running_pid(run_dir, backend->interface);
	case NCFG_BACKEND_OPENVPN:
		return ncfg_openvpn_running_pid(run_dir, backend->interface);
	case NCFG_BACKEND_DHCP4:
	case NCFG_BACKEND_DHCP6:
		/*
		 * Either of the two netcfgd can start answering is enough. A machine
		 * running dhcpcd has neither file, which is why this is not allowed to
		 * clear on its own: see below.
		 */
		pid = ncfg_dhcp_running_pid(run_dir, "udhcpc", backend->interface);
		if (pid <= 0) {
			pid = ncfg_dhcp_running_pid(run_dir, "busybox", backend->interface);
		}
		if (pid <= 0 && !dhcp_pid_file(run_dir, "udhcpc", backend->interface) &&
		    !dhcp_pid_file(run_dir, "busybox", backend->interface)) {
			/*
			 * **Not answerable, rather than answered `no`.** dhcpcd is the
			 * default client on a Debian machine and netcfgd gives it no pid
			 * file at all, so clearing on a missing file would report every
			 * dhcpcd client on the machine as dead -- and the planner would
			 * restart a client that is running, taking the lease down to do
			 * it. `dhcp.h` names `ncfg_dhcpcd_whose` as the question for one
			 * of those, and it needs the machine's paths, which an observation
			 * pass is not given.
			 *
			 * **The file's absence is the test, not the pid's.** A pid file
			 * that is there and names nothing is netcfgd's own record of a
			 * client that has gone, and while this arm answered "cannot tell"
			 * to both, a udhcpc client that died stayed `running` for ever --
			 * so the planner never restarted it and the interface kept no
			 * lease at all (project.md 10.206). The Rust asks `path.exists()`
			 * first for the same reason.
			 */
			*answerable = 0;
		}
		return pid;
	case NCFG_BACKEND_PPPOE:
		/* The Rust answers this one, through an options file `pppd` carries in
		 * its own `argv`. This port does not start `pppd` at all -- a pppoe
		 * `link.create` is refused by name -- so there is nothing of netcfgd's
		 * to find, and saying "gone" about a session netcfgd never started is
		 * the invention this pass is arranged to avoid. */
		*answerable = 0;
		return 0;
	case NCFG_BACKEND_WIREGUARD:
	case NCFG_BACKEND_DNS:
		/* Neither is a process netcfgd starts: WireGuard is a kernel device
		 * and DNS is a file delivered to somebody else's daemon. A record
		 * carrying one is not describing something with a pid. */
		*answerable = 0;
		return 0;
	}
	*answerable = 0;
	return 0;
}

/*
 * What a running DHCPv4 client was started with, where netcfgd wrote it down.
 *
 * Absent where it cannot tell -- no record, an unreadable one, or a client
 * started before the record existed -- which `dhcp.h` keeps distinct from a
 * metric of zero, that being a legitimate and the strongest value. Only a
 * DHCPv4 client: `-m` is never given to anything else, and a record beside
 * another kind would be a number nobody wrote.
 */
static void note_started_metric(ncfg_observed_backend_t *backend, const char *run_dir)
{
	if (backend->kind != (int)NCFG_BACKEND_DHCP4) {
		return;
	}
	backend->started_metric = ncfg_dhcp_started_metric(run_dir, backend->interface);
}

int ncfg_observe_backend_liveness(ncfg_observed_t *observed, const char *run_dir, char *err,
    size_t err_size)
{
	size_t i;

	if (!observed || !run_dir || !run_dir[0]) {
		ncfg_error_set(err, err_size,
		    "a liveness round needs an observation and the run directory the daemons "
		    "were started under");
		return 0;
	}
	for (i = 0; i < observed->backend_count; i++) {
		ncfg_observed_backend_t *backend = &observed->backends[i];
		int                      answerable = 0;

		/*
		 * Only what the record says is up. Asking about the rest would cost a
		 * `/proc` read per backend to learn something the record already
		 * says, and -- because this never sets `running` -- could not change
		 * the answer if it did.
		 */
		if (!backend->running || !backend->interface) {
			continue;
		}
		if (pid_of_backend(backend, run_dir, &answerable) > 0 || !answerable) {
			/* Still up as far as this pass can tell, which is the condition
			 * the metric record is an observation under. */
			note_started_metric(backend, run_dir);
			continue;
		}
		backend->running = 0;
		/*
		 * `answering` goes with it, and that is not tidying. 0078 keeps the
		 * two apart because a wedged daemon holds its pid and serves nobody --
		 * but the converse is not a question anyone can ask: a process that is
		 * gone is not answering, and leaving a stale `true` there would let a
		 * pass conclude that a dead hostapd is serving its LAN.
		 */
		backend->answering.has = 1;
		backend->answering.value = 0;
	}
	return 1;
}
