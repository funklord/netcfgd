/*
 * backend_adopt.c -- taking back a daemon netcfgd started and lost the record of.
 *
 * WHY THIS IS ONE FUNCTION FOR EVERY KIND
 *   It was five, and four of them did not exist. Each backend module answers
 *   "is one of mine already running?" by reading the pid file netcfgd wrote --
 *   which is the right first question and is useless in the case that actually
 *   happens: **`systemctl stop netcfgd` takes `/run/netcfgd` with it**
 *   (`RuntimeDirectoryPreserve=restart` keeps it across a restart and not
 *   across a stop) while `KillMode=process` leaves every daemon netcfgd
 *   started running. The pid file is gone and the process is not.
 *
 *   The supplicant had a recovery for that and nothing else did, so an access
 *   point, a router advertisement daemon, an OpenVPN tunnel or a PPPoE session
 *   found in that state was started *again* -- two on one radio, two on one
 *   line. The Rust generalised this for exactly that reason, and its own
 *   comment records what per-backend recovery cost: four kinds that could not
 *   be recovered at all, "which is what kept `KillMode=process` unshippable"
 *   (0142).
 *
 * THE THREE ANSWERS
 *   * **A pid file that still names a live process of ours**: it is running,
 *     and the caller must not start a second. This is the converged case and
 *     the one every pass takes.
 *   * **No usable pid file, and the daemon answers**: it is ours, by a marker
 *     it carries in its own `argv`, so the record is written again and the
 *     caller stops. That is 0140's recovery, generalised.
 *   * **No usable pid file, and it does not answer**: it is a corpse holding a
 *     radio. It is **stopped**, and the caller starts a fresh one -- because
 *     starting a second beside it is what drops the association, and leaving
 *     it is netcfgd holding a device it cannot drive.
 *
 * WHY A WEAK MARKER GETS NO ENTRY
 *   The marker has to be an absolute path netcfgd composed -- an options file,
 *   a management socket, a generated configuration, a pid file it named. The
 *   two DHCP clients get the interface name instead, which `dhcp.h` calls the
 *   weakest marker netcfgd uses: `eth0` is a short string an unrelated command
 *   line could contain, and scanning `/proc` for it would reach somebody
 *   else's process. They keep the two specific recoveries they already have.
 *
 * WHY STOPPING HERE IS NOT 0141'S CASE
 *   0141 is about not killing a daemon that may only be busy, and a false
 *   positive there kills somebody's healthy process -- so a person decides,
 *   with `--restart-wedged`. Here the marker is a path netcfgd chose and the
 *   process carries in its own `argv`, so "is this mine" is answered rather
 *   than guessed, and what is stopped is something netcfgd started, cannot
 *   talk to, and has no record of. A backend whose pid file still names a live
 *   process never reaches that branch, wedged or not.
 */
#include "ncfg/service.h"

#include "service_internal.h"

#include "ncfg/base.h"
#include "ncfg/hostapd.h"
#include "ncfg/log.h"
#include "ncfg/openvpn.h"
#include "ncfg/pppoe.h"
#include "ncfg/process.h"
#include "ncfg/ra.h"
#include "ncfg/supplicant.h"

#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* A run directory, a subdirectory and `<iface>.pid`, which is `backend_ops.c`'s
 * bound for the same paths. */
#define ADOPT_PATH_MAX 4352u

/*
 * Write a pid file, here rather than through `ncfg_backend_write_file`.
 *
 * That call is `src/backend/`'s own and says so in its header; reaching across
 * a boundary a module states is the thing `backend_internal.h` refuses. What
 * is written is two bytes and a newline, so what that call adds -- a mode set
 * on the open, a refusal that names the file -- is the part this repeats
 * rather than the part it borrows.
 */
static int write_pid(const char *path, pid_t pid, char *err, size_t err_size)
{
	char    text[32];
	char    parent[ADOPT_PATH_MAX];
	char   *cut;
	int     fd;
	ssize_t wrote;
	size_t  length;

	/*
	 * **The directory has to be made, and that is the whole reason this is
	 * not three lines.** The case adoption exists for is `/run/netcfgd` being
	 * taken away, and it takes `radvd/`, `openvpn/`, `supplicant/` and `ppp/`
	 * with it -- so the daemon is running, its mark is in `/proc`, and the
	 * place its pid file goes does not exist. Writing without this answered
	 * *could not be recorded* for every kind whose file lives in a
	 * subdirectory, which is all of them but one.
	 */
	(void)snprintf(parent, sizeof(parent), "%s", path);
	cut = strrchr(parent, '/');
	if (cut && cut != parent) {
		*cut = '\0';
		if (mkdir(parent, 0755) != 0 && errno != EEXIST) {
			ncfg_error_set(err, err_size, "cannot make %s: %s", parent, strerror(errno));
			return 0;
		}
	}
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		ncfg_error_set(err, err_size, "cannot write %s: %s", path, strerror(errno));
		return 0;
	}
	length = (size_t)snprintf(text, sizeof(text), "%d\n", (int)pid);
	wrote = write(fd, text, length);
	if (close(fd) != 0 || wrote < 0 || (size_t)wrote != length) {
		ncfg_error_set(err, err_size, "cannot write %s: %s", path, strerror(errno));
		return 0;
	}
	return 1;
}

int ncfg_service_backend_handle(const char *run, int kind, const char *iface, char *pid_path,
    size_t pid_size, char *marker, size_t marker_size)
{
	char scratch[NCFG_ERROR_MAX];

	if (!run || !iface || !pid_path || !marker) {
		return 0;
	}
	pid_path[0] = '\0';
	marker[0] = '\0';
	switch ((ncfg_backend_kind_t)kind) {
	case NCFG_BACKEND_SUPPLICANT:
		/* The pid file's own path is the marker, which is the strongest kind:
		 * netcfgd chose it, it names the interface, and `-P` puts it in the
		 * command line (0080). */
		return ncfg_supplicant_pid_path(run, iface, pid_path, pid_size, scratch,
		           sizeof(scratch)) &&
		    ncfg_supplicant_pid_path(run, iface, marker, marker_size, scratch,
		        sizeof(scratch));
	case NCFG_BACKEND_ACCESS_POINT:
		/* The same, and it was nothing at all until 0110 -- which made an
		 * access point the one backend netcfgd could never notice had died. */
		return ncfg_hostapd_pid_path(run, iface, pid_path, pid_size, scratch,
		           sizeof(scratch)) &&
		    ncfg_hostapd_pid_path(run, iface, marker, marker_size, scratch,
		        sizeof(scratch));
	case NCFG_BACKEND_ROUTER_ADVERT:
		/* radvd is started with `--config <path>`, so the generated file is
		 * what it recites. */
		return ncfg_ra_pid_path(run, iface, pid_path, pid_size, scratch, sizeof(scratch)) &&
		    ncfg_ra_config_path(run, iface, marker, marker_size, scratch, sizeof(scratch));
	case NCFG_BACKEND_OPENVPN:
		/* `--management <path> unix`, which is unique to this tunnel on this
		 * machine. */
		return ncfg_openvpn_pid_path(run, iface, pid_path, pid_size, scratch,
		           sizeof(scratch)) &&
		    ncfg_openvpn_socket_path(run, iface, marker, marker_size, scratch,
		        sizeof(scratch));
	case NCFG_BACKEND_PPPOE:
		/*
		 * pppd carries netcfgd's options file as `file <path>` for as long as
		 * the session lives, which is 0140's shape exactly. **The pid file is
		 * netcfgd's own record rather than pppd's**: pppd daemonises, so the
		 * pid netcfgd could observe at exec time is not the one that
		 * survives, and the marker scan is what fills this in.
		 */
		return ncfg_pppoe_options_path(run, iface, marker, marker_size, scratch,
		           sizeof(scratch)) &&
		    (size_t)snprintf(pid_path, pid_size, "%s/ppp/%s.pid", run, iface) < pid_size;
	case NCFG_BACKEND_DHCP4:
	case NCFG_BACKEND_DHCP6:
	case NCFG_BACKEND_WIREGUARD:
	case NCFG_BACKEND_DNS:
		/* No handle, which is not the same as "not running" and must not be
		 * read as one. The clients' marker is an interface name -- `dhcp.h`
		 * calls it the weakest netcfgd uses -- and the other two are not
		 * daemons at all. */
		return 0;
	}
	return 0;
}

/* Whether a backend of this kind on this interface still answers.
 *
 * Only two kinds can be asked, and the rest answer yes: a radvd or a pppd has
 * no control socket, so "does it answer" is a question with no way to put it
 * -- and answering no would stop a daemon on no evidence. */
static int answers(const ncfg_service_t *service, int kind, const char *iface)
{
	if (kind == NCFG_BACKEND_SUPPLICANT) {
		return service->supplicant_dir &&
		    ncfg_supplicant_answers(service->supplicant_dir, iface);
	}
	if (kind == NCFG_BACKEND_OPENVPN) {
		char                       socket_path[NCFG_OPENVPN_PATH_MAX];
		char                       scratch[NCFG_ERROR_MAX];
		ncfg_openvpn_management_t *management;

		if (!ncfg_openvpn_socket_path(service->run_dir, iface, socket_path,
		        sizeof(socket_path), scratch, sizeof(scratch))) {
			return 1;
		}
		/* Connect and drop it. No command is sent: the connect is the whole
		 * question, and asking one would cost a round trip in an apply for an
		 * answer this does not read. */
		management = ncfg_openvpn_connect(socket_path, scratch, sizeof(scratch));
		if (!management) {
			return 0;
		}
		ncfg_openvpn_disconnect(management);
		return 1;
	}
	return 1;
}

int ncfg_service_backend_adopt(const ncfg_service_t *service, int kind, const char *iface,
    int *adopted, char *err, size_t err_size)
{
	char  pid_path[ADOPT_PATH_MAX];
	char  marker[ADOPT_PATH_MAX];
	char  scratch[NCFG_ERROR_MAX];
	pid_t pid;

	if (adopted) {
		*adopted = 0;
	}
	if (!service || !service->run_dir || !iface || !adopted) {
		ncfg_error_set(err, err_size,
		    "an adoption needs a service context, an interface and somewhere to put the "
		    "answer");
		return 0;
	}
	if (!ncfg_service_backend_handle(service->run_dir, kind, iface, pid_path,
	        sizeof(pid_path), marker, sizeof(marker))) {
		/* No handle on this kind. Not an error: the caller starts one, which
		 * is what it would have done before this existed. */
		return 1;
	}
	/*
	 * **A pid file that still names a live process means it is already
	 * running**, and starting it again is the thing this exists to prevent.
	 * The Rust records falling through here starting a second daemon beside a
	 * first netcfgd had just recorded.
	 */
	if (ncfg_process_pid_of(pid_path, marker) > 0) {
		*adopted = 1;
		return 1;
	}
	pid = ncfg_process_pid_by_marker(marker);
	if (pid <= 0) {
		/* Nothing of netcfgd's is running under that mark, which is the
		 * ordinary first start. */
		return 1;
	}
	if (answers(service, kind, iface)) {
		if (!write_pid(pid_path, pid, scratch, sizeof(scratch))) {
			/* Running and netcfgd cannot write down which one: the next pass
			 * would adopt again, and go on adopting for ever. */
			ncfg_error_set(err, err_size,
			    "the %s backend on %s is netcfgd's and running, and its pid could not "
			    "be recorded (%s), so the next pass would adopt it again",
			    ncfg_backend_kind_name(kind), iface, scratch);
			return 0;
		}
		ncfg_log_emitf("backend", NCFG_LOG_INFO,
		    "adopted the %s backend already running on %s (pid %d); it is netcfgd's, by "
		    "the `%s` it was started with and the privilege it runs with",
		    ncfg_backend_kind_name(kind), iface, (int)pid, marker);
		*adopted = 1;
		return 1;
	}
	/*
	 * **An unreachable orphan of netcfgd's own is stopped, not stepped
	 * around.** Neither adopted, nor refused, nor left: the Rust measured that
	 * third state producing one extra supplicant per stop/start cycle, two
	 * deauthenticating each other until the association was lost.
	 *
	 * The namespace check is 0167's: a container's daemons are visible in
	 * `/proc` and are somebody else's, and this fails closed -- an unreadable
	 * link means "not ours to signal".
	 */
	if (!ncfg_process_shares_network_namespace(pid)) {
		ncfg_log_emitf("backend", NCFG_LOG_NOTE,
		    "the %s backend on %s (pid %d) carries netcfgd's mark and is in another "
		    "network namespace, so it is somebody else's to stop",
		    ncfg_backend_kind_name(kind), iface, (int)pid);
		return 1;
	}
	ncfg_log_emitf("backend", NCFG_LOG_NOTE,
	    "stopping the %s backend orphaned on %s (pid %d); it is netcfgd's by the `%s` in "
	    "its own argv, it does not answer its control socket, and starting a second "
	    "beside it would drop the association",
	    ncfg_backend_kind_name(kind), iface, (int)pid, marker);
	if (!ncfg_process_terminate(pid, scratch, sizeof(scratch))) {
		ncfg_log_emitf("backend", NCFG_LOG_ERROR,
		    "could not stop the orphaned %s backend on %s (pid %d): %s",
		    ncfg_backend_kind_name(kind), iface, (int)pid, scratch);
	}
	return 1;
}
