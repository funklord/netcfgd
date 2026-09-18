/*
 * openvpn.c -- a tunnel's lifecycle, and the script that reports what it
 * negotiated.
 *
 * See `openvpn.h` for why this module never reads the operator's `.ovpn`, what
 * the report script is for, and why nothing listening is not nothing running.
 */
#include "ncfg/openvpn.h"

#include "../backend_internal.h"
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/hooks.h"
#include "ncfg/log.h"
#include "ncfg/process.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* An operator's `.ovpn` with inline certificates. Generous, and a ceiling all
 * the same: this is a file netcfgd hashes and does not otherwise read. */
#define OVPN_CEILING (4u * 1024u * 1024u)

/* The generated script. Fixed text plus two paths, so this is a ceiling that
 * cannot be reached rather than a budget. */
#define SCRIPT_MAX (64u * 1024u)

/*
 * OpenVPN's own vocabulary for a start that failed.
 *
 * The same problem and the same answer as hostapd's: a daemon that fails
 * announces the reason and then narrates its shutdown, so the tail is the wrong
 * lines. `Options error:` is a configuration it will not take, and `Cannot` or
 * `Could not` is a file or a socket it cannot have.
 */
static const char *const OVPN_MARKERS[] = { "options error", "error:", "cannot", "could not",
	"fatal" };

int ncfg_openvpn_run_dir(const char *run, char *out, size_t out_size, char *err, size_t err_size)
{
	return ncfg_backend_join(out, out_size, run, "openvpn", err, err_size);
}

int ncfg_openvpn_socket_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "openvpn", iface, ".sock", err, err_size);
}

int ncfg_openvpn_log_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "openvpn", iface, ".log", err, err_size);
}

int ncfg_openvpn_pid_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "openvpn", iface, ".pid", err, err_size);
}

int ncfg_openvpn_auth_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "openvpn", iface, ".auth", err, err_size);
}

int ncfg_openvpn_script_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "openvpn", iface, ".report", err, err_size);
}

int ncfg_openvpn_config_hash_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "openvpn", iface, ".ovpn.sha256", err,
	    err_size);
}

char *ncfg_openvpn_binary(void)
{
	return ncfg_backend_find_program("openvpn");
}

int ncfg_openvpn_hash_of(const char *config, char *out, size_t out_size)
{
	char  *bytes;
	size_t length = 0;

	if (!out || out_size < NCFG_SHA256_HEX_SIZE) {
		return 0;
	}
	out[0] = '\0';
	/* **The only bytes of the operator's file this module ever looks at, and it
	 * does not interpret them.** 0046 keeps the `.ovpn` theirs; 0053 still needs
	 * an edit to be noticeable, and a digest is how a hook's body is watched
	 * without being read either. */
	bytes = ncfg_backend_read_file(config, &length, OVPN_CEILING);
	if (!bytes) {
		return 0;
	}
	ncfg_sha256_hex(bytes, length, out);
	free(bytes);
	return 1;
}

int ncfg_openvpn_record_started_from(const char *run, const char *iface, const char *config,
    char *err, size_t err_size)
{
	char hash[NCFG_SHA256_HEX_SIZE];
	char dir[NCFG_OPENVPN_PATH_MAX];
	char path[NCFG_OPENVPN_PATH_MAX];
	char said[NCFG_ERROR_MAX];

	if (!ncfg_openvpn_hash_of(config, hash, sizeof(hash))) {
		/* Nothing to hash is not a write failing. `ncfg_openvpn_hash_of`
		 * documents why "the operator's file is not there" and "it changed" are
		 * kept apart, and the caller's own check on the missing file speaks. */
		return 1;
	}
	if (!ncfg_openvpn_run_dir(run, dir, sizeof(dir), said, sizeof(said)) ||
	    !ncfg_backend_make_dir(dir, 0755, said, sizeof(said))) {
		ncfg_error_set(err, err_size,
		    "cannot record what %s was started from: %s; an edited config will not be "
		    "noticed",
		    iface, said);
		return 0;
	}
	if (!ncfg_openvpn_config_hash_path(run, iface, path, sizeof(path), said, sizeof(said)) ||
	    !ncfg_backend_write_file(path, hash, strlen(hash), 0644, said, sizeof(said))) {
		ncfg_error_set(err, err_size,
		    "cannot record what %s was started from: %s; an edited config will not be "
		    "noticed",
		    iface, said);
		return 0;
	}
	return 1;
}

/*
 * The one piece of arithmetic: `255.255.255.0` becomes `24`.
 *
 * openvpn hands IPv4 netmasks dotted and IPv6 prefixes already in CIDR, which
 * is its asymmetry rather than netcfgd's. **A mask with a hole in it fails**
 * rather than summing to a number that means something else -- the kernel would
 * refuse such a route anyway, and skipping it here leaves the line it came from
 * visible in the log.
 */
static void mask_conversion(ncfg_buf_t *buf)
{
	ncfg_buf_add_text(buf,
	    "prefix_of() {\n"
	    "\ttotal=0\n"
	    "\tended=\n"
	    "\tfor octet in $(printf '%s' \"$1\" | tr '.' ' '); do\n"
	    "\t\tcase \"$octet\" in\n"
	    "\t\t255) bits=8 ;;\n"
	    "\t\t254) bits=7 ;;\n"
	    "\t\t252) bits=6 ;;\n"
	    "\t\t248) bits=5 ;;\n"
	    "\t\t240) bits=4 ;;\n"
	    "\t\t224) bits=3 ;;\n"
	    "\t\t192) bits=2 ;;\n"
	    "\t\t128) bits=1 ;;\n"
	    "\t\t0) bits=0 ;;\n"
	    "\t\t*) return 1 ;;\n"
	    "\t\tesac\n"
	    "\t\t[ -n \"$ended\" ] && [ \"$bits\" != 0 ] && return 1\n"
	    "\t\t[ \"$bits\" = 8 ] || ended=yes\n"
	    "\t\ttotal=$((total + bits))\n"
	    "\tdone\n"
	    "\tprintf '%s' \"$total\"\n"
	    "}\n");
}

/*
 * Both families of route, out of the environment openvpn filled in.
 *
 * **A fixed range rather than a break on the first gap**: `setenv_route` skips a
 * route it did not fully define and the counter moves on anyway, so the
 * numbering has holes in it.
 */
static void route_lines(ncfg_buf_t *buf)
{
	ncfg_buf_add_text(buf,
	    "\ti=1\n"
	    "\twhile [ \"$i\" -le 256 ]; do\n"
	    "\t\teval \"network=\\${route_network_$i:-}\"\n"
	    "\t\teval \"netmask=\\${route_netmask_$i:-}\"\n"
	    "\t\teval \"gateway=\\${route_gateway_$i:-}\"\n"
	    "\t\ti=$((i + 1))\n"
	    "\t\t[ -n \"$network\" ] || continue\n"
	    "\t\tprefix=$(prefix_of \"$netmask\") || continue\n"
	    "\t\tif [ -n \"$gateway\" ]; then\n"
	    "\t\t\tprintf 'route=%s/%s via %s\\n' \"$network\" \"$prefix\" \"$gateway\"\n"
	    "\t\telse\n"
	    "\t\t\tprintf 'route=%s/%s\\n' \"$network\" \"$prefix\"\n"
	    "\t\tfi\n"
	    "\tdone\n"
	    "\ti=1\n"
	    "\twhile [ \"$i\" -le 256 ]; do\n"
	    "\t\teval \"network=\\${route_ipv6_network_$i:-}\"\n"
	    "\t\teval \"gateway=\\${route_ipv6_gateway_$i:-}\"\n"
	    "\t\ti=$((i + 1))\n"
	    "\t\t[ -n \"$network\" ] || continue\n"
	    "\t\tif [ -n \"$gateway\" ]; then\n"
	    "\t\t\tprintf 'route=%s via %s\\n' \"$network\" \"$gateway\"\n"
	    "\t\telse\n"
	    "\t\t\tprintf 'route=%s\\n' \"$network\"\n"
	    "\t\tfi\n"
	    "\tdone\n");
}

/*
 * The nameservers, and the two things a server does not get to decide.
 *
 * openvpn folds both the old `dhcp-option DNS` and 2.6's `--dns server` into one
 * `foreign_option` list on anything that is not Windows, so reading one
 * spelling reads both.
 *
 * `DOMAIN` and `DOMAIN-SEARCH` are reported as **search suffixes** (0067): what
 * to append to a bare name travels under the same gate as a nameserver, while
 * *which names go through this tunnel* is a routing domain, is the operator's
 * to say in the document, and has no report key at all (0049).
 */
static void server_lines(ncfg_buf_t *buf)
{
	ncfg_buf_add_text(buf,
	    "\ti=1\n"
	    "\twhile [ \"$i\" -le 256 ]; do\n"
	    "\t\teval \"option=\\${foreign_option_$i:-}\"\n"
	    "\t\ti=$((i + 1))\n"
	    "\t\t[ -n \"$option\" ] || continue\n"
	    "\t\tset -- $option\n"
	    "\t\t[ \"${1:-}\" = dhcp-option ] || continue\n"
	    "\t\tcase \"${2:-}\" in\n"
	    "\t\tDNS|DNS6) [ -n \"${3:-}\" ] && printf 'dns=%s\\n' \"$3\" ;;\n"
	    "\t\tDOMAIN|DOMAIN-SEARCH)\n"
	    "\t\t\tshift 2\n"
	    "\t\t\tfor suffix in \"$@\"; do\n"
	    "\t\t\t\t[ -n \"$suffix\" ] && printf 'search=%s\\n' \"$suffix\"\n"
	    "\t\t\tdone\n"
	    "\t\t\t;;\n"
	    "\t\t*) printf '# the server also said: %s\\n' \"$option\" ;;\n"
	    "\t\tesac\n"
	    "\tdone\n");
}

char *ncfg_openvpn_report_script(const char *iface, const char *report, char *err,
    size_t err_size)
{
	ncfg_buf_t buf;
	char      *out;

	if (!iface || !report) {
		ncfg_error_set(err, err_size, "a report script was rendered with no interface or no "
		                  "report");
		return NULL;
	}
	ncfg_buf_init(&buf, SCRIPT_MAX);
	ncfg_buf_addf(&buf,
	    "#!/bin/sh\n"
	    "# Written by netcfgd for %s. Do not edit; it is rewritten on every\n"
	    "# start, and openvpn is the only thing that runs it.\n"
	    "#\n"
	    "# Called twice over a tunnel's life: as --route-up once the routes\n"
	    "# openvpn was told not to install are known, and as --down when the\n"
	    "# tunnel goes. doc/interface-report.md is the format.\n"
	    "set -u\n"
	    "\n"
	    "target='%s'\n",
	    iface, report);
	/* **A dotted name, not `.tmp`.** netcfgd skips a staging file by the
	 * contract's rule -- a leading dot -- which `<iface>.tmp` does not satisfy,
	 * so a half-written report was read as an interface of its own: `ncfg
	 * status` listed `vpn0.tmp` carrying the address and nameservers being
	 * written. That is 0113's defect again, and the window here is the widest of
	 * the three writers -- the block below forks once per pushed route, which is
	 * exactly the netlink burst that wakes a reconcile. */
	ncfg_buf_add_text(&buf,
	    "dir=$(dirname \"$target\")\n"
	    "tmp=\"$dir/.$(basename \"$target\")\"\n"
	    "mkdir -p \"$dir\" || exit 1\n"
	    "\n");
	/* The tunnel is gone, so the routes are. **Emptied rather than removed**:
	 * the contract makes an empty report mean "nothing, deliberately" and a
	 * missing one mean "nobody is watching", and openvpn running its down script
	 * is somebody watching. */
	ncfg_buf_add_text(&buf,
	    "if [ \"${script_type:-}\" = down ]; then\n"
	    "\t: > \"$tmp\" && mv \"$tmp\" \"$target\"\n"
	    "\texit 0\n"
	    "fi\n"
	    "\n");
	mask_conversion(&buf);
	ncfg_buf_add_text(&buf, "\n{\n");
	ncfg_buf_addf(&buf,
	    "\tprintf '# %%s, written by netcfgd from openvpn --route-up\\n' '%s'\n", iface);
	route_lines(&buf);
	server_lines(&buf);
	ncfg_buf_add_text(&buf, "} > \"$tmp\" || exit 1\nmv \"$tmp\" \"$target\"\n");

	if (ncfg_buf_failed(&buf)) {
		ncfg_error_set(err, err_size, "the report script for %s is larger than this build will "
		                  "render",
		    iface);
		ncfg_buf_free(&buf);
		return NULL;
	}
	out = ncfg_buf_take(&buf, NULL);
	if (!out) {
		ncfg_error_set(err, err_size, "out of memory rendering the report script for %s", iface);
	}
	ncfg_buf_free(&buf);
	return out;
}

/* Write the reporting script, executable, next to the tunnel's other state.
 *
 * Rewritten on every start rather than written once: it carries the interface
 * name and the report path, and a tunnel renamed in the document would
 * otherwise keep reporting under the old name. */
static int write_script(const char *run, const char *iface, const char *report, char *path,
    size_t path_size, char *err, size_t err_size)
{
	char *text;
	int   ok;

	if (!ncfg_openvpn_script_path(run, iface, path, path_size, err, err_size)) {
		return 0;
	}
	text = ncfg_openvpn_report_script(iface, report, err, err_size);
	if (!text) {
		return 0;
	}
	ok = ncfg_backend_write_file(path, text, strlen(text), 0755, err, err_size);
	free(text);
	return ok;
}

/* Write the credentials file, which is the only way `--auth-user-pass` takes
 * one. */
static int write_auth(const char *run, const char *iface, const char *username,
    const char *password, char *path, size_t path_size, char *err, size_t err_size)
{
	ncfg_buf_t buf;
	int        ok;

	if (!ncfg_openvpn_auth_path(run, iface, path, path_size, err, err_size)) {
		return 0;
	}
	/* **Exactly two lines, which is what `--auth-user-pass` reads.** A username
	 * containing a newline would become a password line; nothing in the model
	 * stops one, so it is stopped here. */
	if (strchr(username, '\n') != NULL || strchr(password, '\n') != NULL) {
		ncfg_error_set(err, err_size,
		    "the openvpn credentials for %s contain a newline, which would be read as a "
		    "different field",
		    iface);
		return 0;
	}
	ncfg_buf_init(&buf, SCRIPT_MAX);
	ncfg_buf_addf(&buf, "%s\n%s\n", username, password);
	if (ncfg_buf_failed(&buf)) {
		ncfg_buf_free(&buf);
		ncfg_error_set(err, err_size, "the openvpn credentials for %s are larger than this "
		                  "build will write",
		    iface);
		return 0;
	}
	/* 0600, set on the open handle before a byte goes in -- a chmod after the
	 * write leaves a window in which the password is world-readable, and a mode
	 * that was wrong once is a mode that was wrong. */
	ok = ncfg_backend_write_file(path, ncfg_buf_text(&buf), strlen(ncfg_buf_text(&buf)), 0600,
	    err, err_size);
	/* The password is in this buffer; wiped before it is released. */
	if (buf.data) {
		memset(buf.data, 0, buf.capacity);
	}
	ncfg_buf_free(&buf);
	return ok;
}

int ncfg_openvpn_start(const char *run, const char *iface, const char *config,
    const char *username, const char *password, const char *report, const char *program,
    char *err, size_t err_size)
{
	char        dir[NCFG_OPENVPN_PATH_MAX];
	char        socket_path[NCFG_OPENVPN_PATH_MAX];
	char        log[NCFG_OPENVPN_PATH_MAX];
	char        pid[NCFG_OPENVPN_PATH_MAX];
	char        script[NCFG_OPENVPN_PATH_MAX];
	char        auth[NCFG_OPENVPN_PATH_MAX];
	char        name[128];
	char        said[NCFG_ERROR_MAX];
	char       *found = NULL;
	const char *argv[26];
	size_t      at = 0;
	int         exited_ok = 0;
	int         status = 0;

	if (!iface || !config || !report) {
		ncfg_error_set(err, err_size, "a tunnel was started without an interface, a config or "
		                  "a report");
		return 0;
	}
	if (!ncfg_openvpn_run_dir(run, dir, sizeof(dir), err, err_size) ||
	    !ncfg_backend_make_dir(dir, 0755, err, err_size)) {
		return 0;
	}
	/* **Checked here rather than left to openvpn, only because the error is so
	 * much better**: netcfgd knows the path came from a document and can say so,
	 * where openvpn says "Options error" against a file the operator may not
	 * realise netcfgd chose. It is an existence check and nothing more -- the
	 * file's contents are the operator's (0046). */
	if (access(config, F_OK) != 0) {
		ncfg_error_set(err, err_size,
		    "the openvpn configuration for %s is `%s`, and there is no file there", iface,
		    config);
		return 0;
	}
	if (!ncfg_openvpn_socket_path(run, iface, socket_path, sizeof(socket_path), err, err_size) ||
	    !ncfg_openvpn_log_path(run, iface, log, sizeof(log), err, err_size) ||
	    !ncfg_openvpn_pid_path(run, iface, pid, sizeof(pid), err, err_size)) {
		return 0;
	}
	if (!program) {
		found = ncfg_openvpn_binary();
		if (!found) {
			ncfg_error_set(err, err_size,
			    "no openvpn found for %s; a tunnel needs the openvpn package", iface);
			return 0;
		}
		program = found;
	}

	/* A socket left by a daemon that died takes the bind, and openvpn does not
	 * clear it. Removing it here is safe because `stop` has already been asked
	 * of anything netcfgd started. */
	(void)unlink(socket_path);
	/* Whatever the last tunnel negotiated is not what this one will. Removed
	 * before the daemon starts rather than after it connects, because between
	 * those two moments netcfgd would otherwise be installing the previous
	 * tunnel's routes down the new one. */
	(void)unlink(report);

	if (!write_script(run, iface, report, script, sizeof(script), err, err_size)) {
		free(found);
		return 0;
	}
	if (username && password) {
		if (!write_auth(run, iface, username, password, auth, sizeof(auth), err, err_size)) {
			free(found);
			return 0;
		}
	} else {
		/* No credentials in the document. Left to the `.ovpn`, which for a file
		 * with inline certificates authenticates without any -- and removed if
		 * an earlier configuration had some, so a password does not outlive the
		 * document that asked for it. */
		auth[0] = '\0';
		if (ncfg_openvpn_auth_path(run, iface, auth, sizeof(auth), NULL, 0)) {
			(void)unlink(auth);
		}
		auth[0] = '\0';
	}

	(void)snprintf(name, sizeof(name), "netcfgd-%s", iface);
	argv[at++] = program;
	argv[at++] = "--config";
	argv[at++] = config;
	/* The interface name is netcfgd's to choose, not the file's: the document
	 * says `interface vpn0`, and a `.ovpn` that named something else would
	 * produce a tunnel no plan could find. */
	argv[at++] = "--dev";
	argv[at++] = iface;
	argv[at++] = "--management";
	argv[at++] = socket_path;
	argv[at++] = "unix";
	/* So the apply does not block. A tunnel can take seconds to negotiate, and
	 * the interface arriving later is already how a PPPoE session behaves -- the
	 * planner gets there on the next reconcile. */
	argv[at++] = "--daemon";
	argv[at++] = name;
	/* So there is a handle when the management socket is not answering -- which
	 * is every moment between the fork this returns from and the bind its child
	 * gets round to (0074). */
	argv[at++] = "--writepid";
	argv[at++] = pid;
	argv[at++] = "--log";
	argv[at++] = log;
	/* The routes are netcfgd's, which is the half of a tunnel 0047 says is worth
	 * taking: a daemon installing its own default route walks into the middle of
	 * netcfgd's uplink arbitration with a metric netcfgd did not choose, and
	 * neither side knows the other is there. */
	argv[at++] = "--route-noexec";
	/* **Without this openvpn runs no script at all and says so once, at verb 1,
	 * in a log nobody reads** -- the routes would simply never be reported and
	 * nothing would fail. It is the default in 2.6, checked in `run_command.c`:
	 * `script_security_level` starts at `SSEC_BUILT_IN`. */
	argv[at++] = "--script-security";
	argv[at++] = "2";
	argv[at++] = "--route-up";
	argv[at++] = script;
	/* The same script, told apart by `script_type`. `--down` rather than
	 * `--route-pre-down`, which openvpn only runs when a route list exists -- a
	 * tunnel that pushed nothing would then leave its report behind. */
	argv[at++] = "--down";
	argv[at++] = script;
	if (auth[0] != '\0') {
		/* **The path, never the values.** A password on a command line is
		 * readable by every process on the machine through `/proc`. */
		argv[at++] = "--auth-user-pass";
		argv[at++] = auth;
	}
	argv[at] = NULL;

	if (!ncfg_backend_run(program, argv, log, &exited_ok, &status, err, err_size)) {
		free(found);
		return 0;
	}
	free(found);

	if (exited_ok) {
		/* What the tunnel was started from, so that an edited `.ovpn` is
		 * something the next reconcile can notice. Written after the daemon took
		 * it, because a hash of a file openvpn refused is a record of nothing.
		 *
		 * **Reported and not returned**: the tunnel is up, and a record that
		 * could not be kept must not turn a working start into a failure. What
		 * it costs is named all the same (0180). */
		said[0] = '\0';
		if (!ncfg_openvpn_record_started_from(run, iface, config, said, sizeof(said))) {
			ncfg_log_emitf("openvpn", NCFG_LOG_WARNING, "%s", said);
		}
		return 1;
	}

	if (ncfg_backend_complaints(log, OVPN_MARKERS,
	    sizeof(OVPN_MARKERS) / sizeof(OVPN_MARKERS[0]), NULL, 0u, 2u, said, sizeof(said))) {
		ncfg_error_set(err, err_size, "openvpn would not start on %s: %s. Its output is in %s",
		    iface, said, log);
	} else {
		ncfg_error_set(err, err_size,
		    "openvpn would not start on %s: it exited with status %d. Its output is in %s",
		    iface, status, log);
	}
	return 0;
}

pid_t ncfg_openvpn_running_pid(const char *run, const char *iface)
{
	char pid[NCFG_OPENVPN_PATH_MAX];
	char socket_path[NCFG_OPENVPN_PATH_MAX];

	if (!ncfg_openvpn_pid_path(run, iface, pid, sizeof(pid), NULL, 0) ||
	    !ncfg_openvpn_socket_path(run, iface, socket_path, sizeof(socket_path), NULL, 0)) {
		return 0;
	}
	/* Against **this interface's own socket path** rather than the interface
	 * name alone: `vpn0` is a short string that a wholly unrelated command line
	 * could contain, where the socket path is unique to this tunnel on this
	 * machine. */
	return ncfg_process_pid_of(pid, socket_path);
}

/*
 * Stop a daemon that is not answering its socket, by the pid it wrote.
 *
 * A pid file naming nothing, or naming something that is not this tunnel, is
 * removed and reported as stopped -- which is the state the caller asked for,
 * and is what "stopping one that is already stopped is not an error" means.
 */
static int stop_by_pid(const char *run, const char *iface, char *err, size_t err_size)
{
	char  pid_file[NCFG_OPENVPN_PATH_MAX];
	char  auth[NCFG_OPENVPN_PATH_MAX];
	pid_t pid = ncfg_openvpn_running_pid(run, iface);

	if (ncfg_openvpn_pid_path(run, iface, pid_file, sizeof(pid_file), NULL, 0) == 0) {
		pid_file[0] = '\0';
	}
	if (pid <= 0) {
		if (pid_file[0] != '\0') {
			(void)unlink(pid_file);
		}
		return 1;
	}
	if (!ncfg_process_terminate(pid, err, err_size)) {
		return 0;
	}
	if (pid_file[0] != '\0') {
		(void)unlink(pid_file);
	}
	if (ncfg_openvpn_auth_path(run, iface, auth, sizeof(auth), NULL, 0)) {
		(void)unlink(auth);
	}
	return 1;
}

int ncfg_openvpn_stop(const char *run, const char *iface, const char *report, char *err,
    size_t err_size)
{
	char                       socket_path[NCFG_OPENVPN_PATH_MAX];
	char                       hash[NCFG_OPENVPN_PATH_MAX];
	char                       pid[NCFG_OPENVPN_PATH_MAX];
	char                       auth[NCFG_OPENVPN_PATH_MAX];
	ncfg_openvpn_management_t *management;

	/* **Before the signal, and outside the "is anything listening" question.** A
	 * report is a claim that routes exist, and the tunnel they belong to is
	 * going either way -- a daemon that already died is exactly the case where
	 * nobody comes back to tidy up, which is the lesson a stopped access point's
	 * passphrase paid for.
	 *
	 * The daemon's own `--down` script may still write an empty report after
	 * this, because openvpn runs it when it gets round to exiting. That is a
	 * race with no wrong outcome: gone and empty both mean no routes, and the
	 * contract gives them both that meaning deliberately. */
	if (report) {
		(void)unlink(report);
	}
	/* And the record of which `.ovpn` this was started from, which describes a
	 * tunnel that is no longer running. */
	if (ncfg_openvpn_config_hash_path(run, iface, hash, sizeof(hash), NULL, 0)) {
		(void)unlink(hash);
	}
	/* The script itself stays: it is regenerated on every start, it does nothing
	 * unless openvpn runs it, and removing it here would pull it out from under
	 * the `--down` call that has not happened yet -- which openvpn would report
	 * as a failed script in a log an operator then has to explain. */

	if (!ncfg_openvpn_socket_path(run, iface, socket_path, sizeof(socket_path), err,
	    err_size)) {
		return 0;
	}
	management = ncfg_openvpn_connect(socket_path, NULL, 0);
	if (!management) {
		/* Nothing is listening, which used to end the matter -- and did so
		 * wrongly for a daemon that had forked and not yet bound (0074). */
		return stop_by_pid(run, iface, err, err_size);
	}
	if (!ncfg_openvpn_command(management, "signal SIGTERM", NULL, 0u, err, err_size)) {
		ncfg_openvpn_disconnect(management);
		return 0;
	}
	ncfg_openvpn_disconnect(management);

	if (ncfg_openvpn_pid_path(run, iface, pid, sizeof(pid), NULL, 0)) {
		(void)unlink(pid);
	}
	/* The daemon removes its own socket on the way out, but only if it got far
	 * enough to install the handler. Left behind, it would take the bind on the
	 * next start. */
	(void)unlink(socket_path);
	/* And the credentials, which have nothing left to authenticate. */
	if (ncfg_openvpn_auth_path(run, iface, auth, sizeof(auth), NULL, 0)) {
		(void)unlink(auth);
	}
	return 1;
}
