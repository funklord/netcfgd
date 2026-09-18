/*
 * hostapd.c -- the files an access point is made of, and starting the daemon
 * that reads them.
 *
 * See `hostapd.h` for why the configuration is a file rather than a socket, for
 * what the credential's presence in it costs, and for which half of the control
 * socket this build does not carry yet.
 */
#include "ncfg/hostapd.h"

#include "../backend_internal.h"
#include "ncfg/base.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * hostapd's own vocabulary for a start that failed.
 *
 * **The tail is the wrong answer**, which is what running this against a real
 * hostapd showed: it announces the problem and then narrates its shutdown, so
 * the last three lines of a failed start are `AP-DISABLED`,
 * `CTRL-EVENT-TERMINATING` and `Interface ap0 wasn't started` -- all true, none
 * of them the reason, and the operator is sent to look at the interface when
 * the answer was "this driver is not a wireless driver" four lines earlier.
 *
 * So the diagnosis is picked out by what it looks like instead. The two
 * failures that matter both announce themselves in the first line that matches:
 * a configuration hostapd will not parse says `Line 6: ...`, and a driver it
 * cannot attach to says `nl80211 driver initialization failed`.
 */
static const char *const AP_MARKERS[] = { "fail", "error", "not support", "cannot", "could not",
	"invalid" };
static const char *const AP_PREFIXES[] = { "Line " };

/* A station list a netcfgd wrote. A ceiling because it is read back off disk;
 * generous because an access point's deny list is an operator's to grow. */
#define ACL_CEILING (1024u * 1024u)

int ncfg_hostapd_ctrl_dir(const char *run, char *out, size_t out_size, char *err, size_t err_size)
{
	return ncfg_backend_join(out, out_size, run, "hostapd", err, err_size);
}

int ncfg_hostapd_config_path(const char *run, const char *device, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "hostapd", device, ".conf", err, err_size);
}

int ncfg_hostapd_acl_path(const char *run, const char *device, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "hostapd", device, ".acl", err, err_size);
}

int ncfg_hostapd_log_path(const char *run, const char *device, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "hostapd", device, ".log", err, err_size);
}

int ncfg_hostapd_pid_path(const char *run, const char *device, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "hostapd", device, ".pid", err, err_size);
}

char *ncfg_hostapd_binary(void)
{
	return ncfg_backend_find_program("hostapd");
}

int ncfg_hostapd_write_acl(const char *run, const ncfg_access_point_t *access_point, char *err,
    size_t err_size)
{
	char  path[NCFG_HOSTAPD_PATH_MAX];
	char *text;
	int   ok;

	if (!access_point) {
		ncfg_error_set(err, err_size, "a station list was written with no access point");
		return 0;
	}
	if (!ncfg_hostapd_acl_path(run, access_point->device, path, sizeof(path), err, err_size)) {
		return 0;
	}
	if (!access_point->access_control) {
		/* A block that was there and is not any more. **Leaving the file would
		 * leave a list that nothing reads**, which is worse than no file: the
		 * next person to look would find an ACL and believe it. */
		if (unlink(path) != 0 && errno != ENOENT) {
			ncfg_error_set(err, err_size, "cannot remove %s: %s", path, strerror(errno));
			return 0;
		}
		return 1;
	}
	text = ncfg_hostapd_acl_contents(access_point->access_control, err, err_size);
	if (!text) {
		return 0;
	}
	/* 0644 rather than the configuration's 0600: this holds no secret, and a
	 * list of MAC addresses only root can read is a list nobody debugging an
	 * access point can read either. The mode is set at the open rather than
	 * left to the umask, so the sentence above is a fact about the file and not
	 * about whoever started the daemon. */
	ok = ncfg_backend_write_file(path, text, strlen(text), 0644, err, err_size);
	free(text);
	return ok;
}

int ncfg_hostapd_write_config(const char *run, const ncfg_access_point_t *access_point,
    const ncfg_secret_resolver_t *resolver, char *path_out, size_t path_size, char *err,
    size_t err_size)
{
	char                 dir[NCFG_HOSTAPD_PATH_MAX];
	char                 path[NCFG_HOSTAPD_PATH_MAX];
	ncfg_hostapd_lines_t lines;
	ncfg_secret_t       *passphrase = NULL;
	char                *text;
	char                 said[NCFG_ERROR_MAX];
	int                  ok;

	if (path_out && path_size > 0u) {
		path_out[0] = '\0';
	}
	if (!access_point) {
		ncfg_error_set(err, err_size, "a configuration was written with no access point");
		return 0;
	}
	if (!ncfg_hostapd_ctrl_dir(run, dir, sizeof(dir), err, err_size) ||
	    !ncfg_backend_make_dir(dir, 0755, err, err_size) ||
	    !ncfg_hostapd_config_path(run, access_point->device, path, sizeof(path), err,
	    err_size)) {
		return 0;
	}

	if (access_point->security.kind == NCFG_SECURITY_PSK) {
		said[0] = '\0';
		passphrase = ncfg_secret_resolve(resolver, &access_point->security.psk.passphrase,
		    NULL, said, sizeof(said));
		if (!passphrase) {
			/* The resolver's sentence discloses nothing, which is the property
			 * `secrets.h` exists for; the block's id is added because a machine
			 * with four access points needs to know which one. */
			ncfg_error_set(err, err_size, "`%s`: %s",
			    access_point->id ? access_point->id : "", said);
			return 0;
		}
	}

	said[0] = '\0';
	ok = ncfg_hostapd_config(access_point, dir, passphrase ? ncfg_secret_expose(passphrase)
	                              : NULL,
	    &lines, NULL, said, sizeof(said));
	if (!ok) {
		ncfg_secret_free(passphrase);
		ncfg_error_set(err, err_size, "`%s`: %s", access_point->id ? access_point->id : "",
		    said);
		return 0;
	}

	/* **Before the configuration that names it.** hostapd refuses to start when
	 * `deny_mac_file` points at nothing, so a run where this failed silently
	 * would take the access point down rather than leave the list unenforced.
	 * Written even for an empty list, for the same reason: an empty file is the
	 * statement "nobody is denied", and a missing one is a failure. */
	if (!ncfg_hostapd_write_acl(run, access_point, err, err_size)) {
		ncfg_hostapd_lines_free(&lines);
		ncfg_secret_free(passphrase);
		return 0;
	}

	text = ncfg_hostapd_to_file(access_point->id, &lines, err, err_size);
	ncfg_hostapd_lines_free(&lines);
	ncfg_secret_free(passphrase);
	if (!text) {
		return 0;
	}
	/* 0600, and `ncfg_backend_write_file` corrects the mode on the handle before
	 * a byte goes in -- see its comment for the measurement behind that. */
	ok = ncfg_backend_write_file(path, text, strlen(text), 0600, err, err_size);
	/* The passphrase is in this buffer. Wiped before it is released rather than
	 * left in a freed allocation for whatever reuses the page. */
	memset(text, 0, strlen(text));
	free(text);
	if (!ok) {
		return 0;
	}
	if (path_out && path_size > 0u) {
		(void)snprintf(path_out, path_size, "%s", path);
	}
	return 1;
}

void ncfg_hostapd_recorded_policy(const char *run, const char *device, ncfg_observed_policy_t *out)
{
	char  path[NCFG_HOSTAPD_PATH_MAX];
	char *text;
	int   policy = 0;

	if (!out) {
		return;
	}
	memset(out, 0, sizeof(*out));
	out->kind = NCFG_OBSERVED_POLICY_UNKNOWN;
	if (!ncfg_hostapd_acl_path(run, device, path, sizeof(path), NULL, 0)) {
		return;
	}
	text = ncfg_backend_read_file(path, NULL, ACL_CEILING);
	if (!text) {
		/* **Absent and unreadable are opposite answers.** The write removes the
		 * file when the document carries no `access_control` block, so absence
		 * says hostapd was started without one and has no `macaddr_acl` at all.
		 * A file netcfgd cannot open says nothing about what hostapd read out
		 * of it, and reporting `UNSET` there would have the planner restart an
		 * access point over a permissions problem. */
		out->kind = errno == ENOENT ? NCFG_OBSERVED_POLICY_UNSET
		                : NCFG_OBSERVED_POLICY_UNKNOWN;
		return;
	}
	if (ncfg_hostapd_policy_in(text, &policy)) {
		out->kind = NCFG_OBSERVED_POLICY_SET;
		out->policy = policy;
	}
	free(text);
}

size_t ncfg_hostapd_start_args(const char *program, const char *pid_path, const char *config_path,
    const char **out, size_t out_size)
{
	if (!out || out_size < 5u) {
		return 0;
	}
	out[0] = program;
	out[1] = "-B";
	out[2] = "-P";
	out[3] = pid_path;
	out[4] = config_path;
	if (out_size > 5u) {
		out[5] = NULL;
	}
	return 5u;
}

int ncfg_hostapd_start(const char *run, const ncfg_access_point_t *access_point,
    const ncfg_secret_resolver_t *resolver, const char *program, char *err, size_t err_size)
{
	char        config[NCFG_HOSTAPD_PATH_MAX];
	char        pid[NCFG_HOSTAPD_PATH_MAX];
	char        log[NCFG_HOSTAPD_PATH_MAX];
	char        said[NCFG_ERROR_MAX];
	char       *found = NULL;
	const char *argv[8];
	int         exited_ok = 0;
	int         status = 0;

	if (!access_point) {
		ncfg_error_set(err, err_size, "an access point was started with no access point");
		return 0;
	}
	if (!ncfg_hostapd_write_config(run, access_point, resolver, config, sizeof(config), err,
	    err_size)) {
		return 0;
	}
	if (!ncfg_hostapd_pid_path(run, access_point->device, pid, sizeof(pid), err, err_size) ||
	    !ncfg_hostapd_log_path(run, access_point->device, log, sizeof(log), err, err_size)) {
		return 0;
	}
	if (!program) {
		found = ncfg_hostapd_binary();
		if (!found) {
			ncfg_error_set(err, err_size,
			    "no hostapd found for %s; an access point needs the hostapd package. "
			    "netcfgd does not implement one itself (doc/decision/0026)",
			    access_point->device ? access_point->device : "");
			return 0;
		}
		program = found;
	}
	if (ncfg_hostapd_start_args(program, pid, config, argv,
	    sizeof(argv) / sizeof(argv[0])) == 0u) {
		free(found);
		ncfg_error_set(err, err_size, "the hostapd argument list would not fit");
		return 0;
	}

	/* Startup diagnostics go to a file rather than a pipe. hostapd daemonizes on
	 * success and closes its standard streams when it does, so a pipe would be
	 * fine -- but a file is fine either way, and it leaves the reason an access
	 * point failed somewhere the operator can read it after the fact rather than
	 * only in whatever captured netcfgd's stderr. */
	if (!ncfg_backend_run(program, argv, log, &exited_ok, &status, err, err_size)) {
		free(found);
		return 0;
	}
	free(found);
	if (!exited_ok) {
		/* hostapd exits nonzero for a configuration it will not parse *and* for
		 * a driver it cannot initialise -- it daemonizes only after the
		 * interface is up, which is what makes this check worth making at all. */
		if (ncfg_backend_complaints(log, AP_MARKERS, sizeof(AP_MARKERS) / sizeof(AP_MARKERS[0]),
		    AP_PREFIXES, sizeof(AP_PREFIXES) / sizeof(AP_PREFIXES[0]), 2u, said,
		    sizeof(said))) {
			ncfg_error_set(err, err_size, "hostapd would not start on %s: %s. Its output is "
			                  "in %s",
			    access_point->device ? access_point->device : "", said, log);
		} else {
			ncfg_error_set(err, err_size,
			    "hostapd would not start on %s: it exited with status %d. Its output is "
			    "in %s",
			    access_point->device ? access_point->device : "", status, log);
		}
		return 0;
	}
	return 1;
}
