/*
 * ra.c -- radvd's configuration, and the lifecycle of the daemon that reads it.
 *
 * See `ra.h` for why netcfgd does not send an advertisement itself, why an
 * unimplemented backend is refused by name, and why reload is a signal rather
 * than a restart. What is here is the rendering and the four calls around it.
 */
#include "ncfg/ra.h"

#include "../backend_internal.h"
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/process.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * A generated radvd configuration. Bounded, like everything built in this
 * port: the prefix list comes from a delegation a lease supplied, so its
 * length is not netcfgd's to assume.
 */
#define RA_CONFIG_MAX (256u * 1024u)

/* radvd's own vocabulary for a start that failed. Its `--configtest` and its
 * startup both announce the reason and then narrate the shutdown, so the tail
 * is the wrong lines. */
static const char *const RA_MARKERS[] = { "error", "syntax", "cannot", "could not", "fatal",
	"exiting" };

int ncfg_ra_run_dir(const char *run, char *out, size_t out_size, char *err, size_t err_size)
{
	return ncfg_backend_join(out, out_size, run, "radvd", err, err_size);
}

int ncfg_ra_config_path(const char *run, const char *iface, char *out, size_t out_size, char *err,
    size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "radvd", iface, ".conf", err, err_size);
}

int ncfg_ra_pid_path(const char *run, const char *iface, char *out, size_t out_size, char *err,
    size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "radvd", iface, ".pid", err, err_size);
}

int ncfg_ra_log_path(const char *run, const char *iface, char *out, size_t out_size, char *err,
    size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "radvd", iface, ".log", err, err_size);
}

static const char *on_off(int value)
{
	return value ? "on" : "off";
}

char *ncfg_ra_render(const char *iface, const ncfg_ra_policy_t *policy,
    const char *const *prefixes, size_t prefix_count, const char *const *servers,
    size_t server_count, char *err, size_t err_size)
{
	ncfg_buf_t buf;
	size_t     at;
	char      *out;

	if (!iface || !policy) {
		ncfg_error_set(err, err_size, "an advertisement was rendered with no interface");
		return NULL;
	}
	ncfg_buf_init(&buf, RA_CONFIG_MAX);
	ncfg_buf_addf(&buf,
	    "# Written by netcfgd for %s. Do not edit; it is rewritten on apply.\n"
	    "interface %s\n"
	    "{\n"
	    "\tAdvSendAdvert on;\n"
	    "\tAdvManagedFlag %s;\n"
	    "\tAdvOtherConfigFlag %s;\n",
	    iface, iface, on_off(policy->managed), on_off(policy->other_config));
	if (policy->lifetime.has) {
		/* The router's own lifetime as a default gateway. **Zero is meaningful
		 * and is how a host is told this router is not one**, so it is passed
		 * through rather than treated as "unset" -- which is the whole reason
		 * the model has an optional integer rather than a plain one. */
		ncfg_buf_addf(&buf, "\tAdvDefaultLifetime %lld;\n", (long long)policy->lifetime.value);
	}
	for (at = 0u; at < prefix_count; at++) {
		ncfg_buf_addf(&buf,
		    "\tprefix %s\n"
		    "\t{\n"
		    "\t\tAdvOnLink on;\n"
		    "\t\tAdvAutonomous on;\n"
		    "\t};\n",
		    prefixes[at]);
	}
	if (policy->dns && server_count > 0u) {
		ncfg_buf_add_text(&buf, "\tRDNSS ");
		for (at = 0u; at < server_count; at++) {
			if (at > 0u) {
				ncfg_buf_add_char(&buf, ' ');
			}
			ncfg_buf_add_text(&buf, servers[at]);
		}
		ncfg_buf_add_text(&buf, " { };\n");
	}
	ncfg_buf_add_text(&buf, "};\n");

	if (ncfg_buf_failed(&buf)) {
		ncfg_error_set(err, err_size,
		    "the advertisement for %s is larger than this build will render", iface);
		ncfg_buf_free(&buf);
		return NULL;
	}
	out = ncfg_buf_take(&buf, NULL);
	if (!out) {
		ncfg_error_set(err, err_size, "out of memory rendering the advertisement for %s",
		    iface);
	}
	ncfg_buf_free(&buf);
	return out;
}

char *ncfg_ra_binary(void)
{
	return ncfg_backend_find_program("radvd");
}

/*
 * What both `start` and `reload` refuse before anything is written.
 *
 * A policy with nothing to advertise would produce a file radvd accepts and an
 * advertisement that configures nobody -- an RA with no prefix still makes the
 * router a default gateway, which is a thing to ask for deliberately rather
 * than to arrive at by a reference that resolved to nothing. The usual cause is
 * a delegation that has not come back yet.
 */
static int has_something_to_advertise(const char *iface, size_t prefix_count, int reloading,
    char *err, size_t err_size)
{
	if (prefix_count > 0u) {
		return 1;
	}
	if (reloading) {
		ncfg_error_set(err, err_size,
		    "`%s` would advertise no prefix after the change, which is not something to "
		    "reload into -- stop advertising instead",
		    iface);
		return 0;
	}
	ncfg_error_set(err, err_size,
	    "`%s` advertises no prefix: every reference in its `advertise` block resolved to "
	    "nothing, which usually means the delegation it names has not arrived. Nothing is "
	    "advertised until one has",
	    iface);
	return 0;
}

/* Write the rendered configuration, having made the directory it goes in. */
static int write_config(const char *run, const char *iface, const ncfg_ra_policy_t *policy,
    const char *const *prefixes, size_t prefix_count, const char *const *servers,
    size_t server_count, char *path, size_t path_size, char *err, size_t err_size)
{
	char  dir[NCFG_RA_PATH_MAX];
	char *text;
	int   ok;

	if (!ncfg_ra_run_dir(run, dir, sizeof(dir), err, err_size) ||
	    !ncfg_backend_make_dir(dir, 0755, err, err_size) ||
	    !ncfg_ra_config_path(run, iface, path, path_size, err, err_size)) {
		return 0;
	}
	text = ncfg_ra_render(iface, policy, prefixes, prefix_count, servers, server_count, err,
	    err_size);
	if (!text) {
		return 0;
	}
	ok = ncfg_backend_write_file(path, text, strlen(text), 0644, err, err_size);
	free(text);
	return ok;
}

int ncfg_ra_start(const char *run, const char *iface, const ncfg_ra_policy_t *policy,
    const char *const *prefixes, size_t prefix_count, const char *const *servers,
    size_t server_count, const char *program, char *err, size_t err_size)
{
	char        config[NCFG_RA_PATH_MAX];
	char        pid[NCFG_RA_PATH_MAX];
	char        log[NCFG_RA_PATH_MAX];
	char        said[NCFG_ERROR_MAX];
	char       *found = NULL;
	const char *argv[8];
	int         exited_ok = 0;
	int         status = 0;

	if (!policy) {
		ncfg_error_set(err, err_size, "an advertisement was started with no policy");
		return 0;
	}
	switch (policy->backend.kind) {
	case NCFG_RA_BACKEND_AUTO:
	case NCFG_RA_BACKEND_RADVD:
		break;
	case NCFG_RA_BACKEND_ODHCPD:
		/* **Refused by name rather than silently substituted.** odhcpd takes
		 * entirely different configuration from radvd, so handing it radvd's
		 * would be a document that stopped describing the system. */
		ncfg_error_set(err, err_size,
		    "`%s` asks for the odhcpd backend, which this build does not implement. odhcpd "
		    "takes entirely different configuration from radvd, so netcfgd will not quietly "
		    "hand it radvd's -- name `radvd`, or leave the backend unset and netcfgd will "
		    "use whichever is installed",
		    iface);
		return 0;
	case NCFG_RA_BACKEND_EXEC:
	default:
		ncfg_error_set(err, err_size,
		    "`%s` asks for `%s` to advertise, which this build does not implement", iface,
		    policy->backend.command ? policy->backend.command : "");
		return 0;
	}

	if (!has_something_to_advertise(iface, prefix_count, 0, err, err_size)) {
		return 0;
	}
	if (!write_config(run, iface, policy, prefixes, prefix_count, servers, server_count, config,
	    sizeof(config), err, err_size)) {
		return 0;
	}
	if (!ncfg_ra_pid_path(run, iface, pid, sizeof(pid), err, err_size) ||
	    !ncfg_ra_log_path(run, iface, log, sizeof(log), err, err_size)) {
		return 0;
	}
	if (!program) {
		found = ncfg_ra_binary();
		if (!found) {
			ncfg_error_set(err, err_size,
			    "no radvd found for %s; advertising needs the radvd package", iface);
			return 0;
		}
		program = found;
	}

	argv[0] = program;
	argv[1] = "--config";
	argv[2] = config;
	argv[3] = "--pidfile";
	argv[4] = pid;
	/* Its own file rather than syslog, so the reason an advertisement did not
	 * start is readable after the fact on a machine with no syslog at all --
	 * which is the embedded case this project is built for. */
	argv[5] = "--logmethod";
	argv[6] = "stderr";
	argv[7] = NULL;

	if (!ncfg_backend_run(program, argv, log, &exited_ok, &status, err, err_size)) {
		free(found);
		return 0;
	}
	free(found);
	if (!exited_ok) {
		if (ncfg_backend_complaints(log, RA_MARKERS, sizeof(RA_MARKERS) / sizeof(RA_MARKERS[0]),
		    NULL, 0u, 2u, said, sizeof(said))) {
			ncfg_error_set(err, err_size, "radvd would not start on %s: %s. Its output is in %s",
			    iface, said, log);
		} else {
			ncfg_error_set(err, err_size,
			    "radvd would not start on %s: it exited with status %d. Its output is in %s",
			    iface, status, log);
		}
		return 0;
	}
	return 1;
}

int ncfg_ra_reload(const char *run, const char *iface, const ncfg_ra_policy_t *policy,
    const char *const *prefixes, size_t prefix_count, const char *const *servers,
    size_t server_count, char *err, size_t err_size)
{
	char  config[NCFG_RA_PATH_MAX];
	pid_t pid;

	if (!has_something_to_advertise(iface, prefix_count, 1, err, err_size)) {
		return 0;
	}
	pid = ncfg_ra_running_pid(run, iface);
	if (pid <= 0) {
		ncfg_error_set(err, err_size,
		    "no radvd of netcfgd's is running on %s to reload; it has to be started rather "
		    "than reloaded",
		    iface);
		return 0;
	}
	/* **Rewritten before the signal.** radvd reads the file when it is told to,
	 * so a signal sent first would reload the old contents -- and the caller
	 * would have been told the new prefix was on the wire. */
	if (!write_config(run, iface, policy, prefixes, prefix_count, servers, server_count, config,
	    sizeof(config), err, err_size)) {
		return 0;
	}
	if (!ncfg_process_hangup(pid, err, err_size)) {
		return 0;
	}
	return 1;
}

int ncfg_ra_stop(const char *run, const char *iface, char *err, size_t err_size)
{
	char  pid_file[NCFG_RA_PATH_MAX];
	pid_t pid = ncfg_ra_running_pid(run, iface);

	if (pid <= 0) {
		return 1;
	}
	if (!ncfg_process_terminate(pid, err, err_size)) {
		return 0;
	}
	/* The generated configuration stays: it is rewritten on every start, it
	 * says what was last advertised, and unlike hostapd's it holds no secret. */
	if (ncfg_ra_pid_path(run, iface, pid_file, sizeof(pid_file), NULL, 0)) {
		(void)unlink(pid_file);
	}
	return 1;
}

pid_t ncfg_ra_running_pid(const char *run, const char *iface)
{
	char config[NCFG_RA_PATH_MAX];
	char pid_file[NCFG_RA_PATH_MAX];

	/* The generated configuration is the marker: it is a path netcfgd chose, so
	 * it is unique to this daemon on this machine. An operator's own radvd
	 * cannot match it, which is a stronger claim than "not by name". */
	if (!ncfg_ra_config_path(run, iface, config, sizeof(config), NULL, 0) ||
	    !ncfg_ra_pid_path(run, iface, pid_file, sizeof(pid_file), NULL, 0)) {
		return 0;
	}
	return ncfg_process_pid_of(pid_file, config);
}
