/*
 * ra.c -- radvd's configuration, and the lifecycle of the daemon that reads it.
 *
 * See `ra.h` for why netcfgd does not send an advertisement itself, why an
 * unimplemented backend is refused by name, and why reload is a signal rather
 * than a restart. What is here is the rendering and the four calls around it,
 * for radvd and for uradvd, OpenWrt 25.12's (10.817).
 */
#include "ncfg/ra.h"

#include "../backend_internal.h"
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/process.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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

/*
 * The first line of the file a uradvd was started from, and how a reload
 * tells it from radvd's: a backend of `auto` may have started either, and the
 * file is netcfgd's own record of which.
 */
#define URADVD_HEAD "# uradvd for "

/* uradvd's own limits, from its `uradvd.c` at the commit OpenWrt 25.12 builds
 * (1e64364d): more than these and it exits naming the one it hit. */
#define URADVD_MAX_PREFIXES 8u
#define URADVD_MAX_RDNSS 3u

/*
 * radvd's default router lifetime, three times its default MaxRtrAdvInterval
 * of 600 s. **uradvd's own default is 0, which tells every host this router is
 * not a default gateway**, so a policy that leaves the lifetime unset is given
 * radvd's, and the two daemons mean the same thing by the same document.
 */
#define URADVD_DEFAULT_LIFETIME 1800

/* How long a start waits before asking whether the uradvd it began is still
 * there: it reads its arguments and opens its sockets at once, and exits at
 * once when it cannot. */
#define URADVD_SETTLE_MILLISECONDS 300

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

char *ncfg_ra_uradvd_binary(void)
{
	return ncfg_backend_find_program("uradvd");
}

/* Whether this prefix's length is 64, the only one uradvd takes. */
static int is_slash_64(const char *prefix)
{
	const char *slash = strrchr(prefix, '/');

	return slash && strcmp(slash, "/64") == 0;
}

char *ncfg_ra_uradvd_render(const char *iface, const ncfg_ra_policy_t *policy,
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
	/* **Refused, not dropped.** uradvd sends both flags as zero and has no
	 * argument for either, so a document asking for DHCPv6 on the LAN would
	 * be advertised as SLAAC with nothing to say so. */
	if (policy->managed || policy->other_config) {
		ncfg_error_set(err, err_size,
		    "`%s` asks for the %s flag, which uradvd cannot send: it advertises both as "
		    "off. Name `radvd`, or leave the flag off",
		    iface, policy->managed ? "managed" : "other-config");
		return NULL;
	}
	if (prefix_count > URADVD_MAX_PREFIXES) {
		ncfg_error_set(err, err_size,
		    "`%s` would advertise %zu prefixes and uradvd takes at most %u", iface,
		    prefix_count, URADVD_MAX_PREFIXES);
		return NULL;
	}
	for (at = 0u; at < prefix_count; at++) {
		if (!is_slash_64(prefixes[at])) {
			ncfg_error_set(err, err_size,
			    "`%s` would advertise %s, and uradvd takes only a /64, the length a "
			    "host can make an address in by itself",
			    iface, prefixes[at]);
			return NULL;
		}
	}
	/* RFC 4861 6.2.1: 0, or at most 9000. radvd refuses the rest itself. */
	if (policy->lifetime.has && (policy->lifetime.value < 0 || policy->lifetime.value > 9000)) {
		ncfg_error_set(err, err_size,
		    "`%s` asks for a router lifetime of %lld s, and an advertisement carries 0 "
		    "to 9000",
		    iface, (long long)policy->lifetime.value);
		return NULL;
	}
	if (policy->dns && server_count > URADVD_MAX_RDNSS) {
		ncfg_error_set(err, err_size,
		    "`%s` would advertise %zu name servers and uradvd takes at most %u", iface,
		    server_count, URADVD_MAX_RDNSS);
		return NULL;
	}

	ncfg_buf_init(&buf, RA_CONFIG_MAX);
	ncfg_buf_addf(&buf,
	    URADVD_HEAD "%s, written by netcfgd. Do not edit; it is rewritten on apply.\n"
	    "# uradvd reads no file: these are the arguments it was started with, one\n"
	    "# to a line, and this file's path follows them, which is how netcfgd knows\n"
	    "# its process from anybody else's.\n"
	    "-i\n%s\n",
	    iface, iface);
	/* **`-p`, not `-a`.** Both make a prefix autonomous; `-p` makes it on-link
	 * as well, which is what radvd's `AdvOnLink on` says above. With `-a` a
	 * host takes an address and sends everything for its own /64 to the
	 * router -- the reverse of what the two flags read like, and what
	 * uradvd's own init script calls "off link". From `uradvd.c` at 1e64364d. */
	for (at = 0u; at < prefix_count; at++) {
		ncfg_buf_addf(&buf, "-p\n%s\n", prefixes[at]);
	}
	ncfg_buf_addf(&buf, "--default-lifetime\n%lld\n",
	    policy->lifetime.has ? (long long)policy->lifetime.value
	                         : (long long)URADVD_DEFAULT_LIFETIME);
	if (policy->dns) {
		for (at = 0u; at < server_count; at++) {
			ncfg_buf_addf(&buf, "--rdnss\n%s\n", servers[at]);
		}
	}
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

/* Write the rendered configuration, having made the directory it goes in:
 * radvd's file, or for uradvd the record of its arguments. */
static int write_config(const char *run, const char *iface, const ncfg_ra_policy_t *policy,
    const char *const *prefixes, size_t prefix_count, const char *const *servers,
    size_t server_count, const char *uradvd, char *path, size_t path_size, char *err,
    size_t err_size)
{
	char  dir[NCFG_RA_PATH_MAX];
	char *text;
	int   ok;

	if (!ncfg_ra_run_dir(run, dir, sizeof(dir), err, err_size) ||
	    !ncfg_backend_make_dir(dir, 0755, err, err_size) ||
	    !ncfg_ra_config_path(run, iface, path, path_size, err, err_size)) {
		return 0;
	}
	text = uradvd ? ncfg_ra_uradvd_render(iface, policy, prefixes, prefix_count, servers,
	                    server_count, err, err_size)
	              : ncfg_ra_render(iface, policy, prefixes, prefix_count, servers,
	                    server_count, err, err_size);
	if (!text) {
		return 0;
	}
	/* And for uradvd, which program: a reload restarts it, and its command
	 * line cannot say -- a program run through an interpreter shows the
	 * interpreter there. */
	if (uradvd) {
		size_t length = strlen(text);
		size_t extra = strlen("# started as \n") + strlen(uradvd);
		char  *grown = realloc(text, length + extra + 1u);

		if (!grown) {
			free(text);
			ncfg_error_set(err, err_size, "out of memory recording uradvd for %s", iface);
			return 0;
		}
		text = grown;
		(void)snprintf(text + length, extra + 1u, "# started as %s\n", uradvd);
	}
	ok = ncfg_backend_write_file(path, text, strlen(text), 0644, err, err_size);
	free(text);
	return ok;
}

/*
 * Start a uradvd from the record `write_config` made of its arguments.
 *
 * **uradvd neither detaches nor writes a pid file**, where radvd does both,
 * so a shell does the two for it: `"$@" &` and the pid it gets written where
 * radvd would have written its own. `ncfg_backend_run` puts the shell in a
 * process group of its own before the exec, and the uradvd it leaves behind
 * keeps that group, so it is no child of netcfgd's terminal either. The
 * record's path goes last, after `--`, where uradvd's option parsing stops and
 * nothing more is read: that is the marker `ncfg_ra_running_pid` asks the
 * command line for, so stopping and liveness are radvd's unchanged.
 *
 * And it is asked after a moment whether it is still there, since uradvd
 * starting is not uradvd running: it exits at once on what it cannot use, and
 * the shell has already said 0.
 */
static int start_uradvd(const char *iface, const char *program, const char *config,
    const char *pid, const char *log, char *err, size_t err_size)
{
	char            said[NCFG_ERROR_MAX];
	char           *text;
	const char    **argv = NULL;
	size_t          lines = 0u;
	size_t          count = 0u;
	size_t          at;
	char           *line;
	char           *next;
	int             exited_ok = 0;
	int             status = 0;
	int             ok = 0;
	struct timespec settle;

	text = ncfg_backend_read_file(config, NULL, RA_CONFIG_MAX);
	if (!text) {
		ncfg_error_set(err, err_size, "the record of uradvd's arguments for %s, %s, could "
		    "not be read back", iface, config);
		return 0;
	}
	for (at = 0u; text[at]; at++) {
		lines += text[at] == '\n';
	}
	/* sh, -c, the script, $0, the pid file, the program, the arguments, `--`,
	 * the record, and the NULL. */
	argv = calloc(lines + 9u, sizeof(*argv));
	if (!argv) {
		ncfg_error_set(err, err_size, "out of memory starting uradvd on %s", iface);
		free(text);
		return 0;
	}
	argv[count++] = "sh";
	argv[count++] = "-c";
	argv[count++] = "pid=$1; shift; \"$@\" & echo $! > \"$pid\"";
	argv[count++] = "sh";
	argv[count++] = pid;
	argv[count++] = program;
	for (line = text; *line; line = next) {
		next = strchr(line, '\n');
		if (next) {
			*next++ = '\0';
		} else {
			next = line + strlen(line);
		}
		if (line[0] != '\0' && line[0] != '#') {
			argv[count++] = line;
		}
	}
	argv[count++] = "--";
	argv[count++] = config;
	argv[count] = NULL;

	if (!ncfg_backend_run("/bin/sh", argv, log, &exited_ok, &status, err,
	    err_size)) {
		goto out;
	}
	if (!exited_ok) {
		ncfg_error_set(err, err_size,
		    "uradvd could not be started on %s: the shell starting it exited with status %d. "
		    "Its output is in %s", iface, status, log);
		goto out;
	}
	settle.tv_sec = 0;
	settle.tv_nsec = (long)URADVD_SETTLE_MILLISECONDS * 1000000L;
	(void)nanosleep(&settle, NULL);
	if (ncfg_process_pid_of(pid, config) <= 0) {
		if (ncfg_backend_complaints(log, RA_MARKERS, sizeof(RA_MARKERS) / sizeof(RA_MARKERS[0]),
		    NULL, 0u, 2u, said, sizeof(said))) {
			ncfg_error_set(err, err_size, "uradvd would not start on %s: %s. Its output is in "
			    "%s", iface, said, log);
		} else {
			ncfg_error_set(err, err_size, "uradvd would not start on %s: it was gone %d ms "
			    "after it began. Its output is in %s", iface, URADVD_SETTLE_MILLISECONDS, log);
		}
		(void)unlink(pid);
		goto out;
	}
	ok = 1;
out:
	free((void *)argv);
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
	int         uradvd;

	if (!policy) {
		ncfg_error_set(err, err_size, "an advertisement was started with no policy");
		return 0;
	}
	switch (policy->backend.kind) {
	case NCFG_RA_BACKEND_AUTO:
	case NCFG_RA_BACKEND_RADVD:
	case NCFG_RA_BACKEND_URADVD:
		break;
	case NCFG_RA_BACKEND_ODHCPD:
		/* **Refused by name rather than silently substituted.** odhcpd takes
		 * entirely different configuration from radvd, so handing it radvd's
		 * would be a document that stopped describing the system. */
		ncfg_error_set(err, err_size,
		    "`%s` asks for the odhcpd backend, which this build does not implement. odhcpd "
		    "takes entirely different configuration from radvd, so netcfgd will not quietly "
		    "hand it radvd's -- name `radvd` or `uradvd`, or leave the backend unset and "
		    "netcfgd will use whichever is installed",
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
	/*
	 * **Which daemon.** A program passed in is the backend named, or radvd for
	 * `auto`, as it always was. Otherwise `auto` takes radvd where there is one
	 * and uradvd where there is not: OpenWrt 25.12 carries no radvd in any of
	 * its feeds, and uradvd is in its packages feed (10.817).
	 */
	uradvd = policy->backend.kind == NCFG_RA_BACKEND_URADVD;
	if (!program) {
		if (!uradvd) {
			found = ncfg_ra_binary();
		}
		if (!found && policy->backend.kind != NCFG_RA_BACKEND_RADVD) {
			found = ncfg_ra_uradvd_binary();
			uradvd = found != NULL;
		}
		if (!found) {
			ncfg_error_set(err, err_size,
			    "no %s found for %s; advertising needs %s",
			    policy->backend.kind == NCFG_RA_BACKEND_RADVD    ? "radvd"
			    : policy->backend.kind == NCFG_RA_BACKEND_URADVD ? "uradvd"
			                                                     : "radvd or uradvd",
			    iface,
			    policy->backend.kind == NCFG_RA_BACKEND_RADVD ? "the radvd package"
			    : policy->backend.kind == NCFG_RA_BACKEND_URADVD
			        ? "the uradvd package (`apk add uradvd` on OpenWrt)"
			        : "one of them: radvd, or on OpenWrt 25.12, which has none, "
			          "`apk add uradvd`");
			return 0;
		}
		program = found;
	}
	if (!write_config(run, iface, policy, prefixes, prefix_count, servers, server_count,
	    uradvd ? program : NULL, config, sizeof(config), err, err_size) ||
	    !ncfg_ra_pid_path(run, iface, pid, sizeof(pid), err, err_size) ||
	    !ncfg_ra_log_path(run, iface, log, sizeof(log), err, err_size)) {
		free(found);
		return 0;
	}
	if (uradvd) {
		int ok = start_uradvd(iface, program, config, pid, log, err, err_size);

		free(found);
		return ok;
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

/* Whether the advertisement on this interface was started as uradvd, by the
 * first line of the record netcfgd wrote when it started it. */
static int started_uradvd(const char *run, const char *iface)
{
	char  config[NCFG_RA_PATH_MAX];
	char *text;
	int   is;

	if (!ncfg_ra_config_path(run, iface, config, sizeof(config), NULL, 0)) {
		return 0;
	}
	text = ncfg_backend_read_file(config, NULL, RA_CONFIG_MAX);
	is = text && strncmp(text, URADVD_HEAD, strlen(URADVD_HEAD)) == 0;
	free(text);
	return is;
}

/*
 * A uradvd's reload: stopped, and started again as the same program, which
 * the record names on its `# started as` line.
 */
static int restart_uradvd(const char *run, const char *iface, const ncfg_ra_policy_t *policy,
    const char *const *prefixes, size_t prefix_count, const char *const *servers,
    size_t server_count, char *err, size_t err_size)
{
	static const char marker[] = "\n# started as ";
	char              config[NCFG_RA_PATH_MAX];
	char              program[NCFG_RA_PATH_MAX];
	ncfg_ra_policy_t  as_uradvd;
	char             *text;
	const char       *at;
	size_t            length;

	if (!ncfg_ra_config_path(run, iface, config, sizeof(config), err, err_size)) {
		return 0;
	}
	text = ncfg_backend_read_file(config, NULL, RA_CONFIG_MAX);
	at = text ? strstr(text, marker) : NULL;
	length = at ? strcspn(at + strlen(marker), "\n") : 0u;
	if (!at || length == 0u || length >= sizeof(program)) {
		free(text);
		ncfg_error_set(err, err_size, "the record of the uradvd on %s, %s, does not say which "
		    "program it started, so it is not restarted", iface, config);
		return 0;
	}
	memcpy(program, at + strlen(marker), length);
	program[length] = '\0';
	free(text);
	if (!ncfg_ra_stop(run, iface, err, err_size)) {
		return 0;
	}
	as_uradvd = *policy;
	as_uradvd.backend.kind = NCFG_RA_BACKEND_URADVD;
	return ncfg_ra_start(run, iface, &as_uradvd, prefixes, prefix_count, servers, server_count,
	    program, err, err_size);
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
	/* **uradvd has nothing to re-read**, so its reload is a restart of the
	 * same program, told apart from radvd by netcfgd's own record. */
	if (started_uradvd(run, iface)) {
		return restart_uradvd(run, iface, policy, prefixes, prefix_count, servers,
		    server_count, err, err_size);
	}
	/* **Rewritten before the signal.** radvd reads the file when it is told to,
	 * so a signal sent first would reload the old contents -- and the caller
	 * would have been told the new prefix was on the wire. */
	if (!write_config(run, iface, policy, prefixes, prefix_count, servers, server_count, NULL,
	    config, sizeof(config), err, err_size)) {
		return 0;
	}
	if (!ncfg_process_hangup(pid, err, err_size)) {
		return 0;
	}
	return 1;
}

/*
 * Wait for a signalled radvd to go, and say whether it did.
 *
 * **The defect this exists for is the same class as `autoip`'s (10.565) with
 * a different ending.** This stop signalled, unlinked the pid file and
 * returned -- and `ncfg_ra_running_pid` reads only that file, so a radvd still
 * exiting read as *absent*. A restart is a stop and then a start, so the
 * start met an interface the old daemon still held: two radvds sending
 * conflicting advertisements on one link, from a stop that reported success.
 *
 * `kill()` returning says the signal was queued, not that the target has run,
 * which is the whole of the window. The check is `ncfg_ra_running_pid`'s own
 * question -- the pid file plus `/proc/<pid>/cmdline` -- asked until it
 * answers 0, so it inherits that function's care about recycled pids rather
 * than repeating it.
 */
#define RA_STOP_PATIENCE_MILLISECONDS 1000
#define RA_STOP_STEP_MILLISECONDS 25

static int wait_for_exit(pid_t pid, const char *run, const char *iface)
{
	char marker[NCFG_RA_PATH_MAX];
	int  waited = 0;

	/* By the pid taken before the signal, where there is one: radvd removes
	 * its own pid file as it exits, before it has (10.661). The marker is the
	 * same generated configuration. */
	if (pid > 0 && !ncfg_ra_config_path(run, iface, marker, sizeof(marker), NULL, 0)) {
		pid = 0;
	}
	for (;;) {
		struct timespec step;

		if (pid > 0 ? !ncfg_process_still(pid, marker)
		            : ncfg_ra_running_pid(run, iface) <= 0) {
			return 1;
		}
		if (waited >= RA_STOP_PATIENCE_MILLISECONDS) {
			return 0;
		}
		step.tv_sec = 0;
		step.tv_nsec = (long)RA_STOP_STEP_MILLISECONDS * 1000000L;
		(void)nanosleep(&step, NULL);
		waited += RA_STOP_STEP_MILLISECONDS;
	}
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
	/*
	 * **Waited for before the record goes, which is the order that matters.**
	 * radvd removes its own pid file on the way out, so the common case
	 * returns on the first look and the unlink below is a tidy-up for a
	 * daemon that was killed rather than asked.
	 */
	if (!wait_for_exit(pid, run, iface)) {
		ncfg_error_set(err, err_size,
		    "the advertising daemon on %s is still running %d ms after SIGTERM, still "
		    "reciting the "
		    "configuration netcfgd gave it. Its pid file is left in place, so a start "
		    "that follows will see it rather than beginning a second daemon on the "
		    "same link", iface, RA_STOP_PATIENCE_MILLISECONDS);
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
