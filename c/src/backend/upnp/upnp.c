/*
 * upnp.c -- miniupnpd as the router's UPnP IGD and NAT-PMP/PCP server,
 * described in upnp.h.
 */
#include "ncfg/upnp.h"

#include "../backend_internal.h"
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/process.h"
#include "ncfg/sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* A generated file is short; one a hundred times longer is not ours. */
#define UPNP_CONFIG_MAX 8192u

/* What miniupnpd says when it will not start. */
static const char *const UPNP_MARKERS[] = { "miniupnpd", "error", "failed", "cannot",
	"unknown", "invalid" };

static const char SUMMARY_PREFIX[] = "# maps: ";

int ncfg_upnp_config_path(const char *run, char *out, size_t out_size, char *err,
    size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "upnp", "miniupnpd", ".conf", err, err_size);
}

int ncfg_upnp_pid_path(const char *run, char *out, size_t out_size, char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "upnp", "miniupnpd", ".pid", err, err_size);
}

int ncfg_upnp_leases_path(const char *run, char *out, size_t out_size, char *err,
    size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "upnp", "miniupnpd", ".leases", err,
	    err_size);
}

static int log_path(const char *run, char *out, size_t out_size, char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "upnp", "miniupnpd", ".log", err, err_size);
}

int ncfg_upnp_summary(const ncfg_upnp_t *upnp, char *out, size_t out_size)
{
	ncfg_buf_t buf;
	size_t     at;
	int        fits;

	if (!upnp || !upnp->uplink || !out || out_size == 0u) {
		return 0;
	}
	ncfg_buf_init(&buf, 0);
	ncfg_buf_addf(&buf, "uplink %s lan", upnp->uplink);
	for (at = 0; at < upnp->lan_count; at++) {
		ncfg_buf_addf(&buf, " %s", upnp->lan[at]);
	}
	fits = buf.length < out_size;
	if (fits) {
		memcpy(out, buf.data, buf.length);
		out[buf.length] = '\0';
	}
	ncfg_buf_free(&buf);
	return fits;
}

int ncfg_upnp_recorded(const char *run, char *out, size_t out_size)
{
	char   path[NCFG_UPNP_PATH_MAX];
	char   line[NCFG_UPNP_SUMMARY_MAX + sizeof(SUMMARY_PREFIX)];
	FILE  *file;
	size_t length;

	if (!ncfg_upnp_config_path(run, path, sizeof(path), NULL, 0)) {
		return 0;
	}
	file = fopen(path, "r");
	if (!file) {
		return 0;
	}
	if (!fgets(line, sizeof(line), file)) {
		(void)fclose(file);
		return 0;
	}
	(void)fclose(file);
	if (strncmp(line, SUMMARY_PREFIX, sizeof(SUMMARY_PREFIX) - 1u) != 0) {
		return 0;
	}
	length = strcspn(line + sizeof(SUMMARY_PREFIX) - 1u, "\n");
	if (length >= out_size) {
		return 0;
	}
	memcpy(out, line + sizeof(SUMMARY_PREFIX) - 1u, length);
	out[length] = '\0';
	return 1;
}

char *ncfg_upnp_render(const ncfg_upnp_t *upnp, const char *leases, const char *uuid, char *err,
    size_t err_size)
{
	char       summary[NCFG_UPNP_SUMMARY_MAX];
	ncfg_buf_t buf;
	size_t     at;
	char      *text;

	if (!ncfg_upnp_summary(upnp, summary, sizeof(summary))) {
		ncfg_error_set(err, err_size, "a UPnP configuration with no uplink, or too many LANs");
		return NULL;
	}
	ncfg_buf_init(&buf, 0);
	ncfg_buf_addf(&buf, "%s%s\n", SUMMARY_PREFIX, summary);
	ncfg_buf_add_text(&buf, "# Written by netcfgd from `global { upnp { } }` (0310); "
	    "an edit here is replaced.\n");
	ncfg_buf_addf(&buf, "ext_ifname=%s\n", upnp->uplink);
	for (at = 0; at < upnp->lan_count; at++) {
		ncfg_buf_addf(&buf, "listening_ip=%s\n", upnp->lan[at]);
	}
	/* Both protocols on one switch, which is what the holder asked for. */
	ncfg_buf_add_text(&buf, "enable_upnp=yes\nenable_pcp_pmp=yes\n");
	/* A client maps ports to itself and to nobody else: the one setting that
	 * keeps a compromised host from opening the rest of the LAN. */
	ncfg_buf_add_text(&buf, "secure_mode=yes\n");
	/* The table netcfgd made, and its three hooked chains (0310). */
	ncfg_buf_addf(&buf, "upnp_table_name=%s\nupnp_nat_table_name=%s\n", NCFG_UPNP_TABLE,
	    NCFG_UPNP_TABLE);
	ncfg_buf_addf(&buf, "upnp_forward_chain=%s\nupnp_nat_chain=%s\n"
	    "upnp_nat_postrouting_chain=%s\n", NCFG_UPNP_CHAIN_FORWARD,
	    NCFG_UPNP_CHAIN_PREROUTING, NCFG_UPNP_CHAIN_POSTROUTING);
	ncfg_buf_addf(&buf, "lease_file=%s\n", leases);
	ncfg_buf_addf(&buf, "uuid=%s\n", uuid);
	ncfg_buf_add_text(&buf, "system_uptime=yes\n");
	/* Ports below 1024 stay closed to a mapping, as every router's default
	 * has them: a client asking for 80 or 22 on the uplink is the case an
	 * operator would want to be asked about. */
	ncfg_buf_add_text(&buf, "allow 1024-65535 0.0.0.0/0 1024-65535\n"
	    "deny 0-65535 0.0.0.0/0 0-65535\n");
	if (buf.length > UPNP_CONFIG_MAX) {
		ncfg_buf_free(&buf);
		ncfg_error_set(err, err_size, "the UPnP configuration would be over %u bytes",
		    (unsigned)UPNP_CONFIG_MAX);
		return NULL;
	}
	text = ncfg_buf_take(&buf, NULL);
	if (!text) {
		ncfg_error_set(err, err_size, "out of memory rendering the UPnP configuration");
	}
	return text;
}

/*
 * The device's UUID, the same on every start: a client lists the router by
 * it, and a new one each start would be a new router each time. Derived from
 * `/etc/machine-id`, and from the uplink's name where there is none.
 */
static void device_uuid(const char *uplink, char out[37])
{
	char    seed[128];
	char    digest[NCFG_SHA256_HEX_SIZE];
	FILE   *file = fopen("/etc/machine-id", "r");
	size_t  length = 0;

	seed[0] = '\0';
	if (file) {
		if (fgets(seed, sizeof(seed), file)) {
			length = strcspn(seed, "\n");
			seed[length] = '\0';
		}
		(void)fclose(file);
	}
	if (!seed[0]) {
		(void)snprintf(seed, sizeof(seed), "netcfgd-upnp-%s", uplink);
	}
	(void)strncat(seed, "/upnp", sizeof(seed) - strlen(seed) - 1u);
	ncfg_sha256_hex(seed, strlen(seed), digest);
	/* A version-4 shaped UUID from the digest's first 32 digits. */
	(void)snprintf(out, 37, "%.8s-%.4s-4%.3s-8%.3s-%.12s", digest, digest + 8, digest + 13,
	    digest + 17, digest + 20);
}

int ncfg_upnp_start(const char *run, const ncfg_upnp_t *upnp, const char *program, char *err,
    size_t err_size)
{
	char        dir[NCFG_UPNP_PATH_MAX];
	char        config[NCFG_UPNP_PATH_MAX];
	char        pid[NCFG_UPNP_PATH_MAX];
	char        log[NCFG_UPNP_PATH_MAX];
	char        leases[NCFG_UPNP_PATH_MAX];
	char        uuid[37];
	char        said[NCFG_ERROR_MAX];
	char       *found = NULL;
	char       *text;
	const char *argv[6];
	int         exited_ok = 0;
	int         status = 0;
	int         ok;

	if (!upnp || !upnp->uplink) {
		ncfg_error_set(err, err_size, "UPnP was started with no uplink");
		return 0;
	}
	if (!ncfg_backend_join(dir, sizeof(dir), run, "upnp", err, err_size) ||
	    !ncfg_backend_make_dir(dir, 0755, err, err_size) ||
	    !ncfg_upnp_config_path(run, config, sizeof(config), err, err_size) ||
	    !ncfg_upnp_pid_path(run, pid, sizeof(pid), err, err_size) ||
	    !log_path(run, log, sizeof(log), err, err_size) ||
	    !ncfg_upnp_leases_path(run, leases, sizeof(leases), err, err_size)) {
		return 0;
	}
	device_uuid(upnp->uplink, uuid);
	text = ncfg_upnp_render(upnp, leases, uuid, err, err_size);
	if (!text) {
		return 0;
	}
	ok = ncfg_backend_write_file(config, text, strlen(text), 0644, err, err_size);
	free(text);
	if (!ok) {
		return 0;
	}
	if (!program) {
		found = ncfg_backend_find_program("miniupnpd");
		if (!found) {
			ncfg_error_set(err, err_size,
			    "no miniupnpd found; UPnP needs the miniupnpd package with its nftables "
			    "backend, miniupnpd-nftables");
			return 0;
		}
		program = found;
	}
	/* `-f <path>` as two arguments, so the path is a whole element of the
	 * daemon's argv and `ncfg_process_pid_of` can take it as the marker --
	 * the fused spelling cost dnsmasq the same test (`dhcp_server.c`). */
	argv[0] = program;
	argv[1] = "-f";
	argv[2] = config;
	argv[3] = "-P";
	argv[4] = pid;
	argv[5] = NULL;
	if (!ncfg_backend_run(program, argv, log, &exited_ok, &status, err, err_size)) {
		free(found);
		return 0;
	}
	free(found);
	if (!exited_ok) {
		if (ncfg_backend_complaints(log, UPNP_MARKERS,
		        sizeof(UPNP_MARKERS) / sizeof(UPNP_MARKERS[0]), NULL, 0u, 2u, said,
		        sizeof(said))) {
			ncfg_error_set(err, err_size, "miniupnpd would not start: %s. Its output is in %s",
			    said, log);
		} else {
			ncfg_error_set(err, err_size, "miniupnpd would not start: it exited with status "
			    "%d. Its output is in %s", status, log);
		}
		return 0;
	}
	return 1;
}

pid_t ncfg_upnp_running_pid(const char *run)
{
	char config[NCFG_UPNP_PATH_MAX];
	char pid_file[NCFG_UPNP_PATH_MAX];

	if (!ncfg_upnp_config_path(run, config, sizeof(config), NULL, 0) ||
	    !ncfg_upnp_pid_path(run, pid_file, sizeof(pid_file), NULL, 0)) {
		return 0;
	}
	return ncfg_process_pid_of(pid_file, config);
}

/* dnsmasq's wait, for its reason: a stop that returns while the daemon is
 * still exiting lets a restart start a second one beside it. */
#define UPNP_STOP_PATIENCE_MS 2000
#define UPNP_STOP_STEP_MS 25

int ncfg_upnp_stop(const char *run, char *err, size_t err_size)
{
	char  pid_file[NCFG_UPNP_PATH_MAX];
	char  config[NCFG_UPNP_PATH_MAX];
	pid_t pid = ncfg_upnp_running_pid(run);
	int   waited = 0;

	if (pid <= 0) {
		return 1;
	}
	if (!ncfg_upnp_config_path(run, config, sizeof(config), err, err_size) ||
	    !ncfg_process_terminate(pid, err, err_size)) {
		return 0;
	}
	/* The pid signalled, followed to its end, for dnsmasq's reason (10.772). */
	while (ncfg_process_still(pid, config)) {
		struct timespec step;

		if (waited >= UPNP_STOP_PATIENCE_MS) {
			ncfg_error_set(err, err_size,
			    "miniupnpd is still running %d ms after SIGTERM; its pid file is left in "
			    "place, so a start that follows sees it rather than beginning a second",
			    UPNP_STOP_PATIENCE_MS);
			return 0;
		}
		step.tv_sec = 0;
		step.tv_nsec = (long)UPNP_STOP_STEP_MS * 1000000L;
		(void)nanosleep(&step, NULL);
		waited += UPNP_STOP_STEP_MS;
	}
	if (ncfg_upnp_pid_path(run, pid_file, sizeof(pid_file), NULL, 0)) {
		(void)unlink(pid_file);
	}
	return 1;
}

void ncfg_upnp_mappings_free(ncfg_observed_mapping_t *mappings, size_t count)
{
	size_t at;

	for (at = 0; mappings && at < count; at++) {
		free(mappings[at].protocol);
		free(mappings[at].address);
		free(mappings[at].description);
	}
	free(mappings);
}

static char *copy_text(const char *text)
{
	size_t length = strlen(text) + 1u;
	char  *copy = malloc(length);

	if (copy) {
		memcpy(copy, text, length);
	}
	return copy;
}

int ncfg_upnp_mappings_in_text(const char *text, ncfg_observed_mapping_t **out, size_t *count)
{
	const char *line = text;

	*out = NULL;
	*count = 0;
	while (line && *line && *count < NCFG_UPNP_MAPPINGS_MAX) {
		const char              *end = strchr(line, '\n');
		const size_t             length = end ? (size_t)(end - line) : strlen(line);
		char                     one[512];
		char                     protocol[8];
		char                     address[64];
		char                     description[256];
		unsigned                 external = 0;
		unsigned                 internal = 0;
		unsigned long long       expiry = 0;
		ncfg_observed_mapping_t *grown;
		ncfg_observed_mapping_t *mapping;

		const char              *start = line;

		line = end ? end + 1 : NULL;
		if (length >= sizeof(one)) {
			continue;
		}
		memcpy(one, start, length);
		one[length] = '\0';
		description[0] = '\0';
		if (sscanf(one, "%7[^:]:%u:%63[^:]:%u:%llu:%255[^\n]", protocol, &external, address,
		        &internal, &expiry, description) < 4 ||
		    external == 0u || external > 65535u || internal == 0u || internal > 65535u) {
			continue;
		}
		grown = realloc(*out, (*count + 1u) * sizeof(*grown));
		if (!grown) {
			ncfg_upnp_mappings_free(*out, *count);
			*out = NULL;
			*count = 0;
			return 0;
		}
		*out = grown;
		mapping = &grown[*count];
		memset(mapping, 0, sizeof(*mapping));
		mapping->protocol = copy_text(protocol);
		mapping->address = copy_text(address);
		mapping->description = copy_text(description);
		mapping->external_port = (int64_t)external;
		mapping->internal_port = (int64_t)internal;
		mapping->expires = (int64_t)expiry;
		(*count)++;
		if (!mapping->protocol || !mapping->address || !mapping->description) {
			ncfg_upnp_mappings_free(*out, *count);
			*out = NULL;
			*count = 0;
			return 0;
		}
	}
	return 1;
}
