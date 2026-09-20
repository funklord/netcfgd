/*
 * currency.c -- whether a running daemon still holds what the document asks
 * for.
 *
 * TWO PASSES, ONE SHAPE
 *   An access point's passphrase and a tunnel's `.ovpn` are both things netcfgd
 *   hands a daemon **once, when it starts it**. The daemon reads them and never
 *   looks again, so editing the document or the secret store changes nothing
 *   until something restarts the process -- and nothing can decide to restart
 *   it without knowing that what it is holding has gone stale. These are the
 *   two answers that make that decidable, and both are read out of files
 *   netcfgd itself wrote.
 *
 * WHY EACH IS A BOOLEAN AND NOT A VALUE
 *   0052, and `observed.h` says it at the field: an observation that carried
 *   the passphrase would put it in `/run/netcfgd/observed.json`, in
 *   `ncfg status --json`, and in front of anyone who can read either. What a
 *   planner needs is whether it changed, so that is the whole of what is
 *   stored.
 *
 * WHY ABSENT IS AN ANSWER
 *   Three of the ways these can come back absent are ordinary and one is a
 *   fault, and none of them is "it differs":
 *
 *     * There is no document, so there is nothing to be current *with*.
 *     * The generated file is gone -- a `/run` cleared under a running daemon,
 *       or one started by a build too old to write the record.
 *     * The secret store cannot answer, which `secrets.h` reports without
 *       disclosing anything.
 *
 *   Each leaves the field absent, and `apply.h`'s rule is that a planner does
 *   nothing about a question nobody answered. Answering "differs" from any of
 *   them would restart a working daemon on a guess; answering "matches" would
 *   let a rotated credential sit unused for ever.
 *
 * WHAT IS COMPARED, AND WHERE THE SECRET GOES
 *   The passphrase comparison reads the value out of the generated
 *   `hostapd.conf` and the value out of the store, and compares them. Both are
 *   in this process' memory for the length of that comparison and are wiped
 *   before it returns -- which is `secrets.h`'s discipline, and the reason the
 *   line is read into a buffer this file owns rather than left in a string the
 *   caller could keep.
 *
 *   The tunnel comparison never reads the `.ovpn` for meaning: it digests the
 *   file and compares that against the digest netcfgd recorded when it started
 *   the tunnel, which is what 0046 protects.
 */
#include "ncfg/observe.h"

#include "observe_internal.h"

#include "ncfg/base.h"
#include "ncfg/hooks.h"
#include "ncfg/hostapd.h"
#include "ncfg/openvpn.h"
#include "ncfg/secrets.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * How much of a generated file is read.
 *
 * Generous for what netcfgd writes and a ceiling rather than a growing read,
 * because these run once per running daemon on every observation. Past it the
 * file is treated as unreadable, which leaves the answer absent -- the same as
 * a file that is not there, and for the same reason.
 */
#define CURRENCY_FILE_MAX 65536

static char *read_whole(const char *path)
{
	FILE  *file = fopen(path, "rb");
	char  *body;
	size_t got;

	if (!file) {
		return NULL;
	}
	body = malloc((size_t)CURRENCY_FILE_MAX + 1u);
	if (!body) {
		(void)fclose(file);
		return NULL;
	}
	got = fread(body, 1u, (size_t)CURRENCY_FILE_MAX, file);
	if (!feof(file) || ferror(file)) {
		(void)fclose(file);
		free(body);
		return NULL;
	}
	(void)fclose(file);
	body[got] = '\0';
	return body;
}

/*
 * The value of `key=` in a generated configuration, copied into `out`.
 *
 * The first match wins, which is hostapd's own reading of its file. 1 with the
 * value, 0 where the key is absent or would not fit -- and **not fitting is
 * the same as absent** here rather than a truncated comparison, because a
 * truncated passphrase compares unequal to the store's and would restart a
 * working access point on every reconcile.
 */
static int value_of(const char *text, const char *key, char *out, size_t out_size)
{
	const char *line = text;
	size_t      key_length = strlen(key);

	while (line && *line) {
		const char *end = strchr(line, '\n');
		const char *stop = end ? end : line + strlen(line);
		const char *at = line;

		while (at < stop && (*at == ' ' || *at == '\t')) {
			at++;
		}
		if ((size_t)(stop - at) > key_length && strncmp(at, key, key_length) == 0 &&
		    at[key_length] == '=') {
			size_t length = (size_t)(stop - at) - key_length - 1u;

			if (length + 1u > out_size) {
				return 0;
			}
			memcpy(out, at + key_length + 1u, length);
			out[length] = '\0';
			return 1;
		}
		line = end ? end + 1 : NULL;
	}
	return 0;
}

/* The access point block for this device, or NULL. */
static const ncfg_access_point_t *point_on(const ncfg_document_t *desired, const char *device)
{
	size_t at;

	for (at = 0; desired && device && at < desired->access_point_count; at++) {
		if (desired->access_points[at].device &&
		    strcmp(desired->access_points[at].device, device) == 0) {
			return &desired->access_points[at];
		}
	}
	return NULL;
}

/* The openvpn configuration path this device names, or NULL. */
static const char *tunnel_config_on(const ncfg_document_t *desired, const char *name)
{
	size_t at;

	for (at = 0; desired && name && at < desired->device_count; at++) {
		const ncfg_device_t *device = &desired->devices[at];

		if (device->kind.kind == NCFG_KIND_OPENVPN && device->name &&
		    strcmp(device->name, name) == 0) {
			return device->kind.openvpn.config;
		}
	}
	return NULL;
}

/*
 * Whether the passphrase hostapd was started with is the one the store holds.
 *
 * Left absent for an open network and for one this build does not render:
 * there is nothing to compare rather than something that differs.
 */
static void access_point_currency(ncfg_observed_backend_t *backend, const char *run_dir,
    const ncfg_document_t *desired, const ncfg_secret_resolver_t *secrets)
{
	const ncfg_access_point_t *point = point_on(desired, backend->interface);
	char                       path[NCFG_HOSTAPD_PATH_MAX];
	char                       started[NCFG_HOSTAPD_PASSPHRASE_MAX + 1u];
	char                       why[NCFG_ERROR_MAX];
	ncfg_secret_t             *wanted;
	char                      *text;

	if (!point || point->security.kind != NCFG_SECURITY_PSK) {
		return;
	}
	if (!ncfg_hostapd_config_path(run_dir, backend->interface, path, sizeof(path), NULL, 0)) {
		return;
	}
	text = read_whole(path);
	if (!text) {
		return;
	}
	if (!value_of(text, "wpa_passphrase", started, sizeof(started))) {
		/* A file netcfgd wrote for a PSK network always has one, so this is a
		 * file somebody else wrote or one from a build that rendered
		 * differently. Nothing may be concluded from it. */
		free(text);
		return;
	}
	free(text);
	why[0] = '\0';
	wanted = ncfg_secret_resolve(secrets, &point->security.psk.passphrase, NULL, why,
	    sizeof(why));
	if (!wanted) {
		/*
		 * The store could not answer -- `secrets.h` guarantees the sentence
		 * discloses nothing, and this pass does not repeat it: a note per
		 * observation about a credential is a log line that says a secret
		 * exists, once every five seconds.
		 */
		explicit_bzero(started, sizeof(started));
		return;
	}
	backend->secret_matches.has = 1;
	backend->secret_matches.value = strcmp(started, ncfg_secret_expose(wanted)) == 0;
	/* Both sides wiped before returning, which is `secrets.h`'s discipline: the
	 * buffer is netcfgd's until the last instant, and clearing it shortens the
	 * window in which a core dump or a later allocation carries a passphrase. */
	ncfg_secret_free(wanted);
	explicit_bzero(started, sizeof(started));
}

/*
 * Whether the `.ovpn` a tunnel was started from is still the file the document
 * names.
 *
 * **`config_present` is asked before the record and separately**, because it is
 * a fact about the document rather than about netcfgd's bookkeeping: a `.ovpn`
 * that cannot be read is a fault whether or not there is a hash to compare it
 * to, and `observed.h` says that absence left the operator with silence -- a
 * document pointing at a file that is not there produced `nothing to do` on
 * every apply, for ever, while the daemon went on running what it started with.
 */
static void tunnel_currency(ncfg_observed_backend_t *backend, const char *run_dir,
    const ncfg_document_t *desired)
{
	const char *config = tunnel_config_on(desired, backend->interface);
	char        path[NCFG_OPENVPN_PATH_MAX];
	char        current[NCFG_SHA256_HEX_SIZE];
	char       *recorded;
	int         have;

	if (!config) {
		return;
	}
	have = ncfg_openvpn_hash_of(config, current, sizeof(current));
	backend->config_present.has = 1;
	backend->config_present.value = have;
	if (!ncfg_openvpn_config_hash_path(run_dir, backend->interface, path, sizeof(path), NULL,
	    0)) {
		return;
	}
	recorded = read_whole(path);
	if (!recorded) {
		/* Started by a build too old to write the record, or a `/run` cleared
		 * underneath a running tunnel. Nothing may be concluded. */
		return;
	}
	if (have) {
		size_t length = strlen(recorded);

		while (length > 0u && (unsigned char)recorded[length - 1u] <= ' ') {
			recorded[--length] = '\0';
		}
		backend->config_matches.has = 1;
		backend->config_matches.value = strcmp(current, recorded) == 0;
	}
	/*
	 * A file that cannot be read leaves `config_matches` absent rather than
	 * false. `config_present` above already says the file is the fault, and
	 * saying "differs" as well would have the planner restart a tunnel to fix
	 * something a restart cannot fix.
	 */
	free(recorded);
}

int ncfg_observe_currency(ncfg_observed_t *observed, const char *run_dir,
    const ncfg_secret_resolver_t *secrets, const ncfg_document_t *desired, char *err,
    size_t err_size)
{
	size_t at;

	if (!observed || !run_dir || !run_dir[0]) {
		ncfg_error_set(err, err_size,
		    "a currency round needs an observation and the run directory the daemons "
		    "were started under");
		return 0;
	}
	if (!desired) {
		/* No document, so nothing to be current with. Every field stays as it
		 * was, which is absent. */
		return 1;
	}
	for (at = 0; at < observed->backend_count; at++) {
		ncfg_observed_backend_t *backend = &observed->backends[at];

		if (!backend->running || !backend->interface) {
			continue;
		}
		if (backend->kind == NCFG_BACKEND_ACCESS_POINT) {
			access_point_currency(backend, run_dir, desired, secrets);
		} else if (backend->kind == NCFG_BACKEND_OPENVPN) {
			tunnel_currency(backend, run_dir, desired);
		}
	}
	return 1;
}
