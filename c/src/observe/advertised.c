/*
 * advertised.c -- what a running router advertisement daemon is announcing.
 *
 * WHAT THIS CLOSES
 *   `ncfg_observed_backend_t::advertised` is the one value in a document that
 *   arrives *after* the document does: the prefixes come from a delegation a
 *   lease supplied, so an ISP renumbering moves them under a daemon that is
 *   already running. `plan/advertise.c` compares what the policy resolves to
 *   now against what the daemon was last given, and reloads on a difference --
 *   but it treats an **empty** list as "netcfgd cannot tell", not as
 *   "announcing nothing", because an empty list would plan a reload on every
 *   reconcile.
 *
 *   Nothing filled that list, so it was always empty, so the comparison never
 *   ran: a renumbered prefix left radvd announcing the old block for ever,
 *   telling every host on the wire to use an address the upstream will not
 *   route. That is the mirror of the WireGuard defect 0054 left -- a pass that
 *   plans nothing, ever, rather than one that plans the same thing for ever.
 *
 * WHY IT READS THE FILE RATHER THAN ASKING THE DAEMON
 *   radvd has no control socket. What it is announcing is whatever was in its
 *   configuration when it last read one, and netcfgd generated that file --
 *   so the file *is* the record of what the daemon was given, and reading it
 *   back is the same shape as `<run>/dns/` and `<run>/wireguard/`. The path
 *   comes from `ncfg_ra_config_path` rather than being composed here, which is
 *   the rule every record reader in this port follows: two spellings of one
 *   path is a reader looking where nothing was written.
 *
 * WHY AN UNREADABLE FILE SAYS NOTHING
 *   The list stays empty, which `plan/advertise.c` reads as "cannot tell" and
 *   does nothing about. That is deliberate in both directions: a file gone
 *   from under a daemon the record says is running is not evidence that the
 *   daemon is announcing nothing, and answering "nothing" would plan a reload
 *   against a guess.
 */
#include "ncfg/observe.h"

#include "observe_internal.h"

#include "ncfg/base.h"
#include "ncfg/ra.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * How much of a generated `radvd.conf` is read.
 *
 * Generous for what netcfgd writes -- a handful of prefixes and an `RDNSS`
 * line -- and a ceiling rather than a growing read, because this runs once per
 * advertising interface on every observation. Past it the file is treated as
 * unreadable, which is the answer that says nothing rather than a wrong one.
 */
#define RA_CONFIG_MAX 65536

/* The whole file, or NULL. Absent, unreadable and past the ceiling are one
 * answer, for the reason this file's header gives. */
static char *read_config(const char *path)
{
	FILE  *file = fopen(path, "rb");
	char  *body;
	size_t got;

	if (!file) {
		return NULL;
	}
	body = malloc((size_t)RA_CONFIG_MAX + 1u);
	if (!body) {
		(void)fclose(file);
		return NULL;
	}
	got = fread(body, 1u, (size_t)RA_CONFIG_MAX, file);
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
 * The prefixes a generated configuration declares, in the order it declares
 * them.
 *
 * `prefix <block>` is what `ncfg_ra_config` writes, one per line and indented
 * with a tab. **The order is kept rather than sorted**, because the comparison
 * in `plan/advertise.c` is against the policy's own order -- it joins both
 * sides into a string and compares those, so sorting one side would plan a
 * reload on every reconcile for a document whose prefixes are not in
 * ascending order.
 *
 * Anything that is not a `prefix` line is skipped rather than refused: the
 * file carries `AdvSendAdvert`, an `RDNSS` list and the braces of each block,
 * and a reader that insisted on a shape would stop working the day the
 * renderer gained a line.
 */
static int prefixes_of(const char *text, char ***out, size_t *count)
{
	const char *line = text;

	while (line && *line) {
		const char *end = strchr(line, '\n');
		const char *stop = end ? end : line + strlen(line);
		const char *at = line;
		char        prefix[NCFG_ADDRESS_MAX];
		size_t      length = 0;

		while (at < stop && (*at == ' ' || *at == '\t')) {
			at++;
		}
		if ((size_t)(stop - at) > strlen("prefix ") &&
		    strncmp(at, "prefix ", strlen("prefix ")) == 0) {
			at += strlen("prefix ");
			while (at < stop && (*at == ' ' || *at == '\t')) {
				at++;
			}
			while (at < stop && length + 1u < sizeof(prefix) &&
			    (unsigned char)*at > ' ') {
				prefix[length++] = *at++;
			}
			prefix[length] = '\0';
			/*
			 * A prefix that did not fit is left out rather than truncated
			 * into a shorter one: a truncated block compares unequal to what
			 * the policy wants and would plan a reload for ever, which is the
			 * failure this pass exists to close rather than to cause.
			 */
			if (length != 0u && length + 1u < sizeof(prefix) &&
			    !observe_list_add(out, count, prefix)) {
				return 0;
			}
		}
		line = end ? end + 1 : NULL;
	}
	return 1;
}

int ncfg_observe_advertised(ncfg_observed_t *observed, const char *run_dir, char *err,
    size_t err_size)
{
	size_t at;

	if (!observed || !run_dir || !run_dir[0]) {
		ncfg_error_set(err, err_size,
		    "an advertisement round needs an observation and the run directory the "
		    "daemons were started under");
		return 0;
	}
	for (at = 0; at < observed->backend_count; at++) {
		ncfg_observed_backend_t *backend = &observed->backends[at];
		char                     path[NCFG_RA_PATH_MAX];
		char                   **found = NULL;
		size_t                   count = 0;
		char                    *text;

		if (backend->kind != NCFG_BACKEND_ROUTER_ADVERT || !backend->running ||
		    !backend->interface) {
			continue;
		}
		if (!ncfg_ra_config_path(run_dir, backend->interface, path, sizeof(path), NULL, 0)) {
			continue;
		}
		text = read_config(path);
		if (!text) {
			continue;
		}
		if (!prefixes_of(text, &found, &count)) {
			free(text);
			observe_names_free(found, count);
			ncfg_error_set(err, err_size,
			    "out of memory reading what %s is advertising", backend->interface);
			return 0;
		}
		free(text);
		/*
		 * Replaced rather than appended, and only where something was found:
		 * a configuration with no `prefix` line at all leaves the list as it
		 * was, which is empty, which is the "cannot tell" the planner does
		 * nothing about -- and is right, because `ncfg_ra_start` refuses to
		 * start a daemon with no prefix, so a generated file without one is a
		 * file netcfgd did not write.
		 */
		if (count == 0u) {
			observe_names_free(found, count);
			continue;
		}
		observe_names_free(backend->advertised, backend->advertised_count);
		backend->advertised = found;
		backend->advertised_count = count;
	}
	return 1;
}
