/*
 * state_report.c -- what something that is not netcfgd says an interface was given.
 *
 * THE FORMAT IS A DOCUMENTED CONTRACT
 *   `doc/interface-report.md` is the whole of it, and 0045 says why the writer
 *   is deliberately plural. Changing what is parsed here changes what somebody
 *   else's script has to write, so the tests in `state_test.c` carry the
 *   document's own example verbatim: if the two ever disagree, the document is
 *   right -- it is what somebody wrote their helper against.
 *
 *   Named `reported` rather than `modem` because a modem helper was merely the
 *   first writer; 0047 has the argument for taking the name off it.
 */
#include "ncfg/state.h"

#include "host_internal.h"
#include "ncfg/base.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

/*
 * A report is a handful of addresses and nameservers. This is four orders of
 * magnitude more than any helper writes, and it is a ceiling because the
 * writer is somebody else's program: a daemon that reads whatever it is handed
 * is a daemon that program can exhaust.
 */
#define REPORT_MAX (256u * 1024u)

/* One prefix per line, and a delegation is one lease's worth. */
#define DELEGATION_MAX (64u * 1024u)

/* Everything one interface reported, in the order it applies. */
typedef struct {
	char  *interface;
	char **bodies;
	size_t body_count;
	size_t body_capacity;
} gathered_t;

static void gathered_free(gathered_t *at, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		free(at[i].interface);
		ncfg_host_strings_free(at[i].bodies, at[i].body_count);
	}
	free(at);
}

static gathered_t *gathered_for(gathered_t **at, size_t *count, size_t *capacity,
    const char *interface)
{
	size_t i;

	for (i = 0; i < *count; i++) {
		if (strcmp((*at)[i].interface, interface) == 0) {
			return &(*at)[i];
		}
	}
	if (*count == *capacity) {
		size_t want = *capacity ? *capacity * 2u : 8u;
		gathered_t *grown = realloc(*at, want * sizeof(*grown));

		if (!grown) {
			return NULL;
		}
		*at = grown;
		*capacity = want;
	}
	memset(&(*at)[*count], 0, sizeof((*at)[*count]));
	(*at)[*count].interface = strdup(interface);
	if (!(*at)[*count].interface) {
		return NULL;
	}
	return &(*at)[(*count)++];
}

static int by_interface(const void *one, const void *other)
{
	const gathered_t *a = one;
	const gathered_t *b = other;

	return strcmp(a->interface, b->interface);
}

/* ------------------------------------------------------------- the parsing */

/* Both ends, in place: a leading tab and a trailing space are what a helper
 * writing `\t address = 10.0.0.1/32 \t` leaves, and the document says they do
 * not matter. */
static char *trim(char *text)
{
	size_t length;

	while (*text == ' ' || *text == '\t' || *text == '\r') {
		text++;
	}
	length = strlen(text);
	while (length && (text[length - 1u] == ' ' || text[length - 1u] == '\t' ||
	    text[length - 1u] == '\r')) {
		text[--length] = '\0';
	}
	return text;
}

/*
 * `<destination>` or `<destination> via <gateway>`.
 *
 * Deliberately the spelling a `routes` line in a configuration file already
 * uses, so that somebody reading a report and somebody reading a config are
 * reading the same thing. **Nothing else is accepted**: a metric belongs to
 * netcfgd rather than to the writer, and an unrecognised tail is a line the
 * writer thought meant something, which is worse to half-apply than to skip --
 * `metric 50` silently ignored would be a route with a metric netcfgd chose
 * and an operator thought they had.
 */
static int parse_route(char *value, ncfg_reported_route_t *out)
{
	char *save = NULL;
	char *destination = strtok_r(value, " \t", &save);
	char *word = destination ? strtok_r(NULL, " \t", &save) : NULL;
	char *gateway = NULL;

	memset(out, 0, sizeof(*out));
	if (!destination) {
		return 0;
	}
	if (word) {
		if (strcmp(word, "via") != 0) {
			return 0;
		}
		gateway = strtok_r(NULL, " \t", &save);
		if (!gateway) {
			return 0;
		}
		/* Anything after the gateway is a word this contract does not define. */
		if (strtok_r(NULL, " \t", &save)) {
			return 0;
		}
	}
	out->destination = strdup(destination);
	if (!out->destination) {
		return 0;
	}
	if (gateway) {
		out->via = strdup(gateway);
		if (!out->via) {
			free(out->destination);
			out->destination = NULL;
			return 0;
		}
	}
	return 1;
}

static int add_route(ncfg_observed_report_t *report, char *value)
{
	ncfg_reported_route_t one;
	ncfg_reported_route_t *grown;

	if (!parse_route(value, &one)) {
		/* Skipped, not refused: the rest of the report is still worth having. */
		return 1;
	}
	grown = realloc(report->routes, (report->route_count + 1u) * sizeof(*grown));
	if (!grown) {
		free(one.destination);
		free(one.via);
		return 0;
	}
	report->routes = grown;
	report->routes[report->route_count++] = one;
	return 1;
}

int ncfg_state_parse_report(const char *interface, const char *body, size_t length,
    ncfg_observed_report_t *out, char *err, size_t err_size)
{
	char *work;
	char *line;
	char *save = NULL;
	size_t address_capacity = 0;
	size_t gateway_capacity = 0;
	size_t nameserver_capacity = 0;
	size_t search_capacity = 0;
	int ok = 1;

	if (!out) {
		ncfg_error_set(err, err_size, "a report was parsed into nothing");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	out->interface = strdup(interface ? interface : "");
	if (!out->interface) {
		ncfg_error_set(err, err_size, "out of memory reading a report");
		return 0;
	}
	work = malloc(length + 1u);
	if (!work) {
		ncfg_error_set(err, err_size, "out of memory reading a report");
		return 0;
	}
	if (length) {
		memcpy(work, body, length);
	}
	work[length] = '\0';

	for (line = strtok_r(work, "\n", &save); line && ok; line = strtok_r(NULL, "\n", &save)) {
		char *equals;
		char *key;
		char *value;

		/*
		 * No `#` branch, deliberately. A comment is ignored because its key
		 * does not match -- `#dns=8.8.8.8` has the key `#dns` -- and a branch
		 * testing for `#` on top of that is one no input can make fire, which
		 * this project does not keep whatever it looks like it is guarding.
		 * The *guarantee* is pinned by the tests rather than by a line of
		 * code, so it survives however the matching is written.
		 */
		equals = strchr(line, '=');
		if (!equals) {
			continue;
		}
		*equals = '\0';
		key = trim(line);
		value = trim(equals + 1);
		if (!value[0]) {
			continue;
		}
		/* Kept as text and validated where it is used, which is how every
		 * other address in the observed model arrives. Parsing it here would
		 * put the refusal in the reader, where the operator cannot see which
		 * line of whose file was wrong. */
		if (strcmp(key, "address") == 0) {
			ok = ncfg_host_strings_add(&out->addresses, &out->address_count,
			    &address_capacity, value);
		} else if (strcmp(key, "gateway") == 0) {
			ok = ncfg_host_strings_add(&out->gateways, &out->gateway_count,
			    &gateway_capacity, value);
		} else if (strcmp(key, "dns") == 0) {
			ok = ncfg_host_strings_add(&out->nameservers, &out->nameserver_count,
			    &nameserver_capacity, value);
		} else if (strcmp(key, "search") == 0) {
			/* One suffix per line, like a nameserver. A writer with several
			 * has several lines, which is the shape every repeating key here
			 * has. */
			ok = ncfg_host_strings_add(&out->search, &out->search_count,
			    &search_capacity, value);
		} else if (strcmp(key, "iccid") == 0 || strcmp(key, "sim") == 0) {
			/* **Last writer wins, where every key above accumulates.** These
			 * two describe one card and one source rather than a list, and a
			 * report is rewritten whole each time -- so a second line is a
			 * writer correcting itself within one file, not a second card. */
			char **field = (key[0] == 'i') ? &out->iccid : &out->sim;
			char *copy = strdup(value);

			if (!copy) {
				ok = 0;
			} else {
				free(*field);
				*field = copy;
			}
		} else if (strcmp(key, "route") == 0) {
			/* The one key with a shape of its own, because a route needs two
			 * values and the contract will not make somebody number them. */
			ok = add_route(out, value);
		}
	}
	free(work);
	if (!ok) {
		ncfg_error_set(err, err_size, "out of memory reading a report");
		return 0;
	}
	return 1;
}

void ncfg_state_report_free(ncfg_observed_report_t *report)
{
	size_t i;

	if (!report) {
		return;
	}
	free(report->interface);
	ncfg_host_strings_free(report->addresses, report->address_count);
	ncfg_host_strings_free(report->gateways, report->gateway_count);
	ncfg_host_strings_free(report->nameservers, report->nameserver_count);
	ncfg_host_strings_free(report->search, report->search_count);
	for (i = 0; i < report->route_count; i++) {
		free(report->routes[i].destination);
		free(report->routes[i].via);
	}
	free(report->routes);
	free(report->iccid);
	free(report->sim);
	memset(report, 0, sizeof(*report));
}

void ncfg_state_reports_free(ncfg_observed_report_t *reports, size_t count)
{
	size_t i;

	if (!reports) {
		return;
	}
	for (i = 0; i < count; i++) {
		ncfg_state_report_free(&reports[i]);
	}
	free(reports);
}

/* ------------------------------------------------------------- the reading */

/* Append one file's contents to what an interface has reported. Unreadable is
 * skipped rather than fatal. */
static int gather_file(gathered_t *into, const char *path)
{
	size_t length = 0;
	char *body = ncfg_host_read_file(path, &length, REPORT_MAX);
	int ok;

	if (!body) {
		return 1;
	}
	ok = ncfg_host_strings_add_bytes(&into->bodies, &into->body_count, &into->body_capacity,
	    body, length);
	free(body);
	return ok;
}

static int gather_single_files(const char *run_dir, gathered_t **at, size_t *count,
    size_t *capacity, char *err, size_t err_size)
{
	/* **Not spelled here twice.** `reported/` is where the contract's single
	 * file lives, and a reader that joined it for itself would be a second
	 * definition of where those files are -- which would work until one of the
	 * two moved. It is one string, in one function. */
	char *dir = ncfg_host_join(run_dir, "reported", err, err_size);
	DIR *open_dir;
	const struct dirent *found;
	int ok = 1;

	if (!dir) {
		return 0;
	}
	open_dir = opendir(dir);
	if (!open_dir) {
		free(dir);
		return 1;
	}
	while (ok && (found = readdir(open_dir)) != NULL) {
		gathered_t *into;
		char *path;

		if (strcmp(found->d_name, ".") == 0 || strcmp(found->d_name, "..") == 0 ||
		    ncfg_host_is_staging(found->d_name)) {
			continue;
		}
		path = ncfg_host_join(dir, found->d_name, err, err_size);
		if (!path) {
			ok = 0;
			break;
		}
		into = gathered_for(at, count, capacity, found->d_name);
		ok = into && gather_file(into, path);
		free(path);
	}
	(void)closedir(open_dir);
	free(dir);
	if (!ok) {
		ncfg_error_set(err, err_size, "out of memory reading the interface reports");
	}
	return ok;
}

static int gather_fragments(const char *run_dir, gathered_t **at, size_t *count,
    size_t *capacity, char *err, size_t err_size)
{
	char *dir = ncfg_host_join(run_dir, "reported.d", err, err_size);
	DIR *open_dir;
	const struct dirent *found;
	int ok = 1;

	if (!dir) {
		return 0;
	}
	open_dir = opendir(dir);
	if (!open_dir) {
		free(dir);
		return 1;
	}
	while (ok && (found = readdir(open_dir)) != NULL) {
		char *interface_dir;
		DIR *fragments;
		const struct dirent *one;
		char **names = NULL;
		size_t name_count = 0;
		size_t name_capacity = 0;
		size_t i;
		gathered_t *into;

		if (strcmp(found->d_name, ".") == 0 || strcmp(found->d_name, "..") == 0 ||
		    ncfg_host_is_staging(found->d_name)) {
			continue;
		}
		interface_dir = ncfg_host_join(dir, found->d_name, err, err_size);
		if (!interface_dir) {
			ok = 0;
			break;
		}
		fragments = opendir(interface_dir);
		if (!fragments) {
			free(interface_dir);
			continue;
		}
		while (ok && (one = readdir(fragments)) != NULL) {
			if (strcmp(one->d_name, ".") == 0 || strcmp(one->d_name, "..") == 0 ||
			    ncfg_host_is_staging(one->d_name)) {
				continue;
			}
			ok = ncfg_host_strings_add(&names, &name_count, &name_capacity, one->d_name);
		}
		(void)closedir(fragments);
		/* **Sorted**, because `readdir` order is the filesystem's and a
		 * nameserver list that changed order between boots would look like a
		 * change to anything comparing it. */
		ncfg_host_strings_sort_unique(names, &name_count);
		into = ok ? gathered_for(at, count, capacity, found->d_name) : NULL;
		for (i = 0; ok && into && i < name_count; i++) {
			char *path = ncfg_host_join(interface_dir, names[i], err, err_size);

			ok = path && gather_file(into, path);
			free(path);
		}
		ok = ok && into != NULL;
		ncfg_host_strings_free(names, name_count);
		free(interface_dir);
	}
	(void)closedir(open_dir);
	free(dir);
	if (!ok) {
		ncfg_error_set(err, err_size, "out of memory reading the interface reports");
	}
	return ok;
}

int ncfg_state_report_path(const char *run_dir, const char *interface, char *out,
    size_t out_size, char *err, size_t err_size)
{
	int written;

	if (!run_dir || !run_dir[0] || !interface || !interface[0] || !out || out_size == 0u) {
		ncfg_error_set(err, err_size,
		    "a report path needs a run directory and an interface to name");
		return 0;
	}
	/*
	 * A name with a separator in it would escape the directory the reader
	 * walks, which is the same guard every other path composer in this port
	 * applies. An interface name cannot contain one; a caller passing
	 * something that is not an interface name is the case this refuses.
	 */
	if (strchr(interface, '/') != NULL || strcmp(interface, ".") == 0 ||
	    strcmp(interface, "..") == 0) {
		ncfg_error_set(err, err_size,
		    "`%s` cannot name a report: it is not one path component", interface);
		return 0;
	}
	written = snprintf(out, out_size, "%s/reported/%s", run_dir, interface);
	if (written < 0 || (size_t)written >= out_size) {
		out[0] = '\0';
		ncfg_error_set(err, err_size, "the report path for %s does not fit in %zu bytes",
		    interface, out_size - 1u);
		return 0;
	}
	return 1;
}

int ncfg_state_read_reports(const char *run_dir, ncfg_observed_report_t **out, size_t *count_out,
    char *err, size_t err_size)
{
	gathered_t *at = NULL;
	size_t count = 0;
	size_t capacity = 0;
	ncfg_observed_report_t *reports = NULL;
	size_t i;
	int ok;

	if (!out || !count_out) {
		ncfg_error_set(err, err_size, "the reports were asked for with nowhere to put them");
		return 0;
	}
	*out = NULL;
	*count_out = 0;
	if (!run_dir) {
		return 1;
	}
	/* The single file first, then the fragments, which is the order they
	 * apply in. */
	ok = gather_single_files(run_dir, &at, &count, &capacity, err, err_size) &&
	    gather_fragments(run_dir, &at, &count, &capacity, err, err_size);
	if (ok && count) {
		qsort(at, count, sizeof(*at), by_interface);
		reports = calloc(count, sizeof(*reports));
		ok = reports != NULL;
	}
	for (i = 0; ok && i < count; i++) {
		ncfg_buf_t joined;
		size_t j;

		ncfg_buf_init(&joined, REPORT_MAX * 8u);
		for (j = 0; j < at[i].body_count; j++) {
			if (j) {
				ncfg_buf_add_char(&joined, '\n');
			}
			ncfg_buf_add_text(&joined, at[i].bodies[j]);
		}
		ok = !ncfg_buf_failed(&joined) &&
		    ncfg_state_parse_report(at[i].interface, ncfg_buf_text(&joined),
		    strlen(ncfg_buf_text(&joined)), &reports[i], err, err_size);
		ncfg_buf_free(&joined);
	}
	gathered_free(at, count);
	if (!ok) {
		ncfg_state_reports_free(reports, count);
		return 0;
	}
	*out = reports;
	*count_out = count;
	return 1;
}

/* ----------------------------------------------------------- delegations */

void ncfg_state_delegations_free(ncfg_delegation_t *delegations, size_t count)
{
	size_t i;

	if (!delegations) {
		return;
	}
	for (i = 0; i < count; i++) {
		free(delegations[i].interface);
		ncfg_host_strings_free(delegations[i].prefixes, delegations[i].prefix_count);
	}
	free(delegations);
}

static int by_delegation_interface(const void *one, const void *other)
{
	const ncfg_delegation_t *a = one;
	const ncfg_delegation_t *b = other;

	return strcmp(a->interface, b->interface);
}

int ncfg_state_read_delegations(const char *run_dir, ncfg_delegation_t **out, size_t *count_out,
    char *err, size_t err_size)
{
	char *dir;
	DIR *open_dir;
	const struct dirent *found;
	ncfg_delegation_t *delegations = NULL;
	size_t count = 0;
	size_t capacity = 0;
	int ok = 1;

	if (!out || !count_out) {
		ncfg_error_set(err, err_size,
		    "the delegations were asked for with nowhere to put them");
		return 0;
	}
	*out = NULL;
	*count_out = 0;
	if (!run_dir) {
		return 1;
	}
	dir = ncfg_host_join(run_dir, "prefixes", err, err_size);
	if (!dir) {
		return 0;
	}
	open_dir = opendir(dir);
	if (!open_dir) {
		/* No client has reported one, which is the state of every machine
		 * that is not a router. */
		free(dir);
		return 1;
	}
	while (ok && (found = readdir(open_dir)) != NULL) {
		char *path;
		char *body;
		size_t length = 0;
		size_t prefix_capacity = 0;
		ncfg_delegation_t one;
		char *line;
		char *save = NULL;

		if (strcmp(found->d_name, ".") == 0 || strcmp(found->d_name, "..") == 0 ||
		    /* Staged the same way, by the script netcfgd generates for
		     * odhcp6c (0113). */
		    ncfg_host_is_staging(found->d_name)) {
			continue;
		}
		path = ncfg_host_join(dir, found->d_name, err, err_size);
		if (!path) {
			ok = 0;
			break;
		}
		body = ncfg_host_read_file(path, &length, DELEGATION_MAX);
		free(path);
		if (!body) {
			continue;
		}
		memset(&one, 0, sizeof(one));
		one.interface = strdup(found->d_name);
		ok = one.interface != NULL;
		for (line = ok ? strtok_r(body, "\n", &save) : NULL; ok && line;
		    line = strtok_r(NULL, "\n", &save)) {
			char *text = trim(line);

			if (!text[0] || text[0] == '#') {
				continue;
			}
			ok = ncfg_host_strings_add(&one.prefixes, &one.prefix_count,
			    &prefix_capacity, text);
		}
		free(body);
		if (ok && count == capacity) {
			size_t want = capacity ? capacity * 2u : 8u;
			ncfg_delegation_t *grown = realloc(delegations, want * sizeof(*grown));

			if (!grown) {
				ok = 0;
			} else {
				delegations = grown;
				capacity = want;
			}
		}
		if (!ok) {
			free(one.interface);
			ncfg_host_strings_free(one.prefixes, one.prefix_count);
			break;
		}
		delegations[count++] = one;
	}
	(void)closedir(open_dir);
	free(dir);
	if (!ok) {
		ncfg_state_delegations_free(delegations, count);
		ncfg_error_set(err, err_size, "out of memory reading the delegated prefixes");
		return 0;
	}
	if (count) {
		qsort(delegations, count, sizeof(*delegations), by_delegation_interface);
	}
	*out = delegations;
	*count_out = count;
	return 1;
}
