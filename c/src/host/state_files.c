/*
 * state_files.c -- the desired document, its per-interface projections, and
 * the provenance table.
 *
 * HOW A PROJECTION IS MADE, AND WHY IT IS A SLICE
 *   Section 2 is explicit that the whole-host document is canonical and the
 *   per-interface files are "projections for convenience, not separate
 *   documents". The Rust serialises one `Interface` for each; here the only
 *   writer for an interface is the model's own field table, which is static to
 *   `src/model/document.c` -- and a second copy of it is exactly the
 *   duplication 0263 forbids.
 *
 *   So a projection is **the bytes of `interfaces[i]` out of the document this
 *   function has just rendered**. That is a format-level operation and not a
 *   second copy of the schema: it knows what a JSON string and a balanced
 *   brace are, and nothing about what an interface contains.
 *
 *   **Every slice carries its own proof.** A sliced element is parsed back and
 *   its `name` member compared against the interface it is supposed to be; a
 *   mismatch writes nothing and says so. A scanner that drifted by one byte
 *   would otherwise put a valid-looking file under the wrong interface's name,
 *   which is the one failure a projection must not have -- somebody reads
 *   `desired/eth0.json` precisely because they do not want to search the whole
 *   file.
 */
#include "ncfg/state.h"

#include "host_internal.h"
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/json_write.h"
#include "ncfg_json.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define STATE_FILE_MAX (16u * 1024u * 1024u)
#define STATE_BUILD_MAX (32u * 1024u * 1024u)

/* ------------------------------------------------------------ provenance */

void ncfg_provenance_free(ncfg_provenance_t *provenance)
{
	size_t i;

	if (!provenance) {
		return;
	}
	for (i = 0; i < provenance->count; i++) {
		free(provenance->entries[i].path);
		free(provenance->entries[i].file);
	}
	free(provenance->entries);
	memset(provenance, 0, sizeof(*provenance));
}

int ncfg_provenance_record(ncfg_provenance_t *provenance, const char *path, const char *file,
    int64_t line, int64_t column, char *err, size_t err_size)
{
	ncfg_provenance_entry_t *grown;
	char *path_copy;
	char *file_copy;

	if (!provenance || !path || !file) {
		ncfg_error_set(err, err_size, "a position was recorded for nothing");
		return 0;
	}
	grown = realloc(provenance->entries, (provenance->count + 1u) * sizeof(*grown));
	if (grown) {
		provenance->entries = grown;
	}
	path_copy = strdup(path);
	file_copy = strdup(file);
	if (!grown || !path_copy || !file_copy) {
		free(path_copy);
		free(file_copy);
		ncfg_error_set(err, err_size, "out of memory recording where a field came from");
		return 0;
	}
	provenance->entries[provenance->count].path = path_copy;
	provenance->entries[provenance->count].file = file_copy;
	provenance->entries[provenance->count].line = line;
	provenance->entries[provenance->count].column = column;
	provenance->count++;
	return 1;
}

const ncfg_provenance_entry_t *ncfg_provenance_lookup(const ncfg_provenance_t *provenance,
    const char *path)
{
	size_t i;

	if (!provenance || !path) {
		return NULL;
	}
	for (i = 0; i < provenance->count; i++) {
		if (strcmp(provenance->entries[i].path, path) == 0) {
			return &provenance->entries[i];
		}
	}
	return NULL;
}

void ncfg_provenance_location(const ncfg_provenance_entry_t *entry, char *out, size_t out_size)
{
	if (!out || !out_size) {
		return;
	}
	if (!entry) {
		out[0] = '\0';
		return;
	}
	(void)snprintf(out, out_size, "%s:%lld:%lld", entry->file, (long long)entry->line,
	    (long long)entry->column);
}

/*
 * By path, and by arrival where two entries share one.
 *
 * **The tie-break is the whole point.** `qsort` is not stable, and the rule
 * below -- the first entry for a path wins -- is a fact about the order the
 * compiler reached them in, which an unstable sort is free to destroy. Where
 * two records exist for one field the earlier is the base and the later the
 * override, so losing that order would make `ncfg explain` send a reader to
 * the file that was overridden rather than to the one that produced the value,
 * and it would do it differently on different libcs.
 *
 * What is sorted is an index of pointers into the entry array, and `qsort`
 * never moves that array -- only the index. So two pointers into it still say
 * which of the two arrived first, and the comparison is total without the
 * entry needing to carry a sequence number it has no other use for.
 */
static int by_path_then_arrival(const void *one, const void *other)
{
	const ncfg_provenance_entry_t *const *a = one;
	const ncfg_provenance_entry_t *const *b = other;
	int order = strcmp((*a)->path, (*b)->path);

	if (order != 0) {
		return order;
	}
	if (*a < *b) {
		return -1;
	}
	return *a > *b ? 1 : 0;
}

int ncfg_provenance_canonicalize(ncfg_provenance_t *provenance, char *err, size_t err_size)
{
	const ncfg_provenance_entry_t **order;
	ncfg_provenance_entry_t *sorted;
	size_t kept = 0;
	size_t i;

	if (!provenance) {
		ncfg_error_set(err, err_size, "nothing was given to canonicalize");
		return 0;
	}
	if (provenance->count < 2u) {
		return 1;
	}
	order = malloc(provenance->count * sizeof(*order));
	sorted = malloc(provenance->count * sizeof(*sorted));
	if (!order || !sorted) {
		free(order);
		free(sorted);
		ncfg_error_set(err, err_size, "out of memory ordering %zu recorded position(s)",
		    provenance->count);
		return 0;
	}
	for (i = 0; i < provenance->count; i++) {
		order[i] = &provenance->entries[i];
	}
	qsort(order, provenance->count, sizeof(*order), by_path_then_arrival);
	/* **The first entry for a path wins**, which is the Rust's `dedup_by`:
	 * where two records exist for one field the earlier one is the one the
	 * compiler reached first, and an explanation that named the later would
	 * send a reader to the override rather than to what produced the value. */
	for (i = 0; i < provenance->count; i++) {
		if (kept && strcmp(sorted[kept - 1u].path, order[i]->path) == 0) {
			free(order[i]->path);
			free(order[i]->file);
			continue;
		}
		sorted[kept++] = *order[i];
	}
	free(order);
	free(provenance->entries);
	provenance->entries = sorted;
	provenance->count = kept;
	return 1;
}

int ncfg_state_write_provenance(const char *run_dir, ncfg_provenance_t *provenance, char *err,
    size_t err_size)
{
	ncfg_buf_t buf;
	ncfg_json_writer_t writer;
	char *path;
	size_t i;
	int ok;

	if (!run_dir || !provenance) {
		ncfg_error_set(err, err_size, "the provenance was asked to be written to nowhere");
		return 0;
	}
	/* Sorted, so the file is stable across compiles for the same reason the
	 * document is: a table that reordered itself would make every `diff` of
	 * two runs look like a change. */
	if (!ncfg_provenance_canonicalize(provenance, err, err_size)) {
		return 0;
	}

	ncfg_buf_init(&buf, STATE_BUILD_MAX);
	ncfg_json_write_init(&writer, &buf);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_key(&writer, "entries");
	ncfg_json_write_array_begin(&writer);
	for (i = 0; i < provenance->count; i++) {
		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_member_string(&writer, "path", provenance->entries[i].path);
		ncfg_json_write_member_string(&writer, "file", provenance->entries[i].file);
		ncfg_json_write_member_int(&writer, "line", provenance->entries[i].line);
		ncfg_json_write_member_int(&writer, "column", provenance->entries[i].column);
		ncfg_json_write_object_end(&writer);
	}
	ncfg_json_write_array_end(&writer);
	ncfg_json_write_object_end(&writer);
	if (!ncfg_json_write_done(&writer)) {
		ncfg_error_set(err, err_size, "the provenance could not be built: %s",
		    ncfg_json_write_failure(&writer) ? ncfg_json_write_failure(&writer)
		    : "it did not fit");
		ncfg_buf_free(&buf);
		return 0;
	}
	path = ncfg_host_join(run_dir, "provenance.json", err, err_size);
	if (!path) {
		ncfg_buf_free(&buf);
		return 0;
	}
	ok = ncfg_write_atomically(path, ncfg_buf_text(&buf), strlen(ncfg_buf_text(&buf)),
	    NCFG_RUN_FILE_MODE, err, err_size);
	free(path);
	ncfg_buf_free(&buf);
	return ok;
}

int ncfg_state_read_provenance(const char *run_dir, ncfg_provenance_t *out, char *err,
    size_t err_size)
{
	char *path;
	char *text;
	size_t length = 0;
	ncfg_json_doc_t *doc;
	uint32_t entries;
	uint32_t i;
	int ok = 1;

	if (!out) {
		ncfg_error_set(err, err_size, "the provenance was asked for with nowhere to put it");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!run_dir) {
		return 1;
	}
	path = ncfg_host_join(run_dir, "provenance.json", err, err_size);
	if (!path) {
		return 0;
	}
	text = ncfg_host_read_file(path, &length, STATE_FILE_MAX);
	free(path);
	if (!text) {
		/* **An explanation without file positions is still worth printing**,
		 * so absent and unreadable are both empty here and neither is said out
		 * loud -- unlike the ownership record, nothing is forgotten that
		 * decides whether netcfgd may remove something. */
		return 1;
	}
	doc = ncfg_json_parse(text, length, NULL, 0);
	free(text);
	if (!doc) {
		return 1;
	}
	entries = ncfg_json_member(doc, ncfg_json_root(doc), "entries");
	for (i = 0; ok && entries != NCFG_JSON_NONE && i < ncfg_json_count(doc, entries); i++) {
		uint32_t element = ncfg_json_at(doc, entries, i);
		size_t path_length = 0;
		size_t file_length = 0;
		const char *entry_path = ncfg_json_string(doc,
		    ncfg_json_member(doc, element, "path"), &path_length);
		const char *entry_file = ncfg_json_string(doc,
		    ncfg_json_member(doc, element, "file"), &file_length);
		char *path_copy;
		char *file_copy;

		if (!entry_path || !entry_file) {
			continue;
		}
		path_copy = malloc(path_length + 1u);
		file_copy = malloc(file_length + 1u);
		if (!path_copy || !file_copy) {
			free(path_copy);
			free(file_copy);
			ok = 0;
			break;
		}
		memcpy(path_copy, entry_path, path_length);
		path_copy[path_length] = '\0';
		memcpy(file_copy, entry_file, file_length);
		file_copy[file_length] = '\0';
		ok = ncfg_provenance_record(out, path_copy, file_copy,
		    ncfg_json_int(doc, ncfg_json_member(doc, element, "line"), 0),
		    ncfg_json_int(doc, ncfg_json_member(doc, element, "column"), 0), err, err_size);
		free(path_copy);
		free(file_copy);
	}
	ncfg_json_free(doc);
	if (!ok) {
		ncfg_provenance_free(out);
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------ the slicer */

static const char *skip_ws(const char *at)
{
	while (*at == ' ' || *at == '\t' || *at == '\n' || *at == '\r') {
		at++;
	}
	return at;
}

/* Past a string literal, whose opening quote `at` points at. NULL where it
 * does not end -- which cannot happen in bytes this module just wrote, and is
 * checked because a scanner that runs off the end of a buffer is worse than
 * one that refuses. */
static const char *skip_string(const char *at)
{
	at++;
	while (*at) {
		if (*at == '\\') {
			if (!at[1]) {
				return NULL;
			}
			at += 2;
			continue;
		}
		if (*at == '"') {
			return at + 1;
		}
		at++;
	}
	return NULL;
}

static const char *skip_value(const char *at)
{
	at = skip_ws(at);
	if (*at == '"') {
		return skip_string(at);
	}
	if (*at == '{' || *at == '[') {
		char close = (*at == '{') ? '}' : ']';
		int object = *at == '{';

		at = skip_ws(at + 1);
		if (*at == close) {
			return at + 1;
		}
		for (;;) {
			if (object) {
				at = skip_ws(at);
				if (*at != '"') {
					return NULL;
				}
				at = skip_string(at);
				if (!at) {
					return NULL;
				}
				at = skip_ws(at);
				if (*at != ':') {
					return NULL;
				}
				at++;
			}
			at = skip_value(at);
			if (!at) {
				return NULL;
			}
			at = skip_ws(at);
			if (*at == ',') {
				at++;
				continue;
			}
			if (*at == close) {
				return at + 1;
			}
			return NULL;
		}
	}
	/* A number, `true`, `false` or `null`: everything up to the next
	 * separator. */
	while (*at && *at != ',' && *at != '}' && *at != ']' && *at != ' ' && *at != '\t' &&
	    *at != '\n' && *at != '\r') {
		at++;
	}
	return at;
}

/* The value of `name` in the object `at` points at, or NULL. */
static const char *member_value(const char *at, const char *name)
{
	size_t want = strlen(name);

	at = skip_ws(at);
	if (*at != '{') {
		return NULL;
	}
	at = skip_ws(at + 1);
	while (*at == '"') {
		const char *key = at + 1;
		const char *after = skip_string(at);
		size_t length;

		if (!after) {
			return NULL;
		}
		length = (size_t)(after - key) - 1u;
		at = skip_ws(after);
		if (*at != ':') {
			return NULL;
		}
		at = skip_ws(at + 1);
		if (length == want && memcmp(key, name, want) == 0) {
			return at;
		}
		at = skip_value(at);
		if (!at) {
			return NULL;
		}
		at = skip_ws(at);
		if (*at != ',') {
			return NULL;
		}
		at = skip_ws(at + 1);
	}
	return NULL;
}

/* ------------------------------------------------------ the desired document */

/*
 * Remove the projections that are there now.
 *
 * **By suffix, in a directory this function built**, and never by a pattern
 * handed in: the directory is `<run_dir>/desired`, `run_dir` has been checked
 * non-empty by the caller, and the only entries touched are those ending in
 * `.json`. An interface dropped from the configuration must not leave a file
 * claiming it is still configured -- principle 2 depends on what is in the run
 * directory being true, not merely once-true.
 */
static void remove_projections(const char *dir)
{
	DIR *open_dir = opendir(dir);
	const struct dirent *found;

	if (!open_dir) {
		return;
	}
	while ((found = readdir(open_dir)) != NULL) {
		size_t length = strlen(found->d_name);
		char *path;

		if (length < 6u || strcmp(found->d_name + length - 5u, ".json") != 0) {
			continue;
		}
		path = ncfg_host_join(dir, found->d_name, NULL, 0);
		if (path) {
			(void)unlink(path);
			free(path);
		}
	}
	(void)closedir(open_dir);
}

/* A name that may be a filename inside a directory this module owns. A
 * compiled document's interface names cannot fail this; a hand-built one's
 * could, and a path join with `../` in it would be a file written outside the
 * directory. */
static int usable_leaf(const char *name)
{
	return name && name[0] && name[0] != '.' && !strchr(name, '/');
}

int ncfg_state_write_desired(const char *run_dir, ncfg_document_t *document, char *err,
    size_t err_size)
{
	ncfg_buf_t buf;
	char *path;
	char *dir;
	const char *text;
	const char *array;
	size_t i;
	int ok;

	if (!run_dir || !run_dir[0] || !document) {
		ncfg_error_set(err, err_size, "the document was asked to be written to nowhere");
		return 0;
	}
	ncfg_buf_init(&buf, STATE_BUILD_MAX);
	if (!ncfg_document_write_canonical(document, &buf, err, err_size)) {
		ncfg_buf_free(&buf);
		return 0;
	}
	text = ncfg_buf_text(&buf);
	path = ncfg_host_join(run_dir, "desired.json", err, err_size);
	if (!path) {
		ncfg_buf_free(&buf);
		return 0;
	}
	ok = ncfg_write_atomically(path, text, strlen(text), NCFG_RUN_FILE_MODE, err, err_size);
	free(path);
	if (!ok) {
		ncfg_buf_free(&buf);
		return 0;
	}

	dir = ncfg_host_join(run_dir, "desired", err, err_size);
	if (!dir) {
		ncfg_buf_free(&buf);
		return 0;
	}
	remove_projections(dir);
	if (document->interface_count == 0u) {
		/* **No interfaces, no directory.** Section 4.6: the filesystem
		 * reflects use, not capability. */
		free(dir);
		ncfg_buf_free(&buf);
		return 1;
	}
	if (!ncfg_host_make_directory(dir, (mode_t)0755, err, err_size)) {
		free(dir);
		ncfg_buf_free(&buf);
		return 0;
	}
	array = member_value(text, "interfaces");
	if (!array || *array != '[') {
		/* A document with interfaces whose rendering has none is the scanner
		 * and the writer disagreeing, which is the case this refuses to guess
		 * its way through. */
		ncfg_error_set(err, err_size,
		    "the rendered document does not carry an interfaces list, so no "
		    "per-interface view could be written");
		free(dir);
		ncfg_buf_free(&buf);
		return 0;
	}
	array = skip_ws(array + 1);
	for (i = 0; ok && i < document->interface_count; i++) {
		const char *end = skip_value(array);
		ncfg_json_doc_t *slice;
		char *leaf;
		char *file;

		if (!end || end <= array) {
			ncfg_error_set(err, err_size,
			    "the rendered document ended before interface %zu", i);
			ok = 0;
			break;
		}
		/* **The proof.** The slice is parsed back and asked its own name; a
		 * scanner off by one byte writes nothing rather than a valid-looking
		 * file under the wrong interface's name. */
		slice = ncfg_json_parse(array, (size_t)(end - array), NULL, 0);
		if (!slice || !ncfg_json_string_equals(slice,
		    ncfg_json_member(slice, ncfg_json_root(slice), "name"),
		    document->interfaces[i].name)) {
			ncfg_json_free(slice);
			ncfg_error_set(err, err_size,
			    "the per-interface view of `%s` did not come back as itself, so "
			    "nothing was written for it",
			    document->interfaces[i].name ? document->interfaces[i].name : "");
			ok = 0;
			break;
		}
		ncfg_json_free(slice);
		if (!usable_leaf(document->interfaces[i].name)) {
			ncfg_error_set(err, err_size,
			    "`%s` cannot be a filename, so no per-interface view was written "
			    "for it",
			    document->interfaces[i].name ? document->interfaces[i].name : "");
			ok = 0;
			break;
		}
		{
			size_t leaf_size = strlen(document->interfaces[i].name) + 6u;

			leaf = malloc(leaf_size);
			if (!leaf) {
				ncfg_error_set(err, err_size, "out of memory");
				ok = 0;
				break;
			}
			(void)snprintf(leaf, leaf_size, "%s.json", document->interfaces[i].name);
		}
		file = ncfg_host_join(dir, leaf, err, err_size);
		free(leaf);
		if (!file) {
			ok = 0;
			break;
		}
		ok = ncfg_write_atomically(file, array, (size_t)(end - array),
		    NCFG_RUN_FILE_MODE, err, err_size);
		free(file);
		array = skip_ws(end);
		if (*array == ',') {
			array = skip_ws(array + 1);
		}
	}
	free(dir);
	ncfg_buf_free(&buf);
	return ok;
}

/*
 * One link and everything on it, as `<run>/observed/<name>.json`.
 *
 * **Built through the model's own writers rather than sliced out of the
 * whole-host rendering**, which is where this differs from the desired
 * projections above: those are one interface block each and *are* a slice of
 * `desired.json`, so slicing it and parsing the slice back proves they agree.
 * This one is three things joined -- the link, the addresses on it and the
 * routes on it -- and no slice of `observed.json` has that shape. So the three
 * element writers are published (`observed.h`) and used here, which is what
 * keeps a field added to the model from going missing out of this file.
 */
static int write_observed_projection(const char *dir, const ncfg_observed_t *observed,
    const ncfg_observed_link_t *link, char *err, size_t err_size)
{
	ncfg_buf_t         buf;
	ncfg_json_writer_t writer;
	char              *leaf;
	char              *file;
	size_t             leaf_size;
	size_t             at;
	int                ok;

	if (!usable_leaf(link->name)) {
		ncfg_error_set(err, err_size,
		    "`%s` cannot be a filename, so no per-link view was written for it",
		    link->name ? link->name : "");
		return 0;
	}
	ncfg_buf_init(&buf, 0u);
	ncfg_json_write_init(&writer, &buf);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_key(&writer, "link");
	ncfg_json_write_object_begin(&writer);
	ncfg_observed_link_write(&writer, link);
	ncfg_json_write_object_end(&writer);
	ncfg_json_write_key(&writer, "addresses");
	ncfg_json_write_array_begin(&writer);
	for (at = 0u; at < observed->address_count; at++) {
		if (!observed->addresses[at].interface ||
		    strcmp(observed->addresses[at].interface, link->name) != 0) {
			continue;
		}
		ncfg_json_write_object_begin(&writer);
		ncfg_observed_address_write(&writer, &observed->addresses[at]);
		ncfg_json_write_object_end(&writer);
	}
	ncfg_json_write_array_end(&writer);
	ncfg_json_write_key(&writer, "routes");
	ncfg_json_write_array_begin(&writer);
	for (at = 0u; at < observed->route_count; at++) {
		if (!observed->routes[at].interface ||
		    strcmp(observed->routes[at].interface, link->name) != 0) {
			continue;
		}
		ncfg_json_write_object_begin(&writer);
		ncfg_observed_route_write(&writer, &observed->routes[at]);
		ncfg_json_write_object_end(&writer);
	}
	ncfg_json_write_array_end(&writer);
	ncfg_json_write_object_end(&writer);
	if (!ncfg_json_write_done(&writer)) {
		const char *why = ncfg_json_write_failure(&writer);

		ncfg_error_set(err, err_size, "the per-link view of `%s` could not be written: %s",
		    link->name, why ? why : "it did not fit");
		ncfg_buf_free(&buf);
		return 0;
	}
	leaf_size = strlen(link->name) + 6u;
	leaf = malloc(leaf_size);
	if (!leaf) {
		ncfg_error_set(err, err_size, "out of memory");
		ncfg_buf_free(&buf);
		return 0;
	}
	(void)snprintf(leaf, leaf_size, "%s.json", link->name);
	file = ncfg_host_join(dir, leaf, err, err_size);
	free(leaf);
	if (!file) {
		ncfg_buf_free(&buf);
		return 0;
	}
	ok = ncfg_write_atomically(file, ncfg_buf_text(&buf), strlen(ncfg_buf_text(&buf)),
	    NCFG_RUN_FILE_MODE, err, err_size);
	free(file);
	ncfg_buf_free(&buf);
	return ok;
}

/*
 * Every link's own view, and nothing left over.
 *
 * Removed first, so a link that has gone does not leave a file claiming it is
 * still there -- principle 2 depends on what is in `/run` being true rather
 * than once-true. No links, no directory: section 4.6, the filesystem reflects
 * use rather than capability.
 *
 * A file that could not be written fails the call and is named. The whole-host
 * `observed.json` is on disk by then, which is the half that matters -- but a
 * reader that finds a per-link file has to be able to trust it, and refusing
 * is what keeps a half-written set from reading as a whole one.
 */
static int write_observed_projections(const char *run_dir, const ncfg_observed_t *observed,
    char *err, size_t err_size)
{
	char  *dir = ncfg_host_join(run_dir, "observed", err, err_size);
	size_t at;
	int    ok = 1;

	if (!dir) {
		return 0;
	}
	remove_projections(dir);
	if (observed->link_count == 0u) {
		free(dir);
		return 1;
	}
	if (!ncfg_host_make_directory(dir, (mode_t)0755, err, err_size)) {
		free(dir);
		return 0;
	}
	for (at = 0u; ok && at < observed->link_count; at++) {
		ok = write_observed_projection(dir, observed, &observed->links[at], err, err_size);
	}
	free(dir);
	return ok;
}

int ncfg_state_write_observed(const char *run_dir, ncfg_observed_t *observed, char *err,
    size_t err_size)
{
	ncfg_buf_t buf;
	char *path;
	int ok;

	if (!run_dir || !observed) {
		ncfg_error_set(err, err_size, "the observation was asked to be written to nowhere");
		return 0;
	}
	ncfg_buf_init(&buf, STATE_BUILD_MAX);
	if (!ncfg_observed_write_canonical(observed, &buf, err, err_size)) {
		ncfg_buf_free(&buf);
		return 0;
	}
	path = ncfg_host_join(run_dir, "observed.json", err, err_size);
	if (!path) {
		ncfg_buf_free(&buf);
		return 0;
	}
	ok = ncfg_write_atomically(path, ncfg_buf_text(&buf), strlen(ncfg_buf_text(&buf)),
	    NCFG_RUN_FILE_MODE, err, err_size);
	free(path);
	ncfg_buf_free(&buf);
	/* And one file per link, so a reader asking about `eth0` does not have to
	 * filter the whole-host view. After the whole file rather than before: the
	 * projections are a convenience and `observed.json` is the record, so a
	 * run directory that can hold only one of them holds that one. */
	return ok && write_observed_projections(run_dir, observed, err, err_size);
}
