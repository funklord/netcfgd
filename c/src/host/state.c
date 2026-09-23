/*
 * state.c -- the run directory: the record, the document and the provenance.
 *
 * See `state.h` for what is in the directory and what this build does not
 * carry yet. What is here is the reading and writing, and three decisions that
 * are defects rather than preferences: the boot stamp, the lock, and the
 * temporary file's name (which is in `host_util.c`, with the measurement in
 * `state.h`).
 *
 * WHY THE FILES ARE ONE LINE AND THE RUST'S ARE INDENTED
 *   `ncfg_json_write` is the socket's writer and writes one value on one line;
 *   the Rust uses `to_string_pretty` here. That is a property of the port
 *   rather than a choice of this module -- `ncfg_document_write` produces the
 *   same shape for every caller -- and it is written down here because
 *   somebody comparing `/run/netcfgd/owned.json` between a Rust netcfgd and a
 *   C one will see it first.
 */
#include "ncfg/state.h"

#include "host_internal.h"
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/json_write.h"
#include "ncfg/lock.h"
#include "ncfg/log.h"
#include "ncfg/value.h"
#include "ncfg_json.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Every file this module reads is one netcfgd wrote. A record past this is a
 * fault rather than content. */
#define STATE_FILE_MAX (16u * 1024u * 1024u)

/* The ceiling on what this module builds. A document is the big one and
 * `ncfg_document_write` is bounded by its own caller; this is the buffer
 * around it. */
#define STATE_BUILD_MAX (32u * 1024u * 1024u)

const char *ncfg_state_resolve_dir(const char *explicit_dir, char *out, size_t out_size)
{
	const char *from_environment;

	if (!out || !out_size) {
		return NCFG_RUN_DIR_DEFAULT;
	}
	if (explicit_dir && explicit_dir[0]) {
		(void)snprintf(out, out_size, "%s", explicit_dir);
		return out;
	}
	from_environment = getenv(NCFG_RUN_DIR_ENV);
	(void)snprintf(out, out_size, "%s",
	    (from_environment && from_environment[0]) ? from_environment : NCFG_RUN_DIR_DEFAULT);
	return out;
}

int ncfg_write_atomically(const char *path, const void *bytes, size_t length, unsigned int mode,
    char *err, size_t err_size)
{
	return ncfg_host_write_atomically(path, bytes, length, (mode_t)mode, err, err_size);
}

char *ncfg_state_boot_id(void)
{
	size_t length = 0;
	char *text = ncfg_host_read_file("/proc/sys/kernel/random/boot_id", &length, 4096u);

	if (!text) {
		return NULL;
	}
	while (length && (text[length - 1u] == '\n' || text[length - 1u] == ' ' ||
	    text[length - 1u] == '\t' || text[length - 1u] == '\r')) {
		text[--length] = '\0';
	}
	if (!length) {
		free(text);
		return NULL;
	}
	return text;
}

/* ------------------------------------------------------------ the record */

void ncfg_owned_free(ncfg_owned_state_t *owned)
{
	size_t i;

	if (!owned) {
		return;
	}
	free(owned->boot);
	ncfg_host_strings_free(owned->created_links, owned->created_link_count);
	for (i = 0; i < owned->address_count; i++) {
		free(owned->addresses[i].interface);
		free(owned->addresses[i].key);
	}
	free(owned->addresses);
	for (i = 0; i < owned->route_count; i++) {
		free(owned->routes[i].interface);
		free(owned->routes[i].key);
	}
	free(owned->routes);
	ncfg_observed_backends_free(owned->backends, owned->backend_count);
	for (i = 0; i < owned->backend_restart_count; i++) {
		free(owned->backend_restarts[i].interface);
	}
	free(owned->backend_restarts);
	ncfg_applied_dns_free(owned->dns, owned->dns_count);
	ncfg_host_strings_free(owned->forwarding, owned->forwarding_count);
	ncfg_host_strings_free(owned->privacy, owned->privacy_count);
	ncfg_host_strings_free(owned->accept_ra, owned->accept_ra_count);
	for (i = 0; i < owned->hook_state_count; i++) {
		free(owned->hook_state[i].interface);
		free(owned->hook_state[i].value);
	}
	free(owned->hook_state);
	ncfg_host_strings_free(owned->qdisc, owned->qdisc_count);
	ncfg_host_strings_free(owned->ingress, owned->ingress_count);
	memset(owned, 0, sizeof(*owned));
}

int ncfg_owned_remember(char ***list, size_t *count, const char *interface, int ours)
{
	size_t i;
	size_t capacity;

	if (!list || !count || !interface) {
		return 0;
	}
	for (i = 0; i < *count; i++) {
		if (strcmp((*list)[i], interface) != 0) {
			continue;
		}
		free((*list)[i]);
		memmove(&(*list)[i], &(*list)[i + 1u], (*count - i - 1u) * sizeof(**list));
		(*count)--;
		break;
	}
	if (!ours) {
		return 1;
	}
	capacity = *count;
	return ncfg_host_strings_add(list, count, &capacity, interface);
}

int ncfg_owned_note_hook_state(ncfg_owned_state_t *owned, const char *interface, int phase,
    const char *value)
{
	size_t i;
	ncfg_observed_hook_state_t *grown;
	char *name;
	char *told;

	if (!owned || !interface || !value) {
		return 0;
	}
	for (i = 0; i < owned->hook_state_count; i++) {
		if (owned->hook_state[i].phase != phase ||
		    strcmp(owned->hook_state[i].interface, interface) != 0) {
			continue;
		}
		free(owned->hook_state[i].interface);
		free(owned->hook_state[i].value);
		memmove(&owned->hook_state[i], &owned->hook_state[i + 1u],
		    (owned->hook_state_count - i - 1u) * sizeof(*owned->hook_state));
		owned->hook_state_count--;
		break;
	}
	name = strdup(interface);
	told = strdup(value);
	grown = realloc(owned->hook_state,
	    (owned->hook_state_count + 1u) * sizeof(*owned->hook_state));
	if (grown) {
		/* The old array is gone whichever way this goes, so the record takes
		 * the new one before anything can return: a failure that left
		 * `hook_state` pointing at the freed one would be a use-after-free in
		 * the caller's cleanup rather than here. */
		owned->hook_state = grown;
	}
	if (!name || !told || !grown) {
		free(name);
		free(told);
		return 0;
	}
	owned->hook_state[owned->hook_state_count].interface = name;
	owned->hook_state[owned->hook_state_count].phase = phase;
	owned->hook_state[owned->hook_state_count].value = told;
	owned->hook_state_count++;
	return 1;
}

/* ------------------------------------------------------- the record, read */

/* The kind's word, looked up through the model's own table rather than a
 * second one here: a table tested only against the kinds somebody remembered
 * is a table with a vacuous pass in it. */
static int backend_kind_from_name(const char *word, int *out)
{
	int kind;

	for (kind = 0; kind < 64; kind++) {
		const char *name = ncfg_backend_kind_name(kind);

		if (!name) {
			break;
		}
		if (strcmp(name, word) == 0) {
			*out = kind;
			return 1;
		}
	}
	return 0;
}

static int origin_from_name(const char *word, int *out)
{
	int origin;

	for (origin = 0; origin < 64; origin++) {
		const char *name = ncfg_origin_name(origin);

		if (!name) {
			break;
		}
		if (strcmp(name, word) == 0) {
			*out = origin;
			return 1;
		}
	}
	return 0;
}

static int key_is(const ncfg_json_doc_t *doc, uint32_t node, const char *name)
{
	size_t length = 0;
	const char *key = ncfg_json_key(doc, node, &length);

	return key && length == strlen(name) && memcmp(key, name, length) == 0;
}

/* A JSON string as an owned C string, or NULL where the node is not one. */
static char *string_of(const ncfg_json_doc_t *doc, uint32_t node)
{
	size_t length = 0;
	const char *text = ncfg_json_string(doc, node, &length);
	char *copy;

	if (!text) {
		return NULL;
	}
	copy = malloc(length + 1u);
	if (!copy) {
		return NULL;
	}
	memcpy(copy, text, length);
	copy[length] = '\0';
	return copy;
}

static int read_strings(const ncfg_json_doc_t *doc, uint32_t node, char ***out, size_t *count)
{
	size_t capacity = 0;
	uint32_t i;

	if (ncfg_json_type(doc, node) != NCFG_JSON_ARRAY) {
		return 0;
	}
	for (i = 0; i < ncfg_json_count(doc, node); i++) {
		size_t length = 0;
		const char *text = ncfg_json_string(doc, ncfg_json_at(doc, node, i), &length);

		if (!text || !ncfg_host_strings_add_bytes(out, count, &capacity, text, length)) {
			return 0;
		}
	}
	return 1;
}

static int read_objects(const ncfg_json_doc_t *doc, uint32_t node, ncfg_owned_object_t **out,
    size_t *count)
{
	uint32_t i;

	if (ncfg_json_type(doc, node) != NCFG_JSON_ARRAY) {
		return 0;
	}
	if (ncfg_json_count(doc, node) == 0u) {
		return 1;
	}
	*out = calloc(ncfg_json_count(doc, node), sizeof(**out));
	if (!*out) {
		return 0;
	}
	for (i = 0; i < ncfg_json_count(doc, node); i++) {
		uint32_t element = ncfg_json_at(doc, node, i);
		const ncfg_json_node_t *object = ncfg_json_node(doc, element);
		uint32_t child;
		char *word;

		if (ncfg_json_type(doc, element) != NCFG_JSON_OBJECT) {
			return 0;
		}
		/* Three members and no others, which is the Rust's
		 * `deny_unknown_fields`: a record carrying a fourth was written by
		 * something this build does not understand, and guessing at it is how
		 * a downgrade adopts an object it cannot describe. */
		for (child = object->first_child; child != NCFG_JSON_NONE;
		    child = ncfg_json_node(doc, child)->next_sibling) {
			if (!key_is(doc, child, "interface") && !key_is(doc, child, "key") &&
			    !key_is(doc, child, "origin")) {
				return 0;
			}
		}
		(*out)[i].interface = string_of(doc, ncfg_json_member(doc, element, "interface"));
		(*out)[i].key = string_of(doc, ncfg_json_member(doc, element, "key"));
		word = string_of(doc, ncfg_json_member(doc, element, "origin"));
		if (!(*out)[i].interface || !(*out)[i].key || !word) {
			free(word);
			*count = i + 1u;
			return 0;
		}
		if (!origin_from_name(word, &(*out)[i].origin)) {
			free(word);
			*count = i + 1u;
			return 0;
		}
		free(word);
		*count = i + 1u;
	}
	return 1;
}

static int read_restarts(const ncfg_json_doc_t *doc, uint32_t node,
    ncfg_backend_restart_t **out, size_t *count)
{
	uint32_t i;

	if (ncfg_json_type(doc, node) != NCFG_JSON_ARRAY) {
		return 0;
	}
	if (ncfg_json_count(doc, node) == 0u) {
		return 1;
	}
	*out = calloc(ncfg_json_count(doc, node), sizeof(**out));
	if (!*out) {
		return 0;
	}
	for (i = 0; i < ncfg_json_count(doc, node); i++) {
		uint32_t element = ncfg_json_at(doc, node, i);
		uint32_t number;
		char *word;

		/* A list of a kind, an interface and a number. Positional, because
		 * that is what the Rust's tuple serialises to -- a reader that
		 * accepted an object here would accept something it refuses. */
		if (ncfg_json_type(doc, element) != NCFG_JSON_ARRAY ||
		    ncfg_json_count(doc, element) != 3u) {
			return 0;
		}
		word = string_of(doc, ncfg_json_at(doc, element, 0));
		if (!word || !backend_kind_from_name(word, &(*out)[i].kind)) {
			free(word);
			*count = i + 1u;
			return 0;
		}
		free(word);
		(*out)[i].interface = string_of(doc, ncfg_json_at(doc, element, 1));
		*count = i + 1u;
		number = ncfg_json_at(doc, element, 2);
		if (!(*out)[i].interface || ncfg_json_type(doc, number) != NCFG_JSON_NUMBER) {
			return 0;
		}
		(*out)[i].count = ncfg_json_int(doc, number, -1);
		if ((*out)[i].count < 0 || (*out)[i].count > 4294967295LL) {
			return 0;
		}
	}
	return 1;
}

static int read_hook_state(const ncfg_json_doc_t *doc, uint32_t node,
    ncfg_observed_hook_state_t **out, size_t *count)
{
	uint32_t i;

	if (ncfg_json_type(doc, node) != NCFG_JSON_ARRAY) {
		return 0;
	}
	if (ncfg_json_count(doc, node) == 0u) {
		return 1;
	}
	*out = calloc(ncfg_json_count(doc, node), sizeof(**out));
	if (!*out) {
		return 0;
	}
	for (i = 0; i < ncfg_json_count(doc, node); i++) {
		uint32_t element = ncfg_json_at(doc, node, i);
		const ncfg_json_node_t *object = ncfg_json_node(doc, element);
		uint32_t child;
		char *word;
		ncfg_hook_phase_t phase;

		if (ncfg_json_type(doc, element) != NCFG_JSON_OBJECT) {
			return 0;
		}
		for (child = object->first_child; child != NCFG_JSON_NONE;
		    child = ncfg_json_node(doc, child)->next_sibling) {
			if (!key_is(doc, child, "interface") && !key_is(doc, child, "phase") &&
			    !key_is(doc, child, "value")) {
				return 0;
			}
		}
		(*out)[i].interface = string_of(doc, ncfg_json_member(doc, element, "interface"));
		(*out)[i].value = string_of(doc, ncfg_json_member(doc, element, "value"));
		*count = i + 1u;
		word = string_of(doc, ncfg_json_member(doc, element, "phase"));
		if (!(*out)[i].interface || !(*out)[i].value || !word) {
			free(word);
			return 0;
		}
		/* Through `value.h`'s own table, which is the one the config language
		 * and the environment variable both use: a spelling that drifted
		 * between the two would be a record naming a phase no hook runs in. */
		if (!ncfg_hook_phase_from_name(word, &phase, NULL, 0)) {
			free(word);
			return 0;
		}
		free(word);
		(*out)[i].phase = (int)phase;
	}
	return 1;
}

/*
 * Every member `owned.json` may carry, in the order the Rust's derive writes
 * them.
 *
 * The whole set, which is the Rust's `deny_unknown_fields`: a member that is
 * not here was written by something this build does not understand, and
 * guessing at it is how a downgrade adopts a record it cannot describe. Two of
 * these -- `backends` and `dns` -- were listed here and read by nothing for
 * several waves; `state.h` says what that cost.
 */
static const char *const owned_members[] = { "boot", "created_links", "addresses", "routes",
	"backends", "backend_restarts", "dns", "forwarding", "privacy", "accept_ra", "hook_state",
	"qdisc", "ingress" };

static int read_owned_text(const char *text, size_t length, ncfg_owned_state_t *out)
{
	ncfg_json_doc_t *doc = ncfg_json_parse(text, length, NULL, 0);
	uint32_t root;
	const ncfg_json_node_t *object;
	uint32_t child;
	uint32_t member;
	int ok = 1;
	size_t i;

	if (!doc) {
		return 0;
	}
	root = ncfg_json_root(doc);
	object = ncfg_json_node(doc, root);
	if (!object || ncfg_json_type(doc, root) != NCFG_JSON_OBJECT) {
		ncfg_json_free(doc);
		return 0;
	}
	for (child = object->first_child; ok && child != NCFG_JSON_NONE;
	    child = ncfg_json_node(doc, child)->next_sibling) {
		int known = 0;

		for (i = 0; i < sizeof(owned_members) / sizeof(owned_members[0]); i++) {
			known = known || key_is(doc, child, owned_members[i]);
		}
		if (!known) {
			ok = 0;
		}
	}
	member = ncfg_json_member(doc, root, "boot");
	if (ok && member != NCFG_JSON_NONE) {
		out->boot = string_of(doc, member);
		ok = out->boot != NULL;
	}
	member = ncfg_json_member(doc, root, "created_links");
	if (ok && member != NCFG_JSON_NONE) {
		ok = read_strings(doc, member, &out->created_links, &out->created_link_count);
	}
	member = ncfg_json_member(doc, root, "addresses");
	if (ok && member != NCFG_JSON_NONE) {
		ok = read_objects(doc, member, &out->addresses, &out->address_count);
	}
	member = ncfg_json_member(doc, root, "routes");
	if (ok && member != NCFG_JSON_NONE) {
		ok = read_objects(doc, member, &out->routes, &out->route_count);
	}
	member = ncfg_json_member(doc, root, "backends");
	if (ok && member != NCFG_JSON_NONE) {
		/* The model's own table, through the call `observed.h` publishes for
		 * this file. A refusal here still hands back whatever it had read, so
		 * `ncfg_owned_free` below takes it apart. */
		ok = ncfg_observed_backends_read(doc, member, &out->backends, &out->backend_count,
		    NULL, 0);
	}
	member = ncfg_json_member(doc, root, "backend_restarts");
	if (ok && member != NCFG_JSON_NONE) {
		ok = read_restarts(doc, member, &out->backend_restarts,
		    &out->backend_restart_count);
	}
	member = ncfg_json_member(doc, root, "dns");
	if (ok && member != NCFG_JSON_NONE) {
		ok = ncfg_applied_dns_read(doc, member, &out->dns, &out->dns_count, NULL, 0);
	}
	member = ncfg_json_member(doc, root, "forwarding");
	if (ok && member != NCFG_JSON_NONE) {
		ok = read_strings(doc, member, &out->forwarding, &out->forwarding_count);
	}
	member = ncfg_json_member(doc, root, "privacy");
	if (ok && member != NCFG_JSON_NONE) {
		ok = read_strings(doc, member, &out->privacy, &out->privacy_count);
	}
	member = ncfg_json_member(doc, root, "accept_ra");
	if (ok && member != NCFG_JSON_NONE) {
		ok = read_strings(doc, member, &out->accept_ra, &out->accept_ra_count);
	}
	member = ncfg_json_member(doc, root, "hook_state");
	if (ok && member != NCFG_JSON_NONE) {
		ok = read_hook_state(doc, member, &out->hook_state, &out->hook_state_count);
	}
	member = ncfg_json_member(doc, root, "qdisc");
	if (ok && member != NCFG_JSON_NONE) {
		ok = read_strings(doc, member, &out->qdisc, &out->qdisc_count);
	}
	member = ncfg_json_member(doc, root, "ingress");
	if (ok && member != NCFG_JSON_NONE) {
		ok = read_strings(doc, member, &out->ingress, &out->ingress_count);
	}
	ncfg_json_free(doc);
	return ok;
}

int ncfg_owned_read(const char *run_dir, ncfg_owned_state_t *out, char *err, size_t err_size)
{
	char *path;
	char *text;
	size_t length = 0;

	if (!out) {
		ncfg_error_set(err, err_size, "the record was asked for with nowhere to put it");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!run_dir) {
		return 1;
	}
	path = ncfg_host_join(run_dir, "owned.json", err, err_size);
	if (!path) {
		return 0;
	}
	text = ncfg_host_read_file(path, &length, STATE_FILE_MAX);
	if (!text) {
		/* Absent is the ordinary case, on every machine before the first
		 * apply. */
		free(path);
		return 1;
	}
	if (!read_owned_text(text, length, out)) {
		ncfg_owned_free(out);
		/* **Absent and unreadable are treated the same and reported
		 * differently** (0189). Measured before this: the daemon started,
		 * stayed configured, and said nothing at all. */
		ncfg_log_emitf("state", NCFG_LOG_WARNING,
		    "%s is there and does not parse, so netcfgd is starting with no record of "
		    "what it owns: an address or route it configured earlier will read as "
		    "somebody else's and be left alone. Written by a newer netcfgd, most "
		    "likely. Removing the file makes this quiet; the record rebuilds on the "
		    "next apply", path);
	}
	free(text);

	/*
	 * **A record from a previous boot is not stale information, it is wrong
	 * information**: every object it names is gone, and anything that has
	 * taken the same name since would be adopted by a claim that never applied
	 * to it (0138).
	 *
	 * Both unknowns mean "do not judge". An absent field is a file written
	 * before this existed, and an unreadable `boot_id` is a kernel that does
	 * not expose one -- discarding on either would throw ownership away for a
	 * reason that has nothing to do with a reboot.
	 */
	if (out->boot && out->boot[0]) {
		char *now = ncfg_state_boot_id();

		if (now && strcmp(now, out->boot) != 0) {
			ncfg_log_emitf("state", NCFG_LOG_WARNING,
			    "the ownership record in %s was written during a different boot, so "
			    "it is being discarded; objects netcfgd installed before that reboot "
			    "are gone, and anything matching them now belongs to somebody else",
			    run_dir);
			ncfg_owned_free(out);
		}
		free(now);
	}
	free(path);
	return 1;
}

/* ------------------------------------------------------ the record, written */

static void write_strings(ncfg_json_writer_t *writer, const char *name, char *const *items,
    size_t count)
{
	size_t i;

	ncfg_json_write_key(writer, name);
	ncfg_json_write_array_begin(writer);
	for (i = 0; i < count; i++) {
		ncfg_json_write_string(writer, items[i] ? items[i] : "");
	}
	ncfg_json_write_array_end(writer);
}

static void write_objects(ncfg_json_writer_t *writer, const char *name,
    const ncfg_owned_object_t *items, size_t count)
{
	size_t i;

	ncfg_json_write_key(writer, name);
	ncfg_json_write_array_begin(writer);
	for (i = 0; i < count; i++) {
		const char *origin = ncfg_origin_name(items[i].origin);

		ncfg_json_write_object_begin(writer);
		ncfg_json_write_member_string(writer, "interface",
		    items[i].interface ? items[i].interface : "");
		ncfg_json_write_member_string(writer, "key", items[i].key ? items[i].key : "");
		/* A word outside the set is written as nothing rather than as a
		 * plausible one, which is `value.h`'s rule: the writer then refuses
		 * the whole file instead of putting a record in front of somebody
		 * that nobody wrote. */
		if (origin) {
			ncfg_json_write_member_string(writer, "origin", origin);
		}
		ncfg_json_write_object_end(writer);
	}
	ncfg_json_write_array_end(writer);
}

int ncfg_owned_write(const char *run_dir, const ncfg_owned_state_t *owned, char *err,
    size_t err_size)
{
	ncfg_buf_t buf;
	ncfg_json_writer_t writer;
	char *path;
	char *boot;
	size_t i;
	int ok;

	if (!run_dir || !owned) {
		ncfg_error_set(err, err_size, "the record was asked to be written to nowhere");
		return 0;
	}
	/* **Stamped on the way out rather than asked for by every caller**: a
	 * record that forgot to say which boot it belongs to is one the read
	 * cannot judge, and it would fail open. */
	boot = ncfg_state_boot_id();

	ncfg_buf_init(&buf, STATE_BUILD_MAX);
	ncfg_json_write_init(&writer, &buf);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "boot", boot ? boot : "");
	write_strings(&writer, "created_links", owned->created_links, owned->created_link_count);
	write_objects(&writer, "addresses", owned->addresses, owned->address_count);
	write_objects(&writer, "routes", owned->routes, owned->route_count);
	/* Through the model's tables, for the reason `owned_members` gives: the
	 * reader above and this writer are the same two calls pointed opposite
	 * ways, so a member added to either element type is added to both. */
	ncfg_json_write_key(&writer, "backends");
	ncfg_observed_backends_write(&writer, owned->backends, owned->backend_count);
	ncfg_json_write_key(&writer, "backend_restarts");
	ncfg_json_write_array_begin(&writer);
	for (i = 0; i < owned->backend_restart_count; i++) {
		const char *word = ncfg_backend_kind_name(owned->backend_restarts[i].kind);

		ncfg_json_write_array_begin(&writer);
		if (word) {
			ncfg_json_write_string(&writer, word);
		}
		ncfg_json_write_string(&writer, owned->backend_restarts[i].interface
		    ? owned->backend_restarts[i].interface : "");
		ncfg_json_write_int(&writer, owned->backend_restarts[i].count);
		ncfg_json_write_array_end(&writer);
	}
	ncfg_json_write_array_end(&writer);
	ncfg_json_write_key(&writer, "dns");
	ncfg_applied_dns_write(&writer, owned->dns, owned->dns_count);
	write_strings(&writer, "forwarding", owned->forwarding, owned->forwarding_count);
	write_strings(&writer, "privacy", owned->privacy, owned->privacy_count);
	write_strings(&writer, "accept_ra", owned->accept_ra, owned->accept_ra_count);
	ncfg_json_write_key(&writer, "hook_state");
	ncfg_json_write_array_begin(&writer);
	for (i = 0; i < owned->hook_state_count; i++) {
		const char *word = ncfg_hook_phase_name((ncfg_hook_phase_t)owned->hook_state[i].phase);

		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_member_string(&writer, "interface",
		    owned->hook_state[i].interface ? owned->hook_state[i].interface : "");
		if (word) {
			ncfg_json_write_member_string(&writer, "phase", word);
		}
		ncfg_json_write_member_string(&writer, "value",
		    owned->hook_state[i].value ? owned->hook_state[i].value : "");
		ncfg_json_write_object_end(&writer);
	}
	ncfg_json_write_array_end(&writer);
	write_strings(&writer, "qdisc", owned->qdisc, owned->qdisc_count);
	write_strings(&writer, "ingress", owned->ingress, owned->ingress_count);
	ncfg_json_write_object_end(&writer);
	free(boot);

	if (!ncfg_json_write_done(&writer)) {
		ncfg_error_set(err, err_size, "the ownership record could not be built: %s",
		    ncfg_json_write_failure(&writer) ? ncfg_json_write_failure(&writer)
		    : "it did not fit");
		ncfg_buf_free(&buf);
		return 0;
	}
	path = ncfg_host_join(run_dir, "owned.json", err, err_size);
	if (!path) {
		ncfg_buf_free(&buf);
		return 0;
	}
	/*
	 * 0666 is what an ordinary write opens with, so the umask still decides
	 * the mode exactly as it did before and this is not a permission change
	 * riding along inside something else. The record carries secret *digests*
	 * (0055), so tightening it is a decision to take deliberately rather than
	 * in passing.
	 */
	ok = ncfg_write_atomically(path, ncfg_buf_text(&buf), strlen(ncfg_buf_text(&buf)),
	    NCFG_RUN_FILE_MODE, err, err_size);
	free(path);
	ncfg_buf_free(&buf);
	return ok;
}

int ncfg_owned_update(const char *run_dir, int (*change)(ncfg_owned_state_t *owned, void *context),
    void *context, char *err, size_t err_size)
{
	char *path;
	ncfg_lock_t lock;
	ncfg_owned_state_t owned;
	int ok;

	if (!run_dir || !change) {
		ncfg_error_set(err, err_size, "the record was asked to be changed by nothing");
		return 0;
	}
	path = ncfg_host_join(run_dir, "owned.lock", err, err_size);
	if (!path) {
		return 0;
	}
	/*
	 * `ncfg_lock_take` is `sys/lock.c`'s and not a second flock here: two
	 * implementations of one lock is two answers to whether it blocks, and the
	 * only thing this record's safety rests on is that it does. **A failure to
	 * take it is returned rather than swallowed** -- carrying on unlocked is
	 * exactly the behaviour this function replaces.
	 */
	ncfg_lock_init(&lock);
	if (!ncfg_lock_take(&lock, path, err, err_size)) {
		free(path);
		return 0;
	}
	free(path);
	ok = ncfg_owned_read(run_dir, &owned, err, err_size);
	if (ok) {
		/* Returning 0 from the change abandons the update without writing,
		 * which is how a caller says "nothing to record after all". */
		ok = change(&owned, context);
		if (ok) {
			ok = ncfg_owned_write(run_dir, &owned, err, err_size);
		}
		ncfg_owned_free(&owned);
	}
	ncfg_lock_release(&lock);
	return ok;
}
