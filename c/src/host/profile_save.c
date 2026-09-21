/*
 * profile_save.c -- writing what the machine is running into a profile.
 *
 * The one profile operation that needs the renderer, which is why it is its
 * own file. `ncfg profile save` was a command before it was a function here,
 * which meant a machine with a gui could switch between profiles it already
 * had and never make one -- and a profile is most wanted on the machine
 * somebody is standing in front of.
 *
 * THE ORDER IS THE SAFETY PROPERTY
 *   The fold comes out of `conf.d` first, then the snapshot, then the
 *   selection, then the proof; and each step undoes on failure. What a failure
 *   has to put back includes the **selection**, which is the part that was
 *   missed: the cleanup removed the snapshot, the directory and the fold, and
 *   left the drop-in where it was written. So a save that reported "nothing
 *   was kept" had changed which profile the machine selects.
 *
 * WHY THERE IS JSON IN HERE
 *   Two of the steps need to compare documents, and one needs a copy of one
 *   with parts taken out. The Rust had `#[derive(PartialEq, Clone)]` for both;
 *   in C the document's own writer and reader are the only things that know
 *   its shape, so the comparison and the copy go through them rather than
 *   through a hand-written walk over fifty structs. `field.h` has the case
 *   that argues for this: `Document`'s equality was written field by field,
 *   `bluetooth` was missed for as long as the field existed, and `ncfg profile
 *   save` accepted a snapshot that did not reproduce the machine.
 *
 * THE COMPILES ARE COMPILES TO READ
 *   The base is compiled to learn which blocks exist -- an `override` on a
 *   block nothing defines is an error and its absence on one that is defined
 *   is a different one -- and the proof compiles the result to compare it.
 *   Both go through `ncfg_config_compile_for_reading` and its unwritten hook
 *   sink.
 *
 *   **The Rust's proof compile here still uses the refusing sink.** It is the
 *   one site the fix for that defect missed, and its effect is the shape the
 *   other two had: on a machine with a hook the proof cannot compile, so the
 *   save is refused with "would not reproduce what this machine is running ...
 *   That is a fault in the snapshot ... please report it" -- about a snapshot
 *   that is correct. The port uses the unwritten sink at both.
 */
#include "config_internal.h"
#include "host_internal.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/config.h"
#include "ncfg/json_write.h"
#include "ncfg/render.h"
#include "ncfg_json.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* The file a saved profile's rendering goes in. Its presence is also what
 * says netcfgd wrote the profile: a directory without one was written by hand
 * and saving over it would discard files this cannot reproduce. */
#define SNAPSHOT_LEAF "00-saved.conf"

/* ------------------------------------------------------------------------ *
 * Comparing and copying through the document's own JSON
 * ------------------------------------------------------------------------ */

/* The members of one object this copy leaves out. Bounded because `globals`
 * has nine members and a document that grew thirty-two would be a different
 * question; past the bound nothing is dropped, which refuses the save rather
 * than writing a snapshot nobody checked. */
typedef struct {
	char   keys[32][64];
	size_t count;
	int    overflowed;
} drop_list_t;

static int dropped(const drop_list_t *drop, const char *key)
{
	size_t i;

	for (i = 0; i < drop->count; i++) {
		if (strcmp(drop->keys[i], key) == 0) {
			return 1;
		}
	}
	return 0;
}

typedef struct {
	ncfg_json_writer_t *writer;
	uint32_t            filtered;
	const drop_list_t  *drop;
	int                 failed;
} copy_t;

static void copy_json(const ncfg_json_doc_t *doc, uint32_t node, copy_t *into)
{
	const ncfg_json_node_t *at = ncfg_json_node(doc, node);
	uint32_t                child;

	switch (ncfg_json_type(doc, node)) {
	case NCFG_JSON_NULL:
		ncfg_json_write_null(into->writer);
		return;
	case NCFG_JSON_BOOL:
		ncfg_json_write_bool(into->writer, ncfg_json_bool(doc, node, 0));
		return;
	case NCFG_JSON_NUMBER:
		ncfg_json_write_int(into->writer, ncfg_json_int(doc, node, 0));
		return;
	case NCFG_JSON_STRING: {
		size_t      length = 0;
		const char *text = ncfg_json_string(doc, node, &length);

		ncfg_json_write_string_bytes(into->writer, text ? text : "", length);
		return;
	}
	case NCFG_JSON_ARRAY:
		ncfg_json_write_array_begin(into->writer);
		for (child = at->first_child; child != NCFG_JSON_NONE;
		    child = ncfg_json_node(doc, child)->next_sibling) {
			copy_json(doc, child, into);
		}
		ncfg_json_write_array_end(into->writer);
		return;
	case NCFG_JSON_OBJECT:
		ncfg_json_write_object_begin(into->writer);
		for (child = at->first_child; child != NCFG_JSON_NONE;
		    child = ncfg_json_node(doc, child)->next_sibling) {
			char        key[64];
			size_t      length = 0;
			const char *name = ncfg_json_key(doc, child, &length);

			if (!name || length + 1u > sizeof(key)) {
				/* A member whose name this cannot carry is not silently
				 * left out: a snapshot missing a member is exactly the
				 * silent drop this whole module refuses. */
				into->failed = 1;
				continue;
			}
			memcpy(key, name, length);
			key[length] = '\0';
			if (node == into->filtered && into->drop && dropped(into->drop, key)) {
				continue;
			}
			/*
			 * **A null member is written as an absent one**, which is not a
			 * drop: the model writes `null` in exactly one situation, for a
			 * field whose Rust counterpart has no `skip_serializing_if` and
			 * whose value is absent, so the two spell the same thing. Saying
			 * it by leaving the member out keeps this copy readable by the
			 * reader that has to take it back, rather than depending on that
			 * reader accepting every spelling the writer can produce.
			 */
			if (ncfg_json_type(doc, child) == NCFG_JSON_NULL) {
				continue;
			}
			ncfg_json_write_key(into->writer, key);
			copy_json(doc, child, into);
		}
		ncfg_json_write_object_end(into->writer);
		return;
	default:
		into->failed = 1;
		return;
	}
}

/*
 * The running document with what the base already says taken out of `global`.
 *
 * **What the base already says is not the profile's to restate**, and for
 * `global` that is not a redundancy but a compile error: 0147 makes the block
 * a singleton whose sub-blocks merge, so a profile restating `control` is
 * `control` set twice. The consequence, unnoticed until a live test tried to
 * save on a machine configured the way that test must configure itself: a base
 * with `global { control { ... } }` -- which is every machine whose desktop
 * client can reach the daemon at all (0127) -- made the snapshot restate
 * `control`, and the save was refused with "`control` is already set in
 * `global`". `ncfg profile save` therefore did not work on the machines most
 * likely to run it.
 *
 * Clearing a part the base already carries identically leaves the *effective*
 * document unchanged, since the profile layers on the base and the base still
 * supplies it -- which is exactly what the proof below checks, and is why this
 * is a redundancy to drop rather than a decision about precedence. A part that
 * DIFFERS from the base is left alone and will still be refused; that case is
 * a profile carrying a `global` setting the base also sets to something else,
 * and the language has no way to say it (10.58).
 *
 * **Every member rather than a list of seven names**, which is the divergence.
 * The Rust names `dns`, `control`, `remote`, `hostname_policy`, `networking`,
 * `on_drift_default` and `confirm_default` one at a time, and a list that has
 * to agree with a struct and is maintained by hand does not stay agreeing --
 * `field.h` records that exact failure, in this exact function's caller, for
 * the field that was missed. Asking the members themselves cannot go stale.
 */
static ncfg_document_t *without_what_the_base_says(const ncfg_document_t *running,
    const ncfg_document_t *base, char *err, size_t err_size)
{
	ncfg_json_doc_t    *running_json = NULL;
	ncfg_json_doc_t    *base_json = NULL;
	ncfg_document_t    *out = NULL;
	ncfg_buf_t          rebuilt;
	ncfg_json_writer_t  writer;
	copy_t              into;
	drop_list_t         drop;
	char               *running_text;
	char               *base_text = NULL;
	char               *trimmed_text = NULL;
	size_t              running_length = 0;
	size_t              base_length = 0;
	size_t              trimmed_length = 0;
	uint32_t            running_globals;
	uint32_t            base_globals;
	uint32_t            child;

	running_text = ncfg_config_document_json(running, &running_length, err, err_size);
	if (!running_text) {
		return NULL;
	}
	/* **A base of nothing is not a special path.** It does not compile, so
	 * nothing it says can be called redundant and the drop list stays empty --
	 * but the copy still goes through the same rebuild, because the caller
	 * needs a document of its own and the rebuild is what makes one readable
	 * back. A second path here would be a second thing to be right. */
	if (base) {
		base_text = ncfg_config_document_json(base, &base_length, err, err_size);
		if (!base_text) {
			free(running_text);
			return NULL;
		}
		base_json = ncfg_json_parse(base_text, base_length, err, err_size);
		free(base_text);
	}
	running_json = ncfg_json_parse(running_text, running_length, err, err_size);
	free(running_text);
	if (!running_json || (base && !base_json)) {
		ncfg_json_free(running_json);
		ncfg_json_free(base_json);
		return NULL;
	}

	memset(&drop, 0, sizeof(drop));
	running_globals = ncfg_json_member(running_json, ncfg_json_root(running_json), "globals");
	base_globals = base_json ? ncfg_json_member(base_json, ncfg_json_root(base_json), "globals")
	    : NCFG_JSON_NONE;
	if (running_globals != NCFG_JSON_NONE && base_globals != NCFG_JSON_NONE) {
		for (child = ncfg_json_node(running_json, running_globals)->first_child;
		    child != NCFG_JSON_NONE;
		    child = ncfg_json_node(running_json, child)->next_sibling) {
			char        key[64];
			size_t      length = 0;
			const char *name = ncfg_json_key(running_json, child, &length);
			uint32_t    theirs;

			if (!name || length + 1u > sizeof(key)) {
				continue;
			}
			memcpy(key, name, length);
			key[length] = '\0';
			theirs = ncfg_json_member(base_json, base_globals, key);
			if (theirs == NCFG_JSON_NONE ||
			    !ncfg_config_json_same(running_json, child, base_json, theirs)) {
				continue;
			}
			if (drop.count >= sizeof(drop.keys) / sizeof(drop.keys[0])) {
				drop.overflowed = 1;
				break;
			}
			(void)snprintf(drop.keys[drop.count], sizeof(drop.keys[0]), "%s", key);
			drop.count++;
		}
	}

	ncfg_buf_init(&rebuilt, 4u * 1024u * 1024u);
	ncfg_json_write_init(&writer, &rebuilt);
	into.writer = &writer;
	into.filtered = running_globals;
	into.drop = &drop;
	into.failed = 0;
	copy_json(running_json, ncfg_json_root(running_json), &into);
	if (into.failed || drop.overflowed || ncfg_json_write_failed(&writer) ||
	    ncfg_buf_failed(&rebuilt)) {
		ncfg_error_set(err, err_size,
		    "this configuration could not be prepared for saving, so nothing was kept");
	} else {
		trimmed_text = ncfg_buf_take(&rebuilt, &trimmed_length);
	}
	ncfg_buf_free(&rebuilt);
	ncfg_json_free(running_json);
	ncfg_json_free(base_json);
	if (!trimmed_text) {
		return NULL;
	}
	out = ncfg_document_read(trimmed_text, trimmed_length, err, err_size);
	free(trimmed_text);
	return out;
}

/* ------------------------------------------------------------------------ *
 * Saving
 * ------------------------------------------------------------------------ */

/* Which blocks the base still defines, now that the fold is out of it.
 * `override` on a block nothing defines is a compile error, and its absence on
 * one that is defined is a different one -- so this is not a detail the
 * renderer can guess. */
static int collect_overrides(const ncfg_document_t *base, ncfg_overrides_t *overrides, char *err,
    size_t err_size)
{
	size_t i;

	if (!base) {
		return 1;
	}
	for (i = 0; i < base->interface_count; i++) {
		if (!ncfg_overrides_add(overrides, "interface", base->interfaces[i].name, err,
		    err_size)) {
			return 0;
		}
	}
	for (i = 0; i < base->network_count; i++) {
		if (!ncfg_overrides_add(overrides, "network", base->networks[i].id, err,
		    err_size)) {
			return 0;
		}
	}
	for (i = 0; i < base->device_count; i++) {
		if (!ncfg_overrides_add(overrides, "device", base->devices[i].name, err,
		    err_size)) {
			return 0;
		}
	}
	/* Added when the renderer learned bluetooth. A block the base defines and
	 * the snapshot restates needs `override` exactly as an interface does;
	 * without it the save was refused for a redefinition, which is the
	 * renderer's new capability defeated by a list that had not moved. */
	for (i = 0; i < base->bluetooth_count; i++) {
		if (!ncfg_overrides_add(overrides, "bluetooth", base->bluetooth[i].id, err,
		    err_size)) {
			return 0;
		}
	}
	return 1;
}

/* The half of the save that can fail with something to undo. */
static int write_profile_snapshot(const char *config_dir, const char *factory_dir,
    const char *name, const ncfg_document_t *running, const char *directory,
    const char *snapshot, int *denied, char *err, size_t err_size)
{
	ncfg_config_sources_t sources = { 0 };
	ncfg_document_t      *base = NULL;
	ncfg_document_t      *to_write = NULL;
	ncfg_document_t      *after = NULL;
	ncfg_overrides_t      overrides;
	ncfg_unrenderable_t   missing;
	ncfg_buf_t            text;
	char                  quiet[NCFG_ERROR_MAX];
	char                  where[NCFG_ERROR_MAX];
	int                   ok = 0;

	ncfg_overrides_init(&overrides);
	ncfg_unrenderable_init(&missing);
	ncfg_buf_init(&text, NCFG_CONFIG_FILE_MAX);

	/* The base as it is now, with the fold already taken out of it. It not
	 * compiling is not fatal here: the proof at the end is what decides, and
	 * a base nothing can be learned from simply contributes no overrides. */
	if (ncfg_config_load_layered(factory_dir, config_dir, &sources, quiet, sizeof(quiet))) {
		base = ncfg_config_compile_for_reading(&sources, quiet, sizeof(quiet));
	}
	ncfg_config_sources_free(&sources);

	if (!collect_overrides(base, &overrides, err, err_size)) {
		goto done;
	}
	to_write = without_what_the_base_says(running, base, err, err_size);
	if (!to_write) {
		goto done;
	}
	if (!ncfg_render(to_write, &overrides, &text, &missing, quiet, sizeof(quiet))) {
		char list[NCFG_ERROR_MAX];
		size_t at = 0;
		size_t i;

		list[0] = '\0';
		for (i = 0; i < missing.count && at + 1u < sizeof(list); i++) {
			int put = snprintf(list + at, sizeof(list) - at, "%s%s", at ? "\n  " : "",
			    missing.items[i]);

			if (put < 0) {
				break;
			}
			at += (size_t)put;
		}
		ncfg_error_set(err, err_size,
		    "this configuration cannot be written out yet, so it was not saved. What is "
		    "in the way:\n  %s\nWrite the profile by hand instead",
		    at ? list : quiet);
		goto done;
	}

	if (!ncfg_host_make_directory(directory, (mode_t)0755, err, err_size)) {
		goto done;
	}
	if (!ncfg_config_write_atomically(snapshot, ncfg_buf_text(&text),
	    strlen(ncfg_buf_text(&text)), 0644u, denied, err, err_size)) {
		goto done;
	}

	/* Selecting is part of the same act: having just said what this profile
	 * means, being left on none would be a surprise. */
	if (!ncfg_profile_set(config_dir, factory_dir, name, NULL, denied, err, err_size)) {
		goto done;
	}

	/* The proof. What the machine compiles to now must be what it was
	 * running, but for the selection this just made. The unwritten hook sink
	 * -- see the file's header for the site the Rust left refusing. */
	if (ncfg_config_load_with_profile(factory_dir, config_dir, &sources, quiet,
	    sizeof(quiet))) {
		after = ncfg_config_compile_for_reading(&sources, quiet, sizeof(quiet));
	}
	ncfg_config_sources_free(&sources);
	if (!ncfg_config_documents_agree(running, name, after, where, sizeof(where))) {
		ncfg_error_set(err, err_size,
		    "saving `%s` would not reproduce what this machine is running, so nothing "
		    "was kept. That is a fault in the snapshot rather than in your "
		    "configuration; write the profile by hand and please report it.%s",
		    name, where);
		goto done;
	}
	ok = 1;

done:
	ncfg_document_free(after);
	ncfg_document_free(to_write);
	ncfg_document_free(base);
	ncfg_buf_free(&text);
	ncfg_unrenderable_free(&missing);
	ncfg_overrides_free(&overrides);
	return ok;
}

int ncfg_profile_save(const char *config_dir, const char *factory_dir, const char *name,
    int replace, const ncfg_document_t *running, const char *how_to_replace, char **path_out,
    int *denied, char *err, size_t err_size)
{
	ncfg_config_taken_t *taken = NULL;
	size_t               taken_count = 0;
	struct stat          about;
	char                *profile_root;
	char                *directory;
	char                *snapshot;
	char                *selection = NULL;
	char                *selected_before = NULL;
	size_t               selected_length = 0;
	char                 quiet[NCFG_ERROR_MAX];
	int                  ok;

	if (path_out) {
		*path_out = NULL;
	}
	if (denied) {
		*denied = 0;
	}
	if (!ncfg_profile_name_usable(name, err, err_size)) {
		return 0;
	}
	if (!running) {
		ncfg_error_set(err, err_size,
		    "there is no compiled configuration, so there is nothing to save");
		return 0;
	}
	profile_root = ncfg_host_join(config_dir, "profile", err, err_size);
	directory = profile_root ? ncfg_host_join(profile_root, name, err, err_size) : NULL;
	free(profile_root);
	if (!directory) {
		return 0;
	}
	snapshot = ncfg_host_join(directory, SNAPSHOT_LEAF, err, err_size);
	if (!snapshot) {
		free(directory);
		return 0;
	}
	/* Refused rather than merged. An existing profile is somebody's work, and
	 * guessing here is the failure this exists to prevent. The remedy is the
	 * caller's words, not this function's: `ncfg` has a flag to name and a gui
	 * has a prompt to offer, and a message naming the wrong one is worse than
	 * one naming neither. */
	if (stat(directory, &about) == 0 && S_ISDIR(about.st_mode)) {
		if (!replace) {
			ncfg_error_set(err, err_size, "`%s` already exists (%s); %s to overwrite it",
			    name, directory, how_to_replace ? how_to_replace : "ask to replace it");
			free(snapshot);
			free(directory);
			return 0;
		}
		if (stat(snapshot, &about) != 0) {
			ncfg_error_set(err, err_size,
			    "`%s` was written by hand (%s), so saving over it would discard files "
			    "this cannot reproduce. Save as another name, or take that directory "
			    "away first", name, directory);
			free(snapshot);
			free(directory);
			return 0;
		}
	}

	if (!ncfg_config_take_folded(config_dir, &taken, &taken_count, err, err_size)) {
		free(snapshot);
		free(directory);
		return 0;
	}
	/*
	 * **The selection is part of what a failure has to put back.** Remembered
	 * rather than recomputed: what was there before is the only thing that
	 * can be put back, and it is either a file or an absence.
	 */
	selection = ncfg_config_drop_in_path(config_dir, NCFG_PROFILE_DROP_IN, quiet,
	    sizeof(quiet));
	if (selection) {
		selected_before = ncfg_host_read_file(selection, &selected_length,
		    NCFG_CONFIG_FILE_MAX);
	}

	ok = write_profile_snapshot(config_dir, factory_dir, name, running, directory, snapshot,
	    denied, err, err_size);
	if (!ok) {
		(void)unlink(snapshot);
		(void)rmdir(directory);
		if (selection) {
			if (selected_before) {
				(void)ncfg_config_write_atomically(selection, selected_before,
				    selected_length, 0644u, NULL, quiet, sizeof(quiet));
			} else {
				(void)unlink(selection);
			}
		}
		ncfg_config_restore_folded(taken, taken_count);
	} else if (path_out) {
		*path_out = snapshot;
		snapshot = NULL;
	}
	ncfg_config_taken_free(taken, taken_count);
	free(selected_before);
	free(selection);
	free(snapshot);
	free(directory);
	return ok;
}
