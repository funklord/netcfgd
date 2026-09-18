/*
 * state.c -- what the daemon knows, and the two ways it changes.
 *
 * Deliberately free of threads, sockets and signals: everything here is a call
 * taking the state and returning what happened. The loop decides *when* these
 * run and the tests decide *that* they behave, which is the same seam that
 * makes the planner testable without hardware.
 *
 * WHAT IS HERE AND WHAT IS NOT
 *   The document, the reload, the observation and the rejected-configuration
 *   hash. Not the confirm window, the probe verdicts, the SIM pairings or the
 *   resolv guard: each is its own module in the Rust, each lands with its own
 *   tests, and a field here that nothing maintained would read as a feature
 *   that exists.
 */
#include "ncfg/daemon.h"

#include "ncfg/config.h"
#include "ncfg/hooks.h"
#include "ncfg/log.h"
#include "ncfg/state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A copy of `text`, or NULL. */
static char *duplicate(const char *text)
{
	size_t length;
	char  *copy;

	if (!text) {
		return NULL;
	}
	length = strlen(text) + 1u;
	copy = malloc(length);
	if (copy) {
		memcpy(copy, text, length);
	}
	return copy;
}

/* Replace an owned string, freeing what was there. */
static void hold(char **field, char *value)
{
	free(*field);
	*field = value;
}

int ncfg_daemon_state_init(ncfg_daemon_state_t *state, const char *factory_dir,
    const char *config_dir, const char *run_dir, char *err, size_t err_size)
{
	if (!state) {
		ncfg_error_set(err, err_size, "there is no state to set up");
		return 0;
	}
	memset(state, 0, sizeof(*state));
	if (!config_dir || !config_dir[0] || !run_dir || !run_dir[0]) {
		/*
		 * No default, and the reason is `tests/testdir.h`'s: the real netcfgd
		 * runs on the machine this is built on, with that machine's
		 * configuration in `/etc/netcfgd` and its runtime state in
		 * `/run/netcfgd`. A state that filled these in for itself would be
		 * one mistake away from a test reading them.
		 */
		ncfg_error_set(err, err_size,
		    "a daemon state needs a config directory and a run directory, and neither "
		    "has a default here");
		return 0;
	}
	state->paths.factory = duplicate(factory_dir ? factory_dir : "");
	state->paths.config = duplicate(config_dir);
	state->paths.run = duplicate(run_dir);
	if (!state->paths.factory || !state->paths.config || !state->paths.run) {
		ncfg_daemon_state_free(state);
		ncfg_error_set(err, err_size, "there was no memory for the daemon's paths");
		return 0;
	}
	return 1;
}

void ncfg_daemon_state_free(ncfg_daemon_state_t *state)
{
	if (!state) {
		return;
	}
	free(state->paths.factory);
	free(state->paths.config);
	free(state->paths.run);
	ncfg_document_free(state->desired);
	free(state->diagnostics);
	free(state->rejected);
	ncfg_observed_free(state->observed);
	memset(state, 0, sizeof(*state));
}

int ncfg_daemon_document_hash(const ncfg_document_t *document, char *out, char *err,
    size_t err_size)
{
	ncfg_buf_t  text;
	/* Cast away const to clear one field and put it back. The alternative is
	 * a deep copy of the whole document to hash it, which is the shape the
	 * Rust takes because a clone is one line there and a page here. */
	ncfg_document_t *mutable_document = (ncfg_document_t *)document;
	char        *generated_by;
	int          written;

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the hash");
		return 0;
	}
	out[0] = '\0';
	if (!document) {
		ncfg_error_set(err, err_size, "there is no document to hash");
		return 0;
	}
	/*
	 * `generated_by` names the version that produced the document. Leaving it
	 * in would make an upgrade look like an edit, and the whole use of this
	 * is telling "the same configuration" from "a different one".
	 */
	generated_by = mutable_document->generated_by;
	mutable_document->generated_by = NULL;
	ncfg_buf_init(&text, 0);
	written = ncfg_document_write_canonical(mutable_document, &text, err, err_size);
	mutable_document->generated_by = generated_by;
	if (!written) {
		ncfg_buf_free(&text);
		return 0;
	}
	ncfg_sha256_hex(ncfg_buf_text(&text), text.length, out);
	ncfg_buf_free(&text);
	return 1;
}

/* Every diagnostic, one per line, which is what an operator reads. */
static char *render_diagnostics(const ncfg_lower_diags_t *diags)
{
	ncfg_buf_t body;
	size_t     at;

	ncfg_buf_init(&body, 0);
	for (at = 0; at < diags->count; at++) {
		char one[NCFG_ERROR_MAX];

		ncfg_lower_diag_render(&diags->at[at], one, sizeof(one));
		ncfg_buf_add_text(&body, one);
		ncfg_buf_add_char(&body, '\n');
	}
	if (diags->total > diags->count) {
		ncfg_buf_addf(&body, "... and %lu more\n",
		    (unsigned long)(diags->total - diags->count));
	}
	if (ncfg_buf_failed(&body)) {
		ncfg_buf_free(&body);
		return NULL;
	}
	return ncfg_buf_take(&body, NULL);
}

int ncfg_daemon_state_reload(ncfg_daemon_state_t *state, char *err, size_t err_size)
{
	ncfg_config_sources_t sources = { 0 };
	ncfg_lower_diags_t    diags = { 0 };
	ncfg_pending_hooks_t *pending;
	ncfg_document_t      *document;
	char                  hash[NCFG_DAEMON_HASH_MAX];
	char                  why[NCFG_ERROR_MAX];
	char                  sentence[NCFG_ERROR_MAX + 256];

	if (!state) {
		ncfg_error_set(err, err_size, "there is no state to reload");
		return 0;
	}
	pending = ncfg_pending_hooks_new(state->paths.run, why, sizeof(why));
	if (!pending) {
		hold(&state->diagnostics, duplicate(why));
		ncfg_error_set(err, err_size, "%s", why);
		return 0;
	}
	if (!ncfg_config_load_with_profile(state->paths.factory, state->paths.config, &sources,
	        why, sizeof(why))) {
		/*
		 * The previous desired state is kept deliberately. Dropping it would
		 * mean an unreadable directory silently disarms drift detection,
		 * which is the moment it is most wanted.
		 */
		(void)snprintf(sentence, sizeof(sentence), "%s: %s", state->paths.config, why);
		hold(&state->diagnostics, duplicate(sentence));
		ncfg_error_set(err, err_size, "%s", sentence);
		ncfg_pending_hooks_free(pending);
		ncfg_config_sources_free(&sources);
		return 0;
	}
	document = ncfg_config_compile(&sources, ncfg_pending_hooks_sink(pending), &diags, why,
	    sizeof(why));
	if (!document) {
		char *rendered = render_diagnostics(&diags);

		hold(&state->diagnostics, rendered ? rendered : duplicate(why));
		ncfg_error_set(err, err_size, "%s", why);
		ncfg_lower_diags_free(&diags);
		ncfg_pending_hooks_free(pending);
		ncfg_config_sources_free(&sources);
		return 0;
	}
	ncfg_lower_diags_free(&diags);
	ncfg_config_sources_free(&sources);
	/*
	 * **After the compile succeeded, not during it.** The daemon is about to
	 * hold this document and apply from it, so the hooks it names have to
	 * exist -- but a compile that failed now leaves nothing behind, where
	 * writing as it went would have left whichever hooks it reached before
	 * the diagnostic.
	 */
	if (!ncfg_pending_hooks_write(pending, why, sizeof(why))) {
		ncfg_log_emitf("config", NCFG_LOG_ERROR, "%s", why);
	}
	ncfg_pending_hooks_free(pending);

	if (state->rejected && ncfg_daemon_document_hash(document, hash, why, sizeof(why)) &&
	    strcmp(state->rejected, hash) == 0) {
		/*
		 * The same configuration a revert already rejected. Adopting it would
		 * undo the revert on the next drift check, which the operator would
		 * watch happen and be unable to explain.
		 *
		 * **Refused without recording diagnostics**, which is why a caller
		 * must read this call's answer rather than `state->diagnostics`: that
		 * field would still be holding an *earlier* failure's text, and a
		 * reload reported from it would name a problem that is not this one.
		 */
		ncfg_document_free(document);
		ncfg_error_set(err, err_size,
		    "this configuration was reverted away from and has not changed since; edit "
		    "it to try again");
		return 0;
	}
	(void)ncfg_state_write_desired(state->paths.run, document, why, sizeof(why));
	ncfg_document_free(state->desired);
	state->desired = document;
	hold(&state->diagnostics, NULL);
	/* A different document is a different answer, so *fixing* the config
	 * clears the rejection by itself -- which is why this is a hash and not a
	 * flag. */
	hold(&state->rejected, NULL);
	return 1;
}

/*
 * Whether the link set moved: names and their up state, compared in order.
 *
 * **The link set rather than the whole observation**, because a caller uses
 * this to decide whether to tell subscribers the machine changed, and the rest
 * of an observation carries values that move on their own -- a probe verdict,
 * a lease timer -- which would make an idle machine emit events for ever.
 *
 * `observed.h` says `links` is sorted by name, so this compares in order
 * rather than sorting again: netlink does not promise to report links in the
 * same order twice, and two unsorted lists would report movement on a machine
 * where nothing happened.
 */
static int links_moved(const ncfg_observed_t *before, const ncfg_observed_t *after)
{
	size_t at;

	if (!before || !after) {
		return before != after;
	}
	if (before->link_count != after->link_count) {
		return 1;
	}
	for (at = 0; at < before->link_count; at++) {
		const char *was = before->links[at].name ? before->links[at].name : "";
		const char *now = after->links[at].name ? after->links[at].name : "";

		if (strcmp(was, now) != 0 || before->links[at].up != after->links[at].up) {
			return 1;
		}
	}
	return 0;
}

int ncfg_daemon_state_reobserve(ncfg_daemon_state_t *state, int *moved, char *err,
    size_t err_size)
{
	ncfg_observed_t *fresh = NULL;

	if (moved) {
		*moved = 0;
	}
	if (!state) {
		ncfg_error_set(err, err_size, "there is no state to observe into");
		return 0;
	}
	if (!state->observe) {
		ncfg_error_set(err, err_size,
		    "this daemon was given no way to observe the machine");
		return 0;
	}
	if (!state->observe(state->observe_context, state->desired, &fresh, err, err_size) ||
	    !fresh) {
		/* The previous observation is kept, for the reason a failed reload
		 * keeps the previous document: an unreadable kernel that silently
		 * disarmed drift detection would do it at the moment it is most
		 * wanted. */
		return 0;
	}
	if (moved) {
		*moved = links_moved(state->observed, fresh);
	}
	ncfg_observed_free(state->observed);
	state->observed = fresh;
	return 1;
}
