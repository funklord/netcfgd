/*
 * confirm.c -- the commit-confirm state machine, and the two files that make
 * it survive the process.
 *
 * Free of threads and sockets, like the rest of the daemon's state: every call
 * here takes the state and returns what happened, and the loop decides when
 * they run.
 *
 * THE TWO FILES ARE A SIBLING OF THE RUN DIRECTORY
 *   `ncfg_confirm_dir` composes it and `daemon.h` says why: an init that
 *   removes `/run/netcfgd` on a stop would otherwise destroy the one record
 *   nothing in the world holds a copy of (0163). Everything below joins to
 *   that directory and nothing writes into the run directory except
 *   `desired.json`, which is a projection rather than a promise.
 *
 * WHAT IS BORROWED FROM ELSEWHERE, RATHER THAN WRITTEN AGAIN
 *   `ncfg_apply_revert` replays the inverses. `ncfg_write_atomically` writes
 *   both files, and it is the one that creates the sibling directory as a side
 *   effect of writing into it -- which is why nothing here calls `mkdir`.
 *   `ncfg_daemon_document_hash` is the identity of a document, `ncfg_plan_build`
 *   and `ncfg_apply` are the re-plan a revert ends with.
 */
#include "ncfg/daemon.h"

#include "daemon_internal.h"
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/json_write.h"
#include "ncfg/log.h"
#include "ncfg/state.h"
#include "ncfg_json.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* A window file is three members and a hash; a last-good document is a whole
 * configuration. Both are netcfgd's own, and both are read back into memory,
 * so both are bounded -- `state_files.c`'s number for the document. */
#define WINDOW_FILE_MAX  (64u * 1024u)
#define DOCUMENT_FILE_MAX (16u * 1024u * 1024u)

/* The mode both files are written with, which is `state.h`'s one answer for a
 * record under `/run`: readable by anyone, writable by netcfgd, and stated
 * rather than left to the umask -- see the constant for what that cost. */
#define CONFIRM_FILE_MODE NCFG_RUN_FILE_MODE

/* ------------------------------------------------------------------------ *
 * Where the promise is kept
 * ------------------------------------------------------------------------ */

const char *ncfg_confirm_dir(const char *run_dir, char *out, size_t out_size)
{
	size_t length;
	size_t at;
	int    written;
	int    has_slash = 0;
	size_t slash = 0;

	if (!out || out_size == 0u) {
		return NULL;
	}
	out[0] = '\0';
	if (!run_dir) {
		run_dir = "";
	}
	length = strlen(run_dir);
	/* A trailing slash names the same directory and must not answer
	 * differently. `/` itself keeps its one character and falls through to the
	 * no-component case below. */
	while (length > 1u && run_dir[length - 1u] == '/') {
		length--;
	}
	for (at = 0; at < length; at++) {
		if (run_dir[at] == '/') {
			has_slash = 1;
			slash = at;
		}
	}
	if (length == 0u) {
		/* No run directory at all. Not a real configuration, and a relative
		 * name is the answer that cannot escape upwards. */
		written = snprintf(out, out_size, "confirm");
	} else if (length == 1u && run_dir[0] == '/') {
		written = snprintf(out, out_size, "/confirm");
	} else if (!has_slash) {
		written = snprintf(out, out_size, "%.*s-confirm", (int)length, run_dir);
	} else if (slash == 0u) {
		written = snprintf(out, out_size, "/%.*s-confirm", (int)(length - 1u), run_dir + 1);
	} else {
		written = snprintf(out, out_size, "%.*s/%.*s-confirm", (int)slash, run_dir,
		    (int)(length - slash - 1u), run_dir + slash + 1u);
	}
	if (written < 0 || (size_t)written >= out_size) {
		out[0] = '\0';
		return NULL;
	}
	return out;
}

/* `<confirm dir>/<leaf>` in the caller's buffer. */
static int confirm_path(const char *run_dir, const char *leaf, char *out, size_t out_size)
{
	char directory[NCFG_CONFIRM_PATH_MAX];
	int  written;

	if (!ncfg_confirm_dir(run_dir, directory, sizeof(directory))) {
		return 0;
	}
	written = snprintf(out, out_size, "%s/%s", directory, leaf);
	return written >= 0 && (size_t)written < out_size;
}

/*
 * The whole of a file, NUL-terminated, or NULL.
 *
 * Its own rather than the host module's `ncfg_host_read_file`, which is
 * private to `src/host/` by the same rule that keeps `plan_internal.h` inside
 * the planner. Bounded, because a file under `/run` is still a file somebody
 * can make large.
 */
static char *read_whole(const char *path, size_t *length_out, size_t ceiling)
{
	FILE  *file;
	char  *body;
	long   size;
	size_t got;

	if (length_out) {
		*length_out = 0u;
	}
	file = fopen(path, "rb");
	if (!file) {
		return NULL;
	}
	if (fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) < 0 ||
	    (unsigned long)size > (unsigned long)ceiling) {
		(void)fclose(file);
		return NULL;
	}
	rewind(file);
	body = malloc((size_t)size + 1u);
	if (!body) {
		(void)fclose(file);
		return NULL;
	}
	got = size ? fread(body, 1u, (size_t)size, file) : 0u;
	body[got] = '\0';
	if (length_out) {
		*length_out = got;
	}
	(void)fclose(file);
	return body;
}

/* ------------------------------------------------------------------------ *
 * The window file
 * ------------------------------------------------------------------------ */

uint64_t ncfg_confirm_now(void)
{
	time_t now = time(NULL);

	/* A clock before the epoch answers zero, which makes every window look
	 * closed. That is the direction that reverts rather than the one that
	 * lets a change stand unconfirmed. */
	return now > 0 ? (uint64_t)now : 0u;
}

int ncfg_confirm_expired_at(const ncfg_confirm_window_t *window, uint64_t now)
{
	if (!window) {
		return 1;
	}
	return now >= window->deadline_epoch;
}

uint64_t ncfg_confirm_remaining_at(const ncfg_confirm_window_t *window, uint64_t now)
{
	if (!window || now >= window->deadline_epoch) {
		return 0u;
	}
	return window->deadline_epoch - now;
}

/* Whether a member name is one of the three. Unknown members refuse the file,
 * which is `deny_unknown_fields` in the Rust. */
static int window_member(const ncfg_json_doc_t *doc, uint32_t member, const char *name)
{
	size_t      length = 0u;
	const char *key = ncfg_json_key(doc, member, &length);

	return key && length == strlen(name) && memcmp(key, name, length) == 0;
}

int ncfg_confirm_read_window(const char *run_dir, ncfg_confirm_window_t *out)
{
	char             path[NCFG_CONFIRM_PATH_MAX];
	char            *text;
	size_t           length = 0u;
	ncfg_json_doc_t *doc;
	uint32_t         root;
	uint32_t         member;
	int              have_deadline = 0;
	int              have_seconds = 0;
	const char      *hash = NULL;
	size_t           hash_length = 0u;
	int64_t          deadline = 0;
	int64_t          seconds = 0;

	if (!out) {
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!confirm_path(run_dir, "confirm.json", path, sizeof(path))) {
		return 0;
	}
	text = read_whole(path, &length, WINDOW_FILE_MAX);
	if (!text) {
		return 0;
	}
	doc = ncfg_json_parse(text, length, NULL, 0u);
	free(text);
	if (!doc) {
		return 0;
	}
	root = ncfg_json_root(doc);
	if (ncfg_json_type(doc, root) != NCFG_JSON_OBJECT) {
		ncfg_json_free(doc);
		return 0;
	}
	for (member = ncfg_json_node(doc, root)->first_child; member != NCFG_JSON_NONE;
	    member = ncfg_json_node(doc, member)->next_sibling) {
		if (window_member(doc, member, "deadline_epoch")) {
			deadline = ncfg_json_int(doc, member, -1);
			have_deadline = ncfg_json_type(doc, member) == NCFG_JSON_NUMBER;
		} else if (window_member(doc, member, "window_seconds")) {
			seconds = ncfg_json_int(doc, member, -1);
			have_seconds = ncfg_json_type(doc, member) == NCFG_JSON_NUMBER;
		} else if (window_member(doc, member, "last_good_hash")) {
			hash = ncfg_json_string(doc, member, &hash_length);
		} else {
			/* A member netcfgd did not write. The file is netcfgd's own, so
			 * this is not a version skew to accommodate -- it is a file
			 * something else has been writing. */
			ncfg_json_free(doc);
			return 0;
		}
	}
	if (!have_deadline || !have_seconds || !hash || deadline < 0 || seconds < 0 ||
	    seconds > (int64_t)UINT32_MAX || hash_length >= sizeof(out->last_good_hash)) {
		ncfg_json_free(doc);
		memset(out, 0, sizeof(*out));
		return 0;
	}
	out->deadline_epoch = (uint64_t)deadline;
	out->window_seconds = (uint32_t)seconds;
	memcpy(out->last_good_hash, hash, hash_length);
	out->last_good_hash[hash_length] = '\0';
	ncfg_json_free(doc);
	return 1;
}

int ncfg_confirm_write_window(const char *run_dir, const ncfg_confirm_window_t *window,
    char *err, size_t err_size)
{
	char               path[NCFG_CONFIRM_PATH_MAX];
	ncfg_buf_t         body;
	ncfg_json_writer_t writer;
	int                ok;

	if (!window) {
		ncfg_error_set(err, err_size, "there is no window to write");
		return 0;
	}
	if (!confirm_path(run_dir, "confirm.json", path, sizeof(path))) {
		ncfg_error_set(err, err_size,
		    "the confirm directory for `%s` does not fit in %d bytes",
		    run_dir ? run_dir : "", (int)NCFG_CONFIRM_PATH_MAX);
		return 0;
	}
	ncfg_buf_init(&body, 0u);
	ncfg_json_write_init(&writer, &body);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_key(&writer, "deadline_epoch");
	ncfg_json_write_uint(&writer, window->deadline_epoch);
	ncfg_json_write_key(&writer, "window_seconds");
	ncfg_json_write_uint(&writer, (uint64_t)window->window_seconds);
	ncfg_json_write_member_string(&writer, "last_good_hash", window->last_good_hash);
	ncfg_json_write_object_end(&writer);
	if (!ncfg_json_write_done(&writer)) {
		ncfg_error_set(err, err_size, "could not build the confirm window: %s",
		    ncfg_json_write_failure(&writer));
		ncfg_buf_free(&body);
		return 0;
	}
	ok = ncfg_write_atomically(path, ncfg_buf_text(&body), strlen(ncfg_buf_text(&body)),
	    CONFIRM_FILE_MODE, err, err_size);
	ncfg_buf_free(&body);
	return ok;
}

int ncfg_confirm_clear_window(const char *run_dir, char *err, size_t err_size)
{
	char path[NCFG_CONFIRM_PATH_MAX];

	if (!confirm_path(run_dir, "confirm.json", path, sizeof(path))) {
		ncfg_error_set(err, err_size,
		    "the confirm directory for `%s` does not fit in %d bytes",
		    run_dir ? run_dir : "", (int)NCFG_CONFIRM_PATH_MAX);
		return 0;
	}
	/*
	 * A file that is not there is the state the caller asked for. An expiry
	 * and an explicit revert can both reach this and neither should fail
	 * because the other won.
	 */
	if (unlink(path) != 0 && errno != ENOENT) {
		ncfg_error_set(err, err_size, "could not close the confirm window at %s: %s", path,
		    strerror(errno));
		return 0;
	}
	return 1;
}

ncfg_document_t *ncfg_confirm_read_last_good(const char *run_dir, char *err, size_t err_size)
{
	char             path[NCFG_CONFIRM_PATH_MAX];
	char            *text;
	size_t           length = 0u;
	ncfg_document_t *document;

	if (!confirm_path(run_dir, "last-good.json", path, sizeof(path))) {
		ncfg_error_set(err, err_size,
		    "the confirm directory for `%s` does not fit in %d bytes",
		    run_dir ? run_dir : "", (int)NCFG_CONFIRM_PATH_MAX);
		return NULL;
	}
	text = read_whole(path, &length, DOCUMENT_FILE_MAX);
	if (!text) {
		ncfg_error_set(err, err_size, "there is no readable last-good configuration at %s",
		    path);
		return NULL;
	}
	document = ncfg_document_read(text, length, err, err_size);
	free(text);
	return document;
}

int ncfg_confirm_write_last_good(const char *run_dir, ncfg_document_t *document, char *err,
    size_t err_size)
{
	char       path[NCFG_CONFIRM_PATH_MAX];
	ncfg_buf_t body;
	int        ok;

	if (!document) {
		ncfg_error_set(err, err_size, "there is no document to record as last-good");
		return 0;
	}
	if (!confirm_path(run_dir, "last-good.json", path, sizeof(path))) {
		ncfg_error_set(err, err_size,
		    "the confirm directory for `%s` does not fit in %d bytes",
		    run_dir ? run_dir : "", (int)NCFG_CONFIRM_PATH_MAX);
		return 0;
	}
	ncfg_buf_init(&body, 0u);
	if (!ncfg_document_write_canonical(document, &body, err, err_size)) {
		ncfg_buf_free(&body);
		return 0;
	}
	ok = ncfg_write_atomically(path, ncfg_buf_text(&body), body.length, CONFIRM_FILE_MODE,
	    err, err_size);
	ncfg_buf_free(&body);
	return ok;
}

/* ------------------------------------------------------------------------ *
 * What an open window covers
 * ------------------------------------------------------------------------ */

/* The record for an action, or NULL where the journal has none. */
static const ncfg_record_t *record_for(const ncfg_journal_t *journal, uint32_t id)
{
	size_t at;

	for (at = 0; at < journal->record_count; at++) {
		if (journal->records[at].id == id) {
			return &journal->records[at];
		}
	}
	return NULL;
}

int ncfg_confirm_armed_from(const ncfg_plan_t *plan, const ncfg_journal_t *journal,
    const ncfg_document_t *document, ncfg_confirm_armed_t *out, char *err, size_t err_size)
{
	size_t at;

	if (!out) {
		ncfg_error_set(err, err_size, "there is nowhere to record what the window covers");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	ncfg_journal_init(&out->journal);
	if (!plan || !journal) {
		ncfg_error_set(err, err_size,
		    "a window covers a plan and the journal of applying it, and one is missing");
		return 0;
	}
	out->undo = ncfg_plan_new(err, err_size);
	if (!out->undo) {
		return 0;
	}
	if (document && !ncfg_daemon_document_hash(document, out->document, err, err_size)) {
		ncfg_confirm_armed_free(out);
		return 0;
	}
	for (at = 0; at < plan->action_count; at++) {
		const ncfg_action_t *action = &plan->actions[at];
		const ncfg_record_t *record = record_for(journal, action->id);
		ncfg_record_t        kept;
		uint32_t             id;

		/*
		 * Only what reached the kernel, and only what declared an inverse.
		 * The three rejections are the point rather than the acceptance: an
		 * action that failed or never ran has nothing to undo, and an action
		 * with no inverse is one the plan has already warned cannot be taken
		 * back.
		 */
		if (!record || record->outcome != NCFG_OUTCOME_DONE || !action->has_inverse) {
			continue;
		}
		id = ncfg_plan_add(out->undo, &action->op, &action->reason, NULL, 0u,
		    &action->inverse);
		if (id == NCFG_PLAN_NO_ACTION) {
			break;
		}
		memset(&kept, 0, sizeof(kept));
		kept.id = id;
		kept.op = record->op;
		kept.interface = record->interface;
		kept.reason = action->reason;
		kept.outcome = NCFG_OUTCOME_DONE;
		ncfg_journal_push(&out->journal, &kept);
	}
	if (ncfg_plan_failed(out->undo) || ncfg_journal_failed(&out->journal)) {
		ncfg_confirm_armed_free(out);
		ncfg_error_set(err, err_size, "there was no memory to record what the window covers");
		return 0;
	}
	return 1;
}

void ncfg_confirm_armed_free(ncfg_confirm_armed_t *armed)
{
	if (!armed) {
		return;
	}
	ncfg_plan_free(armed->undo);
	ncfg_journal_free(&armed->journal);
	memset(armed, 0, sizeof(*armed));
}

/* ------------------------------------------------------------------------ *
 * The state machine
 * ------------------------------------------------------------------------ */

ncfg_document_t *ncfg_confirm_may_arm(const ncfg_daemon_state_t *state, char *err,
    size_t err_size)
{
	ncfg_confirm_window_t window;
	ncfg_document_t      *last_good;

	if (!state) {
		ncfg_error_set(err, err_size, "there is no daemon state to arm a window against");
		return NULL;
	}
	if (ncfg_confirm_read_window(state->paths.run, &window)) {
		ncfg_error_set(err, err_size,
		    "a confirm window is already open with %lus left; confirm or revert first",
		    (unsigned long)ncfg_confirm_remaining_at(&window, ncfg_confirm_now()));
		return NULL;
	}
	last_good = ncfg_confirm_read_last_good(state->paths.run, NULL, 0u);
	if (!last_good) {
		/*
		 * Refused rather than allowed with an empty target. A window whose
		 * revert does nothing is worse than no window, because the operator
		 * believes they have a safety net.
		 */
		ncfg_error_set(err, err_size,
		    "no last-good configuration to revert to; apply once without a window first");
		return NULL;
	}
	return last_good;
}

int ncfg_confirm_arm(const ncfg_daemon_state_t *state, uint32_t window_seconds,
    const ncfg_document_t *last_good, ncfg_proto_event_t *event, char *err, size_t err_size)
{
	ncfg_confirm_window_t window;

	if (!state || !last_good) {
		ncfg_error_set(err, err_size, "a window needs a daemon state and a document to "
		    "revert to");
		return 0;
	}
	memset(&window, 0, sizeof(window));
	window.deadline_epoch = ncfg_confirm_now() + window_seconds;
	window.window_seconds = window_seconds;
	if (!ncfg_daemon_document_hash(last_good, window.last_good_hash, err, err_size)) {
		return 0;
	}
	if (!ncfg_confirm_write_window(state->paths.run, &window, err, err_size)) {
		/*
		 * **A window that could not be written is not a window.** The Rust
		 * logs this and returns the event anyway, which tells every client the
		 * change is covered while nothing on disk will ever resolve it. Said
		 * here as well as returned, because the caller has already applied by
		 * the time it gets here and the operator needs to know the net is not
		 * there.
		 */
		ncfg_log_emitf("confirm", NCFG_LOG_ERROR,
		    "could not write the confirm window: %s; this change is NOT covered and "
		    "will not revert on its own", err ? err : "");
		return 0;
	}
	if (event) {
		memset(event, 0, sizeof(*event));
		event->kind = NCFG_PROTO_EVENT_CONFIRM_ARMED;
		event->seconds = (int64_t)window_seconds;
	}
	return 1;
}

int ncfg_confirm_keep(ncfg_daemon_state_t *state, ncfg_confirm_armed_t *armed,
    ncfg_document_t *applied, ncfg_proto_event_t *event, char *err, size_t err_size)
{
	ncfg_confirm_window_t window;

	if (!state) {
		ncfg_error_set(err, err_size, "there is no daemon state to confirm against");
		return 0;
	}
	if (!ncfg_confirm_read_window(state->paths.run, &window)) {
		ncfg_error_set(err, err_size, "no confirm window is open");
		return 0;
	}
	(void)ncfg_confirm_clear_window(state->paths.run, NULL, 0u);
	/* The change stood, so there is nothing to take back. */
	ncfg_confirm_armed_free(armed);
	/*
	 * And it becomes what a future revert falls back to -- the document the
	 * window covered, which the caller passes because it is the only one that
	 * can know: a reload inside the window may have left the daemon holding an
	 * edit that was deferred and never applied.
	 */
	if (applied) {
		(void)ncfg_confirm_write_last_good(state->paths.run, applied, NULL, 0u);
	}
	if (event) {
		memset(event, 0, sizeof(*event));
		event->kind = NCFG_PROTO_EVENT_CONFIRM_RESOLVED;
		event->confirmed = 1u;
	}
	return 1;
}

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

/*
 * The re-plan a revert ends with: converge on the last-good document from
 * wherever the machine actually is.
 *
 * The safety net rather than a duplicate of the inverses -- it covers a
 * half-applied plan that stopped at a failure, and a restart, which loses the
 * inverses entirely. If the inverses were complete it finds nothing to do.
 */
static void replan_onto_last_good(ncfg_daemon_state_t *state, const ncfg_executor_t *executor)
{
	char             why[NCFG_ERROR_MAX];
	ncfg_plan_t     *plan;
	ncfg_journal_t   journal;
	const ncfg_record_t *failure;

	if (!state->desired || !state->observed) {
		/* Said rather than skipped: this is the half that covers whatever the
		 * inverses could not take back, and a machine that has never been
		 * observed is one the revert has just left half-way. */
		ncfg_log_emitf("confirm", NCFG_LOG_ERROR,
		    "revert: nothing has been observed of this machine, so the plan back to the "
		    "last-good configuration did not run");
		return;
	}
	why[0] = '\0';
	plan = ncfg_plan_build(state->desired, state->observed, NULL, why, sizeof(why));
	if (!plan) {
		ncfg_log_emitf("confirm", NCFG_LOG_ERROR, "revert: could not plan the way back: %s",
		    why);
		return;
	}
	ncfg_journal_init(&journal);
	(void)ncfg_apply(plan, executor, &journal, why, sizeof(why));
	ncfg_daemon_record_what_ran(state, "confirm", plan, &journal);
	failure = ncfg_journal_failure(&journal);
	if (failure) {
		ncfg_log_emitf("confirm", NCFG_LOG_ERROR, "revert incomplete: %s failed: %s",
		    failure->op ? failure->op : "an action",
		    failure->error ? failure->error : "no detail");
	}
	ncfg_journal_free(&journal);
	ncfg_plan_free(plan);
}

int ncfg_confirm_revert(ncfg_daemon_state_t *state, ncfg_confirm_armed_t *armed,
    const ncfg_executor_t *executor, const char *reason, ncfg_proto_event_t *event, char *err,
    size_t err_size)
{
	ncfg_confirm_window_t window;
	ncfg_document_t      *last_good;
	char                  hash[NCFG_DAEMON_HASH_MAX];
	char                  why[NCFG_ERROR_MAX];
	const char           *rejected = NULL;

	if (!state || !executor || !executor->execute) {
		ncfg_error_set(err, err_size,
		    "a revert needs a daemon state and an executor to carry it out");
		return 0;
	}
	if (!ncfg_confirm_read_window(state->paths.run, &window)) {
		ncfg_error_set(err, err_size, "no confirm window is open");
		return 0;
	}
	last_good = ncfg_confirm_read_last_good(state->paths.run, NULL, 0u);
	if (!last_good) {
		/*
		 * The window is closed anyway. A window nothing can resolve is a timer
		 * that never stops, and leaving it open would refuse every later
		 * apply as well.
		 */
		(void)ncfg_confirm_clear_window(state->paths.run, NULL, 0u);
		ncfg_confirm_armed_free(armed);
		ncfg_error_set(err, err_size,
		    "the last-good configuration is unreadable; nothing reverted");
		return 0;
	}
	ncfg_log_emitf("confirm", NCFG_LOG_NOTE, "reverting to %.12s (%s)", window.last_good_hash,
	    reason ? reason : "no reason given");

	/*
	 * **What the window covered, not what is on disk now.** An operator
	 * editing twice inside one window leaves `desired` holding an edit that
	 * was deferred and never applied, and blacklisting that one refuses the
	 * operator's newest configuration for something it never did. The fallback
	 * is what a restarted daemon gets, having lost the record.
	 */
	if (armed && armed->document[0]) {
		rejected = armed->document;
	} else if (state->desired &&
	    ncfg_daemon_document_hash(state->desired, hash, why, sizeof(why))) {
		rejected = hash;
	}
	free(state->rejected);
	state->rejected = duplicate(rejected);

	/*
	 * The desired state becomes the last-good one *before* the revert is
	 * planned, and stays that way afterwards. Without this the next drift
	 * check would compare the machine against the config that just broke it
	 * and put the breakage straight back -- a revert that undoes itself within
	 * seconds is worse than none, because the operator watches it work and
	 * then watches it fail.
	 */
	ncfg_document_free(state->desired);
	state->desired = last_good;
	/* `/run/netcfgd/desired.json` is what `cat` answers with, so it has to say
	 * what is actually in effect rather than what is on disk. */
	(void)ncfg_state_write_desired(state->paths.run, state->desired, NULL, 0u);

	if (armed && armed->undo && armed->undo->action_count != 0u) {
		size_t total = armed->undo->action_count;
		size_t undone = ncfg_apply_revert(armed->undo, &armed->journal, executor);

		ncfg_log_emitf("confirm", NCFG_LOG_NOTE, "revert: undid %lu of %lu applied action(s)",
		    (unsigned long)undone, (unsigned long)total);
		/*
		 * **Folded again, and the second fold is what takes the claims back.**
		 * `ncfg_apply_revert` marks every record whose inverse ran
		 * `NCFG_OUTCOME_REVERTED`, and `ncfg_apply_record` folds the *inverse*
		 * for those -- so an address this window installed stops being
		 * netcfgd's the moment it is withdrawn. A record whose inverse failed
		 * stays `done` and is folded again, which is the honest answer: that
		 * change is still in effect. Folding one journal twice is safe by
		 * construction, every rule in the fold replacing or removing before it
		 * adds.
		 */
		ncfg_daemon_record_what_ran(state, "confirm", armed->undo, &armed->journal);
		/*
		 * **The re-plan below has to see the machine the inverses left.**
		 * Without this it plans against the observation taken before they ran
		 * and re-issues work already done -- which the kernel then refuses,
		 * because a route removed twice is gone the second time. Measured: a
		 * revert that undid all five of its actions correctly went on to
		 * report "revert incomplete: route.del failed: No such process", so a
		 * clean revert announced itself as a broken one.
		 */
		(void)ncfg_daemon_state_reobserve(state, NULL, NULL, 0u);
	}
	ncfg_confirm_armed_free(armed);

	replan_onto_last_good(state, executor);
	(void)ncfg_confirm_clear_window(state->paths.run, NULL, 0u);
	(void)ncfg_daemon_state_reobserve(state, NULL, NULL, 0u);

	if (event) {
		memset(event, 0, sizeof(*event));
		event->kind = NCFG_PROTO_EVENT_CONFIRM_RESOLVED;
		event->confirmed = 0u;
	}
	return 1;
}

int ncfg_confirm_resolve_on_startup(ncfg_daemon_state_t *state, ncfg_confirm_armed_t *armed,
    const ncfg_executor_t *executor, int *resolved, ncfg_proto_event_t *event, char *err,
    size_t err_size)
{
	ncfg_confirm_window_t window;

	if (resolved) {
		*resolved = 0;
	}
	if (!state) {
		ncfg_error_set(err, err_size, "there is no daemon state to resolve a window in");
		return 0;
	}
	if (!ncfg_confirm_read_window(state->paths.run, &window)) {
		return 1;
	}
	ncfg_log_emitf("confirm", NCFG_LOG_NOTE,
	    "a confirm window was open when this daemon started");
	/*
	 * Reverted whether or not the deadline has passed. A daemon that died
	 * inside a window cannot have received a confirmation, and honouring the
	 * remaining time assumes the operator is still there and still able to
	 * reach a socket that has been gone for however long the daemon was down
	 * -- which is exactly the assumption commit-confirm exists because you
	 * cannot make.
	 */
	if (!ncfg_confirm_revert(state, armed, executor, "the daemon restarted inside the window",
	        event, err, err_size)) {
		return 0;
	}
	if (resolved) {
		*resolved = 1;
	}
	return 1;
}
