/*
 * journal.c -- what happened, in a form somebody can read with `cat`.
 *
 * Written to `/run/netcfgd/plan.last.json`. This is the file that answers
 * "what did it actually do?" after an apply, and the reason it carries the
 * reason for each action as well as its outcome: an operator reading it after
 * a failure needs to know why the action existed, not only that it failed.
 *
 * WHY THERE IS AN ARENA
 *   `ncfg_plan_t`'s, for its reason. A record names four or five strings, none
 *   of which can be borrowed: the plan may be freed first, and the error
 *   message was built on the executor's stack. So a push copies what it names
 *   into the journal's own array of allocations and `ncfg_journal_free` is one
 *   loop -- which makes "who frees this?" have one answer instead of six.
 *
 * THE STICKY FAILURE
 *   `ncfg_buf_t`'s discipline, again for its reason: an apply pushes a record
 *   per action and checks once. A journal that failed writes nothing rather
 *   than half a journal, because a half journal that looks whole is one that
 *   gets believed.
 */
#include "ncfg/apply.h"

#include "ncfg/base.h"
#include "ncfg/json_write.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ *
 * The arena
 * ------------------------------------------------------------------------ */

/* Record one allocation as the journal's, or free it and fail. */
static void *keep(ncfg_journal_t *journal, void *block)
{
	void **grown;
	size_t wanted;

	if (!block) {
		journal->failed = 1;
		return NULL;
	}
	if (journal->owned_count == journal->owned_capacity) {
		wanted = journal->owned_capacity ? journal->owned_capacity * 2u : 32u;
		grown = realloc(journal->owned, wanted * sizeof(*grown));
		if (!grown) {
			free(block);
			journal->failed = 1;
			return NULL;
		}
		journal->owned = grown;
		journal->owned_capacity = wanted;
	}
	journal->owned[journal->owned_count++] = block;
	return block;
}

/* A copy of `text` the journal owns and frees. NULL in is NULL out, which is
 * what an absent optional member means everywhere in this project. */
static const char *intern(ncfg_journal_t *journal, const char *text)
{
	size_t length;
	char  *copy;

	if (!text || journal->failed) {
		return NULL;
	}
	length = strlen(text);
	copy = malloc(length + 1u);
	if (copy) {
		memcpy(copy, text, length + 1u);
	}
	return keep(journal, copy);
}

/* ------------------------------------------------------------------------ *
 * The container
 * ------------------------------------------------------------------------ */

void ncfg_journal_init(ncfg_journal_t *journal)
{
	if (journal) {
		memset(journal, 0, sizeof(*journal));
	}
}

void ncfg_journal_free(ncfg_journal_t *journal)
{
	size_t i;

	if (!journal) {
		return;
	}
	for (i = 0; i < journal->owned_count; i++) {
		free(journal->owned[i]);
	}
	free(journal->owned);
	free(journal->records);
	memset(journal, 0, sizeof(*journal));
}

int ncfg_journal_failed(const ncfg_journal_t *journal)
{
	return journal && journal->failed;
}

void ncfg_journal_push(ncfg_journal_t *journal, const ncfg_record_t *record)
{
	ncfg_record_t *slot;

	if (!journal || !record || journal->failed) {
		return;
	}
	if (journal->record_count == journal->record_capacity) {
		size_t         wanted = journal->record_capacity ? journal->record_capacity * 2u : 16u;
		ncfg_record_t *grown = realloc(journal->records, wanted * sizeof(*grown));

		if (!grown) {
			journal->failed = 1;
			return;
		}
		journal->records = grown;
		journal->record_capacity = wanted;
	}
	slot = &journal->records[journal->record_count];
	memset(slot, 0, sizeof(*slot));
	slot->id = record->id;
	slot->outcome = record->outcome;
	slot->op = intern(journal, record->op);
	slot->interface = intern(journal, record->interface);
	slot->error = intern(journal, record->error);
	slot->reason.interface = intern(journal, record->reason.interface);
	slot->reason.field = intern(journal, record->reason.field);
	slot->reason.desired = intern(journal, record->reason.desired);
	slot->reason.observed = intern(journal, record->reason.observed);
	/*
	 * Counted even where an allocation above failed. The sticky flag is what
	 * the caller checks, and a record dropped on the floor here would make
	 * `skipped()` and `done()` disagree with the plan's own length -- which is
	 * the arithmetic an operator does to find out what is left to re-run.
	 */
	journal->record_count++;
}

/* ------------------------------------------------------------------------ *
 * The questions asked of it
 * ------------------------------------------------------------------------ */

const char *ncfg_outcome_name(int outcome)
{
	switch ((ncfg_outcome_t)outcome) {
	case NCFG_OUTCOME_DONE:
		return "done";
	case NCFG_OUTCOME_FAILED:
		return "failed";
	case NCFG_OUTCOME_SKIPPED:
		return "skipped";
	case NCFG_OUTCOME_REVERTED:
		return "reverted";
	}
	return NULL;
}

/* How many records ended this way. */
static size_t counted(const ncfg_journal_t *journal, int outcome)
{
	size_t found = 0;
	size_t i;

	if (!journal) {
		return 0;
	}
	for (i = 0; i < journal->record_count; i++) {
		if (journal->records[i].outcome == outcome) {
			found++;
		}
	}
	return found;
}

int ncfg_journal_succeeded(const ncfg_journal_t *journal)
{
	size_t i;

	if (!journal) {
		return 0;
	}
	for (i = 0; i < journal->record_count; i++) {
		/*
		 * A reverted action ran and the kernel accepted it, so it counts here
		 * as done. Whether the change is still in effect is a different
		 * question and `ncfg_journal_reverted` is the one that answers it: an
		 * apply that succeeded and was then taken back did not retroactively
		 * fail, and reporting it as a failure would send an operator looking
		 * for a fault that never happened.
		 */
		if (journal->records[i].outcome != NCFG_OUTCOME_DONE &&
		    journal->records[i].outcome != NCFG_OUTCOME_REVERTED) {
			return 0;
		}
	}
	return 1;
}

const ncfg_record_t *ncfg_journal_failure(const ncfg_journal_t *journal)
{
	size_t i;

	if (!journal) {
		return NULL;
	}
	for (i = 0; i < journal->record_count; i++) {
		if (journal->records[i].outcome == NCFG_OUTCOME_FAILED) {
			return &journal->records[i];
		}
	}
	return NULL;
}

size_t ncfg_journal_done(const ncfg_journal_t *journal)
{
	return counted(journal, NCFG_OUTCOME_DONE);
}

size_t ncfg_journal_skipped(const ncfg_journal_t *journal)
{
	return counted(journal, NCFG_OUTCOME_SKIPPED);
}

size_t ncfg_journal_reverted(const ncfg_journal_t *journal)
{
	return counted(journal, NCFG_OUTCOME_REVERTED);
}

/* ------------------------------------------------------------------------ *
 * Writing it out
 * ------------------------------------------------------------------------ */

/* A string member, or `null`. `write.c`'s rule: an absent optional member is
 * written rather than tidied away, except for the three the Rust marks
 * `skip_serializing_if` -- of which a reason's `interface` is one. */
static void member_text(ncfg_json_writer_t *writer, const char *name, const char *text)
{
	ncfg_json_write_key(writer, name);
	if (text) {
		ncfg_json_write_string(writer, text);
	} else {
		ncfg_json_write_null(writer);
	}
}

/* The plan writer's shape, member for member: this is the same `Reason`. */
static void write_reason(ncfg_json_writer_t *writer, const ncfg_reason_t *reason)
{
	ncfg_json_write_object_begin(writer);
	if (reason->interface) {
		ncfg_json_write_member_string(writer, "interface", reason->interface);
	}
	member_text(writer, "field", reason->field);
	member_text(writer, "desired", reason->desired);
	member_text(writer, "observed", reason->observed);
	ncfg_json_write_object_end(writer);
}

static void write_record(ncfg_json_writer_t *writer, const ncfg_record_t *record)
{
	const char *outcome = ncfg_outcome_name(record->outcome);

	ncfg_json_write_object_begin(writer);
	ncfg_json_write_member_int(writer, "id", (int64_t)record->id);
	member_text(writer, "op", record->op);
	/* Omitted when absent, not written as null: `Record::interface` carries
	 * `skip_serializing_if` and a writer that wrote it would produce a line
	 * the Rust cannot read back into the same value. */
	if (record->interface) {
		ncfg_json_write_member_string(writer, "interface", record->interface);
	}
	ncfg_json_write_key(writer, "reason");
	write_reason(writer, &record->reason);
	member_text(writer, "outcome", outcome);
	if (record->error) {
		ncfg_json_write_member_string(writer, "error", record->error);
	}
	ncfg_json_write_object_end(writer);
}

int ncfg_journal_write(const ncfg_journal_t *journal, ncfg_buf_t *buf, char *err,
    size_t err_size)
{
	ncfg_json_writer_t writer;
	size_t             i;

	if (!journal || !buf) {
		ncfg_error_set(err, err_size, "a journal and a buffer are both needed to write one");
		return 0;
	}
	if (journal->failed) {
		ncfg_error_set(err, err_size,
		    "this journal ran out of memory while it was being built; "
		    "it would not say what really happened");
		return 0;
	}
	ncfg_json_write_init(&writer, buf);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_key(&writer, "records");
	ncfg_json_write_array_begin(&writer);
	for (i = 0; i < journal->record_count; i++) {
		write_record(&writer, &journal->records[i]);
	}
	ncfg_json_write_array_end(&writer);
	ncfg_json_write_object_end(&writer);
	if (!ncfg_json_write_done(&writer)) {
		const char *why = ncfg_json_write_failure(&writer);

		ncfg_error_set(err, err_size, "could not write the journal: %s",
		    why ? why : "the buffer would not take it");
		return 0;
	}
	return 1;
}
