/*
 * record_emit.h -- everything a configuration would put on the wire, and
 * everything it would not.
 *
 * WHAT THIS JOINS
 *   `compile/walk.h` finds the keys and says which may travel.
 *   `record_encode.h` turns one key and its value into the fields a record
 *   carries. Both existed and nothing put them together, so the question the
 *   whole chain was built to answer -- *what of this machine's configuration
 *   can be replicated* -- had never been asked of an actual document.
 *
 * IT SIGNS NOTHING
 *   The issuer, the sequence and the clock are a node's, not a document's.
 *   This hands each record's fields to a sink and lets the caller sign them,
 *   for the reason `record_encode.h` gives: a function holding a signer is one
 *   somebody calls with it when they meant to ask a question.
 *
 * THE TALLY IS THE POINT AS MUCH AS THE RECORDS
 *   A configuration that produces eleven records and withholds forty is a
 *   different thing from one that produces fifty, and neither is visible from
 *   either half alone. The counts are per reason, so "this machine replicates
 *   almost nothing because almost nothing is registered" and "because almost
 *   all of it is host-private" are different answers rather than one number.
 *
 * AND THE ENCODER CAN STILL REFUSE WHAT THE WALKER PASSED
 *   The walker checks the scope and the wire number; it does not check the
 *   value. A body over `FZN_RECORD_BODY_MAX`, or one carrying a NUL, is
 *   refused here and counted apart -- those are the keys a document can hold
 *   and a record cannot, which is a limit worth knowing before somebody writes
 *   a configuration that silently half-replicates.
 */
#ifndef NCFG_RECORD_EMIT_H
#define NCFG_RECORD_EMIT_H

#include "record_encode.h"

#include "ncfg/walk.h"

#include <stddef.h>

/*
 * One per `ncfg_withheld_t`, indexed by it.
 *
 * **Derived from the enum, not counted by hand.** This was a literal `6u`, and
 * `record_emit.c` guards the index with `<` -- so adding a reason to `walk.h`
 * would have kept compiling, kept passing, and silently counted the newest
 * reason as nothing. A tally whose denominator is a number somebody typed is
 * the vacuous count `evidence.md` opens with, and the fix is to make the array
 * grow with the thing it counts.
 */
#define NCFG_EMIT_REASONS ((size_t)NCFG_WITHHELD_REASONS)

typedef struct {
	/* Keys that became a record's fields. */
	size_t emitted;
	/* Keys the walker would not pass, by `ncfg_withheld_t`. */
	size_t withheld[NCFG_EMIT_REASONS];
	/*
	 * Keys the walker passed and the encoder refused: a value too large for a
	 * body, or one carrying a NUL. Counted apart because the walker's reasons
	 * are about the KEY and these are about the VALUE -- a configuration can
	 * acquire one by growing a list, with nothing about the key changing.
	 */
	size_t refused;
	/* The last refusal, for a caller that wants to say which. */
	ncfg_record_err_t last_refusal;
} ncfg_emit_tally_t;

/* Where the roots come from, one per kind, since a document names none of
 * them: a host is this machine's key, and a group and an estate are names
 * somebody chose. Any may be NULL, and a block rooting at a kind with no root
 * is counted as refused rather than guessed at. */
typedef struct {
	const ncfg_record_rootref_t *host;
	const ncfg_record_rootref_t *group;
	const ncfg_record_rootref_t *estate;
} ncfg_emit_roots_t;

/*
 * One record's worth of fields, with the key they came from.
 *
 * `block`, `label` and `path` are borrowed from the walk and die with the
 * call; `fields.body` borrows the caller's text. Return nonzero to carry on.
 */
typedef int (*ncfg_emit_fn)(void *ctx, const ncfg_walk_item_t *key,
    const ncfg_record_fields_t *fields);

/*
 * Walk `text` and offer every key that can travel.
 *
 * Returns 1 having walked it, or 0 with a sentence in `err` when the text does
 * not parse -- in which case nothing was offered and the tally is zero, because
 * a document with a mistake in it is not a document somebody wrote.
 *
 * `sink` may be NULL for a caller that wants only the tally, which is the
 * cheap way to ask what a configuration would replicate without building
 * anything.
 */
int ncfg_records_of(const char *text, size_t length, const fzn_hash_ops_t *hash,
    const ncfg_emit_roots_t *roots, ncfg_emit_fn sink, void *ctx, ncfg_emit_tally_t *tally,
    char *err, size_t err_size);

#endif /* NCFG_RECORD_EMIT_H */
