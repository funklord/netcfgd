/*
 * record_emit.c -- the walk, the encode, and the tally.
 *
 * `record_emit.h` carries why this exists and why it signs nothing.
 */
#include "record_emit.h"

#include <stdio.h>
#include <string.h>

typedef struct {
	const fzn_hash_ops_t    *hash;
	const ncfg_emit_roots_t *roots;
	ncfg_emit_fn             sink;
	void                    *ctx;
	ncfg_emit_tally_t       *tally;
	int                      going;
} emit_t;

/* The root a block's objects hang from, or NULL where the caller gave none. */
static const ncfg_record_rootref_t *root_for(const ncfg_emit_roots_t *roots,
    ncfg_block_t block)
{
	switch (ncfg_record_root_of(block)) {
	case NCFG_ROOT_GROUP:
		return roots->group;
	case NCFG_ROOT_ESTATE:
		return roots->estate;
	case NCFG_ROOT_HOST:
	default:
		return roots->host;
	}
}

static int visit(void *ctx, const ncfg_walk_item_t *item)
{
	emit_t                      *emit = ctx;
	const ncfg_record_rootref_t *root;
	ncfg_record_fields_t         fields;
	ncfg_record_err_t            made;

	if (item->what == NCFG_WALK_WITHHELD) {
		if ((size_t)item->withheld < NCFG_EMIT_REASONS) {
			emit->tally->withheld[item->withheld]++;
		}
		return emit->going;
	}

	root = root_for(emit->roots, item->block);
	if (!root) {
		/*
		 * **Counted as refused rather than guessed at.** A document names no
		 * estate and no group; those are a deployment's, and inventing one
		 * here would put records under a subject nobody chose -- which is the
		 * one mistake a subject cannot recover from, every host deriving a
		 * different one.
		 */
		emit->tally->refused++;
		emit->tally->last_refusal = NCFG_RECORD_ERR_SUBJECT;
		return emit->going;
	}

	made = ncfg_record_encode(emit->hash, item->block, root, item->label, item->label_len,
	    item->path, item->value, item->value_len, &fields);
	if (made != NCFG_RECORD_OK) {
		/*
		 * The walker already refused what the SCOPE and the registry refuse,
		 * so what reaches here is about the VALUE: too large for a body, or
		 * carrying a NUL. A configuration acquires one of these by growing a
		 * list, with nothing about the key changing.
		 */
		emit->tally->refused++;
		emit->tally->last_refusal = made;
		return emit->going;
	}

	emit->tally->emitted++;
	if (emit->sink && !emit->sink(emit->ctx, item, &fields)) {
		emit->going = 0;
	}
	return emit->going;
}

int ncfg_records_of(const char *text, size_t length, const fzn_hash_ops_t *hash,
    const ncfg_emit_roots_t *roots, ncfg_emit_fn sink, void *ctx, ncfg_emit_tally_t *tally,
    char *err, size_t err_size)
{
	emit_t            emit;
	ncfg_emit_tally_t counted;

	if (!tally) {
		tally = &counted;
	}
	memset(tally, 0, sizeof(*tally));
	if (!text || !hash || !roots) {
		if (err && err_size > 0u) {
			(void)snprintf(err, err_size, "nothing to emit records from");
		}
		return 0;
	}

	emit.hash = hash;
	emit.roots = roots;
	emit.sink = sink;
	emit.ctx = ctx;
	emit.tally = tally;
	emit.going = 1;

	if (!ncfg_walk(text, length, visit, &emit, err, err_size)) {
		/* The walk visited nothing, so the tally it filled is about a document
		 * nobody wrote. Zeroed rather than left part-counted. */
		memset(tally, 0, sizeof(*tally));
		return 0;
	}
	return 1;
}
