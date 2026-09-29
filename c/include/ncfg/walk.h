/*
 * walk.h -- every configuration key in a document, with the value as written
 * and the verdict on whether it may travel.
 *
 * WHAT THIS IS FOR
 *   `compile/scope.c` answers about one key at a time. This finds the keys.
 *   It is the producer for `bridge/record_encode.h`, which turns one key and
 *   its value into a statement fuzznet can carry, and it is the reader half of
 *   the mirror in project.md 10.324: an operator's edit of a rendered file
 *   comes back through here as a sequence of keys and values.
 *
 * IT WALKS TEXT, AND A DOCUMENT IS TEXT ONCE RENDERED
 *   The value it hands back is a SLICE of the source -- the bytes the operator
 *   or the renderer wrote -- so the input has to be the text. A caller holding
 *   an `ncfg_document_t` renders it with `ncfg_render` and walks the result,
 *   which is the same path a config file takes.
 *
 * WHY A SLICE AND NOT A SPELLING
 *   **So that there is no second value encoder.** `render.c` writes a value
 *   and `parse.c` reads it, and those two are deliberately disciplined against
 *   each other; a third that re-spelled an AST node would be a new thing for
 *   both to disagree with. A slice is what was written, so `key = <slice>`
 *   re-parses to the value it came from -- which is a property a test can
 *   assert rather than a claim this comment makes.
 *
 *   It cost one parser fix to be true. A list's span covered its opening
 *   bracket alone, so every list sliced to `[`; `parse.c`'s `close_list` says
 *   what that was and what it also cost a diagnostic.
 *
 * NOTHING IS SKIPPED SILENTLY
 *   A key that may not travel is reported as `NCFG_WALK_WITHHELD` with a
 *   reason, not passed over. A walk that quietly emitted less than it was
 *   asked for is the failure this tree keeps finding -- a build with no
 *   backend, a gate over an empty file list -- and here it would be a host
 *   whose configuration silently half-replicated.
 */
#ifndef NCFG_WALK_H
#define NCFG_WALK_H

#include "ncfg/lex.h"
#include "ncfg/scope.h"

#include <stddef.h>

typedef enum {
	/* A key, its value, its scope and its wire number. */
	NCFG_WALK_EMIT = 0,
	/* A key with a value that may not become a record. `why` says which of
	 * the reasons it is, and the caller decides whether to care -- but it
	 * had to be handed one to ignore. */
	NCFG_WALK_WITHHELD
} ncfg_walk_what_t;

/* Why something was withheld. Ordered by permanence rather than by when the
 * walk notices: a caller reporting one of these to an operator wants to say
 * "never" or "not yet" correctly. */
typedef enum {
	NCFG_WITHHELD_NONE = 0,
	/* A `phase { }` body is shell, and an `include` is a path. Neither can
	 * travel at all: "a document that can carry shell is remote code
	 * execution with extra steps". */
	NCFG_WITHHELD_PROGRAM,
	/* The key is host-private. Permanent, and above the next one because
	 * it is about the KEY: such a key does not travel whatever is written
	 * on the right of the `=`. */
	NCFG_WITHHELD_HOST_PRIVATE,
	/* The VALUE names a file this machine can read, under a key that also
	 * accepts a stored secret. `document.h` on `ncfg_cert_source_t`: a
	 * path "is an instruction to open it *as root*; a caller who is not
	 * root cannot send one". Permanent for this value and not for the key
	 * -- the same key written `@secret:name` travels. */
	NCFG_WITHHELD_PRIVILEGED,
	/* The key has no wire number yet. Not permanent: see the kind
	 * registry, which is filled in over time. */
	NCFG_WITHHELD_UNREGISTERED,
	/* A block this build does not know. Its whole contents are withheld
	 * under one report rather than key by key, because nothing here can
	 * say what a key inside it means. */
	NCFG_WITHHELD_UNKNOWN_BLOCK
} ncfg_withheld_t;

/*
 * One key, or one thing that will not be one.
 *
 * **Every pointer borrows.** `value` points into the text the caller passed
 * and is NOT NUL-terminated -- a value may legitimately contain a NUL, which
 * `ast.h` records as the reason a string carries its length. `path`,
 * `block_name` and `label` point into storage that lives until the visit
 * returns and no longer.
 */
typedef struct {
	ncfg_walk_what_t what;
	/* Meaningful for everything but an unknown block. */
	ncfg_block_t     block;
	const char      *block_name;
	/* The block's label -- an interface's name, a network's id -- or NULL
	 * where the block takes none. `global` has none.
	 *
	 * **With a length, because a label can be an SSID** and an SSID is 32
	 * arbitrary bytes rather than a C string. `bridge/record_encode.h`
	 * hashes it into a subject and takes it the same way; passing the
	 * pointer alone would silently shorten a network whose name holds a
	 * NUL, and two such networks would then share a cell. */
	const char      *label;
	size_t           label_len;
	/* The key's path within the block: `mtu`, `advertise.prefix`. Empty
	 * for a report about the block itself. */
	const char      *path;
	/* As written, borrowed from the caller's text. */
	const char      *value;
	size_t           value_len;
	/* EMIT only. */
	ncfg_scope_t     scope;
	unsigned         kind;
	/* WITHHELD only. */
	ncfg_withheld_t  withheld;
	/* Where it was written, for a diagnostic. */
	ncfg_span_t      span;
} ncfg_walk_item_t;

/* Return nonzero to carry on, zero to stop the walk. Stopping is not a
 * failure: `ncfg_walk` returns 1 either way, because a caller that has seen
 * enough has not met a broken document. */
typedef int (*ncfg_walk_fn)(void *ctx, const ncfg_walk_item_t *item);

/*
 * Walk `length` bytes of configuration text.
 *
 * Returns 1 having visited everything, or 0 with a sentence in `err` when the
 * text does not parse -- in which case nothing was visited, because a document
 * with a mistake in it is not a document somebody wrote.
 */
int ncfg_walk(const char *text, size_t length, ncfg_walk_fn visit, void *ctx, char *err,
    size_t err_size);

/* What a verdict means, for a log line or a diagnostic. Never NULL. */
const char *ncfg_withheld_why(ncfg_withheld_t withheld);

#endif /* NCFG_WALK_H */
