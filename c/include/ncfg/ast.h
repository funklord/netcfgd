/*
 * ast.h -- what a configuration file says, before any of it means anything.
 *
 * **Deliberately dumb, and that is the design.** A block here is a head, a
 * label and a list of items; whether `interface` may hold a `wifi` block, and
 * what `config = "dhcp"` implies, belong to the module that lowers this into
 * a document. Keeping interpretation out of the tree is what lets every
 * diagnostic point at the text that caused it -- a tree that had already
 * decided what a block meant would have nothing left to point at.
 *
 * **Every node carries its span**, for `lex.h`'s reason: a diagnostic names a
 * line and a column or the reader searches a directory of drop-ins for the
 * line that was meant. The span is the one the lexer produced rather than a
 * position recovered later, because a second pass counting newlines is a
 * second opinion and the two eventually disagree.
 *
 * **One owner, one free.** The Rust this replaces had ownership in the type
 * system; here it is a rule, so it is written down and tested. Every node
 * belongs to the file that holds it and `ncfg_ast_file_free` releases the
 * whole tree: a caller of the parser frees the file and nothing else, and
 * there is no free-per-node to forget. `ncfg_ast_item_free` and
 * `ncfg_ast_value_free` are here for the parser, which builds a node before
 * it has anywhere to put it and has to release that one when the statement
 * around it turns out to be a mistake.
 *
 * **Text that came from a string carries its length; text that came from an
 * identifier does not.** A string may contain a NUL because the source may
 * put one there, and stopping at it would turn a value the operator wrote
 * into a shorter one nobody would ever see was short -- the same position
 * `lex.h` takes about a string token. An identifier cannot contain one:
 * `ncfg_is_ident_continue` has no production for a NUL, so a head, a key or a
 * phase is a C string and treating it as one loses nothing.
 *
 * Conventions are `base.h`'s throughout.
 */
#ifndef NCFG_AST_H
#define NCFG_AST_H

#include <stddef.h>
#include <stdint.h>

#include "ncfg/lex.h"

/*
 * The kinds of value the language has, and there are no others.
 *
 * No float: `lex.h` refuses one by name rather than letting the `.` surface
 * as punctuation, so nothing downstream has to have an opinion about a
 * number that is not an integer. A secret reference is a string here --
 * `"@secret:cafe"` is text until the module that lowers this looks at it,
 * which is where the knowledge of what a sigil means belongs.
 */
typedef enum {
	NCFG_AST_STRING,
	NCFG_AST_NUMBER,
	NCFG_AST_BOOL,
	NCFG_AST_LIST
} ncfg_ast_value_kind_t;

typedef struct ncfg_ast_value ncfg_ast_value_t;

/*
 * A growable run of values, which is what a list holds.
 *
 * `at` is an array of pointers rather than of values because a growing array
 * moves, and the parser holds a child while it builds the next one. Read
 * `at` and `count`; `capacity` is the builder's and means nothing to a
 * reader.
 */
typedef struct {
	ncfg_ast_value_t **at;
	size_t             count;
	size_t             capacity;
} ncfg_ast_values_t;

/*
 * A value on the right of an `=`.
 *
 * One struct with a kind rather than a union, because every arm carries a
 * span and a union would put the common field outside it anyway. Only the
 * field the kind names is meaningful; the rest are zero.
 */
struct ncfg_ast_value {
	ncfg_ast_value_kind_t kind;
	/* Where it was written. */
	ncfg_span_t           span;
	/* NCFG_AST_STRING: NUL-terminated, with the byte count beside it. */
	char                 *string;
	size_t                string_length;
	/* NCFG_AST_NUMBER. */
	int64_t               number;
	/* NCFG_AST_BOOL. */
	int                   boolean;
	/* NCFG_AST_LIST. */
	ncfg_ast_values_t     entries;
};

/* The kinds of statement. */
typedef enum {
	NCFG_AST_ITEM_BLOCK,
	NCFG_AST_ITEM_ASSIGNMENT,
	NCFG_AST_ITEM_HOOK,
	NCFG_AST_ITEM_INCLUDE
} ncfg_ast_item_kind_t;

typedef struct ncfg_ast_item ncfg_ast_item_t;

/* A growable run of statements, for the same reason `ncfg_ast_values_t` is
 * one. A file holds one of these and so does every block. */
typedef struct {
	ncfg_ast_item_t **at;
	size_t            count;
	size_t            capacity;
} ncfg_ast_items_t;

/* A `key = value` line. `span` is the key's, because that is what a
 * diagnostic about the line should underline. */
typedef struct {
	char             *key;
	ncfg_ast_value_t *value;
	ncfg_span_t       span;
} ncfg_ast_assignment_t;

/*
 * A `phase { ... }` block whose body is raw shell.
 *
 * `phase` is the word as written -- `post_up`, or the event after `on` -- and
 * is not turned into `ncfg_hook_phase_t` here: a phase this build does not
 * know has to reach the lowering module as text, or the diagnostic that names
 * it can only say that something was wrong.
 *
 * `body` is exactly the bytes `ncfg_lexer_hook_body` handed back, closing
 * line excluded and every other newline kept. A hook body is shell:
 * re-indenting it, or dropping the newline off its last line, changes what
 * the shell does.
 */
typedef struct {
	char       *phase;
	char       *body;
	size_t      body_length;
	ncfg_span_t span;
} ncfg_ast_hook_t;

/* `include "path"`. Resolution is the caller's job and this compiler opens no
 * files, which is what keeps the whole front end testable from fixtures with
 * no filesystem at all. */
typedef struct {
	char       *path;
	size_t      path_length;
	ncfg_span_t span;
} ncfg_ast_include_t;

/*
 * A `head label { ... }` block.
 *
 * `label` is NULL where the block takes none -- `global` has no name --
 * rather than an empty string, because `network "" { }` is a different
 * mistake from `network { }` and the module that refuses them has to be able
 * to tell which was written.
 */
typedef struct {
	char            *head;
	char            *label;
	size_t           label_length;
	/* Whether `override` preceded it. */
	int              overrides;
	ncfg_ast_items_t items;
	/* Position of the head keyword. */
	ncfg_span_t      span;
} ncfg_ast_block_t;

/*
 * One statement.
 *
 * A union, because an item is exactly one of these and a struct with four
 * pointers would let two be set at once -- which is the state no reader of
 * this tree should have to consider. Read `kind` first and then the arm it
 * names.
 */
struct ncfg_ast_item {
	ncfg_ast_item_kind_t kind;
	union {
		ncfg_ast_block_t      block;
		ncfg_ast_assignment_t assignment;
		ncfg_ast_hook_t       hook;
		ncfg_ast_include_t    include;
	} as;
};

/* One parsed file: its statements, in the order written. Order is kept
 * because precedence is by position -- a later drop-in wins -- and a tree
 * that sorted itself would have thrown that away. */
typedef struct {
	ncfg_ast_items_t items;
} ncfg_ast_file_t;

/*
 * Release a whole tree.
 *
 * The one free a caller of the parser needs. Freeing NULL is nothing, which
 * is the rule every error path in the parser is written on.
 *
 * It walks the tree recursively, and that is safe only because the parser
 * refuses anything nested deeper than `NCFG_MAX_NESTING_DEPTH`: a tree built
 * by something that did not bound itself could take the stack out here
 * instead. Nothing but the parser builds one of these, and that is why.
 */
void ncfg_ast_file_free(ncfg_ast_file_t *file);

/* Release one detached node and everything under it. For the parser, which
 * builds a node before it has anywhere to put it; a caller holding a tree
 * frees the file and never these. */
void ncfg_ast_item_free(ncfg_ast_item_t *item);
void ncfg_ast_value_free(ncfg_ast_value_t *value);

/*
 * A name for this kind of value, for "expected X, found Y".
 *
 * Described rather than quoted -- "a string", not the string -- for
 * `ncfg_token_describe`'s reason: reciting a value the reader just wrote says
 * nothing they did not know.
 */
const char *ncfg_ast_value_describe(const ncfg_ast_value_t *value);

/* `interface eth0`, or `global` where there is no label. Always
 * NUL-terminates. A label with a NUL in it is printed up to the NUL and no
 * further, which is the one place this module lets that happen: this string
 * is for a human to read, not for anything to compare against. */
void ncfg_ast_block_describe(const ncfg_ast_block_t *block, char *out, size_t out_size);

/*
 * Whether two blocks are the same block, for the redefinition check.
 *
 * Head and label together, compared over the label's full length rather than
 * to its first NUL. It lives here, beside the fields, so that the merge and
 * the diagnostic cannot come to disagree about what "already defined" means.
 */
int ncfg_ast_block_same_key(const ncfg_ast_block_t *first, const ncfg_ast_block_t *second);

#endif /* NCFG_AST_H */
