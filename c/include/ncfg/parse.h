/*
 * parse.h -- the grammar, as a recursive descent parser over `lex.h`.
 *
 * **It reports every mistake, not the first.** A configuration with four
 * errors should take one edit round rather than four, so the parser recovers
 * at the next statement boundary and keeps going -- and a lexer failure
 * becomes a diagnostic rather than the end of the parse, which is why
 * `ncfg_lexer_next` leaves its cursor usable after a failure. That is the
 * whole reason this module hands back a list of diagnostics instead of the
 * single sentence `base.h`'s convention would otherwise ask for. The
 * convention is still kept: 1 for success, 0 for failure, `char *err` last,
 * and the first diagnostic's sentence is what lands in `err` for a caller
 * that wants no more than that.
 *
 * **It opens no files.** `include "path"` becomes a node; resolving it is the
 * caller's, which is what lets the whole front end be tested from fixtures
 * with no filesystem at all.
 *
 * Every node it produces carries a span, and the tree it produces is freed
 * with one call. See `ast.h`.
 */
#ifndef NCFG_PARSE_H
#define NCFG_PARSE_H

#include <stddef.h>

#include "ncfg/ast.h"
#include "ncfg/lex.h"

/*
 * How deeply anything may nest before the parser refuses.
 *
 * **The limit is 32, and it is not decoration.** The parser descends once per
 * `{` *and once per `[`*, so without a bound a file of nothing but open
 * braces -- or open brackets -- exhausts the stack. That is a crash rather
 * than a diagnostic, in a daemon that re-reads its configuration directory
 * whenever anything in it changes, on input an unprivileged edit can produce.
 *
 * `cargo fuzz` on the `config_parse` target found it twice. The first report
 * was an `AddressSanitizer` stack-overflow on 3679 bytes containing 1238 `{`,
 * and bounding blocks alone did not fix it: re-running the fuzzer against
 * that fix found `parse_value` -> `parse_list` -> `parse_value`, the same
 * defect down a path a block counter cannot see. So there is **one counter
 * for both**, and a third nesting construct cannot be given its own private
 * budget. Both those inputs are in `tests/parse_test.c`, the first one
 * verbatim.
 *
 * Thirty-two is roughly ten times the deepest nesting the language actually
 * has -- `interface` holds `qdisc` holds its keys, and that is three -- so no
 * real configuration comes near it, and a file that does is a mistake worth
 * naming rather than a shape worth supporting.
 */
#define NCFG_MAX_NESTING_DEPTH 32

/*
 * How many diagnostics one parse keeps.
 *
 * The Rust kept every one, which is right in a test harness and wrong in a
 * daemon: a diagnostic per token is a file-sized allocation bought with a
 * malformed file, and the input that overflowed the stack produces one for
 * every brace in it. Nobody reads the sixty-fifth message either. So the
 * first `NCFG_DIAGS_MAX` are kept and `total` goes on counting, which lets a
 * caller say how many more there were rather than pretending there were none.
 */
#define NCFG_DIAGS_MAX 64

/*
 * One failure, as a sentence and a place.
 *
 * `message` is a single sentence and never has a second line. Where the Rust
 * attached a separate help string, the two are joined with `": "` -- which is
 * how `lex.c` already renders the ones it inherited ("unterminated string: a
 * string runs to its closing quote, across lines if need be"), and two
 * spellings of one message is how a grep for a diagnostic finds half of them.
 */
typedef struct {
	ncfg_span_t span;
	char       *message;
} ncfg_diag_t;

/*
 * Every failure a parse found.
 *
 * Declare one as `ncfg_diags_t diags = {0}` -- there is nothing else to set
 * up -- and free it with `ncfg_diags_free`. `count` is how many are kept here
 * and `total` is how many were found; they differ only past
 * `NCFG_DIAGS_MAX`.
 */
typedef struct {
	ncfg_diag_t *at;
	size_t       count;
	size_t       total;
	size_t       capacity;
} ncfg_diags_t;

/* Release what a set of diagnostics holds, and leave it usable and empty.
 * Freeing one that was never filled in is nothing. */
void ncfg_diags_free(ncfg_diags_t *diags);

/*
 * `name:line:column: message`, which is what an operator reads.
 *
 * The file name is the caller's because this module is never told one: it is
 * handed bytes, and the thing that read the directory is the only thing that
 * knows which file they came from. Always NUL-terminates; a NULL or empty
 * name renders as `<unknown>` rather than leaving a stray colon.
 */
void ncfg_diag_render(const ncfg_diag_t *diag, const char *name, char *out, size_t out_size);

/*
 * Parse `length` bytes at `text`.
 *
 * Returns 1 with a tree in `*file_out`, or 0 with `*file_out` NULL and a
 * sentence in `err`. A partly built tree is never handed back: a file with a
 * mistake in it parsed into a document would be a configuration the operator
 * did not write, and the parser has no way to know which half survived.
 *
 * `diags` may be NULL for a caller that wants only the first sentence, and
 * where it is given it holds every failure with the position of each. A
 * caller that will show the error to a human passes one, because `err` is the
 * sentence alone -- the position of the first failure is
 * `diags->at[0].span`, the same split `lex.h` makes between its error buffer
 * and `ncfg_lexer_error_span`.
 *
 * The text is borrowed and need not outlive the call: every string in the
 * tree is a copy, for the reason `ncfg_lexer_init` gives.
 */
int ncfg_parse(const char *text, size_t length, ncfg_ast_file_t **file_out,
    ncfg_diags_t *diags, char *err, size_t err_size);

#endif /* NCFG_PARSE_H */
