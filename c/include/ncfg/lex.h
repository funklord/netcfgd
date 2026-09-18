/*
 * lex.h -- tokens, where they came from, and the one production that is not
 * tokenised at all.
 *
 * **Every token carries its span, and that is half of what this module is
 * for.** A parse error names a file, a line and a column because otherwise
 * the reader searches a directory of drop-ins for the line that was meant --
 * so a token that knows only what it is and not where it was found makes
 * every diagnostic built on top of it useless. The span is kept on the token
 * rather than recovered later: a second pass counting newlines would be a
 * second opinion about a position, and the two would eventually disagree.
 *
 * **The lexer copies nothing and opens nothing.** It reads the bytes the
 * caller handed in and leaves them there; the only allocations are the text
 * of an identifier or a string, whose escapes have been resolved and which
 * therefore is not a slice of anything, and a hook body.
 *
 * **A hook body is raw shell and must not be tokenised at all.** That is why
 * this is a hand-written cursor rather than a table: the caller steps out of
 * the token stream at `{`, takes the body as lines, and steps back in.
 * `ncfg_lexer_hook_body` says what ends a body and what that costs.
 *
 * Conventions are `base.h`'s: 1 for success, 0 for failure, `char *err,
 * size_t err_size` last, and an `ncfg_x_free` beside anything handed out.
 * A failure also leaves `ncfg_lexer_error_span` pointing at what the sentence
 * in the error buffer is about, because an error message with no position is
 * the thing the paragraph above exists to prevent.
 */
#ifndef NCFG_LEX_H
#define NCFG_LEX_H

#include <stddef.h>
#include <stdint.h>

/*
 * A position in the text, and how much of it something covers.
 *
 * `offset` and `length` are bytes from the start of the text; `line` and
 * `column` are one-based and are what a diagnostic prints. Both pairs are
 * kept because they answer different questions -- a caret needs the byte
 * range, a message needs the line -- and deriving either from the other at
 * report time means counting the file again.
 *
 * `column` counts bytes, not characters: a two-byte character inside a string
 * moves it by two.
 *
 * When the diagnostics module lands it takes this type from here rather than
 * growing its own. Two spellings of a position is how a caret ends up under
 * the wrong column.
 */
typedef struct {
	size_t offset;
	size_t length;
	size_t line;
	size_t column;
} ncfg_span_t;

/* The kinds of token. `NCFG_TOKEN_TERMINATOR` is a newline or a semicolon:
 * the grammar ends a statement with either, and the parser must not care
 * which was written. */
typedef enum {
	NCFG_TOKEN_IDENT,
	NCFG_TOKEN_STRING,
	NCFG_TOKEN_NUMBER,
	NCFG_TOKEN_BOOL,
	NCFG_TOKEN_LBRACE,
	NCFG_TOKEN_RBRACE,
	NCFG_TOKEN_LBRACKET,
	NCFG_TOKEN_RBRACKET,
	NCFG_TOKEN_EQUALS,
	NCFG_TOKEN_COMMA,
	NCFG_TOKEN_TERMINATOR,
	NCFG_TOKEN_EOF
} ncfg_token_kind_t;

/*
 * A token together with where it came from.
 *
 * `text` belongs to the token and is NUL-terminated, for an identifier or a
 * string and nothing else. `text_length` is carried beside it because a
 * string is bytes rather than a C string -- the source may put a NUL in one,
 * and truncating there would turn a value the operator wrote into a shorter
 * one nobody would ever see was short.
 *
 * `number` is only meaningful for `NCFG_TOKEN_NUMBER` and `boolean` only for
 * `NCFG_TOKEN_BOOL`. There are no floats in this language; see
 * `ncfg_lexer_next`.
 */
typedef struct {
	ncfg_token_kind_t kind;
	ncfg_span_t       span;
	char             *text;
	size_t            text_length;
	int64_t           number;
	int               boolean;
} ncfg_token_t;

/*
 * A cursor over one file's text.
 *
 * The fields are here so a caller can put one on the stack; read them rather
 * than writing them. `error_span` means something only after a call from this
 * module has returned 0.
 */
typedef struct {
	const char *text;
	size_t      length;
	size_t      position;
	size_t      line;
	size_t      column;
	ncfg_span_t error_span;
} ncfg_lexer_t;

/*
 * Start at the beginning of `length` bytes at `text`.
 *
 * The text is borrowed and must outlive the lexer and every token it hands
 * back -- except that a token's own `text` is a copy, so a token outlives the
 * source it came from. That asymmetry is deliberate: escapes are resolved, so
 * a string token was never a slice of the source in the first place.
 */
void ncfg_lexer_init(ncfg_lexer_t *lexer, const char *text, size_t length);

/* Where the cursor is now, as an empty span. What a caller reports when it
 * runs out of input and has no token to blame. */
ncfg_span_t ncfg_lexer_span(const ncfg_lexer_t *lexer);

/* What the last failure was about. Only meaningful after a 0 return. */
ncfg_span_t ncfg_lexer_error_span(const ncfg_lexer_t *lexer);

/*
 * The next token, or 0 with a sentence in `err`.
 *
 * Fails for an unterminated string, an unknown escape, a number that does not
 * fit in 64 bits, a float -- which is refused by name here rather than
 * letting the `.` surface as an unexpected character on the next token, where
 * the message would be about punctuation instead of about the rule -- or a
 * character the grammar has no production for.
 *
 * On failure the cursor has moved, and that is intentional: the parser turns
 * a lexer failure into a diagnostic and keeps going, so that a file with
 * three mistakes reports three rather than the first.
 *
 * `out` is overwritten and owns its `text`; free it with `ncfg_token_free`.
 */
int ncfg_lexer_next(ncfg_lexer_t *lexer, ncfg_token_t *out, char *err, size_t err_size);

/* Release what a token holds. A token that was never filled in, or has
 * already been freed, costs nothing. */
void ncfg_token_free(ncfg_token_t *token);

/*
 * A name for this token, for "expected X, found Y". Always NUL-terminates.
 *
 * An identifier is quoted and named, everything else is described -- "a
 * string", not the string, because a diagnostic that quotes back a value the
 * reader just wrote says nothing they did not know.
 */
void ncfg_token_describe(const ncfg_token_t *token, char *out, size_t out_size);

/*
 * Take raw lines up to and including the first line that is nothing but a
 * closing brace, and hand back everything before it.
 *
 * This is the one irregular production in the grammar. A hook body is
 * arbitrary shell, so brace counting would mean parsing shell; ending at a
 * lone `}` line needs no shell knowledge and is explainable in one sentence
 * of documentation.
 *
 * **Braces nested inside the shell are not irrelevant.** A shell function is
 * the commonest multi-line construct there is and it closes with a `}` alone
 * on a line, so writing one inside a hook ends the body early and the rest of
 * the shell is then read as configuration -- which fails somewhere else,
 * talking about `=` and `{` at a line the operator wrote shell on. The rule
 * is right and the cost is real, so the sentence of documentation is actually
 * written, in the README and in `netcfgd.conf.example`, with the one-line
 * form that works.
 *
 * The line is trimmed before it is compared, so an indented `}` still ends
 * the body -- a hook inside an `interface` block is written indented, and a
 * rule that only saw a brace in column one would never fire on a real file.
 *
 * Fails if the text ends before that line. `*body_out` is NUL-terminated and
 * the caller frees it; `length_out` may be NULL, and is the length in bytes,
 * for the same reason a string token carries one.
 */
int ncfg_lexer_hook_body(ncfg_lexer_t *lexer, char **body_out, size_t *length_out,
    char *err, size_t err_size);

/*
 * Whether a byte may start, or continue, an identifier.
 *
 * Exposed because the rule is a fact about the language rather than about
 * this cursor: whatever validates a name later has to agree with what was
 * lexed, and two copies of this would eventually not.
 */
int ncfg_is_ident_start(unsigned char byte);
int ncfg_is_ident_continue(unsigned char byte);

#endif /* NCFG_LEX_H */
