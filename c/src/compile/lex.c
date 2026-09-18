/*
 * lex.c -- the cursor described in lex.h.
 */
#include "ncfg/lex.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* How much of a number a message quotes back. Long enough for any number a
 * person meant to write, short enough that a file of digits cannot push the
 * rest of the sentence out of the error buffer. */
#define NUMBER_SHOWN 40

int ncfg_is_ident_start(unsigned char byte)
{
	return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') || byte == '_';
}

int ncfg_is_ident_continue(unsigned char byte)
{
	/* A dot is legal *inside* an identifier and not at the start, which is
	 * what keeps `eth0.42` an interface name while a bare `.42` stays an
	 * error. Linux names VLAN interfaces that way by universal convention
	 * and the design's own example is `interface eth0.42`, so without this
	 * the standard spelling of the commonest virtual interface does not
	 * parse.
	 *
	 * It cannot be confused with a float: a number never begins with a
	 * letter, and floats are refused by the number lexer independently. */
	return ncfg_is_ident_start(byte) || (byte >= '0' && byte <= '9') || byte == '-'
	    || byte == '.';
}

/*
 * The byte under the cursor, or -1 where the text has run out.
 *
 * Not 0 for the end: a NUL byte in the source is data, and a lexer that took
 * it for an end would stop half way through a file with no complaint. The
 * buffer type takes the same position about a NUL in what it holds.
 */
static int peek_byte(const ncfg_lexer_t *lexer)
{
	if (lexer->position >= lexer->length) {
		return -1;
	}
	return (unsigned char)lexer->text[lexer->position];
}

static int bump(ncfg_lexer_t *lexer)
{
	int byte = peek_byte(lexer);

	if (byte < 0) {
		return -1;
	}
	lexer->position++;
	if (byte == '\n') {
		lexer->line++;
		lexer->column = 1u;
	} else {
		lexer->column++;
	}
	return byte;
}

static ncfg_span_t span_here(const ncfg_lexer_t *lexer)
{
	ncfg_span_t span;

	span.offset = lexer->position;
	span.length = 0;
	span.line = lexer->line;
	span.column = lexer->column;
	return span;
}

/* `start` extended to cover everything consumed since. The line and column
 * stay at the start, because that is where a reader is sent. */
static ncfg_span_t span_to(const ncfg_lexer_t *lexer, ncfg_span_t start)
{
	start.length = lexer->position - start.offset;
	return start;
}

/*
 * Every failure in this module goes through here.
 *
 * It sets the span and the sentence together rather than leaving either to a
 * caller, because a failure path that sets only one of them is exactly the
 * path nobody notices until an operator gets a message with nowhere to look.
 */
static int fail(ncfg_lexer_t *lexer, ncfg_span_t span, char *err, size_t err_size,
    const char *format, ...)
{
	va_list args;

	lexer->error_span = span;
	va_start(args, format);
	ncfg_error_setv(err, err_size, format, args);
	va_end(args);
	return 0;
}

/*
 * A byte as a message says it.
 *
 * Itself when it is printable, and its value when it is not: a control
 * character copied out of a file and into a diagnostic reaches a terminal,
 * and the terminal does what the character says rather than printing it.
 */
static void describe_byte(int byte, char *out, size_t out_size)
{
	if (byte >= 0x20 && byte < 0x7f) {
		(void)snprintf(out, out_size, "%c", (char)byte);
	} else {
		(void)snprintf(out, out_size, "\\x%02x", (unsigned int)byte);
	}
}

static char *copy_range(const char *bytes, size_t length)
{
	char *copy = malloc(length + 1u);

	if (!copy) {
		return NULL;
	}
	if (length) {
		memcpy(copy, bytes, length);
	}
	copy[length] = '\0';
	return copy;
}

/*
 * Hand a buffer's bytes over, NUL-terminated, or NULL if something failed.
 *
 * `ncfg_buf_take` answers NULL for a buffer that never allocated, and that is
 * the empty string rather than a failure -- `""` is a value an operator
 * writes and an empty hook body is legal. So emptiness is turned into a
 * one-byte allocation here, and only a buffer that says it failed, or a
 * refused `malloc`, is a failure.
 */
static char *take_text(ncfg_buf_t *buf, size_t *length_out)
{
	char *taken;

	if (ncfg_buf_failed(buf)) {
		return NULL;
	}
	taken = ncfg_buf_take(buf, length_out);
	if (taken) {
		return taken;
	}
	taken = malloc(1u);
	if (taken) {
		taken[0] = '\0';
	}
	return taken;
}

/*
 * Skip spaces, tabs, carriage returns and comments, but never a newline: a
 * newline is a statement terminator and the parser needs to see it.
 */
static void skip_trivia(ncfg_lexer_t *lexer)
{
	for (;;) {
		int byte = peek_byte(lexer);

		if (byte == ' ' || byte == '\t' || byte == '\r') {
			(void)bump(lexer);
		} else if (byte == '#') {
			int next = peek_byte(lexer);

			while (next >= 0 && next != '\n') {
				(void)bump(lexer);
				next = peek_byte(lexer);
			}
		} else {
			return;
		}
	}
}

static int lex_ident(ncfg_lexer_t *lexer, ncfg_span_t start, ncfg_token_t *out,
    char *err, size_t err_size)
{
	size_t begin = lexer->position;
	size_t length;
	int byte = peek_byte(lexer);

	while (byte >= 0 && ncfg_is_ident_continue((unsigned char)byte)) {
		(void)bump(lexer);
		byte = peek_byte(lexer);
	}
	length = lexer->position - begin;
	out->span = span_to(lexer, start);
	/* `true` and `false` are not identifiers the parser has to know about:
	 * a keyword recognised here cannot be used as a block name by accident
	 * somewhere the parser forgot to check. */
	if (length == 4u && memcmp(lexer->text + begin, "true", 4u) == 0) {
		out->kind = NCFG_TOKEN_BOOL;
		out->boolean = 1;
		return 1;
	}
	if (length == 5u && memcmp(lexer->text + begin, "false", 5u) == 0) {
		out->kind = NCFG_TOKEN_BOOL;
		out->boolean = 0;
		return 1;
	}
	out->kind = NCFG_TOKEN_IDENT;
	out->text = copy_range(lexer->text + begin, length);
	if (!out->text) {
		return fail(lexer, out->span, err, err_size, "out of memory for an identifier");
	}
	out->text_length = length;
	return 1;
}

static int lex_number(ncfg_lexer_t *lexer, ncfg_span_t start, ncfg_token_t *out,
    char *err, size_t err_size)
{
	size_t begin = lexer->position;
	size_t digits_begin;
	uint64_t value = 0u;
	uint64_t limit;
	int negative = 0;
	int overflowed = 0;
	int byte;

	if (peek_byte(lexer) == '-') {
		(void)bump(lexer);
		negative = 1;
	}
	digits_begin = lexer->position;
	/* The magnitude is accumulated rather than the value, because the
	 * negative range reaches one further than the positive one: the
	 * smallest number there is has no positive counterpart to hold it on
	 * the way in. */
	limit = negative ? (uint64_t)INT64_MAX + 1u : (uint64_t)INT64_MAX;
	byte = peek_byte(lexer);
	while (byte >= '0' && byte <= '9') {
		uint64_t digit = (uint64_t)(byte - '0');

		if (value > (limit - digit) / 10u) {
			/* Scan the rest anyway: the span and the message both
			 * want the number the operator wrote, not the part of
			 * it that fitted. */
			overflowed = 1;
		}
		if (!overflowed) {
			value = value * 10u + digit;
		}
		(void)bump(lexer);
		byte = peek_byte(lexer);
	}
	if (lexer->position == digits_begin) {
		return fail(lexer, span_to(lexer, start), err, err_size,
		    "expected digits after `-`");
	}
	/* A trailing `.` would be a float, and the language forbids floats
	 * outright. Catching it here gives a better message than letting the
	 * `.` surface as an unexpected character on the next token, where the
	 * message would be about punctuation instead of about the rule. */
	if (peek_byte(lexer) == '.') {
		return fail(lexer, span_to(lexer, start), err, err_size,
		    "numbers in this language are integers: no value in the "
		    "desired-state document is a float");
	}
	if (overflowed) {
		size_t length = lexer->position - begin;

		return fail(lexer, span_to(lexer, start), err, err_size,
		    "number %.*s does not fit in 64 bits",
		    (int)(length > (size_t)NUMBER_SHOWN ? (size_t)NUMBER_SHOWN : length),
		    lexer->text + begin);
	}
	out->kind = NCFG_TOKEN_NUMBER;
	out->span = span_to(lexer, start);
	if (!negative || value == 0u) {
		/* `-0` is written down sometimes and is zero. Taking it through
		 * the branch below would ask for `0 - 1` in unsigned
		 * arithmetic, which is not zero and is not small. */
		out->number = (int64_t)value;
	} else {
		/* Negated one short of the way, so the magnitude never has to
		 * exist as a positive value: the smallest number there is has
		 * no positive counterpart, and `-(int64_t)value` on it is the
		 * overflow this function is written to avoid. */
		out->number = -(int64_t)(value - 1u) - 1;
	}
	return 1;
}

/* How many bytes this lead byte introduces, including itself. */
static size_t utf8_sequence_length(unsigned char lead)
{
	if (lead < 0x80u) {
		return 1u;
	}
	if ((lead >> 5) == 0x06u) {
		return 2u;
	}
	if ((lead >> 4) == 0x0eu) {
		return 3u;
	}
	if ((lead >> 3) == 0x1eu) {
		return 4u;
	}
	/* A stray continuation byte. Take it alone and let the check below
	 * refuse it with a real message. */
	return 1u;
}

/*
 * Whether these bytes are one well-formed UTF-8 character.
 *
 * The ranges are the Unicode table rather than the shorter "lead byte, then
 * continuation bytes" test, which accepts an overlong encoding -- a second
 * spelling of a character that has one. A second spelling of `/` or of a NUL
 * is how a value that was checked becomes a different value once something
 * downstream decodes it.
 */
static int utf8_is_valid(const unsigned char *bytes, size_t length)
{
	unsigned char lead = bytes[0];
	unsigned char first = length > 1u ? bytes[1] : 0u;
	size_t i;

	for (i = 1u; i < length; i++) {
		if (bytes[i] < 0x80u || bytes[i] > 0xbfu) {
			return 0;
		}
	}
	switch (length) {
	case 1u:
		return lead < 0x80u;
	case 2u:
		return lead >= 0xc2u && lead <= 0xdfu;
	case 3u:
		if (lead == 0xe0u) {
			return first >= 0xa0u;
		}
		if (lead == 0xedu) {
			/* 0xed 0xa0.. is a surrogate half, which is not a
			 * character and which JSON cannot carry. */
			return first <= 0x9fu;
		}
		return lead >= 0xe1u && lead <= 0xefu;
	case 4u:
		if (lead == 0xf0u) {
			return first >= 0x90u;
		}
		if (lead == 0xf4u) {
			return first <= 0x8fu;
		}
		return lead >= 0xf1u && lead <= 0xf3u;
	default:
		return 0;
	}
}

/*
 * Lex a quoted string.
 *
 * A string may span lines. The grammar says so -- it excludes only the quote
 * -- and it has to, because the netifrc spelling puts several addresses or
 * routes in one quoted value, one per line. The cost is that a missing
 * closing quote swallows everything up to the next one, so every diagnostic
 * here starts at the opening quote rather than at wherever the lexer
 * eventually gave up: reporting where it stopped sends the reader to a line
 * that is not the mistake.
 */
static int lex_string(ncfg_lexer_t *lexer, ncfg_span_t start, ncfg_token_t *out,
    char *err, size_t err_size)
{
	static const char *unterminated
	    = "unterminated string: a string runs to its closing quote, across lines if "
	      "need be";
	ncfg_buf_t text;
	int byte;

	(void)bump(lexer); /* the opening quote */
	ncfg_buf_init(&text, 0);
	for (;;) {
		byte = bump(lexer);
		if (byte < 0) {
			ncfg_buf_free(&text);
			return fail(lexer, span_to(lexer, start), err, err_size, "%s",
			    unterminated);
		}
		if (byte == '"') {
			break;
		}
		if (byte == '\\') {
			ncfg_span_t escape = span_here(lexer);
			int escaped = bump(lexer);
			char shown[8];

			switch (escaped) {
			case '"':
				ncfg_buf_add_char(&text, '"');
				continue;
			case '\\':
				ncfg_buf_add_char(&text, '\\');
				continue;
			case 'n':
				ncfg_buf_add_char(&text, '\n');
				continue;
			case 't':
				ncfg_buf_add_char(&text, '\t');
				continue;
			default:
				break;
			}
			ncfg_buf_free(&text);
			if (escaped < 0) {
				return fail(lexer, span_to(lexer, start), err, err_size, "%s",
				    unterminated);
			}
			escape.length = 1u;
			describe_byte(escaped, shown, sizeof(shown));
			return fail(lexer, escape, err, err_size,
			    "unknown escape `\\%s`: the escapes are \\\" \\\\ \\n and \\t",
			    shown);
		}
		{
			/* The raw byte goes through UTF-8 reconstruction rather
			 * than straight into the buffer: the source may
			 * legitimately hold non-ASCII inside a string, for an
			 * SSID or a search domain, and a value that reaches
			 * JSON and the daemon's own files has to be text by the
			 * time it gets there rather than bytes that were never
			 * looked at. */
			unsigned char sequence[4];
			size_t want = utf8_sequence_length((unsigned char)byte);
			size_t i;

			sequence[0] = (unsigned char)byte;
			for (i = 1u; i < want; i++) {
				int next = bump(lexer);

				if (next < 0) {
					ncfg_buf_free(&text);
					return fail(lexer, span_to(lexer, start), err, err_size,
					    "%s", unterminated);
				}
				sequence[i] = (unsigned char)next;
			}
			if (!utf8_is_valid(sequence, want)) {
				ncfg_buf_free(&text);
				return fail(lexer, span_to(lexer, start), err, err_size,
				    "string is not valid UTF-8");
			}
			ncfg_buf_add(&text, sequence, want);
		}
	}
	out->kind = NCFG_TOKEN_STRING;
	out->span = span_to(lexer, start);
	out->text = take_text(&text, &out->text_length);
	ncfg_buf_free(&text);
	if (!out->text) {
		return fail(lexer, out->span, err, err_size,
		    "cannot hold a string that long: out of memory, or past the "
		    "buffer's ceiling");
	}
	return 1;
}

void ncfg_lexer_init(ncfg_lexer_t *lexer, const char *text, size_t length)
{
	if (!lexer) {
		return;
	}
	lexer->text = text ? text : "";
	lexer->length = text ? length : 0u;
	lexer->position = 0u;
	lexer->line = 1u;
	lexer->column = 1u;
	lexer->error_span = span_here(lexer);
}

ncfg_span_t ncfg_lexer_span(const ncfg_lexer_t *lexer)
{
	ncfg_span_t empty;

	if (lexer) {
		return span_here(lexer);
	}
	empty.offset = 0u;
	empty.length = 0u;
	empty.line = 1u;
	empty.column = 1u;
	return empty;
}

ncfg_span_t ncfg_lexer_error_span(const ncfg_lexer_t *lexer)
{
	return lexer ? lexer->error_span : ncfg_lexer_span(NULL);
}

void ncfg_token_free(ncfg_token_t *token)
{
	if (!token) {
		return;
	}
	free(token->text);
	token->text = NULL;
	token->text_length = 0u;
}

int ncfg_lexer_next(ncfg_lexer_t *lexer, ncfg_token_t *out, char *err, size_t err_size)
{
	ncfg_span_t span;
	int byte;
	char shown[8];

	if (!lexer || !out) {
		ncfg_error_set(err, err_size, "no lexer to read a token from");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	skip_trivia(lexer);
	span = span_here(lexer);
	byte = peek_byte(lexer);
	if (byte < 0) {
		out->kind = NCFG_TOKEN_EOF;
		out->span = span;
		return 1;
	}
	switch (byte) {
	/* A newline and a semicolon are one token: the grammar ends a statement
	 * with either, and nothing above here should have to ask which was
	 * written. */
	case '\n':
	case ';':
		out->kind = NCFG_TOKEN_TERMINATOR;
		break;
	case '{':
		out->kind = NCFG_TOKEN_LBRACE;
		break;
	case '}':
		out->kind = NCFG_TOKEN_RBRACE;
		break;
	case '[':
		out->kind = NCFG_TOKEN_LBRACKET;
		break;
	case ']':
		out->kind = NCFG_TOKEN_RBRACKET;
		break;
	case '=':
		out->kind = NCFG_TOKEN_EQUALS;
		break;
	case ',':
		out->kind = NCFG_TOKEN_COMMA;
		break;
	case '"':
		return lex_string(lexer, span, out, err, err_size);
	default:
		if (byte == '-' || (byte >= '0' && byte <= '9')) {
			return lex_number(lexer, span, out, err, err_size);
		}
		if (ncfg_is_ident_start((unsigned char)byte)) {
			return lex_ident(lexer, span, out, err, err_size);
		}
		/* Consumed before the complaint, so that a parser which keeps
		 * going after a lexer failure makes progress rather than
		 * reporting the same character until it gives up. */
		(void)bump(lexer);
		describe_byte(byte, shown, sizeof(shown));
		return fail(lexer, span_to(lexer, span), err, err_size,
		    "unexpected character `%s`", shown);
	}
	(void)bump(lexer);
	out->span = span_to(lexer, span);
	return 1;
}

void ncfg_token_describe(const ncfg_token_t *token, char *out, size_t out_size)
{
	const char *name;

	if (!out || !out_size) {
		return;
	}
	if (!token) {
		(void)snprintf(out, out_size, "nothing");
		return;
	}
	switch (token->kind) {
	case NCFG_TOKEN_IDENT:
		/* Named, because "expected `=`, found `eth0`" is the message
		 * that tells the reader where they are. Everything else is
		 * described rather than quoted: reciting a string the reader
		 * just wrote says nothing they did not know. */
		(void)snprintf(out, out_size, "`%s`", token->text ? token->text : "");
		return;
	case NCFG_TOKEN_STRING:
		name = "a string";
		break;
	case NCFG_TOKEN_NUMBER:
		name = "a number";
		break;
	case NCFG_TOKEN_BOOL:
		name = "a boolean";
		break;
	case NCFG_TOKEN_LBRACE:
		name = "`{`";
		break;
	case NCFG_TOKEN_RBRACE:
		name = "`}`";
		break;
	case NCFG_TOKEN_LBRACKET:
		name = "`[`";
		break;
	case NCFG_TOKEN_RBRACKET:
		name = "`]`";
		break;
	case NCFG_TOKEN_EQUALS:
		name = "`=`";
		break;
	case NCFG_TOKEN_COMMA:
		name = "`,`";
		break;
	case NCFG_TOKEN_TERMINATOR:
		name = "end of statement";
		break;
	case NCFG_TOKEN_EOF:
		name = "end of file";
		break;
	default:
		name = "a token this lexer does not name";
		break;
	}
	(void)snprintf(out, out_size, "%s", name);
}

static int is_space(char one)
{
	return one == ' ' || one == '\t' || one == '\r' || one == '\n' || one == '\v'
	    || one == '\f';
}

/*
 * Whether a line is nothing but a closing brace once both ends are trimmed.
 *
 * Trimmed first, and that is the whole rule: a hook inside an `interface`
 * block is written indented, so a test that wanted the brace in column one
 * would never fire on a file anybody actually wrote.
 */
static int is_closing_line(const char *line, size_t length)
{
	size_t start = 0u;
	size_t end = length;

	while (end > start && is_space(line[end - 1u])) {
		end--;
	}
	while (start < end && is_space(line[start])) {
		start++;
	}
	return end - start == 1u && line[start] == '}';
}

int ncfg_lexer_hook_body(ncfg_lexer_t *lexer, char **body_out, size_t *length_out,
    char *err, size_t err_size)
{
	ncfg_buf_t body;
	ncfg_span_t open;

	if (!lexer || !body_out) {
		ncfg_error_set(err, err_size, "no lexer to read a hook body from");
		return 0;
	}
	*body_out = NULL;
	if (length_out) {
		*length_out = 0u;
	}
	open = span_here(lexer);
	ncfg_buf_init(&body, 0u);
	for (;;) {
		size_t line_begin;
		int byte;

		if (lexer->position >= lexer->length) {
			ncfg_buf_free(&body);
			open.length = lexer->length - open.offset;
			return fail(lexer, open, err, err_size,
			    "unterminated hook body: a hook body ends at the first line "
			    "containing only a closing brace");
		}
		line_begin = lexer->position;
		byte = bump(lexer);
		while (byte >= 0 && byte != '\n') {
			byte = bump(lexer);
		}
		if (is_closing_line(lexer->text + line_begin, lexer->position - line_begin)) {
			break;
		}
		/* The line goes in exactly as it was written, newline and all.
		 * A hook body is shell: re-indenting it, or dropping the
		 * newline off the last line, changes what the shell does. */
		ncfg_buf_add(&body, lexer->text + line_begin, lexer->position - line_begin);
	}
	*body_out = take_text(&body, length_out);
	ncfg_buf_free(&body);
	if (!*body_out) {
		open.length = lexer->position - open.offset;
		return fail(lexer, open, err, err_size,
		    "cannot hold a hook body that long: out of memory, or past the "
		    "buffer's ceiling");
	}
	return 1;
}
