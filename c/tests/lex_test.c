/*
 * lex_test.c -- the token stream, the spans, and the hook body.
 *
 * WHY THIS EXISTS
 *   Every diagnostic the compiler prints is a span this module produced, so a
 *   lexer that is right about tokens and wrong about positions sends every
 *   reader to the wrong line and nothing above it can tell. The spans are
 *   therefore checked as hard as the tokens are.
 *
 *   The cases below are not a sweep. Each one is a rule the language has --
 *   the dot inside an identifier, the float refused by name, the string that
 *   spans lines, the hook body that ends at a lone brace -- and several are
 *   rules that exist because a file somebody wrote did not parse without
 *   them.
 */
#include "ncfg/base.h"
#include "ncfg/lex.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-58s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* A block lifted from `doc/netcfgd.conf.example`: the wireless three-parter,
 * which is the densest real thing in the file -- nested blocks, a boolean, a
 * quoted block name and a secret reference. */
static const char *const example_block =
    "device wlan0 {\n"
    "\twifi {\n"
    "\t\tautoconnect = true\n"
    "\t}\n"
    "}\n"
    "interface wlan0 {\n"
    "\tconfig = \"dhcp\"\n"
    "}\n"
    "network \"Cafe Wifi\" {\n"
    "\twifi {\n"
    "\t\tpsk = \"@secret:cafe\"\n"
    "\t}\n"
    "}\n";

/* A hook as the manual writes one: inside an `interface` block, indented, and
 * closed by a brace on a line of its own. */
static const char *const hook_plain =
    "interface eth0 {\n"
    "\tpost_up {\n"
    "\t\tlogger -t netcfgd \"eth0 is up with $NCFG_ADDRESSES\"\n"
    "\t}\n"
    "}\n";

static const char *const hook_tab_closed =
    "interface eth0 {\n"
    "\tpost_up {\n"
    "\techo hi\n"
    "\t}\n"
    "}\n";

static const char *const hook_trailing_space =
    "interface eth0 {\n"
    "\tpost_up {\n"
    "echo hi\n"
    "}  \n"
    "}\n";

/* The shell function spread over three lines, which is the shape the example
 * file warns about by name. */
static const char *const hook_shell_function =
    "interface eth0 {\n"
    "\tpost_up {\n"
    "\tgreet() {\n"
    "\techo hello\n"
    "\t}\n"
    "\tgreet\n"
    "\t}\n"
    "}\n";

/* The same function written the way the manual says to write it. */
static const char *const hook_one_line_function =
    "interface eth0 {\n"
    "\tpost_up {\n"
    "\tgreet() { echo hello; }\n"
    "\tgreet\n"
    "\t}\n"
    "}\n";

static const char *const hook_then_more =
    "interface eth0 {\n"
    "\tpost_up {\n"
    "\techo hi\n"
    "\t}\n"
    "\tmtu = 1500\n"
    "}\n";

static const char *const hook_unterminated =
    "interface eth0 {\n"
    "\tpost_up {\n"
    "echo hi\n";

static const char *const hook_empty =
    "interface eth0 {\n"
    "\tpost_up {\n"
    "\t}\n"
    "}\n";

/*
 * One character per token, so that a test can say what a whole file lexes to
 * on one line: `i` an identifier, `s` a string, `n` a number, `b` a boolean,
 * `;` a terminator -- newline or semicolon, which are the same token -- `$`
 * end of input, and the punctuation for itself.
 */
static char shape_of(const ncfg_token_t *token)
{
	switch (token->kind) {
	case NCFG_TOKEN_IDENT:
		return 'i';
	case NCFG_TOKEN_STRING:
		return 's';
	case NCFG_TOKEN_NUMBER:
		return 'n';
	case NCFG_TOKEN_BOOL:
		return 'b';
	case NCFG_TOKEN_LBRACE:
		return '{';
	case NCFG_TOKEN_RBRACE:
		return '}';
	case NCFG_TOKEN_LBRACKET:
		return '[';
	case NCFG_TOKEN_RBRACKET:
		return ']';
	case NCFG_TOKEN_EQUALS:
		return '=';
	case NCFG_TOKEN_COMMA:
		return ',';
	case NCFG_TOKEN_TERMINATOR:
		return ';';
	case NCFG_TOKEN_EOF:
		return '$';
	default:
		return '?';
	}
}

/* Whether `text` lexes to exactly `shape`, end of input included. It says
 * what it got when it does not: a shape one character out is not something to
 * find by eye. */
static int stream_is(const char *text, const char *shape)
{
	char message[NCFG_ERROR_MAX];
	char got[512];
	ncfg_lexer_t lexer;
	size_t count = 0u;

	ncfg_lexer_init(&lexer, text, strlen(text));
	for (;;) {
		ncfg_token_t token;

		if (!ncfg_lexer_next(&lexer, &token, message, sizeof(message))) {
			printf("    the lexer refused it: %s\n", message);
			return 0;
		}
		if (count + 1u >= sizeof(got)) {
			ncfg_token_free(&token);
			printf("    more tokens than this test can hold\n");
			return 0;
		}
		got[count] = shape_of(&token);
		count++;
		if (token.kind == NCFG_TOKEN_EOF) {
			ncfg_token_free(&token);
			break;
		}
		ncfg_token_free(&token);
	}
	got[count] = '\0';
	if (strcmp(got, shape) != 0) {
		printf("    wanted %s\n    got    %s\n", shape, got);
		return 0;
	}
	return 1;
}

/* The `index`th token, counting from zero, or 0 where the lexer failed before
 * reaching it. The caller frees `out`. */
static int token_at(const char *text, size_t index, ncfg_token_t *out)
{
	char message[NCFG_ERROR_MAX];
	ncfg_lexer_t lexer;
	size_t i;

	ncfg_lexer_init(&lexer, text, strlen(text));
	for (i = 0u;; i++) {
		if (!ncfg_lexer_next(&lexer, out, message, sizeof(message))) {
			printf("    the lexer refused it: %s\n", message);
			return 0;
		}
		if (i == index) {
			return 1;
		}
		if (out->kind == NCFG_TOKEN_EOF) {
			ncfg_token_free(out);
			printf("    the file has no token %u\n", (unsigned int)index);
			return 0;
		}
		ncfg_token_free(out);
	}
}

/* Lex to the end and report the first failure, with the span it was about. */
static int lex_fails(const char *text, char *message, size_t message_size, ncfg_span_t *span)
{
	ncfg_lexer_t lexer;
	ncfg_token_t token;

	message[0] = '\0';
	ncfg_lexer_init(&lexer, text, strlen(text));
	for (;;) {
		if (!ncfg_lexer_next(&lexer, &token, message, message_size)) {
			*span = ncfg_lexer_error_span(&lexer);
			return 1;
		}
		if (token.kind == NCFG_TOKEN_EOF) {
			ncfg_token_free(&token);
			return 0;
		}
		ncfg_token_free(&token);
	}
}

static int says(const char *message, const char *fragment)
{
	if (strstr(message, fragment)) {
		return 1;
	}
	printf("    wanted a message about \"%s\", got: %s\n", fragment, message);
	return 0;
}

static int text_is(const ncfg_token_t *token, const char *want)
{
	return token->text && strcmp(token->text, want) == 0;
}

/*
 * Take a hook body the way the parser does.
 *
 * Lex up to the `{` that opens `post_up`, drop the newline behind it, and
 * hand the raw remainder of the file to the body scanner. Everything past
 * that point is shell, so stepping out of the token stream here is the only
 * way to read it -- which is why the lexer is written to be stepped out of.
 * The cursor comes back in `lexer_out`, still usable, because the parser goes
 * on lexing configuration once the body has been taken.
 */
static int hook_body_of(const char *text, char **body_out, size_t *length_out,
    char *message, size_t message_size, ncfg_lexer_t *lexer_out)
{
	ncfg_token_t token;
	int after_post_up = 0;

	message[0] = '\0';
	ncfg_lexer_init(lexer_out, text, strlen(text));
	for (;;) {
		if (!ncfg_lexer_next(lexer_out, &token, message, message_size)) {
			return 0;
		}
		if (token.kind == NCFG_TOKEN_EOF) {
			ncfg_token_free(&token);
			printf("    this fixture has no `post_up {` in it\n");
			return 0;
		}
		if (token.kind == NCFG_TOKEN_LBRACE && after_post_up) {
			ncfg_token_free(&token);
			break;
		}
		after_post_up = token.kind == NCFG_TOKEN_IDENT && text_is(&token, "post_up");
		ncfg_token_free(&token);
	}
	if (!ncfg_lexer_next(lexer_out, &token, message, message_size)) {
		return 0;
	}
	if (token.kind != NCFG_TOKEN_TERMINATOR) {
		ncfg_token_free(&token);
		printf("    this fixture does not put the body on its own line\n");
		return 0;
	}
	ncfg_token_free(&token);
	return ncfg_lexer_hook_body(lexer_out, body_out, length_out, message, message_size);
}

int main(void)
{
	char message[NCFG_ERROR_MAX];
	ncfg_span_t span;

	/* THE STREAM. What the parser above this actually consumes. */
	{
		ncfg_token_t token;

		check(stream_is("", "$"), "an empty file is one end-of-input token");
		check(stream_is("interface eth0 {\n\tconfig = \"dhcp\"\n}\n", "ii{;i=s;};$"),
		    "a block lexes to its punctuation and its words");
		check(stream_is(example_block, "ii{;i{;i=b;};};ii{;i=s;};is{;i{;i=s;};};$"),
		    "and so does a real block from the example file");
		check(stream_is("a;b\nc", "i;i;i$"),
		    "a semicolon and a newline are the same token");
		check(stream_is("config = [\"dhcp\", \"2001:db8::10/64\"]\n", "i=[s,s];$"),
		    "a list is brackets, strings and commas");
		/* Trivia is skipped and the newline is not, because the newline
		 * ends a statement and the parser has to see it. */
		check(stream_is("# prose\nkey = 1 # trailing\n", ";i=n;$"),
		    "a comment runs to the newline and no further");
		check(stream_is("a # a comment with no newline after it", "i$"),
		    "and a comment may end the file");
		check(stream_is("a\r\nb", "i;i$"), "a carriage return is trivia");
		check(stream_is("   \t a", "i$"), "so are spaces and tabs");

		if (token_at("mtu = 1500\n", 2u, &token)) {
			check(token.kind == NCFG_TOKEN_NUMBER && token.number == 1500,
			    "a number is a number rather than its digits");
			ncfg_token_free(&token);
		} else {
			check(0, "a number is a number rather than its digits");
		}
	}

	/* SPANS. Every later error is one of these. */
	{
		ncfg_token_t token;

		if (token_at("mtu = 1500\n", 0u, &token)) {
			check(token.span.offset == 0u && token.span.length == 3u
			    && token.span.line == 1u && token.span.column == 1u,
			    "a token's span covers exactly the token");
			ncfg_token_free(&token);
		} else {
			check(0, "a token's span covers exactly the token");
		}
		if (token_at("mtu = 1500\n", 2u, &token)) {
			check(token.span.offset == 6u && token.span.length == 4u
			    && token.span.column == 7u,
			    "and the next one starts where it starts");
			ncfg_token_free(&token);
		} else {
			check(0, "and the next one starts where it starts");
		}
		/* The line counter moves on a newline and nowhere else, which
		 * is what makes the second line's first column one again. */
		if (token_at("a\nbb\n", 2u, &token)) {
			check(token.span.line == 2u && token.span.column == 1u
			    && token.span.offset == 2u,
			    "a newline starts a line and resets the column");
			ncfg_token_free(&token);
		} else {
			check(0, "a newline starts a line and resets the column");
		}
		if (token_at("a\n", 2u, &token)) {
			check(token.kind == NCFG_TOKEN_EOF && token.span.length == 0u
			    && token.span.offset == 2u,
			    "end of input has a position and no width");
			ncfg_token_free(&token);
		} else {
			check(0, "end of input has a position and no width");
		}
	}

	/* IDENTIFIERS, and the dot rule. Linux names VLAN interfaces `eth0.42`
	 * by universal convention and the design's own example is that name,
	 * so a lexer without the rule cannot read the commonest virtual
	 * interface there is. */
	{
		ncfg_token_t token;

		if (token_at("interface eth0.42 {\n", 1u, &token)) {
			check(token.kind == NCFG_TOKEN_IDENT && text_is(&token, "eth0.42"),
			    "`eth0.42` is one identifier, dot and all");
			ncfg_token_free(&token);
		} else {
			check(0, "`eth0.42` is one identifier, dot and all");
		}
		/* And a dot may not start one, which is what keeps `.42` an
		 * error rather than a name, and a float refused rather than
		 * lexed as something. */
		check(lex_fails(".42 { }\n", message, sizeof(message), &span)
		    && says(message, "unexpected character"),
		    "a bare dot is not a name");
		check(span.offset == 0u && span.line == 1u && span.column == 1u,
		    "and the complaint points at the dot");

		if (token_at("_a-b.c0 = 1\n", 0u, &token)) {
			check(text_is(&token, "_a-b.c0"),
			    "an underscore, a hyphen and a digit continue a name");
			ncfg_token_free(&token);
		} else {
			check(0, "an underscore, a hyphen and a digit continue a name");
		}
		check(stream_is("true false", "bb$"), "`true` and `false` are booleans");
		if (token_at("truely", 0u, &token)) {
			check(token.kind == NCFG_TOKEN_IDENT && text_is(&token, "truely"),
			    "but a word that merely begins like one is a name");
			ncfg_token_free(&token);
		} else {
			check(0, "but a word that merely begins like one is a name");
		}
		if (token_at("mtu=1", 0u, &token)) {
			check(text_is(&token, "mtu"), "a name ends where the `=` begins");
			ncfg_token_free(&token);
		} else {
			check(0, "a name ends where the `=` begins");
		}
	}

	/* NUMBERS. Integers only, and the whole range of one. */
	{
		ncfg_token_t token;

		if (token_at("-1", 0u, &token)) {
			check(token.kind == NCFG_TOKEN_NUMBER && token.number == -1,
			    "a number may be negative");
			ncfg_token_free(&token);
		} else {
			check(0, "a number may be negative");
		}
		if (token_at("-0", 0u, &token)) {
			check(token.number == 0, "and `-0` is zero, not something else");
			ncfg_token_free(&token);
		} else {
			check(0, "and `-0` is zero, not something else");
		}
		if (token_at("9223372036854775807", 0u, &token)) {
			check(token.number == 9223372036854775807LL,
			    "the largest number there is fits");
			ncfg_token_free(&token);
		} else {
			check(0, "the largest number there is fits");
		}
		/* The smallest has no positive counterpart, so it is the case
		 * the accumulator is written around rather than the one it
		 * happens to survive. */
		if (token_at("-9223372036854775808", 0u, &token)) {
			check(token.number == -9223372036854775807LL - 1LL,
			    "and so does the smallest, which has no positive twin");
			ncfg_token_free(&token);
		} else {
			check(0, "and so does the smallest, which has no positive twin");
		}
		check(lex_fails("9223372036854775808", message, sizeof(message), &span)
		    && says(message, "does not fit in 64 bits"),
		    "one past it does not, and says so");
		/* Refused by name here rather than as a stray `.` on the next
		 * token, where the message would be about punctuation instead
		 * of about the rule. */
		check(lex_fails("mtu = 15.5\n", message, sizeof(message), &span)
		    && says(message, "integers"),
		    "a float is refused in the words of the rule");
		check(span.offset == 6u && span.column == 7u,
		    "pointing at the number rather than at the dot");
		check(lex_fails("mtu = -\n", message, sizeof(message), &span)
		    && says(message, "expected digits after `-`"),
		    "a minus with nothing after it is not a number");
	}

	/* STRINGS. */
	{
		ncfg_token_t token;

		if (token_at("\"a\\n\\t\\\"\\\\b\"", 0u, &token)) {
			check(token.kind == NCFG_TOKEN_STRING && text_is(&token, "a\n\t\"\\b"),
			    "the four escapes are resolved in the token");
			ncfg_token_free(&token);
		} else {
			check(0, "the four escapes are resolved in the token");
		}
		/* A string spans lines because the netifrc spelling puts
		 * several routes in one value, one per line. */
		if (token_at("routes = \"default via 192.0.2.1\nvia 192.0.2.2\"\n", 2u,
		    &token)) {
			check(text_is(&token, "default via 192.0.2.1\nvia 192.0.2.2"),
			    "a string runs across lines, newline and all");
			ncfg_token_free(&token);
		} else {
			check(0, "a string runs across lines, newline and all");
		}
		if (token_at("\"\"", 0u, &token)) {
			check(token.kind == NCFG_TOKEN_STRING && text_is(&token, "")
			    && token.text_length == 0u,
			    "an empty string is a value, not a failure");
			ncfg_token_free(&token);
		} else {
			check(0, "an empty string is a value, not a failure");
		}
		/* Non-ASCII belongs in a string: an SSID is whatever the cafe
		 * called it, and a search domain need not be Latin. */
		if (token_at("\"Caf\xc3\xa9\"", 0u, &token)) {
			check(token.text_length == 5u && text_is(&token, "Caf\xc3\xa9"),
			    "a string carries non-ASCII through unchanged");
			ncfg_token_free(&token);
		} else {
			check(0, "a string carries non-ASCII through unchanged");
		}
		check(lex_fails("\"\xff\"", message, sizeof(message), &span)
		    && says(message, "not valid UTF-8"),
		    "but a byte that is not text is refused");
		/* An overlong encoding decodes to a character it is not
		 * spelled as, which is how a value that was checked becomes a
		 * different value once something downstream decodes it. */
		check(lex_fails("\"\xc0\xaf\"", message, sizeof(message), &span)
		    && says(message, "not valid UTF-8"),
		    "and so is a second spelling of an ASCII character");
		check(lex_fails("\"a\\q\"", message, sizeof(message), &span)
		    && says(message, "unknown escape `\\q`"),
		    "an escape that is not one of the four is named");
		check(span.offset == 3u && span.length == 1u,
		    "and pointed at, rather than the string as a whole");
	}

	/* THE RUNAWAY STRING, which is what the line-spanning above costs: a
	 * missing quote swallows the rest of the file. So the diagnostic
	 * starts at the opening quote -- reporting where the lexer gave up
	 * would send the reader to a line that is not the mistake. */
	{
		check(lex_fails("interface eth0 {\n\tconfig = \"dhcp\n\tmtu = 1500\n}\n",
		      message, sizeof(message), &span)
		    && says(message, "unterminated string"),
		    "an unterminated string is refused");
		check(span.line == 2u && span.column == 11u,
		    "at the opening quote, not where the lexer stopped");
		check(lex_fails("\"a\\", message, sizeof(message), &span)
		    && says(message, "unterminated string"),
		    "and a file ending inside an escape is the same fault");
	}

	/* A NUL IN THE SOURCE IS DATA. The lexer is handed bytes and a length
	 * rather than a C string, so a NUL inside a quoted value travels like
	 * any other byte -- stopping there would turn a value the operator
	 * wrote into a shorter one nobody would see was short. */
	{
		static const char source[] = "psk = \"x\0y\"\n";
		char nul_message[NCFG_ERROR_MAX];
		ncfg_lexer_t lexer;
		ncfg_token_t token;
		int got = 0;
		int i;

		ncfg_lexer_init(&lexer, source, sizeof(source) - 1u);
		for (i = 0; i < 3; i++) {
			if (!ncfg_lexer_next(&lexer, &token, nul_message,
			    sizeof(nul_message))) {
				break;
			}
			if (i == 2) {
				got = token.kind == NCFG_TOKEN_STRING
				    && token.text_length == 3u
				    && memcmp(token.text, "x\0y", 3u) == 0;
			}
			ncfg_token_free(&token);
		}
		check(got, "a NUL inside a string is a byte, not an end");
	}

	/* THE HOOK BODY, the one irregular production in the grammar. */
	{
		char *body = NULL;
		size_t length = 0u;
		ncfg_lexer_t lexer;

		if (hook_body_of(hook_plain, &body, &length, message, sizeof(message),
		    &lexer)) {
			check(body
			    && strcmp(body,
			           "\t\tlogger -t netcfgd \"eth0 is up with "
			           "$NCFG_ADDRESSES\"\n")
			        == 0,
			    "a hook body is shell, kept exactly as written");
			check(length == strlen(body ? body : ""),
			    "and its length is the bytes it holds");
			free(body);
		} else {
			check(0, "a hook body is shell, kept exactly as written");
			check(0, "and its length is the bytes it holds");
		}

		/* The line is trimmed before it is compared, which is the only
		 * reason the rule fires on a real file at all: a hook inside
		 * an `interface` block is written indented. */
		body = NULL;
		if (hook_body_of(hook_tab_closed, &body, NULL, message, sizeof(message),
		    &lexer)) {
			check(body && strcmp(body, "\techo hi\n") == 0,
			    "a closing brace indented with a tab still closes it");
			free(body);
		} else {
			check(0, "a closing brace indented with a tab still closes it");
		}

		body = NULL;
		if (hook_body_of(hook_trailing_space, &body, NULL, message, sizeof(message),
		    &lexer)) {
			check(body && strcmp(body, "echo hi\n") == 0,
			    "and so does one with whitespace after it");
			free(body);
		} else {
			check(0, "and so does one with whitespace after it");
		}

		/* **The documented cost, not a defect.** A shell function is
		 * the commonest multi-line construct there is and it closes
		 * with a `}` alone on a line, so writing one inside a hook
		 * ends the body early and the rest of the shell is read as
		 * configuration -- which fails somewhere else, talking about
		 * `=` and `{` at a line the operator wrote shell on. netcfgd
		 * does not parse shell and so cannot tell the operator's
		 * braces from its own. The manual says so and gives the
		 * one-line form, which is the next case. */
		body = NULL;
		if (hook_body_of(hook_shell_function, &body, NULL, message, sizeof(message),
		    &lexer)) {
			check(body && strcmp(body, "\tgreet() {\n\techo hello\n") == 0,
			    "a shell function's own brace ends the body early");
			free(body);
		} else {
			check(0, "a shell function's own brace ends the body early");
		}

		body = NULL;
		if (hook_body_of(hook_one_line_function, &body, NULL, message,
		    sizeof(message), &lexer)) {
			check(body
			    && strcmp(body, "\tgreet() { echo hello; }\n\tgreet\n") == 0,
			    "while the one-line form the manual gives survives");
			free(body);
		} else {
			check(0, "while the one-line form the manual gives survives");
		}

		/* The parser steps back into the token stream afterwards, so
		 * what follows a hook has to lex as configuration again. */
		body = NULL;
		if (hook_body_of(hook_then_more, &body, NULL, message, sizeof(message),
		    &lexer)) {
			ncfg_token_t token;

			free(body);
			if (ncfg_lexer_next(&lexer, &token, message, sizeof(message))) {
				check(token.kind == NCFG_TOKEN_IDENT && text_is(&token, "mtu"),
				    "and the file goes back to being configuration");
				ncfg_token_free(&token);
			} else {
				check(0, "and the file goes back to being configuration");
			}
		} else {
			check(0, "and the file goes back to being configuration");
		}

		body = NULL;
		if (hook_body_of(hook_unterminated, &body, NULL, message, sizeof(message),
		    &lexer)) {
			free(body);
			check(0, "a hook body with no closing line is refused");
			check(0, "naming where the body began");
		} else {
			check(says(message, "unterminated hook body"),
			    "a hook body with no closing line is refused");
			span = ncfg_lexer_error_span(&lexer);
			check(span.offset == 28u && span.line == 3u,
			    "naming where the body began");
		}

		/* An empty body is legal: a hook with nothing in it yet is a
		 * place to put something, and it is not a failure. */
		body = NULL;
		length = 1u;
		if (hook_body_of(hook_empty, &body, &length, message, sizeof(message),
		    &lexer)) {
			check(body && body[0] == '\0' && length == 0u,
			    "an empty hook body is empty rather than absent");
			free(body);
		} else {
			check(0, "an empty hook body is empty rather than absent");
		}
	}

	/* DESCRIBING A TOKEN, the other half of "expected X, found Y". */
	{
		ncfg_token_t token;
		char described[64];

		if (token_at("interface eth0 {", 1u, &token)) {
			ncfg_token_describe(&token, described, sizeof(described));
			check(strcmp(described, "`eth0`") == 0,
			    "an identifier is named, because the reader is lost");
			ncfg_token_free(&token);
		} else {
			check(0, "an identifier is named, because the reader is lost");
		}
		if (token_at("\"dhcp\"", 0u, &token)) {
			ncfg_token_describe(&token, described, sizeof(described));
			check(strcmp(described, "a string") == 0,
			    "a string is described, because reciting it says nothing");
			ncfg_token_free(&token);
		} else {
			check(0, "a string is described, because reciting it says nothing");
		}
	}

	/* Freeing what was never filled in is nothing, which is the rule the
	 * error paths in this module are written on. */
	{
		ncfg_token_t token;

		memset(&token, 0, sizeof(token));
		ncfg_token_free(&token);
		ncfg_token_free(&token);
		ncfg_token_free(NULL);
		check(1, "freeing an empty token, twice, costs nothing");
	}

	if (failures == 0) {
		printf("lex_test: all checks passed\n");
	} else {
		printf("lex_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
