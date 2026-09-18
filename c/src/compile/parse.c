/*
 * parse.c -- the grammar of project.md section 3, as recursive descent.
 *
 * TWO THINGS THIS FILE IS CAREFUL ABOUT
 *
 * **Recovery.** A statement that does not parse is a diagnostic and a skip to
 * the next statement boundary, not the end of the parse. Without it the
 * parser reports one problem and stops, which is the behaviour that makes
 * people fix a configuration one line per compile.
 *
 * **Ownership, which the Rust did not have to write down.** A token owns its
 * text; a tree node owns its strings; a node not yet attached to a tree is
 * owned by whoever built it. So the rules here are: a helper that is handed a
 * string takes it, and frees it on every path including the failing ones; a
 * push takes the node it is given, and frees it when it cannot store it. That
 * way no failure path has a list of things to remember, because the failure
 * paths are where a leak lives.
 */
#include "ncfg/parse.h"

#include "ncfg/ast.h"
#include "ncfg/base.h"
#include "ncfg/lex.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Long enough for "expected `=` or `{` after `x`, found `y`" with a name in
 * it, and bounded so a file of one enormous identifier cannot push the rest
 * of a sentence out of the error buffer. */
#define FOUND_MAX 128

/* The phases a hook block may name directly. `on <event>` covers the rest. */
static const char *const HOOK_PHASES[]
    = { "pre_up", "up", "post_up", "pre_down", "down", "post_down" };

/* Blocks that take a label, and are therefore not hook blocks even where the
 * name collides. */
static const char *const LABELLED_BLOCKS[] = { "interface", "network", "device", "peer" };

typedef struct {
	ncfg_lexer_t  lexer;
	ncfg_token_t  lookahead;
	int           have_lookahead;
	ncfg_diags_t *diags;
	/* How many blocks and lists are currently open. See
	 * NCFG_MAX_NESTING_DEPTH. */
	size_t        depth;
	/*
	 * Set when an allocation was refused, and never cleared.
	 *
	 * The Rust had nothing like this: it either allocated or aborted. Here
	 * a refused allocation is a value, so every loop in this file checks
	 * it and gives up -- otherwise a parser that cannot build a node goes
	 * on reading a file it can do nothing with, reporting a diagnostic per
	 * statement for a fault that is not in the file at all.
	 */
	int           out_of_memory;
} parser_t;

static void parse_file(parser_t *parser, ncfg_ast_file_t *file);
static ncfg_ast_item_t *parse_item(parser_t *parser);
static ncfg_ast_item_t *parse_include(parser_t *parser);
static ncfg_ast_item_t *parse_hook(parser_t *parser);
static ncfg_ast_item_t *parse_block(parser_t *parser);
static ncfg_ast_item_t *parse_block_after_head(parser_t *parser, char *head, ncfg_span_t span);
static ncfg_ast_item_t *parse_block_items(parser_t *parser, ncfg_ast_item_t *item);
static ncfg_ast_value_t *parse_value(parser_t *parser);
static ncfg_ast_value_t *parse_list(parser_t *parser, ncfg_span_t span);
static ncfg_ast_value_t *parse_list_entries(parser_t *parser, ncfg_ast_value_t *list);
static void expect_terminator(parser_t *parser);
static int recover(parser_t *parser);

/* ------------------------------------------------------------------ *
 * Diagnostics
 * ------------------------------------------------------------------ */

static void note_oom(parser_t *parser)
{
	parser->out_of_memory = 1;
}

/*
 * Keep one diagnostic, and count it either way.
 *
 * Past NCFG_DIAGS_MAX only the count moves: nobody reads the sixty-fifth
 * message, and a diagnostic per token is a file-sized allocation bought with
 * a malformed file in a daemon that re-reads its configuration directory
 * whenever anything in it changes.
 */
static void store_diag(parser_t *parser, ncfg_span_t span, const char *message)
{
	ncfg_diags_t *diags = parser->diags;
	ncfg_diag_t  *grown;
	size_t        want;
	size_t        length;
	char         *copy;

	diags->total++;
	if (diags->count >= (size_t)NCFG_DIAGS_MAX) {
		return;
	}
	if (diags->count == diags->capacity) {
		if (diags->capacity > SIZE_MAX / 2u / sizeof(*grown)) {
			note_oom(parser);
			return;
		}
		want = diags->capacity ? diags->capacity * 2u : 8u;
		if (want > (size_t)NCFG_DIAGS_MAX) {
			want = (size_t)NCFG_DIAGS_MAX;
		}
		grown = realloc(diags->at, want * sizeof(*grown));
		if (!grown) {
			note_oom(parser);
			return;
		}
		diags->at = grown;
		diags->capacity = want;
	}
	length = strlen(message);
	copy = malloc(length + 1u);
	if (!copy) {
		note_oom(parser);
		return;
	}
	memcpy(copy, message, length + 1u);
	diags->at[diags->count].span = span;
	diags->at[diags->count].message = copy;
	diags->count++;
}

/*
 * Every complaint in this module goes through here.
 *
 * The span and the sentence are set together, for `lex.c`'s reason: a failure
 * path that sets only one of them is the path nobody notices until an
 * operator gets a message with nowhere to look.
 */
static void push_diag(parser_t *parser, ncfg_span_t span, const char *format, ...)
{
	char    message[NCFG_ERROR_MAX];
	va_list args;

	va_start(args, format);
	ncfg_error_setv(message, sizeof(message), format, args);
	va_end(args);
	store_diag(parser, span, message);
}

void ncfg_diags_free(ncfg_diags_t *diags)
{
	size_t i;

	if (!diags) {
		return;
	}
	for (i = 0u; i < diags->count; i++) {
		free(diags->at[i].message);
	}
	free(diags->at);
	diags->at = NULL;
	diags->count = 0u;
	diags->total = 0u;
	diags->capacity = 0u;
}

void ncfg_diag_render(const ncfg_diag_t *diag, const char *name, char *out, size_t out_size)
{
	if (!out || !out_size) {
		return;
	}
	if (!diag) {
		(void)snprintf(out, out_size, "<unknown>: nothing went wrong");
		return;
	}
	(void)snprintf(out, out_size, "%s:%u:%u: %s", (name && name[0]) ? name : "<unknown>",
	    (unsigned int)diag->span.line, (unsigned int)diag->span.column,
	    diag->message ? diag->message : "");
}

/* ------------------------------------------------------------------ *
 * The token stream
 * ------------------------------------------------------------------ */

/*
 * Pull a token, turning a lexer failure into a diagnostic and an end of
 * input.
 *
 * The parser keeps going afterwards where it can, which is why
 * `ncfg_lexer_next` leaves its cursor usable after a failure: a file with
 * three mistakes should report three.
 */
static void pull(parser_t *parser, ncfg_token_t *out)
{
	char message[NCFG_ERROR_MAX];

	memset(out, 0, sizeof(*out));
	if (ncfg_lexer_next(&parser->lexer, out, message, sizeof(message))) {
		return;
	}
	ncfg_token_free(out);
	memset(out, 0, sizeof(*out));
	out->kind = NCFG_TOKEN_EOF;
	out->span = ncfg_lexer_error_span(&parser->lexer);
	store_diag(parser, out->span, message);
}

/* The next token without consuming it. The pointer is the parser's and is
 * good until the next `take`, `drop` or `skip_terminators` -- never hold one
 * across those. */
static const ncfg_token_t *peek(parser_t *parser)
{
	if (!parser->have_lookahead) {
		pull(parser, &parser->lookahead);
		parser->have_lookahead = 1;
	}
	return &parser->lookahead;
}

/* The next token, which the caller now owns and must free. */
static void take(parser_t *parser, ncfg_token_t *out)
{
	if (parser->have_lookahead) {
		*out = parser->lookahead;
		memset(&parser->lookahead, 0, sizeof(parser->lookahead));
		parser->have_lookahead = 0;
		return;
	}
	pull(parser, out);
}

/* Consume one token and throw it away. */
static void drop(parser_t *parser)
{
	ncfg_token_t token;

	take(parser, &token);
	ncfg_token_free(&token);
}

/* Throw away a buffered token without consuming input past it. The bytes it
 * covered are already gone from the cursor; see `parse_hook`, which is the
 * only caller and the only place that matters. */
static void discard_lookahead(parser_t *parser)
{
	if (parser->have_lookahead) {
		ncfg_token_free(&parser->lookahead);
		parser->have_lookahead = 0;
	}
}

static void skip_terminators(parser_t *parser)
{
	while (peek(parser)->kind == NCFG_TOKEN_TERMINATOR) {
		drop(parser);
	}
}

/*
 * Move a token's text into the tree, leaving the token holding nothing.
 *
 * The text is already a copy with its escapes resolved -- `lex.h` says so --
 * so moving it is right and copying it again would be a second allocation for
 * nothing.
 */
static char *steal_text(ncfg_token_t *token, size_t *length_out)
{
	char *text = token->text;

	if (length_out) {
		*length_out = token->text_length;
	}
	token->text = NULL;
	token->text_length = 0u;
	return text;
}

static int token_is(const ncfg_token_t *token, const char *word)
{
	return token->kind == NCFG_TOKEN_IDENT && token->text
	    && strcmp(token->text, word) == 0;
}

static int in_list(const char *const *names, size_t count, const char *name)
{
	size_t i;

	for (i = 0u; i < count; i++) {
		if (strcmp(names[i], name) == 0) {
			return 1;
		}
	}
	return 0;
}

/*
 * Whether this word opens a hook block rather than a block of settings.
 *
 * `device` is in both tables in spirit -- it is a phase nowhere and a
 * labelled block everywhere -- and the exclusion is what keeps a block whose
 * head happens to collide with a phase name from being read as shell.
 */
static int is_hook_head(const char *name)
{
	if (strcmp(name, "on") == 0) {
		return 1;
	}
	return in_list(HOOK_PHASES, sizeof(HOOK_PHASES) / sizeof(HOOK_PHASES[0]), name)
	    && !in_list(LABELLED_BLOCKS, sizeof(LABELLED_BLOCKS) / sizeof(LABELLED_BLOCKS[0]),
	    name);
}

/* ------------------------------------------------------------------ *
 * Building nodes
 * ------------------------------------------------------------------ */

static ncfg_ast_item_t *new_item(parser_t *parser, ncfg_ast_item_kind_t kind)
{
	ncfg_ast_item_t *item = calloc(1u, sizeof(*item));

	if (!item) {
		note_oom(parser);
		return NULL;
	}
	item->kind = kind;
	return item;
}

static ncfg_ast_value_t *new_value(parser_t *parser, ncfg_ast_value_kind_t kind,
    ncfg_span_t span)
{
	ncfg_ast_value_t *value = calloc(1u, sizeof(*value));

	if (!value) {
		note_oom(parser);
		return NULL;
	}
	value->kind = kind;
	value->span = span;
	return value;
}

/* Append, taking ownership either way: on failure the item is freed here, so
 * no caller has to unwind one. */
static int items_push(ncfg_ast_items_t *items, ncfg_ast_item_t *item)
{
	ncfg_ast_item_t **grown;
	size_t            want;

	if (items->count == items->capacity) {
		if (items->capacity > SIZE_MAX / 2u / sizeof(*grown)) {
			ncfg_ast_item_free(item);
			return 0;
		}
		want = items->capacity ? items->capacity * 2u : 4u;
		grown = realloc(items->at, want * sizeof(*grown));
		if (!grown) {
			ncfg_ast_item_free(item);
			return 0;
		}
		items->at = grown;
		items->capacity = want;
	}
	items->at[items->count] = item;
	items->count++;
	return 1;
}

/* The same, for the entries of a list. */
static int values_push(ncfg_ast_values_t *values, ncfg_ast_value_t *value)
{
	ncfg_ast_value_t **grown;
	size_t             want;

	if (values->count == values->capacity) {
		if (values->capacity > SIZE_MAX / 2u / sizeof(*grown)) {
			ncfg_ast_value_free(value);
			return 0;
		}
		want = values->capacity ? values->capacity * 2u : 4u;
		grown = realloc(values->at, want * sizeof(*grown));
		if (!grown) {
			ncfg_ast_value_free(value);
			return 0;
		}
		values->at = grown;
		values->capacity = want;
	}
	values->at[values->count] = value;
	values->count++;
	return 1;
}

/* ------------------------------------------------------------------ *
 * The grammar
 * ------------------------------------------------------------------ */

static void parse_file(parser_t *parser, ncfg_ast_file_t *file)
{
	for (;;) {
		ncfg_ast_item_t *item;

		skip_terminators(parser);
		if (parser->out_of_memory) {
			return;
		}
		if (peek(parser)->kind == NCFG_TOKEN_EOF) {
			return;
		}
		item = parse_item(parser);
		if (item) {
			if (!items_push(&file->items, item)) {
				note_oom(parser);
				return;
			}
		} else if (!recover(parser)) {
			return;
		}
	}
}

/*
 * Skip to the next statement boundary after an error.
 *
 * Returns 0 at end of input. Without this the parser reports one problem and
 * stops, which is what makes people fix a configuration one line per compile.
 */
static int recover(parser_t *parser)
{
	for (;;) {
		ncfg_token_t      token;
		ncfg_token_kind_t kind;

		if (parser->out_of_memory) {
			return 0;
		}
		take(parser, &token);
		kind = token.kind;
		ncfg_token_free(&token);
		if (kind == NCFG_TOKEN_EOF) {
			return 0;
		}
		if (kind == NCFG_TOKEN_TERMINATOR) {
			return 1;
		}
	}
}

static ncfg_ast_item_t *parse_item(parser_t *parser)
{
	const ncfg_token_t *head = peek(parser);
	const ncfg_token_t *next;
	ncfg_ast_item_t    *item;
	ncfg_ast_value_t   *value;
	ncfg_token_t        key;
	ncfg_span_t         span;
	char               *name;
	char                found[FOUND_MAX];

	if (head->kind != NCFG_TOKEN_IDENT || !head->text) {
		ncfg_token_describe(head, found, sizeof(found));
		push_diag(parser, head->span, "expected a statement, found %s", found);
		return NULL;
	}
	if (token_is(head, "include")) {
		return parse_include(parser);
	}
	if (token_is(head, "override")) {
		drop(parser);
		item = parse_block(parser);
		if (!item) {
			return NULL;
		}
		item->as.block.overrides = 1;
		return item;
	}
	if (is_hook_head(head->text)) {
		return parse_hook(parser);
	}

	/*
	 * An assignment and a block differ only after the key, so the decision
	 * is made by what follows rather than by a keyword table: `dns = ...`
	 * and `dns { ... }` are both legitimate spellings, for different
	 * things.
	 */
	take(parser, &key);
	next = peek(parser);
	switch (next->kind) {
	case NCFG_TOKEN_EQUALS:
		drop(parser);
		value = parse_value(parser);
		if (!value) {
			ncfg_token_free(&key);
			return NULL;
		}
		expect_terminator(parser);
		item = new_item(parser, NCFG_AST_ITEM_ASSIGNMENT);
		if (!item) {
			ncfg_ast_value_free(value);
			ncfg_token_free(&key);
			return NULL;
		}
		item->as.assignment.span = key.span;
		item->as.assignment.key = steal_text(&key, NULL);
		item->as.assignment.value = value;
		ncfg_token_free(&key);
		return item;
	case NCFG_TOKEN_LBRACE:
	case NCFG_TOKEN_IDENT:
	case NCFG_TOKEN_STRING:
		span = key.span;
		name = steal_text(&key, NULL);
		ncfg_token_free(&key);
		return parse_block_after_head(parser, name, span);
	default:
		ncfg_token_describe(next, found, sizeof(found));
		push_diag(parser, next->span, "expected `=` or `{` after `%s`, found %s",
		    key.text ? key.text : "", found);
		ncfg_token_free(&key);
		return NULL;
	}
}

static ncfg_ast_item_t *parse_include(parser_t *parser)
{
	ncfg_ast_item_t *item;
	ncfg_token_t     keyword;
	ncfg_token_t     value;
	char             found[FOUND_MAX];

	take(parser, &keyword);
	take(parser, &value);
	if (value.kind != NCFG_TOKEN_STRING) {
		ncfg_token_describe(&value, found, sizeof(found));
		push_diag(parser, value.span, "expected a quoted path after `include`, found %s",
		    found);
		ncfg_token_free(&value);
		ncfg_token_free(&keyword);
		return NULL;
	}
	expect_terminator(parser);
	item = new_item(parser, NCFG_AST_ITEM_INCLUDE);
	if (item) {
		/* The keyword's span rather than the path's: `include` is what
		 * the reader has to find on the line, and a caller that cannot
		 * resolve the path points at the statement. */
		item->as.include.span = keyword.span;
		item->as.include.path = steal_text(&value, &item->as.include.path_length);
	}
	ncfg_token_free(&value);
	ncfg_token_free(&keyword);
	return item;
}

static ncfg_ast_item_t *parse_hook(parser_t *parser)
{
	ncfg_ast_item_t *item;
	ncfg_token_t     keyword;
	ncfg_token_t     brace;
	ncfg_span_t      span;
	char            *phase;
	char            *body = NULL;
	size_t           body_length = 0u;
	char             message[NCFG_ERROR_MAX];
	char             found[FOUND_MAX];

	take(parser, &keyword);
	span = keyword.span;
	phase = steal_text(&keyword, NULL);
	ncfg_token_free(&keyword);
	if (!phase) {
		/* Only reachable if the token that decided this was a hook
		 * stopped being an identifier between the peek and the take,
		 * which nothing does. Refuse rather than build a hook with no
		 * phase. */
		note_oom(parser);
		return NULL;
	}

	if (strcmp(phase, "on") == 0) {
		ncfg_token_t event;

		take(parser, &event);
		if (event.kind != NCFG_TOKEN_IDENT || !event.text) {
			ncfg_token_describe(&event, found, sizeof(found));
			push_diag(parser, event.span, "expected an event name after `on`, found %s",
			    found);
			ncfg_token_free(&event);
			free(phase);
			return NULL;
		}
		/* The phase becomes the event, and the span stays on `on`:
		 * that is the word the reader scans a file for. */
		free(phase);
		phase = steal_text(&event, NULL);
		ncfg_token_free(&event);
	}

	take(parser, &brace);
	if (brace.kind != NCFG_TOKEN_LBRACE) {
		ncfg_token_describe(&brace, found, sizeof(found));
		push_diag(parser, brace.span, "expected `{` after `%s`, found %s", phase, found);
		ncfg_token_free(&brace);
		free(phase);
		return NULL;
	}
	ncfg_token_free(&brace);

	/*
	 * Step out of the token stream here.
	 *
	 * The lexer has probably buffered the newline behind the `{`; consume
	 * it, and then drop whatever else is buffered so the body scanner
	 * starts at raw bytes. Dropping a buffered token throws its bytes away
	 * -- there is nowhere to put them back -- so anything but a newline
	 * after the `{` loses a word out of the body. That only arises on
	 * input that has no body to lose: a body ends at a line containing
	 * nothing but `}`, so a hook written all on one line is unterminated
	 * whatever this does with it, and the manual's one-line form is a
	 * shell function *inside* a body rather than a body on one line.
	 */
	if (peek(parser)->kind == NCFG_TOKEN_TERMINATOR) {
		drop(parser);
	}
	discard_lookahead(parser);

	if (!ncfg_lexer_hook_body(&parser->lexer, &body, &body_length, message,
	    sizeof(message))) {
		push_diag(parser, ncfg_lexer_error_span(&parser->lexer), "%s", message);
		free(phase);
		return NULL;
	}
	item = new_item(parser, NCFG_AST_ITEM_HOOK);
	if (!item) {
		free(body);
		free(phase);
		return NULL;
	}
	item->as.hook.span = span;
	item->as.hook.phase = phase;
	/* Exactly what the lexer handed back, with nothing trimmed and nothing
	 * re-indented: a hook body is shell, and both of those change what the
	 * shell does. */
	item->as.hook.body = body;
	item->as.hook.body_length = body_length;
	return item;
}

/* A block after `override`, which has no head yet. */
static ncfg_ast_item_t *parse_block(parser_t *parser)
{
	ncfg_token_t head;
	ncfg_span_t  span;
	char        *name;
	char         found[FOUND_MAX];

	take(parser, &head);
	if (head.kind != NCFG_TOKEN_IDENT || !head.text) {
		ncfg_token_describe(&head, found, sizeof(found));
		push_diag(parser, head.span, "expected a block after `override`, found %s", found);
		ncfg_token_free(&head);
		return NULL;
	}
	span = head.span;
	name = steal_text(&head, NULL);
	ncfg_token_free(&head);
	return parse_block_after_head(parser, name, span);
}

/*
 * A block whose head has been read. Takes `head`, and frees it on every path.
 */
static ncfg_ast_item_t *parse_block_after_head(parser_t *parser, char *head, ncfg_span_t span)
{
	ncfg_ast_item_t    *item;
	const ncfg_token_t *next;
	ncfg_token_t        brace;
	char                found[FOUND_MAX];

	item = new_item(parser, NCFG_AST_ITEM_BLOCK);
	if (!item) {
		free(head);
		return NULL;
	}
	item->as.block.head = head;
	item->as.block.span = span;

	next = peek(parser);
	if (next->kind == NCFG_TOKEN_IDENT || next->kind == NCFG_TOKEN_STRING) {
		ncfg_token_t label;

		take(parser, &label);
		item->as.block.label = steal_text(&label, &item->as.block.label_length);
		ncfg_token_free(&label);
	}

	take(parser, &brace);
	if (brace.kind != NCFG_TOKEN_LBRACE) {
		ncfg_token_describe(&brace, found, sizeof(found));
		push_diag(parser, brace.span, "expected `{` to open `%s`, found %s",
		    item->as.block.head, found);
		ncfg_token_free(&brace);
		ncfg_ast_item_free(item);
		return NULL;
	}
	/*
	 * Bounded here rather than at the recursive call, because this is the
	 * one place a block body is entered from: `parse_block` and
	 * `parse_item` both arrive through it.
	 */
	if (parser->depth >= (size_t)NCFG_MAX_NESTING_DEPTH) {
		push_diag(parser, brace.span,
		    "`%s` nests more than %d blocks deep: this is almost always an "
		    "unclosed block earlier in the file",
		    item->as.block.head, NCFG_MAX_NESTING_DEPTH);
		ncfg_token_free(&brace);
		ncfg_ast_item_free(item);
		return NULL;
	}
	ncfg_token_free(&brace);
	parser->depth++;
	item = parse_block_items(parser, item);
	parser->depth--;
	return item;
}

/*
 * The body of a block, once its head, label and `{` are consumed. Takes
 * `item`, and frees it on every failing path.
 *
 * Split from `parse_block_after_head` so the depth counter has one place to
 * go up and one to come back down, rather than a decrement before each of
 * several early returns -- which is the shape that eventually grows a return
 * without one.
 */
static ncfg_ast_item_t *parse_block_items(parser_t *parser, ncfg_ast_item_t *item)
{
	for (;;) {
		const ncfg_token_t *next;
		ncfg_ast_item_t    *child;

		skip_terminators(parser);
		if (parser->out_of_memory) {
			ncfg_ast_item_free(item);
			return NULL;
		}
		next = peek(parser);
		if (next->kind == NCFG_TOKEN_RBRACE) {
			drop(parser);
			break;
		}
		if (next->kind == NCFG_TOKEN_EOF) {
			/* Reported at the head rather than at the end of the
			 * file, because the brace that is missing belongs to
			 * the block that was opened here. */
			push_diag(parser, item->as.block.span,
			    "unclosed block `%s`: every block needs a closing `}`",
			    item->as.block.head);
			ncfg_ast_item_free(item);
			return NULL;
		}
		child = parse_item(parser);
		if (child) {
			if (!items_push(&item->as.block.items, child)) {
				note_oom(parser);
				ncfg_ast_item_free(item);
				return NULL;
			}
		} else if (!recover(parser)) {
			ncfg_ast_item_free(item);
			return NULL;
		}
	}
	expect_terminator(parser);
	return item;
}

static ncfg_ast_value_t *parse_value(parser_t *parser)
{
	ncfg_ast_value_t *value;
	ncfg_token_t      token;
	ncfg_span_t       span;
	char              found[FOUND_MAX];

	take(parser, &token);
	span = token.span;
	switch (token.kind) {
	case NCFG_TOKEN_STRING:
		value = new_value(parser, NCFG_AST_STRING, span);
		if (value) {
			value->string = steal_text(&token, &value->string_length);
		}
		break;
	case NCFG_TOKEN_NUMBER:
		value = new_value(parser, NCFG_AST_NUMBER, span);
		if (value) {
			value->number = token.number;
		}
		break;
	case NCFG_TOKEN_BOOL:
		value = new_value(parser, NCFG_AST_BOOL, span);
		if (value) {
			value->boolean = token.boolean;
		}
		break;
	case NCFG_TOKEN_LBRACKET:
		ncfg_token_free(&token);
		return parse_list(parser, span);
	default:
		ncfg_token_describe(&token, found, sizeof(found));
		push_diag(parser, span, "expected a value, found %s", found);
		value = NULL;
		break;
	}
	ncfg_token_free(&token);
	return value;
}

static ncfg_ast_value_t *parse_list(parser_t *parser, ncfg_span_t span)
{
	ncfg_ast_value_t *list;

	/*
	 * The same counter as a block's, and that is the point.
	 *
	 * `parse_value` -> `parse_list` -> `parse_value` recurses exactly as a
	 * run of `{` does, and the first fix for the stack overflow bounded
	 * blocks alone -- the fuzzer found this path again in under five
	 * minutes. A second construct with its own budget would be the same
	 * defect a third time.
	 */
	if (parser->depth >= (size_t)NCFG_MAX_NESTING_DEPTH) {
		push_diag(parser, span,
		    "a list nests more than %d deep: this is almost always an unclosed "
		    "`[` earlier in the file",
		    NCFG_MAX_NESTING_DEPTH);
		return NULL;
	}
	list = new_value(parser, NCFG_AST_LIST, span);
	if (!list) {
		return NULL;
	}
	parser->depth++;
	list = parse_list_entries(parser, list);
	parser->depth--;
	return list;
}

/* The entries of a list, with the depth counter already raised. Takes `list`,
 * and frees it on every failing path. */
static ncfg_ast_value_t *parse_list_entries(parser_t *parser, ncfg_ast_value_t *list)
{
	for (;;) {
		const ncfg_token_t *next;
		ncfg_ast_value_t   *entry;
		char                found[FOUND_MAX];

		/* A list may span lines -- a long one is unreadable otherwise
		 * -- so a terminator inside it is whitespace. */
		skip_terminators(parser);
		if (parser->out_of_memory) {
			ncfg_ast_value_free(list);
			return NULL;
		}
		if (peek(parser)->kind == NCFG_TOKEN_RBRACKET) {
			drop(parser);
			break;
		}
		entry = parse_value(parser);
		if (!entry) {
			ncfg_ast_value_free(list);
			return NULL;
		}
		if (!values_push(&list->entries, entry)) {
			note_oom(parser);
			ncfg_ast_value_free(list);
			return NULL;
		}
		skip_terminators(parser);
		next = peek(parser);
		if (next->kind == NCFG_TOKEN_COMMA) {
			drop(parser);
			continue;
		}
		if (next->kind == NCFG_TOKEN_RBRACKET) {
			drop(parser);
			break;
		}
		ncfg_token_describe(next, found, sizeof(found));
		push_diag(parser, next->span, "expected `,` or `]` in list, found %s", found);
		ncfg_ast_value_free(list);
		return NULL;
	}
	return list;
}

/*
 * Consume the end of a statement, if one was written.
 *
 * End of input and `}` end a statement without a terminator, because
 * `interface eth0 { config = "dhcp" }` is a spelling people use and the
 * grammar allows.
 */
static void expect_terminator(parser_t *parser)
{
	const ncfg_token_t *next = peek(parser);
	char                found[FOUND_MAX];

	if (next->kind == NCFG_TOKEN_TERMINATOR) {
		drop(parser);
		return;
	}
	if (next->kind == NCFG_TOKEN_EOF || next->kind == NCFG_TOKEN_RBRACE) {
		return;
	}
	ncfg_token_describe(next, found, sizeof(found));
	push_diag(parser, next->span, "expected end of statement, found %s", found);
}

/* ------------------------------------------------------------------ *
 * The entry point
 * ------------------------------------------------------------------ */

int ncfg_parse(const char *text, size_t length, ncfg_ast_file_t **file_out,
    ncfg_diags_t *diags, char *err, size_t err_size)
{
	parser_t         parser;
	ncfg_diags_t     own;
	ncfg_ast_file_t *file;

	if (!file_out) {
		ncfg_error_set(err, err_size, "nowhere to put the parsed file");
		return 0;
	}
	*file_out = NULL;
	memset(&own, 0, sizeof(own));
	memset(&parser, 0, sizeof(parser));
	/* A caller that wants only the sentence still gets one, because the
	 * diagnostics have to be collected somewhere for the first of them to
	 * be reportable at all. */
	parser.diags = diags ? diags : &own;
	ncfg_lexer_init(&parser.lexer, text, length);

	file = calloc(1u, sizeof(*file));
	if (!file) {
		ncfg_error_set(err, err_size, "out of memory for the parsed file");
		return 0;
	}
	parse_file(&parser, file);
	discard_lookahead(&parser);

	if (parser.diags->total == 0u && !parser.out_of_memory) {
		*file_out = file;
		return 1;
	}
	/*
	 * A partly built tree is never handed back. Half a configuration that
	 * looks whole is what `buf.h` refuses to hand out for the same reason:
	 * the parser cannot know which half survived, and a document the
	 * operator did not write is worse than no document.
	 */
	ncfg_ast_file_free(file);
	if (parser.diags->count > 0u) {
		ncfg_error_set(err, err_size, "%s", parser.diags->at[0].message);
	} else {
		ncfg_error_set(err, err_size, "out of memory while parsing the configuration");
	}
	ncfg_diags_free(&own);
	return 0;
}
