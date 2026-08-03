/*
 * ncfg_json.c -- the reader described in ncfg_json.h.
 *
 * Parsing is one pass, iterative, with an explicit stack of open containers
 * bounded by NCFG_JSON_MAX_DEPTH. Recursion would be shorter and is the reason
 * a JSON parser turns up in half the CVE lists there are: a document nests as
 * deep as its author likes, and a C stack does not.
 */
#include "ncfg_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ncfg_json_doc {
	char             *text;   /* a copy, unescaped in place */
	ncfg_json_node_t *nodes;
	uint32_t          count;
	uint32_t          capacity;
};

/* Where the parser is, and what it is inside. */
typedef struct {
	const char      *in;
	size_t           length;
	size_t           at;
	ncfg_json_doc_t *doc;
	char            *out;      /* the write head into doc->text */
	char            *err;
	size_t           err_size;
} parser_t;

static void fail(parser_t *p, const char *what)
{
	if (p->err && p->err_size) {
		snprintf(p->err, p->err_size, "%s at byte %zu", what, p->at);
	}
}

static int reserve(parser_t *p)
{
	ncfg_json_doc_t *doc = p->doc;

	if (doc->count < doc->capacity) {
		return 1;
	}
	/* Doubling, from a size that covers a `hello` outright so the common
	 * small response never reallocates at all. */
	uint32_t next = doc->capacity ? doc->capacity * 2u : 32u;
	if (next < doc->capacity) {
		fail(p, "too many values");
		return 0;
	}
	ncfg_json_node_t *grown = realloc(doc->nodes, (size_t)next * sizeof(*grown));
	if (!grown) {
		fail(p, "out of memory");
		return 0;
	}
	doc->nodes = grown;
	doc->capacity = next;
	return 1;
}

static uint32_t new_node(parser_t *p, ncfg_json_type_t type)
{
	if (!reserve(p)) {
		return NCFG_JSON_NONE;
	}
	uint32_t index = p->doc->count++;
	ncfg_json_node_t *node = &p->doc->nodes[index];

	node->type = type;
	node->key_offset = 0;
	node->key_length = 0;
	node->value_offset = 0;
	node->value_length = 0;
	node->bool_value = 0;
	node->first_child = NCFG_JSON_NONE;
	node->child_count = 0;
	node->next_sibling = NCFG_JSON_NONE;
	return index;
}

static void skip_space(parser_t *p)
{
	/* The four JSON calls whitespace, and no others: a vertical tab between
	 * two members is not something netcfgd emits, so accepting it would be
	 * accepting a document from something else. */
	while (p->at < p->length) {
		char c = p->in[p->at];
		if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
			p->at++;
		} else {
			break;
		}
	}
}

static int hex_nibble(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}

/* One \uXXXX, as a code unit. -1 on anything malformed. */
static int read_code_unit(parser_t *p)
{
	if (p->length - p->at < 4) {
		return -1;
	}
	int value = 0;
	for (int i = 0; i < 4; i++) {
		int nibble = hex_nibble(p->in[p->at + (size_t)i]);
		if (nibble < 0) {
			return -1;
		}
		value = (value << 4) | nibble;
	}
	p->at += 4;
	return value;
}

static void write_utf8(parser_t *p, uint32_t code_point)
{
	if (code_point < 0x80u) {
		*p->out++ = (char)code_point;
	} else if (code_point < 0x800u) {
		*p->out++ = (char)(0xc0u | (code_point >> 6));
		*p->out++ = (char)(0x80u | (code_point & 0x3fu));
	} else if (code_point < 0x10000u) {
		*p->out++ = (char)(0xe0u | (code_point >> 12));
		*p->out++ = (char)(0x80u | ((code_point >> 6) & 0x3fu));
		*p->out++ = (char)(0x80u | (code_point & 0x3fu));
	} else {
		*p->out++ = (char)(0xf0u | (code_point >> 18));
		*p->out++ = (char)(0x80u | ((code_point >> 12) & 0x3fu));
		*p->out++ = (char)(0x80u | ((code_point >> 6) & 0x3fu));
		*p->out++ = (char)(0x80u | (code_point & 0x3fu));
	}
}

/*
 * A string, unescaped into doc->text at the write head.
 *
 * The opening quote has been consumed. On success `offset` and `length` say
 * where the unescaped bytes went.
 */
static int parse_string(parser_t *p, uint32_t *offset, uint32_t *length)
{
	char *start = p->out;

	for (;;) {
		if (p->at >= p->length) {
			fail(p, "a string with no closing quote");
			return 0;
		}
		unsigned char c = (unsigned char)p->in[p->at];

		if (c == '"') {
			p->at++;
			*offset = (uint32_t)(start - p->doc->text);
			*length = (uint32_t)(p->out - start);
			return 1;
		}
		if (c < 0x20u) {
			/* JSON forbids it, and netcfgd's own framing would break on
			 * the one that matters: a raw newline inside a string would
			 * split one message into two. */
			fail(p, "a control character in a string");
			return 0;
		}
		if (c != '\\') {
			*p->out++ = (char)c;
			p->at++;
			continue;
		}

		p->at++;
		if (p->at >= p->length) {
			fail(p, "an escape at the end of the input");
			return 0;
		}
		char escape = p->in[p->at++];
		switch (escape) {
		case '"':  *p->out++ = '"';  break;
		case '\\': *p->out++ = '\\'; break;
		case '/':  *p->out++ = '/';  break;
		case 'b':  *p->out++ = '\b'; break;
		case 'f':  *p->out++ = '\f'; break;
		case 'n':  *p->out++ = '\n'; break;
		case 'r':  *p->out++ = '\r'; break;
		case 't':  *p->out++ = '\t'; break;
		case 'u': {
			int unit = read_code_unit(p);
			if (unit < 0) {
				fail(p, "a \\u escape that is not four hex digits");
				return 0;
			}
			uint32_t code_point = (uint32_t)unit;
			if (code_point >= 0xd800u && code_point <= 0xdbffu) {
				/* A high surrogate has to be followed by its low
				 * half. Half a pair is not a character, and
				 * writing it out would produce invalid UTF-8 that
				 * a Qt string would then refuse or mangle. */
				if (p->length - p->at < 2 || p->in[p->at] != '\\' ||
				    p->in[p->at + 1] != 'u') {
					fail(p, "a high surrogate with no low surrogate");
					return 0;
				}
				p->at += 2;
				int low = read_code_unit(p);
				if (low < 0xdc00 || low > 0xdfff) {
					fail(p, "a surrogate pair whose second half is not one");
					return 0;
				}
				code_point = 0x10000u + ((code_point - 0xd800u) << 10) +
					     ((uint32_t)low - 0xdc00u);
			} else if (code_point >= 0xdc00u && code_point <= 0xdfffu) {
				fail(p, "a low surrogate with no high surrogate");
				return 0;
			}
			write_utf8(p, code_point);
			break;
		}
		default:
			fail(p, "an escape that is not one of JSON's");
			return 0;
		}
	}
}

/*
 * A number, kept as text.
 *
 * Only its shape is checked here; the conversion happens in ncfg_json_int, on
 * the members a caller actually reads. netcfgd sends integers -- an MTU, a
 * metric, a priority -- and keeping the text means an unusual one is reported
 * rather than silently rounded through a double.
 */
static int parse_number(parser_t *p, uint32_t *offset, uint32_t *length)
{
	size_t start = p->at;

	if (p->at < p->length && p->in[p->at] == '-') {
		p->at++;
	}
	if (p->at >= p->length) {
		fail(p, "a number with no digits");
		return 0;
	}
	if (p->in[p->at] == '0') {
		p->at++;
		/* A leading zero is JSON's own rule, and keeping it means `007`
		 * cannot arrive and be read as 7 by one implementation and
		 * refused by another. */
	} else if (p->in[p->at] >= '1' && p->in[p->at] <= '9') {
		while (p->at < p->length && p->in[p->at] >= '0' && p->in[p->at] <= '9') {
			p->at++;
		}
	} else {
		fail(p, "a number with no digits");
		return 0;
	}
	if (p->at < p->length && p->in[p->at] == '.') {
		p->at++;
		size_t digits = 0;
		while (p->at < p->length && p->in[p->at] >= '0' && p->in[p->at] <= '9') {
			p->at++;
			digits++;
		}
		if (!digits) {
			fail(p, "a decimal point with no digits after it");
			return 0;
		}
	}
	if (p->at < p->length && (p->in[p->at] == 'e' || p->in[p->at] == 'E')) {
		p->at++;
		if (p->at < p->length && (p->in[p->at] == '+' || p->in[p->at] == '-')) {
			p->at++;
		}
		size_t digits = 0;
		while (p->at < p->length && p->in[p->at] >= '0' && p->in[p->at] <= '9') {
			p->at++;
			digits++;
		}
		if (!digits) {
			fail(p, "an exponent with no digits");
			return 0;
		}
	}

	/* The text is copied rather than pointed at, so that every value in the
	 * document lives in one buffer and the input can be freed. */
	size_t span = p->at - start;
	memcpy(p->out, p->in + start, span);
	*offset = (uint32_t)(p->out - p->doc->text);
	*length = (uint32_t)span;
	p->out += span;
	return 1;
}

static int literal(parser_t *p, const char *word)
{
	size_t span = strlen(word);

	if (p->length - p->at < span || memcmp(p->in + p->at, word, span) != 0) {
		return 0;
	}
	p->at += span;
	return 1;
}

/* An open container, while its children are being read. */
typedef struct {
	uint32_t node;
	uint32_t last_child;
	int      is_object;
} frame_t;

ncfg_json_doc_t *ncfg_json_parse(const char *text, size_t length, char *err, size_t err_size)
{
	if (err && err_size) {
		err[0] = '\0';
	}
	if (!text) {
		if (err && err_size) {
			snprintf(err, err_size, "no input");
		}
		return NULL;
	}

	ncfg_json_doc_t *doc = calloc(1, sizeof(*doc));
	if (!doc) {
		if (err && err_size) {
			snprintf(err, err_size, "out of memory");
		}
		return NULL;
	}
	/* One byte more than the input, so that a document consisting of one
	 * empty string still has somewhere to point. Unescaping only ever
	 * shrinks, so this is an upper bound rather than a guess. */
	doc->text = malloc(length + 1u);
	if (!doc->text) {
		free(doc);
		if (err && err_size) {
			snprintf(err, err_size, "out of memory");
		}
		return NULL;
	}

	parser_t parser = {
		.in = text,
		.length = length,
		.at = 0,
		.doc = doc,
		.out = doc->text,
		.err = err,
		.err_size = err_size,
	};
	parser_t *p = &parser;

	frame_t stack[NCFG_JSON_MAX_DEPTH];
	size_t depth = 0;
	uint32_t pending_key_offset = 0;
	uint32_t pending_key_length = 0;
	int have_pending_key = 0;

	skip_space(p);
	if (p->at >= p->length) {
		fail(p, "an empty message");
		goto refused;
	}

	for (;;) {
		/* One value, whatever it is, attached to the container on top of
		 * the stack -- or the root if there is none. */
		skip_space(p);
		if (p->at >= p->length) {
			fail(p, "a value that stops in the middle");
			goto refused;
		}

		char c = p->in[p->at];
		uint32_t index = NCFG_JSON_NONE;

		switch (c) {
		case '{':
		case '[': {
			if (depth >= NCFG_JSON_MAX_DEPTH) {
				fail(p, "a document nested deeper than this reads");
				goto refused;
			}
			p->at++;
			index = new_node(p, c == '{' ? NCFG_JSON_OBJECT : NCFG_JSON_ARRAY);
			if (index == NCFG_JSON_NONE) {
				goto refused;
			}
			break;
		}
		case '"': {
			p->at++;
			index = new_node(p, NCFG_JSON_STRING);
			if (index == NCFG_JSON_NONE) {
				goto refused;
			}
			uint32_t offset = 0;
			uint32_t span = 0;
			if (!parse_string(p, &offset, &span)) {
				goto refused;
			}
			doc->nodes[index].value_offset = offset;
			doc->nodes[index].value_length = span;
			break;
		}
		case 't':
		case 'f': {
			index = new_node(p, NCFG_JSON_BOOL);
			if (index == NCFG_JSON_NONE) {
				goto refused;
			}
			if (literal(p, "true")) {
				doc->nodes[index].bool_value = 1;
			} else if (literal(p, "false")) {
				doc->nodes[index].bool_value = 0;
			} else {
				fail(p, "a word that is not true or false");
				goto refused;
			}
			break;
		}
		case 'n': {
			index = new_node(p, NCFG_JSON_NULL);
			if (index == NCFG_JSON_NONE) {
				goto refused;
			}
			if (!literal(p, "null")) {
				fail(p, "a word that is not null");
				goto refused;
			}
			break;
		}
		default: {
			index = new_node(p, NCFG_JSON_NUMBER);
			if (index == NCFG_JSON_NONE) {
				goto refused;
			}
			uint32_t offset = 0;
			uint32_t span = 0;
			if (!parse_number(p, &offset, &span)) {
				goto refused;
			}
			doc->nodes[index].value_offset = offset;
			doc->nodes[index].value_length = span;
			break;
		}
		}

		if (have_pending_key) {
			doc->nodes[index].key_offset = pending_key_offset;
			doc->nodes[index].key_length = pending_key_length;
			have_pending_key = 0;
		}

		/* Attach it to whatever is open. */
		if (depth > 0) {
			frame_t *frame = &stack[depth - 1];
			if (frame->last_child == NCFG_JSON_NONE) {
				doc->nodes[frame->node].first_child = index;
			} else {
				doc->nodes[frame->last_child].next_sibling = index;
			}
			frame->last_child = index;
			doc->nodes[frame->node].child_count++;
		}

		if (c == '{' || c == '[') {
			stack[depth].node = index;
			stack[depth].last_child = NCFG_JSON_NONE;
			stack[depth].is_object = (c == '{');
			depth++;

			/* An empty container closes immediately, and so may the one
			 * that contained it. */
			skip_space(p);
			if (p->at < p->length &&
			    ((c == '{' && p->in[p->at] == '}') ||
			     (c == '[' && p->in[p->at] == ']'))) {
				p->at++;
				depth--;
			} else {
				if (c == '{') {
					goto expect_key;
				}
				continue; /* read the array's first element */
			}
		}

		/* A value has been read. Close whatever is finished, then either
		 * read the next value or stop. */
		for (;;) {
			if (depth == 0) {
				skip_space(p);
				if (p->at != p->length) {
					fail(p, "something after the end of the value");
					goto refused;
				}
				return doc;
			}
			skip_space(p);
			if (p->at >= p->length) {
				fail(p, "a container that is never closed");
				goto refused;
			}
			char next = p->in[p->at];
			frame_t *frame = &stack[depth - 1];

			if (next == ',') {
				p->at++;
				if (frame->is_object) {
					goto expect_key;
				}
				break; /* read the array's next element */
			}
			if ((next == '}' && frame->is_object) ||
			    (next == ']' && !frame->is_object)) {
				p->at++;
				depth--;
				continue; /* the parent may be finished too */
			}
			fail(p, "a container with something other than a comma or a close");
			goto refused;
		}
		continue;

expect_key:
		skip_space(p);
		if (p->at >= p->length || p->in[p->at] != '"') {
			fail(p, "an object member with no name");
			goto refused;
		}
		p->at++;
		if (!parse_string(p, &pending_key_offset, &pending_key_length)) {
			goto refused;
		}
		skip_space(p);
		if (p->at >= p->length || p->in[p->at] != ':') {
			fail(p, "a member name with no colon after it");
			goto refused;
		}
		p->at++;
		have_pending_key = 1;
	}

refused:
	ncfg_json_free(doc);
	return NULL;
}

void ncfg_json_free(ncfg_json_doc_t *doc)
{
	if (!doc) {
		return;
	}
	free(doc->nodes);
	free(doc->text);
	free(doc);
}

uint32_t ncfg_json_root(const ncfg_json_doc_t *doc)
{
	return (doc && doc->count) ? 0u : NCFG_JSON_NONE;
}

const ncfg_json_node_t *ncfg_json_node(const ncfg_json_doc_t *doc, uint32_t index)
{
	if (!doc || index >= doc->count) {
		return NULL;
	}
	return &doc->nodes[index];
}

ncfg_json_type_t ncfg_json_type(const ncfg_json_doc_t *doc, uint32_t index)
{
	const ncfg_json_node_t *node = ncfg_json_node(doc, index);

	/* Absent reads as null, which is wrong for exactly one caller and right
	 * for the rest -- so the one that cares compares against
	 * NCFG_JSON_NONE itself rather than asking the type. */
	return node ? node->type : NCFG_JSON_NULL;
}

uint32_t ncfg_json_member(const ncfg_json_doc_t *doc, uint32_t object, const char *name)
{
	const ncfg_json_node_t *node = ncfg_json_node(doc, object);

	if (!node || node->type != NCFG_JSON_OBJECT || !name) {
		return NCFG_JSON_NONE;
	}
	size_t want = strlen(name);
	for (uint32_t child = node->first_child; child != NCFG_JSON_NONE;
	     child = doc->nodes[child].next_sibling) {
		const ncfg_json_node_t *member = &doc->nodes[child];
		if (member->key_length == want &&
		    memcmp(doc->text + member->key_offset, name, want) == 0) {
			return child;
		}
	}
	return NCFG_JSON_NONE;
}

uint32_t ncfg_json_at(const ncfg_json_doc_t *doc, uint32_t array, uint32_t index)
{
	const ncfg_json_node_t *node = ncfg_json_node(doc, array);

	if (!node || (node->type != NCFG_JSON_ARRAY && node->type != NCFG_JSON_OBJECT)) {
		return NCFG_JSON_NONE;
	}
	uint32_t child = node->first_child;
	while (child != NCFG_JSON_NONE && index--) {
		child = doc->nodes[child].next_sibling;
	}
	return child;
}

uint32_t ncfg_json_count(const ncfg_json_doc_t *doc, uint32_t index)
{
	const ncfg_json_node_t *node = ncfg_json_node(doc, index);

	return node ? node->child_count : 0u;
}

const char *ncfg_json_string(const ncfg_json_doc_t *doc, uint32_t index, size_t *length_out)
{
	const ncfg_json_node_t *node = ncfg_json_node(doc, index);

	if (!node || node->type != NCFG_JSON_STRING) {
		if (length_out) {
			*length_out = 0;
		}
		return NULL;
	}
	if (length_out) {
		*length_out = node->value_length;
	}
	return doc->text + node->value_offset;
}

int ncfg_json_string_equals(const ncfg_json_doc_t *doc, uint32_t index, const char *other)
{
	size_t length = 0;
	const char *text = ncfg_json_string(doc, index, &length);

	if (!text || !other) {
		return 0;
	}
	size_t want = strlen(other);
	return length == want && memcmp(text, other, want) == 0;
}

int64_t ncfg_json_int(const ncfg_json_doc_t *doc, uint32_t index, int64_t fallback)
{
	const ncfg_json_node_t *node = ncfg_json_node(doc, index);

	if (!node || node->type != NCFG_JSON_NUMBER || !node->value_length) {
		return fallback;
	}

	/* By hand rather than through strtoll: the text is counted rather than
	 * terminated, and copying it into a buffer to terminate it would be more
	 * code than this. Anything that overflows, or that is not an integer,
	 * returns the fallback -- netcfgd sends neither, and a client that
	 * silently saturated would draw a wrong number rather than none. */
	const char *text = doc->text + node->value_offset;
	size_t length = node->value_length;
	size_t at = 0;
	int negative = 0;

	if (text[0] == '-') {
		negative = 1;
		at = 1;
	}
	if (at >= length) {
		return fallback;
	}
	uint64_t value = 0;
	for (; at < length; at++) {
		if (text[at] < '0' || text[at] > '9') {
			return fallback; /* a fraction or an exponent */
		}
		uint64_t digit = (uint64_t)(text[at] - '0');
		if (value > (UINT64_MAX - digit) / 10u) {
			return fallback;
		}
		value = value * 10u + digit;
	}
	if (negative) {
		if (value > (uint64_t)INT64_MAX + 1u) {
			return fallback;
		}
		if (value == (uint64_t)INT64_MAX + 1u) {
			return INT64_MIN;
		}
		return -(int64_t)value;
	}
	if (value > (uint64_t)INT64_MAX) {
		return fallback;
	}
	return (int64_t)value;
}

int ncfg_json_bool(const ncfg_json_doc_t *doc, uint32_t index, int fallback)
{
	const ncfg_json_node_t *node = ncfg_json_node(doc, index);

	if (!node || node->type != NCFG_JSON_BOOL) {
		return fallback;
	}
	return node->bool_value;
}

size_t ncfg_json_copy_member(const ncfg_json_doc_t *doc, uint32_t object, const char *name,
			     char *out, size_t out_size)
{
	if (!out || !out_size) {
		return 0;
	}
	out[0] = '\0';

	size_t length = 0;
	const char *text = ncfg_json_string(doc, ncfg_json_member(doc, object, name), &length);
	if (!text) {
		return 0;
	}
	if (length > out_size - 1u) {
		length = out_size - 1u;
	}
	memcpy(out, text, length);
	out[length] = '\0';
	return length;
}
