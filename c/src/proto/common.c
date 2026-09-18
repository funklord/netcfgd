/*
 * common.c -- the pieces both directions are built from: counted strings, the
 * memory a decoded message owns, and typed member access with a refusal.
 */
#include "internal.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------ the strings */

ncfg_proto_str_t ncfg_proto_str(const char *text)
{
	ncfg_proto_str_t out;

	out.bytes = text;
	out.length = text ? strlen(text) : 0;
	return out;
}

ncfg_proto_str_t ncfg_proto_str_none(void)
{
	ncfg_proto_str_t out;

	out.bytes = NULL;
	out.length = 0;
	return out;
}

int ncfg_proto_str_present(ncfg_proto_str_t text)
{
	return text.bytes != NULL;
}

int ncfg_proto_str_equals(ncfg_proto_str_t text, const char *other)
{
	size_t length;

	if (!text.bytes || !other) {
		/* Absent equals absent and nothing else. An absent SSID name and
		 * an empty one are different networks (section 8), so this does
		 * not quietly treat NULL as "". */
		return !text.bytes && !other;
	}
	length = strlen(other);
	return length == text.length && memcmp(text.bytes, other, length) == 0;
}

/* ------------------------------------------------------- what a message owns */

int ncfg_proto_fail(ncfg_proto_dec_t *dec, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	ncfg_error_setv(dec->err, dec->err_size, format, args);
	va_end(args);
	return 0;
}

void *ncfg_proto_block(ncfg_proto_dec_t *dec, size_t count, size_t size)
{
	void *block;

	if (!count) {
		/* The empty list. A caller reads the count, so there is nothing
		 * here to point at and nothing to free. */
		return NULL;
	}
	if (dec->message->block_count == dec->message->block_capacity) {
		size_t next = dec->message->block_capacity ? dec->message->block_capacity * 2u : 8u;
		void **grown = realloc(dec->message->blocks, next * sizeof(*grown));

		if (!grown) {
			ncfg_proto_fail(dec, "out of memory decoding a message");
			return NULL;
		}
		dec->message->blocks = grown;
		dec->message->block_capacity = next;
	}
	block = calloc(count, size);
	if (!block) {
		ncfg_proto_fail(dec, "out of memory decoding a message");
		return NULL;
	}
	dec->message->blocks[dec->message->block_count++] = block;
	return block;
}

/* --------------------------------------------------------------- members */

/*
 * Whether a member is there at all, treating null as absent.
 *
 * Every optional member in this protocol is a serde `Option` skipped when it
 * is `None`, so no member's null means something its absence does not -- and
 * a daemon writing `null` where it means nothing is section 7's second bullet
 * rather than a third state this has to carry. A caller that needs the
 * difference anyway reads the parsed document, which the message keeps.
 */
static int present(const ncfg_json_doc_t *doc, uint32_t node)
{
	return node != NCFG_JSON_NONE && ncfg_json_type(doc, node) != NCFG_JSON_NULL;
}

int ncfg_proto_get_str(ncfg_proto_dec_t *dec, uint32_t object, const char *name,
    int required, const char *what, ncfg_proto_str_t *out)
{
	uint32_t node = ncfg_json_member(dec->doc, object, name);
	size_t length = 0;
	const char *bytes;

	*out = ncfg_proto_str_none();
	if (!present(dec->doc, node)) {
		if (required) {
			return ncfg_proto_fail(dec, "%s is missing `%s`", what, name);
		}
		return 1;
	}
	bytes = ncfg_json_string(dec->doc, node, &length);
	if (!bytes) {
		return ncfg_proto_fail(dec, "`%s` on %s is not a string", name, what);
	}
	out->bytes = bytes;
	out->length = length;
	return 1;
}

int ncfg_proto_get_bool(ncfg_proto_dec_t *dec, uint32_t object, const char *name,
    int required, unsigned char fallback, const char *what, unsigned char *out)
{
	uint32_t node = ncfg_json_member(dec->doc, object, name);

	*out = fallback;
	if (!present(dec->doc, node)) {
		if (required) {
			return ncfg_proto_fail(dec, "%s is missing `%s`", what, name);
		}
		return 1;
	}
	if (ncfg_json_type(dec->doc, node) != NCFG_JSON_BOOL) {
		return ncfg_proto_fail(dec, "`%s` on %s is not true or false", name, what);
	}
	*out = ncfg_json_bool(dec->doc, node, 0) ? 1u : 0u;
	return 1;
}

int ncfg_proto_get_int(ncfg_proto_dec_t *dec, uint32_t object, const char *name,
    int required, const char *what, ncfg_proto_int_t *out)
{
	uint32_t node = ncfg_json_member(dec->doc, object, name);
	int64_t low;
	int64_t high;

	out->present = 0;
	out->value = 0;
	if (!present(dec->doc, node)) {
		if (required) {
			return ncfg_proto_fail(dec, "%s is missing `%s`", what, name);
		}
		return 1;
	}
	if (ncfg_json_type(dec->doc, node) != NCFG_JSON_NUMBER) {
		return ncfg_proto_fail(dec, "`%s` on %s is not a number", name, what);
	}
	/*
	 * Asked twice with different fallbacks, because the reader answers "not
	 * an integer, or too big for one" by handing back whatever the caller
	 * offered. Two answers that agree came from the text; two that differ
	 * mean the reader never converted anything -- which is a `1e9`, a
	 * fraction, or a number past 64 bits, none of which netcfgd sends and
	 * all of which would otherwise be read as the fallback and drawn.
	 */
	low = ncfg_json_int(dec->doc, node, INT64_MIN);
	high = ncfg_json_int(dec->doc, node, INT64_MAX);
	if (low != high) {
		return ncfg_proto_fail(dec, "`%s` on %s is not a whole number this can hold",
		    name, what);
	}
	out->present = 1;
	out->value = low;
	return 1;
}

int ncfg_proto_get_version(ncfg_proto_dec_t *dec, uint32_t object, const char *name,
    const char *what, ncfg_proto_version_t *out)
{
	uint32_t node = ncfg_json_member(dec->doc, object, name);
	ncfg_proto_int_t major;
	ncfg_proto_int_t minor;

	out->major = 0;
	out->minor = 0;
	if (!present(dec->doc, node) || ncfg_json_type(dec->doc, node) != NCFG_JSON_OBJECT) {
		return ncfg_proto_fail(dec, "%s is missing a `%s` version", what, name);
	}
	if (!ncfg_proto_get_int(dec, node, "major", 1, name, &major) ||
	    !ncfg_proto_get_int(dec, node, "minor", 1, name, &minor)) {
		return 0;
	}
	out->major = major.value;
	out->minor = minor.value;
	return 1;
}

int ncfg_proto_get_array(ncfg_proto_dec_t *dec, uint32_t object, const char *name,
    int required, const char *what, uint32_t *array_out, size_t *count_out)
{
	uint32_t node = ncfg_json_member(dec->doc, object, name);

	*array_out = NCFG_JSON_NONE;
	*count_out = 0;
	if (!present(dec->doc, node)) {
		if (required) {
			return ncfg_proto_fail(dec, "%s is missing `%s`", what, name);
		}
		return 1;
	}
	if (ncfg_json_type(dec->doc, node) != NCFG_JSON_ARRAY) {
		return ncfg_proto_fail(dec, "`%s` on %s is not a list", name, what);
	}
	*array_out = node;
	*count_out = ncfg_json_count(dec->doc, node);
	return 1;
}

int ncfg_proto_get_strs(ncfg_proto_dec_t *dec, uint32_t object, const char *name,
    int required, const char *what, ncfg_proto_strs_t *out)
{
	uint32_t array;
	size_t count;
	ncfg_proto_str_t *items;
	size_t at;

	out->items = NULL;
	out->count = 0;
	if (!ncfg_proto_get_array(dec, object, name, required, what, &array, &count)) {
		return 0;
	}
	if (!count) {
		return 1;
	}
	items = ncfg_proto_block(dec, count, sizeof(*items));
	if (!items) {
		return 0;
	}
	for (at = 0; at < count; at++) {
		uint32_t element = ncfg_json_at(dec->doc, array, (uint32_t)at);
		size_t length = 0;
		const char *bytes = ncfg_json_string(dec->doc, element, &length);

		if (!bytes) {
			return ncfg_proto_fail(dec, "`%s` on %s holds something that is not a string",
			    name, what);
		}
		items[at].bytes = bytes;
		items[at].length = length;
	}
	out->items = items;
	out->count = count;
	return 1;
}

/* ------------------------------------------------- refusing a member by name */

/*
 * Where the parsed document keeps its text.
 *
 * **This is the one thing the reader's public face does not offer.** A node
 * carries `key_offset` and `key_length` and `ncfg_json.h` says both index the
 * document's text, but nothing hands that text out -- the reader gives values
 * by name, because a response's keys are a schema rather than data. Refusing
 * an unknown member *by name* is the one job that needs the keys themselves.
 *
 * So the base is derived from a member whose value is a string:
 * `ncfg_json_string` returns that text at `value_offset`, so subtracting the
 * offset is the start. And it is then **checked rather than assumed** --
 * `known_key` is a member of this object whose spelling is already certain,
 * so reading its key back through the derived base either produces that
 * spelling or the derivation is wrong and this returns NULL.
 *
 * The alternative was scanning the line for its keys, which is a second
 * reader of one format: 0263 says why this port does not start one, and the
 * GUI and the CLI spelling an access point's name three ways is what it says
 * it with.
 */
static const char *text_base(const ncfg_json_doc_t *doc, uint32_t object, const char *known_key)
{
	uint32_t member = ncfg_json_member(doc, object, known_key);
	const ncfg_json_node_t *node = ncfg_json_node(doc, member);
	size_t length = 0;
	const char *value = ncfg_json_string(doc, member, &length);
	const char *base;
	size_t known_length;

	if (!node || !value) {
		return NULL;
	}
	base = value - (size_t)node->value_offset;
	known_length = strlen(known_key);
	if ((size_t)node->key_length != known_length ||
	    memcmp(base + (size_t)node->key_offset, known_key, known_length) != 0) {
		return NULL;
	}
	return base;
}

int ncfg_proto_check_members(ncfg_proto_dec_t *dec, uint32_t object, const char *known_key,
    const char *const *allowed, size_t allowed_count, const char *what)
{
	uint32_t count;
	uint32_t at;
	const char *base;

	/*
	 * The whole of the direction asymmetry, in one branch. A response is
	 * read by a client that may be older than the daemon it is talking to,
	 * so a member it does not recognise is ignored rather than refused --
	 * refusing one is how an upgrade breaks a working client.
	 */
	if (!dec->strict) {
		return 1;
	}
	count = ncfg_json_count(dec->doc, object);
	base = text_base(dec->doc, object, known_key);
	for (at = 0; at < count; at++) {
		uint32_t member = ncfg_json_at(dec->doc, object, at);
		const ncfg_json_node_t *node = ncfg_json_node(dec->doc, member);
		size_t which;
		int known;

		if (!node) {
			continue;
		}
		/*
		 * Matched by node rather than by name, which is what makes a
		 * repeated key refused rather than accepted twice: `ncfg_json_member`
		 * answers with the first member of that name, so a second one is
		 * nobody's and is reported. The reader does not merge duplicates
		 * and this protocol does not send them.
		 */
		known = ncfg_json_member(dec->doc, object, known_key) == member;
		for (which = 0; !known && which < allowed_count; which++) {
			known = ncfg_json_member(dec->doc, object, allowed[which]) == member;
		}
		if (known) {
			continue;
		}
		if (base) {
			return ncfg_proto_fail(dec, "unknown member `%.*s` on %s",
			    (int)node->key_length, base + (size_t)node->key_offset, what);
		}
		/* Refusing is the half that protects the daemon; naming it is the
		 * half that tells a client what to fix. Losing the second is bad
		 * and losing the first is dangerous, so this still refuses. */
		return ncfg_proto_fail(dec, "a member %s does not define, at position %u",
		    what, (unsigned)at);
	}
	return 1;
}
