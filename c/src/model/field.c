/*
 * field.c -- the engine `field.h` describes.
 *
 * NAMING THE MEMBER THAT WAS REFUSED, WITH THE READER THIS PORT SHARES
 *   `client/ncfg_json.h` offers no way to read a member's *name*: lookup is by
 *   name, and a node carries its key as an offset into a buffer the reader
 *   does not hand out. That is fine for a client reading known fields and it
 *   is not fine here, because `deny_unknown_fields` has to say **which**
 *   member it refused -- an operator holding a 117 KB document and told only
 *   "unknown field" has been given a search, not a diagnostic.
 *
 *   So the offending member is found by elimination -- every table field is
 *   looked up by name, and a member nothing claimed is the one -- and its name
 *   is recovered from the one thing the reader does publish about that buffer:
 *   `ncfg_json_string` returns a pointer into it, and its node says at what
 *   offset. One string anywhere in the object therefore locates the buffer,
 *   and every key in it is at a known offset from there.
 *
 *   **That is a derivation, so it is proved before it is used.** Before any
 *   name is quoted, the same arithmetic is applied to a member the table *did*
 *   claim and the result compared against the name the table looked it up by.
 *   If they do not agree -- a reader that changed how it stores strings, an
 *   object with nothing to anchor on -- nothing is quoted and the refusal
 *   names the member's position instead. The document is refused either way;
 *   what the check protects is the sentence, not the decision.
 */
#include "field.h"

#include "ncfg/document.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ *
 * Reaching a member without pretending a pointer is another pointer
 *
 * A list is a `T *` beside a `size_t` at offsets this table knows, and the
 * engine has to load and store both without knowing `T`. Casting the pair to a
 * `struct { void *; size_t; } *` works everywhere and is still one object
 * being read through the wrong type; `memcpy` says the same thing and is what
 * the standard actually allows. It costs a few instructions on a path that is
 * already walking a JSON tree.
 * ------------------------------------------------------------------------ */

static void *member_at(void *base, size_t offset)
{
	return (void *)((char *)base + offset);
}

static const void *member_at_const(const void *base, size_t offset)
{
	return (const void *)((const char *)base + offset);
}

static void *load_pointer(const void *base, size_t offset)
{
	void *value;

	memcpy(&value, member_at_const(base, offset), sizeof(value));
	return value;
}

static void store_pointer(void *base, size_t offset, void *value)
{
	memcpy(member_at(base, offset), &value, sizeof(value));
}

static size_t load_count(const void *base, size_t offset)
{
	size_t value;

	memcpy(&value, member_at_const(base, offset), sizeof(value));
	return value;
}

static void store_count(void *base, size_t offset, size_t value)
{
	memcpy(member_at(base, offset), &value, sizeof(value));
}

/* ------------------------------------------------------------------------ *
 * Scalars
 * ------------------------------------------------------------------------ */

/*
 * `a` or `an`, for a message that names a type.
 *
 * Here because the messages are read by an operator and "a interface" reads as
 * a typo in the tool rather than as a fault in the document -- which is the
 * one thing a diagnostic must not do. A leading digit takes `an` because the
 * only one in these names is `802.1X`, which is read as "eight".
 */
static const char *article(const char *what)
{
	char first = what && what[0] ? what[0] : 'x';

	return strchr("aeiouAEIOU8", first) ? "an" : "a";
}

char *ncfg_field_string(const ncfg_json_doc_t *doc, uint32_t node, const char *what,
    char *err, size_t err_size)
{
	size_t      length = 0;
	const char *bytes = ncfg_json_string(doc, node, &length);
	char       *copy;

	if (!bytes) {
		ncfg_error_set(err, err_size, "%s is not a string", what);
		return NULL;
	}
	/*
	 * A JSON string may hold a NUL and this reader does not lose it; the
	 * model's strings are NUL-terminated and would. Refused rather than
	 * truncated, because a name silently cut at its first NUL is a link the
	 * document describes and the machine does not have.
	 */
	if (memchr(bytes, '\0', length)) {
		ncfg_error_set(err, err_size, "%s contains a NUL byte", what);
		return NULL;
	}
	copy = malloc(length + 1u);
	if (!copy) {
		ncfg_error_set(err, err_size, "out of memory reading %s", what);
		return NULL;
	}
	memcpy(copy, bytes, length);
	copy[length] = '\0';
	return copy;
}

/*
 * An integer, and whether the text was one at all.
 *
 * `ncfg_json_int` answers a malformed number with the caller's fallback, which
 * cannot be told from a document that really said that. Asked twice with two
 * fallbacks, a disagreement *is* the answer: no integer produces both.
 */
static int read_int(const ncfg_json_doc_t *doc, uint32_t node, int64_t *out)
{
	int64_t low = ncfg_json_int(doc, node, INT64_MIN);
	int64_t high = ncfg_json_int(doc, node, INT64_MAX);

	if (ncfg_json_type(doc, node) != NCFG_JSON_NUMBER || low != high) {
		return 0;
	}
	*out = low;
	return 1;
}

static int read_bounded(const ncfg_json_doc_t *doc, uint32_t node, const char *what,
    int64_t low, int64_t high, int64_t *out, char *err, size_t err_size)
{
	int64_t value = 0;

	if (!read_int(doc, node, &value)) {
		ncfg_error_set(err, err_size, "%s is not a whole number", what);
		return 0;
	}
	if (value < low || value > high) {
		ncfg_error_set(err, err_size, "%s is %lld, and the range is %lld to %lld", what,
		    (long long)value, (long long)low, (long long)high);
		return 0;
	}
	*out = value;
	return 1;
}

static int read_bool(const ncfg_json_doc_t *doc, uint32_t node, const char *what, int *out,
    char *err, size_t err_size)
{
	if (ncfg_json_type(doc, node) != NCFG_JSON_BOOL) {
		ncfg_error_set(err, err_size, "%s is not true or false", what);
		return 0;
	}
	*out = ncfg_json_bool(doc, node, 0);
	return 1;
}

const char *ncfg_field_enum_name(const ncfg_enum_t *set, int value)
{
	if (set->name_of) {
		return set->name_of(value);
	}
	if (value < 0 || (size_t)value >= set->count) {
		return NULL;
	}
	return set->names[value];
}

int ncfg_field_enum(const ncfg_enum_t *set, const ncfg_json_doc_t *doc, uint32_t node,
    int *out, char *err, size_t err_size)
{
	size_t      length = 0;
	const char *bytes = ncfg_json_string(doc, node, &length);
	char        word[64];
	size_t      i;

	if (!bytes) {
		ncfg_error_set(err, err_size, "a %s is a word, and this is not a string", set->what);
		return 0;
	}
	/* Counted rather than terminated, and every word in every set here is far
	 * shorter than this; anything longer cannot be one of them. */
	if (length >= sizeof(word) || memchr(bytes, '\0', length)) {
		ncfg_error_set(err, err_size, "`%.*s` is not a %s", (int)(length > 32u ? 32u : length),
		    bytes, set->what);
		return 0;
	}
	memcpy(word, bytes, length);
	word[length] = '\0';

	if (set->from_name) {
		/* value.h's own reader for the sets it owns, so that no second table
		 * of those spellings exists to drift from the first. */
		return set->from_name(word, out, err, err_size);
	}
	for (i = 0; i < set->count; i++) {
		if (strcmp(set->names[i], word) == 0) {
			*out = (int)i;
			return 1;
		}
	}
	ncfg_error_set(err, err_size, "`%s` is not a %s", word, set->what);
	return 0;
}

uint32_t ncfg_field_only_member(const ncfg_json_doc_t *doc, uint32_t object)
{
	const ncfg_json_node_t *node = ncfg_json_node(doc, object);

	if (!node || node->type != NCFG_JSON_OBJECT || node->child_count != 1u) {
		return NCFG_JSON_NONE;
	}
	return node->first_child;
}

/* ------------------------------------------------------------------------ *
 * Recovering the name of a member nothing claimed. See the file comment.
 * ------------------------------------------------------------------------ */

/*
 * The buffer every string in `doc` lives in, located through one of them.
 *
 * Searched from the object being refused and downwards, which finds one in
 * anything that names something -- a device, an interface, a hook. An object
 * of nothing but numbers below an object of nothing but numbers has none, and
 * then the refusal gives a position instead of a name. The recursion is
 * bounded by the reader's own `NCFG_JSON_MAX_DEPTH`, which is why it is safe
 * to write as recursion at all.
 */
static const char *string_arena(const ncfg_json_doc_t *doc, uint32_t object)
{
	const ncfg_json_node_t *parent = ncfg_json_node(doc, object);
	uint32_t                child;

	if (!parent) {
		return NULL;
	}
	for (child = parent->first_child; child != NCFG_JSON_NONE;) {
		const ncfg_json_node_t *node = ncfg_json_node(doc, child);
		const char             *bytes;

		if (!node) {
			return NULL;
		}
		bytes = ncfg_json_string(doc, child, NULL);
		if (bytes) {
			return bytes - node->value_offset;
		}
		if (node->type == NCFG_JSON_OBJECT || node->type == NCFG_JSON_ARRAY) {
			bytes = string_arena(doc, child);
			if (bytes) {
				return bytes;
			}
		}
		child = node->next_sibling;
	}
	return NULL;
}

/*
 * The key of `member`, or NULL where the derivation could not be proved.
 *
 * `proof` is a member the table did claim and `proof_name` is what it was
 * looked up by; agreeing on that one is what licenses quoting this one.
 */
static const char *member_key(const ncfg_json_doc_t *doc, uint32_t object, uint32_t member,
    uint32_t proof, const char *proof_name, char *out, size_t out_size)
{
	const char             *arena = string_arena(doc, object);
	const ncfg_json_node_t *node;
	const ncfg_json_node_t *witness;
	size_t                  i;

	if (!arena || proof == NCFG_JSON_NONE || !proof_name) {
		return NULL;
	}
	witness = ncfg_json_node(doc, proof);
	node = ncfg_json_node(doc, member);
	if (!witness || !node || !node->key_length || node->key_length >= out_size) {
		return NULL;
	}
	if (strlen(proof_name) != witness->key_length ||
	    memcmp(arena + witness->key_offset, proof_name, witness->key_length) != 0) {
		return NULL;
	}
	memcpy(out, arena + node->key_offset, node->key_length);
	out[node->key_length] = '\0';
	/* Quoted into a diagnostic, so anything that is not an ordinary member
	 * name is not quoted at all. */
	for (i = 0; i < node->key_length; i++) {
		if (out[i] < 0x20 || out[i] >= 0x7f) {
			return NULL;
		}
	}
	return out;
}

/* ------------------------------------------------------------------------ *
 * Defaults
 * ------------------------------------------------------------------------ */

int ncfg_type_init(const ncfg_type_t *type, void *base)
{
	size_t i;

	for (i = 0; i < type->field_count; i++) {
		const ncfg_field_t *field = &type->fields[i];
		void               *slot = member_at(base, field->offset);

		switch (field->kind) {
		case NCFG_F_BOOL:
		case NCFG_F_ENUM: {
			int value = (int)field->fallback;

			memcpy(slot, &value, sizeof(value));
			break;
		}
		case NCFG_F_INT: {
			int64_t value = field->fallback;

			memcpy(slot, &value, sizeof(value));
			break;
		}
		case NCFG_F_STRUCT:
			if (!ncfg_type_init(field->type, slot)) {
				return 0;
			}
			break;
		case NCFG_F_CUSTOM:
			if (field->custom->init && !field->custom->init(slot)) {
				return 0;
			}
			break;
		default:
			/* Zero is the default: an absent option, an empty list, no
			 * string. The caller zeroes before this runs. */
			break;
		}
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Releasing one field
 *
 * Shared between the free walk and the list readers, and that sharing is the
 * point: a list field may already hold a default this reader is about to
 * replace -- a connectivity policy's `ignore` is five allocated strings before
 * the document is looked at -- and a reader that stored over it would leak
 * them. ASan found exactly that, twelve allocations per document read.
 * ------------------------------------------------------------------------ */

static void release_field(const ncfg_field_t *field, void *base)
{
	void *slot = member_at(base, field->offset);

	switch (field->kind) {
	case NCFG_F_STR:
		free(load_pointer(base, field->offset));
		store_pointer(base, field->offset, NULL);
		break;
	case NCFG_F_STRUCT:
		ncfg_type_free(field->type, slot);
		break;
	case NCFG_F_OPT_STRUCT: {
		void *nested = load_pointer(base, field->offset);

		if (nested) {
			ncfg_type_free(field->type, nested);
			free(nested);
			store_pointer(base, field->offset, NULL);
		}
		break;
	}
	case NCFG_F_LIST: {
		char  *items = (char *)load_pointer(base, field->offset);
		size_t count = load_count(base, field->count_offset);
		size_t index;

		for (index = 0; items && index < count; index++) {
			void *element = items + index * field->element_size;

			if (field->custom) {
				if (field->custom->release) {
					field->custom->release(element);
				}
			} else {
				ncfg_type_free(field->type, element);
			}
		}
		free(items);
		store_pointer(base, field->offset, NULL);
		store_count(base, field->count_offset, 0);
		break;
	}
	case NCFG_F_STR_LIST: {
		char **items = (char **)load_pointer(base, field->offset);
		size_t count = load_count(base, field->count_offset);
		size_t index;

		for (index = 0; items && index < count; index++) {
			free(items[index]);
		}
		free(items);
		store_pointer(base, field->offset, NULL);
		store_count(base, field->count_offset, 0);
		break;
	}
	case NCFG_F_INT_LIST:
		free(load_pointer(base, field->offset));
		store_pointer(base, field->offset, NULL);
		store_count(base, field->count_offset, 0);
		break;
	case NCFG_F_CUSTOM:
		if (field->custom->release) {
			field->custom->release(slot);
		}
		break;
	default:
		break;
	}
}

/* ------------------------------------------------------------------------ *
 * Reading
 * ------------------------------------------------------------------------ */

static int read_one(const ncfg_field_t *field, const ncfg_type_t *owner,
    const ncfg_json_doc_t *doc, uint32_t node, void *base, char *err, size_t err_size);

static int read_list(const ncfg_field_t *field, const ncfg_type_t *owner,
    const ncfg_json_doc_t *doc, uint32_t node, void *base, char *err, size_t err_size)
{
	const ncfg_json_node_t *array = ncfg_json_node(doc, node);
	size_t                  count;
	size_t                  index = 0;
	char                   *items;
	uint32_t                child;

	if (!array || array->type != NCFG_JSON_ARRAY) {
		ncfg_error_set(err, err_size, "`%s` of %s is not a list", field->name, owner->what);
		return 0;
	}
	count = array->child_count;
	/* Whatever is already there -- a default this table put in place -- is
	 * released rather than stored over. */
	release_field(field, base);
	if (count == 0) {
		return 1;
	}
	items = calloc(count, field->element_size);
	if (!items) {
		ncfg_error_set(err, err_size, "out of memory reading `%s` of %s", field->name,
		    owner->what);
		return 0;
	}
	store_pointer(base, field->offset, items);
	/* The count is stored before the elements are read, so that a failure
	 * half way leaves a tree the one free walk can still take apart. */
	store_count(base, field->count_offset, count);

	for (child = array->first_child; child != NCFG_JSON_NONE; index++) {
		const ncfg_json_node_t *element = ncfg_json_node(doc, child);
		void                   *slot;

		if (!element || index >= count) {
			ncfg_error_set(err, err_size, "`%s` of %s is a list that changed under the reader",
			    field->name, owner->what);
			return 0;
		}
		slot = items + index * field->element_size;
		if (field->custom) {
			if (field->custom->init && !field->custom->init(slot)) {
				ncfg_error_set(err, err_size, "out of memory reading `%s` of %s",
				    field->name, owner->what);
				return 0;
			}
			if (!field->custom->read(doc, child, slot, err, err_size)) {
				return 0;
			}
		} else {
			if (!ncfg_type_init(field->type, slot)) {
				ncfg_error_set(err, err_size, "out of memory reading `%s` of %s",
				    field->name, owner->what);
				return 0;
			}
			if (!ncfg_type_read(field->type, doc, child, slot, err, err_size)) {
				return 0;
			}
		}
		child = element->next_sibling;
	}
	return 1;
}

static int read_string_list(const ncfg_field_t *field, const ncfg_type_t *owner,
    const ncfg_json_doc_t *doc, uint32_t node, void *base, char *err, size_t err_size)
{
	const ncfg_json_node_t *array = ncfg_json_node(doc, node);
	size_t                  count;
	size_t                  index = 0;
	char                  **items;
	uint32_t                child;

	if (!array || array->type != NCFG_JSON_ARRAY) {
		ncfg_error_set(err, err_size, "`%s` of %s is not a list", field->name, owner->what);
		return 0;
	}
	count = array->child_count;
	/* Whatever is already there -- a default this table put in place -- is
	 * released rather than stored over. */
	release_field(field, base);
	if (count == 0) {
		return 1;
	}
	items = calloc(count, sizeof(*items));
	if (!items) {
		ncfg_error_set(err, err_size, "out of memory reading `%s` of %s", field->name,
		    owner->what);
		return 0;
	}
	store_pointer(base, field->offset, items);
	store_count(base, field->count_offset, count);

	for (child = array->first_child; child != NCFG_JSON_NONE; index++) {
		const ncfg_json_node_t *element = ncfg_json_node(doc, child);
		char                    what[128];

		if (!element || index >= count) {
			ncfg_error_set(err, err_size, "`%s` of %s is a list that changed under the reader",
			    field->name, owner->what);
			return 0;
		}
		ncfg_error_set(what, sizeof(what), "an entry of `%s` of %s", field->name, owner->what);
		items[index] = ncfg_field_string(doc, child, what, err, err_size);
		if (!items[index]) {
			return 0;
		}
		child = element->next_sibling;
	}
	return 1;
}

static int read_int_list(const ncfg_field_t *field, const ncfg_type_t *owner,
    const ncfg_json_doc_t *doc, uint32_t node, void *base, char *err, size_t err_size)
{
	const ncfg_json_node_t *array = ncfg_json_node(doc, node);
	size_t                  count;
	size_t                  index = 0;
	int64_t                *items;
	uint32_t                child;

	if (!array || array->type != NCFG_JSON_ARRAY) {
		ncfg_error_set(err, err_size, "`%s` of %s is not a list", field->name, owner->what);
		return 0;
	}
	count = array->child_count;
	/* Whatever is already there -- a default this table put in place -- is
	 * released rather than stored over. */
	release_field(field, base);
	if (count == 0) {
		return 1;
	}
	items = calloc(count, sizeof(*items));
	if (!items) {
		ncfg_error_set(err, err_size, "out of memory reading `%s` of %s", field->name,
		    owner->what);
		return 0;
	}
	store_pointer(base, field->offset, items);
	store_count(base, field->count_offset, count);

	for (child = array->first_child; child != NCFG_JSON_NONE; index++) {
		const ncfg_json_node_t *element = ncfg_json_node(doc, child);
		char                    what[128];

		if (!element || index >= count) {
			ncfg_error_set(err, err_size, "`%s` of %s is a list that changed under the reader",
			    field->name, owner->what);
			return 0;
		}
		ncfg_error_set(what, sizeof(what), "an entry of `%s` of %s", field->name, owner->what);
		if (!read_bounded(doc, child, what, field->low, field->high, &items[index], err,
		    err_size)) {
			return 0;
		}
		child = element->next_sibling;
	}
	return 1;
}

static int read_one(const ncfg_field_t *field, const ncfg_type_t *owner,
    const ncfg_json_doc_t *doc, uint32_t node, void *base, char *err, size_t err_size)
{
	void *slot = member_at(base, field->offset);
	char  what[160];

	ncfg_error_set(what, sizeof(what), "`%s` of %s", field->name, owner->what);

	switch (field->kind) {
	case NCFG_F_BOOL: {
		int value = 0;

		if (!read_bool(doc, node, what, &value, err, err_size)) {
			return 0;
		}
		memcpy(slot, &value, sizeof(value));
		return 1;
	}
	case NCFG_F_OPT_BOOL: {
		ncfg_optbool_t value = { 1, 0 };

		if (!read_bool(doc, node, what, &value.value, err, err_size)) {
			return 0;
		}
		memcpy(slot, &value, sizeof(value));
		return 1;
	}
	case NCFG_F_INT: {
		int64_t value = 0;

		if (!read_bounded(doc, node, what, field->low, field->high, &value, err, err_size)) {
			return 0;
		}
		memcpy(slot, &value, sizeof(value));
		return 1;
	}
	case NCFG_F_OPT_INT: {
		ncfg_optint_t value = { 1, 0 };

		if (!read_bounded(doc, node, what, field->low, field->high, &value.value, err,
		    err_size)) {
			return 0;
		}
		memcpy(slot, &value, sizeof(value));
		return 1;
	}
	case NCFG_F_STR: {
		char *value = ncfg_field_string(doc, node, what, err, err_size);

		if (!value) {
			return 0;
		}
		free(load_pointer(base, field->offset));
		store_pointer(base, field->offset, value);
		return 1;
	}
	case NCFG_F_ENUM: {
		int value = 0;

		if (!ncfg_field_enum(field->choices, doc, node, &value, err, err_size)) {
			return 0;
		}
		memcpy(slot, &value, sizeof(value));
		return 1;
	}
	case NCFG_F_OPT_ENUM: {
		ncfg_optint_t value = { 1, 0 };
		int           word = 0;

		if (!ncfg_field_enum(field->choices, doc, node, &word, err, err_size)) {
			return 0;
		}
		value.value = word;
		memcpy(slot, &value, sizeof(value));
		return 1;
	}
	case NCFG_F_STRUCT:
		return ncfg_type_read(field->type, doc, node, slot, err, err_size);
	case NCFG_F_OPT_STRUCT: {
		void *nested = load_pointer(base, field->offset);

		if (!nested) {
			nested = calloc(1, field->element_size);
			if (!nested) {
				ncfg_error_set(err, err_size, "out of memory reading %s", what);
				return 0;
			}
			store_pointer(base, field->offset, nested);
			if (!ncfg_type_init(field->type, nested)) {
				ncfg_error_set(err, err_size, "out of memory reading %s", what);
				return 0;
			}
		}
		return ncfg_type_read(field->type, doc, node, nested, err, err_size);
	}
	case NCFG_F_LIST:
		return read_list(field, owner, doc, node, base, err, err_size);
	case NCFG_F_STR_LIST:
		return read_string_list(field, owner, doc, node, base, err, err_size);
	case NCFG_F_INT_LIST:
		return read_int_list(field, owner, doc, node, base, err, err_size);
	case NCFG_F_CUSTOM:
		return field->custom->read(doc, node, slot, err, err_size);
	default:
		ncfg_error_set(err, err_size, "%s has a kind this build does not handle", what);
		return 0;
	}
}

/*
 * The member nothing claimed, named where the name can be proved.
 *
 * Always a refusal. What varies is how much the sentence can say, and the file
 * comment has why it is allowed to say the name at all.
 */
static void refuse_stray_member(const ncfg_type_t *type, const ncfg_json_doc_t *doc,
    uint32_t object, const uint32_t *claimed, size_t claimed_count, uint32_t proof,
    const char *proof_name, char *err, size_t err_size)
{
	const ncfg_json_node_t *parent = ncfg_json_node(doc, object);
	uint32_t                child;
	size_t                  ordinal = 0;

	if (!parent) {
		ncfg_error_set(err, err_size, "%s %s could not be read", article(type->what), type->what);
		return;
	}
	for (child = parent->first_child; child != NCFG_JSON_NONE; ordinal++) {
		const ncfg_json_node_t *node = ncfg_json_node(doc, child);
		size_t                  i;
		int                     taken = 0;
		char                    name[128];
		const char             *key;

		if (!node) {
			break;
		}
		for (i = 0; i < claimed_count; i++) {
			if (claimed[i] == child) {
				taken = 1;
				break;
			}
		}
		if (taken) {
			child = node->next_sibling;
			continue;
		}

		key = member_key(doc, object, child, proof, proof_name, name, sizeof(name));
		if (!key) {
			ncfg_error_set(err, err_size,
			    "member %zu of %s %s is one this build does not know, and a document is "
			    "refused rather than half read",
			    ordinal + 1u, article(type->what), type->what);
			return;
		}
		for (i = 0; i < type->field_count; i++) {
			if (strcmp(type->fields[i].name, key) == 0) {
				/* Claimed by nothing and yet a name the table has: the
				 * object states it twice, and this reader does no
				 * duplicate-key merging. */
				ncfg_error_set(err, err_size, "%s %s states `%s` more than once",
				    article(type->what), type->what, key);
				return;
			}
		}
		if (type->tag && strcmp(type->tag, key) == 0) {
			ncfg_error_set(err, err_size, "%s %s states `%s` more than once",
			    article(type->what), type->what, key);
			return;
		}
		ncfg_error_set(err, err_size,
		    "%s %s carries `%s`, which this build does not know; a document is refused "
		    "rather than half read",
		    article(type->what), type->what, key);
		return;
	}
	ncfg_error_set(err, err_size, "%s %s carries a member this build does not know",
	    article(type->what), type->what);
}

int ncfg_type_read(const ncfg_type_t *type, const ncfg_json_doc_t *doc, uint32_t node,
    void *base, char *err, size_t err_size)
{
	/* One slot per field plus the tag; every table here is far short of it,
	 * and a table that were not is refused rather than silently unchecked. */
	uint32_t claimed[80];
	size_t   claimed_count = 0;
	uint32_t proof = NCFG_JSON_NONE;
	const char *proof_name = NULL;
	size_t   i;
	uint32_t members;

	if (ncfg_json_type(doc, node) != NCFG_JSON_OBJECT) {
		ncfg_error_set(err, err_size, "%s %s is an object, and this is not one", article(type->what), type->what);
		return 0;
	}
	if (type->field_count + 1u > sizeof(claimed) / sizeof(claimed[0])) {
		ncfg_error_set(err, err_size, "%s %s has more members than this reader checks",
		    article(type->what), type->what);
		return 0;
	}

	if (type->tag) {
		uint32_t tag = ncfg_json_member(doc, node, type->tag);

		if (tag != NCFG_JSON_NONE) {
			claimed[claimed_count++] = tag;
			proof = tag;
			proof_name = type->tag;
		}
	}

	for (i = 0; i < type->field_count; i++) {
		const ncfg_field_t *field = &type->fields[i];
		uint32_t            found = ncfg_json_member(doc, node, field->name);

		if (found == NCFG_JSON_NONE) {
			if (field->flags & NCFG_FF_REQUIRED) {
				ncfg_error_set(err, err_size, "%s %s has no `%s`, and one is required",
				    article(type->what), type->what, field->name);
				return 0;
			}
			continue;
		}
		claimed[claimed_count++] = found;
		if (proof == NCFG_JSON_NONE) {
			proof = found;
			proof_name = field->name;
		}
		if (!read_one(field, type, doc, found, base, err, err_size)) {
			return 0;
		}
	}

	/*
	 * Every member accounted for, or the document is refused.
	 *
	 * `project.md` section 2: a consumer acting on something it only half read
	 * is worse than one that refuses. A newer netcfgd writes a member an older
	 * one has never heard of, and the older one silently dropping the one that
	 * says "this interface is guarded" would take down the link the operator
	 * said not to touch.
	 */
	members = ncfg_json_count(doc, node);
	if ((size_t)members != claimed_count) {
		refuse_stray_member(type, doc, node, claimed, claimed_count, proof, proof_name, err,
		    err_size);
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Writing
 * ------------------------------------------------------------------------ */

static int omit(const ncfg_field_t *field, const void *base)
{
	const void *slot = member_at_const(base, field->offset);

	/* A field whose Rust counterpart has no `skip_serializing_if` is written
	 * as `null` when it is absent, so it is never omitted. See
	 * NCFG_FF_NULL_ABSENT. */
	if (field->flags & NCFG_FF_NULL_ABSENT) {
		return 0;
	}
	switch (field->kind) {
	case NCFG_F_BOOL: {
		int value;

		memcpy(&value, slot, sizeof(value));
		if ((field->flags & NCFG_FF_OMIT_TRUE) && value) {
			return 1;
		}
		return (field->flags & NCFG_FF_OMIT_FALSE) && !value;
	}
	case NCFG_F_INT: {
		int64_t value;

		memcpy(&value, slot, sizeof(value));
		return (field->flags & NCFG_FF_OMIT_ZERO) && value == 0;
	}
	case NCFG_F_OPT_BOOL: {
		ncfg_optbool_t value;

		memcpy(&value, slot, sizeof(value));
		return !value.has;
	}
	case NCFG_F_OPT_INT:
	case NCFG_F_OPT_ENUM: {
		ncfg_optint_t value;

		memcpy(&value, slot, sizeof(value));
		return !value.has;
	}
	case NCFG_F_STR:
	case NCFG_F_OPT_STRUCT:
		return load_pointer(base, field->offset) == NULL;
	case NCFG_F_LIST:
	case NCFG_F_STR_LIST:
	case NCFG_F_INT_LIST:
		return (field->flags & NCFG_FF_OMIT_EMPTY) &&
		    load_count(base, field->count_offset) == 0;
	case NCFG_F_CUSTOM:
		return field->custom->omit ? field->custom->omit(slot) : 0;
	default:
		return 0;
	}
}

static void write_one(const ncfg_field_t *field, ncfg_json_writer_t *writer, const void *base)
{
	const void *slot = member_at_const(base, field->offset);

	switch (field->kind) {
	case NCFG_F_BOOL: {
		int value;

		memcpy(&value, slot, sizeof(value));
		ncfg_json_write_bool(writer, value);
		break;
	}
	case NCFG_F_OPT_BOOL: {
		ncfg_optbool_t value;

		memcpy(&value, slot, sizeof(value));
		ncfg_json_write_bool(writer, value.value);
		break;
	}
	case NCFG_F_INT: {
		int64_t value;

		memcpy(&value, slot, sizeof(value));
		ncfg_json_write_int(writer, value);
		break;
	}
	case NCFG_F_OPT_INT: {
		ncfg_optint_t value;

		memcpy(&value, slot, sizeof(value));
		/* Absent reaches here only for a field that is written rather than
		 * omitted, which is what `null` spells. */
		if (value.has) {
			ncfg_json_write_int(writer, value.value);
		} else {
			ncfg_json_write_null(writer);
		}
		break;
	}
	case NCFG_F_STR:
		ncfg_json_write_string(writer, (const char *)load_pointer(base, field->offset));
		break;
	case NCFG_F_ENUM:
	case NCFG_F_OPT_ENUM: {
		int         value;
		const char *word;

		if (field->kind == NCFG_F_ENUM) {
			memcpy(&value, slot, sizeof(value));
		} else {
			ncfg_optint_t option;

			memcpy(&option, slot, sizeof(option));
			value = (int)option.value;
		}
		word = ncfg_field_enum_name(field->choices, value);
		/*
		 * A value outside its set writes nothing, and the writer's own rule
		 * then makes the document unfinishable: a name with no value is a
		 * misuse it reports. value.h's reason applies here too -- a plausible
		 * word for a value that is not one is worse than no word.
		 */
		if (word) {
			ncfg_json_write_string(writer, word);
		}
		break;
	}
	case NCFG_F_STRUCT:
	case NCFG_F_OPT_STRUCT: {
		const void *nested = field->kind == NCFG_F_STRUCT ? slot :
		    (const void *)load_pointer(base, field->offset);

		ncfg_json_write_object_begin(writer);
		ncfg_type_write(field->type, writer, nested);
		ncfg_json_write_object_end(writer);
		break;
	}
	case NCFG_F_LIST: {
		const char *items = (const char *)load_pointer(base, field->offset);
		size_t      count = load_count(base, field->count_offset);
		size_t      i;

		ncfg_json_write_array_begin(writer);
		for (i = 0; i < count; i++) {
			const void *element = items + i * field->element_size;

			if (field->custom) {
				field->custom->write(writer, element);
			} else {
				ncfg_json_write_object_begin(writer);
				ncfg_type_write(field->type, writer, element);
				ncfg_json_write_object_end(writer);
			}
		}
		ncfg_json_write_array_end(writer);
		break;
	}
	case NCFG_F_STR_LIST: {
		char *const *items = (char *const *)load_pointer(base, field->offset);
		size_t       count = load_count(base, field->count_offset);
		size_t       i;

		ncfg_json_write_array_begin(writer);
		for (i = 0; i < count; i++) {
			ncfg_json_write_string(writer, items[i]);
		}
		ncfg_json_write_array_end(writer);
		break;
	}
	case NCFG_F_INT_LIST: {
		const int64_t *items = (const int64_t *)load_pointer(base, field->offset);
		size_t         count = load_count(base, field->count_offset);
		size_t         i;

		ncfg_json_write_array_begin(writer);
		for (i = 0; i < count; i++) {
			ncfg_json_write_int(writer, items[i]);
		}
		ncfg_json_write_array_end(writer);
		break;
	}
	case NCFG_F_CUSTOM:
		field->custom->write(writer, slot);
		break;
	default:
		break;
	}
}

void ncfg_type_write(const ncfg_type_t *type, ncfg_json_writer_t *writer, const void *base)
{
	size_t i;

	for (i = 0; i < type->field_count; i++) {
		const ncfg_field_t *field = &type->fields[i];

		if (omit(field, base)) {
			continue;
		}
		ncfg_json_write_key(writer, field->name);
		write_one(field, writer, base);
	}
}

/* ------------------------------------------------------------------------ *
 * Freeing
 * ------------------------------------------------------------------------ */

void ncfg_type_free(const ncfg_type_t *type, void *base)
{
	size_t i;

	for (i = 0; i < type->field_count; i++) {
		release_field(&type->fields[i], base);
	}
}
