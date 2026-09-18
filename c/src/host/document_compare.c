/*
 * document_compare.c -- whether two documents describe the same machine.
 *
 * WHY THIS EXISTS AT ALL
 *   Two operations in this module are proofs: the fold compiles the
 *   configuration before and after and requires the two to agree, and the save
 *   requires the profile it wrote to reproduce what the machine was running.
 *   Both need document equality, which the Rust had from
 *   `#[derive(PartialEq)]`.
 *
 * WHY IT GOES THROUGH THE DOCUMENT'S OWN WRITER
 *   The alternative is a comparison written field by field, and `field.h`
 *   records what that costs in this exact place: `Document`'s equality was
 *   written by hand, `bluetooth` was missed for as long as the field existed,
 *   and `ncfg profile save` accepted a snapshot that did not reproduce the
 *   machine. A list that has to agree with a struct and is maintained by hand
 *   does not stay agreeing. The writer is driven by the field tables, so a
 *   member added to the model is in this comparison the day it is added.
 *
 *   **Written and compared, never written and read back.** A round trip
 *   through `ncfg_document_read` would be a second, stronger claim -- that the
 *   reader accepts everything the writer emits -- and this comparison does not
 *   need it. Nothing here should fail because of something neither document
 *   says.
 *
 * WHAT IS LEFT OUT OF THE COMPARISON, AND WHY
 *   `generated_by` is provenance, and `document.h` says in as many words that
 *   it is excluded from equality: two documents differing only there describe
 *   the same desired state and must plan identically.
 *
 *   `globals.profile` is stated by the caller rather than taken from either
 *   document, because every comparison here is "the same but for the
 *   selection" and the selection is the one thing being changed. Comparing the
 *   whole document would fail every time and prove nothing; comparing nothing
 *   would prove nothing either.
 *
 * ORDER
 *   Two documents are compared in the order their members were written, which
 *   is exact because one field table drives both. Lists are compared in order
 *   too, which is what makes canonicalisation load-bearing: `ncfg_compile`
 *   canonicalises before it validates, so documents from the compiler are
 *   sorted the same way. A caller comparing a document from somewhere else
 *   owes it the same treatment, exactly as the Rust's `PartialEq` on a `Vec`
 *   does.
 */
#include "config_internal.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *ncfg_config_document_json(const ncfg_document_t *document, size_t *length_out, char *err,
    size_t err_size)
{
	ncfg_buf_t buf;
	char      *text;

	if (length_out) {
		*length_out = 0;
	}
	if (!document) {
		ncfg_error_set(err, err_size, "there is no document to write out");
		return NULL;
	}
	ncfg_buf_init(&buf, 4u * 1024u * 1024u);
	if (!ncfg_document_write(document, &buf, err, err_size)) {
		ncfg_buf_free(&buf);
		return NULL;
	}
	text = ncfg_buf_take(&buf, length_out);
	ncfg_buf_free(&buf);
	if (!text) {
		ncfg_error_set(err, err_size, "out of memory writing a document out");
	}
	return text;
}

int ncfg_config_json_same(const ncfg_json_doc_t *a, uint32_t x, const ncfg_json_doc_t *b,
    uint32_t y)
{
	const ncfg_json_node_t *at;
	const ncfg_json_node_t *other;
	uint32_t                left;
	uint32_t                right;

	if (x == NCFG_JSON_NONE || y == NCFG_JSON_NONE) {
		return x == y;
	}
	if (ncfg_json_type(a, x) != ncfg_json_type(b, y)) {
		return 0;
	}
	switch (ncfg_json_type(a, x)) {
	case NCFG_JSON_NULL:
		return 1;
	case NCFG_JSON_BOOL:
		return ncfg_json_bool(a, x, 0) == ncfg_json_bool(b, y, 1);
	case NCFG_JSON_NUMBER:
		/* Integers, because this model has no floats: the language has none
		 * and the writer never emits one. */
		return ncfg_json_int(a, x, 0) == ncfg_json_int(b, y, 1);
	case NCFG_JSON_STRING: {
		size_t      x_length = 0;
		size_t      y_length = 0;
		const char *x_text = ncfg_json_string(a, x, &x_length);
		const char *y_text = ncfg_json_string(b, y, &y_length);

		return x_length == y_length && x_text && y_text &&
		    memcmp(x_text, y_text, x_length) == 0;
	}
	case NCFG_JSON_ARRAY:
	case NCFG_JSON_OBJECT:
		if (ncfg_json_count(a, x) != ncfg_json_count(b, y)) {
			return 0;
		}
		at = ncfg_json_node(a, x);
		other = ncfg_json_node(b, y);
		left = at->first_child;
		right = other->first_child;
		while (left != NCFG_JSON_NONE && right != NCFG_JSON_NONE) {
			size_t      left_key = 0;
			size_t      right_key = 0;
			const char *left_name = ncfg_json_key(a, left, &left_key);
			const char *right_name = ncfg_json_key(b, right, &right_key);

			if (left_key != right_key ||
			    (left_key && memcmp(left_name, right_name, left_key) != 0)) {
				return 0;
			}
			if (!ncfg_config_json_same(a, left, b, right)) {
				return 0;
			}
			left = ncfg_json_node(a, left)->next_sibling;
			right = ncfg_json_node(b, right)->next_sibling;
		}
		return left == NCFG_JSON_NONE && right == NCFG_JSON_NONE;
	default:
		return 0;
	}
}

/* Whether `globals.profile` on the `got` side is the selection the caller
 * expects. An absent member and a null one both mean no profile: the writer
 * omits a string it has nothing to say about, and a reader of this comparison
 * should not have to know which. */
static int selection_is(const ncfg_json_doc_t *doc, uint32_t globals, const char *profile)
{
	uint32_t member = ncfg_json_member(doc, globals, "profile");

	if (member == NCFG_JSON_NONE || ncfg_json_type(doc, member) == NCFG_JSON_NULL) {
		return profile == NULL;
	}
	return profile != NULL && ncfg_json_string_equals(doc, member, profile);
}

/* How many members, not counting the selection, which is excused on both
 * sides because it is the thing being changed. */
static uint32_t members_but_profile(const ncfg_json_doc_t *doc, uint32_t object)
{
	uint32_t count = ncfg_json_count(doc, object);

	return ncfg_json_member(doc, object, "profile") == NCFG_JSON_NONE ? count : count - 1u;
}

/* The two `globals` blocks, but for the selection. */
static int globals_agree(const ncfg_json_doc_t *want, uint32_t mine, const ncfg_json_doc_t *got,
    uint32_t theirs, const char *profile)
{
	const ncfg_json_node_t *at;
	uint32_t                child;

	if (mine == NCFG_JSON_NONE || theirs == NCFG_JSON_NONE) {
		return mine == theirs;
	}
	if (!selection_is(got, theirs, profile)) {
		return 0;
	}
	at = ncfg_json_node(want, mine);
	for (child = at->first_child; child != NCFG_JSON_NONE;
	    child = ncfg_json_node(want, child)->next_sibling) {
		char        key[64];
		size_t      length = 0;
		const char *name = ncfg_json_key(want, child, &length);

		if (!name || length + 1u > sizeof(key)) {
			return 0;
		}
		memcpy(key, name, length);
		key[length] = '\0';
		if (strcmp(key, "profile") == 0) {
			continue;
		}
		if (!ncfg_config_json_same(want, child, got, ncfg_json_member(got, theirs, key))) {
			return 0;
		}
	}
	/* A member the other side has and this one does not is a difference too,
	 * and counting is how that is noticed without walking twice. */
	return members_but_profile(want, mine) == members_but_profile(got, theirs);
}

/*
 * Which part of the document the other one failed to reproduce.
 *
 * **Named rather than left to a bisect.** The refusal this feeds is the
 * round-trip proof doing its job, and it used to say only that the two
 * differed -- so finding out which field the renderer had dropped meant
 * halving a configuration by hand until it saved. Measured once, on a
 * `proto = "wpa3"` network whose generation was not being written: six trials
 * to find it.
 *
 * A section and a name, not a field diff. The documents are large and the
 * answer wanted is "where do I look", which the block that differs gives while
 * a full comparison would bury it.
 */
static void name_the_difference(const ncfg_json_doc_t *want, const ncfg_json_doc_t *got,
    const char *profile, char *out, size_t out_size)
{
	static const struct {
		const char *member;
		const char *key;
		const char *shape;
	} lists[] = {
		{ "interfaces", "name", " `interface %s` is what differs." },
		{ "devices", "name", " `device %s` is what differs." },
		{ "networks", "id", " `network \"%s\"` is what differs." },
		{ "bluetooth", "id", " `bluetooth \"%s\"` is what differs." }
	};
	size_t which;

	if (!out || out_size == 0u) {
		return;
	}
	/* A block that is in one document and not the other, or a list this does
	 * not walk. Saying so beats naming a block that is in fact identical. */
	(void)snprintf(out, out_size, " The two differ in a block this cannot name.");
	if (!want || !got) {
		return;
	}
	if (!globals_agree(want, ncfg_json_member(want, ncfg_json_root(want), "globals"), got,
	    ncfg_json_member(got, ncfg_json_root(got), "globals"), profile)) {
		(void)snprintf(out, out_size, " The `global` block is what differs.");
		return;
	}
	for (which = 0; which < sizeof(lists) / sizeof(lists[0]); which++) {
		uint32_t mine = ncfg_json_member(want, ncfg_json_root(want), lists[which].member);
		uint32_t theirs = ncfg_json_member(got, ncfg_json_root(got), lists[which].member);
		uint32_t element;

		if (mine == NCFG_JSON_NONE) {
			continue;
		}
		for (element = ncfg_json_node(want, mine)->first_child; element != NCFG_JSON_NONE;
		    element = ncfg_json_node(want, element)->next_sibling) {
			uint32_t    named = ncfg_json_member(want, element, lists[which].key);
			size_t      length = 0;
			const char *name = ncfg_json_string(want, named, &length);
			char        spelled[128];
			uint32_t    other;
			int         found = 0;

			if (!name || length + 1u > sizeof(spelled)) {
				continue;
			}
			memcpy(spelled, name, length);
			spelled[length] = '\0';
			for (other = theirs == NCFG_JSON_NONE ? NCFG_JSON_NONE
			    : ncfg_json_node(got, theirs)->first_child;
			    other != NCFG_JSON_NONE;
			    other = ncfg_json_node(got, other)->next_sibling) {
				if (!ncfg_json_string_equals(got,
				    ncfg_json_member(got, other, lists[which].key), spelled)) {
					continue;
				}
				found = ncfg_config_json_same(want, element, got, other);
				break;
			}
			if (!found) {
				(void)snprintf(out, out_size, lists[which].shape, spelled);
				return;
			}
		}
	}
}

int ncfg_config_documents_agree(const ncfg_document_t *want, const char *profile,
    const ncfg_document_t *got, char *where, size_t where_size)
{
	ncfg_json_doc_t        *mine = NULL;
	ncfg_json_doc_t        *theirs = NULL;
	const ncfg_json_node_t *root;
	char                   *my_text;
	char                   *their_text = NULL;
	char                    quiet[NCFG_ERROR_MAX];
	size_t                  my_length = 0;
	size_t                  their_length = 0;
	uint32_t                child;
	int                     agree = 0;

	if (where && where_size) {
		(void)snprintf(where, where_size, " The two differ in a block this cannot name.");
	}
	if (!want || !got) {
		return 0;
	}
	my_text = ncfg_config_document_json(want, &my_length, quiet, sizeof(quiet));
	if (my_text) {
		their_text = ncfg_config_document_json(got, &their_length, quiet, sizeof(quiet));
	}
	if (my_text && their_text) {
		mine = ncfg_json_parse(my_text, my_length, quiet, sizeof(quiet));
		theirs = ncfg_json_parse(their_text, their_length, quiet, sizeof(quiet));
	}
	free(my_text);
	free(their_text);
	if (!mine || !theirs) {
		ncfg_json_free(mine);
		ncfg_json_free(theirs);
		return 0;
	}

	agree = ncfg_json_count(mine, ncfg_json_root(mine)) ==
	    ncfg_json_count(theirs, ncfg_json_root(theirs));
	root = ncfg_json_node(mine, ncfg_json_root(mine));
	for (child = root->first_child; agree && child != NCFG_JSON_NONE;
	    child = ncfg_json_node(mine, child)->next_sibling) {
		char        key[64];
		size_t      length = 0;
		const char *name = ncfg_json_key(mine, child, &length);
		uint32_t    other;

		if (!name || length + 1u > sizeof(key)) {
			agree = 0;
			break;
		}
		memcpy(key, name, length);
		key[length] = '\0';
		if (strcmp(key, "generated_by") == 0) {
			continue;
		}
		other = ncfg_json_member(theirs, ncfg_json_root(theirs), key);
		if (strcmp(key, "globals") == 0) {
			agree = globals_agree(mine, child, theirs, other, profile);
			continue;
		}
		agree = ncfg_config_json_same(mine, child, theirs, other);
	}
	if (!agree) {
		name_the_difference(mine, theirs, profile, where, where_size);
	}
	ncfg_json_free(mine);
	ncfg_json_free(theirs);
	return agree;
}
