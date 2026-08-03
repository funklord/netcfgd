/*
 * ncfg_json.h -- a small JSON reader for netcfgd's control socket.
 *
 * WHY THIS EXISTS AT ALL
 *   netcfgd speaks newline-delimited JSON on its control socket, pinned by
 *   docs/schema/socket.json, and this layer is below the widgets (gui/
 *   project.md sec 3) so it is C. That leaves the choice between a dependency
 *   and a few hundred lines, and this is the few hundred lines: the family's
 *   other trees are dependency-light by policy, and a JSON reader that only
 *   ever has to read what one known daemon writes is a smaller problem than a
 *   general one.
 *
 *   It is deliberately NOT general. No comments, no trailing commas, no NaN,
 *   no duplicate-key merging, one value per input. If netcfgd would not emit
 *   it, this refuses it -- and refusing is the whole point of a reader whose
 *   input is a contract rather than a file somebody wrote by hand.
 *
 * SHAPE
 *   A document is parsed once into a flat array of nodes, and nothing is
 *   allocated per node. Two allocations for a whole response: the node array,
 *   and a copy of the text that strings point into. Lookup is by walking
 *   sibling links, which for objects of a handful of members is faster than
 *   anything that would need a hash and is a great deal less code.
 *
 *   Strings are unescaped in place. That is safe because an unescaped string
 *   is never longer than its escaped form -- `\n` is two bytes in and one out,
 *   `\uXXXX` is six in and at most three out, a surrogate pair twelve in and
 *   four out.
 *
 * WHAT IT REFUSES, AND WHY EACH ONE
 *   - depth beyond NCFG_JSON_MAX_DEPTH: parsing is iterative precisely so a
 *     deep document cannot exhaust the C stack, and the cap is what makes the
 *     iterative container stack a fixed size.
 *   - a lone surrogate, an invalid escape, a control character in a string,
 *     a leading zero, a bare `.5`: all things netcfgd will never send, so
 *     accepting them would only widen what this has to be correct about.
 *   - anything after the value: the framing is one JSON object per line
 *     (netcfgd-proto's codec.rs refuses to emit a message containing a
 *     newline), so a second value on one line means the framing is already
 *     wrong and reading on would compound it.
 */
#ifndef NCFG_JSON_H
#define NCFG_JSON_H

#include <stddef.h>
#include <stdint.h>

/* Deep enough for anything the schema witness contains, with room to spare:
 * the deepest response today is an explanation's facts inside a response
 * object, which is four. */
#define NCFG_JSON_MAX_DEPTH 32

typedef enum {
	NCFG_JSON_NULL = 0,
	NCFG_JSON_BOOL,
	NCFG_JSON_NUMBER,
	NCFG_JSON_STRING,
	NCFG_JSON_ARRAY,
	NCFG_JSON_OBJECT,
} ncfg_json_type_t;

/*
 * One value.
 *
 * Indices rather than pointers, so the node array can be reallocated while
 * parsing without anything to fix up afterwards. NCFG_JSON_NONE is the
 * absent index, and 0 is the root, which is why absent cannot be 0.
 */
#define NCFG_JSON_NONE ((uint32_t)0xffffffffu)

typedef struct {
	ncfg_json_type_t type;
	/* Members of an object carry the key they were reached by; elements of an
	 * array and the root do not. Both point into the document's text. */
	uint32_t key_offset;
	uint32_t key_length;
	/* Strings: the unescaped bytes. Numbers: the text as it arrived, converted
	 * on demand -- a status carries integers and this avoids a float round
	 * trip that could lose one. Booleans: value in `number_or_bool`. */
	uint32_t value_offset;
	uint32_t value_length;
	int      bool_value;
	/* Containers. */
	uint32_t first_child;
	uint32_t child_count;
	/* Every node but the last of its parent. */
	uint32_t next_sibling;
} ncfg_json_node_t;

typedef struct ncfg_json_doc ncfg_json_doc_t;

/*
 * Parse one line. `text` need not be NUL-terminated and is copied.
 *
 * Returns NULL on any refusal, with `err` (if given) holding a sentence that
 * names what was wrong and where -- the byte offset, because a response that
 * fails to parse is a bug in one of two programs and the offset is what says
 * which.
 */
ncfg_json_doc_t *ncfg_json_parse(const char *text, size_t length, char *err, size_t err_size);
void ncfg_json_free(ncfg_json_doc_t *doc);

/* The root value, or NCFG_JSON_NONE for a document that failed to parse --
 * which cannot happen, since parse returns NULL for that. */
uint32_t ncfg_json_root(const ncfg_json_doc_t *doc);
const ncfg_json_node_t *ncfg_json_node(const ncfg_json_doc_t *doc, uint32_t index);
ncfg_json_type_t ncfg_json_type(const ncfg_json_doc_t *doc, uint32_t index);

/*
 * `object.name`, or NCFG_JSON_NONE.
 *
 * Absent and null are deliberately different answers: netcfgd omits a field it
 * has nothing to say about (serde's skip_serializing_if) and writes null where
 * the answer is "known to be nothing", and a client that conflated them would
 * report "no MAC address" for a device it had not asked about.
 */
uint32_t ncfg_json_member(const ncfg_json_doc_t *doc, uint32_t object, const char *name);

/* `array[index]`, or NCFG_JSON_NONE. */
uint32_t ncfg_json_at(const ncfg_json_doc_t *doc, uint32_t array, uint32_t index);

/* How many members or elements. Zero for anything else. */
uint32_t ncfg_json_count(const ncfg_json_doc_t *doc, uint32_t index);

/*
 * The bytes of a string, not NUL-terminated -- a string in JSON may contain a
 * NUL and this reader does not lose it. `length_out` may be NULL.
 * Returns NULL for anything that is not a string.
 */
const char *ncfg_json_string(const ncfg_json_doc_t *doc, uint32_t index, size_t *length_out);

/*
 * A string compared against a C string. The comparison every caller wants and
 * nobody should write twice, since the bytes are counted rather than
 * terminated.
 */
int ncfg_json_string_equals(const ncfg_json_doc_t *doc, uint32_t index, const char *other);

/*
 * Numbers and booleans, with a default for the absent case.
 *
 * The default is the caller's because the right one differs: a missing `mtu`
 * is not 0, a missing `up` is not false, and a reader that picked for the
 * caller would make one of those wrong somewhere.
 */
int64_t ncfg_json_int(const ncfg_json_doc_t *doc, uint32_t index, int64_t fallback);
int ncfg_json_bool(const ncfg_json_doc_t *doc, uint32_t index, int fallback);

/*
 * Copy a string member into a caller's buffer, NUL-terminated and truncated
 * to fit. Returns the number of bytes written, not counting the terminator.
 *
 * Here rather than in every caller because "get a name out of an object into a
 * fixed buffer" is what a UI does with almost every field, and doing it by
 * hand four hundred times is where an off-by-one lives.
 */
size_t ncfg_json_copy_member(const ncfg_json_doc_t *doc, uint32_t object, const char *name,
			     char *out, size_t out_size);

#endif /* NCFG_JSON_H */
