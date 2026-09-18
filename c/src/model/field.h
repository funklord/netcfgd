/*
 * field.h -- the table every struct in the document is read and written by.
 *
 * WHY A TABLE AND NOT FIFTY PAIRS OF FUNCTIONS
 *   The desired-state document is about fifty structs and two hundred and
 *   fifty members. Written by hand that is two hundred and fifty lines of
 *   reader, two hundred and fifty of writer and two hundred and fifty of free,
 *   each of which has to agree with the other two -- and the Rust it replaces
 *   got that agreement from one `#[derive]`. It also has to agree about the
 *   part nobody sees: `deny_unknown_fields` means every reader must know the
 *   whole member set of its own struct, so a hand-written one carries the list
 *   twice, once in the parsing and once in the refusal.
 *
 *   `crates/netcfgd-model/src/lib.rs` has the case that says why that matters,
 *   for a list maintained by hand that was not the member set at all:
 *   `Document`'s equality was written field by field and `bluetooth` was
 *   missed for as long as the field existed, so two documents differing only
 *   in a Bluetooth device compared EQUAL and `ncfg profile save` accepted a
 *   snapshot that did not reproduce the machine. **A list that must agree with
 *   a struct and is maintained by hand does not stay agreeing.** One table per
 *   struct is that list written once: the reader, the writer, the free walk
 *   and the unknown-member refusal are all derived from it, so a member added
 *   in one place is added in all four or in none.
 *
 * WHAT A TABLE DOES NOT COVER
 *   A tagged union -- an addressing source, an interface kind, a security
 *   choice, a principal -- is a custom triple of functions, because choosing
 *   the arm is the part a table cannot express. Those are in `document.c`
 *   beside the tables of the arms themselves, and each one is still reading
 *   and writing through this engine once the arm is chosen.
 *
 * ERRORS
 *   base.h's convention: 1 or 0, and a sentence. Every message names the
 *   member and the block it was in, because "invalid document" is not a
 *   diagnostic and an operator holding a 117 KB file needs to be told where.
 */
#ifndef NCFG_MODEL_FIELD_H
#define NCFG_MODEL_FIELD_H

#include <stddef.h>
#include <stdint.h>

#include "ncfg/base.h"
#include "ncfg/json_write.h"
#include "ncfg_json.h"

typedef struct ncfg_type ncfg_type_t;

typedef enum {
	/* `int`, with `fallback` for a document that says nothing. */
	NCFG_F_BOOL,
	/* `ncfg_optbool_t`. */
	NCFG_F_OPT_BOOL,
	/* `int64_t`, checked against `low`..`high`. */
	NCFG_F_INT,
	/* `ncfg_optint_t`. */
	NCFG_F_OPT_INT,
	/* `char *`, NULL where absent. */
	NCFG_F_STR,
	/* `int`, one of `choices`. */
	NCFG_F_ENUM,
	/* `ncfg_optint_t` holding one of `choices`. */
	NCFG_F_OPT_ENUM,
	/* A nested struct, inline. */
	NCFG_F_STRUCT,
	/* A nested struct behind a pointer, NULL where absent. */
	NCFG_F_OPT_STRUCT,
	/* A counted array of structs, or of custom values. */
	NCFG_F_LIST,
	/* A counted array of `char *`. */
	NCFG_F_STR_LIST,
	/* A counted array of `int64_t`, each checked against `low`..`high`. */
	NCFG_F_INT_LIST,
	/* Whatever a table cannot say. */
	NCFG_F_CUSTOM
} ncfg_field_kind_t;

/* Absent is a refusal rather than a default. */
#define NCFG_FF_REQUIRED   0x01u
/* Write nothing for an empty list. The Rust's `skip_serializing_if =
 * "Vec::is_empty"`, which is on some lists and deliberately not on others: a
 * document that has always written `"routes": []` goes on writing it, because
 * the rule every optional field here follows is that an upgrade must not look
 * like a configuration change. */
#define NCFG_FF_OMIT_EMPTY 0x02u
/* Write nothing where the value is true. Exactly one field: a probe's
 * `require_lease`, whose default is on. */
#define NCFG_FF_OMIT_TRUE  0x04u
/* Write nothing where the value is false. A qdisc's `ingress`. */
#define NCFG_FF_OMIT_FALSE 0x08u
/* Write nothing where the value is zero. A probe's `hold_down`. */
#define NCFG_FF_OMIT_ZERO  0x10u

/*
 * Write `null` where the value is absent, rather than leaving the member out.
 *
 * **Exactly one field in the model wants this**, and the reason is serde's:
 * an `Option` carries `skip_serializing_if` or it does not, and
 * `Globals::confirm_default` is the only one in `netcfgd-model` that does not
 * -- measured across every `Option` field in that crate, not assumed. So the
 * Rust writes `"confirm_default": null` on a machine that states no window,
 * which is nearly every machine, and this engine omitted the member instead.
 *
 * The witness could not catch it: `doc/schema/document.json` states a window
 * of 90, so the field's *absent* form appears nowhere in the file that
 * everything else here is checked against. It was found by running the C
 * `ncfg show` beside the installed Rust one against this machine's own
 * configuration -- which is the only check that had both the absent case and
 * something to compare it with.
 */
#define NCFG_FF_NULL_ABSENT 0x20u

/*
 * A closed set of words.
 *
 * Either a table of names here, or the pair of functions `value.h` already
 * publishes for the six sets it owns. **Never both, and never a second table
 * for a set value.h has**: an enum whose table said something plausible would
 * compile a block that means something else, which this project has done
 * twice.
 */
typedef struct {
	const char        *what; /* "hook phase", for the message */
	const char *const *names;
	size_t             count;
	const char *(*name_of)(int value);
	int (*from_name)(const char *name, int *out, char *err, size_t err_size);
} ncfg_enum_t;

typedef struct {
	int (*read)(const ncfg_json_doc_t *doc, uint32_t node, void *field, char *err,
	    size_t err_size);
	void (*write)(ncfg_json_writer_t *writer, const void *field);
	/* Whether to write nothing at all. NULL means always write. */
	int (*omit)(const void *field);
	/* NULL where the value owns nothing. */
	void (*release)(void *field);
	/*
	 * NULL where zero is the default.
	 *
	 * Fallible, and the one default that makes it so is a connectivity
	 * policy's `ignore`: its default is five strings that have to be
	 * allocated, and a default that silently came out empty would be a
	 * document claiming to count links it was written not to count.
	 */
	int (*init)(void *field);
} ncfg_custom_t;

typedef struct {
	const char   *name;
	unsigned char kind;
	unsigned char flags;
	size_t        offset;
	/* For a list: where its `size_t` count lives. */
	size_t        count_offset;
	int64_t       low;
	int64_t       high;
	/* The value a document that says nothing gets. */
	int64_t       fallback;
	const ncfg_enum_t   *choices;
	const ncfg_type_t   *type;
	size_t               element_size;
	const ncfg_custom_t *custom;
} ncfg_field_t;

struct ncfg_type {
	/* Named in every message this table produces. */
	const char         *what;
	const ncfg_field_t *fields;
	size_t              field_count;
	/*
	 * A member this table does not own because the caller already consumed it:
	 * the internal tag of a tagged union.
	 *
	 * Ignored on read and never written here -- the custom handler writes it
	 * first, so that the tag leads the object exactly as serde writes it.
	 */
	const char         *tag;
};

/* The value a document that says nothing gets, applied to a zeroed struct.
 * 0 only where a default could not be allocated. */
int ncfg_type_init(const ncfg_type_t *type, void *base);

/* Read one JSON object into `base`, refusing a member this table does not
 * have and a required member it does not carry. */
int ncfg_type_read(const ncfg_type_t *type, const ncfg_json_doc_t *doc, uint32_t node,
    void *base, char *err, size_t err_size);

/* Write the members, in declaration order. The caller opens and closes the
 * object, because a tagged union writes its tag between the two. */
void ncfg_type_write(const ncfg_type_t *type, ncfg_json_writer_t *writer, const void *base);

/* Free everything the struct owns, leaving it zeroed. */
void ncfg_type_free(const ncfg_type_t *type, void *base);

/* The pieces the custom handlers in document.c need, rather than a second
 * copy of each. */
char *ncfg_field_string(const ncfg_json_doc_t *doc, uint32_t node, const char *what,
    char *err, size_t err_size);
int ncfg_field_enum(const ncfg_enum_t *set, const ncfg_json_doc_t *doc, uint32_t node,
    int *out, char *err, size_t err_size);
const char *ncfg_field_enum_name(const ncfg_enum_t *set, int value);
/* `object` has exactly one member, and this is it. NCFG_JSON_NONE otherwise. */
uint32_t ncfg_field_only_member(const ncfg_json_doc_t *doc, uint32_t object);

#endif /* NCFG_MODEL_FIELD_H */
