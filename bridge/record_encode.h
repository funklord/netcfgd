/*
 * record_encode.h -- turning one configuration key into a statement fuzznet
 * can carry.
 *
 * WHAT THIS IS FOR
 *   `compile/scope.c` says how far a key travels and what number it travels
 *   under. This is the other end: given a key, its value, and who the
 *   statement is about, it fills in the fields `fzn_record_sign` needs and
 *   refuses the cases that must not become a record at all.
 *
 *   It does NOT sign, allocate, or touch a key. The issuer, the sequence and
 *   the clock are the caller's, because those are facts about a node rather
 *   than about a configuration key -- and a function holding a signer is a
 *   function somebody calls with one when they meant to check something.
 *
 * WHY IT LIVES IN `bridge/` AND NOT IN `compile/`
 *   Because it cites fuzznet's constants rather than copying them, and the
 *   daemon does not link fuzznet: `doc/shared-protocol-brief.md` section 3
 *   keeps everything fuzznet away from the process holding CAP_NET_ADMIN.
 *   `FZN_RECORD_BODY_MAX`, `FZN_SUBJECT_LEN` and `FZN_STREAM_RESERVED` are
 *   fuzznet's to move, and a copy of one here would be a number nobody
 *   re-derives -- so this compiles against their header and takes exactly one
 *   source file out of `c/` for the registry.
 *
 * THE BODY IS THE VALUE AS THE LANGUAGE SPELLS IT
 *   Not a second encoding. project.md 10.324 settles the mirror: netcfgd's
 *   format is what records are rendered into and read back from, so a record
 *   whose body is the language's own text round-trips through `render.c` and
 *   `parse.c`, which are already disciplined against each other. A second
 *   value encoding here would be a third thing for those two to disagree
 *   with.
 *
 *   **A newline in a body is legitimate and is not an injection.** The
 *   lexer's strings "run to the closing quote, across lines if need be",
 *   because the netifrc spelling puts several addresses in one value; and
 *   `ncfg_render_quote` escapes the quote and the backslash. That was checked
 *   in the source rather than assumed, because the obvious guess is the other
 *   way and a refusal written on the guess would have refused a whole class
 *   of real values.
 *
 * WHAT IT REFUSES, AND WHY EACH IS STRUCTURAL
 *   A key with no number, a key that is host-private, a subject that does not
 *   match the key's scope, a body over fuzznet's bound, and a NUL in text.
 *   The middle one is the load-bearing refusal: the stream is DERIVED from the
 *   scope rather than passed in, so a caller cannot put an estate-wide value
 *   in the host stream even deliberately.
 *
 * WHAT IT CANNOT REFUSE, WHICH CORRECTS 10.325
 *   That entry said a record encoder refusing `NCFG_CERT_SOURCE_PATH` is what
 *   would let `dot1x.ca_cert` and its two siblings be numbered. The refusal
 *   cannot live here: a cert source is a document type, this takes bytes, and
 *   giving it the document model would pull `ncfg/document.h` into the
 *   unprivileged network-facing program that section 3 exists to keep small.
 *   The refusal belongs wherever a document field becomes a value -- which is
 *   not written yet, so the three keys stay unregistered and this refuses them
 *   as unregistered like any other. project.md 10.327.
 */
#ifndef NCFG_RECORD_ENCODE_H
#define NCFG_RECORD_ENCODE_H

#include "ncfg/scope.h"

#include "record/record.h"
#include "session/commitment.h"

#include <stddef.h>
#include <stdint.h>

/*
 * ONE STREAM PER SCOPE, WHICH IS FUZZNET'S OWN ARGUMENT RATHER THAN A CHOICE
 *
 * `record/record.h` says a stream exists because of PARTIAL ENTITLEMENT: an
 * issuer numbers each stream from 1 independently, `fzn_journal_admit` refuses
 * a gap, and "if a recipient is not allowed to see some of an issuer's
 * records, its position develops holes it is not permitted to fill" -- and
 * then asks for the missing one for ever.
 *
 * A host that may see this machine's own configuration and not the estate's is
 * exactly that recipient. With one stream for everything it would stall on the
 * first estate record it was not entitled to; with one per scope each track
 * stays contiguous for whoever may follow it.
 *
 * Cross-scope ordering is not lost, because there is none to lose: two scopes
 * are two cells, and `state/state.h` orders within a writer, which is
 * (issuer, stream). What DOES need ordering -- a set and a clear of one key --
 * shares a scope by construction and therefore a stream.
 *
 * **The numbers are netcfgd's and mean nothing to anybody else.** A stream is
 * scoped to its issuer, so no assignment is needed and none was asked for.
 * What is not netcfgd's is the floor: below `FZN_STREAM_RESERVED` is fuzznet's
 * range, kept for a well-known stream that means the same thing for every
 * issuer. The static assert below is what keeps that true if the floor moves.
 */
#define NCFG_STREAM_HOST   (FZN_STREAM_RESERVED + 0u)
#define NCFG_STREAM_GROUP  (FZN_STREAM_RESERVED + 1u)
#define NCFG_STREAM_ESTATE (FZN_STREAM_RESERVED + 2u)

/* What a record about a key is a statement about. The caller says which it is
 * holding, and this refuses one that does not match the key's scope -- a
 * 32-byte subject is opaque, so nothing else could tell an estate's from a
 * host's. */
typedef enum {
	/* This machine, named by its public key. `FZN_SUBJECT_LEN` is 32 so
	 * that it can hold one, which `record/record.h` states is the common
	 * case. */
	NCFG_RECORD_SUBJECT_HOST = 0,
	/* A zone, a building, a VLAN domain: a name hashed to 32 bytes by
	 * `ncfg_record_subject_of_name`. */
	NCFG_RECORD_SUBJECT_GROUP,
	/* The estate, by the same derivation. */
	NCFG_RECORD_SUBJECT_ESTATE
} ncfg_record_subject_t;

typedef enum {
	NCFG_RECORD_OK = 0,
	/* The caller has a bug: a null pointer, a block out of range. Kept
	 * apart from every refusal below, which are all answers about a
	 * configuration key rather than about the call. */
	NCFG_RECORD_ERR_MALFORMED = -1,
	/* The key has no wire number, so it cannot be a record yet. Not an
	 * error in the key or the value -- see `NCFG_KIND_NONE`. */
	NCFG_RECORD_ERR_UNREGISTERED = -2,
	/* The key must never leave this machine. Unreachable through a
	 * registry that gives host-private keys no number, and checked anyway:
	 * it is the one refusal whose failure is silent and permanent. */
	NCFG_RECORD_ERR_HOST_PRIVATE = -3,
	/* The subject is not the kind this key's scope takes -- an estate-wide
	 * key handed a host, or the reverse. */
	NCFG_RECORD_ERR_SUBJECT = -4,
	/* Over `FZN_RECORD_BODY_MAX`. Its own code because it is a sizing
	 * answer a caller can act on, which is the distinction
	 * `fzn_record_err_t` already draws. */
	NCFG_RECORD_ERR_TOO_LARGE = -5,
	/* A NUL inside a value the language spells as text. It would survive
	 * the record and truncate on the way back out through any of the C
	 * string paths that render it, so the two directions would disagree
	 * about a value that verified. */
	NCFG_RECORD_ERR_NOT_TEXT = -6
} ncfg_record_err_t;

/* Everything a record carries that comes from the KEY rather than from the
 * node. The caller adds its issuer, its sequence and the time, and calls
 * `fzn_record_sign`.
 *
 * `body` borrows the caller's value and is not copied, on the same terms as
 * `fzn_record_t`: it must outlive the signing call. */
typedef struct {
	uint32_t       kind;
	uint32_t       stream;
	ncfg_scope_t   scope;
	uint8_t        subject[FZN_SUBJECT_LEN];
	const uint8_t *body;
	size_t         body_len;
} ncfg_record_fields_t;

/*
 * A subject for a named group or estate.
 *
 * **Domain-separated, and the scope is inside the separation.** A group called
 * `roof` and an estate called `roof` are different subjects, and neither may
 * collide with what another consumer of the same library hashes into its own
 * subjects. The tag is versioned because changing the derivation later would
 * silently re-point every cell.
 *
 * `hash` is the caller's binding, as every other fuzznet seam takes it --
 * `session/hash_monocypher.h` seats the one this tree uses. Refuses
 * `NCFG_RECORD_SUBJECT_HOST`: a host's subject is its public key and is not
 * derived from anything.
 */
ncfg_record_err_t ncfg_record_subject_of_name(const fzn_hash_ops_t *hash,
    ncfg_record_subject_t which, const char *name, uint8_t out[FZN_SUBJECT_LEN]);

/*
 * Fill in the fields for one key's value.
 *
 * `path` is the key's path within the block, exactly as `ncfg_scope_of` and
 * `ncfg_kind_of` take it -- `mtu`, `advertise.prefix`, `wifi.roam.signal`.
 * `value` is the value as the language spells it, and is borrowed.
 *
 * On any refusal `*out` is left untouched, so a caller cannot half-fill a
 * record it was told not to make.
 */
ncfg_record_err_t ncfg_record_encode(ncfg_block_t block, const char *path,
    ncfg_record_subject_t which, const uint8_t subject[FZN_SUBJECT_LEN], const char *value,
    size_t value_len, ncfg_record_fields_t *out);

/* The stream a scope's records go in, or 0 for a scope that has none --
 * host-private, which is every scope that does not travel. Exposed because a
 * reader that follows one track needs to name it without encoding anything. */
uint32_t ncfg_record_stream_of(ncfg_scope_t scope);

/* What a refusal means, for a log line. Never NULL. */
const char *ncfg_record_why(ncfg_record_err_t err);

#endif /* NCFG_RECORD_ENCODE_H */
