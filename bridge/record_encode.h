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
 *   Not a second encoding. project.md 10.355 settles the mirror: netcfgd's
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
 * WHAT IT CANNOT REFUSE, WHICH CORRECTS 10.356
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

/*
 * A SUBJECT IS A CONFIGURED OBJECT, NOT A MACHINE
 *
 * **Settled by the copyright holder 2026-09-29: fold the instance into the
 * subject.** project.md 10.359 measured what the first version cost -- fuzznet
 * addresses a cell by `(issuer, subject, kind)`, a kind names the KEY, and
 * with a host for a subject `wlan0`'s MTU and `eth0`'s MTU were one cell. The
 * second write won and every host in the estate agreed about the wrong answer.
 *
 * So a subject is `(root, block, label)`: this host's `wlan0`, the estate's
 * `network "home"`, this group's `rule "uplink"`. The 32 bytes are a hash over
 * those three, and the label is what separates two interfaces.
 *
 * **What it costs, which is the reason it was a decision rather than a fix.**
 * A host's subject is no longer its public key. Reading a host's configuration
 * is not `fzn_state_get(state, host_key, kind)` any more: a reader derives the
 * subject for the object it wants, so it has to know the labels. Enumerating
 * what a host holds becomes a question for the estate's own records rather
 * than one the state answers by itself.
 *
 * THE ROOT COMES FROM THE BLOCK, THE STREAM FROM THE KEY, AND THOSE ARE TWO
 * QUESTIONS
 *
 * The first version mapped a key's SCOPE onto a subject one-to-one, which read
 * "how far does this travel" and "what is this about" as one question. They
 * are not. `interface.dns` is estate-scoped and is about one link on one
 * machine: everyone may see it, and it describes `wlan0` here.
 *
 * An `interface` is a thing on a machine and a `network` is a thing in the
 * estate, whatever the scope of any key inside them -- so the ROOT is a
 * property of the block, and `ncfg_record_root_of` derives it from
 * `ncfg_block_default_scope` rather than from a second table. The key's own
 * scope still chooses the stream, which is the other question.
 */
typedef enum {
	/* Named by a 32-byte public key: the machine itself. */
	NCFG_ROOT_HOST = 0,
	/* Named by a name, hashed in with everything else. */
	NCFG_ROOT_GROUP,
	NCFG_ROOT_ESTATE
} ncfg_record_root_t;

/* Which root a block's objects hang from. Derived from the block's default
 * scope, so adding a block puts it somewhere by the same rule that scopes it
 * -- and a host-private block roots at the host, having nowhere else to be. */
ncfg_record_root_t ncfg_record_root_of(ncfg_block_t block);

/* Where a subject hangs from: a host by its key, or a group or estate by its
 * name. `kind` must be the one `ncfg_record_root_of` gives the block, which is
 * checked rather than assumed. */
typedef struct {
	ncfg_record_root_t kind;
	/* NCFG_ROOT_HOST. */
	const uint8_t     *key;
	/* NCFG_ROOT_GROUP and NCFG_ROOT_ESTATE. */
	const char        *name;
} ncfg_record_rootref_t;

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
	/* The root is not the one this block's objects hang from -- an
	 * interface rooted at the estate, a network rooted at a host. */
	NCFG_RECORD_ERR_SUBJECT = -4,
	/* Over `FZN_RECORD_BODY_MAX`, or a name or label longer than a subject
	 * transcript carries. Its own code because it is a sizing answer a
	 * caller can act on, which is the distinction `fzn_record_err_t`
	 * already draws. */
	NCFG_RECORD_ERR_TOO_LARGE = -5,
	/* A NUL inside a value the language spells as text. It would survive
	 * the record and truncate on the way back out through any of the C
	 * string paths that render it, so the two directions would disagree
	 * about a value that verified. */
	NCFG_RECORD_ERR_NOT_TEXT = -6
} ncfg_record_err_t;

/* Everything a record carries that comes from the KEY and the object it is
 * about. The caller adds its issuer, its sequence and the time, and calls
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
 * The subject for one configured object.
 *
 * Exported beside `ncfg_record_encode`, which derives its own, because a
 * READER needs one without encoding anything: `fzn_state_get` takes a subject
 * and a kind, so asking what the estate currently says about `wlan0`'s MTU
 * starts here.
 *
 * `label` is the block's label -- an interface's name, a network's id -- and
 * NULL where the block takes none. It is taken with a length because a label
 * can be an SSID, and an SSID is 32 arbitrary bytes rather than a C string.
 *
 * **Every component is length-prefixed in the transcript rather than separated
 * by a byte.** A separator has to be a byte no component can contain, and a
 * label can be an SSID, which is 32 arbitrary bytes. It is kept as
 * unconditional robustness rather than as a fix for a reachable fault:
 * measured by sabotage, a trailing-NUL scheme passes every test in this
 * module, because only the label is length-taken and it is last. The prefix
 * stays correct if a root ever becomes length-taken or a component is added
 * after the label -- project.md 10.360 records that the tests cannot tell the
 * two schemes apart, so the claim is not stronger than that.
 *
 * `hash` is the caller's binding, as every other fuzznet seam takes it.
 */
ncfg_record_err_t ncfg_record_subject_of(const fzn_hash_ops_t *hash, ncfg_block_t block,
    const ncfg_record_rootref_t *root, const char *label, size_t label_len,
    uint8_t out[FZN_SUBJECT_LEN]);

/*
 * Fill in the fields for one key's value on one object.
 *
 * `path` is the key's path within the block, exactly as `ncfg_scope_of` and
 * `ncfg_kind_of` take it -- `mtu`, `advertise.prefix`, `wifi.roam.signal`.
 * `value` is the value as the language spells it, and is borrowed.
 *
 * **The subject is derived here rather than passed in.** A caller that could
 * hand over 32 opaque bytes could hand over the wrong ones, and nothing
 * downstream can tell what a subject is about.
 *
 * On any refusal `*out` is left untouched, so a caller cannot half-fill a
 * record it was told not to make.
 */
ncfg_record_err_t ncfg_record_encode(const fzn_hash_ops_t *hash, ncfg_block_t block,
    const ncfg_record_rootref_t *root, const char *label, size_t label_len,
    const char *path, const char *value, size_t value_len, ncfg_record_fields_t *out);

/* The stream a scope's records go in, or 0 for a scope that has none --
 * host-private, which is every scope that does not travel. Exposed because a
 * reader that follows one track needs to name it without encoding anything. */
uint32_t ncfg_record_stream_of(ncfg_scope_t scope);

/* What a refusal means, for a log line. Never NULL. */
const char *ncfg_record_why(ncfg_record_err_t err);

#endif /* NCFG_RECORD_ENCODE_H */
