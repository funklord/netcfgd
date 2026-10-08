/*
 * record_encode.c -- the refusals, the stream map, and the subject derivation.
 *
 * `record_encode.h` carries why this exists, why it lives here rather than in
 * `compile/`, and what it deliberately cannot refuse. This carries the walk.
 */
#include "record_encode.h"

#include <string.h>

/* The floor is fuzznet's and this is where the two files can be made to
 * disagree, so it refuses to compile rather than drifting. `record/record.h`
 * keeps 0..FZN_STREAM_RESERVED for a well-known stream that means the same
 * thing for every issuer; netcfgd's three sit above it. */
_Static_assert(NCFG_STREAM_HOST >= FZN_STREAM_RESERVED,
    "netcfgd's streams must sit above fuzznet's reserved range");
_Static_assert(NCFG_STREAM_ESTATE > NCFG_STREAM_GROUP &&
        NCFG_STREAM_GROUP > NCFG_STREAM_HOST,
    "the three scope streams must be distinct");

/*
 * The derivation's tag, versioned because changing how an object becomes a
 * subject silently re-points every cell -- the records would still verify and
 * would be about something else.
 *
 * **v2 as of 2026-09-29**, when the instance was folded in (project.md 10.360).
 * v1 hashed a scope and a name and had no room for a label, so two interfaces
 * shared a cell. Nothing had ever derived a v1 subject outside a test, so
 * nothing is stranded -- and the tag is bumped anyway, because a reader
 * holding records needs to be able to tell which derivation produced them and
 * that is the entire job of the string.
 */
static const char SUBJECT_TAG[] = "netcfgd subject v2";

/* What a transcript may carry per component. A label is an interface name or
 * an SSID; a root name is a site's. Bounded because nothing here allocates. */
#define SUBJECT_COMPONENT_MAX 256u

uint32_t ncfg_record_stream_of(ncfg_scope_t scope)
{
	switch (scope) {
	case NCFG_SCOPE_HOST:
		return NCFG_STREAM_HOST;
	case NCFG_SCOPE_GROUP:
		return NCFG_STREAM_GROUP;
	case NCFG_SCOPE_ESTATE:
		return NCFG_STREAM_ESTATE;
	case NCFG_SCOPE_HOST_PRIVATE:
	case NCFG_SCOPE_COUNT:
	default:
		/* No stream, because nothing in this scope travels. Zero rather
		 * than a spare number, so a caller that ignores the refusal
		 * above cannot accidentally name a real track. */
		return 0u;
	}
}

/*
 * Which root a block's objects hang from.
 *
 * **Derived from the block's default scope rather than from a second table.**
 * An `interface` is a thing on a machine and a `network` is a thing in the
 * estate, and the block defaults already say which of those a block is. A
 * host-private block roots at the host because there is nowhere else for it to
 * be -- and nothing in one travels anyway, so the answer costs nothing.
 */
ncfg_record_root_t ncfg_record_root_of(ncfg_block_t block)
{
	switch (ncfg_block_default_scope(block)) {
	case NCFG_SCOPE_GROUP:
		return NCFG_ROOT_GROUP;
	case NCFG_SCOPE_ESTATE:
		return NCFG_ROOT_ESTATE;
	case NCFG_SCOPE_HOST:
	case NCFG_SCOPE_HOST_PRIVATE:
	case NCFG_SCOPE_COUNT:
	default:
		return NCFG_ROOT_HOST;
	}
}

/* Append a length-prefixed component. Two bytes of length, big-endian, then
 * the bytes -- so a label containing any byte at all, an SSID included, cannot
 * be read as the end of one component and the start of the next. */
static int put_component(uint8_t *into, size_t cap, size_t *at, const void *bytes, size_t len)
{
	if (len > SUBJECT_COMPONENT_MAX || *at + 2u + len > cap) {
		return 0;
	}
	into[(*at)++] = (uint8_t)(len >> 8);
	into[(*at)++] = (uint8_t)(len & 0xffu);
	if (len > 0u) {
		memcpy(into + *at, bytes, len);
		*at += len;
	}
	return 1;
}

ncfg_record_err_t ncfg_record_subject_of(const fzn_hash_ops_t *hash, ncfg_block_t block,
    const ncfg_record_rootref_t *root, const char *label, size_t label_len,
    uint8_t out[FZN_SUBJECT_LEN])
{
	/* The tag with its NUL, the root kind, then three length-prefixed
	 * components: the root, the block's name, the label. */
	uint8_t transcript[sizeof(SUBJECT_TAG) + 1u + 3u * (2u + SUBJECT_COMPONENT_MAX)];
	size_t  at = 0u;

	if (!hash || !hash->hash || !root || !out) {
		return NCFG_RECORD_ERR_MALFORMED;
	}
	if ((int)block < 0 || (int)block >= (int)NCFG_BLOCK_COUNT) {
		return NCFG_RECORD_ERR_MALFORMED;
	}
	/* **The check the first version made against the wrong thing.** It
	 * compared the subject to the KEY's scope, which conflated how far a
	 * value travels with what it is about. This compares the root to the
	 * BLOCK, which is the question that has an answer. */
	if (root->kind != ncfg_record_root_of(block)) {
		return NCFG_RECORD_ERR_SUBJECT;
	}
	if (label_len > 0u && !label) {
		return NCFG_RECORD_ERR_MALFORMED;
	}

	memcpy(transcript, SUBJECT_TAG, sizeof(SUBJECT_TAG)); /* with its NUL */
	at = sizeof(SUBJECT_TAG);
	transcript[at++] = (uint8_t)root->kind;

	if (root->kind == NCFG_ROOT_HOST) {
		if (!root->key) {
			return NCFG_RECORD_ERR_MALFORMED;
		}
		if (!put_component(transcript, sizeof(transcript), &at, root->key,
		        (size_t)FZN_PUBKEY_LEN)) {
			return NCFG_RECORD_ERR_TOO_LARGE;
		}
	} else {
		if (!root->name) {
			return NCFG_RECORD_ERR_MALFORMED;
		}
		if (!put_component(transcript, sizeof(transcript), &at, root->name,
		        strlen(root->name))) {
			return NCFG_RECORD_ERR_TOO_LARGE;
		}
	}
	/* The block's own spelling, so that `interface "x"` and `linkset "x"`
	 * on one host are two objects. */
	if (!put_component(transcript, sizeof(transcript), &at, ncfg_block_name(block),
	        strlen(ncfg_block_name(block)))) {
		return NCFG_RECORD_ERR_TOO_LARGE;
	}
	/* And the label, which is what separates two interfaces. Absent for a
	 * block that takes none, where the zero length is itself the answer
	 * rather than a missing component. */
	if (!put_component(transcript, sizeof(transcript), &at, label, label_len)) {
		return NCFG_RECORD_ERR_TOO_LARGE;
	}

	/* **Nonzero is success**, which `session/commitment.h` states in capitals
	 * and this file got backwards first. The header explains why it is worth
	 * a paragraph: the two mistakes are not symmetric. Reading success as
	 * failure refuses a good hash, which is loud; reading failure as success
	 * hands the caller whatever was on the stack, which here would be a
	 * subject nobody can predict and every host would compute differently. */
	if (!hash->hash(hash->ctx, out, (size_t)FZN_SUBJECT_LEN, transcript, at)) {
		return NCFG_RECORD_ERR_MALFORMED;
	}
	return NCFG_RECORD_OK;
}

ncfg_record_err_t ncfg_record_encode(const fzn_hash_ops_t *hash, ncfg_block_t block,
    const ncfg_record_rootref_t *root, const char *label, size_t label_len, const char *path,
    const char *value, size_t value_len, ncfg_record_fields_t *out)
{
	ncfg_scope_t      scope;
	unsigned          kind;
	size_t            at;
	uint8_t           subject[FZN_SUBJECT_LEN];
	ncfg_record_err_t derived;

	if (!path || !out || (!value && value_len > 0u)) {
		return NCFG_RECORD_ERR_MALFORMED;
	}
	if ((int)block < 0 || (int)block >= (int)NCFG_BLOCK_COUNT) {
		return NCFG_RECORD_ERR_MALFORMED;
	}

	/*
	 * **The two tables are asked in this order deliberately.** The scope
	 * decides whether a key may travel at all; the number decides whether
	 * it can be said yet. Asking the scope first means a host-private key
	 * is refused as host-private rather than as unregistered, and a reader
	 * of the log learns which of the two it is looking at.
	 */
	scope = ncfg_scope_of(block, path);
	if (scope == NCFG_SCOPE_HOST_PRIVATE) {
		return NCFG_RECORD_ERR_HOST_PRIVATE;
	}
	kind = ncfg_kind_of(block, path);
	if (kind == NCFG_KIND_NONE) {
		return NCFG_RECORD_ERR_UNREGISTERED;
	}
	if (value_len > (size_t)FZN_RECORD_BODY_MAX) {
		return NCFG_RECORD_ERR_TOO_LARGE;
	}
	/* Text, because the mirror renders this back into a config file and
	 * reads it again. A NUL survives the record and truncates on the way
	 * out, so the two directions would disagree about a value that
	 * verified. */
	for (at = 0u; at < value_len; at++) {
		if (value[at] == '\0') {
			return NCFG_RECORD_ERR_NOT_TEXT;
		}
	}
	/* Last, because it is the only step that can cost a hash -- and every
	 * refusal above is about the key rather than about the object, so
	 * nothing below would change their answer. */
	derived = ncfg_record_subject_of(hash, block, root, label, label_len, subject);
	if (derived != NCFG_RECORD_OK) {
		return derived;
	}

	memset(out, 0, sizeof(*out));
	out->kind = (uint32_t)kind;
	/* **Derived, never passed in.** A caller that could name the stream
	 * could put an estate-wide value in the host track, where a host that
	 * may see its own configuration would read it as its own. */
	out->stream = ncfg_record_stream_of(scope);
	out->scope = scope;
	memcpy(out->subject, subject, sizeof(subject));
	out->body = (const uint8_t *)value;
	out->body_len = value_len;
	return NCFG_RECORD_OK;
}

const char *ncfg_record_why(ncfg_record_err_t err)
{
	switch (err) {
	case NCFG_RECORD_OK:
		return "ok";
	case NCFG_RECORD_ERR_MALFORMED:
		return "the call is wrong: a null argument or a block this build does not know";
	case NCFG_RECORD_ERR_UNREGISTERED:
		return "this key has no wire number yet, so it cannot be carried as a record";
	case NCFG_RECORD_ERR_HOST_PRIVATE:
		return "this key is host-private and must not leave the machine";
	case NCFG_RECORD_ERR_SUBJECT:
		return "the root is not the one this block's objects hang from";
	case NCFG_RECORD_ERR_TOO_LARGE:
		return "the value, the label or the root name is larger than this carries";
	case NCFG_RECORD_ERR_NOT_TEXT:
		return "the value holds a NUL, and the language spells values as text";
	default:
		break;
	}
	return "unknown";
}
