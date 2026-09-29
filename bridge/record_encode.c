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

/* The derivation's tag. Versioned, because changing how a name becomes a
 * subject would silently re-point every cell that name addresses -- the
 * records would still verify and would be about something else. */
static const char SUBJECT_TAG[] = "netcfgd subject v1";

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

/* Which subject a scope's records are about. The pairing is the whole of what
 * `NCFG_RECORD_ERR_SUBJECT` checks, and it is one-to-one: a host-scoped key is
 * a statement about a host, a group-scoped one about a group. */
static int subject_matches(ncfg_scope_t scope, ncfg_record_subject_t which)
{
	switch (scope) {
	case NCFG_SCOPE_HOST:
		return which == NCFG_RECORD_SUBJECT_HOST;
	case NCFG_SCOPE_GROUP:
		return which == NCFG_RECORD_SUBJECT_GROUP;
	case NCFG_SCOPE_ESTATE:
		return which == NCFG_RECORD_SUBJECT_ESTATE;
	case NCFG_SCOPE_HOST_PRIVATE:
	case NCFG_SCOPE_COUNT:
	default:
		return 0;
	}
}

ncfg_record_err_t ncfg_record_subject_of_name(const fzn_hash_ops_t *hash,
    ncfg_record_subject_t which, const char *name, uint8_t out[FZN_SUBJECT_LEN])
{
	/* The tag, a NUL, the scope byte, a NUL, then the name. The separators
	 * are what stop a group named `x\1estate` reaching an estate's cell:
	 * without them the concatenation is ambiguous, which is the whole of
	 * what domain separation is for. */
	uint8_t transcript[sizeof(SUBJECT_TAG) + 2u + 256u];
	size_t  name_len;
	size_t  at;

	if (!hash || !hash->hash || !name || !out) {
		return NCFG_RECORD_ERR_MALFORMED;
	}
	if (which != NCFG_RECORD_SUBJECT_GROUP && which != NCFG_RECORD_SUBJECT_ESTATE) {
		/* A host's subject is its public key. Deriving one from a name
		 * would invent a second way to address a host, and the two
		 * would disagree the first time a host was renamed. */
		return NCFG_RECORD_ERR_SUBJECT;
	}
	name_len = strlen(name);
	if (name_len > 256u) {
		return NCFG_RECORD_ERR_TOO_LARGE;
	}

	at = 0u;
	memcpy(transcript + at, SUBJECT_TAG, sizeof(SUBJECT_TAG)); /* with its NUL */
	at += sizeof(SUBJECT_TAG);
	transcript[at++] = (uint8_t)which;
	transcript[at++] = 0u;
	memcpy(transcript + at, name, name_len);
	at += name_len;

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

ncfg_record_err_t ncfg_record_encode(ncfg_block_t block, const char *path,
    ncfg_record_subject_t which, const uint8_t subject[FZN_SUBJECT_LEN], const char *value,
    size_t value_len, ncfg_record_fields_t *out)
{
	ncfg_scope_t scope;
	unsigned     kind;
	size_t       at;

	if (!path || !subject || !out || (!value && value_len > 0u)) {
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
	if (!subject_matches(scope, which)) {
		return NCFG_RECORD_ERR_SUBJECT;
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

	memset(out, 0, sizeof(*out));
	out->kind = (uint32_t)kind;
	/* **Derived, never passed in.** A caller that could name the stream
	 * could put an estate-wide value in the host track, where a host that
	 * may see its own configuration would read it as its own. */
	out->stream = ncfg_record_stream_of(scope);
	out->scope = scope;
	memcpy(out->subject, subject, (size_t)FZN_SUBJECT_LEN);
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
		return "the subject is not the kind this key's scope is about";
	case NCFG_RECORD_ERR_TOO_LARGE:
		return "the value is larger than a record body carries";
	case NCFG_RECORD_ERR_NOT_TEXT:
		return "the value holds a NUL, and the language spells values as text";
	default:
		break;
	}
	return "unknown";
}
