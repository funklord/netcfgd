/*
 * internal.h -- what the proto sources share and nothing outside them needs.
 *
 * Not under include/: the port's public face is one header per module
 * (0263), and a second installed header would invite a caller to reach past
 * proto.h into the decoder's working parts.
 */
#ifndef NCFG_PROTO_INTERNAL_H
#define NCFG_PROTO_INTERNAL_H

#include "ncfg/proto.h"

/*
 * One decode in progress: where the bytes came from, what owns the result,
 * and where a refusal goes.
 *
 * Carried as a struct rather than five arguments because every helper below
 * needs all five, and a decoder for a message with fourteen members is where
 * an argument list gets reordered by accident.
 */
typedef struct {
	ncfg_proto_message_t *message;
	ncfg_json_doc_t      *doc;
	char                 *err;
	size_t                err_size;
	/* Whether a member this build does not know is refused. Set for a
	 * request and clear for a response; see proto.h on the asymmetry. */
	int                   strict;
} ncfg_proto_dec_t;

/*
 * `count` items of `size` bytes, zeroed, owned by the message being decoded.
 *
 * NULL on failure, with the refusal already written. A zero count allocates
 * nothing and returns NULL, which is the empty list rather than an error --
 * so a caller checks the count, not the pointer.
 */
void *ncfg_proto_block(ncfg_proto_dec_t *dec, size_t count, size_t size);

/* Write a refusal and return 0, so a caller can `return ncfg_proto_fail(...)`. */
int ncfg_proto_fail(ncfg_proto_dec_t *dec, const char *format, ...);

/*
 * Members, by name, with the type checked.
 *
 * `required` says what an absent member means. JSON null lands where absent
 * does on an optional member, because every optional member in this protocol
 * is a serde `Option` that is skipped when unset -- and it is refused on a
 * required one, which is what serde does.
 */
int ncfg_proto_get_str(ncfg_proto_dec_t *dec, uint32_t object, const char *name,
    int required, const char *what, ncfg_proto_str_t *out);
int ncfg_proto_get_bool(ncfg_proto_dec_t *dec, uint32_t object, const char *name,
    int required, unsigned char fallback, const char *what, unsigned char *out);
int ncfg_proto_get_int(ncfg_proto_dec_t *dec, uint32_t object, const char *name,
    int required, const char *what, ncfg_proto_int_t *out);
int ncfg_proto_get_version(ncfg_proto_dec_t *dec, uint32_t object, const char *name,
    const char *what, ncfg_proto_version_t *out);
/* An array of strings. Absent is the empty list where `required` is clear. */
int ncfg_proto_get_strs(ncfg_proto_dec_t *dec, uint32_t object, const char *name,
    int required, const char *what, ncfg_proto_strs_t *out);
/*
 * An array of objects: the node and how many, for a caller that then decodes
 * each element itself.
 */
int ncfg_proto_get_array(ncfg_proto_dec_t *dec, uint32_t object, const char *name,
    int required, const char *what, uint32_t *array_out, size_t *count_out);

/*
 * Refuse a member this message does not define, naming it.
 *
 * A no-op where `dec->strict` is clear, which is the whole of the direction
 * asymmetry: one call, in both decoders, that does nothing on the way back to
 * a client. `known_key` names a member of this object whose value is a string
 * and whose spelling is certain -- the tag, or a required member -- and is
 * what lets the key bytes be found; see the implementation.
 */
int ncfg_proto_check_members(ncfg_proto_dec_t *dec, uint32_t object, const char *known_key,
    const char *const *allowed, size_t allowed_count, const char *what);

/* The decoders the two directions share. */
int ncfg_proto_decode_event(ncfg_proto_dec_t *dec, uint32_t object, ncfg_proto_event_t *out);
int ncfg_proto_decode_response(ncfg_proto_dec_t *dec, uint32_t object,
    ncfg_proto_response_t *out);
int ncfg_proto_decode_request(ncfg_proto_dec_t *dec, uint32_t object,
    ncfg_proto_request_t *out);

#endif /* NCFG_PROTO_INTERNAL_H */
