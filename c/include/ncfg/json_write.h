/*
 * json_write.h -- the writing half of the control socket's JSON.
 *
 * WHY THIS EXISTS AT ALL
 *   `client/ncfg_json.h` reads what netcfgd sends. What a client sends back is
 *   built a request at a time: an `snprintf` with a format string per verb,
 *   and `ncfg_client_quote` for each string that goes into it. What that leaves
 *   to the caller is the structure: `wifi_request` spends twenty lines writing
 *   two members, because it owns every brace and comma, counts the bytes left
 *   after each one, and abandons the request when the next will not fit. A
 *   member that is only sometimes there is the same again, with a comma that
 *   is written by hand or not.
 *
 *   This is the reader's counterpart: the structure becomes the writer's
 *   problem and the ceiling becomes `ncfg_buf_t`'s. It writes what that reader
 *   reads, refuses what that reader refuses, and takes NCFG_JSON_MAX_DEPTH
 *   from it rather than copying the number -- two halves of one protocol that
 *   disagreed about a limit would be a message one can build and the other
 *   cannot parse.
 *
 *   It escapes strings itself rather than calling `ncfg_client_quote`, which
 *   is not the same job: that one fills a caller's fixed array and answers
 *   "it did not fit", and a streaming writer has no array to offer it and a
 *   ceiling of its own already. It also refuses a string that is not UTF-8,
 *   which that one passes through as it arrived.
 *
 * SEPARATORS ARE THE WRITER'S JOB, NEVER THE CALLER'S
 *   A caller writes values and member names; it never writes a comma, a
 *   colon, a quote or a brace. The comma between two members is the one piece
 *   of punctuation that a hand-rolled builder gets wrong -- present after the
 *   last member, absent after a member that a condition skipped -- and it is
 *   the piece a caller has no way to test without a parser. So it is not
 *   offered: there is no call that emits one.
 *
 * MISUSE IS A VALUE, NOT A CRASH
 *   A member outside an object, a value where a name belongs, an object
 *   closed as an array, a document with two values in it: each sets a sticky
 *   failure and makes every later call a no-op, exactly as `ncfg_buf_t` does
 *   and for the same reason -- a caller may write forty calls and check once,
 *   which is what makes the check get written at all. Nothing here aborts and
 *   nothing asserts: this runs inside a daemon and inside a GUI, and a
 *   malformed request is a message to refuse rather than a process to end.
 *
 *   The failure also travels into the buffer being written into, so a caller
 *   that checks neither reads "" from `ncfg_buf_text` rather than half a
 *   message. Half a message is the one that gets sent by accident.
 *
 * WHAT IT REFUSES, AND WHY EACH ONE
 *   - **a string that is not valid UTF-8**, refused rather than repaired.
 *     Three repairs were available and each is worse. Emitting the bytes raw
 *     produces a line this project's own reader will hand to a Qt string that
 *     then refuses or mangles it. Escaping each stray byte as \u00XX is valid
 *     JSON that means different bytes, because the reader unescapes U+00XX to
 *     its UTF-8 form -- so `wifi_add` would store an SSID nobody typed.
 *     Substituting U+FFFD is the same silent change with a nicer name. And
 *     the protocol already carries arbitrary bytes where it needs to: an SSID
 *     travels hex-encoded (`"ssid":"686f6d65"`) precisely because it is not
 *     text. So a string that is not UTF-8 is a caller's bug, and the only
 *     answer that does not put a wrong value in front of a user is to say so
 *     and write nothing.
 *   - **nesting past NCFG_JSON_MAX_DEPTH**, which is the reader's cap. A
 *     document this could build and that could not be read back is a bug
 *     discovered at the far end of a socket instead of here.
 *   - **a second value at the top level.** The framing is one JSON value per
 *     line and the reader refuses anything after the first, so a writer that
 *     allowed two would be building a line that cannot be read.
 *   - **a NULL string.** Absent, null and empty are three different answers
 *     on this socket -- `ncfg_json_member`'s comment has the case where
 *     conflating them reports "no MAC address" for a device nobody asked
 *     about -- so a null pointer is not quietly promoted to a JSON null. The
 *     caller that means null says `ncfg_json_write_null`.
 *
 *   Floating point is not offered at all. Everything the schema carries is an
 *   integer -- an MTU, a metric, a signal in dBm, a byte count -- and a
 *   `double` on the wire would be a value that does not survive being read
 *   back as one, which is the round trip `ncfg_json_int` exists to protect.
 */
#ifndef NCFG_JSON_WRITE_H
#define NCFG_JSON_WRITE_H

#include <stddef.h>
#include <stdint.h>

#include "ncfg/buf.h"
/* For NCFG_JSON_MAX_DEPTH, and for the reader this is the counterpart to. */
#include "ncfg_json.h"

/* One open container, while its members or elements are being written. */
typedef struct {
	unsigned char is_object;
	/* Something is already in here, so the next thing owes a comma. */
	unsigned char has_child;
	/* A member name has been written and its value has not. */
	unsigned char wants_value;
} ncfg_json_write_frame_t;

/*
 * A writer, which owns no memory and may live on the stack.
 *
 * `frames[0]` is the document itself rather than a container: it is what
 * holds the rule that a line carries exactly one value, so the top level does
 * not need a case of its own in every function.
 */
typedef struct {
	ncfg_buf_t             *buf;
	/* The first misuse, as a sentence, or NULL. A pointer to a literal
	 * rather than a copied string: the writer allocates nothing, and the
	 * sentence outlives any writer that could report it. */
	const char             *failure;
	size_t                  depth;
	ncfg_json_write_frame_t frames[NCFG_JSON_MAX_DEPTH + 1u];
} ncfg_json_writer_t;

/*
 * Start writing into `buf`, which the caller owns and must outlive this.
 *
 * The buffer is not emptied first, so a caller framing a line may put its own
 * prefix in. It is also not sized here: the ceiling is the caller's, because
 * the bound on a response differs from the bound on a request.
 */
void ncfg_json_write_init(ncfg_json_writer_t *writer, ncfg_buf_t *buf);

/*
 * Re-indent finished compact JSON, in `serde_json::to_string_pretty`'s shape.
 *
 * **A second pass over the bytes rather than a mode on the writer**, and that
 * is the whole design. Every writer here is compact by construction, the
 * frozen witnesses in `doc/schema/` are compared against compact output, and
 * the control socket sends compact -- so a mode would put a branch in each of
 * those places to serve one that is none of them. This serves exactly the
 * human boundary: `ncfg <verb> --json` on a terminal.
 *
 * The shape is serde's, because a script written against the Rust's output has
 * to keep working: two spaces per level, `": "` between a key and its value,
 * one array element or object member per line, and an empty array or object
 * written `[]` or `{}` on the line it started. Strings are copied through
 * without being re-escaped, escapes and all, so this cannot change a value.
 *
 * 0 where the input is not the compact JSON this writer produces -- an
 * unterminated string, brackets that do not balance -- and `out` is then not
 * to be printed. A caller with nothing better to do may print the compact form
 * instead, which is what `ncfg` does: a document the operator asked for is
 * worth more badly laid out than not at all.
 */
int ncfg_json_pretty(const char *compact, ncfg_buf_t *out);

/* Containers. Each end must match the begin that is open, or it is a misuse. */
void ncfg_json_write_object_begin(ncfg_json_writer_t *writer);
void ncfg_json_write_object_end(ncfg_json_writer_t *writer);
void ncfg_json_write_array_begin(ncfg_json_writer_t *writer);
void ncfg_json_write_array_end(ncfg_json_writer_t *writer);

/* A member name, only inside an object, and only where a value is not owed. */
void ncfg_json_write_key(ncfg_json_writer_t *writer, const char *name);

/* Values. Each is a misuse anywhere a value cannot go. */
void ncfg_json_write_string(ncfg_json_writer_t *writer, const char *text);
/*
 * A string by count, which is the one a caller re-emitting what it read wants.
 * The reader's strings are counted rather than terminated -- they sit end to
 * end in one buffer -- so `strlen` on one does not stop where that string does,
 * and a JSON string may hold a NUL in the middle of itself besides.
 */
void ncfg_json_write_string_bytes(ncfg_json_writer_t *writer, const char *bytes, size_t length);
void ncfg_json_write_int(ncfg_json_writer_t *writer, int64_t value);
void ncfg_json_write_uint(ncfg_json_writer_t *writer, uint64_t value);
void ncfg_json_write_bool(ncfg_json_writer_t *writer, int value);
void ncfg_json_write_null(ncfg_json_writer_t *writer);

/*
 * A name and its value together.
 *
 * Here because the pair is what an object is made of, and because a name
 * written without its value is the misuse these make unwriteable rather than
 * merely detectable.
 */
void ncfg_json_write_member_string(ncfg_json_writer_t *writer, const char *name,
    const char *text);
void ncfg_json_write_member_int(ncfg_json_writer_t *writer, const char *name, int64_t value);
void ncfg_json_write_member_bool(ncfg_json_writer_t *writer, const char *name, int value);

/*
 * Whether anything went wrong -- the misuse above, or the buffer's own
 * ceiling, which is a failure of this document just as much.
 */
int ncfg_json_write_failed(const ncfg_json_writer_t *writer);

/* The first misuse as a sentence, or NULL. For a diagnostic, and for tests. */
const char *ncfg_json_write_failure(const ncfg_json_writer_t *writer);

/*
 * Whether a whole document was written: one value, everything opened closed,
 * nothing failed.
 *
 * Separate from `ncfg_json_write_failed` because an unclosed object is not
 * detectable when it happens -- only a caller that says it is finished can
 * be told that it is not. This is the check before the line is sent.
 */
int ncfg_json_write_done(const ncfg_json_writer_t *writer);

#endif /* NCFG_JSON_WRITE_H */
