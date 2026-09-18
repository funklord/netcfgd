/*
 * buf.h -- a growable byte buffer, with a ceiling.
 *
 * **Everything that builds text in this port builds it here**: a rendered
 * configuration block, a JSON document, a netlink message, a line for the
 * socket. The Rust it replaces used `String` and `Vec<u8>`, which grow until
 * the allocator says no; this is the same thing with two differences that are
 * the point rather than the cost.
 *
 * **It has a limit, and the limit is the caller's.** A daemon that builds a
 * message from what a client sent it has to bound the result, or a client can
 * ask for a document the daemon cannot survive rendering. `netcfgd-proto`
 * bounds its line at `MAX_LINE` for exactly that reason, and a buffer with no
 * ceiling would move that bound somewhere nobody can see it.
 *
 * **A failed allocation is a value, not a crash.** `ncfg_buf_failed` stays
 * true once anything has failed, and every append after that is a no-op -- so
 * a caller may write twenty appends and check once, which is what makes the
 * error handling readable enough to actually be done. Reading a buffer that
 * failed gives the empty string rather than a truncated one, because half a
 * configuration block is worse than none.
 */
#ifndef NCFG_BUF_H
#define NCFG_BUF_H

#include <stddef.h>

typedef struct {
	char  *data;
	size_t length;
	size_t capacity;
	size_t limit;
	/* Set by the first failure and never cleared: out of memory, or the
	 * limit reached. See the header comment for why this is sticky. */
	int    failed;
} ncfg_buf_t;

/*
 * Start a buffer that will not grow past `limit` bytes.
 *
 * `limit` of 0 means the default ceiling, which is generous enough for any
 * document netcfgd compiles and small enough that a runaway is an error rather
 * than a machine with no memory left.
 */
void ncfg_buf_init(ncfg_buf_t *buf, size_t limit);

/* Release what it holds, and leave it usable and empty. */
void ncfg_buf_free(ncfg_buf_t *buf);

/* Append bytes, text, one byte, or a formatted string. Each is a no-op on a
 * buffer that has already failed. */
void ncfg_buf_add(ncfg_buf_t *buf, const void *bytes, size_t length);
void ncfg_buf_add_text(ncfg_buf_t *buf, const char *text);
void ncfg_buf_add_char(ncfg_buf_t *buf, char one);
void ncfg_buf_addf(ncfg_buf_t *buf, const char *format, ...);

/*
 * Whether anything went wrong, which is the one check a caller owes.
 *
 * Checked once after a run of appends rather than after each: the sticky flag
 * is what makes that safe, and a caller that checks every call is a caller
 * that stops checking.
 */
int ncfg_buf_failed(const ncfg_buf_t *buf);

/*
 * The bytes, NUL-terminated, or "" where the buffer failed.
 *
 * Never NULL, so a caller can print it without a guard -- and never a partial
 * result, because a half-written block that looks whole is the failure this
 * refuses to hand out.
 */
const char *ncfg_buf_text(const ncfg_buf_t *buf);

/* Hand the bytes over, leaving the buffer empty. NULL where it failed, and
 * the caller owns what comes back. */
char *ncfg_buf_take(ncfg_buf_t *buf, size_t *length_out);

#endif /* NCFG_BUF_H */
