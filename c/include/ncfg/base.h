/*
 * base.h -- what every file in the C port agrees about.
 *
 * **Three conventions, and they are the whole of the calling discipline.**
 * They are not invented here: `client/ncfg_client.h` has used them against a
 * live daemon since M4, and a port that answered the same questions
 * differently would make the two halves of one program argue about what a
 * failure is.
 *
 *   * A call that can fail returns **1 for success and 0 for failure**, and
 *     takes `char *err, size_t err_size` as its last two arguments. Not
 *     `errno`, not a negative code: the failures here are sentences an
 *     operator reads -- "`eth0` is not a name the kernel would take for a
 *     link" -- and an integer cannot carry one.
 *   * A call that returns a pointer returns `NULL` for failure, with the same
 *     error buffer.
 *   * Every aggregate this library hands out has an `ncfg_x_free` beside it,
 *     and freeing something that was never filled in is nothing. The Rust it
 *     replaces had ownership in the type system; here it is a rule, so it is
 *     written down and tested rather than assumed.
 *
 * `NCFG_ERROR_MAX` is the buffer every caller declares. It is the client's
 * number, for the reason above.
 */
#ifndef NCFG_BASE_H
#define NCFG_BASE_H

#include <stdarg.h>
#include <stddef.h>

/* Long enough for a compiler diagnostic with a file, a line and a sentence of
 * help, which is the longest thing that travels this way. */
#define NCFG_ERROR_MAX 512

/*
 * Fill in an error buffer, or do nothing where the caller passed none.
 *
 * **A caller that does not want the message passes NULL**, and every failure
 * path calls this unconditionally rather than testing first -- which is what
 * stops a path from being written without a message at all. Truncation is
 * silent and deliberate: a message that does not fit is still better than a
 * failure with nothing said, and the buffer is sized so it does not happen.
 */
void ncfg_error_set(char *err, size_t err_size, const char *format, ...);

/* The same, for a caller that already has a `va_list`. */
void ncfg_error_setv(char *err, size_t err_size, const char *format, va_list args);

#endif /* NCFG_BASE_H */
