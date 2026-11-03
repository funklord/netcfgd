/*
 * fuzznet_line.h -- one line asked of a fuzznet local socket, and its %XX
 * escape (project.md 10.664, 10.688).
 *
 * WHY ONE COPY
 *   The seen recorder writes records over this conversation, and `ncfg
 *   status` reads the daemon's status over it (`call status FROM`). Two
 *   copies of a bounded socket conversation are two places for a wait to go
 *   unbounded, so both use this.
 *
 * THE CONVERSATION
 *   One connection per line: the line and a newline, and one line back.
 *   **Bounded at both ends**: the connect's send and the reply each wait at
 *   most `wait_ms`, because neither the daemon's pass nor a person's command
 *   may stall on a fuzznet that is wedged, and a line longer than the reply
 *   buffer is no answer.
 *
 * THE ESCAPE IS fuzznet's (its sec 668): a byte up to a space, a `%`, a comma
 *   or DEL written as `%` and two hex digits, lower case, read back in either
 *   case.
 */
#ifndef NCFG_FUZZNET_LINE_H
#define NCFG_FUZZNET_LINE_H

#include <stddef.h>

/*
 * Ask `line` (with or without its newline) of the socket at `path`. 1 with
 * the reply in `reply`, its newline taken off; 0 with a sentence in `why`,
 * and `*silent` set where nobody answered -- no socket, nothing listening, no
 * reply within the wait -- rather than an answer that did not fit.
 */
int ncfg_fuzznet_ask(const char *path, const char *line, char *reply, size_t reply_size,
    int wait_ms, int *silent, char *why, size_t why_size);

/*
 * The socket of the process serving the store at `store`, as the store's
 * `face` file names it -- one line, an absolute path, as fuzznetd writes it --
 * into `out`. 0 where there is no face, or it cannot be read.
 */
int ncfg_fuzznet_face(const char *store, char *out, size_t out_size);

/* `text` escaped into `out`, NUL-ended: 0 where it does not fit. */
int ncfg_fuzznet_escape(const char *text, char *out, size_t out_size);

/*
 * `length` bytes of escaped `text` back into `out`, at most `out_size`:
 * the bytes' count, or -1 for a malformed escape or an output that does not
 * fit. Not NUL-ended, since an answer's bytes may hold a NUL.
 */
long ncfg_fuzznet_unescape(const char *text, size_t length, char *out, size_t out_size);

#endif /* NCFG_FUZZNET_LINE_H */
