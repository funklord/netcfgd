/*
 * ncfg_fuzznet.h -- netcfgd's daemon over fuzznet's local socket: one line
 * asked, its %XX escape, the store's face, and the daemon's status a page at
 * a time put back together (project.md 10.664, 10.688, 10.689).
 *
 * WHY IT IS IN client/
 *   0311 puts everything internal on fuzznet's protocols, and three programs
 *   read the daemon's status: `ncfg`, the GUI and the NM shim. The last two
 *   link this library and not libncfg, so the one copy lives here and `c/`
 *   compiles it in as it does `ncfg_json.c` -- a bounded conversation kept
 *   twice is two places for a wait to go unbounded. Plain C and libc only,
 *   for the reason `ncfg_client.h` gives.
 *
 * THE CONVERSATION
 *   One connection per line: the line and a newline, and one line back.
 *   **Bounded at both ends**: the send and the reply each wait at most
 *   `wait_ms`, because neither the daemon's pass nor a person's window may
 *   stall on a fuzznet that is wedged, and a line longer than the reply
 *   buffer is no answer. The escape is fuzznet's (its sec 668): a byte up to
 *   a space, a `%`, a comma or DEL as `%` and two hex digits, lower case,
 *   read back in either case.
 *
 * THE PAGE
 *   `ok TOTAL FROM COUNT DIGEST`, a newline, and COUNT bytes of the status's
 *   JSON from offset FROM: paged, because fuzznet's replies have caps this
 *   side does not choose -- a remote answer's, and one local reply line once
 *   escaped -- and a busy router's status is tens of kilobytes.
 *
 *   **DIGEST is of the whole status the page was cut from** (FNV-1a, 64
 *   bits, sixteen lower-case hex digits). Each page is cut from the status as
 *   it is when that page is asked, and a router's status moves between two
 *   asks: pages of two statuses joined blindly make JSON that fails to parse
 *   at best and, at the same length, one that parses as a status that never
 *   existed. It says which status, and protects nothing -- the transport is
 *   fuzznet's, authenticated already.
 */
#ifndef NCFG_FUZZNET_H
#define NCFG_FUZZNET_H

#include <stddef.h>
#include <stdint.h>

/*
 * Ask `line` (with or without its newline) of the socket at `path`. 1 with
 * the reply in `reply`, its newline taken off; 0 with a sentence in `why`,
 * and `*silent` set where nobody answered -- no socket, nothing listening, no
 * reply within the wait -- rather than an answer that did not fit.
 */
int ncfg_fuzznet_ask(const char *path, const char *line, char *reply, size_t reply_size,
    int wait_ms, int *silent, char *why, size_t why_size);

/*
 * The longest line fuzznet's local socket reads, its newline included: its
 * `FZN_REQUEST_MAX` (`local/vocabulary.h`). Far less than a reply's 1024,
 * which is the number 10.694 first sized requests by -- measured when a 600-
 * byte piece came back `malformed a request is at most 512 bytes`.
 */
#define NCFG_FUZZNET_REQUEST_MAX 512u

/* `text` escaped into `out`, NUL-ended: 0 where it does not fit. */
int ncfg_fuzznet_escape(const char *text, char *out, size_t out_size);

/*
 * `length` bytes of escaped `text` back into `out`, at most `out_size`: the
 * bytes' count, or -1 for a malformed escape or an output that does not fit.
 * Not NUL-ended, since an answer's bytes may hold a NUL.
 */
long ncfg_fuzznet_unescape(const char *text, size_t length, char *out, size_t out_size);

/*
 * The socket of the process serving the store at `store`, as the store's
 * `face` file names it -- one line, an absolute path, as fuzznetd writes it
 * -- into `out`. 0 where there is no face, or it cannot be read.
 */
int ncfg_fuzznet_face(const char *store, char *out, size_t out_size);

/*
 * Where to ask the daemon whose run directory is `run_dir`, into `out`: the
 * store's face where `<run_dir>/node` names a store this caller can read,
 * since the face names whatever socket fuzznet was given; else
 * `<run_dir>/fuzznet.sock`, where a daemon puts it unless told otherwise
 * (10.683), and the one a caller who cannot read root's store can reach.
 */
int ncfg_fuzznet_daemon_socket(const char *run_dir, char *out, size_t out_size);

/* A whole status this large is refused rather than gathered. */
#define NCFG_STATUS_PAGE_TOTAL_MAX (64u * 1024u * 1024u)

typedef struct {
	size_t      total;
	size_t      from;
	size_t      count;
	uint64_t    digest;
	const char *bytes; /* the COUNT bytes, inside the page read */
} ncfg_status_page_t;

/* FNV-1a, 64 bits, of `length` bytes. */
uint64_t ncfg_status_page_digest(const char *bytes, size_t length);

/* `page`, `length` bytes, read as a page: 1 with its fields, 0 where it is
 * not one -- a refusal (`denied ...`), a header out of shape, or COUNT that
 * is not the bytes after it. */
int ncfg_status_page_read(const char *page, size_t length, ncfg_status_page_t *out);

/* One page from `from`, its bytes into `page` (at most `cap`) and their
 * count into `*length`: 1, or 0 with a sentence where none came. */
typedef int (*ncfg_status_page_ask_fn)(void *context, size_t from, char *page, size_t cap,
    size_t *length, char *err, size_t err_size);

/*
 * Every page, asked through `ask`, joined: 1 with the whole status in
 * `*out` (malloc'd, NUL-ended, the caller's to free) and its length, its
 * digest having matched every page's. A page of another status starts the
 * gathering again, at most four times, since a status that moves faster than
 * it can be read is not going to be read whole. 0 with a sentence otherwise.
 */
int ncfg_status_pages_join(ncfg_status_page_ask_fn ask, void *context, char **out,
    size_t *length, char *err, size_t err_size);

/*
 * The daemon's status over fuzznet: the `status` procedure (`call status
 * FROM`, fuzznet's sec 853) on `ncfg_fuzznet_daemon_socket(run_dir)`, every
 * page joined, as `ncfg_status_pages_join` says. 1 with the JSON in `*out`.
 */
int ncfg_fuzznet_status(const char *run_dir, char **out, size_t *length, char *err,
    size_t err_size);

/*
 * This user's own fuzznetd, where it serves when given no `--socket` and a
 * client looks when told nowhere (fuzznet's sec 663): `$XDG_RUNTIME_DIR/
 * fuzznet/fuzznetd.sock`, or `/tmp/fuzznet-UID/fuzznetd.sock` where that
 * variable is unset or not absolute. Into `out`; 0 where it does not fit.
 */
int ncfg_fuzznet_user_socket(char *out, size_t out_size);

/*
 * Another node's status, asked as an operator of its estate (0311, 10.691):
 * through the fuzznetd at `socket` -- this user's own, the third of
 * fuzznet's three models -- `call status at HOST FROM`, `host` the node's
 * key in hex, every page joined as `ncfg_status_pages_join` says. That node
 * answers by its own `remote` block. 1 with the JSON in `*out`.
 */
int ncfg_fuzznet_status_at(const char *socket, const char *host, char **out, size_t *length,
    char *err, size_t err_size);

/*
 * Any control-socket request of another node (0312, 10.694): `request` the
 * socket's own JSON line, without its newline, carried as `call ask at HOST
 * FROM REQUEST` through the fuzznetd at `socket`, every page joined. 1 with
 * the node's answer line in `*out`, as its socket would have written it.
 *
 * **A request longer than one fuzznet line is sent in pieces** (10.695):
 * `call askpart at HOST TOTAL OFFSET DIGEST PIECE` in order from 0, each
 * answered `ok HAVE TOTAL`, and then `ask` names it as `@DIGEST`. That node
 * keeps the pieces for this caller only until it is whole and run, and
 * refuses one past 256 KiB.
 */
int ncfg_fuzznet_ask_at(const char *socket, const char *host, const char *request, char **out,
    size_t *length, char *err, size_t err_size);

/* A host's key in hex, and its NUL. */
#define NCFG_FUZZNET_KEY_TEXT 65u

/*
 * The members of this user's estate, as the fuzznetd at `socket` knows them
 * (`list peer [FROM]`, every page): the keys `ncfg_fuzznet_status_at` takes,
 * into `keys`, at most `cap`, their number in `*count`. A contact -- a peer
 * paired for a share, marked `,contact` -- is no member and is left out;
 * the node itself is not its own peer. 1, or 0 with a sentence, including
 * for more members than `cap` rather than a list cut short.
 */
int ncfg_fuzznet_members(const char *socket, char (*keys)[NCFG_FUZZNET_KEY_TEXT], size_t cap,
    size_t *count, char *err, size_t err_size);

#endif /* NCFG_FUZZNET_H */
