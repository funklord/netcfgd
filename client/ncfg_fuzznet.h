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
 * The pair netcfgd's nodes run under (fuzznet's `chain/service.h`): a host's
 * netcfgd and a phone's fuzznetd must agree on it to be one estate. Restated
 * here because this file is libc only; `src/node/node.c` holds it to theirs.
 */
#define NCFG_FUZZNET_SERVICE 1u
#define NCFG_FUZZNET_PRODUCT 3u

/* The port a node serves its remote hop on, where one is served at all. */
#define NCFG_FUZZNET_PORT 48090u

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

/*
 * The run directory a control socket's path says it is in, into `out`: 1 only
 * for one named `<run>/netcfgd.sock`, as a daemon names its own. A socket
 * elsewhere, a test's in /tmp, says nothing, and treating its directory as a
 * run directory would ask a stranger's fuzznet (10.690).
 */
int ncfg_fuzznet_run_dir_of(const char *socket_path, char *out, size_t out_size);

/*
 * A control request asked of the daemon on this machine over fuzznet, `call
 * ask` on its node's socket (0309, 10.712), the answer as its socket would
 * have written it. 1 with `*out` malloc'd.
 *
 * **0 with `*nothing_ran` set is the only failure a caller may retry on the
 * control socket**: no node, nobody listening, or fuzznet itself refusing the
 * call, so the daemon cannot have seen the request. Clear means it may have,
 * and sending an `apply` a second time would arm a second window. That failure
 * is the caller's to report.
 */
int ncfg_fuzznet_ask_here(const char *run_dir, const char *request, char **out, size_t *length,
    int *nothing_ran, char *err, size_t err_size);

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
 * This machine's daemon's events, held (0309, 10.729): `get events net` on the
 * fuzznet socket in `run_dir`, fuzznet's sec 899. The descriptor, blocking, past
 * its `ok events`; -1 with a sentence. Read by whoever the `net` permit lets,
 * which follows the `observe` tier, and `any` has no such grant.
 */
int ncfg_fuzznet_events_hold(const char *run_dir, char *why, size_t why_size);

/*
 * One line of that stream as the event line the control socket would have sent,
 * into `out`: 1, or 0 for a line that is not one of netcfgd's events. **Only the
 * kind arrives** -- no interface, no `ok`, no seconds -- so the summary says what
 * happened and that the rest is in the status, which is how fuzznet means a stream
 * to be read.
 */
int ncfg_fuzznet_event_json(const char *line, char *out, size_t out_size);

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

/* An event's subject as fuzznet carries it: lower-case letters and hyphens,
 * at most 16, and its NUL. */
#define NCFG_FUZZNET_SUBJECT_TEXT 17u

/*
 * Another node's events since `from` (10.703): fuzznet's own procedure,
 * `call events at HOST FROM` (its sec 866), whose answer is `NEXT FIRST
 * [SUBJECT NAME]...`, escaped inside the call's own `ok`, from the last 256
 * that node published. The subjects into
 * `subjects`, at most `cap`, their number in `*count`; `*next`, where to ask
 * from next time; `*first`, the oldest it still holds. **A FIRST above
 * `from` means some were missed, and a NEXT below it that the node
 * restarted**: either way the caller re-reads the node's status rather than
 * trusting what it had. 1, or 0 with a sentence.
 */
int ncfg_fuzznet_events_at(const char *socket, const char *host, size_t from, size_t *next,
    size_t *first, char (*subjects)[NCFG_FUZZNET_SUBJECT_TEXT], size_t cap, size_t *count,
    char *err, size_t err_size);

/*
 * The `NEXT FIRST [SUBJECT NAME]...` that `events` answers, already
 * unescaped, read on its own (10.705) so a fuzzer can reach it: it is another
 * host's text. As `ncfg_fuzznet_events_at` returns it.
 */
int ncfg_fuzznet_events_read(const char *text, size_t length, size_t *next, size_t *first,
    char (*subjects)[NCFG_FUZZNET_SUBJECT_TEXT], size_t cap, size_t *count, char *err,
    size_t err_size);

/*
 * Whether `target` names many hosts rather than one (10.708): `estate`, or
 * `group=NAME` with NAME of 1..32 of a-z 0-9 `._-`, as fuzznet names a group.
 */
int ncfg_fuzznet_target_is_many(const char *target);

/*
 * A request carried out on many hosts (10.708): fuzznet's propagation, `call
 * do at TARGET REQUEST` (its sec 872), a request longer than a line staged
 * with `askpart` at the same target first. Its answer, `ok TOTAL ANSWERED`
 * and a `KEY16:STATUS` for each host -- ok, unknown, denied, failed or
 * silent, and `+N` for rows that did not fit -- into `rows`. 1, or 0 with a
 * sentence. **This host is not among them**: fuzznet does not call its own.
 */
int ncfg_fuzznet_do_many(const char *socket, const char *target, const char *request,
    char *rows, size_t rows_size, char *err, size_t err_size);

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
