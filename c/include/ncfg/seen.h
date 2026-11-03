/*
 * seen.h -- the hosts this machine sees, written down in fuzznet's records
 * (project.md 10.591, 10.664, 10.666).
 *
 * WHO WRITES, AND WHERE
 *   The daemon, as the holder settled on 2026-11-02: it is root that runs
 *   netcfgd and observes the stations and leases, so it is root that writes
 *   down what it saw. **Into the face of the daemon's own fuzznet store**
 *   (0308, project.md 10.669): netcfgd is a node but holds no claim, since
 *   it does not run fuzznet's loop yet, so a record goes where any
 *   follower's would -- to the socket the store's `face` file names, read
 *   again before each write (`ncfg_seen_use_store`). Without a node, the
 *   socket the environment or fuzznetd's default names. When netcfgd runs
 *   the loop itself it is the face, and writes in-process; the policy below
 *   carries over either way.
 *
 * WHAT A RECORD SAYS
 *   KEY is `seen/<interface>/<mac>`, the MAC with dashes because a colon is
 *   not in fuzznet's key grammar: what fuzznet's own retention selects by,
 *   `text=seen/wlan0/` an interface and `aa-bb-cc` a manufacturer. VALUE is
 *   `station` for one associated to an access point, `lease ADDRESS [NAME]`
 *   for one holding a lease from netcfgd's DHCP server.
 *
 * HOW OFTEN
 *   fuzznet keeps every record written, so writing each pass would fill a
 *   month's bucket with one station. A record is written when a host is first
 *   seen, when what is said about it changes, and once a day while it stays --
 *   so "seen" also says "still seen". Retention is fuzznet's rules, not this.
 *
 * WHEN NOBODY IS LISTENING
 *   An ordinary machine runs no fuzznetd, and that is not a fault: nothing is
 *   written, a line says so once, and a minute passes before it is asked
 *   again.
 */
#ifndef NCFG_SEEN_H
#define NCFG_SEEN_H

#include "ncfg/observed.h"

#include <stddef.h>
#include <stdint.h>

/* fuzznet's setting-key bound. */
#define NCFG_SEEN_KEY_MAX 64u
/* fuzznet's setting-value bound. */
#define NCFG_SEEN_VALUE_MAX 256u
/* A host still seen is written again after this long. */
#define NCFG_SEEN_REFRESH_SECONDS (24u * 60u * 60u)
/* How long after fuzznetd did not answer before it is asked again. */
#define NCFG_SEEN_RETRY_SECONDS 60u
/* The most hosts remembered between passes; the oldest goes first. */
#define NCFG_SEEN_HELD_MAX 4096u

/* Reading seen back: pages of `list record` asked in one pass, how long a
 * finished listing stands before the next begins, and the most stations
 * kept. A page is one connection and holds about eight records. */
#define NCFG_SEEN_READ_PAGES 32u
#define NCFG_SEEN_READ_SECONDS 60u
#define NCFG_SEEN_STATIONS_MAX 4096u

typedef struct ncfg_seen ncfg_seen_t;

/* A recorder writing to `socket_path`, or to fuzznetd's own default for this
 * user where it is NULL: `$XDG_RUNTIME_DIR/fuzznet/fuzznetd.sock`, else
 * `/tmp/fuzznet-UID/fuzznetd.sock`. NULL on out of memory. */
ncfg_seen_t *ncfg_seen_new(const char *socket_path);

/*
 * Write to whichever process is the face of the fuzznet store at `dir`, as
 * that store's `face` file names it (fuzznet sec 827), read again before each
 * write since the face can change. This is the daemon's node's store
 * (`ncfg/node.h`): netcfgd holds no claim, so a record it makes goes to the
 * face as any follower's would. A store no process serves is the absence the
 * header describes -- nothing is written and a line says so once.
 *
 * It replaces fuzznetd's guessed default socket, which a service started
 * without `$XDG_RUNTIME_DIR` would look for in another place from the one a
 * fuzznetd started in a shell serves on. An explicit `NCFG_FUZZNET_SOCKET`
 * is not overridden: the daemon does not call this where one is given.
 */
void ncfg_seen_use_store(ncfg_seen_t *seen, const char *dir);
/*
 * This process is now its store's face (project.md 10.676): the socket the
 * `face` file names is served by the thread that would be blocked writing to
 * it, so nothing is written or read through it -- until fuzznet takes a local
 * request in-process. Said once in the log. `here` 0 undoes it, for a face
 * whose loop has ended.
 */
void ncfg_seen_face_is_here(ncfg_seen_t *seen, int here);
void ncfg_seen_free(ncfg_seen_t *seen);

/*
 * Write what `observed` shows that is new, changed or due again. `now` is
 * seconds since the epoch. Returns the number of records written; a fuzznetd
 * that is not there writes none and is not an error.
 */
size_t ncfg_seen_record(ncfg_seen_t *seen, const ncfg_observed_t *observed, uint64_t now);

/* `seen/<interface>/<mac>`, or 0 where either cannot be written in fuzznet's
 * key grammar (a-z 0-9 . _ / -, at most 64 bytes). */
int ncfg_seen_key(const char *interface, const char *mac, char *out, size_t out_size);

/*
 * READING IT BACK (10.667, 10.674): the stations ever recorded as seen, by
 * any host whose records this store holds, for an allow list's prefix to
 * expand against. Asked of the same face the records are written to, with
 * fuzznet's `list record`, every host's records.
 *
 * **Bounded per pass, and never a partial answer.** A listing is paged --
 * a reply holds about eight records -- so at most NCFG_SEEN_READ_PAGES are
 * asked in one pass and the next pass carries on from there. The stations
 * a listing finds replace the previous set only once it has finished, so
 * a set is always one whole listing, and a read that stops partway (no
 * face, a refusal) leaves the last whole one standing. A new listing
 * starts NCFG_SEEN_READ_SECONDS after one finished.
 *
 * Only keys `seen/<interface>/<mac>` are read, and the MAC is given back
 * as the kernel and hostapd spell it, lowercase with colons.
 */
void ncfg_seen_read(ncfg_seen_t *seen, uint64_t now);

/* The stations the last whole listing found, sorted, borrowed until the
 * next `ncfg_seen_read`; NULL with a zero count before one has finished. */
char *const *ncfg_seen_stations(const ncfg_seen_t *seen, size_t *count);

/* The listing parsed: each MAC a `seen/` key names, added to `out` (sorted
 * and unique, at most `room`). Returns the records the reply says it shows,
 * or -1 where it is not `ok FROM SHOWN MORE ...`; `*more` from it. Public
 * so a test can hand it a reply without a fuzznetd. */
long ncfg_seen_parse_listing(const char *reply, char **out, size_t *count, size_t room,
    int *more);

#endif /* NCFG_SEEN_H */
