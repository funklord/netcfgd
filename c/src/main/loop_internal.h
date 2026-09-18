/*
 * loop_internal.h -- the descriptors a daemon owns, and the loop over them.
 *
 * WHY THIS IS IN `src/main/` AND NOT IN THE DAEMON MODULE
 *   `reconcile_pass.c` is a pass: hand it a wake and the world's seams and it
 *   does one round. It deliberately owns no descriptor, which is what makes
 *   every ordering in it a list a test reads back rather than a claim. The
 *   other half of that sentence is that somebody has to own the netlink
 *   socket, the configuration watch, `/dev/rfkill`, the supplicant's control
 *   directory and the window's timer -- and 0263 says that somebody is a
 *   `main`, because owning descriptors and deciding an exit status are the two
 *   things this directory exists for.
 *
 * THE SPLIT, WHICH IS THE SAME ONE THE DAEMON MODULE MAKES
 *   `daemon_wake.c` is what the loop **decides**. Every call in it takes
 *   values and answers one: what a `revents` mask means, what `poll`'s return
 *   meant, how long to wait, whether a source that has failed keeps its place,
 *   which wake a ready descriptor folds into, whether a round is worth a pass.
 *   It opens nothing and reads nothing.
 *
 *   `daemon_loop.c` is the **order**: wait, take what is queued, collapse the
 *   burst, drive `ncfg_reconcile_pass` once, answer what was waiting. The one
 *   thing in it that needs a live descriptor is the `poll` itself.
 *
 *   `daemon_watchers.c` is the five real sources. It is the only file here
 *   that opens anything.
 *
 *   The reason is the reason it is everywhere else in this port: a loop around
 *   `poll` is a loop nothing can test, and the ways this shape fails -- a
 *   descriptor that spins at 100% because nobody drops it, a burst that
 *   starves the pass, a window whose timer fires while a pass is running, a
 *   signal that lands between the check and the wait -- are none of them
 *   visible to a test that drives the happy path.
 *
 * WHAT IS NOT HERE
 *   Answering a request. `ncfg_daemon_answer_fn` says what a handler owes and
 *   the loop implements none of it: the mailbox below carries a request across
 *   to the loop's thread so that `ncfg_reconcile_pass` can see what is waiting
 *   -- a pending window defers the reconcile, an explicit apply releases the
 *   `--no-apply-on-start` hold -- and then hands it straight to the seam the
 *   caller supplied.
 */
#ifndef NCFG_MAIN_LOOP_INTERNAL_H
#define NCFG_MAIN_LOOP_INTERNAL_H

#include "ncfg/daemon.h"
#include "ncfg/lock.h"
#include "ncfg/netlink.h"
#include "ncfg/proto.h"
#include "ncfg/rfkill.h"
#include "ncfg/supplicant.h"
#include "ncfg/watch.h"

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* ------------------------------------------------------------------------ *
 * The numbers
 * ------------------------------------------------------------------------ */

/*
 * How long a quiet loop waits before looking anyway.
 *
 * The Rust's `TICK_MS`, and its comment is the reason: the watchers are
 * event-driven, so this is a backstop rather than the mechanism -- it catches
 * anything neither netlink nor the configuration watch reports, and it is what
 * makes a missed event cost seconds rather than for ever.
 *
 * **It is measured from the top of the round rather than from the last wait.**
 * The Rust takes it from `recv_timeout`, which restarts on every message, so a
 * machine producing a netlink event every four seconds never ticks at all --
 * the backstop is switched off by exactly the chattiness it is meant to
 * survive. Here the deadline is computed once and the wait is whatever is left
 * of it, so the tick happens on schedule however loud the machine is.
 */
#define NCFG_MAIN_TICK_MS 5000

/*
 * How many times a burst is looked at again before the pass runs anyway.
 *
 * Collapsing is the point: bringing an interface up produces a run of netlink
 * messages and re-reading once per message would make the daemon's cost scale
 * with the kernel's chattiness. But "keep collapsing while anything is ready"
 * is a loop with no floor -- one descriptor that is permanently readable and
 * whose drain takes nothing off it means the pass never runs, and a daemon
 * that stopped reconciling while spinning at 100% is the worst of both. So the
 * collapse is bounded and whatever is left is the next round's, which is
 * microseconds away.
 */
#define NCFG_MAIN_DRAIN_ROUNDS 64

/*
 * How many failing looks a source is given before it is taken out of the set.
 *
 * `POLLERR` is not always fatal -- a socket reports a queued error once and is
 * fine afterwards -- so a source that errors is read rather than dropped, and
 * the read is what clears it. What must not happen is the two-line version of
 * this: a descriptor that reports `POLLERR` for ever, is never read and is
 * never dropped, so `poll` returns instantly on every call. That is the
 * ordinary way a daemon comes to spin at 100% CPU, and it does it silently.
 */
#define NCFG_MAIN_SOURCE_PATIENCE 3

/*
 * How many events one radio may hand over before the others get a turn.
 *
 * The Rust's `EVENT_BURST`, for its reason: a burst is a dozen or so -- a
 * disconnect, a scan, its results, a reconnect -- so this is well clear of one
 * and still bounds what a radio stuck in a loop can cost the rest.
 */
#define NCFG_MAIN_EVENT_BURST 64

/*
 * How many roams one round carries.
 *
 * **Not collapsed the way a netlink burst is**: two roams are two events and a
 * station that moved twice moved twice, which is what `daemon.h` says about
 * the list travelling beside the wake. What a bound buys is that a radio
 * flapping cannot make one round's allocation the operator's to choose;
 * whatever does not fit is counted and said, rather than dropped in silence.
 */
#define NCFG_MAIN_ROAMS_MAX 16

/* `a0:a4:7f:23:9a:cf` and a NUL, which is what `supplicant.h` asks for. */
#define NCFG_MAIN_BSSID_MAX 18

/* How many radios are watched at once. A machine has one, or two. */
#define NCFG_MAIN_RADIOS_MAX 8

/* Seven fixed sources -- netlink, the configuration, `/dev/rfkill`, the
 * supplicant directory, the window timer, the pipe a waiting request is
 * announced on and the pipe a signal writes to -- and a descriptor per
 * radio. */
#define NCFG_MAIN_SOURCES_MAX (7u + (size_t)NCFG_MAIN_RADIOS_MAX)

/*
 * How many requests may be waiting for the loop at once.
 *
 * `daemon.h` says the answer seam is called with the server's lock held, so
 * exactly one connection can be inside it at a time and the true depth is one.
 * This is margin rather than a capacity estimate, and a mailbox that filled
 * anyway refuses by name rather than blocking the loop -- a queue that grows
 * because the loop is slow is a daemon that answers nothing while looking
 * busy.
 */
#define NCFG_MAIN_PENDING_MAX 8

/* ------------------------------------------------------------------------ *
 * What woke the loop
 * ------------------------------------------------------------------------ */

/* Which of the things a daemon watches a descriptor belongs to. */
typedef enum {
	/* Netlink, in the observed multicast groups. */
	NCFG_MAIN_SOURCE_KERNEL = 0,
	/* Something wrote in the configuration directory. */
	NCFG_MAIN_SOURCE_CONFIG,
	/*
	 * `/dev/rfkill`.
	 *
	 * It folds into the same wake netlink does, which is the Rust's
	 * arrangement: a kill switch is the machine moving, and what the loop does
	 * about it is look again. There is no separate wake for it because there
	 * is no separate answer.
	 */
	NCFG_MAIN_SOURCE_RFKILL,
	/* The supplicant's control directory: a radio appearing or leaving. */
	NCFG_MAIN_SOURCE_RADIO_DIR,
	/* One attached radio's control socket. */
	NCFG_MAIN_SOURCE_RADIO,
	/* The commit-confirm window's timer. */
	NCFG_MAIN_SOURCE_TIMER,
	/*
	 * The pipe a waiting request is announced on.
	 *
	 * Separate from the stop pipe rather than one pipe carrying two kinds of
	 * byte, because the two are read by different code at different moments
	 * and a loop that had to tell them apart by value would have one place
	 * where a request could be read as a shutdown. Two descriptors cost two
	 * integers.
	 */
	NCFG_MAIN_SOURCE_REQUEST,
	/* The pipe a signal handler writes one byte to. */
	NCFG_MAIN_SOURCE_STOP
} ncfg_main_source_kind_t;

/* A word for the log. Never NULL. */
const char *ncfg_main_source_name(ncfg_main_source_kind_t kind);

/* One station that moved, with the text this round owns. */
typedef struct {
	char interface[NCFG_LINK_NAME_MAX + 1u];
	char bssid[NCFG_MAIN_BSSID_MAX];
} ncfg_main_roam_text_t;

/*
 * Everything one round took off its descriptors.
 *
 * Declare it `= {0}` per round. It owns nothing: the roam text is storage
 * inside it and the `ncfg_reconcile_roam_t` list handed to the pass points at
 * that storage, which is why the pass is driven before this goes out of scope.
 */
typedef struct {
	ncfg_reconcile_wake_t wake;
	ncfg_main_roam_text_t roams[NCFG_MAIN_ROAMS_MAX];
	size_t                roam_count;
	/* Roams this round could not carry. Counted rather than dropped quietly:
	 * a number nobody can act on is still better than a station that moved and
	 * nothing anywhere saying so. */
	size_t                roams_missed;
	/* Something asked the loop to stop. */
	int                   stopping;
	/* The supplicant directory moved, so the radios are worth looking at
	 * again. */
	int                   rescan;
} ncfg_main_harvest_t;

/* Add one, or say it did not fit. Always answers what the caller should do
 * next, which is carry on either way. */
void ncfg_main_harvest_roam(ncfg_main_harvest_t *harvest, const char *interface,
    const char *bssid);

/* ------------------------------------------------------------------------ *
 * The decisions -- daemon_wake.c, which opens nothing
 * ------------------------------------------------------------------------ */

/*
 * What a descriptor's `revents` said.
 *
 * Five answers and not two, for `ncfg_wire_step_t`'s reason: a boolean cannot
 * tell "there is something to read" from "this descriptor will never say
 * anything again", and folding them is how a loop comes either to spin on a
 * hung-up pipe or to stop watching a socket that merely had a queued error.
 */
typedef enum {
	/* Nothing happened on it. */
	NCFG_MAIN_READY_NOTHING = 0,
	/*
	 * There is something to read.
	 *
	 * **`POLLIN` wins over `POLLHUP`**, and that is the whole of why this is
	 * not a chain of `if`s at the call site: a writer that queued bytes and
	 * then closed sets both, and a loop that saw the hang-up first would drop
	 * the source with its last events still in the buffer. The hang-up is
	 * still there on the next round, with nothing left to read.
	 */
	NCFG_MAIN_READY_DATA,
	/* An error is queued on it. Read it out; the read is what clears it. */
	NCFG_MAIN_READY_ERRORED,
	/* The far end is gone. Nothing will ever arrive again. */
	NCFG_MAIN_READY_ENDED,
	/* It is not an open descriptor at all. */
	NCFG_MAIN_READY_CLOSED
} ncfg_main_ready_t;

ncfg_main_ready_t ncfg_main_readiness(short revents);
const char       *ncfg_main_readiness_name(ncfg_main_ready_t ready);

/*
 * Whether a source keeps its place in the set.
 *
 * `failures` is how many rounds in a row it has answered something other than
 * data, counted by the caller. A hang-up and a closed descriptor are answered
 * no at once, because there is nothing to wait for and `poll` returns
 * instantly on both -- which is the 100%-CPU spin, arriving through the
 * politest-looking code in the file.
 */
int ncfg_main_source_survives(ncfg_main_ready_t ready, unsigned failures);

/*
 * Whether a *subscriber's* descriptor says the client has gone.
 *
 * **Not `ncfg_main_readiness`, and the difference is `POLLIN`.** A source is
 * read by whoever owns it, so data has to win over the hang-up or a burst is
 * dropped with its last records unread. A subscriber's descriptor is never
 * read by anybody: events are written to it and nothing else. So `POLLIN` on
 * one is either a client talking into a stream that does not listen, or the
 * end of file a close leaves behind -- and a close sets `POLLIN|POLLHUP`
 * together, for ever. Reading it the source's way would keep exactly the
 * descriptor this exists to drop.
 *
 * Readable-only, with no hang-up and no error, is therefore **not** gone: it
 * is somebody sending bytes down a stream, which is rude and not a reason to
 * stop telling them what is happening.
 *
 * A value here rather than a condition in the loop, which is this file's rule:
 * what a `revents` means is a decision, and the decisions live where they can
 * be checked without a descriptor.
 */
int ncfg_main_subscriber_ended(short revents);

/* What `poll` came back with. */
typedef enum {
	/* At least one descriptor has something to say. */
	NCFG_MAIN_WAIT_READY = 0,
	/* Nothing arrived in time, which is the loop's own backstop. */
	NCFG_MAIN_WAIT_TICKED,
	/*
	 * A signal arrived mid-syscall, so ask again.
	 *
	 * **Not a failure and not a tick.** 0233 is what taking `EINTR` for a
	 * failure cost once already -- a machine kept a previous network's search
	 * domain for fifty-two minutes because `SIGCHLD` landed on a watcher's
	 * receive two seconds before a network change. netcfgd forks a child every
	 * time it runs a hook, so this arrives on an ordinary day. It cannot spin:
	 * every one of them is a signal that really arrived, and the wait that
	 * follows is what is left of the same deadline rather than a fresh one.
	 */
	NCFG_MAIN_WAIT_AGAIN,
	NCFG_MAIN_WAIT_FAILED
} ncfg_main_wait_t;

/* `answered` is what `poll` returned and `code` what it left in `errno`. */
ncfg_main_wait_t ncfg_main_wait_meant(int answered, int code);

/*
 * How long to wait, in milliseconds, given a deadline and the clock.
 *
 * Clamped into `[0, NCFG_MAIN_TICK_MS]`. A deadline already past is zero
 * rather than a negative number, which `poll` reads as "wait for ever" -- the
 * one arithmetic slip in this file that would stop a daemon dead, since a loop
 * with no descriptor ready would never tick again.
 */
int ncfg_main_timeout_until(uint64_t deadline_ms, uint64_t now_ms);

/* Whether the burst is worth looking at once more. `round` is how many have
 * been spent on it already. */
int ncfg_main_drains_again(unsigned round);

/*
 * Which wake a ready descriptor of this kind folds into.
 *
 * 1 with the wake in `*out`; 0 for a kind that is not news -- a radio's socket
 * and the supplicant directory, whose events travel as a list and as a rescan,
 * and the stop pipe, which is not something to reconcile about.
 */
int ncfg_main_woke_for(ncfg_main_source_kind_t kind, ncfg_woke_t *out);

/*
 * Whether this round is worth a pass.
 *
 * A round that woke only to drop a descriptor that had hung up has nothing to
 * tell `ncfg_reconcile_pass` and nothing to ask it: running one would re-read
 * the kernel and rebuild a plan because a pipe closed. The tick is what makes
 * that safe -- the backstop comes round in at most five seconds whatever
 * happened here.
 */
int ncfg_main_passes(const ncfg_reconcile_wake_t *wake, size_t roams, size_t requests);

/*
 * Whether a `CONNECTED` is a roam, given what this radio last reported.
 *
 * The Rust's `is_roam`, and its reasoning is 0239's: a different address is
 * not a roam, because `roam` promises "a station moved to a different access
 * point **on the same network**" and a machine leaving home wifi for the
 * office satisfies the address half while contradicting the network half. The
 * event carries the configured network's id beside the address, so the pair
 * decides what the address alone was standing in for.
 *
 * `had_last` is 0 before this radio has reported anything, which is an
 * association rather than a roam: there is nothing to have moved from, and
 * firing then would run the hook on every boot. `has_network` is 0 where the
 * id could not be read, which answers no rather than falling back to comparing
 * addresses -- an unreadable id is not a network established as the same one,
 * and the cost of erring this way is a hook that does not fire.
 */
int ncfg_main_is_roam(int had_last, uint32_t last_network, const char *last_bssid,
    int has_network, uint32_t network, const char *bssid);

/*
 * Whether a request has to reach the loop before it is answered.
 *
 * Every one does, and this exists to say so in one place rather than to
 * choose. The Rust queues every request into the same channel the watchers
 * feed and serves them in the loop body, which is what keeps one thread inside
 * the daemon's state; a seam that answered some requests on the connection's
 * own thread would be a second writer of that state, and `server.c`'s lock
 * would be the only thing between them.
 */
int ncfg_main_request_waits(const ncfg_proto_request_t *request);

/* ------------------------------------------------------------------------ *
 * The sources
 * ------------------------------------------------------------------------ */

/*
 * Take everything queued on one descriptor, and fold it into the harvest.
 *
 * 0 with a sentence where the source itself failed, which the loop counts
 * against `NCFG_MAIN_SOURCE_PATIENCE` rather than treating as fatal: a daemon
 * that stopped watching the kernel because one read failed is a daemon that
 * stopped.
 */
typedef int (*ncfg_main_drain_fn)(void *context, ncfg_main_harvest_t *harvest, char *err,
    size_t err_size);

/* One thing the loop watches. */
typedef struct {
	ncfg_main_source_kind_t kind;
	/*
	 * The descriptor, or -1.
	 *
	 * **-1 is a source that is asked rather than waited on**, and the
	 * configuration watch under `--poll-config` is the whole of why it exists:
	 * there is no descriptor because the question is answered by walking the
	 * filesystem. Inventing a pipe nobody writes to would make the two shapes
	 * look alike and leave the fall-back reporting nothing for ever.
	 */
	int                     fd;
	ncfg_main_drain_fn      drain;
	void                   *context;
	/* Looks in a row that came to nothing -- a readiness that was not data,
	 * or a drain that failed. Cleared by any look that read something.
	 * `ncfg_main_source_survives` is what reads it. */
	unsigned                failures;
	/* A path or an interface, for the line that says it was dropped.
	 * Borrowed, and it outlives the set. */
	const char             *what;
} ncfg_main_source_t;

typedef struct {
	ncfg_main_source_t at[NCFG_MAIN_SOURCES_MAX];
	size_t             count;
} ncfg_main_sources_t;

void ncfg_main_sources_init(ncfg_main_sources_t *sources);
int  ncfg_main_sources_add(ncfg_main_sources_t *sources, const ncfg_main_source_t *source,
    char *err, size_t err_size);
/* Take the one at `at` out, keeping the order of the rest. */
void ncfg_main_sources_forget(ncfg_main_sources_t *sources, size_t at);
/* Where the first source of this kind is, or the count where there is none. */
size_t ncfg_main_sources_find(const ncfg_main_sources_t *sources, ncfg_main_source_kind_t kind);

/* ------------------------------------------------------------------------ *
 * The mailbox: a request on its way to the loop's thread
 * ------------------------------------------------------------------------ */

/*
 * Where a request waits while the loop looks at it.
 *
 * **The request is borrowed and not copied**, which is safe for exactly one
 * reason and it is written here rather than left to be worked out: the
 * connection's thread is blocked inside `ncfg_main_mailbox_answer` for the
 * whole of the request's stay, so the decoded message it points into is alive
 * and nothing else can free it. A queue that let the caller walk away would
 * have to own every string, and `ncfg_proto_request_t` is a flat struct of
 * borrowed text precisely so that nothing does.
 *
 * Treat every field as private.
 */
typedef struct {
	const ncfg_proto_request_t *request;
	const ncfg_peer_t          *peer;
	ncfg_arrival_t              arrival;
	ncfg_buf_t                 *out;
	char                       *err;
	size_t                      err_size;
	/* A connection waiting to become a subscriber, or -1 for an ordinary
	 * request. The two share a slot because they share everything that
	 * matters about waiting -- a thread parked until the loop has looked --
	 * and a second array would be a second thing to shut, to bound and to
	 * answer on the way down. `request` is NULL for one of these, which is
	 * what keeps `ncfg_main_mailbox_take` from handing a subscription to the
	 * pass as though it were something to reconcile against. */
	int                         stream_fd;
	int                         in_use;
	/* The loop has taken it and is looking at it. */
	int                         taken;
	int                         answered;
	int                         result;
} ncfg_main_waiting_t;

typedef struct {
	pthread_mutex_t       lock;
	pthread_cond_t        settled;
	ncfg_main_waiting_t   at[NCFG_MAIN_PENDING_MAX];
	/* The descriptor a waiting request is announced on. Borrowed from the
	 * loop's stop pipe's sibling; -1 leaves the tick to find it. */
	int                   wake;
	/* Shut: every waiter is refused rather than left holding a connection. */
	int                   shut;
	/* What actually answers, once the loop has seen it. NULL refuses by
	 * name -- see `ncfg_main_mailbox_answer`. */
	ncfg_daemon_answer_fn answer;
	/* What takes a subscribed connection, on the loop's thread. NULL refuses
	 * by name too, and the caller keeps the descriptor. */
	ncfg_daemon_stream_fn stream;
	/* Shared by both, for `ncfg_daemon_serve_t`'s reason: they are two halves
	 * of one answer and two contexts would be two states. */
	void                 *answer_context;
} ncfg_main_mailbox_t;

int  ncfg_main_mailbox_open(ncfg_main_mailbox_t *mailbox, ncfg_daemon_answer_fn answer,
    ncfg_daemon_stream_fn stream, void *answer_context, int wake, char *err, size_t err_size);

/*
 * Refuse everything waiting, and everything that arrives afterwards.
 *
 * Every waiter is *answered* rather than abandoned, which is the point: a
 * connection thread left on the condition never returns, so its slot is held
 * for the life of the process and its client is told nothing at all --
 * `server.c` calls that indistinguishable from a crash.
 */
void ncfg_main_mailbox_shut(ncfg_main_mailbox_t *mailbox);

/*
 * Release what it holds.
 *
 * **Shut it, then stop the server, then close this** -- in that order, and
 * the order is a requirement rather than tidiness. This destroys a mutex and a
 * condition, and a thread that is still inside `ncfg_main_mailbox_answer`
 * would be about to lock one of them; what guarantees there is no such thread
 * is `ncfg_daemon_server_stop`, which joins every connection thread before it
 * returns. Shutting first is what lets that join finish, since a waiter is
 * released by being answered.
 */
void ncfg_main_mailbox_close(ncfg_main_mailbox_t *mailbox);

/*
 * `ncfg_daemon_answer_fn`, to be installed in `ncfg_daemon_serve_t::answer`.
 *
 * `context` is the mailbox. Hands the request to the loop and waits for the
 * answer; refuses by name where the mailbox is shut or full, which is still an
 * answer and is what a refusal has to be (`answer.c`).
 */
int ncfg_main_mailbox_answer(void *context, const ncfg_proto_request_t *request,
    const ncfg_peer_t *peer, ncfg_arrival_t arrival, ncfg_buf_t *out, char *err,
    size_t err_size);

/*
 * `ncfg_daemon_stream_fn`, to be installed in `ncfg_daemon_serve_t::stream`.
 *
 * `context` is the mailbox. **This is the crossing the subscriber list needs
 * and cannot do without**: that list holds no lock because every call on it
 * happens on the loop's thread, so a connection thread adding to it directly
 * would race the pass announcing through it. The descriptor therefore waits
 * here exactly as a request does, and is handed to `stream` from inside
 * `ncfg_main_mailbox_settle`.
 *
 * **The descriptor is taken only where this answers 1.** A mailbox that is
 * shut or full refuses by name and the caller still owns it, which is what
 * lets `server.c` close its copy on a refusal without wondering whether the
 * loop has it.
 *
 * It settles **after** the round's pass, never before, which is deliberate
 * and is the Rust's order as well: a client that asks to watch is told what
 * happens next rather than about a pass that was already running when it
 * asked.
 */
int ncfg_main_mailbox_stream(void *context, int fd, char *err, size_t err_size);

/*
 * Take what is waiting, as an array the pass can read.
 *
 * The structs are copied by value; the text inside them stays the waiter's,
 * which is alive for the reason above. Answers how many were taken.
 */
size_t ncfg_main_mailbox_take(ncfg_main_mailbox_t *mailbox, ncfg_proto_request_t *out,
    size_t out_max);

/* Answer everything that was taken, through the seam, and let the waiters
 * go. */
void ncfg_main_mailbox_settle(ncfg_main_mailbox_t *mailbox);

/* ------------------------------------------------------------------------ *
 * The loop
 * ------------------------------------------------------------------------ */

/* What one round did. `report` may be NULL; declare it `= {0}`. */
typedef struct {
	ncfg_reconcile_wake_t   wake;
	size_t                  roam_count;
	size_t                  roams_missed;
	size_t                  request_count;
	/* How many times it waited. One is an ordinary round; anything more is
	 * a burst being collapsed, and `NCFG_MAIN_DRAIN_ROUNDS` is the ceiling. */
	unsigned                drains;
	/* `EINTR`s waited through. */
	unsigned                interrupted;
	/* Sources taken out of the set this round, and how many are left. */
	size_t                  dropped;
	size_t                  sources;
	/* Subscribers whose client had gone, swept this round. Reported so that a
	 * test can see the sweep happened rather than inferring it from a count
	 * that went down for either of two reasons. */
	size_t                  pruned;
	/* Something asked the loop to stop. */
	int                     stopping;
	/* The pass ran, and what it did. */
	int                     passed;
	ncfg_reconcile_report_t pass;
} ncfg_main_round_report_t;

/*
 * Everything one round is driven with.
 *
 * Every member may be NULL and the round says what a missing one costs, which
 * is `ncfg_reconcile_world_t`'s bargain applied one layer out: a run with no
 * `loop` collapses its wake, reports it and drives no pass; one with no
 * mailbox sees no requests; one with no `refresh` never looks for a new radio.
 * That is what lets a test install exactly the sources its case is about.
 */
/* Declared further down, beside the calls on it -- this struct holds only a
 * pointer, and moving the whole section up here to satisfy the compiler would
 * put the list's rules a long way from the list. */
typedef struct ncfg_main_subscribers ncfg_main_subscribers_t;

typedef struct {
	ncfg_reconcile_t    *loop;
	ncfg_main_sources_t *sources;
	ncfg_main_mailbox_t *mailbox;
	/*
	 * The streams events are written to, swept once a round for the ones
	 * whose client has gone. NULL sweeps nothing, which is this struct's
	 * bargain -- and is what a run with no `monitor` seam already has.
	 *
	 * The same list the world announces through, and it must be: two would be
	 * two answers to how many streams are open, and the bound is the thing
	 * that refuses the seventeenth.
	 */
	ncfg_main_subscribers_t *subscribers;
	/*
	 * Monotonic milliseconds. NULL is `CLOCK_MONOTONIC`.
	 *
	 * A seam for `ncfg_confirm_expired_at`'s reason, pointed at the clock the
	 * deadline is measured against: "a burst that spans a tick still ticks" is
	 * checked by moving a number rather than by waiting five seconds in a
	 * suite.
	 */
	uint64_t           (*ticks)(void *context);
	void                *ticks_context;
	/* Look for radios that have appeared or gone. NULL never looks. */
	void               (*refresh)(void *context, ncfg_main_sources_t *sources);
	void                *refresh_context;
} ncfg_main_run_t;

/*
 * One round: wait, take what is queued, collapse it, pass, answer.
 *
 * 0 with a sentence only where the round could not be carried out at all --
 * which is `poll` itself failing, and nothing else. A source that failed is
 * counted and possibly dropped, a pass that refused is reported, and both
 * leave the loop running, because a daemon that stopped on one bad read is a
 * daemon that stopped.
 */
int ncfg_main_round(const ncfg_main_run_t *run, ncfg_main_round_report_t *report, char *err,
    size_t err_size);

/*
 * Rounds until something asks it to stop.
 *
 * What stops it is a byte on the stop source, which is what a signal handler
 * writes and what `ncfg_main_watchers_stop` writes. A round that fails stops it
 * too, and says why.
 */
int ncfg_main_serve(const ncfg_main_run_t *run, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * The real descriptors -- daemon_watchers.c
 * ------------------------------------------------------------------------ */

/* What to open, and where. Every path is the caller's and none has a default:
 * `testdir.h`'s rule, and the reason is that the default here is the machine
 * this is built on. */
typedef struct {
	/* The writable configuration directory. `conf.d` beneath it is watched
	 * too, and the factory layer is not -- it is part of the image and cannot
	 * change while the daemon runs. */
	const char *config_dir;
	/* `/dev/rfkill`, or somewhere else. NULL watches no kill switch. */
	const char *rfkill_device;
	/* The supplicant's control directory. NULL watches no radio. */
	const char *supplicant_dir;
	/* Subscribe to the kernel's observed multicast groups. */
	int         kernel;
	/* Watch the configuration by mtime rather than by inotify. */
	int         poll_config;
} ncfg_main_watch_t;

/* One radio whose events are being read. Private. */
typedef struct {
	ncfg_supplicant_client_t *client;
	char                      interface[NCFG_LINK_NAME_MAX + 1u];
	/* `(device, inode)` of the socket this connection was made to, which is
	 * what tells a supplicant that restarted from one that is simply quiet.
	 * 0240. */
	uint64_t                  device;
	uint64_t                  inode;
	/* What this radio last reported, which is the pair a roam is defined by. */
	int                       has_last;
	uint32_t                  last_network;
	char                      last_bssid[NCFG_MAIN_BSSID_MAX];
} ncfg_main_radio_t;

/*
 * Everything a daemon has open. Treat every field as private.
 *
 * `ncfg_main_watchers_close` is the one `ncfg_x_free` for it, and closing one
 * that was never opened is nothing.
 */
typedef struct {
	ncfg_netlink_t      netlink;
	int                 has_netlink;
	ncfg_watch_t        watch;
	int                 has_watch;
	ncfg_rfkill_t       rfkill;
	int                 has_rfkill;
	ncfg_inotify_t      radio_dir;
	int                 has_radio_dir;
	/* The directory said something moved, so the next refresh reads it.
	 * Set at startup too, which is what makes the first refresh the scan. */
	int                 radios_stale;
	char                supplicant_dir[512];
	ncfg_main_radio_t   radios[NCFG_MAIN_RADIOS_MAX];
	size_t              radio_count;
	/* The commit-confirm window's timer. */
	int                 timer;
	/* Written to by a signal handler and by `ncfg_main_watchers_stop`. */
	int                 stop_read;
	int                 stop_write;
	/* Written to when a request is put in the mailbox, so that the loop does
	 * not sit out the rest of its five seconds with somebody waiting. */
	int                 nudge_read;
	int                 nudge_write;
	ncfg_main_sources_t sources;
} ncfg_main_watchers_t;

void ncfg_main_watchers_init(ncfg_main_watchers_t *watchers);

/*
 * Open what `what` asks for, and build the source set.
 *
 * **A source that cannot be opened is a line in the log and not a refusal**,
 * for the reason the Rust gives about each of them in turn: a machine with no
 * radio has no `/dev/rfkill`, a container may refuse inotify, and a daemon
 * that would not start because one of the five was unavailable would be
 * refusing to watch the four that are. What is said each time is what is lost
 * by it. 0 with a sentence only where nothing at all could be opened, not even
 * the pipe a signal writes to.
 */
int ncfg_main_watchers_open(ncfg_main_watchers_t *watchers, const ncfg_main_watch_t *what,
    char *err, size_t err_size);

/* Close everything and release what it holds. */
void ncfg_main_watchers_close(ncfg_main_watchers_t *watchers);

/* Ask the loop to stop. Async-signal-safe, which is the point: this is what a
 * `SIGTERM` handler calls. */
void ncfg_main_watchers_stop(ncfg_main_watchers_t *watchers);

/*
 * `ncfg_reconcile_world_t::expiry`: arm the window's timer for `seconds`.
 *
 * `context` is the watchers. A timer that cannot be armed is a line in the log
 * and nothing else, because the tick closes the window within five seconds
 * anyway -- which is 0234's arrangement, where the Rust discarded the result of
 * the spawn and a timer that never started left a window open for ever.
 */
void ncfg_main_watchers_expiry(void *context, uint32_t seconds);

/*
 * `ncfg_main_run_t::refresh`: attach to radios that have appeared, and let go
 * of those that have not.
 *
 * `context` is the watchers. Cheap on an ordinary round -- it is a `stat` per
 * watched radio and nothing else -- and a directory read only where the
 * directory said it moved.
 */
void ncfg_main_watchers_refresh(void *context, ncfg_main_sources_t *sources);

/*
 * Install handlers for `SIGTERM` and `SIGINT` that write to `watchers`.
 *
 * **The self-pipe rather than a flag**, and that is the whole reason this is
 * not three lines in `main`: a handler that sets a flag races the loop, which
 * checks the flag and then sleeps five seconds in `poll` with the flag already
 * set. A byte in a descriptor cannot be missed, because the descriptor is in
 * the wait.
 *
 * `ncfg_main_signals_restore` puts back what was there, which matters because
 * a test runs this in its own process.
 */
int  ncfg_main_signals_watch(ncfg_main_watchers_t *watchers, char *err, size_t err_size);
void ncfg_main_signals_restore(void);

/* ------------------------------------------------------------------------ *
 * Who is listening -- daemon_world.c
 * ------------------------------------------------------------------------ */

/*
 * How many monitor streams are carried at once.
 *
 * Generous for what subscribes -- a tray, a window, a TUI is three -- and a
 * bound rather than a list that grows, for the reason the Rust's does not
 * have one: `monitor` needs only the `observe` tier, which
 * `control { observe = "any" }` opens to every local user, and the only
 * pruning the Rust does is inside a broadcast. A converged machine broadcasts
 * nothing, so a client that subscribes and hangs up sits in the list until
 * something happens. Here the list cannot outgrow this, and the refusal to
 * add a subscriber past it is an answer the caller can send.
 */
#define NCFG_MAIN_SUBSCRIBERS_MAX 16

/*
 * The descriptors an event is written to.
 *
 * **Every call on one of these happens on the loop's thread**, which is what
 * lets it hold no lock: the pass announces from inside `ncfg_main_round`, and
 * a subscription arrives the way every other request does -- through the
 * mailbox, which hands it to the seam while the round is inside
 * `ncfg_main_mailbox_settle`. That is the Rust's arrangement as well, where
 * `Command::Subscribe` crosses the same channel the requests do.
 *
 * Each descriptor is this list's own: `ncfg_main_subscribers_add` is handed
 * one to keep, and `ncfg_main_subscribers_close` closes every one. A caller
 * that also holds the connection duplicates it first, so that the server
 * closing a connection leaves this list writing to a descriptor it still owns
 * -- which fails with `EPIPE` and drops the subscriber, rather than writing
 * into whatever the number has since been reused for.
 */
typedef struct ncfg_main_subscribers {
	int    at[NCFG_MAIN_SUBSCRIBERS_MAX];
	size_t count;
	/* Subscribers dropped for refusing an event, over this list's life. For
	 * a caller that wants to say so, and for a test that would otherwise have
	 * to infer it from a count that went down. */
	size_t dropped;
} ncfg_main_subscribers_t;

void ncfg_main_subscribers_init(ncfg_main_subscribers_t *subscribers);

/*
 * Take a descriptor to write events to. **It becomes this list's.**
 *
 * The descriptor is put in non-blocking mode, which is the property that
 * matters: the loop writes from the thread that reconciles, so a client that
 * stopped reading must not be able to stall the daemon. 0 with a sentence
 * where the list is full or the descriptor could not be set, and the caller
 * still owns it in that case -- a failed add that had closed it would leave a
 * connection thread writing a refusal to a number it no longer has.
 */
int ncfg_main_subscribers_add(ncfg_main_subscribers_t *subscribers, int fd, char *err,
    size_t err_size);

/* Close every one and leave the list usable and empty. */
void ncfg_main_subscribers_close(ncfg_main_subscribers_t *subscribers);

/*
 * Drop the subscribers whose far end has gone, and answer how many went.
 *
 * **The gap this closes is named in 0263 and is the list's own.** Until this
 * existed the only pruning was inside `ncfg_main_subscribers_tell`, so a
 * subscriber was found to be dead by a write to it failing -- and a converged
 * machine announces nothing at all. A client that subscribed and hung up
 * therefore held one of `NCFG_MAIN_SUBSCRIBERS_MAX` places until something
 * happened, which on a quiet machine is never, and the seventeenth `monitor`
 * was refused over sixteen streams nobody was reading.
 *
 * It asks `poll` with a zero timeout about its own descriptors rather than
 * being handed a `revents` the loop gathered, and the reason is what a
 * subscriber *is*: it has no drain, no kind and no place in the source set,
 * so putting sixteen of them into the loop's own wait would make the daemon
 * wake for a hang-up it can do nothing about beyond this. Once a round is
 * enough -- the loop ticks at `NCFG_MAIN_TICK_MS` whatever else happens, so a
 * dead stream is carried for at most one tick instead of for ever.
 *
 * Counted into `dropped` exactly as a failed write is, because from the list's
 * point of view they are the same event: a subscriber that is no longer there.
 * On the loop's thread like every other call on this list, which is what lets
 * it hold no lock.
 */
size_t ncfg_main_subscribers_prune(ncfg_main_subscribers_t *subscribers);

/*
 * Write one event to each, dropping the ones that would not take it.
 *
 * Encoded once rather than per subscriber. A descriptor that is full, that has
 * gone or that took only part of the line is dropped: a partial line would
 * frame as half a message and the next event would be read as its tail, so
 * there is no "try again later" that a reader could survive. That is the
 * Rust's `retain` over `try_send`, with the same reasoning and a different
 * failure to detect.
 */
void ncfg_main_subscribers_tell(ncfg_main_subscribers_t *subscribers,
    const ncfg_proto_event_t *event);

/*
 * One event as the JSON object a monitor stream carries, appended to `out`.
 *
 * `{"response":"event","event":"<kind>",...}` with the members that kind
 * carries, which is `proto.h`'s decoder read backwards -- it decodes every
 * response and encodes none, so an encoder belongs beside whatever produces
 * the thing. This one produces events, so it is here. No newline: the caller
 * frames it.
 */
int ncfg_main_event_encode(const ncfg_proto_event_t *event, ncfg_buf_t *out, char *err,
    size_t err_size);

/* ------------------------------------------------------------------------ *
 * The world the pass reaches through -- daemon_world.c
 * ------------------------------------------------------------------------ */

/*
 * How many hooks an executor is given to check a script against.
 *
 * `ncfg_kernel_set_hooks` takes a flat array and the document keeps one list
 * per interface and one per network, so somebody has to join them. A hook that
 * did not fit is not run -- `ncfg_hook_run` refuses where it has nothing to
 * check against -- which is the safe direction, and the count that did not fit
 * is said out loud rather than left to be noticed as a hook that stopped
 * firing.
 */
#define NCFG_MAIN_HOOKS_MAX 64

/*
 * How many interfaces one contention check asks about.
 *
 * The claims are the interfaces netcfgd is running a backend on, which is a
 * handful on any machine and is bounded here so that a configuration naming a
 * thousand interfaces cannot make a per-tick allocation the operator's to
 * choose. Past it the rest are not asked about, which is the same direction
 * the narrowing skip takes: not asking is safer than asking wrongly.
 */
#define NCFG_MAIN_CLAIMS_MAX 32

/* How long an executor waits for the apply lock before giving up, which is
 * the Rust's `APPLY_PATIENCE`: long enough for an ordinary apply, which is a
 * few netlink calls and whatever a hook does, and short enough that a wedged
 * one is reported rather than inherited. */
#define NCFG_MAIN_APPLY_PATIENCE_MS 30000

/*
 * What `ncfg_reconcile_world_t::context` carries.
 *
 * **One struct because that seam has one `void *` for every member**, and the
 * four this program implements want different things: an executor wants the
 * apply lock and a netlink socket, giving a contended radio back wants those
 * *and* where to look for other daemons, and announcing wants the subscriber
 * list. Written as three contexts they could not be installed at once; written
 * as one they share the thing that actually needs sharing, which is the open
 * executor -- giving a radio back opens one through the same two calls the
 * pass does, so "ask who is contending before opening one" is a property of
 * one function rather than a convention two of them keep.
 *
 * Treat every field as private. `ncfg_main_world_open` fills it and
 * `ncfg_main_world_close` is its one free.
 */
typedef struct {
	/* Where `apply.lock` is. Borrowed, and it outlives this. */
	const char              *run_dir;
	/*
	 * What the executor is given to check a hook against, and the document it
	 * was read from. Borrowed: `apply.h` says an executor must not outlive
	 * the document, and open-to-close is inside one call of the pass.
	 */
	const ncfg_daemon_state_t *state;
	/* Where a contention check reads. Resolved once, for
	 * `ncfg_observe_source_machine`'s reason: a seam that read the
	 * environment per tick would answer differently as the daemon ran. */
	ncfg_contention_where_t  contention;
	/* Who is listening. NULL is nobody, which is an ordinary daemon with no
	 * monitor attached. */
	ncfg_main_subscribers_t *subscribers;
	/* Whose timer a window's expiry is armed on. NULL leaves the tick to
	 * close a window, which costs seconds rather than the window. */
	ncfg_main_watchers_t    *watchers;
	/* What one open executor holds, and whether there is one. At most one at
	 * a time: a second would ask `flock` for a lock this process already
	 * holds on another description and wait out the whole patience for it. */
	ncfg_lock_t              lock;
	ncfg_kernel_t           *kernel;
	int                      open;
	ncfg_hook_ref_t          hooks[NCFG_MAIN_HOOKS_MAX];
	size_t                   hook_count;
	/* How long to wait for the apply lock. A field so that a test does not
	 * have to wait thirty seconds to see the refusal. */
	long                     patience_ms;
} ncfg_main_world_t;

/*
 * Point one at a machine. Opens nothing: an executor is per operation.
 *
 * `run_dir` and `state` are borrowed and must outlive this. `subscribers` may
 * be NULL.
 */
int ncfg_main_world_open(ncfg_main_world_t *world, const char *run_dir,
    const ncfg_daemon_state_t *state, ncfg_main_subscribers_t *subscribers,
    ncfg_main_watchers_t *watchers, char *err, size_t err_size);

/* Release what it holds, including an executor left open by a failure path. */
void ncfg_main_world_close(ncfg_main_world_t *world);

/*
 * Fill in the four seams this program implements, and the context.
 *
 * The other members -- the hook runner, the portal probe, the expiry timer,
 * the clock and the resolv machine -- are the caller's, because each of them
 * belongs to something else: two are the daemon module's own implementations
 * and the third is the watchers'. `out` is not zeroed, so the caller fills it
 * in whatever order it likes.
 */
void ncfg_main_world_seams(ncfg_main_world_t *world, ncfg_reconcile_world_t *out);

/* `ncfg_reconcile_world_t::executor_open`. `context` is the world. */
int ncfg_main_world_executor_open(void *context, ncfg_executor_t *out, char *err,
    size_t err_size);
/* `ncfg_reconcile_world_t::executor_close`. */
void ncfg_main_world_executor_close(void *context, ncfg_executor_t *executor);
/* `ncfg_reconcile_world_t::announce`. Nothing where no list was given. */
void ncfg_main_world_announce(void *context, const ncfg_proto_event_t *event);

/*
 * `ncfg_reconcile_world_t::expiry`, forwarded to the watchers' timer.
 *
 * **This is the clearest argument for one context struct.** That seam has one
 * `void *` for all of its members, the timer is the watchers' and the executor
 * is this file's -- so a world that did not carry the watchers could not have
 * both installed at once, and a daemon would be choosing between arming a
 * window on time and being able to change the machine.
 */
void ncfg_main_world_expiry(void *context, uint32_t seconds);

/*
 * `ncfg_reconcile_world_t::release_contended`.
 *
 * **It asks who is contending before it opens an executor**, which is 0263's
 * divergence and 10.169's defect: the Rust opens one as soon as netcfgd runs
 * any backend at all, so every laptop with wifi takes the global apply lock
 * and a netlink socket every five seconds to find out there is nothing to give
 * back. It also asks whether this build's executor can carry out the stop
 * before taking the lock, which is the same ordering one step further.
 */
int ncfg_main_world_release_contended(void *context, ncfg_daemon_state_t *state, char *err,
    size_t err_size);

/*
 * The interfaces netcfgd is running a backend on, as claims a contention check
 * can be made with.
 *
 * Only those: a contended interface netcfgd is not touching is the ordinary
 * coexistence case, and saying anything about it here would repeat the warning
 * the plan already carries.
 *
 * **An interface whose kernel index does not fit is left out**, which is
 * 0263's narrowing rule pointed at a claim: every daemon `contention` knows
 * about keys its state by index, so a truncated one matches a contender
 * against an interface nobody named -- and what netcfgd does about a match is
 * stop its own backend. Not asking is the safe direction.
 *
 * Answers how many were taken, up to `out_max`. The names are borrowed from
 * the document and live as long as it does.
 */
size_t ncfg_main_claims_of(const ncfg_daemon_state_t *state, ncfg_interface_claim_t *out,
    size_t out_max);

/*
 * The hooks of a document, flattened into `out`.
 *
 * What did not fit is counted in `*missed`, which may be NULL. Interfaces
 * first and then networks, which is the order the planner visits them in --
 * this build emits `hook.run` for interface hooks only, and a network's are
 * collected anyway so that the day the wifi passes land nothing has to
 * remember to come back here.
 */
size_t ncfg_main_hooks_of(const ncfg_document_t *document, ncfg_hook_ref_t *out, size_t out_max,
    size_t *missed);

/* ------------------------------------------------------------------------ *
 * What answers a request -- daemon_answer.c
 * ------------------------------------------------------------------------ */

/*
 * Everything the dispatcher needs, as `ncfg_daemon_answer_fn::context`.
 *
 * Borrowed, all of it. `where` is `daemon.h`'s three wifi directories, which
 * have no defaults for that header's reason: the real netcfgd runs on the
 * machine these tests are built on and its wifi is real.
 */
typedef struct {
	ncfg_daemon_state_t     *state;
	ncfg_wifi_where_t        where;
	/* Where `@secret:` names resolve, and where a stored certificate is
	 * materialised for a supplicant to open. Neither has a default. */
	const char              *secrets_dir;
	const char              *certs_dir;
	/* Where a `monitor` lands, and who is told when a reload is asked for.
	 * NULL tells nobody and refuses a subscription by name. */
	ncfg_main_subscribers_t *subscribers;
} ncfg_main_desk_t;

/*
 * `ncfg_daemon_answer_fn`, to be installed in `ncfg_daemon_serve_t::answer`
 * -- through `ncfg_main_mailbox_answer`, which is what parks the connection's
 * thread until the loop has driven a pass with the request in hand.
 *
 * `context` is an `ncfg_main_desk_t *`. Every request kind is either answered
 * or refused with a sentence naming it; there is no arm that says nothing.
 */
int ncfg_main_answer(void *context, const ncfg_proto_request_t *request,
    const ncfg_peer_t *peer, ncfg_arrival_t arrival, ncfg_buf_t *out, char *err,
    size_t err_size);

/*
 * `ncfg_daemon_stream_fn`, reached through `ncfg_main_mailbox_stream` so that
 * it runs on the loop's thread.
 *
 * `context` is an `ncfg_main_desk_t *`, and all this does is put the
 * descriptor in the desk's subscriber list -- which is the whole of what
 * `monitor` is. A desk with no list refuses by name rather than closing a
 * connection somebody is waiting on events from.
 */
int ncfg_main_stream(void *context, int fd, char *err, size_t err_size);

/*
 * Why this build cannot answer a request kind, or NULL where it can.
 *
 * Reachable on its own so that the whole table is a thing a test walks rather
 * than thirty-two cases somebody remembers to write. **A refusal names the
 * request and says what is missing**, because a daemon answering `error` with
 * nothing in it reads as a request it did not recognise -- which is the
 * confusion `daemon_main.c` refused to start over.
 */
const char *ncfg_main_answer_unported(ncfg_proto_request_kind_t kind);

#endif /* NCFG_MAIN_LOOP_INTERNAL_H */
