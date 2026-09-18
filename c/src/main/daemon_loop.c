/*
 * daemon_loop.c -- the order the descriptors are acted on in.
 *
 * **Nothing in this file decides anything.** Every rule it applies is a call
 * into `daemon_wake.c`, and the only thing in it that needs a live descriptor
 * is the `poll` itself. That is `reconcile_pass.c`'s arrangement one layer
 * out, and it is taken for the same reason: the interesting things about a
 * loop like this are not reachable from a test that drives the happy path.
 *
 * THE ORDER, AND WHY EACH STEP IS WHERE IT IS
 *   1. **Look for radios that have appeared**, before the wait rather than
 *      after it. A supplicant that started while the last pass was running is
 *      one whose first events are already queued, and attaching after the wait
 *      would mean sitting out five seconds with them in the socket.
 *   2. **Wait**, for whatever is left of a deadline computed at the top of the
 *      round. Not a fresh five seconds per wait: the Rust takes its backstop
 *      from `recv_timeout`, which restarts on every message, so a machine
 *      producing an event every four seconds never ticks -- the backstop
 *      switched off by exactly the chattiness it exists to survive.
 *   3. **Take what is queued, then look again with no timeout**, folding
 *      everything into one `ncfg_reconcile_wake_t`. Bringing an interface up
 *      produces a run of netlink messages and re-reading once per message
 *      would make the daemon's cost scale with the kernel's chattiness. The
 *      looking again is bounded, because a descriptor that is permanently
 *      ready would otherwise mean the pass never runs at all.
 *   4. **Take the waiting requests**, before the pass, because two of its
 *      decisions turn on them: a pending window defers the reconcile and an
 *      explicit apply releases the `--no-apply-on-start` hold. A request
 *      answered first would have the reconcile happen underneath it, and the
 *      window would then cover nothing.
 *   5. **Drive `ncfg_reconcile_pass` once**, with the collapsed wake.
 *   6. **Answer what was taken**, through the seam the caller supplied. The
 *      loop answers nothing itself: `ncfg_daemon_answer_fn` already says what
 *      a handler owes.
 *
 *   A comment can claim an order. `loop_test.c` reads it back: the pass is
 *   counted, the requests record when they were answered relative to it, and
 *   the assertion is the list.
 *
 * WHAT THIS FILE MAY NOT DO
 *   Exit, assert or print. It is under `src/main/` and 0263 allows a `main`
 *   both, but nothing here is a `main`: `ncfg_main_round` is called by tests
 *   and by `ncfg_main_serve`, and a round that ended the process would end
 *   the suite. What it does instead is what every other module does -- return
 *   0 with a sentence -- and the log is for the things that are neither a
 *   failure of the round nor worth nothing.
 */
#include "loop_internal.h"

#include "ncfg/log.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------------ *
 * The clock
 * ------------------------------------------------------------------------ */

/*
 * Monotonic milliseconds.
 *
 * `CLOCK_MONOTONIC` rather than the wall clock, for `client.c`'s reason: a
 * clock stepped by NTP in the middle of a wait must not make it end early or
 * never. It is a seam above this so that "a burst that spans a tick still
 * ticks" is a number a test moves rather than five seconds of a suite.
 */
static uint64_t ticks_now(void)
{
	struct timespec when;

	if (clock_gettime(CLOCK_MONOTONIC, &when) != 0) {
		/*
		 * A clock that cannot be read is not a reason to stop, and zero is
		 * the one answer that cannot make a deadline look far away: the
		 * round computes `now + tick`, so a constant here means every wait
		 * is the full tick, which is the behaviour of a loop with no
		 * backstop problem rather than one with a broken one.
		 */
		return 0u;
	}
	return (uint64_t)when.tv_sec * 1000u + (uint64_t)when.tv_nsec / 1000000u;
}

static uint64_t ticks_of(const ncfg_main_run_t *run)
{
	if (run && run->ticks) {
		return run->ticks(run->ticks_context);
	}
	return ticks_now();
}

/* ------------------------------------------------------------------------ *
 * The mailbox
 * ------------------------------------------------------------------------ */

/*
 * One byte on a pipe, and never a blocking write.
 *
 * A pipe with a byte already in it says everything a second byte would: the
 * loop is going to wake and look. So `EAGAIN` on a full pipe is success here,
 * and a blocking write would be the connection thread waiting on the loop it
 * is trying to wake.
 */
static void nudge(int fd)
{
	static const char one = 'w';

	if (fd < 0) {
		return;
	}
	(void)!write(fd, &one, 1u);
}

int ncfg_main_mailbox_open(ncfg_main_mailbox_t *mailbox, ncfg_daemon_answer_fn answer,
    ncfg_daemon_stream_fn stream, void *answer_context, int wake, char *err, size_t err_size)
{
	size_t at;

	if (!mailbox) {
		ncfg_error_set(err, err_size, "a mailbox needs somewhere to be");
		return 0;
	}
	memset(mailbox, 0, sizeof(*mailbox));
	mailbox->wake = wake;
	mailbox->answer = answer;
	mailbox->stream = stream;
	mailbox->answer_context = answer_context;
	/* Spelled out rather than left to the `memset`, because zero is a
	 * descriptor: a slot whose `stream_fd` read as 0 would be a subscription
	 * to this process' standard input that nobody asked for. */
	for (at = 0; at < (size_t)NCFG_MAIN_PENDING_MAX; at++) {
		mailbox->at[at].stream_fd = -1;
	}
	if (pthread_mutex_init(&mailbox->lock, NULL) != 0) {
		ncfg_error_set(err, err_size, "the request mailbox could not take a lock");
		return 0;
	}
	if (pthread_cond_init(&mailbox->settled, NULL) != 0) {
		(void)pthread_mutex_destroy(&mailbox->lock);
		ncfg_error_set(err, err_size, "the request mailbox could not take a condition");
		return 0;
	}
	return 1;
}

/* The refusal a waiter gets when the loop will never look at it. One sentence,
 * spelled once, because both callers of it are failure paths and a failure
 * path with its own wording is one nobody compares. */
static const char shutting_down[] =
    "the daemon is shutting down, so this request was not acted on";

void ncfg_main_mailbox_shut(ncfg_main_mailbox_t *mailbox)
{
	size_t at;

	if (!mailbox) {
		return;
	}
	(void)pthread_mutex_lock(&mailbox->lock);
	mailbox->shut = 1;
	for (at = 0; at < (size_t)NCFG_MAIN_PENDING_MAX; at++) {
		ncfg_main_waiting_t *slot = &mailbox->at[at];

		if (!slot->in_use || slot->answered) {
			continue;
		}
		/*
		 * Answered rather than abandoned. A waiter left on the condition is a
		 * connection thread that never returns, which is a slot held for the
		 * life of the process and a client that is told nothing at all --
		 * `server.c` calls that indistinguishable from a crash, and it is
		 * worse here because the daemon really is going away and could have
		 * said so.
		 */
		ncfg_error_set(slot->err, slot->err_size, "%s", shutting_down);
		slot->result = 0;
		slot->answered = 1;
	}
	(void)pthread_cond_broadcast(&mailbox->settled);
	(void)pthread_mutex_unlock(&mailbox->lock);
}

void ncfg_main_mailbox_close(ncfg_main_mailbox_t *mailbox)
{
	if (!mailbox) {
		return;
	}
	ncfg_main_mailbox_shut(mailbox);
	(void)pthread_cond_destroy(&mailbox->settled);
	(void)pthread_mutex_destroy(&mailbox->lock);
	memset(mailbox, 0, sizeof(*mailbox));
}

/*
 * A free slot, with the mailbox's lock **still held** -- or NULL with the lock
 * released and a sentence written.
 *
 * The asymmetry is spelled here because it is the kind that gets missed: the
 * caller fills the slot it is given and unlocks, and does nothing at all where
 * it is given NULL.
 *
 * Both kinds of waiter -- a request and a subscription -- meet these same two
 * walls, and a wall said in two places is a wall said two ways.
 */
static ncfg_main_waiting_t *slot_to_wait_in(ncfg_main_mailbox_t *mailbox, char *err,
    size_t err_size)
{
	size_t at;

	(void)pthread_mutex_lock(&mailbox->lock);
	if (mailbox->shut) {
		(void)pthread_mutex_unlock(&mailbox->lock);
		ncfg_error_set(err, err_size, "%s", shutting_down);
		return NULL;
	}
	for (at = 0; at < (size_t)NCFG_MAIN_PENDING_MAX; at++) {
		if (!mailbox->at[at].in_use) {
			return &mailbox->at[at];
		}
	}
	(void)pthread_mutex_unlock(&mailbox->lock);
	/*
	 * Refused rather than queued or waited for, which is the same bargain
	 * `NCFG_DAEMON_MAX_CONNECTIONS` takes: a queue that grows because the
	 * loop is slow is a daemon that answers nothing while looking busy, and
	 * every client on the other end is holding a connection open waiting for
	 * it. The sentence says what happened and what to do.
	 */
	ncfg_error_set(err, err_size,
	    "%d requests are already waiting for this daemon's loop; try again",
	    NCFG_MAIN_PENDING_MAX);
	return NULL;
}

/* Wake the loop and wait for it, then give the slot back. Called with the lock
 * released and a filled slot in hand. */
static int wait_for_the_loop(ncfg_main_mailbox_t *mailbox, ncfg_main_waiting_t *slot)
{
	int result;

	/* Outside the lock, because a write is a syscall and the loop has to be
	 * able to take this lock to answer. */
	nudge(mailbox->wake);

	(void)pthread_mutex_lock(&mailbox->lock);
	while (!slot->answered) {
		/*
		 * **The predicate is the slot and not the flag**, which is what makes
		 * a spurious wake-up harmless and what makes `shut` safe: shutting
		 * answers every waiting slot before it broadcasts, so there is no
		 * arrangement in which this loop sees `shut` and an unanswered slot
		 * and has to decide between them.
		 */
		(void)pthread_cond_wait(&mailbox->settled, &mailbox->lock);
	}
	result = slot->result;
	/* A slot nobody is in holds no descriptor, which is what lets every walk
	 * below read `stream_fd` without also asking whether the slot is live. */
	slot->stream_fd = -1;
	slot->in_use = 0;
	(void)pthread_mutex_unlock(&mailbox->lock);
	return result;
}

int ncfg_main_mailbox_answer(void *context, const ncfg_proto_request_t *request,
    const ncfg_peer_t *peer, ncfg_arrival_t arrival, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	ncfg_main_mailbox_t *mailbox = context;
	ncfg_main_waiting_t *slot;

	if (!mailbox || !request) {
		ncfg_error_set(err, err_size, "this daemon has no way to act on a request");
		return 0;
	}
	if (!ncfg_main_request_waits(request)) {
		ncfg_error_set(err, err_size, "this daemon has no way to act on a request");
		return 0;
	}
	slot = slot_to_wait_in(mailbox, err, err_size);
	if (!slot) {
		return 0;
	}
	memset(slot, 0, sizeof(*slot));
	slot->request = request;
	slot->peer = peer;
	slot->arrival = arrival;
	slot->out = out;
	slot->err = err;
	slot->err_size = err_size;
	slot->stream_fd = -1;
	slot->in_use = 1;
	(void)pthread_mutex_unlock(&mailbox->lock);

	return wait_for_the_loop(mailbox, slot);
}

int ncfg_main_mailbox_stream(void *context, int fd, char *err, size_t err_size)
{
	ncfg_main_mailbox_t *mailbox = context;
	ncfg_main_waiting_t *slot;

	if (!mailbox || fd < 0) {
		ncfg_error_set(err, err_size, "this daemon has no way to take a subscription");
		return 0;
	}
	slot = slot_to_wait_in(mailbox, err, err_size);
	if (!slot) {
		return 0;
	}
	memset(slot, 0, sizeof(*slot));
	/*
	 * No request and no buffer. `ncfg_main_mailbox_take` skips a slot with no
	 * request, which is what keeps a subscription out of the array the pass
	 * reads -- a `monitor` is not something to reconcile against, and one
	 * copied in as a request with a zeroed kind would read as a `hello`.
	 */
	slot->err = err;
	slot->err_size = err_size;
	slot->stream_fd = fd;
	slot->in_use = 1;
	(void)pthread_mutex_unlock(&mailbox->lock);

	return wait_for_the_loop(mailbox, slot);
}

size_t ncfg_main_mailbox_take(ncfg_main_mailbox_t *mailbox, ncfg_proto_request_t *out,
    size_t out_max)
{
	size_t at;
	size_t taken = 0;

	if (!mailbox || !out || out_max == 0u) {
		return 0;
	}
	(void)pthread_mutex_lock(&mailbox->lock);
	for (at = 0; at < (size_t)NCFG_MAIN_PENDING_MAX && taken < out_max; at++) {
		ncfg_main_waiting_t *slot = &mailbox->at[at];

		if (!slot->in_use || slot->taken || slot->answered || !slot->request) {
			continue;
		}
		/*
		 * Copied by value, and the text inside it is not. That is safe for
		 * exactly one reason: the waiter is blocked in
		 * `ncfg_main_mailbox_answer` until this round answers it, so the
		 * decoded message the strings point into is alive for longer than
		 * this array is. A queue that let the caller walk away would have to
		 * own every string.
		 */
		out[taken] = *slot->request;
		slot->taken = 1;
		taken++;
	}
	(void)pthread_mutex_unlock(&mailbox->lock);
	return taken;
}

void ncfg_main_mailbox_settle(ncfg_main_mailbox_t *mailbox)
{
	size_t at;

	if (!mailbox) {
		return;
	}
	for (at = 0; at < (size_t)NCFG_MAIN_PENDING_MAX; at++) {
		ncfg_main_waiting_t        *slot = &mailbox->at[at];
		const ncfg_proto_request_t *request;
		const ncfg_peer_t          *peer;
		ncfg_arrival_t              arrival;
		ncfg_buf_t                 *out;
		char                       *err;
		size_t                      err_size;
		int                         stream_fd;
		int                         result;

		(void)pthread_mutex_lock(&mailbox->lock);
		if (!slot->in_use || slot->answered) {
			(void)pthread_mutex_unlock(&mailbox->lock);
			continue;
		}
		/*
		 * A request is answered only once the round has *taken* it, because
		 * the whole point of the mailbox is that the pass sees it first. A
		 * subscription is not taken by anything -- it never reaches the pass
		 * -- so it is marked here, under the lock, for the same reason a
		 * taken request is safe to work on outside it.
		 */
		if (slot->stream_fd < 0 && !slot->taken) {
			(void)pthread_mutex_unlock(&mailbox->lock);
			continue;
		}
		slot->taken = 1;
		stream_fd = slot->stream_fd;
		request = slot->request;
		peer = slot->peer;
		arrival = slot->arrival;
		out = slot->out;
		err = slot->err;
		err_size = slot->err_size;
		/*
		 * The lock is dropped around the seam, and that is deliberate: the
		 * seam is somebody else's code and holding a lock across it is how a
		 * daemon acquires a deadlock it cannot see. The slot cannot move
		 * underneath this -- the waiter does not release it until `answered`
		 * is set, and nothing else writes a slot that is `taken`.
		 */
		(void)pthread_mutex_unlock(&mailbox->lock);

		if (stream_fd >= 0) {
			if (mailbox->stream) {
				result = mailbox->stream(mailbox->answer_context, stream_fd, err,
				    err_size);
			} else {
				/*
				 * Named, and the descriptor left alone. A refusal that had
				 * closed it would be this loop reaching into a connection it
				 * had just told the server it was not taking.
				 */
				ncfg_error_set(err, err_size,
				    "this build has no implementation of ncfg_daemon_stream_fn, so "
				    "nothing here can take a subscribed connection");
				result = 0;
			}
		} else if (mailbox->answer) {
			result = mailbox->answer(mailbox->answer_context, request, peer, arrival, out,
			    err, err_size);
		} else {
			/*
			 * Named rather than silent. A loop with no answer path is what
			 * this port has until the request dispatcher lands, and a client
			 * told "the daemon had no answer for that" with nothing else said
			 * would read it as a request the daemon did not recognise.
			 */
			ncfg_error_set(err, err_size,
			    "this build has no implementation of ncfg_daemon_answer_fn, so nothing "
			    "here can answer a request");
			result = 0;
		}

		(void)pthread_mutex_lock(&mailbox->lock);
		slot->result = result;
		slot->answered = 1;
		(void)pthread_cond_broadcast(&mailbox->settled);
		(void)pthread_mutex_unlock(&mailbox->lock);
	}
}

/* ------------------------------------------------------------------------ *
 * One round
 * ------------------------------------------------------------------------ */

/*
 * Take what one ready source has to say.
 *
 * The drain is the source's own, because what a readiness means is the
 * source's business: a netlink datagram, an inotify batch, an rfkill record
 * and a supplicant event are four different reads. What is decided here is
 * only the two things every source shares -- that a drain which failed counts
 * against the source's patience, and that a source with no drain has its
 * readiness taken as the whole of its news.
 */
static void take_from(ncfg_main_source_t *source, ncfg_main_harvest_t *harvest)
{
	char        message[NCFG_ERROR_MAX];
	ncfg_woke_t woke;

	if (!source->drain) {
		/*
		 * A source whose readiness is the news and whose descriptor somebody
		 * else consumes. Nothing here reads it, so a caller that installs one
		 * and never empties it is asking for a burst that fills every drain
		 * round -- which is bounded, and is the one shape that would otherwise
		 * stop the pass from running.
		 */
		if (ncfg_main_woke_for(source->kind, &woke)) {
			ncfg_reconcile_collapse(&harvest->wake, woke);
		}
		return;
	}
	message[0] = '\0';
	if (!source->drain(source->context, harvest, message, sizeof(message))) {
		source->failures++;
		ncfg_log_emitf("loop", NCFG_LOG_WARNING, "the %s watch could not be read: %s",
		    ncfg_main_source_name(source->kind), message);
		return;
	}
	source->failures = 0;
}

/* Say what was lost, once, as it is lost. A source dropped in silence is a
 * daemon that has stopped watching something and looks exactly like one that
 * has nothing to watch. */
static void say_dropped(const ncfg_main_source_t *source, ncfg_main_ready_t ready)
{
	ncfg_log_emitf("loop", NCFG_LOG_WARNING,
	    "the %s watch%s%s is no longer being read (%s); what it reports will be noticed "
	    "only on the loop's own tick from now on",
	    ncfg_main_source_name(source->kind), source->what ? " on " : "",
	    source->what ? source->what : "", ncfg_main_readiness_name(ready));
}

/* Ask the sources that have no descriptor to wait on. `--poll-config` is the
 * whole of why they exist; see `ncfg_main_source_t::fd`. */
static void ask_the_unwaited(ncfg_main_sources_t *sources, ncfg_main_harvest_t *harvest)
{
	size_t at;

	for (at = 0; at < sources->count; at++) {
		if (sources->at[at].fd >= 0) {
			continue;
		}
		take_from(&sources->at[at], harvest);
	}
}

int ncfg_main_round(const ncfg_main_run_t *run, ncfg_main_round_report_t *report, char *err,
    size_t err_size)
{
	ncfg_main_harvest_t   harvest;
	ncfg_reconcile_roam_t roams[NCFG_MAIN_ROAMS_MAX];
	ncfg_proto_request_t  requests[NCFG_MAIN_PENDING_MAX];
	struct pollfd         waiting[NCFG_MAIN_SOURCES_MAX];
	size_t                from[NCFG_MAIN_SOURCES_MAX];
	int                   drop[NCFG_MAIN_SOURCES_MAX];
	size_t                request_count = 0;
	size_t                dropped = 0;
	size_t                pruned = 0;
	unsigned              interrupted = 0;
	unsigned              round;
	uint64_t              deadline;
	int                   asked = 0;

	memset(&harvest, 0, sizeof(harvest));
	if (report) {
		memset(report, 0, sizeof(*report));
	}
	if (!run || !run->sources) {
		ncfg_error_set(err, err_size, "a round needs a set of descriptors to wait on");
		return 0;
	}

	/* Before the wait: a supplicant that started while the last pass was
	 * running has its first events queued already, and attaching afterwards
	 * would mean sitting out the tick with them in the socket. */
	if (run->refresh) {
		run->refresh(run->refresh_context, run->sources);
	}

	deadline = ticks_of(run) + (uint64_t)NCFG_MAIN_TICK_MS;

	for (round = 0u;; round++) {
		ncfg_main_wait_t meant;
		size_t           count = 0;
		size_t           at;
		int              answered;
		int              timeout;
		int              why = 0;

		memset(drop, 0, sizeof(drop));
		for (at = 0; at < run->sources->count; at++) {
			if (run->sources->at[at].fd < 0) {
				continue;
			}
			waiting[count].fd = run->sources->at[at].fd;
			waiting[count].events = POLLIN;
			waiting[count].revents = 0;
			from[count] = at;
			count++;
		}

		/*
		 * The first wait is the round's; every one after it asks "is there
		 * anything else already here?" and must not sleep. Taken from the
		 * deadline rather than from a constant, so a round that has already
		 * spent four seconds waits one.
		 */
		timeout = (round == 0u) ? ncfg_main_timeout_until(deadline, ticks_of(run)) : 0;
		for (;;) {
			errno = 0;
			answered = poll(waiting, (nfds_t)count, timeout);
			/* Kept, because everything after this is a call and any of them
			 * may leave `errno` somewhere else -- including the one that is
			 * about to render it into a sentence. */
			why = errno;
			meant = ncfg_main_wait_meant(answered, why);
			if (meant != NCFG_MAIN_WAIT_AGAIN) {
				break;
			}
			interrupted++;
			/*
			 * Whatever is left of the same deadline, never a fresh one --
			 * which is also what makes this terminate: a signal arriving over
			 * and over shortens the wait each time until it is zero, and a
			 * `poll` of zero answers at once.
			 */
			timeout = (round == 0u) ? ncfg_main_timeout_until(deadline, ticks_of(run)) : 0;
		}

		if (meant == NCFG_MAIN_WAIT_FAILED) {
			ncfg_error_set(err, err_size, "waiting on this daemon's descriptors: %s",
			    strerror(why));
			return 0;
		}
		if (meant == NCFG_MAIN_WAIT_TICKED) {
			/*
			 * Only the round's own wait is a tick. A later look that found
			 * nothing is the burst ending, and collapsing a tick there would
			 * make every burst report a backstop that did not happen -- which
			 * `ncfg_reconcile_should_resolve_window` reads, so it would ask
			 * the confirm window on every netlink event for ever.
			 */
			if (round == 0u) {
				ncfg_reconcile_collapse(&harvest.wake, NCFG_WOKE_TICK);
				ask_the_unwaited(run->sources, &harvest);
				asked = 1;
			}
			break;
		}

		for (at = 0; at < count; at++) {
			size_t             which = from[at];
			ncfg_main_source_t *source = &run->sources->at[which];
			ncfg_main_ready_t   ready = ncfg_main_readiness(waiting[at].revents);

			if (ready == NCFG_MAIN_READY_DATA) {
				take_from(source, &harvest);
				/*
				 * A drain that failed is the same shape as a queued error and
				 * is asked the same question, which is what keeps a source
				 * that is readable for ever and unreadable for ever from
				 * costing a full burst every round until the daemon stops.
				 * `take_from` clears the count on any drain that worked.
				 */
				if (source->failures > 0u &&
				    !ncfg_main_source_survives(NCFG_MAIN_READY_ERRORED,
				    source->failures)) {
					say_dropped(source, NCFG_MAIN_READY_ERRORED);
					drop[which] = 1;
				}
				continue;
			}
			if (ready == NCFG_MAIN_READY_NOTHING) {
				continue;
			}
			source->failures++;
			if (ncfg_main_source_survives(ready, source->failures)) {
				/* An error that may clear: read it out, since the read is
				 * what clears it, and count the round against the patience
				 * above. */
				take_from(source, &harvest);
				continue;
			}
			say_dropped(source, ready);
			drop[which] = 1;
		}

		/*
		 * Dropped after the walk and from the end, because the walk holds
		 * indices into the set that a removal shifts. `ncfg_main_sources_forget`
		 * keeps the order for the same reason.
		 */
		for (at = run->sources->count; at > 0u; at--) {
			if (drop[at - 1u]) {
				ncfg_main_sources_forget(run->sources, at - 1u);
				dropped++;
			}
		}

		if (!asked) {
			ask_the_unwaited(run->sources, &harvest);
			asked = 1;
		}
		if (!ncfg_main_drains_again(round + 1u)) {
			/*
			 * The burst is still going and the pass is owed a turn. Whatever
			 * is left stays queued and is the next round's, which is
			 * microseconds away -- the alternative is a pass that never runs
			 * while the daemon looks perfectly busy.
			 */
			ncfg_log_emitf("loop", NCFG_LOG_NOTE,
			    "a burst was still arriving after %d looks, so the rest of it is left "
			    "for the next round", NCFG_MAIN_DRAIN_ROUNDS);
			break;
		}
	}

	if (run->mailbox) {
		request_count = ncfg_main_mailbox_take(run->mailbox, requests,
		    (size_t)NCFG_MAIN_PENDING_MAX);
	}

	/*
	 * Sweep the streams before the pass announces down them, not after.
	 *
	 * A subscriber whose client has gone is otherwise found only by a write
	 * that fails, and a converged machine writes nothing -- so on the machine
	 * that most needs the places in that list, nothing ever frees one. Here
	 * rather than inside `ncfg_main_subscribers_tell` because that is the same
	 * arrangement one layer down: a list swept only when it is written to is a
	 * list nobody sweeps.
	 *
	 * Before the pass so that an event this round announces is not written to
	 * a descriptor already known to be gone, and after the mailbox has been
	 * emptied so that a `monitor` that arrived this round is in the list and
	 * is swept with everything else -- it will not be found gone, having just
	 * been handed over, and a sweep that skipped it would be a rule with an
	 * exception in it.
	 */
	if (run->subscribers) {
		pruned = ncfg_main_subscribers_prune(run->subscribers);
	}

	if (report) {
		report->pruned = pruned;
		report->wake = harvest.wake;
		report->roam_count = harvest.roam_count;
		report->roams_missed = harvest.roams_missed;
		report->request_count = request_count;
		/* Waits, not extra waits: one is an ordinary round. A test that had
		 * to add one to reach the bound would be a test spelling an
		 * off-by-one. */
		report->drains = round + 1u;
		report->interrupted = interrupted;
		report->dropped = dropped;
		report->sources = run->sources->count;
		report->stopping = harvest.stopping;
	}
	if (harvest.roams_missed > 0u) {
		ncfg_log_emitf("loop", NCFG_LOG_WARNING,
		    "%zu roam(s) in one round did not fit and were not reported",
		    harvest.roams_missed);
	}

	if (run->loop && ncfg_main_passes(&harvest.wake, harvest.roam_count, request_count)) {
		char   message[NCFG_ERROR_MAX];
		size_t at;

		for (at = 0; at < harvest.roam_count; at++) {
			roams[at].interface = harvest.roams[at].interface;
			roams[at].bssid = harvest.roams[at].bssid;
		}
		message[0] = '\0';
		if (!ncfg_reconcile_pass(run->loop, &harvest.wake, roams, harvest.roam_count,
		    requests, request_count, report ? &report->pass : NULL, message,
		    sizeof(message))) {
			/*
			 * Reported and not returned. `daemon.h` says a pass answers 0 only
			 * where it could not be carried out at all, and even that is not a
			 * reason to stop watching: a daemon that stopped reconciling
			 * because one pass failed is a daemon that stopped, and the next
			 * tick is five seconds away.
			 */
			ncfg_log_emitf("reconcile", NCFG_LOG_ERROR, "this pass did not run: %s",
			    message);
		}
		if (report) {
			report->passed = 1;
		}
	}

	/*
	 * Last, and unconditionally. A round that ran no pass still answers what
	 * was waiting -- otherwise a request arriving on a quiet machine would
	 * hold its connection until something else woke the loop.
	 */
	if (run->mailbox) {
		ncfg_main_mailbox_settle(run->mailbox);
	}
	return 1;
}

int ncfg_main_serve(const ncfg_main_run_t *run, char *err, size_t err_size)
{
	for (;;) {
		ncfg_main_round_report_t report;

		if (!ncfg_main_round(run, &report, err, err_size)) {
			return 0;
		}
		/*
		 * The one thing that ends this, and it is a byte on a descriptor
		 * rather than a flag: a handler that set a flag would race the wait
		 * below, which is the classic version of this loop failing to stop --
		 * the signal arrives after the check and the daemon sleeps five
		 * seconds with the flag already set. See `ncfg_main_signals_watch`.
		 */
		if (report.stopping) {
			break;
		}
	}
	return 1;
}
