/*
 * daemon_wake.c -- what the descriptor loop decides.
 *
 * **Every call here takes values and answers one.** Nothing in this file
 * opens a descriptor, reads one, waits on one or writes anything, which is
 * `reconcile.c`'s arrangement applied to the layer below it and taken for the
 * same reason: a loop around `poll` is a loop nothing can test, so the part
 * with the rules in it is moved out of the part with the syscall in it, and
 * what is left in `daemon_loop.c` is an order.
 *
 * WHAT THESE RULES ARE ABOUT, WHICH IS NOT THE HAPPY PATH
 *   A daemon's poll loop is easy to write and easy to write wrong, and the
 *   ways it goes wrong are all invisible to a test that sends one event and
 *   asserts one pass:
 *
 *     * a descriptor that hung up and was never dropped, so `poll` returns
 *       instantly for ever and the daemon spins at 100% CPU while still
 *       answering clients -- which is what makes it survive a casual look;
 *     * a burst collapsed with no floor, so one permanently-ready descriptor
 *       means the pass never runs at all;
 *     * `EINTR` read as a failure, which is 0233 and cost a machine its
 *       network configuration for fifty-two minutes;
 *     * a negative timeout handed to `poll`, which is not a mistake it
 *       reports -- it is "wait for ever", and a loop with nothing ready never
 *       ticks again.
 *
 *   Each of those is a function below, and each is a check.
 */
#include "loop_internal.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>

const char *ncfg_main_source_name(ncfg_main_source_kind_t kind)
{
	switch (kind) {
	case NCFG_MAIN_SOURCE_KERNEL:
		return "netlink";
	case NCFG_MAIN_SOURCE_CONFIG:
		return "config";
	case NCFG_MAIN_SOURCE_RFKILL:
		return "rfkill";
	case NCFG_MAIN_SOURCE_RADIO_DIR:
		return "supplicant directory";
	case NCFG_MAIN_SOURCE_RADIO:
		return "supplicant";
	case NCFG_MAIN_SOURCE_TIMER:
		return "confirm timer";
	case NCFG_MAIN_SOURCE_REQUEST:
		return "request";
	case NCFG_MAIN_SOURCE_STOP:
		return "stop";
	default:
		break;
	}
	/* A kind outside the enum, which is a caller that built a source by hand.
	 * Named rather than answered with one of the seven, so a log line about it
	 * does not read as a real source misbehaving. */
	return "unknown";
}

ncfg_main_ready_t ncfg_main_readiness(short revents)
{
	/*
	 * `POLLNVAL` first, because it is the one answer that is about the
	 * *program* rather than about the far end: the descriptor in the set is
	 * not open. Everything else `poll` might also have set on it is noise,
	 * and reading it would be reading a descriptor this process does not
	 * have.
	 */
	if ((revents & POLLNVAL) != 0) {
		return NCFG_MAIN_READY_CLOSED;
	}
	/*
	 * Then data, ahead of both the error and the hang-up.
	 *
	 * A writer that queued bytes and closed sets `POLLIN|POLLHUP` together,
	 * and a socket with a queued error still hands over what arrived before
	 * it. Taking the hang-up first would drop the source with its last
	 * records unread -- for `/dev/rfkill` that is the switch being flipped as
	 * the device went away, and for a supplicant it is the disconnect that
	 * explains why the socket closed. The hang-up is not lost by waiting: it
	 * is still set on the next round, when there is nothing left to read.
	 */
	if ((revents & POLLIN) != 0) {
		return NCFG_MAIN_READY_DATA;
	}
	if ((revents & POLLERR) != 0) {
		return NCFG_MAIN_READY_ERRORED;
	}
	if ((revents & POLLHUP) != 0) {
		return NCFG_MAIN_READY_ENDED;
	}
	return NCFG_MAIN_READY_NOTHING;
}

const char *ncfg_main_readiness_name(ncfg_main_ready_t ready)
{
	switch (ready) {
	case NCFG_MAIN_READY_NOTHING:
		return "nothing";
	case NCFG_MAIN_READY_DATA:
		return "something to read";
	case NCFG_MAIN_READY_ERRORED:
		return "an error queued on it";
	case NCFG_MAIN_READY_ENDED:
		return "the far end gone";
	case NCFG_MAIN_READY_CLOSED:
		return "no open descriptor";
	default:
		break;
	}
	return "something this build has no word for";
}

int ncfg_main_source_survives(ncfg_main_ready_t ready, unsigned failures)
{
	switch (ready) {
	case NCFG_MAIN_READY_NOTHING:
	case NCFG_MAIN_READY_DATA:
		return 1;
	case NCFG_MAIN_READY_ERRORED:
		/*
		 * Given a few looks, because a queued error is often transient and
		 * the read that follows is what clears it. What the bound refuses is
		 * the other case: a descriptor that reports `POLLERR` on every call
		 * and hands over nothing, which makes `poll` return instantly for
		 * ever.
		 *
		 * `failures` is **looks in a row** rather than rounds, and the
		 * difference is deliberate: a burst is looked at again up to
		 * `NCFG_MAIN_DRAIN_ROUNDS` times, so a source that is ready for ever
		 * and unreadable for ever is let go of inside one round instead of
		 * costing a full burst on every round until the daemon stops. Any
		 * look that read something clears the count, so a socket that errors
		 * once an hour never reaches it.
		 */
		return failures < (unsigned)NCFG_MAIN_SOURCE_PATIENCE;
	case NCFG_MAIN_READY_ENDED:
	case NCFG_MAIN_READY_CLOSED:
		/*
		 * At once, and with no patience at all. There is nothing to wait for
		 * -- a hung-up descriptor is ready every single time it is polled, so
		 * "try again next round" is a busy loop with a counter in it.
		 */
		return 0;
	default:
		break;
	}
	/* An answer this build has no word for is not a reason to go on polling
	 * something. */
	return 0;
}

ncfg_main_wait_t ncfg_main_wait_meant(int answered, int code)
{
	if (answered > 0) {
		return NCFG_MAIN_WAIT_READY;
	}
	if (answered == 0) {
		return NCFG_MAIN_WAIT_TICKED;
	}
	if (code == EINTR) {
		/*
		 * 0233's case, at the one syscall the whole daemon sleeps in. netcfgd
		 * spawns a child every time it runs a hook, so `SIGCHLD` lands here on
		 * an ordinary day; treating it as a failure once cost a machine its
		 * network configuration for fifty-two minutes. Asking again cannot
		 * spin, because every one of these is a signal that really arrived and
		 * the wait that follows is what is left of the same deadline.
		 */
		return NCFG_MAIN_WAIT_AGAIN;
	}
	(void)code;
	return NCFG_MAIN_WAIT_FAILED;
}

int ncfg_main_timeout_until(uint64_t deadline_ms, uint64_t now_ms)
{
	uint64_t left;

	/*
	 * Past, or exactly on it. Zero rather than a negative number: `poll`
	 * reads a negative timeout as "no timeout", so the arithmetic slip here
	 * does not produce a short wait or a long one -- it produces a daemon
	 * asleep for ever on a machine where nothing is happening, which is
	 * precisely the machine the backstop exists for.
	 */
	if (now_ms >= deadline_ms) {
		return 0;
	}
	left = deadline_ms - now_ms;
	/*
	 * And never longer than a tick. A clock that went backwards -- a
	 * deadline computed before a step and compared after one -- would
	 * otherwise put the daemon to sleep for however far it moved.
	 * `ncfg_confirm_expired_at` takes its clock as an argument for the same
	 * family of reasons; this one cannot, since it is what `poll` is handed,
	 * so it is clamped instead.
	 */
	if (left > (uint64_t)NCFG_MAIN_TICK_MS) {
		return NCFG_MAIN_TICK_MS;
	}
	return (int)left;
}

int ncfg_main_drains_again(unsigned round)
{
	return round < (unsigned)NCFG_MAIN_DRAIN_ROUNDS;
}

int ncfg_main_woke_for(ncfg_main_source_kind_t kind, ncfg_woke_t *out)
{
	if (!out) {
		return 0;
	}
	switch (kind) {
	case NCFG_MAIN_SOURCE_KERNEL:
	case NCFG_MAIN_SOURCE_RFKILL:
		/*
		 * The kill switch folds into the kernel's wake, which is the Rust's
		 * arrangement and is right because the *answer* is the same: look
		 * again. A wake of its own would be a fourth flag that every reader
		 * of `ncfg_reconcile_wake_t` would have to remember means what
		 * `kernel_changed` already means.
		 */
		*out = NCFG_WOKE_KERNEL;
		return 1;
	case NCFG_MAIN_SOURCE_CONFIG:
		*out = NCFG_WOKE_CONFIG;
		return 1;
	case NCFG_MAIN_SOURCE_TIMER:
		*out = NCFG_WOKE_CONFIRM_EXPIRED;
		return 1;
	case NCFG_MAIN_SOURCE_RADIO:
	case NCFG_MAIN_SOURCE_RADIO_DIR:
	case NCFG_MAIN_SOURCE_REQUEST:
	case NCFG_MAIN_SOURCE_STOP:
		/*
		 * None of these four is news to reconcile about. A radio's events
		 * travel as a roam list, because two roams are two events; the
		 * directory moving is a reason to look for radios and nothing more --
		 * a supplicant starting does not change the machine, and the netlink
		 * event that accompanies it is what does; a waiting request travels as
		 * the request list, which is what `ncfg_main_passes` reads; and the
		 * stop pipe is not something to reconcile about at all.
		 *
		 * **A request must not set `ticked`**, which is the tempting shortcut
		 * and is wrong twice: `ncfg_reconcile_looks` would then re-read the
		 * kernel on every `ncfg status`, and a client polling once a second
		 * would hold the daemon at a full observation per second while
		 * reporting a machine nobody had changed.
		 */
		return 0;
	default:
		break;
	}
	return 0;
}

int ncfg_main_passes(const ncfg_reconcile_wake_t *wake, size_t roams, size_t requests)
{
	if (roams > 0u || requests > 0u) {
		return 1;
	}
	if (!wake) {
		return 0;
	}
	/*
	 * `ncfg_reconcile_looks` is not the question here and asking it would be
	 * the wrong one: it answers whether a pass should look at the *machine*,
	 * and a pass does four things before it gets there -- it resolves a window
	 * whose timer fired, runs the roam hooks, reloads the configuration and
	 * runs the probes that are due. A round carrying a config change and no
	 * kernel event still has all four to do.
	 *
	 * What this refuses is the empty round: one that woke only because a pipe
	 * hung up and was dropped. Running a pass there would re-read the kernel
	 * and rebuild a plan because a descriptor closed, and the tick is what
	 * makes skipping it safe -- five seconds later the backstop comes round
	 * whatever happened here.
	 */
	return wake->kernel_changed || wake->config_changed || wake->confirm_expired ||
	    wake->ticked;
}

int ncfg_main_is_roam(int had_last, uint32_t last_network, const char *last_bssid,
    int has_network, uint32_t network, const char *bssid)
{
	if (!had_last || !has_network || !last_bssid || !bssid) {
		/*
		 * No last report is a first association: there is nothing to have
		 * moved from, and firing then would run the hook on every boot. An
		 * unreadable id answers the same way, which is 0239's direction --
		 * an id that could not be read is not a network established as the
		 * same one, and erring towards a hook that does not fire is the way
		 * the first-association case already errs.
		 */
		return 0;
	}
	if (last_network != network) {
		/*
		 * A different network is not a roam however different the address is.
		 * `HookPhase::Roam` promises "a station moved to a different access
		 * point on the same network", and comparing addresses alone made
		 * switching from home wifi to the office fire the `roam` hooks with
		 * `NCFG_REASON` naming a move that had not happened.
		 */
		return 0;
	}
	return strcmp(last_bssid, bssid) != 0;
}

int ncfg_main_request_waits(const ncfg_proto_request_t *request)
{
	/*
	 * All of them, and the single `return` is the statement rather than a
	 * placeholder for a filter somebody will write later.
	 *
	 * The Rust queues every request into the channel the watchers feed and
	 * serves them in the loop body, which is what keeps exactly one thread
	 * inside the daemon's state. A seam that answered some of them on the
	 * connection's own thread would be a second writer of that state, with
	 * `server.c`'s lock as the only thing between them -- and that lock is
	 * held around the seam rather than around the state, so it would not be
	 * between them for long.
	 *
	 * It takes the request so that the day a kind genuinely does not need the
	 * loop, the exception is written here rather than discovered at a call
	 * site.
	 */
	(void)request;
	return 1;
}

void ncfg_main_harvest_roam(ncfg_main_harvest_t *harvest, const char *interface,
    const char *bssid)
{
	ncfg_main_roam_text_t *roam;

	if (!harvest || !interface || !bssid) {
		return;
	}
	if (harvest->roam_count >= (size_t)NCFG_MAIN_ROAMS_MAX) {
		/*
		 * Counted rather than dropped in silence, which is the same rule
		 * `NCFG_DRIFT_MAX` takes and is right for the same reason: a station
		 * that moved and nothing anywhere saying so is worse than a number an
		 * operator has to interpret. A radio producing seventeen roams in one
		 * round is one that is flapping, and that is the fact worth carrying
		 * out of here.
		 */
		harvest->roams_missed++;
		return;
	}
	roam = &harvest->roams[harvest->roam_count];
	(void)snprintf(roam->interface, sizeof(roam->interface), "%s", interface);
	(void)snprintf(roam->bssid, sizeof(roam->bssid), "%s", bssid);
	harvest->roam_count++;
}

/* ------------------------------------------------------------------------ *
 * The source set
 * ------------------------------------------------------------------------ */

void ncfg_main_sources_init(ncfg_main_sources_t *sources)
{
	if (!sources) {
		return;
	}
	memset(sources, 0, sizeof(*sources));
}

int ncfg_main_sources_add(ncfg_main_sources_t *sources, const ncfg_main_source_t *source,
    char *err, size_t err_size)
{
	if (!sources || !source) {
		ncfg_error_set(err, err_size, "a source needs somewhere to be put");
		return 0;
	}
	if (sources->count >= NCFG_MAIN_SOURCES_MAX) {
		/*
		 * A refusal and not a truncation, because what overflows this is the
		 * radios: a machine with nine of them would otherwise have one that is
		 * watched by nothing and says so nowhere, which is the shape
		 * `NCFG_OBSERVE_RECORDS_MAX` refuses for.
		 */
		ncfg_error_set(err, err_size,
		    "this daemon watches at most %zu descriptors and already has that many, so "
		    "the %s source was not added", (size_t)NCFG_MAIN_SOURCES_MAX,
		    ncfg_main_source_name(source->kind));
		return 0;
	}
	sources->at[sources->count] = *source;
	sources->at[sources->count].failures = 0;
	sources->count++;
	return 1;
}

void ncfg_main_sources_forget(ncfg_main_sources_t *sources, size_t at)
{
	size_t next;

	if (!sources || at >= sources->count) {
		return;
	}
	/*
	 * The order is kept rather than the last one swapped in, because the loop
	 * walks the set against a parallel array of `struct pollfd` it built a
	 * moment earlier: a swap would make index `at` a different source
	 * mid-walk, and the next readiness would be attributed to it.
	 */
	for (next = at + 1u; next < sources->count; next++) {
		sources->at[next - 1u] = sources->at[next];
	}
	sources->count--;
	memset(&sources->at[sources->count], 0, sizeof(sources->at[sources->count]));
}

size_t ncfg_main_sources_find(const ncfg_main_sources_t *sources, ncfg_main_source_kind_t kind)
{
	size_t at;

	if (!sources) {
		return 0;
	}
	for (at = 0; at < sources->count; at++) {
		if (sources->at[at].kind == kind) {
			return at;
		}
	}
	return sources->count;
}
