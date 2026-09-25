/*
 * daemon_watchers.c -- the five things a daemon watches, and the two pipes.
 *
 * THIS IS THE ONLY FILE HERE THAT OPENS ANYTHING
 *   `daemon_wake.c` decides and `daemon_loop.c` sequences; neither has a
 *   descriptor in it but the `poll`. Everything that binds a socket, opens a
 *   device, takes an inotify instance or arms a timer is in this file, so that
 *   "what does this loop do when a descriptor hangs up" is a question a test
 *   answers with a pipe it made rather than with a kernel.
 *
 * WHAT IS WATCHED, AND WHY EACH ONE IS NOT ENOUGH ON ITS OWN
 *   **Netlink**, in the observed multicast groups, which is the machine
 *   moving. It misses a kill switch being unblocked, which produces no link
 *   event until something else happens (rfkill.h).
 *
 *   **The configuration directory**, by inotify where the kernel allows it and
 *   by mtime otherwise. `watch.h` says why the fall-back is not defensive
 *   programming: `inotify_init1` fails with `EMFILE` on a busy machine and
 *   some container runtimes refuse it outright, and a configuration daemon
 *   that stopped noticing configuration changes because a limit elsewhere was
 *   reached is worse than one that polls.
 *
 *   **`/dev/rfkill`**, which is the kernel's own notification for a switch
 *   being flipped. A machine with no radio does not have it, and that is not a
 *   fault -- 0199 is that anything else is, and used to be silent.
 *
 *   **The supplicant's control directory and the radios in it**, which is the
 *   one event an observation cannot catch: a station moving to a different
 *   access point. netcfgd asks a station nothing during an observation, so the
 *   alternative is a round trip per radio on every netlink event.
 *
 *   **The commit-confirm window's timer**, which is a `timerfd` rather than
 *   the Rust's sleeping thread. 0234 is what the thread cost: the result of
 *   the spawn was discarded, so a timer that never started left a window open
 *   for ever -- and this was the only thing that closed one. A descriptor
 *   cannot half-start, and the loop's tick asks the window anyway.
 *
 *   And two pipes, which are not watches: one a signal handler writes to, one
 *   a waiting request is announced on. Both exist because a byte in a
 *   descriptor cannot be missed by a wait that descriptor is part of, and a
 *   flag can.
 *
 * WHAT A MISSING ONE COSTS, SAID RATHER THAN REFUSED
 *   None of the five is required and each says in the log what is lost by its
 *   absence, which is `ncfg_reconcile_world_t`'s bargain: a daemon that would
 *   not start because one of five watches was unavailable is a daemon
 *   refusing to watch the four that are.
 */
#include "loop_internal.h"

#include "ncfg/log.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <unistd.h>

/* ------------------------------------------------------------------------ *
 * Reading only what is there
 * ------------------------------------------------------------------------ */

/*
 * Is there anything queued on it right now?
 *
 * **This is what makes every blocking call below safe to make.**
 * `ncfg_netlink_wait_for_change` waits on the socket's own timeout,
 * `ncfg_rfkill_next` blocks outright, and `ncfg_supplicant_next_event` blocks
 * for ever when handed a timeout of zero -- `SO_RCVTIMEO` of `{0,0}` is "no
 * deadline", which is the trap the supplicant's own scan wait already steps
 * around. Each of them is called only after this has said there is a datagram
 * to take, which is the one arrangement in which none of them can block.
 *
 * A failure answers no, which ends the drain rather than risking the wait.
 */
static int readable(int fd)
{
	struct pollfd waiting;

	if (fd < 0) {
		return 0;
	}
	waiting.fd = fd;
	waiting.events = POLLIN;
	waiting.revents = 0;
	if (poll(&waiting, (nfds_t)1, 0) <= 0) {
		return 0;
	}
	return (waiting.revents & POLLIN) != 0;
}

/* ------------------------------------------------------------------------ *
 * The drains
 * ------------------------------------------------------------------------ */

/*
 * Netlink: take every datagram queued, and fold them into one wake.
 *
 * **`ENOBUFS` is not told apart from an ordinary change here, and that is
 * deliberate rather than an omission.** `ncfg_netlink_change_from` already
 * decides what a gap means -- it is a change, because the daemon re-reads the
 * machine rather than applying deltas, and a watcher that stopped there would
 * stop precisely when the most was happening. A second place that told the two
 * apart would be a second answer to the same question, and the only thing it
 * could do differently is re-read the machine, which is what one change
 * already causes. The bytes are thrown away either way.
 *
 * A datagram that did not come from the kernel is dropped inside
 * `ncfg_netlink_wait_for_change` and reported here as nothing having arrived,
 * which ends this drain and leaves the rest queued -- so a local process
 * writing to the socket costs one datagram per round rather than a wake.
 */
static int drain_kernel(void *context, ncfg_main_harvest_t *harvest, char *err, size_t err_size)
{
	ncfg_netlink_t *netlink = context;
	unsigned        round;

	for (round = 0u; round < (unsigned)NCFG_MAIN_EVENT_BURST; round++) {
		int         changed = 0;
		ncfg_woke_t woke;

		if (!readable(ncfg_netlink_descriptor(netlink))) {
			break;
		}
		if (!ncfg_netlink_wait_for_change(netlink, &changed, err, err_size)) {
			return 0;
		}
		if (!changed) {
			break;
		}
		if (ncfg_main_woke_for(NCFG_MAIN_SOURCE_KERNEL, &woke)) {
			ncfg_reconcile_collapse(&harvest->wake, woke);
		}
	}
	return 1;
}

/*
 * The configuration: one question, however it is answered.
 *
 * The same call serves both mechanisms, which is why the polling fall-back
 * needs no arm of its own anywhere in this loop: `ncfg_watch_wait` with a zero
 * timeout reads whatever inotify has queued, or walks the fingerprint, and
 * both answer "did it change".
 */
static int drain_config(void *context, ncfg_main_harvest_t *harvest, char *err, size_t err_size)
{
	ncfg_watch_t *watch = context;
	unsigned      round;

	for (round = 0u; round < (unsigned)NCFG_MAIN_EVENT_BURST; round++) {
		int         changed = 0;
		ncfg_woke_t woke;

		if (!ncfg_watch_wait(watch, 0, &changed, err, err_size)) {
			return 0;
		}
		if (!changed) {
			break;
		}
		if (ncfg_main_woke_for(NCFG_MAIN_SOURCE_CONFIG, &woke)) {
			ncfg_reconcile_collapse(&harvest->wake, woke);
		}
		if (!readable(ncfg_watch_descriptor(watch))) {
			/*
			 * The polling mechanism has no descriptor, so this ends the loop
			 * after one answer -- which is right: a fingerprint walk has
			 * already taken everything there was to take, and asking again
			 * would walk the filesystem a second time for the same answer.
			 */
			break;
		}
	}
	return 1;
}

/*
 * `/dev/rfkill`: one record per read, which is the kernel's own arrangement.
 *
 * The event itself is thrown away and the wake is the kernel's, because what
 * netcfgd does about a switch being flipped is look at the machine again --
 * the state is read out of `/sys` during the observation that follows, which
 * is the one place it is read. Keeping it here would be a second answer to
 * what `ncfg_observe_rfkill` already answers.
 */
static int drain_rfkill(void *context, ncfg_main_harvest_t *harvest, char *err, size_t err_size)
{
	ncfg_rfkill_t *rfkill = context;
	unsigned       round;

	for (round = 0u; round < (unsigned)NCFG_MAIN_EVENT_BURST; round++) {
		ncfg_rfkill_event_t event;
		int                 got = 0;
		ncfg_woke_t         woke;

		if (!readable(ncfg_rfkill_descriptor(rfkill))) {
			break;
		}
		if (!ncfg_rfkill_next(rfkill, &event, &got, err, err_size)) {
			return 0;
		}
		if (!got) {
			/*
			 * End of file, which for this device means it went away.
			 * Reported as a failure of the source rather than as nothing
			 * having arrived, because those are not the same thing: a
			 * descriptor at end of file stays readable, so "nothing arrived"
			 * would be a drain that returns immediately on every round for
			 * ever. Three of these and the loop stops reading it.
			 */
			ncfg_error_set(err, err_size,
			    "the kill-switch device ended, so a switch being flipped will no "
			    "longer be noticed");
			return 0;
		}
		if (ncfg_main_woke_for(NCFG_MAIN_SOURCE_RFKILL, &woke)) {
			ncfg_reconcile_collapse(&harvest->wake, woke);
		}
	}
	return 1;
}

/* The supplicant directory: something appeared or went away, so the radios are
 * worth reading again. Not a wake -- a supplicant starting does not change the
 * machine, and the netlink event beside it is what does. */
static int drain_radio_dir(void *context, ncfg_main_harvest_t *harvest, char *err,
    size_t err_size)
{
	ncfg_main_watchers_t *watchers = context;
	ncfg_inotify_batch_t  batch;

	for (;;) {
		if (!readable(ncfg_inotify_descriptor(&watchers->radio_dir))) {
			break;
		}
		if (!ncfg_inotify_wait(&watchers->radio_dir, 0, &batch, err, err_size)) {
			return 0;
		}
		if (batch.length == 0u) {
			break;
		}
		watchers->radios_stale = 1;
		harvest->rescan = 1;
	}
	return 1;
}

/*
 * One radio: everything it has to say, bounded.
 *
 * Bounded for the Rust's reason -- one chatty radio must not starve the others
 * on a machine with several -- and drained rather than taken one at a time,
 * which is 0240: a supplicant losing an access point produces a burst, and a
 * watcher that fell behind filled the socket's receive buffer, at which point
 * `wpa_supplicant` detaches a monitor it cannot send to and the radio is quiet
 * for ever with nothing saying so.
 */
static int drain_radio(void *context, ncfg_main_harvest_t *harvest, char *err, size_t err_size)
{
	ncfg_main_radio_t *radio = context;
	unsigned           round;

	for (round = 0u; round < (unsigned)NCFG_MAIN_EVENT_BURST; round++) {
		ncfg_supplicant_event_t event;
		char                    bssid[NCFG_MAIN_BSSID_MAX];
		uint32_t                network = 0;
		int                     got = 0;
		int                     has_network;

		if (!readable(ncfg_supplicant_client_descriptor(radio->client))) {
			break;
		}
		/*
		 * One millisecond and not zero. Zero is `SO_RCVTIMEO` of `{0,0}`,
		 * which the kernel reads as "no deadline at all" -- a blocking read on
		 * the daemon's only thread. The wait above is what makes the deadline
		 * moot; this is what makes a race between the two cost a millisecond
		 * rather than the daemon.
		 */
		if (!ncfg_supplicant_next_event(radio->client, 1, &event, &got, err, err_size)) {
			return 0;
		}
		if (!got) {
			break;
		}
		/*
		 * **Said before anything is decided about it.** What the watcher does
		 * with an event is narrow -- it looks for a roam -- and until this
		 * line the rest of the stream reached the daemon and left no trace at
		 * all: a station refused, a network given up on, a scan the radio
		 * could not run, and the association itself. The first tryout of this
		 * daemon on a live machine produced a log of three startup lines while
		 * the Rust beside it narrated every one of these (project.md 10.237).
		 *
		 * The decision is `ncfg_main_supplicant_event_line`'s, which is where
		 * it can be tested; this is the part that writes and cannot be.
		 */
		{
			char said[NCFG_LOG_MAX];
			int  severity = NCFG_LOG_NOTE;

			if (ncfg_main_supplicant_event_line(radio->interface, &event, &severity, said,
			        sizeof(said))) {
				ncfg_log_emitf("supplicant", (ncfg_severity_t)severity, "%s", said);
			}
		}
		if (!ncfg_supplicant_event_is(&event, "CTRL-EVENT-CONNECTED")) {
			continue;
		}
		if (!ncfg_supplicant_event_connected_bssid(&event, bssid, sizeof(bssid))) {
			/* A connect that named no address is not a move to nowhere; it is
			 * an event this cannot read, and comparing an empty address would
			 * report a roam off every access point. */
			continue;
		}
		has_network = ncfg_supplicant_event_network_id(&event, &network);
		if (ncfg_main_is_roam(radio->has_last, radio->last_network, radio->last_bssid,
		    has_network, network, bssid)) {
			ncfg_main_harvest_roam(harvest, radio->interface, bssid);
		}
		/*
		 * Recorded only where the id could be read, which is the
		 * representation doing the work: there is no room here for an address
		 * without a network, so two unknown ids can never compare equal and
		 * be read as one network.
		 */
		if (has_network) {
			radio->has_last = 1;
			radio->last_network = network;
			(void)snprintf(radio->last_bssid, sizeof(radio->last_bssid), "%s", bssid);
		}
	}
	return 1;
}

/*
 * The window's timer: it fired, which is a prompt to ask the window.
 *
 * The eight bytes are read and thrown away. What they carry is how many times
 * it expired, which cannot be more than one here -- the timer is one-shot --
 * and would mean nothing if it were: `NCFG_WOKE_CONFIRM_EXPIRED` carries no
 * identity, so it is a prompt to ask the window rather than an instruction to
 * revert. A timer outliving the window it was armed for finds a window with
 * time left, which is not one that closed.
 */
static int drain_timer(void *context, ncfg_main_harvest_t *harvest, char *err, size_t err_size)
{
	int         *timer = context;
	uint64_t     fired = 0;
	ssize_t      got;
	ncfg_woke_t  woke;

	got = read(*timer, &fired, sizeof(fired));
	if (got < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			return 1;
		}
		ncfg_error_set(err, err_size, "reading the confirm window's timer: %s",
		    strerror(errno));
		return 0;
	}
	if (ncfg_main_woke_for(NCFG_MAIN_SOURCE_TIMER, &woke)) {
		ncfg_reconcile_collapse(&harvest->wake, woke);
	}
	return 1;
}

/* Empty a pipe, and say whether there was anything in it. What a byte meant is
 * the source's kind rather than its value; how many there were means nothing at
 * all, since a writer that finds the pipe full writes none. */
static int empty(int fd)
{
	char taken[64];
	int  anything = 0;

	for (;;) {
		ssize_t got = read(fd, taken, sizeof(taken));

		if (got <= 0) {
			return anything;
		}
		anything = 1;
		if ((size_t)got < sizeof(taken)) {
			return anything;
		}
	}
}

/* A request is waiting. The wake is empty on purpose -- see
 * `ncfg_main_woke_for` -- and `ncfg_main_passes` is what reads the request
 * count. */
static int drain_request(void *context, ncfg_main_harvest_t *harvest, char *err, size_t err_size)
{
	int *fd = context;

	(void)harvest;
	(void)err;
	(void)err_size;
	(void)empty(*fd);
	return 1;
}

static int drain_stop(void *context, ncfg_main_harvest_t *harvest, char *err, size_t err_size)
{
	int *fd = context;

	(void)err;
	(void)err_size;
	/*
	 * Only where a byte was really there. The loop calls a drain when `poll`
	 * says the descriptor is ready, so on this path the two are the same
	 * thing -- but a source with no descriptor is *asked* on every round
	 * instead, and a stop that answered yes to being asked would end the
	 * daemon on its first tick. The question this answers is "was anything
	 * written", and that is the one to answer.
	 */
	if (empty(*fd)) {
		harvest->stopping = 1;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Opening
 * ------------------------------------------------------------------------ */

void ncfg_main_watchers_init(ncfg_main_watchers_t *watchers)
{
	if (!watchers) {
		return;
	}
	memset(watchers, 0, sizeof(*watchers));
	ncfg_netlink_init(&watchers->netlink);
	ncfg_rfkill_init(&watchers->rfkill);
	ncfg_inotify_init(&watchers->radio_dir);
	watchers->timer = -1;
	watchers->stop_read = -1;
	watchers->stop_write = -1;
	watchers->nudge_read = -1;
	watchers->nudge_write = -1;
	ncfg_main_sources_init(&watchers->sources);
}

/* Both ends non-blocking and close-on-exec. Non-blocking on the write end is
 * what keeps a signal handler from blocking in `write`; on the read end it is
 * what lets `empty` stop. */
static int pipe_pair(int *read_end, int *write_end, char *err, size_t err_size)
{
	int ends[2];
	int which;

	if (pipe(ends) != 0) {
		ncfg_error_set(err, err_size, "this daemon could not make a pipe to wake itself "
		    "with: %s", strerror(errno));
		return 0;
	}
	for (which = 0; which < 2; which++) {
		int flags = fcntl(ends[which], F_GETFL, 0);

		if (flags >= 0) {
			(void)fcntl(ends[which], F_SETFL, flags | O_NONBLOCK);
		}
		(void)fcntl(ends[which], F_SETFD, FD_CLOEXEC);
	}
	*read_end = ends[0];
	*write_end = ends[1];
	return 1;
}

static void add(ncfg_main_watchers_t *watchers, ncfg_main_source_kind_t kind, int fd,
    ncfg_main_drain_fn drain, void *context, const char *what)
{
	ncfg_main_source_t source;
	char               message[NCFG_ERROR_MAX];

	memset(&source, 0, sizeof(source));
	source.kind = kind;
	source.fd = fd;
	source.drain = drain;
	source.context = context;
	source.what = what;
	message[0] = '\0';
	if (!ncfg_main_sources_add(&watchers->sources, &source, message, sizeof(message))) {
		ncfg_log_emitf("loop", NCFG_LOG_WARNING, "%s", message);
	}
}

int ncfg_main_watchers_open(ncfg_main_watchers_t *watchers, const ncfg_main_watch_t *what,
    char *err, size_t err_size)
{
	char message[NCFG_ERROR_MAX];

	if (!watchers || !what) {
		ncfg_error_set(err, err_size, "opening a daemon's watches needs somewhere to put "
		    "them and something to watch");
		return 0;
	}
	ncfg_main_watchers_init(watchers);

	/*
	 * The two pipes first, and they are the only thing here whose failure is
	 * fatal. Everything else is a watch that can be missing; these two are how
	 * the loop is stopped and how a request reaches it, and a daemon that
	 * could not be stopped is one an operator has to kill.
	 */
	if (!pipe_pair(&watchers->stop_read, &watchers->stop_write, err, err_size)) {
		return 0;
	}
	if (!pipe_pair(&watchers->nudge_read, &watchers->nudge_write, err, err_size)) {
		return 0;
	}
	add(watchers, NCFG_MAIN_SOURCE_STOP, watchers->stop_read, drain_stop,
	    &watchers->stop_read, NULL);
	add(watchers, NCFG_MAIN_SOURCE_REQUEST, watchers->nudge_read, drain_request,
	    &watchers->nudge_read, NULL);

	watchers->timer = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	if (watchers->timer < 0) {
		/* Not fatal, and 0234 is why it is worth a line: the tick asks the
		 * window on every pass, so a missing timer costs seconds rather than
		 * the window. What it would cost silently is a window whose length is
		 * not the length it says. */
		ncfg_log_emitf("confirm", NCFG_LOG_WARNING,
		    "no timer could be made (%s), so a commit-confirm window will close on the "
		    "loop's five-second tick rather than on time", strerror(errno));
	} else {
		add(watchers, NCFG_MAIN_SOURCE_TIMER, watchers->timer, drain_timer,
		    &watchers->timer, NULL);
	}

	if (what->kernel) {
		message[0] = '\0';
		if (!ncfg_netlink_open_groups(&watchers->netlink, NCFG_NETLINK_GROUPS_OBSERVED,
		    message, sizeof(message))) {
			ncfg_log_emitf("netlink", NCFG_LOG_ERROR,
			    "cannot watch netlink (%s); a change to a link, an address or a route "
			    "will be noticed only on the loop's own tick", message);
		} else {
			watchers->has_netlink = 1;
			add(watchers, NCFG_MAIN_SOURCE_KERNEL,
			    ncfg_netlink_descriptor(&watchers->netlink), drain_kernel,
			    &watchers->netlink, NULL);
		}
	}

	if (what->config_dir) {
		/*
		 * The writable layer only, which is the Rust's choice and its reason:
		 * the factory layer is part of the image, it cannot change while the
		 * daemon runs on the read-only root it exists for, and watching it
		 * would cost two more inotify descriptors on the device with the
		 * fewest to spare.
		 */
		char        conf_d[512];
		const char *directories[2];
		int         opened;

		(void)snprintf(conf_d, sizeof(conf_d), "%s/conf.d", what->config_dir);
		directories[0] = what->config_dir;
		directories[1] = conf_d;
		message[0] = '\0';
		if (what->poll_config) {
			opened = ncfg_watch_open_polling(&watchers->watch, directories, 2u,
			    message, sizeof(message));
		} else {
			opened = ncfg_watch_open(&watchers->watch, directories, 2u, message,
			    sizeof(message));
		}
		if (!opened) {
			ncfg_log_emitf("config", NCFG_LOG_ERROR,
			    "cannot watch %s (%s); a configuration change will not be noticed "
			    "until something else wakes the loop", what->config_dir, message);
		} else {
			watchers->has_watch = 1;
			/* **Not announced here**, because the daemon says it once: the
			 * mechanism and the socket are one fact about how this daemon can
			 * be reached and changed, and `start()` emits them together as
			 * the Rust does. Said in both places, an operator counting
			 * `watching` lines in a log finds two and a reader of the second
			 * has to know the first exists. The failure above is still said
			 * here, because a watcher that could not open is this function's
			 * news and not the socket's. */
			add(watchers, NCFG_MAIN_SOURCE_CONFIG,
			    ncfg_watch_descriptor(&watchers->watch), drain_config,
			    &watchers->watch, what->config_dir);
		}
	}

	if (what->rfkill_device) {
		message[0] = '\0';
		if (!ncfg_rfkill_open(&watchers->rfkill, what->rfkill_device, message,
		    sizeof(message))) {
			/*
			 * **A machine with no radio has no `/dev/rfkill` and that is not a
			 * fault** -- 0199, which is that anything else is one and used to
			 * be silent. The distinction is `ENOENT` and is made here rather
			 * than by reading the sentence, which `config.h` forbids: the
			 * absence is quiet and everything else is a warning naming what
			 * is lost.
			 */
			if (errno == ENOENT) {
				ncfg_log_emitf("rfkill", NCFG_LOG_VERBOSE,
				    "there is no %s on this machine, so there is no kill switch "
				    "to watch", what->rfkill_device);
			} else {
				ncfg_log_emitf("rfkill", NCFG_LOG_WARNING,
				    "cannot read %s (%s); netcfgd will not notice a kill switch "
				    "being flipped on this machine", what->rfkill_device, message);
			}
		} else {
			watchers->has_rfkill = 1;
			add(watchers, NCFG_MAIN_SOURCE_RFKILL,
			    ncfg_rfkill_descriptor(&watchers->rfkill), drain_rfkill,
			    &watchers->rfkill, what->rfkill_device);
		}
	}

	if (what->supplicant_dir) {
		int    wd = -1;
		size_t reaped;

		(void)snprintf(watchers->supplicant_dir, sizeof(watchers->supplicant_dir), "%s",
		    what->supplicant_dir);
		/*
		 * **The dead reply sockets go before anything lists this directory**,
		 * which is the one moment they can be swept without racing the scan
		 * that follows. netcfgd installs no `SIGTERM` handler, so every one of
		 * its lives leaves two behind -- 18 entries to 20 per restart, for
		 * ever (0193) -- and `attach` has to walk past each of them on every
		 * refresh.
		 *
		 * **Here rather than where the directory is resolved.** It was in
		 * `daemon_main.c`, one call in the one function a test may not run,
		 * so the only thing holding it was a `grep` of the source
		 * (project.md 10.239). The sweep belongs with the code that lists the
		 * directory in any case: this is the first thing in this program that
		 * reads it, and the reason the sweep is once rather than per connect
		 * is that the set can only grow when a process dies.
		 */
		reaped = ncfg_supplicant_reap_reply_sockets(watchers->supplicant_dir);
		if (reaped > 0u) {
			ncfg_log_emitf("supplicant", NCFG_LOG_NOTE,
			    "removed %zu reply socket(s) in %s left by processes that are gone",
			    reaped, watchers->supplicant_dir);
		}
		/* Stale from the start, so that the first refresh is the scan: the
		 * radios that already exist produce no inotify event, having appeared
		 * before there was anything watching. */
		watchers->radios_stale = 1;
		message[0] = '\0';
		if (!ncfg_inotify_open(&watchers->radio_dir, message, sizeof(message)) ||
		    !ncfg_inotify_watch(&watchers->radio_dir, watchers->supplicant_dir,
		    NCFG_WATCH_CONFIG_MASK, &wd, message, sizeof(message))) {
			ncfg_inotify_close(&watchers->radio_dir);
			/* The scan still happens, on the tick: what is lost is
			 * promptness, which is why this is a note rather than a warning.
			 * A radio appearing is followed by netlink events of its own. */
			ncfg_log_emitf("supplicant", NCFG_LOG_NOTE,
			    "cannot watch %s (%s); a radio appearing will be picked up on the "
			    "loop's tick rather than at once", watchers->supplicant_dir, message);
		} else {
			watchers->has_radio_dir = 1;
			add(watchers, NCFG_MAIN_SOURCE_RADIO_DIR,
			    ncfg_inotify_descriptor(&watchers->radio_dir), drain_radio_dir,
			    watchers, watchers->supplicant_dir);
		}
	}
	return 1;
}

static void forget_radio(ncfg_main_watchers_t *watchers, ncfg_main_radio_t *radio)
{
	size_t at;

	for (at = watchers->sources.count; at > 0u; at--) {
		ncfg_main_source_t *source = &watchers->sources.at[at - 1u];

		if (source->kind == NCFG_MAIN_SOURCE_RADIO && source->context == radio) {
			ncfg_main_sources_forget(&watchers->sources, at - 1u);
		}
	}
	ncfg_supplicant_client_free(radio->client);
	memset(radio, 0, sizeof(*radio));
}

void ncfg_main_watchers_close(ncfg_main_watchers_t *watchers)
{
	size_t at;

	if (!watchers) {
		return;
	}
	for (at = 0; at < (size_t)NCFG_MAIN_RADIOS_MAX; at++) {
		if (watchers->radios[at].client) {
			forget_radio(watchers, &watchers->radios[at]);
		}
	}
	if (watchers->has_netlink) {
		ncfg_netlink_close(&watchers->netlink);
	}
	if (watchers->has_watch) {
		ncfg_watch_close(&watchers->watch);
	}
	if (watchers->has_rfkill) {
		ncfg_rfkill_close(&watchers->rfkill);
	}
	if (watchers->has_radio_dir) {
		ncfg_inotify_close(&watchers->radio_dir);
	}
	if (watchers->timer >= 0) {
		(void)close(watchers->timer);
	}
	if (watchers->stop_read >= 0) {
		(void)close(watchers->stop_read);
	}
	if (watchers->stop_write >= 0) {
		(void)close(watchers->stop_write);
	}
	if (watchers->nudge_read >= 0) {
		(void)close(watchers->nudge_read);
	}
	if (watchers->nudge_write >= 0) {
		(void)close(watchers->nudge_write);
	}
	ncfg_main_watchers_init(watchers);
}

void ncfg_main_watchers_stop(ncfg_main_watchers_t *watchers)
{
	static const char one = 's';

	if (!watchers || watchers->stop_write < 0) {
		return;
	}
	/*
	 * `write` and nothing else, because this is called from a signal handler.
	 * A full pipe already says what a second byte would, so `EAGAIN` is
	 * success -- and the write is non-blocking, so a handler cannot be left
	 * inside it.
	 */
	(void)!write(watchers->stop_write, &one, 1u);
}

void ncfg_main_watchers_expiry(void *context, uint32_t seconds)
{
	ncfg_main_watchers_t *watchers = context;
	struct itimerspec     when;

	if (!watchers || watchers->timer < 0) {
		return;
	}
	memset(&when, 0, sizeof(when));
	when.it_value.tv_sec = (time_t)seconds;
	/*
	 * A window of no seconds still has to fire, and `{0,0}` disarms a timerfd
	 * rather than firing it at once -- so the one nanosecond is not a rounding
	 * choice, it is the difference between a window that closes and one that
	 * never does. `--confirm-within 0` never reaches here (it is two spellings
	 * of "no window"), which makes this the arithmetic case rather than the
	 * operator's.
	 */
	if (seconds == 0u) {
		when.it_value.tv_nsec = 1;
	}
	if (timerfd_settime(watchers->timer, 0, &when, NULL) != 0) {
		ncfg_log_emitf("confirm", NCFG_LOG_WARNING,
		    "the window's timer could not be armed (%s), so it will close on the loop's "
		    "tick instead", strerror(errno));
	}
}

/* ------------------------------------------------------------------------ *
 * Radios
 * ------------------------------------------------------------------------ */

/* `(device, inode)` of a path, which is what tells a supplicant that restarted
 * from one that is simply quiet. A modification time would not: a supplicant
 * restarting within the same second gets a new inode and may not get a new
 * timestamp. 0240. */
static int socket_identity(const char *path, uint64_t *device, uint64_t *inode)
{
	struct stat about;

	if (stat(path, &about) != 0) {
		return 0;
	}
	*device = (uint64_t)about.st_dev;
	*inode = (uint64_t)about.st_ino;
	return 1;
}

/* Is this radio's descriptor still in the set? The loop drops a source that
 * hung up, and the radio it belonged to has to be let go of with it -- an
 * attached client nothing polls is a connection held open for the life of the
 * daemon, reporting nothing. */
static int still_watched(const ncfg_main_watchers_t *watchers, const ncfg_main_radio_t *radio)
{
	size_t at;

	for (at = 0; at < watchers->sources.count; at++) {
		if (watchers->sources.at[at].kind == NCFG_MAIN_SOURCE_RADIO &&
		    watchers->sources.at[at].context == radio) {
			return 1;
		}
	}
	return 0;
}

static int watched_already(const ncfg_main_watchers_t *watchers, const char *interface)
{
	size_t at;

	for (at = 0; at < (size_t)NCFG_MAIN_RADIOS_MAX; at++) {
		if (watchers->radios[at].client &&
		    strcmp(watchers->radios[at].interface, interface) == 0) {
			return 1;
		}
	}
	return 0;
}

/* Attach to one radio, and put its descriptor in the set. Quiet on failure:
 * every entry in that directory that is not a supplicant has already been
 * filtered out, and what is left failing is a supplicant that is starting. */
static void attach(ncfg_main_watchers_t *watchers, const char *name)
{
	char                      interface[NCFG_LINK_NAME_MAX + 1u];
	char                      path[640];
	char                      message[NCFG_ERROR_MAX];
	ncfg_supplicant_client_t *client;
	ncfg_main_radio_t        *radio = NULL;
	size_t                    at;
	size_t                    length;

	/*
	 * An interface name is at most fifteen characters, which
	 * `ncfg_supplicant_connect_within` refuses past and which this copies
	 * rather than truncates: a directory entry longer than that is not an
	 * interface, and a name cut to fit would be a connection attempt against a
	 * socket somebody else named. It is also what bounds the two buffers
	 * below, so that the compiler can see they cannot overflow.
	 */
	if (!name) {
		return;
	}
	length = strlen(name);
	if (length >= sizeof(interface)) {
		return;
	}
	memcpy(interface, name, length);
	interface[length] = '\0';

	for (at = 0; at < (size_t)NCFG_MAIN_RADIOS_MAX; at++) {
		if (!watchers->radios[at].client) {
			radio = &watchers->radios[at];
			break;
		}
	}
	if (!radio) {
		ncfg_log_emitf("supplicant", NCFG_LOG_WARNING,
		    "this daemon watches at most %d radios, so %s is not being watched; roaming "
		    "and authentication failures will go unreported for it",
		    NCFG_MAIN_RADIOS_MAX, interface);
		return;
	}
	message[0] = '\0';
	/*
	 * Impatiently, for the reason every other control-socket deadline in this
	 * tree has one: what is left after the reply-socket filter is a real
	 * supplicant, and a wedged one would otherwise cost the loop ten seconds
	 * in the middle of a round. 0114.
	 */
	client = ncfg_supplicant_connect_within(watchers->supplicant_dir, interface,
	    NCFG_SUPPLICANT_IMPATIENT_MS, message, sizeof(message));
	if (!client) {
		return;
	}
	/*
	 * **Without `ATTACH` this connection gets replies and no events**, so the
	 * drain would be a silent no-op for ever -- and the failure used to be
	 * silent too (0225), which is the same sentence pointed at netcfgd: every
	 * diagnostic read through this connection is one netcfgd has gone quiet
	 * about.
	 */
	if (!ncfg_supplicant_attach(client, message, sizeof(message))) {
		ncfg_log_emitf("supplicant", NCFG_LOG_WARNING,
		    "%s: cannot watch this radio's events (%s); roaming, authentication "
		    "failures and refused associations will go unreported for it", interface,
		    message);
		ncfg_supplicant_client_free(client);
		return;
	}
	(void)snprintf(path, sizeof(path), "%s/%s", watchers->supplicant_dir, interface);
	/* Recorded after attaching rather than before, so a supplicant that
	 * restarts in between costs one extra reconnect rather than leaving a
	 * stale identity recorded as current. */
	if (!socket_identity(path, &radio->device, &radio->inode)) {
		ncfg_supplicant_client_free(client);
		memset(radio, 0, sizeof(*radio));
		return;
	}
	radio->client = client;
	memcpy(radio->interface, interface, sizeof(interface));
	add(watchers, NCFG_MAIN_SOURCE_RADIO, ncfg_supplicant_client_descriptor(client),
	    drain_radio, radio, radio->interface);
}

void ncfg_main_watchers_refresh(void *context, ncfg_main_sources_t *sources)
{
	ncfg_main_watchers_t *watchers = context;
	DIR                  *directory;
	struct dirent        *entry;
	size_t                at;

	if (!watchers || watchers->supplicant_dir[0] == '\0') {
		return;
	}
	/* The set this is handed is the watchers' own -- `ncfg_main_run_t::sources`
	 * points at it -- and the argument is there because the seam is the loop's
	 * rather than this module's. Everything below goes through the field, so
	 * that `add` and `forget_radio` cannot be pointed at a different one. */
	(void)sources;

	/*
	 * **Before anything is read, because a dead connection reads as a quiet
	 * one (0240).** `next_event` only ever receives, and a connected datagram
	 * socket whose peer has exited does not report that: the read times out,
	 * which is indistinguishable from a radio with nothing to say. So the
	 * entry stayed, the scan below skipped the interface because it already
	 * had one, and the radio went deaf for the life of the process.
	 *
	 * One `stat` per radio per round, no round trip, and nothing to mistake
	 * for an event.
	 */
	for (at = 0; at < (size_t)NCFG_MAIN_RADIOS_MAX; at++) {
		ncfg_main_radio_t *radio = &watchers->radios[at];
		char               path[640];
		uint64_t           device = 0;
		uint64_t           inode = 0;

		if (!radio->client) {
			continue;
		}
		(void)snprintf(path, sizeof(path), "%s/%s", watchers->supplicant_dir,
		    radio->interface);
		if (socket_identity(path, &device, &inode) && device == radio->device &&
		    inode == radio->inode && still_watched(watchers, radio)) {
			continue;
		}
		ncfg_log_emitf("supplicant", NCFG_LOG_NOTE,
		    "%s: the control socket was replaced or went away, so this radio's events "
		    "were going nowhere; re-attaching", radio->interface);
		forget_radio(watchers, radio);
		watchers->radios_stale = 1;
	}

	/*
	 * **A directory nothing is watching is a directory that is always stale.**
	 * The inotify above exists to make a radio appearing noticed at once, and
	 * `radios_stale` is what keeps the scan off the ordinary round; where the
	 * descriptor could not be opened -- a container, or
	 * `fs.inotify.max_user_instances` exhausted -- nothing would ever set the
	 * flag again once the last radio had gone, and a supplicant started
	 * afterwards would never be attached to for the life of the daemon. So
	 * that build scans every round, which is what the Rust does on every
	 * machine.
	 */
	if (!watchers->has_radio_dir) {
		watchers->radios_stale = 1;
	}
	if (!watchers->radios_stale) {
		return;
	}
	watchers->radios_stale = 0;
	directory = opendir(watchers->supplicant_dir);
	if (!directory) {
		return;
	}
	while ((entry = readdir(directory)) != NULL) {
		if (entry->d_name[0] == '.') {
			continue;
		}
		/*
		 * **Not every entry here is an interface.** A datagram client binds
		 * its own reply socket in this directory, so netcfgd's own in-flight
		 * connections appear beside the supplicants -- and connecting to one
		 * waits out the full deadline against a process that will never
		 * answer, while delivering the `PING` into that client's reply queue
		 * where it can be read as the answer to a command it actually sent.
		 * 0112.
		 */
		if (ncfg_supplicant_is_reply_socket(entry->d_name)) {
			continue;
		}
		if (watched_already(watchers, entry->d_name)) {
			continue;
		}
		attach(watchers, entry->d_name);
	}
	(void)closedir(directory);
}

/* ------------------------------------------------------------------------ *
 * Signals
 * ------------------------------------------------------------------------ */

/*
 * The one piece of global state in this directory, and it is what a signal
 * handler is allowed to touch.
 *
 * A handler takes no argument, so the descriptor it writes to has to reach it
 * some other way. `volatile sig_atomic_t` is not enough for a pointer, so what
 * is kept is the pointer and what the handler does with it is one
 * `write` -- which is async-signal-safe, which is the whole reason the byte
 * goes in a pipe rather than into a flag.
 */
static ncfg_main_watchers_t *signalled;
static struct sigaction      was_term;
static struct sigaction      was_int;
static int                   handlers_installed;

static void asked_to_stop(int signal_number)
{
	int saved = errno;

	(void)signal_number;
	if (signalled) {
		ncfg_main_watchers_stop(signalled);
	}
	/*
	 * Put `errno` back. A handler that changes it corrupts whatever syscall it
	 * interrupted -- and the syscall it interrupts here is the `poll` the
	 * whole daemon sleeps in, whose `EINTR` is read out of exactly this
	 * variable.
	 */
	errno = saved;
}

int ncfg_main_signals_watch(ncfg_main_watchers_t *watchers, char *err, size_t err_size)
{
	struct sigaction action;

	if (!watchers || watchers->stop_write < 0) {
		ncfg_error_set(err, err_size, "there is no pipe for a signal to be written to");
		return 0;
	}
	signalled = watchers;
	memset(&action, 0, sizeof(action));
	action.sa_handler = asked_to_stop;
	(void)sigemptyset(&action.sa_mask);
	/*
	 * No `SA_RESTART`, which changes nothing about `poll` -- it is never
	 * restarted -- and is the honest setting: what stops this loop is the byte
	 * in the pipe, and `EINTR` is handled where it arrives rather than avoided
	 * here.
	 */
	action.sa_flags = 0;
	if (sigaction(SIGTERM, &action, &was_term) != 0 ||
	    sigaction(SIGINT, &action, &was_int) != 0) {
		ncfg_error_set(err, err_size, "this daemon could not arrange to be stopped: %s",
		    strerror(errno));
		signalled = NULL;
		return 0;
	}
	handlers_installed = 1;
	return 1;
}

void ncfg_main_signals_restore(void)
{
	if (!handlers_installed) {
		return;
	}
	(void)sigaction(SIGTERM, &was_term, NULL);
	(void)sigaction(SIGINT, &was_int, NULL);
	handlers_installed = 0;
	signalled = NULL;
}
