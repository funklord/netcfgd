/*
 * loop_test.c -- the descriptor loop, against descriptors this file made.
 *
 * NOTHING HERE TOUCHES THE MACHINE THIS IS BUILT ON
 *   netcfgd is running on it and it is somebody's workstation. So: no netlink
 *   socket is opened in a multicast group, `/dev/rfkill` is never opened, the
 *   real daemon's socket is never connected to, nothing is written outside a
 *   directory this binary made with `mkdtemp`, and no path below has a
 *   default. Every descriptor the loop is driven over is a pipe, a fifo, a
 *   timerfd or an inotify watch on that directory.
 *
 *   The one thing that is real and could not be faked is the configuration
 *   watch, which is `ncfg_watch_open` over the test's own directory -- both
 *   mechanisms, because a fall-back that only runs when something else has
 *   already gone wrong is a fall-back nobody has ever seen work.
 *
 * WHAT IS WORTH CHECKING IN A LOOP, WHICH IS NOT THE HAPPY PATH
 *   One event in and one pass out is the case that works in every version of
 *   this file, including the wrong ones. What separates them is the rest:
 *
 *     * a burst of fifty writes that must collapse into **one** observation,
 *       and a burst that never ends, which must not stop the pass from
 *       running at all;
 *     * a descriptor that reports `POLLHUP`, or `POLLNVAL`, or `POLLERR`
 *       for ever -- each of which makes `poll` return instantly, which is how
 *       a daemon comes to spin at 100% CPU while still answering clients;
 *     * `POLLIN` arriving together with `POLLHUP`, where reading first is the
 *       difference between the last records and no records;
 *     * `EINTR`, which netcfgd generates itself every time it runs a hook,
 *       and which must not restart the backstop it interrupted;
 *     * a signal arriving between the check and the wait, which is why the
 *       byte goes in a pipe;
 *     * a window's timer that fires while a pass is running, whose wake must
 *       still be there on the other side of it;
 *     * and a request waiting on a thread of its own, which the pass must see
 *       before it is answered.
 *
 *   The clock is a seam, so none of this waits. The one exception is the
 *   `EINTR` case, which needs a signal to really arrive and spends fifty
 *   milliseconds on it.
 */
#include "../src/main/loop_internal.h"

#include "ncfg/base.h"
#include "ncfg/daemon.h"
#include "ncfg/log.h"
#include "ncfg/netlink.h"
#include "ncfg/observed.h"
#include "ncfg/proto.h"
#include "ncfg/rfkill.h"
#include "ncfg/supplicant.h"
#include "ncfg/watch.h"

#include "supplicantfake.h"
#include "testdir.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

static int failures;
static int checks;

static void check(int condition, const char *what)
{
	checks++;
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static void detail(const char *label, const char *text)
{
	printf("       %s: %s\n", label, text ? text : "(none)");
}

/* ------------------------------------------------------------------------ *
 * A clock this file moves
 * ------------------------------------------------------------------------ */

static uint64_t hands[8];
static size_t   hand_count;
static size_t   hand_at;

static void clock_is(const uint64_t *readings, size_t count)
{
	size_t at;

	hand_count = count < 8u ? count : 8u;
	hand_at = 0;
	for (at = 0; at < hand_count; at++) {
		hands[at] = readings[at];
	}
}

/* The readings in order, and the last one for ever afterwards. A clock that
 * ran out mid-round would otherwise answer zero and make every deadline look
 * far away, which is the one wrong answer that would hang the suite. */
static uint64_t fake_ticks(void *context)
{
	(void)context;
	if (hand_at < hand_count) {
		return hands[hand_at++];
	}
	return hand_count > 0u ? hands[hand_count - 1u] : 0u;
}

/* Two readings a round apart, which makes every wait below a `poll` of zero
 * milliseconds: the deadline is already past by the time the timeout is
 * computed. */
static void clock_is_expired(void)
{
	static const uint64_t readings[2] = { 0u, (uint64_t)NCFG_MAIN_TICK_MS };

	clock_is(readings, 2u);
}

/* The same, leaving two hundred milliseconds of the deadline unspent: a wait
 * long enough for the kernel to deliver something that has already been asked
 * for, and short enough that a check which never gets it fails rather than
 * holding the suite up. */
static void clock_is_patient(void)
{
	static const uint64_t readings[2] = { 0u, (uint64_t)NCFG_MAIN_TICK_MS - 200u };

	clock_is(readings, 2u);
}

static uint64_t elapsed_ms(const struct timespec *from)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
		return 0u;
	}
	return (uint64_t)(now.tv_sec - from->tv_sec) * 1000u +
	    (uint64_t)((now.tv_nsec - from->tv_nsec) / 1000000);
}

/* ------------------------------------------------------------------------ *
 * The decisions
 * ------------------------------------------------------------------------ */

static void a_revents_mask_says_one_of_five_things(void)
{
	check(ncfg_main_readiness(POLLIN) == NCFG_MAIN_READY_DATA,
	    "something to read is something to read");
	check(ncfg_main_readiness(0) == NCFG_MAIN_READY_NOTHING,
	    "and an empty mask is nothing at all");
	check(ncfg_main_readiness(POLLHUP) == NCFG_MAIN_READY_ENDED,
	    "a hang-up on its own is the far end gone");
	check(ncfg_main_readiness(POLLERR) == NCFG_MAIN_READY_ERRORED,
	    "an error on its own is an error");
	check(ncfg_main_readiness(POLLNVAL) == NCFG_MAIN_READY_CLOSED,
	    "and a descriptor that is not open is neither of those");

	/*
	 * The three that decide whether a last record is read or thrown away. A
	 * writer that queued bytes and closed sets both, and so does a socket
	 * that errored after delivering.
	 */
	check(ncfg_main_readiness(POLLIN | POLLHUP) == NCFG_MAIN_READY_DATA,
	    "data arriving with a hang-up is read first, not dropped with it");
	check(ncfg_main_readiness(POLLIN | POLLERR) == NCFG_MAIN_READY_DATA,
	    "and so is data arriving with an error");
	check(ncfg_main_readiness(POLLERR | POLLHUP) == NCFG_MAIN_READY_ERRORED,
	    "an error and a hang-up together is the error, which a read can clear");
	/* And the one exception to "read first": there is nothing to read from a
	 * descriptor this process does not have. */
	check(ncfg_main_readiness(POLLIN | POLLNVAL) == NCFG_MAIN_READY_CLOSED,
	    "but a descriptor that is not open is never read, whatever else is set");
}

static void a_source_that_cannot_answer_loses_its_place(void)
{
	check(ncfg_main_source_survives(NCFG_MAIN_READY_DATA, 0u), "a source with data stays");
	check(ncfg_main_source_survives(NCFG_MAIN_READY_NOTHING, 0u),
	    "and so does one that said nothing");
	check(ncfg_main_source_survives(NCFG_MAIN_READY_ERRORED, 1u),
	    "an error is given a few rounds, because a read is what clears one");
	check(!ncfg_main_source_survives(NCFG_MAIN_READY_ERRORED,
	    (unsigned)NCFG_MAIN_SOURCE_PATIENCE),
	    "and an error that will not clear is not polled for ever");
	/*
	 * No patience at all for these two, and that is the whole point: a
	 * hung-up descriptor is ready every single time it is polled, so "give it
	 * another round" is a busy loop with a counter in it.
	 */
	check(!ncfg_main_source_survives(NCFG_MAIN_READY_ENDED, 0u),
	    "a far end that has gone is dropped at once and not after three tries");
	check(!ncfg_main_source_survives(NCFG_MAIN_READY_CLOSED, 0u),
	    "and so is a descriptor that is not open");
}

static void what_poll_came_back_with(void)
{
	check(ncfg_main_wait_meant(1, 0) == NCFG_MAIN_WAIT_READY, "a positive answer is readiness");
	check(ncfg_main_wait_meant(0, 0) == NCFG_MAIN_WAIT_TICKED,
	    "nothing in time is the loop's own backstop");
	check(ncfg_main_wait_meant(-1, EINTR) == NCFG_MAIN_WAIT_AGAIN,
	    "a signal mid-syscall means ask again, which is 0233");
	check(ncfg_main_wait_meant(-1, EBADF) == NCFG_MAIN_WAIT_FAILED,
	    "and everything else is a failure");
	check(ncfg_main_wait_meant(-1, EINVAL) == NCFG_MAIN_WAIT_FAILED,
	    "including one that says the wait itself was wrong");
}

static void the_wait_is_what_is_left_of_the_deadline(void)
{
	check(ncfg_main_timeout_until(5000u, 1000u) == 4000,
	    "a deadline four seconds off is a wait of four seconds");
	check(ncfg_main_timeout_until(5000u, 5000u) == 0,
	    "a deadline reached exactly is a wait of none");
	/*
	 * The one arithmetic slip here that would stop a daemon dead. `poll`
	 * reads a negative timeout as "no timeout", so a deadline in the past
	 * would put it to sleep for ever on the machine the backstop exists for.
	 */
	check(ncfg_main_timeout_until(5000u, 9000u) == 0,
	    "and a deadline already past is a wait of none, never a negative number");
	check(ncfg_main_timeout_until(50000u, 0u) == NCFG_MAIN_TICK_MS,
	    "a deadline further off than a tick is clamped to one");
	check(ncfg_main_timeout_until(0u, 0u) == 0, "and a clock that answers nothing waits");
}

static void a_burst_is_collapsed_but_not_for_ever(void)
{
	check(ncfg_main_drains_again(1u), "a burst is looked at again");
	check(ncfg_main_drains_again((unsigned)NCFG_MAIN_DRAIN_ROUNDS - 1u),
	    "and again, up to the bound");
	check(!ncfg_main_drains_again((unsigned)NCFG_MAIN_DRAIN_ROUNDS),
	    "and then the pass gets its turn, whatever is still arriving");
}

static void which_wake_a_descriptor_folds_into(void)
{
	ncfg_woke_t woke = NCFG_WOKE_TICK;

	check(ncfg_main_woke_for(NCFG_MAIN_SOURCE_KERNEL, &woke) && woke == NCFG_WOKE_KERNEL,
	    "netlink is the kernel saying the machine moved");
	woke = NCFG_WOKE_TICK;
	check(ncfg_main_woke_for(NCFG_MAIN_SOURCE_RFKILL, &woke) && woke == NCFG_WOKE_KERNEL,
	    "and a kill switch is the same wake, because the answer is the same");
	woke = NCFG_WOKE_TICK;
	check(ncfg_main_woke_for(NCFG_MAIN_SOURCE_CONFIG, &woke) && woke == NCFG_WOKE_CONFIG,
	    "the configuration directory is its own");
	woke = NCFG_WOKE_TICK;
	check(ncfg_main_woke_for(NCFG_MAIN_SOURCE_TIMER, &woke) &&
	    woke == NCFG_WOKE_CONFIRM_EXPIRED,
	    "and so is the window's timer");
	check(!ncfg_main_woke_for(NCFG_MAIN_SOURCE_RADIO, &woke),
	    "a radio's events are not a wake -- two roams are two events");
	check(!ncfg_main_woke_for(NCFG_MAIN_SOURCE_RADIO_DIR, &woke),
	    "nor is a supplicant appearing, which changes no machine");
	check(!ncfg_main_woke_for(NCFG_MAIN_SOURCE_REQUEST, &woke),
	    "nor a waiting request, which must not make every `ncfg status` re-read "
	    "the kernel");
	check(!ncfg_main_woke_for(NCFG_MAIN_SOURCE_STOP, &woke),
	    "and being asked to stop is not something to reconcile about");
}

static void a_round_with_nothing_in_it_runs_no_pass(void)
{
	ncfg_reconcile_wake_t wake;

	memset(&wake, 0, sizeof(wake));
	check(!ncfg_main_passes(&wake, 0u, 0u),
	    "a round that woke only to drop a descriptor plans nothing");
	check(ncfg_main_passes(&wake, 1u, 0u), "a roam is worth a pass");
	check(ncfg_main_passes(&wake, 0u, 1u), "and so is a request waiting to be answered");
	ncfg_reconcile_collapse(&wake, NCFG_WOKE_TICK);
	check(ncfg_main_passes(&wake, 0u, 0u), "and the backstop always is");
	memset(&wake, 0, sizeof(wake));
	ncfg_reconcile_collapse(&wake, NCFG_WOKE_CONFIG);
	check(ncfg_main_passes(&wake, 0u, 0u),
	    "a write in the configuration directory is a pass even with no kernel event");
}


/*
 * What the log says about one supplicant event.
 *
 * **Every arm used to end in a log macro**, which writes and returns nothing,
 * so a test could assert that the code compiled and no more -- the Rust's own
 * comment records an arm going in with nothing holding it. The decision is a
 * value here, which is what makes these checks possible at all.
 *
 * And the levels are the subject as much as the words: a disconnect this
 * machine caused happens dozens of times a day and a station being dropped is
 * rare, so reporting both the same way is a log nobody can read.
 */
static void what_the_log_says_about_a_supplicant_event(void)
{
	ncfg_supplicant_event_t event;
	char                    said[NCFG_LOG_MAX];
	int                     severity = -1;

	/* The association itself, which is what somebody reading a day's log is
	 * looking for. */
	check(ncfg_supplicant_event_parse(
	          "<3>CTRL-EVENT-CONNECTED - Connection to a0:a4:7f:23:9a:cf completed "
	          "[id=0 id_str=]", &event) &&
	        ncfg_main_supplicant_event_line("wlan0", &event, &severity, said, sizeof(said)),
	    "a `CONNECTED` is worth a line");
	check(strcmp(said, "wlan0: joined a0:a4:7f:23:9a:cf") == 0, "  naming what it joined");
	check(severity == NCFG_LOG_NOTE, "  at note, because an association is rare on a desk");

	/* **Who ended a disconnect is its whole content.** */
	check(ncfg_supplicant_event_parse(
	          "<3>CTRL-EVENT-DISCONNECTED bssid=a0:a4:7f:23:9a:cf reason=3 "
	          "locally_generated=1", &event) &&
	        ncfg_main_supplicant_event_line("wlan0", &event, &severity, said, sizeof(said)),
	    "a disconnect this machine caused is reported");
	check(strcmp(said, "wlan0: left a0:a4:7f:23:9a:cf (reason 3)") == 0,
	    "  as this machine leaving");
	check(severity == NCFG_LOG_VERBOSE,
	    "  at verbose, because there are dozens of them on an ordinary day");
	check(ncfg_supplicant_event_parse(
	          "<3>CTRL-EVENT-DISCONNECTED bssid=a0:a4:7f:23:9a:cf reason=3", &event) &&
	        ncfg_main_supplicant_event_line("wlan0", &event, &severity, said, sizeof(said)),
	    "and one the access point caused is reported differently");
	check(strcmp(said, "wlan0: dropped by a0:a4:7f:23:9a:cf (reason 3)") == 0,
	    "  as the station being dropped");
	check(severity == NCFG_LOG_NOTE, "  at note, because that one is rare and wanted");

	/* The network given up on, and the network tried again -- 0225's pair. */
	check(ncfg_supplicant_event_parse(
	          "<3>CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"Cafe\" auth_failures=2 "
	          "duration=10 reason=WRONG_KEY", &event) &&
	        ncfg_main_supplicant_event_line("wlan0", &event, &severity, said, sizeof(said)) &&
	        severity == NCFG_LOG_WARNING,
	    "a network the supplicant has given up on is a warning");
	check(strstr(said, "not trying `Cafe` for 10s") != NULL &&
	        strstr(said, "2 failed attempts so far (WRONG_KEY)") != NULL,
	    "  carrying the supplicant's own reason, which is where a person goes next");
	check(ncfg_supplicant_event_parse("<3>CTRL-EVENT-SSID-REENABLED id=0 ssid=\"Cafe\"",
	          &event) &&
	        ncfg_main_supplicant_event_line("wlan0", &event, &severity, said, sizeof(said)),
	    "and the recovery is reported too, which is the half that was missing");
	check(strcmp(said, "wlan0: trying `Cafe` again") == 0,
	    "  so a network that came back does not read as an outage that never ended");

	/* The two the access point refuses, and the scan that could not run. */
	check(ncfg_supplicant_event_parse("<3>CTRL-EVENT-ASSOC-REJECT status_code=17", &event) &&
	        ncfg_main_supplicant_event_line("wlan0", &event, &severity, said, sizeof(said)) &&
	        severity == NCFG_LOG_WARNING &&
	        strcmp(said, "wlan0: the access point refused this station, status 17") == 0,
	    "an access point refusing the station says so, with its status");
	check(ncfg_supplicant_event_parse("<3>CTRL-EVENT-SCAN-FAILED ret=-16", &event) &&
	        ncfg_main_supplicant_event_line("wlan0", &event, &severity, said, sizeof(said)) &&
	        strcmp(said, "wlan0: the radio could not scan (ret=-16)") == 0,
	    "and a scan the radio could not run is a line rather than silence");

	/* Most of the stream by volume, and netcfgd has nothing to say about it. */
	check(ncfg_supplicant_event_parse("<3>CTRL-EVENT-SCAN-RESULTS ", &event) &&
	        !ncfg_main_supplicant_event_line("wlan0", &event, &severity, said, sizeof(said)),
	    "a scan result is not narrated, which is most of the stream");
	check(said[0] == '\0', "  and nothing is left in the buffer to be printed by mistake");

	/* A field the event does not carry is `?` rather than a gap in the
	 * sentence: what is being reported is what arrived. */
	check(ncfg_supplicant_event_parse("<3>CTRL-EVENT-DISCONNECTED reason=3", &event) &&
	        ncfg_main_supplicant_event_line("wlan0", &event, &severity, said, sizeof(said)) &&
	        strcmp(said, "wlan0: dropped by ? (reason 3)") == 0,
	    "a field the event did not carry reads as `?`");
}


/*
 * A supplicant event reaches the log, driven rather than read.
 *
 * **This is what `main_test.c` was grepping the source for.** The decision --
 * which events are worth a line, at what level -- is checked above as a value.
 * What could not be checked was the watcher actually saying it: that wants a
 * supplicant bound in a control directory, and the fake for one lived inside
 * `supplicant_client_test.c` where nothing else could reach it. It is
 * `supplicantfake.h` now, and this is the first thing that needed it.
 *
 * Nothing here goes near a radio: the socket is in a directory this test made,
 * the interface is `wlan0` and exists only there, and the fake is a forked
 * process this test started and takes down by its own recorded pid.
 */

/*
 * The dead reply sockets are swept when the watches open.
 *
 * **A live one beside them is the half that matters.** A sweep that removed
 * everything shaped like a reply socket would take the one a client has open
 * right now -- netcfgd's own in-flight connections live in this directory --
 * and the command that client is waiting on would never be answered. So the
 * question is asked of the kernel: connecting to a unix datagram address
 * answers `ECONNREFUSED` when nobody has it bound, which is the definition of
 * a stale file rather than a guess at one (0224).
 *
 * This is what `main_test.c` was grepping `daemon_main.c` for. The call moved
 * to where the directory is first listed, which is both the right place and
 * somewhere a test can reach.
 */
static void the_dead_reply_sockets_are_swept(const char *base)
{
	struct sockaddr_un   address;
	ncfg_main_watchers_t watchers;
	ncfg_main_watch_t    what;
	/* Sized to a unix address rather than to a path, because that is the
	 * bound these two have to fit: a name longer than `sun_path` is one the
	 * kernel would truncate, and a fixture that did that would be binding
	 * something other than what it checks for. */
	char                 dir[sizeof(address.sun_path) / 2u];
	char                 dead[sizeof(address.sun_path)];
	char                 alive[sizeof(address.sun_path)];
	char                 busy[sizeof(address.sun_path)];
	char                 err[NCFG_ERROR_MAX];
	int                  keeper;
	int                  talker;
	int                  gone;

	(void)snprintf(dir, sizeof(dir), "%s/reap", base);
	(void)mkdir(dir, 0700);
	(void)snprintf(dead, sizeof(dead), "%s/netcfgd-999001-0", dir);
	(void)snprintf(alive, sizeof(alive), "%s/netcfgd-999002-0", dir);
	(void)snprintf(busy, sizeof(busy), "%s/netcfgd-999003-0", dir);

	/* One bound and closed, which leaves the file with nothing behind it --
	 * exactly what a netcfgd that exited leaves -- and one bound and kept. */
	gone = socket(AF_UNIX, SOCK_DGRAM, 0);
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	(void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", dead);
	check(gone >= 0 && bind(gone, (struct sockaddr *)&address, sizeof(address)) == 0,
	    "a reply socket whose process is about to go");
	(void)close(gone);

	keeper = socket(AF_UNIX, SOCK_DGRAM, 0);
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	(void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", alive);
	check(keeper >= 0 && bind(keeper, (struct sockaddr *)&address, sizeof(address)) == 0,
	    "and one that is still bound, waiting for an answer");

	/*
	 * **And one that is bound *and connected*, which is what a live reply
	 * socket actually is.** The sweep has two guards and this fixture had
	 * only reached the first: a bound socket nobody has connected answers a
	 * probe's `connect` with success, while a client that has connected to
	 * its supplicant makes the kernel answer `EPERM` -- and it is the second
	 * that every in-flight netcfgd connection is. A sabotage that removed the
	 * `EPERM` guard passed against the old fixture, which is how this was
	 * found.
	 */
	talker = socket(AF_UNIX, SOCK_DGRAM, 0);
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	(void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", busy);
	check(talker >= 0 && bind(talker, (struct sockaddr *)&address, sizeof(address)) == 0,
	    "and one bound by a client that is mid-conversation");
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	(void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", alive);
	check(talker >= 0 && connect(talker, (struct sockaddr *)&address, sizeof(address)) == 0,
	    "  connected, which is what makes the kernel refuse a second connect to it");

	memset(&what, 0, sizeof(what));
	what.supplicant_dir = dir;
	what.poll_config = 1;
	err[0] = '\0';
	if (!ncfg_main_watchers_open(&watchers, &what, err, sizeof(err))) {
		detail("the watches would not open", err);
		check(0, "the watches open over a control directory");
		(void)close(keeper);
		return;
	}
	check(!testdir_exists(dead), "opening the watches takes the dead socket away");
	check(testdir_exists(alive),
	    "  and leaves the one somebody is still waiting on, which is the whole risk");
	check(testdir_exists(busy),
	    "  and the one whose client is mid-conversation, which the kernel says by "
	    "refusing the probe rather than by refusing the address");

	ncfg_main_watchers_close(&watchers);
	(void)close(keeper);
	(void)close(talker);
	(void)unlink(alive);
	(void)unlink(busy);
}

static void a_supplicant_event_reaches_the_log(const char *base)
{
	ncfg_main_watchers_t      watchers;
	ncfg_main_watch_t         what;
	ncfg_main_run_t           run;
	ncfg_main_round_report_t  report;
	ncfg_supplicant_client_t *tester;
	char                      dir[512];
	char                      log_path[640];
	char                      message[NCFG_ERROR_MAX];
	char                      err[NCFG_ERROR_MAX];
	char                     *said;
	ncfg_severity_t           kept_level;
	int                       saved_stderr;
	int                       fd;

	(void)snprintf(dir, sizeof(dir), "%s/ctrl", base);
	(void)mkdir(dir, 0700);
	(void)snprintf(log_path, sizeof(log_path), "%s/fake.log", base);
	if (!fake_start(dir, "wlan0", log_path)) {
		check(0, "a fake radio to watch");
		return;
	}

	memset(&what, 0, sizeof(what));
	what.supplicant_dir = dir;
	what.poll_config = 1;
	err[0] = '\0';
	if (!ncfg_main_watchers_open(&watchers, &what, err, sizeof(err))) {
		detail("the watches would not open", err);
		check(0, "the watches open over a control directory");
		fake_stop();
		return;
	}
	memset(&run, 0, sizeof(run));
	run.sources = &watchers.sources;
	run.ticks = fake_ticks;
	/*
	 * **The refresh, which is how a radio is ever found.** The watcher scans
	 * the control directory from `ncfg_main_watchers_refresh`, and a round
	 * with no `refresh` installed never looks -- which is exactly what the
	 * first version of this case did, and the fake heard no `ATTACH` at all.
	 * `daemon_main.c` installs the same pair.
	 */
	run.refresh = ncfg_main_watchers_refresh;
	run.refresh_context = &watchers;

	/* A round to find the socket and attach to it. The watcher's own
	 * `ATTACH` is what makes the fake broadcast reach it at all. */
	clock_is_expired();
	err[0] = '\0';
	(void)ncfg_main_round(&run, &report, err, sizeof(err));

	/*
	 * The event, sent through a second connection of this test's own:
	 * `TROUBLE` is the fake's way of being told to emit one, and it
	 * broadcasts to everything that has attached -- which is the watcher.
	 */
	message[0] = '\0';
	tester = ncfg_supplicant_connect_within(dir, "wlan0", 2000, message, sizeof(message));
	check(tester != NULL, "a second connection, to tell the fake what to emit");
	if (!tester) {
		ncfg_main_watchers_close(&watchers);
		fake_stop();
		return;
	}

	/* **Both streams captured across the round**, because the log writes
	 * straight to descriptor 2 -- which is `log.c`'s arrangement and the
	 * reason the only honest way to read it is to be the reader. */
	(void)fflush(stderr);
	saved_stderr = dup(STDERR_FILENO);
	fd = open(log_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0 || saved_stderr < 0) {
		check(0, "stderr can be captured");
		ncfg_supplicant_client_free(tester);
		ncfg_main_watchers_close(&watchers);
		fake_stop();
		return;
	}
	(void)snprintf(log_path, sizeof(log_path), "%s/narration", base);
	(void)close(fd);
	fd = open(log_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
	(void)dup2(fd, STDERR_FILENO);
	(void)close(fd);

	/*
	 * **And the level raised, which is the half that made this fail first.**
	 * `main` sets the suite to `CRITICAL` so that a hundred and seventy checks
	 * do not narrate themselves; a note written into that is a note nothing
	 * records, and the capture came back empty. Put back straight after, so
	 * the rest of the file is as quiet as it was.
	 */
	kept_level = ncfg_log_accepted();
	ncfg_log_accept(NCFG_LOG_VERBOSE);
	message[0] = '\0';
	(void)ncfg_supplicant_command(tester,
	    "TROUBLE CTRL-EVENT-CONNECTED - Connection to a0:a4:7f:23:9a:cf completed "
	    "[id=0 id_str=]", message, sizeof(message));
	clock_is_expired();
	err[0] = '\0';
	(void)ncfg_main_round(&run, &report, err, sizeof(err));
	ncfg_log_accept(kept_level);

	(void)fflush(stderr);
	(void)dup2(saved_stderr, STDERR_FILENO);
	(void)close(saved_stderr);

	said = testdir_read(log_path, NULL);
	check(said != NULL && strstr(said, "wlan0: joined a0:a4:7f:23:9a:cf") != NULL,
	    "an association the supplicant reported is in the daemon's log");
	if (!said || strstr(said, "wlan0: joined a0:a4:7f:23:9a:cf") == NULL) {
		detail("what it said", said ? said : "(nothing)");
	}
	free(said);

	ncfg_supplicant_client_free(tester);
	ncfg_main_watchers_close(&watchers);
	fake_stop();
}

static void a_roam_is_a_move_within_one_network(void)
{
	check(!ncfg_main_is_roam(0, 0u, "", 1, 3u, "aa:bb:cc:dd:ee:01"),
	    "the first association a radio reports is not a roam");
	check(ncfg_main_is_roam(1, 3u, "aa:bb:cc:dd:ee:01", 1, 3u, "aa:bb:cc:dd:ee:02"),
	    "a different access point on the same network is");
	check(!ncfg_main_is_roam(1, 3u, "aa:bb:cc:dd:ee:01", 1, 3u, "aa:bb:cc:dd:ee:01"),
	    "the same access point reported twice is not");
	check(!ncfg_main_is_roam(1, 3u, "aa:bb:cc:dd:ee:01", 1, 4u, "aa:bb:cc:dd:ee:02"),
	    "and a different network is not, which is 0239 -- home wifi to the office "
	    "is not a roam");
	check(!ncfg_main_is_roam(1, 3u, "aa:bb:cc:dd:ee:01", 0, 0u, "aa:bb:cc:dd:ee:02"),
	    "an id that could not be read is not a network established as the same one");
}

static void the_source_set_keeps_its_order(void)
{
	ncfg_main_sources_t sources;
	ncfg_main_source_t  one;
	char                err[NCFG_ERROR_MAX];
	size_t              at;

	ncfg_main_sources_init(&sources);
	memset(&one, 0, sizeof(one));
	one.fd = 3;
	one.kind = NCFG_MAIN_SOURCE_KERNEL;
	check(ncfg_main_sources_add(&sources, &one, err, sizeof(err)), "a source goes in");
	one.fd = 4;
	one.kind = NCFG_MAIN_SOURCE_CONFIG;
	(void)ncfg_main_sources_add(&sources, &one, err, sizeof(err));
	one.fd = 5;
	one.kind = NCFG_MAIN_SOURCE_RFKILL;
	(void)ncfg_main_sources_add(&sources, &one, err, sizeof(err));
	check(sources.count == 3u, "and so do the next two");
	check(ncfg_main_sources_find(&sources, NCFG_MAIN_SOURCE_RFKILL) == 2u,
	    "each is found where it was put");
	check(ncfg_main_sources_find(&sources, NCFG_MAIN_SOURCE_TIMER) == sources.count,
	    "and a kind that is not there answers past the end rather than zero");

	ncfg_main_sources_forget(&sources, 0u);
	/*
	 * The order matters and is not a preference: the loop walks the set
	 * against an array of `struct pollfd` it built a moment earlier, so
	 * swapping the last one into the gap would make one index name a
	 * different source mid-walk and the next readiness be attributed to it.
	 */
	check(sources.count == 2u && sources.at[0].fd == 4 && sources.at[1].fd == 5,
	    "forgetting one keeps the order of the rest rather than swapping the last in");

	ncfg_main_sources_init(&sources);
	for (at = 0; at < NCFG_MAIN_SOURCES_MAX; at++) {
		one.fd = (int)at;
		(void)ncfg_main_sources_add(&sources, &one, err, sizeof(err));
	}
	err[0] = '\0';
	check(!ncfg_main_sources_add(&sources, &one, err, sizeof(err)),
	    "a set that is full refuses rather than dropping one quietly");
	check(strstr(err, "descriptors") != NULL, "and the refusal says what the ceiling is");
	detail("it said", err);
}

static void a_roam_that_does_not_fit_is_counted(void)
{
	ncfg_main_harvest_t harvest;
	size_t              at;

	memset(&harvest, 0, sizeof(harvest));
	for (at = 0; at < (size_t)NCFG_MAIN_ROAMS_MAX + 3u; at++) {
		ncfg_main_harvest_roam(&harvest, "wlan0", "aa:bb:cc:dd:ee:01");
	}
	check(harvest.roam_count == (size_t)NCFG_MAIN_ROAMS_MAX,
	    "a round carries as many roams as it has room for");
	check(harvest.roams_missed == 3u,
	    "and says how many it could not, rather than dropping them in silence");
	check(strcmp(harvest.roams[0].interface, "wlan0") == 0 &&
	    strcmp(harvest.roams[0].bssid, "aa:bb:cc:dd:ee:01") == 0,
	    "the text is the round's own, so the pass can borrow it");
}

/* ------------------------------------------------------------------------ *
 * Sources this file can drive
 * ------------------------------------------------------------------------ */

/* A drain that reads one byte and calls it a kernel change. What a real
 * netlink drain does, without a netlink socket. */
typedef struct {
	int      fd;
	unsigned taken;
	/* How many times the loop asked, whether or not anything came of it. */
	unsigned asked;
	/* Answer 0 every time, which is a source that cannot be read. */
	int      always_fails;
	/* Read nothing, so the descriptor stays ready for ever. */
	int      never_reads;
} counter_t;

static int drain_counter(void *context, ncfg_main_harvest_t *harvest, char *err,
    size_t err_size)
{
	counter_t *counter = context;
	char       byte;

	counter->asked++;
	if (counter->always_fails) {
		ncfg_error_set(err, err_size, "this source refuses to be read, deliberately");
		return 0;
	}
	if (counter->never_reads) {
		counter->taken++;
		ncfg_reconcile_collapse(&harvest->wake, NCFG_WOKE_KERNEL);
		return 1;
	}
	while (read(counter->fd, &byte, 1u) == 1) {
		counter->taken++;
		ncfg_reconcile_collapse(&harvest->wake, NCFG_WOKE_KERNEL);
	}
	return 1;
}

static void install(ncfg_main_sources_t *sources, ncfg_main_source_kind_t kind, int fd,
    ncfg_main_drain_fn drain, void *context)
{
	ncfg_main_source_t source;
	char               err[NCFG_ERROR_MAX];

	memset(&source, 0, sizeof(source));
	source.kind = kind;
	source.fd = fd;
	source.drain = drain;
	source.context = context;
	if (!ncfg_main_sources_add(sources, &source, err, sizeof(err))) {
		detail("a source would not go in", err);
	}
}

static int pipe_of(int *read_end, int *write_end)
{
	int ends[2];

	if (pipe(ends) != 0) {
		return 0;
	}
	(void)fcntl(ends[0], F_SETFL, O_NONBLOCK);
	(void)fcntl(ends[1], F_SETFL, O_NONBLOCK);
	*read_end = ends[0];
	*write_end = ends[1];
	return 1;
}

static void a_burst_collapses_into_one_wake(void)
{
	ncfg_main_sources_t      sources;
	ncfg_main_run_t          run;
	ncfg_main_round_report_t report;
	counter_t                counter;
	char                     err[NCFG_ERROR_MAX];
	int                      reading = -1;
	int                      writing = -1;
	int                      at;

	if (!pipe_of(&reading, &writing)) {
		check(0, "a pipe for the burst");
		return;
	}
	memset(&counter, 0, sizeof(counter));
	counter.fd = reading;
	ncfg_main_sources_init(&sources);
	install(&sources, NCFG_MAIN_SOURCE_KERNEL, reading, drain_counter, &counter);

	for (at = 0; at < 50; at++) {
		(void)!write(writing, "k", 1u);
	}
	memset(&run, 0, sizeof(run));
	run.sources = &sources;
	run.ticks = fake_ticks;
	clock_is_expired();
	err[0] = '\0';
	check(ncfg_main_round(&run, &report, err, sizeof(err)), "a round over a burst runs");
	detail("if not", err);
	check(counter.taken == 50u, "every one of the fifty events is taken off the descriptor");
	check(report.wake.kernel_changed == 1,
	    "and the fifty of them are one wake, not fifty -- the daemon's cost does not "
	    "scale with the kernel's chattiness");
	check(!report.wake.ticked,
	    "a burst that ended is the burst ending, not the loop's backstop firing");

	(void)close(reading);
	(void)close(writing);
}

static void a_burst_that_never_ends_still_lets_the_pass_run(void)
{
	ncfg_main_sources_t      sources;
	ncfg_main_run_t          run;
	ncfg_main_round_report_t report;
	counter_t                counter;
	char                     err[NCFG_ERROR_MAX];
	int                      reading = -1;
	int                      writing = -1;

	if (!pipe_of(&reading, &writing)) {
		check(0, "a pipe for the endless burst");
		return;
	}
	(void)!write(writing, "k", 1u);
	memset(&counter, 0, sizeof(counter));
	counter.fd = reading;
	/* Ready for ever, because nothing takes the byte off it. A drain with a
	 * bug in it looks exactly like this. */
	counter.never_reads = 1;
	ncfg_main_sources_init(&sources);
	install(&sources, NCFG_MAIN_SOURCE_KERNEL, reading, drain_counter, &counter);

	memset(&run, 0, sizeof(run));
	run.sources = &sources;
	run.ticks = fake_ticks;
	clock_is_expired();
	err[0] = '\0';
	check(ncfg_main_round(&run, &report, err, sizeof(err)),
	    "a round over a descriptor that is ready for ever still ends");
	check(report.drains == (unsigned)NCFG_MAIN_DRAIN_ROUNDS,
	    "it looks at the burst exactly as many times as the bound allows");
	check(report.wake.kernel_changed == 1,
	    "and what it took is still one wake the pass will be given");

	(void)close(reading);
	(void)close(writing);
}

static void a_descriptor_that_hung_up_is_dropped(void)
{
	ncfg_main_sources_t      sources;
	ncfg_main_run_t          run;
	ncfg_main_round_report_t report;
	counter_t                counter;
	char                     err[NCFG_ERROR_MAX];
	int                      reading = -1;
	int                      writing = -1;

	if (!pipe_of(&reading, &writing)) {
		check(0, "a pipe for the hang-up");
		return;
	}
	memset(&counter, 0, sizeof(counter));
	counter.fd = reading;
	ncfg_main_sources_init(&sources);
	install(&sources, NCFG_MAIN_SOURCE_KERNEL, reading, drain_counter, &counter);
	memset(&run, 0, sizeof(run));
	run.sources = &sources;
	run.ticks = fake_ticks;

	/*
	 * Two records queued and then the writer gone, which sets `POLLIN` and
	 * `POLLHUP` together. Reading first is the difference between the last
	 * two records and none of them -- for `/dev/rfkill` that is the switch
	 * being flipped as the device went away.
	 */
	(void)!write(writing, "kk", 2u);
	(void)close(writing);
	clock_is_expired();
	err[0] = '\0';
	check(ncfg_main_round(&run, &report, err, sizeof(err)), "a round over a closed writer runs");
	check(counter.taken == 2u,
	    "what was queued before the hang-up is read rather than thrown away with it");
	check(report.wake.kernel_changed == 1, "and it is still news");
	/*
	 * And then let go of, in the same round: the collapse looks again, finds
	 * the hang-up with nothing behind it, and drops it. That is the whole
	 * point -- a hung-up descriptor is ready every time it is polled, so one
	 * left in the set is a `poll` that returns instantly for ever.
	 */
	check(report.dropped == 1u && report.sources == 0u,
	    "and once there is nothing left behind it, the hung-up descriptor is dropped");

	clock_is_expired();
	err[0] = '\0';
	check(ncfg_main_round(&run, &report, err, sizeof(err)),
	    "a round with nothing left to watch still runs");
	check(report.wake.ticked && !report.wake.kernel_changed,
	    "and is the loop's own backstop rather than a source saying anything");

	(void)close(reading);
}

/*
 * A round sweeps the streams, on a machine where nothing at all happened.
 *
 * `world_test.c` checks what the sweep decides; what is checked here is that
 * the loop reaches it -- and reaches it on the round that matters, which is
 * the one with no event, no request and no pass. That is the machine 0263
 * describes: converged, announcing nothing, with sixteen places in a list held
 * by clients that have gone and the seventeenth `monitor` refused.
 */
static void a_round_sweeps_the_streams_even_when_nothing_happened(void)
{
	ncfg_main_sources_t      sources;
	ncfg_main_subscribers_t  subscribers;
	ncfg_main_run_t          run;
	ncfg_main_round_report_t report;
	char                     err[NCFG_ERROR_MAX];
	int                      ends[2];
	int                      live[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, ends) != 0 ||
	    socketpair(AF_UNIX, SOCK_STREAM, 0, live) != 0) {
		check(0, "socket pairs for two streams");
		return;
	}
	ncfg_main_subscribers_init(&subscribers);
	err[0] = '\0';
	if (!ncfg_main_subscribers_add(&subscribers, ends[1], err, sizeof(err)) ||
	    !ncfg_main_subscribers_add(&subscribers, live[1], err, sizeof(err))) {
		check(0, "two subscribers could be taken");
		return;
	}
	ncfg_main_sources_init(&sources);
	memset(&run, 0, sizeof(run));
	run.sources = &sources;
	run.subscribers = &subscribers;
	run.ticks = fake_ticks;

	clock_is_expired();
	err[0] = '\0';
	check(ncfg_main_round(&run, &report, err, sizeof(err)),
	    "a round with nothing to watch and nothing to say runs");
	check(report.pruned == 0u && subscribers.count == 2u,
	    "and sweeps nothing while both clients are there");

	/* The client leaves. Nothing announces, nothing is written, and no pass
	 * runs -- which is exactly the machine where the old arrangement kept the
	 * place for ever. */
	(void)close(ends[0]);
	clock_is_expired();
	err[0] = '\0';
	check(ncfg_main_round(&run, &report, err, sizeof(err)),
	    "the next backstop round runs");
	check(report.pruned == 1u && subscribers.count == 1u,
	    "and the stream whose client has gone is swept, with nothing having happened");
	check(!report.passed, "  on a round that ran no pass at all");

	ncfg_main_subscribers_close(&subscribers);
	(void)close(live[0]);
}

static void a_descriptor_that_is_not_open_is_dropped_at_once(void)
{
	ncfg_main_sources_t      sources;
	ncfg_main_run_t          run;
	ncfg_main_round_report_t report;
	char                     err[NCFG_ERROR_MAX];
	int                      gone;

	/* Closed and then not reopened, so the number is certainly not a
	 * descriptor this process has. */
	gone = dup(STDIN_FILENO);
	if (gone < 0) {
		check(0, "a descriptor to close");
		return;
	}
	(void)close(gone);

	ncfg_main_sources_init(&sources);
	install(&sources, NCFG_MAIN_SOURCE_KERNEL, gone, NULL, NULL);
	memset(&run, 0, sizeof(run));
	run.sources = &sources;
	run.ticks = fake_ticks;
	clock_is_expired();
	err[0] = '\0';
	check(ncfg_main_round(&run, &report, err, sizeof(err)),
	    "a round holding a descriptor that is not open still runs");
	check(report.dropped == 1u && report.sources == 0u,
	    "and drops it on the first round rather than polling it for ever");
}

static void a_source_that_will_not_be_read_loses_its_place(void)
{
	ncfg_main_sources_t      sources;
	ncfg_main_run_t          run;
	ncfg_main_round_report_t report;
	counter_t                counter;
	char                     err[NCFG_ERROR_MAX];
	int                      reading = -1;
	int                      writing = -1;
	int                      round;

	if (!pipe_of(&reading, &writing)) {
		check(0, "a pipe for the failing drain");
		return;
	}
	(void)!write(writing, "k", 1u);
	memset(&counter, 0, sizeof(counter));
	counter.fd = reading;
	counter.always_fails = 1;
	ncfg_main_sources_init(&sources);
	install(&sources, NCFG_MAIN_SOURCE_KERNEL, reading, drain_counter, &counter);
	memset(&run, 0, sizeof(run));
	run.sources = &sources;
	run.ticks = fake_ticks;

	clock_is_expired();
	err[0] = '\0';
	check(ncfg_main_round(&run, &report, err, sizeof(err)),
	    "a round over a source that refuses to be read still runs");
	/*
	 * Tried exactly as many times as the patience allows and then let go of.
	 * The tries are the burst's own looks rather than whole rounds, which is
	 * what keeps a source that is ready for ever and unreadable for ever from
	 * costing a full sixty-four-look burst on every round until the daemon
	 * stops. A source that fails once and reads the next time has its count
	 * cleared, which is the case this must not punish.
	 */
	check(counter.asked == (unsigned)NCFG_MAIN_SOURCE_PATIENCE,
	    "a source that will not be read is asked exactly as often as the patience allows");
	check(report.dropped == 1u && report.sources == 0u, "and then let go of");
	check(report.drains < (unsigned)NCFG_MAIN_DRAIN_ROUNDS,
	    "without spending a whole burst on it first");

	(void)close(reading);
	(void)close(writing);
	(void)round;
}

static volatile sig_atomic_t alarms;

static void took_the_alarm(int signal_number)
{
	(void)signal_number;
	alarms++;
}

static void a_signal_mid_wait_does_not_restart_the_backstop(void)
{
	ncfg_main_sources_t      sources;
	ncfg_main_run_t          run;
	ncfg_main_round_report_t report;
	struct sigaction         action;
	struct sigaction         was;
	struct itimerval         soon;
	char                     err[NCFG_ERROR_MAX];
	struct timespec          began;
	uint64_t                 spent;
	int                      reading = -1;
	int                      writing = -1;
	/*
	 * A whole tick, then a clock that has run past the deadline. So the first
	 * wait is the full five seconds, the alarm interrupts it, and the wait
	 * that follows is what is left of the *same* deadline -- which is none.
	 * A loop that restarted the deadline would sit here for another five
	 * seconds, and this check would take ten.
	 */
	static const uint64_t    readings[3] = { 0u, 0u, 10000u };

	if (!pipe_of(&reading, &writing)) {
		check(0, "a pipe for the interrupted wait");
		return;
	}
	ncfg_main_sources_init(&sources);
	install(&sources, NCFG_MAIN_SOURCE_KERNEL, reading, NULL, NULL);
	memset(&run, 0, sizeof(run));
	run.sources = &sources;
	run.ticks = fake_ticks;
	clock_is(readings, 3u);

	alarms = 0;
	memset(&action, 0, sizeof(action));
	action.sa_handler = took_the_alarm;
	(void)sigemptyset(&action.sa_mask);
	/* No `SA_RESTART`, because what is being checked is what the loop does
	 * with the `EINTR` a signal really produces. */
	action.sa_flags = 0;
	(void)sigaction(SIGALRM, &action, &was);
	memset(&soon, 0, sizeof(soon));
	soon.it_value.tv_usec = 50000;
	(void)clock_gettime(CLOCK_MONOTONIC, &began);
	(void)setitimer(ITIMER_REAL, &soon, NULL);

	err[0] = '\0';
	check(ncfg_main_round(&run, &report, err, sizeof(err)),
	    "a wait a signal interrupted is not a failure of the wait (0233)");
	spent = elapsed_ms(&began);
	(void)sigaction(SIGALRM, &was, NULL);

	check(alarms == 1, "the signal really arrived");
	check(report.interrupted == 1u, "the round says it waited through one");
	check(report.wake.ticked == 1,
	    "and what it ended with is the backstop, so the loop went on running");
	check(spent < 2000u,
	    "and the deadline was not restarted by it -- the second wait was what was left");
	detail("milliseconds spent", spent < 2000u ? "under two seconds" : "too many");

	(void)close(reading);
	(void)close(writing);
}

/* ------------------------------------------------------------------------ *
 * The real watchers
 * ------------------------------------------------------------------------ */

static void the_configuration_watch_answers_the_same_question_either_way(const char *base,
    int polling)
{
	ncfg_main_watchers_t     watchers;
	ncfg_main_watch_t        what;
	ncfg_main_run_t          run;
	ncfg_main_round_report_t report;
	char                     config[512];
	char                     dropped[640];
	char                     err[NCFG_ERROR_MAX];
	FILE                    *file;
	int                      at;

	(void)snprintf(config, sizeof(config), "%s/%s", base, polling ? "etc-poll" : "etc-in");
	(void)mkdir(config, 0700);

	memset(&what, 0, sizeof(what));
	what.config_dir = config;
	what.poll_config = polling;
	err[0] = '\0';
	if (!ncfg_main_watchers_open(&watchers, &what, err, sizeof(err))) {
		detail("the watches would not open", err);
		check(0, "the watches open");
		return;
	}
	check(ncfg_main_sources_find(&watchers.sources, NCFG_MAIN_SOURCE_CONFIG) <
	    watchers.sources.count,
	    polling ? "a polling configuration watch is a source like any other"
	        : "an inotify configuration watch is a source");
	check(ncfg_main_sources_find(&watchers.sources, NCFG_MAIN_SOURCE_STOP) <
	    watchers.sources.count,
	    "and so is the pipe that stops the loop");
	if (polling) {
		/*
		 * -1, which is the whole reason a source may have no descriptor: the
		 * question is answered by walking the filesystem, and inventing a pipe
		 * nobody writes to would leave the fall-back reporting nothing for
		 * ever.
		 */
		check(ncfg_watch_descriptor(&watchers.watch) < 0,
		    "a polling watch has no descriptor to wait on, and says so");
	} else {
		check(ncfg_watch_descriptor(&watchers.watch) >= 0,
		    "an inotify watch has one");
	}

	memset(&run, 0, sizeof(run));
	run.sources = &watchers.sources;
	run.ticks = fake_ticks;

	/* A round before anything is written, which must report nothing: a watch
	 * that said "changed" on its first look would make every daemon recompile
	 * on startup for no reason. */
	clock_is_expired();
	err[0] = '\0';
	(void)ncfg_main_round(&run, &report, err, sizeof(err));

	for (at = 0; at < 50; at++) {
		(void)snprintf(dropped, sizeof(dropped), "%s/%02d-drop.conf", config, at);
		file = fopen(dropped, "w");
		if (file) {
			(void)fprintf(file, "global { }\n");
			(void)fclose(file);
		}
	}
	clock_is_expired();
	err[0] = '\0';
	check(ncfg_main_round(&run, &report, err, sizeof(err)),
	    "a round after fifty drop-ins were written runs");
	check(report.wake.config_changed == 1,
	    "fifty writes are one configuration change, not fifty recompiles");

	ncfg_main_watchers_close(&watchers);
	check(watchers.sources.count == 0u && watchers.stop_read < 0,
	    "and closing the watches leaves nothing open");
}

static void a_device_that_ends_stops_being_read(const char *base)
{
	ncfg_main_watchers_t     watchers;
	ncfg_main_watch_t        what;
	ncfg_main_run_t          run;
	ncfg_main_round_report_t report;
	char                     device[640];
	char                     err[NCFG_ERROR_MAX];
	unsigned char            record[NCFG_RFKILL_RECORD];
	int                      writer;
	int                      round;
	int                      gone = 0;

	/*
	 * A fifo standing in for `/dev/rfkill`, which this test may not open:
	 * netcfgd is managing this machine's radios. What it reproduces is the
	 * shape that matters -- a character device that hands over whole records
	 * and then ends.
	 */
	(void)snprintf(device, sizeof(device), "%s/rfkill-fifo", base);
	(void)unlink(device);
	if (mkfifo(device, 0600) != 0) {
		check(0, "a fifo standing in for the kill-switch device");
		return;
	}
	/* Opened before the reader, because the reader's `O_RDONLY` waits for a
	 * writer -- and this test may not wait for anything. */
	writer = open(device, O_RDWR | O_NONBLOCK);
	if (writer < 0) {
		check(0, "a writer on the fifo");
		(void)unlink(device);
		return;
	}
	memset(&what, 0, sizeof(what));
	what.rfkill_device = device;
	err[0] = '\0';
	if (!ncfg_main_watchers_open(&watchers, &what, err, sizeof(err))) {
		check(0, "the kill-switch watch opens");
		(void)close(writer);
		(void)unlink(device);
		return;
	}
	check(ncfg_main_sources_find(&watchers.sources, NCFG_MAIN_SOURCE_RFKILL) <
	    watchers.sources.count,
	    "a kill-switch device is a source");

	memset(record, 0, sizeof(record));
	record[4] = (unsigned char)RFKILL_TYPE_WLAN;
	record[5] = (unsigned char)RFKILL_OP_CHANGE;
	(void)!write(writer, record, sizeof(record));
	(void)!write(writer, record, sizeof(record));

	memset(&run, 0, sizeof(run));
	run.sources = &watchers.sources;
	run.ticks = fake_ticks;
	clock_is_expired();
	err[0] = '\0';
	check(ncfg_main_round(&run, &report, err, sizeof(err)), "a round over two records runs");
	check(report.wake.kernel_changed == 1,
	    "and a switch being flipped is the machine moving, which is the kernel's wake");

	/*
	 * And now the device goes away, which is what a laptop's radio being
	 * removed looks like. A reader that kept polling it would find it ready
	 * on every call for the life of the daemon.
	 */
	(void)close(writer);
	for (round = 0; round < NCFG_MAIN_SOURCE_PATIENCE + 1; round++) {
		clock_is_expired();
		err[0] = '\0';
		(void)ncfg_main_round(&run, &report, err, sizeof(err));
		if (ncfg_main_sources_find(&watchers.sources, NCFG_MAIN_SOURCE_RFKILL) >=
		    watchers.sources.count) {
			gone = 1;
			break;
		}
	}
	check(gone, "a device that ended is let go of rather than polled for ever");

	ncfg_main_watchers_close(&watchers);
	(void)unlink(device);
}

static void a_window_timer_that_fires_during_a_pass_is_not_lost(const char *base)
{
	ncfg_main_watchers_t     watchers;
	ncfg_main_watch_t        what;
	ncfg_main_run_t          run;
	ncfg_main_round_report_t report;
	char                     err[NCFG_ERROR_MAX];

	(void)base;
	memset(&what, 0, sizeof(what));
	err[0] = '\0';
	if (!ncfg_main_watchers_open(&watchers, &what, err, sizeof(err))) {
		check(0, "the watches open with nothing but the pipes and the timer");
		return;
	}
	check(ncfg_main_sources_find(&watchers.sources, NCFG_MAIN_SOURCE_TIMER) <
	    watchers.sources.count,
	    "the confirm window's timer is a descriptor rather than a sleeping thread");

	memset(&run, 0, sizeof(run));
	run.sources = &watchers.sources;
	run.ticks = fake_ticks;

	clock_is_expired();
	err[0] = '\0';
	(void)ncfg_main_round(&run, &report, err, sizeof(err));
	check(!report.wake.confirm_expired, "an unarmed timer says nothing");

	/*
	 * Armed between two rounds, which is where it is armed for real: a window
	 * is opened by a pass, and the timer therefore fires while that pass is
	 * still running or just after it. What must not happen is the wake being
	 * consumed by the round that armed it or lost by the one after.
	 *
	 * The round that follows is given two hundred milliseconds to wait rather
	 * than none, because a `timerfd` armed one nanosecond out still has to be
	 * delivered by the kernel: a `poll` of zero right behind the arming is a
	 * race this file would lose about once a run, and a flaky check is worth
	 * less than no check. The wait is the fake clock's, so it is bounded and
	 * the suite does not spend it.
	 */
	ncfg_main_watchers_expiry(&watchers, 0u);
	clock_is_patient();
	err[0] = '\0';
	check(ncfg_main_round(&run, &report, err, sizeof(err)),
	    "the round after a window was armed runs");
	check(report.wake.confirm_expired == 1,
	    "and a timer armed while a pass was running is still there on the other side "
	    "of it");
	/*
	 * Zero seconds is the arithmetic case rather than the operator's --
	 * `--confirm-within 0` is two spellings of "no window" and never reaches
	 * the timer -- and it is worth a check because `{0,0}` *disarms* a
	 * timerfd rather than firing it at once. A window that never closed is
	 * the failure commit-confirm exists to prevent.
	 */
	check(report.wake.confirm_expired == 1,
	    "a window of no seconds fires rather than disarming the timer");

	clock_is_expired();
	err[0] = '\0';
	(void)ncfg_main_round(&run, &report, err, sizeof(err));
	check(!report.wake.confirm_expired,
	    "and a one-shot timer says it once, not on every round afterwards");

	ncfg_main_watchers_close(&watchers);
}

static void a_signal_between_the_check_and_the_wait_still_stops_it(void)
{
	ncfg_main_watchers_t     watchers;
	ncfg_main_watch_t        what;
	ncfg_main_run_t          run;
	ncfg_main_round_report_t report;
	char                     err[NCFG_ERROR_MAX];
	struct timespec          began;
	uint64_t                 spent;

	memset(&what, 0, sizeof(what));
	err[0] = '\0';
	if (!ncfg_main_watchers_open(&watchers, &what, err, sizeof(err))) {
		check(0, "the watches open");
		return;
	}
	err[0] = '\0';
	check(ncfg_main_signals_watch(&watchers, err, sizeof(err)),
	    "the daemon arranges to be stopped");
	detail("if not", err);

	/*
	 * **The signal arrives before the wait, which is the race a flag loses.**
	 * A handler that set a flag would have set it here, and the loop would
	 * then check the flag, find nothing else ready, and sleep out its whole
	 * tick with the flag already set. A byte in a pipe cannot be missed,
	 * because the pipe is in the wait.
	 *
	 * Nothing else is ready and the clock is the real one, so a loop that got
	 * this wrong would spend five seconds here.
	 */
	raise(SIGTERM);
	memset(&run, 0, sizeof(run));
	run.sources = &watchers.sources;
	(void)clock_gettime(CLOCK_MONOTONIC, &began);
	err[0] = '\0';
	/*
	 * One round rather than `ncfg_main_serve`, and that is what makes this a
	 * check rather than a hang: a loop that missed the signal would serve for
	 * ever, and one round that missed it waits out a single tick and comes
	 * back with nothing. The difference is a red line either way, and only one
	 * of them ends.
	 */
	check(ncfg_main_round(&run, &report, err, sizeof(err)),
	    "a round that a signal arrived just before still runs");
	spent = elapsed_ms(&began);
	check(report.stopping,
	    "and the signal reached it, because the byte was already in the wait");
	check(spent < 2000u,
	    "at once rather than at the end of the tick it was about to sleep through");
	detail("milliseconds spent", spent < 2000u ? "under two seconds" : "too many");
	check(!report.wake.kernel_changed && !report.wake.config_changed,
	    "and being asked to stop is not news to reconcile about");

	/* And the loop itself ends on it. By hand here, which is what a caller
	 * with no signal to send does -- and what keeps this last step bounded
	 * whatever the handler above did. */
	ncfg_main_watchers_stop(&watchers);
	err[0] = '\0';
	check(ncfg_main_serve(&run, err, sizeof(err)),
	    "and serving ends without a failure when it is asked to stop");

	ncfg_main_signals_restore();
	ncfg_main_watchers_close(&watchers);
}

/* ------------------------------------------------------------------------ *
 * A radio, against a supplicant this file stands up
 * ------------------------------------------------------------------------ */

/*
 * The smallest thing that answers like `wpa_supplicant`.
 *
 * A thread rather than a forked child, deliberately: `running-code.md` is
 * about processes that outlive what started them, and a datagram socket served
 * from a thread of this process cannot be orphaned. It answers `PING` and
 * `ATTACH` and nothing else, because what is under test is the loop's reading
 * of events rather than the control protocol -- `supplicant_client_test.c`
 * drives that against a fake that answers command for command.
 *
 * Two `CONNECTED` events, which is the smallest pair that can contain a roam:
 * the first is an association, since there is nothing to have moved from, and
 * the second names a different access point on the same configured network.
 */
static const char FIRST_JOIN[] =
    "<3>CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:01 completed [id=7 id_str=]";
/*
 * A join whose configured network cannot be read.
 *
 * `-1` is what the supplicant writes when the association has no configured
 * network behind it, and it does not parse as an unsigned number. It is not a
 * roam -- an unreadable id is not a network established as the same one -- and
 * it must not be **recorded** either, which is the half a rule about roams
 * cannot state: recording it would leave this radio remembering a network it
 * was never on, and the real join after it would compare against that and
 * report nothing. A missed roam, arriving through the arm that exists to
 * prevent a wrong one.
 */
static const char UNKNOWN_NETWORK[] =
    "<3>CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:03 completed [id=-1 id_str=]";
static const char THE_ROAM[] =
    "<3>CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:02 completed [id=7 id_str=]";

typedef struct {
	int                    fd;
	volatile sig_atomic_t  stop;
	volatile sig_atomic_t  attached;
} supplicant_t;

static void *the_supplicant(void *argument)
{
	supplicant_t  *fake = argument;
	struct timeval patience;
	int            rounds;

	patience.tv_sec = 0;
	patience.tv_usec = 100000;
	(void)setsockopt(fake->fd, SOL_SOCKET, SO_RCVTIMEO, &patience, (socklen_t)sizeof(patience));

	/* Bounded twice: by the stop flag the test sets, and by a count, so that a
	 * client which never speaks cannot leave this running. */
	for (rounds = 0; rounds < 200 && !fake->stop; rounds++) {
		char               heard[512];
		struct sockaddr_un from;
		socklen_t          from_length = (socklen_t)sizeof(from);
		ssize_t            got;

		memset(&from, 0, sizeof(from));
		got = recvfrom(fake->fd, heard, sizeof(heard) - 1u, 0, (struct sockaddr *)&from,
		    &from_length);
		if (got < 0) {
			continue;
		}
		heard[got] = '\0';
		if (strcmp(heard, "PING") == 0) {
			(void)sendto(fake->fd, "PONG\n", 5u, 0, (const struct sockaddr *)&from,
			    from_length);
			continue;
		}
		if (strcmp(heard, "ATTACH") == 0) {
			(void)sendto(fake->fd, "OK\n", 3u, 0, (const struct sockaddr *)&from,
			    from_length);
			/* The events go to whoever attached, which is what `ATTACH`
			 * means: a client that has not asked gets replies only. */
			(void)sendto(fake->fd, FIRST_JOIN, strlen(FIRST_JOIN), 0,
			    (const struct sockaddr *)&from, from_length);
			(void)sendto(fake->fd, UNKNOWN_NETWORK, strlen(UNKNOWN_NETWORK), 0,
			    (const struct sockaddr *)&from, from_length);
			(void)sendto(fake->fd, THE_ROAM, strlen(THE_ROAM), 0,
			    (const struct sockaddr *)&from, from_length);
			fake->attached = 1;
			continue;
		}
		(void)sendto(fake->fd, "OK\n", 3u, 0, (const struct sockaddr *)&from, from_length);
	}
	return NULL;
}

static void a_station_that_moved_is_carried_out_of_the_round(const char *base)
{
	ncfg_main_watchers_t     watchers;
	ncfg_main_watch_t        what;
	ncfg_main_run_t          run;
	ncfg_main_round_report_t report;
	supplicant_t             fake;
	pthread_t                thread;
	struct sockaddr_un       address;
	char                     dir[80];
	/* A `sun_path` and no more, because that is what it becomes. A test
	 * directory too deep to bind in would otherwise fail as a truncated
	 * address, which reads as a supplicant that is not answering. */
	char                     path[sizeof(address.sun_path)];
	char                     err[NCFG_ERROR_MAX];
	int                      written;
	int                      at;
	int                      moved = 0;

	if (snprintf(dir, sizeof(dir), "%s/wpa", base) >= (int)sizeof(dir)) {
		check(0, "a control directory whose name fits in a socket address");
		return;
	}
	(void)mkdir(dir, 0700);
	written = snprintf(path, sizeof(path), "%s/wlan0", dir);
	if (written < 0 || (size_t)written >= sizeof(path)) {
		check(0, "a control socket whose name fits in a socket address");
		return;
	}
	(void)unlink(path);

	memset(&fake, 0, sizeof(fake));
	fake.fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fake.fd < 0) {
		check(0, "a socket for the supplicant this test stands up");
		return;
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	memcpy(address.sun_path, path, (size_t)written + 1u);
	if (bind(fake.fd, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) != 0) {
		check(0, "the supplicant binds its control socket");
		(void)close(fake.fd);
		return;
	}
	if (pthread_create(&thread, NULL, the_supplicant, &fake) != 0) {
		check(0, "the supplicant answers");
		(void)close(fake.fd);
		(void)unlink(path);
		return;
	}

	memset(&what, 0, sizeof(what));
	what.supplicant_dir = dir;
	err[0] = '\0';
	if (!ncfg_main_watchers_open(&watchers, &what, err, sizeof(err))) {
		check(0, "the watches open");
		fake.stop = 1;
		(void)pthread_join(thread, NULL);
		(void)close(fake.fd);
		(void)unlink(path);
		return;
	}
	check(ncfg_main_sources_find(&watchers.sources, NCFG_MAIN_SOURCE_RADIO_DIR) <
	    watchers.sources.count,
	    "the supplicant's control directory is watched, so a radio appearing is noticed "
	    "at once rather than on the tick");

	memset(&run, 0, sizeof(run));
	run.sources = &watchers.sources;
	run.refresh = ncfg_main_watchers_refresh;
	run.refresh_context = &watchers;
	/* The real clock for this one, because what has to arrive is a datagram
	 * from another thread: a round of no wait at all would be a race rather
	 * than a check. The wait is bounded by the loop's own tick. */

	for (at = 0; at < 2; at++) {
		err[0] = '\0';
		if (!ncfg_main_round(&run, &report, err, sizeof(err))) {
			detail("a round failed", err);
			break;
		}
		if (report.roam_count > 0u) {
			moved = 1;
			break;
		}
	}
	check(watchers.radio_count > 0u || ncfg_main_sources_find(&watchers.sources,
	    NCFG_MAIN_SOURCE_RADIO) < watchers.sources.count,
	    "the loop attaches to the radio it found in that directory");
	check(moved && report.roam_count == 1u,
	    "three joins are one roam: the first is an association, since there is "
	    "nothing to have moved from, and the one whose network could not be read is "
	    "neither a roam nor something to remember");
	check(!report.wake.kernel_changed && !report.wake.config_changed,
	    "and a roam is not a wake -- it travels beside one, because two roams are "
	    "two events");

	fake.stop = 1;
	ncfg_main_watchers_close(&watchers);
	(void)pthread_join(thread, NULL);
	(void)close(fake.fd);
	(void)unlink(path);
}

/* ------------------------------------------------------------------------ *
 * The mailbox
 * ------------------------------------------------------------------------ */

/*
 * What happened, counted rather than listed.
 *
 * **This was a list of step names and the check was where two of them landed
 * in it, and that was wrong twice over.** A list is an ordering only where
 * each step happens once, and the pass here happens on every round -- so the
 * ordering check passed against a loop that answered first, because an earlier
 * round had already put "pass" at the front. And the list had a ceiling, so
 * once enough rounds had gone by it silently stopped recording and the check
 * failed for a reason that had nothing to do with what it was about.
 *
 * Two counters and a sticky flag answer the same question and cannot do
 * either: the flag is set by the pass if anything had been answered before it
 * looked, and the check is that it never was.
 */
static int observations;
static int answered_before_the_pass;
static int answers;
static ncfg_proto_request_kind_t answered_kind;

static int answer_fixture(void *context, const ncfg_proto_request_t *request,
    const ncfg_peer_t *peer, ncfg_arrival_t arrival, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	(void)context;
	(void)peer;
	(void)arrival;
	(void)out;
	(void)err;
	(void)err_size;
	answers++;
	answered_kind = request->kind;
	return 1;
}

/*
 * What the stream seam was handed, and -- the part that matters -- which
 * thread handed it over.
 *
 * The subscriber list holds no lock because every call on it happens on the
 * loop's thread. That sentence is worth nothing unless something checks it,
 * and the way it fails is silent: a subscription added from the connection's
 * own thread works perfectly until the day a pass is announcing while one
 * arrives. So the seam records `pthread_self()` and the check is that it is
 * the loop's.
 */
static int       streams;
static int       streamed_fd;
static pthread_t streamed_on;
static int       stream_refuses;

static int stream_fixture(void *context, int fd, char *err, size_t err_size)
{
	(void)context;
	streams++;
	streamed_fd = fd;
	streamed_on = pthread_self();
	if (stream_refuses) {
		ncfg_error_set(err, err_size, "this fixture is not taking subscriptions today");
		return 0;
	}
	return 1;
}

typedef struct {
	ncfg_main_mailbox_t *mailbox;
	ncfg_proto_request_t request;
	ncfg_buf_t           out;
	char                 err[NCFG_ERROR_MAX];
	int                  result;
	int                  arrived;
} caller_t;

/* A connection asking to be streamed to, on its own thread. `fd` is what it
 * hands over; the mailbox takes it only where the seam answers yes. */
typedef struct {
	ncfg_main_mailbox_t *mailbox;
	int                  fd;
	char                 err[NCFG_ERROR_MAX];
	int                  result;
	int                  arrived;
} subscriber_caller_t;

static void *the_subscribing_thread(void *argument)
{
	subscriber_caller_t *caller = argument;

	caller->err[0] = '\0';
	caller->result = ncfg_main_mailbox_stream(caller->mailbox, caller->fd, caller->err,
	    sizeof(caller->err));
	caller->arrived = 1;
	return NULL;
}

static void *the_connection_thread(void *argument)
{
	caller_t *caller = argument;

	caller->err[0] = '\0';
	caller->result = ncfg_main_mailbox_answer(caller->mailbox, &caller->request, NULL,
	    NCFG_ARRIVED_LOCAL, &caller->out, caller->err, sizeof(caller->err));
	caller->arrived = 1;
	return NULL;
}

/* An observation seam that records when the pass looked. Empty, because what
 * is being checked is when it happened rather than what was seen. */
static int observe_nothing(void *context, const ncfg_document_t *desired,
    ncfg_observed_t **out, char *err, size_t err_size)
{
	(void)context;
	(void)desired;
	observations++;
	if (answers > 0) {
		answered_before_the_pass = 1;
	}
	*out = ncfg_observed_new(err, err_size);
	return *out != NULL;
}

/* Everything the daemon half of a request test needs, over this test's own
 * directories. */
typedef struct {
	ncfg_daemon_state_t state;
	ncfg_probes_t      *probes;
	ncfg_sims_t        *sims;
	ncfg_reconcile_t    loop;
	char                config[512];
	char                run_dir[512];
} harness_t;

static int harness_start(harness_t *harness, const char *base, const char *leaf)
{
	char err[NCFG_ERROR_MAX];

	memset(harness, 0, sizeof(*harness));
	(void)snprintf(harness->config, sizeof(harness->config), "%s/%s-etc", base, leaf);
	(void)snprintf(harness->run_dir, sizeof(harness->run_dir), "%s/%s-run", base, leaf);
	(void)mkdir(harness->config, 0700);
	(void)mkdir(harness->run_dir, 0700);
	err[0] = '\0';
	if (!ncfg_daemon_state_init(&harness->state, "", harness->config, harness->run_dir, err,
	    sizeof(err))) {
		detail("the state would not start", err);
		return 0;
	}
	harness->state.observe = observe_nothing;
	harness->probes = ncfg_probes_new(err, sizeof(err));
	harness->sims = ncfg_sims_new(err, sizeof(err));
	harness->loop.state = &harness->state;
	harness->loop.probes = harness->probes;
	harness->loop.sims = harness->sims;
	return harness->probes != NULL && harness->sims != NULL;
}

static void harness_stop(harness_t *harness)
{
	ncfg_probes_free(harness->probes);
	ncfg_sims_free(harness->sims);
	ncfg_daemon_state_free(&harness->state);
}

/*
 * Fifty events are one observation, which is the whole of what collapsing is
 * for.
 *
 * The check above this one reads the wake and can only ever say "the kernel
 * changed" once, because that is a flag. This one asks the question the flag
 * stands in for: how many times did the daemon go and look at the machine.
 * Bringing an interface up produces a run of netlink messages, and a loop that
 * drove a pass per message would make the daemon's cost scale with the
 * kernel's chattiness -- an observation is seven dumps and a plan.
 */
static void fifty_events_are_one_observation(const char *base)
{
	ncfg_main_sources_t      sources;
	ncfg_main_run_t          run;
	ncfg_main_round_report_t report;
	harness_t                harness;
	counter_t                counter;
	char                     err[NCFG_ERROR_MAX];
	int                      reading = -1;
	int                      writing = -1;
	int                      at;

	if (!harness_start(&harness, base, "collapse")) {
		check(0, "a daemon state over this test's own directories");
		harness_stop(&harness);
		return;
	}
	if (!pipe_of(&reading, &writing)) {
		check(0, "a pipe for the burst");
		harness_stop(&harness);
		return;
	}
	memset(&counter, 0, sizeof(counter));
	counter.fd = reading;
	ncfg_main_sources_init(&sources);
	install(&sources, NCFG_MAIN_SOURCE_KERNEL, reading, drain_counter, &counter);

	memset(&run, 0, sizeof(run));
	run.sources = &sources;
	run.loop = &harness.loop;
	run.ticks = fake_ticks;

	for (at = 0; at < 50; at++) {
		(void)!write(writing, "k", 1u);
	}
	observations = 0;
	clock_is_expired();
	err[0] = '\0';
	check(ncfg_main_round(&run, &report, err, sizeof(err)), "a round over fifty events runs");
	detail("if not", err);
	check(counter.taken == 50u, "all fifty are taken off the descriptor");
	check(report.passed && observations == 1,
	    "and the machine is looked at once, not fifty times");

	/* And a round with nothing in it looks at nothing at all, which is the
	 * other half: a backstop that observed on every wake would cost an
	 * observation per descriptor error. */
	observations = 0;
	ncfg_main_sources_init(&sources);
	clock_is_expired();
	err[0] = '\0';
	(void)ncfg_main_round(&run, &report, err, sizeof(err));
	check(report.wake.ticked && observations == 1,
	    "and the loop's own backstop is worth exactly one look as well");

	(void)close(reading);
	(void)close(writing);
	harness_stop(&harness);
}

/*
 * The reconcile runs before the request is served, and that is the order.
 *
 * `ncfg_reconcile_defers` and `ncfg_reconcile_releases_hold` are the two
 * decisions that turn on what is waiting, and both are worthless if the
 * request has already been answered: an `apply --confirm-within 60` landing in
 * the same burst as the write it accompanies would have the change applied
 * underneath it, and the window would then cover nothing -- which is worse
 * than no window, because the operator believes they have a way back.
 *
 * Driven with the mailbox's wake left closed, so that every round below is the
 * loop's own tick rather than a race with the thread that is enqueuing. The
 * nudge has a check of its own below.
 */
static void the_pass_sees_a_waiting_request_before_anything_answers_it(const char *base)
{
	ncfg_main_sources_t      sources;
	ncfg_main_mailbox_t      mailbox;
	ncfg_main_run_t          run;
	ncfg_main_round_report_t report;
	harness_t                harness;
	caller_t                 caller;
	pthread_t                thread;
	char                     err[NCFG_ERROR_MAX];
	int                      took = 0;
	int                      at;

	if (!harness_start(&harness, base, "order")) {
		check(0, "a daemon state over this test's own directories");
		harness_stop(&harness);
		return;
	}
	/* `--no-apply-on-start`, so that the pass has something to say about the
	 * request it was given rather than only having been handed one. */
	harness.loop.holding = 1;

	err[0] = '\0';
	if (!ncfg_main_mailbox_open(&mailbox, answer_fixture, stream_fixture, NULL, -1, err,
	    sizeof(err))) {
		check(0, "a mailbox for a request waiting on its own thread");
		harness_stop(&harness);
		return;
	}
	ncfg_main_sources_init(&sources);
	memset(&run, 0, sizeof(run));
	run.sources = &sources;
	run.mailbox = &mailbox;
	run.loop = &harness.loop;
	run.ticks = fake_ticks;

	observations = 0;
	answers = 0;
	answered_before_the_pass = 0;
	memset(&caller, 0, sizeof(caller));
	caller.mailbox = &mailbox;
	caller.request.kind = NCFG_PROTO_REQ_APPLY;
	if (pthread_create(&thread, NULL, the_connection_thread, &caller) != 0) {
		check(0, "a thread standing in for a connection");
		ncfg_main_mailbox_close(&mailbox);
		harness_stop(&harness);
		return;
	}

	/*
	 * Rounds until the request has been put in the mailbox. Bounded, because
	 * a test that waited on another thread without a bound would hang the
	 * suite rather than fail it -- and every round here is a `poll` of zero
	 * milliseconds over an empty set, so the bound is reached in
	 * milliseconds.
	 */
	for (at = 0; at < 2000; at++) {
		clock_is_expired();
		err[0] = '\0';
		if (!ncfg_main_round(&run, &report, err, sizeof(err))) {
			detail("a round failed", err);
			break;
		}
		if (report.request_count > 0u) {
			took = 1;
			break;
		}
	}
	check(took, "the loop takes a request that was waiting on another thread");
	check(report.request_count == 1u, "exactly the one that was waiting");
	check(report.passed && report.wake.ticked,
	    "and the round it arrived in runs a pass");
	check(observations > 0 && answers > 0 && !answered_before_the_pass,
	    "the pass sees the waiting request before anything answers it");
	check(report.pass.released_hold && !harness.loop.holding,
	    "and it was really given the request -- an explicit apply released the "
	    "`--no-apply-on-start` hold");
	check(answers == 1 && answered_kind == NCFG_PROTO_REQ_APPLY,
	    "the request the seam is handed is the one that was sent");

	/*
	 * A join is a wait with no bound, and the thread is only released by a
	 * round that answered it -- so the failing case is turned into a refusal
	 * rather than a suite that hangs. The condition is whether a round **took**
	 * the request and not whether the thread has noticed yet: a round that
	 * took one always settles it, and asking the thread's own flag would shut
	 * the mailbox in the window between the answer and the thread waking up.
	 */
	if (!took) {
		ncfg_main_mailbox_shut(&mailbox);
	}
	(void)pthread_join(thread, NULL);
	check(caller.arrived && caller.result == 1,
	    "the thread that was waiting gets the seam's answer back");

	/*
	 * And with no seam at all, which is what this build is until the request
	 * dispatcher lands: a refusal naming the symbol rather than silence. A
	 * client told "the daemon had no answer for that" would read it as a
	 * request the daemon did not recognise.
	 */
	mailbox.answer = NULL;
	memset(&caller, 0, sizeof(caller));
	caller.mailbox = &mailbox;
	caller.request.kind = NCFG_PROTO_REQ_STATUS;
	took = 0;
	if (pthread_create(&thread, NULL, the_connection_thread, &caller) == 0) {
		for (at = 0; at < 2000; at++) {
			clock_is_expired();
			err[0] = '\0';
			if (!ncfg_main_round(&run, &report, err, sizeof(err))) {
				break;
			}
			if (report.request_count > 0u) {
				took = 1;
				break;
			}
		}
		if (!took) {
			ncfg_main_mailbox_shut(&mailbox);
		}
		(void)pthread_join(thread, NULL);
		check(caller.result == 0 &&
		    strstr(caller.err, "ncfg_daemon_answer_fn") != NULL,
		    "a build with no answer path refuses by naming the seam it is missing");
		detail("it said", caller.err);
	}

	ncfg_main_mailbox_close(&mailbox);
	harness_stop(&harness);
}

/*
 * A subscription crosses to the loop's thread, and is never a request.
 *
 * **This is the whole of why `monitor` goes through the mailbox at all.** The
 * subscriber list holds no lock, on the stated grounds that every call on it
 * happens on the thread that reconciles -- so a connection thread adding to it
 * directly would race the pass announcing through it, and would work until the
 * first machine busy enough for the two to overlap.
 *
 * The second half is that a subscription is not something to reconcile
 * against. It carries no request, and a slot copied into the pass' array with
 * a zeroed kind would read as a `hello` the loop was asked to act on.
 */
static void a_subscription_crosses_to_the_loops_thread(const char *base)
{
	ncfg_main_sources_t      sources;
	ncfg_main_mailbox_t      mailbox;
	ncfg_main_run_t          run;
	ncfg_main_round_report_t report;
	harness_t                harness;
	subscriber_caller_t      caller;
	pthread_t                thread;
	char                     err[NCFG_ERROR_MAX];
	int                      ends[2];
	int                      requests_seen = 0;
	int                      at;

	if (!harness_start(&harness, base, "stream")) {
		check(0, "a daemon state over this test's own directories");
		harness_stop(&harness);
		return;
	}
	err[0] = '\0';
	if (!ncfg_main_mailbox_open(&mailbox, answer_fixture, stream_fixture, NULL, -1, err,
	    sizeof(err))) {
		check(0, "a mailbox for a connection waiting to be subscribed");
		harness_stop(&harness);
		return;
	}
	ncfg_main_sources_init(&sources);
	memset(&run, 0, sizeof(run));
	run.sources = &sources;
	run.mailbox = &mailbox;
	run.loop = &harness.loop;
	run.ticks = fake_ticks;

	/* A socketpair rather than a pipe: what is handed over is a connection,
	 * and this test's own descriptors never leave this process. */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, ends) != 0) {
		check(0, "a socketpair standing in for a connection");
		ncfg_main_mailbox_close(&mailbox);
		harness_stop(&harness);
		return;
	}
	streams = 0;
	streamed_fd = -1;
	stream_refuses = 0;
	answers = 0;
	memset(&caller, 0, sizeof(caller));
	caller.mailbox = &mailbox;
	caller.fd = ends[0];
	if (pthread_create(&thread, NULL, the_subscribing_thread, &caller) != 0) {
		check(0, "a thread standing in for a connection asking to watch");
		(void)close(ends[0]);
		(void)close(ends[1]);
		ncfg_main_mailbox_close(&mailbox);
		harness_stop(&harness);
		return;
	}
	/* Bounded, for the reason every wait in this file is: a crossing that
	 * never happens must fail this rather than hang the suite. */
	for (at = 0; at < 2000 && streams == 0; at++) {
		clock_is_expired();
		err[0] = '\0';
		if (!ncfg_main_round(&run, &report, err, sizeof(err))) {
			detail("a round failed", err);
			break;
		}
		requests_seen += (int)report.request_count;
	}
	check(streams == 1, "a waiting subscription reaches the stream seam");
	check(pthread_equal(streamed_on, pthread_self()) != 0,
	    "on the loop's thread and not the connection's, which is what lets the "
	    "subscriber list hold no lock");
	check(streamed_fd == ends[0], "and it is the descriptor the connection handed over");
	check(requests_seen == 0 && answers == 0,
	    "a subscription is never handed to the pass or the answer seam as a request");
	if (streams == 0) {
		ncfg_main_mailbox_shut(&mailbox);
	}
	(void)pthread_join(thread, NULL);
	check(caller.arrived && caller.result == 1,
	    "and the connection thread is told the loop took it");

	/*
	 * A seam that refuses leaves the descriptor with the caller. `server.c`
	 * closes its copy on a refusal, so a mailbox that had closed it as well
	 * would be the double close the whole hand-over is arranged to avoid --
	 * and the way that shows up is a daemon writing one client's events into
	 * another client's socket.
	 */
	stream_refuses = 1;
	streams = 0;
	memset(&caller, 0, sizeof(caller));
	caller.mailbox = &mailbox;
	caller.fd = ends[0];
	if (pthread_create(&thread, NULL, the_subscribing_thread, &caller) == 0) {
		for (at = 0; at < 2000 && streams == 0; at++) {
			clock_is_expired();
			err[0] = '\0';
			if (!ncfg_main_round(&run, &report, err, sizeof(err))) {
				break;
			}
		}
		if (streams == 0) {
			ncfg_main_mailbox_shut(&mailbox);
		}
		(void)pthread_join(thread, NULL);
		check(caller.result == 0 && strstr(caller.err, "not taking subscriptions") != NULL,
		    "a seam that refuses a subscription says so, through to the connection");
		check(fcntl(ends[0], F_GETFD) >= 0,
		    "and the refused descriptor is still the caller's to close");
	}

	/*
	 * And with no seam at all, which is what a daemon assembled without one
	 * would be: a refusal naming the symbol rather than a connection quietly
	 * taken and never written to.
	 */
	mailbox.stream = NULL;
	streams = 0;
	memset(&caller, 0, sizeof(caller));
	caller.mailbox = &mailbox;
	caller.fd = ends[0];
	if (pthread_create(&thread, NULL, the_subscribing_thread, &caller) == 0) {
		for (at = 0; at < 2000 && !caller.arrived; at++) {
			clock_is_expired();
			err[0] = '\0';
			if (!ncfg_main_round(&run, &report, err, sizeof(err))) {
				break;
			}
		}
		if (!caller.arrived) {
			ncfg_main_mailbox_shut(&mailbox);
		}
		(void)pthread_join(thread, NULL);
		check(caller.result == 0 && strstr(caller.err, "ncfg_daemon_stream_fn") != NULL,
		    "a build with no stream seam refuses by naming the seam it is missing");
		detail("it said", caller.err);
		check(fcntl(ends[0], F_GETFD) >= 0,
		    "and leaves the descriptor alone rather than closing a connection it "
		    "would not take");
	}

	(void)close(ends[0]);
	(void)close(ends[1]);
	ncfg_main_mailbox_close(&mailbox);
	harness_stop(&harness);
}

/*
 * And the wait ends when a request arrives, rather than at the end of the tick.
 *
 * The real clock here, deliberately: what is being checked is that the byte on
 * the mailbox's pipe is in the same `poll` the daemon sleeps in. A loop that
 * had no such descriptor would answer this request up to five seconds later,
 * and would look perfectly correct doing it.
 */
static void a_request_arriving_ends_the_wait(const char *base)
{
	ncfg_main_watchers_t     watchers;
	ncfg_main_watch_t        what;
	ncfg_main_mailbox_t      mailbox;
	ncfg_main_run_t          run;
	ncfg_main_round_report_t report;
	caller_t                 caller;
	pthread_t                thread;
	struct timespec          began;
	uint64_t                 spent;
	char                     err[NCFG_ERROR_MAX];

	(void)base;
	memset(&what, 0, sizeof(what));
	err[0] = '\0';
	if (!ncfg_main_watchers_open(&watchers, &what, err, sizeof(err))) {
		check(0, "the watches open");
		return;
	}
	err[0] = '\0';
	if (!ncfg_main_mailbox_open(&mailbox, answer_fixture, stream_fixture, NULL,
	    watchers.nudge_write, err, sizeof(err))) {
		check(0, "a mailbox wired to the pipe the loop waits on");
		ncfg_main_watchers_close(&watchers);
		return;
	}
	check(ncfg_main_sources_find(&watchers.sources, NCFG_MAIN_SOURCE_REQUEST) <
	    watchers.sources.count,
	    "the pipe a waiting request is announced on is a source of its own");

	memset(&run, 0, sizeof(run));
	run.sources = &watchers.sources;
	run.mailbox = &mailbox;
	/* No clock seam, so the round really would wait five seconds. */

	answers = 0;
	memset(&caller, 0, sizeof(caller));
	caller.mailbox = &mailbox;
	caller.request.kind = NCFG_PROTO_REQ_STATUS;
	(void)clock_gettime(CLOCK_MONOTONIC, &began);
	if (pthread_create(&thread, NULL, the_connection_thread, &caller) != 0) {
		check(0, "a thread standing in for a connection");
		ncfg_main_mailbox_close(&mailbox);
		ncfg_main_watchers_close(&watchers);
		return;
	}
	err[0] = '\0';
	check(ncfg_main_round(&run, &report, err, sizeof(err)),
	    "a round waiting on nothing else still runs");
	spent = elapsed_ms(&began);
	if (report.request_count == 0u) {
		ncfg_main_mailbox_shut(&mailbox);
	}
	(void)pthread_join(thread, NULL);

	check(report.request_count == 1u, "and the request that arrived is taken");
	check(spent < 2000u,
	    "in well under the tick it was about to sleep through, because the pipe is in "
	    "the same wait");
	detail("milliseconds spent", spent < 2000u ? "under two seconds" : "too many");

	ncfg_main_mailbox_close(&mailbox);
	ncfg_main_watchers_close(&watchers);
}

static void a_mailbox_that_is_shut_or_full_refuses_rather_than_holding_on(void)
{
	ncfg_main_mailbox_t  mailbox;
	ncfg_proto_request_t request;
	ncfg_buf_t           out;
	caller_t             caller;
	pthread_t            thread;
	char                 err[NCFG_ERROR_MAX];
	int                  at;

	memset(&request, 0, sizeof(request));
	memset(&out, 0, sizeof(out));
	request.kind = NCFG_PROTO_REQ_STATUS;
	err[0] = '\0';
	if (!ncfg_main_mailbox_open(&mailbox, answer_fixture, stream_fixture, NULL, -1, err,
	    sizeof(err))) {
		check(0, "a mailbox");
		return;
	}

	/*
	 * Filled from this thread, which no server would do -- the answer seam is
	 * called with the server's lock held, so exactly one request can be inside
	 * it. What is being checked is the margin's behaviour when it is gone, and
	 * the only way to reach it is to put the slots there directly.
	 */
	for (at = 0; at < NCFG_MAIN_PENDING_MAX; at++) {
		mailbox.at[at].in_use = 1;
		mailbox.at[at].request = &request;
	}
	err[0] = '\0';
	check(!ncfg_main_mailbox_answer(&mailbox, &request, NULL, NCFG_ARRIVED_LOCAL, &out, err,
	    sizeof(err)),
	    "a full mailbox refuses rather than queueing behind a slow loop");
	check(strstr(err, "waiting") != NULL, "and says what happened");
	detail("it said", err);
	for (at = 0; at < NCFG_MAIN_PENDING_MAX; at++) {
		mailbox.at[at].in_use = 0;
	}

	/* A waiter that is inside the mailbox when the daemon goes away is
	 * answered rather than abandoned: a connection thread that never returns
	 * is a slot held for the life of the process and a client told nothing at
	 * all. */
	memset(&caller, 0, sizeof(caller));
	caller.mailbox = &mailbox;
	caller.request.kind = NCFG_PROTO_REQ_STATUS;
	if (pthread_create(&thread, NULL, the_connection_thread, &caller) == 0) {
		int parked = 0;

		/*
		 * **Wait until it is really in the mailbox before shutting it.** The
		 * first version of this shut in a loop until the thread returned, and
		 * the thread then took the refusal at the *top* of
		 * `ncfg_main_mailbox_answer` -- the arm for a request that arrives
		 * after the shutdown. Both checks below passed and neither had
		 * exercised the case they are about, which is a waiter already parked
		 * on the condition. Bounded, so that a thread which never arrives
		 * fails this rather than hanging the suite.
		 */
		for (at = 0; at < 2000 && !parked; at++) {
			(void)pthread_mutex_lock(&mailbox.lock);
			parked = mailbox.at[0].in_use;
			(void)pthread_mutex_unlock(&mailbox.lock);
			if (!parked) {
				(void)poll(NULL, 0, 1);
			}
		}
		check(parked, "a waiter is parked in the mailbox before anything shuts it");
		ncfg_main_mailbox_shut(&mailbox);

		/*
		 * **Waited for with a bound, rather than joined.** What a shutdown
		 * that failed to answer its waiters produces is a thread that never
		 * returns, so a plain `pthread_join` here would turn this check into
		 * a suite that hangs -- and `make -C c test` has no clock on it. The
		 * bound turns the same fault into a red line, and the thread is left
		 * detached rather than joined: the mailbox below is not closed either,
		 * because destroying a mutex a live thread is about to take is how a
		 * failing check becomes a crash that hides it.
		 */
		for (at = 0; at < 2000 && !caller.arrived; at++) {
			(void)poll(NULL, 0, 1);
		}
		check(caller.arrived,
		    "and is let go of by the shutdown rather than left on the condition for "
		    "the life of the process");
		if (!caller.arrived) {
			(void)pthread_detach(thread);
			return;
		}
		(void)pthread_join(thread, NULL);
		check(caller.result == 0, "a waiter caught by a shutdown is refused");
		check(strstr(caller.err, "shutting down") != NULL,
		    "and told that is what happened, rather than left holding the connection");
		detail("it said", caller.err);
	}

	err[0] = '\0';
	check(!ncfg_main_mailbox_answer(&mailbox, &request, NULL, NCFG_ARRIVED_LOCAL, &out, err,
	    sizeof(err)),
	    "and a request arriving after the shutdown is refused too");
	ncfg_main_mailbox_close(&mailbox);
}

/* ------------------------------------------------------------------------ *
 * The accessors the loop needs, which are the one thing it reaches into other
 * modules for
 * ------------------------------------------------------------------------ */

static void a_closed_thing_has_no_descriptor(void)
{
	ncfg_netlink_t netlink;
	ncfg_rfkill_t  rfkill;
	ncfg_inotify_t inotify;

	ncfg_netlink_init(&netlink);
	ncfg_rfkill_init(&rfkill);
	ncfg_inotify_init(&inotify);

	/*
	 * -1 on everything unopened, which is what makes a source set built from
	 * watches that failed to open a set with nothing in it rather than one
	 * polling descriptor zero -- which is standard input.
	 */
	check(ncfg_netlink_descriptor(&netlink) < 0, "an unopened netlink socket has none");
	check(ncfg_netlink_descriptor(NULL) < 0, "and neither has no socket at all");
	check(ncfg_rfkill_descriptor(&rfkill) < 0, "an unopened kill-switch reader has none");
	check(ncfg_rfkill_descriptor(NULL) < 0, "and neither has no reader at all");
	check(ncfg_inotify_descriptor(&inotify) < 0, "an unopened inotify instance has none");
	check(ncfg_inotify_descriptor(NULL) < 0, "and neither has no instance at all");
	check(ncfg_watch_descriptor(NULL) < 0, "and neither has no watcher at all");
	check(ncfg_supplicant_client_descriptor(NULL) < 0, "nor no supplicant connection");
}

/* ------------------------------------------------------------------------ */

int main(void)
{
	const char *base;

	/* Quiet, because what this file drives logs a line per dropped source and
	 * the suite's output is the checks. */
	ncfg_log_accept(NCFG_LOG_CRITICAL);

	base = testdir_make("loop");
	if (!base) {
		printf("could not make a directory to work in\n");
		return 1;
	}
	printf("== loop_test in %s\n", base);

	a_revents_mask_says_one_of_five_things();
	a_source_that_cannot_answer_loses_its_place();
	what_poll_came_back_with();
	the_wait_is_what_is_left_of_the_deadline();
	a_burst_is_collapsed_but_not_for_ever();
	which_wake_a_descriptor_folds_into();
	a_round_with_nothing_in_it_runs_no_pass();
	a_roam_is_a_move_within_one_network();
	what_the_log_says_about_a_supplicant_event();
	the_source_set_keeps_its_order();
	a_roam_that_does_not_fit_is_counted();

	a_burst_collapses_into_one_wake();
	a_burst_that_never_ends_still_lets_the_pass_run();
	a_descriptor_that_hung_up_is_dropped();
	a_descriptor_that_is_not_open_is_dropped_at_once();
	a_round_sweeps_the_streams_even_when_nothing_happened();
	a_source_that_will_not_be_read_loses_its_place();
	a_signal_mid_wait_does_not_restart_the_backstop();

	the_configuration_watch_answers_the_same_question_either_way(base, 0);
	the_configuration_watch_answers_the_same_question_either_way(base, 1);
	a_device_that_ends_stops_being_read(base);
	a_window_timer_that_fires_during_a_pass_is_not_lost(base);
	a_signal_between_the_check_and_the_wait_still_stops_it();
	a_station_that_moved_is_carried_out_of_the_round(base);
	a_supplicant_event_reaches_the_log(base);
	the_dead_reply_sockets_are_swept(base);

	fifty_events_are_one_observation(base);
	the_pass_sees_a_waiting_request_before_anything_answers_it(base);
	a_subscription_crosses_to_the_loops_thread(base);
	a_request_arriving_ends_the_wait(base);
	a_mailbox_that_is_shut_or_full_refuses_rather_than_holding_on();
	a_closed_thing_has_no_descriptor();

	testdir_remove(base);

	printf("loop_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("loop_test: all checks passed\n");
	} else {
		printf("loop_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
