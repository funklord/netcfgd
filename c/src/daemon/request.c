/*
 * request.c -- the three requests that change the machine.
 *
 * WHY THESE ARE HERE AND NOT IN THE ANSWER SEAM
 *   `apply`, `confirm` and `revert` are the only requests whose answer is a
 *   record of something that happened rather than a reading of something that
 *   is. Each of them opens an executor, each can leave the machine different
 *   from how it found it, and all three touch the same four things the
 *   reconcile pass touches: the desired document, the ownership record, the
 *   confirm window and what that window covers. So they belong beside the
 *   pass, sharing its seams, rather than in `src/main/`'s dispatcher -- which
 *   takes a request apart and hands the pieces on, and is where a second copy
 *   of the arming rule would have ended up.
 *
 * WHAT THE ANSWER IS
 *   A journal, for `apply`, whether the plan ran to the end or stopped at its
 *   third action: the client asked what happened, and what happened is the
 *   answer. `0` with a sentence is for an apply that never started -- a
 *   configuration that does not compile, a window somebody else holds, no way
 *   to reach the machine -- because there is then nothing that ran to report.
 *   `confirm` and `revert` answer `ok`, which is `answer.c`'s envelope, and
 *   their events go to whoever is watching.
 *
 * WHAT IS DELIBERATELY NOT DONE HERE
 *   **The resolv guard is the reconcile pass's and stays there.** It counts
 *   how many passes in a row have had to take `/etc/resolv.conf` back, and a
 *   deliberate apply is not a pass: an operator applying three times in a row
 *   is not a fight with another daemon, and counting it as one would sweep on
 *   the third.
 */
#include "daemon_internal.h"

#include "ncfg/base.h"
#include "ncfg/log.h"

#include <string.h>

/* The reconcile pass's bound, for its reason: a document may name more modems
 * than a pass can cycle in one go, and the ones that do not fit keep their
 * note for the next attempt. */
#define REQUEST_CYCLES_MAX 16

/* ------------------------------------------------------------------------ *
 * apply
 * ------------------------------------------------------------------------ */

/*
 * What this apply falls back to if nobody confirms, or NULL where no window
 * was asked for.
 *
 * **Asked before anything is applied**, so a refusal leaves the machine
 * untouched rather than changed-but-unprotected: a window somebody else holds,
 * or a machine with no last-good configuration to go back to, is an answer the
 * client gets instead of an apply rather than after one.
 */
static ncfg_document_t *window_target(const ncfg_reconcile_t *loop, uint32_t seconds,
    char *err, size_t err_size)
{
	if (seconds == 0u) {
		return NULL;
	}
	return ncfg_confirm_may_arm(loop->state, err, err_size);
}

/*
 * What to record as last-good where no window was armed.
 *
 * **Unless a window is open, in which case the record is somebody else's.** A
 * plain apply inside an outstanding window used to clear the inverses recorded
 * against it and overwrite the last-good with the very configuration the
 * window exists to undo -- so the expiry found nothing to take back, re-planned
 * to what was already in effect, and reported a revert that had reverted
 * nothing. The safety net disappeared without a word. Leaving the record alone
 * is the whole fix: the window resolves on its own terms, and this apply is
 * inside it rather than instead of it.
 */
static void settle_without_a_window(ncfg_reconcile_t *loop)
{
	ncfg_confirm_window_t window;

	if (ncfg_confirm_read_window(loop->state->paths.run, &window)) {
		ncfg_log_emitf("confirm", NCFG_LOG_NOTE,
		    "applied inside an open confirm window; the window still reverts to what "
		    "it was armed against");
		return;
	}
	ncfg_confirm_armed_free(loop->armed);
	if (loop->state->desired) {
		(void)ncfg_confirm_write_last_good(loop->state->paths.run, loop->state->desired,
		    NULL, 0u);
	}
}

int ncfg_daemon_apply_request(ncfg_reconcile_t *loop, const ncfg_daemon_apply_ask_t *ask,
    ncfg_journal_t *out, char *err, size_t err_size)
{
	ncfg_daemon_apply_ask_t nothing_asked;
	ncfg_plan_options_t     options;
	ncfg_plan_t            *plan;
	ncfg_document_t        *last_good;
	ncfg_executor_t         executor;
	const char             *pending[REQUEST_CYCLES_MAX];
	const char             *cycled[REQUEST_CYCLES_MAX];
	char                    revert_to[NCFG_DAEMON_HASH_MAX];
	char                    message[NCFG_ERROR_MAX];
	size_t                  waiting;
	size_t                  cycles;
	uint32_t                seconds;
	int                     moved = 0;

	if (!loop || !loop->state || !out) {
		ncfg_error_set(err, err_size, "an apply needs a loop to run in and somewhere to "
		    "put what it did");
		return 0;
	}
	if (!ask) {
		memset(&nothing_asked, 0, sizeof(nothing_asked));
		ask = &nothing_asked;
	}
	/*
	 * **The configuration's own diagnostics, not a sentence of this module's.**
	 * A client asking to apply a configuration that does not compile wants the
	 * line and the column, which is what the reload recorded; "there is no
	 * desired document" would send them looking for a different fault.
	 */
	if (loop->state->diagnostics) {
		ncfg_error_set(err, err_size, "%s", loop->state->diagnostics);
		return 0;
	}
	if (!loop->state->desired || !loop->state->observed) {
		ncfg_error_set(err, err_size, "this daemon has nothing to apply: it has %s",
		    loop->state->desired ? "not managed to observe the machine"
		                         : "no configuration");
		return 0;
	}
	/*
	 * **`--confirm-within 0` is how an operator declines a window on a machine
	 * whose configuration sets one, and it is the only way to say it (0094).**
	 * The planner is still told the zero -- that is what suppresses the
	 * document's default -- and nothing here may arm from it. A window of no
	 * seconds arms and expires, which is the apply undoing itself a moment
	 * after it succeeded: measured at the time as an interface with no address
	 * four seconds after the flag documented as declining a window was used.
	 */
	seconds = (ask->confirm.has && ask->confirm.value > 0) ? (uint32_t)ask->confirm.value : 0u;
	message[0] = '\0';
	last_good = window_target(loop, seconds, message, sizeof(message));
	if (seconds > 0u && !last_good) {
		ncfg_error_set(err, err_size, "%s", message);
		return 0;
	}

	memset(&options, 0, sizeof(options));
	options.confirm_window = ask->confirm;
	options.allow_disruption = ask->allow_disruption;
	options.allow_disruption_count = ask->allow_disruption_count;
	/* The two consents the planner gained with `strand.c` and `wedged.c`.
	 * They were carried here and warned about rather than passed on, which is
	 * `ncfg_daemon_apply_ask_t`'s note -- and that note goes with them. */
	options.strand_credentials = ask->strand_credentials;
	options.strand_credentials_count = ask->strand_credentials_count;
	options.restart_wedged = ask->restart_wedged;
	options.restart_wedged_count = ask->restart_wedged_count;
	if (last_good) {
		message[0] = '\0';
		if (ncfg_daemon_document_hash(last_good, revert_to, message, sizeof(message))) {
			options.revert_to = revert_to;
		} else {
			/* The plan still runs and the window still opens; what is lost is
			 * the hash in the plan's `commit.arm`, which is a record of what
			 * a revert would go back to rather than the thing that does it. */
			ncfg_log_emitf("confirm", NCFG_LOG_NOTE,
			    "the last-good configuration could not be hashed (%s), so this plan "
			    "does not name what it would revert to", message);
		}
	}
	/*
	 * A deliberate apply performs a SIM cycle that is waiting, the same as a
	 * reconcile pass would: the operator asked netcfgd to make the machine
	 * match, and a modem sitting on a source nothing selected is one of the
	 * ways it does not. Taken before the plan and cleared only after it ran,
	 * so an apply that could not start leaves the note for the next attempt.
	 */
	for (waiting = 0; waiting < ncfg_sims_pending_count(loop->sims) &&
	    waiting < (size_t)REQUEST_CYCLES_MAX; waiting++) {
		pending[waiting] = ncfg_sims_pending_at(loop->sims, waiting);
	}
	options.cycle = pending;
	options.cycle_count = waiting;

	message[0] = '\0';
	plan = ncfg_plan_build(loop->state->desired, loop->state->observed, &options, message,
	    sizeof(message));
	if (!plan) {
		ncfg_document_free(last_good);
		ncfg_error_set(err, err_size, "this machine could not be planned for: %s", message);
		return 0;
	}
	cycles = waiting == 0u ? 0u
	                       : ncfg_daemon_cycles_in(plan, loop->sims, cycled,
	                             REQUEST_CYCLES_MAX);

	message[0] = '\0';
	if (!ncfg_daemon_open_executor(&loop->world, &executor, message, sizeof(message))) {
		ncfg_plan_free(plan);
		ncfg_document_free(last_good);
		ncfg_error_set(err, err_size, "cannot start an apply: %s", message);
		return 0;
	}
	ncfg_journal_init(out);
	message[0] = '\0';
	(void)ncfg_apply(plan, &executor, out, message, sizeof(message));
	ncfg_daemon_record_what_ran(loop->state, "apply", plan, out);
	ncfg_daemon_close_executor(&loop->world, &executor);

	/*
	 * **Cleared here as well as in the reconcile loop, and it was not.** The
	 * note that a modem is waiting for its link to be cycled is taken before
	 * the plan and forgotten after the plan ran; the pass did both and this
	 * path did only the first. So an `ncfg apply` performed the cycle and left
	 * the note, and every apply after it cycled the link again -- taking the
	 * link down and up on a machine that had already switched SIM.
	 */
	ncfg_sims_cycled(loop->sims, cycled, cycles, out);
	message[0] = '\0';
	(void)ncfg_daemon_state_reobserve(loop->state, &moved, message, sizeof(message));
	ncfg_daemon_state_publish(loop->state);

	if (seconds > 0u) {
		ncfg_daemon_arm_window(loop, plan, out, seconds, last_good, NULL);
	} else {
		settle_without_a_window(loop);
	}
	ncfg_plan_free(plan);
	ncfg_document_free(last_good);
	return 1;
}

/* ------------------------------------------------------------------------ *
 * confirm
 * ------------------------------------------------------------------------ */

/*
 * The document the open window covers, or NULL where this daemon cannot say.
 *
 * **Not simply the desired document**, which is what the Rust confirms with. A
 * reload inside the window replaces `desired` with an edit that was deferred
 * and never applied, so confirming would record as last-good a configuration
 * the machine has never been in -- and the next window's revert would then take
 * the machine somewhere it has never been. The armed record carries the hash of
 * what actually ran, so the two can be compared, and a disagreement is answered
 * by recording nothing: a last-good that is one apply out of date is a worse
 * safety net than the one already on disk.
 *
 * A daemon that restarted inside the window has no armed record and no way to
 * tell, and falls back to `desired` -- which is the Rust's behaviour and the
 * old one.
 */
static ncfg_document_t *what_the_window_covered(ncfg_reconcile_t *loop)
{
	char hash[NCFG_DAEMON_HASH_MAX];
	char message[NCFG_ERROR_MAX];

	if (!loop->state->desired) {
		return NULL;
	}
	if (!loop->armed || loop->armed->document[0] == '\0') {
		return loop->state->desired;
	}
	message[0] = '\0';
	if (!ncfg_daemon_document_hash(loop->state->desired, hash, message, sizeof(message))) {
		ncfg_log_emitf("confirm", NCFG_LOG_NOTE,
		    "the desired configuration could not be hashed (%s), so this confirmation "
		    "leaves the last-good configuration as it was", message);
		return NULL;
	}
	if (strcmp(hash, loop->armed->document) != 0) {
		ncfg_log_emitf("confirm", NCFG_LOG_NOTE,
		    "the configuration was edited inside the window and that edit has not been "
		    "applied, so the last-good configuration is left as it was rather than set "
		    "to something this machine has never been in");
		return NULL;
	}
	return loop->state->desired;
}

int ncfg_daemon_confirm_request(ncfg_reconcile_t *loop, char *err, size_t err_size)
{
	ncfg_proto_event_t event;

	if (!loop || !loop->state) {
		ncfg_error_set(err, err_size, "there is no daemon state to confirm against");
		return 0;
	}
	if (!ncfg_confirm_keep(loop->state, loop->armed, what_the_window_covered(loop), &event,
	        err, err_size)) {
		return 0;
	}
	ncfg_daemon_announce(&loop->world, &event);
	return 1;
}

/* ------------------------------------------------------------------------ *
 * revert
 * ------------------------------------------------------------------------ */

int ncfg_daemon_revert_request(ncfg_reconcile_t *loop, const char *reason, char *err,
    size_t err_size)
{
	ncfg_confirm_window_t window;
	ncfg_proto_event_t    event;
	ncfg_executor_t       executor;
	char                  message[NCFG_ERROR_MAX];
	int                   reverted;

	if (!loop || !loop->state) {
		ncfg_error_set(err, err_size, "there is no daemon state to revert");
		return 0;
	}
	/*
	 * **Asked before the executor is opened**, which the Rust does not do:
	 * opening one takes the apply lock and three netlink sockets, and a
	 * `revert` with no window open is refused either way. 0184 is the same
	 * argument about the contention check -- a lock taken to find out there
	 * is nothing to do is a lock `ncfg apply` is waiting on.
	 */
	if (!ncfg_confirm_read_window(loop->state->paths.run, &window)) {
		ncfg_error_set(err, err_size, "no confirm window is open");
		return 0;
	}
	message[0] = '\0';
	if (!ncfg_daemon_open_executor(&loop->world, &executor, message, sizeof(message))) {
		ncfg_error_set(err, err_size, "cannot start a revert: %s", message);
		return 0;
	}
	reverted = ncfg_confirm_revert(loop->state, loop->armed, &executor,
	    reason ? reason : "asked to", &event, err, err_size);
	ncfg_daemon_close_executor(&loop->world, &executor);
	if (!reverted) {
		return 0;
	}
	ncfg_daemon_announce(&loop->world, &event);
	return 1;
}
