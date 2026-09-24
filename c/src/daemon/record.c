/*
 * record.c -- what an apply did, written down where the next pass will read it.
 *
 * WHY THIS IS ONE FUNCTION AND NOT TWO
 *   Two paths apply a plan and then have to say so: the reconcile pass and the
 *   confirm window's revert. They used to hold a copy each of this, identical
 *   but for the log tag, and the copies were about to diverge in the way that
 *   matters -- one of them learning to record the delivered DNS scopes and the
 *   other not. A record that a revert leaves stale is exactly the case
 *   `apply.h` warns about: the planner asks for a delivery on every pass while
 *   it stands.
 *
 * WHAT IT COSTS TO SKIP EITHER HALF
 *   The fold decides what netcfgd may later remove, and the journal is the file
 *   that answers *where an apply stopped*. A reconcile has no terminal, so
 *   without the second a pass that halted at its third action leaves that fact
 *   in the log alone -- and the Rust's own record of this says the log held two
 *   startup lines and nothing else while `plan.last.json` named the cause
 *   exactly. On the revert path it is the only record of the revert at all:
 *   the inverses ran without anybody watching, and that file is where somebody
 *   finding the machine afterwards reads which of them stood.
 */
#include "daemon_internal.h"

#include "ncfg/base.h"
#include "ncfg/dns.h"
#include "ncfg/log.h"

void ncfg_daemon_record_what_ran(const ncfg_daemon_state_t *state, const char *tag,
    const ncfg_plan_t *plan, const ncfg_journal_t *journal)
{
	ncfg_dns_scopes_t      *scopes = NULL;
	const ncfg_dns_scope_t *delivered = NULL;
	size_t                  count = 0u;
	char                    message[NCFG_ERROR_MAX];

	if (!state || !plan || !journal) {
		return;
	}
	if (!tag) {
		tag = "apply";
	}
	message[0] = '\0';
	if (state->desired) {
		scopes = ncfg_dns_scopes_of(state->desired, state->observed, message,
		    sizeof(message));
		if (scopes) {
			delivered = ncfg_dns_scopes_items(scopes, &count);
		} else {
			/*
			 * Said out loud rather than passed as nothing, because the two
			 * look identical from the record's side and are not: a caller with
			 * no list costs one re-delivery, while a list that could not be
			 * taken here means this pass delivered scopes nobody wrote down
			 * and the next one will deliver them again.
			 */
			ncfg_log_emitf(tag, NCFG_LOG_NOTE,
			    "the DNS scopes of this configuration could not be taken (%s), so "
			    "what was delivered is not recorded and will be delivered again",
			    message);
		}
	}
	message[0] = '\0';
	if (!ncfg_apply_record(state->paths.run, plan, journal, delivered, count, state->observed,
	        message, sizeof(message))) {
		ncfg_log_emitf(tag, NCFG_LOG_NOTE,
		    "what this apply did could not be recorded (%s), so netcfgd will not "
		    "claim those objects as its own", message);
	}
	ncfg_dns_scopes_free(scopes);
	message[0] = '\0';
	if (!ncfg_apply_write_journal(state->paths.run, journal, message, sizeof(message))) {
		ncfg_log_emitf(tag, NCFG_LOG_NOTE,
		    "the journal of this apply could not be written (%s), so nothing under "
		    "the run directory says where it got to", message);
	}
}
