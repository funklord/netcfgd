/*
 * plan.c -- `ncfg plan` and `ncfg show`: what would change, and what was
 * asked for.
 *
 * WHY EVERY ACTION CARRIES A REASON
 *   An action list without reasons is a black box with extra steps. Each line
 *   says what will be done, to which interface, which field differs and what
 *   the two sides of that field are -- `addr.add eth0  addressing[0]:
 *   192.168.1.10/24 (was <absent>)`. The planner carries the reason on the
 *   action for exactly this line; nothing here computes one.
 *
 * WHY A REFUSAL AND A STRANDING ARE NOT WARNINGS
 *   A guard that dropped an action, and a credential a plan walks away from,
 *   are each a question somebody has to answer -- and burying them among
 *   warnings is how they get ignored (0010, 0042). So each prints its own
 *   block, with the exact invocation that consents to it quoted verbatim
 *   rather than described: a refusal the operator cannot act on is just a
 *   complaint.
 */
#include "ncfg/cli.h"

#include "ncfg/buf.h"
#include "ncfg/log.h"

#include <stdio.h>

/*
 * The longest action line this renders.
 *
 * A reason is four short strings -- an interface, a dotted field path and two
 * values -- and a ceiling on the line is `buf.h`'s rule applied to a stack
 * buffer: a rendered value a client chose the length of has to be bounded
 * somewhere. Truncation shows, which is the point; a line silently built to
 * whatever arrived would not.
 */
#define DESCRIBE_MAX 1024

/*
 * One line saying what an action does and why.
 *
 * `<absent>` on either side is the planner's word, not this one's: a field
 * that is not there is a value, and rendering it as an empty string would make
 * "the document says nothing" and "the document says the empty string" the
 * same line.
 */
static const char *describe(const char *op, const ncfg_reason_t *reason, char *out,
    size_t out_size)
{
	char where[80];

	where[0] = '\0';
	if (reason->interface) {
		(void)snprintf(where, sizeof(where), " %s", reason->interface);
	}
	(void)snprintf(out, out_size, "%s%s  %s: %s (was %s)", op ? op : "?", where,
	    reason->field ? reason->field : "", reason->desired ? reason->desired : "",
	    reason->observed ? reason->observed : "");
	return out;
}

/*
 * What a guard stopped, and the exact command that consents to it.
 *
 * Printed for `plan` and `apply` alike.
 */
static void print_refusals(const ncfg_plan_t *plan)
{
	size_t at;

	for (at = 0; at < plan->refusal_count; at++) {
		const ncfg_refusal_t *refusal = &plan->refusals[at];
		char                  line[DESCRIBE_MAX];

		ncfg_out_writef("refused: %s on %s -- %s depends on it\n", refusal->op,
		    refusal->interface, refusal->guard);
		ncfg_out_writef("         would have been: %s\n",
		    describe(refusal->op, &refusal->reason, line, sizeof(line)));
		ncfg_out_writef("         to allow it:     %s\n", refusal->override_with);
	}
}

/*
 * What a plan walks away from that cannot be taken back.
 *
 * Both ways out are printed, and the config one first: the flag consents for
 * one run, and the config key is the answer that is still there next time
 * somebody reads the file. Printing them the other way round would make the
 * flag look like the fix.
 */
static void print_stranded(const ncfg_plan_t *plan)
{
	size_t at;

	for (at = 0; at < plan->stranded_count; at++) {
		const ncfg_stranded_t *stranded = &plan->stranded[at];

		ncfg_out_writef("stranded: unmanaging %s leaves %s\n", stranded->interface,
		    stranded->credential);
		ncfg_out_writef("          it cannot be revoked: %s\n", stranded->irrevocable);
		ncfg_out_writef("          to remove it:  %s\n", stranded->remove_with);
		ncfg_out_writef("          to leave it:   %s\n", stranded->consent_with);
	}
}

void ncfg_cli_print_plan(const ncfg_plan_t *plan)
{
	size_t at;

	if (!plan) {
		return;
	}
	if (ncfg_plan_is_empty(plan)) {
		ncfg_out_line("nothing to do");
	} else {
		for (at = 0; at < plan->action_count; at++) {
			const ncfg_action_t *action = &plan->actions[at];
			char                 line[DESCRIBE_MAX];

			ncfg_out_writef("%3u  %s\n", (unsigned)action->id,
			    describe(ncfg_op_name(&action->op), &action->reason, line,
			    sizeof(line)));
		}
	}
	for (at = 0; at < plan->warning_count; at++) {
		const ncfg_warning_t *warning = &plan->warnings[at];

		if (warning->interface) {
			ncfg_out_writef("warning: %s: %s\n", warning->interface, warning->message);
		} else {
			ncfg_out_writef("warning: %s\n", warning->message);
		}
	}
	print_refusals(plan);
	print_stranded(plan);
}

/*
 * `ncfg show`: the compiled document, where `cat` can reach it.
 *
 * **The canonical form, not a pretty one.** The Rust prints
 * `serde_json::to_string_pretty`; this port has one document writer and it is
 * the wire writer, and adding a second spelling of one document so that a
 * terminal looks nicer is the drift 0263 spends its length refusing. What is
 * printed is the same document with the same members in the same order, on one
 * line -- which is what `jq` was going to be handed anyway.
 */
int ncfg_cli_print_document(ncfg_document_t *document, char *err, size_t err_size)
{
	ncfg_buf_t buf;
	int        wrote;

	ncfg_buf_init(&buf, 0);
	wrote = ncfg_document_write_canonical(document, &buf, err, err_size);
	if (wrote) {
		/* `ncfg_buf_t` hands out the empty string for a buffer that failed,
		 * never the part that fitted: half a document that looks whole is the
		 * failure mode that rule exists for. */
		ncfg_out_line(ncfg_buf_text(&buf));
	}
	ncfg_buf_free(&buf);
	return wrote;
}
