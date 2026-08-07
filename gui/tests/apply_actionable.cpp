/*
 * apply_actionable.cpp -- can the operator act on a plan whose only content is
 * a refusal?
 *
 * project.md records this as a bug found once, by a headless probe that was
 * never committed: "Is there anything to do?" was read off the action list, and
 * a refusal usually means *no* actions -- the guard stops the ones it covers --
 * so a plan whose only content was a refusal had an empty action list and
 * Apply was disabled on exactly the plan consent (0088) exists for.
 *
 * The fix is in the tree and the probe that found it is not, so nothing stops
 * it coming back. This is that probe, kept.
 *
 * It needs no daemon and no connection: the question is a property of a plan,
 * which is why it is a predicate now rather than three conditions inline.
 */

#include "../src/apply_dialog.h"
#include "../src/ncfg_connection.h"

#include <QCoreApplication>

#include <cstdio>

static int failures;

static void check(bool condition, const char *what)
{
	fprintf(stderr, "apply_actionable: %-50s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static ncfg_note_row note(const char *text)
{
	ncfg_note_row row;
	row.detail = QString::fromLatin1(text);
	return row;
}

int main(int argc, char **argv)
{
	QCoreApplication application(argc, argv);

	/* A converged machine. The only plan Apply should be shut for. */
	ncfg_plan_data converged;
	check(!ncfg_apply_dialog::actionable(converged),
	    "a converged machine has nothing to do");

	/* The ordinary case. */
	ncfg_plan_data work;
	work.actions.append(ncfg_action_row());
	check(ncfg_apply_dialog::actionable(work), "a plan with actions is actionable");

	/* The bug. No actions at all, because the guard stopped them -- and this
	 * is precisely the plan an operator opened the dialog to consent to. */
	ncfg_plan_data refused;
	refused.refusals.append(note("eth0 would lose its address"));
	check(refused.actions.isEmpty(), "the refused plan really has no actions");
	check(ncfg_apply_dialog::actionable(refused),
	    "a plan that is only a refusal is actionable");

	/* The same shape for the other consent, which is a separate list on
	 * purpose: agreeing to an outage on one interface is not agreeing to leave
	 * a private key on another. */
	ncfg_plan_data stranded;
	stranded.stranded.append(note("wg0's key would be unreachable"));
	check(stranded.actions.isEmpty(), "the stranded plan really has no actions");
	check(ncfg_apply_dialog::actionable(stranded),
	    "a plan that is only a stranded credential is actionable");

	/* Warnings are not consent and are not work. A plan carrying only a
	 * warning has genuinely nothing to apply, and treating it as actionable
	 * would put an enabled Apply in front of somebody with nothing behind it. */
	ncfg_plan_data warned;
	warned.warnings.append(note("eth0's probe has never run"));
	check(!ncfg_apply_dialog::actionable(warned),
	    "a plan with only a warning is not actionable");

	return failures ? 1 : 0;
}
