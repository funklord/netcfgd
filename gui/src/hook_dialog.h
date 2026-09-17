/*
 * hook_dialog.h -- the program netcfgd runs when the network changes.
 *
 * **A hook is shell, and this edits it as one**, for the reason the probe
 * editor gives: what netcfgd runs is a program, and any attempt to present a
 * program as a set of boxes either constrains what an operator can express or
 * lies about what is running.
 *
 * This one writes nothing. A hook lives inside an `interface` block, one
 * drop-in owns that block whole, and a second file declaring the same
 * interface is a duplicate the loader refuses -- correctly. So the interface
 * editor owns the block and this returns a phase and a body to it.
 *
 * **What is deliberately absent is `run_as` and `timeout`.** The model has
 * both fields and the hook runner honours both; the configuration language has
 * no key for either, so there is nothing a form could write that would reach
 * them. `netcfgd.conf.example` showed `run_as=nobody` inside a hook body as
 * though it worked, and it does not: those lines are shell, the hook still
 * runs as root, and the example is corrected in the same round as this file.
 * Offering a field here would have been the third copy of that mistake.
 */
#ifndef NCFG_HOOK_DIALOG_H
#define NCFG_HOOK_DIALOG_H

#include "ncfg_connection.h"

#include <QDialog>
#include <QString>

class QComboBox;
class QLabel;
class QPlainTextEdit;
class QPushButton;

class ncfg_hook_dialog : public QDialog {
	Q_OBJECT

public:
	/*
	 * `existing` with an empty phase means a hook being written: the body
	 * starts from a template, because a blank page says nothing about the two
	 * things that are not guessable -- what is in the environment, and that a
	 * line of its own containing `}` ends the hook early.
	 */
	explicit ncfg_hook_dialog(const ncfg_hook_script &existing, QWidget *parent = nullptr);

	/* What was chosen, once the dialog was accepted. */
	QString chosen_phase() const { return phase_key; }
	QString chosen_body() const { return body_text; }

private slots:
	void submit();

private:
	QString phase_key;
	QString body_text;

	QComboBox      *phase;
	QPlainTextEdit *body;
	QLabel         *note;
	QPushButton    *save_button;
};

/*
 * One hook block, as it goes inside an `interface` block.
 *
 * A free function for the reason every other block writer here is one: what it
 * produces is configuration netcfgd has to compile, and the ways it can be
 * wrong are invisible in a screenshot. Two in particular:
 *
 * * **The body is written verbatim, at column zero.** Indenting it would be
 *   cosmetic in the language and destructive in practice: the materialiser
 *   prepends `#!/bin/sh` to a body that does not start with one, so an
 *   indented shebang is not a shebang, and each save would add another line to
 *   the script netcfgd runs.
 * * **The five event phases are spelled `on carrier`**, not `carrier`. The
 *   parser takes the six lifecycle phases bare and the rest after `on`, and a
 *   block that got that wrong would be read as an assignment and refused.
 */
QString ncfg_hook_block(const QString &phase, const QString &body);

/*
 * Whether a body would end where it says it does.
 *
 * A hook body ends at the **first line containing only a closing brace**,
 * which is the one irregular production in the grammar: brace counting would
 * mean parsing shell. The cost is that a multi-line shell function ends the
 * hook early and the rest of the script is then read as configuration, which
 * fails somewhere else entirely, talking about `=` and `{` at a line the
 * operator wrote shell on. Cheaper to say so beside the field.
 */
bool ncfg_hook_body_terminates_early(const QString &body);

#endif /* NCFG_HOOK_DIALOG_H */
