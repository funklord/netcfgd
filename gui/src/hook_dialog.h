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
#include <QWidget>

class QComboBox;
class QLabel;
class QListWidget;
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

/*
 * The hooks one block declares, as a list: shown, added, changed, removed.
 *
 * **Shared by the interface and network dialogs** (10.616). The interface
 * dialog had this; a network's hooks had no editor, on the reasoning that the
 * GUI had no way to read them -- which stopped being true when 10.34 made
 * `hook_scripts` list a network's too, so a network carrying a hook was
 * refused for a reason that was no longer so.
 *
 * `prefix` names the widgets (`iface_hooks`), which the probes find them by.
 */
class ncfg_hooks_editor : public QWidget {
	Q_OBJECT

public:
	ncfg_hooks_editor(const QString &prefix, QWidget *parent = nullptr);

	/*
	 * Load the hooks one block declares: an interface's, or a network's when
	 * `network` is true. `declared` is how many the document says it has.
	 *
	 * **Two questions, two tiers, and both answers are needed.** Whether
	 * there are hooks comes from the document, which is `observe`; what is in
	 * them comes from the file the compiler materialised, which is `admin` --
	 * netcfgd keeps it at 0700 because it runs as root. An editor that can see
	 * the first and not the second knows there is a hook and not what it
	 * says, and `withheld` is then true: its block must not be saved, since
	 * that would write the hook empty.
	 *
	 * Answers a sentence for the dialog's note where that happened, and
	 * empty where every script was read.
	 */
	QString load(ncfg_connection *connection, const QString &owner, bool network, int declared);
	/* Each hook as its block, verbatim, in order: see `ncfg_hook_block`. */
	QStringList blocks() const;
	bool        withheld() const { return unknown; }

signals:
	void noted(const QString &text);

private slots:
	void add();
	void change();
	void drop();

private:
	void put(const ncfg_hook_script &hook);

	QListWidget            *list;
	QPushButton            *add_button;
	QPushButton            *change_button;
	QPushButton            *drop_button;
	QList<ncfg_hook_script> scripts;
	QString                 owner;
	bool                    network = false;
	bool                    unknown = false;
};

#endif /* NCFG_HOOK_DIALOG_H */
