/*
 * live_rule.cpp -- a routing rule written through the dialog, against a daemon.
 *
 * WHY THIS EXISTS
 *   `rule_block` checks the text. What it cannot check is whether netcfgd made
 *   the rule the form meant: the compiler has its own names for these keys, a
 *   selector it does not recognise is a refusal rather than a silent drop, and
 *   the one thing a rule editor must never do is write a rule that matches
 *   more traffic than the operator asked it to.
 *
 *   So this writes one through the dialog, reads it back through the daemon's
 *   own answer, and asserts the refusals that belong to the form rather than
 *   to the daemon -- naming the dialog's own sentence, because the daemon
 *   refuses some of the same things in words of its own.
 */

#include "../../src/ncfg_connection.h"
#include "../../src/rule_dialog.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>

#include <cstdio>

static int failures;

static void check(const char *what, bool condition, const QString &detail = QString())
{
	if (condition) {
		printf("ok   %s\n", what);
	} else {
		printf("FAIL %s\n", what);
		if (!detail.isEmpty()) {
			printf("       %s\n", detail.toUtf8().constData());
		}
		failures++;
	}
	fflush(stdout);
}

static bool declared(ncfg_connection *connection, const QString &id, ncfg_rule_row *out)
{
	QList<ncfg_rule_row> rules;
	QString error;
	if (!connection->rules(&rules, &error)) {
		return false;
	}
	for (const ncfg_rule_row &rule : rules) {
		if (rule.id == id) {
			*out = rule;
			return true;
		}
	}
	return false;
}

int main(int argc, char **argv)
{
	QApplication app(argc, argv);

	ncfg_connection connection;
	QString error;
	if (!connection.open(QString(), &error)) {
		printf("FAIL the dialog's connection reaches netcfgd\n       %s\n",
		    error.toUtf8().constData());
		return 1;
	}
	check("the dialog's connection reaches netcfgd", true);

	const QString name = QStringLiteral("gui-rule");

	{
		ncfg_rule_dialog dialog(&connection, ncfg_rule_row());
		auto *id = dialog.findChild<QLineEdit *>(QStringLiteral("rule_id"));
		auto *priority = dialog.findChild<QSpinBox *>(QStringLiteral("rule_priority"));
		auto *from = dialog.findChild<QLineEdit *>(QStringLiteral("rule_from"));
		auto *fwmark = dialog.findChild<QSpinBox *>(QStringLiteral("rule_fwmark"));
		auto *fwmask = dialog.findChild<QSpinBox *>(QStringLiteral("rule_fwmask"));
		auto *action = dialog.findChild<QComboBox *>(QStringLiteral("rule_action"));
		auto *table = dialog.findChild<QSpinBox *>(QStringLiteral("rule_table"));
		auto *suppress = dialog.findChild<QSpinBox *>(QStringLiteral("rule_suppress"));
		auto *note = dialog.findChild<QLabel *>(QStringLiteral("rule_note"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("rule_save"));
		if (!id || !priority || !from || !fwmark || !fwmask || !action || !table
		    || !suppress || !note || !save) {
			check("the dialog has the fields it needs", false);
			return 1;
		}
		check("the dialog has the fields it needs", true);
		check("a new rule offers a priority rather than leaving it at zero",
		    priority->value() == 1000, QString::number(priority->value()));
		/* -1 rather than 0, because 0 is a mark and a rule on `fwmark 0` is a
		 * rule somebody wrote on purpose. */
		check("and no mark, which is not the same as a mark of zero",
		    fwmark->value() == -1, QString::number(fwmark->value()));

		save->click();
		check("a rule with no name is refused by the dialog",
		    note->text().startsWith(QStringLiteral("a rule needs a name")), note->text());

		id->setText(name);
		/* **A mask with no mark.** The kernel takes it, the compiler takes it,
		 * and the rule it makes does not fire. Refused here, by name, because
		 * nothing further down calls it a mistake. */
		fwmask->setValue(0xff);
		save->click();
		check("and so is a mark mask with no mark to mask",
		    note->text().startsWith(QStringLiteral("a mark mask needs a mark")),
		    note->text());

		fwmark->setValue(1);
		priority->setValue(600);
		from->setText(QStringLiteral("10.9.0.0/24"));
		action->setCurrentIndex(action->findData(QStringLiteral("lookup")));
		table->setValue(42);
		/* Zero, which is the commonest use of it: ignore the table's default
		 * route so a rule below can catch what it would have swallowed. */
		suppress->setValue(0);
		save->click();
		check("and a whole rule is written", dialog.outcome().contains(name),
		    QStringLiteral("%1 / %2").arg(dialog.outcome(), note->text()));
		/* Configuration is not the kernel: netcfgd re-read the document, and
		 * the machine still has whatever rules it had a moment ago. */
		check("and the outcome says apply is what changes the machine",
		    dialog.outcome().contains(QStringLiteral("apply")), dialog.outcome());
	}

	{
		ncfg_rule_row written;
		check("netcfgd compiled the rule", declared(&connection, name, &written));
		check("at the priority it was given", written.priority == 600,
		    QString::number(written.priority));
		check("with the source it matches on", written.from == QStringLiteral("10.9.0.0/24"),
		    written.from);
		check("and the table it consults", written.action == QStringLiteral("lookup")
		        && written.table == QStringLiteral("42"),
		    QStringLiteral("%1 %2").arg(written.action, written.table));
		check("and the mark, which is a mark and not an absence",
		    written.fwmark == 1 && written.fwmask == 0xff,
		    QStringLiteral("%1/%2").arg(written.fwmark).arg(written.fwmask));
		check("and the suppression of zero, which survived being zero",
		    written.suppress_prefixlength == 0,
		    QString::number(written.suppress_prefixlength));
		/* The column the window shows. A blank phrase on a rule with selectors
		 * reads as "matches everything", which is the opposite of what it does
		 * -- which is why the mark was added to it this round. */
		check("and the selector phrase names what it matches",
		    written.selector.contains(QStringLiteral("10.9.0.0/24"))
		        && written.selector.contains(QStringLiteral("fwmark")),
		    written.selector);
	}

	/* Re-opening loads what was written: a form that saves and does not load
	 * replaces the block with its own defaults, which for a rule means the
	 * selectors quietly go. */
	{
		ncfg_rule_row existing;
		if (!declared(&connection, name, &existing)) {
			check("the rule is there to edit", false);
			return 1;
		}
		ncfg_rule_dialog dialog(&connection, existing);
		auto *id = dialog.findChild<QLineEdit *>(QStringLiteral("rule_id"));
		auto *priority = dialog.findChild<QSpinBox *>(QStringLiteral("rule_priority"));
		auto *from = dialog.findChild<QLineEdit *>(QStringLiteral("rule_from"));
		auto *fwmark = dialog.findChild<QSpinBox *>(QStringLiteral("rule_fwmark"));
		auto *suppress = dialog.findChild<QSpinBox *>(QStringLiteral("rule_suppress"));
		auto *action = dialog.findChild<QComboBox *>(QStringLiteral("rule_action"));
		auto *table = dialog.findChild<QSpinBox *>(QStringLiteral("rule_table"));
		check("the name of an existing rule cannot be edited", id->isReadOnly());
		check("and the priority is loaded", priority->value() == 600,
		    QString::number(priority->value()));
		check("and the source", from->text() == QStringLiteral("10.9.0.0/24"),
		    from->text());
		check("and the mark", fwmark->value() == 1, QString::number(fwmark->value()));
		check("and the suppression, as zero rather than as off",
		    suppress->value() == 0, QString::number(suppress->value()));
		/* The number, not merely the row: the document holds a table as a
		 * number and the client read it as text, so it came back empty and
		 * the editor loaded a zero over it. A form that saves and loads is
		 * worth nothing if what it loads is a default. */
		check("and the table it consults", table->value() == 42,
		    QString::number(table->value()));
		/* A table beside an action that consults none is a number the kernel
		 * ignores and a reader has to explain away, so the rows go. */
		check("a lookup shows the table it consults", !table->isHidden());
		action->setCurrentIndex(action->findData(QStringLiteral("blackhole")));
		check("and an action that stops there hides it", table->isHidden());
		check("and hides the suppression with it", suppress->isHidden());
	}

	{
		QString removed;
		check("the rule can be removed again",
		    connection.config_delete(QStringLiteral("rule-%1").arg(name), &removed),
		    removed);
		ncfg_rule_row gone;
		check("and netcfgd stops reporting it", !declared(&connection, name, &gone));
	}

	if (failures == 0) {
		printf("live_rule: all checks passed\n");
	} else {
		printf("live_rule: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
