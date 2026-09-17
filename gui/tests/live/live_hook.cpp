/*
 * live_hook.cpp -- a hook, through the interface editor, against a daemon.
 *
 * WHY THIS EXISTS
 *   `hook_block` checks the text. What it cannot check is the thing this round
 *   is about: that netcfgd hands the body back, that what it hands back is
 *   what was written, and that the interface editor -- which writes the whole
 *   block, because a drop-in owns it whole -- puts the hook back exactly as it
 *   found it.
 *
 *   The last one is the defect this replaces. Until now the editor refused to
 *   save any interface carrying a hook, because saving would have deleted it,
 *   so "the editor keeps the hook" is not a nicety: it is the reason the
 *   refusal could be lifted.
 */

#include "../../src/hook_dialog.h"
#include "../../src/interface_dialog.h"
#include "../../src/ncfg_connection.h"

#include <QApplication>
#include <QFile>
#include <QLabel>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QPushButton>

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

static bool script_for(ncfg_connection *connection, const QString &interface,
    ncfg_hook_script *out)
{
	QList<ncfg_hook_script> scripts;
	QString error;
	if (!connection->hook_scripts(&scripts, &error)) {
		return false;
	}
	for (const ncfg_hook_script &script : scripts) {
		if (script.interface == interface) {
			*out = script;
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

	/* An interface of this probe's own. `gui_wifi.sh` runs every probe against
	 * one daemon and one configuration directory, so a drop-in written here is
	 * still there when the next one runs -- which once cost `live_wifi` three
	 * checks about a radio another probe had configured. */
	const QString iface = QStringLiteral("gui-hook0");
	const QString body = QStringLiteral(
	    "#!/bin/sh\n# written by live_hook\nlogger -t netcfgd \"$NCFG_INTERFACE up\"\n");

	{
		QStringList block;
		block << QStringLiteral("interface %1 {").arg(iface);
		block << QStringLiteral("\tconfig = \"dhcp\"");
		block << ncfg_hook_block(QStringLiteral("post_up"), body);
		block << QStringLiteral("}");
		QString written;
		check("an interface with a hook can be written at all",
		    connection.config_put(QStringLiteral("interface-%1").arg(iface),
		        block.join(QStringLiteral("\n")) + QStringLiteral("\n"), true, &written),
		    written);
	}

	ncfg_hook_script compiled;
	{
		check("netcfgd compiled the hook and hands the script back",
		    script_for(&connection, iface, &compiled));
		check("on the phase it was written at", compiled.phase == QStringLiteral("post_up"),
		    compiled.phase);
		check("and says it could read the file it names", compiled.readable, compiled.path);
		/* **Byte for byte.** The materialiser prepends `#!/bin/sh` to a body
		 * that has none; this one has one, so what comes back is what was
		 * typed -- and a body that came back with a second shebang would be a
		 * body that grows by a line on every save. */
		check("and the script is exactly what was written", compiled.text == body,
		    compiled.text);
	}

	/* The document's own listing, which is `observe` and carries no body. Both
	 * halves matter to the editor: this one says a hook is there, the one
	 * above says what is in it. */
	{
		QList<ncfg_hook_row> declared;
		QString listed;
		check("the hook is in the document listing too",
		    connection.hooks(&declared, &listed), listed);
		bool found = false;
		for (const ncfg_hook_row &row : declared) {
			if (row.interface == iface) {
				found = true;
				/* Empty on every machine, because the language has no key for
				 * it. Asserted so that the day one appears, somebody has to
				 * come here and say so. */
				check("and runs as nobody in particular, which means root",
				    row.run_as.isEmpty(), row.run_as);
			}
		}
		check("and names this interface", found);
	}

	/* **The editor keeps it.** This is what the round bought: the interface
	 * editor writes the block whole, so a hook it could not carry was a hook
	 * saving deleted -- which is why it used to refuse. */
	{
		ncfg_interface_dialog dialog(&connection, iface);
		auto *list = dialog.findChild<QListWidget *>(QStringLiteral("iface_hooks"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("iface_save"));
		auto *note = dialog.findChild<QLabel *>(QStringLiteral("iface_note"));
		if (!list || !save) {
			check("the interface dialog has a hooks list", false);
			return 1;
		}
		check("the interface dialog has a hooks list", true);
		check("with this interface's hook in it", list->count() == 1,
		    QString::number(list->count()));
		check("named by its phase",
		    list->count() == 1 && list->item(0)->text().startsWith(
		                              QStringLiteral("post_up")),
		    list->count() == 1 ? list->item(0)->text() : QString());
		/* And the row says what the script does rather than what every script
		 * starts with: the first line that is neither shebang nor comment. */
		check("and by what it does rather than by its shebang",
		    list->count() == 1 && list->item(0)->text().contains(QStringLiteral("logger")),
		    list->count() == 1 ? list->item(0)->text() : QString());

		save->click();
		check("and the interface saves, where it used to refuse",
		    dialog.outcome().contains(iface),
		    QStringLiteral("%1 / %2").arg(dialog.outcome(),
		        note ? note->text() : QString()));
	}

	{
		ncfg_hook_script after;
		check("the hook survived the save", script_for(&connection, iface, &after));
		check("with the same script, byte for byte", after.text == body, after.text);
		/* The specific way it would not survive: an indented shebang stops
		 * being one and the materialiser adds another, once per save. */
		check("and no second shebang on top of the first",
		    !after.text.contains(QStringLiteral("#!/bin/sh\n#!/bin/sh")), after.text);
	}

	/* The two refusals that belong to the editor rather than to the daemon.
	 * The second is the grammar's one irregular production said beside the
	 * field: netcfgd would report it as a syntax error about `=` and `{` at a
	 * line the operator wrote shell on. */
	{
		ncfg_hook_dialog dialog(ncfg_hook_script(), nullptr);
		auto *text = dialog.findChild<QPlainTextEdit *>(QStringLiteral("hook_body"));
		auto *note = dialog.findChild<QLabel *>(QStringLiteral("hook_note"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("hook_save"));
		if (!text || !note || !save) {
			check("the hook editor has its fields", false);
			return 1;
		}
		check("the hook editor has its fields", true);
		check("and says up front that a hook runs as root",
		    note->text().contains(QStringLiteral("runs as root")), note->text());

		text->setPlainText(QString());
		save->click();
		check("an empty hook is refused by the editor",
		    note->text().startsWith(QStringLiteral("an empty hook runs nothing")),
		    note->text());

		text->setPlainText(QStringLiteral("#!/bin/sh\ngreet() {\n\techo hi\n}\ngreet\n"));
		save->click();
		check("and so is a body whose brace ends the hook early",
		    note->text().startsWith(QStringLiteral("a line containing only")),
		    note->text());

		text->setPlainText(QStringLiteral("#!/bin/sh\ngreet() { echo hi; }\ngreet\n"));
		save->click();
		check("while the one-line form is kept",
		    dialog.chosen_body().contains(QStringLiteral("greet() { echo hi; }")),
		    dialog.chosen_body());
		check("with the phase it was opened at",
		    dialog.chosen_phase() == QStringLiteral("post_up"), dialog.chosen_phase());
	}

	/* **A hook netcfgd cannot read back.** The document still names it, so the
	 * editor must refuse rather than write the block with an empty body -- the
	 * one way this round could delete somebody's script. Made by taking the
	 * materialised file away, which is what an operator clearing `/run` by
	 * hand does; the next reload writes it again, so the window closes when
	 * this probe removes the interface below. */
	{
		check("the materialised script can be taken away",
		    QFile::remove(compiled.path), compiled.path);

		ncfg_hook_script unreadable;
		check("netcfgd still lists the hook the document names",
		    script_for(&connection, iface, &unreadable));
		check("and says it could not read it", !unreadable.readable, unreadable.path);
		check("with no text, which is not a hook with nothing in it",
		    unreadable.text.isEmpty(), unreadable.text);

		ncfg_interface_dialog dialog(&connection, iface);
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("iface_save"));
		auto *note = dialog.findChild<QLabel *>(QStringLiteral("iface_note"));
		save->click();
		check("and the interface editor refuses to save over it",
		    dialog.outcome().isEmpty(), dialog.outcome());
		check("saying which it is, in its own words",
		    note && note->text().contains(QStringLiteral("would write the hook empty")),
		    note ? note->text() : QString());
	}

	{
		QString removed;
		check("the interface can be removed again",
		    connection.config_delete(QStringLiteral("interface-%1").arg(iface), &removed),
		    removed);
		ncfg_hook_script gone;
		check("and netcfgd stops reporting its hook", !script_for(&connection, iface, &gone));
	}

	if (failures == 0) {
		printf("live_hook: all checks passed\n");
	} else {
		printf("live_hook: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
