/*
 * live_interface_dialog.cpp -- configuring an interface, against a daemon.
 *
 * WHY THIS EXISTS
 *   Two things had no way to be set from this program: `preference`, which is
 *   which uplink wins and is how a wired cable takes over from wifi, and the
 *   probe, which is how netcfgd decides a link actually works.
 *
 *   The probe matters more than it looks. netcfgd used to choose an uplink by
 *   carrier alone, and a cable into a switch that has lost its own uplink has
 *   carrier and no path -- so netcfgd kept preferring it while the wifi that
 *   worked sat at a worse metric doing nothing. Decision 0119 makes a failing
 *   probe withhold routes exactly as a missing carrier does. A dialog that
 *   wrote a probe netcfgd could not compile would leave the operator with
 *   carrier-only behaviour and a screen saying otherwise.
 *
 * WHAT IT ASSERTS
 *   The compiled document, because that is what proves netcfgd made sense of
 *   the block -- and the probe's argv in particular. `-I <interface>` is not
 *   decoration: netcfgd runs the command as given and binds nothing, so a probe
 *   without it answers about whichever interface the route table picked, which
 *   is the failure the probe exists to catch.
 */

#include "../../src/interface_dialog.h"
#include "../../src/probe_dialog.h"
#include "../../src/ncfg_connection.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QFile>
#include <QLineEdit>
#include <QPushButton>
#include <QFormLayout>
#include <QPlainTextEdit>
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

int main(int argc, char **argv)
{
	QApplication app(argc, argv);
	const QString conf = QString::fromUtf8(qgetenv("NCFG_CONFIG_DIR")) + "/conf.d/";
	/*
	 * **A name of this probe's own, not the radio the other probes use.**
	 *
	 * `gui_wifi.sh` runs every probe against one daemon and one config
	 * directory, in glob order, so a drop-in written here is still there when
	 * the next one runs. The first version configured `radio0` -- giving it
	 * DHCP and a probe pinging an address nothing answers -- and `live_wifi`
	 * then failed three checks about activating that radio, several probes
	 * later, with nothing to connect the two.
	 *
	 * Nothing here needs the interface to exist: every assertion is about the
	 * text written and whether netcfgd compiled it. An interface the machine
	 * does not have compiles to a warning, which is the right answer and not
	 * a failure.
	 */
	const QString iface = QStringLiteral("gui-probe0");

	ncfg_connection connection;
	QString error;
	if (!connection.open(QString(), &error)) {
		printf("FAIL the dialog's connection reaches netcfgd\n       %s\n",
		    error.toUtf8().constData());
		return 1;
	}
	check("the dialog's connection reaches netcfgd", true);

	ncfg_interface_dialog dialog(&connection, iface);
	auto *addressing = dialog.findChild<QComboBox *>(QStringLiteral("iface_addressing"));
	auto *preference = dialog.findChild<QSpinBox *>(QStringLiteral("iface_preference"));
	auto *mtu = dialog.findChild<QSpinBox *>(QStringLiteral("iface_mtu"));
	auto *detection = dialog.findChild<QComboBox *>(QStringLiteral("iface_detection"));
	auto *save = dialog.findChild<QPushButton *>(QStringLiteral("iface_save"));
	if (!addressing || !preference || !mtu || !detection || !save) {
		check("the dialog has the fields it needs", false);
		return 1;
	}
	check("the dialog has the fields it needs", true);

	/* Carrier-only is offered and is named rather than being the absence of a
	 * setting: it is the answer that was wrong often enough to need replacing,
	 * and an operator choosing it should be choosing it. */
	check("carrier-only link detection is offered by name",
	    detection->findData(QString()) >= 0);
	/* The scripts come off the disk rather than out of this dialog, so the
	 * list depends on what is installed. `--` in the label is how a script row
	 * is spelled; the fixture writes one so this is not testing the packaging.
	 */
	/* The daemon's config dir, because the list now comes from netcfgd rather
	 * than from this machine's disk -- which is the whole point of asking it. */
	const QString script = QString::fromUtf8(qgetenv("NCFG_CONFIG_DIR")) +
	    QStringLiteral("/probe/example");
	int at = detection->findData(script);
	check("a link-detection script the daemon knows about is offered", at >= 0,
	    QStringLiteral("looked for %1").arg(script));
	check("and running a command is still offered as the escape hatch",
	    detection->findData(QStringLiteral("command")) >= 0);
	if (at < 0) {
		return 1;
	}

	addressing->setCurrentIndex(addressing->findData(QStringLiteral("dhcp")));
	preference->setValue(50);
	/* **The MTU, because it is the field that moved.** 0155 pass 1a put it on
	 * the device, and this dialog went on writing it inside `interface` -- a
	 * block the compiler refuses. Nothing caught that: this test set every
	 * other field and not this one, so the check below on whether netcfgd
	 * compiled the result had nothing to compile wrongly. */
	mtu->setValue(1492);
	detection->setCurrentIndex(at);
	save->click();

	/* The file, because the probe's argv is the part that has to be exactly
	 * right and the document does not show it back as text. */
	QFile written(conf + QStringLiteral("interface-gui-probe0.conf"));
	check("the drop-in is there", written.exists(), written.fileName());
	if (written.open(QIODevice::ReadOnly)) {
		const QString text = QString::fromUtf8(written.readAll());
		check("the mtu was written as a device block, not an interface key",
		    text.contains(QStringLiteral("device gui-probe0 {")) &&
		        text.contains(QStringLiteral("mtu = 1492")),
		    text);
		check("the preference was written", text.contains(QStringLiteral("preference = 50")),
		    text);
		check("and a probe block", text.contains(QStringLiteral("probe {")), text);
		/* The interface is the script's argument, and it is not optional:
		 * netcfgd runs the command as given and binds nothing, so a script
		 * without it answers about whichever interface the route table
		 * picked. */
		check("whose argv names this interface",
		    text.contains(QStringLiteral("args = [\"gui-probe0\"]")), text);
		check("and the script it was given",
		    text.contains(script), text);
		/* Defaults are not restated: interval and timeout were left alone. */
		check("and does not restate the defaults it was not given",
		    !text.contains(QStringLiteral("interval")) &&
		        !text.contains(QStringLiteral("timeout")),
		    text);
		written.close();
	}

	/* And netcfgd compiled it, which is what proves the block is not merely
	 * well-shaped text. A plan is the cheapest thing that fails when the
	 * document does not compile. */
	ncfg_plan_data plan;
	check("netcfgd compiled the interface block", connection.plan(&plan, &error), error);

	/* Removed, because the daemon and this directory outlive this probe and
	 * the next one should not inherit a configuration it did not write. */
	written.remove();

	/*
	 * **Every field is actually in the layout.**
	 *
	 * `findChild` finds a widget whether or not anything laid it out, so every
	 * check above passes on a dialog that shows the operator nothing. That is
	 * not hypothetical: an edit that removed a dead field took the link
	 * detection row's `addRow` with it, and the combo box sat orphaned through
	 * a green test run. A widget with no parent layout is one nobody can use.
	 */
	{
		QFormLayout *form = dialog.findChild<QFormLayout *>();
		check("the dialog has a form", form != nullptr);
		if (form) {
			const QWidget *fields[] = { addressing, preference, detection };
			const char *names[] = { "addressing", "preference", "link detection" };
			for (int i = 0; i < 3; i++) {
				int row = -1;
				QFormLayout::ItemRole role{};
				/* A widget inside a row's layout rather than the row
				 * itself still counts: the detection row holds the
				 * combo beside its buttons. */
				form->getWidgetPosition(const_cast<QWidget *>(fields[i]), &row, &role);
				bool placed = row >= 0;
				if (!placed) {
					for (int r = 0; r < form->rowCount() && !placed; r++) {
						QLayoutItem *item = form->itemAt(r, QFormLayout::FieldRole);
						placed = item && item->layout() &&
						     item->layout()->indexOf(
						         const_cast<QWidget *>(fields[i])) >= 0;
					}
				}
				check(names[i], placed, QStringLiteral("is not in the layout"));
			}
		}
	}

	/*
	 * The editor: a probe is a shell script, and this is the thing that makes
	 * it editable without leaving the program.
	 */
	{
		/* The editor is handed the script, not a path: a client does not open
		 * the machine's files. Fetched the way the dialog fetches it. */
		QList<ncfg_probe_row> found;
		check("the daemon lists its own scripts", connection.probes(&found, &error), error);
		ncfg_probe_row opening;
		for (const ncfg_probe_row &one : found) {
			if (one.name == QStringLiteral("example")) {
				opening = one;
			}
		}
		check("including the one the fixture wrote", !opening.name.isEmpty());
		check("and says it is the operator's rather than a shipped example",
		    opening.editable);
		ncfg_probe_dialog editor(&connection, opening);
		auto *name = editor.findChild<QLineEdit *>(QStringLiteral("probe_name"));
		auto *body = editor.findChild<QPlainTextEdit *>(QStringLiteral("probe_body"));
		auto *save = editor.findChild<QPushButton *>(QStringLiteral("probe_save"));
		if (!name || !body || !save) {
			check("the probe editor has a name, a body and a save", false);
			return 1;
		}
		check("the probe editor has a name, a body and a save", true);
		/* It opened the file rather than a blank page: an editor that showed
		 * nothing would look identical to one whose read failed. */
		check("and the editor shows what the daemon sent",
		    body->toPlainText().contains(QStringLiteral("exit 0")),
		    body->toPlainText());
		check("and named it", name->text() == QStringLiteral("example"), name->text());

		/* Writing needs root, and the daemon refuses it otherwise. Under the
		 * live suite this runs as root in a namespace, so it should be
		 * stored -- and the refusal path is what a desktop user meets. */
		body->setPlainText(QStringLiteral("#!/bin/sh\n# edited by the test\nexit 0\n"));
		name->setText(QStringLiteral("edited-by-test"));
		save->click();
		check("saving a script reports where it went",
		    editor.outcome().contains(QStringLiteral("edited-by-test")),
		    editor.outcome());
	}

	printf("\n");
	if (failures) {
		printf("live_interface_dialog: %d failed\n", failures);
		return 1;
	}
	printf("live_interface_dialog: all checks passed\n");
	return 0;
}
