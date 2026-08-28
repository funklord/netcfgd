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
#include "../../src/ncfg_connection.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QFile>
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
	auto *detection = dialog.findChild<QComboBox *>(QStringLiteral("iface_detection"));
	auto *host = dialog.findChild<QLineEdit *>(QStringLiteral("iface_probe_host"));
	auto *save = dialog.findChild<QPushButton *>(QStringLiteral("iface_save"));
	if (!addressing || !preference || !detection || !host || !save) {
		check("the dialog has the fields it needs", false);
		return 1;
	}
	check("the dialog has the fields it needs", true);

	/* Carrier-only is offered and is named rather than being the absence of a
	 * setting: it is the answer that was wrong often enough to need replacing,
	 * and an operator choosing it should be choosing it. */
	check("carrier-only link detection is offered by name",
	    detection->findData(QString()) >= 0);
	check("and so is a probe", detection->findData(QStringLiteral("ping")) >= 0);

	addressing->setCurrentIndex(addressing->findData(QStringLiteral("dhcp")));
	preference->setValue(50);
	detection->setCurrentIndex(detection->findData(QStringLiteral("ping")));
	host->setText(QStringLiteral("192.0.2.1"));
	save->click();

	/* The file, because the probe's argv is the part that has to be exactly
	 * right and the document does not show it back as text. */
	QFile written(conf + QStringLiteral("interface-gui-probe0.conf"));
	check("the drop-in is there", written.exists(), written.fileName());
	if (written.open(QIODevice::ReadOnly)) {
		const QString text = QString::fromUtf8(written.readAll());
		check("the preference was written", text.contains(QStringLiteral("preference = 50")),
		    text);
		check("and a probe block", text.contains(QStringLiteral("probe {")), text);
		/* The interface is named in the argv. Without it the probe answers
		 * about whichever interface the route table picked. */
		check("whose argv binds this interface",
		    text.contains(QStringLiteral("\"-I\", \"gui-probe0\"")), text);
		check("and names the host it was given",
		    text.contains(QStringLiteral("192.0.2.1")), text);
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

	printf("\n");
	if (failures) {
		printf("live_interface_dialog: %d failed\n", failures);
		return 1;
	}
	printf("live_interface_dialog: all checks passed\n");
	return 0;
}
