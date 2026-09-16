/*
 * live_device_dialog.cpp -- configuring hardware, against a daemon.
 *
 * WHY THIS EXISTS
 *   `device_block` checks the text. What it cannot check is whether netcfgd
 *   made anything of it: a block can be well formed, name a key the compiler
 *   spells differently, and be refused -- with the dialog reporting success in
 *   a screenshot nobody was reading.
 *
 *   So this asserts the compiled document afterwards, read back through the
 *   daemon's own answer about the device. That goes through the compiler, so a
 *   block this editor wrote and netcfgd could not parse fails here.
 *
 * THE OTHER HALF, WHICH IS WHY THE DEVICE TAB EXISTS AT ALL
 *   The MTU used to be written by the *interface* editor, as a `device` block
 *   inside `interface-<name>.conf`. Two screens writing one block into two
 *   drop-ins is a duplicate the loader refuses, so the move is not a tidy-up:
 *   this probe writes `device-<name>` and the interface probe asserts its own
 *   drop-in no longer carries one.
 */

#include "../../src/device_dialog.h"
#include "../../src/ncfg_connection.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
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

	ncfg_connection connection;
	QString error;
	if (!connection.open(QString(), &error)) {
		printf("FAIL the dialog's connection reaches netcfgd\n       %s\n",
		    error.toUtf8().constData());
		return 1;
	}
	check("the dialog's connection reaches netcfgd", true);

	/* A name of this probe's own, for the reason `live_interface_dialog`
	 * records: these probes share one daemon and one configuration, and a
	 * device block left on the radio would change what every probe after this
	 * one sees. */
	const QString name = QStringLiteral("gui-dev0");

	{
		ncfg_device_dialog dialog(&connection, name);
		auto *managed = dialog.findChild<QCheckBox *>(QStringLiteral("device_managed"));
		auto *mtu = dialog.findChild<QSpinBox *>(QStringLiteral("device_mtu"));
		auto *mac = dialog.findChild<QLineEdit *>(QStringLiteral("device_mac"));
		auto *autoneg = dialog.findChild<QComboBox *>(QStringLiteral("device_autoneg"));
		auto *gro = dialog.findChild<QComboBox *>(QStringLiteral("device_gro"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("device_save"));
		if (!managed || !mtu || !mac || !autoneg || !gro || !save) {
			check("the dialog has the fields it needs", false);
			return 1;
		}
		check("the dialog has the fields it needs", true);
		/* A device the document has never mentioned opens on defaults rather
		 * than on nothing: managing is what netcfgd does unless told not to. */
		check("a device with no block opens as managed", managed->isChecked());

		mtu->setValue(9000);
		mac->setText(QStringLiteral("02:00:00:00:00:01"));
		autoneg->setCurrentIndex(autoneg->findData(QStringLiteral("on")));
		gro->setCurrentIndex(gro->findData(QStringLiteral("off")));
		save->click();
		check("saving says where it went", dialog.outcome().contains(name),
		    dialog.outcome());
	}

	/* netcfgd compiled it -- which is the whole point of asking the daemon
	 * rather than reading back the file this program just wrote. */
	{
		ncfg_device_config written;
		check("netcfgd compiled the device block",
		    connection.device_config(name, &written, &error), error);
		check("and reports the block as present", written.present);
		check("with the mtu it was given", written.mtu == 9000,
		    QString::number(written.mtu));
		check("and the mac", written.mac == QStringLiteral("02:00:00:00:00:01"),
		    written.mac);
		/* Three-valued, and the two that are not "leave alone" both survive:
		 * a toggle that came back `unmanaged` would mean the block said
		 * nothing about it. */
		check("and autonegotiation on", written.autoneg == 1,
		    QString::number(written.autoneg));
		check("and an offload turned off, which is not the same as left alone",
		    written.gro == 2, QString::number(written.gro));
		check("while a toggle nobody touched stays left alone", written.gso == 0,
		    QString::number(written.gso));
	}

	/* Re-opening loads what was written. A dialog that saves and does not load
	 * is the fault `interface_load` exists for: every field back at its
	 * default, and save replaces the block with that. */
	{
		ncfg_device_dialog dialog(&connection, name);
		auto *mtu = dialog.findChild<QSpinBox *>(QStringLiteral("device_mtu"));
		auto *gro = dialog.findChild<QComboBox *>(QStringLiteral("device_gro"));
		check("re-opening loads the mtu", mtu && mtu->value() == 9000,
		    QString::number(mtu ? mtu->value() : -1));
		check("and the offload it turned off",
		    gro && gro->currentData().toString() == QStringLiteral("off"),
		    gro ? gro->currentData().toString() : QString());
	}

	/* The device list, which is the tab's own question: the union of what the
	 * kernel has and what the document describes. */
	{
		QList<ncfg_device_row> rows;
		check("the daemon lists devices", connection.devices(&rows, &error), error);
		bool described = false;
		bool hardware = false;
		for (const ncfg_device_row &row : rows) {
			if (row.name == name) {
				described = row.configured && !row.present;
			}
			if (row.name == QStringLiteral("radio0")) {
				hardware = row.present;
			}
		}
		check("including one the document describes and the kernel does not have",
		    described);
		check("and one the kernel has", hardware);
	}

	{
		QString removed;
		check("the block can be removed again",
		    connection.config_delete(QStringLiteral("device-%1").arg(name), &removed),
		    removed);
	}

	if (failures == 0) {
		printf("live_device_dialog: all checks passed\n");
	} else {
		printf("live_device_dialog: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
