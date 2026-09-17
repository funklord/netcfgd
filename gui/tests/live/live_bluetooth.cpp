/*
 * live_bluetooth.cpp -- a bluetooth device written through the dialog.
 *
 * WHY THIS EXISTS
 *   `bluetooth_block` checks the text. What it cannot check is whether netcfgd
 *   made the device the form meant -- and the profile is the field where that
 *   has gone wrong before: the model's spelling and the language's have to be
 *   the same string, and twice in this campaign they were not, which compiled
 *   into a block with the feature missing rather than into an error.
 *
 *   It also pins the sentence the operator is left with. This build does not
 *   act on a `bluetooth` block at all, and an editor that wrote one without
 *   saying so would be the window claiming something the daemon does not do.
 */

#include "../../src/bluetooth_dialog.h"
#include "../../src/ncfg_connection.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
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

static bool declared(ncfg_connection *connection, const QString &id, ncfg_bluetooth_row *out)
{
	QList<ncfg_bluetooth_row> devices;
	QString error;
	if (!connection->bluetooth(&devices, &error)) {
		return false;
	}
	for (const ncfg_bluetooth_row &device : devices) {
		if (device.id == id) {
			*out = device;
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

	const QString name = QStringLiteral("gui-headphones");

	{
		ncfg_bluetooth_dialog dialog(&connection, ncfg_bluetooth_row());
		auto *id = dialog.findChild<QLineEdit *>(QStringLiteral("bt_id"));
		auto *address = dialog.findChild<QLineEdit *>(QStringLiteral("bt_address"));
		auto *profile = dialog.findChild<QComboBox *>(QStringLiteral("bt_profile"));
		auto *autoconnect = dialog.findChild<QCheckBox *>(QStringLiteral("bt_autoconnect"));
		auto *consequence = dialog.findChild<QLabel *>(QStringLiteral("bt_consequence"));
		auto *note = dialog.findChild<QLabel *>(QStringLiteral("bt_note"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("bt_save"));
		if (!id || !address || !profile || !autoconnect || !consequence || !note || !save) {
			check("the dialog has the fields it needs", false);
			return 1;
		}
		check("the dialog has the fields it needs", true);
		check("a device is connected on its own unless somebody says otherwise",
		    autoconnect->isChecked());
		/* Five, and no more: the language names exactly these and refuses
		 * anything else, so an editor offering a sixth would be offering a
		 * round trip to find that out. */
		check("every profile the language takes is offered", profile->count() == 5,
		    QString::number(profile->count()));

		save->click();
		check("a device with no name is refused by the dialog",
		    note->text().startsWith(QStringLiteral("a device needs a name")), note->text());

		id->setText(name);
		address->setText(QStringLiteral("not an address"));
		save->click();
		check("and so is something that is not a Bluetooth address",
		    note->text().startsWith(QStringLiteral("that is not a Bluetooth address")),
		    note->text());

		/* An audio profile says what netcfgd will not be doing about the
		 * sound, because nothing else in the program will. */
		check("an audio profile says the sound is somebody else's",
		    consequence->text().contains(QStringLiteral("bluealsa")), consequence->text());
		profile->setCurrentIndex(profile->findData(QStringLiteral("pan")));
		check("and a network profile says the link still needs configuring",
		    consequence->text().contains(QStringLiteral("interface")), consequence->text());

		profile->setCurrentIndex(profile->findData(QStringLiteral("a2dp-sink")));
		/* Typed the way a label prints it, which the language does not take.
		 * The dialog converts rather than refusing -- and what lands in the
		 * document is the form the compiler asked for. */
		address->setText(QStringLiteral("aa-bb-cc-dd-ee-ff"));
		save->click();
		check("and a whole device is written", dialog.outcome().contains(name),
		    QStringLiteral("%1 / %2").arg(dialog.outcome(), note->text()));
		/* **The half the daemon cannot say for itself here.** `ncfg plan`
		 * warns per device; somebody who never runs it would otherwise be left
		 * expecting sound. */
		check("and the outcome says this build does not act on the block",
		    dialog.outcome().contains(QStringLiteral("does not act on it")),
		    dialog.outcome());
	}

	{
		ncfg_bluetooth_row written;
		check("netcfgd compiled the device", declared(&connection, name, &written));
		check("with the address in the form the language uses",
		    written.address == QStringLiteral("AA:BB:CC:DD:EE:FF"), written.address);
		/* The spelling trap, asserted rather than assumed: the document's word
		 * for the profile and the language's have to be the same string. */
		check("and the profile as the language spells it",
		    written.profile == QStringLiteral("a2dp-sink"), written.profile);
		check("and connects on its own", written.autoconnect);
	}

	/* Re-opening loads what was written, which is the fault every editor here
	 * has had to be rescued from: a form that saves and does not load replaces
	 * the block with its own defaults. */
	{
		ncfg_bluetooth_row existing;
		if (!declared(&connection, name, &existing)) {
			check("the device is there to edit", false);
			return 1;
		}
		ncfg_bluetooth_dialog dialog(&connection, existing);
		auto *id = dialog.findChild<QLineEdit *>(QStringLiteral("bt_id"));
		auto *address = dialog.findChild<QLineEdit *>(QStringLiteral("bt_address"));
		auto *profile = dialog.findChild<QComboBox *>(QStringLiteral("bt_profile"));
		auto *autoconnect = dialog.findChild<QCheckBox *>(QStringLiteral("bt_autoconnect"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("bt_save"));
		check("the name of an existing device cannot be edited", id->isReadOnly());
		check("and the address is loaded",
		    address->text() == QStringLiteral("AA:BB:CC:DD:EE:FF"), address->text());
		check("and the profile", profile->currentData().toString()
		        == QStringLiteral("a2dp-sink"),
		    profile->currentData().toString());

		autoconnect->setChecked(false);
		save->click();
		ncfg_bluetooth_row changed;
		check("and turning autoconnect off reaches the document",
		    declared(&connection, name, &changed) && !changed.autoconnect);
		check("without disturbing the address", changed.address
		        == QStringLiteral("AA:BB:CC:DD:EE:FF"),
		    changed.address);

		/* **And it comes back off**, which is the half the check above cannot
		 * make: every other assertion here sets the field before saving, so a
		 * dialog that loaded nothing and started at its defaults would pass
		 * them all. The only value that proves a load is one that differs from
		 * the default -- and `autoconnect` is true by default, so this is the
		 * one field in the block where that is possible. */
		ncfg_bluetooth_dialog again(&connection, changed);
		auto *loaded = again.findChild<QCheckBox *>(QStringLiteral("bt_autoconnect"));
		check("and re-opening shows it off rather than at the default",
		    loaded && !loaded->isChecked());
	}

	{
		QString removed;
		check("the device can be removed again",
		    connection.config_delete(QStringLiteral("bluetooth-%1").arg(name), &removed),
		    removed);
		ncfg_bluetooth_row gone;
		check("and netcfgd stops reporting it", !declared(&connection, name, &gone));
	}

	if (failures == 0) {
		printf("live_bluetooth: all checks passed\n");
	} else {
		printf("live_bluetooth: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
