/*
 * live_access_point.cpp -- a network this machine offers, against a daemon.
 *
 * WHY THIS EXISTS
 *   `access_point_block` checks the text. What it cannot check is whether
 *   netcfgd made anything of it -- the `wifi` block inside an access point is
 *   parsed by the same reader a station profile's is, and a key that means
 *   something there and nothing here would compile into a different network.
 *
 *   So this asserts the compiled document afterwards, read back through the
 *   daemon's own answer, and the refusals that belong to this form rather than
 *   to the daemon.
 */

#include "../../src/access_point_dialog.h"
#include "../../src/ncfg_connection.h"

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

static bool offered(ncfg_connection *connection, const QString &id, ncfg_access_point_config *out)
{
	QList<ncfg_access_point_config> points;
	QString error;
	if (!connection->access_points(&points, &error)) {
		return false;
	}
	for (const ncfg_access_point_config &point : points) {
		if (point.id == id) {
			*out = point;
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

	const QString name = QStringLiteral("gui-ap");

	{
		ncfg_access_point_dialog dialog(&connection, ncfg_access_point_config());
		auto *id = dialog.findChild<QLineEdit *>(QStringLiteral("ap_id"));
		auto *device = dialog.findChild<QComboBox *>(QStringLiteral("ap_device"));
		auto *security = dialog.findChild<QComboBox *>(QStringLiteral("ap_security"));
		auto *credential = dialog.findChild<QLineEdit *>(QStringLiteral("ap_credential"));
		auto *channel = dialog.findChild<QSpinBox *>(QStringLiteral("ap_channel"));
		auto *acl = dialog.findChild<QComboBox *>(QStringLiteral("ap_acl_policy"));
		auto *stations = dialog.findChild<QLineEdit *>(QStringLiteral("ap_stations"));
		auto *note = dialog.findChild<QLabel *>(QStringLiteral("ap_note"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("ap_save"));
		if (!id || !device || !security || !credential || !channel || !acl || !stations
		    || !save) {
			check("the dialog has the fields it needs", false);
			return 1;
		}
		check("the dialog has the fields it needs", true);
		/* The harness gives this daemon one dummy radio, and the device list
		 * is built from the links netcfgd reports as wireless. */
		check("and offers the machine's radio", device->count() > 0,
		    QString::number(device->count()));

		id->setText(name);
		device->setCurrentText(QStringLiteral("radio0"));
		security->setCurrentIndex(security->findData(QStringLiteral("psk")));

		/* A passphrase typed where a reference belongs: refused here, beside
		 * the field, because the document type cannot hold one. */
		credential->setText(QStringLiteral("hunter2hunter2"));
		save->click();
		check("a passphrase typed instead of a reference is refused here",
		    note && note->text().startsWith(
		                QStringLiteral("the passphrase is a reference, not the passphrase")),
		    note ? note->text() : QString());

		credential->setText(QStringLiteral("@secret:gui-ap"));
		/* An empty station list with a policy says something, and what it says
		 * is "admit nobody" -- refused rather than written. */
		acl->setCurrentIndex(acl->findData(QStringLiteral("allow")));
		save->click();
		check("a station list that is empty is refused",
		    note && note->text().startsWith(QStringLiteral("a station list that is empty")),
		    note ? note->text() : QString());

		stations->setText(QStringLiteral("00:11:22:33:44:55"));
		channel->setValue(6);
		save->click();
		check("and a whole access point is written", dialog.outcome().contains(name),
		    QStringLiteral("%1 / %2").arg(dialog.outcome(),
		        note ? note->text() : QString()));
		/* **The sentence the example file spends a paragraph on.** hostapd
		 * beacons and stations associate; a station still needs an address,
		 * and netcfgd serves no DHCP. */
		check("and the outcome says the radio still needs an address",
		    dialog.outcome().contains(QStringLiteral("address")), dialog.outcome());
	}

	{
		ncfg_access_point_config written;
		check("netcfgd compiled the access point", offered(&connection, name, &written));
		check("on the radio it was given", written.device == QStringLiteral("radio0"),
		    written.device);
		check("with the security kind", written.security == QStringLiteral("psk"),
		    written.security);
		/* The reference, and only the reference: the document cannot hold the
		 * passphrase itself, so what comes back is the secret's name. */
		check("and the credential as a name rather than a passphrase",
		    written.credential == QStringLiteral("gui-ap"), written.credential);
		check("and the channel", written.channel == 6, QString::number(written.channel));
		check("and the station list", written.acl_policy == QStringLiteral("allow")
		        && written.stations == QStringLiteral("00:11:22:33:44:55"),
		    QStringLiteral("%1 %2").arg(written.acl_policy, written.stations));
		/* Nothing is running it: the harness starts no hostapd, and an access
		 * point that is configured and not on the air is the state an operator
		 * most needs to see. */
		check("and says it is not on the air", !written.running);
	}

	/* Re-opening loads what was written, which is the fault every editor here
	 * has had to be rescued from: a form that saves and does not load replaces
	 * the block with its own defaults. */
	{
		ncfg_access_point_config existing;
		if (!offered(&connection, name, &existing)) {
			check("the access point is there to edit", false);
			return 1;
		}
		ncfg_access_point_dialog dialog(&connection, existing);
		auto *id = dialog.findChild<QLineEdit *>(QStringLiteral("ap_id"));
		auto *channel = dialog.findChild<QSpinBox *>(QStringLiteral("ap_channel"));
		auto *credential = dialog.findChild<QLineEdit *>(QStringLiteral("ap_credential"));
		check("the name of an existing access point cannot be edited", id->isReadOnly());
		check("and the channel is loaded", channel->value() == 6,
		    QString::number(channel->value()));
		/* Spelled back as a reference rather than as the bare name the
		 * document holds, because that is what the field takes. */
		check("and the credential comes back as the reference it is",
		    credential->text() == QStringLiteral("@secret:gui-ap"), credential->text());
	}

	{
		QString removed;
		check("the access point can be removed again",
		    connection.config_delete(QStringLiteral("access-point-%1").arg(name), &removed),
		    removed);
		ncfg_access_point_config gone;
		check("and netcfgd stops reporting it", !offered(&connection, name, &gone));
	}

	if (failures == 0) {
		printf("live_access_point: all checks passed\n");
	} else {
		printf("live_access_point: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
