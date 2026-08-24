/*
 * live_add_dialog.cpp -- the add-network dialog against a real daemon.
 *
 * WHY THIS EXISTS
 *   `add_network_enterprise.cpp` checks the form: which fields appear, which
 *   button is enabled, what a method change does to the widgets. It stops
 *   where the socket begins. What it cannot answer is whether pressing `Add`
 *   produces a *network* -- whether the fields the operator filled in arrive
 *   as an `eap` block netcfgd writes, or arrive at all.
 *
 *   That join is where the enterprise faults were. `--ca-cert @secret:NAME`
 *   was refused by netcfgd's own round-trip check for a year of commits with
 *   nothing to notice, and the dialog builds the same request from a form.
 *
 * WHAT IT ASSERTS
 *   The file on disk afterwards, because that is the thing a network is. Not
 *   the request, not the widgets: `wifi_add` can be well formed and produce a
 *   `network` block that says something else, which is exactly what the
 *   round-trip check exists to catch and exactly what it got wrong.
 *
 *   The dialog is driven by clicking `Add`, which is what an operator does.
 *   `submit()` is a private slot and calling it directly would be testing a
 *   function rather than a button.
 */

#include "../../src/add_network_dialog.h"
#include "../../src/ncfg_connection.h"

#include <QApplication>
#include <QComboBox>
#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QLineEdit>
#include <QPushButton>
#include <QThread>

#include <cstdio>
#include <functional>

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

static QPushButton *button(QWidget *of, const char *label)
{
	for (QPushButton *candidate : of->findChildren<QPushButton *>()) {
		if (candidate->text() == QString::fromUtf8(label)) {
			return candidate;
		}
	}
	return nullptr;
}

/* The one field with no object name, because a placeholder or a name on a
 * secret is text about a secret sitting in the window. */
static QLineEdit *secret_field(QWidget *of)
{
	for (QLineEdit *candidate : of->findChildren<QLineEdit *>()) {
		if (candidate->echoMode() == QLineEdit::Password) {
			return candidate;
		}
	}
	return nullptr;
}

static QString slurp(const QString &path)
{
	QFile file(path);
	if (!file.open(QIODevice::ReadOnly)) {
		return QString();
	}
	return QString::fromUtf8(file.readAll());
}

/* Written by the daemon, so it appears a moment after `Add` returns. Bounded,
 * and the timeout is the assertion. */
static QString settles(const QString &path, int milliseconds = 8000)
{
	QElapsedTimer clock;
	clock.start();
	while (clock.elapsed() < milliseconds) {
		const QString text = slurp(path);
		if (!text.isEmpty()) {
			return text;
		}
		QCoreApplication::processEvents();
		QThread::msleep(50);
	}
	return slurp(path);
}

static QString hex_of(const char *text)
{
	QString out;
	for (const char *at = text; *at; at++) {
		out += QString::asprintf("%02x", static_cast<unsigned char>(*at));
	}
	return out;
}

int main(int argc, char **argv)
{
	QApplication app(argc, argv);
	const QString conf = QString::fromUtf8(qgetenv("NCFG_CONFIG_DIR")) + "/conf.d/";

	ncfg_connection connection;
	QString error;
	if (!connection.open(QString(), &error)) {
		printf("FAIL the dialog's connection reaches netcfgd\n       %s\n",
		    error.toUtf8().constData());
		return 1;
	}
	check("the dialog's connection reaches netcfgd", true);

	/* 1. A network with a passphrase, which is the ordinary case. */
	{
		ncfg_add_network_dialog dialog(&connection, hex_of("HomeFiber"),
		    QStringLiteral("HomeFiber"), true, false);
		QLineEdit *passphrase = secret_field(&dialog);
		QPushButton *add = button(&dialog, "Add");
		check("a secured network asks for a passphrase", passphrase != nullptr);
		check("and has an Add button", add != nullptr);
		if (!passphrase || !add) {
			return 1;
		}
		check("which is refused until there is one", !add->isEnabled());
		passphrase->setText(QStringLiteral("hunter2hunter2"));
		check("and offered once there is", add->isEnabled());

		add->click();
		const QString block = settles(conf + "wifi-HomeFiber.conf");
		check("pressing Add wrote the network", !block.isEmpty());
		check("with a reference rather than the passphrase",
		    block.contains(QStringLiteral("@secret:HomeFiber")) &&
		        !block.contains(QStringLiteral("hunter2hunter2")),
		    block);
	}

	/* 2. An enterprise network, which is the case the form exists for.
	 *
	 * The fields an operator fills in have to arrive as an `eap` block. Every
	 * layer between here and the file was correct on its own while
	 * `--ca-cert @secret:NAME` was rejected outright, so what is asserted is
	 * the file. */
	{
		ncfg_add_network_dialog dialog(&connection, hex_of("eduroam"),
		    QStringLiteral("eduroam"), true, true);
		QLineEdit *identity = dialog.findChild<QLineEdit *>(QStringLiteral("eap_identity"));
		QLineEdit *phase2 = dialog.findChild<QLineEdit *>(QStringLiteral("eap_phase2"));
		QLineEdit *password = dialog.findChild<QLineEdit *>(QStringLiteral("eap_password"));
		QComboBox *method = dialog.findChild<QComboBox *>(QStringLiteral("eap_method"));
		QPushButton *add = button(&dialog, "Add");
		check("an enterprise network asks for an identity, a method and a password",
		    identity && phase2 && password && method && add);
		if (!identity || !phase2 || !password || !method || !add) {
			return 1;
		}

		method->setCurrentIndex(method->findData(QStringLiteral("peap")));
		identity->setText(QStringLiteral("you@corp.example"));
		phase2->setText(QStringLiteral("mschapv2"));
		password->setText(QStringLiteral("corp-password"));
		QCoreApplication::processEvents();
		check("and offers Add once they are filled in", add->isEnabled());

		add->click();
		const QString block = settles(conf + "wifi-eduroam.conf");
		check("pressing Add wrote the network", !block.isEmpty());
		check("as an enterprise one", block.contains(QStringLiteral("eap = \"peap\"")), block);
		check("with the identity the form collected",
		    block.contains(QStringLiteral("you@corp.example")), block);
		check("and the inner method", block.contains(QStringLiteral("mschapv2")), block);
		check("and a reference rather than the password",
		    block.contains(QStringLiteral("password = \"@secret:eduroam\"")) &&
		        !block.contains(QStringLiteral("corp-password")),
		    block);
	}

	/* 3. The payload the `Choose...` button sends.
	 *
	 * The button opens a modal file chooser, which a probe cannot drive -- so
	 * what is checked is what it does *with* the file: the content crosses as
	 * a secret under a name, and the daemon stores it. A path never crosses,
	 * which is the property that makes it safe for a client to offer at all. */
	{
		const QString pem = QStringLiteral(
		    "-----BEGIN CERTIFICATE-----\nRmFrZUNlcnRGb3JBVGVzdA==\n"
		    "-----END CERTIFICATE-----\n");
		QString stored_error;
		const bool stored = connection.secret_put(QStringLiteral("corp-ca"), pem, false,
		    &stored_error);
		check("a certificate's content crosses as a secret", stored, stored_error);

		const QString secrets = QString::fromUtf8(qgetenv("NCFG_CONFIG_DIR")) + "/secrets/corp-ca";
		check("and the daemon wrote it", QFile::exists(secrets));
		check("holding what was sent", slurp(secrets).contains(QStringLiteral("BEGIN CERTIFICATE")));
		check("at 0600, because it is key material",
		    (QFile::permissions(secrets) &
		        (QFileDevice::ReadGroup | QFileDevice::ReadOther |
		            QFileDevice::WriteGroup | QFileDevice::WriteOther)) == 0);
	}

	printf("\n");
	if (failures) {
		printf("live_add_dialog: %d failed\n", failures);
		return 1;
	}
	printf("live_add_dialog: all checks passed\n");
	return 0;
}
