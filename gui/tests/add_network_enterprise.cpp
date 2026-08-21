/*
 * add_network_enterprise.cpp -- the add dialog asks for the credential the
 * network actually uses.
 *
 * A corporate network needs an identity and a password; a home one needs a
 * passphrase. Asking for the wrong one is not a cosmetic fault: the operator
 * has no passphrase to type, so the dialog gives them nothing to do and no
 * reason why. Until this arm existed the answer to "can I add a corporate
 * network from the GUI" was no, and the dialog did not say so.
 *
 * The properties worth pinning are the ones a later edit could quietly break,
 * and each has a way of failing that still looks like a working dialog:
 *
 *   - An enterprise network offers no `proto`. It pins the generation
 *     protecting a passphrase, an enterprise network negotiates its own, and
 *     the daemon refuses the pair -- so a control here would collect an answer
 *     that guarantees a refusal.
 *   - TLS asks for a certificate and the rest ask for a password. The
 *     supplicant refuses the network outright if given the other, so this is
 *     correctness rather than presentation.
 *   - The field that is hidden is also cleared. A hidden field holding text is
 *     a value the operator cannot see and submit() would send.
 *   - `Add` stays disabled until the daemon would accept the request, which is
 *     the same courtesy the wifi tab's greyed join button pays.
 *
 * No daemon and no radio: the dialog is constructed against a connection that
 * never connects, because nothing here presses Add.
 */

#include "../src/add_network_dialog.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>

#include <cstdio>

static int failures;

static void check(bool condition, const char *what)
{
	fprintf(stderr, "add_network_enterprise: %-56s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* By object name rather than by walking the layout or matching on wording.
 * The layout is what the dialog is free to rearrange, and the first version of
 * this probe matched placeholder text -- where the server certificate's differs
 * from the client certificate's only by an "optional" prefix, so `contains`
 * found the wrong field and the failure looked like a bug in the dialog. */
static QLineEdit *edit(QWidget *of, const char *name)
{
	return of->findChild<QLineEdit *>(QString::fromUtf8(name));
}

static QPushButton *add_button_of(QWidget *of)
{
	const QList<QPushButton *> buttons = of->findChildren<QPushButton *>();
	for (QPushButton *candidate : buttons) {
		if (candidate->text() == QStringLiteral("Add")) {
			return candidate;
		}
	}
	return nullptr;
}

int main(int argc, char **argv)
{
	QApplication app(argc, argv);
	ncfg_connection connection;

	/* An ordinary secured network first, as the control: without it a probe
	 * that found no EAP widgets anywhere would pass the enterprise case for
	 * the wrong reason. */
	{
		ncfg_add_network_dialog dialog(&connection, QStringLiteral("686f6d65"),
		                   QStringLiteral("home"), true, false);
		check(dialog.findChildren<QComboBox *>().size() == 1,
		      "a personal network offers the generation and nothing else");
		check(edit(&dialog, "eap_identity") == nullptr,
		      "and asks for no identity");
	}

	ncfg_add_network_dialog dialog(&connection, QStringLiteral("656475726f616d"),
	                   QStringLiteral("eduroam"), true, true);

	QLineEdit *identity = edit(&dialog, "eap_identity");
	QLineEdit *client_cert = edit(&dialog, "eap_client_cert");
	QLineEdit *ca_cert = edit(&dialog, "eap_ca_cert");
	QPushButton *add = add_button_of(&dialog);
	check(identity != nullptr, "an enterprise network asks for an identity");
	check(add != nullptr, "the dialog has an Add button");
	if (!identity || !client_cert || !add) {
		return 1;
	}

	QLineEdit *password = edit(&dialog, "eap_password");
	check(password != nullptr, "and for a password");
	if (!password) {
		return 1;
	}
	check(password->echoMode() == QLineEdit::Password, "which is never echoed");
	check(ca_cert != nullptr && ca_cert != client_cert,
	      "the two certificate fields are two fields");

	QComboBox *method = nullptr;
	const QList<QComboBox *> combos = dialog.findChildren<QComboBox *>();
	for (QComboBox *candidate : combos) {
		if (candidate->findData(QStringLiteral("peap")) >= 0) {
			method = candidate;
		}
	}
	check(method != nullptr, "and offers the EAP methods");
	if (!method) {
		return 1;
	}
	check(combos.size() == 1,
	      "and offers no generation, which the daemon would refuse beside eap");

	check(!add->isEnabled(), "Add is refused with nothing filled in");
	identity->setText(QStringLiteral("you@corp.example"));
	check(!add->isEnabled(), "and with an identity but no credential");
	password->setText(QStringLiteral("hunter2"));
	check(add->isEnabled(), "and allowed once both are there");

	/* The method decides which credential is asked for, and the switch has to
	 * take the other one away rather than leave it filled in and hidden. */
	method->setCurrentIndex(method->findData(QStringLiteral("tls")));
	check(password->text().isEmpty(), "switching to TLS clears the password");
	check(!add->isEnabled(), "and Add waits for the certificate instead");
	client_cert->setText(QStringLiteral("corp-crt"));
	check(add->isEnabled(), "which a stored certificate's name satisfies");

	method->setCurrentIndex(method->findData(QStringLiteral("peap")));
	check(client_cert->text().isEmpty(), "switching back clears the certificate");
	check(!add->isEnabled(), "and Add waits for the password again");

	if (failures) {
		fprintf(stderr, "add_network_enterprise: %d failed\n", failures);
		return 1;
	}
	fprintf(stderr, "add_network_enterprise: all checks passed\n");
	return 0;
}
