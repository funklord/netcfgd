/*
 * add_network_hidden.cpp -- adding a network that does not broadcast its
 * name.
 *
 * Every other add starts from a scan row, which carries the SSID as the exact
 * octets the radio heard. A hidden network is never heard by name, so this is
 * the one place a typed name becomes an SSID, and the properties worth pinning
 * are the ones that turn into a block that never joins:
 *
 *   - The SSID is the name's UTF-8, as lowercase hex, and the 32-octet limit
 *     is counted in octets: a name in another script reaches it well before 32
 *     characters.
 *   - The security asked for decides which credential the add dialog then
 *     asks for, since no beacon can say.
 *   - The add dialog's "does not broadcast" box is ticked and cannot be
 *     unticked: a block for a hidden network without `hidden` is one the
 *     supplicant never probes for.
 *
 * No daemon: nothing here presses Add.
 */

#include "../src/add_network_dialog.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDialog>
#include <QLineEdit>
#include <QPushButton>
#include <QTimer>

#include <cstdio>

static int failures;

static void check(bool condition, const char *what)
{
	fprintf(stderr, "add_network_hidden: %-58s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static QPushButton *button_of(QWidget *of, const QString &text)
{
	const QList<QPushButton *> buttons = of->findChildren<QPushButton *>();
	for (QPushButton *candidate : buttons) {
		if (candidate->text() == text) {
			return candidate;
		}
	}
	return nullptr;
}

/* Fill in the prompt once it is showing, and press Next -- the prompt is
 * modal, so this runs from the event loop its exec() starts. `next_enabled`
 * records whether Next could be pressed for the name given. */
static void answer_prompt(const QString &name, int kind, bool *next_enabled)
{
	QTimer::singleShot(0, [name, kind, next_enabled]() {
		QWidget *prompt = QApplication::activeModalWidget();
		if (!prompt) {
			return;
		}
		prompt->findChild<QLineEdit *>(QStringLiteral("hidden_name"))->setText(name);
		prompt->findChild<QComboBox *>(QStringLiteral("hidden_kind"))->setCurrentIndex(kind);
		QPushButton *next = button_of(prompt, QStringLiteral("Next"));
		*next_enabled = next && next->isEnabled();
		if (*next_enabled) {
			next->click();
		} else {
			static_cast<QDialog *>(prompt)->reject();
		}
	});
}

int main(int argc, char **argv)
{
	QApplication app(argc, argv);
	ncfg_connection connection;

	check(ncfg_ssid_hex_for(QStringLiteral("Home")) == QStringLiteral("486f6d65"),
	    "a name is its octets as lowercase hex");
	check(ncfg_ssid_hex_for(QString::fromUtf8("caf\xc3\xa9")) == QStringLiteral("636166c3a9"),
	    "as UTF-8, not Latin-1");
	check(ncfg_ssid_hex_for(QString(32, QLatin1Char('a'))).size() == 64,
	    "32 octets is a name");
	check(ncfg_ssid_hex_for(QString(33, QLatin1Char('a'))).isEmpty(), "33 is not");
	/* Eleven three-octet characters: 33 octets in 11 characters. */
	check(ncfg_ssid_hex_for(QString(11, QChar(0x20ac))).isEmpty(),
	    "the limit is octets, not characters");
	check(ncfg_ssid_hex_for(QString()).isEmpty(), "and no name is not a name");

	QString ssid_hex;
	QString shown;
	bool secured = false;
	bool enterprise = false;
	bool next_enabled = false;

	answer_prompt(QStringLiteral("Attic"), 0, &next_enabled);
	bool asked = ncfg_ask_hidden_network(nullptr, &ssid_hex, &shown, &secured, &enterprise);
	check(asked && next_enabled, "a name and a passphrase can go on");
	check(ssid_hex == QStringLiteral("4174746963") && shown == QStringLiteral("Attic"),
	    "carrying the SSID and the name shown");
	check(secured && !enterprise, "as a passphrase network");

	answer_prompt(QStringLiteral("Corp"), 1, &next_enabled);
	asked = ncfg_ask_hidden_network(nullptr, &ssid_hex, &shown, &secured, &enterprise);
	check(asked && secured && enterprise, "a login is an 802.1X network");

	answer_prompt(QStringLiteral("Guest"), 2, &next_enabled);
	asked = ncfg_ask_hidden_network(nullptr, &ssid_hex, &shown, &secured, &enterprise);
	check(asked && !secured && !enterprise, "and open is neither");

	answer_prompt(QString(33, QLatin1Char('x')), 0, &next_enabled);
	asked = ncfg_ask_hidden_network(nullptr, &ssid_hex, &shown, &secured, &enterprise);
	check(!asked && !next_enabled, "a name too long cannot go on");

	{
		ncfg_add_network_dialog dialog(&connection, QStringLiteral("4174746963"),
		                               QStringLiteral("Attic"), true, false);
		QCheckBox *box = dialog.findChild<QCheckBox *>(QStringLiteral("hidden"));
		check(box && !box->isChecked() && box->isEnabled(),
		    "a network from a scan leaves the box to the operator");
		dialog.set_hidden();
		check(box && box->isChecked() && !box->isEnabled(),
		    "a typed one has it ticked, and locked");
	}

	return failures ? 1 : 0;
}
