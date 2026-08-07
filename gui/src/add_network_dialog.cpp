/*
 * add_network_dialog.cpp -- the dialog described in add_network_dialog.h.
 */
#include "add_network_dialog.h"

#include "ncfg_connection.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

ncfg_add_network_dialog::ncfg_add_network_dialog(ncfg_connection *connection,
                         const QString &ssid_hex, const QString &shown,
                         bool secured, QWidget *parent)
    : QDialog(parent), connection(connection), ssid_hex(ssid_hex), secured(secured)
{
	setWindowTitle(QStringLiteral("Add a network"));

	auto *layout = new QVBoxLayout(this);
	auto *form = new QFormLayout();

	/* The SSID is shown and not editable. It came from the radio as exact
	 * octets; letting somebody retype it would turn a network whose name does
	 * not render into one they get wrong, which is the case the hex is for. */
	auto *ssid_label = new QLabel(shown, this);
	ssid_label->setTextInteractionFlags(Qt::TextSelectableByMouse);
	form->addRow(QStringLiteral("network"), ssid_label);

	id = new QLineEdit(this);
	id->setPlaceholderText(QStringLiteral("optional; defaults to the network's name"));
	form->addRow(QStringLiteral("call it"), id);

	if (secured) {
		passphrase = new QLineEdit(this);
		/* Never echoed, and never put in a placeholder, a tooltip or a
		 * window title. The one field in this client that holds a secret. */
		passphrase->setEchoMode(QLineEdit::Password);
		form->addRow(QStringLiteral("passphrase"), passphrase);

		proto = new QComboBox(this);
		/* Empty first, and it is the default: netcfgd negotiates WPA2 and
		 * WPA3 both unless told otherwise, and a client that pinned one on
		 * the operator's behalf would be answering a question nobody asked. */
		proto->addItem(QStringLiteral("negotiate both"), QString());
		proto->addItem(QStringLiteral("WPA2 only"), QStringLiteral("wpa2"));
		proto->addItem(QStringLiteral("WPA3 only"), QStringLiteral("wpa3"));
		form->addRow(QStringLiteral("security"), proto);
	} else {
		passphrase = nullptr;
		proto = nullptr;
		form->addRow(QStringLiteral("security"),
		         new QLabel(QStringLiteral("open -- no passphrase"), this));
	}

	hidden = new QCheckBox(QStringLiteral("the network does not broadcast its name"), this);
	form->addRow(QString(), hidden);
	layout->addLayout(form);

	note = new QLabel(this);
	note->setWordWrap(true);
	note->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(note);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
	add_button = buttons->addButton(QStringLiteral("Add"), QDialogButtonBox::AcceptRole);
	layout->addWidget(buttons);

	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(add_button, &QPushButton::clicked, this, &ncfg_add_network_dialog::submit);
	connect(id, &QLineEdit::textChanged, this, &ncfg_add_network_dialog::revalidate);
	if (passphrase) {
		connect(passphrase, &QLineEdit::textChanged, this,
		    &ncfg_add_network_dialog::revalidate);
	}
	revalidate();
}

void ncfg_add_network_dialog::revalidate()
{
	/* A secured network with no passphrase would be refused by the daemon
	 * after the operator pressed the button. Saying so before is the same
	 * courtesy the wifi tab's greyed join button pays. */
	const bool ready = !secured || !passphrase->text().isEmpty();
	add_button->setEnabled(ready);
}

void ncfg_add_network_dialog::submit()
{
	QString error;
	const QString chosen = proto ? proto->currentData().toString() : QString();
	const bool done = connection->wifi_add(ssid_hex, id->text(),
	                       passphrase ? passphrase->text() : QString(),
	                       chosen, hidden->isChecked(), &error);
	if (!done) {
		/* The daemon's own sentence. A refusal names the tier that would have
		 * been needed, and `admin` is one a desktop session often does not
		 * have -- replacing that with wording of this dialog's own would throw
		 * away the part that says what to do about it. */
		note->setText(error);
		return;
	}

	/* Cleared before the dialog closes rather than left for the destructor.
	 * Qt will free the widget, but the string it held is the one thing here
	 * worth not leaving lying about a second longer than needed. */
	if (passphrase) {
		passphrase->clear();
	}
	accept();
}
