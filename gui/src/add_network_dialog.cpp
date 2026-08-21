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
                         bool secured, bool enterprise, QWidget *parent)
    : QDialog(parent), connection(connection), ssid_hex(ssid_hex), secured(secured),
      enterprise(enterprise), eap_method(nullptr), eap_identity(nullptr),
      eap_anonymous(nullptr), eap_phase2(nullptr), eap_ca_cert(nullptr),
      eap_client_cert(nullptr), passphrase_label(nullptr), client_cert_label(nullptr)
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

	if (secured && enterprise) {
		/* No `proto` row at all rather than a disabled one: it pins the
		 * generation protecting a passphrase, an enterprise network
		 * negotiates its own, and the daemon refuses the pair. A control
		 * that cannot be used is a question the operator still has to
		 * read. */
		proto = nullptr;

		eap_method = new QComboBox(this);
		/* Named so a test can find them without matching on wording. Two
		 * of the placeholders below differ only by an "optional" prefix,
		 * and a probe that matched on text found the wrong field. */
		eap_method->setObjectName(QStringLiteral("eap_method"));
		eap_method->addItem(QStringLiteral("PEAP"), QStringLiteral("peap"));
		eap_method->addItem(QStringLiteral("TTLS"), QStringLiteral("ttls"));
		eap_method->addItem(QStringLiteral("TLS (certificate)"), QStringLiteral("tls"));
		eap_method->addItem(QStringLiteral("PWD"), QStringLiteral("pwd"));
		form->addRow(QStringLiteral("method"), eap_method);

		eap_identity = new QLineEdit(this);
		eap_identity->setObjectName(QStringLiteral("eap_identity"));
		eap_identity->setPlaceholderText(
		    QStringLiteral("who you are to the authentication server"));
		form->addRow(QStringLiteral("identity"), eap_identity);

		passphrase = new QLineEdit(this);
		passphrase->setObjectName(QStringLiteral("eap_password"));
		passphrase->setEchoMode(QLineEdit::Password);
		passphrase_label = new QLabel(QStringLiteral("password"), this);
		form->addRow(passphrase_label, passphrase);

		eap_anonymous = new QLineEdit(this);
		eap_anonymous->setObjectName(QStringLiteral("eap_anonymous"));
		/* The one field here worth explaining in place: it is what the
		 * radio can see, and everyone nearby can see the radio. */
		eap_anonymous->setPlaceholderText(
		    QStringLiteral("optional; who you are outside the tunnel"));
		form->addRow(QStringLiteral("outer identity"), eap_anonymous);

		eap_phase2 = new QLineEdit(this);
		eap_phase2->setObjectName(QStringLiteral("eap_phase2"));
		eap_phase2->setPlaceholderText(QStringLiteral("optional; often mschapv2"));
		form->addRow(QStringLiteral("inner method"), eap_phase2);

		/* Named, not chosen from disk. A path in the request would be an
		 * instruction to open a file as root, so there is no field for
		 * one -- the note below says how a certificate gets there. */
		eap_ca_cert = new QLineEdit(this);
		eap_ca_cert->setObjectName(QStringLiteral("eap_ca_cert"));
		eap_ca_cert->setPlaceholderText(
		    QStringLiteral("optional; the name of a stored certificate"));
		form->addRow(QStringLiteral("server certificate"), eap_ca_cert);

		eap_client_cert = new QLineEdit(this);
		eap_client_cert->setObjectName(QStringLiteral("eap_client_cert"));
		eap_client_cert->setPlaceholderText(
		    QStringLiteral("the name of a stored certificate"));
		client_cert_label = new QLabel(QStringLiteral("your certificate"), this);
		form->addRow(client_cert_label, eap_client_cert);
	} else if (secured) {
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
	if (eap_method) {
		connect(eap_identity, &QLineEdit::textChanged, this,
		    &ncfg_add_network_dialog::revalidate);
		connect(eap_client_cert, &QLineEdit::textChanged, this,
		    &ncfg_add_network_dialog::revalidate);
		connect(eap_method, &QComboBox::currentIndexChanged, this,
		    &ncfg_add_network_dialog::method_changed);
		method_changed();
	}
	revalidate();
}

void ncfg_add_network_dialog::method_changed()
{
	const bool tls = eap_method->currentData().toString() == QStringLiteral("tls");

	/* TLS presents a certificate; the others present a password. The
	 * supplicant refuses the network outright if given the other, so this is
	 * not a matter of presentation -- offering both would let an operator
	 * fill in the one that cannot work. */
	passphrase->setVisible(!tls);
	passphrase_label->setVisible(!tls);
	eap_client_cert->setVisible(tls);
	client_cert_label->setVisible(tls);

	/* Cleared rather than merely hidden. A hidden field that still holds
	 * text is a value the operator cannot see and submit() would send. */
	if (tls) {
		passphrase->clear();
	} else {
		eap_client_cert->clear();
	}

	note->setText(
	    tls ? QStringLiteral(
	              "TLS needs a certificate and a key the daemon already holds. "
	              "Store them at a terminal first, with `ncfg secret set NAME < file` "
	              "for the certificate and `ncfg secret set <the name above> < key` "
	              "for the key -- this window can name them and cannot put them there.")
	        : QString());
	revalidate();
}

void ncfg_add_network_dialog::revalidate()
{
	/* A secured network with no credential would be refused by the daemon
	 * after the operator pressed the button. Saying so before is the same
	 * courtesy the wifi tab's greyed join button pays. */
	bool ready = true;
	if (eap_method) {
		/* The daemon requires a method and an identity, and the credential
		 * the method implies: a certificate name for TLS, a password
		 * otherwise. Everything else on this form is optional. */
		const bool tls = eap_method->currentData().toString() == QStringLiteral("tls");
		ready = !eap_identity->text().isEmpty()
		    && !(tls ? eap_client_cert->text() : passphrase->text()).isEmpty();
	} else if (secured) {
		ready = !passphrase->text().isEmpty();
	}
	add_button->setEnabled(ready);
}

void ncfg_add_network_dialog::submit()
{
	QString error;
	const QString chosen = proto ? proto->currentData().toString() : QString();

	ncfg_connection::eap_request eap;
	if (eap_method) {
		eap.method = eap_method->currentData().toString();
		eap.identity = eap_identity->text();
		eap.anonymous_identity = eap_anonymous->text();
		eap.phase2 = eap_phase2->text();
		eap.ca_cert = eap_ca_cert->text();
		eap.client_cert = eap_client_cert->text();
	}

	const bool done = connection->wifi_add(ssid_hex, id->text(),
	                       passphrase ? passphrase->text() : QString(),
	                       chosen, hidden->isChecked(),
	                       eap_method ? &eap : nullptr, &error);
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
