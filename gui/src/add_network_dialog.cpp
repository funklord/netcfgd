/*
 * add_network_dialog.cpp -- the dialog described in add_network_dialog.h.
 */
#include "add_network_dialog.h"

#include "ncfg_connection.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QVBoxLayout>

/*
 * A field with its `Choose...` button, as one widget for the form row.
 *
 * The button is created and *disabled* rather than omitted where the
 * connection cannot store a secret. A control that is absent tells an operator
 * nothing; one that is present and greyed, with a tooltip saying which tier is
 * missing, tells them what to ask for -- and it is the same choice the wifi
 * tab's join button already makes.
 */
static QWidget *with_chooser(QLineEdit *field, bool may_store, QPushButton **out)
{
	auto *row = new QWidget(field->parentWidget());
	auto *layout = new QHBoxLayout(row);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(field);

	auto *button = new QPushButton(QStringLiteral("Choose..."), row);
	button->setObjectName(field->objectName() + QStringLiteral("_choose"));
	button->setEnabled(may_store);
	if (!may_store) {
		button->setToolTip(QStringLiteral(
		    "Storing a certificate needs the admin tier, and this connection has "
		    "the wifi tier. Somebody who has it can store one with "
		    "`ncfg secret set NAME < file`, and its name goes in the field."));
	}
	layout->addWidget(button);
	*out = button;
	return row;
}

ncfg_add_network_dialog::ncfg_add_network_dialog(ncfg_connection *connection,
                         const QString &ssid_hex, const QString &shown,
                         bool secured, bool enterprise, QWidget *parent)
    : QDialog(parent), connection(connection), ssid_hex(ssid_hex), secured(secured),
      enterprise(enterprise), eap_method(nullptr), eap_identity(nullptr),
      eap_anonymous(nullptr), eap_phase2(nullptr), eap_ca_cert(nullptr),
      eap_client_cert(nullptr), passphrase_label(nullptr), client_cert_label(nullptr),
      ca_cert_button(nullptr), client_cert_button(nullptr)
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

		/* What crosses the socket is a *name*: a path would be an
		 * instruction to open a file as root. `Choose...` reads the file
		 * here, with this operator's own permissions, and sends the
		 * content -- which is 0127 in one control. Storing is `admin`
		 * while adding is `wifi`, so the button appears only where the
		 * connection holds it and the field still takes a typed name
		 * where it does not. */
		const bool may_store = connection->tiers().admin != 0;

		eap_ca_cert = new QLineEdit(this);
		eap_ca_cert->setObjectName(QStringLiteral("eap_ca_cert"));
		eap_ca_cert->setPlaceholderText(
		    QStringLiteral("optional; the name of a stored certificate"));
		form->addRow(QStringLiteral("server certificate"),
		         with_chooser(eap_ca_cert, may_store, &ca_cert_button));

		eap_client_cert = new QLineEdit(this);
		eap_client_cert->setObjectName(QStringLiteral("eap_client_cert"));
		eap_client_cert->setPlaceholderText(
		    QStringLiteral("the name of a stored certificate"));
		client_cert_label = new QLabel(QStringLiteral("your certificate"), this);
		form->addRow(client_cert_label,
		         with_chooser(eap_client_cert, may_store, &client_cert_button));
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
		connect(ca_cert_button, &QPushButton::clicked, this,
		    &ncfg_add_network_dialog::choose_ca_certificate);
		connect(client_cert_button, &QPushButton::clicked, this,
		    &ncfg_add_network_dialog::choose_client_certificate);
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
	/* The button lives in the same row widget, so hiding the field alone
	 * would leave a Choose button beside nothing. */
	eap_client_cert->parentWidget()->setVisible(tls);
	client_cert_label->setVisible(tls);

	/* Cleared rather than merely hidden. A hidden field that still holds
	 * text is a value the operator cannot see and submit() would send. */
	if (tls) {
		passphrase->clear();
	} else {
		eap_client_cert->clear();
	}

	/* The key is not a field: for TLS it *is* the credential, so it goes in
	 * the password box the same way a passphrase does and is stored under the
	 * network's own name. Saying so is the difference between a form somebody
	 * can fill in and one where the obvious field is missing. */
	note->setText(tls ? QStringLiteral(
	                "TLS presents a certificate instead of a password. Choose "
	                "the certificate, and put the private key that goes with "
	                "it in the password box -- it is stored under this "
	                "network's own name.")
	              : QString());
	revalidate();
}

/*
 * A secret name derived from a file name.
 *
 * `usable_id` refuses a name with a path separator, a quote, a backslash, a
 * control character, a leading dot or `..`, and anything over 64 bytes. So the
 * basename is stripped of its suffix and of everything outside a small safe
 * set rather than passed through and refused: a file called `corp ca (1).pem`
 * is an ordinary thing to have chosen, and being told the name is unusable
 * teaches an operator nothing they can act on.
 */
QString ncfg_secret_name_for(const QString &path)
{
	const QString base = QFileInfo(path).completeBaseName();
	QString name;
	for (const QChar &character : base) {
		if (character.isLetterOrNumber() || character == QLatin1Char('-')
		    || character == QLatin1Char('_') || character == QLatin1Char('.')) {
			name.append(character);
		} else if (!name.endsWith(QLatin1Char('-'))) {
			name.append(QLatin1Char('-'));
		}
	}
	/* A leading dot would name a hidden file and `..` would leave the
	 * directory; both are refused, so neither is offered. Trailing separators
	 * go for a different reason: `corp ca (1).pem` ends in a character that
	 * became a dash, and `corp-ca-1-` is not what anybody would call that
	 * file. Truncation happens first, so a name cut at 64 bytes cannot be
	 * left ending in one either. */
	name.replace(QStringLiteral(".."), QStringLiteral("."));
	name.truncate(64);
	while (!name.isEmpty()
	       && (name.startsWith(QLatin1Char('.')) || name.startsWith(QLatin1Char('-')))) {
		name.remove(0, 1);
	}
	while (!name.isEmpty()
	       && (name.endsWith(QLatin1Char('.')) || name.endsWith(QLatin1Char('-')))) {
		name.chop(1);
	}
	return name;
}

QString ncfg_add_network_dialog::store_certificate(const QString &role)
{
	const QString path = QFileDialog::getOpenFileName(this,
	    QStringLiteral("Choose the %1").arg(role), QString(),
	    QStringLiteral("Certificates (*.pem *.crt *.cer *.der);;All files (*)"));
	if (path.isEmpty()) {
		return QString();
	}

	/* Read **here**, as whoever is running this window, with their own
	 * permissions. That is the whole of 0127 in one operation: the daemon
	 * never learns the path, so nothing asks root to open a file chosen by
	 * somebody who is not root. */
	QFile file(path);
	if (!file.open(QIODevice::ReadOnly)) {
		note->setText(QStringLiteral("could not read %1: %2").arg(path, file.errorString()));
		return QString();
	}
	const QByteArray content = file.readAll();
	file.close();
	if (content.isEmpty()) {
		note->setText(QStringLiteral("%1 is empty, and an empty certificate fails at the "
		                 "moment it is used rather than now")
		              .arg(path));
		return QString();
	}

	const QString name = ncfg_secret_name_for(path);
	if (name.isEmpty()) {
		note->setText(QStringLiteral("no usable name could be made from %1 -- store it at a "
		                 "terminal with `ncfg secret set NAME < file` and type "
		                 "the name here")
		              .arg(QFileInfo(path).fileName()));
		return QString();
	}

	QString error;
	if (connection->secret_put(name, QString::fromUtf8(content), false, &error)) {
		note->setText(QStringLiteral("stored as `%1`").arg(name));
		return name;
	}

	/* Said rather than assumed, which is 0042's rule: a stored credential
	 * nobody has another copy of cannot be got back, so replacing one is a
	 * question and never a default. The daemon's own refusal is what asks
	 * it, because only the daemon knows the name is taken. */
	const QMessageBox::StandardButton answer = QMessageBox::question(this,
	    QStringLiteral("Replace `%1`?").arg(name),
	    QStringLiteral("%1\n\nReplace what is stored under `%2`?").arg(error, name),
	    QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
	if (answer != QMessageBox::Yes) {
		note->setText(error);
		return QString();
	}
	if (connection->secret_put(name, QString::fromUtf8(content), true, &error)) {
		note->setText(QStringLiteral("replaced `%1`").arg(name));
		return name;
	}
	note->setText(error);
	return QString();
}

void ncfg_add_network_dialog::choose_ca_certificate()
{
	const QString name = store_certificate(QStringLiteral("server certificate"));
	if (!name.isEmpty()) {
		eap_ca_cert->setText(name);
	}
}

void ncfg_add_network_dialog::choose_client_certificate()
{
	const QString name = store_certificate(QStringLiteral("client certificate"));
	if (!name.isEmpty()) {
		eap_client_cert->setText(name);
	}
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
