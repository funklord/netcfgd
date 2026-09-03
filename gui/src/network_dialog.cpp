#include "network_dialog.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

namespace {

/* The security kinds a `wifi` block can express, spelled as an operator would
 * recognise them. The data is the key this file writes; the text is what the
 * label on somebody's router says. */
struct choice {
	const char *shown;
	const char *key;
};

const choice securities[] = {
	{ "WPA2/WPA3 passphrase", "psk" },
	{ "802.1X (enterprise)", "eap" },
	{ "open -- no passphrase", "open" },
	{ "OWE (opportunistic encryption)", "owe" },
};

/* Absent negotiates both, which is why the empty key is offered first and is
 * the default: pinning a generation is the exception. */
const choice protos[] = {
	{ "negotiate WPA2 and WPA3", "" },
	{ "WPA2 only", "wpa2" },
	{ "WPA3 only", "wpa3" },
};

const choice methods[] = {
	{ "PEAP", "peap" },
	{ "TTLS", "ttls" },
	{ "TLS (certificate)", "tls" },
	{ "PWD", "pwd" },
};

/* Addressing for this network, overriding the interface's while it is joined.
 * "leave to the interface" is first and is the ordinary answer: a network block
 * that says nothing about addressing is one the interface configures. */
const choice addressings[] = {
	{ "leave to the interface", "" },
	{ "DHCP (IPv4)", "dhcp" },
	{ "DHCPv6", "dhcp6" },
	{ "none -- no address on this network", "null" },
};

void fill(QComboBox *box, const choice *from, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		box->addItem(QString::fromLatin1(from[i].shown), QString::fromLatin1(from[i].key));
	}
}

/* A value going into a quoted string in the config language. Refused rather
 * than escaped: a quote or a backslash in an identity is far more likely to be
 * a mistake than a name, and this dialog writes configuration. */
bool safe_value(const QString &text)
{
	return !text.contains(QLatin1Char('"')) && !text.contains(QLatin1Char('\\')) &&
	       !text.contains(QLatin1Char('\n'));
}

} // namespace

ncfg_network_dialog::ncfg_network_dialog(ncfg_connection *connection,
    const ncfg_saved_network_row &existing, QWidget *parent)
    : QDialog(parent), connection(connection), before(existing),
      editing(!existing.id.isEmpty())
{
	setWindowTitle(editing ? QStringLiteral("network: %1").arg(existing.id)
	                 : QStringLiteral("add a network by hand"));

	auto *layout = new QVBoxLayout(this);
	auto *form = new QFormLayout();

	id = new QLineEdit(existing.id, this);
	id->setObjectName(QStringLiteral("network_id"));
	/* The id is the block's name and the drop-in's filename. Changing it on an
	 * existing network would write a second one and leave the first, so it is
	 * fixed once there is something to edit. */
	id->setReadOnly(editing);
	form->addRow(QStringLiteral("name"), id);

	ssid_hex = new QLineEdit(this);
	ssid_hex->setObjectName(QStringLiteral("network_ssid"));
	ssid_hex->setPlaceholderText(
	    QStringLiteral("leave blank when the name above is the SSID"));
	/* Only written when it is not simply the id: an SSID is 0..32 arbitrary
	 * octets, so hex is the escape hatch for one that is not text. */
	if (editing && !existing.ssid.isEmpty() &&
	    existing.ssid != QString::fromUtf8(existing.id.toUtf8().toHex())) {
		ssid_hex->setText(existing.ssid);
	}
	form->addRow(QStringLiteral("ssid (hex)"), ssid_hex);

	security = new QComboBox(this);
	security->setObjectName(QStringLiteral("network_security"));
	fill(security, securities, sizeof(securities) / sizeof(securities[0]));
	if (editing) {
		const int at = security->findData(existing.security);
		if (at >= 0) {
			security->setCurrentIndex(at);
		}
	}
	form->addRow(QStringLiteral("security"), security);

	proto = new QComboBox(this);
	proto->setObjectName(QStringLiteral("network_proto"));
	fill(proto, protos, sizeof(protos) / sizeof(protos[0]));
	/* **Restored, like the security above it.** Without this the combo opened
	 * at "negotiate WPA2 and WPA3" whatever the document said, and
	 * `block_text` writes the generation only when the combo names one -- so
	 * opening a `proto = "wpa3"` network and pressing save silently widened it
	 * to accept WPA2 again. The kind was put back and the generation was not,
	 * which is the whole of the fault: one of two fields on the same object
	 * was wired. */
	if (editing) {
		const int at = proto->findData(existing.proto);
		if (at >= 0) {
			proto->setCurrentIndex(at);
		}
	}
	form->addRow(QStringLiteral("generation"), proto);

	eap_method = new QComboBox(this);
	eap_method->setObjectName(QStringLiteral("network_eap"));
	fill(eap_method, methods, sizeof(methods) / sizeof(methods[0]));
	form->addRow(QStringLiteral("eap method"), eap_method);

	identity = new QLineEdit(this);
	form->addRow(QStringLiteral("identity"), identity);
	anonymous_identity = new QLineEdit(this);
	anonymous_identity->setPlaceholderText(QStringLiteral("optional, sent in the clear"));
	form->addRow(QStringLiteral("anonymous identity"), anonymous_identity);
	phase2 = new QLineEdit(this);
	phase2->setPlaceholderText(QStringLiteral("mschapv2, for example"));
	form->addRow(QStringLiteral("phase 2"), phase2);
	ca_cert = new QLineEdit(this);
	ca_cert->setPlaceholderText(QStringLiteral("path to the issuer's certificate"));
	form->addRow(QStringLiteral("ca certificate"), ca_cert);
	client_cert = new QLineEdit(this);
	form->addRow(QStringLiteral("client certificate"), client_cert);

	credential = new QLineEdit(this);
	credential->setObjectName(QStringLiteral("network_credential"));
	credential->setEchoMode(QLineEdit::Password);
	/* Blank means keep. The block keeps an `@secret:` reference and the
	 * passphrase lives in the secret store, so rewriting the block does not
	 * disturb it -- and this dialog has no way to read one back, which is the
	 * property that makes leaving it blank safe rather than lossy. */
	credential->setPlaceholderText(editing
	    ? QStringLiteral("leave blank to keep the stored credential")
	    : QStringLiteral("the passphrase"));
	form->addRow(QStringLiteral("passphrase"), credential);

	metric = new QSpinBox(this);
	metric->setObjectName(QStringLiteral("network_metric"));
	/* The same range the interface dialog offers for `preference`, because
	 * they are the same number on the same scale and get compared against each
	 * other. Two ranges would imply two scales. */
	metric->setRange(0, 4000);
	metric->setValue(existing.metric >= 0 ? existing.metric : 0);
	metric->setSpecialValueText(QStringLiteral("unset"));
	/* **Stands on its own.** The tooltip this replaced had to explain a second
	 * ranking that ran the other way; there is only one now, so this says what
	 * the number does rather than what it is not (0154). */
	metric->setToolTip(QStringLiteral(
	    "How much this network is preferred -- lower wins. It ranks against every "
	    "other link on the machine, wired ones included, and also decides which "
	    "network to join when several are in range. Unset leaves the interface's "
	    "own preference in force."));
	form->addRow(QStringLiteral("metric (lower wins)"), metric);

	addressing = new QComboBox(this);
	addressing->setObjectName(QStringLiteral("network_addressing"));
	fill(addressing, addressings, sizeof(addressings) / sizeof(addressings[0]));
	form->addRow(QStringLiteral("addressing"), addressing);

	autoconnect = new QCheckBox(QStringLiteral("join this network without being asked"), this);
	autoconnect->setObjectName(QStringLiteral("network_autoconnect"));
	autoconnect->setChecked(editing ? existing.autoconnect : true);
	form->addRow(QString(), autoconnect);

	hidden = new QCheckBox(QStringLiteral("the network does not broadcast its name"), this);
	hidden->setObjectName(QStringLiteral("network_hidden"));
	hidden->setChecked(existing.hidden);
	form->addRow(QString(), hidden);

	metered = new QCheckBox(QStringLiteral("metered -- avoid large transfers"), this);
	metered->setObjectName(QStringLiteral("network_metered"));
	form->addRow(QString(), metered);

	layout->addLayout(form);

	note = new QLabel(this);
	note->setWordWrap(true);
	note->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(note);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
	save_button = buttons->addButton(editing ? QStringLiteral("Save")
	                              : QStringLiteral("Add"),
	    QDialogButtonBox::AcceptRole);
	save_button->setObjectName(QStringLiteral("network_save"));
	layout->addWidget(buttons);

	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(save_button, &QPushButton::clicked, this, &ncfg_network_dialog::submit);
	connect(security, &QComboBox::currentIndexChanged, this,
	    &ncfg_network_dialog::security_changed);
	connect(id, &QLineEdit::textChanged, this, &ncfg_network_dialog::revalidate);
	connect(credential, &QLineEdit::textChanged, this, &ncfg_network_dialog::revalidate);

	security_changed();
}

void ncfg_network_dialog::security_changed()
{
	const QString kind = security->currentData().toString();
	const bool is_eap = kind == QStringLiteral("eap");
	const bool is_psk = kind == QStringLiteral("psk");

	/* Rows are hidden rather than disabled: a greyed field still reads as
	 * something that could apply here, and an open network has no passphrase
	 * in any sense. */
	auto *form = qobject_cast<QFormLayout *>(layout()->itemAt(0)->layout());
	if (form) {
		form->setRowVisible(proto, is_psk);
		form->setRowVisible(eap_method, is_eap);
		form->setRowVisible(identity, is_eap);
		form->setRowVisible(anonymous_identity, is_eap);
		form->setRowVisible(phase2, is_eap);
		form->setRowVisible(ca_cert, is_eap);
		form->setRowVisible(client_cert, is_eap);
		form->setRowVisible(credential, is_eap || is_psk);
	}
	revalidate();
}

void ncfg_network_dialog::revalidate()
{
	const QString kind = security->currentData().toString();
	QString why;

	if (id->text().trimmed().isEmpty()) {
		why = QStringLiteral("a network needs a name");
	} else if (!safe_value(id->text())) {
		why = QStringLiteral("a name cannot carry a quote or a backslash");
	} else if (!editing && kind == QStringLiteral("psk") && credential->text().isEmpty()) {
		why = QStringLiteral("a WPA2/WPA3 network needs a passphrase");
	} else if (kind == QStringLiteral("eap") && identity->text().trimmed().isEmpty() &&
	    editing == false) {
		why = QStringLiteral("an 802.1X network needs an identity");
	}

	note->setText(why);
	save_button->setEnabled(why.isEmpty());
}

QString ncfg_network_dialog::block_text() const
{
	const QString name = id->text().trimmed();
	const QString kind = security->currentData().toString();

	QStringList wifi;
	if (kind == QStringLiteral("psk")) {
		wifi << QStringLiteral("\t\tpsk = \"@secret:%1\"").arg(name);
		const QString generation = proto->currentData().toString();
		if (!generation.isEmpty()) {
			wifi << QStringLiteral("\t\tproto = \"%1\"").arg(generation);
		}
	} else if (kind == QStringLiteral("eap")) {
		wifi << QStringLiteral("\t\teap = \"%1\"").arg(eap_method->currentData().toString());
		if (!identity->text().trimmed().isEmpty()) {
			wifi << QStringLiteral("\t\tidentity = \"%1\"").arg(identity->text().trimmed());
		}
		if (!anonymous_identity->text().trimmed().isEmpty()) {
			wifi << QStringLiteral("\t\tanonymous_identity = \"%1\"")
			        .arg(anonymous_identity->text().trimmed());
		}
		if (!phase2->text().trimmed().isEmpty()) {
			wifi << QStringLiteral("\t\tphase2 = \"%1\"").arg(phase2->text().trimmed());
		}
		if (!ca_cert->text().trimmed().isEmpty()) {
			wifi << QStringLiteral("\t\tca_cert = \"%1\"").arg(ca_cert->text().trimmed());
		}
		if (!client_cert->text().trimmed().isEmpty()) {
			wifi << QStringLiteral("\t\tclient_cert = \"%1\"")
			        .arg(client_cert->text().trimmed());
		}
		if (eap_method->currentData().toString() != QStringLiteral("tls")) {
			wifi << QStringLiteral("\t\tpassword = \"@secret:%1\"").arg(name);
		}
	} else if (kind == QStringLiteral("owe")) {
		wifi << QStringLiteral("\t\towe = true");
	} else {
		wifi << QStringLiteral("\t\topen = true");
	}

	/* Written only when it is false: true is the default, and a block that
	 * restates every default is one nobody can read for what is unusual. */
	if (!autoconnect->isChecked()) {
		wifi << QStringLiteral("\t\tautoconnect = false");
	}

	QStringList block;
	block << QStringLiteral("# Written by netcfgd's gui. Ordinary netcfgd configuration:");
	block << QStringLiteral("# edit it, diff it, commit it, or delete it.");
	block << QString();
	block << QStringLiteral("network \"%1\" {").arg(name);
	block << QStringLiteral("\twifi {");
	block << wifi;
	block << QStringLiteral("\t}");
	if (!ssid_hex->text().trimmed().isEmpty()) {
		block << QStringLiteral("\tssid = \"%1\"").arg(ssid_hex->text().trimmed());
	}
	if (hidden->isChecked()) {
		block << QStringLiteral("\thidden = true");
	}
	/* Beside `metered` rather than inside `wifi`, which is where the parser
	 * reads it: a metric ranks this network against every link on the machine,
	 * so it is not a property of the radio. */
	if (metric->value() > 0) {
		block << QStringLiteral("\tmetric = %1").arg(metric->value());
	}
	if (metered->isChecked()) {
		block << QStringLiteral("\tmetered = true");
	}
	const QString addressed = addressing->currentData().toString();
	if (!addressed.isEmpty()) {
		block << QStringLiteral("\tconfig = \"%1\"").arg(addressed);
	}
	block << QStringLiteral("}");
	return block.join(QStringLiteral("\n")) + QStringLiteral("\n");
}

void ncfg_network_dialog::submit()
{
	const QString name = id->text().trimmed();
	QString error;

	/* Every value that reaches the text is checked, not just the name. The
	 * dialog composes the block, so the only way a key an operator did not
	 * choose could appear is through one of these fields. */
	const QLineEdit *values[] = { id, ssid_hex, identity, anonymous_identity, phase2, ca_cert,
		client_cert };
	for (const QLineEdit *value : values) {
		if (!safe_value(value->text())) {
			note->setText(QStringLiteral("a value cannot carry a quote, a backslash "
			              "or a newline"));
			return;
		}
	}

	/* The credential first, so a network is never written pointing at a secret
	 * that is not there. Blank leaves the stored one alone, which is what
	 * editing anything other than the passphrase looks like. */
	if (!credential->text().isEmpty()) {
		if (!connection->secret_put(name, credential->text(), true, &error)) {
			note->setText(error);
			return;
		}
	}

	if (!connection->config_put(QStringLiteral("wifi-%1").arg(name), block_text(), true,
	    &error)) {
		note->setText(error);
		return;
	}

	summary = QStringLiteral("wrote wifi-%1: netcfgd re-read its configuration. "
	              "Run apply to make the machine match it.")
	          .arg(name);
	accept();
}
