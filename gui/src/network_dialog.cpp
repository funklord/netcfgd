#include "network_dialog.h"

#include <QCheckBox>
#include <QComboBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QTableWidget>
#include <QScrollArea>
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
/* The same modes the interface dialog offers, for a network's own scope. */
const choice dns_modes[] = {
	{ "leave to the interface and the global policy", "" },
	{ "none -- netcfgd writes nothing", "none" },
	{ "write /etc/resolv.conf", "write_resolv_conf" },
	{ "resolvconf", "resolvconf" },
	{ "openresolv", "openresolv" },
	{ "systemd-resolved", "resolved" },
	{ "dnsmasq", "dnsmasq" },
	{ "unbound", "unbound" },
};

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
	form_layout = form;

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
	client_cert->setPlaceholderText(QStringLiteral("a path, or @secret:NAME"));
	form->addRow(QStringLiteral("client certificate"), client_cert);
	private_key = new QLineEdit(this);
	private_key->setObjectName(QStringLiteral("network_private_key"));
	private_key->setPlaceholderText(QStringLiteral("the client's key: a path, or @secret:NAME"));
	form->addRow(QStringLiteral("private key"), private_key);
	domain_suffix_match = new QLineEdit(this);
	domain_suffix_match->setObjectName(QStringLiteral("network_domain_suffix_match"));
	/* 0206: `ca_cert` alone says who signed the server's certificate, not
	 * whose it is, so a public CA's signature would do for any server. */
	domain_suffix_match->setPlaceholderText(
	    QStringLiteral("the name the server's certificate must carry"));
	form->addRow(QStringLiteral("server name"), domain_suffix_match);
	identity->setObjectName(QStringLiteral("network_identity"));
	ca_cert->setObjectName(QStringLiteral("network_ca_cert"));
	client_cert->setObjectName(QStringLiteral("network_client_cert"));
	/* What the document holds, put back (10.611). Before this the fields
	 * opened empty and Save wrote them so, which is how an enterprise
	 * network lost its identity and certificates. */
	if (editing) {
		const int at = eap_method->findData(existing.eap_method);
		if (at >= 0) {
			eap_method->setCurrentIndex(at);
		}
		identity->setText(existing.identity);
		anonymous_identity->setText(existing.anonymous_identity);
		phase2->setText(existing.phase2);
		ca_cert->setText(existing.ca_cert);
		client_cert->setText(existing.client_cert);
		private_key->setText(existing.private_key);
		domain_suffix_match->setText(existing.domain_suffix_match);
	}

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
	/* What the document holds, which this used not to read: the combo opened
	 * on "leave to the interface" for every network and Save wrote that back
	 * (10.606). An empty list and `null` are one document, so both open on
	 * the first choice and neither loses anything. */
	if (editing) {
		const int at = addressing->findData(existing.addressing);
		if (at >= 0) {
			addressing->setCurrentIndex(at);
		}
	}
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
	metered->setChecked(existing.metered);
	form->addRow(QString(), metered);

	bssid = new QLineEdit(this);
	bssid->setObjectName(QStringLiteral("network_bssid"));
	bssid->setPlaceholderText(QStringLiteral("02:00:00:00:00:01 -- only these access points; "
	                        "blank for any"));
	form->addRow(QStringLiteral("pinned to"), bssid);
	roam = new QCheckBox(QStringLiteral("move to a stronger access point of this network"), this);
	roam->setObjectName(QStringLiteral("network_roam"));
	form->addRow(QString(), roam);
	roam_signal = new QSpinBox(this);
	roam_signal->setObjectName(QStringLiteral("network_roam_signal"));
	roam_signal->setRange(-100, -1);
	roam_signal->setSuffix(QStringLiteral(" dBm"));
	form->addRow(QStringLiteral("when weaker than"), roam_signal);
	roam_interval = new QSpinBox(this);
	roam_interval->setRange(1, 86400);
	roam_interval->setSuffix(QStringLiteral(" s"));
	form->addRow(QStringLiteral("look every"), roam_interval);
	roam_slow_interval = new QSpinBox(this);
	roam_slow_interval->setRange(1, 86400);
	roam_slow_interval->setSuffix(QStringLiteral(" s"));
	form->addRow(QStringLiteral("and when strong, every"), roam_slow_interval);
	const auto roaming = [this](bool on) {
		roam_signal->setEnabled(on);
		roam_interval->setEnabled(on);
		roam_slow_interval->setEnabled(on);
	};
	connect(roam, &QCheckBox::toggled, this, roaming);

	routes = new QTableWidget(0, 3, this);
	routes->setObjectName(QStringLiteral("network_routes"));
	routes->setHorizontalHeaderLabels(
	    { QStringLiteral("destination"), QStringLiteral("via"), QStringLiteral("metric") });
	routes->verticalHeader()->setVisible(false);
	routes->horizontalHeader()->setStretchLastSection(true);
	routes->setMaximumHeight(100);
	form->addRow(QStringLiteral("routes"), routes);
	{
		auto *row = new QHBoxLayout();
		auto *add = new QPushButton(QStringLiteral("add route"), this);
		auto *drop = new QPushButton(QStringLiteral("remove route"), this);
		row->addWidget(add);
		row->addWidget(drop);
		row->addStretch(1);
		form->addRow(QString(), row);
		connect(add, &QPushButton::clicked, this, [this]() {
			routes->insertRow(routes->rowCount());
			routes->setCurrentCell(routes->rowCount() - 1, 0);
		});
		connect(drop, &QPushButton::clicked, this, [this]() {
			if (routes->currentRow() >= 0) {
				routes->removeRow(routes->currentRow());
			}
		});
	}

	dns_mode = new QComboBox(this);
	dns_mode->setObjectName(QStringLiteral("network_dns_mode"));
	fill(dns_mode, dns_modes, sizeof(dns_modes) / sizeof(dns_modes[0]));
	form->addRow(QStringLiteral("dns"), dns_mode);
	dns_servers = new QLineEdit(this);
	dns_servers->setObjectName(QStringLiteral("network_dns_servers"));
	dns_servers->setPlaceholderText(QStringLiteral("1.1.1.1 9.9.9.9 -- blank takes the lease's"));
	form->addRow(QStringLiteral("nameservers"), dns_servers);
	dns_search = new QLineEdit(this);
	form->addRow(QStringLiteral("search domains"), dns_search);
	dns_domains = new QLineEdit(this);
	dns_domains->setPlaceholderText(QStringLiteral("names under these go to this network's "
	                          "servers"));
	form->addRow(QStringLiteral("routing domains"), dns_domains);

	roam_signal->setValue(existing.roam_signal);
	roam_interval->setValue(existing.roam_interval);
	roam_slow_interval->setValue(existing.roam_slow_interval);
	if (editing) {
		bssid->setText(existing.bssid);
		roam->setChecked(existing.roam);
		for (const ncfg_route_row &route : existing.routes) {
			const int row = routes->rowCount();
			routes->insertRow(row);
			routes->setItem(row, 0, new QTableWidgetItem(route.destination));
			routes->setItem(row, 1, new QTableWidgetItem(route.via));
			routes->setItem(row, 2, new QTableWidgetItem(
			    route.metric >= 0 ? QString::number(route.metric) : QString()));
		}
		const int mode = dns_mode->findData(existing.dns_mode);
		if (mode >= 0) {
			dns_mode->setCurrentIndex(mode);
		}
		dns_servers->setText(existing.dns_servers);
		dns_search->setText(existing.dns_search);
		dns_domains->setText(existing.dns_domains);
	}
	roaming(roam->isChecked());

	/* In a scroll area since 10.612, which made the form taller than a
	 * laptop's screen. */
	auto *holder = new QWidget(this);
	holder->setLayout(form);
	auto *scroll = new QScrollArea(this);
	scroll->setWidgetResizable(true);
	scroll->setFrameShape(QFrame::NoFrame);
	scroll->setWidget(holder);
	layout->addWidget(scroll, 1);

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
	/* A member: the form is inside a scroll area since 10.612. */
	QFormLayout *form = form_layout;
	if (form) {
		form->setRowVisible(proto, is_psk);
		form->setRowVisible(eap_method, is_eap);
		form->setRowVisible(identity, is_eap);
		form->setRowVisible(anonymous_identity, is_eap);
		form->setRowVisible(phase2, is_eap);
		form->setRowVisible(ca_cert, is_eap);
		form->setRowVisible(client_cert, is_eap);
		form->setRowVisible(private_key, is_eap);
		form->setRowVisible(domain_suffix_match, is_eap);
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
		wifi << QStringLiteral("\t\tpsk = \"%1\"").arg(credential_reference());
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
		if (!private_key->text().trimmed().isEmpty()) {
			wifi << QStringLiteral("\t\tprivate_key = \"%1\"")
			        .arg(private_key->text().trimmed());
		}
		if (!domain_suffix_match->text().trimmed().isEmpty()) {
			wifi << QStringLiteral("\t\tdomain_suffix_match = \"%1\"")
			        .arg(domain_suffix_match->text().trimmed());
		}
		/* A password for every method but TLS, and for a TLS network that
		 * already refers to one, whatever it is for. */
		if (eap_method->currentData().toString() != QStringLiteral("tls") ||
		    (editing && before.security == QStringLiteral("eap") &&
		    !before.credential_reference.isEmpty())) {
			wifi << QStringLiteral("\t\tpassword = \"%1\"").arg(credential_reference());
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
	/* Inside `wifi`, where the language reads it: roaming is the radio's. */
	if (roam->isChecked()) {
		wifi << QStringLiteral("\t\troam { signal = %1; interval = %2; slow_interval = %3 }")
		            .arg(roam_signal->value())
		            .arg(roam_interval->value())
		            .arg(roam_slow_interval->value());
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
	const QStringList pinned = bssid->text().split(QLatin1Char(' '), Qt::SkipEmptyParts);
	if (!pinned.isEmpty()) {
		QStringList quoted;
		for (const QString &one : pinned) {
			quoted << QStringLiteral("\"%1\"").arg(one);
		}
		block << QStringLiteral("\tbssid = [%1]").arg(quoted.join(QStringLiteral(", ")));
	}
	QStringList lines;
	for (int row = 0; row < routes->rowCount(); row++) {
		const auto at = [this, row](int column) {
			const QTableWidgetItem *item = routes->item(row, column);
			return item ? item->text().trimmed() : QString();
		};
		QString line = at(0);
		if (!at(1).isEmpty()) {
			line += QStringLiteral(" via %1").arg(at(1));
		}
		if (!at(2).isEmpty()) {
			line += QStringLiteral(" metric %1").arg(at(2));
		}
		lines << QStringLiteral("\"%1\"").arg(line);
	}
	if (!lines.isEmpty()) {
		block << QStringLiteral("\troutes = [%1]").arg(lines.join(QStringLiteral(", ")));
	}
	const QString mode = dns_mode->currentData().toString();
	if (!mode.isEmpty() || !dns_servers->text().trimmed().isEmpty() ||
	    !dns_search->text().trimmed().isEmpty() || !dns_domains->text().trimmed().isEmpty()) {
		const struct {
			const char *key;
			QString     value;
		} scopes[] = {
			{ "servers", dns_servers->text().trimmed() },
			{ "search", dns_search->text().trimmed() },
			{ "domains", dns_domains->text().trimmed() },
		};
		block << QStringLiteral("\tdns {");
		if (!mode.isEmpty()) {
			block << QStringLiteral("\t\tmode = \"%1\"").arg(mode);
		}
		for (const auto &one : scopes) {
			if (one.value.isEmpty()) {
				continue;
			}
			QStringList quoted;
			for (const QString &word : one.value.split(QLatin1Char(' '), Qt::SkipEmptyParts)) {
				quoted << QStringLiteral("\"%1\"").arg(word);
			}
			block << QStringLiteral("\t\t%1 = [%2]")
			             .arg(QString::fromLatin1(one.key), quoted.join(QStringLiteral(", ")));
		}
		block << QStringLiteral("\t}");
	}
	block << QStringLiteral("}");
	return block.join(QStringLiteral("\n")) + QStringLiteral("\n");
}

QString ncfg_network_dialog::credential_reference() const
{
	/* Kept where the network keeps the same kind of credential: a passphrase
	 * stays a passphrase and a password a password, each under the name and
	 * the store the document gave it. Changing the kind is a new credential,
	 * and a new one is stored under the network's own name. */
	if (editing && before.security == security->currentData().toString() &&
	    !before.credential_reference.isEmpty()) {
		return before.credential_reference;
	}
	return QStringLiteral("@secret:%1").arg(id->text().trimmed());
}

void ncfg_network_dialog::submit()
{
	const QString name = id->text().trimmed();
	QString error;

	/* **Refused rather than approximated**, by the interface dialog's rule
	 * (10.606). The block is written whole with `replace`, so whatever this
	 * form has no field for -- a pinned BSSID, a route, a hook, an
	 * enterprise network's identity -- would be deleted by saving, and the
	 * operator would find out when the network stopped working. */
	if (editing && !before.unmodelled.isEmpty()) {
		note->setText(QStringLiteral(
		    "this network's configuration carries %1, which this dialog has no field "
		    "for -- saving would delete it. Edit the file instead: "
		    "`ncfg config edit wifi-%2`.")
		        .arg(before.unmodelled, before.id));
		return;
	}

	/* Every value that reaches the text is checked, not just the name. The
	 * dialog composes the block, so the only way a key an operator did not
	 * choose could appear is through one of these fields. */
	const QLineEdit *values[] = { id, ssid_hex, identity, anonymous_identity, phase2, ca_cert,
		client_cert, private_key, domain_suffix_match, bssid, dns_servers, dns_search,
		dns_domains };
	for (const QLineEdit *value : values) {
		if (!safe_value(value->text())) {
			note->setText(QStringLiteral("a value cannot carry a quote, a backslash "
			              "or a newline"));
			return;
		}
	}

	/* A route's cells are text inside a quoted list entry: refused if they
	 * could close it, a metric only as a number, and a route needs where it
	 * goes (10.612). */
	for (int row = 0; row < routes->rowCount(); row++) {
		bool          number = true;
		const QString cells[3] = {
			routes->item(row, 0) ? routes->item(row, 0)->text().trimmed() : QString(),
			routes->item(row, 1) ? routes->item(row, 1)->text().trimmed() : QString(),
			routes->item(row, 2) ? routes->item(row, 2)->text().trimmed() : QString(),
		};
		if (!cells[2].isEmpty()) {
			(void)cells[2].toUInt(&number);
		}
		if (cells[0].isEmpty() || !number || !safe_value(cells[0]) || !safe_value(cells[1]) ||
		    cells[0].contains(QLatin1Char(' ')) || cells[1].contains(QLatin1Char(' '))) {
			note->setText(QStringLiteral("route %1 needs a destination, and a gateway and "
			              "metric are one word each").arg(row + 1));
			return;
		}
	}

	/* The credential first, so a network is never written pointing at a secret
	 * that is not there. Blank leaves the stored one alone, which is what
	 * editing anything other than the passphrase looks like. */
	if (!credential->text().isEmpty()) {
		/* Into the store the reference names, under its name (10.611): the
		 * network's id is only the name of a credential this dialog made. A
		 * reference to the keyring or to `pass` is somebody else's store, which
		 * netcfgd reads and does not write, so a new passphrase for one is set
		 * there rather than here. */
		const QString reference = credential_reference();
		const QString stored = reference.mid(QStringLiteral("@secret:").size());
		if (!reference.startsWith(QStringLiteral("@secret:")) || stored.contains(QLatin1Char(':'))) {
			note->setText(QStringLiteral("this network's credential is %1, which netcfgd reads "
			              "and does not write: change it there, and leave the field here blank")
			                  .arg(reference));
			return;
		}
		if (!connection->secret_put(stored, credential->text(), true, &error)) {
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
