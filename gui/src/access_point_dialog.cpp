/*
 * access_point_dialog.cpp -- the editor described in access_point_dialog.h.
 */
#include "access_point_dialog.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

namespace {

struct choice {
	const char *shown;
	const char *key;
};

/* How stations authenticate to it.
 *
 * Narrower than a station profile's list, and deliberately: `eap` on an access
 * point means pointing hostapd at a RADIUS server rather than holding a
 * credential, which is a different form and not this one. The model's type is
 * shared and wide; what this offers is what netcfgd can render. */
const choice securities[] = {
	{ "WPA2/WPA3 passphrase", "psk" },
	{ "open -- no passphrase", "open" },
	{ "OWE -- opportunistic encryption", "owe" },
};

const choice bands[] = {
	{ "let hostapd choose", "" },
	{ "2.4 GHz", "2.4" },
	{ "5 GHz", "5" },
	{ "6 GHz", "6" },
};

/* Who may associate. One list or the other, never both, because hostapd reads
 * one file or the other. */
const choice acls[] = {
	{ "everyone", "" },
	{ "only these stations", "allow" },
	{ "everyone but these", "deny" },
};

void fill(QComboBox *box, const choice *from, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		box->addItem(QString::fromLatin1(from[i].shown), QString::fromLatin1(from[i].key));
	}
}

void select(QComboBox *box, const QString &key)
{
	const int at = box->findData(key);
	if (at >= 0) {
		box->setCurrentIndex(at);
	}
}

bool safe_value(const QString &text)
{
	return !text.contains(QLatin1Char('"')) && !text.contains(QLatin1Char('\\')) &&
	       !text.contains(QLatin1Char('\n'));
}

} // namespace

QString ncfg_access_point_block(const ncfg_access_point_config &settings)
{
	QStringList body;

	body << QStringLiteral("\tdevice = \"%1\"").arg(settings.device);
	if (settings.channel > 0) {
		body << QStringLiteral("\tchannel = %1").arg(settings.channel);
	}
	if (!settings.band.isEmpty()) {
		body << QStringLiteral("\tband = \"%1\"").arg(settings.band);
	}
	if (!settings.regdom.isEmpty()) {
		body << QStringLiteral("\tregdom = \"%1\"").arg(settings.regdom);
	}
	/* Only when true. `hidden = false` is what an access point does unless
	 * somebody says otherwise, and it is not a security measure either way --
	 * it suppresses the name in beacons and makes every client that knows the
	 * network broadcast it while probing, wherever they are. */
	if (settings.hidden) {
		body << QStringLiteral("\thidden = true");
	}

	/* The `wifi` block, which is the same shape a station profile's is: the
	 * compiler parses both with one reader. A passphrase is a reference and
	 * never the passphrase, which is what makes a document safe to write to
	 * /run. */
	body << QStringLiteral("\twifi {");
	if (settings.security == QLatin1String("psk")) {
		body << QStringLiteral("\t\tpsk = \"%1\"").arg(settings.credential);
	} else if (settings.security == QLatin1String("owe")) {
		body << QStringLiteral("\t\towe = true");
	} else {
		body << QStringLiteral("\t\topen = true");
	}
	body << QStringLiteral("\t}");

	if (!settings.acl_policy.isEmpty()) {
		QStringList quoted;
		const QStringList each =
		    settings.stations.split(QLatin1Char(' '), Qt::SkipEmptyParts);
		for (const QString &one : each) {
			quoted << QStringLiteral("\"%1\"").arg(one);
		}
		body << QStringLiteral("\taccess_control {");
		body << QStringLiteral("\t\t%1 = [%2]")
		        .arg(settings.acl_policy, quoted.join(QStringLiteral(", ")));
		body << QStringLiteral("\t}");
	}

	QStringList block;
	block << QStringLiteral("# Written by netcfgd's gui. Ordinary netcfgd configuration:");
	block << QStringLiteral("# edit it, diff it, commit it, or delete it.");
	block << QString();
	block << QStringLiteral("access_point \"%1\" {").arg(settings.id);
	block << body;
	block << QStringLiteral("}");
	return block.join(QStringLiteral("\n")) + QStringLiteral("\n");
}

ncfg_access_point_dialog::ncfg_access_point_dialog(ncfg_connection *connection,
    const ncfg_access_point_config &existing, QWidget *parent)
    : QDialog(parent), connection(connection), before(existing), editing(!existing.id.isEmpty())
{
	setWindowTitle(editing ? QStringLiteral("access point: %1").arg(existing.id)
	                       : QStringLiteral("new access point"));
	setObjectName(QStringLiteral("access_point_dialog"));

	auto *layout = new QVBoxLayout(this);
	auto *form = new QFormLayout();

	id = new QLineEdit(existing.id, this);
	id->setObjectName(QStringLiteral("ap_id"));
	/* The id is the SSID as written and the block's name and the drop-in's
	 * filename, which is why it is fixed once there is something to edit:
	 * changing it would write a second access point and leave the first. */
	id->setReadOnly(editing);
	id->setPlaceholderText(QStringLiteral("the network name to broadcast"));
	form->addRow(QStringLiteral("name"), id);

	device = new QComboBox(this);
	device->setObjectName(QStringLiteral("ap_device"));
	device->setEditable(true);
	form->addRow(QStringLiteral("radio"), device);

	security = new QComboBox(this);
	security->setObjectName(QStringLiteral("ap_security"));
	fill(security, securities, sizeof(securities) / sizeof(securities[0]));
	form->addRow(QStringLiteral("security"), security);

	credential = new QLineEdit(this);
	credential->setObjectName(QStringLiteral("ap_credential"));
	credential->setPlaceholderText(QStringLiteral("@secret:ap -- `ncfg secret set ap` "
	            "puts one there"));
	form->addRow(QStringLiteral("passphrase"), credential);

	band = new QComboBox(this);
	band->setObjectName(QStringLiteral("ap_band"));
	fill(band, bands, sizeof(bands) / sizeof(bands[0]));
	form->addRow(QStringLiteral("band"), band);

	channel = new QSpinBox(this);
	channel->setObjectName(QStringLiteral("ap_channel"));
	channel->setRange(0, 233);
	channel->setSpecialValueText(QStringLiteral("hostapd chooses"));
	form->addRow(QStringLiteral("channel"), channel);

	regdom = new QLineEdit(this);
	regdom->setObjectName(QStringLiteral("ap_regdom"));
	regdom->setPlaceholderText(QStringLiteral("SE -- the country it is in"));
	form->addRow(QStringLiteral("regulatory domain"), regdom);

	hidden = new QCheckBox(QStringLiteral("do not broadcast the name"), this);
	hidden->setObjectName(QStringLiteral("ap_hidden"));
	hidden->setToolTip(QStringLiteral(
	    "Not a security measure. It keeps the network out of a list of nearby ones "
	    "and makes every client that knows it broadcast the name while probing, "
	    "wherever they are."));
	form->addRow(QString(), hidden);

	acl_policy = new QComboBox(this);
	acl_policy->setObjectName(QStringLiteral("ap_acl_policy"));
	fill(acl_policy, acls, sizeof(acls) / sizeof(acls[0]));
	form->addRow(QStringLiteral("who may associate"), acl_policy);

	stations = new QLineEdit(this);
	stations->setObjectName(QStringLiteral("ap_stations"));
	stations->setPlaceholderText(QStringLiteral("00:11:22:33:44:55 -- addresses, "
	            "separated by spaces"));
	form->addRow(QStringLiteral("stations"), stations);
	layout->addLayout(form);

	note = new QLabel(this);
	note->setObjectName(QStringLiteral("ap_note"));
	note->setWordWrap(true);
	note->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(note);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
	save_button = buttons->addButton(QStringLiteral("Save"), QDialogButtonBox::AcceptRole);
	save_button->setObjectName(QStringLiteral("ap_save"));
	remove_button = nullptr;
	if (editing) {
		remove_button = buttons->addButton(QStringLiteral("delete"),
		    QDialogButtonBox::DestructiveRole);
		remove_button->setObjectName(QStringLiteral("ap_remove"));
		connect(remove_button, &QPushButton::clicked, this, &ncfg_access_point_dialog::remove);
	}
	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(save_button, &QPushButton::clicked, this, &ncfg_access_point_dialog::submit);
	connect(security, &QComboBox::currentIndexChanged, this,
	    &ncfg_access_point_dialog::security_changed);
	layout->addWidget(buttons);
	resize(560, 460);

	offer_radios();
	if (editing) {
		device->setCurrentText(existing.device);
		select(security, existing.security);
		credential->setText(existing.credential.isEmpty()
		        ? QString()
		        : QStringLiteral("@secret:%1").arg(existing.credential));
		select(band, existing.band);
		channel->setValue(existing.channel > 0 ? existing.channel : 0);
		regdom->setText(existing.regdom);
		hidden->setChecked(existing.hidden);
		select(acl_policy, existing.acl_policy);
		stations->setText(existing.stations);

		/* **What hostapd actually took**, where it differs from what the block
		 * asks for. A channel can be refused and a band unsupported, and
		 * hostapd then chooses -- an access point beaconing on channel 6 while
		 * the block says 36 is a fact only the observation has, and the one an
		 * operator is looking for when the network is not where they put it. */
		if (existing.running && existing.started_channel > 0
		    && existing.channel > 0 && existing.started_channel != existing.channel) {
			note->setText(QStringLiteral("running on channel %1, not %2: hostapd chose "
			              "when it could not take the one configured")
			          .arg(existing.started_channel)
			          .arg(existing.channel));
		}
	}
	security_changed();
}

void ncfg_access_point_dialog::offer_radios()
{
	QList<ncfg_link_row> links;
	QString error;
	if (!connection->links(&links, &error)) {
		note->setText(error);
		return;
	}
	for (const ncfg_link_row &link : links) {
		if (link.wireless) {
			device->addItem(link.name);
		}
	}
	/* Editable rather than a closed list: a radio that is not plugged in yet
	 * has no row, and an access point for one is a perfectly ordinary thing to
	 * write before the card arrives. */
	if (device->count() == 0) {
		note->setText(QStringLiteral("this machine reports no radio. An access point can "
		              "still be written for one that is not here yet."));
	}
}

void ncfg_access_point_dialog::security_changed()
{
	const bool needs = security->currentData().toString() == QLatin1String("psk");
	auto *form = qobject_cast<QFormLayout *>(layout()->itemAt(0)->layout());
	if (form) {
		form->setRowVisible(credential, needs);
	}
}

QString ncfg_access_point_dialog::block_text() const
{
	ncfg_access_point_config settings;
	settings.id = id->text().trimmed();
	settings.device = device->currentText().trimmed();
	settings.security = security->currentData().toString();
	settings.credential = credential->text().trimmed();
	settings.band = band->currentData().toString();
	settings.channel = channel->value();
	settings.regdom = regdom->text().trimmed();
	settings.hidden = hidden->isChecked();
	settings.acl_policy = acl_policy->currentData().toString();
	settings.stations = stations->text().trimmed();
	return ncfg_access_point_block(settings);
}

void ncfg_access_point_dialog::submit()
{
	const QLineEdit *values[] = { id, credential, regdom, stations };
	for (const QLineEdit *value : values) {
		if (!safe_value(value->text())) {
			note->setText(QStringLiteral("a value cannot carry a quote, a backslash "
			              "or a newline"));
			return;
		}
	}
	if (id->text().trimmed().isEmpty()) {
		note->setText(QStringLiteral("an access point needs a name: it is the network it "
		              "broadcasts"));
		return;
	}
	if (device->currentText().trimmed().isEmpty()) {
		note->setText(QStringLiteral("an access point needs the radio that runs it"));
		return;
	}
	if (security->currentData().toString() == QLatin1String("psk")
	    && !credential->text().trimmed().startsWith(QLatin1String("@secret:"))) {
		note->setText(QStringLiteral("the passphrase is a reference, not the passphrase: "
		              "`@secret:ap`, with `ncfg secret set ap` to put one there"));
		return;
	}
	if (!regdom->text().trimmed().isEmpty() && regdom->text().trimmed().size() != 2) {
		note->setText(QStringLiteral("a regulatory domain is a two-letter country code, "
		              "such as SE or US"));
		return;
	}
	if (!acl_policy->currentData().toString().isEmpty()
	    && stations->text().trimmed().isEmpty()) {
		note->setText(QStringLiteral("a station list that is empty says something: "
		              "`only these` with nobody on it admits nobody"));
		return;
	}

	QString error;
	const QString name = id->text().trimmed();
	if (!connection->config_put(QStringLiteral("access-point-%1").arg(name), block_text(), true,
	        &error)) {
		note->setText(error);
		return;
	}
	/* **The sentence the example file spends a paragraph on.** hostapd beacons
	 * and stations associate; a station then needs an address, a route and a
	 * resolver, and netcfgd serves no DHCP. An access point whose radio has no
	 * address is one every station associates with and reaches nothing through. */
	summary = QStringLiteral("wrote access-point-%1: give %2 an address in `links` if it "
	              "has none -- stations associate and still need one. Run apply.")
	          .arg(name, device->currentText().trimmed());
	accept();
}

void ncfg_access_point_dialog::remove()
{
	const QString question =
	    QStringLiteral("Delete the access point `%1`?\n\nThe radio stays configured; what "
	               "goes is the network it offers.")
	        .arg(before.id);
	QMessageBox box(QMessageBox::Question, QStringLiteral("netcfgd"), question,
	    QMessageBox::Cancel | QMessageBox::Yes, this);
	box.setDefaultButton(QMessageBox::Cancel);
	if (box.exec() != QMessageBox::Yes) {
		return;
	}

	QString error;
	if (!connection->config_delete(QStringLiteral("access-point-%1").arg(before.id), &error)) {
		note->setText(error);
		return;
	}
	summary = QStringLiteral("removed access-point-%1: netcfgd re-read its configuration. "
	              "Run apply to make the machine match it.")
	          .arg(before.id);
	accept();
}
