/*
 * device_dialog.cpp -- the hardware editor described in device_dialog.h.
 *
 * Two things live here and only one is the window. The other is
 * `ncfg_device_block`, which turns a set of answers into the configuration
 * netcfgd compiles, and it is a free function because the ways it can be
 * wrong -- a default written as though it had been chosen, an `ethtool` or
 * `wifi` block emitted empty -- are invisible in a screenshot and checkable
 * without a daemon.
 */
#include "device_dialog.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

namespace {

struct choice {
	const char *shown;
	const char *key;
};

/* Three values, not two: "leave this one alone" is a different instruction
 * from "turn it off", and a checkbox could not say it. */
const choice toggles[] = {
	{ "leave alone", "unmanaged" },
	{ "on", "on" },
	{ "off", "off" },
};

const choice unmanages[] = {
	{ "leave -- change nothing on the way out", "leave" },
	{ "clear -- remove what netcfgd owns first", "clear" },
};

const choice duplexes[] = {
	{ "leave alone", "" },
	{ "full", "full" },
	{ "half", "half" },
};

/* Wake-on-LAN, as ethtool spells it. `g` -- wake on a magic packet -- is the
 * one anybody means; the rest are here because a NIC that was set to one of
 * them should not have it silently rewritten. */
const choice wols[] = {
	{ "leave alone", "" },
	{ "g -- magic packet", "g" },
	{ "d -- disabled", "d" },
	{ "p -- physical activity", "p" },
	{ "u -- unicast", "u" },
	{ "b -- broadcast", "b" },
	{ "m -- multicast", "m" },
	{ "a -- ARP", "a" },
};

const choice backends[] = {
	{ "auto", "auto" },
	{ "wpa_supplicant", "wpa_supplicant" },
	{ "iwd", "iwd" },
};

const choice powersaves[] = {
	{ "the driver's default", "default" },
	{ "on", "on" },
	{ "off", "off" },
};

/* What address the radio uses once it has joined something. The wording is the
 * example file's, because an operator who has read one should recognise the
 * other. */
const choice mac_policies[] = {
	{ "permanent -- the hardware address", "permanent" },
	{ "per network -- a fresh address per network", "per_network" },
	{ "per connection -- a fresh address every time", "per_connection" },
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

/* A value going into a quoted string in the config language. Refused rather
 * than escaped, as every other editor here refuses it: a quote or a backslash
 * in a country code or a MAC is a mistake, not a name. */
bool safe_value(const QString &text)
{
	return !text.contains(QLatin1Char('"')) && !text.contains(QLatin1Char('\\')) &&
	       !text.contains(QLatin1Char('\n'));
}

const char *toggle_word(int value)
{
	switch (value) {
	case 1:
		return "on";
	case 2:
		return "off";
	default:
		return "unmanaged";
	}
}

int toggle_value(const QComboBox *box)
{
	const QString key = box->currentData().toString();
	if (key == QLatin1String("on")) {
		return 1;
	}
	if (key == QLatin1String("off")) {
		return 2;
	}
	return 0;
}

} // namespace

QString ncfg_device_block(const QString &name, const ncfg_device_config &settings)
{
	QStringList body;

	/* **Only what is not the default.** A block that restated every default
	 * would be a block nobody can read for what is unusual -- and `managed`
	 * is true unless somebody says otherwise, so writing `managed = true`
	 * everywhere would bury the one device where it matters. */
	if (!settings.managed) {
		body << QStringLiteral("\tmanaged = false");
		if (!settings.on_unmanage.isEmpty() && settings.on_unmanage != QLatin1String("leave")) {
			body << QStringLiteral("\ton_unmanage = \"%1\"").arg(settings.on_unmanage);
		}
	}
	if (settings.mtu > 0) {
		body << QStringLiteral("\tmtu = %1").arg(settings.mtu);
	}
	if (!settings.mac.isEmpty()) {
		body << QStringLiteral("\tmac = \"%1\"").arg(settings.mac);
	}

	QStringList ethtool;
	const struct {
		const char *key;
		int         value;
	} switches[] = {
		{ "autoneg", settings.autoneg }, { "gro", settings.gro },
		{ "gso", settings.gso },         { "tso", settings.tso },
		{ "rx_checksum", settings.rx_checksum },
		{ "tx_checksum", settings.tx_checksum },
	};
	for (const auto &one : switches) {
		if (one.value != 0) {
			ethtool << QStringLiteral("\t\t%1 = \"%2\"")
			           .arg(QString::fromLatin1(one.key),
			               QString::fromLatin1(toggle_word(one.value)));
		}
	}
	if (settings.speed > 0) {
		ethtool << QStringLiteral("\t\tspeed = %1").arg(settings.speed);
	}
	if (!settings.duplex.isEmpty()) {
		ethtool << QStringLiteral("\t\tduplex = \"%1\"").arg(settings.duplex);
	}
	if (!settings.wol.isEmpty()) {
		ethtool << QStringLiteral("\t\twol = \"%1\"").arg(settings.wol);
	}
	if (settings.rx_ring > 0) {
		ethtool << QStringLiteral("\t\trx_ring = %1").arg(settings.rx_ring);
	}
	if (settings.tx_ring > 0) {
		ethtool << QStringLiteral("\t\ttx_ring = %1").arg(settings.tx_ring);
	}
	/* An empty `ethtool { }` is not the same as no block: it compiles to a
	 * settings object, and netcfgd then has an opinion about a NIC nobody
	 * asked it to touch. */
	if (!ethtool.isEmpty()) {
		body << QStringLiteral("\tethtool {");
		body << ethtool;
		body << QStringLiteral("\t}");
	}

	if (settings.has_wifi) {
		body << QStringLiteral("\twifi {");
		body << QStringLiteral("\t\tbackend = \"%1\"")
		        .arg(settings.wifi_backend.isEmpty() ? QStringLiteral("auto")
		                                             : settings.wifi_backend);
		body << QStringLiteral("\t\tautoconnect = %1")
		        .arg(settings.wifi_autoconnect ? QStringLiteral("true")
		                                       : QStringLiteral("false"));
		if (!settings.powersave.isEmpty() && settings.powersave != QLatin1String("default")) {
			body << QStringLiteral("\t\tpowersave = \"%1\"").arg(settings.powersave);
		}
		if (!settings.mac_policy.isEmpty()
		    && settings.mac_policy != QLatin1String("permanent")) {
			body << QStringLiteral("\t\tmac_policy = \"%1\"").arg(settings.mac_policy);
		}
		if (settings.scan_randomization) {
			body << QStringLiteral("\t\tscan_randomization = true");
		}
		if (!settings.regdom.isEmpty()) {
			body << QStringLiteral("\t\tregdom = \"%1\"").arg(settings.regdom);
		}
		if (!settings.portal_check.isEmpty()) {
			body << QStringLiteral("\t\tportal_check = \"%1\"").arg(settings.portal_check);
		}
		body << QStringLiteral("\t}");
	}

	if (settings.has_modem) {
		body << QStringLiteral("\tmodem {");
		const QStringList wanted =
		    settings.sim.split(QLatin1Char(' '), Qt::SkipEmptyParts);
		if (!wanted.isEmpty()) {
			QStringList quoted;
			for (const QString &one : wanted) {
				quoted << QStringLiteral("\"%1\"").arg(one);
			}
			body << QStringLiteral("\t\tsim = [%1]").arg(quoted.join(QStringLiteral(", ")));
		}
		if (!settings.apn.isEmpty()) {
			body << QStringLiteral("\t\tapn = \"%1\"").arg(settings.apn);
		}
		body << QStringLiteral("\t}");
	}

	QStringList block;
	block << QStringLiteral("# Written by netcfgd's gui. Ordinary netcfgd configuration:");
	block << QStringLiteral("# edit it, diff it, commit it, or delete it.");
	block << QString();
	block << QStringLiteral("device %1 {").arg(name);
	block << body;
	block << QStringLiteral("}");
	return block.join(QStringLiteral("\n")) + QStringLiteral("\n");
}

ncfg_device_dialog::ncfg_device_dialog(ncfg_connection *connection, const QString &name,
    QWidget *parent)
    : QDialog(parent), connection(connection), device(name)
{
	setWindowTitle(QStringLiteral("device: %1").arg(name));
	setObjectName(QStringLiteral("device_dialog"));

	auto *layout = new QVBoxLayout(this);
	auto *form = new QFormLayout();

	managed = new QCheckBox(QStringLiteral("netcfgd configures this device"), this);
	managed->setObjectName(QStringLiteral("device_managed"));
	managed->setChecked(true);
	managed->setToolTip(QStringLiteral(
	    "Unchecked hands the device to whatever else is on this machine. netcfgd "
	    "plans nothing for it and reports it as somebody else's."));
	form->addRow(QString(), managed);

	on_unmanage = new QComboBox(this);
	on_unmanage->setObjectName(QStringLiteral("device_on_unmanage"));
	fill(on_unmanage, unmanages, sizeof(unmanages) / sizeof(unmanages[0]));
	form->addRow(QStringLiteral("on handing it over"), on_unmanage);

	mtu = new QSpinBox(this);
	mtu->setObjectName(QStringLiteral("device_mtu"));
	mtu->setRange(0, 65535);
	mtu->setSpecialValueText(QStringLiteral("unset"));
	form->addRow(QStringLiteral("mtu"), mtu);

	mac = new QLineEdit(this);
	mac->setObjectName(QStringLiteral("device_mac"));
	mac->setPlaceholderText(QStringLiteral("02:00:00:00:00:01 -- blank keeps the "
	            "hardware's"));
	form->addRow(QStringLiteral("mac address"), mac);
	layout->addLayout(form);

	auto *ethtool_box = new QGroupBox(QStringLiteral("link settings and offloads"), this);
	ethtool_box->setObjectName(QStringLiteral("device_ethtool"));
	auto *ethtool = new QFormLayout(ethtool_box);
	autoneg = new QComboBox(this);
	autoneg->setObjectName(QStringLiteral("device_autoneg"));
	fill(autoneg, toggles, sizeof(toggles) / sizeof(toggles[0]));
	ethtool->addRow(QStringLiteral("autonegotiation"), autoneg);
	speed = new QSpinBox(this);
	speed->setObjectName(QStringLiteral("device_speed"));
	speed->setRange(0, 400000);
	speed->setSpecialValueText(QStringLiteral("unset"));
	ethtool->addRow(QStringLiteral("speed, Mbit/s"), speed);
	duplex = new QComboBox(this);
	duplex->setObjectName(QStringLiteral("device_duplex"));
	fill(duplex, duplexes, sizeof(duplexes) / sizeof(duplexes[0]));
	ethtool->addRow(QStringLiteral("duplex"), duplex);
	wol = new QComboBox(this);
	wol->setObjectName(QStringLiteral("device_wol"));
	fill(wol, wols, sizeof(wols) / sizeof(wols[0]));
	ethtool->addRow(QStringLiteral("wake on lan"), wol);
	rx_ring = new QSpinBox(this);
	rx_ring->setObjectName(QStringLiteral("device_rx_ring"));
	rx_ring->setRange(0, 65535);
	rx_ring->setSpecialValueText(QStringLiteral("unset"));
	ethtool->addRow(QStringLiteral("rx ring"), rx_ring);
	tx_ring = new QSpinBox(this);
	tx_ring->setObjectName(QStringLiteral("device_tx_ring"));
	tx_ring->setRange(0, 65535);
	tx_ring->setSpecialValueText(QStringLiteral("unset"));
	ethtool->addRow(QStringLiteral("tx ring"), tx_ring);
	const struct {
		QComboBox **box;
		const char *name;
		const char *shown;
	} offloads[] = {
		{ &gro, "device_gro", "generic receive offload" },
		{ &gso, "device_gso", "generic segmentation offload" },
		{ &tso, "device_tso", "tcp segmentation offload" },
		{ &rx_checksum, "device_rx_checksum", "receive checksums" },
		{ &tx_checksum, "device_tx_checksum", "transmit checksums" },
	};
	for (const auto &one : offloads) {
		*one.box = new QComboBox(this);
		(*one.box)->setObjectName(QString::fromLatin1(one.name));
		fill(*one.box, toggles, sizeof(toggles) / sizeof(toggles[0]));
		ethtool->addRow(QString::fromLatin1(one.shown), *one.box);
	}
	layout->addWidget(ethtool_box);

	wifi_box = new QGroupBox(QStringLiteral("radio"), this);
	wifi_box->setObjectName(QStringLiteral("device_wifi"));
	auto *radio = new QFormLayout(wifi_box);
	wifi_backend = new QComboBox(this);
	wifi_backend->setObjectName(QStringLiteral("device_wifi_backend"));
	fill(wifi_backend, backends, sizeof(backends) / sizeof(backends[0]));
	radio->addRow(QStringLiteral("driven by"), wifi_backend);
	wifi_autoconnect = new QCheckBox(QStringLiteral("join known networks by itself"), this);
	wifi_autoconnect->setObjectName(QStringLiteral("device_wifi_autoconnect"));
	wifi_autoconnect->setChecked(true);
	radio->addRow(QString(), wifi_autoconnect);
	powersave = new QComboBox(this);
	powersave->setObjectName(QStringLiteral("device_powersave"));
	fill(powersave, powersaves, sizeof(powersaves) / sizeof(powersaves[0]));
	radio->addRow(QStringLiteral("power saving"), powersave);
	mac_policy = new QComboBox(this);
	mac_policy->setObjectName(QStringLiteral("device_mac_policy"));
	fill(mac_policy, mac_policies, sizeof(mac_policies) / sizeof(mac_policies[0]));
	radio->addRow(QStringLiteral("address once joined"), mac_policy);
	scan_randomization =
	    new QCheckBox(QStringLiteral("randomise the address in probe requests"), this);
	scan_randomization->setObjectName(QStringLiteral("device_scan_randomization"));
	scan_randomization->setToolTip(QStringLiteral(
	    "Probe requests are broadcast to everyone in range whether or not anything "
	    "is joined. Without this a laptop announces one address to every receiver "
	    "it passes."));
	radio->addRow(QString(), scan_randomization);
	regdom = new QLineEdit(this);
	regdom->setObjectName(QStringLiteral("device_regdom"));
	regdom->setPlaceholderText(QStringLiteral("SE -- the country the radio is in"));
	radio->addRow(QStringLiteral("regulatory domain"), regdom);
	portal_check = new QLineEdit(this);
	portal_check->setObjectName(QStringLiteral("device_portal_check"));
	portal_check->setPlaceholderText(QStringLiteral("http://example.com/generate_204"));
	radio->addRow(QStringLiteral("captive portal check"), portal_check);
	layout->addWidget(wifi_box);

	modem_box = new QGroupBox(QStringLiteral("modem"), this);
	modem_box->setObjectName(QStringLiteral("device_modem"));
	auto *cellular = new QFormLayout(modem_box);
	sim = new QLineEdit(this);
	sim->setObjectName(QStringLiteral("device_sim"));
	sim->setPlaceholderText(QStringLiteral("esim socket -- the sources, in order"));
	cellular->addRow(QStringLiteral("sim sources"), sim);
	apn = new QLineEdit(this);
	apn->setObjectName(QStringLiteral("device_apn"));
	cellular->addRow(QStringLiteral("apn"), apn);
	layout->addWidget(modem_box);

	note = new QLabel(this);
	note->setObjectName(QStringLiteral("device_note"));
	note->setWordWrap(true);
	note->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(note);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
	save_button = buttons->addButton(QStringLiteral("Save"), QDialogButtonBox::AcceptRole);
	save_button->setObjectName(QStringLiteral("device_save"));
	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(save_button, &QPushButton::clicked, this, &ncfg_device_dialog::submit);
	layout->addWidget(buttons);
	resize(560, 640);

	load();
}

void ncfg_device_dialog::load()
{
	QString error;
	if (!connection->device_config(device, &existing, &error)) {
		/* No daemon, or it would not answer. The form stays at its defaults
		 * and `submit` refuses, because what is on the machine is unknown and
		 * overwriting it is not something to do quietly -- the interface
		 * editor's rule, and it is here for the same reason. */
		unknown = true;
		note->setText(error);
		return;
	}

	managed->setChecked(existing.managed);
	select(on_unmanage, existing.on_unmanage.isEmpty() ? QStringLiteral("leave")
	                                                   : existing.on_unmanage);
	mtu->setValue(existing.mtu);
	mac->setText(existing.mac);

	const struct {
		QComboBox *box;
		int        value;
	} switches[] = {
		{ autoneg, existing.autoneg },
		{ gro, existing.gro },
		{ gso, existing.gso },
		{ tso, existing.tso },
		{ rx_checksum, existing.rx_checksum },
		{ tx_checksum, existing.tx_checksum },
	};
	for (const auto &one : switches) {
		select(one.box, QString::fromLatin1(toggle_word(one.value)));
	}
	speed->setValue(existing.speed);
	select(duplex, existing.duplex);
	select(wol, existing.wol);
	rx_ring->setValue(existing.rx_ring);
	tx_ring->setValue(existing.tx_ring);

	/* **Shown only where the device has one.** A `wifi` block on a wired card
	 * compiles and means nothing, and a form that offered it would invite
	 * writing one. The daemon's answer decides, not a guess from the name. */
	wifi_box->setVisible(existing.has_wifi);
	if (existing.has_wifi) {
		select(wifi_backend, existing.wifi_backend);
		wifi_autoconnect->setChecked(existing.wifi_autoconnect);
		select(powersave, existing.powersave);
		select(mac_policy, existing.mac_policy);
		scan_randomization->setChecked(existing.scan_randomization);
		regdom->setText(existing.regdom);
		portal_check->setText(existing.portal_check);
	}
	modem_box->setVisible(existing.has_modem);
	if (existing.has_modem) {
		sim->setText(existing.sim);
		apn->setText(existing.apn);
	}

	if (!existing.unmodelled.isEmpty()) {
		note->setText(QStringLiteral(
		    "this device's configuration carries %1, which this dialog has no field "
		    "for -- saving would delete it. Edit the file instead: "
		    "`ncfg config edit device-%2`.")
		        .arg(existing.unmodelled, device));
		save_button->setEnabled(false);
	} else if (!existing.present) {
		note->setText(QStringLiteral("netcfgd has no `device` block for %1 yet. Saving "
		              "writes one; what is not set here stays unset.")
		          .arg(device));
	}
}

QString ncfg_device_dialog::block_text() const
{
	ncfg_device_config settings;
	settings.managed = managed->isChecked();
	settings.on_unmanage = on_unmanage->currentData().toString();
	settings.mtu = mtu->value();
	settings.mac = mac->text().trimmed();
	settings.autoneg = toggle_value(autoneg);
	settings.speed = speed->value();
	settings.duplex = duplex->currentData().toString();
	settings.wol = wol->currentData().toString();
	settings.rx_ring = rx_ring->value();
	settings.tx_ring = tx_ring->value();
	settings.gro = toggle_value(gro);
	settings.gso = toggle_value(gso);
	settings.tso = toggle_value(tso);
	settings.rx_checksum = toggle_value(rx_checksum);
	settings.tx_checksum = toggle_value(tx_checksum);
	/* The radio and modem halves are written only where the device had them:
	 * this dialog edits a policy, it does not decide that a wired card has a
	 * radio. */
	settings.has_wifi = existing.has_wifi;
	settings.wifi_backend = wifi_backend->currentData().toString();
	settings.wifi_autoconnect = wifi_autoconnect->isChecked();
	settings.powersave = powersave->currentData().toString();
	settings.mac_policy = mac_policy->currentData().toString();
	settings.scan_randomization = scan_randomization->isChecked();
	settings.regdom = regdom->text().trimmed();
	settings.portal_check = portal_check->text().trimmed();
	settings.has_modem = existing.has_modem;
	settings.sim = sim->text().trimmed();
	settings.apn = apn->text().trimmed();
	return ncfg_device_block(device, settings);
}

void ncfg_device_dialog::submit()
{
	const QLineEdit *values[] = { mac, regdom, portal_check, sim, apn };
	for (const QLineEdit *value : values) {
		if (!safe_value(value->text())) {
			note->setText(QStringLiteral("a value cannot carry a quote, a backslash "
			              "or a newline"));
			return;
		}
	}
	if (unknown) {
		note->setText(QStringLiteral(
		    "netcfgd could not say how this device is configured, so saving would "
		    "overwrite something unknown. Check the daemon is running."));
		return;
	}
	if (!existing.unmodelled.isEmpty()) {
		note->setText(QStringLiteral(
		    "this device's configuration carries %1, which this dialog has no field "
		    "for -- saving would delete it.")
		        .arg(existing.unmodelled));
		return;
	}
	if (!regdom->text().trimmed().isEmpty() && regdom->text().trimmed().size() != 2) {
		/* The compiler says the same thing; saying it here costs one round
		 * trip less and puts the sentence beside the field it is about. */
		note->setText(QStringLiteral("a regulatory domain is a two-letter country code, "
		              "such as SE or US"));
		return;
	}

	QString error;
	if (!connection->config_put(QStringLiteral("device-%1").arg(device), block_text(), true,
	        &error)) {
		note->setText(error);
		return;
	}
	summary = QStringLiteral("wrote device-%1: netcfgd re-read its configuration. "
	              "Run apply to make the machine match it.")
	          .arg(device);
	accept();
}
