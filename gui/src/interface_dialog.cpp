#include "interface_dialog.h"

#include "ncfg_connection.h"

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

struct choice {
	const char *shown;
	const char *key;
};

/* What an interface may be given. `dhcp` first because it is what a wired port
 * almost always wants, and "none" last because it is the deliberate one. */
const choice addressings[] = {
	{ "DHCP (IPv4)", "dhcp" },
	{ "DHCP and SLAAC (IPv4 and IPv6)", "dhcp+slaac" },
	{ "SLAAC only (IPv6)", "slaac" },
	{ "DHCPv6", "dhcp6" },
	{ "a fixed address", "static" },
	{ "none -- no address on this interface", "null" },
};

/*
 * How netcfgd decides this link works.
 *
 * "carrier only" is named as what it is rather than left as the absence of a
 * setting, because it is the answer that was wrong often enough to need
 * replacing: a cable into a switch with no uplink of its own has carrier and no
 * path. Decision 0119.
 */
const choice detections[] = {
	{ "carrier only -- the cable is plugged in", "" },
	{ "ping a host through this interface", "ping" },
	{ "run a command", "command" },
};

void fill(QComboBox *box, const choice *from, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		box->addItem(QString::fromLatin1(from[i].shown), QString::fromLatin1(from[i].key));
	}
}

bool safe_value(const QString &text)
{
	return !text.contains(QLatin1Char('"')) && !text.contains(QLatin1Char('\\')) &&
	       !text.contains(QLatin1Char('\n'));
}

} // namespace

ncfg_interface_dialog::ncfg_interface_dialog(ncfg_connection *connection, const QString &name,
    QWidget *parent)
    : QDialog(parent), connection(connection), interface(name)
{
	setWindowTitle(QStringLiteral("interface: %1").arg(name));

	auto *layout = new QVBoxLayout(this);
	auto *form = new QFormLayout();

	addressing = new QComboBox(this);
	addressing->setObjectName(QStringLiteral("iface_addressing"));
	fill(addressing, addressings, sizeof(addressings) / sizeof(addressings[0]));
	form->addRow(QStringLiteral("addressing"), addressing);

	static_address = new QLineEdit(this);
	static_address->setObjectName(QStringLiteral("iface_address"));
	static_address->setPlaceholderText(QStringLiteral("192.0.2.10/24"));
	form->addRow(QStringLiteral("address"), static_address);

	gateway = new QLineEdit(this);
	gateway->setObjectName(QStringLiteral("iface_gateway"));
	gateway->setPlaceholderText(QStringLiteral("192.0.2.1 -- optional"));
	form->addRow(QStringLiteral("default via"), gateway);

	preference = new QSpinBox(this);
	preference->setObjectName(QStringLiteral("iface_preference"));
	preference->setRange(0, 4000);
	preference->setSpecialValueText(QStringLiteral("unset"));
	/* Said in the widget, because it is the opposite of a wifi network's
	 * priority and both are settable in this program. */
	preference->setToolTip(QStringLiteral(
	    "Which interface wins when several could carry the default route. LOWER is "
	    "better -- this is how a wired cable takes over from wifi. Note it is the "
	    "opposite way round from a wireless network's priority, where higher wins."));
	form->addRow(QStringLiteral("preference (lower wins)"), preference);

	mtu = new QSpinBox(this);
	mtu->setObjectName(QStringLiteral("iface_mtu"));
	mtu->setRange(0, 65535);
	mtu->setSpecialValueText(QStringLiteral("unset"));
	form->addRow(QStringLiteral("mtu"), mtu);

	detection = new QComboBox(this);
	detection->setObjectName(QStringLiteral("iface_detection"));
	fill(detection, detections, sizeof(detections) / sizeof(detections[0]));
	form->addRow(QStringLiteral("link detection"), detection);

	probe_host = new QLineEdit(this);
	probe_host->setObjectName(QStringLiteral("iface_probe_host"));
	probe_host->setPlaceholderText(QStringLiteral("the gateway, or something beyond it"));
	form->addRow(QStringLiteral("host to ping"), probe_host);

	probe_command = new QLineEdit(this);
	probe_command->setObjectName(QStringLiteral("iface_probe_command"));
	probe_command->setPlaceholderText(QStringLiteral("/usr/bin/curl"));
	form->addRow(QStringLiteral("command"), probe_command);

	probe_args = new QLineEdit(this);
	probe_args->setObjectName(QStringLiteral("iface_probe_args"));
	probe_args->setPlaceholderText(QStringLiteral("-fsS https://example.invalid"));
	form->addRow(QStringLiteral("arguments"), probe_args);

	probe_interval = new QSpinBox(this);
	probe_interval->setRange(0, 3600);
	probe_interval->setSpecialValueText(QStringLiteral("default (30s)"));
	form->addRow(QStringLiteral("interval, seconds"), probe_interval);

	probe_timeout = new QSpinBox(this);
	probe_timeout->setRange(0, 600);
	probe_timeout->setSpecialValueText(QStringLiteral("default (5s)"));
	form->addRow(QStringLiteral("timeout, seconds"), probe_timeout);

	enabled = new QCheckBox(QStringLiteral("configure this interface"), this);
	enabled->setObjectName(QStringLiteral("iface_enabled"));
	enabled->setChecked(true);
	enabled->setToolTip(QStringLiteral(
	    "Unchecked keeps the configuration and leaves the link down."));
	form->addRow(QString(), enabled);

	forwarding = new QCheckBox(QStringLiteral("forward packets through it"), this);
	forwarding->setObjectName(QStringLiteral("iface_forwarding"));
	form->addRow(QString(), forwarding);

	nat = new QCheckBox(QStringLiteral("NAT -- share this uplink with other interfaces"), this);
	nat->setObjectName(QStringLiteral("iface_nat"));
	form->addRow(QString(), nat);

	layout->addLayout(form);

	note = new QLabel(this);
	note->setWordWrap(true);
	note->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(note);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
	save_button = buttons->addButton(QStringLiteral("Save"), QDialogButtonBox::AcceptRole);
	save_button->setObjectName(QStringLiteral("iface_save"));
	layout->addWidget(buttons);

	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(save_button, &QPushButton::clicked, this, &ncfg_interface_dialog::submit);
	connect(addressing, &QComboBox::currentIndexChanged, this,
	    &ncfg_interface_dialog::addressing_changed);
	connect(detection, &QComboBox::currentIndexChanged, this,
	    &ncfg_interface_dialog::detection_changed);

	addressing_changed();
	detection_changed();
}

void ncfg_interface_dialog::addressing_changed()
{
	const bool fixed = addressing->currentData().toString() == QStringLiteral("static");
	auto *form = qobject_cast<QFormLayout *>(layout()->itemAt(0)->layout());
	if (form) {
		form->setRowVisible(static_address, fixed);
		form->setRowVisible(gateway, fixed);
	}
}

void ncfg_interface_dialog::detection_changed()
{
	const QString how = detection->currentData().toString();
	auto *form = qobject_cast<QFormLayout *>(layout()->itemAt(0)->layout());
	if (form) {
		form->setRowVisible(probe_host, how == QStringLiteral("ping"));
		form->setRowVisible(probe_command, how == QStringLiteral("command"));
		form->setRowVisible(probe_args, how == QStringLiteral("command"));
		form->setRowVisible(probe_interval, !how.isEmpty());
		form->setRowVisible(probe_timeout, !how.isEmpty());
	}

	if (how == QStringLiteral("ping")) {
		/* Shown rather than described, because a probe is a program netcfgd
		 * runs as root on an interval and an operator should be able to read
		 * exactly what that is. `-I` is not decoration: netcfgd runs the
		 * command as given and binds nothing, so a probe that did not name
		 * this interface would be answering about whichever one the route
		 * table happened to pick. */
		note->setText(QStringLiteral(
		    "netcfgd will run:  /usr/bin/ping -c 1 -I %1 <host>\n"
		    "A failing probe withholds this interface's routes, exactly as an "
		    "unplugged cable does.")
		          .arg(interface));
	} else if (how.isEmpty()) {
		note->setText(QStringLiteral(
		    "Carrier alone. A cable into a switch that has lost its own uplink has "
		    "carrier and no path, and netcfgd will keep preferring it."));
	} else {
		note->setText(QStringLiteral(
		    "Exit status zero means the link works. It runs as root, on an "
		    "interval, and a probe that cannot be started counts as a failure."));
	}
}

QString ncfg_interface_dialog::block_text() const
{
	QStringList body;

	const QString kind = addressing->currentData().toString();
	if (kind == QStringLiteral("static")) {
		body << QStringLiteral("\tconfig = \"%1\"").arg(static_address->text().trimmed());
		if (!gateway->text().trimmed().isEmpty()) {
			body << QStringLiteral("\troutes = \"default via %1\"")
			        .arg(gateway->text().trimmed());
		}
	} else if (kind == QStringLiteral("dhcp+slaac")) {
		body << QStringLiteral("\tconfig = [\"dhcp\", \"slaac\"]");
	} else {
		body << QStringLiteral("\tconfig = \"%1\"").arg(kind);
	}

	if (preference->value() > 0) {
		body << QStringLiteral("\tpreference = %1").arg(preference->value());
	}
	if (mtu->value() > 0) {
		body << QStringLiteral("\tmtu = %1").arg(mtu->value());
	}
	/* Only when false: enabled is true unless a document says otherwise, and a
	 * block restating every default is one nobody can read for what is
	 * unusual. */
	if (!enabled->isChecked()) {
		body << QStringLiteral("\tenabled = false");
	}
	if (forwarding->isChecked()) {
		body << QStringLiteral("\tforwarding = true");
	}
	if (nat->isChecked()) {
		body << QStringLiteral("\tnat = true");
	}

	const QString how = detection->currentData().toString();
	if (!how.isEmpty()) {
		QString command;
		QString args;
		if (how == QStringLiteral("ping")) {
			command = QStringLiteral("/usr/bin/ping");
			args = QStringLiteral("\"-c\", \"1\", \"-I\", \"%1\", \"%2\"")
			       .arg(interface, probe_host->text().trimmed());
		} else {
			command = probe_command->text().trimmed();
			QStringList each;
			const QStringList given = probe_args->text().split(QLatin1Char(' '),
			    Qt::SkipEmptyParts);
			for (const QString &one : given) {
				each << QStringLiteral("\"%1\"").arg(one);
			}
			args = each.join(QStringLiteral(", "));
		}
		body << QStringLiteral("\tprobe {");
		body << QStringLiteral("\t\tcommand = \"%1\"").arg(command);
		if (!args.isEmpty()) {
			body << QStringLiteral("\t\targs = [%1]").arg(args);
		}
		if (probe_interval->value() > 0) {
			body << QStringLiteral("\t\tinterval = %1").arg(probe_interval->value());
		}
		if (probe_timeout->value() > 0) {
			body << QStringLiteral("\t\ttimeout = %1").arg(probe_timeout->value());
		}
		body << QStringLiteral("\t}");
	}

	QStringList block;
	block << QStringLiteral("# Written by netcfgd's gui. Ordinary netcfgd configuration:");
	block << QStringLiteral("# edit it, diff it, commit it, or delete it.");
	block << QString();
	block << QStringLiteral("interface %1 {").arg(interface);
	block << body;
	block << QStringLiteral("}");
	return block.join(QStringLiteral("\n")) + QStringLiteral("\n");
}

void ncfg_interface_dialog::submit()
{
	const QLineEdit *values[] = { static_address, gateway, probe_host, probe_command,
		probe_args };
	for (const QLineEdit *value : values) {
		if (!safe_value(value->text())) {
			note->setText(QStringLiteral("a value cannot carry a quote, a backslash "
			              "or a newline"));
			return;
		}
	}
	if (addressing->currentData().toString() == QStringLiteral("static") &&
	    static_address->text().trimmed().isEmpty()) {
		note->setText(QStringLiteral("a fixed address needs an address"));
		return;
	}
	if (detection->currentData().toString() == QStringLiteral("ping") &&
	    probe_host->text().trimmed().isEmpty()) {
		note->setText(QStringLiteral("a ping probe needs a host to ping"));
		return;
	}
	if (detection->currentData().toString() == QStringLiteral("command") &&
	    !probe_command->text().trimmed().startsWith(QLatin1Char('/'))) {
		/* The model says the command is absolute, and a relative one would be
		 * resolved against whatever directory netcfgd happens to be in. */
		note->setText(QStringLiteral("a probe command must be an absolute path"));
		return;
	}

	QString error;
	if (!connection->config_put(QStringLiteral("interface-%1").arg(interface), block_text(),
	    true, &error)) {
		note->setText(error);
		return;
	}

	summary = QStringLiteral("wrote interface-%1: netcfgd re-read its configuration. "
	              "Run apply to make the machine match it.")
	          .arg(interface);
	accept();
}
