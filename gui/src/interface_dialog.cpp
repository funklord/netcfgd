#include "interface_dialog.h"

#include "probe_dialog.h"

#include "ncfg_connection.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QFileInfo>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
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
 *
 * The rest of the list is **read off the disk**, not written here. A probe is
 * a shell script that exits zero when the link works, so the set of them is a
 * directory listing -- which means this dialog, `ncfg` and any other front end
 * offer the same set without anyone keeping three lists in step.
 */
const choice detections[] = {
	{ "carrier only -- the cable is plugged in", "" },
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
	 * metric and both are settable in this program -- and since 0154 they are
	 * the same scale, so this no longer has to warn about a second one. */
	preference->setToolTip(QStringLiteral(
	    "Which interface wins when several could carry the default route. LOWER is "
	    "better -- this is how a wired cable takes over from wifi. Note it is the "
	    "same scale as a wireless network's metric, so the two compare directly."));
	form->addRow(QStringLiteral("preference (lower wins)"), preference);

	mtu = new QSpinBox(this);
	mtu->setObjectName(QStringLiteral("iface_mtu"));
	mtu->setRange(0, 65535);
	mtu->setSpecialValueText(QStringLiteral("unset"));
	form->addRow(QStringLiteral("mtu"), mtu);

	detection = new QComboBox(this);
	detection->setObjectName(QStringLiteral("iface_detection"));
	reload_detections(QString());

	/* The list, and the two things an operator does with it. `view / edit`
	 * because a probe is a shell script and reading the one that is judging
	 * your link is the first thing anybody wants; `new` because writing one
	 * should not mean leaving the program. */
	auto *detection_row = new QHBoxLayout();
	detection_row->addWidget(detection, 1);
	edit_detection_button = new QPushButton(QStringLiteral("view / edit"), this);
	edit_detection_button->setObjectName(QStringLiteral("iface_edit_probe"));
	detection_row->addWidget(edit_detection_button);
	auto *new_probe = new QPushButton(QStringLiteral("new"), this);
	new_probe->setObjectName(QStringLiteral("iface_new_probe"));
	detection_row->addWidget(new_probe);
	form->addRow(QStringLiteral("link detection"), detection_row);

	connect(edit_detection_button, &QPushButton::clicked, this,
	    &ncfg_interface_dialog::edit_detection);
	/* `this->connection`, because the constructor's parameter of that name
	 * shadows the member here and a lambda cannot capture a parameter it was
	 * not told about. */
	connect(new_probe, &QPushButton::clicked, this, [this]() {
		ncfg_probe_dialog dialog(this->connection, ncfg_probe_row(), this);
		if (dialog.exec() == QDialog::Accepted) {
			reload_detections(dialog.written_name());
			note->setText(dialog.outcome());
		}
	});

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

/*
 * The scripts on disk, rebuilt.
 *
 * A method rather than constructor code because the editor can create one, and
 * a list read before that script existed would not contain it -- which reads as
 * the save having failed.
 *
 * Inserted before "run a command" so the escape hatch stays last, and keyed by
 * absolute path because that is what gets written: the model requires an
 * absolute command, and a name resolved later could resolve to something else.
 * A name seen in /etc wins over the same name in /usr/share, so an operator who
 * copied an example and edited it gets theirs.
 */
void ncfg_interface_dialog::reload_detections(const QString &select)
{
	const QString had = select.isEmpty() ? detection->currentData().toString() : QString();
	detection->clear();
	fill(detection, detections, sizeof(detections) / sizeof(detections[0]));

	/*
	 * **Asked of the daemon, not read off this machine.** A client only ever
	 * talks to netcfgd, and these files belong to the machine netcfgd runs on.
	 * Listing the local /etc would show the operator's own laptop while
	 * configuring a remote one -- and the editor would then save an edit of
	 * one machine's script onto another.
	 *
	 * The daemon has already resolved the shadowing, so each name appears once
	 * and is the one netcfgd would run.
	 */
	QString error;
	scripts.clear();
	if (!connection->probes(&scripts, &error)) {
		/* Not fatal: the rest of the dialog works, and carrier-only and a
		 * hand-written command are both still reachable. */
		note->setText(error);
	}

	for (const ncfg_probe_row &script : scripts) {
		/* Keyed by absolute path, which is what gets written: the model
		 * requires an absolute command, and a name resolved later could
		 * resolve to something else. */
		detection->insertItem(detection->count() - 1,
		    QStringLiteral("%1 -- %2").arg(script.name, script.directory),
		    QStringLiteral("%1/%2").arg(script.directory, script.name));
	}

	QString chosen;
	if (!select.isEmpty()) {
		for (const ncfg_probe_row &script : scripts) {
			if (script.name == select) {
				chosen = QStringLiteral("%1/%2").arg(script.directory, script.name);
				break;
			}
		}
	}
	const QString want = chosen.isEmpty() ? had : chosen;
	const int at = detection->findData(want);
	if (at >= 0) {
		detection->setCurrentIndex(at);
	}
}

void ncfg_interface_dialog::edit_detection()
{
	const QString chosen = detection->currentData().toString();
	/* Only a script can be opened. "Carrier only" is not a program, and "run a
	 * command" names one this dialog did not put there and does not own. */
	if (chosen.isEmpty() || chosen == QStringLiteral("command")) {
		note->setText(QStringLiteral(
		    "choose a script to view it. `run a command` names a program this dialog "
		    "did not write, so there is nothing here to open."));
		return;
	}

	/* The text is already in hand from the listing, so the editor is given it
	 * rather than a path to open: reading the file here would be the same
	 * mistake in the other direction. */
	ncfg_probe_row opening;
	for (const ncfg_probe_row &script : scripts) {
		if (QStringLiteral("%1/%2").arg(script.directory, script.name) == chosen) {
			opening = script;
			break;
		}
	}
	ncfg_probe_dialog dialog(connection, opening, this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	/* An edit of a shipped example is saved as a copy in /etc, so the list has
	 * gained an entry and the selection should follow it there. */
	reload_detections(dialog.written_name());
	note->setText(dialog.outcome());
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
	const bool custom = how == QStringLiteral("command");
	auto *form = qobject_cast<QFormLayout *>(layout()->itemAt(0)->layout());
	if (form) {
		form->setRowVisible(probe_command, custom);
		form->setRowVisible(probe_args, custom);
		form->setRowVisible(probe_interval, !how.isEmpty());
		form->setRowVisible(probe_timeout, !how.isEmpty());
	}

	if (how.isEmpty()) {
		note->setText(QStringLiteral(
		    "Carrier alone. A cable into a switch that has lost its own uplink has "
		    "carrier and no path, and netcfgd will keep preferring it."));
	} else if (custom) {
		note->setText(QStringLiteral(
		    "Exit status zero means the link works. It runs as root, on an "
		    "interval, and what it prints on standard error is shown here and in "
		    "`ncfg status`. Do not background anything: netcfgd kills the process "
		    "it started, and a child left running outlives it."));
	} else {
		/* The exact command line, because a probe is a program netcfgd runs as
		 * root on an interval and an operator should be able to read what that
		 * is rather than trust a friendly word for it. The interface is passed
		 * as an argument because netcfgd binds nothing: a script that did not
		 * take it would answer about whichever interface the route table
		 * happened to pick. */
		note->setText(QStringLiteral(
		    "netcfgd will run:  %1 %2\n"
		    "Exit zero means the link works. A failing probe withholds this "
		    "interface's routes, exactly as an unplugged cable does -- and what "
		    "the script prints on standard error is shown as the reason. It is an "
		    "ordinary shell script: copy it into /etc/netcfgd/probe and edit it.")
		          .arg(how, interface));
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
		if (how != QStringLiteral("command")) {
			/* A script from the list. The interface is its only argument, and
			 * it is not optional: netcfgd runs the command as given and binds
			 * nothing. */
			command = how;
			args = QStringLiteral("\"%1\"").arg(interface);
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
	const QLineEdit *values[] = { static_address, gateway, probe_command, probe_args };
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
