/*
 * devices_view.cpp -- the hardware table described in devices_view.h.
 */
#include "devices_view.h"

#include "hand_written.h"
#include "device_dialog.h"
#include "ncfg_connection.h"
#include "table_view.h"

#include <QPushButton>
#include <QStringList>
#include <QVBoxLayout>

ncfg_devices_view::ncfg_devices_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	/* What it is called, what kind of thing it is, whether the kernel has it,
	 * whether netcfgd manages it, what extra policy it carries, and the two
	 * facts the kernel reports about the adapter itself. */
	QStringList columns;
	columns << QStringLiteral("device") << QStringLiteral("kind")
	        << QStringLiteral("present") << QStringLiteral("managed")
	        << QStringLiteral("policy") << QStringLiteral("mac")
	        << QStringLiteral("mtu");
	table = new ncfg_table_view(columns, QStringLiteral("devices_note"), this);

	configure_button = new QPushButton(QStringLiteral("configure"), this);
	configure_button->setObjectName(QStringLiteral("configure_device"));
	configure_button->setEnabled(false);
	table->add_control(configure_button);
	/* **Where a virtual link is made.** A bridge, a bond, a VLAN, a veth pair:
	 * each is a link netcfgd creates rather than finds, and until this existed
	 * the only way to ask for one was to write the block by hand. */
	new_button = new QPushButton(QStringLiteral("new device..."), this);
	new_button->setObjectName(QStringLiteral("new_device"));
	table->add_control(new_button);
	/* **Where a tunnel is brought up.** An IPsec tunnel's connection is
	 * strongSwan's (0325), and until this the only way to ask for it from
	 * netcfgd was `ncfg tunnel up` in a terminal. The device row is the
	 * tunnel's, so the control is here rather than in a tab of its own. */
	tunnel_up_button = new QPushButton(QStringLiteral("bring up"), this);
	tunnel_up_button->setObjectName(QStringLiteral("tunnel_up"));
	tunnel_up_button->setEnabled(false);
	table->add_control(tunnel_up_button);
	tunnel_down_button = new QPushButton(QStringLiteral("take down"), this);
	tunnel_down_button->setObjectName(QStringLiteral("tunnel_down"));
	tunnel_down_button->setEnabled(false);
	table->add_control(tunnel_down_button);

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);

	connect(configure_button, &QPushButton::clicked, this,
	    &ncfg_devices_view::configure_selected);
	connect(new_button, &QPushButton::clicked, this, &ncfg_devices_view::new_device);
	connect(table, &ncfg_table_view::activated, this,
	    &ncfg_devices_view::configure_selected);
	connect(tunnel_up_button, &QPushButton::clicked, this, &ncfg_devices_view::tunnel_up);
	connect(tunnel_down_button, &QPushButton::clicked, this, &ncfg_devices_view::tunnel_down);
	connect(table, &ncfg_table_view::selection_changed, this,
	    &ncfg_devices_view::selection_changed);
}

void ncfg_devices_view::selection_changed()
{
	configure_button->setEnabled(table->selected_row() >= 0);
	/* By the document's kind, which is what the daemon judges too: a tunnel
	 * the document does not describe has no connection to ask for. */
	const bool tunnel = table->selected_cell(1) == QStringLiteral("xfrm");
	tunnel_up_button->setEnabled(tunnel);
	tunnel_down_button->setEnabled(tunnel);
}

void ncfg_devices_view::tunnel_up()
{
	set_tunnel(true);
}

void ncfg_devices_view::tunnel_down()
{
	set_tunnel(false);
}

void ncfg_devices_view::set_tunnel(bool activate)
{
	const QString name = table->selected_cell(0);
	if (name.isEmpty()) {
		return;
	}
	QString error;
	if (!connection->set_tunnel(name, activate, &error)) {
		/* The daemon's words, which name the device and the reason. */
		emit reported(error);
		return;
	}
	/* Asked, not done: strongSwan brings it up, and the tunnel's addresses
	 * in `links` are what say it is. */
	emit reported(activate
	        ? QStringLiteral("asked strongSwan to bring %1 up").arg(name)
	        : QStringLiteral("asked strongSwan to take %1 down").arg(name));
}

void ncfg_devices_view::refresh()
{
	QString error;
	if (!connection->devices(&rows, &error)) {
		/* The daemon's own words: a refusal names the tier that would have
		 * been needed (0013), and replacing that with "could not load" throws
		 * away the one sentence that says what to do about it. */
		table->show_error(error);
		emit reported(error);
		return;
	}

	QList<QStringList> drawn;
	int described = 0;
	for (const ncfg_device_row &device : rows) {
		QStringList cells;
		cells << device.name;
		/* The document's kind, and `--` where there is no block: the kernel's
		 * own kind belongs to the link and is in the links tab. An empty cell
		 * would read as a value this program failed to fetch. */
		cells << (device.kind.isEmpty() ? QStringLiteral("--") : device.kind);
		cells << (device.present ? QStringLiteral("yes") : QStringLiteral("no"));
		/* **Only for a device the document describes.** Managing is what
		 * netcfgd does unless a block says otherwise, so printing `yes`
		 * against an adapter nobody has configured would claim a decision
		 * nobody made. */
		cells << (!device.configured ? QString()
		        : device.managed     ? QStringLiteral("yes")
		                             : QStringLiteral("no"));
		cells << device.policy;
		cells << device.mac;
		cells << (device.mtu > 0 ? QString::number(device.mtu) : QString());
		drawn << cells;
		if (device.configured) {
			described++;
		}
	}
	table->show_rows(drawn);
	table->set_note(QStringLiteral("%1 device(s), %2 described by the configuration. "
	            "A device is the hardware; what it carries is in `links`.")
	        .arg(drawn.size())
	        .arg(described));
}

void ncfg_devices_view::new_device()
{
	ncfg_device_dialog dialog(connection, QString(), this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	emit reported(dialog.outcome());
	emit changed();
	refresh();
}

void ncfg_devices_view::configure_selected()
{
	const QString name = table->selected_cell(0);
	if (name.isEmpty()) {
		return;
	}

	ncfg_device_dialog dialog(connection, name, this);
	for (const ncfg_device_row &device : rows) {
		if (device.name == name && device.configured &&
		    connection->written_by_hand(QStringLiteral("device-%1").arg(name))) {
			ncfg_show_read_only(&dialog, QStringLiteral("`device %1`").arg(name));
			break;
		}
	}
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	emit reported(dialog.outcome());
	emit changed();
	refresh();
}
