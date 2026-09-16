/*
 * devices_view.cpp -- the hardware table described in devices_view.h.
 */
#include "devices_view.h"

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

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);

	connect(configure_button, &QPushButton::clicked, this,
	    &ncfg_devices_view::configure_selected);
	connect(table, &ncfg_table_view::activated, this,
	    &ncfg_devices_view::configure_selected);
	connect(table, &ncfg_table_view::selection_changed, this,
	    [this]() { configure_button->setEnabled(table->selected_row() >= 0); });
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

void ncfg_devices_view::configure_selected()
{
	const QString name = table->selected_cell(0);
	if (name.isEmpty()) {
		return;
	}

	ncfg_device_dialog dialog(connection, name, this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	emit reported(dialog.outcome());
	emit changed();
	refresh();
}
