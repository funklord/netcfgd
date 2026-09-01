/*
 * devices_view.cpp -- the devices table described in devices_view.h.
 */
#include "devices_view.h"

#include "interface_dialog.h"
#include "ncfg_connection.h"
#include "table_view.h"

#include <QPushButton>
#include <QStringList>
#include <QVBoxLayout>

ncfg_devices_view::ncfg_devices_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	/* In the order an operator reads them: what it is called, what it is,
	 * whether it is working, and what it has. The MAC is last because it is
	 * the one nobody looks at first. */
	QStringList columns;
	columns << QStringLiteral("interface") << QStringLiteral("kind")
	        << QStringLiteral("state") << QStringLiteral("addresses")
	        << QStringLiteral("mtu") << QStringLiteral("mac");
	table = new ncfg_table_view(columns, QStringLiteral("devices_note"), this);

	configure_button = new QPushButton(QStringLiteral("configure"), this);
	configure_button->setObjectName(QStringLiteral("configure_interface"));
	configure_button->setEnabled(false);
	table->add_control(configure_button);

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);

	connect(configure_button, &QPushButton::clicked, this,
	    &ncfg_devices_view::configure_selected);
	connect(table, &ncfg_table_view::activated, this, &ncfg_devices_view::configure_selected);
	connect(table, &ncfg_table_view::selection_changed, this,
	    [this]() { configure_button->setEnabled(table->selected_row() >= 0); });
}

void ncfg_devices_view::refresh()
{
	QList<ncfg_link_row> found;
	QString error;

	if (!connection->links(&found, &error)) {
		/* The daemon's own words. A refusal names the tier that would have
		 * been needed (0013), and replacing that with "could not load" would
		 * throw away the one sentence that says what to do about it. */
		table->show_error(error);
		emit reported(error);
		return;
	}

	QList<QStringList> rows;
	for (const ncfg_link_row &link : found) {
		QStringList cells;
		cells << link.name;
		cells << link.kind;
		cells << link.state;
		cells << link.addresses;
		cells << (link.mtu ? QString::number(link.mtu) : QString());
		cells << link.mac;
		rows << cells;
	}
	table->show_rows(rows);

	emit reported(rows.isEmpty() ? QStringLiteral("no interfaces reported")
	                 : QStringLiteral("%1 interfaces").arg(rows.size()));
}

void ncfg_devices_view::configure_selected()
{
	/* The name out of the first column, which is where the table puts it. A
	 * row with no name is a row this view did not draw. */
	const QString name = table->selected_cell(0);
	if (name.isEmpty()) {
		return;
	}

	ncfg_interface_dialog dialog(connection, name, this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	emit reported(dialog.outcome());
	emit changed();
}
