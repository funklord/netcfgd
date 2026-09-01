/*
 * bluetooth_view.cpp -- the table described in bluetooth_view.h.
 *
 * The table itself is `ncfg_table_view`, shared with every other list here.
 * What is left is this view's own subject: which columns, and how one row
 * becomes strings.
 */
#include "bluetooth_view.h"

#include "ncfg_connection.h"
#include "table_view.h"

#include <QVBoxLayout>

ncfg_bluetooth_view::ncfg_bluetooth_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	QStringList columns;
	columns << QStringLiteral("id") << QStringLiteral("address") << QStringLiteral("profile") << QStringLiteral("autoconnect");
	table = new ncfg_table_view(columns, QStringLiteral("bluetooth_note"), this);

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);
}

void ncfg_bluetooth_view::refresh()
{
	QList<ncfg_bluetooth_row> found;
	QString error;

	if (!connection->bluetooth(&found, &error)) {
		table->show_error(error);
		emit reported(error);
		return;
	}

	QList<QStringList> rows;
	for (const ncfg_bluetooth_row &item : found) {
		QStringList cells;
		cells << item.id;
		cells << item.address;
		cells << item.profile;
		cells << (item.autoconnect ? QStringLiteral("yes") : QStringLiteral("no"));
		rows << cells;
	}
	table->show_rows(rows);

	if (rows.isEmpty()) {
		table->set_note(QStringLiteral(
		    "No `bluetooth` block in the configuration. A device is declared like a "
		    "network and netcfgd pairs and connects it."));
		emit reported(QStringLiteral("no devices configured"));
		return;
	}
	table->set_note(QStringLiteral(
	    "`autoconnect` is whether netcfgd connects this device without being asked."));
	emit reported(QStringLiteral("%1 devices").arg(rows.size()));
}
