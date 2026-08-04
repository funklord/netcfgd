/*
 * devices_view.cpp -- the devices table described in devices_view.h.
 */
#include "devices_view.h"

#include "ncfg_connection.h"

#include <QHeaderView>
#include <QTableWidget>
#include <QVBoxLayout>

namespace {

/* The columns, in the order an operator reads them: what it is called, what it
 * is, whether it is working, and what it has. The MAC is last because it is the
 * one nobody looks at first. */
const char *const column_titles[] = { "interface", "kind", "state", "addresses", "mtu", "mac" };
constexpr int column_count = static_cast<int>(sizeof(column_titles) / sizeof(column_titles[0]));

} /* namespace */

ncfg_devices_view::ncfg_devices_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	auto *layout = new QVBoxLayout(this);

	table = new QTableWidget(0, column_count, this);
	QStringList headers;
	for (int i = 0; i < column_count; i++) {
		headers << QString::fromLatin1(column_titles[i]);
	}
	table->setHorizontalHeaderLabels(headers);
	table->verticalHeader()->setVisible(false);
	table->setSelectionBehavior(QAbstractItemView::SelectRows);
	/* Read-only, and that is a statement rather than a shortcut: nothing is
	 * changed by typing into an observation. What this client can change it
	 * changes through plan and apply, where the operator sees the whole
	 * change before any of it happens. */
	table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	table->horizontalHeader()->setStretchLastSection(true);
	layout->addWidget(table);
}

void ncfg_devices_view::refresh()
{
	QList<ncfg_link_row> rows;
	QString error;

	if (!connection->links(&rows, &error)) {
		/* The daemon's own words. A refusal names the tier that would
		 * have been needed (0013), and replacing that with "could not
		 * load" would throw away the one sentence that says what to do
		 * about it. */
		table->setRowCount(0);
		emit reported(error);
		return;
	}

	table->setRowCount(rows.size());
	for (int row = 0; row < rows.size(); row++) {
		const ncfg_link_row &link = rows.at(row);
		const QString cells[column_count] = {
			link.name,
			link.kind,
			link.state,
			link.addresses,
			link.mtu ? QString::number(link.mtu) : QString(),
			link.mac,
		};
		for (int column = 0; column < column_count; column++) {
			table->setItem(row, column, new QTableWidgetItem(cells[column]));
		}
	}
	table->resizeColumnsToContents();
	table->horizontalHeader()->setStretchLastSection(true);

	emit reported(rows.isEmpty() ? QStringLiteral("no interfaces reported")
	                 : QStringLiteral("%1 interfaces").arg(rows.size()));
}
