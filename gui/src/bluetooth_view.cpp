/*
 * bluetooth_view.cpp -- the table described in bluetooth_view.h.
 */
#include "bluetooth_view.h"

#include "ncfg_connection.h"

#include <QHeaderView>
#include <QLabel>
#include <QTableWidget>
#include <QVBoxLayout>

namespace {

const char *const column_titles[] = { "id", "address", "profile", "autoconnect" };
constexpr int column_count = static_cast<int>(sizeof(column_titles) / sizeof(column_titles[0]));

} /* namespace */

ncfg_bluetooth_view::ncfg_bluetooth_view(ncfg_connection *connection, QWidget *parent)
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
	table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	table->horizontalHeader()->setStretchLastSection(true);
	layout->addWidget(table);

	note = new QLabel(this);
	note->setObjectName(QStringLiteral("bluetooth_note"));
	note->setWordWrap(true);
	layout->addWidget(note);
}

void ncfg_bluetooth_view::refresh()
{
	QList<ncfg_bluetooth_row> rows;
	QString error;

	if (!connection->bluetooth(&rows, &error)) {
		/* The daemon's own words: a refusal names the tier it wanted
		 * (0013), and replacing that with "could not load" throws away
		 * the one sentence that says what to do about it. */
		table->setRowCount(0);
		note->setText(error);
		emit reported(error);
		return;
	}

	table->setRowCount(rows.size());
	for (int row = 0; row < rows.size(); row++) {
		const ncfg_bluetooth_row &item = rows.at(row);
		const QString cells[column_count] = {
			item.id,
			item.address,
			item.profile,
			item.autoconnect ? QStringLiteral("yes") : QStringLiteral("no"),
		};
		for (int column = 0; column < column_count; column++) {
			table->setItem(row, column, new QTableWidgetItem(cells[column]));
		}
	}
	table->resizeColumnsToContents();
	table->horizontalHeader()->setStretchLastSection(true);

	if (rows.isEmpty()) {
		note->setText(QStringLiteral(
		    "No `bluetooth` block in the configuration. A device is declared like a network and netcfgd pairs and connects it."));
		emit reported(QStringLiteral("no devices configured"));
		return;
	}
	note->setText(QStringLiteral(
	    "`autoconnect` is whether netcfgd connects this device without being asked."));
	emit reported(QStringLiteral("%1 devices").arg(rows.size()));
}
