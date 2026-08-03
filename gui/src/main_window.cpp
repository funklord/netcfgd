/*
 * main_window.cpp -- the devices table, and the two things beside it.
 */
#include "main_window.h"

#include "ncfg_connection.h"

#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QStatusBar>
#include <QTableWidget>
#include <QToolBar>
#include <QVBoxLayout>
#include <QWidget>

namespace {

/* The columns, in the order an operator reads them: what it is called, what it
 * is, whether it is working, and what it has. The MAC is last because it is the
 * one nobody looks at first. */
const char *const column_titles[] = { "interface", "kind", "state", "addresses", "mtu", "mac" };
constexpr int column_count = static_cast<int>(sizeof(column_titles) / sizeof(column_titles[0]));

} /* namespace */

ncfg_main_window::ncfg_main_window(ncfg_connection *connection, QWidget *parent)
	: QMainWindow(parent), connection(connection)
{
	setWindowTitle(QStringLiteral("netcfgd"));

	auto *central = new QWidget(this);
	auto *layout = new QVBoxLayout(central);

	/* Which machine this is, on screen and not in a menu. A client that can
	 * configure a router across the room must never leave the operator
	 * unsure whose network they are about to change. */
	where = new QLabel(central);
	where->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(where);

	table = new QTableWidget(0, column_count, central);
	QStringList headers;
	for (int i = 0; i < column_count; i++) {
		headers << QString::fromLatin1(column_titles[i]);
	}
	table->setHorizontalHeaderLabels(headers);
	table->verticalHeader()->setVisible(false);
	table->setSelectionBehavior(QAbstractItemView::SelectRows);
	/* Read-only, and that is a statement rather than a shortcut: this client
	 * has no write path yet, and a table that looked editable would promise
	 * one. */
	table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	table->horizontalHeader()->setStretchLastSection(true);
	layout->addWidget(table);

	setCentralWidget(central);

	auto *tools = addToolBar(QStringLiteral("main"));
	auto *refresh_button = new QPushButton(QStringLiteral("Refresh"), tools);
	connect(refresh_button, &QPushButton::clicked, this, &ncfg_main_window::refresh);
	tools->addWidget(refresh_button);

	status = new QLabel(this);
	statusBar()->addWidget(status);

	resize(760, 420);
	refresh();
}

void ncfg_main_window::refresh()
{
	where->setText(QStringLiteral("netcfgd at %1").arg(connection->where()));

	QList<ncfg_link_row> rows;
	QString error;
	if (!connection->links(&rows, &error)) {
		/* The daemon's own words. A refusal names the tier that would
		 * have been needed (0013), and replacing that with "could not
		 * load" would throw away the one sentence that says what to do
		 * about it. */
		status->setText(error);
		table->setRowCount(0);
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

	status->setText(rows.isEmpty() ? QStringLiteral("no interfaces reported")
				       : QStringLiteral("%1 interfaces").arg(rows.size()));
}
