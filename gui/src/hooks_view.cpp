/*
 * hooks_view.cpp -- the table described in hooks_view.h.
 */
#include "hooks_view.h"

#include "ncfg_connection.h"

#include <QHeaderView>
#include <QLabel>
#include <QTableWidget>
#include <QVBoxLayout>

namespace {

const char *const column_titles[] = { "interface", "phase", "path", "runs as", "timeout" };
constexpr int column_count = static_cast<int>(sizeof(column_titles) / sizeof(column_titles[0]));

} /* namespace */

ncfg_hooks_view::ncfg_hooks_view(ncfg_connection *connection, QWidget *parent)
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
	note->setObjectName(QStringLiteral("hooks_note"));
	note->setWordWrap(true);
	layout->addWidget(note);
}

void ncfg_hooks_view::refresh()
{
	QList<ncfg_hook_row> rows;
	QString error;

	if (!connection->hooks(&rows, &error)) {
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
		const ncfg_hook_row &item = rows.at(row);
		const QString cells[column_count] = {
			item.interface,
			item.phase,
			item.path,
			item.run_as.isEmpty() ? QStringLiteral("root (the daemon)") : item.run_as,
			item.timeout ? QString::number(item.timeout) : QString(),
		};
		for (int column = 0; column < column_count; column++) {
			table->setItem(row, column, new QTableWidgetItem(cells[column]));
		}
	}
	table->resizeColumnsToContents();
	table->horizontalHeader()->setStretchLastSection(true);

	if (rows.isEmpty()) {
		note->setText(QStringLiteral(
		    "No interface declares a hook. A hook is a program netcfgd runs at a named moment -- pre_up, up, post_up, lease, carrier, drift and the rest."));
		emit reported(QStringLiteral("no hooks configured"));
		return;
	}
	note->setText(QStringLiteral(
	    "A hook with `root (the daemon)` in `runs as` was given no user and runs privileged. The timeout is when netcfgd kills one that has not finished; blank means the default."));
	emit reported(QStringLiteral("%1 hooks").arg(rows.size()));
}
