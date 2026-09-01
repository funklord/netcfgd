/*
 * rules_view.cpp -- the table described in rules_view.h.
 */
#include "rules_view.h"

#include "ncfg_connection.h"

#include <QHeaderView>
#include <QLabel>
#include <QTableWidget>
#include <QVBoxLayout>

namespace {

const char *const column_titles[] = { "priority", "id", "family", "selector", "action", "table" };
constexpr int column_count = static_cast<int>(sizeof(column_titles) / sizeof(column_titles[0]));

} /* namespace */

ncfg_rules_view::ncfg_rules_view(ncfg_connection *connection, QWidget *parent)
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
	note->setObjectName(QStringLiteral("rules_note"));
	note->setWordWrap(true);
	layout->addWidget(note);
}

void ncfg_rules_view::refresh()
{
	QList<ncfg_rule_row> rows;
	QString error;

	if (!connection->rules(&rows, &error)) {
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
		const ncfg_rule_row &item = rows.at(row);
		const QString cells[column_count] = {
			QString::number(item.priority),
			item.id,
			item.family,
			item.selector,
			item.action,
			item.table,
		};
		for (int column = 0; column < column_count; column++) {
			table->setItem(row, column, new QTableWidgetItem(cells[column]));
		}
	}
	table->resizeColumnsToContents();
	table->horizontalHeader()->setStretchLastSection(true);

	if (rows.isEmpty()) {
		note->setText(QStringLiteral(
		    "No `rule` block in the configuration. A rule sends chosen traffic to a chosen routing table, and is how a VPN or a VRF keeps its routes away from everything else."));
		emit reported(QStringLiteral("no rules configured"));
		return;
	}
	note->setText(QStringLiteral(
	    "The order is the priority: the kernel consults a lower number first. This is the configuration rather than what the kernel has now -- the plan tab is where the difference shows."));
	emit reported(QStringLiteral("%1 rules").arg(rows.size()));
}
