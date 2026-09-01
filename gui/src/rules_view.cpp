/*
 * rules_view.cpp -- the table described in rules_view.h.
 *
 * The table itself is `ncfg_table_view`, shared with every other list here.
 * What is left is this view's own subject: which columns, and how one row
 * becomes strings.
 */
#include "rules_view.h"

#include "ncfg_connection.h"
#include "table_view.h"

#include <QVBoxLayout>

ncfg_rules_view::ncfg_rules_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	QStringList columns;
	columns << QStringLiteral("priority") << QStringLiteral("id") << QStringLiteral("family") << QStringLiteral("selector") << QStringLiteral("action") << QStringLiteral("table");
	table = new ncfg_table_view(columns, QStringLiteral("rules_note"), this);

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);
}

void ncfg_rules_view::refresh()
{
	QList<ncfg_rule_row> found;
	QString error;

	if (!connection->rules(&found, &error)) {
		table->show_error(error);
		emit reported(error);
		return;
	}

	QList<QStringList> rows;
	for (const ncfg_rule_row &item : found) {
		QStringList cells;
		cells << QString::number(item.priority);
		cells << item.id;
		cells << item.family;
		cells << item.selector;
		cells << item.action;
		cells << item.table;
		rows << cells;
	}
	table->show_rows(rows);

	if (rows.isEmpty()) {
		table->set_note(QStringLiteral(
		    "No `rule` block in the configuration. A rule sends chosen traffic to a "
		    "chosen routing table, and is how a VPN or a VRF keeps its routes away "
		    "from everything else."));
		emit reported(QStringLiteral("no rules configured"));
		return;
	}
	table->set_note(QStringLiteral(
	    "The order is the priority: the kernel consults a lower number first. This "
	    "is the configuration rather than what the kernel has now -- the plan tab is "
	    "where the difference shows."));
	emit reported(QStringLiteral("%1 rules").arg(rows.size()));
}
