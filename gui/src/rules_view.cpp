/*
 * rules_view.cpp -- the table described in rules_view.h.
 *
 * The table itself is `ncfg_table_view`, shared with every other list here.
 * What is left is this view's own subject: which columns, and how one row
 * becomes strings.
 */
#include "rules_view.h"

#include "ncfg_connection.h"
#include "rule_dialog.h"
#include "table_view.h"

#include <QPushButton>
#include <QVBoxLayout>

ncfg_rules_view::ncfg_rules_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	QStringList columns;
	columns << QStringLiteral("priority") << QStringLiteral("id") << QStringLiteral("family") << QStringLiteral("selector") << QStringLiteral("action") << QStringLiteral("table");
	table = new ncfg_table_view(columns, QStringLiteral("rules_note"), this);

	edit_button = new QPushButton(QStringLiteral("view / change"), this);
	edit_button->setObjectName(QStringLiteral("edit_rule"));
	edit_button->setEnabled(false);
	table->add_control(edit_button);
	/* The one control here that needs no row: a rule being written is not in
	 * the list yet. */
	new_button = new QPushButton(QStringLiteral("new rule..."), this);
	new_button->setObjectName(QStringLiteral("new_rule"));
	table->add_control(new_button);

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);

	connect(edit_button, &QPushButton::clicked, this, &ncfg_rules_view::edit_selected);
	connect(new_button, &QPushButton::clicked, this, &ncfg_rules_view::new_rule);
	connect(table, &ncfg_table_view::activated, this, &ncfg_rules_view::edit_selected);
	connect(table, &ncfg_table_view::selection_changed, this,
	    [this]() { edit_button->setEnabled(table->selected_row() >= 0); });
}

void ncfg_rules_view::edit_selected()
{
	const int row = table->selected_row();
	if (row < 0 || row >= rules.size()) {
		return;
	}
	ncfg_rule_dialog dialog(connection, rules.at(row), this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	emit reported(dialog.outcome());
	refresh();
	emit changed();
}

void ncfg_rules_view::new_rule()
{
	ncfg_rule_dialog dialog(connection, ncfg_rule_row(), this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	emit reported(dialog.outcome());
	refresh();
	emit changed();
}

void ncfg_rules_view::refresh()
{
	QList<ncfg_rule_row> found;
	QString error;

	if (!connection->rules(&found, &error)) {
		rules.clear();
		table->show_error(error);
		emit reported(error);
		return;
	}

	/* Kept, so the editor opens on the daemon's own row rather than on a
	 * re-parse of the strings this view just made out of it. */
	rules = found;

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
