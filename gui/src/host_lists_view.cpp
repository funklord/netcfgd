/*
 * host_lists_view.cpp -- the table described in host_lists_view.h.
 */
#include "host_lists_view.h"

#include "host_list_dialog.h"
#include "table_view.h"

#include <QPushButton>
#include <QVBoxLayout>

ncfg_host_lists_view::ncfg_host_lists_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	QStringList columns;
	columns << QStringLiteral("name") << QStringLiteral("stations");
	table = new ncfg_table_view(columns, QStringLiteral("host_lists_note"), this);

	edit_button = new QPushButton(QStringLiteral("view / change"), this);
	edit_button->setObjectName(QStringLiteral("edit_host_list"));
	edit_button->setEnabled(false);
	table->add_control(edit_button);
	auto *new_button = new QPushButton(QStringLiteral("new host list..."), this);
	new_button->setObjectName(QStringLiteral("new_host_list"));
	table->add_control(new_button);

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);

	connect(edit_button, &QPushButton::clicked, this, &ncfg_host_lists_view::edit_selected);
	connect(new_button, &QPushButton::clicked, this, &ncfg_host_lists_view::new_list);
	connect(table, &ncfg_table_view::activated, this, &ncfg_host_lists_view::edit_selected);
	connect(table, &ncfg_table_view::selection_changed, this,
	    [this]() { edit_button->setEnabled(table->selected_row() >= 0); });
}

void ncfg_host_lists_view::open(const ncfg_host_list_row &list)
{
	ncfg_host_list_dialog dialog(connection, list, this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	emit reported(dialog.outcome());
	refresh();
	emit changed();
}

void ncfg_host_lists_view::edit_selected()
{
	const int row = table->selected_row();
	if (row >= 0 && row < lists.size()) {
		open(lists.at(row));
	}
}

void ncfg_host_lists_view::new_list()
{
	open(ncfg_host_list_row());
}

void ncfg_host_lists_view::refresh()
{
	QString error;
	if (!connection->host_lists(&lists, &error)) {
		lists.clear();
		table->show_error(error);
		emit reported(error);
		return;
	}

	QList<QStringList> rows;
	for (const ncfg_host_list_row &list : lists) {
		rows << QStringList { list.name, list.mac.join(QStringLiteral(", ")) };
	}
	table->show_rows(rows);
	if (rows.isEmpty()) {
		table->set_note(QStringLiteral(
		    "No `host_list` block. A host list names a set of stations once, so an access "
		    "point's allow or deny list and a firewall rule can name it as "
		    "@host_list:NAME rather than repeating the addresses."));
		emit reported(QStringLiteral("no host lists configured"));
		return;
	}
	table->set_note(QStringLiteral(
	    "Named elsewhere as @host_list:NAME -- in an access point's access_control and in "
	    "a firewall rule's `mac`."));
	emit reported(QStringLiteral("%1 host lists").arg(rows.size()));
}
