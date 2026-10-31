/*
 * block_lists_view.cpp -- the table described in block_lists_view.h.
 */
#include "block_lists_view.h"

#include "block_list_dialog.h"
#include "table_view.h"

#include <QPushButton>
#include <QVBoxLayout>

ncfg_block_lists_view::ncfg_block_lists_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	QStringList columns;
	columns << QStringLiteral("name") << QStringLiteral("blocks") << QStringLiteral("allows");
	table = new ncfg_table_view(columns, QStringLiteral("block_lists_note"), this);

	edit_button = new QPushButton(QStringLiteral("view / change"), this);
	edit_button->setObjectName(QStringLiteral("edit_block_list"));
	edit_button->setEnabled(false);
	table->add_control(edit_button);
	auto *new_button = new QPushButton(QStringLiteral("new list..."), this);
	new_button->setObjectName(QStringLiteral("new_block_list"));
	table->add_control(new_button);

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);

	connect(edit_button, &QPushButton::clicked, this, &ncfg_block_lists_view::edit_selected);
	connect(new_button, &QPushButton::clicked, this, &ncfg_block_lists_view::new_list);
	connect(table, &ncfg_table_view::activated, this, &ncfg_block_lists_view::edit_selected);
	connect(table, &ncfg_table_view::selection_changed, this,
	    [this]() { edit_button->setEnabled(table->selected_row() >= 0); });
}

void ncfg_block_lists_view::open(const ncfg_block_list_row &list)
{
	ncfg_block_list_dialog dialog(connection, list, this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	emit reported(dialog.outcome());
	refresh();
	emit changed();
}

void ncfg_block_lists_view::edit_selected()
{
	const int row = table->selected_row();
	if (row >= 0 && row < lists.size()) {
		open(lists.at(row));
	}
}

void ncfg_block_lists_view::new_list()
{
	open(ncfg_block_list_row());
}

void ncfg_block_lists_view::refresh()
{
	QString error;
	if (!connection->block_lists(&lists, &error)) {
		lists.clear();
		table->show_error(error);
		emit reported(error);
		return;
	}

	QList<QStringList> rows;
	for (const ncfg_block_list_row &list : lists) {
		QStringList blocks;
		if (!list.file.isEmpty()) {
			blocks << list.file;
		}
		if (!list.domain.isEmpty()) {
			blocks << list.domain;
		}
		rows << QStringList { list.name, blocks.join(QStringLiteral("; ")), list.allow };
	}
	table->show_rows(rows);
	if (rows.isEmpty()) {
		table->set_note(QStringLiteral(
		    "No `block_list` block. A block list is names the router refuses to resolve -- "
		    "ad and tracker domains -- from files a list is published in, or written here. "
		    "A network applies one with `block` in its DHCP server."));
		emit reported(QStringLiteral("no block lists configured"));
		return;
	}
	table->set_note(QStringLiteral(
	    "Applied by each DHCP server that names the list in `block`; the plan says so where "
	    "none does, or where a file is not there yet."));
	emit reported(QStringLiteral("%1 block lists").arg(rows.size()));
}
