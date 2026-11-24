/*
 * zones_view.cpp -- the table described in zones_view.h.
 */
#include "zones_view.h"

#include "counted.h"
#include "table_view.h"
#include "zone_dialog.h"

#include <QPushButton>
#include <QVBoxLayout>

ncfg_zones_view::ncfg_zones_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	QStringList columns;
	columns << QStringLiteral("name") << QStringLiteral("reaches")
	        << QStringLiteral("each client");
	table = new ncfg_table_view(columns, QStringLiteral("zones_note"), this);

	edit_button = new QPushButton(QStringLiteral("view / change"), this);
	edit_button->setObjectName(QStringLiteral("edit_zone"));
	edit_button->setEnabled(false);
	table->add_control(edit_button);
	auto *new_button = new QPushButton(QStringLiteral("new zone..."), this);
	new_button->setObjectName(QStringLiteral("new_zone"));
	table->add_control(new_button);

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);

	connect(edit_button, &QPushButton::clicked, this, &ncfg_zones_view::edit_selected);
	connect(new_button, &QPushButton::clicked, this, &ncfg_zones_view::new_zone);
	connect(table, &ncfg_table_view::activated, this, &ncfg_zones_view::edit_selected);
	connect(table, &ncfg_table_view::selection_changed, this,
	    [this]() { edit_button->setEnabled(table->selected_row() >= 0); });
}

void ncfg_zones_view::open(const ncfg_zone_row &zone)
{
	ncfg_zone_dialog dialog(connection, zone, this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	emit reported(dialog.outcome());
	refresh();
	emit changed();
}

void ncfg_zones_view::edit_selected()
{
	const int row = table->selected_row();
	if (row >= 0 && row < zones.size()) {
		open(zones.at(row));
	}
}

void ncfg_zones_view::new_zone()
{
	open(ncfg_zone_row());
}

void ncfg_zones_view::refresh()
{
	QString error;
	if (!connection->zones(&zones, &error)) {
		zones.clear();
		table->show_error(error);
		emit reported(error);
		return;
	}

	QList<QStringList> rows;
	for (const ncfg_zone_row &zone : zones) {
		rows << QStringList { zone.name,
			zone.reach.isEmpty() ? QStringLiteral("nothing") : zone.reach.join(QStringLiteral(", ")),
			zone.client_limit.isEmpty() ? QStringLiteral("no cap") : zone.client_limit };
	}
	table->show_rows(rows);
	if (rows.isEmpty()) {
		table->set_note(QStringLiteral(
		    "No `zone` block. A zone names a purpose of the estate's -- guest, iot, trusted "
		    "-- and the zones its traffic may reach; a link joins one with `zone` in its "
		    "interface, and each host compiles its links' zones into its firewall."));
		emit reported(QStringLiteral("no zones configured"));
		return;
	}
	table->set_note(QStringLiteral(
	    "A link joins a zone in its interface dialog. The firewall needs a block for the "
	    "zones to compile into; a cap holds each client's address to its rate, each way."));
	emit reported(ncfg_counted(rows.size(), "zone", "zones"));
}
