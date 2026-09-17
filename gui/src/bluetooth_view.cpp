/*
 * bluetooth_view.cpp -- the table described in bluetooth_view.h.
 *
 * The table itself is `ncfg_table_view`, shared with every other list here.
 * What is left is this view's own subject: which columns, and how one row
 * becomes strings.
 */
#include "bluetooth_view.h"

#include "bluetooth_dialog.h"
#include "ncfg_connection.h"
#include "table_view.h"

#include <QPushButton>
#include <QVBoxLayout>

ncfg_bluetooth_view::ncfg_bluetooth_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	QStringList columns;
	columns << QStringLiteral("id") << QStringLiteral("address") << QStringLiteral("profile") << QStringLiteral("autoconnect");
	table = new ncfg_table_view(columns, QStringLiteral("bluetooth_note"), this);

	edit_button = new QPushButton(QStringLiteral("view / change"), this);
	edit_button->setObjectName(QStringLiteral("edit_bluetooth"));
	edit_button->setEnabled(false);
	table->add_control(edit_button);
	/* The one control here that needs no row: a device being written is not in
	 * the list yet. */
	new_button = new QPushButton(QStringLiteral("new device..."), this);
	new_button->setObjectName(QStringLiteral("new_bluetooth"));
	table->add_control(new_button);

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);

	connect(edit_button, &QPushButton::clicked, this, &ncfg_bluetooth_view::edit_selected);
	connect(new_button, &QPushButton::clicked, this, &ncfg_bluetooth_view::new_device);
	connect(table, &ncfg_table_view::activated, this, &ncfg_bluetooth_view::edit_selected);
	connect(table, &ncfg_table_view::selection_changed, this,
	    [this]() { edit_button->setEnabled(table->selected_row() >= 0); });
}

void ncfg_bluetooth_view::edit_selected()
{
	const int row = table->selected_row();
	if (row < 0 || row >= devices.size()) {
		return;
	}
	ncfg_bluetooth_dialog dialog(connection, devices.at(row), this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	emit reported(dialog.outcome());
	refresh();
	emit changed();
}

void ncfg_bluetooth_view::new_device()
{
	ncfg_bluetooth_dialog dialog(connection, ncfg_bluetooth_row(), this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	emit reported(dialog.outcome());
	refresh();
	emit changed();
}

void ncfg_bluetooth_view::refresh()
{
	QList<ncfg_bluetooth_row> found;
	QString error;

	devices.clear();
	if (!connection->bluetooth(&found, &error)) {
		table->show_error(error);
		emit reported(error);
		return;
	}

	QList<QStringList> cells_by_row;
	for (const ncfg_bluetooth_row &item : found) {
		QStringList cells;
		cells << item.id;
		cells << item.address;
		cells << item.profile;
		cells << (item.autoconnect ? QStringLiteral("yes") : QStringLiteral("no"));
		cells_by_row << cells;
	}
	table->show_rows(cells_by_row);
	devices = found;

	if (cells_by_row.isEmpty()) {
		/* **This said netcfgd pairs and connects the device, and it does
		 * not.** The planner warns per device that the block is understood
		 * and not acted on; the one sentence an operator reads before there
		 * is anything in the table said the opposite. */
		table->set_note(QStringLiteral(
		    "No `bluetooth` block in the configuration. A device is declared like a "
		    "network -- `new device...` writes one -- and this build understands the "
		    "block without acting on it: nothing pairs, connects, or brings a `pan` "
		    "link up yet."));
		emit reported(QStringLiteral("no devices configured"));
		return;
	}
	table->set_note(QStringLiteral(
	    "`autoconnect` is whether netcfgd would connect this device without being asked. "
	    "This build acts on none of it: the block is kept so a configuration written now "
	    "still means this when the backends arrive, and `ncfg plan` says so per device."));
	emit reported(QStringLiteral("%1 devices").arg(cells_by_row.size()));
}
