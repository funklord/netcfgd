/*
 * hooks_view.cpp -- the table described in hooks_view.h.
 *
 * The table itself is `ncfg_table_view`, shared with every other list here.
 * What is left is this view's own subject: which columns, and how one row
 * becomes strings.
 */
#include "hooks_view.h"

#include "counted.h"
#include "hand_written.h"
#include "interface_dialog.h"
#include "ncfg_connection.h"
#include "table_view.h"

#include <QInputDialog>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>

ncfg_hooks_view::ncfg_hooks_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	QStringList columns;
	columns << QStringLiteral("interface") << QStringLiteral("phase") << QStringLiteral("path") << QStringLiteral("runs as") << QStringLiteral("timeout");
	table = new ncfg_table_view(columns, QStringLiteral("hooks_note"), this);

	/* One button, and it opens the interface editor rather than a form of its
	 * own: the drop-in that carries a hook carries the whole interface. */
	edit_button = new QPushButton(QStringLiteral("edit the interface..."), this);
	edit_button->setObjectName(QStringLiteral("edit_hook"));
	edit_button->setEnabled(false);
	table->add_control(edit_button);

	/* **Starting one here** (10.808). The tab could only edit an interface
	 * that already had a hook, and its note sent a person to the links tab,
	 * `configure`, then hooks. This asks which interface, opens the same
	 * editor, and presses its own `new hook...` -- the hook still lives in
	 * the interface's block, so there is still one form and one save. */
	add_button = new QPushButton(QStringLiteral("new hook..."), this);
	add_button->setObjectName(QStringLiteral("add_hook"));
	table->add_control(add_button);

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);

	connect(edit_button, &QPushButton::clicked, this, &ncfg_hooks_view::edit_selected);
	connect(add_button, &QPushButton::clicked, this, &ncfg_hooks_view::add_hook);
	connect(table, &ncfg_table_view::activated, this, &ncfg_hooks_view::edit_selected);
	connect(table, &ncfg_table_view::selection_changed, this,
	    [this]() { edit_button->setEnabled(table->selected_row() >= 0); });
}

void ncfg_hooks_view::edit_selected()
{
	const int row = table->selected_row();
	if (row < 0 || row >= rows.size()) {
		return;
	}
	ncfg_interface_dialog dialog(connection, rows.at(row).interface, this);
	if (connection->written_by_hand(QStringLiteral("interface-%1").arg(rows.at(row).interface))) {
		ncfg_show_read_only(&dialog, QStringLiteral("`interface %1`").arg(rows.at(row).interface));
	}
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	emit reported(dialog.outcome());
	refresh();
	emit changed();
}

void ncfg_hooks_view::add_hook()
{
	/* The inventory rather than the links, as the links tab has it: it says
	 * which interfaces already have a block, and only those can be written
	 * by hand -- `written_by_hand` answers for a block that exists, and asked
	 * of one that does not it says yes (the probe for this found that). */
	QList<ncfg_inventory_row> known;
	QString error;
	if (!connection->inventory(&known, &error)) {
		emit reported(error);
		return;
	}
	QStringList names;
	QStringList configured;
	for (const ncfg_inventory_row &row : known) {
		/* Interfaces only: a network row has its own hooks, in its own dialog. */
		if (row.subject != QStringLiteral("interface") || row.name.isEmpty() ||
		    row.name == QStringLiteral("lo") || names.contains(row.name)) {
			continue;
		}
		names << row.name;
		if (row.configured) {
			configured << row.name;
		}
	}
	if (names.isEmpty()) {
		emit reported(QStringLiteral("this machine has no interface to run a hook on"));
		return;
	}
	bool chosen = false;
	const QString interface = QInputDialog::getItem(this, QStringLiteral("netcfgd"),
	    QStringLiteral("Run a hook when this interface changes:"), names, 0, false, &chosen);
	if (!chosen || interface.isEmpty()) {
		return;
	}
	ncfg_interface_dialog dialog(connection, interface, this);
	if (configured.contains(interface) &&
	    connection->written_by_hand(QStringLiteral("interface-%1").arg(interface))) {
		/* Not editable here (10.778), so there is no form to open: the
		 * dialog says where it is written instead. */
		ncfg_show_read_only(&dialog, QStringLiteral("`interface %1`").arg(interface));
	} else if (auto *start = dialog.findChild<QPushButton *>(QStringLiteral("iface_hook_add"))) {
		QTimer::singleShot(0, start, &QPushButton::click);
	}
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	emit reported(dialog.outcome());
	refresh();
	emit changed();
}

void ncfg_hooks_view::refresh()
{
	QList<ncfg_hook_row> found;
	QString error;

	rows.clear();
	if (!connection->hooks(&found, &error)) {
		table->show_error(error);
		emit reported(error);
		return;
	}

	QList<QStringList> cells_by_row;
	for (const ncfg_hook_row &item : found) {
		QStringList cells;
		cells << item.interface;
		cells << item.phase;
		cells << item.path;
		cells << (item.run_as.isEmpty() ? QStringLiteral("root (the daemon)") : item.run_as);
		cells << (item.timeout ? QString::number(item.timeout) : QString());
		cells_by_row << cells;
	}
	table->show_rows(cells_by_row);
	this->rows = found;

	if (cells_by_row.isEmpty()) {
		table->set_note(QStringLiteral(
		    "No interface declares a hook. A hook is a program netcfgd runs at a named "
		    "moment -- pre_up, up, post_up, lease, carrier, drift and the rest. One is "
		    "belongs to an interface: new hook... asks which, and opens its editor."));
		emit reported(QStringLiteral("no hooks configured"));
		return;
	}
	/* **Every row says root, and it is not a coincidence.** The hook runner
	 * drops to `run_as` and kills at `timeout` where the document names them,
	 * and the configuration language has no key for either -- so nothing on
	 * any machine can put anything but the default in these two columns. Said
	 * here because the columns otherwise read as a setting somebody forgot to
	 * use. */
	table->set_note(QStringLiteral(
	    "Every hook runs as root with the default timeout: netcfgd's hook runner can "
	    "drop to another user and stop a hook that overruns, and the configuration "
	    "language has no key to ask for either, so these two columns cannot yet say "
	    "anything else. A `run_as=` line inside a hook body is a shell assignment and "
	    "does nothing."));
	emit reported(ncfg_counted(cells_by_row.size(), "hook", "hooks"));
}
