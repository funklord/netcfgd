/*
 * hooks_view.cpp -- the table described in hooks_view.h.
 *
 * The table itself is `ncfg_table_view`, shared with every other list here.
 * What is left is this view's own subject: which columns, and how one row
 * becomes strings.
 */
#include "hooks_view.h"

#include "interface_dialog.h"
#include "ncfg_connection.h"
#include "table_view.h"

#include <QPushButton>
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

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);

	connect(edit_button, &QPushButton::clicked, this, &ncfg_hooks_view::edit_selected);
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
		    "moment -- pre_up, up, post_up, lease, carrier, drift and the rest."));
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
	emit reported(QStringLiteral("%1 hooks").arg(cells_by_row.size()));
}
