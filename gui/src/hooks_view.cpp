/*
 * hooks_view.cpp -- the table described in hooks_view.h.
 *
 * The table itself is `ncfg_table_view`, shared with every other list here.
 * What is left is this view's own subject: which columns, and how one row
 * becomes strings.
 */
#include "hooks_view.h"

#include "ncfg_connection.h"
#include "table_view.h"

#include <QVBoxLayout>

ncfg_hooks_view::ncfg_hooks_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	QStringList columns;
	columns << QStringLiteral("interface") << QStringLiteral("phase") << QStringLiteral("path") << QStringLiteral("runs as") << QStringLiteral("timeout");
	table = new ncfg_table_view(columns, QStringLiteral("hooks_note"), this);

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);
}

void ncfg_hooks_view::refresh()
{
	QList<ncfg_hook_row> found;
	QString error;

	if (!connection->hooks(&found, &error)) {
		table->show_error(error);
		emit reported(error);
		return;
	}

	QList<QStringList> rows;
	for (const ncfg_hook_row &item : found) {
		QStringList cells;
		cells << item.interface;
		cells << item.phase;
		cells << item.path;
		cells << (item.run_as.isEmpty() ? QStringLiteral("root (the daemon)") : item.run_as);
		cells << (item.timeout ? QString::number(item.timeout) : QString());
		rows << cells;
	}
	table->show_rows(rows);

	if (rows.isEmpty()) {
		table->set_note(QStringLiteral(
		    "No interface declares a hook. A hook is a program netcfgd runs at a named "
		    "moment -- pre_up, up, post_up, lease, carrier, drift and the rest."));
		emit reported(QStringLiteral("no hooks configured"));
		return;
	}
	table->set_note(QStringLiteral(
	    "A hook with `root (the daemon)` in `runs as` was given no user and runs "
	    "privileged. The timeout is when netcfgd kills one that has not finished; "
	    "blank means the default."));
	emit reported(QStringLiteral("%1 hooks").arg(rows.size()));
}
