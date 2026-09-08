/*
 * config_view.cpp -- the configuration table described in config_view.h.
 */
#include "config_view.h"

#include "ncfg_connection.h"
#include "table_view.h"

#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>

ncfg_config_view::ncfg_config_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	QStringList columns;
	/* `order` first, because it is the column that answers the question this
	 * tab exists for. A reader scanning for "why did my setting not take"
	 * wants to see which file comes after which. */
	columns << QStringLiteral("order") << QStringLiteral("file")
	        << QStringLiteral("name") << QStringLiteral("removable");
	table = new ncfg_table_view(columns, QStringLiteral("config_note"), this);

	/* **`admin`, so the button is off without it** rather than offering an
	 * action the daemon will refuse. The tooltip names the tier, because a
	 * greyed control with no reason is indistinguishable from a broken one
	 * (0092). */
	remove_button = new QPushButton(QStringLiteral("remove"), this);
	remove_button->setObjectName(QStringLiteral("remove_drop_in"));
	remove_button->setEnabled(false);
	if (connection->tiers().admin == 0) {
		remove_button->setToolTip(
		    QStringLiteral("removing a drop-in needs the `admin` tier, which this "
		               "connection does not have"));
	}
	table->add_control(remove_button);

	contents = new QPlainTextEdit(this);
	contents->setObjectName(QStringLiteral("config_contents"));
	/* Read-only, and that is this tab's whole boundary: the dialogs write
	 * configuration in the vocabulary of what is being configured, and an
	 * editable box here would be a second way in whose only advantage is that
	 * it can express anything. */
	contents->setReadOnly(true);
	contents->setPlaceholderText(QStringLiteral("choose a file to see what it says"));

	connect(remove_button, &QPushButton::clicked, this, &ncfg_config_view::remove_selected);
	connect(table, &ncfg_table_view::selection_changed, this, &ncfg_config_view::show_selected);

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table, 2);
	layout->addWidget(contents, 3);
}

void ncfg_config_view::refresh()
{
	QList<ncfg_config_row> found;
	QString error;

	if (!connection->configs(&found, &error)) {
		table->show_error(error);
		emit reported(error);
		return;
	}
	shown = found;

	QList<QStringList> rows;
	int at = 0;
	int removable = 0;
	for (const ncfg_config_row &file : found) {
		at++;
		if (file.removable) {
			removable++;
		}
		QStringList cells;
		cells << QString::number(at);
		cells << file.file;
		/* A dash rather than a blank for the file that has no name: blank
		 * reads as a value the program failed to fetch, and this one has no
		 * name by design. */
		cells << (file.name.isEmpty() ? QStringLiteral("--") : file.name);
		cells << (file.removable ? QStringLiteral("yes") : QStringLiteral("no"));
		rows << cells;
	}
	table->show_rows(rows);
	show_selected();

	if (rows.isEmpty()) {
		table->set_note(QStringLiteral(
		    "netcfgd is reading no configuration at all: no netcfgd.conf and nothing in "
		    "conf.d. That is what a fresh install looks like, and it compiles to a "
		    "document that manages nothing."));
		emit reported(QStringLiteral("no configuration"));
		return;
	}
	table->set_note(
	    QStringLiteral("In the order netcfgd reads them: a later file overrides an earlier "
	               "one. %1 of %2 were filed by a client and can be removed; "
	               "netcfgd.conf is the machine's own and is not one of them.")
	        .arg(removable)
	        .arg(rows.size()));
	emit reported(QStringLiteral("%1 config file(s)").arg(rows.size()));
}

void ncfg_config_view::show_selected()
{
	const int row = table->selected_row();
	const bool chosen = row >= 0 && row < shown.size();
	contents->setPlainText(chosen ? shown.at(row).text : QString());
	remove_button->setEnabled(chosen && shown.at(row).removable
	    && connection->tiers().admin != 0);
}

void ncfg_config_view::remove_selected()
{
	const int row = table->selected_row();
	if (row < 0 || row >= shown.size()) {
		return;
	}
	const ncfg_config_row file = shown.at(row);
	if (!file.removable) {
		return;
	}

	/* **Asked, and the question shows what is being removed.** A drop-in is
	 * somebody's configuration and the file name alone is a poor description
	 * of it -- `90-profile` says nothing about what it does. The first line
	 * that is not a comment is usually the block it opens, which is the
	 * shortest true summary available here. */
	QString first;
	for (const QString &line : file.text.split(QLatin1Char('\n'))) {
		const QString trimmed = line.trimmed();
		if (!trimmed.isEmpty() && !trimmed.startsWith(QLatin1Char('#'))) {
			first = trimmed;
			break;
		}
	}
	QString question = QStringLiteral("Remove the drop-in `%1`?").arg(file.name);
	if (!first.isEmpty()) {
		question += QStringLiteral("\n\nIt begins `%1`.").arg(first);
	}
	question += QStringLiteral(
	    "\n\nnetcfgd re-reads its configuration afterwards, so whatever this file "
	    "asked for stops being asked for.");

	QMessageBox box(QMessageBox::Warning, QStringLiteral("netcfgd"), question,
	            QMessageBox::Cancel | QMessageBox::Yes, this);
	box.setDefaultButton(QMessageBox::Cancel);
	if (box.exec() != QMessageBox::Yes) {
		return;
	}

	QString error;
	if (!connection->config_delete(file.name, &error)) {
		table->show_error(error);
		emit reported(error);
		return;
	}
	/* The refresh first and the sentence after it, for the reason the wifi
	 * view's forget learned: refresh writes its own summary. */
	refresh();
	emit reported(QStringLiteral("removed `%1`").arg(file.name));
	emit changed();
}
