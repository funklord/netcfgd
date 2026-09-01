/*
 * profiles_view.cpp -- the profiles table described in profiles_view.h.
 */
#include "profiles_view.h"

#include "ncfg_connection.h"

#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

namespace {

const char *const column_titles[] = { "profile", "source", "in use" };
constexpr int column_count = static_cast<int>(sizeof(column_titles) / sizeof(column_titles[0]));

/* The first row, which is the default state rather than a profile. Held as a
 * constant because two places need to recognise it: the row that draws it, and
 * the switch that turns it back into the empty name `profile_set` wants. */
const char *const none_chosen = "(none chosen)";

} /* namespace */

ncfg_profiles_view::ncfg_profiles_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	auto *layout = new QVBoxLayout(this);

	table = new QTableWidget(0, column_count, this);
	QStringList headers;
	for (int i = 0; i < column_count; i++) {
		headers << QString::fromLatin1(column_titles[i]);
	}
	table->setHorizontalHeaderLabels(headers);
	table->verticalHeader()->setVisible(false);
	table->setSelectionBehavior(QAbstractItemView::SelectRows);
	table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	table->horizontalHeader()->setStretchLastSection(true);
	layout->addWidget(table);

	auto *controls = new QHBoxLayout();
	use_button = new QPushButton(QStringLiteral("use"), this);
	use_button->setObjectName(QStringLiteral("use_profile"));
	use_button->setEnabled(false);
	controls->addWidget(use_button);
	controls->addStretch();
	layout->addLayout(controls);

	note = new QLabel(this);
	note->setObjectName(QStringLiteral("profiles_note"));
	note->setWordWrap(true);
	layout->addWidget(note);

	connect(use_button, &QPushButton::clicked, this, &ncfg_profiles_view::use_selected);
	connect(table, &QTableWidget::doubleClicked, this, &ncfg_profiles_view::use_selected);
	connect(table, &QTableWidget::itemSelectionChanged, this,
	    [this]() { use_button->setEnabled(table->currentRow() >= 0); });
}

void ncfg_profiles_view::refresh()
{
	QList<ncfg_profile_row> rows;
	QString chosen;
	QString error;

	if (!connection->profiles(&rows, &chosen, &error)) {
		table->setRowCount(0);
		note->setText(error);
		emit reported(error);
		return;
	}

	/* "None chosen" first, because it is the default and because it is the
	 * row somebody wants when a profile has just broken something. */
	table->setRowCount(rows.size() + 1);
	const QString cells[column_count] = {
		QString::fromLatin1(none_chosen),
		QStringLiteral("the machine's own configuration"),
		chosen.isEmpty() ? QStringLiteral("yes") : QString(),
	};
	for (int column = 0; column < column_count; column++) {
		table->setItem(0, column, new QTableWidgetItem(cells[column]));
	}

	for (int row = 0; row < rows.size(); row++) {
		const ncfg_profile_row &profile = rows.at(row);
		/* A local copy shadows a shipped one of the same name and only the
		 * copy is listed, which is the rule the loader layers by -- so
		 * "shipped" here means "and you have not replaced it". */
		const QString source = profile.shipped ? QStringLiteral("shipped with netcfgd")
		                                       : QStringLiteral("this machine's");
		const QString profile_cells[column_count] = {
			profile.name,
			source,
			profile.name == chosen ? QStringLiteral("yes") : QString(),
		};
		for (int column = 0; column < column_count; column++) {
			table->setItem(row + 1, column, new QTableWidgetItem(profile_cells[column]));
		}
	}
	table->resizeColumnsToContents();
	table->horizontalHeader()->setStretchLastSection(true);

	note->setText(QStringLiteral(
	    "A profile is a directory of drop-ins layered over conf.d, so one machine can "
	    "behave differently by place. Switching is manual and only manual. Changing any "
	    "setting by hand takes the machine off its profile without changing what is "
	    "running -- the profile's files are folded into conf.d in the same step."));
	emit reported(chosen.isEmpty() ? QStringLiteral("no profile chosen")
	                               : QStringLiteral("on the `%1` profile").arg(chosen));
}

void ncfg_profiles_view::use_selected()
{
	const int row = table->currentRow();
	if (row < 0) {
		return;
	}
	const QTableWidgetItem *named = table->item(row, 0);
	if (!named) {
		return;
	}
	/* The first row is the default state, and `profile_set` spells that as an
	 * empty name. The gui never writes netcfgd's own drop-in filename: the
	 * verb is the daemon's and so is where the selection lives. */
	const QString name =
	    named->text() == QString::fromLatin1(none_chosen) ? QString() : named->text();

	/* **Asked first, and for the reason the tray is asked first.** The daemon
	 * reconciles a changed configuration on its own, so writing the selection
	 * *is* the change and there is no later step at which anybody would get
	 * to look. A profile switch is the strongest case for that caution: it
	 * can take down the link the operator is connected over. */
	const QString what = name.isEmpty()
	    ? QStringLiteral("Stop using a profile, and run this machine's own configuration?")
	    : QStringLiteral("Switch to the `%1` profile?").arg(name);
	const QMessageBox::StandardButton answer = QMessageBox::question(this,
	    QStringLiteral("netcfgd"),
	    what + QStringLiteral("\n\nThe network is reconfigured as soon as this is "
	                          "written. Over a remote connection, this can take the "
	                          "link down."),
	    QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
	if (answer != QMessageBox::Yes) {
		return;
	}

	QString error;
	if (!connection->profile_set(name, &error)) {
		/* The daemon's words, which name the tier when the refusal is one. */
		QMessageBox::warning(this, QStringLiteral("netcfgd"), error);
		emit reported(error);
		return;
	}
	refresh();
	emit changed();
}
