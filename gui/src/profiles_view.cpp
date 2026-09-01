/*
 * profiles_view.cpp -- the profiles table described in profiles_view.h.
 */
#include "profiles_view.h"

#include "ncfg_connection.h"

#include "table_view.h"

#include <QInputDialog>
#include <QMessageBox>
#include <QPushButton>
#include <QStringList>
#include <QVBoxLayout>

namespace {

/* The first row, which is the default state rather than a profile. Held as a
 * constant because two places need to recognise it: the row that draws it, and
 * the switch that turns it back into the empty name `profile_set` wants. */
const char *const none_chosen = "(none chosen)";

} /* namespace */

ncfg_profiles_view::ncfg_profiles_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	QStringList columns;
	columns << QStringLiteral("profile") << QStringLiteral("source")
	        << QStringLiteral("in use");
	table = new ncfg_table_view(columns, QStringLiteral("profiles_note"), this);

	use_button = new QPushButton(QStringLiteral("use"), this);
	use_button->setObjectName(QStringLiteral("use_profile"));
	use_button->setEnabled(false);
	table->add_control(use_button);

	save_button = new QPushButton(QStringLiteral("save what is running as..."), this);
	save_button->setObjectName(QStringLiteral("save_profile"));
	table->add_control(save_button);

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);

	connect(use_button, &QPushButton::clicked, this, &ncfg_profiles_view::use_selected);
	connect(save_button, &QPushButton::clicked, this, &ncfg_profiles_view::save_current);
	connect(table, &ncfg_table_view::activated, this, &ncfg_profiles_view::use_selected);
	connect(table, &ncfg_table_view::selection_changed, this,
	    [this]() { use_button->setEnabled(table->selected_row() >= 0); });
}

void ncfg_profiles_view::refresh()
{
	QList<ncfg_profile_row> found;
	QString chosen;
	QString error;

	if (!connection->profiles(&found, &chosen, &error)) {
		table->show_error(error);
		emit reported(error);
		return;
	}

	QList<QStringList> rows;
	/* "None chosen" first, because it is the default and because it is the
	 * row somebody wants when a profile has just broken something. */
	QStringList cells;
	cells << QString::fromLatin1(none_chosen);
	cells << QStringLiteral("the machine's own configuration");
	cells << (chosen.isEmpty() ? QStringLiteral("yes") : QString());
	rows << cells;

	for (const ncfg_profile_row &profile : found) {
		/* A local copy shadows a shipped one of the same name and only the
		 * copy is listed, which is the rule the loader layers by -- so
		 * "shipped" here means "and you have not replaced it". */
		QStringList cells;
		cells << profile.name;
		cells << (profile.shipped ? QStringLiteral("shipped with netcfgd")
		                          : QStringLiteral("this machine's"));
		cells << (profile.name == chosen ? QStringLiteral("yes") : QString());
		rows << cells;
	}
	table->show_rows(rows);

	table->set_note(QStringLiteral(
	    "A profile is a directory of drop-ins layered over conf.d, so one machine can "
	    "behave differently by place. Switching is manual and only manual. Changing any "
	    "setting by hand takes the machine off its profile without changing what is "
	    "running -- the profile's files are folded into conf.d in the same step."));
	emit reported(chosen.isEmpty() ? QStringLiteral("no profile chosen")
	                               : QStringLiteral("on the `%1` profile").arg(chosen));
}

void ncfg_profiles_view::use_selected()
{
	const QString chosen = table->selected_cell(0);
	if (chosen.isEmpty()) {
		return;
	}
	/* The first row is the default state, and `profile_set` spells that as an
	 * empty name. The gui never writes netcfgd's own drop-in filename: the
	 * verb is the daemon's and so is where the selection lives. */
	const QString name = chosen == QString::fromLatin1(none_chosen) ? QString() : chosen;

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

void ncfg_profiles_view::save_current()
{
	bool named = false;
	const QString name = QInputDialog::getText(this, QStringLiteral("netcfgd"),
	    QStringLiteral("Save what this machine is running as a profile called:"),
	    QLineEdit::Normal, QString(), &named)
	                         .trimmed();
	if (!named || name.isEmpty()) {
		return;
	}

	/* Tried without `replace` first, so an existing profile is refused by the
	 * daemon rather than overwritten by a client that guessed. Somebody's
	 * profile is somebody's work, and the second ask is what makes the
	 * overwrite deliberate rather than a consequence of typing a name. */
	QString error;
	if (connection->profile_save(name, false, &error)) {
		emit reported(
		    QStringLiteral("saved what is running as `%1`, and switched to it").arg(name));
		refresh();
		emit changed();
		return;
	}

	/* The daemon's refusal is the message, and only one of its refusals is
	 * worth offering to push past. The others -- a name that cannot be a
	 * directory, a configuration the renderer will not write out, a profile
	 * written by hand -- are answers rather than obstacles. */
	if (!error.contains(QStringLiteral("already exists"))) {
		QMessageBox::warning(this, QStringLiteral("netcfgd"), error);
		emit reported(error);
		return;
	}

	const QMessageBox::StandardButton answer = QMessageBox::question(this,
	    QStringLiteral("netcfgd"),
	    QStringLiteral("`%1` already exists. Overwrite it with what this machine is "
	                   "running?\n\nWhat is in that profile now is replaced.")
	        .arg(name),
	    QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
	if (answer != QMessageBox::Yes) {
		return;
	}
	if (!connection->profile_save(name, true, &error)) {
		QMessageBox::warning(this, QStringLiteral("netcfgd"), error);
		emit reported(error);
		return;
	}
	emit reported(QStringLiteral("saved what is running as `%1`, and switched to it").arg(name));
	refresh();
	emit changed();
}
