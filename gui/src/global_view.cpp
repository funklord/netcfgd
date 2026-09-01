/*
 * global_view.cpp -- the host-wide policy described in global_view.h.
 */
#include "global_view.h"

#include "ncfg_connection.h"

#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

namespace {

const char *const column_titles[] = { "setting", "value" };
constexpr int column_count = static_cast<int>(sizeof(column_titles) / sizeof(column_titles[0]));

/* This view's own drop-in. `global` takes contributions from several files
 * (0147), so writing the off switch here cannot lock out the dns tab writing
 * `50-dns` -- which is the failure that rule exists to prevent. */
const char *const drop_in_name = "50-networking";

} /* namespace */

ncfg_global_view::ncfg_global_view(ncfg_connection *connection, QWidget *parent)
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
	table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	table->horizontalHeader()->setStretchLastSection(true);
	layout->addWidget(table);

	auto *controls = new QHBoxLayout();
	networking_button = new QPushButton(this);
	networking_button->setObjectName(QStringLiteral("toggle_networking"));
	networking_button->setEnabled(false);
	controls->addWidget(networking_button);
	controls->addStretch();
	layout->addLayout(controls);

	note = new QLabel(this);
	note->setObjectName(QStringLiteral("global_note"));
	note->setWordWrap(true);
	layout->addWidget(note);

	connect(networking_button, &QPushButton::clicked, this,
	    &ncfg_global_view::toggle_networking);
}

void ncfg_global_view::refresh()
{
	ncfg_globals globals;
	QString error;

	if (!connection->globals(&globals, &error)) {
		table->setRowCount(0);
		networking_button->setEnabled(false);
		note->setText(error);
		emit reported(error);
		return;
	}

	networking_on = globals.networking != QStringLiteral("off");
	networking_button->setText(networking_on ? QStringLiteral("turn networking off")
	                                         : QStringLiteral("turn networking on"));
	networking_button->setEnabled(true);

	/* Named rather than numbered, so a row means the same thing after
	 * somebody adds one above it. */
	const QPair<QString, QString> rows[] = {
		{ QStringLiteral("networking"), globals.networking },
		{ QStringLiteral("profile"),
		    globals.profile.isEmpty() ? QStringLiteral("none chosen") : globals.profile },
		{ QStringLiteral("hostname"),
		    globals.hostname.isEmpty() ? QStringLiteral("not managed") : globals.hostname },
		{ QStringLiteral("on drift"), globals.on_drift },
		{ QStringLiteral("confirm window"),
		    globals.confirm ? QStringLiteral("%1 seconds").arg(globals.confirm)
		                    : QStringLiteral("none") },
		{ QStringLiteral("observe"), globals.control_observe },
		{ QStringLiteral("wifi"), globals.control_wifi },
		{ QStringLiteral("admin"), globals.control_admin },
		{ QStringLiteral("observe, remotely"),
		    globals.remote_observe ? QStringLiteral("yes") : QStringLiteral("no") },
		{ QStringLiteral("wifi, remotely"),
		    globals.remote_wifi ? QStringLiteral("yes") : QStringLiteral("no") },
		{ QStringLiteral("admin, remotely"),
		    globals.remote_admin ? QStringLiteral("yes") : QStringLiteral("no") },
	};
	constexpr int row_count = static_cast<int>(sizeof(rows) / sizeof(rows[0]));

	table->setRowCount(row_count);
	for (int row = 0; row < row_count; row++) {
		table->setItem(row, 0, new QTableWidgetItem(rows[row].first));
		table->setItem(row, 1, new QTableWidgetItem(rows[row].second));
	}
	table->resizeColumnsToContents();
	table->horizontalHeader()->setStretchLastSection(true);

	note->setText(QStringLiteral(
	    "`observe`, `wifi` and `admin` are who may ask this machine to do what. Config "
	    "access to a network daemon is close to root on it, so read `admin` that way. "
	    "The dns settings are on their own tab: several files may contribute to the "
	    "`global` block, which is what stops two tools locking each other out."));
	emit reported(networking_on ? QStringLiteral("networking is on")
	                            : QStringLiteral("networking is off"));
}

void ncfg_global_view::toggle_networking()
{
	/* **Asked first, and this is the largest thing in the program.** Turning
	 * networking off disables every interface in the document -- links down,
	 * addresses withdrawn -- and the daemon reconciles on its own, so writing
	 * it is the change. Over a remote connection it takes the link away and
	 * nothing will bring it back from here. */
	const QString what =
	    networking_on
	        ? QStringLiteral("Turn this machine's networking off?\n\nEvery interface is "
	                         "disabled: links down, addresses withdrawn. Over a remote "
	                         "connection this takes the link away and you will not be "
	                         "able to turn it back on from here.")
	        : QStringLiteral("Turn this machine's networking back on?\n\nThe interfaces "
	                         "the configuration describes are brought back up.");
	const QMessageBox::StandardButton answer =
	    QMessageBox::question(this, QStringLiteral("netcfgd"), what,
	        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
	if (answer != QMessageBox::Yes) {
		return;
	}

	/* Written as the whole block this drop-in owns. `off` is spelled out and
	 * `on` is written explicitly rather than by deleting the file, so that
	 * what is in force is legible in the configuration rather than being the
	 * absence of something. */
	const QString text =
	    QStringLiteral("global {\n\tnetworking = \"%1\"\n}\n")
	        .arg(networking_on ? QStringLiteral("off") : QStringLiteral("on"));

	QString error;
	if (!connection->config_put(QString::fromLatin1(drop_in_name), text, true, &error)) {
		QMessageBox::warning(this, QStringLiteral("netcfgd"), error);
		emit reported(error);
		return;
	}

	emit reported(QStringLiteral("wrote %1: networking is now `%2`. Run apply to make the "
	                             "machine match it.")
	        .arg(QString::fromLatin1(drop_in_name),
	            networking_on ? QStringLiteral("off") : QStringLiteral("on")));
	emit changed();
	refresh();
}
