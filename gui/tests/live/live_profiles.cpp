/*
 * live_profiles.cpp -- the profiles tab's delete button against a real daemon
 * (10.801).
 *
 * A profile could be saved from this tab and from `ncfg`, and removed by
 * neither -- the GUI walk's "no profile can be deleted" (10.778). The button
 * is offered only for this machine's own profile that is not in use, asks
 * first, and goes through `profile_delete`, which the daemon answers. What is
 * asserted is the daemon's list, not the table: a view that stopped drawing a
 * row it still held would pass the one and fail the other.
 *
 * Offscreen, and `isVisible()` is never asked, for live_secrets' reason.
 */
#include "../../src/ncfg_connection.h"
#include "../../src/profiles_view.h"
#include "../../src/table_view.h"

#include <QApplication>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QThread>
#include <QTimer>

#include <functional>

#include <cstdio>

static int failures;

static void check(const char *what, bool condition, const QString &detail = QString())
{
	if (condition) {
		printf("ok   %s\n", what);
	} else {
		printf("FAIL %s\n", what);
		if (!detail.isEmpty()) {
			printf("       %s\n", detail.toUtf8().constData());
		}
		failures++;
	}
	fflush(stdout);
}

/* Answer a modal question the next time one is up.
 *
 * `QMessageBox::exec` runs its own event loop, so the click has to be queued
 * before the button that opens it and has to find the dialog through
 * `activeModalWidget` -- it does not exist yet when this is scheduled. Bounded
 * by a retry count, because a probe that silently did nothing would leave the
 * test sitting in the dialog until the suite timed out. */
static void answer_modal(QMessageBox::StandardButton which, int tries = 100)
{
	QTimer::singleShot(0, [which, tries]() {
		auto *box = qobject_cast<QMessageBox *>(QApplication::activeModalWidget());
		if (box) {
			QAbstractButton *press = box->button(which);
			if (press) {
				press->click();
			}
			return;
		}
		if (tries > 0) {
			answer_modal(which, tries - 1);
		}
	});
}

static bool settles(const std::function<bool()> &done, int milliseconds = 8000)
{
	QElapsedTimer clock;
	clock.start();
	while (clock.elapsed() < milliseconds) {
		if (done()) {
			return true;
		}
		QCoreApplication::processEvents();
		QThread::msleep(50);
	}
	return done();
}

static bool listed(ncfg_connection *connection, const QString &name)
{
	QList<ncfg_profile_row> rows;
	QString chosen;
	QString why;
	if (!connection->profiles(&rows, &chosen, &why)) {
		return true; /* unknown is not gone */
	}
	for (const ncfg_profile_row &row : rows) {
		if (row.name == name) {
			return true;
		}
	}
	return false;
}

static QPushButton *button(QWidget *of, const char *label)
{
	for (QPushButton *candidate : of->findChildren<QPushButton *>()) {
		if (candidate->text() == QString::fromUtf8(label)) {
			return candidate;
		}
	}
	return nullptr;
}

static int row_of(QTableWidget *grid, const QString &name)
{
	for (int i = 0; i < grid->rowCount(); i++) {
		if (grid->item(i, 0) && grid->item(i, 0)->text() == name) {
			return i;
		}
	}
	return -1;
}

int main(int argc, char **argv)
{
	QApplication app(argc, argv);
	const QString name = QStringLiteral("live-profile-probe");

	ncfg_connection connection;
	QString error;
	if (!connection.open(QString(), &error)) {
		printf("FAIL the profiles view can reach netcfgd\n       %s\n",
		    error.toUtf8().constData());
		return 1;
	}
	check("the profiles view can reach netcfgd", true);
	QString why;
	check("a profile can be saved to delete", connection.profile_save(name, true, &why), why);

	ncfg_profiles_view view(&connection);
	view.refresh();
	auto *table = view.findChild<ncfg_table_view *>();
	QPushButton *remove = button(&view, "delete");
	QTableWidget *grid = table ? table->findChild<QTableWidget *>() : nullptr;
	if (!grid || !remove) {
		printf("FAIL the view has a table and a delete button\n");
		return 1;
	}
	check("the view has a table and a delete button", true);
	check("with no row chosen the button is off", !remove->isEnabled());

	int row = row_of(grid, name);
	check("the saved profile is listed", row >= 0);
	if (row < 0) {
		return 1;
	}
	grid->selectRow(row);
	QCoreApplication::processEvents();
	check("the profile in use is not offered for deletion", !remove->isEnabled());

	check("the machine can stop using it", connection.profile_set(QString(), &why), why);
	view.refresh();
	row = row_of(grid, name);
	grid->selectRow(row);
	QCoreApplication::processEvents();
	check("no longer in use, it is offered", row >= 0 && remove->isEnabled());

	answer_modal(QMessageBox::No);
	remove->click();
	QCoreApplication::processEvents();
	check("answering no keeps it", listed(&connection, name));

	answer_modal(QMessageBox::Yes);
	remove->click();
	check("answering yes deletes it, as the daemon lists",
	    settles([&] { return !listed(&connection, name); }, 4000));
	check("and the table drops the row", row_of(grid, name) < 0);

	printf(failures ? "live_profiles: %d check(s) failed\n" : "live_profiles: all checks passed\n",
	    failures);
	return failures ? 1 : 0;
}
