/*
 * live_secrets.cpp -- the credentials tab against a real daemon, driven by its
 * own button.
 *
 * WHY THIS EXISTS
 *   The view's whole subject is a credential nobody wants any more -- "stored,
 *   unused", which its header calls "a credential still on the machine after
 *   whatever wanted it was deleted". It could name that fault and do nothing
 *   about it, and the note under the table told the operator to remove the
 *   file: a client sent behind the socket, which is what 0127 exists to stop.
 *
 *   So the button is the view finishing its own sentence, and this is what
 *   says the sentence is true -- that pressing it reaches the daemon, that the
 *   store loses the file, and that the two rows the view distinguishes are
 *   offered differently.
 *
 * WHAT IT DOES NOT DO
 *   It never reads a value, because nothing in this direction can: the socket
 *   carries names, `ncfg_secret_row` has no field for a value, and a probe
 *   that wanted to assert one would have to go to the disk behind the program
 *   it is testing. What it asserts instead is the store's own answer -- the
 *   name is listed, then it is not.
 *
 *   Offscreen, and `isVisible()` is never asked: a widget in a window nobody
 *   showed is not visible whatever it was told, which is the trap live_wifi's
 *   header records.
 */
#include "../../src/ncfg_connection.h"
#include "../../src/secrets_view.h"
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

/* Is this name in the store, as the daemon reports it? Asked of the daemon
 * rather than of the table, so that "the row went" and "the credential went"
 * stay two different assertions -- a view that stopped drawing a row it still
 * held would pass the first and fail this. */
static bool stored(ncfg_connection *connection, const QString &name)
{
	QList<ncfg_secret_row> rows;
	QString why;
	if (!connection->secrets(&rows, &why)) {
		return false;
	}
	for (const ncfg_secret_row &row : rows) {
		if (row.name == name) {
			return row.stored;
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

int main(int argc, char **argv)
{
	QApplication app(argc, argv);

	ncfg_connection connection;
	QString error;
	if (!connection.open(QString(), &error)) {
		printf("FAIL the secrets view can reach netcfgd\n       %s\n",
		    error.toUtf8().constData());
		return 1;
	}
	check("the secrets view can reach netcfgd", true);

	/* Stored through the connection rather than through a dialog: this view
	 * deliberately has no field for a value, and the storing half is
	 * `secret_put`'s own probe. What is under test is the removal. */
	QString why;
	check("a credential can be stored to remove",
	    connection.secret_put(QStringLiteral("live-secrets-probe"),
	        QStringLiteral("hunter2hunter2"), true, &why),
	    why);

	QString reported;
	ncfg_secrets_view view(&connection);
	QObject::connect(&view, &ncfg_secrets_view::reported,
	    [&reported](const QString &line) { reported = line; });
	view.refresh();

	auto *table = view.findChild<ncfg_table_view *>();
	QPushButton *forget = button(&view, "forget");
	if (!table || !forget) {
		printf("FAIL the view has a table and a forget button\n");
		return 1;
	}
	check("the view has a table and a forget button", true);

	/* Nothing selected is nothing to forget. A destructive control that is
	 * live with no row chosen is one press away from removing whatever
	 * happens to be first. */
	check("with no row chosen the button is off", !forget->isEnabled());

	int row = -1;
	QTableWidget *grid = table->findChild<QTableWidget *>();
	if (!grid) {
		printf("FAIL the table has a grid\n");
		return 1;
	}
	for (int i = 0; i < grid->rowCount(); i++) {
		if (grid->item(i, 0)
		    && grid->item(i, 0)->text() == QStringLiteral("live-secrets-probe")) {
			row = i;
		}
	}
	check("the stored credential is listed", row >= 0);
	if (row < 0) {
		return 1;
	}
	check("and the store says it holds it",
	    stored(&connection, QStringLiteral("live-secrets-probe")));

	grid->selectRow(row);
	QCoreApplication::processEvents();
	check("choosing a stored row offers the button", forget->isEnabled());

	/* Cancel first: the question has to be a question. A probe that only ever
	 * answered Yes would pass with the dialog removed entirely -- which is
	 * the shape that got past live_wifi's first version. */
	answer_modal(QMessageBox::Cancel);
	forget->click();
	QCoreApplication::processEvents();
	check("answering no keeps the credential",
	    settles([&] { return stored(&connection, QStringLiteral("live-secrets-probe")); },
	        2000));

	grid->selectRow(row);
	answer_modal(QMessageBox::Yes);
	forget->click();
	check("answering yes removes it from the store",
	    settles([&] { return !stored(&connection, QStringLiteral("live-secrets-probe")); }));
	check("and the view says so",
	    reported.contains(QStringLiteral("forgot the credential")),
	    QStringLiteral("status was: %1").arg(reported));

	printf("\n");
	if (failures) {
		printf("live_secrets: %d failed\n", failures);
		return 1;
	}
	printf("live_secrets: all checks passed\n");
	return 0;
}
