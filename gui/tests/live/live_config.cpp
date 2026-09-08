/*
 * live_config.cpp -- the files tab against a real daemon.
 *
 * WHY THIS EXISTS
 *   `config_list` is a verb this tab is the only caller of, and the thing it
 *   has to get right is not the parse but the *pair*: `netcfgd.conf` has no
 *   name and cannot be removed, a drop-in has both, and a view that treated
 *   them alike would offer to remove the machine's own configuration through
 *   a request that has no such verb.
 *
 *   The removal is asserted through the daemon rather than through the table,
 *   so "the row went" and "the file went" stay two claims -- a view that
 *   stopped drawing a row netcfgd still reads would pass the first and fail
 *   the second.
 *
 *   Offscreen, and `isVisible()` is never asked, for the reason live_wifi's
 *   header records.
 */
#include "../../src/config_view.h"
#include "../../src/ncfg_connection.h"
#include "../../src/table_view.h"

#include <QApplication>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QMessageBox>
#include <QPlainTextEdit>
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

/* Does netcfgd still read a drop-in of this name? Asked of the daemon, not of
 * the table. */
static bool reads(ncfg_connection *connection, const QString &name)
{
	QList<ncfg_config_row> files;
	QString why;
	if (!connection->configs(&files, &why)) {
		return false;
	}
	for (const ncfg_config_row &file : files) {
		if (file.name == name) {
			return true;
		}
	}
	return false;
}

static int row_of(QTableWidget *grid, const QString &text)
{
	for (int r = 0; r < grid->rowCount(); r++) {
		for (int c = 0; c < grid->columnCount(); c++) {
			if (grid->item(r, c) && grid->item(r, c)->text() == text) {
				return r;
			}
		}
	}
	return -1;
}

int main(int argc, char **argv)
{
	QApplication app(argc, argv);

	ncfg_connection connection;
	QString error;
	if (!connection.open(QString(), &error)) {
		printf("FAIL the files tab can reach netcfgd\n       %s\n",
		    error.toUtf8().constData());
		return 1;
	}
	check("the files tab can reach netcfgd", true);

	/* Written through `config_put`, which is how a client is supposed to
	 * write configuration (0127) -- so what the tab lists is a file netcfgd
	 * filed rather than one this probe dropped somewhere. */
	QString why;
	check("a drop-in can be filed to list",
	    connection.config_put(QStringLiteral("live-config"),
	        QStringLiteral("# a probe wrote this\nglobal { }\n"), true, &why),
	    why);

	QString reported;
	ncfg_config_view view(&connection);
	QObject::connect(&view, &ncfg_config_view::reported,
	    [&reported](const QString &line) { reported = line; });
	view.refresh();

	auto *table = view.findChild<ncfg_table_view *>();
	auto *grid = view.findChild<QTableWidget *>();
	auto *contents = view.findChild<QPlainTextEdit *>(QStringLiteral("config_contents"));
	QPushButton *remove = view.findChild<QPushButton *>(QStringLiteral("remove_drop_in"));
	if (!table || !grid || !contents || !remove) {
		printf("FAIL the tab has its table, pane and button\n");
		return 1;
	}
	check("the tab has its table, pane and button", true);

	check("the drop-in is listed", row_of(grid, QStringLiteral("live-config")) >= 0);
	check("and so is the machine's own configuration",
	    row_of(grid, QStringLiteral("netcfgd.conf")) >= 0);

	/* The drop-in first, because its text is the only content in this fixture
	 * that is not empty -- the harness writes `netcfgd.conf` as a zero-length
	 * file on purpose, "the state the report came from". */
	const int drop = row_of(grid, QStringLiteral("live-config"));
	grid->selectRow(drop);
	QCoreApplication::processEvents();
	check("choosing a drop-in offers to remove it", remove->isEnabled());
	check("and shows what that file says",
	    contents->toPlainText().contains(QStringLiteral("a probe wrote this")),
	    contents->toPlainText());

	/* **The pair this tab exists to keep apart.** `netcfgd.conf` is listed and
	 * cannot be removed; no request writes or removes it, so a button live for
	 * it would offer a verb that does not exist.
	 *
	 * The pane is checked by what it stopped showing rather than by what it
	 * shows: this file is empty here, so "its text is displayed" would pass
	 * against a pane that had gone blank for any reason at all. Losing the
	 * previous row's text is the observation only a pane following the
	 * selection can produce. */
	const int base = row_of(grid, QStringLiteral("netcfgd.conf"));
	grid->selectRow(base);
	QCoreApplication::processEvents();
	check("choosing netcfgd.conf does not offer to remove it", !remove->isEnabled());
	check("and the pane follows the selection rather than keeping the last file",
	    !contents->toPlainText().contains(QStringLiteral("a probe wrote this")),
	    contents->toPlainText());

	/* Cancel first: the question has to be a question. A probe that only ever
	 * answers Yes passes with the dialog deleted. */
	grid->selectRow(row_of(grid, QStringLiteral("live-config")));
	QCoreApplication::processEvents();
	answer_modal(QMessageBox::Cancel);
	remove->click();
	QCoreApplication::processEvents();
	check("answering no keeps the drop-in",
	    settles([&] { return reads(&connection, QStringLiteral("live-config")); }, 2000));

	grid->selectRow(row_of(grid, QStringLiteral("live-config")));
	QCoreApplication::processEvents();
	answer_modal(QMessageBox::Yes);
	remove->click();
	check("answering yes stops netcfgd reading it",
	    settles([&] { return !reads(&connection, QStringLiteral("live-config")); }));
	check("and the tab says so", reported.contains(QStringLiteral("removed")),
	    QStringLiteral("status was: %1").arg(reported));
	check("and netcfgd.conf is still there",
	    reads(&connection, QString()) || row_of(grid, QStringLiteral("netcfgd.conf")) >= 0);

	printf("\n");
	if (failures) {
		printf("live_config: %d failed\n", failures);
		return 1;
	}
	printf("live_config: all checks passed\n");
	return 0;
}
