/*
 * fleet_view.cpp -- every node of the estate at once (project.md 10.710).
 *
 * WHY THIS EXISTS
 *   The tab has one job a person relies on without checking: it says which
 *   node is down, and it says it while the window goes on working. So what
 *   must hold is that a node answering, a node refusing and a node off the air
 *   read as three different rows; that the one off the air costs a wait in a
 *   child and not in the window; that a node which stops answering keeps its
 *   name; and that the estate is asked a few nodes at a time.
 *
 *   A stand-in `ncfg` on PATH answers by key, so no estate is needed: the
 *   real command is in `c/tests/node_fleet.sh`. HOW IT STOPS: every round is
 *   waited for under a 15-second timer, and the stand-in's slowest answer is
 *   killed by the view's own shortened wait.
 */

#include "../src/fleet_view.h"
#include "../src/main_window.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QComboBox>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QLabel>
#include <QPushButton>
#include <QTabWidget>
#include <QTableWidget>
#include <QTemporaryDir>
#include <QTimer>

#include <cstdio>
#include <cstdlib>

static int failures;

static void check(bool condition, const char *what, const QString &detail = QString())
{
	fprintf(stderr, "%-68s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		if (!detail.isEmpty()) {
			fprintf(stderr, "    %s\n", qPrintable(detail));
		}
		failures++;
	}
}

/* One round to its end, and false if it never got there. */
static bool round_of(ncfg_fleet_view *view)
{
	QEventLoop loop;
	QTimer     limit;
	bool       done = false;

	limit.setSingleShot(true);
	QObject::connect(&limit, &QTimer::timeout, &loop, &QEventLoop::quit);
	QObject::connect(view, &ncfg_fleet_view::finished_round, &loop, [&]() {
		done = true;
		loop.quit();
	});
	limit.start(15000);
	view->refresh();
	loop.exec();
	return done;
}

static QString cell(QTableWidget *cells, int row, int column)
{
	QTableWidgetItem *item = cells->item(row, column);

	return item ? item->text() : QString();
}

int main(int argc, char **argv)
{
	QTemporaryDir bin;
	QFile         script(bin.path() + QStringLiteral("/ncfg"));
	const QString log = bin.path() + QStringLiteral("/log");

	setenv("XDG_RUNTIME_DIR", qPrintable(bin.path()), 1);
	setenv("NCFG_RUN_DIR", qPrintable(bin.path()), 1);
	setenv("PATH", qPrintable(bin.path() + QStringLiteral(":") + QString::fromUtf8(getenv("PATH"))),
	       1);
	setenv("FLEET_LOG", qPrintable(log), 1);
	setenv("FLEET_MODE", "up", 1);
	check(script.open(QIODevice::WriteOnly), "the stand-in ncfg is written");
	script.write("#!/bin/sh\n"
	             "case \"$1\" in\n"
	             "reload|hosts|secret)\n"
	             "  echo \"$*\" >> \"$FLEET_LOG.acts\"\n"
	             "  [ \"$1\" = secret ] && cat >> \"$FLEET_LOG.input\"\n"
	             "  [ \"$FLEET_MODE\" = refuse ] && { echo 'ncfg: group has no members' >&2; "
	             "exit 1; }\n"
	             "  echo 'first line'; echo '1 of 1 netcfgd node(s) carried it out'; exit 0;;\n"
	             "esac\n"
	             "echo + >> \"$FLEET_LOG\"\n"
	             "case \"$3\" in\n"
	             "aa*) [ \"$FLEET_MODE\" = up ] || { echo 'cannot reach it' >&2; "
	             "echo - >> \"$FLEET_LOG\"; exit 1; }\n"
	             "  printf '{\"hostname\":\"router-1\",\"connectivity\":{\"rung\":\"online\","
	             "\"primary\":{\"interface\":\"wan0\"}},\"links\":[{\"carrier\":true},"
	             "{\"carrier\":false}]}\\n';;\n"
	             "bb*) echo 'ncfg: the answer is not a page of the status: denied: this "
	             "needs the observe tier' >&2; "
	             "echo - >> \"$FLEET_LOG\"; exit 1;;\n"
	             "cc*) exec sleep 30;;\n"
	             "*) sleep 0.2;;\n"
	             "esac\n"
	             "echo - >> \"$FLEET_LOG\"\n");
	script.close();
	script.setPermissions(QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);

	QApplication app(argc, argv);
	const QString up = QString(64, QLatin1Char('a'));
	const QString refuses = QString(64, QLatin1Char('b'));
	const QString dead = QString(64, QLatin1Char('c'));
	QStringList   members { up, refuses, dead };

	ncfg_fleet_view view([&members]() { return members; });
	auto           *cells = view.findChild<QTableWidget *>();

	view.set_wait(1500);
	check(cells != nullptr, "the view has a table");
	QElapsedTimer spent;
	spent.start();
	check(round_of(&view), "a round ends, one node never answering");
	check(spent.elapsed() < 10000, "  by the view's own wait, not the stand-in's 30 seconds");
	check(cell(cells, 0, 0) == QStringLiteral("router-1") &&
	          cell(cells, 0, 1) == QStringLiteral("answering") &&
	          cell(cells, 0, 2) == QStringLiteral("online") &&
	          cell(cells, 0, 3) == QStringLiteral("wan0") &&
	          cell(cells, 0, 4) == QStringLiteral("1 of 2"),
	      "a node answering shows its name, rung, primary link and links up",
	      cell(cells, 0, 0) + QStringLiteral(" / ") + cell(cells, 0, 1));
	check(cell(cells, 1, 1).startsWith(QStringLiteral("refused: denied")) &&
	          cell(cells, 1, 1).contains(QStringLiteral("observe")),
	      "a node refusing is refused, in its own words", cell(cells, 1, 1));
	check(cell(cells, 2, 1).startsWith(QStringLiteral("no answer")) &&
	          cell(cells, 2, 5) == QStringLiteral("never"),
	      "a node off the air is no answer, and never answered", cell(cells, 2, 1));
	check(cell(cells, 2, 0) == dead.left(16), "  and a node with no name yet shows its key");

	setenv("FLEET_MODE", "down", 1);
	check(round_of(&view), "a second round ends");
	check(cell(cells, 0, 0) == QStringLiteral("router-1") &&
	          cell(cells, 0, 1).startsWith(QStringLiteral("no answer")) &&
	          cell(cells, 0, 5) != QStringLiteral("never"),
	      "a node that stops answering keeps its name and when it last did",
	      cell(cells, 0, 1));
	setenv("FLEET_MODE", "up", 1);

	QStringList seen;
	QObject::connect(&view, &ncfg_fleet_view::opened, &view,
	                 [&seen](const QString &key) { seen << key; });
	cells->selectRow(1);
	if (auto *open = view.findChild<QPushButton *>(QStringLiteral("fleet_open"))) {
		open->click();
	}
	check(seen == QStringList { refuses }, "Open asks for the selected node, by its whole key");

	/* What an operator does to many: `ncfg`'s verbs, the value off the argv. */
	{
		const QString secret = QStringLiteral("hunter2-never-on-argv");
		bool          worked = false;
		QString       said;
		QEventLoop    loop;
		QTimer        limit;

		limit.setSingleShot(true);
		QObject::connect(&limit, &QTimer::timeout, &loop, &QEventLoop::quit);
		QObject::connect(&view, &ncfg_fleet_view::acted, &loop,
		                 [&](bool ok, const QString &text) {
			worked = ok;
			said = text;
			loop.quit();
		});
		auto wait = [&]() {
			limit.start(10000);
			loop.exec();
		};
		check(view.reload_all(), "reload all starts");
		check(!view.reload_all(), "  and a second waits for it");
		wait();
		check(worked && said.startsWith(QStringLiteral("1 of 1")),
		      "  and says how many nodes carried it out, its last line", said);
		QLabel *note = view.findChild<QLabel *>(QStringLiteral("fleet_note"));
		check(note && note->text().contains(QStringLiteral("1 of 1")),
		      "  under the table", note ? note->text() : QString());
		check(view.add_member(up, QStringLiteral("zone1")), "add to group starts");
		wait();
		check(view.seal(QStringLiteral("zone1"), QStringLiteral("wg/key"), secret),
		      "seal starts");
		wait();
		setenv("FLEET_MODE", "refuse", 1);
		check(view.seal(QStringLiteral("zone1"), QStringLiteral("wg/key"), secret),
		      "a refused seal starts");
		wait();
		check(!worked && said.contains(QStringLiteral("no members")),
		      "  and reads as a failure, in ncfg's own words", said);
		setenv("FLEET_MODE", "up", 1);
		QFile acts(log + QStringLiteral(".acts"));
		QFile input(log + QStringLiteral(".input"));
		const QByteArray asked = acts.open(QIODevice::ReadOnly) ? acts.readAll() : QByteArray();
		const QByteArray given = input.open(QIODevice::ReadOnly) ? input.readAll() : QByteArray();
		check(asked.contains("reload --at estate") &&
		          asked.contains(("hosts member " + up + " zone1").toUtf8()) &&
		          asked.contains("secret seal zone1 wg/key"),
		      "each is ncfg's own verb", QString::fromUtf8(asked));
		check(given.startsWith(secret.toUtf8() + '\n'), "the value goes to standard input");
		check(!asked.contains(secret.toUtf8()), "  and is on no command line");
	}

	/* A wide estate, one answer slow: never more than four asked at once. */
	members.clear();
	for (char at = 'd'; at <= 'm'; at++) {
		members << QString(64, QLatin1Char(at));
	}
	QFile::remove(log);
	check(round_of(&view), "a round of ten nodes ends");
	QFile record(log);
	int   depth = 0;
	int   deepest = 0;
	int   lines = 0;
	if (record.open(QIODevice::ReadOnly)) {
		for (const QByteArray &line : record.readAll().split('\n')) {
			if (line == "+") {
				depth++;
				lines++;
			} else if (line == "-") {
				depth--;
			}
			deepest = qMax(deepest, depth);
		}
	}
	check(lines == 10 && deepest >= 2 && deepest <= 4,
	      "ten nodes are all asked, at most four at once",
	      QStringLiteral("%1 asked, %2 deepest").arg(lines).arg(deepest));
	members.removeLast();
	check(round_of(&view) && cells->rowCount() == 9, "a node gone from the estate leaves the table");

	/* Closed with a node still being asked, which a window now does from its
	 * first moment: the process ends with it and nobody hears it end. */
	{
		const QString slow(64, QLatin1Char('c'));
		auto         *leaving = new ncfg_fleet_view([&slow]() { return QStringList { slow }; });
		bool          heard = false;

		QObject::connect(leaving, &ncfg_fleet_view::finished_round, leaving,
		                 [&heard]() { heard = true; });
		leaving->refresh();
		delete leaving;
		check(!heard, "a view closed in the middle of a round goes quietly");
	}

	/* The tab is the fleet's: none for somebody with one machine. */
	{
		ncfg_connection  home;
		ncfg_main_window window(&home);
		bool             there = false;
		auto            *tabs = window.findChild<QTabWidget *>();

		for (int at = 0; tabs && at < tabs->count(); at++) {
			there = there || tabs->tabText(at) == QStringLiteral("fleet");
		}
		check(tabs && !there, "with no estate there is no fleet tab");
	}
	{
		ncfg_connection  node;
		QString          error;
		check(node.open_at(up, &error), "a connection opens on a node", error);
		ncfg_main_window window(&node);
		auto            *fleet = window.findChild<ncfg_fleet_view *>();
		auto            *tabs = window.findChild<QTabWidget *>();

		check(fleet != nullptr, "a window on a node has one");
		auto *box = window.findChild<QComboBox *>(QStringLiteral("hosts"));
		const int shown = box ? box->findData(up) : -1;
		check(shown >= 0 && box->itemText(shown) == up,
		      "the box lists a host by its key until it has said its name");
		if (fleet && round_of(fleet)) {
			check(shown >= 0 && box->itemText(shown) ==
			          QStringLiteral("router-1 (%1)").arg(up.left(16)),
			      "  and then by that name, with the start of the key beside it",
			      box ? box->itemText(shown) : QString());
			check(box && box->itemData(shown).toString() == up,
			      "  and choosing it still means that key");
		}
		if (fleet && tabs) {
			tabs->setCurrentWidget(fleet);
			emit fleet->opened(up);
			check(tabs->currentWidget() != fleet,
			      "and opening the node it is on goes to that node's tabs");
		}
	}

	if (failures == 0) {
		fprintf(stderr, "fleet_tab: all checks passed\n");
	} else {
		fprintf(stderr, "fleet_tab: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
