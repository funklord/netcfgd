/*
 * node_menu.cpp -- the window's node box (project.md 10.699).
 *
 * WHY THIS EXISTS
 *   The box moves the whole window between this machine and another node,
 *   and the line above the tabs says which. What must hold: opened on a
 *   node, the box shows that node and the window refreshes on its timer; and
 *   a choice that cannot be reached puts the window back where it was rather
 *   than leaving it unconnected while it looks as if it moved.
 *
 *   No daemon and no fuzznetd: `XDG_RUNTIME_DIR` and `NCFG_RUN_DIR` name an
 *   empty directory, so "this machine" cannot be reached, which is the
 *   failure wanted.
 */

#include "../src/main_window.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QComboBox>
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

int main(int argc, char **argv)
{
	QTemporaryDir empty;
	setenv("XDG_RUNTIME_DIR", qPrintable(empty.path()), 1);
	setenv("NCFG_RUN_DIR", qPrintable(empty.path()), 1);
	QApplication app(argc, argv);
	const QString key = QStringLiteral(
	    "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef");
	ncfg_connection connection;
	QString error;

	check(connection.open_at(key, &error), "a connection opens on another node", error);
	ncfg_main_window window(&connection);
	QComboBox *nodes = window.findChild<QComboBox *>(QStringLiteral("nodes"));
	bool polling = false;
	for (QTimer *timer : window.findChildren<QTimer *>()) {
		polling = polling || (timer->interval() == 15000 && timer->isActive());
	}
	check(nodes && nodes->itemData(0).toString().isEmpty() &&
	          nodes->currentData().toString() == key,
	      "the node box shows this machine first, and the node it was opened on");
	check(polling, "  and the window refreshes every 15 seconds, having no event stream");

	if (nodes) {
		nodes->setCurrentIndex(0); /* this machine, which cannot be reached */
	}
	check(connection.node() == key && nodes && nodes->currentData().toString() == key,
	      "a choice that cannot be reached puts the window back on the node",
	      QStringLiteral("node \"%1\", box \"%2\"")
	          .arg(connection.node(), nodes ? nodes->currentData().toString() : QString()));

	if (failures == 0) {
		fprintf(stderr, "node_menu: all checks passed\n");
	} else {
		fprintf(stderr, "node_menu: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
