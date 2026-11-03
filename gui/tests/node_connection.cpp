/*
 * node_connection.cpp -- a connection to another node of the estate
 * (`--at`, project.md 10.698).
 *
 * WHY THIS EXISTS
 *   The window shows `where()` so the operator is never unsure whose network
 *   it is about to change (gui/project.md sec 4), and it reopens a broken
 *   connection from its refresh. Reopened by its socket path, a connection
 *   to another node would have reopened onto the default socket -- this
 *   machine's daemon -- while the window still said the other node. So:
 *   a connection opened on a node, broken by a request no fuzznetd carries,
 *   and reopened, must still be that node.
 *
 *   And the events tab on a node: no stream of this machine's, and its line
 *   said once rather than at every refresh, which the window's 15-second
 *   timer would otherwise have made it.
 *
 *   No fuzznetd and no daemon: `XDG_RUNTIME_DIR` names an empty directory,
 *   so every request fails at the transport, which is the break wanted.
 */

#include "../src/events_view.h"
#include "../src/ncfg_connection.h"

#include <QListWidget>

#include <QApplication>
#include <QTemporaryDir>

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
	QApplication app(argc, argv);
	QTemporaryDir runtime;
	const QString key = QStringLiteral(
	    "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
	ncfg_connection connection;
	QList<ncfg_link_row> links;
	QString error;

	setenv("XDG_RUNTIME_DIR", qPrintable(runtime.path()), 1);
	check(!connection.open_at(QStringLiteral("not-a-key"), &error),
	      "a key that is not one is refused when opened");
	check(connection.open_at(key, &error), "a connection opens on another node", error);
	check(connection.node() == key && connection.where() == QStringLiteral("node %1").arg(key),
	      "  it names that node, by its whole key, as where it is");
	check(!connection.links(&links, &error) && !connection.is_open(),
	      "  a request no fuzznetd carries leaves it broken", error);
	QString why;
	check(connection.reopen_if_broken(&why), "  and it reopens", why);
	check(connection.node() == key && connection.where() == QStringLiteral("node %1").arg(key),
	      "  onto that node again, never this machine's default socket");
	{
		/* The events tab on a node: no stream of this machine's, and its one
		 * line said once, not at every 15-second refresh. */
		ncfg_events_view events(&connection);
		QListWidget *lines = events.findChild<QListWidget *>();

		events.refresh();
		events.refresh();
		events.refresh();
		check(lines && lines->count() == 1 &&
		          lines->item(0)->text().contains(QStringLiteral("not carried")),
		      "the events tab on a node says it has no stream, once over three refreshes",
		      lines ? QStringLiteral("%1 line(s)").arg(lines->count()) : QString());
	}
	connection.close();
	check(connection.node().isEmpty(), "closed, it names no node");

	if (failures == 0) {
		fprintf(stderr, "node_connection: all checks passed\n");
	} else {
		fprintf(stderr, "node_connection: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
