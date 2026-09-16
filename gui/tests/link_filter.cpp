/*
 * link_filter.cpp -- which rows the links tab's category filter keeps.
 *
 * The rule is three lines and two of them are the awkward ones, which is why
 * it is split out of the drawing: a filter that is subtly wrong hides rows,
 * and a hidden row looks exactly like an interface that has gone away.
 *
 * What is *not* here is the categorising. That is the daemon's, in
 * netcfgd-model's `link` module, tested against the three kinds the kernel
 * reports identically -- a wired card, a radio and the loopback all carry an
 * empty `kind`. This window never classifies anything; it renders the answer
 * and filters on it, and these are the cases where rendering can still go
 * wrong.
 */
#include "../src/ncfg_connection.h"

#include <QCoreApplication>
#include <QString>
#include <cstdio>

static int failures;

static void check(bool condition, const char *what)
{
	fprintf(stderr, "link_filter: %-58s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

int main(int argc, char **argv)
{
	QCoreApplication app(argc, argv);

	const QString all = QStringLiteral("all");
	const QString wifi = QStringLiteral("wifi");
	const QString ethernet = QStringLiteral("ethernet");

	/* The ordinary case in both directions. */
	check(ncfg_link_shows(wifi, wifi), "a matching category is shown");
	check(!ncfg_link_shows(ethernet, wifi), "a different one is hidden");

	/* "all" is the way back, and it has to keep everything including the
	 * rows the daemon had no word for. */
	check(ncfg_link_shows(wifi, all), "`all` keeps a categorised row");
	check(ncfg_link_shows(QString(), all), "`all` keeps an uncategorised one");

	/* **The case that matters.** An empty category is a daemon older than
	 * this window, and such a row shows in every filter rather than in none:
	 * a row that disappears because two programs disagree about its kind is
	 * how somebody concludes an interface has gone away. Erring towards
	 * showing costs one row in a filtered list and nothing else. */
	check(ncfg_link_shows(QString(), wifi),
	    "a row the daemon did not categorise is never hidden");

	/* And an empty filter is not a category nothing matches. It is what a
	 * freshly built combo box holds for an instant before its first item is
	 * added, and drawing an empty table then would be a flicker with no
	 * cause an operator could see. */
	check(ncfg_link_shows(wifi, QString()), "an empty filter shows everything");

	/* WHICH EDITOR A ROW CALLS FOR
	 *
	 * The same list holds interfaces and saved wifi networks, and configuring
	 * them is not the same job. Before a row said which it was, `configure`
	 * opened the interface editor for whatever was in column one -- so
	 * selecting a network called `OpenPC.se` offered to set the MTU of an
	 * interface by that name, and there is no such interface. */
	QList<ncfg_inventory_row> rows;
	ncfg_inventory_row network;
	network.name = QStringLiteral("office");
	network.subject = QStringLiteral("network");
	ncfg_inventory_row interface;
	interface.name = QStringLiteral("eth0");
	interface.subject = QStringLiteral("interface");
	ncfg_inventory_row silent;
	silent.name = QStringLiteral("wlan0");
	rows << network << interface << silent;

	check(ncfg_link_subject(rows, QStringLiteral("office")) == QStringLiteral("network"),
	    "a network row asks for the network editor");
	check(ncfg_link_subject(rows, QStringLiteral("eth0")) == QStringLiteral("interface"),
	    "an interface row asks for the interface editor");

	/* The two defaults, which are the same default and are both reached by
	 * rows that exist. A daemon older than this window fills no subject at
	 * all, and a list drawn from the kernel's links has no inventory row to
	 * find: every one of those is an interface, and offering a network editor
	 * for `eth0` is the failure this whole function exists to stop. */
	check(ncfg_link_subject(rows, QStringLiteral("wlan0")) == QStringLiteral("interface"),
	    "a row whose subject the daemon did not fill is an interface");
	check(ncfg_link_subject(rows, QStringLiteral("nothing")) == QStringLiteral("interface"),
	    "and so is a row that is not in the inventory at all");

	/* A linkset is a third kind of row, and it is the one with no editor: a
	 * group opened in an interface dialog would be 0247's fault again, one
	 * kind of row later. */
	ncfg_inventory_row group;
	group.name = QStringLiteral("uplink");
	group.subject = QStringLiteral("linkset");
	rows << group;
	check(ncfg_link_subject(rows, QStringLiteral("uplink")) == QStringLiteral("linkset"),
	    "a group is not sent to either link editor");

	if (failures == 0) {
		fprintf(stderr, "link_filter: all checks passed\n");
	} else {
		fprintf(stderr, "link_filter: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
