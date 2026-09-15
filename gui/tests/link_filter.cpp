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

	if (failures == 0) {
		fprintf(stderr, "link_filter: all checks passed\n");
	} else {
		fprintf(stderr, "link_filter: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
