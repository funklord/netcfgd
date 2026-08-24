/*
 * live_wifi.cpp -- the wifi view against a real daemon, driven by its own
 * buttons.
 *
 * WHY THIS EXISTS
 *   The operator's report that started it was "the buttons don't work
 *   properly", and nothing in this repository could have answered it. The
 *   other probes under `gui/tests/` are widget logic with no daemon: they
 *   check that a state produces a rendering, given the state. What none of
 *   them checks is whether the state ever arrives -- whether pressing `scan`
 *   fills the table, whether `activate radio` leaves a supplicant running,
 *   whether a button that looks enabled does anything when pressed.
 *
 *   Every one of those is a join between the view, the C client, the socket
 *   and the daemon, and every fault this milestone was in a join.
 *
 * WHAT IT DRIVES
 *   The real `ncfg_wifi_view`, by clicking its real buttons, against a real
 *   netcfgd on a fake radio -- the same harness `tests/live/wifi_journey.sh`
 *   uses, for the same reason: a namespace has no wireless hardware, so the
 *   radio is a dummy link that `NCFG_SYS_CLASS_NET` calls wireless and the
 *   supplicant is one netcfgd starts through `NCFG_WPA_SUPPLICANT`.
 *
 *   Offscreen, so it needs a graphical session no more than it needs a person.
 *   `isVisible()` is deliberately never asserted: a widget in a window nobody
 *   showed is not visible, and a probe that checked it would be checking its
 *   own harness.
 */

#include "../../src/ncfg_connection.h"
#include "../../src/wifi_view.h"

#include <QApplication>
#include <QComboBox>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QThread>

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

/* A button by its label, which is what an operator presses. Found by text
 * rather than by object name on purpose: the label is the part a person acts
 * on, so a rename that changed it would be a change to the interface and
 * should be seen here. */
static QPushButton *button(QWidget *of, const char *label)
{
	for (QPushButton *candidate : of->findChildren<QPushButton *>()) {
		if (candidate->text() == QString::fromUtf8(label)) {
			return candidate;
		}
	}
	return nullptr;
}

static QTableWidget *table_of(QWidget *of)
{
	const QList<QTableWidget *> tables = of->findChildren<QTableWidget *>();
	return tables.isEmpty() ? nullptr : tables.first();
}

/* Wait for something the daemon does asynchronously, pumping the event loop.
 *
 * Bounded and the timeout is the assertion, which is the shape this tree
 * settled on after a test that *hung* rather than failed: a hang stalls the
 * suite instead of reporting, and a GUI probe with a live daemon behind it is
 * exactly where one would happen. */
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

int main(int argc, char **argv)
{
	QApplication app(argc, argv);

	ncfg_connection connection;
	QString error;
	if (!connection.open(QString(), &error)) {
		printf("FAIL the view can reach netcfgd\n       %s\n",
		    error.toUtf8().constData());
		return 1;
	}
	check("the view can reach netcfgd", true);

	/* The status line is the button feedback the report was about, so every
	 * step records what it said. */
	QString reported;
	ncfg_wifi_view view(&connection);
	QObject::connect(&view, &ncfg_wifi_view::reported,
	    [&reported](const QString &line) { reported = line; });
	view.refresh();

	QPushButton *activate = button(&view, "activate radio");
	QPushButton *scan = button(&view, "scan");
	QPushButton *add = button(&view, "add");
	QPushButton *join = button(&view, "join");
	if (!activate || !scan || !add || !join) {
		printf("FAIL the view has its buttons\n");
		return 1;
	}
	check("the view has its buttons", true);

	/* 1. Nothing configured: the radio is offered and the rest is refused.
	 *
	 * The state a fresh install is in, and the one the operator was in. A view
	 * that enabled `scan` here would be offering an action that cannot work --
	 * netcfgd runs no supplicant on a radio nobody has activated. */
	check("with no radio activated, scanning is not offered", !scan->isEnabled());
	check("nor joining", !join->isEnabled());
	check("but activating is", activate->isEnabled());
	check("and the status line says which radio and why",
	    reported.contains(QStringLiteral("wlp")) || reported.contains(QStringLiteral("radio0")),
	    QStringLiteral("status was: %1").arg(reported));
	check("and says it is not activated",
	    reported.contains(QStringLiteral("not activated")),
	    QStringLiteral("status was: %1").arg(reported));

	/* 2. Pressing it does something.
	 *
	 * The whole of the report in one assertion: a button that looks live and
	 * changes nothing is worse than one that is greyed, because the operator
	 * has no way to tell it apart from a slow one. */
	activate->click();
	check("pressing activate leaves the radio netcfgd's",
	    settles([&] {
		    QList<ncfg_radio_row> radios;
		    QString ignored;
		    if (!connection.radios(&radios, &ignored)) {
			    return false;
		    }
		    for (const ncfg_radio_row &radio : radios) {
			    if (radio.activated && radio.supplicant) {
				    return true;
			    }
		    }
		    return false;
	    }),
	    QStringLiteral("status was: %1").arg(reported));

	view.refresh();
	check("and scanning is offered afterwards", scan->isEnabled());

	/* 3. Scanning fills the table, which is what makes `add` reachable. */
	QTableWidget *table = table_of(&view);
	check("the view has a table", table != nullptr);
	if (!table) {
		return 1;
	}
	/* Activating scans on its own, and that is deliberate: an operator who
	 * pressed it wants the list, not a second button. Asserted rather than
	 * assumed, because the first version of this expected an empty table
	 * here and was wrong about the design rather than about the code. */
	check("activating scans straight away, so the table is already filled",
	    table->rowCount() > 0, QStringLiteral("rows: %1").arg(table->rowCount()));

	const int found = table->rowCount();
	scan->click();
	check("and pressing scan again refills it", table->rowCount() == found,
	    QStringLiteral("rows: %1, status: %2").arg(table->rowCount()).arg(reported));
	check("and the status line says how many were found",
	    reported.contains(QStringLiteral("access point")),
	    QStringLiteral("status was: %1").arg(reported));

	/* 4. Selecting a row enables the thing to do with it.
	 *
	 * `add` is for a network with no `network` block and `join` is for one
	 * that has one -- the boundary 0013 draws, expressed as which button
	 * lights up rather than as a refusal after the press. */
	table->setCurrentCell(0, 0);
	QCoreApplication::processEvents();
	check("selecting an unconfigured network offers to add it", add->isEnabled());
	check("and does not offer to join what the config does not describe",
	    !join->isEnabled());

	printf("\n");
	if (failures) {
		printf("live_wifi: %d failed\n", failures);
		return 1;
	}
	printf("live_wifi: all checks passed\n");
	return 0;
}
