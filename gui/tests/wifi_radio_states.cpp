/*
 * wifi_radio_states.cpp -- the three states a radio can be in, and the one
 * sentence each of them gets.
 *
 * A radio is not activated-or-not. It is netcfgd's, or nobody's, or another
 * manager's -- and the third is the one that wastes an afternoon: netcfgd
 * declines to take a radio while another manager is running it, so a client
 * offering "activate" there sends somebody to press a button that cannot work.
 *
 * What is tested here is `ncfg_radio_row::state()`, which is where the wording
 * lives so that the GUI, the TUI and `ncfg wifi radios` say the same thing
 * about the same condition -- the reason a scan row carries `display` rather
 * than each widget formatting its own. The button wiring that consumes it
 * needs a daemon and belongs in a live test; this is the part that can be
 * checked with neither a daemon nor a radio.
 */

#include "../src/ncfg_connection.h"

#include <QCoreApplication>
#include <QString>

#include <cstdio>

static int failures;

static void check(bool condition, const char *what)
{
	fprintf(stderr, "wifi_radio_states: %-56s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

int main(int argc, char **argv)
{
	QCoreApplication app(argc, argv);

	ncfg_radio_row ours;
	ours.name = QStringLiteral("wlan0");
	ours.activated = true;
	ours.supplicant = true;
	check(ours.state() == QStringLiteral("netcfgd's"), "a working radio says so plainly");

	ncfg_radio_row stalled;
	stalled.activated = true;
	stalled.supplicant = false;
	check(stalled.state().contains(QStringLiteral("no supplicant")),
	      "activated with nothing answering is named as the fault it is");

	ncfg_radio_row theirs;
	theirs.activated = false;
	theirs.supplicant = true;
	check(theirs.state().contains(QStringLiteral("another manager")),
	      "a radio somebody else holds says who has it");
	check(theirs.state().contains(QStringLiteral("stop it")),
	      "and says what to do about it, which is the whole point");

	ncfg_radio_row free_radio;
	free_radio.activated = false;
	free_radio.supplicant = false;
	check(free_radio.state() == QStringLiteral("not activated"),
	      "a free radio is not confused with somebody else's");

	/* The distinction the fourth state must not blur: two radios that are both
	 * "not activated" and need entirely different things done about them. */
	check(theirs.state() != free_radio.state(),
	      "the two unactivated states are not the same sentence");

	if (failures) {
		fprintf(stderr, "wifi_radio_states: %d failed\n", failures);
		return 1;
	}
	fprintf(stderr, "wifi_radio_states: all checks passed\n");
	return 0;
}
