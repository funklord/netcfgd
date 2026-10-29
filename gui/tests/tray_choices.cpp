/*
 * tray_choices.cpp -- what the tray's `Connect to` submenu offers.
 *
 * The menu itself needs a notification host, which no machine this builds on
 * has (tray_icon.cpp says how that was measured). `ncfg_tray::choices` is the
 * part that decides what the menu says, and it needs nothing: a scan and the
 * network the radio is on go in, entries come out.
 */

#include "../src/tray.h"

#include <QApplication>

#include <cstdio>

static int failures;

static void check(bool condition, const char *what)
{
	fprintf(stderr, "tray_choices: %-60s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static ncfg_access_point_row point(const char *bssid, const char *display, const char *configured,
                                   int signal)
{
	ncfg_access_point_row row;
	row.bssid = QString::fromLatin1(bssid);
	row.display = QString::fromLatin1(display);
	row.configured = QString::fromLatin1(configured);
	row.signal = signal;
	return row;
}

int main(int argc, char **argv)
{
	QApplication application(argc, argv);

	const QList<ncfg_access_point_row> scanned = {
		point("02:00:00:00:00:01", "Cafe", "", -40),
		point("02:00:00:00:00:02", "Home", "home", -70),
		point("02:00:00:00:00:03", "Home", "home", -50),
		point("02:00:00:00:00:04", "Office", "office", -60),
	};

	const QList<ncfg_tray_choice> found = ncfg_tray::choices(scanned, QStringLiteral("office"));

	/* An access point nothing names has no id to join by, and offering it
	 * would be offering a click that can only be refused. */
	bool cafe = false;
	for (const ncfg_tray_choice &choice : found) {
		if (choice.label == QStringLiteral("Cafe")) {
			cafe = true;
		}
	}
	check(!cafe, "an access point no network names is not offered");
	check(found.size() == 2, "two access points carrying one network are one entry");
	check(found.size() == 2 && found.at(0).network == QStringLiteral("home"),
	    "the strongest is first");
	check(found.size() == 2 && found.at(0).signal == -50,
	    "a merged entry carries the strongest signal heard");
	check(found.size() == 2 && !found.at(0).current && found.at(1).current,
	    "the network the radio is on is the one ticked");

	const QList<ncfg_tray_choice> unasked = ncfg_tray::choices(scanned, QString());
	bool ticked = false;
	for (const ncfg_tray_choice &choice : unasked) {
		ticked = ticked || choice.current;
	}
	check(!ticked, "with no current network, nothing is ticked");

	/* Two blocks for one SSID -- a passphrase and an enterprise login, say. */
	QList<ncfg_access_point_row> corp;
	corp.append(point("02:00:00:00:00:05", "Corp", "corp-psk", -55));
	corp.append(point("02:00:00:00:00:06", "Corp", "corp-eap", -45));
	const QList<ncfg_tray_choice> twins = ncfg_tray::choices(corp, QString());
	check(twins.size() == 2 && twins.at(0).label != twins.at(1).label,
	    "two networks with one name read differently");
	check(twins.size() == 2 && twins.at(0).label.contains(QStringLiteral("corp-eap")),
	    "and the difference is the id");

	const QList<ncfg_tray_choice> hidden =
	    ncfg_tray::choices({ point("02:00:00:00:00:07", "", "attic", -65) }, QString());
	check(hidden.size() == 1 && hidden.at(0).label == QStringLiteral("attic"),
	    "a network the scan has no name for is labelled by its id");

	check(ncfg_tray::choices({}, QString()).isEmpty(), "an empty scan offers nothing");

	return failures ? 1 : 0;
}
