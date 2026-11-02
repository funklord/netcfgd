/*
 * tray_choices.cpp -- what the tray's `Connect to` submenu offers.
 *
 * The menu itself needs a notification host, which no machine this builds on
 * has (tray_icon.cpp says how that was measured). `ncfg_tray::choices` is the
 * part that decides what the menu says, and it needs nothing: a scan and the
 * network the radio is on go in, entries come out.
 *
 * The rule itself is the client library's and is tested there
 * (client_test's join choices); this holds the tray's conversion to it, so
 * that a row losing a field on the way down shows up here.
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
	row.name = QString::fromLatin1(display);
	row.named = *display != '\0';
	row.display = row.named ? row.name : QStringLiteral("(hidden)");
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

	/* Below the saved ones, the SSIDs nothing names: `ncfg_new_choices`,
	 * whose rule client_test holds. What is checked here is that every
	 * field the rule reads survives the conversion -- the SSID, and the three
	 * flags that decide what the dialog asks and whether it is offered. */
	QList<ncfg_access_point_row> around = scanned;
	around[0].ssid = QStringLiteral("43616665");
	around[0].secured = true;
	around[1].ssid = around[2].ssid = QStringLiteral("486f6d65");
	around[3].ssid = QStringLiteral("4f6666696365");
	ncfg_access_point_row library = point("02:00:00:00:00:08", "Library", "", -62);
	library.ssid = QStringLiteral("4c696272617279");
	library.secured = true;
	library.enterprise = true;
	around.append(library);
	ncfg_access_point_row owe = point("02:00:00:00:00:09", "Quiet", "", -30);
	owe.ssid = QStringLiteral("5175696574");
	owe.owe = true;
	around.append(owe);

	const QList<ncfg_tray_new_choice> heard = ncfg_tray::new_choices(around);
	check(heard.size() == 2, "the unsaved SSIDs are offered, and an OWE one is not");
	check(heard.size() == 2 && heard.at(0).label == QStringLiteral("Cafe") &&
	          heard.at(0).ssid == QStringLiteral("43616665"),
	    "by name, carrying the SSID the dialog sends");
	check(heard.size() == 2 && heard.at(0).secured && !heard.at(0).enterprise,
	    "a passphrase network says so");
	check(heard.size() == 2 && heard.at(1).enterprise, "and an 802.1X one says so");
	check(ncfg_tray::new_choices({}).isEmpty(), "an empty scan offers nothing new");

	/* What the tray says unasked when the network moves. */
	auto at = [](ncfg_rung_t rung, const char *label) {
		ncfg_connectivity_row row;
		row.rung = rung;
		row.label = QString::fromLatin1(label);
		return row;
	};
	const ncfg_connectivity_row off = at(ncfg_rung_offline, "");
	const ncfg_connectivity_row home_local = at(ncfg_rung_local, "home");
	const ncfg_connectivity_row home = at(ncfg_rung_routed, "home");
	const ncfg_connectivity_row home_probed = at(ncfg_rung_online, "home");
	const ncfg_connectivity_row elsewhere = at(ncfg_rung_routed, "cafe");
	check(ncfg_tray::notice_for(off, home) == QStringLiteral("Connected to home."),
	    "joining says where");
	check(ncfg_tray::notice_for(off, home_local).isEmpty(),
	    "the second a lease takes is not news");
	check(ncfg_tray::notice_for(home_local, home) == QStringLiteral("Connected to home."),
	    "and the route after it is");
	check(ncfg_tray::notice_for(home, elsewhere) == QStringLiteral("Connected to cafe."),
	    "moving to another network is said");
	check(ncfg_tray::notice_for(home, home_probed).isEmpty() &&
	          ncfg_tray::notice_for(home_probed, home).isEmpty(),
	    "a probe confirming the route is not a change");
	check(ncfg_tray::notice_for(home, home_local).contains(QStringLiteral("no default route")),
	    "losing the route on a network is said");
	check(ncfg_tray::notice_for(home, off) == QStringLiteral("Disconnected from home."),
	    "and losing the network, naming it");
	check(ncfg_tray::notice_for(home_local, off) == QStringLiteral("Disconnected from home."),
	    "from a network with no route too");
	check(ncfg_tray::notice_for(off, off).isEmpty() && ncfg_tray::notice_for(home, home).isEmpty(),
	    "and nothing when nothing moved");

	return failures ? 1 : 0;
}
