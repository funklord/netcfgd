/*
 * station_states.cpp -- what the stations tab says is surprising about a
 * station, under each of an access point's three list policies.
 *
 * The one fact worth a probe: `listed` means the opposite thing under `allow`
 * and `deny`. A listed station is the normal case under one and should be
 * impossible under the other, so a view that read the flag alone would mark
 * every welcome guest on an allow list and miss every intruder on a deny
 * list. The wording matches `ncfg wifi clients`, so the two clients say the
 * same thing about the same station.
 */

#include "../src/ncfg_connection.h"

#include <QCoreApplication>
#include <QString>

#include <cstdio>

static int failures;

static void check(bool condition, const char *what)
{
	fprintf(stderr, "station_states: %-56s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

int main(int argc, char **argv)
{
	QCoreApplication app(argc, argv);

	const QString allow = QStringLiteral("allow");
	const QString deny = QStringLiteral("deny");
	const QString none;

	ncfg_station_row listed;
	listed.authorized = true;
	listed.listed = true;
	ncfg_station_row unlisted;
	unlisted.authorized = true;
	unlisted.listed = false;

	check(!listed.anomalous(allow) && listed.state(allow).isEmpty(),
	      "a listed station under allow is the normal case");
	check(unlisted.anomalous(allow) &&
	          unlisted.state(allow).contains(QStringLiteral("not on the allow list")),
	      "an unlisted station under allow is named as the anomaly");
	check(listed.anomalous(deny) &&
	          listed.state(deny).contains(QStringLiteral("on the deny list")),
	      "a listed station under deny is named as the anomaly");
	check(!unlisted.anomalous(deny) && unlisted.state(deny).isEmpty(),
	      "an unlisted station under deny is the normal case");
	check(!listed.anomalous(none) && !unlisted.anomalous(none),
	      "with no list, nobody is against it");

	ncfg_station_row pending;
	pending.authorized = false;
	check(!pending.anomalous(none) &&
	          pending.state(none) == QStringLiteral("associated, not authorized"),
	      "a half-joined station is said, not counted as an anomaly");

	if (failures) {
		fprintf(stderr, "station_states: %d failed\n", failures);
		return 1;
	}
	fprintf(stderr, "station_states: all checks passed\n");
	return 0;
}
