/*
 * stations_view.cpp -- the stations table described in stations_view.h.
 *
 * The table itself is `ncfg_table_view`, shared with every other list here.
 * What is this view's own is which access points to ask, and turning a
 * station into strings.
 */
#include "stations_view.h"

#include "ncfg_connection.h"
#include "table_view.h"

#include <QVBoxLayout>

namespace {

/* Minutes and hours rather than seconds: how long a phone has been on is a
 * question about the last hour, not the last second, and the TUI rounds to
 * minutes for the same reason. */
QString connected_of(const ncfg_station_row &station)
{
	if (station.connected_seconds < 0) {
		return QString();
	}
	const long long minutes = station.connected_seconds / 60;
	if (minutes < 60) {
		return QStringLiteral("%1m").arg(minutes);
	}
	return QStringLiteral("%1h %2m").arg(minutes / 60).arg(minutes % 60);
}

/* Seconds, because idle is the number steering reads: a station silent for
 * more than 30 s is not steered (project.md 10.597), and that threshold is
 * only checkable against a column in the same unit. */
QString idle_of(const ncfg_station_row &station)
{
	if (station.inactive_msec < 0) {
		return QString();
	}
	return QStringLiteral("%1s").arg(station.inactive_msec / 1000);
}

} /* namespace */

ncfg_stations_view::ncfg_stations_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	/* Which access point, then who -- the address that identifies the station
	 * to hostapd, and the name and address netcfgd's DHCP server leased it
	 * where it leased one -- then how well, then what is surprising. */
	QStringList columns;
	columns << QStringLiteral("access point") << QStringLiteral("device")
	        << QStringLiteral("station") << QStringLiteral("name")
	        << QStringLiteral("ipv4") << QStringLiteral("signal")
	        << QStringLiteral("connected") << QStringLiteral("idle")
	        << QStringLiteral("state");
	table = new ncfg_table_view(columns, QStringLiteral("stations_note"), this);

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);
}

void ncfg_stations_view::refresh()
{
	QList<ncfg_access_point_config> access_points;
	QString error;

	if (!connection->access_points(&access_points, &error)) {
		table->show_error(error);
		emit reported(error);
		return;
	}

	QList<QStringList> rows;
	int running = 0;
	int anomalies = 0;
	QStringList unreadable;
	for (const ncfg_access_point_config &access_point : access_points) {
		/* Only one netcfgd has started: hostapd is what holds the station
		 * list, and a configured access point with no hostapd has none to
		 * give. */
		if (!access_point.running) {
			continue;
		}
		running++;

		QList<ncfg_station_row> stations;
		QString policy;
		QString why;
		if (!connection->stations(access_point.device, &stations, &policy, &why)) {
			/* One access point that does not answer is not a reason to
			 * hide the others; say which, under the table. */
			unreadable << QStringLiteral("%1 (%2)").arg(access_point.device, why);
			continue;
		}
		const QString label =
		    access_point.name.isEmpty() ? access_point.ssid : access_point.name;
		for (const ncfg_station_row &station : stations) {
			if (station.anomalous(policy)) {
				anomalies++;
			}
			QStringList cells;
			cells << label << access_point.device << station.address << station.hostname
			      << station.ipv4;
			cells << (station.has_signal ? QStringLiteral("%1 dBm").arg(station.signal)
			                             : QString());
			cells << connected_of(station) << idle_of(station) << station.state(policy);
			rows << cells;
		}
	}
	table->show_rows(rows);

	if (running == 0) {
		table->set_note(QStringLiteral(
		    "No access point netcfgd runs is up, so there is nobody to list. An "
		    "access point is configured on the wifi tab; once netcfgd has started "
		    "hostapd for it, the stations associated with it appear here."));
		emit reported(QStringLiteral("no access point running"));
		return;
	}

	QString note;
	if (!unreadable.isEmpty()) {
		note += QStringLiteral("Could not read the stations of %1. ")
		            .arg(unreadable.join(QStringLiteral(", ")));
	}
	if (anomalies > 0) {
		note += QStringLiteral(
		    "%1 connected against its access point's list -- the list was changed "
		    "and the station was not disconnected, or hostapd has not been told. "
		    "An apply sends the list again. ")
		            .arg(anomalies == 1 ? QStringLiteral("One station is")
		                                : QStringLiteral("%1 stations are").arg(anomalies));
	}
	/* The privacy point is the note's, not a footnote's: this table is other
	 * people's devices, and where a name comes from decides how far it is to
	 * be trusted. */
	note += QStringLiteral(
	    "A name and address are shown only for a station netcfgd's own DHCP server "
	    "leased one to, and the name is whatever the device said it was called -- "
	    "it identifies nothing. Idle is seconds since hostapd last heard from the "
	    "station; one silent for more than 30 s is never steered.");
	table->set_note(note);
	emit reported(QStringLiteral("%1 stations").arg(rows.size()));
}
