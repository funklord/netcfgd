/*
 * stations_view.h -- who is connected to the access points this machine runs.
 *
 * A tab of its own because the stations are a list, which is this program's
 * rule for what earns one, and because they are a different question from the
 * wifi tab's. That tab is this machine as a client and the access points it
 * is configured to run; this one is the other machines, on those access
 * points, right now (project.md 10.603). `ncfg wifi clients` and the TUI's
 * access-point pane already answer it; the GUI was the one client that could
 * configure an access point and not say who was on it.
 *
 * **Every running access point in one table**, with the access point as the
 * first column, rather than one table per access point or a chooser. A router
 * runs one or two, and "is my phone on the 5 GHz one" is answered by reading
 * down a column, which a chooser would turn into a search.
 *
 * Read-only. Removing a station is a change to the access point's
 * `access_control` list, which is the access point dialog's to write; a
 * "kick" button here would be a second, unrecorded way to say the same thing
 * the document says, and the next apply would undo it.
 */
#ifndef NCFG_STATIONS_VIEW_H
#define NCFG_STATIONS_VIEW_H

#include <QWidget>

class ncfg_connection;
class ncfg_table_view;

class ncfg_stations_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_stations_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	void refresh();

signals:
	void reported(const QString &summary);

private:
	ncfg_connection *connection;
	ncfg_table_view *table;
};

#endif /* NCFG_STATIONS_VIEW_H */
