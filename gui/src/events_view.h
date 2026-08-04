/*
 * events_view.h -- the live pane, fed by netcfgd's monitor stream.
 *
 * WHY THIS TAB EXISTS
 *   A network changes without anybody asking it to: a cable comes out, a lease
 *   expires, drift is noticed, a confirm window opens or resolves. The daemon
 *   says so on the `monitor` stream, and a client that only ever showed what it
 *   had last asked for would be a client that goes quietly stale in front of
 *   somebody who is trusting it.
 *
 * WHAT IT DOES NOT DO
 *   Poll. The stream's descriptor is watched by the same event loop that draws
 *   the window -- see monitor_stream.h. Nothing here has a timer.
 */
#ifndef NCFG_EVENTS_VIEW_H
#define NCFG_EVENTS_VIEW_H

#include <QWidget>

#include "monitor_stream.h"

class QListWidget;

class ncfg_connection;

class ncfg_events_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_events_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	/* Subscribes if the stream is not running. Refresh on a live pane is
	 * deliberately a no-op rather than a reconnect: the events already on
	 * screen are a record of what happened, and dropping them to re-open a
	 * stream that is working would destroy the only copy. */
	void refresh();

signals:
	void reported(const QString &summary);

	/* An event arrived that means the machine or the document moved, so
	 * anything drawn from either is now describing the past.
	 *
	 * Emitted per event and deliberately not throttled here: this view knows
	 * what happened and the window knows what it costs to look again, and
	 * putting the rate limit in the emitter would make every future consumer
	 * inherit one view's guess about it. */
	void moved();

private slots:
	void arrived(const ncfg_event_row &event);
	void ended(const QString &reason);

private:
	void append(const QString &line, const QString &raw);

	ncfg_connection     *connection;
	ncfg_monitor_stream *stream;
	QListWidget         *lines;
	int                  counted = 0;
};

#endif /* NCFG_EVENTS_VIEW_H */
