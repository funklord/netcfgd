/*
 * monitor_stream.h -- netcfgd's event stream, in Qt's event loop.
 *
 * WHY A DESCRIPTOR AND NOT A THREAD
 *   client/ hands out ncfg_monitor_fd() precisely so that the program that
 *   already has an event loop owns the waiting. Qt has one, so this is a
 *   QSocketNotifier and nothing else: no thread, and no timer either. A timer
 *   would mean events arriving up to one tick late for no reason and the
 *   process waking when nothing happened, which on a phone is battery; a thread
 *   would mean a library deciding how this program is structured, and would put
 *   the marshalling of every event through a queued connection for the same
 *   result.
 *
 * WHY IT IS A CONNECTION OF ITS OWN
 *   `monitor` turns a connection into a stream and it never goes back -- after
 *   it the daemon writes events onto that connection and reads no more
 *   requests. So this opens its own, and the window keeps its request
 *   connection usable while the pane is live.
 */
#ifndef NCFG_MONITOR_STREAM_H
#define NCFG_MONITOR_STREAM_H

#include <QObject>
#include <QString>

#include "ncfg_connection.h"

class QSocketNotifier;

class ncfg_monitor_stream : public QObject {
	Q_OBJECT

public:
	explicit ncfg_monitor_stream(QObject *parent = nullptr);
	~ncfg_monitor_stream() override;

	/* `socket_path` empty means the C layer's default. Returns false with
	 * the daemon's or the C layer's own words -- a pane that could not
	 * subscribe says so, because a pane that merely stayed empty would be
	 * indistinguishable from a quiet network. */
	bool start(const QString &socket_path, QString *error);
	void stop();
	bool is_running() const { return monitor != nullptr; }

signals:
	void arrived(const ncfg_event_row &event);

	/* The stream is gone and no further events will come. Emitted rather
	 * than swallowed for the same reason: silence is not a state a reader
	 * can tell from a working subscription. */
	void ended(const QString &reason);

private slots:
	void readable();

private:
	ncfg_monitor_t  *monitor = nullptr;
	QSocketNotifier *notifier = nullptr;
};

#endif /* NCFG_MONITOR_STREAM_H */
