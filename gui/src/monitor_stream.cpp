/*
 * monitor_stream.cpp -- the notifier described in monitor_stream.h.
 */
#include "monitor_stream.h"

#include <QSocketNotifier>

ncfg_monitor_stream::ncfg_monitor_stream(QObject *parent) : QObject(parent) {}

ncfg_monitor_stream::~ncfg_monitor_stream()
{
	stop();
}

bool ncfg_monitor_stream::start(const QString &socket_path, QString *error)
{
	stop();

	const QByteArray requested = socket_path.toUtf8();
	char message[NCFG_ERROR_MAX];

	monitor = ncfg_monitor_open(requested.isEmpty() ? nullptr : requested.constData(), message,
	                sizeof(message));
	if (!monitor) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}

	notifier = new QSocketNotifier(ncfg_monitor_fd(monitor), QSocketNotifier::Read, this);
	connect(notifier, &QSocketNotifier::activated, this, &ncfg_monitor_stream::readable);
	return true;
}

void ncfg_monitor_stream::stop()
{
	/* The notifier goes first. Destroying it after the descriptor is closed
	 * leaves Qt deregistering a descriptor number that the next open() in
	 * this process may already have been handed, and the symptom is a pane
	 * somewhere else that stops updating. */
	delete notifier;
	notifier = nullptr;

	if (monitor) {
		ncfg_monitor_close(monitor);
		monitor = nullptr;
	}
}

void ncfg_monitor_stream::readable()
{
	char message[NCFG_ERROR_MAX];

	/*
	 * Drain, rather than take one event per activation.
	 *
	 * One read off the socket can carry several whole lines, and the reader
	 * below the seam keeps the ones it has not been asked for. Once it has
	 * emptied the descriptor the notifier will not fire again -- so an event
	 * still sitting in that buffer would wait for the next unrelated one to
	 * arrive, and on an idle machine that is forever. Loop until it says it
	 * has nothing complete.
	 */
	for (;;) {
		ncfg_event_t event = {};
		const int result = ncfg_monitor_next(monitor, &event, message, sizeof(message));

		if (result == 0) {
			return;
		}
		if (result < 0) {
			const QString reason = QString::fromUtf8(message);
			stop();
			emit ended(reason);
			return;
		}

		ncfg_event_row row;
		row.kind = QString::fromUtf8(event.kind ? event.kind : "");
		row.interface = QString::fromUtf8(event.interface ? event.interface : "");
		row.summary = QString::fromUtf8(event.summary ? event.summary : "");
		row.raw = QString::fromUtf8(event.raw ? event.raw : "");
		ncfg_event_free(&event);

		emit arrived(row);
	}
}
