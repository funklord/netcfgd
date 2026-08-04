/*
 * events_view.cpp -- the pane described in events_view.h.
 */
#include "events_view.h"

#include "ncfg_connection.h"

#include <QFontDatabase>
#include <QListWidget>
#include <QScrollBar>
#include <QVBoxLayout>

namespace {

/*
 * How many lines the pane keeps.
 *
 * A stream is unbounded and a flapping carrier can produce events for as long
 * as the machine is up, so a pane that kept everything would be a slow memory
 * leak with a scrollbar. Old lines fall off the top; what a person is watching
 * for is nearly always the last screen of them, and the daemon's own log is
 * where history lives.
 */
constexpr int line_limit = 2000;

/* Wide enough for the longest kind the daemon emits (`confirm_resolved`), so
 * the interface and the summary line up in a fixed-pitch font instead of
 * sawing left and right as kinds change. */
constexpr int kind_width = 17;

} /* namespace */

ncfg_events_view::ncfg_events_view(ncfg_connection *connection, QWidget *parent)
	: QWidget(parent), connection(connection)
{
	auto *layout = new QVBoxLayout(this);

	lines = new QListWidget(this);
	/* Fixed pitch because the lines are columns of text and a proportional
	 * font would make them ragged -- the same reason the TUI pads its
	 * fields to a width. */
	lines->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
	lines->setSelectionMode(QAbstractItemView::ExtendedSelection);
	lines->setTextElideMode(Qt::ElideNone);
	lines->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
	layout->addWidget(lines);

	stream = new ncfg_monitor_stream(this);
	connect(stream, &ncfg_monitor_stream::arrived, this, &ncfg_events_view::arrived);
	connect(stream, &ncfg_monitor_stream::ended, this, &ncfg_events_view::ended);
}

void ncfg_events_view::refresh()
{
	if (stream->is_running()) {
		return;
	}

	QString error;
	/* The same socket the request connection resolved, and not the default
	 * resolved a second time: a window pointed at one daemon by --socket
	 * must not quietly subscribe to another. */
	if (!stream->start(connection->where(), &error)) {
		append(QStringLiteral("monitor unavailable -- %1").arg(error), QString());
		emit reported(error);
		return;
	}
	append(QStringLiteral("subscribed to %1").arg(connection->where()), QString());
	emit reported(QStringLiteral("monitoring %1").arg(connection->where()));
}

void ncfg_events_view::arrived(const ncfg_event_row &event)
{
	QString line = event.kind.leftJustified(kind_width, QLatin1Char(' '));

	if (!event.interface.isEmpty()) {
		line += event.interface + QStringLiteral(": ");
	}
	line += event.summary;

	append(line, event.raw);
	counted++;
	emit reported(QStringLiteral("%1 events").arg(counted));
}

void ncfg_events_view::ended(const QString &reason)
{
	/* Said on the pane, not swallowed. A monitor that stopped silently
	 * leaves a window that looks merely quiet, which is the one state an
	 * operator must never mistake for a calm network. */
	append(QStringLiteral("monitor stopped -- %1").arg(reason), QString());
	emit reported(QStringLiteral("monitor stopped -- %1").arg(reason));
}

void ncfg_events_view::append(const QString &line, const QString &raw)
{
	/* Only follow the tail if the reader is already at it. Yanking the view
	 * back down while somebody is reading an event from a minute ago is how
	 * a live pane becomes one people close. */
	QScrollBar *bar = lines->verticalScrollBar();
	const bool following = bar->value() >= bar->maximum() - 2;

	auto *item = new QListWidgetItem(line, lines);
	if (!raw.isEmpty()) {
		/* The whole event, on hover. netcfgd may grow a field on an
		 * event kind after this client was built, and a pane that only
		 * showed the fields it knew would make that field invisible
		 * rather than merely unformatted. */
		item->setToolTip(raw);
	}

	while (lines->count() > line_limit) {
		delete lines->takeItem(0);
	}
	if (following) {
		lines->scrollToBottom();
	}
}
