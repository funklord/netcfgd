/*
 * tray.cpp -- the tray applet described in tray.h.
 */
#include "tray.h"

#include "ncfg_connection.h"

#include <QAction>
#include <QIcon>
#include <QMenu>
#include <QPainter>
#include <QPixmap>
#include <QSystemTrayIcon>

/*
 * An icon, drawn rather than shipped.
 *
 * The theme's own `network-wireless` is used where the desktop has one, so
 * that netcfgd looks like everything else on the panel. Where it does not --
 * a bare window manager, a minimal image, the offscreen platform -- the
 * fallback is painted here.
 *
 * Painted and not a file because this tree ships no image assets and adding
 * the first one means a resource system, an install rule and a licence
 * question for a drawing nobody will look at closely. Three arcs and a dot is
 * what a wifi indicator is.
 */
QIcon ncfg_tray::painted_icon(ncfg_reach reach)
{
	QPixmap pixmap(22, 22);
	pixmap.fill(Qt::transparent);

	QPainter painter(&pixmap);
	painter.setRenderHint(QPainter::Antialiasing, true);
	/* Grey when there is nothing, amber when the machine is configured but
	 * has nowhere to send traffic, green when it has. The middle one is the
	 * state this icon used to draw as connected, and it is the one an
	 * operator most needs to see: a radio that joined a network and never
	 * got a usable route looks identical to a working one from every other
	 * angle. A colour of its own would be wrong on half the panels it lands
	 * on, so these stay close to the conventional three. */
	QColor ink(0x88, 0x88, 0x88);
	if (reach == ncfg_reach::routed) {
		ink = QColor(0x33, 0x99, 0x33);
	} else if (reach == ncfg_reach::local) {
		ink = QColor(0xcc, 0x88, 0x22);
	}
	QPen pen(ink);
	pen.setWidth(2);
	painter.setPen(pen);

	for (int arc = 0; arc < 3; arc++) {
		const int inset = 3 + arc * 4;
		const int size = 22 - inset * 2;
		painter.drawArc(inset, inset + 2, size, size, 30 * 16, 120 * 16);
	}
	painter.setBrush(pen.color());
	painter.drawEllipse(9, 15, 4, 4);
	painter.end();

	return QIcon(pixmap);
}

QIcon ncfg_tray::state_icon(ncfg_reach reach)
{
	QString name = QStringLiteral("network-offline");
	if (reach == ncfg_reach::routed) {
		name = QStringLiteral("network-wireless");
	} else if (reach == ncfg_reach::local) {
		/* The themed name for "joined, not usable". Falls through to the
		 * painted icon on a theme without it, which is the common case and
		 * why the painted one carries three colours of its own. */
		name = QStringLiteral("network-wireless-acquiring");
	}
	const QIcon themed = QIcon::fromTheme(name);
	return themed.isNull() ? painted_icon(reach) : themed;
}

ncfg_tray *ncfg_tray::create(ncfg_connection *connection, QObject *parent)
{
	if (!QSystemTrayIcon::isSystemTrayAvailable()) {
		return nullptr;
	}
	return new ncfg_tray(connection, parent);
}

ncfg_tray::ncfg_tray(ncfg_connection *connection, QObject *parent)
    : QObject(parent), connection(connection)
{
	menu = new QMenu();

	/* The state is the first thing in the menu and is not clickable: a menu
	 * whose first entry is a fact reads better than a tooltip nobody hovers
	 * for, and making it an action would invite a click that does nothing. */
	state_action = menu->addAction(QStringLiteral("netcfgd"));
	state_action->setEnabled(false);
	menu->addSeparator();

	QAction *show = menu->addAction(QStringLiteral("Show window"));
	connect(show, &QAction::triggered, this, &ncfg_tray::window_requested);

	disconnect_action = menu->addAction(QStringLiteral("Disconnect wifi"));
	connect(disconnect_action, &QAction::triggered, this, &ncfg_tray::disconnect_radio);

	menu->addSeparator();
	QAction *quit = menu->addAction(QStringLiteral("Quit"));
	connect(quit, &QAction::triggered, this, &ncfg_tray::quit_requested);

	icon = new QSystemTrayIcon(this);
	icon->setContextMenu(menu);
	icon->setIcon(state_icon(ncfg_reach::offline));
	connect(icon, &QSystemTrayIcon::activated, this,
	    [this](QSystemTrayIcon::ActivationReason reason) { activated(reason); });
	icon->show();

	refresh();
}

void ncfg_tray::refresh()
{
	QList<ncfg_link_row> links;
	QString error;

	if (!connection->links(&links, &error)) {
		/* The daemon's own words, including a refusal naming the tier. A
		 * tray that said "unavailable" would throw away the sentence that
		 * says what to do about it. */
		state_action->setText(error);
		icon->setToolTip(error);
		icon->setIcon(state_icon(ncfg_reach::offline));
		disconnect_action->setEnabled(false);
		radio.clear();
		return;
	}

	radio.clear();
	for (const ncfg_link_row &link : links) {
		if (link.wireless) {
			radio = link.name;
			break;
		}
	}

	if (radio.isEmpty()) {
		/* Wired-only machines are ordinary, so this is a state and not a
		 * complaint. The addresses are what the operator wants to know. */
		QStringList addressed;
		bool routed = false;
		for (const ncfg_link_row &link : links) {
			if (link.name == QStringLiteral("lo")) {
				continue;
			}
			if (!link.addresses.isEmpty()) {
				addressed << QStringLiteral("%1 %2").arg(link.name, link.addresses);
			}
			/* Any link with a default route will do: which one carries the
			 * traffic is the kernel's business and a metric's, and an icon
			 * that picked one would be answering a question nobody asked. */
			routed = routed || link.default_route;
		}
		const ncfg_reach reach = routed      ? ncfg_reach::routed
		                     : !addressed.isEmpty() ? ncfg_reach::local
		                                    : ncfg_reach::offline;
		QString line = addressed.isEmpty()
		           ? QStringLiteral("no addressed interface")
		           : addressed.join(QStringLiteral(", "));
		if (reach == ncfg_reach::local) {
			/* Said outright, because this is the state that used to be
			 * drawn as connected: an address with nothing to route
			 * through is a machine that will fail every request and look
			 * configured while it does. */
			line += QStringLiteral(" -- no default route");
		}
		state_action->setText(line);
		icon->setToolTip(line);
		icon->setIcon(state_icon(reach));
		disconnect_action->setEnabled(false);
		return;
	}

	ncfg_wifi_status_row state;
	if (!connection->wifi_status(radio, &state, &error)) {
		state_action->setText(error);
		icon->setToolTip(error);
		icon->setIcon(state_icon(ncfg_reach::offline));
		disconnect_action->setEnabled(false);
		return;
	}

	/* **Association is not connectivity, and this icon used to say it was.**
	 * `state.network` non-empty means the supplicant has joined something --
	 * the earliest step, and true of a radio that never got a lease. What the
	 * operator wants from a tray is whether traffic can leave, so the radio's
	 * own link row is consulted for an address and a default route, and the
	 * icon reports the furthest rung actually reached. */
	bool addressed = false;
	bool routed = false;
	for (const ncfg_link_row &link : links) {
		if (link.name != radio) {
			continue;
		}
		addressed = !link.addresses.isEmpty();
		routed = link.default_route;
		break;
	}
	const bool joined = !state.network.isEmpty() || !state.display.isEmpty();
	const ncfg_reach reach = routed ? ncfg_reach::routed
	                     : (joined || addressed) ? ncfg_reach::local
	                                     : ncfg_reach::offline;

	/* One spelling, composed on the row, so this and the wifi tab cannot
	 * drift into two descriptions of one radio. */
	QString line = state.summary();
	if (reach == ncfg_reach::local) {
		line += addressed ? QStringLiteral(" -- no default route")
		            : QStringLiteral(" -- joined, no address");
	}
	state_action->setText(line);
	icon->setToolTip(line);
	icon->setIcon(state_icon(reach));
	disconnect_action->setEnabled(true);
}

void ncfg_tray::activated(int reason)
{
	if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick) {
		emit window_requested();
	}
}

void ncfg_tray::disconnect_radio()
{
	if (radio.isEmpty()) {
		return;
	}
	QString error;
	if (!connection->wifi_disconnect(radio, &error)) {
		state_action->setText(error);
		icon->setToolTip(error);
		return;
	}
	refresh();
	emit changed();
}
