/*
 * tray.h -- what the machine's network is doing, without a window open.
 *
 * M8 has listed "GUI + tray applet" since it was written and the applet was
 * never started, which section 10 item 5 records. This is it.
 *
 * WHAT IT IS FOR
 *   The operator this was written for has no NetworkManager applet, so the
 *   shim's tiers 1 and 2 buy them nothing and there is no desktop indicator on
 *   the machine at all. A tray icon is the one thing a GUI gives that `ncfg`
 *   and `ncfg tui` structurally cannot: an answer to "am I on the network"
 *   that costs no window and no command.
 *
 * WHAT IT DELIBERATELY DOES NOT DO
 *   **Scan.** A scan blocks for as long as the radio takes to walk its
 *   channels and it transmits probe requests -- doing that because somebody
 *   opened a menu would be wrong twice over. Joining therefore lives in the
 *   window, where a scan is a thing the operator asked for.
 *
 *   **Anything needing the admin tier.** Disconnecting is the `wifi` tier and
 *   is offered; applying is not, because a menu is the wrong place to change a
 *   machine without showing the plan first, which is the whole product.
 *
 * IF THERE IS NO TRAY
 *   Nothing is created and the window behaves as it always did. A desktop
 *   without a status-notifier host is ordinary, and a client that refused to
 *   start over it would be a client nobody could use on that desktop.
 */
#ifndef NCFG_TRAY_H
#define NCFG_TRAY_H

#include <QObject>
#include <QString>

#include <QIcon>

class QAction;
class QMenu;
class QSystemTrayIcon;

class ncfg_connection;

/*
 * What a tray icon can honestly claim, from what is observable here.
 *
 * **A boolean cannot be faithful, which is why this is not one.** The tray
 * showed a radio as connected on association alone -- the earliest of the
 * steps and the least informative, true of a machine that never got a lease.
 * An operator watching it had no way to tell "joined the network" from "the
 * network works", which are the two states worth telling apart.
 *
 * The ladder is what the machine can answer without sending a packet:
 * associated, then addressed, then something to route through. Reachability
 * itself needs a host to ask, and decision 0061 declined to have netcfgd
 * choose one -- so `routed` is the honest ceiling, and it is deliberately not
 * called `online`.
 */
enum class ncfg_reach {
	offline, /* no address, or a radio that has joined nothing */
	local,   /* addressed, with no default route to leave through */
	routed,  /* a default route in the main table */
};

class ncfg_tray : public QObject {
	Q_OBJECT

public:
	/* Returns nullptr when the desktop has no tray, which is not an error. */
	static ncfg_tray *create(ncfg_connection *connection, QObject *parent);

	/* The indicator, and the theme-or-fallback choice in front of it.
	 *
	 * Public because they are the only part of this class reachable without a
	 * notification host -- `create` returns nullptr where there is none, which
	 * is every machine this has been built on. Exposing them is what lets the
	 * icon be rendered and checked rather than asserted about; see
	 * gui/tests/tray_icon.cpp. Not otherwise called from outside. */
	static QIcon painted_icon(ncfg_reach reach);
	static QIcon state_icon(ncfg_reach reach);

	void refresh();

signals:
	/* The operator asked to see the window, or to leave. The window owns
	 * both answers; the tray only reports that they were asked for. */
	void window_requested();
	void quit_requested();
	void changed();

private slots:
	void activated(int reason);
	void disconnect_radio();

private:
	ncfg_tray(ncfg_connection *connection, QObject *parent);

	ncfg_connection *connection;
	QSystemTrayIcon *icon;
	QMenu           *menu;
	QAction         *state_action;
	QAction         *disconnect_action;
	QString          radio;
};

#endif /* NCFG_TRAY_H */
