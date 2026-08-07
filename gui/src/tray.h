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

class QAction;
class QMenu;
class QSystemTrayIcon;

class ncfg_connection;

class ncfg_tray : public QObject {
	Q_OBJECT

public:
	/* Returns nullptr when the desktop has no tray, which is not an error. */
	static ncfg_tray *create(ncfg_connection *connection, QObject *parent);

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
