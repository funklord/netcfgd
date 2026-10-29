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
 *   **Scan on its own.** A scan blocks for as long as the radio takes to walk
 *   its channels and it transmits probe requests -- doing that because
 *   somebody opened a menu would be wrong twice over. So the `Connect to`
 *   submenu lists what the last scan *the operator asked for* found, and
 *   asking is an entry of its own in that submenu. Nothing scans on a timer
 *   or on the menu opening.
 *
 *   **Applying.** A menu is the wrong place to change a machine without
 *   showing the plan first, which is the whole product. Disconnecting, and
 *   joining a network the configuration already names, are offered because
 *   they are the `wifi` tier and need no plan to understand: the join is by
 *   the network's id, exactly as the wifi tab's, and writes nothing.
 *   Joining a network the configuration does *not* name needs a block
 *   written, so that entry opens the window's wifi tab instead.
 *
 * THE ONE ADMIN-TIER THING IT DOES, AND WHY
 *   **Switching profiles**, which is a configuration write and therefore the
 *   `admin` tier. This paragraph used to say the tray did nothing of the kind.
 *   It does now, by instruction, and the reason it is the right exception is
 *   that a profile is the one change whose entire value is being one click
 *   away: an operator moving between office, home and offline is doing it
 *   several times a day, and a change that costs a window and a plan review
 *   each time is one they will stop making.
 *
 *   It is not silent. Switching asks first, naming the profile and saying
 *   plainly that the network is about to be reconfigured -- because the daemon
 *   reconciles a changed configuration on its own, so writing the selection
 *   *is* the change. That confirmation is this menu's stand-in for the plan.
 *
 * IF THERE IS NO TRAY
 *   Nothing is created and the window behaves as it always did. A desktop
 *   without a status-notifier host is ordinary, and a client that refused to
 *   start over it would be a client nobody could use on that desktop.
 */
#ifndef NCFG_TRAY_H
#define NCFG_TRAY_H

#include <QDateTime>
#include <QList>
#include <QObject>
#include <QString>

#include <QIcon>

/* For `ncfg_rung_t` and `ncfg_connectivity_row`: the tray renders the daemon's
 * answer and does not compute one (0243). */
#include "ncfg_connection.h"

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

/*
 * One entry in the `Connect to` submenu: a saved network some access point in
 * the last scan carries.
 *
 * **Saved networks only, and keyed by the network's id rather than its
 * SSID.** The id is what `wifi_connect` takes and what keeps the join inside
 * the `wifi` tier; an access point nothing in the configuration names has no
 * id to send. Several access points carrying one network are one entry, at
 * the strongest signal any of them was heard at, because the supplicant picks
 * the BSS and an operator choosing between two identical names has nothing to
 * choose by.
 */
struct ncfg_tray_choice {
	QString network; /* the id `wifi_connect` takes */
	QString label;
	int     signal = 0;
	bool    current = false;
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
	static ncfg_reach reach_of(ncfg_rung_t rung);
	static QString line_for(const ncfg_connectivity_row &state);
	/* The submenu's entries, strongest first, from a scan and the network the
	 * radio is on. Public for the reason the icon functions are: the menu
	 * itself needs a notification host, and this is the part of it that
	 * decides what the menu says. */
	static QList<ncfg_tray_choice> choices(const QList<ncfg_access_point_row> &scanned,
	                                       const QString &current);

	void refresh();

signals:
	/* The operator asked to see the window, or to leave. The window owns
	 * both answers; the tray only reports that they were asked for. */
	void window_requested();
	/* The operator wants a network the configuration does not name, which
	 * means writing a block: the window's wifi tab is where that is done. */
	void wifi_requested();
	void quit_requested();
	void changed();

private slots:
	void activated(int reason);
	void disconnect_radio();
	/* Write the selection, having asked. An empty name means no profile
	 * chosen, which is the default and is not a profile called "none". */
	void choose_profile(const QString &name);
	void scan();
	void join(const QString &network);

private:
	ncfg_tray(ncfg_connection *connection, QObject *parent);

	ncfg_connection *connection;
	QSystemTrayIcon *icon;
	QMenu           *menu;
	QAction         *state_action;
	QAction         *disconnect_action;
	QMenu           *profile_menu;
	QMenu           *join_menu;
	QString          radio;
	/* The last scan the operator asked for, kept so that the submenu can be
	 * rebuilt on every refresh -- the tick follows the radio when something
	 * else moves it -- without scanning again. `scanned_at` is null until
	 * there has been one, which is not the same as a scan that found
	 * nothing. */
	QList<ncfg_access_point_row> scanned;
	QString                      scanned_radio;
	QString                      scan_stale;
	QDateTime                    scanned_at;
	void rebuild_join(const QString &current);
	/* Rebuilt on every refresh, because a profile can appear or be chosen
	 * from anywhere -- `ncfg`, an editor, another client. A menu built once
	 * would go quietly stale, which is the failure this tray exists to not
	 * have. */
	void rebuild_profiles();
};

#endif /* NCFG_TRAY_H */
