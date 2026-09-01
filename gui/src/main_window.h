/*
 * main_window.h -- the one window there is, and its three tabs.
 *
 * WHY THESE THREE
 *   They are `ncfg`'s three answers. What is the machine doing (`status`), what
 *   would change and why (`plan`), and what has happened since you looked
 *   (`monitor`). The TUI's panes are the same three for the same reason, and a
 *   client that had only the first would be a client that can watch but never
 *   understand.
 *
 * WHAT IS ON SCREEN NO MATTER WHICH TAB
 *   **Which machine this is**, and **what the daemon said when it refused**.
 *   gui/project.md sec 4 says the first must never be inferable rather than
 *   visible, and the second matters more than it looks -- 0013's tiers mean an
 *   unprivileged client is told no, and a window that showed an empty table for
 *   that would be a client that lies.
 */
#ifndef NCFG_MAIN_WINDOW_H
#define NCFG_MAIN_WINDOW_H

#include <QHash>
#include <QMainWindow>
#include <QString>

class QLabel;
class QTabWidget;
class QTimer;

class ncfg_connection;
class ncfg_access_view;
class ncfg_dns_view;
class ncfg_devices_view;
class ncfg_modems_view;
class ncfg_global_view;
class ncfg_profiles_view;
class ncfg_rules_view;
class ncfg_bluetooth_view;
class ncfg_hooks_view;
class ncfg_wifi_view;
class ncfg_events_view;
class ncfg_plan_view;
class ncfg_tray;

class ncfg_main_window : public QMainWindow {
	Q_OBJECT

public:
	explicit ncfg_main_window(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	/* Re-asks the tab in front of the operator. Refreshing all three would
	 * mean two extra round trips for a pane nobody is looking at, and the
	 * events pane has nothing to re-ask in the first place -- it is fed. */
	void refresh();

	/* Everything, after something changed the machine. */
	void reload();

	void open_apply();

	/* Adopt the tray, where the desktop has one. The window owns it because
	 * the window is what "show" and "quit" mean, and because a refresh has to
	 * reach both -- the icon saying one thing while a tab says another is the
	 * drift this project keeps finding in smaller places. */
	void attach_tray(ncfg_tray *tray);

protected:
	/* Hides to the tray instead of closing, but only when there is a tray and
	 * the operator asked for one. Doing it unconditionally is the behaviour
	 * everybody has been surprised by at least once. */
	void closeEvent(QCloseEvent *event) override;

private slots:
	void note(const QString &summary);
	void tab_changed();

	/* An event says the machine moved. Restarts the settle timer rather than
	 * refreshing, so a burst of events costs one look. */
	void moved();

private:
	ncfg_connection   *connection;
	ncfg_tray         *tray = nullptr;
	/* Single-shot, restarted on every event, so the refresh happens once the
	 * events stop rather than once per event. Not a poll: it never fires
	 * unless something arrived, which is the difference between this and
	 * asking the daemon on a schedule. */
	QTimer            *settle;
	QTabWidget        *tabs;
	ncfg_devices_view *devices;
	ncfg_modems_view  *modems;
	ncfg_global_view  *global;
	ncfg_profiles_view *profiles;
	ncfg_rules_view *rules;
	ncfg_bluetooth_view *bluetooth;
	ncfg_hooks_view *hooks;
	ncfg_access_view  *access;
	ncfg_dns_view     *dns;
	ncfg_wifi_view    *wifi;
	ncfg_plan_view    *plan;
	ncfg_events_view  *events;
	QLabel            *where;
	QLabel            *status;

	/* One remembered line per tab. Without it, switching tabs leaves the
	 * status bar describing the pane the operator just left, which is the
	 * kind of small lie that costs somebody an hour. */
	QHash<QWidget *, QString> summaries;
};

#endif /* NCFG_MAIN_WINDOW_H */
