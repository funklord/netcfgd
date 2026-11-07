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
#include <QStringList>

class QLabel;
class QTabWidget;
class QTimer;

class ncfg_connection;
class ncfg_access_view;
class ncfg_dns_view;
class ncfg_links_view;
class ncfg_devices_view;
class ncfg_modems_view;
class ncfg_stations_view;
class ncfg_leases_view;
class ncfg_global_view;
class ncfg_config_view;
class ncfg_secrets_view;
class ncfg_profiles_view;
class ncfg_rules_view;
class ncfg_firewall_view;
class ncfg_host_lists_view;
class ncfg_block_lists_view;
class ncfg_dns_records_view;
class ncfg_meshes_view;
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
	~ncfg_main_window() override;

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

private:
	/* The pane the operator is actually looking at.
	 *
	 * `tabs->currentWidget()` is a *group* now, and a group has no rows to
	 * draw. Everything that asks "which tab is in front" descends one level,
	 * and it is one function so that nothing forgets to. */
	QWidget *current_pane() const;

private slots:
	void note(const QString &summary);
	/* Another node chosen in the toolbar's node box, or this machine (10.699). */
	void node_chosen(int index);
	void join_host();

public slots:
	/*
	 * Another node's events cursor, read on the node timer (10.704): a new
	 * event, a gap or a restart refreshes the window and lists the events;
	 * where the cursor cannot be read, every third tick refreshes anyway, as
	 * the 15-second refresh did before there was a cursor. Public so that a
	 * probe can drive it without waiting on the timer.
	 */
	void poll_node();
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
	/* The node box, and the 15-second refresh a node needs for want of an
	 * event stream; the socket this machine's daemon was reached on, to go
	 * back to (10.699). */
	class QComboBox   *nodes;
	class QPushButton *join_button = nullptr;
	/* Every node at once, where there are any (10.710); null otherwise. */
	class ncfg_fleet_view *fleet = nullptr;
	static QStringList estate_members();
	QTimer            *poll;
	QString            home_socket;
	void               follow_node();
	/* Where the node's events were last read to, once known (10.704). */
	size_t             node_cursor = 0;
	bool               cursor_known = false;
	int                blind_ticks = 0;
	QTabWidget        *tabs;
	/* The three groups. Thirteen tabs in one row is a list to read rather
	 * than a place to look, and the grouping is the question an operator
	 * arrives with: what is this machine doing, what is it configured to do,
	 * and what is about to change. */
	QTabWidget        *machine;
	QTabWidget        *configuration;
	QTabWidget        *changes;
	ncfg_links_view *links;
	ncfg_devices_view *devices;
	ncfg_modems_view  *modems;
	ncfg_stations_view *stations;
	ncfg_leases_view *leases;
	ncfg_global_view  *global;
	ncfg_secrets_view *secrets;
	ncfg_config_view  *config;
	ncfg_profiles_view *profiles;
	ncfg_rules_view *rules;
	ncfg_firewall_view *firewall;
	ncfg_host_lists_view *host_lists;
	ncfg_dns_records_view *dns_records;
	ncfg_block_lists_view *block_lists;
	ncfg_meshes_view *meshes;
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
