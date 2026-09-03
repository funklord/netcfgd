/*
 * wifi_view.h -- scan, join and leave a wireless network.
 *
 * The tab the operator this was written for actually needs: there is no
 * NetworkManager applet on their desktop, so the shim's tier 1 and 2 buy
 * nothing and `nmtui` is what they reach for. `ncfg tui` already has a wifi
 * pane; this is the same pane, in the same vocabulary, so that a person moving
 * between the two clients is not learning two words for one thing.
 *
 * WHAT IT DELIBERATELY CANNOT DO
 *   Join a network the configuration does not already describe. That is not a
 *   gap to fill in later: the socket has no request for it, because decision
 *   0013 puts joining a *known* network in the `wifi` tier and writing config
 *   in `admin`, and decision 0069 makes adding a network *writing a file*
 *   rather than a socket operation at all. So no passphrase is entered here and
 *   none can be read back (0029, 0031).
 *
 *   The consequence is visible instead of surprising: an access point with no
 *   `network` block is listed, marked, and not offered a join button. The
 *   proto's own note on that field asks for exactly this, on the grounds that
 *   the alternative is the operator finding out by being refused.
 *
 * WHY SCANNING IS A BUTTON AND NOT A TIMER
 *   A scan takes as long as the radio takes to walk its channels -- seconds, on
 *   hardware, and this pane blocks while it happens. A window that scanned on a
 *   refresh tick would stall on a cadence nobody chose, and a cached list is a
 *   list of places that may no longer be there.
 */
#ifndef NCFG_WIFI_VIEW_H
#define NCFG_WIFI_VIEW_H

#include <QList>
#include <QWidget>

#include "ncfg_connection.h"

class QComboBox;
class QLabel;
class QPushButton;
class QTableWidget;

class ncfg_connection;

class ncfg_wifi_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_wifi_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	/* Re-reads which interfaces are wireless and what the chosen one is
	 * doing. Does **not** scan: see the header comment. */
	void refresh();

signals:
	void reported(const QString &summary);
	/* The configuration changed, so anything showing a plan is stale. The
	 * same signal the dns and access tabs emit, so the window reloads the
	 * same way whichever tab wrote. */
	void changed();

private slots:
	void scan();
	void join();
	void add();
	void leave();
	void activate();
	void selection_changed();
	void edit_selected();
	void add_manually();

private:
	QString chosen_interface() const;
	void    update_status();
	/* Warnings the planner raised about the chosen radio, which is where
	 * netcfgd records that something else is managing it. Read from the plan
	 * rather than asked for separately: the daemon already works this out for
	 * every apply, and a second answer in a second place is the drift this
	 * tree keeps finding. */
	void    update_contention();

	ncfg_connection *connection;
	QComboBox       *interfaces;
	QLabel          *status;
	/* Another daemon on this radio, shown above the table rather than in the
	 * status line: it is a standing condition, and a status line is where the
	 * last thing that happened goes. Hidden when there is none, so a machine
	 * where netcfgd is the only manager sees nothing. */
	QLabel          *contention;
	QPushButton     *scan_button;
	QPushButton     *join_button;
	QPushButton     *add_button;
	QPushButton     *leave_button;
	/* Hands the chosen radio to netcfgd. Shown only when that is a thing
	 * that could be done: a radio already netcfgd's needs no button, and one
	 * another manager holds cannot be taken while that manager runs. */
	QPushButton     *activate_button;
	/* The chosen radio's state, kept so `scan` and `join` can be disabled
	 * without asking the daemon again. */
	ncfg_radio_row   chosen_radio;
	/* Whether the last refresh could reach netcfgd at all.
	 *
	 * The buttons below are decided from what the daemon last said, so a
	 * refresh that could not ask it must not leave them offering actions
	 * against a machine this view can no longer see. Kept rather than
	 * clearing the radio list, because a daemon that blips should not also
	 * lose the radio the operator picked. */
	bool             reachable = true;
	QTableWidget    *table;
	/* The rows as the daemon sent them, because the table holds rendered text
	 * and `add` needs the exact SSID octets as hex. Re-drawing from a QString
	 * would mean parsing back what was formatted for a person. */
	QList<ncfg_access_point_row> scanned;

	/*
	 * The networks the document configures, which is a different list from
	 * what a scan found.
	 *
	 * A configured network out of range appears here and in no scan, and
	 * before this it appeared nowhere at all: the `configured` column marks
	 * scan rows, so the only saved networks a screen could show were the ones
	 * that happened to be broadcasting. "Where do I see my saved networks"
	 * had no answer in this program.
	 */
	QTableWidget    *saved_table;
	QPushButton     *edit_button;
	QPushButton     *manual_button;
	QList<ncfg_saved_network_row> saved;
	void    update_saved();
	/* Open the editor on a saved network, or on nothing to write one by
	 * hand. One dialog for both, because "view what this is set to" and
	 * "set one up" are the same form with different starting values. */
	void    edit_network(const ncfg_saved_network_row &existing);
};

#endif /* NCFG_WIFI_VIEW_H */
