/*
 * devices_view.h -- what this machine's network is doing.
 *
 * The first tab, and that is not an arbitrary choice: "what is this machine's
 * network doing" is the question `ncfg status` and the TUI's first pane both
 * answer, and a client that could not answer it would be a client nobody opens.
 *
 * The rows come from ncfg_client_links(), below the seam. They used to be
 * assembled here out of the raw `status` document -- the models moved down
 * (gui/project.md sec 3) and this became what it should have been from the
 * start: a table that draws rows somebody else built.
 */
#ifndef NCFG_DEVICES_VIEW_H
#define NCFG_DEVICES_VIEW_H

#include "ncfg_connection.h"

#include <QList>
#include <QWidget>

class QComboBox;
class QPushButton;

class ncfg_connection;
class ncfg_table_view;

class ncfg_devices_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_devices_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	void refresh();

private:
	/* Offer every category the rows contain, and keep the operator's choice
	 * across a refresh where it is still offered. */
	void rebuild_filter();
	/* Draw the rows the filter allows, and say how many it hid. */
	void redraw();
	/* Open the network editor on a saved wifi network, by block id. */
	void configure_network(const QString &id);
	/* Open the group editor, on an existing group or on a new one. */
	void configure_linkset(const QString &name);

signals:
	void reported(const QString &summary);
	/* The configuration changed, so anything showing a plan is stale. */
	void changed();

private slots:
	/* Open the editor the selected row calls for -- the interface one for a
	 * device, the network one for a saved wifi network. This is where
	 * `preference` -- which uplink wins -- and a wired port's addressing are
	 * set, neither of which the program could reach before. */
	void configure_selected();
	/* Make a new group of links. The one thing in this tab that needs no row
	 * selected: there is nothing to select yet. */
	void new_linkset();
	/* Ask netcfgd why the selected interface is the way it is.
	 *
	 * **The tab answers "what" and could not answer "why".** `ncfg explain`
	 * has been the daemon's since the beginning and no window could ask it,
	 * so the one thing this program can say that `ip addr` cannot was
	 * reachable only from a terminal. */
	void explain_selected();

private:
	ncfg_connection *connection;
	ncfg_table_view *table;
	QComboBox       *filter;
	/* Every link the daemon reported, unfiltered: the filter draws from this
	 * rather than re-asking, so changing it costs no round trip. */
	QList<ncfg_link_row> links;
	/* The union the daemon reports: every link this machine has or has been
	 * told about. Empty from a daemon that does not report one, which the
	 * drawing treats as "fall back to `links`". */
	QList<ncfg_inventory_row> rows_known;
	/* What each group chose, from the same observation. Kept beside the rows
	 * so a group's row can say which member it is using without a second
	 * round trip, and empty where the configuration declares no group. */
	QList<ncfg_linkset_row> sets;
	QPushButton     *configure_button;
	QPushButton     *explain_button;
	QPushButton     *group_button;
};

#endif /* NCFG_DEVICES_VIEW_H */
