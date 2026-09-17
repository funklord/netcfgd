/*
 * bluetooth_view.h -- the bluetooth devices the configuration declares.
 *
 * A bluetooth device is a block like a network (decision 0149), so it is a
 * list of fundamental things and gets a tab.
 *
 * Networking and audio both, which is why the profile column is not decoration:
 * a PAN device carries IP and an A2DP sink carries sound, and netcfgd does very
 * different things for the two.
 *
 * **Editable since 0260, and what that writes is the document.** The block is
 * one this build understands and does not act on -- nothing pairs a device,
 * connects it or brings a `pan` link up, which the planner warns about per
 * device -- so the editor says so and the note under this table says so. An
 * operator who cannot tell "netcfgd will do this" from "netcfgd has written
 * this down" is being misled by the program rather than by the daemon.
 *
 * The kernel is changed through plan and apply, where the operator sees the
 * whole change before any of it happens.
 */
#ifndef NCFG_BLUETOOTH_VIEW_H
#define NCFG_BLUETOOTH_VIEW_H

#include "ncfg_connection.h"

#include <QList>
#include <QWidget>

class QPushButton;
class ncfg_connection;
class ncfg_table_view;

class ncfg_bluetooth_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_bluetooth_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	void refresh();

private slots:
	/* Open the editor on the selected device, or on nothing to write one. */
	void edit_selected();
	void new_device();

signals:
	void reported(const QString &summary);
	/* The configuration changed, so anything showing a plan is stale. */
	void changed();

private:
	ncfg_connection *connection;
	/* The devices as the daemon reports them, so the editor opens on the row
	 * rather than on a re-read of the table's strings. */
	QList<ncfg_bluetooth_row> devices;
	QPushButton *edit_button;
	QPushButton *new_button;
	/* The shared read-only table: columns, rows, and the sentence underneath
	 * that says why an empty one is empty. What is this view's own is turning
	 * a row into strings, which is below. */
	ncfg_table_view *table;
};

#endif /* NCFG_BLUETOOTH_VIEW_H */
