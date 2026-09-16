/*
 * devices_view.h -- the hardware this machine has, and netcfgd's policy on it.
 *
 * **The half of the model that had no screen.** `links` answers "what is this
 * machine's network doing"; this answers "what is it doing it with". A device
 * is what has to exist before a link can -- an adapter, a radio, a modem, or a
 * virtual link something created -- and the `device` block is where its MTU,
 * its MAC, its ethtool settings and whether netcfgd manages it at all are
 * said. 0155 moved those keys out of `interface` and no window followed.
 *
 * The rows are a union, for the reason the link inventory is one (0246): the
 * kernel's adapters and the document's blocks do not coincide. A card nobody
 * has configured is the commonest thing on a fresh machine, and a block whose
 * card is out is what an operator is looking for when they ask why nothing
 * came up.
 */
#ifndef NCFG_DEVICES_VIEW_H
#define NCFG_DEVICES_VIEW_H

#include "ncfg_connection.h"

#include <QList>
#include <QWidget>

class QPushButton;
class ncfg_connection;
class ncfg_table_view;

class ncfg_devices_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_devices_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	void refresh();

signals:
	void reported(const QString &summary);
	/* The configuration changed, so anything showing a plan is stale. */
	void changed();

private slots:
	/* Open the hardware editor on the selected device. */
	void configure_selected();
	/* Make a virtual link: a bridge, a bond, a VLAN, a veth pair. The one
	 * control here that needs no row selected, because the device being made
	 * is not in the list yet. */
	void new_device();

private:
	ncfg_connection *connection;
	ncfg_table_view *table;
	QList<ncfg_device_row> rows;
	QPushButton *configure_button;
	QPushButton *new_button;
};

#endif /* NCFG_DEVICES_VIEW_H */
