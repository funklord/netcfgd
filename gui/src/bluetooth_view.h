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
 * Read-only. What this program can change it changes through plan and apply,
 * where the operator sees the whole change before any of it happens.
 */
#ifndef NCFG_BLUETOOTH_VIEW_H
#define NCFG_BLUETOOTH_VIEW_H

#include <QWidget>

class QLabel;
class QTableWidget;

class ncfg_connection;

class ncfg_bluetooth_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_bluetooth_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	void refresh();

signals:
	void reported(const QString &summary);

private:
	ncfg_connection *connection;
	QTableWidget    *table;
	/* Says why the table is empty, which "no rows" cannot: nothing configured
	 * and a daemon that refused look identical otherwise. */
	QLabel          *note;
};

#endif /* NCFG_BLUETOOTH_VIEW_H */
