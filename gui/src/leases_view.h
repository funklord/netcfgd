/*
 * leases_view.h -- who holds which address from netcfgd's DHCP servers
 * (decision 0303).
 *
 * UniFi's client list, and the greppable record 0297 put under /run read back:
 * each server's unexpired leases, the address, the MAC and the name the client
 * sent. **From the observation, not the document** -- nothing here is
 * configuration, so it sits beside `stations` on the machine side rather
 * than with the tabs that write.
 */
#ifndef NCFG_LEASES_VIEW_H
#define NCFG_LEASES_VIEW_H

#include <QWidget>

class ncfg_connection;
class ncfg_table_view;

class ncfg_leases_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_leases_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	void refresh();

signals:
	void reported(const QString &summary);

private:
	ncfg_connection *connection;
	ncfg_table_view *table;
};

#endif /* NCFG_LEASES_VIEW_H */
