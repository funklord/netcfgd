/*
 * dns_records_view.h -- the local DNS records the configuration declares (0303).
 *
 * The router's own names -- a NAS's address, an alias, a domain forwarded to
 * another server -- answered by every DHCP server that forwards DNS. A list of
 * fundamental things, so a tab, beside `host lists`: both are router-wide
 * lists of names. From the document, as the rules and firewall tabs are.
 */
#ifndef NCFG_DNS_RECORDS_VIEW_H
#define NCFG_DNS_RECORDS_VIEW_H

#include "ncfg_connection.h"

#include <QList>
#include <QWidget>

class QPushButton;
class ncfg_table_view;

class ncfg_dns_records_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_dns_records_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	void refresh();

private slots:
	void edit_selected();
	void new_record();

signals:
	void reported(const QString &summary);
	/* The configuration changed, so anything showing a plan is stale. */
	void changed();

private:
	void open(const ncfg_dns_record_row &record);

	ncfg_connection          *connection;
	QList<ncfg_dns_record_row> records;
	QPushButton              *edit_button;
	ncfg_table_view          *table;
};

#endif /* NCFG_DNS_RECORDS_VIEW_H */
