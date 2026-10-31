/*
 * dns_record_dialog.h -- one local DNS record: a name, and what the router
 * answers for it (decision 0303).
 *
 * The router's names, not one LAN's, so each record is a drop-in of its own,
 * `dns_record-NAME`, answered by every DHCP server that forwards DNS. A name
 * may carry an address, an MX, a TXT and an SRV together; a CNAME and a
 * forward each stand alone, which the compiler holds and says.
 *
 * **The name is fixed once written**, as a host list's is: it is the record's
 * identity, and a new name is a new record.
 *
 * `admin`, because it writes configuration.
 */
#ifndef NCFG_DNS_RECORD_DIALOG_H
#define NCFG_DNS_RECORD_DIALOG_H

#include "ncfg_connection.h"

#include <QDialog>
#include <QString>

class QLabel;
class QLineEdit;
class QSpinBox;

/* The `dns_record` block for one record, as configuration text. */
QString ncfg_dns_record_block(const ncfg_dns_record_row &record);

class ncfg_dns_record_dialog : public QDialog {
	Q_OBJECT

public:
	/* `existing` with an empty name means a record being written. */
	ncfg_dns_record_dialog(ncfg_connection *connection, const ncfg_dns_record_row &existing,
	    QWidget *parent = nullptr);

	QString outcome() const { return summary; }

private slots:
	void submit();
	void remove();

private:
	ncfg_connection *connection;
	QString          before;
	QString          summary;

	QLineEdit *name;
	QLineEdit *address;
	QLineEdit *cname;
	QLineEdit *mx;
	QSpinBox  *preference;
	QLineEdit *txt;
	QLineEdit *srv;
	QSpinBox  *port;
	QSpinBox  *priority;
	QSpinBox  *weight;
	QLineEdit *forward;
	QLabel    *note;
};

#endif /* NCFG_DNS_RECORD_DIALOG_H */
