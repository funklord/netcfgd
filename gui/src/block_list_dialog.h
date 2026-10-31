/*
 * block_list_dialog.h -- one block list: names the router refuses to resolve,
 * and the exceptions (decision 0305).
 *
 * The router's, not one LAN's, so each list is a drop-in of its own,
 * `block_list-NAME`, applied by each DHCP server whose `block` names it.
 *
 * **The name is fixed once written**, as a DNS record's is: the servers name
 * the list by it, and a new name is a new list.
 *
 * `admin`, because it writes configuration.
 */
#ifndef NCFG_BLOCK_LIST_DIALOG_H
#define NCFG_BLOCK_LIST_DIALOG_H

#include "ncfg_connection.h"

#include <QDialog>
#include <QString>

class QLabel;
class QLineEdit;

/* The `block_list` block for one list, as configuration text. */
QString ncfg_block_list_block(const ncfg_block_list_row &list);

class ncfg_block_list_dialog : public QDialog {
	Q_OBJECT

public:
	/* `existing` with an empty name means a list being written. */
	ncfg_block_list_dialog(ncfg_connection *connection, const ncfg_block_list_row &existing,
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
	QLineEdit *file;
	QLineEdit *url;
	QLineEdit *domain;
	QLineEdit *allow;
	QLabel    *note;
};

#endif /* NCFG_BLOCK_LIST_DIALOG_H */
