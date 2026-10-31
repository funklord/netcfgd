/*
 * host_list_dialog.h -- one host list: a name, and the stations in it.
 *
 * A host list (10.591, 10.592) is what an access point's allow or deny list
 * and a firewall rule's `mac` name as `@host_list:NAME`, so a household's
 * devices are written once and refused or let in wherever they are named.
 * Each list is its own drop-in, `host_list-NAME`, as a routing rule is.
 *
 * **The name is fixed once written.** Every block that names the list names
 * it by this word, so renaming it here would leave each of those pointing at
 * a list that is gone -- which the compiler refuses, and which this dialog
 * would have caused. A new name is a new list.
 *
 * Deleting a list something still names is refused by the daemon, in its
 * words, for the same reason.
 *
 * `admin`, because it writes configuration.
 */
#ifndef NCFG_HOST_LIST_DIALOG_H
#define NCFG_HOST_LIST_DIALOG_H

#include "ncfg_connection.h"

#include <QDialog>
#include <QString>

class QLabel;
class QLineEdit;
class QPlainTextEdit;

/* The `host_list` block for one list, as configuration text. */
QString ncfg_host_list_block(const ncfg_host_list_row &list);

class ncfg_host_list_dialog : public QDialog {
	Q_OBJECT

public:
	/* `existing` with an empty name means a list being written. */
	ncfg_host_list_dialog(ncfg_connection *connection, const ncfg_host_list_row &existing,
	    QWidget *parent = nullptr);

	QString outcome() const { return summary; }

private slots:
	void submit();
	void remove();

private:
	ncfg_connection *connection;
	QString          before;
	QString          summary;

	QLineEdit      *name;
	QPlainTextEdit *members;
	QLabel         *note;
};

#endif /* NCFG_HOST_LIST_DIALOG_H */
