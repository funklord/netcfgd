/*
 * host_lists_view.h -- the host lists the configuration declares (10.591).
 *
 * A host list is a fundamental thing and there is a list of them, which is
 * this program's rule for what earns a tab. It sits beside the firewall
 * because a firewall rule and an access point's allow or deny list are what
 * name one, and an operator writing `@host_list:kids` in one tab wants to see
 * what is in it without leaving the row.
 *
 * From the document, as the rules and firewall tabs are.
 */
#ifndef NCFG_HOST_LISTS_VIEW_H
#define NCFG_HOST_LISTS_VIEW_H

#include "ncfg_connection.h"

#include <QList>
#include <QWidget>

class QPushButton;
class ncfg_table_view;

class ncfg_host_lists_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_host_lists_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	void refresh();

private slots:
	void edit_selected();
	void new_list();

signals:
	void reported(const QString &summary);
	/* The configuration changed, so anything showing a plan is stale. */
	void changed();

private:
	void open(const ncfg_host_list_row &list);

	ncfg_connection          *connection;
	QList<ncfg_host_list_row> lists;
	QPushButton              *edit_button;
	ncfg_table_view          *table;
};

#endif /* NCFG_HOST_LISTS_VIEW_H */
