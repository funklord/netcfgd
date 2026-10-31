/*
 * block_lists_view.h -- the block lists the configuration declares (0305).
 *
 * Names the router's forwarders refuse to resolve -- ad and tracker domains --
 * applied by each DHCP server that names the list in `block`. A list of
 * router-wide things, so a tab beside `dns records`. From the document, as
 * that tab is.
 */
#ifndef NCFG_BLOCK_LISTS_VIEW_H
#define NCFG_BLOCK_LISTS_VIEW_H

#include "ncfg_connection.h"

#include <QList>
#include <QWidget>

class QPushButton;
class ncfg_table_view;

class ncfg_block_lists_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_block_lists_view(ncfg_connection *connection, QWidget *parent = nullptr);

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
	void open(const ncfg_block_list_row &list);

	ncfg_connection           *connection;
	QList<ncfg_block_list_row> lists;
	QPushButton               *edit_button;
	ncfg_table_view           *table;
};

#endif /* NCFG_BLOCK_LISTS_VIEW_H */
