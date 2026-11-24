/*
 * zones_view.h -- the estate's zones, each opened in its own editor (10.929).
 *
 * A zone is the estate's purpose -- "guest", "iot", "trusted" -- with the zones
 * it may reach and each client's cap (10.927, 10.928). Which of this host's
 * links are in it is set on the link, in the interface dialog; this tab says
 * what the zones are.
 */
#ifndef NCFG_ZONES_VIEW_H
#define NCFG_ZONES_VIEW_H

#include "ncfg_connection.h"

#include <QList>
#include <QWidget>

class QPushButton;
class ncfg_table_view;

class ncfg_zones_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_zones_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	void refresh();

private slots:
	void edit_selected();
	void new_zone();

signals:
	void reported(const QString &summary);
	/* The configuration changed, so anything showing a plan is stale. */
	void changed();

private:
	void open(const ncfg_zone_row &zone);

	ncfg_connection     *connection;
	QList<ncfg_zone_row> zones;
	QPushButton         *edit_button;
	ncfg_table_view     *table;
};

#endif /* NCFG_ZONES_VIEW_H */
