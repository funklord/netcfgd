/*
 * devices_view.h -- what this machine's network is doing.
 *
 * The first tab, and that is not an arbitrary choice: "what is this machine's
 * network doing" is the question `ncfg status` and the TUI's first pane both
 * answer, and a client that could not answer it would be a client nobody opens.
 *
 * The rows come from ncfg_client_links(), below the seam. They used to be
 * assembled here out of the raw `status` document -- the models moved down
 * (gui/project.md sec 3) and this became what it should have been from the
 * start: a table that draws rows somebody else built.
 */
#ifndef NCFG_DEVICES_VIEW_H
#define NCFG_DEVICES_VIEW_H

#include <QWidget>

class QPushButton;
class QTableWidget;

class ncfg_connection;

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
	/* Open the interface editor on the selected row. This is where
	 * `preference` -- which uplink wins -- and a wired port's addressing are
	 * set, neither of which the program could reach before. */
	void configure_selected();

private:
	ncfg_connection *connection;
	QTableWidget    *table;
	QPushButton     *configure_button;
};

#endif /* NCFG_DEVICES_VIEW_H */
