/*
 * main_window.h -- the one window there is so far.
 *
 * The first screen is the devices table, and that is not an arbitrary choice:
 * "what is this machine's network doing" is the question `ncfg status` and the
 * TUI's first pane both answer, and a client that could not answer it would be
 * a client nobody opens.
 *
 * Two things are on screen from the first commit because gui/project.md sec 4
 * says they must never be inferable rather than visible: **which machine this
 * is**, and what the daemon said when it refused. The second one matters more
 * than it looks -- 0013's tiers mean an unprivileged client is told no, and a
 * window that showed an empty table for that would be a client that lies.
 */
#ifndef NCFG_MAIN_WINDOW_H
#define NCFG_MAIN_WINDOW_H

#include <QMainWindow>

class QLabel;
class QTableWidget;

class ncfg_connection;

class ncfg_main_window : public QMainWindow {
	Q_OBJECT

public:
	explicit ncfg_main_window(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	void refresh();

private:
	ncfg_connection *connection;
	QTableWidget    *table;
	QLabel          *where;
	QLabel          *status;
};

#endif /* NCFG_MAIN_WINDOW_H */
