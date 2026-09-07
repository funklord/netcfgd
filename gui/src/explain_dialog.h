/*
 * explain_dialog.h -- why is this interface the way it is.
 *
 * **The question that makes this program worth opening.** Every other view
 * here says what the machine is doing, and so does `ip addr`. This one says
 * which line of which file asked for it, what the kernel reports back, what
 * netcfgd would do next and why -- which only the daemon holding the compiled
 * document can answer, and which no window could ask for until now.
 *
 * Read-only, and that is the whole design. An explanation is netcfgd's account
 * of a decision it has already made; a control here would be editing the
 * answer to a question. The place to change what it says is the interface
 * editor, one button along.
 *
 * `observe`, so there is no tier to check: a connection with no rows to select
 * never reaches this.
 */
#ifndef NCFG_EXPLAIN_DIALOG_H
#define NCFG_EXPLAIN_DIALOG_H

#include <QDialog>
#include <QString>

class ncfg_connection;
class ncfg_table_view;

class ncfg_explain_dialog : public QDialog {
	Q_OBJECT

public:
	ncfg_explain_dialog(ncfg_connection *connection, const QString &interface,
	    QWidget *parent = nullptr);

private:
	ncfg_connection *connection;
	QString          interface;
	ncfg_table_view *table;
};

#endif /* NCFG_EXPLAIN_DIALOG_H */
