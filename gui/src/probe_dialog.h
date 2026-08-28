/*
 * Read and change a link-detection script.
 *
 * **A probe is a shell script and this edits it as one.** No form, no fields:
 * the thing netcfgd runs is a program whose exit status is the answer, and any
 * attempt to present that as a set of boxes would either constrain what an
 * operator can express or lie about what is running.
 *
 * Reading is done from disk, which any user may do -- the scripts are 0755 so
 * that somebody debugging a link judged down can run one by hand. Writing goes
 * over the socket, because 0127 is that a client cannot write system files, and
 * a gui that wrote /etc/netcfgd/probe itself would be the fifth program with
 * root's permissions on what the daemon treats as its own.
 *
 * **Writing needs root, and the dialog says so before the operator types
 * rather than after.** A probe is a program netcfgd runs as root on an
 * interval, so `check_content` refuses this from anyone else -- which is
 * correct and would otherwise be discovered at the moment of saving a screen
 * full of work.
 */

#ifndef NCFG_PROBE_DIALOG_H
#define NCFG_PROBE_DIALOG_H

#include "ncfg_connection.h"

#include <QDialog>
#include <QString>

class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class ncfg_connection;

class ncfg_probe_dialog : public QDialog {
	Q_OBJECT

public:
	/*
	 * An `existing` with an empty name means a new script: the name is asked
	 * for and the body starts from a template, so that "write one" does not
	 * start at a blank page with no clue about the argument or the exit
	 * status.
	 *
	 * The script arrives whole rather than as a path to open. A client does
	 * not read the machine's files -- it asks netcfgd, which may not be this
	 * machine at all.
	 */
	ncfg_probe_dialog(ncfg_connection *connection, const ncfg_probe_row &existing,
	          QWidget *parent = nullptr);

	QString outcome() const { return summary; }
	/* The name written, so the caller can select it in its own list. */
	QString written_name() const { return saved_name; }

private slots:
	void submit();

private:
	ncfg_connection *connection;
	QString          saved_name;
	QString          summary;

	QLineEdit      *name;
	QPlainTextEdit *body;
	QLabel         *note;
	QPushButton    *save_button;
};

#endif
