/*
 * zone_dialog.h -- one zone, written as a drop-in of its own (10.929).
 */
#ifndef NCFG_ZONE_DIALOG_H
#define NCFG_ZONE_DIALOG_H

#include "ncfg_connection.h"

#include <QDialog>
#include <QString>

class QLabel;
class QLineEdit;

/* The block a zone is saved as. */
QString ncfg_zone_block(const ncfg_zone_row &zone);

class ncfg_zone_dialog : public QDialog {
	Q_OBJECT

public:
	/* `existing` with an empty name means a zone being written. */
	ncfg_zone_dialog(ncfg_connection *connection, const ncfg_zone_row &existing,
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
	QLineEdit *reach;
	QLineEdit *client_limit;
	QLabel    *note;
};

#endif /* NCFG_ZONE_DIALOG_H */
