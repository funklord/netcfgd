/*
 * access_point_dialog.h -- a network this machine offers, rather than joins.
 *
 * **The other half of wifi, and the half no window could reach.** A `network`
 * block is somewhere this machine associates; an `access_point` block is a
 * network it runs -- netcfgd generates hostapd's configuration under `/run`
 * and starts it. The block has been in the model since M4 and the only way to
 * write one was by hand.
 *
 * What this dialog does not do is anything about what comes *after* an
 * association. hostapd beacons and stations associate; a station still needs an
 * address, a route and a resolver, and **netcfgd serves no DHCP**. So the note
 * says what the example file says -- give the radio's `interface` block an
 * address -- and the planner's own warning carries the rest.
 *
 * `admin`, because it writes configuration.
 */
#ifndef NCFG_ACCESS_POINT_DIALOG_H
#define NCFG_ACCESS_POINT_DIALOG_H

#include "ncfg_connection.h"

#include <QDialog>
#include <QString>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;

class ncfg_access_point_dialog : public QDialog {
	Q_OBJECT

public:
	/*
	 * `existing` empty means one being made: the id is asked for and every
	 * field starts at its default. Otherwise the id is fixed -- it is the
	 * block's name and the drop-in's filename.
	 */
	ncfg_access_point_dialog(ncfg_connection *connection, const ncfg_access_point_config &existing,
	    QWidget *parent = nullptr);

	QString outcome() const { return summary; }

private slots:
	void submit();
	void remove();
	void security_changed();

private:
	QString block_text() const;
	/* The radios netcfgd knows about, for the device list. */
	void offer_radios();

	ncfg_connection *connection;
	ncfg_access_point_config before;
	bool                     editing;
	QString                  summary;

	QLineEdit *id;
	QComboBox *device;
	QComboBox *security;
	QLineEdit *credential;
	QComboBox *band;
	QSpinBox  *channel;
	QLineEdit *regdom;
	QCheckBox *hidden;
	QComboBox *acl_policy;
	QLineEdit *stations;
	QLabel      *note;
	QPushButton *save_button;
	QPushButton *remove_button;
};

/*
 * The `access_point` block for one set of answers, as configuration text.
 *
 * A free function for the reason every other block writer here is one: what it
 * produces is configuration netcfgd has to compile, and the ways it can be
 * wrong -- a credential written as a passphrase, a station list emptied, a
 * default stated as though it had been chosen -- are invisible in a screenshot.
 */
QString ncfg_access_point_block(const ncfg_access_point_config &settings);

#endif /* NCFG_ACCESS_POINT_DIALOG_H */
