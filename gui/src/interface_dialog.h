/*
 * View and change one interface: addressing, which uplink wins, and how
 * netcfgd decides the link works.
 *
 * **`preference` is the priority knob and it is the reason this exists.** It
 * becomes the route metric, lower wins, and it is how a wired cable takes over
 * from wifi. Nothing in the program could set it.
 *
 * **Link detection is a probe, not the cable.** netcfgd used to choose an
 * uplink by carrier alone, and a cable into a switch that has lost its own
 * uplink has carrier and no path: netcfgd keeps preferring it while the wifi
 * that works sits at a worse metric doing nothing. Decision 0119 answers that
 * with a program whose exit status is the observation -- a failing probe
 * withholds routes exactly as a missing carrier does. So this dialog offers the
 * probe rather than treating carrier as the answer, and shows the command it
 * will run rather than hiding it behind a friendly word.
 *
 * Every closed set is a list, and free text is a *value* in a key this file
 * chose -- an address, a host, a command. The dialog composes the block; the
 * operator never types one.
 */

#ifndef NCFG_INTERFACE_DIALOG_H
#define NCFG_INTERFACE_DIALOG_H

#include <QDialog>
#include <QString>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;
class ncfg_connection;

class ncfg_interface_dialog : public QDialog {
	Q_OBJECT

public:
	/* `name` is the interface this configures. It is always known -- the
	 * devices list is where this opens from -- so unlike a network there is no
	 * "by hand" case with an empty one. */
	ncfg_interface_dialog(ncfg_connection *connection, const QString &name,
	              QWidget *parent = nullptr);

	QString outcome() const { return summary; }

private slots:
	void submit();
	void addressing_changed();
	void detection_changed();

private:
	QString block_text() const;

	ncfg_connection *connection;
	QString          interface;
	QString          summary;

	QComboBox   *addressing;
	QLineEdit   *static_address;
	QLineEdit   *gateway;
	QSpinBox    *preference;
	QSpinBox    *mtu;
	QCheckBox   *enabled;
	QCheckBox   *forwarding;
	QCheckBox   *nat;
	QComboBox   *detection;
	QLineEdit   *probe_host;
	QLineEdit   *probe_command;
	QLineEdit   *probe_args;
	QSpinBox    *probe_interval;
	QSpinBox    *probe_timeout;
	QLabel      *note;
	QPushButton *save_button;
};

#endif
