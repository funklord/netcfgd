/*
 * device_dialog.h -- the hardware, and whether netcfgd touches it.
 *
 * **A device is not a link, and this program only ever had the link half.**
 * A link is where the networking is configured: addresses, routes, which
 * uplink wins. A device is what has to exist before a link can -- the adapter,
 * its MTU and MAC, what drives a radio, whether netcfgd manages it at all.
 * `device` blocks have been the model's since 0155 and no window could write
 * one; the only key any screen reached was the MTU, which the interface editor
 * smuggled out as a second block in its own file.
 *
 * What it does not do, and says so rather than approximating: a device's
 * `kind` is read-only here. A bridge or a bond carries members, a VLAN carries
 * a parent and an id, and a form that wrote the block back without them would
 * empty it -- so a device that is anything but `physical` refuses to save for
 * the same reason the interface editor refuses a block carrying what it has no
 * field for. Making virtual links from the window is its own round.
 *
 * `admin`, because it writes configuration. The refusal comes from the daemon
 * with the tier it needed in it, and is shown as it arrives.
 */
#ifndef NCFG_DEVICE_DIALOG_H
#define NCFG_DEVICE_DIALOG_H

#include "ncfg_connection.h"

#include <QDialog>
#include <QString>

class QCheckBox;
class QComboBox;
class QGroupBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;

class ncfg_device_dialog : public QDialog {
	Q_OBJECT

public:
	ncfg_device_dialog(ncfg_connection *connection, const QString &name,
	    QWidget *parent = nullptr);

	QString outcome() const { return summary; }

private slots:
	void submit();

private:
	/* The block this dialog would write, as configuration text. */
	QString block_text() const;
	void    load();

	ncfg_connection *connection;
	QString          device;
	QString          summary;
	ncfg_device_config existing;
	/* True where the daemon could not be asked. Save is refused then, for the
	 * reason the interface editor refuses: what is on the machine is unknown,
	 * so overwriting it is not something to do quietly. */
	bool unknown = false;

	QCheckBox *managed;
	QComboBox *on_unmanage;
	QSpinBox  *mtu;
	QLineEdit *mac;
	/* ethtool, which is what an operator reaches for when a link negotiates
	 * the wrong speed or a driver's offload is broken. */
	QComboBox *autoneg;
	QSpinBox  *speed;
	QComboBox *duplex;
	QComboBox *wol;
	QSpinBox  *rx_ring;
	QSpinBox  *tx_ring;
	QComboBox *gro;
	QComboBox *gso;
	QComboBox *tso;
	QComboBox *rx_checksum;
	QComboBox *tx_checksum;
	/* The radio half, shown only for a device that has one. */
	QGroupBox *wifi_box;
	QComboBox *wifi_backend;
	QCheckBox *wifi_autoconnect;
	QComboBox *powersave;
	QComboBox *mac_policy;
	QCheckBox *scan_randomization;
	QLineEdit *regdom;
	QLineEdit *portal_check;
	/* The modem half, likewise. */
	QGroupBox *modem_box;
	QLineEdit *sim;
	QLineEdit *apn;

	QLabel      *note;
	QPushButton *save_button;
};

/*
 * The `device` block for one set of answers, as configuration text.
 *
 * A free function so it can be checked without a daemon or a window: what it
 * produces is configuration netcfgd has to compile, and the ways it can be
 * wrong -- a default written out as though it had been chosen, a sub-block
 * emitted empty -- are invisible in a screenshot.
 */
QString ncfg_device_block(const QString &name, const ncfg_device_config &settings);

#endif /* NCFG_DEVICE_DIALOG_H */
