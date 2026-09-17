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
 * **It makes virtual links, which is the other half of `device`.** A bridge, a
 * bond, a VLAN, a veth pair, a macvlan, a VRF, a VXLAN or a tunnel is a link
 * netcfgd creates rather than finds, and until this carried the fields there
 * was no way to ask for one except by writing the block by hand. The kind and
 * the fields it needs are the top of this form; a device with no block at all
 * opens on `physical`, which asks for nothing.
 *
 * What it still does not hold is the kinds that carry something else entirely:
 * a `WireGuard` tunnel's peers and keys, a PPPoE session's credentials, an
 * `OpenVPN` link's own configuration file. Each refuses to save for the reason
 * the interface editor refuses a block carrying what it has no field for --
 * saving would delete it.
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
class QTableWidget;

class ncfg_device_dialog : public QDialog {
	Q_OBJECT

public:
	/*
	 * `name` empty means a device being made: the name is asked for and the
	 * kind starts at `physical`. Otherwise the name is fixed -- it is the
	 * block's name and the drop-in's filename, and changing it would be
	 * writing a second device rather than editing this one.
	 */
	ncfg_device_dialog(ncfg_connection *connection, const QString &name,
	    QWidget *parent = nullptr);

	QString outcome() const { return summary; }

private slots:
	void submit();
	/* Show the fields the chosen kind needs and hide the rest. A bridge's
	 * members and a VLAN's id are not alternatives an operator should have to
	 * read past each other. */
	void kind_changed();
	/* Add an empty peer row, or drop the selected one. A peer is a name, a
	 * public key and a set of allowed prefixes; a device with one is as
	 * ordinary as one with six, so they are a table rather than a form. */
	void add_peer();
	void drop_peer();

private:
	/* The block this dialog would write, as configuration text. */
	QString block_text() const;
	void    load();
	/* One cell of the peers table, trimmed. */
	QString peer_cell(int row, int column) const;

	ncfg_connection *connection;
	QString          device;
	QString          summary;
	ncfg_device_config existing;
	/* True where the daemon could not be asked. Save is refused then, for the
	 * reason the interface editor refuses: what is on the machine is unknown,
	 * so overwriting it is not something to do quietly. */
	bool unknown = false;

	/* Empty for an existing device, which is what makes the name read-only. */
	QLineEdit  *name;
	QComboBox  *kind;
	/* bridge and bond */
	QLineEdit *members;
	QCheckBox *stp;
	QCheckBox *vlan_filtering;
	QComboBox *bond_mode;
	QSpinBox  *miimon;
	/* vlan, macvlan, vxlan, tunnel */
	QLineEdit *parent_link;
	QSpinBox  *vlan_id;
	QComboBox *vlan_protocol;
	QLineEdit *peer;
	QComboBox *macvlan_mode;
	QSpinBox  *vrf_table;
	QComboBox *tunnel_mode;
	QLineEdit *local;
	QLineEdit *remote;
	QSpinBox  *vxlan_id;
	QSpinBox  *port;
	QSpinBox  *ttl;
	QSpinBox  *tunnel_key;
	/* wireguard. The private key is a reference and never the material, so
	 * this is a line edit holding `@secret:wg0` rather than a password box. */
	QLineEdit    *private_key;
	QSpinBox     *listen_port;
	QSpinBox     *fwmark;
	QTableWidget *peers;
	/* pppoe and openvpn: one login, shown for both. */
	QLineEdit *username;
	QLineEdit *password;
	QLineEdit *service;
	QLineEdit *ac;
	QLineEdit *config;
	/* tun and tap: who may attach to the device. */
	QLineEdit *owner;
	QLineEdit *group;
	QWidget      *peer_buttons;
	QPushButton  *peer_add;
	QPushButton  *peer_drop;

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

/*
 * Whether this text can be a device's name, and what to say when it cannot.
 *
 * Empty for a name that is fine. netcfgd uses the name for the link and for
 * every file it keeps about it, so the answer is the kernel's: at most fifteen
 * characters, no slash, no whitespace, and not `.` or `..`.
 */
QString ncfg_device_name_refusal(const QString &name);

#endif /* NCFG_DEVICE_DIALOG_H */
