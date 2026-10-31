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
 *
 * **The hooks are here because the block is here.** A hook belongs to an
 * interface, one drop-in owns that interface's block whole, and a second file
 * declaring the same interface is a duplicate the loader refuses. So an editor
 * for hooks alone would have to compose everything this form composes; the
 * hooks list lives in this dialog instead, and `ncfg_hook_dialog` edits one
 * script and writes nothing. Until 0258 this form refused to save any
 * interface carrying a hook, because saving would have deleted it.
 */

#ifndef NCFG_INTERFACE_DIALOG_H
#define NCFG_INTERFACE_DIALOG_H

#include "ncfg_connection.h"

#include <QDialog>
#include <QString>

class QCheckBox;
class ncfg_addressing_editor;
class ncfg_hooks_editor;
class ncfg_route_editor;
class QComboBox;
class QFormLayout;
class QLabel;
class QLineEdit;
class QListWidget;
class QPushButton;
class QSpinBox;
class QTableWidget;
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
	/* The addressing list, which is a list because the model's is.
	 *
	 * **One combo used to stand for the whole `addressing` list** -- `dhcp`,
	 * `dhcp+slaac`, `static` and four more -- so every composition the list
	 * could hold and that collection did not name was reported as something
	 * the form could not carry, and the editor refused to save the interface
	 * at all. Three sources, two addresses, a lease beside a fixed address:
	 * each is ordinary and none had a shape. The list and the routes are
	 * `address_editors.h`'s since 10.615, shared with the network dialog. */
	void detection_changed();
	/* Open the selected script, or start a new one. A probe is a shell script
	 * and this edits it as one -- no form could express what a program is
	 * without either constraining it or lying about it. */
	void edit_detection();

private:
	QString block_text() const;
	/* The reference the 802.1X password is written as: the one given, or
	 * `@secret:dot1x-<interface>` (10.612). */
	QString dot1x_reference_text() const;
	/* Rebuild the list from disk, keeping the selection where it can be kept.
	 * Called after the editor writes, because a script that was just created
	 * is not in a list read before it existed. */
	void reload_detections(const QString &select);

	ncfg_connection *connection;
	QString          interface;
	QString          summary;

	void load_existing();

	/* What the daemon says is configured, and whether it could be asked. */

	ncfg_interface_config existing;

	bool        unknown = false;
	/* Whether the document's hook listing could be had at all; what was in
	 * the scripts is the hooks editor's to say (`withheld`). */
	bool hooks_unknown = false;

	void load_hooks();


	/* The addressing sources, in the document's order -- the order is what
	 * the model calls a composition -- and the routes. */
	ncfg_addressing_editor *addressing;
	ncfg_route_editor      *route_editor;
	/* This interface's own name resolution: its own scope, not an overlay on
	 * the global one (0007). */
	QComboBox   *dns_mode;
	QLineEdit   *dns_servers;
	QLineEdit   *dns_search;
	QLineEdit   *dns_domains;
	/* What netcfgd does when the machine stops matching this block. */
	QComboBox   *on_drift;
	QSpinBox    *preference;
	QCheckBox   *enabled;
	QCheckBox   *forwarding;
	QCheckBox   *nat;
	/* A DHCP server for the hosts behind it (10.608): on, the range, the
	 * lease and the DNS servers offered. Reservations have no field. */
	QCheckBox   *dhcp_server;
	/* The router's other keys, fields since 10.612: the server's
	 * reservations and the forwarded ports as tables, an advertisement, a
	 * token and a guard. A cell is text the compiler reads on Save, so each
	 * is checked as the word or number it must be before it is written. */
	QFormLayout *form_layout;
	QTableWidget *reservations;
	/* The server's custom options (0303): name, code, type, value. */
	QTableWidget *dhcp_options;
	QTableWidget *forwards;
	QLineEdit   *ipv6_token;
	QLineEdit   *guard;
	/* Wired 802.1X (10.612): the same keys a network's `wifi` block takes,
	 * and the password as its reference plus a field to store a new one. */
	QCheckBox   *dot1x;
	QComboBox   *dot1x_method;
	QLineEdit   *dot1x_identity;
	QLineEdit   *dot1x_anonymous_identity;
	QLineEdit   *dot1x_phase2;
	QLineEdit   *dot1x_domain_suffix_match;
	QLineEdit   *dot1x_ca_cert;
	QLineEdit   *dot1x_client_cert;
	QLineEdit   *dot1x_private_key;
	QLineEdit   *dot1x_reference;
	QLineEdit   *dot1x_password;
	QCheckBox   *advertise;
	QLineEdit   *advertise_prefixes;
	QComboBox   *advertise_backend;
	QCheckBox   *advertise_managed;
	QCheckBox   *advertise_other;
	QCheckBox   *advertise_dns;
	QSpinBox    *advertise_lifetime;
	QLineEdit   *dhcp_range;
	QSpinBox    *dhcp_lease;
	QLineEdit   *dhcp_dns;
	QCheckBox   *dhcp_dns_forward;
	/* The standard options (0303). */
	QLineEdit   *dhcp_gateway;
	QLineEdit   *dhcp_domain;
	QLineEdit   *dhcp_ntp;
	QLineEdit   *dhcp_boot_file;
	QLineEdit   *dhcp_boot_server;
	QLineEdit   *dhcp_tftp_server;
	QLineEdit   *dhcp_wpad;
	QLineEdit   *dhcp_range6;
	QLineEdit   *dhcp_relay;
	ncfg_hooks_editor *hooks;
	QComboBox   *detection;
	/* What the daemon said, kept so the editor can be handed the text rather
	 * than a path this machine would have to open. */
	QList<ncfg_probe_row> scripts;
	QPushButton *edit_detection_button;
	QLineEdit   *probe_command;
	QLineEdit   *probe_args;
	QSpinBox    *probe_interval;
	QSpinBox    *probe_timeout;
	QSpinBox    *probe_down_after;
	QSpinBox    *probe_up_after;
	QSpinBox    *probe_hold_down;
	QCheckBox   *probe_require_lease;
	QLabel      *note = nullptr;
	QPushButton *save_button;
};

#endif
