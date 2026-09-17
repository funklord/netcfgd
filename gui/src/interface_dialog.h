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
class QComboBox;
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
	 * each is ordinary and none had a shape. */
	void add_source();
	void drop_source();
	void move_source_up();
	void move_source_down();
	void add_route();
	void drop_route();
	/* The hooks this interface declares. A hook is shell and is edited as
	 * shell, in `ncfg_hook_dialog`; what is kept here is the list, because a
	 * drop-in owns the whole `interface` block and this is the form that
	 * writes it. */
	void add_hook();
	void change_hook();
	void drop_hook();
	void addressing_changed();
	void detection_changed();
	/* Open the selected script, or start a new one. A probe is a shell script
	 * and this edits it as one -- no form could express what a program is
	 * without either constraining it or lying about it. */
	void edit_detection();

private:
	QString block_text() const;
	/* Put one entry into the addressing list, or one row into the routes
	 * table. Both keep the value on the item rather than in its text, so a
	 * label can say more than the file does. */
	void put_source(const QString &kind, const QString &address);
	void put_route(const QString &destination, const QString &via, int metric);
	/* One cell of the routes table, trimmed. */
	QString cell(int row, int column) const;
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
	/* This interface's hooks, with the scripts, and whether they could all be
	 * read back. **A hook that could not be read is a save refused**: the
	 * block is written whole, so writing a body this form does not have is
	 * deleting somebody's script. Reading them needs `admin`, which a client
	 * below that tier does not have -- and could not save either way. */
	QList<ncfg_hook_script> hook_list;
	bool                    hooks_unknown = false;

	void load_hooks();
	/* One row's label: the phase, and the first line of the script that is
	 * neither the shebang nor a comment. */
	void put_hook(const ncfg_hook_script &hook);


	/* The addressing sources, in the document's order. The order is not
	 * decoration: it is what the model calls a composition, and the entries
	 * are applied in it. */
	QListWidget *sources;
	QComboBox   *source_kind;
	QLineEdit   *source_address;
	QPushButton *source_add;
	QPushButton *source_drop;
	QPushButton *source_up;
	QPushButton *source_down;
	/* Destination, via, metric -- the three parts of a route this form
	 * carries. A route with a table, a scope or a source address is named in
	 * `unmodelled` rather than shortened to these. */
	QTableWidget *routes;
	QPushButton  *route_add;
	QPushButton  *route_drop;
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
	QListWidget *hooks;
	QPushButton *hook_add;
	QPushButton *hook_change;
	QPushButton *hook_drop;
	QComboBox   *detection;
	/* What the daemon said, kept so the editor can be handed the text rather
	 * than a path this machine would have to open. */
	QList<ncfg_probe_row> scripts;
	QPushButton *edit_detection_button;
	QLineEdit   *probe_command;
	QLineEdit   *probe_args;
	QSpinBox    *probe_interval;
	QSpinBox    *probe_timeout;
	QLabel      *note = nullptr;
	QPushButton *save_button;
};

#endif
