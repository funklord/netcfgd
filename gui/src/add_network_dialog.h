/*
 * add_network_dialog.h -- remember a wireless network.
 *
 * The last thing between this client and something an operator uses instead of
 * `nmtui`: joining was only ever possible for networks somebody had already
 * written config for, so every new cafe needed a terminal.
 *
 * WHAT IT IS, UNDERNEATH
 *   A `network` block in a plain text file, written by the daemon because a
 *   desktop client has no permission to write `/etc/netcfgd` itself. Decision
 *   0117: the request carries **typed fields, never config text and never a
 *   path**, because a config file may name a hook and a hook's `run_as`
 *   defaults to root.
 *
 *   So this dialog collects exactly what that request has room for. It is not a
 *   general configuration editor and must not grow into one -- a field here
 *   that needed a new socket member would be an adapter's needs driving the
 *   model, which constraint 6 refuses.
 *
 * WHAT IT DOES WITH THE PASSPHRASE
 *   Sends it, once, and forgets it. The daemon writes it through the secret
 *   provider and the config file keeps an `@secret:` reference, so nothing
 *   here or anywhere else can read it back (0029, 0031). The field is
 *   `QLineEdit::Password` and the dialog holds no copy after it closes.
 *
 * WHY IT IS PREFILLED
 *   Opened from a selected scan row, so the SSID is the exact octets the radio
 *   saw rather than something retyped -- an SSID is not guaranteed to be text,
 *   and a network whose name does not render is exactly the one somebody would
 *   type wrongly.
 */
#ifndef NCFG_ADD_NETWORK_DIALOG_H
#define NCFG_ADD_NETWORK_DIALOG_H

#include <QDialog>
#include <QString>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;

class ncfg_connection;

class ncfg_add_network_dialog : public QDialog {
	Q_OBJECT

public:
	/* `ssid_hex` and `shown` come from the scan row: the first is what gets
	 * sent, the second is what the operator recognises. `secured` decides
	 * whether a passphrase is asked for at all. */
	ncfg_add_network_dialog(ncfg_connection *connection, const QString &ssid_hex,
	            const QString &shown, bool secured, QWidget *parent = nullptr);

private slots:
	void submit();
	void revalidate();

private:
	ncfg_connection *connection;
	QString          ssid_hex;
	QLineEdit       *id;
	QLineEdit       *passphrase;
	QComboBox       *proto;
	QCheckBox       *hidden;
	QLabel          *note;
	QPushButton     *add_button;
	bool             secured;
};

#endif /* NCFG_ADD_NETWORK_DIALOG_H */
