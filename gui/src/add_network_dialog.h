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
 * THE ENTERPRISE ARM
 *   A corporate network wants an identity and a password rather than a
 *   passphrase, and asking for the wrong one is not a small thing: the
 *   operator has no passphrase to type, and the box that asks for one gives
 *   them nothing to do. So which fields appear follows the scan, which now
 *   says whether the credential is 802.1X.
 *
 *   Certificates are named, never chosen from disk -- but a `Choose...` button
 *   beside each one bridges the gap, and the way it does is decision 0127 in a
 *   single control. The file is read **here**, by whoever is running this
 *   window, with their own permissions; what crosses the socket is the
 *   **content**, under a name derived from the file. A request naming a path
 *   would be an instruction to open a file as root, which is a far larger
 *   permission than "remember this certificate".
 *
 *   Storing one is the `admin` tier while adding a network is `wifi`, so the
 *   button is offered only where the connection holds it. Where it does not,
 *   the field still takes a name somebody else stored -- and says so, rather
 *   than presenting a button that fails after the operator picked a file.
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

/*
 * A secret name derived from a chosen file's name.
 *
 * Free rather than a member because it is a pure string rule with a great many
 * ways to be wrong, and a test can reach it here. The daemon refuses a name
 * with a path separator, a quote, a backslash, a control character, a leading
 * dot or `..`, and anything over 64 bytes; this produces one that passes, so
 * that an operator who chose `corp ca (1).pem` -- an ordinary thing to have on
 * disk -- is not told their file name is unusable.
 */
QString ncfg_secret_name_for(const QString &path);

class ncfg_add_network_dialog : public QDialog {
	Q_OBJECT

public:
	/* `ssid_hex` and `shown` come from the scan row: the first is what gets
	 * sent, the second is what the operator recognises. `secured` decides
	 * whether a credential is asked for at all, and `enterprise` decides
	 * which kind. */
	ncfg_add_network_dialog(ncfg_connection *connection, const QString &ssid_hex,
	            const QString &shown, bool secured, bool enterprise,
	            QWidget *parent = nullptr);

private slots:
	void submit();
	void revalidate();
	/* TLS presents a certificate and the others present a password, so the
	 * method decides which of the two the dialog asks for. Changing it after
	 * typing must not leave the wrong field filled in and hidden. */
	void method_changed();
	/* Read a certificate from disk and hand its content to the daemon. Two
	 * buttons share one slot, distinguished by which field is being filled,
	 * because the difference between them is a name and nothing else. */
	void choose_ca_certificate();
	void choose_client_certificate();

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
	bool             enterprise;

	/* The enterprise arm. All null when the network is not one, which is
	 * what submit() and revalidate() test rather than carrying a second
	 * flag that could disagree with the widgets. */
	QComboBox  *eap_method;
	QLineEdit  *eap_identity;
	QLineEdit  *eap_anonymous;
	QLineEdit  *eap_phase2;
	QLineEdit  *eap_ca_cert;
	QLineEdit  *eap_client_cert;
	/* The row labels, kept so the password row can be relabelled and the
	 * client-certificate row shown only for `tls`. */
	QLabel     *passphrase_label;
	QLabel     *client_cert_label;
	/* Null where the connection does not hold `admin`, which is the same
	 * test the constructor makes once rather than each time. */
	QPushButton *ca_cert_button;
	QPushButton *client_cert_button;

	/* Read a certificate and store it, returning the name it went under, or
	 * an empty string if nothing was stored. */
	QString store_certificate(const QString &role);
};

#endif /* NCFG_ADD_NETWORK_DIALOG_H */
