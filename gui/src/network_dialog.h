/*
 * View, change or hand-write one wireless network.
 *
 * **The other dialog adds what a scan found; this one edits what the document
 * holds.** `add_network_dialog` is built from a scan row -- its security type
 * is fixed at construction because the access point already said what it was
 * -- so it cannot open an existing network, and it cannot add one that is not
 * in range. Both are things an operator asks for, and neither had anywhere to
 * happen.
 *
 * Every field whose values are a closed set is a list, for the reason the dns
 * tab's modes are: this writes a configuration drop-in through the daemon, and
 * a box an operator could type a block into would be 0117's remote code
 * execution with a nicer font. The dialog composes the block from choices it
 * made; what an operator types is only ever a *value* in a key this file
 * chose -- an identity, a certificate path, a metric.
 *
 * **The credential is not shown and does not have to be re-entered.** netcfgd
 * writes `psk = "@secret:<id>"` and keeps the passphrase in the secret store,
 * so an edit that rewrites the block leaves the reference alone and the
 * credential survives. The passphrase field is blank for "keep what is there",
 * which is also why it can never display one: this dialog has no way to read
 * it back and should not.
 */

#ifndef NCFG_NETWORK_DIALOG_H
#define NCFG_NETWORK_DIALOG_H

#include "ncfg_connection.h"

#include <QDialog>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;
class ncfg_connection;

class ncfg_network_dialog : public QDialog {
	Q_OBJECT

public:
	/*
	 * `existing` empty means a network being written by hand: the id is asked
	 * for and every field starts at its default. Otherwise the id is fixed --
	 * it is the block's name and the drop-in's filename, and changing it would
	 * be writing a second network rather than editing this one.
	 */
	ncfg_network_dialog(ncfg_connection *connection, const ncfg_saved_network_row &existing,
	            QWidget *parent = nullptr);

	/* What was written, for the caller's status line. */
	QString outcome() const { return summary; }

private slots:
	void submit();
	void security_changed();
	void revalidate();

private:
	QString block_text() const;

	ncfg_connection *connection;
	ncfg_saved_network_row  before;
	bool             editing;
	QString          summary;

	QLineEdit   *id;
	QLineEdit   *ssid_hex;
	QComboBox   *security;
	QComboBox   *proto;
	QComboBox   *eap_method;
	QLineEdit   *identity;
	QLineEdit   *anonymous_identity;
	QLineEdit   *phase2;
	QLineEdit   *ca_cert;
	QLineEdit   *client_cert;
	QLineEdit   *credential;
	QSpinBox    *metric;
	QCheckBox   *autoconnect;
	QCheckBox   *hidden;
	QCheckBox   *metered;
	QComboBox   *addressing;
	QLabel      *note;
	QPushButton *save_button;
};

#endif
