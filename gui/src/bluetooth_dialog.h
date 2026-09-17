/*
 * bluetooth_dialog.h -- a bluetooth device, declared like a network.
 *
 * **A device is a block with a handle, and the address is a fact about the
 * hardware** (decision 0149). The id is what the operator calls it, what
 * netcfgd files it under and what a diagnostic names; replacing the headphones
 * means changing one line rather than everything that refers to them.
 *
 * **What this build does with the block is nothing, and the dialog says so.**
 * The planner warns per device that a `bluetooth` block is understood and not
 * acted on: nothing pairs a device, connects it, or brings a `pan` link up.
 * That is worth writing down anyway -- the block compiles, canonicalises and
 * survives into the document, so a configuration written now still means this
 * when the backends arrive -- but an editor that let somebody write a pair of
 * headphones and walk away expecting sound would be the window lying about
 * what the daemon does.
 *
 * `admin`, because it writes configuration.
 */
#ifndef NCFG_BLUETOOTH_DIALOG_H
#define NCFG_BLUETOOTH_DIALOG_H

#include "ncfg_connection.h"

#include <QDialog>
#include <QString>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;

class ncfg_bluetooth_dialog : public QDialog {
	Q_OBJECT

public:
	/* `existing` with an empty id means a device being written: the id is
	 * asked for and every field starts at its default. */
	ncfg_bluetooth_dialog(ncfg_connection *connection, const ncfg_bluetooth_row &existing,
	    QWidget *parent = nullptr);

	QString outcome() const { return summary; }

private slots:
	void submit();
	void remove();
	void profile_changed();

private:
	ncfg_connection *connection;
	ncfg_bluetooth_row before;
	bool               editing;
	QString            summary;

	QLineEdit *id;
	QLineEdit *address;
	QComboBox *profile;
	QCheckBox *autoconnect;
	QLabel      *consequence;
	QLabel      *note;
	QPushButton *save_button;
	QPushButton *remove_button;
};

/*
 * The `bluetooth` block for one set of answers, as configuration text.
 *
 * A free function for the reason every other block writer here is one: what it
 * produces is configuration netcfgd has to compile, and the ways it can be
 * wrong -- a profile spelled the model's way rather than the language's, an
 * address in a form the compiler refuses, a default stated as though it had
 * been chosen -- are invisible in a screenshot.
 */
QString ncfg_bluetooth_block(const ncfg_bluetooth_row &settings);

/*
 * An address as the language spells it, or empty where it is not one.
 *
 * **Six colon-separated hex octets, uppercase**, which is what the compiler
 * takes and what `normalise_address` makes of it. The two other forms a person
 * arrives with are accepted and converted rather than refused: `aa-bb-...` is
 * what Windows and a good many labels print, and twelve bare hex digits is
 * what `bluetoothctl` output looks like once it has been through a clipboard.
 * Converting here is the editor composing the block, which is its job; what it
 * must not do is write something the compiler would reject and call it saved.
 */
QString ncfg_bluetooth_address(const QString &typed);

#endif /* NCFG_BLUETOOTH_DIALOG_H */
