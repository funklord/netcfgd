/*
 * firewall_dialog.h -- one firewall rule, and the block every edit writes.
 *
 * **The firewall is one block, so every edit writes all of it.** 0294's rules
 * live in `firewall { input { ... } forward { ... } output { ... } }`, and the
 * order inside a chain is the order nftables evaluates them in -- so a rule
 * cannot be a drop-in of its own the way a routing rule is. The view holds the
 * whole firewall as the daemon reported it, the dialog changes one rule in a
 * copy, and the copy is written back whole as the `firewall` drop-in.
 *
 * Which is why the block writer below must carry every key the reader took:
 * a match it forgot is a match Save deletes, on the one block where a
 * dropped match widens a rule to traffic it was never meant to catch.
 *
 * A firewall written by hand in `netcfgd.conf` is not taken over: writing the
 * drop-in is then refused by the daemon as a block defined twice, and the
 * refusal says where the first one is. Overriding it would leave the hand-
 * written block in place and silently dead.
 *
 * `admin`, because it writes configuration.
 */
#ifndef NCFG_FIREWALL_DIALOG_H
#define NCFG_FIREWALL_DIALOG_H

#include "ncfg_connection.h"

#include <QDialog>
#include <QString>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;

/* The drop-in the firewall is written to. */
extern const char *const ncfg_firewall_drop_in;

/* `input`, `forward` or `output`, by name. NULL for anything else. */
ncfg_firewall_chain_row *ncfg_firewall_chain(ncfg_firewall_settings *settings,
    const QString &name);

/*
 * The `firewall` block for these settings, as configuration text.
 *
 * A free function, as every block writer here is, because the ways it can be
 * wrong -- a match dropped, the order changed, a policy left out so the
 * compiler refuses the chain -- are invisible in a screenshot.
 */
QString ncfg_firewall_block(const ncfg_firewall_settings &settings);

/*
 * Write the settings as the firewall drop-in. The daemon compiles the result
 * before keeping it, so a rule it refuses is refused here, in its words.
 */
bool ncfg_firewall_write(ncfg_connection *connection, const ncfg_firewall_settings &settings,
    QString *error);

class ncfg_firewall_rule_dialog : public QDialog {
	Q_OBJECT

public:
	/* `index` -1 for a rule being written into `chain`; otherwise the rule
	 * at that position there, which may be moved to another chain. */
	ncfg_firewall_rule_dialog(ncfg_connection *connection,
	    const ncfg_firewall_settings &settings, const QString &chain, int index,
	    QWidget *parent = nullptr);

	QString outcome() const { return summary; }

private slots:
	void submit();
	void remove();
	void shape_changed();

private:
	bool read_rule(ncfg_firewall_rule_row *rule);

	ncfg_connection        *connection;
	ncfg_firewall_settings  settings;
	QString                 original_chain;
	int                     index;
	QString                 summary;

	QComboBox *chain;
	QLineEdit *name;
	QComboBox *action;
	QComboBox *protocol;
	QLineEdit *ports;
	QLineEdit *from;
	QLineEdit *to;
	QLineEdit *interface;
	QLineEdit *out_interface;
	QCheckBox *state_new;
	QCheckBox *state_established;
	QCheckBox *state_related;
	QCheckBox *state_invalid;
	QLineEdit *stations;
	QLabel      *note;
	QPushButton *save_button;
};

#endif /* NCFG_FIREWALL_DIALOG_H */
