/*
 * rule_dialog.h -- which packets consult which routing table, and when.
 *
 * **A rule says what a route cannot.** A route says where a packet goes; a
 * rule says which set of routes is consulted in the first place, which is what
 * multi-homing, split tunnelling and per-mark routing are all answers to. The
 * block has been the model's since 0018 and the window could only list them:
 * writing one meant `ncfg config edit` and knowing the syntax.
 *
 * The priority is the identity as far as the kernel is concerned -- it decides
 * when the rule is consulted -- so it is asked for rather than invented, and
 * two rules at one priority is a question for the operator rather than
 * something a form should quietly renumber.
 *
 * What is deliberately absent is `invert`. The model has the field and the
 * executor applies it; the configuration language has no key for it, so a form
 * offering it would write a block netcfgd refuses. Recorded rather than
 * quietly added: giving the parser a key is a decision about the language.
 *
 * `admin`, because it writes configuration.
 */
#ifndef NCFG_RULE_DIALOG_H
#define NCFG_RULE_DIALOG_H

#include "ncfg_connection.h"

#include <QDialog>
#include <QString>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;

class ncfg_rule_dialog : public QDialog {
	Q_OBJECT

public:
	/* `existing` with an empty id means a rule being written: the id is asked
	 * for and every field starts at its default. */
	ncfg_rule_dialog(ncfg_connection *connection, const ncfg_rule_row &existing,
	    QWidget *parent = nullptr);

	QString outcome() const { return summary; }

private slots:
	void submit();
	void remove();
	void action_changed();

private:
	QString block_text() const;

	ncfg_connection *connection;
	ncfg_rule_row    before;
	bool             editing;
	QString          summary;

	QLineEdit *id;
	QSpinBox  *priority;
	QComboBox *family;
	QLineEdit *from;
	QLineEdit *to;
	QLineEdit *iif;
	QLineEdit *oif;
	QSpinBox  *fwmark;
	QSpinBox  *fwmask;
	QComboBox *action;
	QSpinBox  *table;
	QSpinBox  *suppress_prefixlength;
	QCheckBox *l3mdev;
	QLabel      *note;
	QPushButton *save_button;
	QPushButton *remove_button;
};

/*
 * The `rule` block for one set of answers, as configuration text.
 *
 * A free function for the reason every other block writer here is one: what it
 * produces is configuration netcfgd has to compile, and the ways it can be
 * wrong -- a selector dropped, a zero written as an absence, a table named for
 * an action that consults none -- are invisible in a screenshot.
 */
QString ncfg_rule_block(const ncfg_rule_row &settings);

#endif /* NCFG_RULE_DIALOG_H */
