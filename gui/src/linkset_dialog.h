/*
 * linkset_dialog.h -- making and changing a group of links.
 *
 * A `linkset` is a named set of links with one of them in use: a cable and a
 * modem, a cable and the office wifi, two providers. Until this window there
 * was no way to make one except by writing the block by hand, which is the
 * state every feature in this program has been rescued from in turn.
 *
 * **The order is the ranking**, where two members' metrics cannot tell them
 * apart, so the list has up and down buttons and nothing here sorts it. That
 * is the one property a list widget will quietly destroy if nobody says so.
 *
 * It shows the standing beside each member -- what carries it, and why it
 * cannot be used where it cannot. That is netcfgd's answer and not this
 * window's: "why am I on the modem" is answered by the members that lost, and
 * recomputing it here would be a second opinion about a failover (0248).
 *
 * `admin`, because it writes configuration. The refusal comes from the daemon
 * with the tier it needed in it, and is shown as it arrives.
 */
#ifndef NCFG_LINKSET_DIALOG_H
#define NCFG_LINKSET_DIALOG_H

#include "ncfg_connection.h"

#include <QDialog>
#include <QString>

class QComboBox;
class QLabel;
class QLineEdit;
class QListWidget;
class QPushButton;

class ncfg_linkset_dialog : public QDialog {
	Q_OBJECT

public:
	/*
	 * `existing` empty means a set being made: the name is asked for and the
	 * member list starts empty. Otherwise the name is fixed -- it is the
	 * block's name and the drop-in's filename, and changing it would be
	 * writing a second set rather than editing this one.
	 */
	ncfg_linkset_dialog(ncfg_connection *connection, const QString &existing,
	    QWidget *parent = nullptr);

	/* What was written, for the caller's status line. */
	QString outcome() const { return summary; }

private slots:
	void submit();
	void remove();
	void add_member();
	void drop_member();
	void move_up();
	void move_down();
	void revalidate();

private:
	/* The block this dialog would write, as configuration text. */
	QString block_text() const;
	/* Fill the member list from the daemon's answer, standings and all. */
	void load();
	/* Every link that could be a member and is not one already. */
	void offer_candidates();

	ncfg_connection *connection;
	QString          existing;
	QString          summary;

	QLineEdit   *name;
	QListWidget *members;
	QComboBox   *candidates;
	QPushButton *add_button;
	QPushButton *drop_button;
	QPushButton *up_button;
	QPushButton *down_button;
	QPushButton *save_button;
	QPushButton *remove_button;
	QLabel      *note;
};

/*
 * The `linkset` block for a name and an ordered member list.
 *
 * A free function so it can be checked without a daemon or a window: what it
 * produces is configuration text that netcfgd has to compile, and the two ways
 * it can be wrong -- a reordered list, a name that needs quoting -- are both
 * invisible in a screenshot.
 */
QString ncfg_linkset_block(const QString &name, const QStringList &members);

/*
 * Whether this text can be a linkset's name, and what to say when it cannot.
 *
 * Empty for a name that is fine. A set is referred to by name from other sets
 * and written to a file called after it, so the answer is narrower than "any
 * string": no whitespace, no quote, no backslash, no path separator.
 */
QString ncfg_linkset_name_refusal(const QString &name);

#endif /* NCFG_LINKSET_DIALOG_H */
