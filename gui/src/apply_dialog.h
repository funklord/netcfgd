/*
 * apply_dialog.h -- plan, then approve, then apply, then keep or undo.
 *
 * WHY THE PLAN IS IN THE DIALOG
 *   project.md constraint 7: not being a black box is the product. `plan`
 *   before `apply` is not a convenience in netcfgd, it is the thing it sells,
 *   and a client with an Apply button that went straight to the daemon would be
 *   the first one here to hide it. So this dialog fetches a plan when it opens,
 *   shows it in the same widget the plan tab uses, and the Apply button is
 *   inert until there is one on screen.
 *
 * WHY THE CONFIRM WINDOW IS ON THIS SCREEN
 *   gui/project.md sec 5: a network change can cut off the person making it,
 *   which is more true from a phone across the room than from a terminal on the
 *   machine. ncfg_client_apply takes the window as an argument precisely
 *   because neither "always" nor "never" is right, so the screen asks -- and
 *   once a window is armed the operator has both Confirm and Revert in front of
 *   them, because a window that armed with no visible way to resolve it would
 *   be worse than none.
 *
 * WHY A REFUSAL STOPS IT
 *   A refusal from the daemon carries the tier or the override that would have
 *   been needed -- "ncfg apply --allow-disruption eth0". This client has no way
 *   to send that: ncfg_client_apply takes a confirm window and nothing else. So
 *   the refusal is a genuine stop here, and the remedy is shown verbatim
 *   because it is the command that gets past it.
 */
#ifndef NCFG_APPLY_DIALOG_H
#define NCFG_APPLY_DIALOG_H

#include <QDialog>

#include "ncfg_connection.h"

class QCheckBox;
class QLabel;
class QPushButton;
class QSpinBox;
class QTableWidget;
class QTimer;

class ncfg_plan_view;

class ncfg_apply_dialog : public QDialog {
	Q_OBJECT

public:
	explicit ncfg_apply_dialog(ncfg_connection *connection, QWidget *parent = nullptr);

signals:
	/* Something changed on the machine. The window behind this reloads what
	 * it is showing, because a table that still described the state before
	 * the apply would be the client contradicting itself. */
	void changed();

private slots:
	void run_apply();
	void run_confirm();
	void run_revert();
	void tick();

private:
	void show_journal(const QList<ncfg_record_row> &journal);
	void arm(unsigned seconds);
	void say(const QString &text);

	ncfg_connection *connection;
	ncfg_plan_view  *plan;
	QCheckBox       *arm_window;
	QSpinBox        *window_seconds;
	QLabel          *message;
	QLabel          *countdown;
	QTableWidget    *journal;
	QPushButton     *apply_button;
	QPushButton     *confirm_button;
	QPushButton     *revert_button;
	QTimer          *clock;
	int              remaining = 0;
};

#endif /* NCFG_APPLY_DIALOG_H */
