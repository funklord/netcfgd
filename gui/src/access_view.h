/*
 * access_view.h -- who may ask netcfgd for what, and the red frame around it.
 *
 * KDE 3.5's administrator mode, deliberately. The policy is shown read-only;
 * pressing the button unlocks the editors and **draws a red frame around
 * them**, and applying runs one privileged command.
 *
 * WHY THE FRAME IS THE POINT
 *   polkit prompts per action and leaves nothing on screen saying whether you
 *   are privileged *now*. A frame is a mode, and a mode can be looked at: an
 *   operator who walks away from a machine can tell at a glance what they left
 *   it able to do. That property is the reason to prefer this shape over a
 *   sequence of invisible prompts (0118).
 *
 * WHY IT SHELLS OUT
 *   This client cannot write `/etc/netcfgd`, and it must not try: 0117 already
 *   refused running a Qt application as root so that it can write one file. So
 *   the privileged step is `ncfg control set`, a typed command that renders the
 *   block itself and can express no hook and no path -- run through whatever
 *   the desktop has to elevate with.
 *
 *   No authentication happens here. This client owns no password prompt and
 *   must never grow one; where nothing can elevate, it prints the command for
 *   the operator to run, which is the answer with no dependency at all.
 *
 * WHY THIS TAB EXISTS AT ALL
 *   Every tier defaults to root, so a client run by a desktop user is refused
 *   before it can show anything. This is the one screen that is useful while
 *   everything else is saying no, and it is where the operator is sent.
 */
#ifndef NCFG_ACCESS_VIEW_H
#define NCFG_ACCESS_VIEW_H

#include <QString>
#include <QWidget>

class QComboBox;
class QFrame;
class QLabel;
class QPushButton;

class ncfg_connection;

class ncfg_access_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_access_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	void refresh();

signals:
	void reported(const QString &summary);
	/* The policy changed, so everything else is stale. */
	void changed();

private slots:
	void unlock();
	void apply();

private:
	void set_administrator_mode(bool live);

	ncfg_connection *connection;
	QFrame          *frame;
	QComboBox       *observe;
	QComboBox       *wifi;
	QComboBox       *admin;
	QLabel          *note;
	QPushButton     *unlock_button;
	QPushButton     *apply_button;
	bool             administrator = false;
};

#endif /* NCFG_ACCESS_VIEW_H */
