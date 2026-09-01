/*
 * global_view.h -- the host-wide policy, and the one switch that turns the
 * machine's networking off.
 *
 * The `global` block is a fundamental thing without being a list, which is why
 * it gets a tab of its own rather than rows in somebody else's. Everything in
 * it is host-wide: whether this machine does networking at all, who may ask it
 * to do what, what happens when something drifts, and how long an unconfirmed
 * change has before it reverts.
 *
 * **The dns half is not here.** It has a tab already, and `global` takes
 * contributions from several files (decision 0147) precisely so that two tools
 * writing different parts of it do not lock each other out. Showing dns twice
 * would invite somebody to change it in the place that is not wired up.
 *
 * **`networking = "off"` is the only control, and it is a large one.** It
 * disables every interface in the document -- links down, addresses withdrawn
 * -- so it asks before writing, in the same words a profile switch asks. It is
 * not `managed = false`, which leaves an interface alone with whatever address
 * it had; this takes the network away deliberately, which is what somebody
 * choosing it wants.
 *
 * The rest is shown and not settable yet. Reading a policy you cannot change
 * is still worth the tab: `control` says who may do what on this machine, and
 * an operator who cannot see it cannot know why a client is being refused.
 */
#ifndef NCFG_GLOBAL_VIEW_H
#define NCFG_GLOBAL_VIEW_H

#include <QWidget>

class QLabel;
class QPushButton;
class QTableWidget;

class ncfg_connection;

class ncfg_global_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_global_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	void refresh();

signals:
	void reported(const QString &summary);
	void changed();

private slots:
	/* Turn the machine's networking off, or back on. Needs `admin`. */
	void toggle_networking();

private:
	ncfg_connection *connection;
	QTableWidget    *table;
	QPushButton     *networking_button;
	QLabel          *note;
	/* What the last refresh read, so the button knows which way it points
	 * without re-asking the daemon at the moment it is clicked. */
	bool             networking_on = true;
};

#endif /* NCFG_GLOBAL_VIEW_H */
