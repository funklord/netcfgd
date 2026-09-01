/*
 * profiles_view.h -- the profiles this machine has, and which one it is on.
 *
 * A profile is a fundamental thing and there is a list of them, which is this
 * program's rule for what earns a tab. Until this it was reachable only from
 * the tray menu, which could *switch* but could not show what a profile is,
 * where it came from, or that a shipped one has been shadowed by a local copy.
 *
 * **The tray keeps its menu, and that is not duplication.** The tray exists so
 * that switching costs one click for an operator who does it several times a
 * day between office, home and offline; this exists so that somebody can look
 * at what the machine has before choosing. Two surfaces onto one verb, for two
 * different questions.
 *
 * **"None chosen" is a row, not an absence.** It is the default and it is not a
 * profile called `none`: a machine with no selection runs its own
 * configuration, which is what a machine that has never heard of profiles
 * does. Leaving it out of the list would make "stop using a profile" invisible,
 * and it is the one an operator reaches for when a profile has broken
 * something.
 */
#ifndef NCFG_PROFILES_VIEW_H
#define NCFG_PROFILES_VIEW_H

#include <QWidget>

class QLabel;
class QPushButton;
class QTableWidget;

class ncfg_connection;

class ncfg_profiles_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_profiles_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	void refresh();

signals:
	void reported(const QString &summary);
	/* The configuration changed, so anything showing a plan is stale. */
	void changed();

private slots:
	/* Switch to the selected profile, asking first. Needs `admin`. */
	void use_selected();

private:
	ncfg_connection *connection;
	QTableWidget    *table;
	QPushButton     *use_button;
	QLabel          *note;
};

#endif /* NCFG_PROFILES_VIEW_H */
