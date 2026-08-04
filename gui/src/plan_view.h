/*
 * plan_view.h -- what `ncfg plan` shows, as a widget.
 *
 * WHY THIS IS ONE WIDGET AND NOT TWO
 *   It is the "plan" tab, and it is also the top half of the apply dialog. Two
 *   renderings of one document would drift, and the operator would learn to
 *   trust whichever one was shorter -- which is exactly the black box
 *   project.md constraint 7 exists to prevent. So the dialog embeds this, and
 *   what a person approves is byte for byte what the tab showed them.
 *
 * WHAT IT REFUSES TO DO
 *   Draw an action without its reason. The reason -- field, observed, desired
 *   -- has its own columns and they are never elided; an action the daemon sent
 *   with no reason at all is drawn as a marked row rather than as an ordinary
 *   one. Dropping such a row would be worse: it is still a change that is going
 *   to happen, and a plan that hid it would be lying about what apply will do.
 *
 *   Warnings, refusals and stranded credentials share a table because they are
 *   one thing to a reader -- something the operator has to know -- but a
 *   refusal is a stop and a warning is not, so the first column says which in a
 *   word and the styling agrees with it. Colour is never the only signal: it is
 *   not readable on every theme or by every reader.
 */
#ifndef NCFG_PLAN_VIEW_H
#define NCFG_PLAN_VIEW_H

#include <QWidget>

#include "ncfg_connection.h"

class QLabel;
class QTableWidget;

class ncfg_plan_view : public QWidget {
	Q_OBJECT

public:
	/* `connection` may be NULL, which makes this a render-only view: the
	 * apply dialog already holds the plan it is asking about and must not
	 * fetch a second one, because a plan computed twice is two different
	 * observations and the operator would be approving the older. */
	explicit ncfg_plan_view(ncfg_connection *connection, QWidget *parent = nullptr);

	void show_plan(const ncfg_plan_data &plan);

	/* The daemon's own words, in place of a plan. A refusal names the tier
	 * that would have been needed (0013), so it is shown and not replaced. */
	void show_message(const QString &message);

	const ncfg_plan_data &plan() const { return current; }
	bool has_plan() const { return loaded; }

public slots:
	void refresh();

signals:
	/* One line for the status bar, so the window does not have to count
	 * rows it does not own. */
	void reported(const QString &summary);

private:
	void report();

	ncfg_connection *connection;
	QLabel          *headline;
	QTableWidget    *notes;
	QTableWidget    *actions;
	ncfg_plan_data   current;
	bool             loaded = false;
};

#endif /* NCFG_PLAN_VIEW_H */
