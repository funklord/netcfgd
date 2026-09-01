/*
 * table_view.h -- one read-only table, so that six views are not six copies.
 *
 * Every list this program shows has the same shape: columns, rows of strings,
 * a sentence underneath saying what an empty table means, and the daemon's own
 * words when it refuses. Those were written out five times, byte for byte --
 * measured, not estimated: the block from `new QTableWidget` to
 * `layout->addWidget(table)` hashed identically in rules, bluetooth, hooks,
 * secrets and modems.
 *
 * **What is shared is the plumbing, and what is not is each view's subject.**
 * Turning rows into strings is where a view earns its file: `secrets` decides
 * that a name with no file reads `MISSING`, `modems` decides that a selection
 * which has moved reads `switching`. None of that belongs here, and a table
 * that tried to own it would have five special cases and no reason for any of
 * them.
 *
 * **The note is not decoration.** "No rows" cannot say whether a machine has
 * no bluetooth device or whether the daemon refused the request, and those
 * need different things done about them. Every view says which, and this makes
 * saying it one call rather than a habit each one has to remember.
 */
#ifndef NCFG_TABLE_VIEW_H
#define NCFG_TABLE_VIEW_H

#include <QStringList>
#include <QWidget>

class QHBoxLayout;
class QLabel;
class QTableWidget;

class ncfg_table_view : public QWidget {
	Q_OBJECT

public:
	/*
	 * `object` names the note label, so a test can find it. The columns are
	 * fixed for the life of the view: a table whose columns moved between
	 * refreshes would be a different table.
	 */
	ncfg_table_view(const QStringList &columns, const QString &object,
	    QWidget *parent = nullptr);

	/* Draw these rows. Each inner list is one row, in column order; a row
	 * with too few entries leaves the rest blank rather than being refused,
	 * because a view that draws nothing is worse than one drawing less. */
	void show_rows(const QList<QStringList> &rows);

	/* The daemon's own words, and no rows. A refusal names the tier it wanted
	 * (0013), and replacing that with "could not load" throws away the one
	 * sentence that says what to do about it. */
	void show_error(const QString &error);

	/* The sentence under the table. Said after `show_rows`, because what it
	 * should say usually depends on what was drawn. */
	void set_note(const QString &note);

	/* For the views that have buttons. They sit between the table and the
	 * note, left-aligned, and the space stays on the right however many are
	 * added.
	 *
	 * A method rather than the layout itself, because the layout carries a
	 * trailing stretch and `addWidget` would put a button after it -- which
	 * looks like a spacing bug and is an API that invites one. */
	void add_control(QWidget *control);

	/* The row the operator has selected, or -1. */
	int selected_row() const;
	/* The text in one cell of the selected row, or empty. */
	QString selected_cell(int column) const;

signals:
	/* A row was chosen, by click or by keyboard. Views with a button connect
	 * this to enable it. */
	void selection_changed();
	/* A row was double-clicked, which every view here treats as its default
	 * action. */
	void activated();

private:
	QTableWidget *table;
	QHBoxLayout  *controls_row = nullptr;
	QLabel       *note;
};

#endif /* NCFG_TABLE_VIEW_H */
