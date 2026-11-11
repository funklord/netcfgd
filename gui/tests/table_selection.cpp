/*
 * table_selection.cpp -- does the selection stay on the item a person chose
 * when a table is refreshed? (10.802)
 *
 * The GUI walk found the selection moving to the next row after a delete
 * (10.778): Qt keeps the current row's number when the rows are replaced, so
 * the row below the deleted one became current, and every view's delete
 * button stayed live on an item nobody had chosen. Headless, no daemon: the
 * question is a property of the table.
 */

#include "../src/table_view.h"

#include <QApplication>
#include <QTableWidget>

#include <cstdio>

static int failures;

static void check(bool condition, const char *what)
{
	fprintf(stderr, "table_selection: %-58s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static QList<QStringList> rows_of(const QStringList &names)
{
	QList<QStringList> rows;
	for (const QString &name : names) {
		rows << QStringList{ name, QStringLiteral("x") };
	}
	return rows;
}

int main(int argc, char **argv)
{
	QApplication application(argc, argv);
	ncfg_table_view view(QStringList{ QStringLiteral("name"), QStringLiteral("what") },
	    QStringLiteral("note"));
	QTableWidget *grid = view.findChild<QTableWidget *>();
	int changes = 0;
	QObject::connect(&view, &ncfg_table_view::selection_changed, [&changes]() { changes++; });

	view.show_rows(rows_of({ QStringLiteral("a"), QStringLiteral("b"), QStringLiteral("c") }));
	check(view.selected_row() < 0, "a fresh table has nothing chosen");

	grid->selectRow(1);
	check(view.selected_cell(0) == QStringLiteral("b"), "choosing b chooses b");

	/* b deleted: the refresh no longer has it. */
	changes = 0;
	view.show_rows(rows_of({ QStringLiteral("a"), QStringLiteral("c") }));
	check(view.selected_row() < 0, "once b is gone nothing is chosen, not c");
	check(changes > 0, "  and the views are told, so their buttons go off");

	/* A refresh that keeps the item keeps the choice, wherever it moved. */
	grid->selectRow(1);
	view.show_rows(rows_of({ QStringLiteral("0"), QStringLiteral("a"), QStringLiteral("c") }));
	check(view.selected_cell(0) == QStringLiteral("c"), "a refresh that keeps c keeps c chosen");

	return failures ? 1 : 0;
}
