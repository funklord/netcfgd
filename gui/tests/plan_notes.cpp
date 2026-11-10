/*
 * gui/tests/plan_notes.cpp -- a plan's warnings are read, not scrolled (10.784).
 *
 * The GUI walk found each warning in the plan one cut line in a strip a line
 * and a half high, read by scrolling sideways: the message column took the
 * width of the longest sentence. This renders a plan with one long warning
 * and nothing to do, and asks what a person would see.
 */
#include "../src/plan_view.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QHeaderView>
#include <QTableWidget>

#include <cstdio>

static int failures;

static void check(bool condition, const char *what)
{
	fprintf(stderr, "plan_notes: %-62s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

int main(int argc, char **argv)
{
	QApplication application(argc, argv);

	ncfg_note_row note;
	note.interface = QStringLiteral("br9");
	note.message = QStringLiteral("br9 has a `device` block and no `interface` block, so nothing "
	                              "is planned for it: netcfgd plans by interface, and a `device` "
	                              "block on its own is policy about hardware nobody has asked "
	                              "it to configure.");
	ncfg_plan_data plan;
	plan.warnings.append(note);

	ncfg_plan_view view(nullptr);
	view.resize(820, 500);
	view.show_plan(plan);
	view.show();
	QApplication::processEvents();

	QTableWidget *notes = nullptr;
	for (QTableWidget *table : view.findChildren<QTableWidget *>()) {
		if (table->rowCount() == 1 && table->item(0, 2) &&
		    table->item(0, 2)->text() == note.message) {
			notes = table;
		}
	}
	check(notes != nullptr, "the warning is in a table");
	if (!notes) {
		return 1;
	}
	check(notes->wordWrap(), "its text wraps");
	check(notes->columnWidth(2) <= 360, "the message column is a readable width");
	check(notes->rowHeight(0) > 2 * notes->fontMetrics().height(),
	      "and the row is as tall as the sentence, not one cut line");
	return failures ? 1 : 0;
}
