/*
 * plan_view.cpp -- the plan pane described in plan_view.h.
 */
#include "plan_view.h"

#include <QBrush>
#include <QColor>
#include <QFont>
#include <QHeaderView>
#include <QLabel>
#include <QTableWidget>
#include <QVBoxLayout>

namespace {

/*
 * The note columns. `severity` is first because it is the only one that says
 * whether the operator may proceed, and a reader who stops after one column
 * must still have been told that.
 *
 * `reason` is why the action was going to happen, for a refusal. Being told no
 * without being told what the no was about is the black box constraint 7 exists
 * to rule out, and it is worst here: the operator is deciding whether to
 * override a guard, and cannot judge that without knowing what would change.
 *
 * The last two columns are two answers and stay two, in this order. `what to
 * change` is the config edit that makes the situation not arise --
 * `on_unmanage = "clear"` -- and `or proceed with` is the flag that does it
 * anyway. `ncfg` prints them this way round on purpose: a flag offered first
 * reads as the fix, and the fix for a key netcfgd is about to walk away from is
 * not a flag that agrees to walk away from it. Both verbatim, because a screen
 * that paraphrases a command says no without saying how.
 */
const char *const note_titles[] = { "severity", "interface",      "message",        "detail",
				    "reason",   "what to change", "or proceed with" };
constexpr int note_column_count = static_cast<int>(sizeof(note_titles) / sizeof(note_titles[0]));

/*
 * The action columns, in the order the change reads: this operation, on this
 * interface, because this field is this now and should be that.
 *
 * `observed` before `desired` is the TUI's ordering (`observed -> desired`)
 * rather than the CLI's (`desired (was observed)`), because a table is read
 * left to right and the change should read the same way. The two are one
 * document under different renderings, which is why the column headings name
 * the fields rather than inventing a phrasing of their own.
 */
const char *const action_titles[] = { "id",       "op",      "interface",  "field",
				      "observed", "desired", "reversible" };
constexpr int action_column_count =
	static_cast<int>(sizeof(action_titles) / sizeof(action_titles[0]));

/* Two shades and a weight, and never on their own -- every row that is styled
 * also says what it is in words, because a theme this program does not choose
 * decides how these land. */
const QColor stop_colour(0xC0, 0x20, 0x20);
const QColor caution_colour(0xB0, 0x60, 0x00);

QTableWidgetItem *cell(const QString &text)
{
	return new QTableWidgetItem(text);
}

/*
 * A note's reason, in the actions table's ordering.
 *
 * One line rather than three columns because only refusals have one, and four
 * mostly-empty columns would push the two remedies off the edge of a window --
 * where the reason is the thing that lets an operator judge a refusal, but the
 * remedy is the thing they act on. Observed before desired, matching the
 * actions table, so one plan does not read two ways.
 */
QString reason_of(const ncfg_note_row &note)
{
	if (note.field.isEmpty() && note.observed.isEmpty() && note.desired.isEmpty()) {
		return QString();
	}
	return QStringLiteral("%1: %2 -> %3")
		.arg(note.field, note.observed, note.desired);
}

void emphasise(QTableWidgetItem *item, const QColor &colour)
{
	QFont font = item->font();

	font.setBold(true);
	item->setFont(font);
	item->setForeground(QBrush(colour));
}

void configure(QTableWidget *table, const char *const *titles, int count)
{
	QStringList headers;

	for (int i = 0; i < count; i++) {
		headers << QString::fromLatin1(titles[i]);
	}
	table->setHorizontalHeaderLabels(headers);
	table->verticalHeader()->setVisible(false);
	table->setSelectionBehavior(QAbstractItemView::SelectRows);
	/* Read-only because a plan is an answer, not a form. Editing a cell
	 * would suggest the change could be altered here, and it cannot: what
	 * apply runs is what the daemon computed. */
	table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	table->horizontalHeader()->setStretchLastSection(true);
}

void tidy(QTableWidget *table)
{
	table->resizeColumnsToContents();
	table->horizontalHeader()->setStretchLastSection(true);
}

} /* namespace */

ncfg_plan_view::ncfg_plan_view(ncfg_connection *connection, QWidget *parent)
	: QWidget(parent), connection(connection)
{
	auto *layout = new QVBoxLayout(this);

	headline = new QLabel(this);
	headline->setTextInteractionFlags(Qt::TextSelectableByMouse);
	headline->setWordWrap(true);
	layout->addWidget(headline);

	notes = new QTableWidget(0, note_column_count, this);
	configure(notes, note_titles, note_column_count);
	layout->addWidget(notes);

	actions = new QTableWidget(0, action_column_count, this);
	configure(actions, action_titles, action_column_count);
	/* The actions get the space. Notes are usually none or a few, and a
	 * table sized to its content would leave the list of what is about to
	 * happen squeezed into a strip. */
	layout->setStretchFactor(notes, 1);
	layout->addWidget(actions, 3);

	headline->setText(QStringLiteral("no plan yet"));
	notes->setVisible(false);
}

void ncfg_plan_view::refresh()
{
	/* A render-only view has nothing to refresh -- see the header. Silently
	 * doing nothing is right here: the dialog that owns such a view already
	 * showed a plan and re-fetching would replace it under the reader. */
	if (!connection) {
		return;
	}

	ncfg_plan_data fetched;
	QString error;

	if (!connection->plan(&fetched, &error)) {
		show_message(error);
		return;
	}
	show_plan(fetched);
}

void ncfg_plan_view::show_message(const QString &message)
{
	current = ncfg_plan_data();
	loaded = false;
	notes->setRowCount(0);
	notes->setVisible(false);
	actions->setRowCount(0);
	headline->setText(message);
	emit reported(message);
}

void ncfg_plan_view::show_plan(const ncfg_plan_data &plan)
{
	current = plan;
	loaded = true;

	/*
	 * Refusals, then stranded credentials, then warnings: hardest stop
	 * first. A reader whose eye stops after two rows has then seen the
	 * thing that decides whether anything happens at all.
	 */
	struct note_group {
		const char   *severity;
		const QColor *colour;
		const QList<ncfg_note_row> *rows;
	};
	const note_group groups[] = {
		{ "REFUSED", &stop_colour, &plan.refusals },
		{ "stranded", &caution_colour, &plan.stranded },
		{ "warning", nullptr, &plan.warnings },
	};

	notes->setRowCount(0);
	for (const note_group &group : groups) {
		for (const ncfg_note_row &note : *group.rows) {
			const int row = notes->rowCount();

			notes->insertRow(row);
			auto *severity = cell(QString::fromLatin1(group.severity));
			if (group.colour) {
				emphasise(severity, *group.colour);
			}
			notes->setItem(row, 0, severity);
			notes->setItem(row, 1, cell(note.interface));
			notes->setItem(row, 2, cell(note.message));
			notes->setItem(row, 3, cell(note.detail));
			notes->setItem(row, 4, cell(reason_of(note)));
			notes->setItem(row, 5, cell(note.remedy));
			notes->setItem(row, 6, cell(note.consent));
		}
	}
	notes->setVisible(notes->rowCount() > 0);
	tidy(notes);

	actions->setRowCount(plan.actions.size());
	for (int row = 0; row < plan.actions.size(); row++) {
		const ncfg_action_row &action = plan.actions.at(row);

		actions->setItem(row, 0, cell(QString::number(action.id)));
		actions->setItem(row, 1, cell(action.op));
		actions->setItem(row, 2, cell(action.interface));

		/*
		 * The reason, and the one case where there is none.
		 *
		 * An action the daemon sent without field, observed or desired
		 * is still a change that apply will make, so hiding the row
		 * would understate what is about to happen. It is marked
		 * instead -- loudly, in the column where the reason should have
		 * been -- so that it can never be read as an ordinary action
		 * whose reason merely did not fit.
		 */
		const bool reasoned = !action.field.isEmpty() || !action.observed.isEmpty() ||
				      !action.desired.isEmpty();
		if (reasoned) {
			actions->setItem(row, 3, cell(action.field));
			actions->setItem(row, 4, cell(action.observed));
			actions->setItem(row, 5, cell(action.desired));
		} else {
			auto *missing = cell(QStringLiteral("no reason reported"));
			emphasise(missing, stop_colour);
			actions->setItem(row, 3, missing);
			actions->setItem(row, 4, cell(QString()));
			actions->setItem(row, 5, cell(QString()));
		}

		/* An action with no inverse is one the confirm window cannot
		 * undo, which is the whole safety net this client offers on an
		 * apply. It is marked rather than left to a blank cell. */
		if (action.reversible) {
			actions->setItem(row, 6, cell(QStringLiteral("yes")));
		} else {
			auto *irreversible =
				cell(QStringLiteral("NO -- confirm cannot undo this"));
			emphasise(irreversible, stop_colour);
			actions->setItem(row, 6, irreversible);
		}
	}
	tidy(actions);

	report();
}

void ncfg_plan_view::report()
{
	QStringList parts;

	if (current.actions.isEmpty()) {
		/* The CLI's and the TUI's own sentence for this. One vocabulary
		 * per concept across the clients, or an operator reading both
		 * has to work out that they mean the same. */
		parts << QStringLiteral("nothing to do -- the machine matches the configuration");
	} else {
		parts << QStringLiteral("%1 actions").arg(current.actions.size());
	}
	if (!current.refusals.isEmpty()) {
		parts << QStringLiteral("%1 refused").arg(current.refusals.size());
	}
	if (!current.stranded.isEmpty()) {
		parts << QStringLiteral("%1 stranded credential(s)").arg(current.stranded.size());
	}
	if (!current.warnings.isEmpty()) {
		parts << QStringLiteral("%1 warnings").arg(current.warnings.size());
	}

	QString summary = parts.join(QStringLiteral(", "));
	if (current.blocked()) {
		/* Said in the summary and not only in the table, because this is
		 * the line a person reads when they are deciding whether to open
		 * the apply dialog at all. */
		summary += QStringLiteral(" -- apply is blocked until the refusals are resolved");
	}

	headline->setText(summary);
	emit reported(summary);
}
