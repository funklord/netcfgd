/*
 * modems_view.cpp -- the modems table described in modems_view.h.
 */
#include "modems_view.h"

#include "ncfg_connection.h"

#include <QHeaderView>
#include <QLabel>
#include <QTableWidget>
#include <QVBoxLayout>

namespace {

/* The columns, in the order the questions get asked: which device, what was
 * asked for, what is in force, whether netcfgd is mid-switch, and the APN --
 * last because it is the one that does not change. */
const char *const column_titles[] = { "device", "sim", "in use", "state", "apn" };
constexpr int column_count = static_cast<int>(sizeof(column_titles) / sizeof(column_titles[0]));

} /* namespace */

ncfg_modems_view::ncfg_modems_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	auto *layout = new QVBoxLayout(this);

	table = new QTableWidget(0, column_count, this);
	QStringList headers;
	for (int i = 0; i < column_count; i++) {
		headers << QString::fromLatin1(column_titles[i]);
	}
	table->setHorizontalHeaderLabels(headers);
	table->verticalHeader()->setVisible(false);
	table->setSelectionBehavior(QAbstractItemView::SelectRows);
	table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	table->horizontalHeader()->setStretchLastSection(true);
	layout->addWidget(table);

	note = new QLabel(this);
	note->setObjectName(QStringLiteral("modems_note"));
	note->setWordWrap(true);
	layout->addWidget(note);
}

void ncfg_modems_view::refresh()
{
	QList<ncfg_modem_row> rows;
	QString error;

	if (!connection->modems(&rows, &error)) {
		/* The daemon's own words: a refusal names the tier it wanted
		 * (0013), and replacing that with "could not load" throws away
		 * the one sentence that says what to do about it. */
		table->setRowCount(0);
		note->setText(error);
		emit reported(error);
		return;
	}

	table->setRowCount(rows.size());
	for (int row = 0; row < rows.size(); row++) {
		const ncfg_modem_row &modem = rows.at(row);

		/* "the machine is on it" against "netcfgd wants it and the link
		 * has not been cycled yet". Those are different states and an
		 * operator watching a modem that will not attach is exactly the
		 * person who needs them told apart. */
		QString state;
		if (modem.cycle_pending) {
			state = QStringLiteral("switching");
		} else if (modem.sim.size() > 1 && modem.selected != modem.sim.value(0)) {
			/* Running, but not on what was asked for first. Said
			 * plainly: a fallback that succeeded looks exactly like a
			 * machine that was configured this way, and the
			 * difference is why the primary is not being used. */
			state = QStringLiteral("fallen back");
		} else if (!modem.sim.isEmpty()) {
			state = QStringLiteral("on its first choice");
		}

		const QString cells[column_count] = {
			modem.device,
			/* The order matters and a comma keeps it visible. An
			 * unordered rendering would lose the one thing the list
			 * is: what to try next. */
			modem.sim.join(QStringLiteral(", ")),
			modem.selected,
			state,
			modem.apn,
		};
		for (int column = 0; column < column_count; column++) {
			table->setItem(row, column, new QTableWidgetItem(cells[column]));
		}
	}
	table->resizeColumnsToContents();
	table->horizontalHeader()->setStretchLastSection(true);

	/* An empty table has two meanings and the label is what separates them.
	 * "This machine has no modem" is the ordinary case on almost every
	 * machine; "the daemon refused" was handled above. Saying neither would
	 * leave an operator wondering whether the tab was broken. */
	if (rows.isEmpty()) {
		note->setText(QStringLiteral(
		    "No device in the configuration has a `modem` block. A cellular machine "
		    "declares one -- device wwan0 { modem { sim = [...]; apn = \"...\" } } -- "
		    "and netcfgd chooses among the SIM sources when a probe says the link "
		    "does not work."));
		emit reported(QStringLiteral("no modems configured"));
		return;
	}

	note->setText(QStringLiteral(
	    "`sim` is what the configuration asks for, in order. `in use` is where netcfgd "
	    "has got to: it moves to the next source when this interface's probe says the "
	    "link does not work, and stops at the last one rather than starting over. A "
	    "modem with no probe configured never falls back."));
	emit reported(QStringLiteral("%1 modems").arg(rows.size()));
}
