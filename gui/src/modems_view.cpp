/*
 * modems_view.cpp -- the modems table described in modems_view.h.
 *
 * The table itself is `ncfg_table_view`, shared with every other list here.
 * What is left is this view's subject: which columns, and the three states a
 * modem can be in.
 */
#include "modems_view.h"

#include "ncfg_connection.h"
#include "table_view.h"

#include <QVBoxLayout>

namespace {

/* "the machine is on it" against "netcfgd wants it and the link has not been
 * cycled yet" against "it is running, but not on what was asked for first".
 * Three states rather than a tick, because an operator watching a modem that
 * will not attach is exactly the person who needs them told apart -- and a
 * fallback that succeeded looks like a machine configured that way unless
 * something says otherwise. */
QString state_of(const ncfg_modem_row &modem)
{
	if (modem.cycle_pending) {
		return QStringLiteral("switching");
	}
	if (modem.sim.size() > 1 && modem.selected != modem.sim.value(0)) {
		return QStringLiteral("fallen back");
	}
	if (!modem.sim.isEmpty()) {
		return QStringLiteral("on its first choice");
	}
	return QString();
}

/* The cards, one source per line, with the one the module is reading now
 * marked. Only the sources a card has actually been read on: the mux shows the
 * module one SIM at a time, so a source netcfgd has never been on has nothing
 * to show, and an empty cell says that better than a placeholder would. */
QString cards_of(const ncfg_modem_row &modem)
{
	QStringList lines;
	for (const ncfg_sim_card &card : modem.cards) {
		const QString here =
		    modem.selected == card.source ? QStringLiteral(" (in use)") : QString();
		lines << QStringLiteral("%1 %2%3").arg(card.source, card.iccid, here);
	}
	return lines.join(QStringLiteral(", "));
}

} /* namespace */

ncfg_modems_view::ncfg_modems_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	/* In the order the questions get asked: which device, what was asked for,
	 * what is in force, whether netcfgd is mid-switch, the APN, and which card
	 * turned out to be in each source. The last two change least -- the APN
	 * never, and a card only when somebody opens the unit. */
	QStringList columns;
	columns << QStringLiteral("device") << QStringLiteral("sim") << QStringLiteral("in use")
	        << QStringLiteral("state") << QStringLiteral("apn")
	        << QStringLiteral("cards");
	table = new ncfg_table_view(columns, QStringLiteral("modems_note"), this);

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);
}

void ncfg_modems_view::refresh()
{
	QList<ncfg_modem_row> found;
	QString error;

	if (!connection->modems(&found, &error)) {
		table->show_error(error);
		emit reported(error);
		return;
	}

	QList<QStringList> rows;
	for (const ncfg_modem_row &modem : found) {
		QStringList cells;
		cells << modem.device;
		/* The order matters and a comma keeps it visible. An unordered
		 * rendering would lose the one thing the list is: what to try
		 * next. */
		cells << modem.sim.join(QStringLiteral(", "));
		cells << modem.selected;
		cells << state_of(modem);
		cells << modem.apn;
		cells << cards_of(modem);
		rows << cells;
	}
	table->show_rows(rows);

	if (rows.isEmpty()) {
		table->set_note(QStringLiteral(
		    "No device in the configuration has a `modem` block. A cellular machine "
		    "declares one -- device wwan0 { modem { sim = [...]; apn = \"...\" } } -- "
		    "and netcfgd chooses among the SIM sources when a probe says the link "
		    "does not work."));
		emit reported(QStringLiteral("no modems configured"));
		return;
	}

	table->set_note(QStringLiteral(
	    "`sim` is what the configuration asks for, in order. `in use` is where netcfgd "
	    "has got to: it moves to the next source when this interface's probe says the "
	    "link does not work, and stops at the last one rather than starting over. A "
	    "modem with no probe configured never falls back. `cards` fills in as sources "
	    "are used -- the mux shows the module one SIM at a time, so the only way to "
	    "learn what is in the other socket is to switch to it, and a source with no "
	    "card listed is one netcfgd has not been on."));
	emit reported(QStringLiteral("%1 modems").arg(rows.size()));
}
