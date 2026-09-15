/*
 * devices_view.cpp -- the devices table described in devices_view.h.
 */
#include "devices_view.h"

#include "explain_dialog.h"
#include "interface_dialog.h"
#include "ncfg_connection.h"
#include "table_view.h"

#include <QComboBox>
#include <QLabel>
#include <QPushButton>
#include <QSignalBlocker>
#include <QStringList>
#include <QVBoxLayout>

/* The unfiltered choice, spelled once so the dropdown and the test agree. */
static const QString ALL = QStringLiteral("all");

ncfg_devices_view::ncfg_devices_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	/* In the order an operator reads them: what it is called, what it is,
	 * whether it is working, what it joined, and what it has. The MAC is last
	 * because it is the one nobody looks at first.
	 *
	 * `network` sits beside `state` rather than at the end because it is part
	 * of the same answer for a radio: a wireless link that is up is up *on*
	 * something, and which network that is decides the link's route metric
	 * (0153). Blank for every wired link, which is most of them -- and a blank
	 * column is the honest rendering, since a cable has no network to be on. */
	QStringList columns;
	columns << QStringLiteral("interface") << QStringLiteral("category")
	        << QStringLiteral("presence") << QStringLiteral("kind")
	        << QStringLiteral("state") << QStringLiteral("network")
	        << QStringLiteral("addresses") << QStringLiteral("mtu")
	        << QStringLiteral("mac");
	table = new ncfg_table_view(columns, QStringLiteral("devices_note"), this);

	/* **The filter, and why its words come from the daemon.**
	 *
	 * A link list is long on any machine that does anything -- a laptop here
	 * has a wired port, a radio, a docker bridge and two WireGuard tunnels,
	 * and a machine with saved wifi networks will have many more. "Show me
	 * only the radios" is the question this answers.
	 *
	 * The categories are not worked out here. The kernel reports an empty
	 * `kind` for every real card, so wired, wireless and loopback are one
	 * value there, and knowing a modem needs the *document* rather than the
	 * link. That rule lives in the daemon; this renders the answer. Three
	 * front ends each writing it would be three rules, and the wrong one
	 * would drop rows from a filtered list without saying anything.
	 *
	 * Built from what is actually present rather than from a fixed list, so
	 * the dropdown never offers a category with nothing behind it -- and a
	 * category this build has never heard of still appears, because it came
	 * from the rows. */
	filter = new QComboBox(this);
	filter->setObjectName(QStringLiteral("link_filter"));
	filter->addItem(ALL);
	table->add_control(new QLabel(QStringLiteral("show"), this));
	table->add_control(filter);

	configure_button = new QPushButton(QStringLiteral("configure"), this);
	configure_button->setObjectName(QStringLiteral("configure_interface"));
	configure_button->setEnabled(false);
	table->add_control(configure_button);
	/* `observe`, so it needs no tier check: a connection that cannot observe
	 * has no rows to select. */
	explain_button = new QPushButton(QStringLiteral("why"), this);
	explain_button->setObjectName(QStringLiteral("explain_interface"));
	explain_button->setEnabled(false);
	table->add_control(explain_button);

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);

	connect(filter, &QComboBox::currentTextChanged, this, [this]() { redraw(); });
	connect(configure_button, &QPushButton::clicked, this,
	    &ncfg_devices_view::configure_selected);
	connect(table, &ncfg_table_view::activated, this, &ncfg_devices_view::configure_selected);
	connect(explain_button, &QPushButton::clicked, this, &ncfg_devices_view::explain_selected);
	connect(table, &ncfg_table_view::selection_changed, this, [this]() {
		const bool chosen = table->selected_row() >= 0;
		configure_button->setEnabled(chosen);
		explain_button->setEnabled(chosen);
	});
}

void ncfg_devices_view::refresh()
{
	QList<ncfg_link_row> found;
	QString error;

	if (!connection->links(&found, &error)) {
		/* The daemon's own words. A refusal names the tier that would have
		 * been needed (0013), and replacing that with "could not load" would
		 * throw away the one sentence that says what to do about it. */
		table->show_error(error);
		emit reported(error);
		return;
	}

	links = found;
	/* **The union, not the kernel's table.** `links()` is what the machine
	 * has; this adds what the document names and the machine does not have --
	 * a saved wifi network, an interface whose card is out. A row can be in
	 * either set or both, and dropping either half loses something real: the
	 * first would hide a configured network that is out of range, the second
	 * would hide `docker0`.
	 *
	 * A daemon that reports no inventory is one older than this window, and
	 * the list falls back to the kernel's links rather than going blank. */
	QString ignored;
	if (!connection->inventory(&rows_known, &ignored)) {
		rows_known.clear();
	}
	rebuild_filter();
	redraw();
}

/* Offer every category the rows actually contain, and no others.
 *
 * A fixed list would offer `modem` on a machine with no modem and leave an
 * operator picking it and seeing nothing -- which reads as a broken filter
 * rather than an empty one. Sorted, so the order does not move about between
 * refreshes, with "all" pinned first because it is the way back.
 *
 * The selection is kept across a refresh where the category is still offered.
 * Losing it every few seconds would make the filter unusable on a machine
 * whose links come and go, which is the machine most likely to want one. */
void ncfg_devices_view::rebuild_filter()
{
	QStringList present;
	for (const ncfg_inventory_row &row : rows_known) {
		if (!row.category.isEmpty() && !present.contains(row.category)) {
			present << row.category;
		}
	}
	for (const ncfg_link_row &link : links) {
		if (!link.category.isEmpty() && !present.contains(link.category)) {
			present << link.category;
		}
	}
	present.sort();

	const QString chosen = filter->currentText();
	QSignalBlocker quiet(filter);
	filter->clear();
	filter->addItem(ALL);
	filter->addItems(present);
	const int again = filter->findText(chosen);
	filter->setCurrentIndex(again >= 0 ? again : 0);
}

void ncfg_devices_view::redraw()
{
	const QString wanted = filter->currentText();
	QList<QStringList> rows;
	int hidden = 0;

	/* Drawn from the union where the daemon reports one, and from the
	 * kernel's links otherwise. The detail columns come from the observed
	 * link, looked up by name -- a row with no observed link is one that is
	 * not there, and its cells are blank rather than invented. */
	if (!rows_known.isEmpty()) {
		for (const ncfg_inventory_row &known : rows_known) {
			if (!ncfg_link_shows(known.category, wanted)) {
				hidden++;
				continue;
			}
			const ncfg_link_row *seen = nullptr;
			for (const ncfg_link_row &link : links) {
				if (link.name == known.name) {
					seen = &link;
					break;
				}
			}
			QStringList cells;
			cells << known.name;
			cells << known.category;
			cells << known.presence;
			cells << (seen ? seen->kind : QString());
			cells << (seen ? seen->state : QString());
			cells << (seen ? seen->network : QString());
			cells << (seen ? seen->addresses : QString());
			cells << (seen && seen->mtu ? QString::number(seen->mtu) : QString());
			cells << (seen ? seen->mac : QString());
			rows << cells;
		}
	} else {
		for (const ncfg_link_row &link : links) {
			if (!ncfg_link_shows(link.category, wanted)) {
				hidden++;
				continue;
			}
			QStringList cells;
			cells << link.name;
			cells << link.category;
			/* No inventory to ask, so nothing is claimed: this is a daemon
			 * older than the window, and the kernel has the link, so it is
			 * there. */
			cells << QStringLiteral("present");
			cells << link.kind;
			cells << link.state;
			cells << link.network;
			cells << link.addresses;
			cells << (link.mtu ? QString::number(link.mtu) : QString());
			cells << link.mac;
			rows << cells;
		}
	}
	table->show_rows(rows);

	/* The hidden count, said rather than left to be noticed. A filtered list
	 * that looks like the whole machine is how somebody concludes an
	 * interface has gone away. */
	if (rows.isEmpty()) {
		emit reported(hidden ? QStringLiteral("no %1 links (%2 hidden)").arg(wanted).arg(hidden)
		                     : QStringLiteral("no links reported"));
	} else if (hidden) {
		emit reported(QStringLiteral("%1 links, %2 hidden").arg(rows.size()).arg(hidden));
	} else {
		emit reported(QStringLiteral("%1 links").arg(rows.size()));
	}
}

void ncfg_devices_view::explain_selected()
{
	const QString name = table->selected_cell(0);
	if (name.isEmpty()) {
		return;
	}

	ncfg_explain_dialog dialog(connection, name, this);
	dialog.exec();
}

void ncfg_devices_view::configure_selected()
{
	/* The name out of the first column, which is where the table puts it. A
	 * row with no name is a row this view did not draw. */
	const QString name = table->selected_cell(0);
	if (name.isEmpty()) {
		return;
	}

	ncfg_interface_dialog dialog(connection, name, this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	emit reported(dialog.outcome());
	emit changed();
}
