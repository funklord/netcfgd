/*
 * devices_view.cpp -- the devices table described in devices_view.h.
 */
#include "devices_view.h"

#include "explain_dialog.h"
#include "interface_dialog.h"
#include "ncfg_connection.h"
#include "network_dialog.h"
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
	 * column is the honest rendering, since a cable has no network to be on.
	 *
	 * **`kind` was here and is not, and the reason was visible rather than
	 * argued.** With `configured` added the table stopped fitting: a
	 * horizontal scrollbar appeared and the MAC was truncated mid-address.
	 * `kind` is the column that had stopped paying for itself -- it reads
	 * `device` for a real card and for the loopback, which is the client's
	 * substitute for the empty string the kernel reports, while `category`
	 * already says `ethernet` and `loopback`; and where the kernel does give a
	 * kind -- `bridge`, `wireguard` -- `category` says the same word. On this
	 * machine it added nothing to any row and cost the width that truncated
	 * the MAC. The kernel's own kind is still in `ncfg_link_row` for anything
	 * that wants it. */
	/* `link`, not `interface`. The first column holds both kinds of block now
	 * -- an interface and a saved wifi network are both links -- and a header
	 * saying `interface` over a row called `OpenPC.se` is the same confusion
	 * the two-row list had, moved into the heading. */
	QStringList columns;
	columns << QStringLiteral("link") << QStringLiteral("category")
	        << QStringLiteral("presence") << QStringLiteral("configured")
	        /* Which group is already deciding about this link. Beside
	         * `configured` because it is the same kind of fact -- what the
	         * document says about the row -- and before the observed columns
	         * for the same reason. */
	        << QStringLiteral("set")
	        << QStringLiteral("state") << QStringLiteral("device")
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

/* How the `configured` flag reads in a cell.
 *
 * **Words rather than a tick or a blank**, because the column has three states
 * and only two of them are the flag. "yes" is a link the document names, "no"
 * is one the machine has that nobody asked for -- a container bridge, a card
 * another manager owns -- and an *empty* cell is a daemon too old to say. A
 * blank standing for "no" would make the third indistinguishable from the
 * second, which is the same collapse `presence` exists to avoid one column
 * over.
 */
static QString configured_word(bool configured)
{
	return configured ? QStringLiteral("yes") : QStringLiteral("no");
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
			/* The observed link this row's detail comes from. For an
			 * interface that is itself; for a wifi network it is the radio
			 * carrying it, because the addresses, the state and the lease
			 * live on the radio while the connection they belong to is the
			 * network. That is the join that turned two half-rows into one
			 * whole one. */
			const QString detail_from = known.carrier.isEmpty() ? known.name : known.carrier;
			const ncfg_link_row *seen = nullptr;
			for (const ncfg_link_row &link : links) {
				if (link.name == detail_from) {
					seen = &link;
					break;
				}
			}
			QStringList cells;
			cells << known.name;
			cells << known.category;
			cells << known.presence;
			cells << configured_word(known.configured);
			cells << known.sets;
			cells << (seen ? seen->state : QString());
			/* Which hardware is carrying it, for a network. Blank for an
			 * interface, which carries itself and would only repeat column
			 * one. */
			cells << known.carrier;
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
			/* No inventory to ask, so this is not claimed either way. An
			 * older daemon does not say which links the document names, and
			 * writing "no" would assert something nobody was told. */
			cells << QString();
			/* And no inventory means no sets: an older daemon has none to
			 * report, and this window does not work them out for itself. */
			cells << QString();
			cells << link.state;
			/* No inventory, so no carrier is known. The kernel's own view has
			 * the network on the radio's row, which is the shape this column
			 * replaced -- leaving it blank says less than it could, and says
			 * nothing wrong. */
			cells << QString();
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

	/* Two kinds of row share this list, and configuring them is not the same
	 * job: an interface has a device to set up, a wifi network has an ssid and
	 * a credential. Dispatch on what the row says it is. Before the row
	 * carried its subject this opened the interface dialog for everything,
	 * which for a network meant an editor for an interface of that name --
	 * and there is no interface called `OpenPC.se`. */
	const QString subject = ncfg_link_subject(rows_known, name);
	if (subject == QLatin1String("network")) {
		configure_network(name);
		return;
	}
	/* **A linkset has no editor yet, and says so rather than opening one for
	 * something else.** It is a `linkset` block in the configuration, which
	 * the files tab edits; offering the interface dialog for a group would be
	 * exactly the fault 0247 fixed, one kind of row later. */
	if (subject == QLatin1String("linkset")) {
		emit reported(QStringLiteral("`%1` is a linkset: a group of links, edited as a "
		         "`linkset` block under configuration > files")
		             .arg(name));
		return;
	}

	ncfg_interface_dialog dialog(connection, name, this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	emit reported(dialog.outcome());
	emit changed();
}

void ncfg_devices_view::configure_network(const QString &id)
{
	/* The dialog edits a block, so it needs the block and not just its name.
	 * The document is the daemon's to hand out; asking for it here keeps this
	 * view from having to mirror every network field in its own row. */
	QList<ncfg_saved_network_row> saved;
	QString error;

	if (!connection->saved_networks(&saved, &error)) {
		emit reported(error);
		return;
	}
	for (const ncfg_saved_network_row &network : saved) {
		if (network.id != id) {
			continue;
		}
		ncfg_network_dialog dialog(connection, network, this);
		if (dialog.exec() != QDialog::Accepted) {
			return;
		}
		emit reported(dialog.outcome());
		emit changed();
		return;
	}
	/* A row naming a network the document no longer has: the list is one
	 * refresh behind. Say so rather than opening an empty editor, which would
	 * write the block back. */
	emit reported(QStringLiteral("no saved network called %1 any more").arg(id));
}
