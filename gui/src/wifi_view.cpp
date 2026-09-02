/*
 * wifi_view.cpp -- the wifi tab described in wifi_view.h.
 */
#include "wifi_view.h"

#include "network_dialog.h"

#include "add_network_dialog.h"
#include "ncfg_connection.h"

#include <QComboBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

namespace {

/* Signal, then name, then whether it can be joined. An operator scanning a room
 * reads strength first and the daemon already sorted by it, so the table keeps
 * the order it arrived in rather than sorting again on a column of its own. */
const char *const column_titles[] = {
	"signal", "network", "security", "configured", "channel", "bssid"
};
constexpr int column_count = static_cast<int>(sizeof(column_titles) / sizeof(column_titles[0]));

/* The document's own columns. `priority` and `metric` are both spelled out with
 * their direction in the cell rather than left as bare numbers, because they
 * run opposite ways and now sit next to each other: `priority` picks which
 * network to join, `metric` ranks the routes of the one joined against every
 * other link, including wired ones (0153). Adjacent deliberately -- an operator
 * comparing them is exactly who must not read them as one scale. */
const char *const saved_column_titles[] = {
	"network", "security", "credential", "priority", "metric", "autoconnect", "in range"
};
constexpr int saved_column_count =
    static_cast<int>(sizeof(saved_column_titles) / sizeof(saved_column_titles[0]));

/*
 * The 2.4 and 5 GHz channel an MHz figure names.
 *
 * Presentation, so it is on this side of the seam: the daemon reports the
 * frequency because that is the fact, and "channel 6" is what the label on
 * somebody's router says. Anything outside the two bands this knows is shown as
 * its frequency rather than guessed at -- 6 GHz numbering is a third rule and
 * inventing it here would print a confident wrong answer.
 */
QString channel_of(int mhz)
{
	if (mhz >= 2412 && mhz <= 2472) {
		return QString::number((mhz - 2407) / 5);
	}
	if (mhz == 2484) {
		return QStringLiteral("14");
	}
	if (mhz >= 5160 && mhz <= 5885) {
		return QString::number((mhz - 5000) / 5);
	}
	return QStringLiteral("%1 MHz").arg(mhz);
}

} /* namespace */

ncfg_wifi_view::ncfg_wifi_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	auto *layout = new QVBoxLayout(this);

	auto *controls = new QHBoxLayout();
	controls->addWidget(new QLabel(QStringLiteral("interface"), this));
	interfaces = new QComboBox(this);
	controls->addWidget(interfaces);

	scan_button = new QPushButton(QStringLiteral("scan"), this);
	join_button = new QPushButton(QStringLiteral("join"), this);
	add_button = new QPushButton(QStringLiteral("add"), this);
	leave_button = new QPushButton(QStringLiteral("disconnect"), this);
	activate_button = new QPushButton(QStringLiteral("activate radio"), this);
	activate_button->setObjectName(QStringLiteral("activate_radio"));
	controls->addWidget(scan_button);
	controls->addWidget(join_button);
	controls->addWidget(add_button);
	controls->addWidget(leave_button);
	controls->addWidget(activate_button);
	controls->addStretch();
	layout->addLayout(controls);

	status = new QLabel(this);
	/* Selectable because it carries the daemon's refusals, and a sentence
	 * naming the tier somebody lacks is one they will want to paste. */
	status->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(status);

	/* Above the table and hard to miss, because what it says explains every
	 * other thing on this tab behaving oddly. An operator whose scans fail
	 * intermittently has no way to guess that two daemons are taking the
	 * radio in turns, and netcfgd has known it all along -- it says so in
	 * every plan, where a wifi tab never looks. */
	contention = new QLabel(this);
	contention->setObjectName(QStringLiteral("contention"));
	contention->setWordWrap(true);
	contention->setTextInteractionFlags(Qt::TextSelectableByMouse);
	contention->setVisible(false);
	layout->addWidget(contention);

	table = new QTableWidget(0, column_count, this);
	QStringList headers;
	for (int i = 0; i < column_count; i++) {
		headers << QString::fromLatin1(column_titles[i]);
	}
	table->setHorizontalHeaderLabels(headers);
	table->verticalHeader()->setVisible(false);
	table->setSelectionBehavior(QAbstractItemView::SelectRows);
	table->setSelectionMode(QAbstractItemView::SingleSelection);
	table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	table->horizontalHeader()->setStretchLastSection(true);
	layout->addWidget(table);

	/* Below the scan and clearly its own list, because the two answer
	 * different questions: the table above is what is around this machine,
	 * and this is what the configuration holds. Keeping them in one table
	 * with a flag would mean a saved network out of range had no row. */
	auto *saved_controls = new QHBoxLayout();
	saved_controls->addWidget(new QLabel(QStringLiteral("saved networks"), this));
	edit_button = new QPushButton(QStringLiteral("view / change"), this);
	edit_button->setObjectName(QStringLiteral("edit_saved"));
	edit_button->setEnabled(false);
	manual_button = new QPushButton(QStringLiteral("add by hand"), this);
	manual_button->setObjectName(QStringLiteral("add_manually"));
	saved_controls->addWidget(edit_button);
	/* "By hand" rather than "add", because the button above the scan table is
	 * also called add and does something different: that one adds what the
	 * scan found, and this one writes a network that need not be in range. */
	saved_controls->addWidget(manual_button);
	saved_controls->addStretch();
	layout->addLayout(saved_controls);

	saved_table = new QTableWidget(0, saved_column_count, this);
	QStringList saved_headers;
	for (int i = 0; i < saved_column_count; i++) {
		saved_headers << QString::fromLatin1(saved_column_titles[i]);
	}
	saved_table->setObjectName(QStringLiteral("saved_networks"));
	saved_table->setHorizontalHeaderLabels(saved_headers);
	saved_table->verticalHeader()->setVisible(false);
	saved_table->setSelectionBehavior(QAbstractItemView::SelectRows);
	saved_table->setSelectionMode(QAbstractItemView::SingleSelection);
	saved_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	saved_table->horizontalHeader()->setStretchLastSection(true);
	layout->addWidget(saved_table);

	connect(edit_button, &QPushButton::clicked, this, &ncfg_wifi_view::edit_selected);
	connect(manual_button, &QPushButton::clicked, this, &ncfg_wifi_view::add_manually);
	/* Double-click opens it too. A table of settings that cannot be opened by
	 * double-clicking a row is one an operator tries to double-click. */
	connect(saved_table, &QTableWidget::doubleClicked, this, &ncfg_wifi_view::edit_selected);
	connect(saved_table, &QTableWidget::itemSelectionChanged, this, [this]() {
		edit_button->setEnabled(saved_table->currentRow() >= 0);
	});

	connect(scan_button, &QPushButton::clicked, this, &ncfg_wifi_view::scan);
	connect(join_button, &QPushButton::clicked, this, &ncfg_wifi_view::join);
	connect(add_button, &QPushButton::clicked, this, &ncfg_wifi_view::add);
	connect(leave_button, &QPushButton::clicked, this, &ncfg_wifi_view::leave);
	connect(activate_button, &QPushButton::clicked, this, &ncfg_wifi_view::activate);
	connect(table, &QTableWidget::itemSelectionChanged, this,
	    &ncfg_wifi_view::selection_changed);
	connect(interfaces, &QComboBox::currentTextChanged, this, [this]() { update_status(); });

	selection_changed();
}

QString ncfg_wifi_view::chosen_interface() const
{
	return interfaces->currentText();
}

/*
 * The document's networks, and which of them the last scan saw.
 *
 * "In range" is cross-referenced rather than asked for: the daemon already
 * marks a scanned access point with the network id that configures it, so the
 * two lists join on that. It is left blank rather than saying "no" when no
 * scan has been run, because "not in range" and "nobody looked" are different
 * facts and a table that spelled them the same way would be the sort of
 * confident wrong answer this program avoids elsewhere.
 */
void ncfg_wifi_view::update_saved()
{
	QString error;
	if (!connection->saved_networks(&saved, &error)) {
		/* Not fatal to the tab: the scan half still works, and a
		 * refusal here is usually a tier this caller lacks. */
		saved_table->setRowCount(0);
		return;
	}

	saved_table->setRowCount(saved.size());
	for (int row = 0; row < saved.size(); row++) {
		const ncfg_saved_network_row &network = saved.at(row);

		QString range;
		if (!scanned.isEmpty()) {
			range = QStringLiteral("no");
			for (const ncfg_access_point_row &point : scanned) {
				if (!point.configured.isEmpty() && point.configured == network.id) {
					range = QStringLiteral("yes");
					break;
				}
			}
		}

		/*
		 * **Dots rather than nothing, because "no credential" and "a
		 * credential you cannot see" are different facts and a blank cell
		 * spells them the same way.** An operator looking at a network that
		 * will not join needs to know whether one was ever configured.
		 *
		 * `configured` and not `stored`: this is the document's reference, and
		 * whether `secrets/<name>` exists is an observed fact nothing here has
		 * asked for. A network written without its passphrase looks exactly
		 * like one written with it, which is the case 0031 answers by asking
		 * an agent -- and is worth showing, once netcfgd is asked.
		 */
		const QString credential = network.credential.isEmpty()
		                   ? QStringLiteral("none needed")
		                   : QStringLiteral("\u2022\u2022\u2022\u2022");

		const QString cells[] = {
			network.name.isEmpty() ? network.id : network.name,
			network.security,
			credential,
			network.priority ? QStringLiteral("%1 (higher wins)").arg(network.priority)
			           : QString(),
			/* Negative is "the document ranks this against nothing", which is
			 * not the same as 0 -- 0 is the strongest metric there is. */
			network.metric >= 0
			    ? QStringLiteral("%1 (lower wins)").arg(network.metric)
			    : QString(),
			network.autoconnect ? QStringLiteral("yes") : QStringLiteral("no"),
			range,
		};
		for (int column = 0; column < saved_column_count; column++) {
			auto *item = new QTableWidgetItem(cells[column]);
			/* The reference in a tooltip rather than a column: it is what an
			 * operator needs when a credential is wrong and noise the rest of
			 * the time. */
			if (column == 2 && !network.credential.isEmpty()) {
				item->setToolTip(QStringLiteral("configured as @secret:%1 -- whether "
				         "that file exists is not shown here")
				             .arg(network.credential));
			}
			saved_table->setItem(row, column, item);
		}
	}
	saved_table->resizeColumnsToContents();
}

void ncfg_wifi_view::edit_network(const ncfg_saved_network_row &existing)
{
	ncfg_network_dialog dialog(connection, existing, this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	emit reported(dialog.outcome());
	/* The document changed, so the saved list and anything showing a plan are
	 * both stale. */
	update_saved();
	emit changed();
}

void ncfg_wifi_view::edit_selected()
{
	const int row = saved_table->currentRow();
	if (row < 0 || row >= saved.size()) {
		return;
	}
	edit_network(saved.at(row));
}

void ncfg_wifi_view::add_manually()
{
	edit_network(ncfg_saved_network_row());
}

void ncfg_wifi_view::refresh()
{
	QList<ncfg_link_row> rows;
	QString error;

	update_saved();

	if (!connection->links(&rows, &error)) {
		status->setText(error);
		emit reported(error);
		return;
	}

	const QString previous = chosen_interface();
	QStringList radios;
	for (const ncfg_link_row &link : rows) {
		if (link.wireless) {
			radios << link.name;
		}
	}

	/* Rebuilt only when it actually changed, so that re-selecting does not
	 * fight an operator who has just picked the second radio. */
	QStringList current;
	for (int i = 0; i < interfaces->count(); i++) {
		current << interfaces->itemText(i);
	}
	if (current != radios) {
		interfaces->clear();
		interfaces->addItems(radios);
		const int at = radios.indexOf(previous);
		if (at >= 0) {
			interfaces->setCurrentIndex(at);
		}
	}

	if (radios.isEmpty()) {
		table->setRowCount(0);
		/* The same sentence the TUI uses, deliberately: one condition, one
		 * wording, whichever client the operator happens to be in. */
		const QString none = QStringLiteral("no wireless device on this machine");
		status->setText(none);
		emit reported(none);
		chosen_radio = ncfg_radio_row();
		update_contention();
		selection_changed();
		return;
	}

	/* Which radios netcfgd has been given, which is not the same question as
	 * which radios exist. A radio nobody has activated used to leave this
	 * view saying "no wireless device in the configuration" and stopping,
	 * which described the problem to somebody standing in front of the fix. */
	QList<ncfg_radio_row> known;
	chosen_radio = ncfg_radio_row();
	if (connection->radios(&known, &error)) {
		for (const ncfg_radio_row &radio : known) {
			if (radio.name == chosen_interface()) {
				chosen_radio = radio;
			}
		}
	}

	if (!chosen_radio.activated) {
		table->setRowCount(0);
		const QString line =
		    QStringLiteral("%1: %2").arg(chosen_interface(), chosen_radio.state());
		status->setText(line);
		emit reported(line);
		update_contention();
		selection_changed();
		return;
	}

	update_status();
	update_contention();
	selection_changed();
}

/* What the planner says about this radio, which is where netcfgd records that
 * something else is managing it.
 *
 * Read out of the plan rather than asked for separately. netcfgd works this
 * out for every apply -- `contention.rs` reads the files NetworkManager and
 * systemd-networkd leave in /run -- and a second route to the same answer is
 * the drift this tree keeps finding.
 *
 * A failure to read the plan leaves the banner alone rather than clearing it:
 * "I could not check" is not "there is no other manager", and the second is
 * what an empty banner says.
 */
void ncfg_wifi_view::update_contention()
{
	const QString interface = chosen_interface();
	if (interface.isEmpty()) {
		contention->setVisible(false);
		return;
	}

	ncfg_plan_data plan;
	QString error;
	if (!connection->plan(&plan, &error)) {
		return;
	}

	for (const ncfg_note_row &warning : plan.warnings) {
		if (warning.interface != interface) {
			continue;
		}
		/* The planner's own sentence, and its remedy after it. Rewording
		 * either would put a second description of one condition in a second
		 * place, and the remedy is the half an operator acts on. */
		QString text = warning.message;
		if (!warning.remedy.isEmpty()) {
			text += QStringLiteral("\n\nTo hand it over: %1").arg(warning.remedy);
		}
		contention->setText(text);
		contention->setVisible(true);
		return;
	}
	contention->setVisible(false);
}

void ncfg_wifi_view::update_status()
{
	const QString interface = chosen_interface();
	if (interface.isEmpty()) {
		return;
	}

	ncfg_wifi_status_row state;
	QString error;

	if (!connection->wifi_status(interface, &state, &error)) {
		status->setText(error);
		emit reported(error);
		return;
	}

	/* Composed once, on the row, because the tray draws the same line. */
	const QString line = state.summary();
	status->setText(line);
	emit reported(line);
}

void ncfg_wifi_view::scan()
{
	const QString interface = chosen_interface();
	if (interface.isEmpty()) {
		return;
	}

	QList<ncfg_access_point_row> points;
	QString error;

	/* Blocks for as long as the radio takes. Saying so beforehand is the
	 * cheapest honest thing a synchronous client can do; the alternative is a
	 * window that looks wedged. */
	scan_button->setEnabled(false);
	status->setText(QStringLiteral("scanning %1...").arg(interface));
	status->repaint();
	const bool done = connection->wifi_scan(interface, &points, &error);
	scan_button->setEnabled(true);

	if (!done) {
		scanned.clear();
		table->setRowCount(0);
		/* **The moment contention actually bites.** Another manager taking
		 * the interface out of the supplicant makes the control socket vanish
		 * for that window, and netcfgd's refusal is then "is wpa_supplicant
		 * running?" -- true, and the wrong question. An operator whose scans
		 * fail every other attempt has no way to guess two daemons are taking
		 * the radio in turns, so the banner is re-read here and its sentence
		 * put after the refusal.
		 */
		update_contention();
		QString said = error;
		if (contention->isVisible()) {
			said += QStringLiteral("\n\n%1").arg(contention->text());
		}
		status->setText(said);
		emit reported(said);
		selection_changed();
		return;
	}

	scanned = points;
	/* The saved list carries an "in range" column derived from this scan, so
	 * it is stale the moment a new one lands. Recomputed here rather than
	 * left until the next refresh, because the operator who just pressed
	 * scan is the one reading it. */
	update_saved();
	table->setRowCount(points.size());
	int joinable = 0;
	for (int row = 0; row < points.size(); row++) {
		const ncfg_access_point_row &point = points.at(row);
		if (point.joinable()) {
			joinable++;
		}
		const QString cells[column_count] = {
			QStringLiteral("%1 dBm").arg(point.signal),
			point.display,
			/* Three words, not two. "secured" on a corporate network
			 * tells an operator to look for a passphrase they do not
			 * have; naming 802.1X says what will be asked for. */
			point.enterprise ? QStringLiteral("enterprise")
			         : point.secured ? QStringLiteral("secured")
			                 : QStringLiteral("open"),
			/* Empty rather than "no": the column answers "which network
			 * block is this" and a word invented for the absent case
			 * would read as a block called "no". */
			point.configured,
			channel_of(point.frequency),
			point.bssid,
		};
		for (int column = 0; column < column_count; column++) {
			auto *item = new QTableWidgetItem(cells[column]);
			if (!point.joinable()) {
				/* Greyed rather than hidden. An access point this
				 * client cannot join is still something the
				 * operator is looking for, and the reason it is
				 * grey is the sentence under the table. */
				item->setForeground(palette().brush(QPalette::Disabled,
				                   QPalette::Text));
			}
			table->setItem(row, column, item);
		}
	}
	table->resizeColumnsToContents();
	table->horizontalHeader()->setStretchLastSection(true);

	const QString summary =
	    points.isEmpty()
	        ? QStringLiteral("%1 found nothing").arg(interface)
	        : QStringLiteral("%1: %2 access points, %3 configured -- the rest need a "
	                 "`network` block before they can be joined")
	              .arg(interface)
	              .arg(points.size())
	              .arg(joinable);
	status->setText(summary);
	emit reported(summary);
	selection_changed();
}

void ncfg_wifi_view::join()
{
	const int row = table->currentRow();
	const QString interface = chosen_interface();
	if (row < 0 || interface.isEmpty()) {
		return;
	}
	/* The network's id, read back out of the column that holds it. The join
	 * is by id and never by SSID: that is what keeps this inside the `wifi`
	 * tier, and it is why an unconfigured row has nothing to send. */
	const QTableWidgetItem *item = table->item(row, 3);
	const QString network = item ? item->text() : QString();
	if (network.isEmpty()) {
		return;
	}

	QString error;
	if (!connection->wifi_connect(interface, network, &error)) {
		status->setText(error);
		emit reported(error);
		return;
	}
	update_status();
}

void ncfg_wifi_view::leave()
{
	const QString interface = chosen_interface();
	if (interface.isEmpty()) {
		return;
	}

	QString error;
	if (!connection->wifi_disconnect(interface, &error)) {
		status->setText(error);
		emit reported(error);
		return;
	}
	update_status();
}

void ncfg_wifi_view::selection_changed()
{
	const bool have_radio = !chosen_interface().isEmpty();
	const int row = table->currentRow();
	const QTableWidgetItem *configured = row >= 0 ? table->item(row, 3) : nullptr;

	/* Everything wireless needs a radio netcfgd has been *given*, not merely
	 * one that exists: scanning goes over a supplicant's control socket, and
	 * netcfgd runs no supplicant on a radio nobody activated. Enabling these
	 * anyway would teach the boundary one failure at a time, which is what the
	 * `join` button below already refuses to do. */
	const bool usable = have_radio && chosen_radio.activated;

	/* Offered only where activating could work. A radio another manager holds
	 * is one netcfgd declines to take while that manager runs, so the button
	 * would do nothing -- the status line says who to stop instead. */
	activate_button->setVisible(have_radio && !chosen_radio.activated);
	activate_button->setEnabled(have_radio && !chosen_radio.activated
	                && !chosen_radio.supplicant);

	scan_button->setEnabled(usable);
	leave_button->setEnabled(usable);
	/* Enabled only for a row that names a `network` block. The button is the
	 * honest place to express 0013's boundary: offering it and answering with
	 * a refusal would teach the operator the rule one failure at a time. */
	const bool joinable = configured && !configured->text().isEmpty();
	join_button->setEnabled(usable && joinable);
	/* The mirror image: `add` is for a row that has *no* block yet. A row with
	 * one is already configured, and offering to add it again would be
	 * offering the refusal the daemon gives by name. */
	add_button->setEnabled(usable && row >= 0 && !joinable);
}

/* Hand the chosen radio to netcfgd, and look at what it can see.
 *
 * The scan follows immediately because activating is only ever a step towards
 * it -- an operator who pressed this wants the list, not a second button. */
void ncfg_wifi_view::activate()
{
	const QString interface = chosen_interface();
	if (interface.isEmpty()) {
		return;
	}

	QString error;
	if (!connection->set_radio(interface, true, &error)) {
		status->setText(error);
		emit reported(error);
		return;
	}

	refresh();
	if (chosen_radio.activated) {
		scan();
	}
}

void ncfg_wifi_view::add()
{
	const int row = table->currentRow();
	if (row < 0) {
		return;
	}
	/* Straight off the selected row rather than retyped. The hex is what the
	 * radio actually saw, and a network whose name does not render as text is
	 * exactly the one somebody would type wrongly. */
	const QTableWidgetItem *shown = table->item(row, 1);
	if (!shown || row >= scanned.size()) {
		return;
	}
	/* From the scan row rather than from the cell it was rendered into. The
	 * text is display vocabulary and reading it back is a comparison that
	 * breaks the moment the word changes -- which it just did, when
	 * `enterprise` became a third value the column can hold. */
	const ncfg_access_point_row &point = scanned.at(row);

	ncfg_add_network_dialog dialog(connection, point.ssid, shown->text(), point.secured,
	                   point.enterprise, this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	/* Re-scan rather than patching the row: the daemon has re-read its
	 * configuration, so `configured` has changed for this access point and
	 * possibly for others, and asking is cheaper than being clever. */
	scan();
}
