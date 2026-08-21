/*
 * wifi_view.cpp -- the wifi tab described in wifi_view.h.
 */
#include "wifi_view.h"

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
	controls->addWidget(scan_button);
	controls->addWidget(join_button);
	controls->addWidget(add_button);
	controls->addWidget(leave_button);
	controls->addStretch();
	layout->addLayout(controls);

	status = new QLabel(this);
	/* Selectable because it carries the daemon's refusals, and a sentence
	 * naming the tier somebody lacks is one they will want to paste. */
	status->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(status);

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

	connect(scan_button, &QPushButton::clicked, this, &ncfg_wifi_view::scan);
	connect(join_button, &QPushButton::clicked, this, &ncfg_wifi_view::join);
	connect(add_button, &QPushButton::clicked, this, &ncfg_wifi_view::add);
	connect(leave_button, &QPushButton::clicked, this, &ncfg_wifi_view::leave);
	connect(table, &QTableWidget::itemSelectionChanged, this,
	    &ncfg_wifi_view::selection_changed);
	connect(interfaces, &QComboBox::currentTextChanged, this, [this]() { update_status(); });

	selection_changed();
}

QString ncfg_wifi_view::chosen_interface() const
{
	return interfaces->currentText();
}

void ncfg_wifi_view::refresh()
{
	QList<ncfg_link_row> rows;
	QString error;

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
		const QString none = QStringLiteral("no wireless device in the configuration");
		status->setText(none);
		emit reported(none);
		selection_changed();
		return;
	}

	update_status();
	selection_changed();
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
		status->setText(error);
		emit reported(error);
		selection_changed();
		return;
	}

	scanned = points;
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

	scan_button->setEnabled(have_radio);
	leave_button->setEnabled(have_radio);
	/* Enabled only for a row that names a `network` block. The button is the
	 * honest place to express 0013's boundary: offering it and answering with
	 * a refusal would teach the operator the rule one failure at a time. */
	const bool joinable = configured && !configured->text().isEmpty();
	join_button->setEnabled(have_radio && joinable);
	/* The mirror image: `add` is for a row that has *no* block yet. A row with
	 * one is already configured, and offering to add it again would be
	 * offering the refusal the daemon gives by name. */
	add_button->setEnabled(have_radio && row >= 0 && !joinable);
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
