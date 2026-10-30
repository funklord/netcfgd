/*
 * address_editors.cpp -- see address_editors.h.
 */

#include "address_editors.h"

#include <QComboBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QRegularExpression>
#include <QTableWidget>
#include <QVBoxLayout>

namespace {

struct choice {
	const char *shown;
	const char *key;
};

/* The sources an `addressing` list can hold, spelled as the config language
 * spells them. `null` is deliberately absent: "no address" is an empty list
 * rather than a source, which is what `config = "null"` compiles to. */
const choice sources[] = {
	{ "DHCP (IPv4)", "dhcp" },
	{ "DHCPv6", "dhcp6" },
	{ "SLAAC (IPv6)", "slaac" },
	{ "a fixed address", "static" },
	{ "a delegated prefix", "delegated" },
	{ "link-local only", "link-local" },
	{ "reported by a helper", "reported" },
};

/* The kinds whose head is the text in the address box rather than the kind's
 * own word: a CIDR, or an `@pd:` reference. */
bool addressed(const QString &kind)
{
	return kind == QLatin1String("static") || kind == QLatin1String("delegated");
}

/* Words the language reads after an entry's head, or a route cell: no quote,
 * backslash or newline, so the quoted entry it goes into stays closed. What
 * the words mean is the compiler's to check, and it says so in its own terms. */
bool plain(const QString &text)
{
	static const QRegularExpression allowed(QStringLiteral("^[A-Za-z0-9_.:/=@ -]*$"));
	return allowed.match(text).hasMatch();
}

QPushButton *a_button(const QString &text, const QString &name, QWidget *parent)
{
	auto *button = new QPushButton(text, parent);
	button->setObjectName(name);
	return button;
}

} // namespace

ncfg_addressing_editor::ncfg_addressing_editor(const QString &prefix, QWidget *parent)
    : QWidget(parent)
{
	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);

	/* **The addressing list, as a list.** A block composes its addresses out
	 * of several sources -- a lease and a fixed address, DHCP and SLAAC, a
	 * helper's report -- and the order is applied in. */
	list = new QListWidget(this);
	list->setObjectName(prefix + QStringLiteral("_sources"));
	list->setSelectionMode(QAbstractItemView::SingleSelection);
	list->setMaximumHeight(110);
	layout->addWidget(list);

	auto *row = new QHBoxLayout();
	kind = new QComboBox(this);
	kind->setObjectName(prefix + QStringLiteral("_source_kind"));
	for (const choice &one : sources) {
		kind->addItem(QString::fromLatin1(one.shown), QString::fromLatin1(one.key));
	}
	address = new QLineEdit(this);
	address->setObjectName(prefix + QStringLiteral("_source_address"));
	address->setPlaceholderText(QStringLiteral("192.0.2.10/24, or @pd:wan0/1=::1/64"));
	options = new QLineEdit(this);
	options->setObjectName(prefix + QStringLiteral("_source_options"));
	options->setPlaceholderText(QStringLiteral("options, as written after it"));
	options->setToolTip(QStringLiteral(
	    "What the language takes after the entry, as you would write it: `peer`, "
	    "`preferred_lft` and `valid_lft` after an address; `pd`, `pd_hint` and "
	    "`pd_length` after dhcp6; `privacy prefer_temporary` after slaac."));
	add_button = a_button(QStringLiteral("add"), prefix + QStringLiteral("_source_add"), this);
	drop_button =
	    a_button(QStringLiteral("remove"), prefix + QStringLiteral("_source_drop"), this);
	up_button = a_button(QStringLiteral("up"), prefix + QStringLiteral("_source_up"), this);
	down_button = a_button(QStringLiteral("down"), prefix + QStringLiteral("_source_down"), this);
	row->addWidget(kind);
	row->addWidget(address, 1);
	row->addWidget(options, 1);
	row->addWidget(add_button);
	row->addWidget(drop_button);
	row->addWidget(up_button);
	row->addWidget(down_button);
	layout->addLayout(row);

	connect(add_button, &QPushButton::clicked, this, &ncfg_addressing_editor::add);
	connect(drop_button, &QPushButton::clicked, this, &ncfg_addressing_editor::drop);
	connect(up_button, &QPushButton::clicked, this, &ncfg_addressing_editor::move_up);
	connect(down_button, &QPushButton::clicked, this, &ncfg_addressing_editor::move_down);
	connect(kind, &QComboBox::currentIndexChanged, this, &ncfg_addressing_editor::changed);
	connect(list, &QListWidget::itemSelectionChanged, this, &ncfg_addressing_editor::changed);
	changed();
}

void ncfg_addressing_editor::load(const QList<ncfg_address_source_row> &loaded)
{
	list->clear();
	for (const ncfg_address_source_row &source : loaded) {
		/* The document's word for a source is not always the config
		 * language's: it compiles `dhcp` into `dhcp4` and `link-local` into
		 * `link_local`, and writing those back would be writing a spelling the
		 * file never had. */
		QString word = source.source;
		if (word == QLatin1String("dhcp4")) {
			word = QStringLiteral("dhcp");
		} else if (word == QLatin1String("link_local")) {
			word = QStringLiteral("link-local");
		}
		put(word, source.address, source.options);
	}
	changed();
}

QStringList ncfg_addressing_editor::entries() const
{
	QStringList out;
	for (int row = 0; row < list->count(); row++) {
		const QListWidgetItem *item = list->item(row);
		const QString which = item->data(Qt::UserRole).toString();
		QString entry = addressed(which) ? item->data(Qt::UserRole + 1).toString() : which;
		const QString extra = item->data(Qt::UserRole + 2).toString();
		if (!extra.isEmpty()) {
			entry += QLatin1Char(' ') + extra;
		}
		out << QStringLiteral("\"%1\"").arg(entry);
	}
	return out;
}

int ncfg_addressing_editor::count() const
{
	return list->count();
}

void ncfg_addressing_editor::changed()
{
	/* The address box belongs to the kinds whose head it is. Enabled rather
	 * than hidden, so the row does not jump about while somebody is using it. */
	address->setEnabled(addressed(kind->currentData().toString()));
	const int row = list->currentRow();
	drop_button->setEnabled(row >= 0);
	up_button->setEnabled(row > 0);
	down_button->setEnabled(row >= 0 && row + 1 < list->count());
}

/* One entry: the kind, the address where it has one and its options, kept on
 * the item rather than parsed back out of its text, which is the mistake that
 * would make a translated label unwritable. */
void ncfg_addressing_editor::put(const QString &which, const QString &where,
    const QString &extra)
{
	QString shown = which;
	if (!where.isEmpty()) {
		shown += QStringLiteral("  ") + where;
	}
	if (!extra.isEmpty()) {
		shown += QStringLiteral("  ") + extra;
	}
	auto *item = new QListWidgetItem(shown, list);
	item->setData(Qt::UserRole, which);
	item->setData(Qt::UserRole + 1, where);
	item->setData(Qt::UserRole + 2, extra);
}

void ncfg_addressing_editor::add()
{
	const QString which = kind->currentData().toString();
	const QString where = address->text().trimmed();
	const QString extra = options->text().simplified();

	if (which == QLatin1String("static") && where.isEmpty()) {
		emit noted(QStringLiteral("a fixed address needs an address"));
		return;
	}
	if (which == QLatin1String("delegated") && !where.startsWith(QLatin1String("@pd:"))) {
		emit noted(QStringLiteral("a delegated prefix is written `@pd:wan0`, or "
		           "`@pd:wan0/1=::1/64` for a subnet and a suffix"));
		return;
	}
	if (!plain(where) || where.contains(QLatin1Char(' ')) || !plain(extra)) {
		emit noted(QStringLiteral("an address is one word, and its options are words "
		           "the language reads: no quote, backslash or newline"));
		return;
	}
	put(which, addressed(which) ? where : QString(), extra);
	address->clear();
	options->clear();
	changed();
}

void ncfg_addressing_editor::drop()
{
	delete list->takeItem(list->currentRow());
	changed();
}

void ncfg_addressing_editor::move_up()
{
	const int row = list->currentRow();
	if (row <= 0) {
		return;
	}
	list->insertItem(row - 1, list->takeItem(row));
	list->setCurrentRow(row - 1);
	changed();
}

void ncfg_addressing_editor::move_down()
{
	const int row = list->currentRow();
	if (row < 0 || row + 1 >= list->count()) {
		return;
	}
	list->insertItem(row + 1, list->takeItem(row));
	list->setCurrentRow(row + 1);
	changed();
}

/* ------------------------------------------------------------------------ */

namespace {

enum { route_destination, route_via, route_metric, route_src, route_table, route_onlink };

} // namespace

ncfg_route_editor::ncfg_route_editor(const QString &prefix, QWidget *parent)
    : QWidget(parent)
{
	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);

	/* Routes, as a table rather than one gateway box. A machine with a second
	 * subnet behind it has a static route to it, and one box could hold only a
	 * default. `src`, `table` and `onlink` are columns since 10.615: a route
	 * carrying one was refused. */
	table = new QTableWidget(0, 6, this);
	table->setObjectName(prefix + QStringLiteral("_routes"));
	table->setHorizontalHeaderLabels({ QStringLiteral("destination"), QStringLiteral("via"),
	    QStringLiteral("metric"), QStringLiteral("source"), QStringLiteral("table"),
	    QStringLiteral("on link") });
	table->verticalHeader()->setVisible(false);
	table->horizontalHeader()->setStretchLastSection(true);
	table->setSelectionBehavior(QAbstractItemView::SelectRows);
	table->setSelectionMode(QAbstractItemView::SingleSelection);
	table->setMaximumHeight(110);
	table->setToolTip(QStringLiteral(
	    "source is the address the machine sends from on this route; table puts it in "
	    "a routing table other than main; on link says the gateway is reachable on "
	    "this link even outside its subnet."));
	layout->addWidget(table);

	auto *row = new QHBoxLayout();
	add_button =
	    a_button(QStringLiteral("add route"), prefix + QStringLiteral("_route_add"), this);
	drop_button =
	    a_button(QStringLiteral("remove route"), prefix + QStringLiteral("_route_drop"), this);
	row->addWidget(add_button);
	row->addWidget(drop_button);
	row->addStretch(1);
	layout->addLayout(row);

	connect(add_button, &QPushButton::clicked, this, [this]() {
		/* An empty row rather than a dialog: cells the operator fills in, and
		 * `refusal` names one with no destination. */
		ncfg_route_row blank;
		blank.destination = QStringLiteral("default");
		put(blank);
		table->setCurrentCell(table->rowCount() - 1, route_via);
	});
	connect(drop_button, &QPushButton::clicked, this, [this]() {
		if (table->currentRow() >= 0) {
			table->removeRow(table->currentRow());
		}
	});
}

void ncfg_route_editor::load(const QList<ncfg_route_row> &routes)
{
	table->setRowCount(0);
	for (const ncfg_route_row &route : routes) {
		put(route);
	}
}

void ncfg_route_editor::put(const ncfg_route_row &route)
{
	const int row = table->rowCount();
	table->insertRow(row);
	table->setItem(row, route_destination, new QTableWidgetItem(route.destination));
	table->setItem(row, route_via, new QTableWidgetItem(route.via));
	table->setItem(row, route_metric,
	    new QTableWidgetItem(route.metric >= 0 ? QString::number(route.metric) : QString()));
	table->setItem(row, route_src, new QTableWidgetItem(route.src));
	table->setItem(row, route_table,
	    new QTableWidgetItem(route.table >= 0 ? QString::number(route.table) : QString()));
	auto *onlink = new QTableWidgetItem();
	onlink->setFlags(Qt::ItemIsUserCheckable | Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	onlink->setCheckState(route.onlink ? Qt::Checked : Qt::Unchecked);
	table->setItem(row, route_onlink, onlink);
}

QString ncfg_route_editor::cell(int row, int column) const
{
	const QTableWidgetItem *item = table->item(row, column);
	return item ? item->text().trimmed() : QString();
}

QStringList ncfg_route_editor::lines() const
{
	QStringList out;
	for (int row = 0; row < table->rowCount(); row++) {
		QString line = cell(row, route_destination);
		const struct {
			const char *word;
			int         column;
		} words[] = {
			{ "via", route_via },
			{ "metric", route_metric },
			{ "src", route_src },
			{ "table", route_table },
		};
		for (const auto &one : words) {
			if (!cell(row, one.column).isEmpty()) {
				line += QStringLiteral(" %1 %2").arg(QString::fromLatin1(one.word),
				    cell(row, one.column));
			}
		}
		const QTableWidgetItem *onlink = table->item(row, route_onlink);
		if (onlink && onlink->checkState() == Qt::Checked) {
			line += QStringLiteral(" onlink");
		}
		out << QStringLiteral("\"%1\"").arg(line);
	}
	return out;
}

QString ncfg_route_editor::refusal() const
{
	for (int row = 0; row < table->rowCount(); row++) {
		if (cell(row, route_destination).isEmpty()) {
			return QStringLiteral("a route needs a destination: `default`, or a network "
			                      "like 10.0.0.0/8");
		}
		for (int column = route_destination; column <= route_table; column++) {
			const QString text = cell(row, column);
			if (!plain(text) || text.contains(QLatin1Char(' '))) {
				return QStringLiteral("route %1: each cell is one word, with no quote, "
				                      "backslash or newline").arg(row + 1);
			}
		}
		for (int column : { int(route_metric), int(route_table) }) {
			bool number = true;
			if (!cell(row, column).isEmpty()) {
				(void)cell(row, column).toUInt(&number);
			}
			if (!number) {
				return QStringLiteral("route %1: a metric and a table are numbers")
				    .arg(row + 1);
			}
		}
	}
	return QString();
}

int ncfg_route_editor::count() const
{
	return table->rowCount();
}
