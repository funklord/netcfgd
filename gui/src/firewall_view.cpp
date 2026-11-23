/*
 * firewall_view.cpp -- the table described in firewall_view.h.
 */
#include "firewall_view.h"

#include "counted.h"
#include "firewall_dialog.h"
#include "table_view.h"

#include <QComboBox>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

namespace {

QComboBox *policy_box(QWidget *parent, const QString &object)
{
	auto *box = new QComboBox(parent);
	box->setObjectName(object);
	box->addItem(QStringLiteral("accept"), QStringLiteral("accept"));
	box->addItem(QStringLiteral("drop"), QStringLiteral("drop"));
	return box;
}

/* What a rule matches, in the configuration's own words, for one column. */
QString matches(const ncfg_firewall_rule_row &rule)
{
	QStringList parts;
	if (rule.protocol != QLatin1String("any") && !rule.protocol.isEmpty()) {
		parts << rule.protocol;
	}
	if (!rule.ports.isEmpty()) {
		QStringList numbers;
		for (int port : rule.ports) {
			numbers << QString::number(port);
		}
		parts << QStringLiteral("port %1").arg(numbers.join(QLatin1Char(',')));
	}
	if (!rule.from.isEmpty()) {
		parts << QStringLiteral("from %1").arg(rule.from.join(QLatin1Char(',')));
	}
	if (!rule.to.isEmpty()) {
		parts << QStringLiteral("to %1").arg(rule.to.join(QLatin1Char(',')));
	}
	if (!rule.interface.isEmpty()) {
		parts << QStringLiteral("on %1").arg(rule.interface);
	}
	if (!rule.out_interface.isEmpty()) {
		parts << QStringLiteral("out %1").arg(rule.out_interface);
	}
	if (!rule.states.isEmpty()) {
		parts << QStringLiteral("state %1").arg(rule.states.join(QLatin1Char(',')));
	}
	if (!rule.stations.isEmpty()) {
		parts << QStringLiteral("mac %1").arg(rule.stations.join(QLatin1Char(',')));
	}
	/* Said rather than left blank: an empty cell reads as "nothing", and
	 * a rule matching nothing in particular matches everything. */
	return parts.isEmpty() ? QStringLiteral("everything") : parts.join(QLatin1Char(' '));
}

} // namespace

ncfg_firewall_view::ncfg_firewall_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);

	auto *policies = new QHBoxLayout();
	input_policy = policy_box(this, QStringLiteral("firewall_input_policy"));
	forward_policy = policy_box(this, QStringLiteral("firewall_forward_policy"));
	output_policy = policy_box(this, QStringLiteral("firewall_output_policy"));
	policies->addWidget(new QLabel(QStringLiteral("input"), this));
	policies->addWidget(input_policy);
	policies->addWidget(new QLabel(QStringLiteral("forward"), this));
	policies->addWidget(forward_policy);
	policies->addWidget(new QLabel(QStringLiteral("output"), this));
	policies->addWidget(output_policy);
	/* A button rather than writing on every change of a box: a policy of
	 * `drop` chosen on the way to another choice is not a thing to write. */
	auto *policies_button = new QPushButton(QStringLiteral("set policies"), this);
	policies_button->setObjectName(QStringLiteral("firewall_set_policies"));
	policies->addWidget(policies_button);
	policies->addStretch();
	layout->addLayout(policies);

	QStringList columns;
	columns << QStringLiteral("chain") << QStringLiteral("name") << QStringLiteral("action")
	        << QStringLiteral("matches") << QStringLiteral("matched");
	table = new ncfg_table_view(columns, QStringLiteral("firewall_view_note"), this);
	layout->addWidget(table);

	edit_button = new QPushButton(QStringLiteral("view / change"), this);
	edit_button->setObjectName(QStringLiteral("firewall_edit"));
	table->add_control(edit_button);
	auto *new_button = new QPushButton(QStringLiteral("new rule..."), this);
	new_button->setObjectName(QStringLiteral("firewall_new"));
	table->add_control(new_button);
	up_button = new QPushButton(QStringLiteral("move up"), this);
	up_button->setObjectName(QStringLiteral("firewall_up"));
	table->add_control(up_button);
	down_button = new QPushButton(QStringLiteral("move down"), this);
	down_button->setObjectName(QStringLiteral("firewall_down"));
	table->add_control(down_button);
	/* A slot's members, written live (0340): enabled on a slot's row. */
	member_add_button = new QPushButton(QStringLiteral("add to slot..."), this);
	member_add_button->setObjectName(QStringLiteral("firewall_slot_add"));
	table->add_control(member_add_button);
	member_remove_button = new QPushButton(QStringLiteral("remove from slot..."), this);
	member_remove_button->setObjectName(QStringLiteral("firewall_slot_remove"));
	table->add_control(member_remove_button);
	member_add_button->setEnabled(false);
	member_remove_button->setEnabled(false);
	for (QPushButton *button : { edit_button, up_button, down_button }) {
		button->setEnabled(false);
	}

	connect(policies_button, &QPushButton::clicked, this, &ncfg_firewall_view::set_policies);
	connect(edit_button, &QPushButton::clicked, this, &ncfg_firewall_view::edit_selected);
	connect(new_button, &QPushButton::clicked, this, &ncfg_firewall_view::new_rule);
	connect(up_button, &QPushButton::clicked, this, &ncfg_firewall_view::move_up);
	connect(down_button, &QPushButton::clicked, this, &ncfg_firewall_view::move_down);
	connect(table, &ncfg_table_view::activated, this, &ncfg_firewall_view::edit_selected);
	connect(member_add_button, &QPushButton::clicked, this, [this]() { ask_member(true); });
	connect(member_remove_button, &QPushButton::clicked, this, [this]() { ask_member(false); });
	connect(table, &ncfg_table_view::selection_changed, this, [this]() {
		const int  row = table->selected_row();
		const bool chosen = row >= 0;
		const bool slot = chosen && row < places.size() && places.at(row).second < 0;
		for (QPushButton *button : { edit_button, up_button, down_button }) {
			button->setEnabled(chosen);
		}
		member_add_button->setEnabled(slot);
		member_remove_button->setEnabled(slot);
	});
}

void ncfg_firewall_view::refresh()
{
	ncfg_firewall_settings found;
	QString                error;

	places.clear();
	if (!connection->firewall(&found, &error)) {
		settings = ncfg_firewall_settings();
		table->show_error(error);
		emit reported(error);
		return;
	}
	settings = found;

	const struct {
		const char                    *name;
		const ncfg_firewall_chain_row *chain;
		QComboBox                     *box;
	} chains[] = {
		{ "input", &settings.input, input_policy },
		{ "forward", &settings.forward, forward_policy },
		{ "output", &settings.output, output_policy },
	};
	/* What each rule has matched (10.901). A read that fails costs this
	 * column and nothing else, as UPnP's mappings cost their rows. */
	QHash<QString, ncfg_firewall_count_row> counts;
	const bool counted = connection->firewall_counts(&counts, nullptr);
	QList<QStringList> rows;
	for (const auto &one : chains) {
		const int at = one.box->findData(one.chain->policy);
		one.box->setCurrentIndex(at >= 0 ? at : 0);
		/* The slots first, as the kernel meets them (0340). A negative place
		 * says the row is a slot, which this tab shows and does not edit. */
		for (int i = 0; i < one.chain->slot_list.size(); i++) {
			const ncfg_firewall_slot_row &slot = one.chain->slot_list.at(i);
			QString what = QStringLiteral("members written live (ncfg slot), by %1")
			                   .arg(slot.match == QLatin1String("to") ? QStringLiteral("destination")
			                                                          : QStringLiteral("source"));
			if (slot.timeout > 0) {
				what += QStringLiteral(", each for %1 s unless given its own").arg(slot.timeout);
			}
			/* What it holds now, and what its two rules have matched. */
			const QString key = QStringLiteral("%1/slot:%2").arg(QString::fromLatin1(one.name),
			    slot.name);
			QString held;
			if (counts.contains(key)) {
				const ncfg_firewall_count_row &seen = counts.value(key);
				held = QStringLiteral("%1; %2")
				           .arg(seen.members.isEmpty()
				                    ? QStringLiteral("empty")
				                    : seen.members.join(QStringLiteral(", ")),
				               ncfg_counted(static_cast<qsizetype>(seen.packets), "packet",
				                   "packets"));
			} else if (counted) {
				held = QStringLiteral("not in the kernel yet");
			}
			rows << QStringList { QString::fromLatin1(one.name),
				QStringLiteral("slot %1").arg(slot.name), slot.action, what, held };
			places << qMakePair(QString::fromLatin1(one.name), -1 - i);
		}
		for (int i = 0; i < one.chain->rules.size(); i++) {
			const ncfg_firewall_rule_row &rule = one.chain->rules.at(i);
			const QString key = QStringLiteral("%1/%2").arg(QString::fromLatin1(one.name),
			    rule.name);
			QString matched;
			if (counts.contains(key)) {
				matched = ncfg_counted(static_cast<qsizetype>(counts.value(key).packets),
				    "packet", "packets");
			} else if (counted) {
				/* Written and not yet applied, or applied by a netcfgd
				 * that kept no count: said, since a blank reads as none. */
				matched = QStringLiteral("not counted yet");
			}
			rows << QStringList { QString::fromLatin1(one.name), rule.name, rule.action,
				matches(rule), matched };
			places << qMakePair(QString::fromLatin1(one.name), i);
		}
	}
	table->show_rows(rows);

	if (!settings.present) {
		table->set_note(QStringLiteral(
		    "No `firewall` block: netcfgd writes no filter chains, and whatever else "
		    "filters this machine is left as it is. Setting the policies or writing a "
		    "rule creates one -- and a chain is then netcfgd's whole say over that hook."));
		emit reported(QStringLiteral("no firewall configured"));
		return;
	}
	table->set_note(QStringLiteral(
	    "Each chain is evaluated top to bottom, and a packet no rule matched meets the "
	    "chain's policy. This is the configuration rather than what nftables has now -- the "
	    "plan tab is where the difference shows, and where a policy that would cut off "
	    "this machine's own replies is warned about. `matched` is what nftables has "
	    "counted for the rule since netcfgd last replaced its table."));
	emit reported(ncfg_counted(rows.size(), "firewall rule", "firewall rules"));
}

void ncfg_firewall_view::write(const ncfg_firewall_settings &next, const QString &said)
{
	QString error;
	if (!ncfg_firewall_write(connection, next, &error)) {
		emit reported(error);
		return;
	}
	emit reported(QStringLiteral("wrote %1: %2. netcfgd puts it in effect itself; Apply... shows anything it holds back.")
	                  .arg(QString::fromLatin1(ncfg_firewall_drop_in), said));
	refresh();
	emit changed();
}

void ncfg_firewall_view::set_policies()
{
	ncfg_firewall_settings next = settings;
	next.present = true;
	next.input.policy = input_policy->currentData().toString();
	next.forward.policy = forward_policy->currentData().toString();
	next.output.policy = output_policy->currentData().toString();
	write(next, QStringLiteral("policies input %1, forward %2, output %3")
	                   .arg(next.input.policy, next.forward.policy,
	                       next.output.policy));
}

/* The preset a rule comes from (0341), or an empty string for the
 * firewall's own: `PRESET/RULE` is a preset's, written in its own block. */
static QString preset_of(const QString &rule)
{
	const int slash = rule.indexOf(QLatin1Char('/'));
	return slash < 0 ? QString() : rule.left(slash);
}

/* Whether the rule at `row` is a preset's, said where the tab can be seen
 * saying it rather than opening a dialog whose Save the compiler refuses. */
bool ncfg_firewall_view::refuse_preset_rule(int row)
{
	if (places.at(row).second < 0) {
		emit reported(QStringLiteral("a slot is opened in the firewall block and its members are "
		                             "written live with `ncfg slot`; the slot itself is changed "
		                             "in the files tab (0340)"));
		return true;
	}
	const ncfg_firewall_chain_row *chain =
	    ncfg_firewall_chain(&settings, places.at(row).first);
	const QString name = chain && places.at(row).second < chain->rules.size()
	    ? chain->rules.at(places.at(row).second).name : QString();
	const QString preset = preset_of(name);

	if (preset.isEmpty()) {
		return false;
	}
	emit reported(QStringLiteral("%1 comes from preset `%2`, after this firewall's own rules; "
	                             "it is changed in that `preset` block, in the files tab")
	                  .arg(name, preset));
	return true;
}

/* The slot a row is, or empty for a rule's row. */
QString ncfg_firewall_view::slot_at(int row) const
{
	if (row < 0 || row >= places.size() || places.at(row).second >= 0) {
		return QString();
	}
	const ncfg_firewall_chain_row *chain =
	    places.at(row).first == QLatin1String("input")     ? &settings.input
	    : places.at(row).first == QLatin1String("forward") ? &settings.forward
	                                                       : &settings.output;
	const int at = -1 - places.at(row).second;
	return at < chain->slot_list.size() ? chain->slot_list.at(at).name : QString();
}

/* Asks for an address -- and for an addition, optionally a lifetime after it,
 * "192.0.2.7 30m" -- then writes it. */
void ncfg_firewall_view::ask_member(bool add)
{
	const QString slot = slot_at(table->selected_row());
	if (slot.isEmpty()) {
		return;
	}
	bool          given = false;
	const QString text = QInputDialog::getText(this,
	    add ? QStringLiteral("Add to slot %1").arg(slot)
	        : QStringLiteral("Remove from slot %1").arg(slot),
	    add ? QStringLiteral("Address, and a lifetime after it if it should lapse "
	                         "(\"192.0.2.7 30m\"):")
	        : QStringLiteral("Address:"),
	    QLineEdit::Normal, QString(), &given);
	if (!given) {
		return;
	}
	const QStringList words = text.split(QLatin1Char(' '), Qt::SkipEmptyParts);
	if (words.isEmpty() || words.size() > (add ? 2 : 1)) {
		emit reported(add ? QStringLiteral("an address, and optionally a lifetime after it")
		                  : QStringLiteral("one address"));
		return;
	}
	(void)write_slot_member(slot, words.at(0), add, words.size() > 1 ? words.at(1) : QString());
}

bool ncfg_firewall_view::write_slot_member(const QString &slot, const QString &address, bool add,
    const QString &lifetime)
{
	QString error;
	if (!connection->set_slot_member(slot, address, add, lifetime, &error)) {
		emit reported(error);
		return false;
	}
	emit reported(QStringLiteral("%1 %2 %3 slot %4; no apply, and it is never drift")
	                  .arg(add ? QStringLiteral("added") : QStringLiteral("removed"), address,
	                      add ? QStringLiteral("to") : QStringLiteral("from"), slot));
	refresh();
	return true;
}

void ncfg_firewall_view::move(int by)
{
	const int row = table->selected_row();
	if (row < 0 || row >= places.size()) {
		return;
	}
	if (refuse_preset_rule(row)) {
		return;
	}
	const QString            chain_name = places.at(row).first;
	const int                at = places.at(row).second;
	ncfg_firewall_settings   next = settings;
	ncfg_firewall_chain_row *chain = ncfg_firewall_chain(&next, chain_name);
	/* Within its chain only: a rule's chain is what it filters, and moving it
	 * to another is an edit the dialog makes on purpose. */
	if (!chain || at + by < 0 || at + by >= chain->rules.size() ||
	    !preset_of(chain->rules.at(at + by).name).isEmpty()) {
		return;
	}
	chain->rules.swapItemsAt(at, at + by);
	write(next, QStringLiteral("moved %1/%2 %3").arg(chain_name, chain->rules.at(at + by).name,
	                   by < 0 ? QStringLiteral("up") : QStringLiteral("down")));
}

void ncfg_firewall_view::move_up()
{
	move(-1);
}

void ncfg_firewall_view::move_down()
{
	move(1);
}

void ncfg_firewall_view::edit_selected()
{
	const int row = table->selected_row();
	if (row < 0 || row >= places.size()) {
		return;
	}
	if (refuse_preset_rule(row)) {
		return;
	}
	ncfg_firewall_rule_dialog dialog(connection, settings, places.at(row).first,
	    places.at(row).second, this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	emit reported(dialog.outcome());
	refresh();
	emit changed();
}

void ncfg_firewall_view::new_rule()
{
	ncfg_firewall_settings base = settings;
	base.present = true;
	ncfg_firewall_rule_dialog dialog(connection, base, QStringLiteral("input"), -1, this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	emit reported(dialog.outcome());
	refresh();
	emit changed();
}
