/*
 * firewall_view.cpp -- the table described in firewall_view.h.
 */
#include "firewall_view.h"

#include "counted.h"
#include "firewall_dialog.h"
#include "table_view.h"

#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRegularExpression>
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
	/* The presets the firewall uses (0341), comma- or space-separated; their
	 * blocks are written in the files tab, as a library is. */
	auto *presets_row = new QHBoxLayout();
	presets_edit = new QLineEdit(this);
	presets_edit->setObjectName(QStringLiteral("firewall_presets"));
	presets_edit->setPlaceholderText(QStringLiteral("presets used, after this firewall's rules"));
	presets_edit->setAccessibleName(QStringLiteral("presets"));
	auto *presets_button = new QPushButton(QStringLiteral("set presets"), this);
	presets_button->setObjectName(QStringLiteral("firewall_set_presets"));
	presets_row->addWidget(new QLabel(QStringLiteral("presets"), this));
	presets_row->addWidget(presets_edit, 1);
	presets_row->addWidget(presets_button);
	layout->addLayout(presets_row);
	connect(presets_button, &QPushButton::clicked, this, [this]() {
		(void)set_presets(presets_edit->text().split(QRegularExpression(QStringLiteral("[,\\s]+")),
		    Qt::SkipEmptyParts));
	});

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
	auto *slot_new_button = new QPushButton(QStringLiteral("new slot..."), this);
	slot_new_button->setObjectName(QStringLiteral("firewall_slot_new"));
	table->add_control(slot_new_button);
	slot_delete_button = new QPushButton(QStringLiteral("delete slot"), this);
	slot_delete_button->setObjectName(QStringLiteral("firewall_slot_delete"));
	table->add_control(slot_delete_button);
	slot_delete_button->setEnabled(false);
	connect(slot_new_button, &QPushButton::clicked, this,
	    [this]() { slot_dialog(QString(), ncfg_firewall_slot_row()); });
	connect(slot_delete_button, &QPushButton::clicked, this, [this]() {
		const QString slot = slot_at(table->selected_row());
		if (!slot.isEmpty()) {
			(void)remove_slot(slot);
		}
	});
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
		slot_delete_button->setEnabled(slot);
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
	presets_edit->setText(settings.presets.join(QStringLiteral(", ")));

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

bool ncfg_firewall_view::write(const ncfg_firewall_settings &next, const QString &said)
{
	QString error;
	if (!ncfg_firewall_write(connection, next, &error)) {
		emit reported(error);
		return false;
	}
	emit reported(QStringLiteral("wrote %1: %2. netcfgd puts it in effect itself; Apply... shows anything it holds back.")
	                  .arg(QString::fromLatin1(ncfg_firewall_drop_in), said));
	refresh();
	emit changed();
	return true;
}

bool ncfg_firewall_view::set_presets(const QStringList &presets)
{
	ncfg_firewall_settings next = settings;
	next.present = true;
	next.presets = presets;
	return write(next, presets.isEmpty() ? QStringLiteral("no presets")
	                                     : QStringLiteral("presets %1").arg(presets.join(", ")));
}

bool ncfg_firewall_view::put_slot(const QString &chain, const ncfg_firewall_slot_row &slot)
{
	ncfg_firewall_settings next = settings;
	next.present = true;
	/* A slot's name is the firewall's: one of that name anywhere goes. */
	for (ncfg_firewall_chain_row *each : { &next.input, &next.forward, &next.output }) {
		for (int at = each->slot_list.size() - 1; at >= 0; at--) {
			if (each->slot_list.at(at).name == slot.name) {
				each->slot_list.removeAt(at);
			}
		}
	}
	ncfg_firewall_chain_row *into = ncfg_firewall_chain(&next, chain);
	if (!into) {
		emit reported(QStringLiteral("%1 is not a chain").arg(chain));
		return false;
	}
	into->slot_list << slot;
	return write(next, QStringLiteral("slot %1 in %2").arg(slot.name, chain));
}

bool ncfg_firewall_view::remove_slot(const QString &name)
{
	ncfg_firewall_settings next = settings;
	bool                   found = false;
	for (ncfg_firewall_chain_row *each : { &next.input, &next.forward, &next.output }) {
		for (int at = each->slot_list.size() - 1; at >= 0; at--) {
			if (each->slot_list.at(at).name == name) {
				each->slot_list.removeAt(at);
				found = true;
			}
		}
	}
	if (!found) {
		emit reported(QStringLiteral("there is no slot %1").arg(name));
		return false;
	}
	return write(next, QStringLiteral("slot %1 removed, and its members with it").arg(name));
}

/* A slot's four keys, new or prefilled from the one being changed. */
void ncfg_firewall_view::slot_dialog(const QString &chain, const ncfg_firewall_slot_row &existing)
{
	QDialog dialog(this);
	dialog.setWindowTitle(existing.name.isEmpty() ? QStringLiteral("New slot")
	                                              : QStringLiteral("Slot %1").arg(existing.name));
	auto *form = new QFormLayout(&dialog);
	auto *where = new QComboBox(&dialog);
	for (const char *one : { "input", "forward", "output" }) {
		where->addItem(QString::fromLatin1(one), QString::fromLatin1(one));
	}
	where->setCurrentIndex(where->findData(chain.isEmpty() ? QStringLiteral("forward") : chain));
	auto *name = new QLineEdit(existing.name, &dialog);
	name->setPlaceholderText(QStringLiteral("quarantine"));
	auto *action = new QComboBox(&dialog);
	for (const char *one : { "drop", "reject", "accept", "none" }) {
		action->addItem(QString::fromLatin1(one), QString::fromLatin1(one));
	}
	if (!existing.action.isEmpty()) {
		action->setCurrentIndex(action->findData(existing.action));
	}
	auto *match = new QComboBox(&dialog);
	match->addItem(QStringLiteral("source (from)"), QStringLiteral("from"));
	match->addItem(QStringLiteral("destination (to)"), QStringLiteral("to"));
	match->setCurrentIndex(match->findData(existing.match == QLatin1String("to")
	                                           ? QStringLiteral("to") : QStringLiteral("from")));
	auto *timeout = new QLineEdit(existing.timeout > 0
	                                  ? QStringLiteral("%1s").arg(existing.timeout) : QString(),
	    &dialog);
	timeout->setPlaceholderText(QStringLiteral("blank: until removed; or 90s, 30m, 1h, 2d"));
	form->addRow(QStringLiteral("chain"), where);
	form->addRow(QStringLiteral("name"), name);
	form->addRow(QStringLiteral("members get"), action);
	form->addRow(QStringLiteral("matched by"), match);
	form->addRow(QStringLiteral("lifetime"), timeout);
	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
	form->addRow(buttons);
	connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
	connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	ncfg_firewall_slot_row slot;
	slot.name = name->text().trimmed();
	slot.action = action->currentData().toString();
	slot.match = match->currentData().toString();
	/* The lifetime in seconds, as the document holds it; the compiler
	 * refuses a spelling it cannot read, and says why. */
	const QString life = timeout->text().trimmed();
	if (!life.isEmpty()) {
		static const QString units = QStringLiteral("smhd");
		const qsizetype unit = units.indexOf(life.right(1));
		bool            number = false;
		const long      count = life.left(life.size() - 1).toLong(&number);
		static const long scale[] = { 1, 60, 3600, 86400 };
		if (unit < 0 || !number || count <= 0) {
			emit reported(QStringLiteral("`%1` is not a lifetime: a count and s, m, h or d").arg(life));
			return;
		}
		slot.timeout = count * scale[unit];
	}
	if (!existing.name.isEmpty() && existing.name != slot.name) {
		(void)remove_slot(existing.name);
	}
	(void)put_slot(where->currentData().toString(), slot);
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
		emit reported(QStringLiteral("a slot always comes first in its chain, so it does not "
		                             "move; view / change edits it, and its members are written "
		                             "live with add and remove, or `ncfg slot` (0340)"));
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
	/* A slot's row opens the slot's own dialog (0340). */
	if (places.at(row).second < 0) {
		const ncfg_firewall_chain_row *chain = ncfg_firewall_chain(&settings, places.at(row).first);
		const int at = -1 - places.at(row).second;
		if (chain && at < chain->slot_list.size()) {
			slot_dialog(places.at(row).first, chain->slot_list.at(at));
		}
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
