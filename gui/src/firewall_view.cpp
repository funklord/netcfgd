/*
 * firewall_view.cpp -- the table described in firewall_view.h.
 */
#include "firewall_view.h"

#include "firewall_dialog.h"
#include "table_view.h"

#include <QComboBox>
#include <QHBoxLayout>
#include <QLabel>
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
	        << QStringLiteral("matches");
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
	for (QPushButton *button : { edit_button, up_button, down_button }) {
		button->setEnabled(false);
	}

	connect(policies_button, &QPushButton::clicked, this, &ncfg_firewall_view::set_policies);
	connect(edit_button, &QPushButton::clicked, this, &ncfg_firewall_view::edit_selected);
	connect(new_button, &QPushButton::clicked, this, &ncfg_firewall_view::new_rule);
	connect(up_button, &QPushButton::clicked, this, &ncfg_firewall_view::move_up);
	connect(down_button, &QPushButton::clicked, this, &ncfg_firewall_view::move_down);
	connect(table, &ncfg_table_view::activated, this, &ncfg_firewall_view::edit_selected);
	connect(table, &ncfg_table_view::selection_changed, this, [this]() {
		const bool chosen = table->selected_row() >= 0;
		for (QPushButton *button : { edit_button, up_button, down_button }) {
			button->setEnabled(chosen);
		}
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
	QList<QStringList> rows;
	for (const auto &one : chains) {
		const int at = one.box->findData(one.chain->policy);
		one.box->setCurrentIndex(at >= 0 ? at : 0);
		for (int i = 0; i < one.chain->rules.size(); i++) {
			const ncfg_firewall_rule_row &rule = one.chain->rules.at(i);
			rows << QStringList { QString::fromLatin1(one.name), rule.name, rule.action,
				matches(rule) };
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
	    "this machine's own replies is warned about."));
	emit reported(QStringLiteral("%1 firewall rules").arg(rows.size()));
}

void ncfg_firewall_view::write(const ncfg_firewall_settings &next, const QString &said)
{
	QString error;
	if (!ncfg_firewall_write(connection, next, &error)) {
		emit reported(error);
		return;
	}
	emit reported(QStringLiteral("wrote %1: %2. Run apply to make the machine match it.")
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

void ncfg_firewall_view::move(int by)
{
	const int row = table->selected_row();
	if (row < 0 || row >= places.size()) {
		return;
	}
	const QString            chain_name = places.at(row).first;
	const int                at = places.at(row).second;
	ncfg_firewall_settings   next = settings;
	ncfg_firewall_chain_row *chain = ncfg_firewall_chain(&next, chain_name);
	/* Within its chain only: a rule's chain is what it filters, and moving it
	 * to another is an edit the dialog makes on purpose. */
	if (!chain || at + by < 0 || at + by >= chain->rules.size()) {
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
