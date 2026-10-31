/*
 * firewall_dialog.cpp -- the editor and block writer described in
 * firewall_dialog.h.
 */
#include "firewall_dialog.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QRegularExpression>
#include <QVBoxLayout>

const char *const ncfg_firewall_drop_in = "firewall";

namespace {

const char *const chain_names[] = { "input", "forward", "output" };

/* 0294's vocabulary, the whole of it. */
const char *const action_words[] = { "accept", "drop", "reject" };
const char *const protocol_words[] = { "any", "tcp", "udp", "icmp", "icmpv6" };

QString quoted(const QString &text)
{
	return QStringLiteral("\"%1\"").arg(text);
}

QString quoted_list(const QStringList &items)
{
	QStringList each;
	for (const QString &item : items) {
		each << quoted(item);
	}
	return QStringLiteral("[%1]").arg(each.join(QStringLiteral(", ")));
}

/* Commas or spaces between members, whichever was typed. */
QStringList split_list(const QString &text)
{
	return text.split(QRegularExpression(QStringLiteral("[,\\s]+")), Qt::SkipEmptyParts);
}

bool safe_value(const QString &text)
{
	return !text.contains(QLatin1Char('"')) && !text.contains(QLatin1Char('\\')) &&
	       !text.contains(QLatin1Char('\n'));
}

void write_rule(QStringList &body, const ncfg_firewall_rule_row &rule)
{
	body << QStringLiteral("\t\t%1 %2 {").arg(rule.action, quoted(rule.name));
	/* `any` is the default and the renderer leaves it out too. */
	if (!rule.protocol.isEmpty() && rule.protocol != QLatin1String("any")) {
		body << QStringLiteral("\t\t\tprotocol = %1").arg(quoted(rule.protocol));
	}
	if (!rule.ports.isEmpty()) {
		QStringList numbers;
		for (int port : rule.ports) {
			numbers << QString::number(port);
		}
		body << QStringLiteral("\t\t\tport = [%1]").arg(numbers.join(QStringLiteral(", ")));
	}
	if (!rule.from.isEmpty()) {
		body << QStringLiteral("\t\t\tfrom = %1").arg(quoted_list(rule.from));
	}
	if (!rule.to.isEmpty()) {
		body << QStringLiteral("\t\t\tto = %1").arg(quoted_list(rule.to));
	}
	if (!rule.interface.isEmpty()) {
		body << QStringLiteral("\t\t\tinterface = %1").arg(quoted(rule.interface));
	}
	if (!rule.out_interface.isEmpty()) {
		body << QStringLiteral("\t\t\tout_interface = %1").arg(quoted(rule.out_interface));
	}
	if (!rule.states.isEmpty()) {
		body << QStringLiteral("\t\t\tstate = %1").arg(quoted_list(rule.states));
	}
	if (!rule.stations.isEmpty()) {
		body << QStringLiteral("\t\t\tmac = %1").arg(quoted_list(rule.stations));
	}
	body << QStringLiteral("\t\t}");
}

} // namespace

ncfg_firewall_chain_row *ncfg_firewall_chain(ncfg_firewall_settings *settings,
    const QString &name)
{
	if (name == QLatin1String("input")) {
		return &settings->input;
	}
	if (name == QLatin1String("forward")) {
		return &settings->forward;
	}
	if (name == QLatin1String("output")) {
		return &settings->output;
	}
	return nullptr;
}

QString ncfg_firewall_block(const ncfg_firewall_settings &settings)
{
	QStringList body;
	const ncfg_firewall_chain_row *chains[] = { &settings.input, &settings.forward,
		&settings.output };

	body << QStringLiteral("firewall {");
	for (int c = 0; c < 3; c++) {
		/* **The policy is always written**: the compiler refuses a chain
		 * without one, and a block with no policy for a chain nobody set
		 * up would be refused rather than mean "accept". */
		const QString policy =
		    chains[c]->policy.isEmpty() ? QStringLiteral("accept") : chains[c]->policy;
		body << QStringLiteral("\t%1 {").arg(QString::fromLatin1(chain_names[c]));
		body << QStringLiteral("\t\tpolicy = %1").arg(quoted(policy));
		for (const ncfg_firewall_rule_row &rule : chains[c]->rules) {
			write_rule(body, rule);
		}
		body << QStringLiteral("\t}");
	}
	body << QStringLiteral("}");
	return body.join(QLatin1Char('\n')) + QLatin1Char('\n');
}

bool ncfg_firewall_write(ncfg_connection *connection, const ncfg_firewall_settings &settings,
    QString *error)
{
	return connection->config_put(QString::fromLatin1(ncfg_firewall_drop_in),
	    ncfg_firewall_block(settings), true, error);
}

ncfg_firewall_rule_dialog::ncfg_firewall_rule_dialog(ncfg_connection *connection,
    const ncfg_firewall_settings &settings, const QString &chain_name, int index,
    QWidget *parent)
    : QDialog(parent), connection(connection), settings(settings),
      original_chain(chain_name), index(index)
{
	setWindowTitle(index < 0 ? QStringLiteral("New firewall rule")
	                         : QStringLiteral("Firewall rule"));
	auto *layout = new QVBoxLayout(this);
	auto *form = new QFormLayout();

	chain = new QComboBox(this);
	chain->setObjectName(QStringLiteral("firewall_chain"));
	chain->addItem(QStringLiteral("input -- traffic to this machine"),
	    QStringLiteral("input"));
	chain->addItem(QStringLiteral("forward -- traffic through it"), QStringLiteral("forward"));
	chain->addItem(QStringLiteral("output -- traffic from it"), QStringLiteral("output"));
	form->addRow(QStringLiteral("chain"), chain);

	name = new QLineEdit(this);
	name->setObjectName(QStringLiteral("firewall_name"));
	name->setPlaceholderText(QStringLiteral("ssh -- what a refusal names it by"));
	form->addRow(QStringLiteral("name"), name);

	action = new QComboBox(this);
	action->setObjectName(QStringLiteral("firewall_action"));
	for (const char *word : action_words) {
		action->addItem(QString::fromLatin1(word), QString::fromLatin1(word));
	}
	action->setToolTip(QStringLiteral(
	    "reject answers the sender that the packet was refused; drop says nothing."));
	form->addRow(QStringLiteral("action"), action);

	protocol = new QComboBox(this);
	protocol->setObjectName(QStringLiteral("firewall_protocol"));
	for (const char *word : protocol_words) {
		protocol->addItem(QString::fromLatin1(word), QString::fromLatin1(word));
	}
	form->addRow(QStringLiteral("protocol"), protocol);

	ports = new QLineEdit(this);
	ports->setObjectName(QStringLiteral("firewall_ports"));
	ports->setPlaceholderText(QStringLiteral("22, 80 -- blank for every port"));
	form->addRow(QStringLiteral("destination ports"), ports);

	from = new QLineEdit(this);
	from->setObjectName(QStringLiteral("firewall_from"));
	from->setPlaceholderText(QStringLiteral("10.0.0.0/8, fd00::/8 -- blank for anywhere"));
	form->addRow(QStringLiteral("from"), from);

	to = new QLineEdit(this);
	to->setObjectName(QStringLiteral("firewall_to"));
	to->setPlaceholderText(QStringLiteral("blank for any destination"));
	form->addRow(QStringLiteral("to"), to);

	interface = new QLineEdit(this);
	interface->setObjectName(QStringLiteral("firewall_interface"));
	interface->setPlaceholderText(QStringLiteral("blank for any"));
	interface->setToolTip(QStringLiteral(
	    "The interface a packet arrives on; in the output chain, the one it leaves by."));
	form->addRow(QStringLiteral("interface"), interface);

	/* 0302: forward chain only, where `interface` is where a packet arrived. */
	out_interface = new QLineEdit(this);
	out_interface->setObjectName(QStringLiteral("firewall_out_interface"));
	out_interface->setPlaceholderText(QStringLiteral("blank for any"));
	out_interface->setToolTip(QStringLiteral(
	    "The interface a forwarded packet leaves by: a guest network kept off the LAN "
	    "is this set to the LAN."));
	form->addRow(QStringLiteral("leaving by"), out_interface);

	auto *states = new QWidget(this);
	auto *states_row = new QHBoxLayout(states);
	states_row->setContentsMargins(0, 0, 0, 0);
	state_new = new QCheckBox(QStringLiteral("new"), states);
	state_established = new QCheckBox(QStringLiteral("established"), states);
	state_related = new QCheckBox(QStringLiteral("related"), states);
	state_invalid = new QCheckBox(QStringLiteral("invalid"), states);
	state_new->setObjectName(QStringLiteral("firewall_state_new"));
	state_established->setObjectName(QStringLiteral("firewall_state_established"));
	state_related->setObjectName(QStringLiteral("firewall_state_related"));
	state_invalid->setObjectName(QStringLiteral("firewall_state_invalid"));
	for (QCheckBox *box : { state_new, state_established, state_related, state_invalid }) {
		states_row->addWidget(box);
	}
	states_row->addStretch();
	states->setToolTip(QStringLiteral(
	    "None ticked matches every state. established and related together are the "
	    "replies to what this machine sent, which a chain that drops needs."));
	form->addRow(QStringLiteral("connection state"), states);

	stations = new QLineEdit(this);
	stations->setObjectName(QStringLiteral("firewall_stations"));
	stations->setPlaceholderText(
	    QStringLiteral("aa:bb:cc:dd:ee:ff, aa:bb:cc:*, @host_list:kids -- blank for any"));
	stations->setToolTip(QStringLiteral("The sending station's hardware address."));
	form->addRow(QStringLiteral("from stations"), stations);
	layout->addLayout(form);

	note = new QLabel(this);
	note->setObjectName(QStringLiteral("firewall_note"));
	note->setWordWrap(true);
	note->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(note);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
	save_button = buttons->addButton(QStringLiteral("Save"), QDialogButtonBox::AcceptRole);
	save_button->setObjectName(QStringLiteral("firewall_save"));
	if (index >= 0) {
		QPushButton *remove_button = buttons->addButton(QStringLiteral("delete"),
		    QDialogButtonBox::DestructiveRole);
		remove_button->setObjectName(QStringLiteral("firewall_remove"));
		connect(remove_button, &QPushButton::clicked, this,
		    &ncfg_firewall_rule_dialog::remove);
	}
	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(save_button, &QPushButton::clicked, this, &ncfg_firewall_rule_dialog::submit);
	layout->addWidget(buttons);
	resize(560, 480);

	chain->setCurrentIndex(chain->findData(chain_name));
	const ncfg_firewall_chain_row *existing = ncfg_firewall_chain(&this->settings, chain_name);
	if (existing && index >= 0 && index < existing->rules.size()) {
		const ncfg_firewall_rule_row &rule = existing->rules.at(index);
		QStringList numbers;
		for (int port : rule.ports) {
			numbers << QString::number(port);
		}
		name->setText(rule.name);
		action->setCurrentIndex(action->findData(rule.action));
		protocol->setCurrentIndex(protocol->findData(rule.protocol));
		ports->setText(numbers.join(QStringLiteral(", ")));
		from->setText(rule.from.join(QStringLiteral(", ")));
		to->setText(rule.to.join(QStringLiteral(", ")));
		interface->setText(rule.interface);
		out_interface->setText(rule.out_interface);
		state_new->setChecked(rule.states.contains(QStringLiteral("new")));
		state_established->setChecked(rule.states.contains(QStringLiteral("established")));
		state_related->setChecked(rule.states.contains(QStringLiteral("related")));
		state_invalid->setChecked(rule.states.contains(QStringLiteral("invalid")));
		stations->setText(rule.stations.join(QStringLiteral(", ")));
	}
	connect(chain, &QComboBox::currentIndexChanged, this,
	    &ncfg_firewall_rule_dialog::shape_changed);
	connect(protocol, &QComboBox::currentIndexChanged, this,
	    &ncfg_firewall_rule_dialog::shape_changed);
	shape_changed();
}

void ncfg_firewall_rule_dialog::shape_changed()
{
	/* Ports belong to a protocol that has them, and only a forwarded packet
	 * both arrives and leaves -- the compiler refuses either elsewhere, so
	 * the form does not offer them there. A value already typed is kept and
	 * refused on Save, rather than silently dropped by hiding it. */
	const QString chosen = protocol->currentData().toString();
	ports->setEnabled(chosen == QLatin1String("tcp") || chosen == QLatin1String("udp") ||
	                  !ports->text().trimmed().isEmpty());
	out_interface->setEnabled(chain->currentData().toString() == QLatin1String("forward") ||
	                          !out_interface->text().trimmed().isEmpty());
}

bool ncfg_firewall_rule_dialog::read_rule(ncfg_firewall_rule_row *rule)
{
	const QLineEdit *values[] = { name, ports, from, to, interface, out_interface, stations };
	for (const QLineEdit *value : values) {
		if (!safe_value(value->text())) {
			note->setText(QStringLiteral("a value cannot carry a quote, a backslash or a "
			              "newline"));
			return false;
		}
	}
	rule->name = name->text().trimmed();
	if (rule->name.isEmpty()) {
		note->setText(QStringLiteral("a rule needs a name: it is its identity in the chain, "
		              "and what a refusal names"));
		return false;
	}
	rule->action = action->currentData().toString();
	rule->protocol = protocol->currentData().toString();
	for (const QString &text : split_list(ports->text())) {
		bool      number = false;
		const int port = text.toInt(&number);
		if (!number || port < 1 || port > 65535) {
			note->setText(QStringLiteral("`%1` is not a port: 1 to 65535").arg(text));
			return false;
		}
		rule->ports << port;
	}
	if (!rule->ports.isEmpty() && rule->protocol != QLatin1String("tcp") &&
	    rule->protocol != QLatin1String("udp")) {
		note->setText(QStringLiteral("only tcp and udp have ports: choose one, or clear the "
		              "ports"));
		return false;
	}
	rule->from = split_list(from->text());
	rule->to = split_list(to->text());
	rule->interface = interface->text().trimmed();
	rule->out_interface = out_interface->text().trimmed();
	if (!rule->out_interface.isEmpty() &&
	    chain->currentData().toString() != QLatin1String("forward")) {
		note->setText(QStringLiteral("only a forwarded packet leaves by another interface: "
		              "in input nothing leaves, and in output `interface` already is the "
		              "one it leaves by"));
		return false;
	}
	const struct {
		QCheckBox  *box;
		const char *word;
	} state_boxes[] = {
		{ state_new, "new" },
		{ state_established, "established" },
		{ state_related, "related" },
		{ state_invalid, "invalid" },
	};
	for (const auto &one : state_boxes) {
		if (one.box->isChecked()) {
			rule->states << QString::fromLatin1(one.word);
		}
	}
	rule->stations = split_list(stations->text());
	return true;
}

void ncfg_firewall_rule_dialog::submit()
{
	ncfg_firewall_rule_row rule;
	if (!read_rule(&rule)) {
		return;
	}

	ncfg_firewall_settings   changed = settings;
	const QString            target_name = chain->currentData().toString();
	ncfg_firewall_chain_row *source = ncfg_firewall_chain(&changed, original_chain);
	ncfg_firewall_chain_row *target = ncfg_firewall_chain(&changed, target_name);
	if (!source || !target) {
		return;
	}
	int at = -1;
	if (index >= 0 && index < source->rules.size()) {
		source->rules.removeAt(index);
		/* Kept in its place when it stays in its chain: the order is what
		 * the chain does, and an edit to a match should not move it. */
		if (source == target) {
			at = index;
		}
	}
	for (const ncfg_firewall_rule_row &other : target->rules) {
		if (other.name == rule.name) {
			note->setText(QStringLiteral("%1 already has a rule named `%2`: a name is a "
			              "rule's identity in its chain").arg(target_name, rule.name));
			return;
		}
	}
	if (at < 0) {
		target->rules << rule;
	} else {
		target->rules.insert(at, rule);
	}

	QString error;
	if (!ncfg_firewall_write(connection, changed, &error)) {
		note->setText(error);
		return;
	}
	summary = QStringLiteral("wrote %1: rule %2/%3. Run apply to make the machine match it.")
	              .arg(QString::fromLatin1(ncfg_firewall_drop_in), target_name, rule.name);
	accept();
}

void ncfg_firewall_rule_dialog::remove()
{
	ncfg_firewall_settings   changed = settings;
	ncfg_firewall_chain_row *source = ncfg_firewall_chain(&changed, original_chain);
	if (!source || index < 0 || index >= source->rules.size()) {
		return;
	}
	const QString rule_name = source->rules.at(index).name;
	const QString question =
	    QStringLiteral("Delete the firewall rule `%1/%2`?\n\nWhat it matched falls through to "
	                   "the rules below it, and then to the chain's policy.")
	        .arg(original_chain, rule_name);
	QMessageBox box(QMessageBox::Question, QStringLiteral("netcfgd"), question,
	    QMessageBox::Cancel | QMessageBox::Yes, this);
	box.setDefaultButton(QMessageBox::Cancel);
	if (box.exec() != QMessageBox::Yes) {
		return;
	}
	source->rules.removeAt(index);

	QString error;
	if (!ncfg_firewall_write(connection, changed, &error)) {
		note->setText(error);
		return;
	}
	summary = QStringLiteral("wrote %1: removed rule %2/%3. Run apply to make the machine "
	              "match it.")
	              .arg(QString::fromLatin1(ncfg_firewall_drop_in), original_chain, rule_name);
	accept();
}
