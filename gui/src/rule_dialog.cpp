/*
 * rule_dialog.cpp -- the editor described in rule_dialog.h.
 */
#include "rule_dialog.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

namespace {

struct choice {
	const char *shown;
	const char *key;
};

/* What happens when the rule matches. `lookup` consults a table; the other
 * three stop there, which is how a rule refuses traffic rather than routing it.
 *
 * Named `verbs` rather than `actions`: `QWidget::actions()` is a member
 * function, and a file-scope array by that name is shadowed by it inside a
 * widget's own methods -- which the compiler reports as a subscript on an
 * overloaded function type, forty lines from the name that clashed. */
const choice verbs[] = {
	{ "look up a table", "lookup" },
	{ "blackhole -- drop it silently", "blackhole" },
	{ "unreachable -- drop it and say so", "unreachable" },
	{ "prohibit -- refuse it administratively", "prohibit" },
};

/* Explicit rather than inferred from the selectors, because a rule with no
 * address selector at all -- `from all fwmark 0x1 lookup 100`, the common
 * shape -- gives nothing to infer from, and guessing would install it in one
 * family only. */
const choice families[] = {
	{ "IPv4", "inet" },
	{ "IPv6", "inet6" },
};

void fill(QComboBox *box, const choice *from, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		box->addItem(QString::fromLatin1(from[i].shown), QString::fromLatin1(from[i].key));
	}
}

void select(QComboBox *box, const QString &key)
{
	const int at = box->findData(key);
	if (at >= 0) {
		box->setCurrentIndex(at);
	}
}

bool safe_value(const QString &text)
{
	return !text.contains(QLatin1Char('"')) && !text.contains(QLatin1Char('\\')) &&
	       !text.contains(QLatin1Char('\n'));
}

} // namespace

QString ncfg_rule_block(const ncfg_rule_row &settings)
{
	QStringList body;

	body << QStringLiteral("\tpriority = %1").arg(settings.priority);
	/* Written both ways rather than only for IPv6: a rule's family is not
	 * inferable from its selectors, and a block that said nothing would be
	 * IPv4 by default -- which is a choice, and one the operator made in the
	 * form rather than by omission. */
	body << QStringLiteral("\tfamily = \"%1\"").arg(settings.family);

	const struct {
		const char *key;
		QString     value;
	} selectors[] = {
		{ "from", settings.from },
		{ "to", settings.to },
		{ "iif", settings.iif },
		{ "oif", settings.oif },
	};
	for (const auto &one : selectors) {
		if (!one.value.isEmpty()) {
			body << QStringLiteral("\t%1 = \"%2\"")
			        .arg(QString::fromLatin1(one.key), one.value);
		}
	}
	/* **Zero is a mark and `none` is not zero**, which is why the absent value
	 * is -1. A rule matching `fwmark 0` is unusual and legal, and a form that
	 * could not write it would silently widen the rule to match everything. */
	if (settings.fwmark >= 0) {
		body << QStringLiteral("\tfwmark = %1").arg(settings.fwmark);
	}
	if (settings.fwmask >= 0) {
		body << QStringLiteral("\tfwmask = %1").arg(settings.fwmask);
	}
	if (settings.l3mdev) {
		body << QStringLiteral("\tl3mdev = true");
	}
	/* The same rule as the mark: `suppress_prefixlength = 0` is the one that
	 * drops a table's default route so a more specific rule below can catch
	 * it, and it is the commonest use of the key. */
	if (settings.suppress_prefixlength >= 0) {
		body << QStringLiteral("\tsuppress_prefixlength = %1")
		        .arg(settings.suppress_prefixlength);
	}

	if (settings.action == QLatin1String("lookup")) {
		body << QStringLiteral("\tlookup = %1").arg(settings.table);
	} else {
		body << QStringLiteral("\taction = \"%1\"").arg(settings.action);
	}

	QStringList block;
	block << QStringLiteral("# Written by netcfgd's gui. Ordinary netcfgd configuration:");
	block << QStringLiteral("# edit it, diff it, commit it, or delete it.");
	block << QString();
	block << QStringLiteral("rule \"%1\" {").arg(settings.id);
	block << body;
	block << QStringLiteral("}");
	return block.join(QStringLiteral("\n")) + QStringLiteral("\n");
}

ncfg_rule_dialog::ncfg_rule_dialog(ncfg_connection *connection, const ncfg_rule_row &existing,
    QWidget *parent)
    : QDialog(parent), connection(connection), before(existing), editing(!existing.id.isEmpty())
{
	setWindowTitle(editing ? QStringLiteral("rule: %1").arg(existing.id)
	                       : QStringLiteral("new routing rule"));
	setObjectName(QStringLiteral("rule_dialog"));

	auto *layout = new QVBoxLayout(this);
	auto *form = new QFormLayout();

	id = new QLineEdit(existing.id, this);
	id->setObjectName(QStringLiteral("rule_id"));
	id->setReadOnly(editing);
	id->setPlaceholderText(QStringLiteral("a name for this rule -- vpn, guest, mgmt"));
	form->addRow(QStringLiteral("name"), id);

	priority = new QSpinBox(this);
	priority->setObjectName(QStringLiteral("rule_priority"));
	priority->setRange(0, 32766);
	priority->setValue(existing.id.isEmpty() ? 1000 : existing.priority);
	priority->setToolTip(QStringLiteral(
	    "The kernel consults a lower number first. This is the rule's identity to "
	    "the kernel, which is why it is asked for rather than invented."));
	form->addRow(QStringLiteral("priority (lower first)"), priority);

	family = new QComboBox(this);
	family->setObjectName(QStringLiteral("rule_family"));
	fill(family, families, sizeof(families) / sizeof(families[0]));
	form->addRow(QStringLiteral("family"), family);

	from = new QLineEdit(this);
	from->setObjectName(QStringLiteral("rule_from"));
	from->setPlaceholderText(QStringLiteral("10.9.0.0/24 -- blank matches any source"));
	form->addRow(QStringLiteral("from"), from);

	to = new QLineEdit(this);
	to->setObjectName(QStringLiteral("rule_to"));
	to->setPlaceholderText(QStringLiteral("blank matches any destination"));
	form->addRow(QStringLiteral("to"), to);

	iif = new QLineEdit(this);
	iif->setObjectName(QStringLiteral("rule_iif"));
	iif->setPlaceholderText(QStringLiteral("the interface it arrived on"));
	form->addRow(QStringLiteral("incoming interface"), iif);

	oif = new QLineEdit(this);
	oif->setObjectName(QStringLiteral("rule_oif"));
	oif->setPlaceholderText(QStringLiteral("the interface it is bound to"));
	form->addRow(QStringLiteral("outgoing interface"), oif);

	fwmark = new QSpinBox(this);
	fwmark->setObjectName(QStringLiteral("rule_fwmark"));
	/* -1 is "no mark" and 0 is a mark, which is why the range starts below
	 * zero and the special text sits on -1 rather than on 0. */
	fwmark->setRange(-1, 2147483647);
	fwmark->setValue(-1);
	fwmark->setSpecialValueText(QStringLiteral("any"));
	form->addRow(QStringLiteral("firewall mark"), fwmark);

	fwmask = new QSpinBox(this);
	fwmask->setObjectName(QStringLiteral("rule_fwmask"));
	fwmask->setRange(-1, 2147483647);
	fwmask->setValue(-1);
	fwmask->setSpecialValueText(QStringLiteral("all bits"));
	form->addRow(QStringLiteral("mark mask"), fwmask);

	l3mdev = new QCheckBox(QStringLiteral("packets belonging to a VRF master"), this);
	l3mdev->setObjectName(QStringLiteral("rule_l3mdev"));
	form->addRow(QString(), l3mdev);

	action = new QComboBox(this);
	action->setObjectName(QStringLiteral("rule_action"));
	fill(action, verbs, sizeof(verbs) / sizeof(verbs[0]));
	form->addRow(QStringLiteral("then"), action);

	table = new QSpinBox(this);
	table->setObjectName(QStringLiteral("rule_table"));
	table->setRange(0, 4294967);
	table->setValue(100);
	form->addRow(QStringLiteral("table"), table);

	suppress_prefixlength = new QSpinBox(this);
	suppress_prefixlength->setObjectName(QStringLiteral("rule_suppress"));
	suppress_prefixlength->setRange(-1, 128);
	suppress_prefixlength->setValue(-1);
	suppress_prefixlength->setSpecialValueText(QStringLiteral("off"));
	suppress_prefixlength->setToolTip(QStringLiteral(
	    "Ignore routes in that table shorter than this. `0` ignores its default "
	    "route, so a more specific rule below can catch the traffic."));
	form->addRow(QStringLiteral("suppress prefixes shorter than"), suppress_prefixlength);
	layout->addLayout(form);

	note = new QLabel(this);
	note->setObjectName(QStringLiteral("rule_note"));
	note->setWordWrap(true);
	note->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(note);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
	save_button = buttons->addButton(QStringLiteral("Save"), QDialogButtonBox::AcceptRole);
	save_button->setObjectName(QStringLiteral("rule_save"));
	remove_button = nullptr;
	if (editing) {
		remove_button = buttons->addButton(QStringLiteral("delete"),
		    QDialogButtonBox::DestructiveRole);
		remove_button->setObjectName(QStringLiteral("rule_remove"));
		connect(remove_button, &QPushButton::clicked, this, &ncfg_rule_dialog::remove);
	}
	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(save_button, &QPushButton::clicked, this, &ncfg_rule_dialog::submit);
	connect(action, &QComboBox::currentIndexChanged, this, &ncfg_rule_dialog::action_changed);
	layout->addWidget(buttons);
	resize(560, 480);

	if (editing) {
		select(family, existing.family);
		from->setText(existing.from);
		to->setText(existing.to);
		iif->setText(existing.iif);
		oif->setText(existing.oif);
		fwmark->setValue(existing.fwmark);
		fwmask->setValue(existing.fwmask);
		l3mdev->setChecked(existing.l3mdev);
		select(action, existing.action);
		table->setValue(existing.table.toInt());
		suppress_prefixlength->setValue(existing.suppress_prefixlength);
	}
	action_changed();
}

void ncfg_rule_dialog::action_changed()
{
	/* The table and the suppression belong to a lookup: the other three
	 * actions stop at the rule and consult nothing. */
	const bool looks_up = action->currentData().toString() == QLatin1String("lookup");
	auto *form = qobject_cast<QFormLayout *>(layout()->itemAt(0)->layout());
	if (form) {
		form->setRowVisible(table, looks_up);
		form->setRowVisible(suppress_prefixlength, looks_up);
	}
}

QString ncfg_rule_dialog::block_text() const
{
	ncfg_rule_row settings;
	settings.id = id->text().trimmed();
	settings.priority = priority->value();
	settings.family = family->currentData().toString();
	settings.from = from->text().trimmed();
	settings.to = to->text().trimmed();
	settings.iif = iif->text().trimmed();
	settings.oif = oif->text().trimmed();
	settings.fwmark = fwmark->value();
	settings.fwmask = fwmask->value();
	settings.l3mdev = l3mdev->isChecked();
	settings.action = action->currentData().toString();
	settings.table = QString::number(table->value());
	settings.suppress_prefixlength =
	    action->currentData().toString() == QLatin1String("lookup")
	    ? suppress_prefixlength->value()
	    : -1;
	return ncfg_rule_block(settings);
}

void ncfg_rule_dialog::submit()
{
	const QLineEdit *values[] = { id, from, to, iif, oif };
	for (const QLineEdit *value : values) {
		if (!safe_value(value->text())) {
			note->setText(QStringLiteral("a value cannot carry a quote, a backslash "
			              "or a newline"));
			return;
		}
	}
	if (id->text().trimmed().isEmpty()) {
		note->setText(QStringLiteral("a rule needs a name: it is how netcfgd files it "
		              "and how you find it again"));
		return;
	}
	/* **A mask with no mark matches nothing anybody meant.** The kernel takes
	 * it and the compiler takes it; what it produces is a rule masking a mark
	 * that was never selected on, which is a rule that does not fire. */
	if (fwmask->value() >= 0 && fwmark->value() < 0) {
		note->setText(QStringLiteral("a mark mask needs a mark to mask: set the firewall "
		              "mark, or leave both alone"));
		return;
	}

	QString error;
	const QString name = id->text().trimmed();
	if (!connection->config_put(QStringLiteral("rule-%1").arg(name), block_text(), true,
	        &error)) {
		note->setText(error);
		return;
	}
	summary = QStringLiteral("wrote rule-%1: netcfgd re-read its configuration. Run apply "
	              "to make the machine match it.")
	          .arg(name);
	accept();
}

void ncfg_rule_dialog::remove()
{
	const QString question =
	    QStringLiteral("Delete the rule `%1`?\n\nThe routes it sends traffic to stay where "
	               "they are; what goes is the rule that sent it there.")
	        .arg(before.id);
	QMessageBox box(QMessageBox::Question, QStringLiteral("netcfgd"), question,
	    QMessageBox::Cancel | QMessageBox::Yes, this);
	box.setDefaultButton(QMessageBox::Cancel);
	if (box.exec() != QMessageBox::Yes) {
		return;
	}

	QString error;
	if (!connection->config_delete(QStringLiteral("rule-%1").arg(before.id), &error)) {
		note->setText(error);
		return;
	}
	summary = QStringLiteral("removed rule-%1: netcfgd re-read its configuration. Run "
	              "apply to make the machine match it.")
	          .arg(before.id);
	accept();
}
