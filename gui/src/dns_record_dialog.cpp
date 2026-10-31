/*
 * dns_record_dialog.cpp -- the editor described in dns_record_dialog.h.
 */
#include "dns_record_dialog.h"

#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

namespace {

bool safe_value(const QString &text)
{
	return !text.contains(QLatin1Char('"')) && !text.contains(QLatin1Char('\\')) &&
	       !text.contains(QLatin1Char('\n'));
}

QString quoted_list(const QString &words)
{
	QStringList quoted;
	for (const QString &one : words.split(QLatin1Char(' '), Qt::SkipEmptyParts)) {
		quoted << QStringLiteral("\"%1\"").arg(one);
	}
	return QStringLiteral("[%1]").arg(quoted.join(QStringLiteral(", ")));
}

/* A number field where the lowest value says "unset". */
QSpinBox *number(QWidget *parent, const char *object, int low, const char *unset)
{
	auto *box = new QSpinBox(parent);
	box->setObjectName(QString::fromLatin1(object));
	box->setRange(low, 65535);
	box->setSpecialValueText(QString::fromLatin1(unset));
	box->setValue(low);
	return box;
}

} // namespace

QString ncfg_dns_record_block(const ncfg_dns_record_row &record)
{
	QStringList body;
	body << QStringLiteral("dns_record \"%1\" {").arg(record.name);
	if (!record.address.trimmed().isEmpty()) {
		body << QStringLiteral("\taddress = %1").arg(quoted_list(record.address));
	}
	const struct {
		const char *key;
		QString     value;
	} texts[] = {
		{ "cname", record.cname },
		{ "mx", record.mx },
		{ "txt", record.txt },
		{ "srv", record.srv },
	};
	for (const auto &one : texts) {
		if (!one.value.isEmpty()) {
			body << QStringLiteral("\t%1 = \"%2\"").arg(QString::fromLatin1(one.key), one.value);
		}
	}
	const struct {
		const char *key;
		int         value;
	} numbers[] = {
		{ "preference", record.preference },
		{ "port", record.port },
		{ "priority", record.priority },
		{ "weight", record.weight },
	};
	for (const auto &one : numbers) {
		if (one.value >= 0) {
			body << QStringLiteral("\t%1 = %2").arg(QString::fromLatin1(one.key)).arg(one.value);
		}
	}
	if (!record.forward.trimmed().isEmpty()) {
		body << QStringLiteral("\tforward = %1").arg(quoted_list(record.forward));
	}
	body << QStringLiteral("}");
	return body.join(QLatin1Char('\n')) + QLatin1Char('\n');
}

ncfg_dns_record_dialog::ncfg_dns_record_dialog(ncfg_connection *connection,
    const ncfg_dns_record_row &existing, QWidget *parent)
    : QDialog(parent), connection(connection), before(existing.name)
{
	setWindowTitle(before.isEmpty() ? QStringLiteral("New DNS record")
	                                : QStringLiteral("DNS record %1").arg(before));
	auto *layout = new QVBoxLayout(this);
	auto *form = new QFormLayout();

	const auto text = [this, form](QLineEdit **field, const char *object, const char *label,
	                      const QString &value, const char *placeholder) {
		*field = new QLineEdit(value, this);
		(*field)->setObjectName(QString::fromLatin1(object));
		(*field)->setPlaceholderText(QString::fromLatin1(placeholder));
		form->addRow(QString::fromLatin1(label), *field);
	};
	text(&name, "record_name", "name", existing.name, "nas.home.lan");
	name->setReadOnly(!before.isEmpty());
	text(&address, "record_address", "addresses", existing.address,
	    "IPv4 and IPv6 addresses, separated by spaces");
	text(&cname, "record_cname", "alias for", existing.cname,
	    "another name -- on its own, as DNS requires");
	text(&mx, "record_mx", "mail server", existing.mx, "mail.home.lan");
	preference = number(this, "record_preference", -1, "default (10)");
	preference->setValue(existing.preference);
	form->addRow(QStringLiteral("mail preference"), preference);
	text(&txt, "record_txt", "text", existing.txt, "v=spf1 -all");
	text(&srv, "record_srv", "service host", existing.srv,
	    "pbx.home.lan -- for a name like _sip._udp.home.lan");
	port = number(this, "record_port", -1, "none");
	port->setValue(existing.port);
	form->addRow(QStringLiteral("service port"), port);
	priority = number(this, "record_priority", -1, "default (0)");
	priority->setValue(existing.priority);
	form->addRow(QStringLiteral("service priority"), priority);
	weight = number(this, "record_weight", -1, "default (0)");
	weight->setValue(existing.weight);
	form->addRow(QStringLiteral("service weight"), weight);
	text(&forward, "record_forward", "forward to", existing.forward,
	    "DNS servers to ask for this domain instead -- on its own");
	layout->addLayout(form);

	note = new QLabel(this);
	note->setObjectName(QStringLiteral("record_note"));
	note->setWordWrap(true);
	note->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(note);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
	QPushButton *save = buttons->addButton(QStringLiteral("Save"), QDialogButtonBox::AcceptRole);
	save->setObjectName(QStringLiteral("record_save"));
	if (!before.isEmpty()) {
		QPushButton *drop = buttons->addButton(QStringLiteral("delete"),
		    QDialogButtonBox::DestructiveRole);
		drop->setObjectName(QStringLiteral("record_remove"));
		connect(drop, &QPushButton::clicked, this, &ncfg_dns_record_dialog::remove);
	}
	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(save, &QPushButton::clicked, this, &ncfg_dns_record_dialog::submit);
	layout->addWidget(buttons);
	resize(520, 480);
}

void ncfg_dns_record_dialog::submit()
{
	for (const QLineEdit *value : { name, address, cname, mx, txt, srv, forward }) {
		if (!safe_value(value->text())) {
			note->setText(QStringLiteral("a value cannot carry a quote, a backslash or a "
			              "newline"));
			return;
		}
	}
	ncfg_dns_record_row record;
	record.name = name->text().trimmed();
	record.address = address->text().trimmed();
	record.cname = cname->text().trimmed();
	record.mx = mx->text().trimmed();
	record.preference = preference->value();
	record.txt = txt->text();
	record.srv = srv->text().trimmed();
	record.port = port->value();
	record.priority = priority->value();
	record.weight = weight->value();
	record.forward = forward->text().trimmed();
	if (record.name.isEmpty() || record.name.contains(QLatin1Char(' '))) {
		note->setText(QStringLiteral("a record needs a name, such as nas.home.lan"));
		return;
	}

	/* The compiler says the rest -- a cname beside an address, an srv with no
	 * port -- in its own words, which the refusal carries. */
	QString error;
	if (!connection->config_put(QStringLiteral("dns_record-%1").arg(record.name),
	        ncfg_dns_record_block(record), true, &error)) {
		note->setText(error);
		return;
	}
	summary = QStringLiteral("wrote dns_record-%1: netcfgd re-read its configuration. Run "
	              "apply to make the machine match it.")
	              .arg(record.name);
	accept();
}

void ncfg_dns_record_dialog::remove()
{
	QMessageBox box(QMessageBox::Question, QStringLiteral("netcfgd"),
	    QStringLiteral("Delete the DNS record `%1`?\n\nThe LAN stops resolving it on the next "
	                   "apply.").arg(before),
	    QMessageBox::Cancel | QMessageBox::Yes, this);
	box.setDefaultButton(QMessageBox::Cancel);
	if (box.exec() != QMessageBox::Yes) {
		return;
	}
	QString error;
	if (!connection->config_delete(QStringLiteral("dns_record-%1").arg(before), &error)) {
		note->setText(error);
		return;
	}
	summary = QStringLiteral("removed dns_record-%1: netcfgd re-read its configuration.")
	              .arg(before);
	accept();
}
