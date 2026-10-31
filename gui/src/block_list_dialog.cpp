/*
 * block_list_dialog.cpp -- the editor described in block_list_dialog.h.
 */
#include "block_list_dialog.h"

#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
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

} // namespace

QString ncfg_block_list_block(const ncfg_block_list_row &list)
{
	QStringList body;
	body << QStringLiteral("block_list \"%1\" {").arg(list.name);
	const struct {
		const char *key;
		QString     value;
	} lists[] = {
		{ "file", list.file },
		{ "url", list.url },
		{ "domain", list.domain },
		{ "allow", list.allow },
	};
	for (const auto &one : lists) {
		if (!one.value.trimmed().isEmpty()) {
			body << QStringLiteral("\t%1 = %2").arg(QString::fromLatin1(one.key),
			    quoted_list(one.value));
		}
	}
	body << QStringLiteral("}");
	return body.join(QLatin1Char('\n')) + QLatin1Char('\n');
}

ncfg_block_list_dialog::ncfg_block_list_dialog(ncfg_connection *connection,
    const ncfg_block_list_row &existing, QWidget *parent)
    : QDialog(parent), connection(connection), before(existing.name)
{
	setWindowTitle(before.isEmpty() ? QStringLiteral("New block list")
	                                : QStringLiteral("Block list %1").arg(before));
	auto *layout = new QVBoxLayout(this);
	auto *form = new QFormLayout();

	const auto text = [this, form](QLineEdit **field, const char *object, const char *label,
	                      const QString &value, const char *placeholder) {
		*field = new QLineEdit(value, this);
		(*field)->setObjectName(QString::fromLatin1(object));
		(*field)->setPlaceholderText(QString::fromLatin1(placeholder));
		form->addRow(QString::fromLatin1(label), *field);
	};
	text(&name, "block_list_name", "name", existing.name, "ads");
	name->setReadOnly(!before.isEmpty());
	text(&file, "block_list_file", "files", existing.file,
	    "/var/lib/netcfgd/block/ads.txt -- hosts, plain or adblock lists, by spaces");
	text(&url, "block_list_url", "fetched from", existing.url,
	    "https://... -- one for each file, in order; `ncfg block fetch` downloads them");
	text(&domain, "block_list_domain", "names", existing.domain,
	    "doubleclick.net -- each blocked with everything under it");
	text(&allow, "block_list_allow", "allow", existing.allow,
	    "names to resolve anyway, separated by spaces");
	layout->addLayout(form);

	note = new QLabel(this);
	note->setObjectName(QStringLiteral("block_list_note"));
	note->setWordWrap(true);
	note->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(note);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
	QPushButton *save = buttons->addButton(QStringLiteral("Save"), QDialogButtonBox::AcceptRole);
	save->setObjectName(QStringLiteral("block_list_save"));
	if (!before.isEmpty()) {
		QPushButton *drop = buttons->addButton(QStringLiteral("delete"),
		    QDialogButtonBox::DestructiveRole);
		drop->setObjectName(QStringLiteral("block_list_remove"));
		connect(drop, &QPushButton::clicked, this, &ncfg_block_list_dialog::remove);
	}
	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(save, &QPushButton::clicked, this, &ncfg_block_list_dialog::submit);
	layout->addWidget(buttons);
	resize(560, 260);
}

void ncfg_block_list_dialog::submit()
{
	for (const QLineEdit *value : { name, file, url, domain, allow }) {
		if (!safe_value(value->text())) {
			note->setText(QStringLiteral("a value cannot carry a quote, a backslash or a "
			              "newline"));
			return;
		}
	}
	ncfg_block_list_row list;
	list.name = name->text().trimmed();
	list.file = file->text().trimmed();
	list.url = url->text().trimmed();
	list.domain = domain->text().trimmed();
	list.allow = allow->text().trimmed();
	if (list.name.isEmpty() || list.name.contains(QLatin1Char(' '))) {
		note->setText(QStringLiteral("a list needs a name, such as ads"));
		return;
	}

	/* The compiler says the rest -- a relative path, a name in capitals -- in
	 * its own words, which the refusal carries. */
	QString error;
	if (!connection->config_put(QStringLiteral("block_list-%1").arg(list.name),
	        ncfg_block_list_block(list), true, &error)) {
		note->setText(error);
		return;
	}
	summary = QStringLiteral("wrote block_list-%1: netcfgd re-read its configuration. Run "
	              "apply to make the machine match it.")
	              .arg(list.name);
	accept();
}

void ncfg_block_list_dialog::remove()
{
	QMessageBox box(QMessageBox::Question, QStringLiteral("netcfgd"),
	    QStringLiteral("Delete the block list `%1`?\n\nA DHCP server that still names it in "
	                   "`block` is refused until it no longer does.").arg(before),
	    QMessageBox::Cancel | QMessageBox::Yes, this);
	box.setDefaultButton(QMessageBox::Cancel);
	if (box.exec() != QMessageBox::Yes) {
		return;
	}
	QString error;
	if (!connection->config_delete(QStringLiteral("block_list-%1").arg(before), &error)) {
		note->setText(error);
		return;
	}
	summary = QStringLiteral("removed block_list-%1: netcfgd re-read its configuration.")
	              .arg(before);
	accept();
}
