/*
 * host_list_dialog.cpp -- the editor described in host_list_dialog.h.
 */
#include "host_list_dialog.h"

#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QVBoxLayout>

QString ncfg_host_list_block(const ncfg_host_list_row &list)
{
	QStringList quoted;
	for (const QString &one : list.mac) {
		quoted << QStringLiteral("\"%1\"").arg(one);
	}
	QString block = QStringLiteral("host_list \"%1\" {\n").arg(list.name);
	/* An empty list is written with no key rather than `mac = []`: both
	 * compile to nothing, and the shorter says so. */
	if (!quoted.isEmpty()) {
		block += QStringLiteral("\tmac = [%1]\n").arg(quoted.join(QStringLiteral(", ")));
	}
	return block + QStringLiteral("}\n");
}

ncfg_host_list_dialog::ncfg_host_list_dialog(ncfg_connection *connection,
    const ncfg_host_list_row &existing, QWidget *parent)
    : QDialog(parent), connection(connection), before(existing.name)
{
	setWindowTitle(before.isEmpty() ? QStringLiteral("New host list")
	                                : QStringLiteral("Host list %1").arg(before));
	auto *layout = new QVBoxLayout(this);
	auto *form = new QFormLayout();

	name = new QLineEdit(existing.name, this);
	name->setObjectName(QStringLiteral("host_list_name"));
	name->setPlaceholderText(QStringLiteral("family -- named as @host_list:family"));
	name->setReadOnly(!before.isEmpty());
	form->addRow(QStringLiteral("name"), name);

	members = new QPlainTextEdit(existing.mac.join(QLatin1Char('\n')), this);
	members->setObjectName(QStringLiteral("host_list_members"));
	members->setPlaceholderText(QStringLiteral(
	    "One station per line: 00:11:22:33:44:55, or aa:bb:cc:* for a manufacturer"));
	members->setToolTip(QStringLiteral(
	    "A manufacturer prefix is taken where the list is used to deny or in a firewall "
	    "rule; an access point's allow list needs exact addresses."));
	form->addRow(QStringLiteral("stations"), members);
	layout->addLayout(form);

	note = new QLabel(this);
	note->setObjectName(QStringLiteral("host_list_note"));
	note->setWordWrap(true);
	note->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(note);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
	QPushButton *save = buttons->addButton(QStringLiteral("Save"), QDialogButtonBox::AcceptRole);
	save->setObjectName(QStringLiteral("host_list_save"));
	if (!before.isEmpty()) {
		QPushButton *drop = buttons->addButton(QStringLiteral("delete"),
		    QDialogButtonBox::DestructiveRole);
		drop->setObjectName(QStringLiteral("host_list_remove"));
		connect(drop, &QPushButton::clicked, this, &ncfg_host_list_dialog::remove);
	}
	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(save, &QPushButton::clicked, this, &ncfg_host_list_dialog::submit);
	layout->addWidget(buttons);
	resize(480, 360);
}

void ncfg_host_list_dialog::submit()
{
	ncfg_host_list_row list;
	list.name = name->text().trimmed();
	list.mac = members->toPlainText().split(QRegularExpression(QStringLiteral("[,\\s]+")),
	    Qt::SkipEmptyParts);

	/* A name becomes a file name and a word other blocks quote, so it is
	 * held to the plain characters both can carry. */
	static const QRegularExpression plain(QStringLiteral("^[A-Za-z0-9_.-]+$"));
	if (!plain.match(list.name).hasMatch()) {
		note->setText(QStringLiteral("a list needs a name of letters, digits, `.`, `_` or "
		              "`-`: it is how other blocks name it"));
		return;
	}
	static const QRegularExpression station(QStringLiteral("^[0-9A-Fa-f:*]+$"));
	for (const QString &one : list.mac) {
		if (!station.match(one).hasMatch()) {
			note->setText(QStringLiteral("`%1` is not a station address").arg(one));
			return;
		}
	}

	QString error;
	if (!connection->config_put(QStringLiteral("host_list-%1").arg(list.name),
	        ncfg_host_list_block(list), true, &error)) {
		note->setText(error);
		return;
	}
	summary = QStringLiteral("wrote host_list-%1: netcfgd re-read its configuration. Run "
	              "apply to make the machine match it.")
	              .arg(list.name);
	accept();
}

void ncfg_host_list_dialog::remove()
{
	QMessageBox box(QMessageBox::Question, QStringLiteral("netcfgd"),
	    QStringLiteral("Delete the host list `%1`?\n\nAn access point or firewall rule that "
	                   "still names it keeps the configuration from compiling, so netcfgd "
	                   "refuses the delete until nothing does.")
	        .arg(before),
	    QMessageBox::Cancel | QMessageBox::Yes, this);
	box.setDefaultButton(QMessageBox::Cancel);
	if (box.exec() != QMessageBox::Yes) {
		return;
	}
	QString error;
	if (!connection->config_delete(QStringLiteral("host_list-%1").arg(before), &error)) {
		note->setText(error);
		return;
	}
	summary = QStringLiteral("removed host_list-%1: netcfgd re-read its configuration.")
	              .arg(before);
	accept();
}
