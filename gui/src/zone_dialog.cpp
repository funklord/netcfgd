/*
 * zone_dialog.cpp -- the editor described in zone_dialog.h.
 *
 * Saved as `conf.d/zone-NAME.conf` on this host. A zone is the estate's, so
 * the same drop-in belongs on every host -- `ncfg config put --at estate`
 * carries it there -- and this dialog says so rather than doing it, since a
 * change to every machine is the operator's to send.
 */
#include "zone_dialog.h"
#include "fixed_name.h"

#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QRegularExpression>
#include <QVBoxLayout>

QString ncfg_zone_block(const ncfg_zone_row &zone)
{
	QStringList quoted;
	for (const QString &one : zone.reach) {
		quoted << QStringLiteral("\"%1\"").arg(one);
	}
	QString block = QStringLiteral("zone \"%1\" {\n\treach = [%2]\n")
	                    .arg(zone.name, quoted.join(QStringLiteral(", ")));
	if (!zone.hosts.isEmpty()) {
		QStringList addresses;
		for (const QString &one : zone.hosts) {
			addresses << QStringLiteral("\"%1\"").arg(one);
		}
		block += QStringLiteral("\thosts = [%1]\n").arg(addresses.join(QStringLiteral(", ")));
	}
	if (!zone.client_limit.isEmpty()) {
		block += QStringLiteral("\tclient_limit = \"%1\"\n").arg(zone.client_limit);
	}
	return block + QStringLiteral("}\n");
}

ncfg_zone_dialog::ncfg_zone_dialog(ncfg_connection *connection, const ncfg_zone_row &existing,
    QWidget *parent)
    : QDialog(parent), connection(connection), before(existing.name)
{
	setWindowTitle(before.isEmpty() ? QStringLiteral("New zone")
	                                : QStringLiteral("Zone %1").arg(before));
	auto *layout = new QVBoxLayout(this);
	auto *form = new QFormLayout();

	name = new QLineEdit(existing.name, this);
	name->setObjectName(QStringLiteral("zone_name"));
	name->setPlaceholderText(QStringLiteral("guest -- a purpose, named the same on every host"));
	ncfg_fix_name(name, !before.isEmpty(), QStringLiteral("zone"));
	form->addRow(QStringLiteral("name"), name);

	reach = new QLineEdit(existing.reach.join(QStringLiteral(", ")), this);
	reach->setObjectName(QStringLiteral("zone_reach"));
	reach->setPlaceholderText(QStringLiteral("internet -- the zones its traffic may reach"));
	form->addRow(QStringLiteral("reaches"), reach);

	hosts = new QLineEdit(existing.hosts.join(QStringLiteral(", ")), this);
	hosts->setObjectName(QStringLiteral("zone_hosts"));
	hosts->setPlaceholderText(QStringLiteral("192.168.1.20 -- hosts in it by address, wherever they are"));
	form->addRow(QStringLiteral("hosts"), hosts);

	client_limit = new QLineEdit(existing.client_limit, this);
	client_limit->setObjectName(QStringLiteral("zone_client_limit"));
	client_limit->setPlaceholderText(QStringLiteral("5mbit -- each client, each way; empty for none"));
	form->addRow(QStringLiteral("each client"), client_limit);
	layout->addLayout(form);

	note = new QLabel(QStringLiteral(
	                      "Saved on this host. A zone is the estate's: put the same drop-in "
	                      "on every host with `ncfg config put --at estate`."),
	    this);
	note->setObjectName(QStringLiteral("zone_note"));
	note->setWordWrap(true);
	note->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(note);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
	QPushButton *save = buttons->addButton(QStringLiteral("Save"), QDialogButtonBox::AcceptRole);
	save->setObjectName(QStringLiteral("zone_save"));
	if (!before.isEmpty()) {
		QPushButton *drop = buttons->addButton(QStringLiteral("delete"),
		    QDialogButtonBox::DestructiveRole);
		drop->setObjectName(QStringLiteral("zone_remove"));
		connect(drop, &QPushButton::clicked, this, &ncfg_zone_dialog::remove);
	}
	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(save, &QPushButton::clicked, this, &ncfg_zone_dialog::submit);
	layout->addWidget(buttons);
	resize(480, 220);
}

void ncfg_zone_dialog::submit()
{
	ncfg_zone_row zone;
	zone.name = name->text().trimmed();
	zone.reach = reach->text().split(QRegularExpression(QStringLiteral("[,\\s]+")),
	    Qt::SkipEmptyParts);
	zone.client_limit = client_limit->text().trimmed();
	zone.hosts = hosts->text().split(QRegularExpression(QStringLiteral("[,\\s]+")),
	    Qt::SkipEmptyParts);

	/* The compiler's own alphabet for a zone's name, asked here so the
	 * sentence names the field rather than a file. */
	static const QRegularExpression plain(QStringLiteral("^[A-Za-z][A-Za-z0-9_-]*$"));
	if (!plain.match(zone.name).hasMatch()) {
		note->setText(QStringLiteral("a zone needs a name: a letter, then letters, digits, "
		                             "`-` or `_`"));
		return;
	}
	for (const QString &one : zone.reach) {
		if (!plain.match(one).hasMatch()) {
			note->setText(QStringLiteral("\"%1\" cannot name a zone").arg(one));
			return;
		}
	}
	static const QRegularExpression rate(QStringLiteral("^[0-9]+(bit|kbit|mbit|gbit)?$"));
	if (!zone.client_limit.isEmpty() && !rate.match(zone.client_limit).hasMatch()) {
		note->setText(QStringLiteral("\"%1\" is not a rate: a number and one of bit, kbit, "
		                             "mbit, gbit, as 5mbit")
		                  .arg(zone.client_limit));
		return;
	}

	QString error;
	if (!connection->config_put(QStringLiteral("zone-%1").arg(zone.name), ncfg_zone_block(zone),
	        true, &error)) {
		note->setText(error);
		return;
	}
	summary = QStringLiteral("wrote zone-%1: netcfgd re-read its configuration. Run apply to "
	                         "make the machine match it, and put the same drop-in on the "
	                         "estate's other hosts.")
	              .arg(zone.name);
	accept();
}

void ncfg_zone_dialog::remove()
{
	QMessageBox box(QMessageBox::Question, QStringLiteral("netcfgd"),
	    QStringLiteral("Delete the zone \"%1\"?\n\nA link still in it, or a zone that still "
	                   "reaches it, keeps the configuration from compiling, so netcfgd "
	                   "refuses the delete until nothing does.")
	        .arg(before),
	    QMessageBox::Cancel | QMessageBox::Yes, this);
	box.setDefaultButton(QMessageBox::Cancel);
	if (box.exec() != QMessageBox::Yes) {
		return;
	}
	QString error;
	if (!connection->config_delete(QStringLiteral("zone-%1").arg(before), &error)) {
		note->setText(error);
		return;
	}
	summary = QStringLiteral("removed zone-%1: netcfgd re-read its configuration.").arg(before);
	accept();
}
