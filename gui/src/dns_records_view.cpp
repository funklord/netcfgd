/*
 * dns_records_view.cpp -- the table described in dns_records_view.h.
 */
#include "dns_records_view.h"

#include "dns_record_dialog.h"
#include "table_view.h"

#include <QPushButton>
#include <QVBoxLayout>

ncfg_dns_records_view::ncfg_dns_records_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	QStringList columns;
	columns << QStringLiteral("name") << QStringLiteral("answers");
	table = new ncfg_table_view(columns, QStringLiteral("dns_records_note"), this);

	edit_button = new QPushButton(QStringLiteral("view / change"), this);
	edit_button->setObjectName(QStringLiteral("edit_record"));
	edit_button->setEnabled(false);
	table->add_control(edit_button);
	auto *new_button = new QPushButton(QStringLiteral("new record..."), this);
	new_button->setObjectName(QStringLiteral("new_record"));
	table->add_control(new_button);

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);

	connect(edit_button, &QPushButton::clicked, this, &ncfg_dns_records_view::edit_selected);
	connect(new_button, &QPushButton::clicked, this, &ncfg_dns_records_view::new_record);
	connect(table, &ncfg_table_view::activated, this, &ncfg_dns_records_view::edit_selected);
	connect(table, &ncfg_table_view::selection_changed, this,
	    [this]() { edit_button->setEnabled(table->selected_row() >= 0); });
}

void ncfg_dns_records_view::open(const ncfg_dns_record_row &record)
{
	ncfg_dns_record_dialog dialog(connection, record, this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	emit reported(dialog.outcome());
	refresh();
	emit changed();
}

void ncfg_dns_records_view::edit_selected()
{
	const int row = table->selected_row();
	if (row >= 0 && row < records.size()) {
		open(records.at(row));
	}
}

void ncfg_dns_records_view::new_record()
{
	open(ncfg_dns_record_row());
}

void ncfg_dns_records_view::refresh()
{
	QString error;
	if (!connection->dns_records(&records, &error)) {
		records.clear();
		table->show_error(error);
		emit reported(error);
		return;
	}

	QList<QStringList> rows;
	for (const ncfg_dns_record_row &record : records) {
		QStringList answers;
		if (!record.address.isEmpty()) {
			answers << record.address;
		}
		if (!record.cname.isEmpty()) {
			answers << QStringLiteral("alias for %1").arg(record.cname);
		}
		if (!record.mx.isEmpty()) {
			answers << QStringLiteral("mail %1").arg(record.mx);
		}
		if (!record.txt.isEmpty()) {
			answers << QStringLiteral("text \"%1\"").arg(record.txt);
		}
		if (!record.srv.isEmpty()) {
			answers << QStringLiteral("service %1:%2").arg(record.srv).arg(record.port);
		}
		if (!record.forward.isEmpty()) {
			answers << QStringLiteral("forwarded to %1").arg(record.forward);
		}
		rows << QStringList { record.name, answers.join(QStringLiteral("; ")) };
	}
	table->show_rows(rows);
	if (rows.isEmpty()) {
		table->set_note(QStringLiteral(
		    "No `dns_record` block. A record is a name this router answers itself -- a NAS "
		    "that holds no lease, an alias, a domain asked of another server. Names the DHCP "
		    "server hands out already resolve."));
		emit reported(QStringLiteral("no DNS records configured"));
		return;
	}
	table->set_note(QStringLiteral(
	    "Answered by every DHCP server with `dns_forward`; the plan says so where none has it."));
	emit reported(QStringLiteral("%1 DNS records").arg(rows.size()));
}
