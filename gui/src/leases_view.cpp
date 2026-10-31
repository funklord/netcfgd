/*
 * leases_view.cpp -- the table described in leases_view.h.
 */
#include "leases_view.h"

#include "ncfg_connection.h"
#include "table_view.h"

#include <QDateTime>
#include <QVBoxLayout>

ncfg_leases_view::ncfg_leases_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	QStringList columns;
	columns << QStringLiteral("interface") << QStringLiteral("address")
	        << QStringLiteral("mac") << QStringLiteral("name") << QStringLiteral("expires");
	table = new ncfg_table_view(columns, QStringLiteral("leases_note"), this);
	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);
}

void ncfg_leases_view::refresh()
{
	QList<ncfg_lease_row> found;
	QString               error;

	if (!connection->leases(&found, &error)) {
		table->show_error(error);
		emit reported(error);
		return;
	}
	QList<QStringList> rows;
	for (const ncfg_lease_row &lease : found) {
		rows << QStringList { lease.interface, lease.address,
			lease.mac.isEmpty() ? QStringLiteral("(DHCPv6)") : lease.mac, lease.hostname,
			lease.expires == 0
			    ? QStringLiteral("never")
			    : QDateTime::fromSecsSinceEpoch(lease.expires).toString(Qt::ISODate) };
	}
	table->show_rows(rows);
	if (rows.isEmpty()) {
		table->set_note(QStringLiteral(
		    "No leases. A `dhcp_server` block on an interface hands out addresses, and each "
		    "one it gives shows here until it expires."));
		emit reported(QStringLiteral("no leases"));
		return;
	}
	table->set_note(QStringLiteral(
	    "From each DHCP server's lease file. The name is the one the client sent, left "
	    "blank where it is not a plain host name."));
	emit reported(QStringLiteral("%1 leases").arg(rows.size()));
}
