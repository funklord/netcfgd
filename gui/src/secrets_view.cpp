/*
 * secrets_view.cpp -- the credentials table described in secrets_view.h.
 *
 * The table itself is `ncfg_table_view`, shared with every other list here.
 * What is left is this view's subject: the three states a credential can be
 * in, and which of them means something is broken right now.
 */
#include "secrets_view.h"

#include "ncfg_connection.h"
#include "table_view.h"

#include <QVBoxLayout>

namespace {

/* Words rather than a tick, because "stored" and "not stored" are not
 * opposites here: whether anything *refers* to it changes what each one
 * means. */
QString state_of(const ncfg_secret_row &secret)
{
	if (!secret.stored) {
		return QStringLiteral("MISSING");
	}
	if (secret.used_by.isEmpty()) {
		return QStringLiteral("stored, unused");
	}
	return QStringLiteral("stored");
}

} /* namespace */

ncfg_secrets_view::ncfg_secrets_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	QStringList columns;
	columns << QStringLiteral("name") << QStringLiteral("state") << QStringLiteral("used by");
	table = new ncfg_table_view(columns, QStringLiteral("secrets_note"), this);

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);
}

void ncfg_secrets_view::refresh()
{
	QList<ncfg_secret_row> found;
	QString error;

	if (!connection->secrets(&found, &error)) {
		table->show_error(error);
		emit reported(error);
		return;
	}

	int missing = 0;
	QList<QStringList> rows;
	for (const ncfg_secret_row &secret : found) {
		if (!secret.stored) {
			missing++;
		}
		QStringList cells;
		cells << secret.name;
		cells << state_of(secret);
		cells << (secret.used_by.isEmpty() ? QStringLiteral("nothing") : secret.used_by);
		rows << cells;
	}
	table->show_rows(rows);

	if (rows.isEmpty()) {
		table->set_note(QStringLiteral(
		    "This machine holds no credentials and its configuration refers to none. A "
		    "passphrase is stored with `ncfg secret set NAME`, which asks for the value "
		    "at a prompt, and the configuration refers to it as @secret:NAME."));
		emit reported(QStringLiteral("no secrets"));
		return;
	}

	/* The count of missing ones leads, because it is the one number here that
	 * means something is broken right now. */
	table->set_note(
	    missing ? QStringLiteral(
	                  "%1 referred to by the configuration and not stored. A network whose "
	                  "passphrase is missing never joins, and it fails with an error about "
	                  "the radio rather than about the credential -- `ncfg secret set NAME` "
	                  "stores one. Values are never shown here or sent over the socket.")
	                  .arg(missing)
	            : QStringLiteral(
	                  "Values are never shown here or sent over the socket -- only names. "
	                  "`stored, unused` is a credential left behind after whatever referred "
	                  "to it was deleted; removing the file is how a machine forgets it."));
	emit reported(missing ? QStringLiteral("%1 secrets, %2 missing").arg(rows.size()).arg(missing)
	                      : QStringLiteral("%1 secrets").arg(rows.size()));
}
