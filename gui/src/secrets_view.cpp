/*
 * secrets_view.cpp -- the credentials table described in secrets_view.h.
 */
#include "secrets_view.h"

#include "ncfg_connection.h"

#include <QHeaderView>
#include <QLabel>
#include <QTableWidget>
#include <QVBoxLayout>

namespace {

const char *const column_titles[] = { "name", "state", "used by" };
constexpr int column_count = static_cast<int>(sizeof(column_titles) / sizeof(column_titles[0]));

} /* namespace */

ncfg_secrets_view::ncfg_secrets_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	auto *layout = new QVBoxLayout(this);

	table = new QTableWidget(0, column_count, this);
	QStringList headers;
	for (int i = 0; i < column_count; i++) {
		headers << QString::fromLatin1(column_titles[i]);
	}
	table->setHorizontalHeaderLabels(headers);
	table->verticalHeader()->setVisible(false);
	table->setSelectionBehavior(QAbstractItemView::SelectRows);
	table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	table->horizontalHeader()->setStretchLastSection(true);
	layout->addWidget(table);

	note = new QLabel(this);
	note->setObjectName(QStringLiteral("secrets_note"));
	note->setWordWrap(true);
	layout->addWidget(note);
}

void ncfg_secrets_view::refresh()
{
	QList<ncfg_secret_row> rows;
	QString error;

	if (!connection->secrets(&rows, &error)) {
		table->setRowCount(0);
		note->setText(error);
		emit reported(error);
		return;
	}

	int missing = 0;
	table->setRowCount(rows.size());
	for (int row = 0; row < rows.size(); row++) {
		const ncfg_secret_row &secret = rows.at(row);

		/* The state is the whole point of the tab, so it is words rather than
		 * a tick: "stored" and "not stored" are not opposites here, because
		 * whether anything *refers* to it changes what each one means. */
		QString state;
		if (!secret.stored) {
			state = QStringLiteral("MISSING");
			missing++;
		} else if (secret.used_by.isEmpty()) {
			state = QStringLiteral("stored, unused");
		} else {
			state = QStringLiteral("stored");
		}

		const QString cells[column_count] = {
			secret.name,
			state,
			secret.used_by.isEmpty() ? QStringLiteral("nothing") : secret.used_by,
		};
		for (int column = 0; column < column_count; column++) {
			table->setItem(row, column, new QTableWidgetItem(cells[column]));
		}
	}
	table->resizeColumnsToContents();
	table->horizontalHeader()->setStretchLastSection(true);

	if (rows.isEmpty()) {
		note->setText(QStringLiteral(
		    "This machine holds no credentials and its configuration refers to none. A "
		    "passphrase is stored with `ncfg secret set NAME`, which asks for the value "
		    "at a prompt, and the configuration refers to it as @secret:NAME."));
		emit reported(QStringLiteral("no secrets"));
		return;
	}

	/* The count of missing ones leads, because it is the one number here that
	 * means something is broken right now. */
	note->setText(
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
