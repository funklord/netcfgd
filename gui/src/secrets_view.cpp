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

#include <QMessageBox>
#include <QPushButton>
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

	/* **`admin`, and the protocol says that is all that guards it** -- so the
	 * button is off where the connection does not hold it, rather than
	 * offering an action that will be refused. The tooltip says which tier,
	 * because a greyed control with no reason is indistinguishable from a
	 * broken one (0092). */
	forget_button = new QPushButton(QStringLiteral("forget"), this);
	forget_button->setObjectName(QStringLiteral("forget_secret"));
	forget_button->setEnabled(false);
	if (connection->tiers().admin == 0) {
		forget_button->setToolTip(
		    QStringLiteral("removing a credential needs the `admin` tier, which this "
		               "connection does not have"));
	}
	table->add_control(forget_button);

	connect(forget_button, &QPushButton::clicked, this, &ncfg_secrets_view::forget_selected);
	connect(table, &ncfg_table_view::selection_changed, this, [this, connection]() {
		const int row = table->selected_row();
		/* **Only a stored one, and only with the tier.** A row that is
		 * MISSING is a name the configuration refers to and the store does
		 * not hold: there is no file to remove, and a button that looked
		 * live for it would be offering to fix the wrong half of the fault.
		 */
		const bool stored = row >= 0 && row < shown.size() && shown.at(row).stored;
		forget_button->setEnabled(stored && connection->tiers().admin != 0);
	});

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);
}

void ncfg_secrets_view::forget_selected()
{
	const int row = table->selected_row();
	if (row < 0 || row >= shown.size()) {
		return;
	}
	const ncfg_secret_row secret = shown.at(row);

	/* **Two questions in one, and which one it is depends on the row.** A
	 * credential nothing refers to is the tidy case this view exists to
	 * surface. One that something still refers to is a network that will stop
	 * joining, so the question names what refers to it rather than warning in
	 * the abstract -- and it is still offered, because rotating a credential
	 * means removing the old one while the reference stays.
	 *
	 * 0042 is why the wording is blunt: a private key nobody has a copy of
	 * cannot be got back, and the protocol adds no second question of its own. */
	QString question = QStringLiteral("Forget the credential `%1`?").arg(secret.name);
	if (secret.used_by.isEmpty()) {
		question += QStringLiteral(
		    "\n\nNothing in the configuration refers to it. The value is gone for good; "
		    "netcfgd never held a copy anywhere else.");
	} else {
		question += QStringLiteral(
		    "\n\nIt is still referred to by %1, which will stop working until a new "
		    "value is stored under the same name. The value is gone for good.")
		        .arg(secret.used_by);
	}

	QMessageBox box(QMessageBox::Warning, QStringLiteral("netcfgd"), question,
	            QMessageBox::Cancel | QMessageBox::Yes, this);
	box.setDefaultButton(QMessageBox::Cancel);
	if (box.exec() != QMessageBox::Yes) {
		return;
	}

	QString error;
	if (!connection->secret_delete(secret.name, &error)) {
		table->show_error(error);
		emit reported(error);
		return;
	}
	/* The refresh first, then the sentence, for the reason the wifi view's
	 * forget learned: `refresh` writes its own summary and would overwrite
	 * this one within a turn of the event loop. */
	refresh();
	const QString said = QStringLiteral("forgot the credential `%1`").arg(secret.name);
	emit reported(said);
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

	shown = found;
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
	                  "to it was deleted; choose it and press forget."));
	emit reported(missing ? QStringLiteral("%1 secrets, %2 missing").arg(rows.size()).arg(missing)
	                      : QStringLiteral("%1 secrets").arg(rows.size()));
}
