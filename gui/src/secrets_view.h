/*
 * secrets_view.h -- the credentials this machine holds, by name.
 *
 * **Never by value, and the design is what guarantees that rather than a
 * rule.** No value crosses the socket in this direction: `SecretEntry` has no
 * field that could carry one, so there is nothing here to accidentally draw.
 *
 * The list is the union of what the store holds and what the configuration
 * refers to, because the two faults worth finding are opposite ways round:
 *
 *   referenced, not stored   a network that will never join -- and it fails at
 *                            association time with an error about the radio
 *                            rather than about the missing passphrase, which
 *                            is why somebody would look here
 *   stored, not referenced   a credential still on the machine after whatever
 *                            wanted it was deleted
 *
 * Neither is visible from anywhere else in the program, which is what earns
 * this a tab rather than a column somewhere.
 *
 * Values go one way only. A MISSING credential can be stored from here, asked
 * for in a password field and sent to `secret_put` at once (10.807); this
 * once said a gui field would be a value in a process that did not need to
 * hold one, which stopped being the project's answer when the network, access
 * point and device dialogs began storing what is typed (10.782, 10.805). What
 * still holds is that nothing is ever read back.
 */
#ifndef NCFG_SECRETS_VIEW_H
#define NCFG_SECRETS_VIEW_H

#include <QList>
#include <QWidget>

#include "ncfg_connection.h"

class QPushButton;
class ncfg_table_view;

class ncfg_secrets_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_secrets_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	void refresh();

signals:
	void reported(const QString &summary);

private slots:
	/* Remove the selected credential, having asked. Removing carries no
	 * value at all, only a name. What it removes is the fault this
	 * view exists to name: "a credential still on the machine after whatever
	 * wanted it was deleted", which the note under the table used to answer
	 * with "removing the file is how a machine forgets it" -- a client being
	 * told to go behind the socket (0127). */
	void forget_selected();
	/* Store a value for the selected MISSING credential, asked for in a
	 * password field (10.807). */
	void store_selected();

private:
	ncfg_connection *connection;
	/* The shared read-only table. What is this view's own is below: turning
	 * one row into strings, which is where the subject lives. */
	ncfg_table_view *table;
	QPushButton     *forget_button;
	QPushButton     *store_button;
	/* What the selected row said it was used by, so the question can name it.
	 * Kept beside the table rather than re-read from a cell, because the cell
	 * holds the rendering and this holds the fact. */
	QList<ncfg_secret_row> shown;
};

#endif /* NCFG_SECRETS_VIEW_H */
