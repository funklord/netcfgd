/*
 * secrets_view.h -- the credentials this machine holds, by name.
 *
 * **Listed by name, never by value, and the design is what guarantees that
 * rather than a rule.** `secret_list`'s rows have no field that could carry a
 * value, so there is nothing in the table to accidentally draw.
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
 * A MISSING credential can be stored from here, asked for in a password field
 * and sent to `secret_put` at once (10.807). A stored one is shown back only
 * to the `root` tier on this machine, by `show...` and only when pressed
 * (0328): the table itself never carries a value, and nothing is shown to a
 * connection below `root` or to another node of the estate.
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
	/* Show the selected credential's value, for `root` on this machine
	 * (0328): asked for when pressed, shown in a box, held no longer. */
	void show_selected();

private:
	ncfg_connection *connection;
	/* The shared read-only table. What is this view's own is below: turning
	 * one row into strings, which is where the subject lives. */
	ncfg_table_view *table;
	QPushButton     *forget_button;
	QPushButton     *store_button;
	QPushButton     *show_button;
	/* What the selected row said it was used by, so the question can name it.
	 * Kept beside the table rather than re-read from a cell, because the cell
	 * holds the rendering and this holds the fact. */
	QList<ncfg_secret_row> shown;
};

#endif /* NCFG_SECRETS_VIEW_H */
