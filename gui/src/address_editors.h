/*
 * address_editors.h -- an `addressing` list and a `routes` table, for any
 * block that has them.
 *
 * **One of each, used by the interface dialog and the network dialog.** The
 * interface dialog had the list and a three-column route table; the network
 * dialog had one addressing choice and its own copy of the table. So a network
 * addressed twice was refused (10.612), and a route's `src`, `table` and
 * `onlink` were refused in both (10.615). Two copies of one editor is how
 * those drift: the fix lands in one and not the other.
 *
 * **Each entry keeps what the language writes after its head.** A static
 * address's lifetimes, a `dhcp6` prefix delegation request and SLAAC's privacy
 * are `options` here, text carried through and shown, because a form that
 * wrote the head alone dropped them on Save without a word (10.615).
 *
 * `prefix` names the widgets -- `iface_sources`, `network_routes` -- which is
 * what the probes find them by.
 */
#ifndef NCFG_ADDRESS_EDITORS_H
#define NCFG_ADDRESS_EDITORS_H

#include "ncfg_connection.h"

#include <QWidget>

class QComboBox;
class QLineEdit;
class QListWidget;
class QPushButton;
class QTableWidget;

class ncfg_addressing_editor : public QWidget {
	Q_OBJECT

public:
	ncfg_addressing_editor(const QString &prefix, QWidget *parent = nullptr);

	/* The document's entries, in its order. */
	void load(const QList<ncfg_address_source_row> &sources);
	/* Each entry as the language writes it, quoted, in order: `"dhcp"`,
	 * `"192.0.2.1/24 preferred_lft 600"`, `"@pd:wan0/1=::1/64"`. */
	QStringList entries() const;
	int         count() const;

signals:
	/* A sentence for the dialog's note, when an entry cannot be added. */
	void noted(const QString &text);

private slots:
	void add();
	void drop();
	void move_up();
	void move_down();
	void changed();

private:
	void put(const QString &kind, const QString &address, const QString &options);

	QListWidget *list;
	QComboBox   *kind;
	QLineEdit   *address;
	QLineEdit   *options;
	QPushButton *add_button;
	QPushButton *drop_button;
	QPushButton *up_button;
	QPushButton *down_button;
};

class ncfg_route_editor : public QWidget {
	Q_OBJECT

public:
	ncfg_route_editor(const QString &prefix, QWidget *parent = nullptr);

	void load(const QList<ncfg_route_row> &routes);
	/* Each route as the language writes it, quoted:
	 * `"10.9.0.0/24 via 192.0.2.1 metric 5 src 192.0.2.10 table 100 onlink"`. */
	QStringList lines() const;
	/* Why a row cannot be written, or empty. A cell is text inside a quoted
	 * list entry, so one that could close it is refused here. */
	QString refusal() const;
	int     count() const;

private:
	void    put(const ncfg_route_row &route);
	QString cell(int row, int column) const;

	QTableWidget *table;
	QPushButton  *add_button;
	QPushButton  *drop_button;
};

#endif /* NCFG_ADDRESS_EDITORS_H */
