/*
 * firewall_view.h -- the firewall the configuration declares (0294).
 *
 * **One table for the three chains, in the order they are evaluated.** A
 * packet meets a chain's rules top to bottom and then its policy, so the rows
 * are shown that way, chain by chain, and moving a row up or down is an edit
 * in its own right: it changes what the chain does without changing a match.
 *
 * **From the document, not from the kernel**, as the rules tab is: what
 * nftables currently holds is drift's question, and the plan tab answers it.
 *
 * Every change rewrites the whole `firewall` drop-in (firewall_dialog.h says
 * why), and nothing reaches the kernel until apply -- which matters more here
 * than anywhere: an input policy of `drop` with no rule for the way the
 * operator is connected is how a machine is locked out, and the plan's
 * warnings (10.620) are written to be read before that happens.
 */
#ifndef NCFG_FIREWALL_VIEW_H
#define NCFG_FIREWALL_VIEW_H

#include "ncfg_connection.h"

#include <QList>
#include <QPair>
#include <QWidget>

class QComboBox;
class QPushButton;
class ncfg_table_view;

class ncfg_firewall_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_firewall_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	void refresh();

private slots:
	void edit_selected();
	void new_rule();
	void move_up();
	void move_down();
	void set_policies();

signals:
	void reported(const QString &summary);
	/* The configuration changed, so anything showing a plan is stale. */
	void changed();

private:
	void move(int by);
	void write(const ncfg_firewall_settings &next, const QString &said);

	ncfg_connection        *connection;
	ncfg_firewall_settings  settings;
	/* Each row's chain and its position there, so a row selects a rule
	 * rather than a re-parse of the table's strings. */
	QList<QPair<QString, int>> places;
	ncfg_table_view *table;
	QComboBox       *input_policy;
	QComboBox       *forward_policy;
	QComboBox       *output_policy;
	QPushButton     *edit_button;
	QPushButton     *up_button;
	QPushButton     *down_button;
};

#endif /* NCFG_FIREWALL_VIEW_H */
