/*
 * rules_view.h -- the routing rules the configuration declares.
 *
 * A rule is a fundamental thing and there is a list of them, which is this
 * program's rule for what earns a tab.
 *
 * **From the document, not from the kernel.** This is what netcfgd was asked
 * for; what the kernel currently has is a different question and belongs to
 * drift, which the plan tab answers. Showing the two in one table without
 * saying which is which is how somebody concludes a rule is installed when it
 * is only configured.
 *
 * The priority leads because it is the identity as far as the kernel is
 * concerned -- it decides when the rule is consulted -- and the selector is
 * one column rather than eight, since a rule setting six of them is
 * unreadable as six columns that are empty on every other row.
 *
 * Read-only. What this program can change it changes through plan and apply,
 * where the operator sees the whole change before any of it happens.
 */
#ifndef NCFG_RULES_VIEW_H
#define NCFG_RULES_VIEW_H

#include <QWidget>

class QLabel;
class QTableWidget;

class ncfg_connection;

class ncfg_rules_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_rules_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	void refresh();

signals:
	void reported(const QString &summary);

private:
	ncfg_connection *connection;
	QTableWidget    *table;
	/* Says why the table is empty, which "no rows" cannot: nothing configured
	 * and a daemon that refused look identical otherwise. */
	QLabel          *note;
};

#endif /* NCFG_RULES_VIEW_H */
