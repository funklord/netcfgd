/*
 * hooks_view.h -- every program netcfgd runs, and when.
 *
 * Flattened across interfaces on purpose. A hook belongs to an interface, but
 * the question an operator has is "what runs on this machine, and when" -- and
 * that is a list, not something to go looking for one interface at a time.
 *
 * **`runs as` is a privilege boundary rather than a detail.** Design section 9
 * says hooks run as a configurable user and not blindly as root; a hook with
 * nothing in that column runs as the daemon, which is root. A list is exactly
 * what makes that visible, and finding it by opening eleven interface dialogs
 * is how it stays invisible.
 *
 * Read-only. What this program can change it changes through plan and apply,
 * where the operator sees the whole change before any of it happens.
 */
#ifndef NCFG_HOOKS_VIEW_H
#define NCFG_HOOKS_VIEW_H

#include <QWidget>

class QLabel;
class QTableWidget;

class ncfg_connection;

class ncfg_hooks_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_hooks_view(ncfg_connection *connection, QWidget *parent = nullptr);

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

#endif /* NCFG_HOOKS_VIEW_H */
