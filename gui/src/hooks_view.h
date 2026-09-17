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
 * **A hook is edited with the interface it belongs to**, and the button here
 * opens that editor. It is not a separate form for a reason worth knowing: a
 * hook lives inside an `interface` block, one drop-in owns that block whole,
 * and a second file declaring the same interface is a duplicate the loader
 * refuses. An editor for hooks alone would have to write everything the
 * interface editor writes, and the two would drift.
 *
 * What this program writes is the *document*. The kernel is changed through
 * plan and apply, where the operator sees the whole change before any of it
 * happens.
 */
#ifndef NCFG_HOOKS_VIEW_H
#define NCFG_HOOKS_VIEW_H

#include "ncfg_connection.h"

#include <QList>
#include <QWidget>

class QPushButton;
class ncfg_connection;
class ncfg_table_view;

class ncfg_hooks_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_hooks_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	void refresh();

private slots:
	/* Open the interface editor on the selected hook's interface. */
	void edit_selected();

signals:
	void reported(const QString &summary);
	/* The configuration changed, so anything showing a plan is stale. */
	void changed();

private:
	ncfg_connection *connection;
	/* The hooks as the daemon reports them, so the button opens on the row's
	 * own interface rather than on a re-read of the table's strings. */
	QList<ncfg_hook_row> rows;
	QPushButton *edit_button;
	/* The shared read-only table: columns, rows, and the sentence underneath
	 * that says why an empty one is empty. What is this view's own is turning
	 * a row into strings, which is below. */
	ncfg_table_view *table;
};

#endif /* NCFG_HOOKS_VIEW_H */
