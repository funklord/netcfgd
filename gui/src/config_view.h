/*
 * config_view.h -- the files that configure this machine.
 *
 * **What netcfgd is reading, in the order it reads it.** Every other tab shows
 * a consequence: the devices tab shows what the machine is doing, the plan
 * shows what would change. This shows the input, which is the thing an
 * operator edits and the thing that explains the rest.
 *
 * The order is not a detail of the listing. A later file overrides an earlier
 * one, so the sequence is the answer to "which of these two won" -- which is
 * why the rows are drawn in it rather than sorted by name.
 *
 * **Read, and remove.** Writing a drop-in is what the interface and network
 * dialogs do, each in the vocabulary of the thing being configured; a text box
 * here would be a second way to write configuration whose only advantage is
 * that it can express anything, which is what `check_content` exists to
 * refuse. Removing needs no such vocabulary: it is a name.
 *
 * `netcfgd.conf` is listed and cannot be removed. It is the machine's own
 * configuration rather than something a client filed, no request writes or
 * removes it, and a button that offered to would be offering a verb that does
 * not exist.
 */
#ifndef NCFG_CONFIG_VIEW_H
#define NCFG_CONFIG_VIEW_H

#include "ncfg_connection.h"

#include <QList>
#include <QWidget>

class QPlainTextEdit;
class QPushButton;
class ncfg_table_view;

class ncfg_config_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_config_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	void refresh();

signals:
	void reported(const QString &summary);
	/* A drop-in went, so anything showing a plan or a document is stale. */
	void changed();

private slots:
	/* Take the selected drop-in away, having asked. */
	void remove_selected();
	/* Show the selected file's text in the pane below the table. */
	void show_selected();

private:
	ncfg_connection       *connection;
	ncfg_table_view       *table;
	QPushButton           *remove_button;
	QPlainTextEdit        *contents;
	QList<ncfg_config_row> shown;
};

#endif /* NCFG_CONFIG_VIEW_H */
