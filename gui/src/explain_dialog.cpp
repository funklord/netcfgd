/*
 * explain_dialog.cpp -- the explanation table described in explain_dialog.h.
 *
 * The table is `ncfg_table_view`, shared with every other list here, so the
 * one thing this file owns is what the three columns mean and what the note
 * under them says when there is nothing to show.
 */
#include "explain_dialog.h"

#include "ncfg_connection.h"
#include "table_view.h"

#include <QDialogButtonBox>
#include <QVBoxLayout>

ncfg_explain_dialog::ncfg_explain_dialog(ncfg_connection *connection, const QString &interface,
    QWidget *parent)
    : QDialog(parent), connection(connection), interface(interface)
{
	setWindowTitle(QStringLiteral("why is %1 like this").arg(interface));
	setObjectName(QStringLiteral("explain_dialog"));

	QStringList columns;
	/* `topic` first because it is what an operator scans for -- "where does
	 * the address come from" is a `desired` row and "why is it down" is an
	 * `observed` or `next` one. The daemon's own vocabulary, drawn as it
	 * arrives: mapping it to a fixed set here would silently drop a topic
	 * added later. */
	columns << QStringLiteral("topic") << QStringLiteral("fact")
	        << QStringLiteral("source");
	table = new ncfg_table_view(columns, QStringLiteral("explain_note"), this);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

	auto *layout = new QVBoxLayout(this);
	layout->addWidget(table);
	layout->addWidget(buttons);
	resize(720, 380);

	QList<ncfg_explain_row> facts;
	QString error;
	if (!connection->explain(interface, &facts, &error)) {
		table->show_error(error);
		return;
	}

	QList<QStringList> rows;
	for (const ncfg_explain_row &fact : facts) {
		QStringList cells;
		cells << fact.topic;
		cells << fact.detail;
		/* An empty source is a fact with no place to open -- "the kernel says
		 * so" -- and drawing a dash for it says that, where a blank cell reads
		 * as a value the program failed to fetch. */
		cells << (fact.source.isEmpty() ? QStringLiteral("--") : fact.source);
		rows << cells;
	}
	table->show_rows(rows);

	/* **An explanation with no facts is an answer, not a failure**, and it is
	 * the one a client is most likely to misread: the daemon knows the name
	 * and has nothing to say about it. Saying so beats an empty table, which
	 * reads as a request that went wrong. */
	table->set_note(rows.isEmpty()
	        ? QStringLiteral("netcfgd has nothing to say about %1. That is an answer: it "
	                     "knows the name and holds no fact about it.")
	              .arg(interface)
	        : QStringLiteral("What netcfgd knows about %1 and where each part came from. "
	                     "`desired` is the configuration, `observed` is the kernel, and "
	                     "`next` is what an apply would do about the difference.")
	              .arg(interface));
}
