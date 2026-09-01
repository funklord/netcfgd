/*
 * table_view.cpp -- the shared table described in table_view.h.
 */
#include "table_view.h"

#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QTableWidget>
#include <QVBoxLayout>

ncfg_table_view::ncfg_table_view(const QStringList &columns, const QString &object,
    QWidget *parent)
    : QWidget(parent)
{
	auto *layout = new QVBoxLayout(this);

	table = new QTableWidget(0, columns.size(), this);
	table->setHorizontalHeaderLabels(columns);
	table->verticalHeader()->setVisible(false);
	table->setSelectionBehavior(QAbstractItemView::SelectRows);
	/* Read-only, and that is a statement rather than a shortcut: nothing is
	 * changed by typing into an observation. What this program can change it
	 * changes through plan and apply, where the operator sees the whole change
	 * before any of it happens. */
	table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	table->horizontalHeader()->setStretchLastSection(true);
	layout->addWidget(table);

	controls_row = new QHBoxLayout();
	controls_row->addStretch();
	layout->addLayout(controls_row);

	note = new QLabel(this);
	note->setObjectName(object);
	note->setWordWrap(true);
	layout->addWidget(note);

	connect(table, &QTableWidget::itemSelectionChanged, this,
	    &ncfg_table_view::selection_changed);
	connect(table, &QTableWidget::doubleClicked, this, &ncfg_table_view::activated);
}

void ncfg_table_view::show_rows(const QList<QStringList> &rows)
{
	const int columns = table->columnCount();
	table->setRowCount(rows.size());
	for (int row = 0; row < rows.size(); row++) {
		const QStringList &cells = rows.at(row);
		for (int column = 0; column < columns; column++) {
			table->setItem(row, column, new QTableWidgetItem(cells.value(column)));
		}
	}
	table->resizeColumnsToContents();
	table->horizontalHeader()->setStretchLastSection(true);
}

void ncfg_table_view::show_error(const QString &error)
{
	table->setRowCount(0);
	note->setText(error);
}

void ncfg_table_view::set_note(const QString &text)
{
	note->setText(text);
}

void ncfg_table_view::add_control(QWidget *control)
{
	/* Before the stretch the constructor added, so buttons stay left. */
	controls_row->insertWidget(controls_row->count() - 1, control);
}

int ncfg_table_view::selected_row() const
{
	return table->currentRow();
}

QString ncfg_table_view::selected_cell(int column) const
{
	const int row = table->currentRow();
	if (row < 0) {
		return QString();
	}
	const QTableWidgetItem *item = table->item(row, column);
	return item ? item->text() : QString();
}
