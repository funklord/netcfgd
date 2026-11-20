// flow_layout.cpp -- see include/qtkit/flow_layout.h.

#include "qtkit/flow_layout.h"

#include <QStyle>
#include <QWidget>

qtkit_flow_layout::qtkit_flow_layout(QWidget *parent, int margin,
                                     int horizontal_gap, int vertical_gap)
    : QLayout(parent), m_horizontal_gap(horizontal_gap), m_vertical_gap(vertical_gap)
{
	if (margin >= 0)
		setContentsMargins(margin, margin, margin, margin);
}

qtkit_flow_layout::~qtkit_flow_layout()
{
	// A layout owns its items, and QLayout does not delete them.
	while (QLayoutItem *item = takeAt(0))
		delete item;
}

int qtkit_flow_layout::gap(Qt::Orientation orientation, int chosen) const
{
	if (chosen >= 0)
		return chosen;
	if (QWidget *widget = parentWidget()) {
		const int asked = widget->style()->layoutSpacing(
		    QSizePolicy::PushButton, QSizePolicy::PushButton, orientation, nullptr, widget);
		if (asked >= 0)
			return asked;
	}
	// The layout's own: inherited from a parent layout or the style's
	// layout metric, so a real number wherever the layout is installed.
	return qMax(0, spacing());
}

int qtkit_flow_layout::horizontal_spacing() const
{
	return gap(Qt::Horizontal, m_horizontal_gap);
}

int qtkit_flow_layout::vertical_spacing() const
{
	return gap(Qt::Vertical, m_vertical_gap);
}

void qtkit_flow_layout::addItem(QLayoutItem *item)
{
	m_items.append(item);
	invalidate();
}

int qtkit_flow_layout::count() const
{
	return int(m_items.size());
}

QLayoutItem *qtkit_flow_layout::itemAt(int index) const
{
	return m_items.value(index);
}

QLayoutItem *qtkit_flow_layout::takeAt(int index)
{
	if (index < 0 || index >= m_items.size())
		return nullptr;
	QLayoutItem *item = m_items.takeAt(index);
	invalidate();
	return item;
}

// None: it takes the width it is given and answers with a height. Saying
// otherwise makes a dialog grow into space it does not need.
Qt::Orientations qtkit_flow_layout::expandingDirections() const
{
	return {};
}

bool qtkit_flow_layout::hasHeightForWidth() const
{
	return true;
}

int qtkit_flow_layout::heightForWidth(int width) const
{
	return place(QRect(0, 0, width, 0), false);
}

void qtkit_flow_layout::setGeometry(const QRect &rect)
{
	QLayout::setGeometry(rect);
	place(rect, true);
}

QSize qtkit_flow_layout::sizeHint() const
{
	QSize row(0, 0);
	bool first = true;
	for (const QLayoutItem *item : m_items) {
		if (item->isEmpty())
			continue;
		const QSize hint = item->sizeHint();
		row.rwidth() += hint.width() + (first ? 0 : horizontal_spacing());
		row.setHeight(qMax(row.height(), hint.height()));
		first = false;
	}
	const QMargins margins = contentsMargins();
	return row + QSize(margins.left() + margins.right(), margins.top() + margins.bottom());
}

QSize qtkit_flow_layout::minimumSize() const
{
	QSize widest(0, 0);
	for (const QLayoutItem *item : m_items)
		if (!item->isEmpty())
			widest = widest.expandedTo(item->minimumSize());
	const QMargins margins = contentsMargins();
	return widest + QSize(margins.left() + margins.right(), margins.top() + margins.bottom());
}

int qtkit_flow_layout::place(const QRect &rect, bool apply) const
{
	const QMargins margins = contentsMargins();
	const QRect area = rect.marginsRemoved(margins);
	const int across = horizontal_spacing();
	const int down = vertical_spacing();
	int x = area.x();
	int y = area.y();
	int line_height = 0;
	bool line_empty = true;

	for (QLayoutItem *item : m_items) {
		if (item->isEmpty())
			continue;
		QSize size = item->sizeHint();
		// Wrap when the item would cross the right edge -- unless it is the
		// first on its line, where wrapping would only find the same edge.
		if (!line_empty && x + size.width() > area.x() + area.width()) {
			x = area.x();
			y += line_height + down;
			line_height = 0;
			line_empty = true;
		}
		// Alone and still too wide: the line's width, but never below the
		// item's own minimum.
		if (size.width() > area.width())
			size.setWidth(qMax(area.width(), item->minimumSize().width()));
		if (apply)
			item->setGeometry(QStyle::visualRect(
			    parentWidget() ? parentWidget()->layoutDirection() : Qt::LeftToRight,
			    area, QRect(QPoint(x, y), size)));
		x += size.width() + across;
		line_height = qMax(line_height, size.height());
		line_empty = false;
	}
	return y + line_height - rect.y() + margins.bottom();
}
