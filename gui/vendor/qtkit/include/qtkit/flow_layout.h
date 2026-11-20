// flow_layout.h -- a row of widgets that becomes several rows when one will
// not fit, so a row of buttons reflows on a narrow window instead of being
// squeezed until its labels are cut ("pen Folde" at 360 pixels, in hydra's
// downloads dialog) or running off behind a scrollbar (fuzzypickles' setup
// page on a folding phone).
//
// A QHBoxLayout cannot do this: its minimum width is the sum of its
// children, so no dialog holding one can be narrower than the whole row.
// This layout's minimum is its widest item, and its height follows from the
// width it is given (heightForWidth), so the window around it grows taller
// rather than clipping.
//
// Gathered from hydra's and fuzzypickles' copies (project.md, *Where each
// part came from*); written here rather than taken from either.
//
//   - **sizeHint is the unwrapped row**, from hydra: a dialog with room opens
//     as one row, laid out item for item as a QHBoxLayout would at that
//     width. fuzzypickles answered the widest item, which opens a dialog
//     sized to its hint with every button on a line of its own.
//   - **Spacing asked of the style for push buttons, then the layout**, from
//     hydra: QStyle::layoutSpacing where the style has an opinion, else
//     QLayout::spacing(), which is always a real number. Fusion answers -1
//     to the first and 6 through the second (measured, Qt 6.8).
//   - **A hidden widget takes no room**, as in every Qt layout. Neither copy
//     skipped one, so hiding a button left its gap.
//   - **A lone item wider than the line is given the line**, down to its
//     own minimum width, rather than its full hint running past the edge.
//   - **Right to left mirrors**, as QBoxLayout does.
//
// Above the unwrapped width the two layouts part company: a QHBoxLayout
// spreads the surplus into children that can grow, and this one leaves it
// empty at the end of the line. Whether a short row should stretch is the
// program's call; put the layout in a QHBoxLayout with a stretch if it should
// sit on the right.

#ifndef QTKIT_FLOW_LAYOUT_H
#define QTKIT_FLOW_LAYOUT_H

#include <QLayout>
#include <QList>

class qtkit_flow_layout : public QLayout {
	Q_OBJECT
public:
	// -1 for a gap means: ask the style, then the layout's own spacing.
	explicit qtkit_flow_layout(QWidget *parent = nullptr, int margin = -1,
	                           int horizontal_gap = -1, int vertical_gap = -1);
	~qtkit_flow_layout() override;

	int horizontal_spacing() const;
	int vertical_spacing() const;

	void addItem(QLayoutItem *item) override;
	int count() const override;
	QLayoutItem *itemAt(int index) const override;
	QLayoutItem *takeAt(int index) override;

	Qt::Orientations expandingDirections() const override;
	bool hasHeightForWidth() const override;
	int heightForWidth(int width) const override;
	QSize sizeHint() const override;
	QSize minimumSize() const override;
	void setGeometry(const QRect &rect) override;

private:
	// One walk over the items, measuring only or placing as well: the
	// height heightForWidth reports and the places setGeometry gives must
	// agree, so they are one piece of code.
	int place(const QRect &rect, bool apply) const;
	int gap(Qt::Orientation orientation, int chosen) const;

	QList<QLayoutItem *> m_items;
	int m_horizontal_gap;
	int m_vertical_gap;
};

#endif
