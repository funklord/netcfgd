/*
 * phone_fit.h -- every dialog fits a phone (project.md 10.728).
 *
 * The dialogs are the desktop's, and gui/project.md section 1 says they stay so:
 * no lite client. But a form's labels took half of a phone's width and left the
 * fields behind a scroll bar, in a window narrower than the screen. So what changes
 * is how each is shown, in one place, rather than forty dialogs knowing about
 * phones: full screen, with each label over its field.
 */
#ifndef NCFG_GUI_PHONE_FIT_H
#define NCFG_GUI_PHONE_FIT_H

#include <QObject>

class ncfg_phone_fit : public QObject {
public:
	using QObject::QObject;

protected:
	bool eventFilter(QObject *watched, QEvent *event) override;
};

#endif
