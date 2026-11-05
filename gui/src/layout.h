/*
 * layout.h -- one window, in a desktop or a mobile shape (project.md 10.736).
 *
 * The phone and the desktop run the same window (gui/project.md section 1: no
 * lite client). What differs falls in two kinds, and they are kept apart here
 * because only one of them is a choice:
 *
 *   THE LAYOUT, `ncfg_layout`: how the same things are shown. The device's by
 *   default, `--layout` over it, so a small Linux machine can have the mobile one
 *   and all of it can be tested with no phone.
 *
 *   THE DEVICE, `ncfg_device_has_local`: what is there at all. Compiled in, not a
 *   mode: an Android phone has no root node of its own and no `ncfg`, so it opens
 *   on a prompt for a host, and nothing a preference says can give it either.
 */
#ifndef NCFG_GUI_LAYOUT_H
#define NCFG_GUI_LAYOUT_H

#include <QObject>
#include <QString>

enum class ncfg_layout {
	desktop,
	mobile,
};

/* Compiled in, as bbq-predictor's is: asking the screen guesses wrong on a
 * desktop with a touchscreen, and a preference is better evidence than pixels. */
ncfg_layout ncfg_layout_for_device();

/* "desktop" or "mobile"; anything else, "auto" among them, is the device's. */
ncfg_layout ncfg_layout_resolve(const QString &preference);

/* Whether this machine has a netcfgd of its own to open. */
constexpr bool ncfg_device_has_local()
{
#ifdef Q_OS_ANDROID
	return false;
#else
	return true;
#endif
}

/*
 * Every dialog fits the mobile layout (10.728). The dialogs are the desktop's, but
 * a form's labels took half of a phone's width and left the fields behind a scroll
 * bar, in a window narrower than the screen. So what changes is how each is shown,
 * in one place, rather than forty dialogs knowing: filling the screen, with each
 * label over its field. Installed on the application.
 */
class ncfg_mobile_fit : public QObject {
public:
	using QObject::QObject;

protected:
	bool eventFilter(QObject *watched, QEvent *event) override;
};

#endif
