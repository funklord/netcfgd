/*
 * fixed_name.h -- the name of a block being edited, which cannot change
 * (10.803).
 *
 * Ten dialogs make their name or id field read-only when they edit an
 * existing block, because the name is what the block is called in the
 * configuration and changing it would write a second one and leave the
 * first. A read-only QLineEdit still draws as an editable box, so the GUI
 * walk found it "looks editable and says nothing" (10.778): a person types,
 * nothing happens, and nothing says why.
 *
 * So it is drawn on the window's colour without a frame, the way a label
 * reads, stays selectable for copying, and says on hover how a rename is
 * done. Header-only for `hand_written.h`'s reason: every dialog and probe has
 * it without a source file to add to each project.
 */
#ifndef NCFG_FIXED_NAME_H
#define NCFG_FIXED_NAME_H

#include <QLineEdit>
#include <QPalette>
#include <QString>

/* `what` is the block's kind as a person would say it, "DNS record". Does
 * nothing unless `fixed`, so a call site reads as the condition it had. */
inline void ncfg_fix_name(QLineEdit *field, bool fixed, const QString &what)
{
	if (!field || !fixed) {
		return;
	}
	field->setReadOnly(true);
	field->setFrame(false);
	QPalette look = field->palette();
	look.setColor(QPalette::Base, look.color(QPalette::Window));
	field->setPalette(look);
	field->setToolTip(QStringLiteral("A %1's name cannot be changed here. To rename it, add "
	                                 "one under the new name and delete this one.")
	                      .arg(what));
}

#endif /* NCFG_FIXED_NAME_H */
