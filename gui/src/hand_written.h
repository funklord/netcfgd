/*
 * hand_written.h -- a dialog shown on a block somebody wrote by hand (10.778).
 *
 * Design section 9.4: hand-written blocks stay read-only to clients.
 * `ncfg_connection::written_by_hand` says which they are; this turns an editor
 * into a viewer for one, before anybody types, rather than taking every edit
 * and refusing the save with the compiler's "already defined".
 *
 * Header-only so that every view and probe that opens a dialog has it without
 * a source file to add to each project.
 */
#ifndef NCFG_HAND_WRITTEN_H
#define NCFG_HAND_WRITTEN_H

#include <QAbstractButton>
#include <QBoxLayout>
#include <QDialog>
#include <QDialogButtonBox>
#include <QLabel>
#include <QString>

/*
 * Hide what would write -- every button in the dialog's button box that
 * accepts or deletes -- turn Cancel into Close, and say why at the top.
 * Hidden rather than disabled: a dialog re-enables Save as its fields
 * validate, and a disabled button with no reason is the thing this exists
 * to stop.
 */
inline void ncfg_show_read_only(QDialog *dialog, const QString &what)
{
	for (QDialogButtonBox *box : dialog->findChildren<QDialogButtonBox *>()) {
		for (QAbstractButton *button : box->buttons()) {
			const QDialogButtonBox::ButtonRole role = box->buttonRole(button);
			if (role == QDialogButtonBox::AcceptRole ||
			    role == QDialogButtonBox::DestructiveRole ||
			    role == QDialogButtonBox::ApplyRole) {
				button->setVisible(false);
			} else if (role == QDialogButtonBox::RejectRole) {
				button->setText(QStringLiteral("Close"));
			}
		}
	}
	auto *note = new QLabel(QStringLiteral("%1 is written by hand in a configuration file, "
	                                       "and netcfgd's clients leave hand-written settings as "
	                                       "they are. This shows it; change it in that file, "
	                                       "which the files tab lists.")
	                            .arg(what),
	                        dialog);
	note->setObjectName(QStringLiteral("hand_written"));
	note->setWordWrap(true);
	if (auto *layout = qobject_cast<QBoxLayout *>(dialog->layout())) {
		layout->insertWidget(0, note);
	}
	dialog->setWindowTitle(dialog->windowTitle() + QStringLiteral(" (written by hand)"));
}

#endif
