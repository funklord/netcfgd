#include "phone_fit.h"

#include <QDialog>
#include <QEvent>
#include <QFormLayout>
#include <QMessageBox>

bool ncfg_phone_fit::eventFilter(QObject *watched, QEvent *event)
{
	if (event->type() == QEvent::Show) {
		auto *dialog = qobject_cast<QDialog *>(watched);

		/* A message box is a sentence and two buttons, and already fits. */
		if (dialog && !qobject_cast<QMessageBox *>(dialog)) {
			for (QFormLayout *form : dialog->findChildren<QFormLayout *>()) {
				form->setRowWrapPolicy(QFormLayout::WrapAllRows);
			}
			dialog->setWindowState(dialog->windowState() | Qt::WindowMaximized);
		}
	}
	return QObject::eventFilter(watched, event);
}
