#include "layout.h"

#include <QDialog>
#include <QEvent>
#include <QFormLayout>
#include <QMessageBox>

ncfg_layout ncfg_layout_for_device()
{
#ifdef Q_OS_ANDROID
	return ncfg_layout::mobile;
#else
	return ncfg_layout::desktop;
#endif
}

ncfg_layout ncfg_layout_resolve(const QString &preference)
{
	if (preference == QStringLiteral("desktop")) {
		return ncfg_layout::desktop;
	}
	if (preference == QStringLiteral("mobile")) {
		return ncfg_layout::mobile;
	}
	return ncfg_layout_for_device();
}

bool ncfg_mobile_fit::eventFilter(QObject *watched, QEvent *event)
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
