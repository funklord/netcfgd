// portal_listener.h -- the portal's change signal, for qtkit_theme. Private
// to src/: a slot taking QDBusVariant cannot sit in the public header, which
// must not need QtDBus.

#ifndef QTKIT_PORTAL_LISTENER_H
#define QTKIT_PORTAL_LISTENER_H

#include "qtkit/theme.h"

#include <QDBusConnection>
#include <QDBusVariant>
#include <QObject>

// Read the address, not the connection: QDBusConnection::sessionBus()
// autolaunches a private dbus-daemon when the variable is unset -- every
// test run, CI run and tty login -- and nothing reaps it. Empty counts as
// absent, since make can clear a variable for a child but not unset it.
inline bool qtkit_session_bus_present()
{
	return !qEnvironmentVariableIsEmpty("DBUS_SESSION_BUS_ADDRESS");
}

class portal_listener : public QObject {
	Q_OBJECT

public:
	explicit portal_listener(qtkit_theme *theme) : QObject(theme), m_theme(theme)
	{
		// Gated like the read: a watch holds its connection for the life of
		// the window, so an autolaunched bus here is one that stays.
		if (qtkit_session_bus_present())
			QDBusConnection::sessionBus().connect(
			    QStringLiteral("org.freedesktop.portal.Desktop"),
			    QStringLiteral("/org/freedesktop/portal/desktop"),
			    QStringLiteral("org.freedesktop.portal.Settings"),
			    QStringLiteral("SettingChanged"), this,
			    SLOT(changed(QString, QString, QDBusVariant)));
	}

private slots:
	void changed(const QString &space, const QString &key, const QDBusVariant &)
	{
		// The portal reports every setting on this desktop; one matters.
		if (space == QLatin1String("org.freedesktop.appearance") &&
		    key == QLatin1String("color-scheme"))
			m_theme->reapply();
	}

private:
	qtkit_theme *m_theme;
};

#endif
