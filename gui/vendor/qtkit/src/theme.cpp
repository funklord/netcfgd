// theme.cpp -- see include/qtkit/theme.h.

#include "qtkit/theme.h"

#include <QApplication>
#include <QDir>
#include <QFile>
#include <QGuiApplication>
#include <QStyle>
#include <QStyleFactory>
#include <QStyleHints>
#include <QTextStream>

// The portal, where QtDBus is there to ask it with (qtkit.pri for qmake).
/// @pkg_optional Qt6DBus defines QTKIT_HAVE_DBUS
#ifdef QTKIT_HAVE_DBUS
#include <QDBusConnection>
#include <QDBusInterface>
#include <QDBusReply>
#include <QDBusVariant>

#include "portal_listener.h"
#endif

namespace {

// Rec. 709 luma. Any correct luminance answers a background against its own
// foreground, the two being far apart in any scheme one can read
// (qt-desktop-integration, settled 2026-09-01).
double luma(const QColor &colour)
{
	return 0.2126 * colour.redF() + 0.7152 * colour.greenF() +
	       0.0722 * colour.blueF();
}

// "0,42,78" as TDE and KDE write a colour, or "#232323" as LXQt does. Both
// spellings are read wherever they appear: they state the same thing.
QColor colour_from(const QString &text)
{
	const QString value = text.trimmed();
	if (value.startsWith(QLatin1Char('#'))) {
		if (value.size() != 7)
			return QColor();
		bool number = false;
		const uint rgb = value.mid(1).toUInt(&number, 16);
		return number ? QColor((rgb >> 16) & 0xff, (rgb >> 8) & 0xff, rgb & 0xff)
		              : QColor();
	}
	const QStringList parts = value.split(QLatin1Char(','));
	if (parts.size() != 3)
		return QColor();
	int rgb[3];
	for (int i = 0; i < 3; ++i) {
		bool number = false;
		rgb[i] = parts.at(i).trimmed().toInt(&number);
		if (!number || rgb[i] < 0 || rgb[i] > 255)
			return QColor();
	}
	return QColor(rgb[0], rgb[1], rgb[2]);
}

// One file's answer. Sections matter: the same key names appear in
// per-application sections, and the last one read would answer about some
// other program's colours. A file over a megabyte is not a desktop's
// settings and is not read.
qtkit_scheme scheme_from_file(const QString &path)
{
	QFile file(path);
	if (!file.open(QIODevice::ReadOnly | QIODevice::Text) ||
	    file.size() > 1024 * 1024)
		return qtkit_scheme::unknown;
	QTextStream in(&file);
	QString section;
	QColor background, foreground;
	while (!in.atEnd()) {
		const QString line = in.readLine().trimmed();
		if (line.startsWith(QLatin1Char('[')) && line.endsWith(QLatin1Char(']'))) {
			section = line.mid(1, line.size() - 2);
			continue;
		}
		const bool general =
		    section.compare(QLatin1String("General"), Qt::CaseInsensitive) == 0;
		const bool palette =
		    section.compare(QLatin1String("Palette"), Qt::CaseInsensitive) == 0;
		const qsizetype equals = line.indexOf(QLatin1Char('='));
		if ((!general && !palette) || equals <= 0)
			continue;
		const QString key = line.left(equals).trimmed();
		const QString value = line.mid(equals + 1);
		// TDE, KDE 3 and KDE: [General]. LXQt: [Palette].
		const QLatin1String back(general ? "windowBackground" : "window_color");
		const QLatin1String fore(general ? "windowForeground" : "window_text_color");
		if (key.compare(back, Qt::CaseInsensitive) == 0)
			background = colour_from(value);
		else if (key.compare(fore, Qt::CaseInsensitive) == 0)
			foreground = colour_from(value);
	}
	return qtkit_scheme_of(background, foreground);
}

QString home_or(const char *variable, const QString &fallback)
{
	const QString set = qEnvironmentVariable(variable);
	return set.isEmpty() ? fallback : set;
}

// The desktop files, the running session's first: on a machine with both
// TDE and LXQt installed, an old file of the other desktop says nothing
// about this one. With no session named, any desktop's file is still
// better evidence than the palette.
qtkit_scheme from_desktop_files()
{
	const QString home = QDir::homePath();
	const QString config = home_or("XDG_CONFIG_HOME", home + QStringLiteral("/.config"));
	const QString trinity = home_or("TDEHOME", home + QStringLiteral("/.trinity"))
	                        + QStringLiteral("/share/config/kdeglobals");
	const QString kde3 = home_or("KDEHOME", home + QStringLiteral("/.kde"))
	                     + QStringLiteral("/share/config/kdeglobals");
	const QString kde = config + QStringLiteral("/kdeglobals");
	// LXQt writes the APPLIED palette here, under [Palette]; the files under
	// its palettes/ directory are a library nothing marks as in use.
	const QString lxqt = config + QStringLiteral("/lxqt/lxqt.conf");

	const QString desktop = qEnvironmentVariable("XDG_CURRENT_DESKTOP").toUpper();
	QStringList session;
	if (desktop.contains(QLatin1String("TDE")))
		session << trinity;
	if (desktop.contains(QLatin1String("KDE")))
		session << kde << kde3;
	if (desktop.contains(QLatin1String("LXQT")))
		session << lxqt;
	if (!session.isEmpty())
		return qtkit_scheme_from_files(session);
	if (desktop.isEmpty())
		return qtkit_scheme_from_files({trinity, kde, kde3, lxqt});
	return qtkit_scheme::unknown;
}

qtkit_scheme from_portal()
{
	switch (qtkit_portal_scheme()) {
	case 1:
		return qtkit_scheme::dark;
	case 2:
		return qtkit_scheme::light;
	default:
		// 0 is "no preference" and -1 "did not answer"; neither is a
		// preference, so both fall through to the files.
		return qtkit_scheme::unknown;
	}
}

qtkit_scheme from_qt_hint()
{
	const QStyleHints *hints = QGuiApplication::styleHints();
	switch (hints ? hints->colorScheme() : Qt::ColorScheme::Unknown) {
	case Qt::ColorScheme::Dark:
		return qtkit_scheme::dark;
	case Qt::ColorScheme::Light:
		return qtkit_scheme::light;
	default:
		return qtkit_scheme::unknown;
	}
}

qtkit_scheme from_override(const char *variable)
{
	if (!variable)
		return qtkit_scheme::unknown;
	const QByteArray asked = qgetenv(variable).trimmed().toLower();
	if (asked == "dark")
		return qtkit_scheme::dark;
	if (asked == "light")
		return qtkit_scheme::light;
	return qtkit_scheme::unknown;
}

// Sources 2 to 6, with the Qt hint skipped when it is our own answer.
qtkit_scheme desktop_scheme(const char *override_variable, bool hint_is_ours)
{
	for (qtkit_scheme said : {from_override(override_variable),
	                          hint_is_ours ? qtkit_scheme::unknown : from_qt_hint()})
		if (said != qtkit_scheme::unknown)
			return said;
	if (const qtkit_scheme said = from_portal(); said != qtkit_scheme::unknown)
		return said;
	if (const qtkit_scheme said = from_desktop_files(); said != qtkit_scheme::unknown)
		return said;
	const QPalette given = QGuiApplication::palette();
	return qtkit_scheme_of(given.color(QPalette::Window),
	                       given.color(QPalette::WindowText));
}


}

qtkit_scheme qtkit_scheme_of(const QColor &background, const QColor &foreground)
{
	if (!background.isValid() || !foreground.isValid())
		return qtkit_scheme::unknown;
	const double back = luma(background), fore = luma(foreground);
	if (back < fore)
		return qtkit_scheme::dark;
	if (back > fore)
		return qtkit_scheme::light;
	return qtkit_scheme::unknown;
}

qtkit_scheme qtkit_scheme_from_files(const QStringList &paths)
{
	for (const QString &path : paths)
		if (const qtkit_scheme said = scheme_from_file(path);
		    said != qtkit_scheme::unknown)
			return said;
	return qtkit_scheme::unknown;
}

#ifdef QTKIT_HAVE_DBUS
int qtkit_portal_scheme(bool *asked)
{
	if (asked)
		*asked = false;
	if (!qtkit_session_bus_present())
		return -1;
	if (asked)
		*asked = true;
	QDBusInterface portal(QStringLiteral("org.freedesktop.portal.Desktop"),
	                      QStringLiteral("/org/freedesktop/portal/desktop"),
	                      QStringLiteral("org.freedesktop.portal.Settings"),
	                      QDBusConnection::sessionBus());
	if (!portal.isValid())
		return -1;
	const QDBusReply<QDBusVariant> reply =
	    portal.call(QStringLiteral("Read"),
	                QStringLiteral("org.freedesktop.appearance"),
	                QStringLiteral("color-scheme"));
	if (!reply.isValid())
		return -1;
	// The portal wraps the value twice: a variant holding a variant.
	QVariant value = reply.value().variant();
	if (value.canConvert<QDBusVariant>())
		value = value.value<QDBusVariant>().variant();
	bool number = false;
	const int scheme = value.toInt(&number);
	return number ? scheme : -1;
}
#else
int qtkit_portal_scheme(bool *asked)
{
	if (asked)
		*asked = false;
	return -1;
}
#endif

qtkit_scheme qtkit_desktop_scheme(const char *override_variable)
{
	return desktop_scheme(override_variable, false);
}

QPalette qtkit_dark_palette()
{
	// Written out rather than derived from the palette Qt handed over, which
	// differs between a Fusion session, a GTK-themed one and Android, so the
	// same choice would look three ways.
	QPalette dark;
	const QColor window(0x2b, 0x2b, 0x2e);
	const QColor base(0x1f, 0x1f, 0x22);
	const QColor text(0xe6, 0xe6, 0xe6);
	const QColor dim(0x9a, 0x9a, 0xa0);
	const QColor accent(0x3d, 0x7e, 0xb8);
	dark.setColor(QPalette::Window, window);
	dark.setColor(QPalette::WindowText, text);
	dark.setColor(QPalette::Base, base);
	dark.setColor(QPalette::AlternateBase, QColor(0x26, 0x26, 0x2a));
	dark.setColor(QPalette::Text, text);
	dark.setColor(QPalette::Button, window);
	dark.setColor(QPalette::ButtonText, text);
	dark.setColor(QPalette::BrightText, QColor(0xff, 0x6b, 0x6b));
	dark.setColor(QPalette::ToolTipBase, base);
	dark.setColor(QPalette::ToolTipText, text);
	dark.setColor(QPalette::Highlight, accent);
	dark.setColor(QPalette::HighlightedText, Qt::white);
	dark.setColor(QPalette::Link, QColor(0x6f, 0xb2, 0xe8));
	dark.setColor(QPalette::LinkVisited, QColor(0xa9, 0x8f, 0xd6));
	dark.setColor(QPalette::PlaceholderText, dim);
	// The five roles a style shades frames, headers, splitters and tab bars
	// with. Left at a light desktop's values they drew near-white grounds
	// under near-white text in hydra. Derived from the window so they keep
	// Qt's order: Light > Midlight > Button > Mid > Dark > Shadow.
	dark.setColor(QPalette::Light, window.lighter(160));
	dark.setColor(QPalette::Midlight, window.lighter(130));
	dark.setColor(QPalette::Mid, window.darker(130));
	dark.setColor(QPalette::Dark, window.darker(160));
	dark.setColor(QPalette::Shadow, window.darker(300));
	// Disabled for every role that uses it, or a greyed control keeps full
	// contrast and stops looking greyed.
	dark.setColor(QPalette::Disabled, QPalette::WindowText, dim);
	dark.setColor(QPalette::Disabled, QPalette::Text, dim);
	dark.setColor(QPalette::Disabled, QPalette::ButtonText, dim);
	dark.setColor(QPalette::Disabled, QPalette::Highlight, QColor(0x3a, 0x3a, 0x40));
	dark.setColor(QPalette::Disabled, QPalette::HighlightedText, dim);
	return dark;
}

QString qtkit_scheme_name(qtkit_scheme scheme)
{
	switch (scheme) {
	case qtkit_scheme::dark:
		return QStringLiteral("dark");
	case qtkit_scheme::light:
		return QStringLiteral("light");
	default:
		return QStringLiteral("unknown");
	}
}

QString qtkit_choice_name(qtkit_choice choice)
{
	switch (choice) {
	case qtkit_choice::dark:
		return QStringLiteral("dark");
	case qtkit_choice::light:
		return QStringLiteral("light");
	default:
		return QStringLiteral("system");
	}
}

qtkit_choice qtkit_choice_from_name(const QString &name)
{
	const QString word = name.trimmed().toLower();
	if (word == QLatin1String("dark"))
		return qtkit_choice::dark;
	if (word == QLatin1String("light"))
		return qtkit_choice::light;
	return qtkit_choice::system;
}

qtkit_theme::qtkit_theme(QApplication &application, qtkit_choice choice,
                         const char *override_variable)
    : QObject(&application), m_application(application), m_choice(choice),
      m_override(override_variable)
{
	// Our own setColorScheme raises this too; reapply() ignores it then.
	if (QStyleHints *hints = QGuiApplication::styleHints())
		connect(hints, &QStyleHints::colorSchemeChanged, this,
		        &qtkit_theme::reapply);
#ifdef QTKIT_HAVE_DBUS
	new portal_listener(this);
#endif
	reapply();
}

void qtkit_theme::set_choice(qtkit_choice choice)
{
	m_choice = choice;
	reapply();
}

qtkit_scheme qtkit_theme::resolve() const
{
	switch (m_choice) {
	case qtkit_choice::dark:
		return qtkit_scheme::dark;
	case qtkit_choice::light:
		return qtkit_scheme::light;
	default:
		return desktop_scheme(m_override, m_told_qt);
	}
}

void qtkit_theme::reapply()
{
	if (m_applying)
		return;
	const qtkit_scheme want = resolve();
	// Repainting every widget is not free, a desktop that sends several
	// notices for one change is ordinary, and setPalette raises the very
	// event a platform may report a system change through.
	if (want == m_applied)
		return;
	apply(want);
	m_applied = want;
	emit applied_changed(want);
}

void qtkit_theme::apply(qtkit_scheme scheme)
{
	m_applying = true;
	if (scheme == qtkit_scheme::dark) {
		// Fusion draws every control from the palette; a native style may
		// not, and would leave light buttons on the dark ground.
		if (QStyle *fusion = QStyleFactory::create(QStringLiteral("Fusion")))
			m_application.setStyle(fusion);
		m_application.setPalette(qtkit_dark_palette());
	} else if (m_applied == qtkit_scheme::dark) {
		// Back to what the style would choose on its own, not a hand-written
		// light: a desktop's light theme is the user's.
		m_application.setPalette(m_application.style()->standardPalette());
	}
#if QT_VERSION >= QT_VERSION_CHECK(6, 8, 0)
	// Told as well, so Qt's own dialogs and anything that asks it rather
	// than the palette agree. Read back, this is our answer and not the
	// desktop's, so resolve() then skips the hint (m_told_qt).
	if (QStyleHints *hints = QGuiApplication::styleHints()) {
		if (scheme == qtkit_scheme::unknown) {
			hints->unsetColorScheme();
			m_told_qt = false;
		} else {
			hints->setColorScheme(scheme == qtkit_scheme::dark
			                          ? Qt::ColorScheme::Dark
			                          : Qt::ColorScheme::Light);
			m_told_qt = true;
		}
	}
#endif
	m_applying = false;
}

qtkit_theme *qtkit_follow_desktop(QApplication &application,
                                  const char *override_variable)
{
	return new qtkit_theme(application, qtkit_choice::system, override_variable);
}

