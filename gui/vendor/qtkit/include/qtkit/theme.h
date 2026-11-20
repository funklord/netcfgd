// theme.h -- whether the desktop is dark, a dark palette for a program that
// should be, and following the desktop when it changes.
//
// Gathered from the five copies the workspace had written, the best part of
// each (project.md, *Where each part came from*):
//
//   - the consult order and the portal's bus gate from hydra;
//   - the desktop files read session first, from snurra and situ;
//   - one reader for both dialects (decimal triples and #rrggbb, in
//     [General] or [Palette]), and abstaining on identical colours, from
//     hydra;
//   - the dark palette from hydra, the one that sets the five shading roles
//     and a disabled highlight, with beerssh's BrightText;
//   - following a change from hydra and beerssh, with beerssh's guard
//     against re-applying what is already on screen;
//   - light restored as the style's own palette, not a hand-written one,
//     from hydra: a desktop's light theme is the user's.
//
// The consult order, the first source that answers:
//
//   1. the program's choice, where it is not "system";
//   2. an override variable the program names (`dark` or `light`);
//   3. Qt's own colour scheme -- unless qtkit set it, when it is our own
//      answer read back and says nothing about the desktop;
//   4. the freedesktop portal, only where the program links QtDBus AND
//      DBUS_SESSION_BUS_ADDRESS is non-empty: asking with no bus named
//      autolaunches a dbus-daemon nothing reaps;
//   5. the file a desktop with no dark status writes -- kdeglobals for TDE,
//      KDE 3 and KDE, lxqt.conf for LXQt -- the running session's first;
//   6. the palette Qt was given, window against window text.
//
// The palette is asked last because it always answers: on a desktop Qt is
// not integrated with it says light, and a file that says dark would never
// be read. A wrong dark is unreadable and a wrong light only plain, so where
// a source is unsure it abstains rather than guess.

#ifndef QTKIT_THEME_H
#define QTKIT_THEME_H

#include <QColor>
#include <QObject>
#include <QPalette>
#include <QString>
#include <QStringList>

class QApplication;

enum class qtkit_scheme { unknown, light, dark };

// What the person chose. `system` follows the desktop and is the default:
// store it as the key's absence, so a later default reaches them
// (working-practice.md, *A config file records choices*).
enum class qtkit_choice { system, light, dark };

// A background against its own foreground: darker is dark. Unknown when
// either is invalid or the two are the same.
qtkit_scheme qtkit_scheme_of(const QColor &background, const QColor &foreground);

// The first of `paths` that states a window background and foreground, in
// either dialect; unknown when none does.
qtkit_scheme qtkit_scheme_from_files(const QStringList &paths);

// The portal's answer: 1 dark, 2 light, 0 no preference, -1 did not answer.
// `asked` is set where the bus connection is about to be made, so a test can
// tell "abstained without touching the bus" from "asked and got nothing".
int qtkit_portal_scheme(bool *asked = nullptr);

// What the desktop says, by sources 2 to 6 above.
qtkit_scheme qtkit_desktop_scheme(const char *override_variable = nullptr);

QPalette qtkit_dark_palette();

// "dark", "light", "unknown"; and "system", "light", "dark" for a choice,
// read back leniently: anything else is "system".
QString qtkit_scheme_name(qtkit_scheme scheme);
QString qtkit_choice_name(qtkit_choice choice);
qtkit_choice qtkit_choice_from_name(const QString &name);

// Applies the scheme to the application and keeps it applied: Qt's own
// change signal and the portal's are followed, and a change of choice is
// applied at once. One per application, made after the QApplication and
// before the first window is shown.
class qtkit_theme : public QObject {
	Q_OBJECT

public:
	explicit qtkit_theme(QApplication &application,
	                     qtkit_choice choice = qtkit_choice::system,
	                     const char *override_variable = nullptr);

	void set_choice(qtkit_choice choice);
	qtkit_choice choice() const { return m_choice; }

	// What is on screen now.
	qtkit_scheme applied() const { return m_applied; }

	// The scheme this choice resolves to now, without applying it.
	qtkit_scheme resolve() const;

public slots:
	// Ask again and apply if the answer changed. Cheap when it has not.
	void reapply();

signals:
	void applied_changed(qtkit_scheme scheme);

private:
	void apply(qtkit_scheme scheme);

	QApplication &m_application;
	qtkit_choice m_choice;
	const char *m_override;
	qtkit_scheme m_applied = qtkit_scheme::unknown;
	bool m_told_qt = false;
	bool m_applying = false;
};

// The one line a program needs: a qtkit_theme owned by the application,
// following the desktop.
qtkit_theme *qtkit_follow_desktop(QApplication &application,
                                  const char *override_variable = nullptr);

#endif
