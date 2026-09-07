/*
 * main.cpp -- start, connect, show.
 *
 * The one argument is the socket, because the first thing an operator does
 * with a client that can reach more than one machine is point it at a
 * different one. Everything else the connection resolves for itself, through
 * the same rules `ncfg` uses -- two clients that disagreed about which daemon
 * they meant would be a bad hour for somebody.
 */
#include "main_window.h"
#include "ncfg_connection.h"
#include "tray.h"

#include <QApplication>
#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QMessageBox>

#include <cstdio>

#ifdef NETCFGD_QTTY
#  include <QFileInfo>
#  include <qtty/qtty.h>
#  include <unistd.h>

/*
 * Which frontend, decided before QApplication exists.
 *
 * `Qtty::prepare_environment()` sets QT_QPA_PLATFORM and QApplication reads
 * that in its constructor, so this cannot wait for QCommandLineParser -- the
 * parser needs an application. The flags are registered with the parser too,
 * further down, or it would reject the one that got us here.
 */
static bool want_tui(int argc, char **argv)
{
	/* Policy builds: a package that must carry only one frontend. They trim
	 * *code paths*, never libraries -- the TUI is these QWidgets on a
	 * character grid, so libQt6Widgets is linked either way. Honoured here
	 * because qtty defines them and netcfgd did not read them, which made a
	 * `DEFINES+=QTTY_NO_GUI` build byte-for-byte identical to a plain one:
	 * the variant existed in the compiler's arguments and nowhere else. */
#if defined(QTTY_NO_TUI)
	(void)argc;
	(void)argv;
	return false;
#elif defined(QTTY_NO_GUI)
	(void)argc;
	(void)argv;
	return true;
#else
	for (int i = 1; i < argc; ++i) {
		if (!qstrcmp(argv[i], "--tui"))
			return true;
		if (!qstrcmp(argv[i], "--gui"))
			return false;
	}
	/* Invoked through a -tui symlink, which is how a terminal-only command
	 * name is given to somebody who should not have to remember a flag. */
	if (QFileInfo(QString::fromLocal8Bit(argv[0])).fileName().endsWith(
	        QStringLiteral("-tui")))
		return true;
	/* Otherwise: a session with no display, on a terminal, wants the TUI.
	 * Both halves matter -- a GUI session running this from a terminal
	 * emulator has a display and should get the window. */
	const bool display = qEnvironmentVariableIsSet("WAYLAND_DISPLAY")
	                  || qEnvironmentVariableIsSet("DISPLAY");
	return !display && isatty(1);
#endif
}
#endif

int main(int argc, char **argv)
{
#ifdef NETCFGD_QTTY
	const bool tui = want_tui(argc, argv);
	if (tui)
		Qtty::prepare_environment();
#endif
	QApplication application(argc, argv);
#ifdef NETCFGD_QTTY
	/* Before any widget is constructed: setup() settles the font and style,
	 * and the shared UI derives its metrics from them. After a widget exists
	 * it is too late for that widget. */
	if (tui)
		Qtty::setup(application);
#endif
	QApplication::setApplicationName(QStringLiteral("netcfgd-gui"));

	QCommandLineParser parser;
	parser.setApplicationDescription(
	    QStringLiteral("A client for netcfgd. Shows what the machine is doing, what "
	               "would change and why, and what has happened since you looked. "
	               "Changes nothing without showing the plan first."));
	parser.addHelpOption();
	QCommandLineOption socket_option(
	    QStringList() << QStringLiteral("socket"),
	    QStringLiteral("The daemon's control socket. Defaults to $NCFG_RUN_DIR or the "
	               "installed location."),
	    QStringLiteral("path"));
	parser.addOption(socket_option);
	QCommandLineOption tray_option(
	    QStringList() << QStringLiteral("tray"),
	    QStringLiteral("Start in the notification area with no window. Closing the window "
	               "then hides it rather than quitting."));
	parser.addOption(tray_option);
#ifdef NETCFGD_QTTY
	/* Registered so the parser accepts them; `want_tui` has already read
	 * them, because the frontend is decided before an application exists. */
	QCommandLineOption tui_option(
	    QStringList() << QStringLiteral("tui"),
	    QStringLiteral("Render on the terminal instead of the desktop. The same "
	               "windows, drawn on a character grid."));
	parser.addOption(tui_option);
	QCommandLineOption gui_option(
	    QStringList() << QStringLiteral("gui"),
	    QStringLiteral("Force the desktop frontend even with no display."));
	parser.addOption(gui_option);
#endif
	parser.process(application);

	ncfg_connection connection;
	QString error;
	/* **Retry rather than exit**, because the thing to do about this happens
	 * in another window. The dialog names the commands (the C layer's message
	 * does), and every one of them ends with netcfgd running -- so quitting
	 * here means the operator starts the daemon and then has to find this
	 * program again. Reported as "I always have to mess around to start it
	 * when NM is running", which is that round trip.
	 *
	 * A window with an empty table is still refused: it would say the machine
	 * has no interfaces, which is a different and much worse claim than
	 * "netcfgd could not be reached". So this loops on the dialog rather than
	 * opening the window unconnected.
	 *
	 * `Retry` is the default button, since somebody who has just read the
	 * message is about to act on it. Cancel is what closing the dialog does,
	 * so there is no way to dismiss it into a window that would lie. */
	while (!connection.open(parser.value(socket_option), &error)) {
		QMessageBox box(QMessageBox::Critical, QStringLiteral("netcfgd"), error,
		            QMessageBox::Retry | QMessageBox::Cancel);
		box.setDefaultButton(QMessageBox::Retry);
		if (box.exec() != QMessageBox::Retry) {
			return 1;
		}
	}

	ncfg_main_window window(&connection);

	/* Returns nullptr where the desktop has no status-notifier host, which is
	 * ordinary rather than an error: the window then behaves exactly as it did
	 * before this existed. */
	ncfg_tray *tray = ncfg_tray::create(&connection, &window);
	const bool wanted_tray = parser.isSet(tray_option);
	if (tray) {
		window.attach_tray(tray);
	} else if (wanted_tray) {
		/* Asked for something the desktop cannot give. Complained about on
		 * stderr and then carried on with a window, which is the daemon's own
		 * convention for a policy it cannot honour: say so loudly, do the
		 * safe thing, do not stop.
		 *
		 * Deliberately not a modal dialog. This is launched from a command
		 * line, the message is for whoever typed the flag, and a box that
		 * blocks startup until somebody clicks it is worse than the situation
		 * it is reporting -- especially on the machines with no tray, which
		 * are the ones most likely to have nobody sitting in front of them.
		 */
		fputs("netcfgd-gui: this desktop has no notification area, so --tray has "
		      "nothing to start in; showing the window instead\n",
		      stderr);
	}

	/* Quitting is the tray's business once there is one: a window that closed
	 * the last visible thing while an icon remained would leave a process
	 * nobody can reach. */
	QApplication::setQuitOnLastWindowClosed(!(tray && wanted_tray));

	if (!tray || !wanted_tray) {
		window.show();
	}
#ifdef NETCFGD_QTTY
	/* Qtty::exec drives the terminal backend and needs the top-level widget;
	 * QApplication::exec would run an event loop with nothing drawing. */
	if (tui)
		return Qtty::exec(application, window);
#endif
	return QApplication::exec();
}
