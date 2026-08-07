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

int main(int argc, char **argv)
{
	QApplication application(argc, argv);
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
	parser.process(application);

	ncfg_connection connection;
	QString error;
	if (!connection.open(parser.value(socket_option), &error)) {
		/* A window with an empty table would say the machine has no
		 * interfaces, which is a different and much worse claim than
		 * "netcfgd could not be reached". The message is the C layer's,
		 * which names the path and says the daemon has to be running.
		 */
		QMessageBox::critical(nullptr, QStringLiteral("netcfgd"), error);
		return 1;
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
	return QApplication::exec();
}
