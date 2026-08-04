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

#include <QApplication>
#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QMessageBox>

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
	window.show();
	return QApplication::exec();
}
