/*
 * reconnect.cpp -- a client whose daemon was restarted underneath it.
 *
 * WHY THIS EXISTS
 *   Every package upgrade restarts netcfgd, which closes every socket it had.
 *   A front end that keeps asking on the old one gets an error for ever, and
 *   what an operator sees is the program having broken. The TDE tray did
 *   exactly that: its `is_open()` tested whether a client had ever been made,
 *   which is true of a dead one, so `refresh()` never reopened -- and stuck on
 *   the no-daemon rung it drew that rung's icon, which was the missing one.
 *
 *   So: a real daemon, killed and started again on the same socket, with a
 *   connection that was open across the whole thing.
 */

#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QProcess>
#include <QProcessEnvironment>
#include <QTemporaryDir>
#include <QThread>

#include <cstdio>

static int failures;

static void check(bool condition, const char *what, const QString &detail = QString())
{
	fprintf(stderr, "reconnect: %-56s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		if (!detail.isEmpty()) {
			fprintf(stderr, "             %s\n", qPrintable(detail));
		}
		failures++;
	}
}

/* Start a daemon over `work`, and hand back its socket once it is listening. */
static QString start(QProcess *daemon, const QString &work)
{
	const QString etc = work + QStringLiteral("/etc");
	const QString run = work + QStringLiteral("/run");
	const QString wpa = work + QStringLiteral("/wpa");
	QDir().mkpath(etc);
	QDir().mkpath(run);
	QDir().mkpath(wpa);

	QFile conf(etc + QStringLiteral("/netcfgd.conf"));
	if (!conf.open(QIODevice::WriteOnly)) {
		return QString();
	}
	conf.write("global { control { observe = \"any\" } }\n");
	conf.close();

	QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
	environment.insert(QStringLiteral("NCFG_CONFIG_DIR"), etc);
	environment.insert(QStringLiteral("NCFG_RUN_DIR"), run);
	/* The control directory too: without it a daemon started here sweeps the
	 * running machine's wpa_supplicant sockets, which decision 0224 records
	 * and which `interface_load` learned the hard way. */
	environment.insert(QStringLiteral("NCFG_WPA_CTRL_DIR"), wpa);
	daemon->setProcessEnvironment(environment);
	daemon->start(QStringLiteral(NETCFGD_BINARY), { QStringLiteral("--no-apply-on-start") });

	const QString socket = run + QStringLiteral("/netcfgd.sock");
	QElapsedTimer waited;
	waited.start();
	/* Bounded, and the bound is what makes this safe to run unattended: a
	 * daemon that never binds ends the test rather than the day. */
	while (!QFile::exists(socket) && waited.elapsed() < 10000) {
		QThread::msleep(50);
	}
	return QFile::exists(socket) ? socket : QString();
}

static void stop(QProcess *daemon)
{
	daemon->kill();
	daemon->waitForFinished(5000);
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);

	if (!QFile::exists(QStringLiteral(NETCFGD_BINARY))) {
		fprintf(stderr, "reconnect: skipping: %s is not built\n", NETCFGD_BINARY);
		return 0;
	}

	QTemporaryDir work;
	QProcess first;
	const QString socket = start(&first, work.path());
	if (socket.isEmpty()) {
		fprintf(stderr, "reconnect: the daemon never bound its socket\n");
		stop(&first);
		return 1;
	}

	ncfg_connection connection;
	QString error;
	if (!connection.open(socket, &error)) {
		check(false, "the connection opens", error);
		stop(&first);
		return 1;
	}
	check(true, "the connection opens");

	QList<ncfg_link_row> links;
	check(connection.links(&links, &error), "and answers a question", error);
	check(connection.is_open(), "and says it is open");

	/* The upgrade, in one line. */
	stop(&first);
	QFile::remove(socket);

	check(!connection.links(&links, &error), "with the daemon gone, the question fails");
	/* **The half that was wrong.** A pointer test says this connection is fine
	 * -- a client was made and nothing set it back to zero -- and nothing ever
	 * reopens it again. */
	check(!connection.is_open(), "and the connection knows it is not open any more");

	QProcess second;
	const QString again = start(&second, work.path());
	if (again.isEmpty()) {
		check(false, "the daemon comes back");
		stop(&second);
		return 1;
	}
	check(true, "the daemon comes back");

	check(connection.reopen_if_broken(), "and the connection reopens itself");
	check(connection.is_open(), "which leaves it open again");
	check(connection.links(&links, &error), "and answering questions", error);
	/* Only where it died: a second call has nothing to do, and a client that
	 * reconnected on every refresh would open a socket per tick. */
	check(!connection.reopen_if_broken(), "while a connection that is fine is left alone");

	stop(&second);

	if (failures == 0) {
		fprintf(stderr, "reconnect: all checks passed\n");
	} else {
		fprintf(stderr, "reconnect: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
