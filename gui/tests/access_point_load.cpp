/*
 * access_point_load.cpp -- the access point dialog saves the passphrase
 * reference it loaded, provider and all.
 *
 * The reader took only the secret's name and the dialog put `@secret:` in
 * front of it, which is the file provider: an access point whose passphrase
 * lived in the keyring, in `pass` or behind a program was switched to a file
 * of the same name by pressing Save, and then failed to start for want of it
 * (10.628). So this writes one with `@secret:keyring:ap`, saves it through
 * the dialog with no change, and reads it back through a real daemon.
 *
 * HOW IT STOPS: one daemon, killed at the end; the wait for its socket is
 * bounded at ten seconds.
 */

#include "../src/access_point_dialog.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QLabel>
#include <QMetaObject>
#include <QProcess>
#include <QTemporaryDir>
#include <QThread>

#include <cstdio>

static int failures;

static void check(const QString &got, const QString &want, const char *what)
{
	const bool ok = got == want;
	fprintf(stderr, "access_point_load: %-50s %s\n", what, ok ? "ok" : "FAILED");
	if (!ok) {
		fprintf(stderr, "               expected: %s\n", qPrintable(want));
		fprintf(stderr, "               actual:   %s\n", qPrintable(got));
		failures++;
	}
}

/* A daemon over `body`, with `drop_in` as `conf.d/access-point-Home.conf`
 * -- the file the dialog's save replaces. */
static QString start(QProcess *daemon, const QString &work, const QString &body,
    const QString &drop_in)
{
	const QString etc = work + QStringLiteral("/etc");
	const QString run = work + QStringLiteral("/run");
	const QString wpa = work + QStringLiteral("/wpa");
	QDir().mkpath(etc + QStringLiteral("/conf.d"));
	QDir().mkpath(run);
	QDir().mkpath(wpa);

	QFile conf(etc + QStringLiteral("/netcfgd.conf"));
	if (!conf.open(QIODevice::WriteOnly)) {
		return QString();
	}
	conf.write(body.toUtf8());
	conf.close();
	if (!drop_in.isEmpty()) {
		QFile file(etc + QStringLiteral("/conf.d/access-point-Home.conf"));
		if (!file.open(QIODevice::WriteOnly)) {
			return QString();
		}
		file.write(drop_in.toUtf8());
	}

	QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
	environment.insert(QStringLiteral("NCFG_CONFIG_DIR"), etc);
	environment.insert(QStringLiteral("NCFG_RUN_DIR"), run);
	// The control directory too, or the daemon sweeps the host's (0224).
	environment.insert(QStringLiteral("NCFG_WPA_CTRL_DIR"), wpa);
	daemon->setProcessEnvironment(environment);
	daemon->start(QStringLiteral(NETCFGD_BINARY), { QStringLiteral("--no-apply-on-start") });

	const QString socket = run + QStringLiteral("/netcfgd.sock");
	QElapsedTimer waited;
	waited.start();
	while (!QFile::exists(socket) && waited.elapsed() < 10000) {
		QThread::msleep(50);
	}
	return QFile::exists(socket) ? socket : QString();
}

static void stop(QProcess *daemon)
{
	daemon->kill();
	daemon->waitForFinished(2000);
}

static QString credential_of(ncfg_connection *connection)
{
	QList<ncfg_access_point_config> points;
	QString                         error;
	if (!connection->access_points(&points, &error)) {
		return error;
	}
	return points.isEmpty() ? QStringLiteral("<none>") : points.first().credential;
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);

	if (!QFile::exists(QStringLiteral(NETCFGD_BINARY))) {
		fprintf(stderr, "access_point_load: skipping: %s is not built\n", NETCFGD_BINARY);
		return 0;
	}

	QTemporaryDir work;
	QProcess      daemon;
	const QString socket = start(&daemon, work.path(),
	    QStringLiteral("global { control { observe = \"any\"; admin = \"any\" } }\n"
	                   "interface wlan0 { config = \"192.168.50.1/24\" }\n"),
	    QStringLiteral("access_point \"Home\" {\n\tdevice = \"wlan0\"\n\tchannel = 36\n"
	                   "\twifi {\n\t\tpsk = \"@secret:keyring:ap\"\n\t}\n}\n"));
	ncfg_connection connection;
	QString         error;
	if (socket.isEmpty() || !connection.open(socket, &error)) {
		fprintf(stderr, "access_point_load: the daemon never started\n");
		stop(&daemon);
		return 1;
	}

	check(credential_of(&connection), QStringLiteral("@secret:keyring:ap"),
	    "the passphrase reads as the reference written, provider and all");

	QList<ncfg_access_point_config> points;
	connection.access_points(&points, &error);
	{
		ncfg_access_point_dialog dialog(&connection, points.value(0));
		QMetaObject::invokeMethod(&dialog, "submit");
		auto *note = dialog.findChild<QLabel *>(QStringLiteral("ap_note"));
		check(!dialog.outcome().isEmpty() ? QStringLiteral("saved")
		                                  : (note ? note->text() : QStringLiteral("<no note>")),
		    QStringLiteral("saved"), "the access point saves unchanged");
	}
	check(credential_of(&connection), QStringLiteral("@secret:keyring:ap"),
	    "  and still takes its passphrase from the keyring");
	stop(&daemon);

	fprintf(stderr, "access_point_load: %s\n", failures ? "FAILED" : "all checks passed");
	return failures ? 1 : 0;
}
