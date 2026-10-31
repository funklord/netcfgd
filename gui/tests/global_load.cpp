/*
 * global_load.cpp -- the global tab pins the country, and unpins it.
 *
 * 0296: a machine follows the country its radios hear unless one is pinned.
 * The tab writes the pin to its own drop-in so that unpinning is removing the
 * file, and this drives both through a real daemon: pinned, the document
 * says so; unpinned, it says nothing and the machine follows again.
 *
 * HOW IT STOPS: one daemon, killed at the end; the wait for its socket is
 * bounded at ten seconds.
 */

#include "../src/global_view.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QLineEdit>
#include <QMetaObject>
#include <QProcess>
#include <QTemporaryDir>
#include <QThread>

#include <cstdio>

static int failures;

static void check(const QString &got, const QString &want, const char *what)
{
	const bool ok = got == want;
	fprintf(stderr, "global_load: %-56s %s\n", what, ok ? "ok" : "FAILED");
	if (!ok) {
		fprintf(stderr, "               expected: %s\n", qPrintable(want));
		fprintf(stderr, "               actual:   %s\n", qPrintable(got));
		failures++;
	}
}

/* A daemon over `body`; `drop_in`, where not empty, as `conf.d/other.conf`. */
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
		QFile file(etc + QStringLiteral("/conf.d/other.conf"));
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

static QString country_of(ncfg_connection *connection)
{
	ncfg_globals globals;
	QString      error;
	if (!connection->globals(&globals, &error)) {
		return error;
	}
	return globals.regdom.isEmpty() ? QStringLiteral("<follows>") : globals.regdom;
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);

	if (!QFile::exists(QStringLiteral(NETCFGD_BINARY))) {
		fprintf(stderr, "global_load: skipping: %s is not built\n", NETCFGD_BINARY);
		return 0;
	}

	QTemporaryDir work;
	QProcess      daemon;
	const QString socket = start(&daemon, work.path(),
	    QStringLiteral("global { control { observe = \"any\"; admin = \"any\" } }\n"),
	    QString());
	ncfg_connection connection;
	QString         error;
	if (socket.isEmpty() || !connection.open(socket, &error)) {
		fprintf(stderr, "global_load: the daemon never started\n");
		stop(&daemon);
		return 1;
	}

	check(country_of(&connection), QStringLiteral("<follows>"), "a machine with no pin follows");

	ncfg_global_view view(&connection);
	view.refresh();
	auto *country = view.findChild<QLineEdit *>(QStringLiteral("global_country"));
	country->setText(QStringLiteral("se"));
	QMetaObject::invokeMethod(&view, "set_country");
	check(country_of(&connection), QStringLiteral("SE"), "a country typed is pinned, in capitals");
	check(country->text(), QStringLiteral("SE"), "  and the field shows the pin");

	country->setText(QStringLiteral("1"));
	QMetaObject::invokeMethod(&view, "set_country");
	check(country_of(&connection), QStringLiteral("SE"), "one character is not a country");

	country->setText(QString());
	QMetaObject::invokeMethod(&view, "set_country");
	check(country_of(&connection), QStringLiteral("<follows>"), "a blank unpins it");
	check(QFile::exists(work.path() + QStringLiteral("/etc/conf.d/50-regdom.conf"))
	        ? QStringLiteral("left") : QStringLiteral("removed"),
	    QStringLiteral("removed"), "  by removing the drop-in");
	stop(&daemon);

	fprintf(stderr, "global_load: %s\n", failures ? "FAILED" : "all checks passed");
	return failures ? 1 : 0;
}
