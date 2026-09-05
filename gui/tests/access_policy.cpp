/*
 * access_policy.cpp -- an editor has to load the value it edits.
 *
 * The access tab has three combo boxes, one per control tier, and `apply()`
 * sends all three. They were filled once in the constructor and left at index
 * 0 -- `root only` -- and nothing ever read the machine's policy into them. So
 * an operator who opened the tab to change `admin` alone sent
 * `set root root <their choice>` and reset the other two.
 *
 * Measured before the fix, on a machine whose policy was
 * `observe = any, wifi = any, admin = root`: changing only `admin` left every
 * non-root client locked out, this window included, with the note reporting
 * success. Recovery needed `sudo ncfg control set` from a terminal.
 *
 * So the property is not "the combos have items". It is that after a refresh
 * each combo carries what the daemon says is in force -- which is what makes
 * an Apply aimed at one tier leave the other two where they were.
 *
 * A real daemon, because the policy has to come from somewhere and the point
 * of the test is the socket round trip the old code did not make.
 */

#include "../src/access_view.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QComboBox>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QList>
#include <QProcess>
#include <QTemporaryDir>
#include <QThread>

#include <cstdio>

static int failures;

static void check(const QString &got, const QString &want, const char *what)
{
	const bool ok = got == want;
	fprintf(stderr, "access_policy: %-46s %s\n", what, ok ? "ok" : "FAILED");
	if (!ok) {
		fprintf(stderr, "                 expected: %s\n", qPrintable(want));
		fprintf(stderr, "                 actual:   %s\n", qPrintable(got));
		failures++;
	}
}

/* The data behind whatever a combo is showing, which is what `apply()` sends. */
static QString shown(const QWidget *view, const char *name)
{
	const auto boxes = view->findChildren<QComboBox *>(QString::fromLatin1(name));
	if (boxes.isEmpty()) {
		return QStringLiteral("<no such combo>");
	}
	return boxes.first()->currentData().toString();
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);

	/* Skipped loudly, the way `make gui` skips itself without qmake: this
	 * probe drives a real daemon, and the gui target does not build the Rust
	 * side. A machine that has not built it should say so rather than report a
	 * failure that is about the build. */
	if (!QFile::exists(QStringLiteral(NETCFGD_BINARY))) {
		fprintf(stderr, "access_policy: skipping: %s is not built\n", NETCFGD_BINARY);
		return 0;
	}

	QTemporaryDir work;
	if (!work.isValid()) {
		fprintf(stderr, "access_policy: no temporary directory\n");
		return 1;
	}
	const QString etc = work.filePath(QStringLiteral("etc"));
	const QString run = work.filePath(QStringLiteral("run"));
	QDir().mkpath(etc);
	QDir().mkpath(run);

	/* A policy that is not the combos' default in any of the three, so a view
	 * that failed to load would show `root` for all of them and be caught. */
	QFile conf(etc + QStringLiteral("/netcfgd.conf"));
	if (!conf.open(QIODevice::WriteOnly)) {
		fprintf(stderr, "access_policy: cannot write the configuration\n");
		return 1;
	}
	conf.write("global {\n\tcontrol {\n\t\tobserve = \"any\"\n"
	           "\t\twifi    = \"group:netcfgd\"\n\t\tadmin   = \"any\"\n\t}\n}\n");
	conf.close();

	QProcess daemon;
	QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
	environment.insert(QStringLiteral("NCFG_CONFIG_DIR"), etc);
	environment.insert(QStringLiteral("NCFG_RUN_DIR"), run);
	daemon.setProcessEnvironment(environment);
	daemon.start(QStringLiteral(NETCFGD_BINARY), { QStringLiteral("--no-apply-on-start") });

	const QString socket = run + QStringLiteral("/netcfgd.sock");
	QElapsedTimer waited;
	waited.start();
	while (!QFile::exists(socket) && waited.elapsed() < 10000) {
		app.processEvents();
		QThread::msleep(50);
	}
	if (!QFile::exists(socket)) {
		fprintf(stderr, "access_policy: the daemon never bound its socket\n");
		daemon.kill();
		daemon.waitForFinished(2000);
		return 1;
	}

	ncfg_connection connection;
	QString error;
	if (!connection.open(socket, &error)) {
		fprintf(stderr, "access_policy: cannot reach the daemon: %s\n", qPrintable(error));
		daemon.kill();
		daemon.waitForFinished(2000);
		return 1;
	}

	ncfg_access_view view(&connection);
	view.resize(480, 360);
	view.show();
	view.refresh();

	check(shown(&view, "access_observe"), QStringLiteral("any"),
	      "observe shows what the machine has");
	check(shown(&view, "access_wifi"), QStringLiteral("group:netcfgd"),
	      "wifi shows what the machine has");
	check(shown(&view, "access_admin"), QStringLiteral("any"),
	      "admin shows what the machine has");

	daemon.kill();
	daemon.waitForFinished(2000);

	fprintf(stderr, "access_policy: %s\n", failures ? "FAILED" : "all checks passed");
	return failures ? 1 : 0;
}
