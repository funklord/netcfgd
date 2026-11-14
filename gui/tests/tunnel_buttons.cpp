/*
 * tunnel_buttons.cpp -- the devices view brings an IPsec tunnel up and down.
 *
 * `ncfg tunnel up|down` (10.864) asks the daemon to have strongSwan initiate
 * or terminate what a tunnel's `xfrm` block names, and nothing in the window
 * could ask it. The devices view now has two buttons for it, enabled on an
 * `xfrm` row and on nothing else.
 *
 * A real daemon, as device_load starts one, with `NCFG_SWANCTL` naming a
 * script that records what it was asked -- as tests/live/ipsec_report.sh
 * does -- so what is checked is the whole path: the button, the client, the
 * socket, the daemon's judgement against the document, and the command it
 * starts. The daemon starts swanctl detached, so the record is waited for.
 *
 * HOW IT STOPS: one daemon, killed at the end; the wait for its socket is
 * bounded at ten seconds and each wait for the record at five.
 */

#include "../src/devices_view.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QProcess>
#include <QPushButton>
#include <QTableWidget>
#include <QTemporaryDir>
#include <QThread>

#include <cstdio>

static int failures;

static void check(const QString &got, const QString &want, const char *what)
{
	const bool ok = got == want;
	fprintf(stderr, "tunnel_buttons: %-56s %s\n", what, ok ? "ok" : "FAILED");
	if (!ok) {
		fprintf(stderr, "                 expected: %s\n", qPrintable(want));
		fprintf(stderr, "                 actual:   %s\n", qPrintable(got));
		failures++;
	}
}

static bool write_file(const QString &path, const QString &text)
{
	QFile file(path);
	if (!file.open(QIODevice::WriteOnly)) {
		return false;
	}
	file.write(text.toUtf8());
	return true;
}

/* The lines swanctl was run with that contain `want`, once one does or five
 * seconds have passed. */
static QString asked(const QString &log, const QString &want)
{
	QElapsedTimer waited;
	waited.start();
	for (;;) {
		QFile file(log);
		if (file.open(QIODevice::ReadOnly)) {
			const QString text = QString::fromUtf8(file.readAll()).trimmed();
			if (text.contains(want) || waited.elapsed() > 5000) {
				return text;
			}
		} else if (waited.elapsed() > 5000) {
			return QStringLiteral("<swanctl was not run>");
		}
		QThread::msleep(50);
	}
}

/* Select the row named `name`, as a click would. */
static bool select(QTableWidget *table, const QString &name)
{
	for (int row = 0; row < table->rowCount(); row++) {
		if (table->item(row, 0) && table->item(row, 0)->text() == name) {
			table->selectRow(row);
			return true;
		}
	}
	return false;
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);

	if (!QFile::exists(QStringLiteral(NETCFGD_BINARY))) {
		fprintf(stderr, "tunnel_buttons: skipping: %s is not built\n", NETCFGD_BINARY);
		return 0;
	}

	QTemporaryDir work;
	const QString etc = work.path() + QStringLiteral("/etc");
	const QString run = work.path() + QStringLiteral("/run");
	const QString wpa = work.path() + QStringLiteral("/wpa");
	const QString log = work.path() + QStringLiteral("/swanctl.log");
	const QString swanctl = work.path() + QStringLiteral("/swanctl");
	QDir().mkpath(etc);
	QDir().mkpath(run);
	QDir().mkpath(wpa);
	if (!write_file(etc + QStringLiteral("/netcfgd.conf"),
	        QStringLiteral("global { control { observe = \"any\"; wifi = \"any\" } }\n"
	                       "device ipsec0 {\n\txfrm { if_id = 7; connection = \"home\"; "
	                       "child = \"all\" }\n}\n"
	                       "device dum0 { kind = \"dummy\" }\n")) ||
	    !write_file(swanctl, QStringLiteral("#!/bin/sh\necho \"$*\" >> '%1'\n").arg(log)) ||
	    !QFile::setPermissions(swanctl, QFileDevice::ReadOwner | QFileDevice::WriteOwner |
	                                        QFileDevice::ExeOwner)) {
		fprintf(stderr, "tunnel_buttons: could not write the fixture\n");
		return 1;
	}

	QProcess daemon;
	QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
	environment.insert(QStringLiteral("NCFG_CONFIG_DIR"), etc);
	environment.insert(QStringLiteral("NCFG_RUN_DIR"), run);
	// The control directory too, or the daemon sweeps the host's (0224).
	environment.insert(QStringLiteral("NCFG_WPA_CTRL_DIR"), wpa);
	environment.insert(QStringLiteral("NCFG_SWANCTL"), swanctl);
	daemon.setProcessEnvironment(environment);
	daemon.start(QStringLiteral(NETCFGD_BINARY), { QStringLiteral("--no-apply-on-start") });

	const QString listening = run + QStringLiteral("/fuzznet.sock");
	QElapsedTimer waited;
	waited.start();
	while (!QFile::exists(listening) && waited.elapsed() < 10000) {
		QThread::msleep(50);
	}
	if (!QFile::exists(listening)) {
		fprintf(stderr, "tunnel_buttons: the daemon did not come up\n");
		daemon.kill();
		daemon.waitForFinished(2000);
		return 1;
	}

	ncfg_connection connection;
	QString error;
	if (!connection.open(run + QStringLiteral("/netcfgd.sock"), &error)) {
		fprintf(stderr, "tunnel_buttons: could not connect: %s\n", qPrintable(error));
		daemon.kill();
		daemon.waitForFinished(2000);
		return 1;
	}

	ncfg_devices_view view(&connection);
	QString said;
	QObject::connect(&view, &ncfg_devices_view::reported,
	    [&said](const QString &summary) { said = summary; });
	view.refresh();
	auto *table = view.findChild<QTableWidget *>();
	auto *up = view.findChild<QPushButton *>(QStringLiteral("tunnel_up"));
	auto *down = view.findChild<QPushButton *>(QStringLiteral("tunnel_down"));
	if (!table || !up || !down) {
		fprintf(stderr, "tunnel_buttons: the view has no table or no tunnel buttons\n");
		daemon.kill();
		daemon.waitForFinished(2000);
		return 1;
	}

	check(QString::fromLatin1(up->isEnabled() ? "enabled" : "disabled"),
	    QStringLiteral("disabled"), "with nothing selected, there is no tunnel to bring up");

	check(QString::fromLatin1(select(table, QStringLiteral("dum0")) ? "selected" : "absent"),
	    QStringLiteral("selected"), "a device that is not a tunnel is listed");
	check(QString::fromLatin1(up->isEnabled() || down->isEnabled() ? "enabled" : "disabled"),
	    QStringLiteral("disabled"), "  and offers neither button");

	check(QString::fromLatin1(select(table, QStringLiteral("ipsec0")) ? "selected" : "absent"),
	    QStringLiteral("selected"), "the tunnel is listed");
	check(QString::fromLatin1(up->isEnabled() && down->isEnabled() ? "enabled" : "disabled"),
	    QStringLiteral("enabled"), "  and offers both");

	up->click();
	check(said, QStringLiteral("asked strongSwan to bring ipsec0 up"),
	    "bring up says what it asked");
	check(asked(log, QStringLiteral("--initiate")),
	    QStringLiteral("--initiate --child all --ike home"),
	    "  and strongSwan is asked for the child of the connection");

	down->click();
	check(said, QStringLiteral("asked strongSwan to take ipsec0 down"),
	    "take down says what it asked");
	check(asked(log, QStringLiteral("--terminate")).section(QLatin1Char('\n'), -1),
	    QStringLiteral("--terminate --ike home"), "  and strongSwan is asked to end it");

	daemon.kill();
	daemon.waitForFinished(5000);

	if (failures) {
		fprintf(stderr, "tunnel_buttons: %d check(s) failed\n", failures);
		return 1;
	}
	fprintf(stderr, "tunnel_buttons: all checks passed\n");
	return 0;
}
