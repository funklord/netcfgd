/*
 * dns_tab.cpp -- the DNS tab writes the global servers and search domains.
 *
 * The inventory the holder asked for (project.md 10.895) found the global
 * `dns { servers, search }` had no control in the window: the tab set the
 * mode alone. It writes all three into its one file now. What is checked is
 * the round trip through a real daemon: what is typed is compiled back as
 * typed, a value that could leave its string is refused before anything is
 * written, and pressing set again without touching the fields changes
 * nothing.
 *
 * HOW IT STOPS: one daemon, killed at the end; the wait for its socket is
 * bounded at ten seconds.
 */

#include "../src/dns_view.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QComboBox>
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
	fprintf(stderr, "dns_tab: %-60s %s\n", what, ok ? "ok" : "FAILED");
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
	const QString listening = run + QStringLiteral("/fuzznet.sock");
	QElapsedTimer waited;
	waited.start();
	while (!QFile::exists(listening) && waited.elapsed() < 10000) {
		QThread::msleep(50);
	}
	return QFile::exists(listening) ? socket : QString();
}

static void stop(QProcess *daemon)
{
	daemon->kill();
	daemon->waitForFinished(2000);
}

static QString dns_of(ncfg_connection *connection)
{
	ncfg_dns_row row;
	QString      error;
	if (!connection->dns(&row, &error)) {
		return error;
	}
	return QStringLiteral("%1 | %2 | %3")
	    .arg(row.mode, row.servers.join(QLatin1Char(',')), row.search.join(QLatin1Char(',')));
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);

	if (!QFile::exists(QStringLiteral(NETCFGD_BINARY))) {
		fprintf(stderr, "dns_tab: skipping: %s is not built\n", NETCFGD_BINARY);
		return 0;
	}

	QTemporaryDir work;
	QProcess      daemon;
	const QString socket = start(&daemon, work.path(),
	    QStringLiteral("global { control { root = \"any\" } }\n"), QString());
	ncfg_connection connection;
	QString         error;
	if (socket.isEmpty() || !connection.open(socket, &error)) {
		fprintf(stderr, "dns_tab: the daemon never started\n");
		daemon.kill();
		daemon.waitForFinished(2000);
		return 1;
	}

	ncfg_dns_view view(&connection);
	view.refresh();
	auto *servers = view.findChild<QLineEdit *>(QStringLiteral("dns_servers"));
	auto *search = view.findChild<QLineEdit *>(QStringLiteral("dns_search"));
	const QString file = work.path() + QStringLiteral("/etc/conf.d/50-dns.conf");

	servers->setText(QStringLiteral("9.9.9.9, 2620:fe::fe"));
	search->setText(QStringLiteral("home.example"));
	QMetaObject::invokeMethod(&view, "apply_mode");
	check(dns_of(&connection), QStringLiteral("none | 9.9.9.9,2620:fe::fe | home.example"),
	    "servers and a search domain are written and compiled back");

	/* Pressing set again with what refresh loaded changes nothing. */
	view.refresh();
	QMetaObject::invokeMethod(&view, "apply_mode");
	check(dns_of(&connection), QStringLiteral("none | 9.9.9.9,2620:fe::fe | home.example"),
	    "set again untouched writes the same");

	/* A quote would close the string and write configuration nobody typed
	 * as such: refused here, and the file is what it was. */
	QFile before_file(file);
	const QByteArray before = before_file.open(QIODevice::ReadOnly) ? before_file.readAll()
	                                                                : QByteArray();
	before_file.close();
	servers->setText(QStringLiteral("9.9.9.9\" ]\n"));
	QMetaObject::invokeMethod(&view, "apply_mode");
	QFile after_file(file);
	const QByteArray after = after_file.open(QIODevice::ReadOnly) ? after_file.readAll()
	                                                              : QByteArray("<gone>");
	check(after == before ? QStringLiteral("unchanged") : QString::fromUtf8(after),
	    QStringLiteral("unchanged"), "a server that could leave its string is refused");

	/* Blank fields write none: the servers go with the text. */
	servers->clear();
	search->clear();
	QMetaObject::invokeMethod(&view, "apply_mode");
	check(dns_of(&connection), QStringLiteral("none |  | "), "blank fields leave none");

	daemon.kill();
	daemon.waitForFinished(5000);

	/* A block holding what the tab cannot write back is refused rather than
	 * saved without it. Its own directory: the first daemon's socket file is
	 * still in the first. */
	QTemporaryDir other;
	QProcess      second;
	const QString other_socket = start(&second, other.path(),
	    QStringLiteral("global { control { root = \"any\" } }\n"),
	    QStringLiteral("global { dns {\n\tmode = \"resolved\"\n\tdomains = [\"corp.example\"]\n} }\n"));
	ncfg_connection other_connection;
	if (other_socket.isEmpty() || !other_connection.open(other_socket, &error)) {
		fprintf(stderr, "dns_tab: the second daemon never started\n");
		second.kill();
		second.waitForFinished(2000);
		return 1;
	}
	ncfg_dns_view other_view(&other_connection);
	QString said;
	QObject::connect(&other_view, &ncfg_dns_view::reported,
	    [&said](const QString &summary) { said = summary; });
	other_view.refresh();
	QMetaObject::invokeMethod(&other_view, "apply_mode");
	check(said.contains(QStringLiteral("does not edit")) ? QStringLiteral("refused") : said,
	    QStringLiteral("refused"), "a block with domains is refused, not saved without them");
	second.kill();
	second.waitForFinished(5000);

	if (failures) {
		fprintf(stderr, "dns_tab: %d check(s) failed\n", failures);
		return 1;
	}
	fprintf(stderr, "dns_tab: all checks passed\n");
	return 0;
}
