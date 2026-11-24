/*
 * zone_load.cpp -- the zones tab's editor against a running daemon (10.929).
 *
 * A zone in a drop-in reads back, saves unchanged, a new one saves beside it,
 * a cap that is no rate is refused by the dialog, and a zone a link is still
 * in cannot be deleted: the daemon refuses a configuration that no longer
 * compiles.
 */
#include "../src/zone_dialog.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QLabel>
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
	fprintf(stderr, "zone_load: %-52s %s\n", what, ok ? "ok" : "FAILED");
	if (!ok) {
		fprintf(stderr, "               expected: %s\n", qPrintable(want));
		fprintf(stderr, "               actual:   %s\n", qPrintable(got));
		failures++;
	}
}

/* A daemon over `body`, with `drop_in` as `conf.d/host_list-kids.conf` --
 * the file the dialog's save replaces. */
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
		QFile file(etc + QStringLiteral("/conf.d/zone-guest.conf"));
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

/* The note after pressing Save, or `saved` where it went through. */
static QString save(ncfg_zone_dialog *dialog)
{
	QMetaObject::invokeMethod(dialog, "submit");
	if (!dialog->outcome().isEmpty()) {
		return QStringLiteral("saved");
	}
	auto *note = dialog->findChild<QLabel *>(QStringLiteral("zone_note"));
	return note ? note->text() : QStringLiteral("<no note>");
}

static QString listed(ncfg_connection *connection)
{
	QList<ncfg_zone_row> zones;
	QString              error;
	if (!connection->zones(&zones, &error)) {
		return error;
	}
	QStringList each;
	for (const ncfg_zone_row &zone : zones) {
		each << QStringLiteral("%1>%2/%3").arg(zone.name, zone.reach.join(QLatin1Char(',')),
		            zone.client_limit);
	}
	return each.join(QLatin1Char(' '));
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);

	if (!QFile::exists(QStringLiteral(NETCFGD_BINARY))) {
		fprintf(stderr, "zone_load: skipping: %s is not built\n", NETCFGD_BINARY);
		return 0;
	}

	QTemporaryDir work;
	QProcess      daemon;
	const QString socket = start(&daemon, work.path(),
	    QStringLiteral("global { control { root = \"any\" } }\n"
	                   "device zg0 { kind = \"dummy\" }\n"
	                   "interface zg0 { config = \"10.91.0.1/24\"; zone = \"guest\" }\n"
	                   "zone \"internet\" { reach = [] }\n"
	                   "firewall {\n\tinput { policy = \"accept\" }\n"
	                   "\tforward { policy = \"drop\" }\n\toutput { policy = \"accept\" }\n}\n"),
	    QStringLiteral("zone \"guest\" {\n\treach = [\"internet\"]\n"
	                   "\tclient_limit = \"5mbit\"\n}\n"));
	ncfg_connection connection;
	QString         error;
	if (socket.isEmpty() || !connection.open(socket, &error)) {
		fprintf(stderr, "zone_load: the daemon never started\n");
		stop(&daemon);
		return 1;
	}

	const QString before = listed(&connection);
	check(before, QStringLiteral("guest>internet/5mbit internet>/"),
	    "the zones read, each with its reach and cap");

	QList<ncfg_zone_row> zones;
	connection.zones(&zones, &error);
	{
		ncfg_zone_dialog dialog(&connection, zones.value(0));
		auto *name = dialog.findChild<QLineEdit *>(QStringLiteral("zone_name"));
		check(name && name->isReadOnly() ? QStringLiteral("fixed") : QStringLiteral("editable"),
		    QStringLiteral("fixed"), "  a zone's name is fixed, since links name it");
		check(save(&dialog), QStringLiteral("saved"), "  and it saves unchanged");
	}
	check(listed(&connection), before, "  and netcfgd compiles back the same zones");

	{
		ncfg_zone_dialog dialog(&connection, ncfg_zone_row());
		dialog.findChild<QLineEdit *>(QStringLiteral("zone_name"))->setText(QStringLiteral("iot"));
		dialog.findChild<QLineEdit *>(QStringLiteral("zone_reach"))
		    ->setText(QStringLiteral("internet"));
		check(save(&dialog), QStringLiteral("saved"), "a new zone saves");
	}
	check(listed(&connection), QStringLiteral("guest>internet/5mbit internet>/ iot>internet/"),
	    "  and reads back among them, sorted");
	/* 10.930: hosts by address, through the dialog and back. */
	{
		ncfg_zone_dialog dialog(&connection, ncfg_zone_row());
		dialog.findChild<QLineEdit *>(QStringLiteral("zone_name"))
		    ->setText(QStringLiteral("printers"));
		dialog.findChild<QLineEdit *>(QStringLiteral("zone_hosts"))
		    ->setText(QStringLiteral("192.0.2.20, 192.0.2.10"));
		check(save(&dialog), QStringLiteral("saved"), "a zone of hosts by address saves");
	}
	{
		QList<ncfg_zone_row> now;
		connection.zones(&now, &error);
		QString hosts;
		for (const ncfg_zone_row &zone : now) {
			if (zone.name == QStringLiteral("printers")) {
				hosts = zone.hosts.join(QLatin1Char(','));
			}
		}
		check(hosts, QStringLiteral("192.0.2.10,192.0.2.20"), "  and its hosts read back, sorted");
	}
	/* 10.934: clients by MAC, through the dialog and back, lowercased. */
	{
		ncfg_zone_dialog dialog(&connection, ncfg_zone_row());
		dialog.findChild<QLineEdit *>(QStringLiteral("zone_name"))
		    ->setText(QStringLiteral("kids"));
		dialog.findChild<QLineEdit *>(QStringLiteral("zone_clients"))
		    ->setText(QStringLiteral("02:AA:BB:CC:DD:01"));
		check(save(&dialog), QStringLiteral("saved"), "a zone of clients by MAC saves");
	}
	{
		QList<ncfg_zone_row> now;
		connection.zones(&now, &error);
		QString clients;
		for (const ncfg_zone_row &zone : now) {
			if (zone.name == QStringLiteral("kids")) {
				clients = zone.clients.join(QLatin1Char(','));
			}
		}
		check(clients, QStringLiteral("02:aa:bb:cc:dd:01"), "  and its clients read back");
	}
	(void)connection.config_delete(QStringLiteral("zone-kids"), &error);
	(void)connection.config_delete(QStringLiteral("zone-printers"), &error);
	{
		ncfg_zone_dialog dialog(&connection, ncfg_zone_row());
		dialog.findChild<QLineEdit *>(QStringLiteral("zone_name"))->setText(QStringLiteral("bad"));
		dialog.findChild<QLineEdit *>(QStringLiteral("zone_client_limit"))
		    ->setText(QStringLiteral("fast"));
		const QString said = save(&dialog);
		check(said.contains(QStringLiteral("not a rate")) ? QStringLiteral("refused") : said,
		    QStringLiteral("refused"), "a cap that is no rate is refused");
	}

	/* What the dialog's delete does once confirmed. A link is still in
	 * `guest`, so the daemon refuses: the zone stays. */
	const bool removed = connection.config_delete(QStringLiteral("zone-guest"), &error);
	check(!removed && error.contains(QStringLiteral("guest")) ? QStringLiteral("refused")
	                                                          : QStringLiteral("deleted: %1").arg(error),
	    QStringLiteral("refused"), "a zone a link is in cannot be deleted");
	check(connection.config_delete(QStringLiteral("zone-iot"), &error) ? QStringLiteral("deleted")
	                                                                    : error,
	    QStringLiteral("deleted"), "one nothing is in can");
	stop(&daemon);

	fprintf(stderr, "zone_load: %s\n", failures ? "FAILED" : "all checks passed");
	return failures ? 1 : 0;
}
