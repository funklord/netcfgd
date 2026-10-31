/*
 * dns_record_load.cpp -- the DNS records tab saves a record as it found it.
 *
 * A record is the router's answer for a name (0303), and a save that dropped
 * a preference, a port or a second address would change what every host on
 * the LAN is told. So this writes one record of each kind, each in its own
 * drop-in, saves each unchanged through the dialog, and compares what netcfgd
 * compiles; then writes a new one, and has the compiler refuse an alias with
 * an address beside it.
 *
 * HOW IT STOPS: one daemon, killed at the end; the wait for its socket is
 * bounded at ten seconds.
 */

#include "../src/dns_record_dialog.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
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
	fprintf(stderr, "dns_record_load: %-52s %s\n", what, ok ? "ok" : "FAILED");
	if (!ok) {
		fprintf(stderr, "               expected: %s\n", qPrintable(want));
		fprintf(stderr, "               actual:   %s\n", qPrintable(got));
		failures++;
	}
}

/* Start a daemon over `body` and the drop-ins in `owned` -- name to text, each
 * under `conf.d/` -- and hand back its socket. A device the dialog edits lives
 * in its own `device-<name>` drop-in, which is the file its save replaces. */
/* One entry of the document as netcfgd compiles the configuration -- `ncfg
 * show` over the same directory the daemon reads -- by its `name` or `id`.
 * Compared before and after a save (10.631): the reader cannot report a key
 * it drops, and the compiler sees every one. */
static QString compiled(const QString &work, const char *section, const QString &name)
{
	QProcess show;
	QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
	environment.insert(QStringLiteral("NCFG_CONFIG_DIR"), work + QStringLiteral("/etc"));
	environment.insert(QStringLiteral("NCFG_RUN_DIR"), work + QStringLiteral("/run"));
	show.setProcessEnvironment(environment);
	/* `ncfg`, the link beside the daemon: one binary, told which it is by
	 * the name it is run as. */
	show.start(QStringLiteral(NETCFGD_BINARY).section(QLatin1Char('/'), 0, -2) +
	        QStringLiteral("/ncfg"),
	    { QStringLiteral("show") });
	if (!show.waitForFinished(20000)) {
		show.kill();
		show.waitForFinished(2000);
		return QStringLiteral("<ncfg show did not finish>");
	}
	const QJsonArray entries = QJsonDocument::fromJson(show.readAllStandardOutput())
	                               .object()
	                               .value(QString::fromLatin1(section))
	                               .toArray();
	for (const QJsonValue &entry : entries) {
		const QJsonObject object = entry.toObject();
		if (object.value(QStringLiteral("name")).toString() == name ||
		    object.value(QStringLiteral("id")).toString() == name) {
			return QString::fromUtf8(QJsonDocument(object).toJson(QJsonDocument::Compact));
		}
	}
	return QStringLiteral("<no %1 %2>").arg(QString::fromLatin1(section), name);
}

static QString start(QProcess *daemon, const QString &work, const QString &body,
    const QList<QPair<QString, QString>> &owned)
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
	for (const auto &one : owned) {
		QFile file(etc + QStringLiteral("/conf.d/%1.conf").arg(one.first));
		if (!file.open(QIODevice::WriteOnly)) {
			return QString();
		}
		file.write(one.second.toUtf8());
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

static QString save(ncfg_dns_record_dialog *dialog)
{
	QMetaObject::invokeMethod(dialog, "submit");
	if (!dialog->outcome().isEmpty()) {
		return QStringLiteral("saved");
	}
	auto *note = dialog->findChild<QLabel *>(QStringLiteral("record_note"));
	return note ? note->text() : QStringLiteral("<no note>");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);

	if (!QFile::exists(QStringLiteral(NETCFGD_BINARY))) {
		fprintf(stderr, "dns_record_load: skipping: %s is not built\n", NETCFGD_BINARY);
		return 0;
	}

	QTemporaryDir work;
	QProcess      daemon;
	QList<QPair<QString, QString>> owned;
	owned << qMakePair(QStringLiteral("dns_record-nas.home.lan"),
	    QStringLiteral("dns_record \"nas.home.lan\" { address = [\"192.168.1.10\", \"fd00::10\"] }\n"));
	owned << qMakePair(QStringLiteral("dns_record-files.home.lan"),
	    QStringLiteral("dns_record \"files.home.lan\" { cname = \"nas.home.lan\" }\n"));
	owned << qMakePair(QStringLiteral("dns_record-home.lan"),
	    QStringLiteral("dns_record \"home.lan\" { mx = \"mail.home.lan\"; preference = 5; "
	                   "txt = \"v=spf1 -all\" }\n"));
	owned << qMakePair(QStringLiteral("dns_record-_sip._udp.home.lan"),
	    QStringLiteral("dns_record \"_sip._udp.home.lan\" { srv = \"pbx.home.lan\"; port = 5060; "
	                   "priority = 1; weight = 2 }\n"));
	owned << qMakePair(QStringLiteral("dns_record-corp.example"),
	    QStringLiteral("dns_record \"corp.example\" { forward = [\"10.0.0.53\"] }\n"));
	const QString socket = start(&daemon, work.path(),
	    QStringLiteral("global { control { observe = \"any\"; admin = \"any\" } }\n"), owned);
	ncfg_connection connection;
	QString         error;
	if (socket.isEmpty() || !connection.open(socket, &error)) {
		fprintf(stderr, "dns_record_load: the daemon never started\n");
		daemon.kill();
		daemon.waitForFinished(2000);
		return 1;
	}

	QList<ncfg_dns_record_row> records;
	check(connection.dns_records(&records, &error) ? QString::number(records.size()) : error,
	    QStringLiteral("5"), "five records read");
	for (const ncfg_dns_record_row &record : records) {
		const QString before = compiled(work.path(), "dns_records", record.name);
		check(before.startsWith(QLatin1Char('{')) ? QStringLiteral("found") : before,
		    QStringLiteral("found"), qPrintable(QStringLiteral("%1 compiles").arg(record.name)));
		ncfg_dns_record_dialog dialog(&connection, record);
		check(save(&dialog), QStringLiteral("saved"), "  and saves unchanged");
		check(compiled(work.path(), "dns_records", record.name), before,
		    "  and compiles to the record it was, whole");
	}

	{
		ncfg_dns_record_dialog dialog(&connection, ncfg_dns_record_row());
		dialog.findChild<QLineEdit *>(QStringLiteral("record_name"))
		    ->setText(QStringLiteral("printer.home.lan"));
		dialog.findChild<QLineEdit *>(QStringLiteral("record_address"))
		    ->setText(QStringLiteral("192.168.1.30"));
		check(save(&dialog), QStringLiteral("saved"), "a new record saves");
	}
	check(compiled(work.path(), "dns_records", QStringLiteral("printer.home.lan")),
	    QStringLiteral("{\"address\":[\"192.168.1.30\"],\"name\":\"printer.home.lan\"}"),
	    "  and compiles");
	{
		ncfg_dns_record_dialog dialog(&connection, ncfg_dns_record_row());
		dialog.findChild<QLineEdit *>(QStringLiteral("record_name"))
		    ->setText(QStringLiteral("both.home.lan"));
		dialog.findChild<QLineEdit *>(QStringLiteral("record_address"))
		    ->setText(QStringLiteral("192.168.1.31"));
		dialog.findChild<QLineEdit *>(QStringLiteral("record_cname"))
		    ->setText(QStringLiteral("nas.home.lan"));
		const QString said = save(&dialog);
		check(said.contains(QStringLiteral("stands alone")) ? QStringLiteral("refused") : said,
		    QStringLiteral("refused"), "an alias with an address beside it is refused");
	}
	daemon.kill();
	daemon.waitForFinished(2000);

	fprintf(stderr, "dns_record_load: %s\n", failures ? "FAILED" : "all checks passed");
	return failures ? 1 : 0;
}
