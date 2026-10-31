/*
 * block_list_load.cpp -- the block lists tab saves a list as it found it.
 *
 * A block list is what every host on a LAN may not resolve (0305), and a save
 * that dropped a file or an exception would block a site the operator
 * allowed, or stop blocking a list they meant. So this writes two lists, each
 * in its own drop-in, saves each unchanged through the dialog, and compares
 * what netcfgd compiles; then writes a new one, and has the compiler refuse a
 * relative path. A server's `block` is interface_load's, beside its other
 * DHCP fields.
 *
 * HOW IT STOPS: one daemon, killed at the end; the wait for its socket is
 * bounded at ten seconds.
 */

#include "../src/block_list_dialog.h"
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
	fprintf(stderr, "block_list_load: %-52s %s\n", what, ok ? "ok" : "FAILED");
	if (!ok) {
		fprintf(stderr, "               expected: %s\n", qPrintable(want));
		fprintf(stderr, "               actual:   %s\n", qPrintable(got));
		failures++;
	}
}

/* One entry of the document as netcfgd compiles the configuration -- `ncfg
 * show` over the same directory the daemon reads -- by its `name`. Compared
 * before and after a save (10.631): the reader cannot report a key it drops,
 * and the compiler sees every one. */
static QString compiled(const QString &work, const char *section, const QString &name)
{
	QProcess show;
	QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
	environment.insert(QStringLiteral("NCFG_CONFIG_DIR"), work + QStringLiteral("/etc"));
	environment.insert(QStringLiteral("NCFG_RUN_DIR"), work + QStringLiteral("/run"));
	show.setProcessEnvironment(environment);
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
		if (object.value(QStringLiteral("name")).toString() == name) {
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

static QString save(ncfg_block_list_dialog *dialog)
{
	QMetaObject::invokeMethod(dialog, "submit");
	if (!dialog->outcome().isEmpty()) {
		return QStringLiteral("saved");
	}
	auto *note = dialog->findChild<QLabel *>(QStringLiteral("block_list_note"));
	return note ? note->text() : QStringLiteral("<no note>");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);

	if (!QFile::exists(QStringLiteral(NETCFGD_BINARY))) {
		fprintf(stderr, "block_list_load: skipping: %s is not built\n", NETCFGD_BINARY);
		return 0;
	}

	QTemporaryDir work;
	QProcess      daemon;
	QList<QPair<QString, QString>> owned;
	owned << qMakePair(QStringLiteral("block_list-ads"),
	    QStringLiteral("block_list \"ads\" { file = [\"/var/lib/netcfgd/block/ads.txt\", "
	                   "\"/var/lib/netcfgd/block/more.txt\"]; domain = [\"doubleclick.net\"]; "
	                   "allow = [\"ok.doubleclick.net\"] }\n"));
	owned << qMakePair(QStringLiteral("block_list-malware"),
	    QStringLiteral("block_list \"malware\" { domain = [\"bad.example\", \"worse.example\"] }\n"));
	const QString socket = start(&daemon, work.path(),
	    QStringLiteral("global { control { observe = \"any\"; admin = \"any\" } }\n"), owned);
	ncfg_connection connection;
	QString         error;
	if (socket.isEmpty() || !connection.open(socket, &error)) {
		fprintf(stderr, "block_list_load: the daemon never started\n");
		daemon.kill();
		daemon.waitForFinished(2000);
		return 1;
	}

	QList<ncfg_block_list_row> lists;
	check(connection.block_lists(&lists, &error) ? QString::number(lists.size()) : error,
	    QStringLiteral("2"), "two lists read");
	for (const ncfg_block_list_row &list : lists) {
		const QString before = compiled(work.path(), "block_lists", list.name);
		check(before.startsWith(QLatin1Char('{')) ? QStringLiteral("found") : before,
		    QStringLiteral("found"), qPrintable(QStringLiteral("%1 compiles").arg(list.name)));
		ncfg_block_list_dialog dialog(&connection, list);
		check(save(&dialog), QStringLiteral("saved"), "  and saves unchanged");
		check(compiled(work.path(), "block_lists", list.name), before,
		    "  and compiles to the list it was, whole");
	}

	{
		ncfg_block_list_dialog dialog(&connection, ncfg_block_list_row());
		dialog.findChild<QLineEdit *>(QStringLiteral("block_list_name"))
		    ->setText(QStringLiteral("trackers"));
		dialog.findChild<QLineEdit *>(QStringLiteral("block_list_domain"))
		    ->setText(QStringLiteral("tracker.example"));
		check(save(&dialog), QStringLiteral("saved"), "a new list saves");
	}
	check(compiled(work.path(), "block_lists", QStringLiteral("trackers")),
	    QStringLiteral("{\"domain\":[\"tracker.example\"],\"name\":\"trackers\"}"),
	    "  and compiles");
	{
		ncfg_block_list_dialog dialog(&connection, ncfg_block_list_row());
		dialog.findChild<QLineEdit *>(QStringLiteral("block_list_name"))
		    ->setText(QStringLiteral("relative"));
		dialog.findChild<QLineEdit *>(QStringLiteral("block_list_file"))
		    ->setText(QStringLiteral("ads.txt"));
		const QString said = save(&dialog);
		check(said.contains(QStringLiteral("absolute path")) ? QStringLiteral("refused") : said,
		    QStringLiteral("refused"), "a relative file is refused");
	}
	daemon.kill();
	daemon.waitForFinished(2000);

	fprintf(stderr, "block_list_load: %s\n", failures ? "FAILED" : "all checks passed");
	return failures ? 1 : 0;
}
