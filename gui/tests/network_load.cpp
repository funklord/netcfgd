/*
 * network_load.cpp -- the network dialog saves a network as it found it.
 *
 * The network dialog had been checked only live, against fake radios, for
 * the keys those scenarios use. Its `security` member is custom -- a
 * passphrase and its generation, or 802.1X with five references and three
 * strings -- so `form_coverage_gate.py` sees the word and nothing inside it,
 * and the access point dialog lost `proto` that way (10.631). So this writes a
 * passphrase network using every network key, a TLS network whose
 * certificates live in three different stores, and a PEAP network, saves
 * each unchanged through the dialog, and compares what netcfgd compiles.
 *
 * HOW IT STOPS: one daemon, killed at the end; the wait for its socket is
 * bounded at ten seconds.
 */

#include "../src/network_dialog.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
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
	fprintf(stderr, "network_load: %-55s %s\n", what, ok ? "ok" : "FAILED");
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

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);

	if (!QFile::exists(QStringLiteral(NETCFGD_BINARY))) {
		fprintf(stderr, "network_load: skipping: %s is not built\n", NETCFGD_BINARY);
		return 0;
	}

	QTemporaryDir work;
	QProcess      daemon;
	QList<QPair<QString, QString>> owned;
	owned << qMakePair(QStringLiteral("wifi-Home"),
	    QStringLiteral("network \"Home\" {\n"
	                   "\tmetric = 50\n"
	                   "\thidden = true\n"
	                   "\tbssid = [\"aa:bb:cc:dd:ee:01\", \"aa:bb:cc:dd:ee:02\"]\n"
	                   "\tmetered = true\n"
	                   "\tconfig = [\"dhcp\", \"192.0.2.10/24\"]\n"
	                   "\troutes = [\"10.9.0.0/24 via 192.0.2.9\"]\n"
	                   "\tdns { mode = \"write_resolv_conf\"; servers = [\"192.0.2.53\"] }\n"
	                   "\twifi {\n"
	                   "\t\tpsk = \"@secret:keyring:home\"\n"
	                   "\t\tproto = \"wpa3\"\n"
	                   "\t\tautoconnect = false\n"
	                   "\t\troam { signal = -70; interval = 10; slow_interval = 60 }\n"
	                   "\t}\n"
	                   "}\n"));
	owned << qMakePair(QStringLiteral("wifi-corp"),
	    QStringLiteral("network \"corp\" {\n"
	                   "\twifi {\n"
	                   "\t\teap = \"tls\"\n"
	                   "\t\tidentity = \"you@corp.example\"\n"
	                   "\t\tca_cert = \"@secret:keyring:corp-ca\"\n"
	                   "\t\tdomain_suffix_match = \"radius.corp.example\"\n"
	                   "\t\tclient_cert = \"@secret:corp-crt\"\n"
	                   "\t\tprivate_key = \"@secret:pass:corp-key\"\n"
	                   "\t}\n"
	                   "}\n"));
	owned << qMakePair(QStringLiteral("wifi-campus"),
	    QStringLiteral("network \"campus\" {\n"
	                   "\twifi {\n"
	                   "\t\teap = \"peap\"\n"
	                   "\t\tidentity = \"me\"\n"
	                   "\t\tanonymous_identity = \"anon@campus\"\n"
	                   "\t\tpassword = \"@secret:pass:campus\"\n"
	                   "\t\tphase2 = \"mschapv2\"\n"
	                   "\t\tca_cert = \"@secret:campus-ca\"\n"
	                   "\t}\n"
	                   "}\n"));
	const QString socket = start(&daemon, work.path(),
	    QStringLiteral("global { control { observe = \"any\"; admin = \"any\" } }\n"), owned);
	ncfg_connection connection;
	QString         error;
	if (socket.isEmpty() || !connection.open(socket, &error)) {
		fprintf(stderr, "network_load: the daemon never started\n");
		daemon.kill();
		daemon.waitForFinished(2000);
		return 1;
	}

	QList<ncfg_saved_network_row> networks;
	check(connection.saved_networks(&networks, &error) ? QString::number(networks.size()) : error,
	    QStringLiteral("3"), "three networks read");
	const char *const ids[] = { "Home", "corp", "campus" };
	for (const char *id : ids) {
		const QString name = QString::fromLatin1(id);
		ncfg_saved_network_row row;
		for (const ncfg_saved_network_row &one : networks) {
			if (one.id == name) {
				row = one;
			}
		}
		const QString before = compiled(work.path(), "networks", name);
		check(before.startsWith(QLatin1Char('{')) ? QStringLiteral("found") : before,
		    QStringLiteral("found"), qPrintable(QStringLiteral("%1 compiles").arg(name)));
		ncfg_network_dialog dialog(&connection, row);
		QMetaObject::invokeMethod(&dialog, "submit");
		/* The dialog's note has no object name, so every label that says
		 * something is what it said. */
		QStringList said;
		for (const QLabel *label : dialog.findChildren<QLabel *>()) {
			if (!label->text().isEmpty() && label->wordWrap()) {
				said << label->text();
			}
		}
		check(!dialog.outcome().isEmpty() ? QStringLiteral("saved") : said.join(QLatin1Char('|')),
		    QStringLiteral("saved"), qPrintable(QStringLiteral("  and saves unchanged")));
		check(compiled(work.path(), "networks", name), before,
		    "  and compiles to the network it was, whole");
	}
	daemon.kill();
	daemon.waitForFinished(2000);

	fprintf(stderr, "network_load: %s\n", failures ? "FAILED" : "all checks passed");
	return failures ? 1 : 0;
}
