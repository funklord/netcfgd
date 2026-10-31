/*
 * device_load.cpp -- the device dialog saves what it loaded, whole.
 *
 * The device dialog refused to save a block carrying `master` or
 * `bridge_vlans`, or a shaped rate finer than a kbit -- and it refused a port
 * whose bridge listed it in `members`, because the compiler turns that list
 * into `master` on the port, so a cable in a bridge could not have its MTU
 * changed from the window at all. And it never read a radio's `wds`, so a
 * save dropped four-address mode without saying anything (10.613).
 *
 * So this writes each of those by hand, opens the dialog on it, presses Save,
 * and reads the result back through the daemon -- which goes through the
 * compiler, so a block the dialog wrote and netcfgd refused fails here.
 *
 * A real daemon, as `interface_load` starts one: the configuration has to come
 * from somewhere, and the socket round trip is what is under test.
 *
 * HOW IT STOPS: one daemon per case, each killed at the end of its case; the
 * wait for its socket is bounded at ten seconds.
 */

#include "../src/device_dialog.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QCheckBox>
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
#include <QSpinBox>
#include <QTableWidget>
#include <QTemporaryDir>
#include <QThread>

#include <cstdio>

static int failures;

static void check(const QString &got, const QString &want, const char *what)
{
	const bool ok = got == want;
	fprintf(stderr, "device_load: %-56s %s\n", what, ok ? "ok" : "FAILED");
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

static QString read_file(const QString &path)
{
	QFile file(path);
	return file.open(QIODevice::ReadOnly) ? QString::fromUtf8(file.readAll())
	                                      : QStringLiteral("<no file>");
}

/* Open the dialog on `name`, press Save, and say what the note said: empty
 * where the save went through, which is what `outcome` then reports. */
static QString save(ncfg_connection *connection, const QString &name, const QString &work)
{
	ncfg_device_dialog dialog(connection, name);
	const QString before = compiled(work, "devices", name);
	if (!before.startsWith(QLatin1Char('{'))) {
		/* Not found: comparing two absences would pass for anything. */
		return before;
	}
	QMetaObject::invokeMethod(&dialog, "submit");
	if (!dialog.outcome().isEmpty()) {
		/* Saved, and compiled to the device it was (10.631). */
		const QString after = compiled(work, "devices", name);
		if (after != before) {
			return QStringLiteral("saved, and changed:\n%1\n%2").arg(before, after);
		}
		return QStringLiteral("saved");
	}
	auto *note = dialog.findChild<QLabel *>(QStringLiteral("device_note"));
	return note ? note->text() : QStringLiteral("<no note>");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);

	if (!QFile::exists(QStringLiteral(NETCFGD_BINARY))) {
		fprintf(stderr, "device_load: skipping: %s is not built\n", NETCFGD_BINARY);
		return 0;
	}

	QTemporaryDir work;
	QProcess daemon;
	QList<QPair<QString, QString>> owned;
	owned << qMakePair(QStringLiteral("device-eth0"),
	    QStringLiteral("device eth0 { mtu = 1500 }\n"));
	owned << qMakePair(QStringLiteral("device-eth1"),
	    QStringLiteral("device eth1 {\n\tmaster = \"br0\"\n"
	                   "\tvlans = [\"10 pvid untagged\", \"20-22\"]\n}\n"));
	owned << qMakePair(QStringLiteral("device-wlan0"),
	    QStringLiteral("device wlan0 { wifi { wds = true } }\n"));
	owned << qMakePair(QStringLiteral("device-dum0"),
	    QStringLiteral("device dum0 {\n\tkind = \"dummy\"\n"
	                   "\tqdisc { kind = \"cake\"; bandwidth = \"1234567bit\" }\n}\n"));
	/* Keys held outside the file store: a reader that kept only the name
	 * would write them back as files (10.628's shape, 10.632). */
	owned << qMakePair(QStringLiteral("device-wg0"),
	    QStringLiteral("device wg0 {\n\twireguard {\n"
	                   "\t\tprivate_key = \"@secret:keyring:wg0\"\n\t\tlisten_port = 51820\n"
	                   "\t\tfwmark = 51820\n"
	                   "\t\tpeer \"office\" {\n"
	                   "\t\t\tpublic_key = \"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\"\n"
	                   "\t\t\tpreshared_key = \"@secret:pass:wg0-office\"\n"
	                   "\t\t\tendpoint = \"vpn.example.com:51820\"\n"
	                   "\t\t\tallowed_ips = [\"10.9.0.0/24\", \"192.168.50.0/24\"]\n"
	                   "\t\t\tkeepalive = 25\n\t\t}\n\t}\n}\n"));
	/* `eth0` joins by the bridge's list, `eth1` by its own `master`; the radio
	 * is in four-address mode; the dummy is shaped at a rate that is not a
	 * whole kbit. */
	const QString socket = start(&daemon, work.path(),
	    QStringLiteral("global { control { observe = \"any\"; admin = \"any\" } }\n"
	                   "device br0 { bridge { members = [\"eth0\"]; vlan_filtering = true } }\n"),
	    owned);
	if (socket.isEmpty()) {
		fprintf(stderr, "device_load: the daemon never started\n");
		daemon.kill();
		daemon.waitForFinished(2000);
		return 1;
	}
	ncfg_connection connection;
	QString error;
	if (!connection.open(socket, &error)) {
		fprintf(stderr, "device_load: cannot reach the daemon: %s\n", qPrintable(error));
		daemon.kill();
		daemon.waitForFinished(2000);
		return 1;
	}
	const QString conf_d = work.path() + QStringLiteral("/etc/conf.d/");

	/* A port by its own `master`, with VLANs: loaded into the fields, saved,
	 * and read back with the range still a range. */
	{
		ncfg_device_dialog dialog(&connection, QStringLiteral("eth1"));
		auto *joins = dialog.findChild<QLineEdit *>(QStringLiteral("device_master"));
		auto *table = dialog.findChild<QTableWidget *>(QStringLiteral("device_vlans"));
		check(joins ? joins->text() : QStringLiteral("<missing>"), QStringLiteral("br0"),
		    "a port's master loads");
		check(table ? QString::number(table->rowCount()) : QStringLiteral("<missing>"),
		    QStringLiteral("2"), "and its vlans as two rows, the range kept whole");
	}
	check(save(&connection, QStringLiteral("eth1"), work.path()), QStringLiteral("saved"),
	    "a port with vlans can be saved");
	const QString port = read_file(conf_d + QStringLiteral("device-eth1.conf"));
	check(port.startsWith(QStringLiteral("# Written by netcfgd's gui")) &&
	        port.contains(QStringLiteral("\tmaster = \"br0\"\n")) &&
	        port.contains(QStringLiteral("\tvlans = [\"10 pvid untagged\", \"20-22\"]\n"))
	        ? QStringLiteral("written")
	        : port,
	    QStringLiteral("written"), "  written by the dialog, master and vlans");
	ncfg_device_config eth1;
	check(connection.device_config(QStringLiteral("eth1"), &eth1, &error) &&
	        eth1.master == QStringLiteral("br0") && eth1.vlans.size() == 2 &&
	        eth1.vlans[0].vids == QStringLiteral("10") && eth1.vlans[0].pvid &&
	        eth1.vlans[0].untagged && eth1.vlans[1].vids == QStringLiteral("20-22")
	        ? QStringLiteral("kept")
	        : QStringLiteral("%1 %2 %3").arg(error, eth1.master).arg(eth1.vlans.size()),
	    QStringLiteral("kept"), "  and netcfgd compiles it back the same");

	/* **A port its bridge lists.** It reads back with a `master` nobody wrote
	 * in its block, and the dialog refused it for that until 10.613. */
	{
		ncfg_device_dialog dialog(&connection, QStringLiteral("eth0"));
		auto *joins = dialog.findChild<QLineEdit *>(QStringLiteral("device_master"));
		check(joins && joins->text() == QStringLiteral("br0") && joins->isReadOnly()
		        ? QStringLiteral("shown")
		        : QStringLiteral("<%1>").arg(joins ? joins->text() : QString()),
		    QStringLiteral("shown"), "a member by the bridge's list shows it, read-only");
	}
	check(save(&connection, QStringLiteral("eth0"), work.path()), QStringLiteral("saved"),
	    "and can be saved");
	const QString member = read_file(conf_d + QStringLiteral("device-eth0.conf"));
	check(member.contains(QStringLiteral("mtu = 1500")) &&
	        !member.contains(QStringLiteral("master"))
	        ? QStringLiteral("written")
	        : member,
	    QStringLiteral("written"), "  without restating the membership");

	/* Four-address mode, which a save used to drop. */
	check(save(&connection, QStringLiteral("wlan0"), work.path()), QStringLiteral("saved"),
	    "a radio in four-address mode can be saved");
	ncfg_device_config wlan0;
	check(connection.device_config(QStringLiteral("wlan0"), &wlan0, &error) && wlan0.wds
	        ? QStringLiteral("kept")
	        : QStringLiteral("dropped %1").arg(error),
	    QStringLiteral("kept"), "  and keeps it");

	/* A rate finer than a kbit, saved for an unrelated change: exact. */
	{
		ncfg_device_dialog dialog(&connection, QStringLiteral("dum0"));
		auto *out = dialog.findChild<QSpinBox *>(QStringLiteral("device_bandwidth"));
		check(out ? QString::number(out->value()) : QStringLiteral("<missing>"),
		    QStringLiteral("1235"), "a rate in bits shows as the nearest kbit");
	}
	check(save(&connection, QStringLiteral("dum0"), work.path()), QStringLiteral("saved"),
	    "a rate finer than a kbit can be saved");
	ncfg_device_config dum0;
	check(connection.device_config(QStringLiteral("dum0"), &dum0, &error)
	        ? QString::number(dum0.bandwidth_bits)
	        : error,
	    QStringLiteral("1234567"), "  and comes back exact rather than rounded");

	/* A WireGuard device whose keys the keyring and `pass` hold. */
	check(save(&connection, QStringLiteral("wg0"), work.path()), QStringLiteral("saved"),
	    "a WireGuard device with keys outside the file store saves unchanged");

	daemon.kill();
	daemon.waitForFinished(2000);

	fprintf(stderr, "device_load: %s\n", failures ? "FAILED" : "all checks passed");
	return failures ? 1 : 0;
}
