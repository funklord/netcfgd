/*
 * mesh_load.cpp -- the mesh tab saves what it loaded.
 *
 * A mesh node that loses its channel, its band or its password's provider on
 * a save stops meeting its peers, and nothing on this node says why -- the
 * others carry on without it. So this loads a mesh whose password the keyring
 * holds, saves it unchanged through the dialog against a real daemon, and
 * reads it back; then writes a second, open mesh, and has the daemon refuse a
 * second mesh on a radio already given to one.
 *
 * HOW IT STOPS: one daemon, killed at the end; the wait for its socket is
 * bounded at ten seconds.
 */

#include "../src/mesh_dialog.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QComboBox>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QProcess>
#include <QSpinBox>
#include <QTemporaryDir>
#include <QThread>

#include <cstdio>

static int failures;

static void check(const QString &got, const QString &want, const char *what)
{
	const bool ok = got == want;
	fprintf(stderr, "mesh_load: %-58s %s\n", what, ok ? "ok" : "FAILED");
	if (!ok) {
		fprintf(stderr, "               expected: %s\n", qPrintable(want));
		fprintf(stderr, "               actual:   %s\n", qPrintable(got));
		failures++;
	}
}

/* A daemon over `body`, with `drop_in` as `conf.d/mesh-backhaul.conf` --
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
		QFile file(etc + QStringLiteral("/conf.d/mesh-backhaul.conf"));
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

static QString save(ncfg_mesh_dialog *dialog)
{
	QMetaObject::invokeMethod(dialog, "submit");
	if (!dialog->outcome().isEmpty()) {
		return QStringLiteral("saved");
	}
	auto *note = dialog->findChild<QLabel *>(QStringLiteral("mesh_note"));
	return note ? note->text() : QStringLiteral("<no note>");
}

static QString listed(ncfg_connection *connection)
{
	QList<ncfg_mesh_row> meshes;
	QString              error;
	if (!connection->meshes(&meshes, &error)) {
		return error;
	}
	QStringList each;
	for (const ncfg_mesh_row &mesh : meshes) {
		each << QStringList { mesh.id, mesh.device, QString::number(mesh.channel), mesh.band,
			mesh.security, mesh.credential, mesh.unmodelled }
		            .join(QLatin1Char('|'));
	}
	return each.join(QLatin1Char(' '));
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);

	if (!QFile::exists(QStringLiteral(NETCFGD_BINARY))) {
		fprintf(stderr, "mesh_load: skipping: %s is not built\n", NETCFGD_BINARY);
		return 0;
	}

	QTemporaryDir work;
	QProcess      daemon;
	const QString socket = start(&daemon, work.path(),
	    QStringLiteral("global { control { observe = \"any\"; admin = \"any\" } }\n"
	                   "interface wlan2 { config = \"10.20.0.1/24\" }\n"),
	    QStringLiteral("mesh \"backhaul\" {\n\tdevice = \"wlan2\"\n\tchannel = 36\n"
	                   "\tband = \"5\"\n\twifi {\n\t\tpsk = \"@secret:keyring:mesh\"\n\t}\n}\n"));
	ncfg_connection connection;
	QString         error;
	if (socket.isEmpty() || !connection.open(socket, &error)) {
		fprintf(stderr, "mesh_load: the daemon never started\n");
		stop(&daemon);
		return 1;
	}

	const QString before = listed(&connection);
	check(before, QStringLiteral("backhaul|wlan2|36|5|psk|@secret:keyring:mesh|"),
	    "a mesh reads: radio, channel, band and the password's reference");

	QList<ncfg_mesh_row> meshes;
	connection.meshes(&meshes, &error);
	{
		ncfg_mesh_dialog dialog(&connection, meshes.value(0));
		auto *id = dialog.findChild<QLineEdit *>(QStringLiteral("mesh_id"));
		check(id && id->isReadOnly() ? QStringLiteral("fixed") : QStringLiteral("editable"),
		    QStringLiteral("fixed"), "  its ID is fixed, since every node shares it");
		check(save(&dialog), QStringLiteral("saved"), "  and it saves unchanged");
	}
	check(listed(&connection), before, "  and netcfgd compiles back the same mesh");

	{
		ncfg_mesh_dialog dialog(&connection, ncfg_mesh_row());
		dialog.findChild<QLineEdit *>(QStringLiteral("mesh_id"))->setText(QStringLiteral("attic"));
		dialog.findChild<QLineEdit *>(QStringLiteral("mesh_device"))
		    ->setText(QStringLiteral("wlan3"));
		const QString said = save(&dialog);
		check(said.contains(QStringLiteral("needs a channel")) ? QStringLiteral("refused") : said,
		    QStringLiteral("refused"), "a mesh with no channel is refused");
		dialog.findChild<QSpinBox *>(QStringLiteral("mesh_channel"))->setValue(6);
		auto *security = dialog.findChild<QComboBox *>(QStringLiteral("mesh_security"));
		security->setCurrentIndex(security->findData(QStringLiteral("open")));
		check(save(&dialog), QStringLiteral("saved"), "an open mesh with a channel saves");
	}
	check(listed(&connection), QStringLiteral("attic|wlan3|6||open|| ") + before,
	    "  and reads back beside the first");

	/* One radio, one mesh: the daemon refuses and names the mesh it has. */
	{
		ncfg_mesh_dialog dialog(&connection, ncfg_mesh_row());
		dialog.findChild<QLineEdit *>(QStringLiteral("mesh_id"))->setText(QStringLiteral("cellar"));
		dialog.findChild<QLineEdit *>(QStringLiteral("mesh_device"))
		    ->setText(QStringLiteral("wlan2"));
		dialog.findChild<QSpinBox *>(QStringLiteral("mesh_channel"))->setValue(36);
		dialog.findChild<QLineEdit *>(QStringLiteral("mesh_credential"))
		    ->setText(QStringLiteral("@secret:cellar"));
		const QString said = save(&dialog);
		check(said.contains(QStringLiteral("backhaul")) ? QStringLiteral("refused") : said,
		    QStringLiteral("refused"), "a second mesh on one radio is refused, naming the first");
	}
	stop(&daemon);

	fprintf(stderr, "mesh_load: %s\n", failures ? "FAILED" : "all checks passed");
	return failures ? 1 : 0;
}
