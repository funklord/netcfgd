/*
 * host_list_load.cpp -- the host lists tab saves what it loaded, and does
 * not delete a list something names.
 *
 * A host list is named by an access point or a firewall rule as
 * `@host_list:NAME`, so the two ways the tab can do harm are a save that
 * loses a station -- which lets in, or stops refusing, a device nobody
 * changed -- and a delete that leaves a name pointing nowhere. This loads a
 * list through a real daemon, saves it unchanged through the dialog, writes a
 * second, and tries to delete the first while a firewall rule names it.
 *
 * HOW IT STOPS: one daemon, killed at the end; the wait for its socket is
 * bounded at ten seconds.
 */

#include "../src/host_list_dialog.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QPlainTextEdit>
#include <QProcess>
#include <QTemporaryDir>
#include <QThread>

#include <cstdio>

static int failures;

static void check(const QString &got, const QString &want, const char *what)
{
	const bool ok = got == want;
	fprintf(stderr, "host_list_load: %-52s %s\n", what, ok ? "ok" : "FAILED");
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
		QFile file(etc + QStringLiteral("/conf.d/host_list-kids.conf"));
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

/* The note after pressing Save, or `saved` where it went through. */
static QString save(ncfg_host_list_dialog *dialog)
{
	QMetaObject::invokeMethod(dialog, "submit");
	if (!dialog->outcome().isEmpty()) {
		return QStringLiteral("saved");
	}
	auto *note = dialog->findChild<QLabel *>(QStringLiteral("host_list_note"));
	return note ? note->text() : QStringLiteral("<no note>");
}

static QString listed(ncfg_connection *connection)
{
	QList<ncfg_host_list_row> lists;
	QString                   error;
	if (!connection->host_lists(&lists, &error)) {
		return error;
	}
	QStringList each;
	for (const ncfg_host_list_row &list : lists) {
		each << QStringLiteral("%1=%2").arg(list.name, list.mac.join(QLatin1Char(',')));
	}
	return each.join(QLatin1Char(' '));
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);

	if (!QFile::exists(QStringLiteral(NETCFGD_BINARY))) {
		fprintf(stderr, "host_list_load: skipping: %s is not built\n", NETCFGD_BINARY);
		return 0;
	}

	QTemporaryDir work;
	QProcess      daemon;
	const QString socket = start(&daemon, work.path(),
	    QStringLiteral("global { control { observe = \"any\"; admin = \"any\" } }\n"
	                   "firewall {\n\tinput {\n\t\tpolicy = \"accept\"\n"
	                   "\t\tdrop \"kids\" { mac = [\"@host_list:kids\"] }\n\t}\n"
	                   "\tforward { policy = \"accept\" }\n\toutput { policy = \"accept\" }\n}\n"),
	    QStringLiteral("host_list \"kids\" {\n"
	                   "\tmac = [\"00:11:22:33:44:01\", \"00:11:22:33:44:02\"]\n}\n"));
	ncfg_connection connection;
	QString         error;
	if (socket.isEmpty() || !connection.open(socket, &error)) {
		fprintf(stderr, "host_list_load: the daemon never started\n");
		stop(&daemon);
		return 1;
	}

	const QString before = listed(&connection);
	check(before, QStringLiteral("kids=00:11:22:33:44:01,00:11:22:33:44:02"),
	    "a host list reads, every station");

	QList<ncfg_host_list_row> lists;
	connection.host_lists(&lists, &error);
	{
		ncfg_host_list_dialog dialog(&connection, lists.value(0));
		auto *name = dialog.findChild<QLineEdit *>(QStringLiteral("host_list_name"));
		check(name && name->isReadOnly() ? QStringLiteral("fixed") : QStringLiteral("editable"),
		    QStringLiteral("fixed"), "  its name is fixed, since other blocks name it");
		check(save(&dialog), QStringLiteral("saved"), "  and it saves unchanged");
	}
	check(listed(&connection), before, "  and netcfgd compiles back the same list");

	{
		ncfg_host_list_dialog dialog(&connection, ncfg_host_list_row());
		dialog.findChild<QLineEdit *>(QStringLiteral("host_list_name"))
		    ->setText(QStringLiteral("guests"));
		dialog.findChild<QPlainTextEdit *>(QStringLiteral("host_list_members"))
		    ->setPlainText(QStringLiteral("aa:bb:cc:dd:ee:01\naa:bb:cc:dd:ee:02"));
		check(save(&dialog), QStringLiteral("saved"), "a new list saves");
	}
	/* The document sorts lists by name. */
	check(listed(&connection),
	    QStringLiteral("guests=aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02 ") + before,
	    "  and reads back beside the first");
	{
		ncfg_host_list_dialog dialog(&connection, ncfg_host_list_row());
		dialog.findChild<QLineEdit *>(QStringLiteral("host_list_name"))
		    ->setText(QStringLiteral("bad"));
		dialog.findChild<QPlainTextEdit *>(QStringLiteral("host_list_members"))
		    ->setPlainText(QStringLiteral("not-a-mac"));
		const QString said = save(&dialog);
		check(said.contains(QStringLiteral("not a station")) ? QStringLiteral("refused") : said,
		    QStringLiteral("refused"), "a member that is not an address is refused");
	}

	/* What the dialog's delete does once confirmed. The firewall still names
	 * `kids`, so the daemon refuses: the list stays. */
	const bool removed = connection.config_delete(QStringLiteral("host_list-kids"), &error);
	check(!removed && error.contains(QStringLiteral("kids")) ? QStringLiteral("refused")
	                                                         : QStringLiteral("deleted: %1").arg(error),
	    QStringLiteral("refused"), "a list a firewall rule names cannot be deleted");
	check(listed(&connection).contains(before) ? QStringLiteral("kept") : listed(&connection),
	    QStringLiteral("kept"), "  and is still there");
	check(connection.config_delete(QStringLiteral("host_list-guests"), &error)
	        ? QStringLiteral("deleted") : error,
	    QStringLiteral("deleted"), "one nothing names can");
	stop(&daemon);

	fprintf(stderr, "host_list_load: %s\n", failures ? "FAILED" : "all checks passed");
	return failures ? 1 : 0;
}
