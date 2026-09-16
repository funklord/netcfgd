/*
 * interface_load.cpp -- a dialog that saves must first load.
 *
 * The interface dialog read nothing about the interface it was opened on. Every
 * field sat at its constructed default -- DHCP, no address, no gateway,
 * preference and MTU unset, forwarding and NAT off -- and `submit()` writes the
 * composed block with `replace = true`. So opening a configured interface and
 * pressing Save replaced its drop-in with that empty form: measured, a static
 * address, a default route, a preference, forwarding, NAT and a link probe all
 * gone, with the note reporting that netcfgd had re-read its configuration.
 *
 * Two properties, and the second is the one that cannot be got by loading
 * harder. An `interface` block carries keys this form has no field for --
 * `dns`, `hooks`, `dot1x` and others -- so a dialog that loaded the six it
 * knows and saved the whole block would still delete the rest. It refuses
 * instead, and names them.
 *
 * A real daemon, because the configuration has to come from somewhere and the
 * socket round trip is the thing that was missing.
 */

#include "../src/interface_dialog.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QLabel>
#include <QLineEdit>
#include <QProcess>
#include <QListWidget>
#include <QSpinBox>
#include <QTableWidget>
#include <QMetaObject>
#include <QTemporaryDir>
#include <QThread>

#include <cstdio>

static int failures;

static void check(const QString &got, const QString &want, const char *what)
{
	const bool ok = got == want;
	fprintf(stderr, "interface_load: %-48s %s\n", what, ok ? "ok" : "FAILED");
	if (!ok) {
		fprintf(stderr, "                  expected: %s\n", qPrintable(want));
		fprintf(stderr, "                  actual:   %s\n", qPrintable(got));
		failures++;
	}
}

template <typename T> static T *widget(const QWidget *view, const char *name)
{
	const auto found = view->findChildren<T *>(QString::fromLatin1(name));
	return found.isEmpty() ? nullptr : found.first();
}

static QString text_of(const QWidget *view, const char *name)
{
	auto *edit = widget<QLineEdit>(view, name);
	return edit ? edit->text() : QStringLiteral("<missing>");
}

/* Start a daemon over `body`, and hand back its socket. */
static QString start(QProcess *daemon, const QString &work, const QString &body)
{
	const QString etc = work + QStringLiteral("/etc");
	const QString run = work + QStringLiteral("/run");
	const QString wpa = work + QStringLiteral("/wpa");
	QDir().mkpath(etc);
	QDir().mkpath(run);
	QDir().mkpath(wpa);

	QFile conf(etc + QStringLiteral("/netcfgd.conf"));
	if (!conf.open(QIODevice::WriteOnly)) {
		return QString();
	}
	conf.write(body.toUtf8());
	conf.close();

	QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
	environment.insert(QStringLiteral("NCFG_CONFIG_DIR"), etc);
	environment.insert(QStringLiteral("NCFG_RUN_DIR"), run);
	// **And the control directory, which is a third path (0224).** Setting the
	// config and run directories reads as complete isolation and is not:
	// wpa_supplicant's control directory defaults to the host's
	// /run/wpa_supplicant, so a daemon started here swept the running machine's
	// reply sockets on startup and left two of its own behind on the way out.
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
		fprintf(stderr, "interface_load: skipping: %s is not built\n", NETCFGD_BINARY);
		return 0;
	}

	/* Everything the form has a field for, and nothing it does not: this half
	 * has to load and be saveable. */
	{
		QTemporaryDir work;
		QProcess daemon;
		const QString socket = start(&daemon, work.path(),
		    QStringLiteral("global { control { observe = \"any\" } }\n"
		                   "device eth0 { kind = \"physical\" }\n"
		                   "interface eth0 {\n"
		                   "\tconfig = [\"dhcp\", \"192.0.2.10/24\"]\n"
		                   "\troutes = [\"default via 192.0.2.1\", "
		                   "\"10.9.0.0/24 via 192.0.2.9\"]\n"
		                   "\tdns { mode = \"write_resolv_conf\" ; "
		                   "servers = [\"192.0.2.53\"] }\n"
		                   "\ton_drift = \"report\"\n"
		                   "\tpreference = 50\n"
		                   "\tforwarding = true\n"
		                   "\tnat = true\n"
		                   "}\n"));
		if (socket.isEmpty()) {
			fprintf(stderr, "interface_load: the daemon never bound its socket\n");
			daemon.kill();
			daemon.waitForFinished(2000);
			return 1;
		}

		ncfg_connection connection;
		QString error;
		if (!connection.open(socket, &error)) {
			fprintf(stderr, "interface_load: cannot reach the daemon: %s\n",
			    qPrintable(error));
			daemon.kill();
			daemon.waitForFinished(2000);
			return 1;
		}

		ncfg_interface_dialog dialog(&connection, QStringLiteral("eth0"));
		/* **The addressing list, in the document's order.** One combo used to
		 * stand for the whole list, so a composition it did not name -- two
		 * sources, a lease beside a fixed address -- was reported as
		 * unrepresentable and the interface could not be edited at all. */
		auto *sources = widget<QListWidget>(&dialog, "iface_sources");
		check(QString::number(sources ? sources->count() : -1), QStringLiteral("2"),
		    "both addressing sources are loaded");
		if (sources && sources->count() == 2) {
			check(sources->item(0)->data(Qt::UserRole).toString(),
			    QStringLiteral("dhcp"), "the first source is the lease");
			check(sources->item(1)->data(Qt::UserRole).toString(),
			    QStringLiteral("static"), "the second is the fixed address");
			check(sources->item(1)->data(Qt::UserRole + 1).toString(),
			    QStringLiteral("192.0.2.10/24"), "with the address beside it");
		}
		auto *routes = widget<QTableWidget>(&dialog, "iface_routes");
		check(QString::number(routes ? routes->rowCount() : -1), QStringLiteral("2"),
		    "both routes are loaded");
		if (routes && routes->rowCount() == 2) {
			/* **In the document's order, which is canonical and not the
			 * order the file was written in**: the compiler sorts routes, so
			 * `10.9.0.0/24` comes before `default`. Asserted as a set for
			 * that reason -- a test that pinned the file's order would be
			 * pinning something netcfgd does not promise. */
			QStringList destinations;
			for (int row = 0; row < routes->rowCount(); row++) {
				destinations << (routes->item(row, 0) ? routes->item(row, 0)->text()
				                                      : QString());
			}
			destinations.sort();
			check(destinations.join(QLatin1Char(' ')),
			    QStringLiteral("10.9.0.0/24 default"),
			    "the default route and the one to another subnet are both there");
		}
		auto *mode = widget<QComboBox>(&dialog, "iface_dns_mode");
		check(mode ? mode->currentData().toString() : QStringLiteral("<missing>"),
		    QStringLiteral("write_resolv_conf"), "the interface's dns mode is loaded");
		check(text_of(&dialog, "iface_dns_servers"), QStringLiteral("192.0.2.53"),
		    "and its nameservers");
		auto *drift = widget<QComboBox>(&dialog, "iface_on_drift");
		check(drift ? drift->currentData().toString() : QStringLiteral("<missing>"),
		    QStringLiteral("report"), "and what it does when the machine drifts");
		auto *preference = widget<QSpinBox>(&dialog, "iface_preference");
		check(QString::number(preference ? preference->value() : -1),
		    QStringLiteral("50"), "the preference is loaded");
		auto *forwarding = widget<QCheckBox>(&dialog, "iface_forwarding");
		check(forwarding && forwarding->isChecked() ? QStringLiteral("yes")
		                                           : QStringLiteral("no"),
		    QStringLiteral("yes"), "forwarding is loaded");

		/* **And it can be saved**, which is the half that was broken for
		 * every interface netcfgd writes itself. The refusal used to fire on
		 * any key that was *present*, and a compiled interface carries
		 * `hooks: []` and a `dns` scope whether anybody wrote them or not --
		 * so `ncfg wifi activate`'s own block could not be edited at all. An
		 * empty list is not content. */
		QMetaObject::invokeMethod(&dialog, "submit");
		auto *note = widget<QLabel>(&dialog, "iface_note");
		const QString said = note ? note->text() : QString();
		check(said.contains(QStringLiteral("would delete")) ? said
		                                                    : QStringLiteral("accepted"),
		    QStringLiteral("accepted"),
		    "and a block whose every key has a field is saveable");

		daemon.kill();
		daemon.waitForFinished(2000);
	}

	/* And a block carrying something the form cannot express. Saving must be
	 * refused, naming it -- loading harder would not help, because there is no
	 * field to load into.
	 *
	 * **`ipv6_token`, because `dns` is a field now.** The refusal used to be
	 * demonstrated with a `dns` scope, and the list of keys that trip it was
	 * "any key that is present" -- so a compiled interface carrying `hooks: []`
	 * and a default scope, which is what `ncfg wifi activate` writes, could not
	 * be edited at all. What is refused now is a key that holds something no
	 * field can. */
	{
		QTemporaryDir work;
		QProcess daemon;
		const QString socket = start(&daemon, work.path(),
		    QStringLiteral("global { control { observe = \"any\" } }\n"
		                   "device eth0 { kind = \"physical\" }\n"
		                   "interface eth0 {\n"
		                   "\tconfig = \"192.0.2.10/24\"\n"
		                   "\tipv6_token = \"::5\"\n"
		                   "}\n"));
		if (socket.isEmpty()) {
			fprintf(stderr, "interface_load: the second daemon never started\n");
			daemon.kill();
			daemon.waitForFinished(2000);
			return 1;
		}

		ncfg_connection connection;
		QString error;
		if (!connection.open(socket, &error)) {
			fprintf(stderr, "interface_load: cannot reach the second daemon\n");
			daemon.kill();
			daemon.waitForFinished(2000);
			return 1;
		}

		ncfg_interface_dialog dialog(&connection, QStringLiteral("eth0"));
		QMetaObject::invokeMethod(&dialog, "submit");
		auto *note = widget<QLabel>(&dialog, "iface_note");
		const QString said = note ? note->text() : QStringLiteral("<no note>");
		check(said.contains(QStringLiteral("ipv6_token")) &&
		        said.contains(QStringLiteral("would delete"))
		        ? QStringLiteral("refused")
		        : said,
		    QStringLiteral("refused"), "saving over an unmodelled key is refused");

		daemon.kill();
		daemon.waitForFinished(2000);
	}

	fprintf(stderr, "interface_load: %s\n", failures ? "FAILED" : "all checks passed");
	return failures ? 1 : 0;
}
