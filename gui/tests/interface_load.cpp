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

/* Start a daemon over `body`, and hand back its socket. `drop_in`, where
 * given, is `conf.d/interface-eth0.conf`: the file the interface dialog owns
 * and replaces, which is where an interface it edits lives -- one declared in
 * `netcfgd.conf` instead is a duplicate its save cannot write (10.608). */
static QString start(QProcess *daemon, const QString &work, const QString &body,
    const QString &drop_in = QString())
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
	if (!drop_in.isEmpty()) {
		QDir().mkpath(etc + QStringLiteral("/conf.d"));
		QFile owned(etc + QStringLiteral("/conf.d/interface-eth0.conf"));
		if (!owned.open(QIODevice::WriteOnly)) {
			return QString();
		}
		owned.write(drop_in.toUtf8());
		owned.close();
	}

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
		/* `admin` open, so the save is a save: with it at `root` the dialog
		 * was refused for permission, and "saveable" could only mean "not
		 * refused for an unmodelled key" (10.608). */
		const QString socket = start(&daemon, work.path(),
		    QStringLiteral("global { control { observe = \"any\"; admin = \"any\" } }\n"
		                   "device eth0 { kind = \"physical\" }\n"),
		    QStringLiteral("interface eth0 {\n"
		                   "\tconfig = [\"dhcp\", \"192.0.2.10/24\"]\n"
		                   "\troutes = [\"default via 192.0.2.1\", "
		                   "\"10.9.0.0/24 via 192.0.2.9\"]\n"
		                   "\tdns { mode = \"write_resolv_conf\" ; "
		                   "servers = [\"192.0.2.53\"] }\n"
		                   "\ton_drift = \"report\"\n"
		                   "\tpreference = 50\n"
		                   "\tforwarding = true\n"
		                   "\tnat = true\n"
		                   "\tdhcp_server { range = \"192.0.2.50-192.0.2.60\"; lease = 3600; "
		                   "dns = [\"192.0.2.53\"]; host \"tv\" { mac = \"AA:BB:CC:DD:EE:01\"; "
		                   "address = \"192.0.2.20\" } }\n"
		                   "\tport_forward \"web\" { protocol = \"tcp\"; port = 443; "
		                   "to = \"192.0.2.20\"; to_port = 8443; hairpin = false }\n"
		                   "\tipv6_token = \"::5\"\n"
		                   "\tguard = \"nfs root\"\n"
		                   "\tadvertise { backend = \"radvd\"; prefixes = [\"@pd:wan0/1\"]; "
		                   "managed = true; lifetime = 1800 }\n"
		                   "\tdot1x { eap = \"peap\"; identity = \"me@example\"; "
		                   "password = \"@secret:wired\"; ca_cert = \"/etc/ssl/ca.pem\" }\n"
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
		/* A DHCP server, a field since 10.608 rather than a refusal. */
		auto *serving = widget<QCheckBox>(&dialog, "iface_dhcp_server");
		auto *lease = widget<QSpinBox>(&dialog, "iface_dhcp_lease");
		check(serving && serving->isChecked() ? QStringLiteral("yes") : QStringLiteral("no"),
		    QStringLiteral("yes"), "a DHCP server is loaded");
		check(text_of(&dialog, "iface_dhcp_range"), QStringLiteral("192.0.2.50-192.0.2.60"),
		    "  with its range");
		check(QString::number(lease ? lease->value() : -1), QStringLiteral("3600"),
		    "  its lease");
		check(text_of(&dialog, "iface_dhcp_dns"), QStringLiteral("192.0.2.53"),
		    "  and the DNS server it offers");

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
		/* Read back through the daemon, so a DHCP server the dialog wrote and
		 * the compiler refused fails here rather than passing on a note. */
		ncfg_interface_config saved;
		check(connection.interface_config(QStringLiteral("eth0"), &saved, &error) &&
		        saved.dhcp_server && saved.dhcp_range == QStringLiteral("192.0.2.50-192.0.2.60") &&
		        saved.dhcp_lease == 3600 && saved.dhcp_dns == QStringLiteral("192.0.2.53")
		        ? QStringLiteral("kept")
		        : QStringLiteral("%1 %2 %3 %4").arg(error, saved.dhcp_range)
		              .arg(saved.dhcp_lease).arg(saved.dhcp_dns),
		    QStringLiteral("kept"), "  and the DHCP server survives the save");
		/* **Through the dialog's own file**, or the reread above would pass on
		 * the hand-written one it replaces -- which already says all three, so
		 * the header the dialog writes is what proves the save happened. */
		QFile written(work.path() + QStringLiteral("/etc/conf.d/interface-eth0.conf"));
		const QString wrote = written.open(QIODevice::ReadOnly)
		    ? QString::fromUtf8(written.readAll())
		    : QStringLiteral("<no file>");
		check(wrote.startsWith(QStringLiteral("# Written by netcfgd's gui")) &&
		        wrote.contains(QStringLiteral("\tdhcp_server {")) &&
		        wrote.contains(QStringLiteral("range = \"192.0.2.50-192.0.2.60\"")) &&
		        wrote.contains(QStringLiteral("lease = 3600")) &&
		        wrote.contains(QStringLiteral("dns = [\"192.0.2.53\"]"))
		        ? QStringLiteral("written")
		        : wrote,
		    QStringLiteral("written"), "  written by the dialog, all three of its fields");
		/* 10.612: the reservation, the forward, the token and the guard, which
		 * the dialog refused to save over until it had fields for them. */
		check(wrote.contains(QStringLiteral("host \"tv\" { mac = \"AA:BB:CC:DD:EE:01\"; "
		                                    "address = \"192.0.2.20\" }")) &&
		        wrote.contains(QStringLiteral("port_forward \"web\" { protocol = \"tcp\"; port = "
		                                    "443; to = \"192.0.2.20\"; to_port = 8443; hairpin = "
		                                    "false }")) &&
		        wrote.contains(QStringLiteral("ipv6_token = \"::5\"")) &&
		        wrote.contains(QStringLiteral("guard = \"nfs root\"")) &&
		        wrote.contains(QStringLiteral("\tadvertise {\n\t\tbackend = \"radvd\"\n"
		                                    "\t\tprefixes = [\"@pd:wan0/1\"]\n"
		                                    "\t\tmanaged = true\n\t\tlifetime = 1800\n\t}")) &&
		        wrote.contains(QStringLiteral("\tdot1x {\n\t\teap = \"peap\"\n\t\tidentity = "
		                                    "\"me@example\"\n\t\tca_cert = \"/etc/ssl/ca.pem\"\n"
		                                    "\t\tpassword = \"@secret:wired\"\n\t}"))
		        ? QStringLiteral("written")
		        : wrote,
		    QStringLiteral("written"),
		    "  and its reservation, port forward, token, guard, advertisement and 802.1X");

		daemon.kill();
		daemon.waitForFinished(2000);
	}

	/* **What Save used to drop or refuse, carried through** (10.615).
	 *
	 * Dropped without a word: a static address's lifetimes, a `dhcp6`
	 * prefix delegation request and SLAAC's privacy -- the reader saw only
	 * the head of each entry, and the form wrote the head back. Refused: a
	 * route's `src`, `table` and `onlink`, a delegated address (whose check
	 * looked for a member the document does not have, so it never fired),
	 * and an exclusive routing domain. Each is written by hand, the dialog
	 * saves it, and both the file and the daemon's reading of it are checked.
	 *
	 * This case used to be the refusal. Nothing the language can write is
	 * refused for an interface now: what is still named -- an exec backend,
	 * a server's port, a route's scope -- has no spelling in it, so no
	 * compiled document carries one. */
	{
		QTemporaryDir work;
		QProcess daemon;
		const QString socket = start(&daemon, work.path(),
		    /* `wan0`, because a delegated address names the interface whose
		     * delegation it comes from, and the compiler refuses one naming an
		     * interface that asks for none. */
		    QStringLiteral("global { control { observe = \"any\"; admin = \"any\" } }\n"
		                   "device eth0 { kind = \"physical\" }\n"
		                   "interface wan0 { config = [\"dhcp6 pd\"] }\n"),
		    QStringLiteral("interface eth0 {\n"
		                   "\tconfig = [\"192.0.2.10/24 preferred_lft 600 valid_lft 900\", "
		                   "\"10.0.0.1/32 peer 10.0.0.2\", \"dhcp6 pd pd_length 56\", "
		                   "\"slaac privacy prefer_temporary\", \"@pd:wan0/1=::1/64\"]\n"
		                   "\troutes = [\"10.9.0.0/24 via 192.0.2.254 src 192.0.2.10 table 100 "
		                   "onlink\"]\n"
		                   "\tdns { mode = \"resolved\"; domains = [\"~corp.example\"] }\n"
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

		ncfg_interface_config read;
		check(connection.interface_config(QStringLiteral("eth0"), &read, &error)
		        ? read.unmodelled
		        : error,
		    QString(), "netcfgd says the dialog can carry all of it");
		ncfg_interface_dialog dialog(&connection, QStringLiteral("eth0"));
		QMetaObject::invokeMethod(&dialog, "submit");
		auto *note = widget<QLabel>(&dialog, "iface_note");
		/* The outcome, not the note's wording: a note that said anything but
		 * "would delete" -- a refusal for permission, say -- read as a save. */
		check(!dialog.outcome().isEmpty() ? QStringLiteral("saved")
		                                  : (note ? note->text() : QStringLiteral("<no note>")),
		    QStringLiteral("saved"), "and it is saved");

		QFile written(work.path() + QStringLiteral("/etc/conf.d/interface-eth0.conf"));
		const QString wrote = written.open(QIODevice::ReadOnly)
		    ? QString::fromUtf8(written.readAll())
		    : QStringLiteral("<no file>");
		const QStringList wanted = {
			QStringLiteral("\"192.0.2.10/24 preferred_lft 600 valid_lft 900\""),
			QStringLiteral("\"10.0.0.1/32 peer 10.0.0.2\""),
			QStringLiteral("\"dhcp6 pd pd_length 56\""),
			QStringLiteral("\"slaac privacy prefer_temporary\""),
			QStringLiteral("\"@pd:wan0/1=::1/64\""),
			QStringLiteral("\"10.9.0.0/24 via 192.0.2.254 src 192.0.2.10 table 100 onlink\""),
			QStringLiteral("\"~corp.example\""),
		};
		QStringList missing;
		for (const QString &one : wanted) {
			if (!wrote.contains(one)) {
				missing << one;
			}
		}
		check(wrote.startsWith(QStringLiteral("# Written by netcfgd's gui")) && missing.isEmpty()
		        ? QStringLiteral("written")
		        : missing.join(QLatin1Char(' ')) + QStringLiteral("\n") + wrote,
		    QStringLiteral("written"),
		    "  each entry's options, the delegation, the route and the domain, as written");

		ncfg_interface_config saved;
		const bool reread = connection.interface_config(QStringLiteral("eth0"), &saved, &error);
		QStringList options;
		for (const ncfg_address_source_row &source : saved.sources) {
			options << source.options;
		}
		check(reread && saved.sources.size() == 5 && saved.routes.size() == 1 &&
		        saved.routes[0].src == QStringLiteral("192.0.2.10") &&
		        saved.routes[0].table == 100 && saved.routes[0].onlink &&
		        saved.dns.domains == QStringLiteral("~corp.example")
		        ? options.join(QLatin1Char('|'))
		        : QStringLiteral("%1 sources, %2 routes, %3").arg(saved.sources.size())
		              .arg(saved.routes.size()).arg(error),
		    QStringLiteral("preferred_lft 600 valid_lft 900|peer 10.0.0.2|pd pd_length 56|"
		                   "privacy prefer_temporary|"),
		    "  and netcfgd compiles it back the same");

		daemon.kill();
		daemon.waitForFinished(2000);
	}

	fprintf(stderr, "interface_load: %s\n", failures ? "FAILED" : "all checks passed");
	return failures ? 1 : 0;
}
