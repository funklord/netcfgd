/*
 * firewall_load.cpp -- the firewall tab saves what it loaded, whole.
 *
 * The firewall is one block, so every edit in the tab rewrites all of it: a
 * key the reader did not take, or the writer did not put back, is a match a
 * save deletes from a rule nobody touched -- and a rule that loses a match
 * filters traffic it was never meant to. So this writes a firewall using
 * every key 0294 and 0302 allow, loads it, saves it back through the dialog
 * without a change, and reads it again through the daemon, which compiles
 * it: anything dropped, reordered or refused fails here.
 *
 * HOW IT STOPS: two daemons, each killed at the end of its case; the wait
 * for a socket is bounded at ten seconds.
 */

#include "../src/firewall_dialog.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
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
	fprintf(stderr, "firewall_load: %-54s %s\n", what, ok ? "ok" : "FAILED");
	if (!ok) {
		fprintf(stderr, "               expected: %s\n", qPrintable(want));
		fprintf(stderr, "               actual:   %s\n", qPrintable(got));
		failures++;
	}
}

/* A daemon over `body`, with `drop_in` as `conf.d/firewall.conf` where it is
 * not empty -- the file the tab's save replaces. */
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
		QFile file(etc + QStringLiteral("/conf.d/firewall.conf"));
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
static QString press(ncfg_firewall_rule_dialog *dialog, const char *slot)
{
	QMetaObject::invokeMethod(dialog, slot);
	if (!dialog->outcome().isEmpty()) {
		return QStringLiteral("saved");
	}
	auto *note = dialog->findChild<QLabel *>(QStringLiteral("firewall_note"));
	return note ? note->text() : QStringLiteral("<no note>");
}

/* Every field of every rule, written out here rather than by the tab's own
 * block writer: comparing the writer's output before and after a save would
 * pass for a key the writer drops, since it would be missing from both. */
static QString dump(const ncfg_firewall_settings &settings)
{
	QStringList lines;
	const ncfg_firewall_chain_row *chains[] = { &settings.input, &settings.forward,
		&settings.output };
	lines << QStringLiteral("present=%1").arg(settings.present);
	for (const ncfg_firewall_chain_row *chain : chains) {
		lines << QStringLiteral("policy=%1").arg(chain->policy);
		for (const ncfg_firewall_rule_row &rule : chain->rules) {
			QStringList ports;
			for (int port : rule.ports) {
				ports << QString::number(port);
			}
			lines << QStringList { rule.name, rule.action, rule.protocol,
				ports.join(QLatin1Char(',')), rule.from.join(QLatin1Char(',')),
				rule.to.join(QLatin1Char(',')), rule.interface, rule.out_interface,
				rule.states.join(QLatin1Char(',')), rule.stations.join(QLatin1Char(',')) }
			             .join(QLatin1Char('|'));
		}
	}
	return lines.join(QLatin1Char('\n'));
}

static const char base[] =
    "global { control { observe = \"any\"; admin = \"any\" } }\n"
    "host_list \"kids\" { mac = [\"00:11:22:33:44:01\"] }\n";

static const char every_key[] =
    "firewall {\n"
    "\tinput {\n"
    "\t\tpolicy = \"drop\"\n"
    "\t\taccept \"established\" { state = [\"established\", \"related\"] }\n"
    "\t\taccept \"ssh\" { protocol = \"tcp\"; port = [22, 2222]; "
    "from = [\"10.0.0.0/8\", \"fd00::/8\"]; interface = \"eth0\" }\n"
    "\t\treject \"kids\" { mac = [\"@host_list:kids\", \"aa:bb:cc:*\"] }\n"
    "\t}\n"
    "\tforward {\n"
    "\t\tpolicy = \"drop\"\n"
    "\t\tdrop \"guest-lan\" { interface = \"guest0\"; out_interface = \"lan0\" }\n"
    "\t\taccept \"out\" { out_interface = \"wan0\"; to = [\"192.0.2.0/24\"] }\n"
    "\t}\n"
    "\toutput { policy = \"accept\" }\n"
    "}\n";

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);

	if (!QFile::exists(QStringLiteral(NETCFGD_BINARY))) {
		fprintf(stderr, "firewall_load: skipping: %s is not built\n", NETCFGD_BINARY);
		return 0;
	}

	QTemporaryDir work;
	QProcess      daemon;
	const QString socket = start(&daemon, work.path(), QString::fromLatin1(base),
	    QString::fromLatin1(every_key));
	if (socket.isEmpty()) {
		fprintf(stderr, "firewall_load: the daemon never started\n");
		stop(&daemon);
		return 1;
	}
	ncfg_connection connection;
	QString         error;
	if (!connection.open(socket, &error)) {
		fprintf(stderr, "firewall_load: cannot reach the daemon: %s\n", qPrintable(error));
		stop(&daemon);
		return 1;
	}

	ncfg_firewall_settings loaded;
	check(connection.firewall(&loaded, &error) ? QStringLiteral("read") : error,
	    QStringLiteral("read"), "the firewall reads");
	check(QStringLiteral("%1 %2 %3 %4 %5/%6/%7")
	          .arg(QString::number(loaded.present), loaded.input.policy,
	              loaded.forward.policy, loaded.output.policy,
	              QString::number(loaded.input.rules.size()),
	              QString::number(loaded.forward.rules.size()),
	              QString::number(loaded.output.rules.size())),
	    QStringLiteral("1 drop drop accept 3/2/0"), "  every chain, its policy and its rules");
	if (loaded.input.rules.size() == 3 && loaded.forward.rules.size() == 2) {
		const ncfg_firewall_rule_row &ssh = loaded.input.rules.at(1);
		check(QStringLiteral("%1 %2 %3:%4 %5 %6")
		          .arg(ssh.name, ssh.action, ssh.protocol)
		          .arg(ssh.ports.size() == 2 ? ssh.ports[1] : -1)
		          .arg(ssh.from.join(QLatin1Char(',')), ssh.interface),
		    QStringLiteral("ssh accept tcp:2222 10.0.0.0/8,fd00::/8 eth0"),
		    "  a rule's ports, sources and interface");
		check(loaded.input.rules.at(0).states.join(QLatin1Char(',')),
		    QStringLiteral("established,related"), "  its states");
		/* The list by name, not the addresses it stood for: a save would
		 * otherwise pin the rule to today's list. */
		check(loaded.input.rules.at(2).stations.join(QLatin1Char(',')),
		    QStringLiteral("@host_list:kids,aa:bb:cc:*"), "  its stations, the list named");
		check(loaded.forward.rules.at(0).out_interface, QStringLiteral("lan0"),
		    "  and where a forwarded packet leaves");
	}

	/* **Save with no change, and nothing moves.** The block the tab would
	 * write is compared before and after, so a key the round trip lost shows
	 * as a difference here rather than as a wider rule on a router. */
	const QString before = dump(loaded);
	{
		ncfg_firewall_rule_dialog dialog(&connection, loaded, QStringLiteral("forward"), 0);
		check(press(&dialog, "submit"), QStringLiteral("saved"),
		    "a forward rule saves unchanged through the dialog");
	}
	ncfg_firewall_settings again;
	check(connection.firewall(&again, &error) ? dump(again) : error, before,
	    "  and netcfgd compiles back the firewall it had, whole");
	const QString written =
	    QFile(work.path() + QStringLiteral("/etc/conf.d/firewall.conf")).exists()
	        ? QStringLiteral("written") : QStringLiteral("missing");
	check(written, QStringLiteral("written"), "  into the firewall drop-in");

	/* A new rule lands at the end of its chain, which is where nftables
	 * meets it last. */
	{
		ncfg_firewall_rule_dialog dialog(&connection, again, QStringLiteral("input"), -1);
		dialog.findChild<QLineEdit *>(QStringLiteral("firewall_name"))
		    ->setText(QStringLiteral("dns"));
		auto *protocol = dialog.findChild<QComboBox *>(QStringLiteral("firewall_protocol"));
		protocol->setCurrentIndex(protocol->findData(QStringLiteral("udp")));
		dialog.findChild<QLineEdit *>(QStringLiteral("firewall_ports"))
		    ->setText(QStringLiteral("53"));
		dialog.findChild<QLineEdit *>(QStringLiteral("firewall_interface"))
		    ->setText(QStringLiteral("lan0"));
		dialog.findChild<QCheckBox *>(QStringLiteral("firewall_state_new"))->setChecked(true);
		check(press(&dialog, "submit"), QStringLiteral("saved"), "a new input rule saves");
	}
	check(connection.firewall(&again, &error) && again.input.rules.size() == 4
	        ? QStringLiteral("%1 %2 %3")
	              .arg(again.input.rules.last().name, again.input.rules.last().protocol,
	                  again.input.rules.last().states.join(QLatin1Char(',')))
	        : error,
	    QStringLiteral("dns udp new"), "  and lands last in its chain");

	/* Leaving by an interface means nothing where nothing leaves. */
	{
		ncfg_firewall_rule_dialog dialog(&connection, again, QStringLiteral("input"), 0);
		dialog.findChild<QLineEdit *>(QStringLiteral("firewall_out_interface"))
		    ->setText(QStringLiteral("wan0"));
		const QString said = press(&dialog, "submit");
		check(said.startsWith(QStringLiteral("only a forwarded packet")) ? QStringLiteral("refused")
		                                                                  : said,
		    QStringLiteral("refused"), "an input rule leaving by an interface is refused");
	}
	/* Ports belong to a protocol that has them. */
	{
		ncfg_firewall_rule_dialog dialog(&connection, again, QStringLiteral("input"), 0);
		dialog.findChild<QLineEdit *>(QStringLiteral("firewall_ports"))
		    ->setText(QStringLiteral("80"));
		const QString said = press(&dialog, "submit");
		check(said.startsWith(QStringLiteral("only tcp and udp")) ? QStringLiteral("refused") : said,
		    QStringLiteral("refused"), "a port with no protocol is refused");
	}
	/* Moving a rule to another chain takes it out of the first. */
	{
		ncfg_firewall_rule_dialog dialog(&connection, again, QStringLiteral("input"), 3);
		auto *chain = dialog.findChild<QComboBox *>(QStringLiteral("firewall_chain"));
		chain->setCurrentIndex(chain->findData(QStringLiteral("forward")));
		check(press(&dialog, "submit"), QStringLiteral("saved"),
		    "a rule moved to another chain saves");
	}
	check(connection.firewall(&again, &error)
	        ? QStringLiteral("%1/%2 %3")
	              .arg(again.input.rules.size())
	              .arg(again.forward.rules.size())
	              .arg(again.forward.rules.isEmpty() ? QString() : again.forward.rules.last().name)
	        : error,
	    QStringLiteral("3/3 dns"), "  and is in the one it was moved to only");
	/* Delete, confirmed: the dialog asks first, so the write is made here as
	 * the dialog would make it, with the rule taken out. */
	{
		ncfg_firewall_settings next = again;
		next.forward.rules.removeLast();
		check(ncfg_firewall_write(&connection, next, &error) ? QStringLiteral("written") : error,
		    QStringLiteral("written"), "a rule removed writes");
		check(connection.firewall(&again, &error) ? dump(again) : error, before,
		    "  and the firewall is the one it started as");
	}
	stop(&daemon);

	/* **A firewall written by hand in netcfgd.conf is not taken over.** The
	 * drop-in is then a second `firewall` block, which the daemon refuses
	 * and says where the first is -- rather than an `override` leaving the
	 * hand-written block in place and silently dead. */
	QTemporaryDir by_hand;
	const QString second = start(&daemon, by_hand.path(),
	    QString::fromLatin1(base) + QString::fromLatin1(every_key), QString());
	ncfg_connection hand;
	if (second.isEmpty() || !hand.open(second, &error)) {
		fprintf(stderr, "firewall_load: the second daemon never started\n");
		stop(&daemon);
		return 1;
	}
	ncfg_firewall_settings in_conf;
	check(hand.firewall(&in_conf, &error) && in_conf.present ? QStringLiteral("read") : error,
	    QStringLiteral("read"), "a firewall in netcfgd.conf reads");
	const bool refused = !ncfg_firewall_write(&hand, in_conf, &error);
	check(refused && error.contains(QStringLiteral("netcfgd.conf")) ? QStringLiteral("refused")
	                                                                 : error,
	    QStringLiteral("refused"), "  and is not overwritten by a drop-in; the refusal names it");
	stop(&daemon);

	fprintf(stderr, "firewall_load: %s\n", failures ? "FAILED" : "all checks passed");
	return failures ? 1 : 0;
}
