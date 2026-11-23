/*
 * firewall_counts.cpp -- the firewall tab says what each rule matched (0337).
 *
 * Every verdict rule netcfgd writes carries a counter, and the tab's `matched`
 * column is that count, a written rule's kernel rules summed. This drives the
 * tab against a real daemon over a document with two rules, and how far it
 * can go depends on where it runs:
 *
 *   - **As an ordinary user** the daemon cannot install a table, so the
 *     status it answers holds no firewall, and each rule reads `not counted
 *     yet` -- said, rather than the blank a failed read leaves.
 *   - **As root in a network namespace** (`unshare -rn`, as tests/live/ runs
 *     firewall.sh), the daemon installs the table on start, three pings on
 *     loopback land on the `ping` rule, and the tab reads `3 packets` there
 *     and `0 packets` on the other.
 *
 * HOW IT STOPS: one daemon, killed at the end; the wait for its socket is
 * bounded at ten seconds and the wait for the table at another ten.
 */

#include "../src/firewall_view.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QProcess>
#include <QPushButton>
#include <QTableWidget>
#include <QTemporaryDir>
#include <QThread>

#include <cstdio>
#include <unistd.h>

static int failures;

static void check(const QString &got, const QString &want, const char *what)
{
	const bool ok = got == want;
	fprintf(stderr, "firewall_counts: %-52s %s\n", what, ok ? "ok" : "FAILED");
	if (!ok) {
		fprintf(stderr, "               expected: %s\n", qPrintable(want));
		fprintf(stderr, "               actual:   %s\n", qPrintable(got));
		failures++;
	}
}

/* The `matched` cell of the rule named `name`, or `<absent>`. */
static QString matched(ncfg_firewall_view *view, const QString &name)
{
	view->refresh();
	auto *cells = view->findChild<QTableWidget *>();
	if (!cells) {
		return QStringLiteral("<no table>");
	}
	for (int row = 0; row < cells->rowCount(); row++) {
		if (cells->item(row, 1) && cells->item(row, 1)->text() == name) {
			return cells->item(row, 4) ? cells->item(row, 4)->text() : QString();
		}
	}
	return QStringLiteral("<absent>");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);

	if (!QFile::exists(QStringLiteral(NETCFGD_BINARY))) {
		fprintf(stderr, "firewall_counts: skipping: %s is not built\n", NETCFGD_BINARY);
		return 0;
	}

	QTemporaryDir work;
	const QString etc = work.path() + QStringLiteral("/etc");
	const QString run = work.path() + QStringLiteral("/run");
	const QString wpa = work.path() + QStringLiteral("/wpa");
	QDir().mkpath(etc + QStringLiteral("/conf.d"));
	QDir().mkpath(run);
	QDir().mkpath(wpa);
	QFile conf(etc + QStringLiteral("/netcfgd.conf"));
	if (!conf.open(QIODevice::WriteOnly)) {
		fprintf(stderr, "firewall_counts: cannot write the configuration\n");
		return 1;
	}
	conf.write("global { control { root = \"any\" } }\n"
	           "preset \"web\" { input { accept \"http\" { protocol = \"tcp\"; port = 80 } } }\n"
	           "firewall {\n"
	           "\tpresets = [\"web\"]\n"
	           "\tinput {\n"
	           "\t\tpolicy = \"accept\"\n"
	           "\t\tslot \"quarantine\" { action = \"drop\"; match = \"from\" }\n"
	           "\t\taccept \"ping\" { protocol = \"icmp\"; icmp_type = \"echo-request\" }\n"
	           "\t\tdrop \"telnet\" { protocol = \"tcp\"; port = 23 }\n"
	           "\t}\n"
	           "\tforward { policy = \"accept\" }\n"
	           "\toutput { policy = \"accept\" }\n"
	           "}\n");
	conf.close();

	/* Root here only in a namespace of its own: an ordinary run must never
	 * reach the host's firewall, and the daemon is told nothing else. */
	const bool privileged = geteuid() == 0 && qEnvironmentVariableIsSet("NCFG_COUNTS_NAMESPACE");
	QProcess daemon;
	QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
	environment.insert(QStringLiteral("NCFG_CONFIG_DIR"), etc);
	environment.insert(QStringLiteral("NCFG_RUN_DIR"), run);
	environment.insert(QStringLiteral("NCFG_WPA_CTRL_DIR"), wpa);
	daemon.setProcessEnvironment(environment);
	if (geteuid() == 0 && !privileged) {
		fprintf(stderr, "firewall_counts: skipping: root outside a namespace this test "
		                "made would change the host's firewall\n");
		return 0;
	}
	daemon.start(QStringLiteral(NETCFGD_BINARY), {});

	const QString socket = run + QStringLiteral("/netcfgd.sock");
	const QString listening = run + QStringLiteral("/fuzznet.sock");
	QElapsedTimer waited;
	waited.start();
	while (!QFile::exists(listening) && waited.elapsed() < 10000) {
		QThread::msleep(50);
	}
	ncfg_connection connection;
	QString         error;
	if (!QFile::exists(listening) || !connection.open(socket, &error)) {
		fprintf(stderr, "firewall_counts: the daemon never started: %s\n", qPrintable(error));
		daemon.kill();
		daemon.waitForFinished(2000);
		return 1;
	}

	ncfg_firewall_view view(&connection);
	if (!privileged) {
		check(matched(&view, QStringLiteral("ping")), QStringLiteral("not counted yet"),
		    "a rule the kernel does not hold is not counted yet");
		check(matched(&view, QStringLiteral("telnet")), QStringLiteral("not counted yet"),
		    "  and neither is the other");
		/* 0340: a slot the kernel does not hold says so, and a live write
		 * into it is refused with the daemon's sentence rather than in
		 * silence. */
		check(matched(&view, QStringLiteral("slot quarantine")),
		    QStringLiteral("not in the kernel yet"), "a slot the kernel does not hold says so");
		QString said_write;
		QObject::connect(&view, &ncfg_firewall_view::reported,
		    [&said_write](const QString &summary) { said_write = summary; });
		check(view.write_slot_member(QStringLiteral("quarantine"), QStringLiteral("192.0.2.7"),
		          true, QString()) || said_write.isEmpty()
		          ? QStringLiteral("unexplained") : QStringLiteral("refused, saying why"),
		    QStringLiteral("refused, saying why"), "  and a member written into it is refused");
	} else {
		/* The table is the daemon's first pass; asked again until it shows. */
		waited.restart();
		while (matched(&view, QStringLiteral("ping")) != QLatin1String("0 packets") &&
		       waited.elapsed() < 10000) {
			QThread::msleep(200);
		}
		check(matched(&view, QStringLiteral("ping")), QStringLiteral("0 packets"),
		    "an installed rule starts at nothing");
		QProcess::execute(QStringLiteral("ip"), { QStringLiteral("link"), QStringLiteral("set"),
		    QStringLiteral("lo"), QStringLiteral("up") });
		QProcess pinger;
		pinger.setStandardOutputFile(QProcess::nullDevice());
		pinger.start(QStringLiteral("ping"), { QStringLiteral("-c"), QStringLiteral("3"),
		    QStringLiteral("-i"), QStringLiteral("0.2"), QStringLiteral("-W"),
		    QStringLiteral("1"), QStringLiteral("127.0.0.1") });
		pinger.waitForFinished(10000);
		/* The daemon's observation is a pass old at most; the backstop is
		 * five seconds. */
		waited.restart();
		while (matched(&view, QStringLiteral("ping")) != QLatin1String("3 packets") &&
		       waited.elapsed() < 10000) {
			QThread::msleep(200);
		}
		check(matched(&view, QStringLiteral("ping")), QStringLiteral("3 packets"),
		    "three pings are three packets on the rule they matched");
		check(matched(&view, QStringLiteral("telnet")), QStringLiteral("0 packets"),
		    "  and none on the rule they did not");
		/* 0340: a member written from the tab lands in the kernel and shows
		 * in the slot's row; removed, it goes. */
		check(view.write_slot_member(QStringLiteral("quarantine"), QStringLiteral("192.0.2.7"),
		          true, QStringLiteral("10m")) ? QStringLiteral("written")
		                                       : QStringLiteral("refused"),
		    QStringLiteral("written"), "a member is written into a slot from the tab");
		/* The row is the daemon's observation, a pass old at most. */
		waited.restart();
		while (!matched(&view, QStringLiteral("slot quarantine")).startsWith(
		           QStringLiteral("192.0.2.7;")) && waited.elapsed() < 10000) {
			QThread::msleep(200);
		}
		check(matched(&view, QStringLiteral("slot quarantine")).startsWith(
		          QStringLiteral("192.0.2.7;")) ? QStringLiteral("shown")
		                                        : matched(&view, QStringLiteral("slot quarantine")),
		    QStringLiteral("shown"), "  and shows in the slot's row");
		(void)view.write_slot_member(QStringLiteral("quarantine"), QStringLiteral("192.0.2.7"),
		    false, QString());
		waited.restart();
		while (!matched(&view, QStringLiteral("slot quarantine")).startsWith(
		           QStringLiteral("empty;")) && waited.elapsed() < 10000) {
			QThread::msleep(200);
		}
		check(matched(&view, QStringLiteral("slot quarantine")).startsWith(QStringLiteral("empty;"))
		          ? QStringLiteral("gone") : matched(&view, QStringLiteral("slot quarantine")),
		    QStringLiteral("gone"), "  and removed, is gone");
	}

	/* 0341: a preset's rule is shown and is not the tab's to move or edit;
	 * asked to, it says where the rule is written and writes nothing. Move
	 * rather than edit, so a guard that failed could not hang this in a
	 * modal dialog. */
	{
		auto       *cells = view.findChild<QTableWidget *>();
		auto       *up = view.findChild<QPushButton *>(QStringLiteral("firewall_up"));
		QString     said;
		const bool  drop_in = QFile::exists(etc + QStringLiteral("/conf.d/firewall.conf"));
		int         row = -1;

		QObject::connect(&view, &ncfg_firewall_view::reported,
		    [&said](const QString &summary) { said = summary; });
		view.refresh();
		for (int at = 0; cells && at < cells->rowCount(); at++) {
			if (cells->item(at, 1) && cells->item(at, 1)->text() == QLatin1String("web/http")) {
				row = at;
			}
		}
		check(row >= 0 ? QStringLiteral("shown") : QStringLiteral("absent"),
		    QStringLiteral("shown"), "a preset's rule is shown under its preset's name");
		if (row >= 0 && up) {
			cells->selectRow(row);
			up->click();
		}
		check(said.contains(QStringLiteral("preset `web`"))
		        ? QStringLiteral("refused") : QStringLiteral("not refused"),
		    QStringLiteral("refused"), "  and moving it is refused, naming the preset");
		/* 0340: a slot is shown first in its chain, and is not the tab's to
		 * move either. */
		int slot_row = -1;
		for (int at = 0; cells && at < cells->rowCount(); at++) {
			if (cells->item(at, 1) &&
			    cells->item(at, 1)->text() == QLatin1String("slot quarantine")) {
				slot_row = at;
			}
		}
		check(slot_row == 0 ? QStringLiteral("first") : QString::number(slot_row),
		    QStringLiteral("first"), "a slot is shown, first in its chain");
		said.clear();
		if (slot_row >= 0 && up) {
			cells->selectRow(slot_row);
			up->click();
		}
		check(said.contains(QStringLiteral("ncfg slot")) ? QStringLiteral("refused")
		                                                 : QStringLiteral("not refused"),
		    QStringLiteral("refused"), "  and moving it is refused, saying how it is written");
		check(QFile::exists(etc + QStringLiteral("/conf.d/firewall.conf")) == drop_in
		        ? QStringLiteral("unwritten") : QStringLiteral("written"),
		    QStringLiteral("unwritten"), "  with nothing written");
	}

	daemon.kill();
	daemon.waitForFinished(2000);
	fprintf(stderr, "firewall_counts: %s\n", failures ? "FAILED" : "all checks passed");
	return failures ? 1 : 0;
}
