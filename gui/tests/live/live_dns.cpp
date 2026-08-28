/*
 * live_dns.cpp -- the dns tab against a real daemon.
 *
 * WHY THIS EXISTS
 *   The tab writes a configuration drop-in through the daemon at the `admin`
 *   tier. What it cannot be trusted about is the join: whether pressing the
 *   button produces a *drop-in netcfgd accepts and re-reads*, or produces text
 *   the compiler rejects and a widget that looks like it worked.
 *
 *   That is the same seam `live_add_dialog` exists for, and the same reason:
 *   a request can be well formed and still say something the document does not
 *   mean.
 *
 * WHAT IT ASSERTS
 *   The daemon's own answer afterwards, read back through `dns()` -- which
 *   goes to the compiled document, so a file netcfgd wrote but could not
 *   compile would fail here rather than pass. The file on disk is checked too,
 *   because the two can disagree and the disagreement is worth naming.
 *
 *   Driven by clicking the button, which is what an operator does. `apply_mode`
 *   is a private slot and calling it directly would test a function rather than
 *   a tab.
 */

#include "../../src/dns_view.h"
#include "../../src/ncfg_connection.h"

#include <QApplication>
#include <QComboBox>
#include <QFile>
#include <QPushButton>

#include <cstdio>

static int failures;

static void check(const char *what, bool condition, const QString &detail = QString())
{
	if (condition) {
		printf("ok   %s\n", what);
	} else {
		printf("FAIL %s\n", what);
		if (!detail.isEmpty()) {
			printf("       %s\n", detail.toUtf8().constData());
		}
		failures++;
	}
	fflush(stdout);
}

int main(int argc, char **argv)
{
	QApplication app(argc, argv);
	const QString conf = QString::fromUtf8(qgetenv("NCFG_CONFIG_DIR")) + "/conf.d/";

	ncfg_connection connection;
	QString error;
	if (!connection.open(QString(), &error)) {
		printf("FAIL the dns tab's connection reaches netcfgd\n       %s\n",
		    error.toUtf8().constData());
		return 1;
	}
	check("the dns tab's connection reaches netcfgd", true);

	ncfg_dns_view view(&connection);
	view.refresh();

	/* The default, and the whole reason the tab exists: `none` is correct and
	 * invisible, so it has to be visible here before anything is set. */
	ncfg_dns_row before;
	check("the daemon starts with resolution unmanaged",
	    connection.dns(&before, &error) && before.mode == QStringLiteral("none"),
	    before.mode + QStringLiteral(" ") + error);
	check("and says so in a sentence rather than a bare key",
	    before.summary().contains(QStringLiteral("not managed by netcfgd")),
	    before.summary());

	auto *box = view.findChild<QComboBox *>(QStringLiteral("dns_mode"));
	auto *set = view.findChild<QPushButton *>(QStringLiteral("dns_apply"));
	if (!box || !set) {
		check("the tab has a mode and a button", false);
		return 1;
	}
	check("the tab has a mode and a button", true);

	/* The box shows what is set, so opening the tab and pressing without
	 * reading changes nothing. */
	check("and it opens on the mode that is already set",
	    box->currentData().toString() == QStringLiteral("none"),
	    box->currentData().toString());

	const int at = box->findData(QStringLiteral("write_resolv_conf"));
	check("write_resolv_conf is offered", at >= 0);
	box->setCurrentIndex(at);
	set->click();

	/* The daemon's answer, not the widget's. This goes through the compiled
	 * document, so text netcfgd wrote and could not compile fails here. */
	ncfg_dns_row after;
	check("the daemon compiled what the tab wrote",
	    connection.dns(&after, &error) && after.mode == QStringLiteral("write_resolv_conf"),
	    after.mode + QStringLiteral(" ") + error);

	/* And the file, because a document that changed with nothing on disk
	 * would not survive a restart -- the drop-in is the durable half. */
	QFile written(conf + QStringLiteral("50-dns.conf"));
	check("and left a drop-in behind", written.exists(), written.fileName());
	if (written.open(QIODevice::ReadOnly)) {
		const QString text = QString::fromUtf8(written.readAll());
		check("naming the mode it was asked for",
		    text.contains(QStringLiteral("write_resolv_conf")), text);
		/* Nothing an operator typed reaches the daemon: the tab composes the
		 * block from a key out of a fixed list. A drop-in carrying anything
		 * else would mean that stopped being true. */
		check("and nothing else", !text.contains(QStringLiteral("hook")) &&
		    !text.contains(QStringLiteral("run_as")), text);
		written.close();
	}

	/* Twice, because the file is this tab's own and setting a mode again
	 * should edit it rather than fail on the second press -- which is what a
	 * drop-in written without `replace` would do. */
	const int back = box->findData(QStringLiteral("none"));
	box->setCurrentIndex(back);
	set->click();
	ncfg_dns_row again;
	check("setting it a second time edits the same drop-in",
	    connection.dns(&again, &error) && again.mode == QStringLiteral("none"),
	    again.mode + QStringLiteral(" ") + error);

	printf("\n");
	if (failures) {
		printf("live_dns: %d failed\n", failures);
		return 1;
	}
	printf("live_dns: all checks passed\n");
	return 0;
}
