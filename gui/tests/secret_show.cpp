/*
 * secret_show.cpp -- the secrets view shows a stored credential to `root`.
 *
 * 0328 lets the `root` tier on the machine itself read a credential back,
 * and the window's `show...` is the button somebody presses to give a guest
 * the wifi password. What is checked is the whole path: the button is off
 * until a stored row is chosen, and pressing it asks the daemon, which reads
 * the store through its resolver, and the box shows exactly what is stored --
 * a `<` included, since a box left to guess its format would drop one.
 *
 * A real daemon, as tunnel_buttons starts one, whose control block opens
 * `root` to any caller: this runs as an ordinary user, and the refusal for
 * anybody below `root` is authorize_test's.
 *
 * HOW IT STOPS: one daemon, killed at the end; the wait for its socket is
 * bounded at ten seconds, and the box is closed by a timer that fires once.
 */

#include "../src/secrets_view.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QTableWidget>
#include <QTemporaryDir>
#include <QThread>
#include <QTextDocument>
#include <QTimer>

#include <cstdio>

static int failures;

static void check(const QString &got, const QString &want, const char *what)
{
	const bool ok = got == want;
	fprintf(stderr, "secret_show: %-59s %s\n", what, ok ? "ok" : "FAILED");
	if (!ok) {
		fprintf(stderr, "              expected: %s\n", qPrintable(want));
		fprintf(stderr, "              actual:   %s\n", qPrintable(got));
		failures++;
	}
}

static bool write_file(const QString &path, const QString &text)
{
	QFile file(path);
	if (!file.open(QIODevice::WriteOnly)) {
		return false;
	}
	file.write(text.toUtf8());
	return true;
}

/* Select the row named `name`, as a click would. */
static bool select(QTableWidget *table, const QString &name)
{
	for (int row = 0; row < table->rowCount(); row++) {
		if (table->item(row, 0) && table->item(row, 0)->text() == name) {
			table->selectRow(row);
			return true;
		}
	}
	return false;
}

static QString enabled(const QPushButton *button)
{
	return QString::fromLatin1(button->isEnabled() ? "enabled" : "disabled");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);

	if (!QFile::exists(QStringLiteral(NETCFGD_BINARY))) {
		fprintf(stderr, "secret_show: skipping: %s is not built\n", NETCFGD_BINARY);
		return 0;
	}

	QTemporaryDir work;
	const QString etc = work.path() + QStringLiteral("/etc");
	const QString run = work.path() + QStringLiteral("/run");
	const QString wpa = work.path() + QStringLiteral("/wpa");
	QDir().mkpath(etc + QStringLiteral("/secrets"));
	QDir().mkpath(run);
	QDir().mkpath(wpa);
	QFile::setPermissions(etc + QStringLiteral("/secrets"),
	    QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
	const QString stored = QStringLiteral("cafe <au> lait");
	if (!write_file(etc + QStringLiteral("/netcfgd.conf"),
	        QStringLiteral("global { control { root = \"any\" } }\n"
	                       "network \"Guest\" {\n\twifi { psk = \"@secret:guest\" }\n}\n"
	                       "network \"Office\" {\n\twifi { psk = \"@secret:office\" }\n}\n")) ||
	    !write_file(etc + QStringLiteral("/secrets/guest"), stored) ||
	    !QFile::setPermissions(etc + QStringLiteral("/secrets/guest"),
	        QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
		fprintf(stderr, "secret_show: could not write the fixture\n");
		return 1;
	}

	QProcess daemon;
	QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
	environment.insert(QStringLiteral("NCFG_CONFIG_DIR"), etc);
	environment.insert(QStringLiteral("NCFG_RUN_DIR"), run);
	// The control directory too, or the daemon sweeps the host's (0224).
	environment.insert(QStringLiteral("NCFG_WPA_CTRL_DIR"), wpa);
	daemon.setProcessEnvironment(environment);
	daemon.start(QStringLiteral(NETCFGD_BINARY), { QStringLiteral("--no-apply-on-start") });

	const QString listening = run + QStringLiteral("/fuzznet.sock");
	QElapsedTimer waited;
	waited.start();
	while (!QFile::exists(listening) && waited.elapsed() < 10000) {
		QThread::msleep(50);
	}
	if (!QFile::exists(listening)) {
		fprintf(stderr, "secret_show: the daemon did not come up\n");
		daemon.kill();
		daemon.waitForFinished(2000);
		return 1;
	}

	ncfg_connection connection;
	QString error;
	if (!connection.open(run + QStringLiteral("/netcfgd.sock"), &error)) {
		fprintf(stderr, "secret_show: could not connect: %s\n", qPrintable(error));
		daemon.kill();
		daemon.waitForFinished(2000);
		return 1;
	}

	ncfg_secrets_view view(&connection);
	view.refresh();
	auto *table = view.findChild<QTableWidget *>();
	auto *show = view.findChild<QPushButton *>(QStringLiteral("show_secret"));
	if (!table || !show) {
		fprintf(stderr, "secret_show: the view has no table or no show button\n");
		daemon.kill();
		daemon.waitForFinished(2000);
		return 1;
	}

	check(enabled(show), QStringLiteral("disabled"), "with nothing selected, nothing to show");
	select(table, QStringLiteral("office"));
	check(enabled(show), QStringLiteral("disabled"), "a credential that is not stored is not offered");
	select(table, QStringLiteral("guest"));
	check(enabled(show), QStringLiteral("enabled"), "a stored one is, to root on this machine");

	QString shown = QStringLiteral("<no box>");
	QTimer::singleShot(0, [&shown]() {
		for (QWidget *widget : QApplication::topLevelWidgets()) {
			auto *box = qobject_cast<QMessageBox *>(widget);
			if (box && box->objectName() == QLatin1String("secret_value")) {
				QTextDocument rendered;
				rendered.setHtml(box->text());
				shown = rendered.toPlainText();
				box->done(QMessageBox::Close);
			}
		}
	});
	show->click();
	check(shown.section(QLatin1Char('\n'), -1), stored,
	    "the box shows what is stored, a `<` and all");

	QString value;
	check(QString::fromLatin1(connection.secret_get(QStringLiteral("office"), &value, &error)
	                              ? "shown"
	                              : "refused"),
	    QStringLiteral("refused"), "one the store does not hold is refused, not shown empty");

	daemon.kill();
	daemon.waitForFinished(5000);

	if (failures) {
		fprintf(stderr, "secret_show: %d check(s) failed\n", failures);
		return 1;
	}
	fprintf(stderr, "secret_show: all checks passed\n");
	return 0;
}
