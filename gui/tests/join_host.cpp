/*
 * join_host.cpp -- the desktop's "Another host..." button (project.md 10.735).
 *
 * WHY THIS EXISTS
 *   A desktop opens on this machine, and this button is how one reaches a host
 *   elsewhere: it asks for a code and runs `ncfg join`. What must hold: it is
 *   offered on a machine that has no host in its box, a key said by `ncfg join`
 *   lands in the box and is chosen, and a refusal is said in ncfg's words and
 *   leaves the box as it was. `note` hears only the pane in front, so the first
 *   version's sentences reached nobody, and this is what found that.
 *
 *   `ncfg` is a script here, first on the PATH, so nothing joins anything.
 *
 * HOW IT STOPS: every wait is a count of event-loop turns, and the script exits
 * at once. The directory is QTemporaryDir's.
 */

#include "../src/main_window.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QComboBox>
#include <QDeadlineTimer>
#include <QFile>
#include <QInputDialog>
#include <QLabel>
#include <QPushButton>
#include <QTemporaryDir>
#include <QTimer>

#include <cstdio>
#include <cstdlib>

static int failures;

static void check(bool condition, const char *what, const QString &detail = QString())
{
	fprintf(stderr, "%-68s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		if (!detail.isEmpty()) {
			fprintf(stderr, "    %s\n", qPrintable(detail));
		}
		failures++;
	}
}

/* Answers the dialog the button is about to open, once it is up. */
static void answer_with(const QString &code)
{
	QTimer::singleShot(50, qApp, [code]() {
		for (QWidget *widget : QApplication::topLevelWidgets()) {
			if (auto *dialog = qobject_cast<QInputDialog *>(widget)) {
				dialog->setTextValue(code);
				dialog->accept();
				return;
			}
		}
	});
}

template <typename done_t> static bool wait_for(done_t done)
{
	QDeadlineTimer deadline(5000);

	while (!done() && !deadline.hasExpired()) {
		QApplication::processEvents(QEventLoop::AllEvents, 20);
	}
	return done();
}

static bool window_says(ncfg_main_window &window, const QString &words)
{
	for (QLabel *label : window.findChildren<QLabel *>()) {
		if (label->text().contains(words)) {
			return true;
		}
	}
	return false;
}

int main(int argc, char **argv)
{
	QTemporaryDir empty;
	const QByteArray path = qgetenv("PATH");
	const QString key = QStringLiteral(
	    "abababababababababababababababababababababababababababababababab");

	setenv("HOME", qPrintable(empty.path()), 1);
	setenv("XDG_RUNTIME_DIR", qPrintable(empty.path()), 1);
	setenv("NCFG_RUN_DIR", qPrintable(empty.path()), 1);
	setenv("PATH", qPrintable(empty.path() + QStringLiteral(":") + QString::fromUtf8(path)), 1);
	{
		QFile script(empty.path() + QStringLiteral("/ncfg"));

		if (!script.open(QIODevice::WriteOnly)) {
			check(false, "a script stands in for ncfg");
			return 1;
		}
		script.write(QStringLiteral("#!/bin/sh\n"
		                            "[ \"$1\" = join ] || exit 3\n"
		                            "[ \"$2\" = GOOD ] && { echo %1; exit 0; }\n"
		                            "echo 'ncfg: that code is spent' >&2\nexit 1\n")
		                 .arg(key).toUtf8());
		script.close();
		script.setPermissions(QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);
	}
	QApplication app(argc, argv);
	ncfg_connection connection;
	ncfg_main_window window(&connection);
	auto *nodes = window.findChild<QComboBox *>(QStringLiteral("hosts"));
	auto *button = window.findChild<QPushButton *>(QStringLiteral("join_host"));

	check(nodes && nodes->count() == 1 && button != nullptr,
	      "a desktop with no host in its box offers the button");
	if (!nodes || !button) {
		return 1;
	}

	answer_with(QStringLiteral("BAD"));
	button->click();
	check(wait_for([&]() { return button->isEnabled() && window_says(window, QStringLiteral("spent")); }),
	      "a refused code is said in ncfg's words, and the button is back");
	check(nodes->count() == 1, "  and the box is as it was");

	answer_with(QString());
	button->click();
	check(wait_for([&]() { return button->isEnabled(); }) && nodes->count() == 1,
	      "an empty code asks nothing");

	answer_with(QStringLiteral("GOOD"));
	button->click();
	check(wait_for([&]() { return nodes->findData(key) >= 0; }) &&
	          nodes->currentData().toString() == key,
	      "the key `ncfg join` says lands in the box, chosen");
	check(button->isHidden(), "  and the button has done its work");

	if (failures == 0) {
		fprintf(stderr, "join_host: all checks passed\n");
	} else {
		fprintf(stderr, "join_host: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
