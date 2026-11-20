/*
 * about_menu.cpp -- what the workspace's GUIs all carry (project.md 10.883).
 *
 * WHY THIS EXISTS
 *   A Help menu holding an About window that says who wrote the program,
 *   with the address whole: `QMessageBox::about` reads rich text and drops a
 *   bare `<nabeel@vibes.se>` as an unknown tag, which is the half of the line
 *   a reader acts on. And the one control with no visible label, the
 *   machine box, has a name a screen reader can say.
 *
 *   HOW IT STOPS: the About box is closed by a timer as soon as it shows, and
 *   a second timer ends the wait after five seconds whatever happens.
 */

#include "../src/main_window.h"
#include "../src/ncfg_connection.h"

#include <QAction>
#include <QApplication>
#include <QComboBox>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
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

int main(int argc, char **argv)
{
	QTemporaryDir empty;
	setenv("XDG_RUNTIME_DIR", qPrintable(empty.path()), 1);
	setenv("NCFG_RUN_DIR", qPrintable(empty.path()), 1);
	QApplication app(argc, argv);
	ncfg_connection connection;
	ncfg_main_window window(&connection);
	QAction *about = nullptr;
	QString  shown;

	for (QAction *menu : window.menuBar()->actions()) {
		if (menu->text().remove(QLatin1Char('&')) != QStringLiteral("Help") || !menu->menu()) {
			continue;
		}
		for (QAction *item : menu->menu()->actions()) {
			if (item->text().remove(QLatin1Char('&')).startsWith(QStringLiteral("About"))) {
				about = item;
			}
		}
	}
	check(about != nullptr, "the menu bar has Help, and Help has About");
	if (about) {
		QTimer::singleShot(0, [&]() {
			for (QWidget *top : QApplication::topLevelWidgets()) {
				auto *box = qobject_cast<QMessageBox *>(top);

				if (box && box->isVisible()) {
					shown = box->text();
					box->accept();
				}
			}
		});
		QTimer::singleShot(5000, [&]() {
			for (QWidget *top : QApplication::topLevelWidgets()) {
				if (auto *box = qobject_cast<QMessageBox *>(top)) {
					box->reject();
				}
			}
		});
		about->trigger();
	}
	check(shown.contains(QStringLiteral("Copyright (C) 2026 Nabeel Sowan")),
	      "About says who wrote it", shown);
	check(shown.contains(QStringLiteral("&lt;nabeel@vibes.se&gt;")),
	      "with the address escaped, so the box shows it rather than dropping it", shown);
	QComboBox *nodes = window.findChild<QComboBox *>(QStringLiteral("hosts"));
	check(nodes && !nodes->accessibleName().isEmpty(),
	      "the unlabelled machine box has a name a screen reader can say");
	fprintf(stderr, "about_menu: %s\n", failures ? "FAILED" : "all passed");
	return failures ? 1 : 0;
}
