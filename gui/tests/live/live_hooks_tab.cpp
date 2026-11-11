/*
 * live_hooks_tab.cpp -- the hooks tab starting a hook (10.808), against a
 * real daemon.
 *
 * The tab could edit an interface that already had a hook and nothing else;
 * its note sent a person to the links tab, `configure`, then hooks. Its
 * `new hook...` asks which interface, opens that interface's editor, and
 * presses the editor's own `new hook...`. What is asserted is that chain:
 * the question lists the machine's interfaces, and the hook form opens over
 * the editor for the one chosen. Every window is closed rather than saved --
 * what a hook form writes is live_hook's subject.
 *
 * The windows are modal and nested, so a poller answers whichever is on top,
 * bounded by a tick count so a window that never came cannot hang the suite.
 */
#include "../../src/hook_dialog.h"
#include "../../src/hooks_view.h"
#include "../../src/interface_dialog.h"
#include "../../src/ncfg_connection.h"

#include <QApplication>
#include <QComboBox>
#include <QInputDialog>
#include <QPushButton>
#include <QTimer>

#include <cstdio>

static int failures;

static void check(const char *what, bool condition, const QString &detail = QString())
{
	printf("%s %s\n", condition ? "ok  " : "FAIL", what);
	if (!condition && !detail.isEmpty()) {
		printf("       %s\n", detail.toUtf8().constData());
	}
	fflush(stdout);
	if (!condition) {
		failures++;
	}
}

static QPushButton *button(QWidget *of, const char *label)
{
	for (QPushButton *candidate : of->findChildren<QPushButton *>()) {
		if (candidate->text() == QString::fromUtf8(label)) {
			return candidate;
		}
	}
	return nullptr;
}

int main(int argc, char **argv)
{
	QApplication app(argc, argv);

	ncfg_connection connection;
	QString error;
	if (!connection.open(QString(), &error)) {
		printf("FAIL the hooks tab can reach netcfgd\n       %s\n", error.toUtf8().constData());
		return 1;
	}
	check("the hooks tab can reach netcfgd", true);

	ncfg_hooks_view view(&connection);
	view.refresh();
	QPushButton *start = button(&view, "new hook...");
	check("the tab has a new hook button", start != nullptr);
	if (!start) {
		return 1;
	}

	QStringList offered;
	QString chosen;
	bool editor_seen = false;
	bool form_seen = false;
	int ticks = 0;
	QTimer poll;
	QObject::connect(&poll, &QTimer::timeout, [&]() {
		/* Past the bound, close whatever is on top, one per tick, until none
		 * is: the event loop has to run between them for the next to surface.
		 * Bounded again, so a window that will not close cannot hang this. */
		if (++ticks > 200) {
			auto *top = qobject_cast<QDialog *>(QApplication::activeModalWidget());
			if (top && ticks < 260) {
				top->reject();
			} else {
				poll.stop();
			}
			return;
		}
		QWidget *top = QApplication::activeModalWidget();
		{
			static QString last;
			const QString now = top ? QString::fromLatin1(top->metaObject()->className())
			                        : QStringLiteral("none");
			if (now != last) {
				printf("       on top: %s\n", now.toUtf8().constData());
				last = now;
			}
		}
		if (auto *ask = qobject_cast<QInputDialog *>(top)) {
			offered = ask->comboBoxItems();
			chosen = offered.value(0);
			ask->setTextValue(chosen);
			ask->accept();
		} else if (auto *form = qobject_cast<ncfg_hook_dialog *>(top)) {
			form_seen = true;
			editor_seen = editor_seen ||
			              qobject_cast<ncfg_interface_dialog *>(form->parentWidget()) != nullptr;
			form->reject();
		} else if (auto *editor = qobject_cast<ncfg_interface_dialog *>(top)) {
			editor_seen = true;
			if (form_seen) {
				editor->reject();
				poll.stop();
			}
		}
	});
	poll.start(50);
	start->click();

	check("it asks which interface, from the machine's own", !offered.isEmpty(),
	    offered.join(QStringLiteral(", ")));
	check("  and lo is not one of them", !offered.contains(QStringLiteral("lo")));
	check("the chosen interface's editor opens", editor_seen, chosen);
	check("  at a new hook form, without another click", form_seen);

	printf(failures ? "live_hooks_tab: %d check(s) failed\n" : "live_hooks_tab: all checks passed\n",
	    failures);
	return failures ? 1 : 0;
}
