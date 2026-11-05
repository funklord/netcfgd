/*
 * node_menu.cpp -- the window's node box (project.md 10.699).
 *
 * WHY THIS EXISTS
 *   The box moves the whole window between this machine and another node,
 *   and the line above the tabs says which. What must hold: opened on a
 *   node, the box shows that node and the window refreshes on its timer; and
 *   a choice that cannot be reached puts the window back where it was rather
 *   than leaving it unconnected while it looks as if it moved.
 *
 *   No daemon and no fuzznetd: `XDG_RUNTIME_DIR` and `NCFG_RUN_DIR` name an
 *   empty directory, so "this machine" cannot be reached, which is the
 *   failure wanted.
 */

#include "../src/main_window.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QComboBox>
#include <QListWidget>
#include <QTemporaryDir>
#include <QTimer>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

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
	const QString key = QStringLiteral(
	    "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef");
	ncfg_connection connection;
	QString error;

	check(connection.open_at(key, &error), "a connection opens on another node", error);
	ncfg_main_window window(&connection);
	QComboBox *nodes = window.findChild<QComboBox *>(QStringLiteral("nodes"));
	bool polling = false;
	for (QTimer *timer : window.findChildren<QTimer *>()) {
		polling = polling || (timer->interval() == 5000 && timer->isActive());
	}
	check(nodes && nodes->itemData(0).toString().isEmpty() &&
	          nodes->currentData().toString() == key,
	      "the node box shows this machine first, and the node it was opened on");
	check(polling, "  and the window reads the node's events cursor every 5 seconds");

	{
		/* The node's events cursor (10.704): a fake fuzznetd on this user's
		 * socket answers `call events` twice -- where the node is, then one
		 * event past it -- and the second read lists it in the events tab. */
		static const char *const answers[] = { "ok 5%205\n", "ok 6%205%20net-drift%20-\n" };
		const QByteArray dir = (empty.path() + QStringLiteral("/fuzznet")).toUtf8();
		const QByteArray sock = dir + "/fuzznetd.sock";
		struct sockaddr_un address;
		int listener = socket(AF_UNIX, SOCK_STREAM, 0);

		(void)mkdir(dir.constData(), 0700);
		memset(&address, 0, sizeof(address));
		address.sun_family = AF_UNIX;
		memcpy(address.sun_path, sock.constData(), (size_t)sock.size() + 1u);
		if (listener >= 0 && bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0 &&
		    listen(listener, 2) == 0) {
			pid_t child = fork();

			if (child == 0) {
				alarm(10);
				for (const char *answer : answers) {
					char line[256];
					int fd = accept(listener, nullptr, nullptr);

					if (fd < 0) {
						_exit(1);
					}
					/* To its newline: the client sends that apart, and a fake
					 * that answers and closes first breaks its send, which
					 * failed this check about one run in four. */
					size_t got = 0;
					while (got < sizeof(line) && read(fd, line + got, 1) == 1 &&
					       line[got++] != '\n') {
					}
					(void)!write(fd, answer, strlen(answer));
					close(fd);
				}
				_exit(0);
			}
			close(listener);
			window.poll_node();
			window.poll_node();
			waitpid(child, nullptr, 0);
			QListWidget *lines = nullptr;
			for (QListWidget *list : window.findChildren<QListWidget *>()) {
				for (int row = 0; row < list->count(); row++) {
					if (list->item(row)->text().contains(QStringLiteral("drift (on node"))) {
						lines = list;
					}
				}
			}
			check(lines != nullptr && lines->item(lines->count() - 1)->text() ==
			                              QStringLiteral("drift (on node %1)").arg(key),
			      "the node's events cursor lists its event, by the node's whole key");
		} else {
			check(false, "a fake fuzznetd for the cursor listens");
		}
		(void)unlink(sock.constData());
		(void)rmdir(dir.constData());
	}

	if (nodes) {
		nodes->setCurrentIndex(0); /* this machine, which cannot be reached */
	}
	check(connection.node() == key && nodes && nodes->currentData().toString() == key,
	      "a choice that cannot be reached puts the window back on the node",
	      QStringLiteral("node \"%1\", box \"%2\"")
	          .arg(connection.node(), nodes ? nodes->currentData().toString() : QString()));

	if (failures == 0) {
		fprintf(stderr, "node_menu: all checks passed\n");
	} else {
		fprintf(stderr, "node_menu: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
