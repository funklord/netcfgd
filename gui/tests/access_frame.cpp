/*
 * access_frame.cpp -- the red frame is a claim about a privileged process.
 *
 * 0120: the frame does not mean "these fields are editable". It means a helper
 * on the other side of a process boundary is running as root. So the property
 * worth testing is not that a bool turns a border red -- it is that the border
 * follows *the helper*, and specifically that it does not redden for a helper
 * that is not root.
 *
 * Which elevator runs is decided by PATH, so PATH is the whole test harness: a
 * fake `pkexec` that prints `ready uid=0` drives the privileged case, and one
 * that prints `ready uid=1000` drives the case that must be refused. Neither
 * needs root, a session, or a real policy file.
 */

#include "../src/access_view.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFrame>
#include <QImage>
#include <QMetaObject>
#include <QTemporaryDir>

#include <cstdio>

static int failures;

static void check(bool condition, const char *what)
{
	fprintf(stderr, "access_frame: %-52s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* How much of the widget is drawn in a red the theme would not have chosen. */
static int red_pixels(QWidget *widget)
{
	const QImage image = widget->grab().toImage();
	int count = 0;

	for (int y = 0; y < image.height(); y++) {
		for (int x = 0; x < image.width(); x++) {
			const QRgb pixel = image.pixel(x, y);
			if (qRed(pixel) > 120 && qGreen(pixel) < 90 && qBlue(pixel) < 90) {
				count++;
			}
		}
	}
	return count;
}

/* A fake elevator. It ignores its arguments, says what it was told to say, and
 * then blocks on stdin -- which is what the real helper does, and is what makes
 * `stop_helper` closing the write channel a thing this test exercises. */
static void write_fake_pkexec(const QString &path, const char *ready)
{
	QFile file(path);
	file.open(QIODevice::WriteOnly);
	/* `read` is a shell builtin and `cat` is not. PATH holds only this
	 * directory -- that is what forces the elevator choice -- so a fake that
	 * shelled out to anything would exit at once, take the helper with it, and
	 * look exactly like a frame that never reddened. It did, on the first run. */
	file.write(QStringLiteral("#!/bin/sh\necho '%1'\nwhile read -r line; do :; done\n")
	               .arg(QString::fromLatin1(ready))
	               .toUtf8());
	file.close();
	QFile::setPermissions(path, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);
}

/* Spin until the condition holds or the time runs out. Returns whether it held,
 * so a timeout is a failed assertion rather than a hang. */
template <typename Predicate> static bool spin_until(Predicate ready, int ms = 5000)
{
	QElapsedTimer timer;
	timer.start();
	while (timer.elapsed() < ms) {
		QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
		if (ready()) {
			return true;
		}
	}
	return ready();
}

int main(int argc, char **argv)
{
	QApplication application(argc, argv);

	QTemporaryDir bin;
	if (!bin.isValid()) {
		fprintf(stderr, "access_frame: no temporary directory -- not a pass\n");
		return 1;
	}
	qputenv("PATH", bin.path().toUtf8());

	ncfg_connection connection;
	ncfg_access_view view(&connection);
	view.resize(480, 360);
	view.show();

	check(red_pixels(&view) == 0, "read-only: no red on screen");

	/* The regression this decision exists for. Before 0120, `unlock` opened
	 * the editors and reddened the frame with nothing authenticated and no
	 * privileged process anywhere. Here there is no elevator on PATH at all,
	 * so nothing can start -- and the frame must stay as it was. */
	QMetaObject::invokeMethod(&view, "unlock");
	spin_until([] { return false; }, 300);
	check(red_pixels(&view) == 0, "unlock with no elevator does not redden it");

	/* A helper that starts but is not root. The elevator ran, so asking
	 * succeeded; what failed is the thing the frame actually claims. */
	write_fake_pkexec(bin.filePath(QStringLiteral("pkexec")), "ready uid=1000");
	QMetaObject::invokeMethod(&view, "unlock");
	spin_until([] { return false; }, 1500);
	check(red_pixels(&view) == 0, "a helper that is not root does not redden it");

	/* And the case it is for. */
	write_fake_pkexec(bin.filePath(QStringLiteral("pkexec")), "ready uid=0");
	QMetaObject::invokeMethod(&view, "unlock");
	const bool reddened = spin_until([&view] { return red_pixels(&view) > 200; });
	check(reddened, "a helper running as root does redden it");

	const int during = red_pixels(&view);

	/* Leaving stops the helper, and the claim must go with it. */
	QMetaObject::invokeMethod(&view, "stop_helper");
	const bool cleared = spin_until([&view] { return red_pixels(&view) == 0; });
	check(cleared, "leaving administrator mode takes the red away");

	fprintf(stderr, "access_frame: %d red pixels while a root helper was running\n", during);
	return failures ? 1 : 0;
}
