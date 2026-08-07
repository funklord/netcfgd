/*
 * access_frame.cpp -- does the administrator mode actually draw the red frame?
 *
 * project.md's item 6 said "the frame has never been drawn", and treated that
 * as blocked on a machine with a graphical session. It is not: Qt's offscreen
 * platform renders a real widget through the real paint path, so the pixels
 * can be counted without anybody looking at them.
 *
 * The frame is the whole argument of 0118 -- polkit prompts per action and
 * leaves nothing on screen saying whether you are privileged *now*, and a mode
 * is a thing you can look at. A mode nobody can look at is the feature not
 * existing, so this is the one property of that decision worth a pixel test
 * rather than a state assertion.
 *
 * It drives `unlock` through the meta-object rather than reaching for the
 * private setter, so what is measured is the slot the button is wired to.
 */

#include "../src/access_view.h"
#include "../src/ncfg_connection.h"

#include <QApplication>
#include <QFrame>
#include <QImage>
#include <QMetaObject>

#include <cstdio>

/* #c00000, the colour access_view.cpp names. Hard-coded here on purpose: a
 * test that read the constant out of the source under test would agree with it
 * however it changed, including into something that is not red. */
static const QRgb ADMINISTRATOR_RED = qRgb(0xc0, 0x00, 0x00);

/* How many pixels of the frame are that exact colour. */
static int red_pixels(QWidget *widget)
{
	const QImage image = widget->grab().toImage();
	int count = 0;

	for (int y = 0; y < image.height(); y++) {
		for (int x = 0; x < image.width(); x++) {
			if (image.pixel(x, y) == ADMINISTRATOR_RED) {
				count++;
			}
		}
	}
	return count;
}

static int failures;

static void check(bool condition, const char *what)
{
	fprintf(stderr, "access_frame: %-46s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

int main(int argc, char **argv)
{
	QApplication application(argc, argv);

	ncfg_connection connection;
	ncfg_access_view view(&connection);
	view.resize(480, 320);
	view.show();

	/* The pair is the point. A test that only looked at the live state would
	 * pass against a frame painted red permanently, which is precisely the bug
	 * that matters here: a red border that is always on says nothing about
	 * whether this window is privileged now. */
	const int before = red_pixels(&view);
	check(before == 0, "read-only: no administrator red on screen");

	const bool invoked = QMetaObject::invokeMethod(&view, "unlock");
	check(invoked, "unlock is reachable as a slot");

	const int during = red_pixels(&view);
	check(during > 0, "administrator mode: the red frame is drawn");

	/* Not merely "some red": a 2px border around a 480x320 widget is hundreds
	 * of pixels, and a handful would mean something else entirely is red. */
	check(during > 200, "the red is a border and not a stray pixel");

	fprintf(stderr, "access_frame: %d red pixels while privileged, %d before\n",
	    during, before);
	return failures ? 1 : 0;
}
