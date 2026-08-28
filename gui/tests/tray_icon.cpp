/*
 * tray_icon.cpp -- is the tray indicator actually drawn, and does it differ?
 *
 * project.md listed the icon as unverified: the tray compiles, the no-tray
 * path runs, and "nothing here has a status-notifier host, so the menu, the
 * refresh and the disconnect have never been drawn or clicked".
 *
 * The menu and the clicks genuinely do want a host -- `isSystemTrayAvailable`
 * is false under both the offscreen and the minimal platform, measured, so
 * `ncfg_tray::create` returns nullptr and there is no object to drive. The
 * *icon* does not want one. It is painted by this tree rather than shipped, so
 * it can be rendered and its pixels compared, and that is the half of the
 * claim that was blocked on nothing.
 *
 * What is worth checking is not that it draws something. It is that the two
 * states draw something *different*: an indicator that looks identical
 * connected and disconnected is not an indicator, and it would pass any test
 * that only asked whether a pixmap came back.
 */

#include "../src/tray.h"

#include <QApplication>
#include <QIcon>
#include <QImage>
#include <QPixmap>

#include <cstdio>

static int failures;

static void check(bool condition, const char *what)
{
	fprintf(stderr, "tray_icon: %-52s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* How many pixels are not transparent -- ink on the panel. */
static int inked(const QImage &image)
{
	int count = 0;

	for (int y = 0; y < image.height(); y++) {
		for (int x = 0; x < image.width(); x++) {
			if (qAlpha(image.pixel(x, y)) != 0) {
				count++;
			}
		}
	}
	return count;
}

static bool has_colour(const QImage &image, QRgb wanted)
{
	for (int y = 0; y < image.height(); y++) {
		for (int x = 0; x < image.width(); x++) {
			const QRgb pixel = image.pixel(x, y);
			if (qAlpha(pixel) == 255 && qRgb(qRed(pixel), qGreen(pixel), qBlue(pixel)) == wanted) {
				return true;
			}
		}
	}
	return false;
}

int main(int argc, char **argv)
{
	QApplication application(argc, argv);

	const QImage connected = ncfg_tray::painted_icon(ncfg_reach::routed).pixmap(22, 22).toImage();
	const QImage offline = ncfg_tray::painted_icon(ncfg_reach::offline).pixmap(22, 22).toImage();
	const QImage local = ncfg_tray::painted_icon(ncfg_reach::local).pixmap(22, 22).toImage();

	check(!connected.isNull() && connected.size() == QSize(22, 22),
	    "connected: a 22x22 pixmap comes back");
	check(!offline.isNull() && offline.size() == QSize(22, 22),
	    "offline: a 22x22 pixmap comes back");

	/* A transparent 22x22 pixmap is what a broken painter returns, and it is
	 * indistinguishable from a working one until somebody counts the ink. */
	check(inked(connected) > 40, "connected: the arcs and the dot are drawn");
	check(inked(offline) > 40, "offline: the arcs and the dot are drawn");

	/* The property that matters. */
	check(connected != offline, "the two states are not the same picture");
	/* **Three states, three pictures.** The middle one exists because a
	 * boolean could not say "joined a network that goes nowhere", and it
	 * earns nothing if it draws as either neighbour: an operator would read
	 * it as the state it resembles. */
	check(local != offline, "local is not drawn as offline");
	check(local != connected, "local is not drawn as connected");
	check(inked(local) > 40, "local: the arcs and the dot are drawn");
	check(has_colour(local, qRgb(0xcc, 0x88, 0x22)), "local is drawn in its own colour");
	check(!has_colour(local, qRgb(0x33, 0x99, 0x33)),
	    "local carries none of the connected colour");
	check(!has_colour(local, qRgb(0x88, 0x88, 0x88)), "local carries none of the offline colour");

	/* And they differ in the way the source says they do, rather than by some
	 * incidental pixel: the pen colour is the whole distinction. */
	check(has_colour(connected, qRgb(0x33, 0x99, 0x33)),
	    "connected is drawn in the connected colour");
	check(has_colour(offline, qRgb(0x88, 0x88, 0x88)),
	    "offline is drawn in the offline colour");
	check(!has_colour(connected, qRgb(0x88, 0x88, 0x88)),
	    "connected carries none of the offline colour");

	/* This machine has no icon theme at all, so `state_icon` must fall through
	 * to the painted one. Where a theme exists the theme wins, which is the
	 * point of that function and is not what this asserts. */
	if (QIcon::themeName().isEmpty()) {
		const QImage themed =
		    ncfg_tray::state_icon(ncfg_reach::routed).pixmap(22, 22).toImage();
		check(themed == connected, "with no icon theme, state_icon paints its own");
	}

	fprintf(stderr, "tray_icon: %d inked pixels connected, %d offline\n",
	    inked(connected), inked(offline));
	return failures ? 1 : 0;
}
