/*
 * phone_pair.cpp -- the phone's first screen, on real nodes (project.md 10.720).
 *
 * WHY THIS EXISTS
 *   Everything a phone does hangs off this screen, and the camera is the one
 *   part that needs a phone. So the rest is held here: a code as a host draws
 *   it is read back from an image, at a width whose rows are padded; a code
 *   nobody issued is refused and never reaches the node; and a code taken by
 *   the view joins a real fuzznetd, started the way the app starts it, to a
 *   real host, ending in `paired` with the host's key.
 *
 * HOW IT STOPS
 *   Every wait is a bounded event loop or a count of looks. The host is under
 *   `timeout` and killed at the end, and the phone's node is this process's
 *   child. The directory is a QTemporaryDir, removed on the way out.
 *
 *   No fuzznetd built: it says so and fails, since `make -C c` is what makes
 *   one, and a screen not tested is no pass.
 */

#include "../src/pair_code.h"
#include "../src/phone/code_reader.h"
#include "../src/phone/pair_view.h"
#include "../src/phone/phone_node.h"
extern "C" {
#include "ncfg_fuzznet.h"
}

#include <QApplication>
#include <QDir>
#include <QEventLoop>
#include <QFile>
#include <QImage>
#include <QLabel>
#include <QProcess>
#include <QTemporaryDir>
#include <QThread>
#include <QTimer>

#include <cstdio>
#include <unistd.h>
#include <vector>

extern "C" {
#include "qr.h"
}

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

/* A code as `ncfg pair` draws one, `scale` pixels a module, with its quiet
 * zone, onto a white page `extra` wider. */
static QImage drawn(const QByteArray &text, int scale, int extra)
{
	std::vector<uint8_t> modules(32768);
	size_t               size = 0;

	if (fzn_qr_encode(text.constData(), (size_t)text.size(), FZN_QR_LEVEL_L, modules.data(),
	                  modules.size(), &size) != FZN_QR_OK) {
		return QImage();
	}
	const int side = ((int)size + 2 * (int)FZN_QR_QUIET) * scale;
	QImage    image(side + extra, side, QImage::Format_RGB32);

	image.fill(Qt::white);
	for (int y = 0; y < (int)size; y++) {
		for (int x = 0; x < (int)size; x++) {
			if (!modules[(size_t)y * size + (size_t)x]) {
				continue;
			}
			for (int dy = 0; dy < scale; dy++) {
				for (int dx = 0; dx < scale; dx++) {
					image.setPixelColor((x + (int)FZN_QR_QUIET) * scale + dx,
					                    (y + (int)FZN_QR_QUIET) * scale + dy, Qt::black);
				}
			}
		}
	}
	return image;
}

static QString ask(const QString &socket, const QString &line)
{
	char             reply[2048];
	char             why[256];
	int              silent = 0;
	const QByteArray path = QFile::encodeName(socket);

	if (!ncfg_fuzznet_ask(path.constData(), line.toUtf8().constData(), reply, sizeof(reply),
	                      5000, &silent, why, sizeof(why))) {
		return QStringLiteral("no answer: ") + QString::fromUtf8(why);
	}
	return QString::fromUtf8(reply);
}

int main(int argc, char **argv)
{
	QApplication application(argc, argv);

	/* ---- the reader, on what a host draws ---- */
	QByteArray card("FZN4:");

	while (card.size() < 700) {
		card += "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	}
	check(ncfg_code_reader::read_image(drawn(card, 4, 0)) == card,
	      "a card's length of code is read back from its image");
	check(ncfg_code_reader::read_image(drawn(card, 3, 1)) == card,
	      "and at a width whose rows are padded");
	check(ncfg_code_reader::read_image(drawn(card, 9, 0)) == card,
	      "and from an image wider than a frame is looked at");
	/* What `ncfg pair` prints, read as the desktop's dialog reads it. */
	{
		std::vector<uint8_t> modules(32768);
		size_t               size = 0;
		QByteArray           printed("cruft\n");

		(void)fzn_qr_encode(card.constData(), (size_t)card.size(), FZN_QR_LEVEL_L, modules.data(),
		                    modules.size(), &size);
		const int side = (int)size + 8;
		auto      dark = [&](int x, int y) {
			return x >= 4 && y >= 4 && x < (int)size + 4 && y < (int)size + 4 &&
			       modules[(size_t)(y - 4) * size + (size_t)(x - 4)];
		};

		for (int y = 0; y < side; y += 2) {
			printed += "\033[30;47m";
			for (int x = 0; x < side; x++) {
				const bool top = dark(x, y);
				const bool bottom = y + 1 < side && dark(x, y + 1);

				printed += top ? (bottom ? "\xe2\x96\x88" : "\xe2\x96\x80")
				               : (bottom ? "\xe2\x96\x84" : " ");
			}
			printed += "\033[0m\n";
		}
		printed += "\nScan this.\n";
		check(ncfg_code_reader::read_image(ncfg_pair_code_image(printed, 4)) == card,
		      "the desktop's picture of what ncfg printed reads back as the code");
		check(ncfg_pair_code_image("no code here\n", 4).isNull(),
		      "and output with no code in it is no picture");
	}
	check(ncfg_code_reader::read_image(drawn(card, 4, 0).flipped(Qt::Vertical)) == card,
	      "and mirrored, as a camera may give it");
	QImage blank(300, 300, QImage::Format_RGB32);

	blank.fill(Qt::white);
	check(ncfg_code_reader::read_image(blank).isEmpty(), "and an image with no code gives none");

	/* ---- the nodes ---- */
	/* From this binary, not the directory it was run in: `make test` runs it from
	 * gui/, a person from beside it. */
	const QString fuzznetd = QDir(QCoreApplication::applicationDirPath() +
	                              QStringLiteral("/../../../../c/fuzznet-build"))
	                             .absoluteFilePath(QStringLiteral("fuzznetd"));
	const QString program = qEnvironmentVariable("NCFG_TEST_FUZZNETD", fuzznetd);

	if (!QFile::exists(program)) {
		check(false, "a fuzznetd to pair with", QStringLiteral("none at %1: `make -C c`").arg(program));
		return 1;
	}
	QTemporaryDir scratch(QStringLiteral("/tmp/ncf.XXXXXX"));
	const QString base = scratch.path();
	QString       why;

	check(ncfg_phone_node_start(program, base + QStringLiteral("/phone"), &application, &why),
	      "the phone's node starts as the app starts it", why);
	char socket[1100];

	check(ncfg_fuzznet_user_socket(socket, sizeof(socket)) != 0 &&
	          QString::fromUtf8(socket).startsWith(base),
	      "and the client's own lookup finds it, in the app's directory");
	const QString phone = QString::fromUtf8(socket);

	check(ncfg_phone_node_start(program, base + QStringLiteral("/phone"), &application, &why),
	      "started again, the node already answering is the node", why);
	check(ncfg_pair_view::joined_host(phone).isEmpty(), "a new phone has joined nothing");

	/* The host, its own socket and port. */
	QProcess host;
	const QString host_socket = base + QStringLiteral("/host.sock");
	const int     port = 34000 + (int)(QCoreApplication::applicationPid() % 400);

	QDir().mkpath(base + QStringLiteral("/host"));
	(void)QFile::setPermissions(base + QStringLiteral("/host"),
	                            QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);
	host.setProgram(QStringLiteral("timeout"));
	host.setArguments({QStringLiteral("-k"), QStringLiteral("5"), QStringLiteral("60"), program,
	                   QStringLiteral("--fuzznet-dir=%1/host").arg(base),
	                   QStringLiteral("--socket=%1").arg(host_socket),
	                   QStringLiteral("--no-log-file"), QStringLiteral("--udp-port=%1").arg(port),
	                   QStringLiteral("--fuzznet-service=%1").arg(NCFG_FUZZNET_SERVICE),
	                   QStringLiteral("--fuzznet-product=%1").arg(NCFG_FUZZNET_PRODUCT)});
	host.setStandardOutputFile(QProcess::nullDevice());
	host.setStandardErrorFile(QProcess::nullDevice());
	host.start();
	for (int look = 0; look < 100 && !QFile::exists(host_socket); look++) {
		QThread::msleep(100);
	}
	check(QFile::exists(host_socket), "a host's node serves");

	/* ---- closed with nothing paired ---- */
	{
		QString       left_host = QStringLiteral("unset");
		QTimer::singleShot(200, &application, []() {
			for (QWidget *top : QApplication::topLevelWidgets()) {
				if (qobject_cast<ncfg_pair_view *>(top)) {
					top->close();
				}
			}
		});
		QTimer stuck;

		stuck.setSingleShot(true);
		/* The child and the directory by hand, since `_exit` runs no destructor:
		 * a node left behind holds the port the next run needs. */
		QObject::connect(&stuck, &QTimer::timeout, [&]() {
			fprintf(stderr, "phone_pair: closing the view left the app waiting\n");
			for (QProcess *node : application.findChildren<QProcess *>()) {
				node->kill();
				node->waitForFinished(2000);
			}
			host.terminate();
			host.waitForFinished(3000);
			(void)scratch.remove();
			_exit(1);
		});
		stuck.start(5000);
		left_host = ncfg_phone_host(phone);
		stuck.stop();
		check(left_host.isEmpty(), "closing the first screen ends the wait, with no host");
	}

	/* ---- the view ---- */
	ncfg_pair_view view(phone);
	QLabel        *status = view.findChild<QLabel *>(QStringLiteral("status"));

	view.take_code("hello");
	check(status && status->text().contains(QStringLiteral("not a pairing code")),
	      "a code nobody issued is refused in words", status ? status->text() : QString());
	view.take_code("FZI1:AB CD");
	check(status && status->text().contains(QStringLiteral("space")),
	      "and a code with a space, which would be two words to the node",
	      status ? status->text() : QString());

	const QString set = ask(host_socket,
	                        QStringLiteral("set setting host net/address 127.0.0.1 %1").arg(port));
	const QString answer = ask(host_socket, QStringLiteral("add invite delegable"));

	check(answer.startsWith(QStringLiteral("ok FZI1:")), "the host makes a code for a phone",
	      answer + QStringLiteral(" / ") + set);
	check(ncfg_code_reader::read_image(drawn(answer.mid(3).toUtf8(), 4, 0)) == answer.mid(3).toUtf8(),
	      "and the real code is read back from its image");

	QString    paired;
	QEventLoop wait;
	QObject::connect(&view, &ncfg_pair_view::paired, &wait, [&](const QString &host_key) {
		paired = host_key;
		wait.quit();
	});
	QTimer::singleShot(40000, &wait, &QEventLoop::quit);
	view.take_code(answer.mid(3).toUtf8());
	wait.exec();
	check(paired.size() == 64, "the code joins the phone, and `paired` names the host",
	      status ? status->text() : QString());
	check(!paired.isEmpty() && ncfg_pair_view::joined_host(phone) == paired,
	      "and the next start of the app finds it joined");
	const QString open_codes = ask(host_socket, QStringLiteral("get invite"));

	check(open_codes == QStringLiteral("ok 0"), "and the code is used up", open_codes);

	/* ---- starting over ---- */
	check(ncfg_phone_node_forget(base + QStringLiteral("/phone"), &application, &why),
	      "forgetting the host stops the node and takes its store", why);
	check(!QDir(base + QStringLiteral("/phone/node")).exists(), "and the store is gone");
	check(ncfg_phone_node_start(program, base + QStringLiteral("/phone"), &application, &why),
	      "and the next start has a node", why);
	check(ncfg_pair_view::joined_host(phone).isEmpty(), "which has joined nothing, so it pairs");

	host.terminate();
	host.waitForFinished(8000);
	fprintf(stderr, "%s\n", failures ? "phone_pair: FAILED" : "phone_pair: all checks passed");
	return failures ? 1 : 0;
}
