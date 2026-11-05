#include "pair_view.h"

#include "code_reader.h"
extern "C" {
#include "ncfg_fuzznet.h"
}

#include <QApplication>
#include <QCloseEvent>
#include <QInputMethod>
#include <QEventLoop>
#include <QFile>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QThread>
#include <QTimer>
#include <QVBoxLayout>

#include <sys/stat.h>

/* A join reaches the host and pulls from it: the longest thing a node is asked
 * here. fuzznet's round waits are 3 s each. */
static const int join_wait_ms = 20000;

/* The node starts again in place after a join; 60 looks, 500 ms apart. */
static const int looks_max = 60;

/* What a pairing code starts with: fuzznet's card, as `ncfg pair` draws it. */
static const char code_prefix[] = "FZN";

QString ncfg_pair_view::joined_host(const QString &socket)
{
	static char      keys[16][NCFG_FUZZNET_KEY_TEXT];
	char             err[256];
	size_t           count = 0;
	const QByteArray path = QFile::encodeName(socket);

	if (!ncfg_fuzznet_members(path.constData(), keys, 16u, &count, err, sizeof(err)) ||
	    count == 0u) {
		return QString();
	}
	return QString::fromUtf8(keys[0]);
}

ncfg_pair_view::ncfg_pair_view(const QString &socket, const QString &scratch, QWidget *parent)
    : QWidget(parent), socket_path(socket), scratch_dir(scratch)
{
	QVBoxLayout *layout = new QVBoxLayout(this);
	QLabel      *title = new QLabel(QStringLiteral("Pair with your netcfgd"), this);
	QLabel      *how = new QLabel(QStringLiteral("On the machine netcfgd runs on, type "
	                                             "<b>ncfg pair</b>. It draws a code. "
	                                             "Point this phone at it."),
	                              this);
	QFont        big = title->font();

	big.setPointSizeF(big.pointSizeF() * 1.5);
	big.setBold(true);
	title->setFont(big);
	title->setWordWrap(true);
	how->setWordWrap(true);
	scan = new QPushButton(QStringLiteral("Scan the code"), this);
	scan->setObjectName(QStringLiteral("scan"));
	scan->setMinimumHeight(scan->fontMetrics().height() * 3);
	status_line = new QLabel(this);
	status_line->setObjectName(QStringLiteral("status"));
	status_line->setWordWrap(true);
	typed = new QLineEdit(this);
	typed->setObjectName(QStringLiteral("typed"));
	typed->setPlaceholderText(QStringLiteral("or type the code"));
	typed->setInputMethodHints(Qt::ImhNoPredictiveText | Qt::ImhNoAutoUppercase);
	use = new QPushButton(QStringLiteral("Use this code"), this);
	use->setObjectName(QStringLiteral("use"));
	layout->addWidget(title);
	layout->addWidget(how);
	layout->addSpacing(how->fontMetrics().height());
	layout->addWidget(scan);
	layout->addWidget(status_line);
	layout->addStretch(1);
	layout->addWidget(typed);
	layout->addWidget(use);
	reader = new ncfg_code_reader(this);
	waiting = new QTimer(this);
	waiting->setInterval(500);
	connect(waiting, &QTimer::timeout, this, &ncfg_pair_view::look_for_node);
	connect(scan, &QPushButton::clicked, reader, [this]() {
		if (reader->running()) {
			reader->stop(QStringLiteral("Stopped."));
		} else {
			reader->start();
		}
	});
	connect(reader, &ncfg_code_reader::running_changed, this, [this](bool running) {
		scan->setText(running ? QStringLiteral("Stop") : QStringLiteral("Scan the code"));
	});
	connect(reader, &ncfg_code_reader::status, status_line, &QLabel::setText);
	connect(reader, &ncfg_code_reader::code_read, this, &ncfg_pair_view::take_code);
	/* Committed first: a phone's keyboard may hold the last of what was typed
	 * as a composition, which `text()` leaves out. */
	auto typed_code = [this]() {
		QGuiApplication::inputMethod()->commit();
		take_code(typed->text().toUtf8());
	};
	connect(use, &QPushButton::clicked, this, typed_code);
	connect(typed, &QLineEdit::returnPressed, this, typed_code);
}

void ncfg_pair_view::closeEvent(QCloseEvent *event)
{
	QWidget::closeEvent(event);
	emit left();
}

void ncfg_pair_view::busy(bool on)
{
	scan->setEnabled(!on);
	use->setEnabled(!on);
	typed->setEnabled(!on);
}

void ncfg_pair_view::take_code(const QByteArray &code)
{
	const QByteArray text = code.trimmed();

	if (!text.startsWith(code_prefix)) {
		status_line->setText(QStringLiteral("That is not a pairing code. It comes from "
		                                    "ncfg pair on the host."));
		return;
	}
	for (char c : text) {
		if (c <= ' ' || c == 0x7f) {
			status_line->setText(QStringLiteral("That code has a space in it, and none "
			                                    "does."));
			return;
		}
	}
	/* A card is longer than the 512 bytes a line to the node may be, so it goes
	 * in a file, which the node reads and which goes straight after. Private
	 * to this app, and the card is the host's to give only to this device. */
	QByteArray line = "add join " + text;
	QString    held;

	if (line.size() >= (int)NCFG_FUZZNET_REQUEST_MAX) {
		held = scratch_dir + QStringLiteral("/code");
		QFile file(held);

		if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate) ||
		    !file.setPermissions(QFile::ReadOwner | QFile::WriteOwner) ||
		    file.write(text) != text.size()) {
			status_line->setText(QStringLiteral("The code could not be held: %1")
			                         .arg(file.errorString()));
			return;
		}
		file.close();
		line = "add join " + QFile::encodeName(held);
	}
	busy(true);
	status_line->setText(QStringLiteral("Reaching the host."));

	const QByteArray         path = QFile::encodeName(socket_path);
	QPointer<ncfg_pair_view> self(this);
	QThread                 *worker = QThread::create([=]() {
		char reply[1024];
		char why[256];
		int  silent = 0;
		int  said = ncfg_fuzznet_ask(path.constData(), line.constData(), reply, sizeof(reply),
		                             join_wait_ms, &silent, why, sizeof(why));
		const QString answer = QString::fromUtf8(said ? reply : why);

		if (!held.isEmpty()) {
			QFile::remove(held);
		}
		QMetaObject::invokeMethod(qApp, [self, said, answer]() {
			if (self) {
				self->asked(said != 0 && answer.startsWith(QStringLiteral("ok")), answer);
			}
		});
	});

	connect(worker, &QThread::finished, worker, &QObject::deleteLater);
	worker->start();
}

void ncfg_pair_view::asked(bool ok, const QString &answer)
{
	if (!ok) {
		busy(false);
		status_line->setText(QStringLiteral("The host did not take it: %1").arg(answer));
		return;
	}
	status_line->setText(QStringLiteral("Joined. Starting again."));
	looks = 0;
	waiting->start();
}

void ncfg_pair_view::look_for_node()
{
	const QString host = joined_host(socket_path);

	if (!host.isEmpty()) {
		waiting->stop();
		emit paired(host);
		return;
	}
	if (++looks >= looks_max) {
		waiting->stop();
		busy(false);
		status_line->setText(QStringLiteral("Joined, and the host has not been heard from. "
		                                    "Is the phone on its network?"));
	}
}

QString ncfg_phone_host(const QString &socket, const QString &scratch)
{
	QString host = ncfg_pair_view::joined_host(socket);

	if (!host.isEmpty()) {
		return host;
	}
	ncfg_pair_view view(socket, scratch);
	QEventLoop     wait;

	QObject::connect(&view, &ncfg_pair_view::paired, &wait, [&](const QString &key) {
		host = key;
		wait.quit();
	});
	/* Back leaves the app. Without this the wait outlived the window: no
	 * screen, and a process Android kept with nothing to bring back. */
	QObject::connect(&view, &ncfg_pair_view::left, &wait, &QEventLoop::quit);
	view.show();
	wait.exec();
	return host;
}
