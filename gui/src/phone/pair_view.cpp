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

#include <cstring>

/* `add join` answers at once, `ok asking`, and asks the host from then on. */
static const int join_wait_ms = 5000;

/* A look every 500 ms. The node asks for fifteen minutes, then says `idle`, so this
 * only bounds a node that stops answering altogether. */
static const int looks_max = 1860;

/* From here on, the wait says what is likely wrong: ten seconds. */
static const int looks_patient = 20;

/* Looks allowed before `idle` means anything: the node starts again in place
 * after it has joined, and is `idle` then too. */
static const int looks_settling = 10;

/* What a pairing code starts with: fuzznet's invite (its sec 896). */
static const char code_prefix[] = "FZI1:";

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

ncfg_pair_view::ncfg_pair_view(const QString &socket, QWidget *parent)
    : QWidget(parent), socket_path(socket)
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
	/* Above the stretch: a phone's keyboard rises over the bottom of the screen,
	 * and a person has to see what they type. */
	layout->addWidget(typed);
	layout->addWidget(use);
	layout->addStretch(1);
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
	const QByteArray line = "add join " + text;

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
	status_line->setText(QStringLiteral("Asking the host."));
	looks = 0;
	waiting->start();
}

void ncfg_pair_view::look_for_node()
{
	const QString    host = joined_host(socket_path);
	const QByteArray path = QFile::encodeName(socket_path);
	char             reply[64];
	char             why[256];
	int              silent = 0;

	if (!host.isEmpty()) {
		waiting->stop();
		emit paired(host);
		return;
	}
	looks++;
	const bool gave_up = looks > looks_settling &&
	    ncfg_fuzznet_ask(path.constData(), "get join", reply, sizeof(reply), 1000, &silent, why,
	                     sizeof(why)) &&
	    strstr(reply, "idle") != nullptr;

	if (gave_up || looks >= looks_max) {
		waiting->stop();
		busy(false);
		status_line->setText(QStringLiteral("The host did not answer. The code may have run "
		                                    "out or been used: run ncfg pair again."));
	} else if (looks == looks_patient) {
		status_line->setText(QStringLiteral("Still asking the host. Is this phone on its "
		                                    "network?"));
	}
}

QString ncfg_phone_host(const QString &socket)
{
	QString host = ncfg_pair_view::joined_host(socket);

	if (!host.isEmpty()) {
		return host;
	}
	ncfg_pair_view view(socket);
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
