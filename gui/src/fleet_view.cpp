/*
 * fleet_view.cpp -- the table described in fleet_view.h.
 */
#include "fleet_view.h"

#include "access_view.h"
#include "pair_code.h"
#include "table_view.h"

#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QInputDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QShowEvent>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>

#ifdef Q_OS_ANDROID
#include "phone/phone_node.h"

#include <QApplication>
#include <QPointer>
#include <QStandardPaths>
#include <QThread>

#include <cstdlib>

extern "C" {
#include "ncfg_fuzznet.h"
}
#endif

/* What `ncfg status --at` takes up on a node at once, and how often the tab
 * asks while it is in front. */
static const int MOST_AT_ONCE = 4;
static const int ROUND_EVERY = 60000;
/* `reload --at estate` waits on every host's round. */
static const int ACTION_WAIT = 120000;
/* The last column, where `open_selected` reads the whole key back. */
static const int KEY_COLUMN = 6;

ncfg_fleet_view::ncfg_fleet_view(std::function<QStringList()> members, QWidget *parent)
    : QWidget(parent), members(std::move(members))
{
	QStringList columns;
	columns << QStringLiteral("host") << QStringLiteral("state")
	        << QStringLiteral("connectivity") << QStringLiteral("primary")
	        << QStringLiteral("links up") << QStringLiteral("answered")
	        << QStringLiteral("key");
	table = new ncfg_table_view(columns, QStringLiteral("fleet_note"), this);
	auto *open_button = new QPushButton(QStringLiteral("Open"), this);
	open_button->setObjectName(QStringLiteral("fleet_open"));
	open_button->setToolTip(QStringLiteral("Move this window to the selected node."));
	connect(open_button, &QPushButton::clicked, this, &ncfg_fleet_view::open_selected);
	table->add_control(open_button);
	auto *reload_button = new QPushButton(QStringLiteral("Reload all..."), this);
	reload_button->setToolTip(QStringLiteral(
	    "Have every node re-read its configuration. A node's own `remote` block decides."));
	connect(reload_button, &QPushButton::clicked, this, &ncfg_fleet_view::ask_reload);
	table->add_control(reload_button);
	auto *member_button = new QPushButton(QStringLiteral("Add to group..."), this);
	member_button->setToolTip(QStringLiteral(
	    "Say the selected node is in a group, so that what is sealed to the group reaches it."));
	connect(member_button, &QPushButton::clicked, this, &ncfg_fleet_view::ask_member);
	table->add_control(member_button);
	auto *seal_button = new QPushButton(QStringLiteral("Seal a value..."), this);
	seal_button->setToolTip(QStringLiteral(
	    "A value only a group's members can read, which a configuration names as "
	    "@secret:estate:KEY."));
	connect(seal_button, &QPushButton::clicked, this, &ncfg_fleet_view::ask_seal);
	table->add_control(seal_button);
	auto *pair_button = new QPushButton(QStringLiteral("Pair a phone..."), this);
	pair_button->setToolTip(QStringLiteral(
	    "Show a code the netcfgd app on a phone scans to join this machine's estate."));
	connect(pair_button, &QPushButton::clicked, this, &ncfg_fleet_view::ask_pair);
	table->add_control(pair_button);
#ifdef Q_OS_ANDROID
	/* Each of these runs `ncfg`, which a phone has none of. A button that
	 * answers that it could not run a program is no use to the person. */
	reload_button->hide();
	member_button->hide();
	seal_button->hide();
	pair_button->hide();
	auto *forget_button = new QPushButton(QStringLiteral("Forget this host..."), this);
	connect(forget_button, &QPushButton::clicked, this, [this]() {
		if (QMessageBox::question(this, QStringLiteral("Forget this host"),
		                          QStringLiteral("This phone leaves the host and starts over, "
		                                         "at the pairing screen, with a new key. For a "
		                                         "host that moved, or a phone it revoked."))
		    != QMessageBox::Yes) {
			return;
		}
		QString why;

		if (!ncfg_phone_node_forget(
		        QStandardPaths::writableLocation(QStandardPaths::AppDataLocation), qApp, &why)) {
			QMessageBox::warning(this, QStringLiteral("Forget this host"), why);
			return;
		}
		/* The app ends here: a window on a host this phone has left shows nothing
		 * true, and the next start is the pairing screen. */
		QCoreApplication::quit();
	});
	table->add_control(forget_button);
#endif
	if (auto *cells = table->findChild<QTableWidget *>()) {
		connect(cells, &QTableWidget::cellDoubleClicked, this,
		        [this](int, int) { open_selected(); });
	}
	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);

	timer = new QTimer(this);
	timer->setInterval(ROUND_EVERY);
	connect(timer, &QTimer::timeout, this, &ncfg_fleet_view::refresh);
}

void ncfg_fleet_view::set_wait(int milliseconds)
{
	wait = milliseconds;
}

void ncfg_fleet_view::showEvent(QShowEvent *event)
{
	QWidget::showEvent(event);
	timer->start();
	refresh();
}

void ncfg_fleet_view::hideEvent(QHideEvent *event)
{
	timer->stop();
	QWidget::hideEvent(event);
}

bool ncfg_fleet_view::read_status(const QByteArray &json, ncfg_fleet_row *row)
{
	const QJsonDocument document = QJsonDocument::fromJson(json);

	if (!document.isObject() || !document.object().value(QStringLiteral("links")).isArray()) {
		return false;
	}
	const QJsonObject status = document.object();
	const QJsonObject connectivity = status.value(QStringLiteral("connectivity")).toObject();
	const QJsonObject primary = connectivity.value(QStringLiteral("primary")).toObject();
	const QJsonArray  links = status.value(QStringLiteral("links")).toArray();
	int               up = 0;

	for (const QJsonValue &link : links) {
		up += link.toObject().value(QStringLiteral("carrier")).toBool() ? 1 : 0;
	}
	row->host = status.value(QStringLiteral("hostname")).toString();
	row->connectivity = connectivity.value(QStringLiteral("rung")).toString();
	row->primary = primary.value(QStringLiteral("interface")).toString();
	row->links = QStringLiteral("%1 of %2").arg(up).arg(links.size());
	return true;
}

void ncfg_fleet_view::refresh()
{
	if (asking > 0 || !waiting.isEmpty()) {
		return;
	}
	keys = members();
	for (const QString &gone : rows.keys()) {
		if (!keys.contains(gone)) {
			rows.remove(gone);
		}
	}
	waiting = keys;
	for (const QString &key : keys) {
		ncfg_fleet_row &row = rows[key];

		if (row.state.isEmpty()) {
			row.state = QStringLiteral("asking...");
		}
	}
	draw();
	if (keys.isEmpty()) {
		emit finished_round();
		return;
	}
	start_next();
}

void ncfg_fleet_view::start_next()
{
	while (asking < MOST_AT_ONCE && !waiting.isEmpty()) {
		const QString key = waiting.takeFirst();
#ifdef Q_OS_ANDROID
		/* There is no `ncfg` to run on a phone, so the same read is made here,
		 * off the window's thread: each call waits on another host. */
		asking++;
		QPointer<ncfg_fleet_view> self(this);
		QThread                  *worker = QThread::create([self, key]() {
			char       socket[1100];
			char       err[256];
			char      *json = nullptr;
			size_t     length = 0;
			err[0] = '\0';
			const bool ok = ncfg_fuzznet_user_socket(socket, sizeof(socket)) &&
			    ncfg_fuzznet_status_at(socket, key.toUtf8().constData(), &json, &length, err,
			                           sizeof(err));
			const QByteArray out = ok ? QByteArray(json, (qsizetype)length) : QByteArray();
			const QByteArray said(err);

			free(json);
			QMetaObject::invokeMethod(qApp, [self, key, ok, out, said]() {
				if (self) {
					self->answered(key, ok ? 0 : 1, out, said);
				}
			});
		});
		connect(worker, &QThread::finished, worker, &QObject::deleteLater);
		worker->start();
		continue;
#endif
		auto         *process = new QProcess(this);
		auto         *limit = new QTimer(process);

		asking++;
		limit->setSingleShot(true);
		limit->setInterval(wait);
		connect(limit, &QTimer::timeout, process, &QProcess::kill);
		connect(process, &QProcess::finished, this, [this, key, process](int code,
		                                                                 QProcess::ExitStatus how) {
			const QByteArray out = process->readAllStandardOutput();
			const QByteArray err = process->readAllStandardError();

			process->deleteLater();
			answered(key, how == QProcess::NormalExit ? code : -1, out, err);
		});
		/* The one failure `finished` does not follow. */
		connect(process, &QProcess::errorOccurred, this, [this, key, process](QProcess::ProcessError what) {
			if (what == QProcess::FailedToStart) {
				process->deleteLater();
				answered(key, -1, QByteArray(), QByteArrayLiteral("`ncfg` could not be run"));
			}
		});
		process->start(QStringLiteral("ncfg"),
		               QStringList { QStringLiteral("status"), QStringLiteral("--at"), key,
		                             QStringLiteral("--json") });
		limit->start();
	}
}

void ncfg_fleet_view::answered(const QString &key, int code, const QByteArray &out,
    const QByteArray &err)
{
	asking--;
	if (rows.contains(key)) {
		ncfg_fleet_row &row = rows[key];
		ncfg_fleet_row  fresh = row;
		const QString   said = QString::fromUtf8(err).section(QLatin1Char('\n'), 0, 0).trimmed();

		if (code == 0 && read_status(out, &fresh)) {
			row = fresh;
			row.state = QStringLiteral("answering");
			row.answered = QDateTime::currentDateTime();
		} else if (said.contains(QStringLiteral("denied"))) {
			/* It is there and said no: a closed tier, not a dead node. */
			row.state = QStringLiteral("refused: %1")
			                .arg(said.mid(said.indexOf(QStringLiteral("denied"))));
		} else if (code == 0) {
			row.state = QStringLiteral("no answer: not a status");
		} else {
			row.state = said.isEmpty() ? QStringLiteral("no answer")
			                           : QStringLiteral("no answer: %1").arg(said);
		}
	}
	draw();
	start_next();
	if (asking == 0 && waiting.isEmpty()) {
		emit finished_round();
	}
}

void ncfg_fleet_view::draw()
{
	const int          selected = table->selected_row();
	QList<QStringList> lines;
	int                answering = 0;

	for (const QString &key : keys) {
		const ncfg_fleet_row row = rows.value(key);

		answering += row.state == QStringLiteral("answering") ? 1 : 0;
		lines << QStringList { row.host.isEmpty() ? key.left(16) : row.host, row.state,
			row.connectivity, row.primary, row.links,
			row.answered.isValid() ? row.answered.toString(QStringLiteral("HH:mm:ss"))
			                       : QStringLiteral("never"),
			key };
	}
	table->show_rows(lines);
	if (auto *cells = table->findChild<QTableWidget *>(); cells && selected >= 0) {
		cells->selectRow(selected);
	}
	const QString summary = keys.isEmpty()
	    ? QStringLiteral("no other nodes in the estate")
	    : QStringLiteral("%1 of %2 nodes answering").arg(answering).arg(keys.size());
	QString note = QStringLiteral(
	    "%1. Each node is asked through this user's fuzznetd and judged by its own `remote` "
	    "block, once a minute while this tab is in front. A double click moves the window "
	    "there.").arg(summary);
	if (!action_said.isEmpty()) {
		note += QLatin1Char('\n') + action_said;
	}
	table->set_note(note);
	emit reported(summary);
}

bool ncfg_fleet_view::act(const QStringList &arguments, const QByteArray &input)
{
	if (acting) {
		return false;
	}
	acting = true;
	auto *process = new QProcess(this);
	auto *limit = new QTimer(process);

	limit->setSingleShot(true);
	limit->setInterval(ACTION_WAIT);
	connect(limit, &QTimer::timeout, process, &QProcess::kill);
	auto ended = [this, process](bool worked, const QString &said) {
		process->deleteLater();
		acting = false;
		action_said = said;
		draw();
		emit acted(worked, said);
	};
	connect(process, &QProcess::finished, this, [process, ended](int code,
	                                                             QProcess::ExitStatus how) {
		const QString out = QString::fromUtf8(process->readAllStandardOutput()).trimmed();
		const QString err = QString::fromUtf8(process->readAllStandardError()).trimmed();
		const bool    worked = how == QProcess::NormalExit && code == 0;

		/* The last line: `reload --at estate` ends on its count of nodes. */
		const QString said = worked ? out : (err.isEmpty() ? out : err);
		ended(worked, said.isEmpty() ? QStringLiteral("no answer")
		                             : said.section(QLatin1Char('\n'), -1));
	});
	connect(process, &QProcess::errorOccurred, this, [ended](QProcess::ProcessError what) {
		if (what == QProcess::FailedToStart) {
			ended(false, QStringLiteral("`ncfg` could not be run"));
		}
	});
	process->start(QStringLiteral("ncfg"), arguments);
	/* Written and closed at once: `ncfg` reads to the end of its input, and
	 * nothing of it stays here past this call. */
	if (!input.isEmpty()) {
		process->write(input);
	}
	process->closeWriteChannel();
	limit->start();
	return true;
}

/*
 * `ncfg pair` as root, through what the access tab elevates with, since the node's
 * trust is not grantable. A root child cannot be signalled from here, so closing
 * this leaves it waiting out its code: ten minutes at most, by its own bound.
 */
void ncfg_fleet_view::ask_pair()
{
	const QString elevate = ncfg_access_view::elevator();

	if (elevate.isEmpty()) {
		QMessageBox::information(this, QStringLiteral("Pair a phone"),
		                         QStringLiteral("Nothing here can ask for root. In a terminal: "
		                                        "sudo ncfg pair"));
		return;
	}
	QDialog      dialog(this);
	auto        *layout = new QVBoxLayout(&dialog);
	auto        *code = new QLabel(&dialog);
	auto        *said = new QLabel(QStringLiteral("Asking for root..."), &dialog);
	auto        *close = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
	auto        *open_button = close->addButton(QStringLiteral("Open this machine"),
	                                            QDialogButtonBox::ActionRole);
	QProcess     process;
	QByteArray   out;
	QStringList  arguments;

	dialog.setWindowTitle(QStringLiteral("Pair a phone"));
	said->setWordWrap(true);
	open_button->hide();
	layout->addWidget(code, 0, Qt::AlignHCenter);
	layout->addWidget(said);
	layout->addWidget(close);
	connect(close, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
	connect(&process, &QProcess::readyReadStandardOutput, &dialog, [&]() {
		out += process.readAllStandardOutput();
		const QImage image = ncfg_pair_code_image(out, 5);

		if (!image.isNull() && code->pixmap().isNull() && out.contains("FZI1:")) {
			code->setPixmap(QPixmap::fromImage(image));
			said->setText(QStringLiteral("Open the netcfgd app on the phone and scan this. It "
			                             "works once, for ten minutes, and whoever scans it "
			                             "may join, so show it to nobody else."));
		}
	});
	connect(&process, &QProcess::finished, &dialog, [&](int exit_code, QProcess::ExitStatus how) {
		const QString err = QString::fromUtf8(process.readAllStandardError()).trimmed();

		code->clear();
		said->setText(how == QProcess::NormalExit && exit_code == 0
		                  ? QStringLiteral("A device joined.")
		                  : (err.isEmpty() ? QStringLiteral("No code was made.") : err));
		emit acted(exit_code == 0, said->text());
		/* A closed machine is a question for the person, in words they can
		 * answer, rather than a sentence about a config block. */
		if (err.contains(QStringLiteral("ncfg pair open"))) {
			said->setText(QStringLiteral("This machine is not open to phones yet. Opening it "
			                             "lets a phone you pair read and change its network, "
			                             "and restarts netcfgd."));
			open_button->show();
		}
	});
	connect(open_button, &QPushButton::clicked, &dialog, [&]() {
		QStringList opening = arguments;

		opening << QStringLiteral("open");
		open_button->hide();
		said->setText(QStringLiteral("Opening..."));
		out.clear();
		process.disconnect(&dialog);
		process.start(elevate, opening);
		process.waitForFinished(60000);
		said->setText(process.exitCode() == 0
		                  ? QStringLiteral("Open. Close this, and press Pair a phone again.")
		                  : QString::fromUtf8(process.readAllStandardError()).trimmed());
	});
	if (elevate == QStringLiteral("sudo")) {
		arguments << QStringLiteral("-A");
	}
	arguments << QStringLiteral("ncfg") << QStringLiteral("pair");
	process.start(elevate, arguments);
	dialog.exec();
	process.disconnect(&dialog);
	/* Told nothing further: see above. A process we still own is let go of. */
	process.closeReadChannel(QProcess::StandardOutput);
	if (process.state() != QProcess::NotRunning) {
		process.kill();
		process.waitForFinished(1000);
	}
}

bool ncfg_fleet_view::reload_all()
{
	const QStringList arguments { QStringLiteral("reload"), QStringLiteral("--at"),
		QStringLiteral("estate") };

	return act(arguments, QByteArray());
}

bool ncfg_fleet_view::add_member(const QString &key, const QString &group)
{
	return act(QStringList { QStringLiteral("nodes"), QStringLiteral("member"), key, group },
	           QByteArray());
}

bool ncfg_fleet_view::seal(const QString &group, const QString &key, const QString &value)
{
	const QStringList arguments { QStringLiteral("secret"), QStringLiteral("seal"), group, key };
	QByteArray        input = value.toUtf8() + '\n';
	const bool        started = act(arguments, input);

	input.fill('\0');
	return started;
}

void ncfg_fleet_view::ask_reload()
{
	if (QMessageBox::question(this, QStringLiteral("Reload all"),
	        QStringLiteral("Have every node of the estate re-read its configuration?")) ==
	    QMessageBox::Yes) {
		(void)reload_all();
	}
}

void ncfg_fleet_view::ask_member()
{
	const QString key = table->selected_cell(KEY_COLUMN);
	bool          given = false;

	if (key.isEmpty()) {
		action_said = QStringLiteral("Select a node first.");
		draw();
		return;
	}
	const QString group = QInputDialog::getText(this, QStringLiteral("Add to group"),
	    QStringLiteral("Group:"), QLineEdit::Normal, QString(), &given);
	if (given && !group.isEmpty()) {
		(void)add_member(key, group);
	}
}

void ncfg_fleet_view::ask_seal()
{
	QDialog dialog(this);
	auto   *form = new QFormLayout(&dialog);
	auto   *group = new QLineEdit(&dialog);
	auto   *key = new QLineEdit(&dialog);
	auto   *value = new QLineEdit(&dialog);
	auto   *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
	                                       &dialog);

	dialog.setWindowTitle(QStringLiteral("Seal a value"));
	value->setEchoMode(QLineEdit::Password);
	form->addRow(QStringLiteral("Group:"), group);
	form->addRow(QStringLiteral("Key:"), key);
	form->addRow(QStringLiteral("Value:"), value);
	form->addRow(buttons);
	connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
	connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
	if (dialog.exec() == QDialog::Accepted) {
		(void)seal(group->text(), key->text(), value->text());
	}
	value->clear();
}

void ncfg_fleet_view::open_selected()
{
	const QString key = table->selected_cell(KEY_COLUMN);

	if (!key.isEmpty()) {
		emit opened(key);
	}
}
