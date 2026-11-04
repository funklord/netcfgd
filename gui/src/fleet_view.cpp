/*
 * fleet_view.cpp -- the table described in fleet_view.h.
 */
#include "fleet_view.h"

#include "table_view.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QPushButton>
#include <QShowEvent>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>

/* What `ncfg status --at` takes up on a node at once, and how often the tab
 * asks while it is in front. */
static const int MOST_AT_ONCE = 4;
static const int ROUND_EVERY = 60000;
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
	table->set_note(QStringLiteral(
	    "%1. Each node is asked through this user's fuzznetd and judged by its own `remote` "
	    "block, once a minute while this tab is in front. A double click moves the window "
	    "there.").arg(summary));
	emit reported(summary);
}

void ncfg_fleet_view::open_selected()
{
	const QString key = table->selected_cell(KEY_COLUMN);

	if (!key.isEmpty()) {
		emit opened(key);
	}
}
