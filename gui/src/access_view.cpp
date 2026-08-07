/*
 * access_view.cpp -- the administrator mode described in access_view.h.
 */
#include "access_view.h"

#include "ncfg_connection.h"

#include <QComboBox>
#include <QFormLayout>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QProcess>
#include <QPushButton>
#include <QStandardPaths>
#include <QVBoxLayout>

namespace {

/*
 * The four shapes a principal has, in the order an operator narrows through.
 *
 * `any` is last and is not the default anywhere: it means every process on the
 * machine, and a list that offered it first would be offering it.
 */
void fill(QComboBox *box)
{
	box->addItem(QStringLiteral("root only"), QStringLiteral("root"));
	box->addItem(QStringLiteral("the netcfgd group"), QStringLiteral("group:netcfgd"));
	box->addItem(QStringLiteral("this user"), QString());
	box->addItem(QStringLiteral("anybody"), QStringLiteral("any"));
	box->setEnabled(false);
}

/*
 * Something that can run a command as root, or nothing.
 *
 * Tried in turn rather than hardcoded, because none of these is on every
 * machine and this client has no business requiring a particular desktop.
 * `pkexec` first because it is the one that shows a dialog on a graphical
 * session; `kdesu` because 0118's pattern is KDE's; `sudo -A` only when an
 * askpass helper is configured, since a `sudo` that wants a terminal from a
 * process with none would hang forever with nothing on screen.
 */
QString elevator()
{
	if (!QStandardPaths::findExecutable(QStringLiteral("pkexec")).isEmpty()) {
		return QStringLiteral("pkexec");
	}
	if (!QStandardPaths::findExecutable(QStringLiteral("kdesu")).isEmpty()) {
		return QStringLiteral("kdesu");
	}
	const bool askpass = !qEnvironmentVariableIsEmpty("SUDO_ASKPASS");
	const bool have_sudo =
		!QStandardPaths::findExecutable(QStringLiteral("sudo")).isEmpty();
	if (askpass && have_sudo) {
		return QStringLiteral("sudo");
	}
	return QString();
}

} /* namespace */

ncfg_access_view::ncfg_access_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	auto *layout = new QVBoxLayout(this);

	auto *explain = new QLabel(
	    QStringLiteral("Every tier is root until somebody says otherwise, so a client run "
	               "by an ordinary user is refused. This changes that, and writes it "
	               "to netcfgd's configuration as ordinary text you can read and "
	               "revert."),
	    this);
	explain->setWordWrap(true);
	layout->addWidget(explain);

	/* The framed part. Everything privileged is inside it and nothing else is,
	 * which is what makes the frame mean something. */
	frame = new QFrame(this);
	frame->setFrameShape(QFrame::Box);
	frame->setLineWidth(2);
	auto *form = new QFormLayout(frame);

	observe = new QComboBox(frame);
	wifi = new QComboBox(frame);
	admin = new QComboBox(frame);
	fill(observe);
	fill(wifi);
	fill(admin);
	form->addRow(QStringLiteral("observe -- what the network looks like"), observe);
	form->addRow(QStringLiteral("wifi -- join, leave and scan known networks"), wifi);
	form->addRow(QStringLiteral("admin -- change anything, including adding a network"), admin);
	layout->addWidget(frame);

	note = new QLabel(this);
	note->setWordWrap(true);
	/* Selectable because when nothing can elevate this holds the command to
	 * run, and a command somebody has to retype is a command they get wrong. */
	note->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(note);

	auto *buttons = new QHBoxLayout();
	unlock_button = new QPushButton(QStringLiteral("Administrator Mode..."), this);
	apply_button = new QPushButton(QStringLiteral("Apply"), this);
	apply_button->setEnabled(false);
	buttons->addWidget(unlock_button);
	buttons->addWidget(apply_button);
	buttons->addStretch();
	layout->addLayout(buttons);
	layout->addStretch();

	connect(unlock_button, &QPushButton::clicked, this, &ncfg_access_view::unlock);
	connect(apply_button, &QPushButton::clicked, this, &ncfg_access_view::apply);

	set_administrator_mode(false);
}

void ncfg_access_view::set_administrator_mode(bool live)
{
	administrator = live;

	/* Red only while privileged, and the frame is otherwise the ordinary one.
	 * A border that was always coloured would say nothing. */
	frame->setStyleSheet(live ? QStringLiteral("QFrame { border: 2px solid #c00000; }")
	                  : QString());
	observe->setEnabled(live);
	wifi->setEnabled(live);
	admin->setEnabled(live);
	apply_button->setEnabled(live);
	unlock_button->setEnabled(!live);
}

void ncfg_access_view::refresh()
{
	ncfg_tiers_t held = connection->tiers();
	const QString summary =
	    QStringLiteral("this connection holds:%1%2%3")
	        .arg(held.observe ? QStringLiteral(" observe") : QString())
	        .arg(held.wifi ? QStringLiteral(" wifi") : QString())
	        .arg(held.admin ? QStringLiteral(" admin") : QString());

	/* What this connection was granted, which is the question somebody on this
	 * tab is asking. The policy itself lives in a file this client cannot read
	 * -- it is root's -- so the honest thing to show is the answer the daemon
	 * gave at the handshake rather than a guess at the file. */
	note->setText(held.observe || held.wifi || held.admin
	              ? summary
	              : QStringLiteral("this connection holds nothing, which is what a "
	                       "default install gives an ordinary user"));
	emit reported(note->text());
}

void ncfg_access_view::unlock()
{
	/* No authentication here, and none is asked for: the elevator owns that.
	 * This only opens the editors, and the command that runs on Apply is the
	 * one that will prompt. */
	set_administrator_mode(true);
	note->setText(QStringLiteral(
	    "Administrator mode. Choosing `this user` writes your own username; "
	    "`anybody` means every process on the machine. Apply runs one command as "
	    "root."));
}

void ncfg_access_view::apply()
{
	/* The `this user` row carries no value, because the username is not known
	 * until now and hardcoding one at construction would be wrong the moment
	 * somebody switches user. */
	const auto chosen = [](QComboBox *box) {
		const QString value = box->currentData().toString();
		if (!value.isEmpty()) {
			return value;
		}
		return QStringLiteral("user:%1").arg(qEnvironmentVariable("USER"));
	};

	QStringList tiers;
	tiers << QStringLiteral("--observe") << chosen(observe);
	tiers << QStringLiteral("--wifi") << chosen(wifi);
	tiers << QStringLiteral("--admin") << chosen(admin);

	const QString elevate = elevator();
	QStringList command;
	command << QStringLiteral("ncfg") << QStringLiteral("control")
	    << QStringLiteral("set") << tiers;

	if (elevate.isEmpty()) {
		/* Nothing on this machine can raise privilege without a terminal, so
		 * the command is shown rather than half-attempted. That is 0118's
		 * no-dependency answer and it is honest: a dialog that failed silently
		 * would be worse than one that says what to type. */
		note->setText(QStringLiteral("nothing here can ask for root (no pkexec, no kdesu, "
		                 "no SUDO_ASKPASS). Run this in a terminal:\n\nsudo %1")
		              .arg(command.join(QLatin1Char(' '))));
		return;
	}

	QStringList arguments;
	if (elevate == QStringLiteral("sudo")) {
		arguments << QStringLiteral("-A");
	}
	arguments << command;

	QProcess process;
	process.start(elevate, arguments);
	if (!process.waitForFinished(120000) || process.exitCode() != 0) {
		const QString said = QString::fromUtf8(process.readAllStandardError()).trimmed();
		/* The command's own words. `ncfg control set` refuses a policy that
		 * would not compile and says why, and replacing that with "failed"
		 * would throw away the sentence that says what to do. */
		note->setText(said.isEmpty()
		              ? QStringLiteral("`%1` did not finish").arg(elevate)
		              : said);
		return;
	}

	set_administrator_mode(false);
	note->setText(QStringLiteral(
	    "written. netcfgd applies it when it next reads its configuration; a member "
	    "of a group has to log out and back in first. Reconnect this client "
	    "afterwards."));
	emit changed();
}
