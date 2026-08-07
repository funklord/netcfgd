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

#include <pwd.h>
#include <unistd.h>
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
} /* namespace */

/*
 * Who is running this, according to the kernel rather than the environment.
 *
 * `$USER` is not identity. It is a string any parent process may set to
 * anything, it survives an `su` that does not reset it, and it is simply
 * absent in some session launches -- while this function's answer decides
 * *whose* name is written into a policy granting access to configure the
 * network. The combo box says `this user`, so writing anything other than this
 * user is the label lying.
 *
 * Measured, all three cases, before this was changed: with `USER=root` the
 * environment says root and `getpwuid(getuid())` says the real account; with
 * `USER` unset the environment says nothing and the kernel still answers. The
 * old code produced `user:root` for the first -- granting a tier to somebody
 * else under a label reading `this user` -- and `user:` for the second, which
 * is refused by `Principal::parse`, but only after the operator has been
 * asked for a root password.
 */
QString ncfg_access_view::current_user()
{
	const struct passwd *entry = getpwuid(getuid());

	if (!entry || !entry->pw_name || !*entry->pw_name) {
		return QString();
	}
	return QString::fromLocal8Bit(entry->pw_name);
}

namespace {

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

	/* TDE's RootInfoWidget, which is the other half of its pattern and the
	 * half that is easy to leave out: the *unprivileged* state says so, in a
	 * frame of its own and deliberately without colour. Only the privileged
	 * frame is red, so red keeps meaning one thing. */
	notice = new QLabel(
	    QStringLiteral("<b>Changes here require root.</b><br>Click "
	               "\"Administrator Mode\" to start a privileged helper and edit them."),
	    this);
	notice->setFrameShape(QFrame::Box);
	notice->setFrameShadow(QFrame::Raised);
	notice->setWordWrap(true);
	layout->addWidget(notice);

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
	frame->setFrameShadow(QFrame::Raised);
	/* 2 and 2, as TDE's ConfigModule::runAsRoot sets them. A raised four-pixel
	 * box rather than a flat line, which is what makes it read as a border
	 * around something rather than as a styled widget. */
	frame->setLineWidth(2);
	frame->setMidLineWidth(2);
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
	unlock_button = new QPushButton(QStringLiteral("&Administrator Mode..."), this);
	leave_button = new QPushButton(QStringLiteral("&Leave Administrator Mode"), this);
	apply_button = new QPushButton(QStringLiteral("Apply"), this);
	apply_button->setEnabled(false);
	buttons->addWidget(unlock_button);
	buttons->addWidget(leave_button);
	buttons->addWidget(apply_button);
	buttons->addStretch();
	layout->addLayout(buttons);
	layout->addStretch();

	connect(unlock_button, &QPushButton::clicked, this, &ncfg_access_view::unlock);
	connect(leave_button, &QPushButton::clicked, this, &ncfg_access_view::stop_helper);
	connect(apply_button, &QPushButton::clicked, this, &ncfg_access_view::apply);

	set_administrator_mode(false);
}

void ncfg_access_view::set_administrator_mode(bool live)
{
	administrator = live;

	/* TDE's own method, from ConfigModule::runAsRoot: build a palette *from*
	 * red so every foreground role derives from it, then put the Background
	 * role back to what the parent had. The border comes out red while the
	 * inside keeps the desktop's own colour -- which a `border: 2px solid`
	 * stylesheet cannot do, because it also overrides the frame's children.
	 *
	 * Red only while a privileged helper is running. A border that was always
	 * coloured would say nothing, and one that reddened before anybody
	 * authenticated would say something false. */
	if (live) {
		QPalette red(Qt::red);
		red.setColor(QPalette::Window, palette().color(QPalette::Window));
		frame->setPalette(red);
	} else {
		frame->setPalette(palette());
	}

	observe->setEnabled(live);
	wifi->setEnabled(live);
	admin->setEnabled(live);
	apply_button->setEnabled(live);
	unlock_button->setEnabled(!live);
	leave_button->setEnabled(live);
	/* The unprivileged notice is about a state that is no longer true. */
	notice->setVisible(!live);
}

void ncfg_access_view::stop_helper()
{
	/* Taken into a local and the member cleared *first*, because
	 * `waitForFinished` runs an event loop: the process's own `finished`
	 * signal is delivered inside it, `helper_finished` runs, and it used to
	 * null the member out from under the rest of this function -- which then
	 * dereferenced it and crashed. Found by the headless probe on its first
	 * run, which is the whole reason this path is exercised rather than
	 * assumed. Disconnecting first is the other half: this function is
	 * already doing what that slot would do. */
	QProcess *going = helper;
	if (!going) {
		return;
	}
	helper = nullptr;
	going->disconnect(this);

	/* Closing the write channel is end-of-file to the helper, which is how its
	 * protocol ends. Killing it would work too and would be worse: this is the
	 * path that runs when the client exits normally, so it is the one worth
	 * exercising every time. */
	going->closeWriteChannel();
	if (!going->waitForFinished(5000)) {
		going->kill();
		going->waitForFinished(2000);
	}
	going->deleteLater();
	set_administrator_mode(false);
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
	if (helper) {
		return;
	}

	const QString elevate = elevator();
	if (elevate.isEmpty()) {
		note->setText(QStringLiteral(
		    "nothing here can ask for root (no pkexec, no kdesu, no SUDO_ASKPASS). "
		    "Run this in a terminal instead:\n\nsudo ncfg control set --observe ... "
		    "--wifi ... --admin ..."));
		return;
	}

	/* The editors stay shut until a helper reports uid 0. Opening them first
	 * and asking afterwards is a form that lies about what it can do: nothing
	 * typed into it could be committed. This is 0120's whole point. */
	QStringList arguments;
	if (elevate == QStringLiteral("sudo")) {
		arguments << QStringLiteral("-A");
	}
	arguments << QStringLiteral("ncfg") << QStringLiteral("control")
	          << QStringLiteral("helper");

	helper = new QProcess(this);
	connect(helper, &QProcess::readyReadStandardOutput, this, &ncfg_access_view::helper_spoke);
	connect(helper, &QProcess::finished, this, &ncfg_access_view::helper_finished);
	note->setText(QStringLiteral("asking %1 for root...").arg(elevate));
	unlock_button->setEnabled(false);
	helper->start(elevate, arguments);
}

void ncfg_access_view::helper_spoke()
{
	while (helper && helper->canReadLine()) {
		const QString line = QString::fromUtf8(helper->readLine()).trimmed();

		if (line.startsWith(QStringLiteral("ready "))) {
			/* The uid the helper actually got, not the one asking implied.
			 * An elevator that silently did nothing would otherwise leave a
			 * red frame around an unprivileged process, which is the single
			 * thing this frame must never mean. */
			const uint uid = line.section(QStringLiteral("uid="), 1).toUInt();
			if (uid != 0) {
				note->setText(QStringLiteral(
				    "the helper started but is running as uid %1, not root, so "
				    "nothing here can be changed. Administrator mode was not "
				    "entered.").arg(uid));
				stop_helper();
				return;
			}
			set_administrator_mode(true);
			note->setText(QStringLiteral(
			    "Administrator mode. A helper is running as root; this window is "
			    "not. `this user` writes your own username, `anybody` means every "
			    "process on the machine. Leaving stops the helper."));
			continue;
		}
		if (line.startsWith(QStringLiteral("ok "))) {
			note->setText(QStringLiteral(
			    "written to %1. netcfgd applies it when it next reads its "
			    "configuration; a member of a group has to log out and back in "
			    "first. Reconnect this client afterwards.").arg(line.mid(3)));
			emit changed();
			continue;
		}
		if (line.startsWith(QStringLiteral("error "))) {
			/* The helper's own words. It refuses a policy that would not
			 * compile and says why, and replacing that with "failed" would
			 * throw away the sentence that says what to do. */
			note->setText(line.mid(6));
			continue;
		}
	}
}

void ncfg_access_view::helper_finished()
{
	QProcess *gone = helper;
	if (!gone) {
		return;
	}
	helper = nullptr;

	/* It went away on its own -- a refused password, a missing `ncfg`, a kill.
	 * Whatever the reason, root is no longer held, so the frame must stop
	 * claiming it is. */
	const bool was_live = administrator;
	const QString said = QString::fromUtf8(gone->readAllStandardError()).trimmed();
	gone->deleteLater();
	set_administrator_mode(false);

	if (!said.isEmpty()) {
		note->setText(said);
	} else if (!was_live) {
		note->setText(QStringLiteral("administrator mode was not entered"));
	}
}

void ncfg_access_view::apply()
{
	if (!helper || !administrator) {
		return;
	}

	const QString me = current_user();
	/* The `this user` row carries no value, because the username is not known
	 * until now and hardcoding one at construction would be wrong the moment
	 * somebody switches user. */
	const auto chosen = [&me](QComboBox *box) {
		const QString value = box->currentData().toString();
		if (!value.isEmpty()) {
			return value;
		}
		return QStringLiteral("user:%1").arg(me);
	};

	if (me.isEmpty()) {
		const bool wants_me = observe->currentData().toString().isEmpty()
		                  || wifi->currentData().toString().isEmpty()
		                  || admin->currentData().toString().isEmpty();
		if (wants_me) {
			note->setText(QStringLiteral(
			    "this account has no name in the password database, so `this user` "
			    "cannot be written. Choose `anybody`, or use `group:netcfgd` from a "
			    "terminal."));
			return;
		}
	}

	/* Three typed principals and a verb. No path, no config text, nothing the
	 * helper has to parse as a file -- the same rule `wifi_add` follows, and
	 * for the same reason: a config file may name a hook whose `run_as`
	 * defaults to root. */
	const QString command = QStringLiteral("set %1 %2 %3\n")
	                        .arg(chosen(observe), chosen(wifi), chosen(admin));
	helper->write(command.toUtf8());
	note->setText(QStringLiteral("writing..."));
}

