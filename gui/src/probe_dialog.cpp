#include "probe_dialog.h"

#include "ncfg_connection.h"

#include <QDialogButtonBox>
#include <QFontDatabase>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>

namespace {

/*
 * What a new script starts as.
 *
 * Not blank, because a blank page says nothing about the two things that are
 * not guessable: that `$1` is the interface and must be used, and that the
 * exit status is the whole answer. It is deliberately not a working probe --
 * there is no address in it -- since netcfgd ships no opinion about who this
 * machine should talk to, and an example carrying a real one gets copied.
 */
const char *const starting_script =
    "#!/bin/sh\n"
    "# netcfgd runs this on an interval and takes the EXIT STATUS as the answer.\n"
    "# Zero means the link works. Anything else withholds this interface's routes,\n"
    "# exactly as an unplugged cable does.\n"
    "#\n"
    "#   $1  the interface this is about. Use it: netcfgd runs this command as\n"
    "#       given and binds nothing, so a probe that does not name the interface\n"
    "#       answers about whichever one the route table happened to pick.\n"
    "#\n"
    "# What you print on standard error is kept and shown as the reason. Do not\n"
    "# background anything: netcfgd kills the process it started, and a child left\n"
    "# running outlives it.\n"
    "#\n"
    "# Aim past the local gateway. A cable into a switch that has lost its own\n"
    "# uplink has carrier AND a gateway that answers, which is the failure this\n"
    "# exists to catch.\n"
    "\n"
    "interface=\"$1\"\n"
    "\n"
    "# Either host answering is enough. Requiring both reports a broken link every\n"
    "# time one of them has a bad day, and a link that flaps takes the default\n"
    "# route with it.\n"
    "for host in 192.0.2.1 192.0.2.2; do\n"
    "\tif ping -c 1 -W 2 -n -I \"$interface\" \"$host\" >/dev/null 2>&1; then\n"
    "\t\texit 0\n"
    "\tfi\n"
    "done\n"
    "\n"
    "echo \"nothing answered via $interface\" >&2\n"
    "exit 1\n";

} // namespace

ncfg_probe_dialog::ncfg_probe_dialog(ncfg_connection *connection, const ncfg_probe_row &existing,
    QWidget *parent)
    : QDialog(parent), connection(connection)
{
	const bool editing = !existing.name.isEmpty();
	setWindowTitle(editing ? QStringLiteral("link detection: %1").arg(existing.name)
	                 : QStringLiteral("new link-detection script"));
	resize(760, 560);

	auto *layout = new QVBoxLayout(this);

	name = new QLineEdit(this);
	name->setObjectName(QStringLiteral("probe_name"));
	name->setPlaceholderText(QStringLiteral("a name, without a path"));
	if (editing) {
		name->setText(existing.name);
	}
	layout->addWidget(name);

	body = new QPlainTextEdit(this);
	body->setObjectName(QStringLiteral("probe_body"));
	/* Fixed width, because this is a program: a proportional font turns the
	 * indentation of a shell `if` into guesswork. */
	body->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
	body->setTabChangesFocus(false);
	if (editing) {
		/* Already in hand from the listing: the daemon sent the text with the
		 * name, so there is no file for this process to open -- and on a
		 * remote connection there would not be one to open here anyway. */
		body->setPlainText(existing.text);
	} else {
		body->setPlainText(QString::fromLatin1(starting_script));
	}
	layout->addWidget(body);

	note = new QLabel(this);
	note->setWordWrap(true);
	note->setTextInteractionFlags(Qt::TextSelectableByMouse);
	/*
	 * Said up front rather than on failure. Saving needs root -- a probe is a
	 * program netcfgd runs as root on an interval, so the daemon refuses it
	 * from anyone else -- and finding that out after writing a script is the
	 * worst moment to find it out.
	 *
	 * Where it is saved is worth saying too: an edit of a shipped example
	 * lands in /etc as a copy, so the example is still there to go back to.
	 */
	note->setText(
	    (editing && !existing.editable)
	        ? QStringLiteral(
	              "This is a shipped example in %1 and is not edited in place: saving "
	              "writes your copy into /etc/netcfgd/probe, which then shadows it. "
	              "The original stays where it is.\nThis needs root: netcfgd runs a "
	              "probe as root, on an interval, so the daemon refuses to store one "
	              "for anybody else.")
	              .arg(existing.directory)
	        : QStringLiteral(
	              "Saved into /etc/netcfgd/probe, executable.\nThis needs root: "
	              "netcfgd runs a probe as root, on an interval, so the daemon "
	              "refuses to store one for anybody else."));
	layout->addWidget(note);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
	save_button = buttons->addButton(QStringLiteral("Save"), QDialogButtonBox::AcceptRole);
	save_button->setObjectName(QStringLiteral("probe_save"));
	layout->addWidget(buttons);

	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(save_button, &QPushButton::clicked, this, &ncfg_probe_dialog::submit);
}

void ncfg_probe_dialog::submit()
{
	const QString wanted = name->text().trimmed();
	if (wanted.isEmpty()) {
		note->setText(QStringLiteral("a script needs a name"));
		return;
	}
	/* Refused here as well as at the daemon, which refuses it too: netcfgd
	 * chooses the directory, and the round trip would not say which part of
	 * the name was the problem. */
	if (wanted.contains(QLatin1Char('/')) || wanted.startsWith(QLatin1Char('.'))) {
		note->setText(QStringLiteral(
		    "a name is a plain filename -- netcfgd chooses the directory"));
		return;
	}
	const QString text = body->toPlainText();
	if (text.trimmed().isEmpty()) {
		/* An empty file exits zero, which netcfgd would read as the link being
		 * up for ever. Worth refusing rather than storing. */
		note->setText(QStringLiteral(
		    "an empty script exits zero, which netcfgd reads as the link being up"));
		return;
	}

	QString error;
	if (!connection->probe_put(wanted, text, true, &error)) {
		note->setText(error);
		return;
	}

	saved_name = wanted;
	summary = QStringLiteral("wrote /etc/netcfgd/probe/%1").arg(wanted);
	accept();
}
