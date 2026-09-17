/*
 * hook_dialog.cpp -- the editor described in hook_dialog.h.
 */
#include "hook_dialog.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFontDatabase>
#include <QFormLayout>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>

namespace {

struct phase_choice {
	const char *key;
	const char *shown;
	/* Whether the block is spelled `on <key>` rather than `<key>`. The parser
	 * takes six phase names bare and every event after `on`, and this is the
	 * whole difference between a hook block and a syntax error. */
	bool event;
};

/* Every phase this build runs. The planner keeps the authoritative list and
 * warns about a hook it will never fire; all eleven are on it today, so none
 * of these needs a caveat beside it. */
const phase_choice phases[] = {
	{ "pre_up", "pre_up -- before the link comes up, while it is still down", false },
	{ "up", "up -- the link is live and nothing is addressed yet", false },
	{ "post_up", "post_up -- after the last address is installed", false },
	{ "pre_down", "pre_down -- before anything is taken away, network still working", false },
	{ "down", "down -- addresses gone, link about to go", false },
	{ "post_down", "post_down -- after the link is down", false },
	{ "carrier", "on carrier -- carrier gained or lost", true },
	{ "lease", "on lease -- a lease acquired, renewed or lost", true },
	{ "roam", "on roam -- the station moved to another access point", true },
	{ "portal", "on portal -- a captive portal was detected", true },
	{ "drift", "on drift -- the machine stopped matching the document", true },
};

/*
 * What a new hook starts as.
 *
 * Not blank. The environment is the part nobody can guess, and the closing
 * rule is the part that bites: a line of its own containing `}` ends the hook,
 * so a shell function written the usual way silently cuts the script in half.
 * The shebang is here so that what is saved and what netcfgd runs are the same
 * bytes -- the materialiser adds one to a body without it, and a body that
 * carries its own round-trips unchanged.
 */
const char *const starting_script =
    "#!/bin/sh\n"
    "# netcfgd runs this when the phase above is reached. What it prints goes to\n"
    "# the journal; a non-zero exit from pre_up, pre_down or down stops the apply.\n"
    "#\n"
    "# The environment is prefixed NCFG_: NCFG_INTERFACE is the interface,\n"
    "# NCFG_PHASE is the phase, and NCFG_REASON says why where there is one.\n"
    "#\n"
    "# A line of its own containing only `}` ENDS THIS HOOK -- a body is raw shell\n"
    "# and the language does not count braces. Write a function on one line:\n"
    "#   announce() { logger -t netcfgd \"$1\"; }\n"
    "\n"
    "logger -t netcfgd \"$NCFG_INTERFACE reached $NCFG_PHASE\"\n";

} // namespace

QString ncfg_hook_block(const QString &phase, const QString &body)
{
	bool event = false;
	for (const auto &one : phases) {
		if (phase == QLatin1String(one.key)) {
			event = one.event;
		}
	}

	QStringList block;
	block << QStringLiteral("\t%1%2 {").arg(event ? QStringLiteral("on ") : QString(), phase);
	/* **Verbatim, at column zero.** The body is shell and the language keeps
	 * every byte of it, so indenting would put whitespace in front of the
	 * shebang -- at which point the materialiser stops recognising it and
	 * prepends another, once per save. */
	QString text = body;
	while (text.endsWith(QLatin1Char('\n'))) {
		text.chop(1);
	}
	block << text;
	block << QStringLiteral("\t}");
	return block.join(QStringLiteral("\n"));
}

bool ncfg_hook_body_terminates_early(const QString &body)
{
	const QStringList lines = body.split(QLatin1Char('\n'));
	for (const QString &line : lines) {
		if (line.trimmed() == QLatin1String("}")) {
			return true;
		}
	}
	return false;
}

ncfg_hook_dialog::ncfg_hook_dialog(const ncfg_hook_script &existing, QWidget *parent)
    : QDialog(parent)
{
	const bool editing = !existing.phase.isEmpty();
	setWindowTitle(editing ? QStringLiteral("hook: %1").arg(existing.phase)
	                       : QStringLiteral("new hook"));
	setObjectName(QStringLiteral("hook_dialog"));
	resize(760, 600);

	auto *layout = new QVBoxLayout(this);
	auto *form = new QFormLayout();

	phase = new QComboBox(this);
	phase->setObjectName(QStringLiteral("hook_phase"));
	for (const auto &one : phases) {
		phase->addItem(QString::fromLatin1(one.shown), QString::fromLatin1(one.key));
	}
	if (editing) {
		const int at = phase->findData(existing.phase);
		if (at >= 0) {
			phase->setCurrentIndex(at);
		}
	} else {
		phase->setCurrentIndex(phase->findData(QStringLiteral("post_up")));
	}
	form->addRow(QStringLiteral("when"), phase);
	layout->addLayout(form);

	body = new QPlainTextEdit(this);
	body->setObjectName(QStringLiteral("hook_body"));
	/* Fixed width, because this is a program: a proportional font turns the
	 * indentation of a shell `if` into guesswork. */
	body->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
	body->setTabChangesFocus(false);
	body->setPlainText(editing ? existing.text : QString::fromLatin1(starting_script));
	layout->addWidget(body);

	note = new QLabel(this);
	note->setObjectName(QStringLiteral("hook_note"));
	note->setWordWrap(true);
	note->setTextInteractionFlags(Qt::TextSelectableByMouse);
	/*
	 * Said before anything is typed, because both halves are found out at the
	 * worst moment otherwise. Writing a hook is root on this machine -- a hook
	 * body is the production `check_content` refuses from anybody else -- and
	 * `run_as` is not a thing this build can be asked for at all.
	 */
	note->setText(QStringLiteral(
	    "This hook runs as root. netcfgd's hook runner can drop to another user, and "
	    "the configuration language has no key to name one, so there is nothing to "
	    "offer here yet -- a `run_as=` line in the body is a shell assignment and "
	    "changes nothing.\nSaving the interface needs root: a hook is a program "
	    "netcfgd runs privileged, which the daemon refuses to take from anybody else."));
	layout->addWidget(note);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
	save_button = buttons->addButton(QStringLiteral("Keep"), QDialogButtonBox::AcceptRole);
	save_button->setObjectName(QStringLiteral("hook_save"));
	layout->addWidget(buttons);

	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(save_button, &QPushButton::clicked, this, &ncfg_hook_dialog::submit);
}

void ncfg_hook_dialog::submit()
{
	const QString text = body->toPlainText();
	if (text.trimmed().isEmpty()) {
		/* An empty hook is a file netcfgd runs at every one of that phase for
		 * no effect, and the operator reading the list later cannot tell it
		 * from one that broke. */
		note->setText(QStringLiteral("an empty hook runs nothing: write the script, or "
		              "cancel and remove the hook"));
		return;
	}
	if (ncfg_hook_body_terminates_early(text)) {
		note->setText(QStringLiteral(
		    "a line containing only `}` ends the hook there, and netcfgd would read "
		    "the rest of this script as configuration. Put a shell function on one "
		    "line instead: `announce() { logger -t netcfgd \"$1\"; }`"));
		return;
	}

	phase_key = phase->currentData().toString();
	body_text = text;
	accept();
}
