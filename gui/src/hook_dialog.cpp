/*
 * hook_dialog.cpp -- the editor described in hook_dialog.h.
 */
#include "hook_dialog.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFontDatabase>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
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

/* ------------------------------------------------------------------------ */

ncfg_hooks_editor::ncfg_hooks_editor(const QString &prefix, QWidget *parent)
    : QWidget(parent)
{
	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);

	/* **Every program netcfgd runs for this block.** A hook belongs to the
	 * block whose lifecycle it follows, and the drop-in a dialog writes owns
	 * that block whole -- so the dialog is where they can be edited at all. */
	list = new QListWidget(this);
	list->setObjectName(prefix + QStringLiteral("_hooks"));
	list->setSelectionMode(QAbstractItemView::SingleSelection);
	list->setMaximumHeight(90);
	layout->addWidget(list);

	auto *row = new QHBoxLayout();
	add_button = new QPushButton(QStringLiteral("new hook..."), this);
	add_button->setObjectName(prefix + QStringLiteral("_hook_add"));
	change_button = new QPushButton(QStringLiteral("view / change"), this);
	change_button->setObjectName(prefix + QStringLiteral("_hook_change"));
	drop_button = new QPushButton(QStringLiteral("remove"), this);
	drop_button->setObjectName(prefix + QStringLiteral("_hook_drop"));
	row->addWidget(add_button);
	row->addWidget(change_button);
	row->addWidget(drop_button);
	row->addStretch(1);
	layout->addLayout(row);

	connect(add_button, &QPushButton::clicked, this, &ncfg_hooks_editor::add);
	connect(change_button, &QPushButton::clicked, this, &ncfg_hooks_editor::change);
	connect(list, &QListWidget::itemActivated, this, &ncfg_hooks_editor::change);
	connect(drop_button, &QPushButton::clicked, this, &ncfg_hooks_editor::drop);
}

QString ncfg_hooks_editor::load(ncfg_connection *connection, const QString &name,
    bool is_network, int declared)
{
	owner = name;
	network = is_network;
	scripts.clear();
	list->clear();
	unknown = false;
	if (declared <= 0) {
		return QString();
	}
	const QString noun = network ? QStringLiteral("network") : QStringLiteral("interface");

	QList<ncfg_hook_script> found;
	QString error;
	if (!connection->hook_scripts(&found, &error)) {
		/* Refused, or a daemon that does not know the verb. Either way this
		 * editor has the hooks' existence and not their bodies. */
		unknown = true;
		return QStringLiteral("this %1 has %2 hook(s) and netcfgd would not hand over "
		                      "what is in them: %3")
		    .arg(noun)
		    .arg(declared)
		    .arg(error);
	}
	for (const ncfg_hook_script &script : found) {
		/* A network's hook has no interface and an interface's no network,
		 * so matching on the one field is enough to never take the other's. */
		if ((network ? script.network : script.interface) != owner) {
			continue;
		}
		if (!script.readable) {
			/* The document names a file netcfgd could not open. Writing the
			 * block back would write an empty body over it. */
			unknown = true;
			return QStringLiteral("netcfgd could not read %1, the script behind this "
			                      "%2's `%3` hook")
			    .arg(script.path, noun, script.phase);
		}
		scripts.append(script);
		put(script);
	}
	if (scripts.size() != declared) {
		/* The document says one number and the listing another. Not a state
		 * anything produces today; refusing is the only safe reading of it. */
		unknown = true;
	}
	return QString();
}

QStringList ncfg_hooks_editor::blocks() const
{
	QStringList out;
	for (const ncfg_hook_script &hook : scripts) {
		out << ncfg_hook_block(hook.phase, hook.text);
	}
	return out;
}

/*
 * One row: the phase, and what the script does.
 *
 * The first line that is neither the shebang nor a comment, because a hook
 * written from the template starts with ten lines explaining the environment
 * and a list showing ten copies of `#!/bin/sh` says nothing about any of them.
 */
void ncfg_hooks_editor::put(const ncfg_hook_script &hook)
{
	QString first;
	const QStringList lines = hook.text.split(QLatin1Char('\n'));
	for (const QString &line : lines) {
		const QString trimmed = line.trimmed();
		if (trimmed.isEmpty() || trimmed.startsWith(QLatin1Char('#'))) {
			continue;
		}
		first = trimmed;
		break;
	}
	auto *item = new QListWidgetItem(
	    first.isEmpty() ? hook.phase : QStringLiteral("%1 -- %2").arg(hook.phase, first), list);
	item->setData(Qt::UserRole, hook.phase);
}

void ncfg_hooks_editor::add()
{
	ncfg_hook_dialog dialog(ncfg_hook_script(), this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	ncfg_hook_script written;
	(network ? written.network : written.interface) = owner;
	written.phase = dialog.chosen_phase();
	written.text = dialog.chosen_body();
	written.readable = true;
	scripts.append(written);
	put(written);
}

void ncfg_hooks_editor::change()
{
	const int row = list->currentRow();
	if (row < 0 || row >= scripts.size()) {
		emit noted(QStringLiteral("choose a hook first"));
		return;
	}
	ncfg_hook_dialog dialog(scripts.at(row), this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	ncfg_hook_script changed = scripts.at(row);
	changed.phase = dialog.chosen_phase();
	changed.text = dialog.chosen_body();
	scripts[row] = changed;
	delete list->takeItem(row);
	put(changed);
	list->insertItem(row, list->takeItem(list->count() - 1));
	list->setCurrentRow(row);
}

void ncfg_hooks_editor::drop()
{
	const int row = list->currentRow();
	if (row < 0 || row >= scripts.size()) {
		return;
	}
	scripts.removeAt(row);
	delete list->takeItem(row);
}
