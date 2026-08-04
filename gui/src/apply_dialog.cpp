/*
 * apply_dialog.cpp -- the flow described in apply_dialog.h.
 */
#include "apply_dialog.h"

#include "plan_view.h"

#include <QBrush>
#include <QCheckBox>
#include <QColor>
#include <QDialogButtonBox>
#include <QFont>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QSpinBox>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>

namespace {

const char *const journal_titles[] = { "id", "op", "interface", "outcome", "detail" };
constexpr int journal_column_count =
	static_cast<int>(sizeof(journal_titles) / sizeof(journal_titles[0]));

/*
 * The window this offers by default.
 *
 * Sixty seconds, because that is what `ncfg tui` arms and one client should not
 * quietly hand out a different amount of rope than another. The document's own
 * `globals.confirm_default` would be the better answer and this contract does
 * not carry it -- ncfg_client_apply takes a number of seconds and there is no
 * call that says what the machine's default is.
 */
constexpr int default_window_seconds = 60;

const QColor failed_colour(0xC0, 0x20, 0x20);
const QColor skipped_colour(0xB0, 0x60, 0x00);

} /* namespace */

ncfg_apply_dialog::ncfg_apply_dialog(ncfg_connection *connection, QWidget *parent)
	: QDialog(parent), connection(connection)
{
	setWindowTitle(QStringLiteral("Apply"));

	auto *layout = new QVBoxLayout(this);

	/* Whose network this is, on the screen that changes it. A client that
	 * can configure a router across the room must never leave the operator
	 * unsure what they are about to reconfigure (gui/project.md sec 4), and
	 * the apply dialog is the last moment that can be said. */
	auto *where = new QLabel(QStringLiteral("About to change netcfgd at %1")
					 .arg(connection->where()),
				 this);
	where->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(where);

	/* Render-only: the plan it shows is the plan this dialog applies. See
	 * plan_view.h -- fetching a second one would let the operator approve an
	 * observation that is no longer the one being acted on. */
	plan = new ncfg_plan_view(nullptr, this);
	layout->addWidget(plan, 3);

	/* Between the plan and the confirm window, because it is read in that
	 * order: what will happen, what the daemon refuses, then how long you get
	 * to change your mind. Hidden when the plan has nothing refused, so an
	 * ordinary apply is the same dialog it was. */
	consent_box = new QGroupBox(QStringLiteral("What the daemon refuses"), this);
	consent_layout = new QVBoxLayout(consent_box);
	consent_box->setVisible(false);
	layout->addWidget(consent_box);

	auto *window_box = new QGroupBox(QStringLiteral("Confirm window"), this);
	auto *window_layout = new QHBoxLayout(window_box);
	arm_window = new QCheckBox(
		QStringLiteral("Arm a confirm window; the change is undone unless confirmed"),
		window_box);
	/* Armed by default. The failure this guards against -- the apply cuts
	 * off the connection that would have confirmed it -- is silent and
	 * unrecoverable without physical access, while the cost of an unwanted
	 * window is one extra click. */
	arm_window->setChecked(true);
	window_layout->addWidget(arm_window);
	window_seconds = new QSpinBox(window_box);
	window_seconds->setRange(1, 3600);
	window_seconds->setValue(default_window_seconds);
	window_seconds->setSuffix(QStringLiteral(" s"));
	window_layout->addWidget(window_seconds);
	window_layout->addStretch(1);
	connect(arm_window, &QCheckBox::toggled, window_seconds, &QSpinBox::setEnabled);
	layout->addWidget(window_box);

	countdown = new QLabel(this);
	countdown->setVisible(false);
	layout->addWidget(countdown);

	journal = new QTableWidget(0, journal_column_count, this);
	QStringList headers;
	for (int i = 0; i < journal_column_count; i++) {
		headers << QString::fromLatin1(journal_titles[i]);
	}
	journal->setHorizontalHeaderLabels(headers);
	journal->verticalHeader()->setVisible(false);
	journal->setEditTriggers(QAbstractItemView::NoEditTriggers);
	journal->horizontalHeader()->setStretchLastSection(true);
	/* Hidden until there is one. An empty journal table beside a plan reads
	 * as "nothing happened", which before an apply is true but says it in a
	 * place the eye takes for a result. */
	journal->setVisible(false);
	layout->addWidget(journal, 2);

	message = new QLabel(this);
	message->setTextInteractionFlags(Qt::TextSelectableByMouse);
	message->setWordWrap(true);
	layout->addWidget(message);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
	apply_button = buttons->addButton(QStringLiteral("Apply"), QDialogButtonBox::AcceptRole);
	confirm_button =
		buttons->addButton(QStringLiteral("Confirm"), QDialogButtonBox::ActionRole);
	revert_button = buttons->addButton(QStringLiteral("Revert"), QDialogButtonBox::ActionRole);
	apply_button->setEnabled(false);
	/* Only meaningful once a window is armed, and enabling them earlier
	 * would offer to confirm a change that has not happened. */
	confirm_button->setEnabled(false);
	revert_button->setEnabled(false);
	connect(apply_button, &QPushButton::clicked, this, &ncfg_apply_dialog::run_apply);
	connect(confirm_button, &QPushButton::clicked, this, &ncfg_apply_dialog::run_confirm);
	connect(revert_button, &QPushButton::clicked, this, &ncfg_apply_dialog::run_revert);
	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	layout->addWidget(buttons);

	/* A clock and not a poll: it counts down the deadline the daemon already
	 * told us about and asks it nothing. The daemon remains the authority on
	 * whether the window is still open -- this is a display, which is why it
	 * does not disable Confirm when it reaches zero. */
	clock = new QTimer(this);
	clock->setInterval(1000);
	connect(clock, &QTimer::timeout, this, &ncfg_apply_dialog::tick);

	resize(820, 600);

	QString error;
	ncfg_plan_data fetched;
	if (!connection->plan(&fetched, &error)) {
		plan->show_message(error);
		say(error);
		return;
	}
	plan->show_plan(fetched);

	build_consent(fetched);

	/* A refusal usually means *no* actions: the guard stops the ones it
	 * covers, and a plan whose only content is a refusal has an empty action
	 * list. So "nothing to do" cannot be read off the actions alone -- doing
	 * that disabled Apply on exactly the plan consent exists for, which is
	 * what the headless probe found on its first run. */
	if (fetched.actions.isEmpty() && !fetched.blocked() && fetched.stranded.isEmpty()) {
		say(QStringLiteral("Nothing to do -- the machine matches the configuration."));
		return;
	}
	apply_button->setEnabled(true);
	if (fetched.blocked()) {
		say(QStringLiteral("The daemon refuses part of this plan. Tick what you agree "
				   "to below -- each one covers exactly the interface it "
				   "names -- or apply without it and the refused actions "
				   "will not run."));
	} else {
		say(QStringLiteral("Review the plan above. Nothing is sent until Apply."));
	}
}

/*
 * One checkbox per thing the daemon refused, each naming what it covers.
 *
 * Never one box marked "override refusals". `ncfg` spells these
 * `--allow-disruption IFACE` and `--strand-credentials DEV`, repeatable and
 * "deliberately not a blanket --force", and a single control would be that
 * blanket with a friendlier label. The two lists are kept apart for the reason
 * the daemon keeps them apart: an operator who accepted an outage on one
 * interface has not agreed to leave a private key on another.
 *
 * Unticked by default, and nothing here pre-selects: the refusal is the daemon
 * saying no, and a dialog that arrived with the override already ticked would
 * be answering on the operator's behalf.
 */
void ncfg_apply_dialog::build_consent(const ncfg_plan_data &fetched)
{
	if (fetched.refusals.isEmpty() && fetched.stranded.isEmpty()) {
		return;
	}
	consent_box->setVisible(true);

	struct group {
		const QList<ncfg_note_row> *rows;
		const char                 *verb;
		QStringList                *into;
	};
	const group groups[] = {
		{ &fetched.refusals, "disrupt", &agreed.disrupt },
		{ &fetched.stranded, "leave the credential on", &agreed.strand },
	};

	for (const group &g : groups) {
		for (const ncfg_note_row &note : *g.rows) {
			if (note.interface.isEmpty()) {
				continue;
			}
			/* The daemon's own remedy is the label's second half, so
			 * that ticking this and running the command it names are
			 * visibly the same act. */
			auto *box = new QCheckBox(
				QStringLiteral("%1 %2 -- %3")
					.arg(QString::fromLatin1(g.verb), note.interface,
					     note.consent.isEmpty() ? note.message : note.consent),
				consent_box);
			QStringList *into = g.into;
			const QString name = note.interface;
			connect(box, &QCheckBox::toggled, this, [into, name](bool on) {
				into->removeAll(name);
				if (on) {
					into->append(name);
				}
			});
			consent_layout->addWidget(box);
		}
	}
}

void ncfg_apply_dialog::say(const QString &text)
{
	message->setText(text);
}

void ncfg_apply_dialog::run_apply()
{
	const unsigned seconds =
		arm_window->isChecked() ? static_cast<unsigned>(window_seconds->value()) : 0u;

	/* One apply per dialog. Disabled before the call rather than after, so
	 * that a second click while the daemon is working cannot queue a second
	 * apply against a machine the first one has already changed. */
	apply_button->setEnabled(false);
	arm_window->setEnabled(false);
	window_seconds->setEnabled(false);

	QList<ncfg_record_row> records;
	QString error;
	if (!connection->apply(seconds, agreed, &records, &error)) {
		/* The daemon's own sentence, unedited. It names the tier or the
		 * override that would have been needed, and that is the only
		 * part of it that tells the operator what to do next. */
		say(error);
		return;
	}

	show_journal(records);
	emit changed();

	if (seconds > 0) {
		arm(seconds);
	} else {
		say(QStringLiteral("Applied. No confirm window was armed, so this stands."));
	}
}

void ncfg_apply_dialog::show_journal(const QList<ncfg_record_row> &records)
{
	journal->setVisible(true);
	journal->setRowCount(records.size());

	for (int row = 0; row < records.size(); row++) {
		const ncfg_record_row &record = records.at(row);
		const QString cells[journal_column_count] = {
			QString::number(record.id), record.op, record.interface, record.outcome,
			record.detail,
		};
		for (int column = 0; column < journal_column_count; column++) {
			journal->setItem(row, column, new QTableWidgetItem(cells[column]));
		}

		/* The outcome word is the daemon's -- done, failed, skipped --
		 * and is not translated here, because two vocabularies for one
		 * thing is how a person ends up unsure whether the GUI's "error"
		 * and the CLI's "failed" are the same event. Only the weight of
		 * the ink is this screen's decision. */
		if (record.outcome == QStringLiteral("failed") ||
		    record.outcome == QStringLiteral("skipped")) {
			QTableWidgetItem *item = journal->item(row, 3);
			QFont font = item->font();
			font.setBold(true);
			item->setFont(font);
			item->setForeground(QBrush(record.outcome == QStringLiteral("failed")
							   ? failed_colour
							   : skipped_colour));
		}
	}
	journal->resizeColumnsToContents();
	journal->horizontalHeader()->setStretchLastSection(true);
}

void ncfg_apply_dialog::arm(unsigned seconds)
{
	remaining = static_cast<int>(seconds);
	confirm_button->setEnabled(true);
	revert_button->setEnabled(true);
	countdown->setVisible(true);
	tick();
	clock->start();
	say(QStringLiteral("Applied, and armed. Confirm keeps it; Revert undoes it now; doing "
			   "neither undoes it when the window closes."));
}

void ncfg_apply_dialog::tick()
{
	if (remaining > 0) {
		countdown->setText(
			QStringLiteral("Confirm window: about %1s left").arg(remaining));
		remaining--;
		return;
	}

	clock->stop();
	/* By this client's clock, not the daemon's -- the two were never
	 * synchronised and a second either way is possible. The buttons stay
	 * enabled deliberately: if the window is in fact still open, taking it
	 * away here would cost the operator the confirm they came for, and if it
	 * is closed the daemon says so in words this screen will show. */
	countdown->setText(QStringLiteral(
		"Confirm window has closed by this client's clock. Unless the daemon says "
		"otherwise, the change has been reverted."));
}

void ncfg_apply_dialog::run_confirm()
{
	QString error;

	if (!connection->confirm(&error)) {
		say(error);
		return;
	}
	clock->stop();
	countdown->setVisible(false);
	confirm_button->setEnabled(false);
	revert_button->setEnabled(false);
	/* The CLI's sentence for this, word for word. */
	say(QStringLiteral("confirmed; the change stands"));
	emit changed();
}

void ncfg_apply_dialog::run_revert()
{
	QString error;

	if (!connection->revert(&error)) {
		say(error);
		return;
	}
	clock->stop();
	countdown->setVisible(false);
	confirm_button->setEnabled(false);
	revert_button->setEnabled(false);
	say(QStringLiteral("reverted to the last-good configuration"));
	emit changed();
}
