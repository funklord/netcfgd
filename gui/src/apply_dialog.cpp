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

	if (fetched.blocked()) {
		say(QStringLiteral("The daemon refuses part of this plan. Apply is not offered: "
				   "the `what to do` column above is the daemon's own remedy, "
				   "and this client cannot send it."));
		return;
	}
	if (fetched.actions.isEmpty()) {
		say(QStringLiteral("Nothing to do -- the machine matches the configuration."));
		return;
	}
	apply_button->setEnabled(true);
	say(QStringLiteral("Review the plan above. Nothing is sent until Apply."));
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
	if (!connection->apply(seconds, &records, &error)) {
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
