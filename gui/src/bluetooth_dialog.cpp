/*
 * bluetooth_dialog.cpp -- the editor described in bluetooth_dialog.h.
 */
#include "bluetooth_dialog.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QVBoxLayout>

namespace {

struct choice {
	const char *shown;
	const char *key;
};

/* What this machine uses the device for. A closed set in the language, and
 * therefore a list here: the compiler names these five and refuses anything
 * else, so free text would be a round trip to find that out. */
const choice profiles[] = {
	{ "a2dp-sink -- this machine plays to it: a speaker, headphones", "a2dp-sink" },
	{ "a2dp-source -- this machine receives from it: a phone", "a2dp-source" },
	{ "hfp -- hands-free: a microphone and an earpiece", "hfp" },
	{ "pan -- this machine joins the device's network", "pan" },
	{ "nap -- this machine serves a network to the device", "nap" },
};

/* Which profiles carry packets rather than sound. The distinction is the
 * model's `is_audio`, and it decides what else the operator has to do. */
bool carries_network(const QString &profile)
{
	return profile == QLatin1String("pan") || profile == QLatin1String("nap");
}

bool safe_value(const QString &text)
{
	return !text.contains(QLatin1Char('"')) && !text.contains(QLatin1Char('\\')) &&
	       !text.contains(QLatin1Char('\n'));
}

} // namespace

QString ncfg_bluetooth_address(const QString &typed)
{
	QString bare;
	for (const QChar one : typed.trimmed()) {
		if (one == QLatin1Char(':') || one == QLatin1Char('-')) {
			continue;
		}
		if (!isxdigit(one.toLatin1())) {
			return QString();
		}
		bare.append(one.toUpper());
	}
	if (bare.size() != 12) {
		return QString();
	}
	QStringList octets;
	for (int at = 0; at < 12; at += 2) {
		octets << bare.mid(at, 2);
	}
	return octets.join(QLatin1Char(':'));
}

QString ncfg_bluetooth_block(const ncfg_bluetooth_row &settings)
{
	QStringList body;

	body << QStringLiteral("\taddress = \"%1\"").arg(settings.address);
	body << QStringLiteral("\tprofile = \"%1\"").arg(settings.profile);
	/* **Only when false.** `autoconnect` is true unless a document says
	 * otherwise -- a device somebody wrote down is one they want used, which
	 * is `network`'s rule -- and a block restating every default is one nobody
	 * can read for what is unusual. */
	if (!settings.autoconnect) {
		body << QStringLiteral("\tautoconnect = false");
	}

	QStringList block;
	block << QStringLiteral("# Written by netcfgd's gui. Ordinary netcfgd configuration:");
	block << QStringLiteral("# edit it, diff it, commit it, or delete it.");
	block << QString();
	block << QStringLiteral("bluetooth \"%1\" {").arg(settings.id);
	block << body;
	block << QStringLiteral("}");
	return block.join(QStringLiteral("\n")) + QStringLiteral("\n");
}

ncfg_bluetooth_dialog::ncfg_bluetooth_dialog(ncfg_connection *connection,
    const ncfg_bluetooth_row &existing, QWidget *parent)
    : QDialog(parent), connection(connection), before(existing), editing(!existing.id.isEmpty())
{
	setWindowTitle(editing ? QStringLiteral("bluetooth: %1").arg(existing.id)
	                       : QStringLiteral("new bluetooth device"));
	setObjectName(QStringLiteral("bluetooth_dialog"));

	auto *layout = new QVBoxLayout(this);
	auto *form = new QFormLayout();

	id = new QLineEdit(existing.id, this);
	id->setObjectName(QStringLiteral("bt_id"));
	/* The block's label and the drop-in's filename, so an existing one cannot
	 * be renamed here: that is a delete and a write, and doing it silently
	 * would leave the old file behind. */
	id->setReadOnly(editing);
	id->setPlaceholderText(QStringLiteral("what you call it -- headphones, phone, car"));
	form->addRow(QStringLiteral("name"), id);

	address = new QLineEdit(existing.address, this);
	address->setObjectName(QStringLiteral("bt_address"));
	address->setPlaceholderText(QStringLiteral("AA:BB:CC:DD:EE:FF"));
	address->setToolTip(QStringLiteral(
	    "The hardware's own address. Dashes or twelve bare hex digits are taken too "
	    "and written back in the form netcfgd's configuration language uses."));
	form->addRow(QStringLiteral("address"), address);

	profile = new QComboBox(this);
	profile->setObjectName(QStringLiteral("bt_profile"));
	for (const auto &one : profiles) {
		profile->addItem(QString::fromLatin1(one.shown), QString::fromLatin1(one.key));
	}
	form->addRow(QStringLiteral("used for"), profile);

	autoconnect = new QCheckBox(QStringLiteral("connect it without being asked"), this);
	autoconnect->setObjectName(QStringLiteral("bt_autoconnect"));
	autoconnect->setChecked(true);
	form->addRow(QString(), autoconnect);
	layout->addLayout(form);

	/* What follows from the profile, which is the half an operator cannot be
	 * expected to know: one produces a link, the other needs a sound daemon. */
	consequence = new QLabel(this);
	consequence->setObjectName(QStringLiteral("bt_consequence"));
	consequence->setWordWrap(true);
	layout->addWidget(consequence);

	note = new QLabel(this);
	note->setObjectName(QStringLiteral("bt_note"));
	note->setWordWrap(true);
	note->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(note);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
	save_button = buttons->addButton(QStringLiteral("Save"), QDialogButtonBox::AcceptRole);
	save_button->setObjectName(QStringLiteral("bt_save"));
	remove_button = nullptr;
	if (editing) {
		remove_button = buttons->addButton(QStringLiteral("delete"),
		    QDialogButtonBox::DestructiveRole);
		remove_button->setObjectName(QStringLiteral("bt_remove"));
		connect(remove_button, &QPushButton::clicked, this, &ncfg_bluetooth_dialog::remove);
	}
	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(save_button, &QPushButton::clicked, this, &ncfg_bluetooth_dialog::submit);
	connect(profile, &QComboBox::currentIndexChanged, this,
	    &ncfg_bluetooth_dialog::profile_changed);
	layout->addWidget(buttons);
	resize(560, 320);

	if (editing) {
		const int at = profile->findData(existing.profile);
		if (at >= 0) {
			profile->setCurrentIndex(at);
		}
		autoconnect->setChecked(existing.autoconnect);
	}
	profile_changed();
}

void ncfg_bluetooth_dialog::profile_changed()
{
	/*
	 * **Said here because nothing downstream will say it.** The planner warns
	 * that the block is not acted on, and that warning is per device and lands
	 * in `ncfg plan`; what it cannot say is which *other* configuration this
	 * choice implies, because that depends on which profile was picked a
	 * moment ago in this window.
	 */
	const QString chosen = profile->currentData().toString();
	consequence->setText(
	    carries_network(chosen)
	        ? QStringLiteral(
	              "A network profile produces a `bnep` link when it connects, and a link "
	              "is configured like any other: give it an `interface` block, or it "
	              "comes up with no address.")
	        : QStringLiteral(
	              "An audio profile carries sound rather than packets. netcfgd routes no "
	              "audio: what plays to it is `bluealsa` and whatever is playing."));
}

void ncfg_bluetooth_dialog::submit()
{
	const QLineEdit *values[] = { id, address };
	for (const QLineEdit *value : values) {
		if (!safe_value(value->text())) {
			note->setText(QStringLiteral("a value cannot carry a quote, a backslash "
			              "or a newline"));
			return;
		}
	}
	const QString name = id->text().trimmed();
	if (name.isEmpty()) {
		note->setText(QStringLiteral("a device needs a name: it is how netcfgd files it "
		              "and how you find it again"));
		return;
	}
	/* **Refused here rather than after a round trip**, and in the form the
	 * compiler asks for: its diagnostic says "six colon-separated hex octets"
	 * and arrives beside a line number in a file the operator did not write. */
	const QString written = ncfg_bluetooth_address(address->text());
	if (written.isEmpty()) {
		note->setText(QStringLiteral(
		    "that is not a Bluetooth address: six hex octets, `AA:BB:CC:DD:EE:FF`. "
		    "Dashes or twelve bare hex digits are taken too."));
		return;
	}

	ncfg_bluetooth_row settings;
	settings.id = name;
	settings.address = written;
	settings.profile = profile->currentData().toString();
	settings.autoconnect = autoconnect->isChecked();

	QString error;
	if (!connection->config_put(QStringLiteral("bluetooth-%1").arg(name),
	        ncfg_bluetooth_block(settings), true, &error)) {
		note->setText(error);
		return;
	}
	/*
	 * **And what it will not do**, which is everything. The planner says so
	 * per device in the plan; saying it here as well is the difference between
	 * an operator reading it and an operator wondering why their headphones
	 * are silent. The wording is the planner's own, on purpose.
	 */
	summary = QStringLiteral("wrote bluetooth-%1: netcfgd re-read its configuration. This "
	              "build understands the block and does not act on it -- nothing "
	              "pairs the device, connects it, or brings a `pan` link up.")
	          .arg(name);
	accept();
}

void ncfg_bluetooth_dialog::remove()
{
	const QString question =
	    QStringLiteral("Delete the bluetooth device `%1`?\n\nThe pairing stays where it "
	               "is: that is the adapter's own key store, and netcfgd does not "
	               "own it.")
	        .arg(before.id);
	QMessageBox box(QMessageBox::Question, QStringLiteral("netcfgd"), question,
	    QMessageBox::Cancel | QMessageBox::Yes, this);
	box.setDefaultButton(QMessageBox::Cancel);
	if (box.exec() != QMessageBox::Yes) {
		return;
	}

	QString error;
	if (!connection->config_delete(QStringLiteral("bluetooth-%1").arg(before.id), &error)) {
		note->setText(error);
		return;
	}
	summary = QStringLiteral("removed bluetooth-%1: netcfgd re-read its configuration.")
	          .arg(before.id);
	accept();
}
