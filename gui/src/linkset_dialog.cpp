/*
 * linkset_dialog.cpp -- the group editor described in linkset_dialog.h.
 *
 * Two things live here and only one of them is the window. The other is
 * `ncfg_linkset_block`, which turns a name and an ordered list into the
 * configuration text netcfgd compiles, and it is a free function because both
 * ways it can be wrong -- a reordered list, a name that needs quoting -- are
 * invisible in a screenshot and checkable without a daemon.
 */
#include "linkset_dialog.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QVBoxLayout>

QString ncfg_linkset_block(const QString &name, const QStringList &members)
{
	QStringList quoted;
	for (const QString &member : members) {
		quoted << QStringLiteral("\"%1\"").arg(member);
	}
	/* **The list in its own order, always as a list.** The order is the
	 * ranking, so nothing sorts it; and a single member is written
	 * `["eth0"]` rather than `"eth0"` even though both compile, because a
	 * block that changes shape when it happens to have one member is one an
	 * operator has to read twice. */
	return QStringLiteral("# Written by netcfgd's gui. Ordinary netcfgd configuration:\n"
	           "# edit it, diff it, commit it, or delete it.\n"
	           "#\n"
	           "# A linkset is a group of links with one of them in use. The\n"
	           "# order below is the ranking where two members' metrics cannot\n"
	           "# tell them apart.\n"
	           "\n"
	           "linkset \"%1\" {\n"
	           "\tmembers = [%2]\n"
	           "}\n")
	    .arg(name, quoted.join(QStringLiteral(", ")));
}

QString ncfg_linkset_name_refusal(const QString &name)
{
	if (name.trimmed().isEmpty()) {
		return QStringLiteral("a group needs a name; it is how other blocks refer to it");
	}
	if (name != name.trimmed()) {
		return QStringLiteral("a name cannot start or end with a space");
	}
	for (const QChar &character : name) {
		if (character.isSpace()) {
			return QStringLiteral("a name cannot contain a space");
		}
		/* A quote or a backslash would end the string early in the file this
		 * writes, and a slash would make the drop-in's filename a path.
		 * Refused rather than escaped: each is far likelier to be a mistake
		 * than a name. */
		if (character == QLatin1Char('"') || character == QLatin1Char('\\') ||
		    character == QLatin1Char('/')) {
			return QStringLiteral("a name cannot contain %1").arg(character);
		}
	}
	return QString();
}

ncfg_linkset_dialog::ncfg_linkset_dialog(ncfg_connection *connection, const QString &existing,
    QWidget *parent)
    : QDialog(parent), connection(connection), existing(existing)
{
	setWindowTitle(existing.isEmpty() ? QStringLiteral("new group of links")
	                 : QStringLiteral("group: %1").arg(existing));
	setObjectName(QStringLiteral("linkset_dialog"));

	auto *layout = new QVBoxLayout(this);
	auto *form = new QFormLayout();

	name = new QLineEdit(existing, this);
	name->setObjectName(QStringLiteral("linkset_name"));
	/* Fixed once there is something to edit: the name is the block's and the
	 * drop-in's filename, so changing it would write a second group and leave
	 * the first. `uplink` is the one name that means something on its own --
	 * it carries the default route and is what "connected" refers to -- and
	 * the placeholder says so rather than leaving it folklore. */
	name->setReadOnly(!existing.isEmpty());
	name->setPlaceholderText(QStringLiteral("uplink, for the one that carries the "
	            "default route"));
	form->addRow(QStringLiteral("name"), name);
	layout->addLayout(form);

	members = new QListWidget(this);
	members->setObjectName(QStringLiteral("linkset_members"));
	members->setSelectionMode(QAbstractItemView::SingleSelection);
	layout->addWidget(new QLabel(QStringLiteral("members, best first:"), this));
	layout->addWidget(members);

	auto *order = new QHBoxLayout();
	candidates = new QComboBox(this);
	candidates->setObjectName(QStringLiteral("linkset_candidates"));
	add_button = new QPushButton(QStringLiteral("add"), this);
	add_button->setObjectName(QStringLiteral("linkset_add"));
	drop_button = new QPushButton(QStringLiteral("remove"), this);
	drop_button->setObjectName(QStringLiteral("linkset_drop"));
	up_button = new QPushButton(QStringLiteral("up"), this);
	up_button->setObjectName(QStringLiteral("linkset_up"));
	down_button = new QPushButton(QStringLiteral("down"), this);
	down_button->setObjectName(QStringLiteral("linkset_down"));
	order->addWidget(candidates, 1);
	order->addWidget(add_button);
	order->addWidget(drop_button);
	order->addWidget(up_button);
	order->addWidget(down_button);
	layout->addLayout(order);

	note = new QLabel(this);
	note->setObjectName(QStringLiteral("linkset_note"));
	note->setWordWrap(true);
	layout->addWidget(note);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
	save_button = buttons->addButton(QStringLiteral("save"), QDialogButtonBox::AcceptRole);
	save_button->setObjectName(QStringLiteral("linkset_save"));
	/* Only for a group that exists. "Delete" on a group being invented is a
	 * button with nothing to act on, and the config call would refuse with a
	 * message about a file nobody wrote. */
	remove_button = nullptr;
	if (!existing.isEmpty()) {
		remove_button = buttons->addButton(QStringLiteral("delete group"),
		    QDialogButtonBox::DestructiveRole);
		remove_button->setObjectName(QStringLiteral("linkset_remove"));
		connect(remove_button, &QPushButton::clicked, this, &ncfg_linkset_dialog::remove);
	}
	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(save_button, &QPushButton::clicked, this, &ncfg_linkset_dialog::submit);
	connect(add_button, &QPushButton::clicked, this, &ncfg_linkset_dialog::add_member);
	connect(drop_button, &QPushButton::clicked, this, &ncfg_linkset_dialog::drop_member);
	connect(up_button, &QPushButton::clicked, this, &ncfg_linkset_dialog::move_up);
	connect(down_button, &QPushButton::clicked, this, &ncfg_linkset_dialog::move_down);
	connect(name, &QLineEdit::textChanged, this, &ncfg_linkset_dialog::revalidate);
	connect(members, &QListWidget::itemSelectionChanged, this,
	    &ncfg_linkset_dialog::revalidate);
	layout->addWidget(buttons);
	resize(560, 420);

	load();
	offer_candidates();
	revalidate();
}

void ncfg_linkset_dialog::load()
{
	if (existing.isEmpty()) {
		return;
	}

	QList<ncfg_linkset_row> found;
	QString error;
	if (!connection->linksets(&found, &error)) {
		note->setText(error);
		return;
	}
	for (const ncfg_linkset_row &set : found) {
		if (set.name != existing) {
			continue;
		}
		for (const ncfg_linkset_member_row &member : set.members) {
			/* **The standing beside the name**, which is the half a list of
			 * names cannot give: which member is carrying traffic, and what
			 * stops each of the others. netcfgd's words, not this window's --
			 * working out a failover here would be a second opinion about one
			 * (0248). */
			QString standing;
			if (set.active == member.name) {
				standing = QStringLiteral("in use");
				if (!member.interface.isEmpty() && member.interface != member.name) {
					standing += QStringLiteral(" on %1").arg(member.interface);
				}
			} else if (!member.ineligible.isEmpty()) {
				standing = member.ineligible;
			} else {
				standing = QStringLiteral("ready");
			}
			if (member.metric >= 0) {
				standing += QStringLiteral(", metric %1").arg(member.metric);
			}
			auto *item = new QListWidgetItem(
			    QStringLiteral("%1  [%2]").arg(member.name, standing), members);
			/* The name alone, because that is what gets written back. The
			 * label carries the standing and the standing is not
			 * configuration. */
			item->setData(Qt::UserRole, member.name);
		}
		return;
	}
	note->setText(QStringLiteral("netcfgd reports no group called `%1`. It may have been "
	              "removed since this list was drawn.")
	          .arg(existing));
}

void ncfg_linkset_dialog::offer_candidates()
{
	candidates->clear();

	QList<ncfg_inventory_row> known;
	QString error;
	if (!connection->inventory(&known, &error)) {
		note->setText(error);
		return;
	}

	QStringList taken;
	for (int row = 0; row < members->count(); row++) {
		taken << members->item(row)->data(Qt::UserRole).toString();
	}
	for (const ncfg_inventory_row &link : known) {
		/* Not itself, and not something already in the list: a member named
		 * twice is two different rankings for one link, which the compiler
		 * refuses. */
		if (link.name == name->text() || taken.contains(link.name)) {
			continue;
		}
		/* Every kind of link, including other groups -- a set is a link in its
		 * own right, which is what lets "the office pair, or failing that the
		 * modem" be written at all. The loopback is the one exception: it is
		 * never a way to reach anything. */
		if (link.name == QLatin1String("lo")) {
			continue;
		}
		candidates->addItem(QStringLiteral("%1 (%2)").arg(link.name, link.category),
		    link.name);
	}
}

void ncfg_linkset_dialog::add_member()
{
	if (candidates->currentIndex() < 0) {
		return;
	}
	const QString chosen = candidates->currentData().toString();
	auto *item = new QListWidgetItem(QStringLiteral("%1  [not saved yet]").arg(chosen),
	    members);
	item->setData(Qt::UserRole, chosen);
	offer_candidates();
	revalidate();
}

void ncfg_linkset_dialog::drop_member()
{
	delete members->takeItem(members->currentRow());
	offer_candidates();
	revalidate();
}

void ncfg_linkset_dialog::move_up()
{
	const int row = members->currentRow();
	if (row <= 0) {
		return;
	}
	members->insertItem(row - 1, members->takeItem(row));
	members->setCurrentRow(row - 1);
	revalidate();
}

void ncfg_linkset_dialog::move_down()
{
	const int row = members->currentRow();
	if (row < 0 || row + 1 >= members->count()) {
		return;
	}
	members->insertItem(row + 1, members->takeItem(row));
	members->setCurrentRow(row + 1);
	revalidate();
}

void ncfg_linkset_dialog::revalidate()
{
	const int row = members->currentRow();
	drop_button->setEnabled(row >= 0);
	up_button->setEnabled(row > 0);
	down_button->setEnabled(row >= 0 && row + 1 < members->count());
	add_button->setEnabled(candidates->count() > 0);

	const QString refusal = ncfg_linkset_name_refusal(name->text());
	/* **A group with no members is refused here as well as by the compiler.**
	 * It can choose nothing, and as `uplink` it would answer "disconnected"
	 * for ever with nothing saying why -- so the button says so before the
	 * daemon has to. */
	save_button->setEnabled(refusal.isEmpty() && members->count() > 0);
	if (!refusal.isEmpty()) {
		note->setText(refusal);
	} else if (members->count() == 0) {
		note->setText(QStringLiteral("a group chooses between links, so it needs some"));
	} else {
		note->setText(QStringLiteral("the first member that works carries traffic; the "
		              "rest go without their routes until it does not"));
	}
}

QString ncfg_linkset_dialog::block_text() const
{
	QStringList names;
	for (int row = 0; row < members->count(); row++) {
		names << members->item(row)->data(Qt::UserRole).toString();
	}
	return ncfg_linkset_block(name->text(), names);
}

void ncfg_linkset_dialog::submit()
{
	const QString refusal = ncfg_linkset_name_refusal(name->text());
	if (!refusal.isEmpty()) {
		note->setText(refusal);
		return;
	}
	if (members->count() == 0) {
		note->setText(QStringLiteral("a group chooses between links, so it needs some"));
		return;
	}

	QString error;
	/* `replace` because this dialog writes the whole block: the member list is
	 * all a linkset has, so there is nothing a save could silently shorten --
	 * which is what makes replacing safe here and not in the interface
	 * editor, where the form has no field for half the keys. */
	if (!connection->config_put(QStringLiteral("linkset-%1").arg(name->text()), block_text(),
	    true, &error)) {
		note->setText(error);
		return;
	}
	summary = QStringLiteral("wrote linkset-%1: netcfgd re-read its configuration. "
	              "Run apply to make the machine match it.")
	          .arg(name->text());
	accept();
}

void ncfg_linkset_dialog::remove()
{
	const QString question =
	    QStringLiteral("Delete the group `%1`?\n\nThe links in it stay configured. What "
	               "goes is the grouping -- so each of them keeps its own routes "
	               "again, and nothing chooses between them.")
	        .arg(existing);
	QMessageBox box(QMessageBox::Question, QStringLiteral("netcfgd"), question,
	    QMessageBox::Cancel | QMessageBox::Yes, this);
	box.setDefaultButton(QMessageBox::Cancel);
	if (box.exec() != QMessageBox::Yes) {
		return;
	}

	QString error;
	if (!connection->config_delete(QStringLiteral("linkset-%1").arg(existing), &error)) {
		note->setText(error);
		return;
	}
	summary = QStringLiteral("removed linkset-%1: netcfgd re-read its configuration. "
	              "Run apply to make the machine match it.")
	          .arg(existing);
	accept();
}
