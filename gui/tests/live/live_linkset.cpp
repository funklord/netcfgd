/*
 * live_linkset.cpp -- making and changing a group of links, against a daemon.
 *
 * WHY THIS EXISTS
 *   `linkset_block` checks the text this dialog writes. What it cannot check
 *   is whether netcfgd made anything of it: a block can be well formed, name a
 *   member that resolves to nothing, and be refused -- and the dialog would
 *   have reported success in a screenshot nobody was reading.
 *
 *   So this asserts the *compiled* document afterwards, read back through the
 *   daemon's own answer about the group. That goes through the compiler and
 *   the five linkset checks, so a group netcfgd wrote and could not parse
 *   fails here rather than passing.
 *
 * WHAT IT ALSO PINS
 *   The order. A member list is a ranking where two metrics cannot tell
 *   members apart (0248), so a save that reordered it would change which link
 *   a machine falls back to -- and both orders compile, which is exactly the
 *   kind of difference nothing downstream can catch.
 *
 * WHAT IT DOES NOT COVER
 *   Deleting. The button asks first, through a modal `QMessageBox`, and a
 *   probe cannot answer one -- so the confirmation is the part that would be
 *   tested and it is the part that blocks. The removal itself is
 *   `config_delete`, which `config_view` already exercises.
 */

#include "../../src/linkset_dialog.h"
#include "../../src/ncfg_connection.h"

#include <QApplication>
#include <QComboBox>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>

#include <cstdio>

static int failures;

static void check(const char *what, bool condition, const QString &detail = QString())
{
	if (condition) {
		printf("ok   %s\n", what);
	} else {
		printf("FAIL %s\n", what);
		if (!detail.isEmpty()) {
			printf("       %s\n", detail.toUtf8().constData());
		}
		failures++;
	}
	fflush(stdout);
}

/* The daemon's own answer about one group, or false where it has none. */
static bool group_named(ncfg_connection *connection, const QString &name, ncfg_linkset_row *out)
{
	QList<ncfg_linkset_row> rows;
	QString error;
	if (!connection->linksets(&rows, &error)) {
		return false;
	}
	for (const ncfg_linkset_row &row : rows) {
		if (row.name == name) {
			*out = row;
			return true;
		}
	}
	return false;
}

static QStringList member_names(const ncfg_linkset_row &set)
{
	QStringList names;
	for (const ncfg_linkset_member_row &member : set.members) {
		names << member.name;
	}
	return names;
}

/* Put a candidate into the member list by name, or say it was not offered. */
static bool add_named(ncfg_linkset_dialog *dialog, const QString &wanted)
{
	auto *candidates = dialog->findChild<QComboBox *>(QStringLiteral("linkset_candidates"));
	auto *add = dialog->findChild<QPushButton *>(QStringLiteral("linkset_add"));
	if (!candidates || !add) {
		return false;
	}
	const int at = candidates->findData(wanted);
	if (at < 0) {
		return false;
	}
	candidates->setCurrentIndex(at);
	add->click();
	return true;
}

int main(int argc, char **argv)
{
	QApplication app(argc, argv);

	ncfg_connection connection;
	QString error;
	if (!connection.open(QString(), &error)) {
		printf("FAIL the dialog's connection reaches netcfgd\n       %s\n",
		    error.toUtf8().constData());
		return 1;
	}
	check("the dialog's connection reaches netcfgd", true);

	/* **Two links of this probe's own, and it takes them away again.**
	 *
	 * The harness gives one dummy radio, and what else is in the list depends
	 * on which probes ran before this one -- `gui_wifi.sh` runs them all
	 * against one daemon and one configuration. A probe that grouped whatever
	 * it found would be a test whose subject changes with the alphabet, and
	 * one that grouped the radio would leave that radio's routes on standby
	 * for `live_wifi`, which runs next. `live_interface_dialog` already
	 * records this hazard and answers it the same way.
	 *
	 * They need no hardware: an `interface` block for a name the kernel does
	 * not have is a link the document names and the machine does not, which
	 * the inventory reports and a group can hold. */
	const QStringList links = { QStringLiteral("gui-set-a"), QStringLiteral("gui-set-b") };
	for (const QString &link : links) {
		const QString block =
		    QStringLiteral("interface %1 {\n\tconfig = \"null\"\n}\n").arg(link);
		if (!connection.config_put(QStringLiteral("interface-%1").arg(link), block, true,
		        &error)) {
			check("the probe can write the links it groups", false, error);
			return 1;
		}
	}
	check("the probe can write the links it groups", true);

	QList<ncfg_inventory_row> known;
	if (!connection.inventory(&known, &error) || known.isEmpty()) {
		check("the daemon reports them back", false, error);
		return 1;
	}
	for (const QString &link : links) {
		bool seen = false;
		for (const ncfg_inventory_row &row : known) {
			seen = seen || row.name == link;
		}
		if (!seen) {
			check("the daemon reports them back", false, link);
			return 1;
		}
	}
	check("the daemon reports them back", true);

	/* 1. A group made from nothing, which is what a fresh machine has. */
	{
		ncfg_linkset_dialog dialog(&connection, QString());
		auto *name = dialog.findChild<QLineEdit *>(QStringLiteral("linkset_name"));
		auto *members = dialog.findChild<QListWidget *>(QStringLiteral("linkset_members"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("linkset_save"));
		if (!name || !members || !save) {
			check("the dialog has the fields it needs", false);
			return 1;
		}
		check("the dialog has the fields it needs", true);

		name->setText(QStringLiteral("uplink"));
		check("a group with no members cannot be saved", !save->isEnabled());

		check("the links this machine has are offered as members",
		    add_named(&dialog, links.at(1)) && add_named(&dialog, links.at(0)),
		    links.join(QLatin1Char(' ')));
		check("and two of them are in the list", members->count() == 2,
		    QString::number(members->count()));
		check("which makes the group saveable", save->isEnabled());
		save->click();

		ncfg_linkset_row written;
		check("netcfgd compiled the group",
		    group_named(&connection, QStringLiteral("uplink"), &written));
		/* **In the order they were added, not sorted.** This is the assertion
		 * the file exists for: both orders compile and only one is what the
		 * operator said. */
		check("with its members in the order they were put in",
		    member_names(written) == QStringList({ links.at(1), links.at(0) }),
		    member_names(written).join(QLatin1Char(' ')));
	}

	/* 2. Opening it again, and moving a member -- which is the only edit a
	 *    group has, and the one a list widget will quietly undo. */
	{
		ncfg_linkset_dialog dialog(&connection, QStringLiteral("uplink"));
		auto *name = dialog.findChild<QLineEdit *>(QStringLiteral("linkset_name"));
		auto *members = dialog.findChild<QListWidget *>(QStringLiteral("linkset_members"));
		auto *down = dialog.findChild<QPushButton *>(QStringLiteral("linkset_down"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("linkset_save"));
		if (!name || !members || !down || !save) {
			check("the editor opens on an existing group", false);
			return 1;
		}
		check("the editor opens on an existing group", members->count() == 2,
		    QString::number(members->count()));
		/* The name is the block's and the drop-in's filename: changing it
		 * would write a second group and leave the first. */
		check("whose name cannot be edited", name->isReadOnly());
		/* The standing is netcfgd's, drawn beside each member. A list of bare
		 * names would not say which one is carrying anything. */
		check("and each member is shown with its standing",
		    members->item(0)->text().contains(QLatin1Char('[')),
		    members->item(0)->text());

		members->setCurrentRow(0);
		check("the first member can be moved down", down->isEnabled());
		down->click();
		save->click();

		ncfg_linkset_row written;
		check("netcfgd took the reordered group",
		    group_named(&connection, QStringLiteral("uplink"), &written));
		check("and the order is the new one",
		    member_names(written) == QStringList({ links.at(0), links.at(1) }),
		    member_names(written).join(QLatin1Char(' ')));
	}

	/* 3. A name that cannot be written is refused before anything is sent.
	 *    The daemon would refuse it too, but a dialog that leans on that has
	 *    already composed a file name out of the text. */
	{
		ncfg_linkset_dialog dialog(&connection, QString());
		auto *name = dialog.findChild<QLineEdit *>(QStringLiteral("linkset_name"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("linkset_save"));
		name->setText(QStringLiteral("../etc/passwd"));
		add_named(&dialog, links.at(0));
		check("a name that would escape the config directory cannot be saved",
		    !save->isEnabled());
	}

	/* 4. And the group goes again.
	 *
	 * **Not tidiness: these probes share one daemon and one configuration.**
	 * A group left behind puts every other member's routes on standby, which
	 * the wifi tab's banner surfaces as a warning about the radio -- so
	 * `live_wifi` failed four checks about a NetworkManager banner that was
	 * really this file's leftovers. Measured, on the first run of this probe.
	 *
	 * `config_delete` rather than the dialog's own button: that one asks
	 * first, through a modal box a probe cannot answer. */
	{
		QString removed;
		check("the group can be removed again",
		    connection.config_delete(QStringLiteral("linkset-uplink"), &removed), removed);
		ncfg_linkset_row gone;
		check("and netcfgd stops reporting it",
		    !group_named(&connection, QStringLiteral("uplink"), &gone));
		for (const QString &link : links) {
			connection.config_delete(QStringLiteral("interface-%1").arg(link), &removed);
		}
	}

	if (failures == 0) {
		printf("live_linkset: all checks passed\n");
	} else {
		printf("live_linkset: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
