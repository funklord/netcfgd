/*
 * linkset_block.cpp -- the configuration text the group editor writes.
 *
 * WHY THIS EXISTS
 *   A dialog that writes configuration is a compiler front end with a form on
 *   it, and the two ways this one can be wrong are both invisible in a
 *   screenshot: a member list written in some other order, and a name that
 *   ends the string it is written into.
 *
 *   The order is not decoration. A linkset's member list is its ranking where
 *   two metrics cannot tell members apart (0248), so a save that reordered it
 *   would silently change which link a machine falls back to -- and nothing
 *   downstream could tell, because both orders compile.
 *
 * WHAT IT DOES NOT DO
 *   It does not compile the text. That needs netcfgd, and `gui_wifi.sh` is
 *   where this window meets a daemon. What is here is the shape: the words,
 *   the order and the refusals.
 */
#include "../src/linkset_dialog.h"

#include <QCoreApplication>
#include <QString>
#include <QStringList>
#include <cstdio>

static int failures;

static void check(bool condition, const char *what)
{
	fprintf(stderr, "linkset_block: %-58s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

int main(int argc, char **argv)
{
	QCoreApplication app(argc, argv);

	QStringList members;
	members << QStringLiteral("wwan0") << QStringLiteral("eth0")
	        << QStringLiteral("office");
	const QString block = ncfg_linkset_block(QStringLiteral("uplink"), members);

	check(block.contains(QStringLiteral("linkset \"uplink\" {")),
	    "the block names the group");

	/* **The order, which is the whole point.** Written alphabetically the
	 * three would be eth0, office, wwan0 -- so a list that sorted itself
	 * would put the modem first and the machine would fall back the other
	 * way round. */
	check(block.contains(
	          QStringLiteral("members = [\"wwan0\", \"eth0\", \"office\"]")),
	    "and the members in the order given, not sorted");

	/* One member is still a list. Both spellings compile; a block that
	 * changes shape when it happens to have one member is one an operator
	 * reads twice. */
	const QString alone =
	    ncfg_linkset_block(QStringLiteral("spare"), QStringList() << QStringLiteral("eth0"));
	check(alone.contains(QStringLiteral("members = [\"eth0\"]")),
	    "a single member is written as a list all the same");

	/* THE NAME RULE. A group is referred to by name from other groups and is
	 * written to a file called after it, so the answer is narrower than "any
	 * string" -- and each refusal says what is wrong rather than greying a
	 * button with no reason. */
	check(ncfg_linkset_name_refusal(QStringLiteral("uplink")).isEmpty(),
	    "an ordinary name is accepted");
	check(!ncfg_linkset_name_refusal(QString()).isEmpty(), "an empty name is refused");
	check(!ncfg_linkset_name_refusal(QStringLiteral("two words")).isEmpty(),
	    "a name with a space is refused");
	check(!ncfg_linkset_name_refusal(QStringLiteral("up\"link")).isEmpty(),
	    "a name carrying a quote is refused, not escaped");
	check(!ncfg_linkset_name_refusal(QStringLiteral("up\\link")).isEmpty(),
	    "and one carrying a backslash");
	check(!ncfg_linkset_name_refusal(QStringLiteral("../etc/passwd")).isEmpty(),
	    "and one that would make the drop-in's name a path");

	/* WHAT A GROUP'S ROW SAYS, and what the `why` button says about it.
	 *
	 * Both are judgements over the daemon's answer rather than fields, and
	 * both of their wrong answers are invisible in a screenshot: a blank cell
	 * reads as a fetch that failed, and an explanation that named the winner
	 * instead of the losers would answer a question nobody asked. */
	ncfg_linkset_row set;
	set.name = QStringLiteral("uplink");
	set.active = QStringLiteral("office");
	set.interface = QStringLiteral("wlan0");
	ncfg_linkset_member_row cable;
	cable.name = QStringLiteral("eth0");
	cable.ineligible = QStringLiteral("no carrier");
	ncfg_linkset_member_row wifi;
	wifi.name = QStringLiteral("office");
	wifi.interface = QStringLiteral("wlan0");
	ncfg_linkset_member_row modem;
	modem.name = QStringLiteral("wwan0");
	modem.interface = QStringLiteral("wwan0");
	set.members << cable << wifi << modem;
	QList<ncfg_linkset_row> sets;
	sets << set;

	check(ncfg_linkset_standing(sets, QStringLiteral("uplink"))
	        == QStringLiteral("using office"),
	    "a group's row says which member it is using");
	check(ncfg_linkset_standing(sets, QStringLiteral("nothing")).isEmpty(),
	    "and claims nothing about a group the daemon did not report");

	const QString why = ncfg_linkset_why(sets, QStringLiteral("uplink"));
	check(why.contains(QStringLiteral("using office")), "the explanation names the winner");
	check(why.contains(QStringLiteral("eth0 no carrier")),
	    "and says what is wrong with the member that should have won");
	check(!why.contains(QStringLiteral("wwan0")),
	    "and says nothing about a member that is merely ready and worse-ranked");

	/* A group with nothing usable is the state that most needs saying, and the
	 * one an empty cell hides. */
	sets[0].active.clear();
	check(ncfg_linkset_standing(sets, QStringLiteral("uplink"))
	        == QStringLiteral("nothing usable"),
	    "a group with nothing usable says so rather than going blank");
	check(ncfg_linkset_why(sets, QStringLiteral("uplink"))
	          .contains(QStringLiteral("nothing it can use")),
	    "and the explanation says it too");

	if (failures == 0) {
		fprintf(stderr, "linkset_block: all checks passed\n");
	} else {
		fprintf(stderr, "linkset_block: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
