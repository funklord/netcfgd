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

	if (failures == 0) {
		fprintf(stderr, "linkset_block: all checks passed\n");
	} else {
		fprintf(stderr, "linkset_block: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
