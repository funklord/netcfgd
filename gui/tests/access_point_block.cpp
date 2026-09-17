/*
 * access_point_block.cpp -- the configuration the access point editor writes.
 *
 * WHY THIS EXISTS
 *   An access point is the one block here that carries a credential, a station
 *   list and a radio all at once, and each of the three has a way of being
 *   wrong that a screenshot cannot show: a passphrase written as itself rather
 *   than as a reference, a station list emptied on save, a default stated as
 *   though somebody had chosen it.
 */
#include "../src/access_point_dialog.h"

#include <QCoreApplication>
#include <QString>
#include <cstdio>

static int failures;

static void check(bool condition, const char *what)
{
	fprintf(stderr, "access_point_block: %-52s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

int main(int argc, char **argv)
{
	QCoreApplication app(argc, argv);

	{
		ncfg_access_point_config home;
		home.id = QStringLiteral("Home");
		home.device = QStringLiteral("wlan0");
		home.security = QStringLiteral("psk");
		home.credential = QStringLiteral("@secret:ap");
		home.band = QStringLiteral("5");
		home.channel = 36;
		home.regdom = QStringLiteral("SE");
		const QString block = ncfg_access_point_block(home);

		check(block.contains(QStringLiteral("access_point \"Home\" {")),
		    "the block is named for the network it broadcasts");
		check(block.contains(QStringLiteral("device = \"wlan0\"")), "and names the radio");
		check(block.contains(QStringLiteral("psk = \"@secret:ap\"")),
		    "with the passphrase as a reference, never as itself");
		check(block.contains(QStringLiteral("channel = 36")) &&
		        block.contains(QStringLiteral("band = \"5\"")) &&
		        block.contains(QStringLiteral("regdom = \"SE\"")),
		    "and the channel, band and country it was given");
		/* `hidden = false` is what an access point does unless somebody says
		 * otherwise, and stating it would bury the one that is hidden. */
		check(!block.contains(QStringLiteral("hidden")),
		    "and says nothing about hiding, which is the default");
		check(!block.contains(QStringLiteral("access_control")),
		    "and writes no station list when it talks to everyone");
	}

	/* An open access point names no credential at all -- not an empty one,
	 * which would be a `psk` block with nothing in it. */
	{
		ncfg_access_point_config guest;
		guest.id = QStringLiteral("Guest");
		guest.device = QStringLiteral("wlan0");
		guest.security = QStringLiteral("open");
		guest.hidden = true;
		const QString block = ncfg_access_point_block(guest);
		check(block.contains(QStringLiteral("open = true")), "an open network says so");
		check(!block.contains(QStringLiteral("psk")), "and carries no passphrase key");
		check(block.contains(QStringLiteral("hidden = true")),
		    "and a hidden one says that too, because it is not the default");
	}

	/* The station list, which is the half a save can silently empty. */
	{
		ncfg_access_point_config gated;
		gated.id = QStringLiteral("Lab");
		gated.device = QStringLiteral("wlan0");
		gated.security = QStringLiteral("owe");
		gated.acl_policy = QStringLiteral("deny");
		gated.stations = QStringLiteral("00:11:22:33:44:55 66:77:88:99:aa:bb");
		const QString block = ncfg_access_point_block(gated);
		check(block.contains(QStringLiteral("owe = true")),
		    "an OWE network says so rather than looking open");
		check(block.contains(QStringLiteral("access_control {")),
		    "a station list gets an access_control block");
		check(block.contains(QStringLiteral("deny = [\"00:11:22:33:44:55\", "
		                                "\"66:77:88:99:aa:bb\"]")),
		    "naming the policy and every station on it");
	}

	if (failures == 0) {
		fprintf(stderr, "access_point_block: all checks passed\n");
	} else {
		fprintf(stderr, "access_point_block: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
