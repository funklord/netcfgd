/*
 * bluetooth_block.cpp -- the configuration the bluetooth editor writes.
 *
 * WHY THIS EXISTS
 *   Two of the three ways this block can be wrong are invisible on screen. An
 *   address the compiler will not take is refused a round trip later, at a
 *   line number in a file the operator did not write; and a profile spelled
 *   the model's way rather than the language's compiles into nothing at all --
 *   which has already happened twice in this campaign, to `wire_guard` and
 *   `open_vpn`.
 */
#include "../src/bluetooth_dialog.h"

#include <QCoreApplication>
#include <QString>
#include <cstdio>

static int failures;

static void check(bool condition, const char *what)
{
	fprintf(stderr, "bluetooth_block: %-54s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

int main(int argc, char **argv)
{
	QCoreApplication app(argc, argv);

	{
		ncfg_bluetooth_row headphones;
		headphones.id = QStringLiteral("headphones");
		headphones.address = QStringLiteral("AA:BB:CC:DD:EE:FF");
		headphones.profile = QStringLiteral("a2dp-sink");
		headphones.autoconnect = true;
		const QString block = ncfg_bluetooth_block(headphones);

		check(block.contains(QStringLiteral("bluetooth \"headphones\" {")),
		    "the block is named by the handle, not by the address");
		check(block.contains(QStringLiteral("address = \"AA:BB:CC:DD:EE:FF\"")),
		    "and carries the address, which is the fact about the hardware");
		check(block.contains(QStringLiteral("profile = \"a2dp-sink\"")),
		    "and the profile, spelled the way the language spells it");
		/* True unless said otherwise. A block restating every default is one
		 * nobody can read for what is unusual. */
		check(!block.contains(QStringLiteral("autoconnect")),
		    "and says nothing about autoconnect, which is true by default");
	}

	{
		ncfg_bluetooth_row car;
		car.id = QStringLiteral("car");
		car.address = QStringLiteral("00:11:22:33:44:55");
		car.profile = QStringLiteral("hfp");
		car.autoconnect = false;
		check(ncfg_bluetooth_block(car).contains(QStringLiteral("autoconnect = false")),
		    "while a device not to connect on its own says so");
	}

	/* **The three forms one address arrives in.** The language takes exactly
	 * one of them, and an editor that passed the other two through would be
	 * writing configuration netcfgd refuses. */
	{
		const QString want = QStringLiteral("AA:BB:CC:DD:EE:FF");
		check(ncfg_bluetooth_address(QStringLiteral("AA:BB:CC:DD:EE:FF")) == want,
		    "colons are what the language takes");
		check(ncfg_bluetooth_address(QStringLiteral("aa:bb:cc:dd:ee:ff")) == want,
		    "lowercase is uppercased, as the compiler does");
		check(ncfg_bluetooth_address(QStringLiteral("aa-bb-cc-dd-ee-ff")) == want,
		    "dashes are taken, which is how a label usually prints one");
		check(ncfg_bluetooth_address(QStringLiteral("aabbccddeeff")) == want,
		    "and twelve bare digits, which is what a clipboard leaves");
		check(ncfg_bluetooth_address(QStringLiteral("  AA:BB:CC:DD:EE:FF  ")) == want,
		    "surrounding space is not part of an address");
	}

	/* And what is not an address at all. Each of these is a plausible typing
	 * mistake, and every one of them would be a compile error somewhere else. */
	{
		check(ncfg_bluetooth_address(QStringLiteral("AA:BB:CC:DD:EE")).isEmpty(),
		    "five octets is not an address");
		check(ncfg_bluetooth_address(QStringLiteral("AA:BB:CC:DD:EE:FF:00")).isEmpty(),
		    "nor seven");
		check(ncfg_bluetooth_address(QStringLiteral("GG:BB:CC:DD:EE:FF")).isEmpty(),
		    "nor one with a digit that is not hex");
		check(ncfg_bluetooth_address(QString()).isEmpty(), "nor nothing at all");
	}

	if (failures == 0) {
		fprintf(stderr, "bluetooth_block: all checks passed\n");
	} else {
		fprintf(stderr, "bluetooth_block: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
