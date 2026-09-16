/*
 * device_block.cpp -- the configuration text the hardware editor writes.
 *
 * WHY THIS EXISTS
 *   A form with thirty fields writes a block with as many keys, and the two
 *   ways that goes wrong are both silent. A default written out as though the
 *   operator had chosen it turns "netcfgd does not manage this" into a
 *   decision nobody made; a sub-block emitted empty is not nothing --
 *   `ethtool { }` compiles to a settings object, and netcfgd then has an
 *   opinion about a NIC nobody asked it to touch.
 *
 * WHAT IT DOES NOT DO
 *   It does not compile the text. That needs netcfgd, and `gui_wifi.sh` is
 *   where this editor meets a daemon.
 */
#include "../src/device_dialog.h"

#include <QCoreApplication>
#include <QString>
#include <cstdio>

static int failures;

static void check(bool condition, const char *what)
{
	fprintf(stderr, "device_block: %-58s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

int main(int argc, char **argv)
{
	QCoreApplication app(argc, argv);

	/* A device with nothing said about it. The block exists -- somebody
	 * pressed save -- and says nothing, which is the honest rendering of a
	 * form nobody filled in. */
	{
		ncfg_device_config bare;
		const QString block = ncfg_device_block(QStringLiteral("eth0"), bare);
		check(block.contains(QStringLiteral("device eth0 {")), "the block names the device");
		check(!block.contains(QStringLiteral("managed")),
		    "and does not restate `managed`, which is true unless said otherwise");
		check(!block.contains(QStringLiteral("ethtool")),
		    "and writes no ethtool block when nothing in it was set");
		check(!block.contains(QStringLiteral("wifi")),
		    "and no wifi block on a device that has no radio");
	}

	/* The hardware keys, which is what this editor exists for. */
	{
		ncfg_device_config settings;
		settings.mtu = 9000;
		settings.mac = QStringLiteral("02:00:00:00:00:01");
		settings.autoneg = 1;
		settings.speed = 1000;
		settings.duplex = QStringLiteral("full");
		settings.wol = QStringLiteral("g");
		settings.gro = 2;
		settings.rx_ring = 4096;
		const QString block = ncfg_device_block(QStringLiteral("eth0"), settings);

		check(block.contains(QStringLiteral("\tmtu = 9000")), "the mtu is written");
		check(block.contains(QStringLiteral("mac = \"02:00:00:00:00:01\"")),
		    "and the mac address");
		check(block.contains(QStringLiteral("ethtool {")), "and an ethtool block");
		check(block.contains(QStringLiteral("autoneg = \"on\"")), "with the toggles on it");
		check(block.contains(QStringLiteral("gro = \"off\"")),
		    "including one turned off, which is not the same as left alone");
		check(block.contains(QStringLiteral("speed = 1000")) &&
		        block.contains(QStringLiteral("duplex = \"full\"")) &&
		        block.contains(QStringLiteral("wol = \"g\"")) &&
		        block.contains(QStringLiteral("rx_ring = 4096")),
		    "and the settings that are not toggles");
		/* A toggle left alone writes nothing: "leave this one alone" is a
		 * different instruction from "turn it off", and writing `unmanaged`
		 * everywhere would bury the two the operator did choose. */
		check(!block.contains(QStringLiteral("gso")),
		    "a toggle left alone is not written at all");
	}

	/* Handing a device to something else, which is the one thing here that
	 * changes what netcfgd does rather than how the hardware behaves. */
	{
		ncfg_device_config settings;
		settings.managed = false;
		settings.on_unmanage = QStringLiteral("clear");
		const QString block = ncfg_device_block(QStringLiteral("eth1"), settings);
		check(block.contains(QStringLiteral("managed = false")),
		    "an unmanaged device says so");
		check(block.contains(QStringLiteral("on_unmanage = \"clear\"")),
		    "and says what to do on the way out");

		/* And `leave` is the default, so it is not written -- the block says
		 * what is unusual and nothing else. */
		settings.on_unmanage = QStringLiteral("leave");
		check(!ncfg_device_block(QStringLiteral("eth1"), settings)
		           .contains(QStringLiteral("on_unmanage")),
		    "but not when it is the default");
	}

	/* The radio half, written only for a device that has one. */
	{
		ncfg_device_config settings;
		settings.has_wifi = true;
		settings.wifi_backend = QStringLiteral("wpa_supplicant");
		settings.wifi_autoconnect = false;
		settings.powersave = QStringLiteral("off");
		settings.mac_policy = QStringLiteral("per_network");
		settings.scan_randomization = true;
		settings.regdom = QStringLiteral("SE");
		const QString block = ncfg_device_block(QStringLiteral("wlan0"), settings);

		check(block.contains(QStringLiteral("wifi {")), "a radio gets a wifi block");
		check(block.contains(QStringLiteral("backend = \"wpa_supplicant\"")),
		    "naming what drives it");
		check(block.contains(QStringLiteral("autoconnect = false")),
		    "and autoconnect, which is written both ways because both are choices");
		check(block.contains(QStringLiteral("powersave = \"off\"")) &&
		        block.contains(QStringLiteral("mac_policy = \"per_network\"")) &&
		        block.contains(QStringLiteral("scan_randomization = true")) &&
		        block.contains(QStringLiteral("regdom = \"SE\"")),
		    "and the rest of the radio policy");
	}

	if (failures == 0) {
		fprintf(stderr, "device_block: all checks passed\n");
	} else {
		fprintf(stderr, "device_block: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
