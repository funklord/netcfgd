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

	/* THE KINDS, which is what makes a link exist at all.
	 *
	 * A bridge, a bond, a VLAN, a veth pair: each is a link netcfgd creates
	 * rather than finds. The block has to name the kind's own sub-block and
	 * the fields that kind needs, and `physical` has to write nothing --
	 * a real adapter is not a creation. */
	{
		ncfg_device_config physical;
		physical.kind = QStringLiteral("physical");
		check(!ncfg_device_block(QStringLiteral("eth0"), physical)
		           .contains(QStringLiteral("kind")),
		    "a physical device asks for nothing to be created");

		ncfg_device_config bridge;
		bridge.kind = QStringLiteral("bridge");
		bridge.members = QStringLiteral("eth0 eth1");
		bridge.stp = true;
		const QString made = ncfg_device_block(QStringLiteral("br0"), bridge);
		check(made.contains(QStringLiteral("bridge {")), "a bridge gets a bridge block");
		check(made.contains(QStringLiteral("members = [\"eth0\", \"eth1\"]")),
		    "with its members as a list");
		check(made.contains(QStringLiteral("stp = true")), "and spanning tree when asked");

		ncfg_device_config bond;
		bond.kind = QStringLiteral("bond");
		bond.members = QStringLiteral("eth2");
		bond.bond_mode = QStringLiteral("802.3ad");
		bond.miimon = 100;
		const QString bonded = ncfg_device_block(QStringLiteral("bond0"), bond);
		check(bonded.contains(QStringLiteral("mode = \"802.3ad\"")),
		    "a bond names its mode, hyphens and dots as the kernel spells them");
		check(bonded.contains(QStringLiteral("miimon = 100")), "and its link check");

		ncfg_device_config vlan;
		vlan.kind = QStringLiteral("vlan");
		vlan.parent = QStringLiteral("eth0");
		vlan.vlan_id = 42;
		const QString tagged = ncfg_device_block(QStringLiteral("eth0.42"), vlan);
		check(tagged.contains(QStringLiteral("parent = \"eth0\"")) &&
		        tagged.contains(QStringLiteral("id = 42")),
		    "a vlan names its parent and its id");
		/* 802.1Q is the default, so it is not written: the block says what is
		 * unusual. */
		check(!tagged.contains(QStringLiteral("protocol")),
		    "and not the protocol when it is the ordinary one");

		ncfg_device_config veth;
		veth.kind = QStringLiteral("veth");
		veth.peer = QStringLiteral("vv-peer");
		check(ncfg_device_block(QStringLiteral("vv"), veth)
		          .contains(QStringLiteral("veth { peer = \"vv-peer\" }")),
		    "a veth names the other end");

		ncfg_device_config vrf;
		vrf.kind = QStringLiteral("vrf");
		vrf.vrf_table = 100;
		check(ncfg_device_block(QStringLiteral("vrf0"), vrf)
		          .contains(QStringLiteral("vrf { table = 100 }")),
		    "a vrf names the table it owns");

		ncfg_device_config tunnel;
		tunnel.kind = QStringLiteral("tunnel");
		tunnel.tunnel_mode = QStringLiteral("gre");
		tunnel.local = QStringLiteral("192.0.2.1");
		tunnel.remote = QStringLiteral("198.51.100.1");
		const QString piped = ncfg_device_block(QStringLiteral("gre0"), tunnel);
		check(piped.contains(QStringLiteral("mode = \"gre\"")) &&
		        piped.contains(QStringLiteral("local = \"192.0.2.1\"")) &&
		        piped.contains(QStringLiteral("remote = \"198.51.100.1\"")),
		    "a tunnel names its encapsulation and both ends");

		ncfg_device_config dummy;
		dummy.kind = QStringLiteral("dummy");
		check(ncfg_device_block(QStringLiteral("d0"), dummy)
		          .contains(QStringLiteral("kind = \"dummy\"")),
		    "and a dummy says so with the key rather than a block");

		/* **The hardware keys are written beside the kind, not instead of
		 * it.** A bridge with an MTU is ordinary, and a block that dropped one
		 * for the other would be half a device. */
		bridge.mtu = 9000;
		const QString both = ncfg_device_block(QStringLiteral("br0"), bridge);
		check(both.contains(QStringLiteral("bridge {")) &&
		        both.contains(QStringLiteral("mtu = 9000")),
		    "a created link can carry hardware settings too");
	}

	/* WIREGUARD, which is the kind that carries a credential and a list.
	 *
	 * **The private key is a reference and never the material.** netcfgd's
	 * document type cannot hold key material at all -- that is what makes a
	 * document safe to write to /run -- so what the block carries is the name
	 * of something the secret store keeps. A block with a key in it would be
	 * the one thing this whole design forbids. */
	{
		ncfg_device_config wg;
		wg.kind = QStringLiteral("wireguard");
		wg.private_key = QStringLiteral("@secret:wg0");
		wg.listen_port = 51820;
		ncfg_wg_peer_row office;
		office.name = QStringLiteral("office");
		office.public_key = QStringLiteral("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=");
		office.endpoint = QStringLiteral("vpn.example.com:51820");
		office.allowed_ips = QStringLiteral("10.9.0.0/24 192.168.50.0/24");
		office.keepalive = 25;
		office.preshared_key = QStringLiteral("@secret:wg0-psk");
		ncfg_wg_peer_row home;
		home.name = QStringLiteral("home");
		home.public_key = QStringLiteral("aTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=");
		home.allowed_ips = QStringLiteral("10.9.1.0/24");
		wg.peers << office << home;
		const QString block = ncfg_device_block(QStringLiteral("wg0"), wg);

		check(block.contains(QStringLiteral("wireguard {")), "a wireguard device gets a block");
		check(block.contains(QStringLiteral("private_key = \"@secret:wg0\"")),
		    "whose private key is a reference, not a key");
		check(block.contains(QStringLiteral("listen_port = 51820")), "and its listen port");
		check(block.contains(QStringLiteral("peer \"office\" {")) &&
		        block.contains(QStringLiteral("peer \"home\" {")),
		    "with a block per peer");
		check(block.contains(QStringLiteral("public_key = \"xTIBA5rboUvnH4htodjb6e697Qj"
		                                "LERt1NAB4mZqp8Dg=\"")),
		    "each carrying its public key, which is an identity and not a secret");
		check(block.contains(QStringLiteral("allowed_ips = [\"10.9.0.0/24\", "
		                                "\"192.168.50.0/24\"]")),
		    "and its allowed prefixes as a list");
		check(block.contains(QStringLiteral("endpoint = \"vpn.example.com:51820\"")) &&
		        block.contains(QStringLiteral("keepalive = 25")),
		    "and an endpoint and keepalive where it has them");
		check(block.contains(QStringLiteral("preshared_key = \"@secret:wg0-psk\"")),
		    "and a preshared key as a reference too");
		/* The peer without them writes neither: a block restating every
		 * default is one nobody can read for what is unusual. */
		check(block.count(QStringLiteral("endpoint")) == 1,
		    "while the peer with no endpoint writes none");
	}

	/* A tunnel's two pinned values, which had no field until now. */
	{
		ncfg_device_config tunnel;
		tunnel.kind = QStringLiteral("tunnel");
		tunnel.tunnel_mode = QStringLiteral("sit");
		tunnel.ttl = 64;
		tunnel.tunnel_key = 7;
		const QString block = ncfg_device_block(QStringLiteral("sit0"), tunnel);
		check(block.contains(QStringLiteral("ttl = 64")), "a tunnel can pin its ttl");
		check(block.contains(QStringLiteral("key = 7")), "and its key");

		/* Zero is a legal tunnel key and `none` is not zero, which is why the
		 * absent value is -1 and not 0. */
		tunnel.tunnel_key = 0;
		check(ncfg_device_block(QStringLiteral("sit0"), tunnel)
		          .contains(QStringLiteral("key = 0")),
		    "and a key of zero, which is a key and not an absence");
		tunnel.tunnel_key = -1;
		check(!ncfg_device_block(QStringLiteral("sit0"), tunnel)
		           .contains(QStringLiteral("key =")),
		    "while no key at all writes nothing");
	}

	/* THE NAME, which is the link's name and the drop-in's filename. */
	{
		check(ncfg_device_name_refusal(QStringLiteral("br0")).isEmpty(),
		    "an ordinary name is accepted");
		check(ncfg_device_name_refusal(QStringLiteral("eth0.42")).isEmpty(),
		    "and so is a vlan's dotted one");
		check(!ncfg_device_name_refusal(QString()).isEmpty(), "an empty name is refused");
		check(!ncfg_device_name_refusal(QStringLiteral("a-very-long-name0")).isEmpty(),
		    "a name past the kernel's fifteen characters is refused");
		check(!ncfg_device_name_refusal(QStringLiteral("two words")).isEmpty(),
		    "a name with a space is refused");
		check(!ncfg_device_name_refusal(QStringLiteral("../etc/x")).isEmpty(),
		    "and one that would make the drop-in's name a path");
	}

	if (failures == 0) {
		fprintf(stderr, "device_block: all checks passed\n");
	} else {
		fprintf(stderr, "device_block: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
