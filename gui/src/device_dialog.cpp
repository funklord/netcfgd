/*
 * device_dialog.cpp -- the hardware editor described in device_dialog.h.
 *
 * Two things live here and only one is the window. The other is
 * `ncfg_device_block`, which turns a set of answers into the configuration
 * netcfgd compiles, and it is a free function because the ways it can be
 * wrong -- a default written as though it had been chosen, an `ethtool` or
 * `wifi` block emitted empty -- are invisible in a screenshot and checkable
 * without a daemon.
 */
#include "device_dialog.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QTableWidget>
#include <QVBoxLayout>

namespace {

struct choice {
	const char *shown;
	const char *key;
};

/* Three values, not two: "leave this one alone" is a different instruction
 * from "turn it off", and a checkbox could not say it. */
const choice toggles[] = {
	{ "leave alone", "unmanaged" },
	{ "on", "on" },
	{ "off", "off" },
};

/* The kinds this form can hold. `physical` is a real card and asks for
 * nothing; the rest are links netcfgd creates. What is deliberately absent --
 * `wireguard`, `pppoe`, `openvpn`, `tun` -- carries keys, credentials or a
 * foreign config file, and a form of these fields would delete them. */
const choice kinds[] = {
	{ "physical -- a real adapter", "physical" },
	{ "bridge", "bridge" },
	{ "bond", "bond" },
	{ "vlan", "vlan" },
	{ "veth pair", "veth" },
	{ "macvlan", "macvlan" },
	{ "vrf", "vrf" },
	{ "vxlan", "vxlan" },
	{ "tunnel", "tunnel" },
	{ "wireguard", "wireguard" },
	{ "pppoe", "pppoe" },
	{ "openvpn", "openvpn" },
	/* Two entries for one `InterfaceKind`, because the mode is what an
	 * operator is choosing: `tun` carries IP packets and `tap` carries
	 * ethernet frames, and which you want is the question -- not a setting
	 * inside a kind called "tun/tap". The config language spells it the same
	 * way, with the block's name saying which. */
	{ "tun -- carries IP packets", "tun" },
	{ "tap -- carries ethernet frames", "tap" },
	{ "dummy", "dummy" },
};

/* The kernel's bonding modes, spelled as the config language spells them --
 * which is how `ip` spells them, hyphens and all. */
const choice bond_modes[] = {
	{ "active-backup -- one link, the rest standing by", "active-backup" },
	{ "balance-rr -- round robin", "balance-rr" },
	{ "balance-xor", "balance-xor" },
	{ "broadcast", "broadcast" },
	{ "802.3ad -- LACP", "802.3ad" },
	{ "balance-tlb", "balance-tlb" },
	{ "balance-alb", "balance-alb" },
};

const choice macvlan_modes[] = {
	{ "private", "private" },
	{ "vepa", "vepa" },
	{ "bridge", "bridge" },
	{ "passthru", "passthru" },
};

const choice tunnel_modes[] = {
	{ "gre", "gre" },
	{ "gretap", "gretap" },
	{ "ip6gre", "ip6gre" },
	{ "ipip", "ipip" },
	{ "sit", "sit" },
	{ "ip6tnl", "ip6tnl" },
	{ "geneve", "geneve" },
};

const choice vlan_protocols[] = {
	{ "802.1Q", "dot1q" },
	{ "802.1ad -- QinQ", "dot1ad" },
};

/* The schedulers netcfgd will put on a link. A closed set, not a free string:
 * 0023 keeps netcfgd to the root qdisc and to schedulers that need no classes
 * or filters under them, and an open string would make that line invisible. */
const choice qdiscs[] = {
	{ "leave alone", "" },
	{ "cake -- the answer for nearly every link", "cake" },
	{ "fq_codel", "fq_codel" },
	{ "fq", "fq" },
	{ "pfifo_fast", "pfifo_fast" },
	{ "noqueue", "noqueue" },
};

const choice unmanages[] = {
	{ "leave -- change nothing on the way out", "leave" },
	{ "clear -- remove what netcfgd owns first", "clear" },
};

const choice duplexes[] = {
	{ "leave alone", "" },
	{ "full", "full" },
	{ "half", "half" },
};

/* Wake-on-LAN, as ethtool spells it. `g` -- wake on a magic packet -- is the
 * one anybody means; the rest are here because a NIC that was set to one of
 * them should not have it silently rewritten. */
const choice wols[] = {
	{ "leave alone", "" },
	{ "g -- magic packet", "g" },
	{ "d -- disabled", "d" },
	{ "p -- physical activity", "p" },
	{ "u -- unicast", "u" },
	{ "b -- broadcast", "b" },
	{ "m -- multicast", "m" },
	{ "a -- ARP", "a" },
};

const choice backends[] = {
	{ "auto", "auto" },
	{ "wpa_supplicant", "wpa_supplicant" },
	{ "iwd", "iwd" },
};

const choice powersaves[] = {
	{ "the driver's default", "default" },
	{ "on", "on" },
	{ "off", "off" },
};

/* What address the radio uses once it has joined something. The wording is the
 * example file's, because an operator who has read one should recognise the
 * other. */
const choice mac_policies[] = {
	{ "permanent -- the hardware address", "permanent" },
	{ "per network -- a fresh address per network", "per_network" },
	{ "per connection -- a fresh address every time", "per_connection" },
};

void fill(QComboBox *box, const choice *from, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		box->addItem(QString::fromLatin1(from[i].shown), QString::fromLatin1(from[i].key));
	}
}

void select(QComboBox *box, const QString &key)
{
	const int at = box->findData(key);
	if (at >= 0) {
		box->setCurrentIndex(at);
	}
}

/* A value going into a quoted string in the config language. Refused rather
 * than escaped, as every other editor here refuses it: a quote or a backslash
 * in a country code or a MAC is a mistake, not a name. */
bool safe_value(const QString &text)
{
	return !text.contains(QLatin1Char('"')) && !text.contains(QLatin1Char('\\')) &&
	       !text.contains(QLatin1Char('\n'));
}

const char *toggle_word(int value)
{
	switch (value) {
	case 1:
		return "on";
	case 2:
		return "off";
	default:
		return "unmanaged";
	}
}

int toggle_value(const QComboBox *box)
{
	const QString key = box->currentData().toString();
	if (key == QLatin1String("on")) {
		return 1;
	}
	if (key == QLatin1String("off")) {
		return 2;
	}
	return 0;
}

} // namespace

QString ncfg_device_name_refusal(const QString &name)
{
	const QString trimmed = name.trimmed();

	if (trimmed.isEmpty()) {
		return QStringLiteral("a device needs a name; it is the link's name too");
	}
	/* The kernel's limit, which netcfgd's model states as IFNAMSIZ_MAX: 16 in
	 * `linux/if.h` including the terminator, so fifteen characters. A longer
	 * name is refused by netlink at apply time, by which point the name has
	 * been joined into half a dozen paths. */
	if (trimmed.size() > 15) {
		return QStringLiteral("a device name is at most 15 characters, which is what "
		              "the kernel takes");
	}
	if (trimmed == QLatin1String(".") || trimmed == QLatin1String("..")) {
		return QStringLiteral("`%1` is a directory, not a name").arg(trimmed);
	}
	for (const QChar &character : trimmed) {
		if (character.isSpace() || character == QLatin1Char('/')) {
			return QStringLiteral("a device name cannot contain a space or a slash: "
			              "netcfgd uses it for the files it keeps about the link");
		}
		if (character == QLatin1Char('"') || character == QLatin1Char('\\')) {
			return QStringLiteral("a device name cannot contain %1").arg(character);
		}
	}
	return QString();
}

namespace {

/* The `kind` sub-block, where the kind needs one.
 *
 * **`physical` writes nothing at all**, and that is not a shortcut: a real
 * adapter is a link the kernel already has, and `kind = "physical"` is the
 * absence of a creation rather than a creation of its own. Every other kind
 * here is a link netcfgd makes, so its fields are what the making needs. */
QStringList ncfg_device_kind_body(const ncfg_device_config &settings)
{
	QStringList body;
	const QString kind = settings.kind;
	const QStringList members =
	    settings.members.split(QLatin1Char(' '), Qt::SkipEmptyParts);
	QStringList quoted;
	for (const QString &one : members) {
		quoted << QStringLiteral("\"%1\"").arg(one);
	}

	if (kind == QLatin1String("bridge")) {
		body << QStringLiteral("\tbridge {");
		if (!quoted.isEmpty()) {
			body << QStringLiteral("\t\tmembers = [%1]").arg(quoted.join(QStringLiteral(", ")));
		}
		if (settings.stp) {
			body << QStringLiteral("\t\tstp = true");
		}
		if (settings.vlan_filtering) {
			body << QStringLiteral("\t\tvlan_filtering = true");
		}
		body << QStringLiteral("\t}");
	} else if (kind == QLatin1String("bond")) {
		body << QStringLiteral("\tbond {");
		if (!quoted.isEmpty()) {
			body << QStringLiteral("\t\tmembers = [%1]").arg(quoted.join(QStringLiteral(", ")));
		}
		body << QStringLiteral("\t\tmode = \"%1\"")
		        .arg(settings.bond_mode.isEmpty() ? QStringLiteral("active-backup")
		                                          : settings.bond_mode);
		if (settings.miimon > 0) {
			body << QStringLiteral("\t\tmiimon = %1").arg(settings.miimon);
		}
		body << QStringLiteral("\t}");
	} else if (kind == QLatin1String("vlan")) {
		body << QStringLiteral("\tvlan {");
		body << QStringLiteral("\t\tparent = \"%1\"").arg(settings.parent);
		body << QStringLiteral("\t\tid = %1").arg(settings.vlan_id < 0 ? 0 : settings.vlan_id);
		if (!settings.vlan_protocol.isEmpty()
		    && settings.vlan_protocol != QLatin1String("dot1q")) {
			body << QStringLiteral("\t\tprotocol = \"%1\"").arg(settings.vlan_protocol);
		}
		body << QStringLiteral("\t}");
	} else if (kind == QLatin1String("veth")) {
		body << QStringLiteral("\tveth { peer = \"%1\" }").arg(settings.peer);
	} else if (kind == QLatin1String("macvlan")) {
		body << QStringLiteral("\tmacvlan {");
		body << QStringLiteral("\t\tparent = \"%1\"").arg(settings.parent);
		if (!settings.macvlan_mode.isEmpty()
		    && settings.macvlan_mode != QLatin1String("private")) {
			body << QStringLiteral("\t\tmode = \"%1\"").arg(settings.macvlan_mode);
		}
		body << QStringLiteral("\t}");
	} else if (kind == QLatin1String("vrf")) {
		body << QStringLiteral("\tvrf { table = %1 }").arg(settings.vrf_table);
	} else if (kind == QLatin1String("vxlan")) {
		body << QStringLiteral("\tvxlan {");
		body << QStringLiteral("\t\tid = %1").arg(settings.vxlan_id < 0 ? 0 : settings.vxlan_id);
		if (!settings.parent.isEmpty()) {
			body << QStringLiteral("\t\tparent = \"%1\"").arg(settings.parent);
		}
		if (!settings.local.isEmpty()) {
			body << QStringLiteral("\t\tlocal = \"%1\"").arg(settings.local);
		}
		if (!settings.remote.isEmpty()) {
			body << QStringLiteral("\t\tremote = \"%1\"").arg(settings.remote);
		}
		if (settings.port > 0) {
			body << QStringLiteral("\t\tport = %1").arg(settings.port);
		}
		body << QStringLiteral("\t}");
	} else if (kind == QLatin1String("tunnel")) {
		body << QStringLiteral("\ttunnel {");
		body << QStringLiteral("\t\tmode = \"%1\"")
		        .arg(settings.tunnel_mode.isEmpty() ? QStringLiteral("gre")
		                                            : settings.tunnel_mode);
		if (!settings.local.isEmpty()) {
			body << QStringLiteral("\t\tlocal = \"%1\"").arg(settings.local);
		}
		if (!settings.remote.isEmpty()) {
			body << QStringLiteral("\t\tremote = \"%1\"").arg(settings.remote);
		}
		if (!settings.parent.isEmpty()) {
			body << QStringLiteral("\t\tparent = \"%1\"").arg(settings.parent);
		}
		if (settings.ttl > 0) {
			body << QStringLiteral("\t\tttl = %1").arg(settings.ttl);
		}
		if (settings.tunnel_key >= 0) {
			body << QStringLiteral("\t\tkey = %1").arg(settings.tunnel_key);
		}
		body << QStringLiteral("\t}");
	} else if (kind == QLatin1String("wireguard")) {
		body << QStringLiteral("\twireguard {");
		body << QStringLiteral("\t\tprivate_key = \"%1\"").arg(settings.private_key);
		if (settings.listen_port > 0) {
			body << QStringLiteral("\t\tlisten_port = %1").arg(settings.listen_port);
		}
		if (settings.fwmark > 0) {
			body << QStringLiteral("\t\tfwmark = %1").arg(settings.fwmark);
		}
		for (const ncfg_wg_peer_row &peer : settings.peers) {
			body << QStringLiteral("\t\tpeer \"%1\" {").arg(peer.name);
			body << QStringLiteral("\t\t\tpublic_key = \"%1\"").arg(peer.public_key);
			if (!peer.endpoint.isEmpty()) {
				body << QStringLiteral("\t\t\tendpoint = \"%1\"").arg(peer.endpoint);
			}
			const QStringList allowed =
			    peer.allowed_ips.split(QLatin1Char(' '), Qt::SkipEmptyParts);
			if (!allowed.isEmpty()) {
				QStringList quoted_ips;
				for (const QString &one : allowed) {
					quoted_ips << QStringLiteral("\"%1\"").arg(one);
				}
				body << QStringLiteral("\t\t\tallowed_ips = [%1]")
				        .arg(quoted_ips.join(QStringLiteral(", ")));
			}
			if (peer.keepalive > 0) {
				body << QStringLiteral("\t\t\tkeepalive = %1").arg(peer.keepalive);
			}
			if (!peer.preshared_key.isEmpty()) {
				body << QStringLiteral("\t\t\tpreshared_key = \"%1\"")
				        .arg(peer.preshared_key);
			}
			body << QStringLiteral("\t\t}");
		}
		body << QStringLiteral("\t}");
	} else if (kind == QLatin1String("pppoe")) {
		body << QStringLiteral("\tpppoe {");
		body << QStringLiteral("\t\tparent = \"%1\"").arg(settings.parent);
		body << QStringLiteral("\t\tusername = \"%1\"").arg(settings.username);
		body << QStringLiteral("\t\tpassword = \"%1\"").arg(settings.password);
		if (!settings.service.isEmpty()) {
			body << QStringLiteral("\t\tservice = \"%1\"").arg(settings.service);
		}
		if (!settings.ac.isEmpty()) {
			body << QStringLiteral("\t\tac = \"%1\"").arg(settings.ac);
		}
		body << QStringLiteral("\t}");
	} else if (kind == QLatin1String("openvpn")) {
		body << QStringLiteral("\topenvpn {");
		body << QStringLiteral("\t\tconfig = \"%1\"").arg(settings.config);
		/* Both optional: a `.ovpn` that carries its own credentials, or one
		 * whose server wants none, is the ordinary case. Written only when the
		 * operator gave them, so the block says what is unusual. */
		if (!settings.username.isEmpty()) {
			body << QStringLiteral("\t\tusername = \"%1\"").arg(settings.username);
		}
		if (!settings.password.isEmpty()) {
			body << QStringLiteral("\t\tpassword = \"%1\"").arg(settings.password);
		}
		body << QStringLiteral("\t}");
	} else if (kind == QLatin1String("tun") || kind == QLatin1String("tap")) {
		/* The block's name is the mode -- `tun { }` or `tap { }` -- which is
		 * how the language spells it, and why these are two entries in the
		 * kind list rather than one with a mode inside. */
		QStringList inner;
		if (!settings.owner.isEmpty()) {
			inner << QStringLiteral("owner = \"%1\"").arg(settings.owner);
		}
		if (!settings.group.isEmpty()) {
			inner << QStringLiteral("group = \"%1\"").arg(settings.group);
		}
		body << QStringLiteral("\t%1 { %2 }")
		        .arg(kind, inner.join(QStringLiteral("; ")))
		        .trimmed()
		        .replace(QStringLiteral("{  }"), QStringLiteral("{ }"));
	} else if (kind == QLatin1String("dummy")) {
		body << QStringLiteral("\tkind = \"dummy\"");
	}
	return body;
}

} // namespace

QString ncfg_device_block(const QString &name, const ncfg_device_config &settings)
{
	QStringList body;

	body << ncfg_device_kind_body(settings);

	/* **Only what is not the default.** A block that restated every default
	 * would be a block nobody can read for what is unusual -- and `managed`
	 * is true unless somebody says otherwise, so writing `managed = true`
	 * everywhere would bury the one device where it matters. */
	if (!settings.managed) {
		body << QStringLiteral("\tmanaged = false");
		if (!settings.on_unmanage.isEmpty() && settings.on_unmanage != QLatin1String("leave")) {
			body << QStringLiteral("\ton_unmanage = \"%1\"").arg(settings.on_unmanage);
		}
	}
	if (settings.mtu > 0) {
		body << QStringLiteral("\tmtu = %1").arg(settings.mtu);
	}
	if (!settings.qdisc_kind.isEmpty()) {
		body << QStringLiteral("\tqdisc {");
		body << QStringLiteral("\t\tkind = \"%1\"").arg(settings.qdisc_kind);
		/* kbit rather than mbit, so a rate that is not a whole megabit is
		 * written as what it is. The language takes either. */
		if (settings.bandwidth_kbit > 0) {
			body << QStringLiteral("\t\tbandwidth = \"%1kbit\"").arg(settings.bandwidth_kbit);
		}
		if (settings.ingress_bandwidth_kbit > 0) {
			body << QStringLiteral("\t\tingress_bandwidth = \"%1kbit\"")
			        .arg(settings.ingress_bandwidth_kbit);
		}
		body << QStringLiteral("\t}");
	}
	if (!settings.mac.isEmpty()) {
		body << QStringLiteral("\tmac = \"%1\"").arg(settings.mac);
	}

	QStringList ethtool;
	const struct {
		const char *key;
		int         value;
	} switches[] = {
		{ "autoneg", settings.autoneg }, { "gro", settings.gro },
		{ "gso", settings.gso },         { "tso", settings.tso },
		{ "rx_checksum", settings.rx_checksum },
		{ "tx_checksum", settings.tx_checksum },
	};
	for (const auto &one : switches) {
		if (one.value != 0) {
			ethtool << QStringLiteral("\t\t%1 = \"%2\"")
			           .arg(QString::fromLatin1(one.key),
			               QString::fromLatin1(toggle_word(one.value)));
		}
	}
	if (settings.speed > 0) {
		ethtool << QStringLiteral("\t\tspeed = %1").arg(settings.speed);
	}
	if (!settings.duplex.isEmpty()) {
		ethtool << QStringLiteral("\t\tduplex = \"%1\"").arg(settings.duplex);
	}
	if (!settings.wol.isEmpty()) {
		ethtool << QStringLiteral("\t\twol = \"%1\"").arg(settings.wol);
	}
	if (settings.rx_ring > 0) {
		ethtool << QStringLiteral("\t\trx_ring = %1").arg(settings.rx_ring);
	}
	if (settings.tx_ring > 0) {
		ethtool << QStringLiteral("\t\ttx_ring = %1").arg(settings.tx_ring);
	}
	/* An empty `ethtool { }` is not the same as no block: it compiles to a
	 * settings object, and netcfgd then has an opinion about a NIC nobody
	 * asked it to touch. */
	if (!ethtool.isEmpty()) {
		body << QStringLiteral("\tethtool {");
		body << ethtool;
		body << QStringLiteral("\t}");
	}

	if (settings.has_wifi) {
		body << QStringLiteral("\twifi {");
		body << QStringLiteral("\t\tbackend = \"%1\"")
		        .arg(settings.wifi_backend.isEmpty() ? QStringLiteral("auto")
		                                             : settings.wifi_backend);
		body << QStringLiteral("\t\tautoconnect = %1")
		        .arg(settings.wifi_autoconnect ? QStringLiteral("true")
		                                       : QStringLiteral("false"));
		if (!settings.powersave.isEmpty() && settings.powersave != QLatin1String("default")) {
			body << QStringLiteral("\t\tpowersave = \"%1\"").arg(settings.powersave);
		}
		if (!settings.mac_policy.isEmpty()
		    && settings.mac_policy != QLatin1String("permanent")) {
			body << QStringLiteral("\t\tmac_policy = \"%1\"").arg(settings.mac_policy);
		}
		if (settings.scan_randomization) {
			body << QStringLiteral("\t\tscan_randomization = true");
		}
		if (!settings.regdom.isEmpty()) {
			body << QStringLiteral("\t\tregdom = \"%1\"").arg(settings.regdom);
		}
		if (!settings.portal_check.isEmpty()) {
			body << QStringLiteral("\t\tportal_check = \"%1\"").arg(settings.portal_check);
		}
		body << QStringLiteral("\t}");
	}

	if (settings.has_modem) {
		body << QStringLiteral("\tmodem {");
		const QStringList wanted =
		    settings.sim.split(QLatin1Char(' '), Qt::SkipEmptyParts);
		if (!wanted.isEmpty()) {
			QStringList quoted;
			for (const QString &one : wanted) {
				quoted << QStringLiteral("\"%1\"").arg(one);
			}
			body << QStringLiteral("\t\tsim = [%1]").arg(quoted.join(QStringLiteral(", ")));
		}
		if (!settings.apn.isEmpty()) {
			body << QStringLiteral("\t\tapn = \"%1\"").arg(settings.apn);
		}
		body << QStringLiteral("\t}");
	}

	QStringList block;
	block << QStringLiteral("# Written by netcfgd's gui. Ordinary netcfgd configuration:");
	block << QStringLiteral("# edit it, diff it, commit it, or delete it.");
	block << QString();
	block << QStringLiteral("device %1 {").arg(name);
	block << body;
	block << QStringLiteral("}");
	return block.join(QStringLiteral("\n")) + QStringLiteral("\n");
}

ncfg_device_dialog::ncfg_device_dialog(ncfg_connection *connection, const QString &name,
    QWidget *parent)
    : QDialog(parent), connection(connection), device(name)
{
	setWindowTitle(name.isEmpty() ? QStringLiteral("new device")
	                              : QStringLiteral("device: %1").arg(name));
	setObjectName(QStringLiteral("device_dialog"));

	auto *layout = new QVBoxLayout(this);
	auto *form = new QFormLayout();

	this->name = new QLineEdit(name, this);
	this->name->setObjectName(QStringLiteral("device_name"));
	/* Fixed once there is something to edit: the name is the block's and the
	 * drop-in's filename, so changing it would write a second device and leave
	 * the first. */
	this->name->setReadOnly(!name.isEmpty());
	this->name->setPlaceholderText(QStringLiteral("br0, bond0, eth0.42"));
	form->addRow(QStringLiteral("name"), this->name);

	/* **The kind, which is what makes a link exist.** A bridge, a bond, a
	 * VLAN, a veth pair: each is a link netcfgd creates rather than finds, and
	 * this is where a machine's virtual topology is asked for. */
	kind = new QComboBox(this);
	kind->setObjectName(QStringLiteral("device_kind"));
	fill(kind, kinds, sizeof(kinds) / sizeof(kinds[0]));
	form->addRow(QStringLiteral("kind"), kind);

	/* **One form, with the rows the kind needs shown.** A stack of pages was
	 * written first and thrown away: `members` belongs to a bridge and a bond
	 * and `parent` to four kinds, so a field would have had to live on two
	 * pages or be explained away with a label pointing at another one. Rows
	 * that appear and disappear keep one field in one place. */
	members = new QLineEdit(this);
	members->setObjectName(QStringLiteral("device_members"));
	members->setPlaceholderText(QStringLiteral("eth0 eth1 -- the links that join it"));
	form->addRow(QStringLiteral("members"), members);

	parent_link = new QLineEdit(this);
	parent_link->setObjectName(QStringLiteral("device_parent"));
	parent_link->setPlaceholderText(QStringLiteral("eth0 -- the link it sits on"));
	form->addRow(QStringLiteral("parent"), parent_link);

	stp = new QCheckBox(QStringLiteral("spanning tree"), this);
	stp->setObjectName(QStringLiteral("device_stp"));
	form->addRow(QString(), stp);
	vlan_filtering = new QCheckBox(QStringLiteral("vlan filtering"), this);
	vlan_filtering->setObjectName(QStringLiteral("device_vlan_filtering"));
	form->addRow(QString(), vlan_filtering);

	bond_mode = new QComboBox(this);
	bond_mode->setObjectName(QStringLiteral("device_bond_mode"));
	fill(bond_mode, bond_modes, sizeof(bond_modes) / sizeof(bond_modes[0]));
	form->addRow(QStringLiteral("bonding mode"), bond_mode);
	miimon = new QSpinBox(this);
	miimon->setObjectName(QStringLiteral("device_miimon"));
	miimon->setRange(0, 60000);
	miimon->setSpecialValueText(QStringLiteral("unset"));
	form->addRow(QStringLiteral("link check, ms"), miimon);

	vlan_id = new QSpinBox(this);
	vlan_id->setObjectName(QStringLiteral("device_vlan_id"));
	vlan_id->setRange(0, 4094);
	form->addRow(QStringLiteral("vlan id"), vlan_id);
	vlan_protocol = new QComboBox(this);
	vlan_protocol->setObjectName(QStringLiteral("device_vlan_protocol"));
	fill(vlan_protocol, vlan_protocols, sizeof(vlan_protocols) / sizeof(vlan_protocols[0]));
	form->addRow(QStringLiteral("vlan protocol"), vlan_protocol);

	peer = new QLineEdit(this);
	peer->setObjectName(QStringLiteral("device_peer"));
	peer->setPlaceholderText(QStringLiteral("the other end's name"));
	form->addRow(QStringLiteral("peer"), peer);

	macvlan_mode = new QComboBox(this);
	macvlan_mode->setObjectName(QStringLiteral("device_macvlan_mode"));
	fill(macvlan_mode, macvlan_modes, sizeof(macvlan_modes) / sizeof(macvlan_modes[0]));
	form->addRow(QStringLiteral("macvlan mode"), macvlan_mode);

	vrf_table = new QSpinBox(this);
	vrf_table->setObjectName(QStringLiteral("device_vrf_table"));
	vrf_table->setRange(0, 4294967);
	form->addRow(QStringLiteral("routing table"), vrf_table);

	tunnel_mode = new QComboBox(this);
	tunnel_mode->setObjectName(QStringLiteral("device_tunnel_mode"));
	fill(tunnel_mode, tunnel_modes, sizeof(tunnel_modes) / sizeof(tunnel_modes[0]));
	form->addRow(QStringLiteral("encapsulation"), tunnel_mode);

	vxlan_id = new QSpinBox(this);
	vxlan_id->setObjectName(QStringLiteral("device_vxlan_id"));
	vxlan_id->setRange(0, 16777215);
	form->addRow(QStringLiteral("vxlan id"), vxlan_id);

	local = new QLineEdit(this);
	local->setObjectName(QStringLiteral("device_local"));
	local->setPlaceholderText(QStringLiteral("this end's address"));
	form->addRow(QStringLiteral("local"), local);
	remote = new QLineEdit(this);
	remote->setObjectName(QStringLiteral("device_remote"));
	remote->setPlaceholderText(QStringLiteral("the other end's address"));
	form->addRow(QStringLiteral("remote"), remote);

	port = new QSpinBox(this);
	port->setObjectName(QStringLiteral("device_port"));
	port->setRange(0, 65535);
	port->setSpecialValueText(QStringLiteral("default"));
	form->addRow(QStringLiteral("port"), port);

	ttl = new QSpinBox(this);
	ttl->setObjectName(QStringLiteral("device_ttl"));
	ttl->setRange(0, 255);
	ttl->setSpecialValueText(QStringLiteral("inherit"));
	form->addRow(QStringLiteral("ttl"), ttl);

	tunnel_key = new QSpinBox(this);
	tunnel_key->setObjectName(QStringLiteral("device_tunnel_key"));
	tunnel_key->setRange(-1, 2147483647);
	tunnel_key->setSpecialValueText(QStringLiteral("none"));
	tunnel_key->setValue(-1);
	form->addRow(QStringLiteral("tunnel key"), tunnel_key);

	/* **The private key is a reference, not a key.** netcfgd's document type
	 * cannot hold key material at all (0042's rule, and the reason a document
	 * is safe to write to /run), so what this field holds is `@secret:wg0` --
	 * the name of something the secret store keeps. A password box here would
	 * be inviting somebody to paste a key into a configuration file. */
	private_key = new QLineEdit(this);
	private_key->setObjectName(QStringLiteral("device_private_key"));
	private_key->setPlaceholderText(QStringLiteral("@secret:wg0 -- `ncfg secret set wg0` "
	            "puts one there"));
	form->addRow(QStringLiteral("private key"), private_key);

	listen_port = new QSpinBox(this);
	listen_port->setObjectName(QStringLiteral("device_listen_port"));
	listen_port->setRange(0, 65535);
	listen_port->setSpecialValueText(QStringLiteral("any"));
	form->addRow(QStringLiteral("listen port"), listen_port);

	fwmark = new QSpinBox(this);
	fwmark->setObjectName(QStringLiteral("device_fwmark"));
	fwmark->setRange(0, 2147483647);
	fwmark->setSpecialValueText(QStringLiteral("none"));
	form->addRow(QStringLiteral("firewall mark"), fwmark);

	peers = new QTableWidget(0, 5, this);
	peers->setObjectName(QStringLiteral("device_peers"));
	QStringList peer_columns;
	peer_columns << QStringLiteral("name") << QStringLiteral("public key")
	             << QStringLiteral("endpoint") << QStringLiteral("allowed ips")
	             << QStringLiteral("keepalive");
	peers->setHorizontalHeaderLabels(peer_columns);
	peers->verticalHeader()->setVisible(false);
	peers->horizontalHeader()->setStretchLastSection(true);
	peers->setSelectionBehavior(QAbstractItemView::SelectRows);
	peers->setSelectionMode(QAbstractItemView::SingleSelection);
	peers->setMaximumHeight(140);
	form->addRow(QStringLiteral("peers"), peers);

	/* The two buttons in a widget rather than a bare layout, so the row can be
	 * hidden with the rest of the `WireGuard` fields: a form row made of a
	 * layout is not a row `setRowVisible` can be given a widget for, and the
	 * buttons would have sat under a bridge's fields. */
	peer_buttons = new QWidget(this);
	auto *peer_row = new QHBoxLayout(peer_buttons);
	peer_row->setContentsMargins(0, 0, 0, 0);
	peer_add = new QPushButton(QStringLiteral("add peer"), this);
	peer_add->setObjectName(QStringLiteral("device_peer_add"));
	peer_drop = new QPushButton(QStringLiteral("remove peer"), this);
	peer_drop->setObjectName(QStringLiteral("device_peer_drop"));
	peer_row->addWidget(peer_add);
	peer_row->addWidget(peer_drop);
	peer_row->addStretch(1);
	form->addRow(QString(), peer_buttons);

	/* **The file OpenVPN already understands, by path.** netcfgd never reads
	 * it: 0046 measured `openvpn --help` at 253 top-level options against
	 * hostapd's couple of dozen, so expressing that surface would be a second
	 * OpenVPN configuration language permanently behind the first. What
	 * netcfgd owns is the lifecycle. */
	config = new QLineEdit(this);
	config->setObjectName(QStringLiteral("device_config"));
	config->setPlaceholderText(QStringLiteral("/etc/openvpn/client.conf"));
	form->addRow(QStringLiteral("openvpn config"), config);

	username = new QLineEdit(this);
	username->setObjectName(QStringLiteral("device_username"));
	username->setPlaceholderText(QStringLiteral("user@isp.example"));
	form->addRow(QStringLiteral("username"), username);

	/* A reference, like every other credential here: the document type cannot
	 * hold the password itself. `ncfg secret set isp` is what puts one in the
	 * store, and this names it. */
	password = new QLineEdit(this);
	password->setObjectName(QStringLiteral("device_password"));
	password->setPlaceholderText(QStringLiteral("@secret:isp -- `ncfg secret set isp` "
	            "puts one there"));
	form->addRow(QStringLiteral("password"), password);

	service = new QLineEdit(this);
	service->setObjectName(QStringLiteral("device_service"));
	service->setPlaceholderText(QStringLiteral("only where the provider requires one"));
	form->addRow(QStringLiteral("service name"), service);

	ac = new QLineEdit(this);
	ac->setObjectName(QStringLiteral("device_ac"));
	ac->setPlaceholderText(QStringLiteral("only where the provider requires one"));
	form->addRow(QStringLiteral("access concentrator"), ac);

	/* **Who may attach to it**, which is the whole point of a persistent tun:
	 * something else -- a VPN daemon, a hypervisor -- opens it later. Without
	 * either only root can, which is the kernel's default rather than a choice
	 * netcfgd makes. */
	owner = new QLineEdit(this);
	owner->setObjectName(QStringLiteral("device_owner"));
	owner->setPlaceholderText(QStringLiteral("a user -- blank leaves it to root"));
	form->addRow(QStringLiteral("owner"), owner);

	group = new QLineEdit(this);
	group->setObjectName(QStringLiteral("device_group"));
	group->setPlaceholderText(QStringLiteral("a group -- blank leaves it to root"));
	form->addRow(QStringLiteral("group"), group);

	/* **Queueing, which is where bufferbloat is fixed** -- and the only way an
	 * `ifb` device comes into being. Shown for every kind, because any link
	 * can be shaped: a cable, a radio, a bridge, a tunnel. */
	qdisc_kind = new QComboBox(this);
	qdisc_kind->setObjectName(QStringLiteral("device_qdisc_kind"));
	fill(qdisc_kind, qdiscs, sizeof(qdiscs) / sizeof(qdiscs[0]));
	form->addRow(QStringLiteral("queueing"), qdisc_kind);

	bandwidth = new QSpinBox(this);
	bandwidth->setObjectName(QStringLiteral("device_bandwidth"));
	bandwidth->setRange(0, 100'000'000);
	bandwidth->setSpecialValueText(QStringLiteral("unshaped"));
	bandwidth->setSuffix(QStringLiteral(" kbit/s"));
	bandwidth->setToolTip(QStringLiteral(
	    "The real rate of the link going out, which is what lets the scheduler keep "
	    "the queue in netcfgd rather than in somebody else's modem."));
	form->addRow(QStringLiteral("bandwidth out"), bandwidth);

	/* **A second number, not another field on the same queue.** The kernel
	 * cannot queue on the way in -- the packets are already here -- so asking
	 * for this makes netcfgd build an `ifb` device, redirect everything
	 * arriving onto it, and shape it there, where it has become egress. The
	 * `ifb` is netcfgd's to make and appears in the device list as one. */
	ingress_bandwidth = new QSpinBox(this);
	ingress_bandwidth->setObjectName(QStringLiteral("device_ingress_bandwidth"));
	ingress_bandwidth->setRange(0, 100'000'000);
	ingress_bandwidth->setSpecialValueText(QStringLiteral("unshaped"));
	ingress_bandwidth->setSuffix(QStringLiteral(" kbit/s"));
	ingress_bandwidth->setToolTip(QStringLiteral(
	    "Shaping traffic arriving here needs an `ifb` device, which netcfgd creates "
	    "and redirects onto. `cake` is the only scheduler that can do it."));
	form->addRow(QStringLiteral("bandwidth in"), ingress_bandwidth);

	managed = new QCheckBox(QStringLiteral("netcfgd configures this device"), this);
	managed->setObjectName(QStringLiteral("device_managed"));
	managed->setChecked(true);
	managed->setToolTip(QStringLiteral(
	    "Unchecked hands the device to whatever else is on this machine. netcfgd "
	    "plans nothing for it and reports it as somebody else's."));
	form->addRow(QString(), managed);

	on_unmanage = new QComboBox(this);
	on_unmanage->setObjectName(QStringLiteral("device_on_unmanage"));
	fill(on_unmanage, unmanages, sizeof(unmanages) / sizeof(unmanages[0]));
	form->addRow(QStringLiteral("on handing it over"), on_unmanage);

	mtu = new QSpinBox(this);
	mtu->setObjectName(QStringLiteral("device_mtu"));
	mtu->setRange(0, 65535);
	mtu->setSpecialValueText(QStringLiteral("unset"));
	form->addRow(QStringLiteral("mtu"), mtu);

	mac = new QLineEdit(this);
	mac->setObjectName(QStringLiteral("device_mac"));
	mac->setPlaceholderText(QStringLiteral("02:00:00:00:00:01 -- blank keeps the "
	            "hardware's"));
	form->addRow(QStringLiteral("mac address"), mac);
	layout->addLayout(form);

	auto *ethtool_box = new QGroupBox(QStringLiteral("link settings and offloads"), this);
	ethtool_box->setObjectName(QStringLiteral("device_ethtool"));
	auto *ethtool = new QFormLayout(ethtool_box);
	autoneg = new QComboBox(this);
	autoneg->setObjectName(QStringLiteral("device_autoneg"));
	fill(autoneg, toggles, sizeof(toggles) / sizeof(toggles[0]));
	ethtool->addRow(QStringLiteral("autonegotiation"), autoneg);
	speed = new QSpinBox(this);
	speed->setObjectName(QStringLiteral("device_speed"));
	speed->setRange(0, 400000);
	speed->setSpecialValueText(QStringLiteral("unset"));
	ethtool->addRow(QStringLiteral("speed, Mbit/s"), speed);
	duplex = new QComboBox(this);
	duplex->setObjectName(QStringLiteral("device_duplex"));
	fill(duplex, duplexes, sizeof(duplexes) / sizeof(duplexes[0]));
	ethtool->addRow(QStringLiteral("duplex"), duplex);
	wol = new QComboBox(this);
	wol->setObjectName(QStringLiteral("device_wol"));
	fill(wol, wols, sizeof(wols) / sizeof(wols[0]));
	ethtool->addRow(QStringLiteral("wake on lan"), wol);
	rx_ring = new QSpinBox(this);
	rx_ring->setObjectName(QStringLiteral("device_rx_ring"));
	rx_ring->setRange(0, 65535);
	rx_ring->setSpecialValueText(QStringLiteral("unset"));
	ethtool->addRow(QStringLiteral("rx ring"), rx_ring);
	tx_ring = new QSpinBox(this);
	tx_ring->setObjectName(QStringLiteral("device_tx_ring"));
	tx_ring->setRange(0, 65535);
	tx_ring->setSpecialValueText(QStringLiteral("unset"));
	ethtool->addRow(QStringLiteral("tx ring"), tx_ring);
	const struct {
		QComboBox **box;
		const char *name;
		const char *shown;
	} offloads[] = {
		{ &gro, "device_gro", "generic receive offload" },
		{ &gso, "device_gso", "generic segmentation offload" },
		{ &tso, "device_tso", "tcp segmentation offload" },
		{ &rx_checksum, "device_rx_checksum", "receive checksums" },
		{ &tx_checksum, "device_tx_checksum", "transmit checksums" },
	};
	for (const auto &one : offloads) {
		*one.box = new QComboBox(this);
		(*one.box)->setObjectName(QString::fromLatin1(one.name));
		fill(*one.box, toggles, sizeof(toggles) / sizeof(toggles[0]));
		ethtool->addRow(QString::fromLatin1(one.shown), *one.box);
	}
	layout->addWidget(ethtool_box);

	wifi_box = new QGroupBox(QStringLiteral("radio"), this);
	wifi_box->setObjectName(QStringLiteral("device_wifi"));
	/* **Hidden until the daemon says this device has one**, and hidden here
	 * rather than only in `load()`: a device being made has no block to read,
	 * so `load()` returns before it can hide anything -- and the new-device
	 * dialog showed a radio policy and a modem policy for a bridge. Found by
	 * looking at the window after the install rather than by any test, which
	 * is the half a screenshot is for. */
	wifi_box->setVisible(false);
	auto *radio = new QFormLayout(wifi_box);
	wifi_backend = new QComboBox(this);
	wifi_backend->setObjectName(QStringLiteral("device_wifi_backend"));
	fill(wifi_backend, backends, sizeof(backends) / sizeof(backends[0]));
	radio->addRow(QStringLiteral("driven by"), wifi_backend);
	wifi_autoconnect = new QCheckBox(QStringLiteral("join known networks by itself"), this);
	wifi_autoconnect->setObjectName(QStringLiteral("device_wifi_autoconnect"));
	wifi_autoconnect->setChecked(true);
	radio->addRow(QString(), wifi_autoconnect);
	powersave = new QComboBox(this);
	powersave->setObjectName(QStringLiteral("device_powersave"));
	fill(powersave, powersaves, sizeof(powersaves) / sizeof(powersaves[0]));
	radio->addRow(QStringLiteral("power saving"), powersave);
	mac_policy = new QComboBox(this);
	mac_policy->setObjectName(QStringLiteral("device_mac_policy"));
	fill(mac_policy, mac_policies, sizeof(mac_policies) / sizeof(mac_policies[0]));
	radio->addRow(QStringLiteral("address once joined"), mac_policy);
	scan_randomization =
	    new QCheckBox(QStringLiteral("randomise the address in probe requests"), this);
	scan_randomization->setObjectName(QStringLiteral("device_scan_randomization"));
	scan_randomization->setToolTip(QStringLiteral(
	    "Probe requests are broadcast to everyone in range whether or not anything "
	    "is joined. Without this a laptop announces one address to every receiver "
	    "it passes."));
	radio->addRow(QString(), scan_randomization);
	regdom = new QLineEdit(this);
	regdom->setObjectName(QStringLiteral("device_regdom"));
	regdom->setPlaceholderText(QStringLiteral("SE -- the country the radio is in"));
	radio->addRow(QStringLiteral("regulatory domain"), regdom);
	portal_check = new QLineEdit(this);
	portal_check->setObjectName(QStringLiteral("device_portal_check"));
	portal_check->setPlaceholderText(QStringLiteral("http://example.com/generate_204"));
	radio->addRow(QStringLiteral("captive portal check"), portal_check);
	layout->addWidget(wifi_box);

	modem_box = new QGroupBox(QStringLiteral("modem"), this);
	modem_box->setObjectName(QStringLiteral("device_modem"));
	modem_box->setVisible(false);
	auto *cellular = new QFormLayout(modem_box);
	sim = new QLineEdit(this);
	sim->setObjectName(QStringLiteral("device_sim"));
	sim->setPlaceholderText(QStringLiteral("esim socket -- the sources, in order"));
	cellular->addRow(QStringLiteral("sim sources"), sim);
	apn = new QLineEdit(this);
	apn->setObjectName(QStringLiteral("device_apn"));
	cellular->addRow(QStringLiteral("apn"), apn);
	layout->addWidget(modem_box);

	note = new QLabel(this);
	note->setObjectName(QStringLiteral("device_note"));
	note->setWordWrap(true);
	note->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(note);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
	save_button = buttons->addButton(QStringLiteral("Save"), QDialogButtonBox::AcceptRole);
	save_button->setObjectName(QStringLiteral("device_save"));
	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(save_button, &QPushButton::clicked, this, &ncfg_device_dialog::submit);
	connect(kind, &QComboBox::currentIndexChanged, this, &ncfg_device_dialog::kind_changed);
	connect(peer_add, &QPushButton::clicked, this, &ncfg_device_dialog::add_peer);
	connect(peer_drop, &QPushButton::clicked, this, &ncfg_device_dialog::drop_peer);
	layout->addWidget(buttons);
	resize(560, 680);

	load();
	kind_changed();
}

/* One peer row, with the value in the cells: a table an operator types into,
 * because a peer is five short strings and a dialog per peer would be a dialog
 * inside a dialog. */
void ncfg_device_dialog::add_peer()
{
	const int row = peers->rowCount();
	peers->insertRow(row);
	for (int column = 0; column < peers->columnCount(); column++) {
		peers->setItem(row, column, new QTableWidgetItem(QString()));
	}
	peers->setCurrentCell(row, 0);
}

void ncfg_device_dialog::drop_peer()
{
	const int row = peers->currentRow();
	if (row >= 0) {
		peers->removeRow(row);
	}
}

void ncfg_device_dialog::kind_changed()
{
	const QString chosen = kind->currentData().toString();
	auto *form = qobject_cast<QFormLayout *>(layout()->itemAt(0)->layout());
	if (!form) {
		return;
	}

	/* Which kinds want which field, written as the table it is. A bridge and a
	 * bond share `members`; four kinds share `parent`; a tunnel and a VXLAN
	 * share the two addresses. */
	const struct {
		QWidget    *field;
		const char *kinds;
	} rows[] = {
		{ members, "bridge bond" },
		{ parent_link, "vlan macvlan vxlan tunnel pppoe" },
		{ stp, "bridge" },
		{ vlan_filtering, "bridge" },
		{ bond_mode, "bond" },
		{ miimon, "bond" },
		{ vlan_id, "vlan" },
		{ vlan_protocol, "vlan" },
		{ peer, "veth" },
		{ macvlan_mode, "macvlan" },
		{ vrf_table, "vrf" },
		{ tunnel_mode, "tunnel" },
		{ vxlan_id, "vxlan" },
		{ local, "vxlan tunnel" },
		{ remote, "vxlan tunnel" },
		{ port, "vxlan" },
		{ ttl, "tunnel" },
		{ tunnel_key, "tunnel" },
		{ private_key, "wireguard" },
		{ listen_port, "wireguard" },
		{ fwmark, "wireguard" },
		{ peers, "wireguard" },
		{ peer_buttons, "wireguard" },
		{ config, "openvpn" },
		{ username, "pppoe openvpn" },
		{ password, "pppoe openvpn" },
		{ service, "pppoe" },
		{ ac, "pppoe" },
		{ owner, "tun tap" },
		{ group, "tun tap" },
	};
	for (const auto &row : rows) {
		const QString wanted = QString::fromLatin1(row.kinds);
		form->setRowVisible(row.field,
		    wanted.split(QLatin1Char(' ')).contains(chosen));
	}
}

void ncfg_device_dialog::load()
{
	if (device.isEmpty()) {
		/* A device being made: there is nothing to read, and asking would
		 * answer about a name the operator has not typed yet. */
		note->setText(QStringLiteral("a new device. netcfgd creates the link this "
		              "describes; give it addresses in `links`."));
		return;
	}

	QString error;
	if (!connection->device_config(device, &existing, &error)) {
		/* No daemon, or it would not answer. The form stays at its defaults
		 * and `submit` refuses, because what is on the machine is unknown and
		 * overwriting it is not something to do quietly -- the interface
		 * editor's rule, and it is here for the same reason. */
		unknown = true;
		note->setText(error);
		return;
	}

	/* A device with no block opens on `physical`, which asks for nothing: an
	 * adapter the kernel has is not a link netcfgd creates. */
	/* **A tap device says `tun` in the document**, because the kernel has one
	 * kind name for both and the model carries the mode beside it. The form
	 * offers the two as two entries, so this is where the pair is put back
	 * together -- without it, opening a tap and saving would write a tun. */
	QString opened = existing.kind.isEmpty() ? QStringLiteral("physical") : existing.kind;
	if (opened == QLatin1String("tun") && existing.tun_mode == QLatin1String("tap")) {
		opened = QStringLiteral("tap");
	}
	select(kind, opened);
	members->setText(existing.members);
	stp->setChecked(existing.stp);
	vlan_filtering->setChecked(existing.vlan_filtering);
	select(bond_mode, existing.bond_mode);
	miimon->setValue(existing.miimon);
	parent_link->setText(existing.parent);
	vlan_id->setValue(existing.vlan_id < 0 ? 0 : existing.vlan_id);
	select(vlan_protocol, existing.vlan_protocol);
	peer->setText(existing.peer);
	select(macvlan_mode, existing.macvlan_mode);
	vrf_table->setValue(existing.vrf_table);
	select(tunnel_mode, existing.tunnel_mode);
	local->setText(existing.local);
	remote->setText(existing.remote);
	vxlan_id->setValue(existing.vxlan_id < 0 ? 0 : existing.vxlan_id);
	port->setValue(existing.port);
	ttl->setValue(existing.ttl);
	tunnel_key->setValue(existing.tunnel_key);
	private_key->setText(existing.private_key);
	username->setText(existing.username);
	password->setText(existing.password);
	service->setText(existing.service);
	ac->setText(existing.ac);
	config->setText(existing.config);
	owner->setText(existing.owner);
	group->setText(existing.group);
	select(qdisc_kind, existing.qdisc_kind);
	bandwidth->setValue(existing.bandwidth_kbit > 0 ? existing.bandwidth_kbit : 0);
	ingress_bandwidth->setValue(
	    existing.ingress_bandwidth_kbit > 0 ? existing.ingress_bandwidth_kbit : 0);
	listen_port->setValue(existing.listen_port);
	fwmark->setValue(existing.fwmark);
	for (const ncfg_wg_peer_row &known : existing.peers) {
		const int row = peers->rowCount();
		peers->insertRow(row);
		peers->setItem(row, 0, new QTableWidgetItem(known.name));
		peers->setItem(row, 1, new QTableWidgetItem(known.public_key));
		peers->setItem(row, 2, new QTableWidgetItem(known.endpoint));
		peers->setItem(row, 3, new QTableWidgetItem(known.allowed_ips));
		peers->setItem(row, 4, new QTableWidgetItem(
		    known.keepalive > 0 ? QString::number(known.keepalive) : QString()));
		/* The preshared key is kept on the row rather than shown: it is a
		 * reference and not material, but a sixth column of `@secret:` names
		 * on a table an operator scans for endpoints is noise. Carried so a
		 * save does not drop it, which is the whole rule this editor follows. */
		peers->item(row, 0)->setData(Qt::UserRole, known.preshared_key);
	}

	managed->setChecked(existing.managed);
	select(on_unmanage, existing.on_unmanage.isEmpty() ? QStringLiteral("leave")
	                                                   : existing.on_unmanage);
	mtu->setValue(existing.mtu);
	mac->setText(existing.mac);

	const struct {
		QComboBox *box;
		int        value;
	} switches[] = {
		{ autoneg, existing.autoneg },
		{ gro, existing.gro },
		{ gso, existing.gso },
		{ tso, existing.tso },
		{ rx_checksum, existing.rx_checksum },
		{ tx_checksum, existing.tx_checksum },
	};
	for (const auto &one : switches) {
		select(one.box, QString::fromLatin1(toggle_word(one.value)));
	}
	speed->setValue(existing.speed);
	select(duplex, existing.duplex);
	select(wol, existing.wol);
	rx_ring->setValue(existing.rx_ring);
	tx_ring->setValue(existing.tx_ring);

	/* **Shown only where the device has one.** A `wifi` block on a wired card
	 * compiles and means nothing, and a form that offered it would invite
	 * writing one. The daemon's answer decides, not a guess from the name. */
	wifi_box->setVisible(existing.has_wifi);
	if (existing.has_wifi) {
		select(wifi_backend, existing.wifi_backend);
		wifi_autoconnect->setChecked(existing.wifi_autoconnect);
		select(powersave, existing.powersave);
		select(mac_policy, existing.mac_policy);
		scan_randomization->setChecked(existing.scan_randomization);
		regdom->setText(existing.regdom);
		portal_check->setText(existing.portal_check);
	}
	modem_box->setVisible(existing.has_modem);
	if (existing.has_modem) {
		sim->setText(existing.sim);
		apn->setText(existing.apn);
	}

	if (!existing.unmodelled.isEmpty()) {
		note->setText(QStringLiteral(
		    "this device's configuration carries %1, which this dialog has no field "
		    "for -- saving would delete it. Edit the file instead: "
		    "`ncfg config edit device-%2`.")
		        .arg(existing.unmodelled, device));
		save_button->setEnabled(false);
	} else if (!existing.present) {
		note->setText(QStringLiteral("netcfgd has no `device` block for %1 yet. Saving "
		              "writes one; what is not set here stays unset.")
		          .arg(device));
	}
}

/* One cell of the peers table, trimmed, empty where there is none. */
QString ncfg_device_dialog::peer_cell(int row, int column) const
{
	const QTableWidgetItem *item = peers->item(row, column);
	return item ? item->text().trimmed() : QString();
}

QString ncfg_device_dialog::block_text() const
{
	ncfg_device_config settings;
	settings.kind = kind->currentData().toString();
	settings.members = members->text().trimmed();
	settings.stp = stp->isChecked();
	settings.vlan_filtering = vlan_filtering->isChecked();
	settings.bond_mode = bond_mode->currentData().toString();
	settings.miimon = miimon->value();
	settings.parent = parent_link->text().trimmed();
	settings.vlan_id = vlan_id->value();
	settings.vlan_protocol = vlan_protocol->currentData().toString();
	settings.peer = peer->text().trimmed();
	settings.macvlan_mode = macvlan_mode->currentData().toString();
	settings.vrf_table = vrf_table->value();
	settings.tunnel_mode = tunnel_mode->currentData().toString();
	settings.local = local->text().trimmed();
	settings.remote = remote->text().trimmed();
	settings.vxlan_id = vxlan_id->value();
	settings.port = port->value();
	settings.ttl = ttl->value();
	settings.tunnel_key = tunnel_key->value();
	settings.private_key = private_key->text().trimmed();
	settings.username = username->text().trimmed();
	settings.password = password->text().trimmed();
	settings.service = service->text().trimmed();
	settings.ac = ac->text().trimmed();
	settings.config = config->text().trimmed();
	settings.owner = owner->text().trimmed();
	settings.group = group->text().trimmed();
	settings.qdisc_kind = qdisc_kind->currentData().toString();
	settings.bandwidth_kbit = bandwidth->value();
	settings.ingress_bandwidth_kbit = ingress_bandwidth->value();
	settings.listen_port = listen_port->value();
	settings.fwmark = fwmark->value();
	for (int row = 0; row < peers->rowCount(); row++) {
		ncfg_wg_peer_row peer;
		peer.name = peer_cell(row, 0);
		peer.public_key = peer_cell(row, 1);
		peer.endpoint = peer_cell(row, 2);
		peer.allowed_ips = peer_cell(row, 3);
		peer.keepalive = peer_cell(row, 4).toInt();
		peer.preshared_key = peers->item(row, 0)
		    ? peers->item(row, 0)->data(Qt::UserRole).toString()
		    : QString();
		settings.peers << peer;
	}
	settings.managed = managed->isChecked();
	settings.on_unmanage = on_unmanage->currentData().toString();
	settings.mtu = mtu->value();
	settings.mac = mac->text().trimmed();
	settings.autoneg = toggle_value(autoneg);
	settings.speed = speed->value();
	settings.duplex = duplex->currentData().toString();
	settings.wol = wol->currentData().toString();
	settings.rx_ring = rx_ring->value();
	settings.tx_ring = tx_ring->value();
	settings.gro = toggle_value(gro);
	settings.gso = toggle_value(gso);
	settings.tso = toggle_value(tso);
	settings.rx_checksum = toggle_value(rx_checksum);
	settings.tx_checksum = toggle_value(tx_checksum);
	/* The radio and modem halves are written only where the device had them:
	 * this dialog edits a policy, it does not decide that a wired card has a
	 * radio. */
	settings.has_wifi = existing.has_wifi;
	settings.wifi_backend = wifi_backend->currentData().toString();
	settings.wifi_autoconnect = wifi_autoconnect->isChecked();
	settings.powersave = powersave->currentData().toString();
	settings.mac_policy = mac_policy->currentData().toString();
	settings.scan_randomization = scan_randomization->isChecked();
	settings.regdom = regdom->text().trimmed();
	settings.portal_check = portal_check->text().trimmed();
	settings.has_modem = existing.has_modem;
	settings.sim = sim->text().trimmed();
	settings.apn = apn->text().trimmed();
	return ncfg_device_block(name->text().trimmed(), settings);
}

void ncfg_device_dialog::submit()
{
	const QString refusal = ncfg_device_name_refusal(name->text());
	if (!refusal.isEmpty()) {
		note->setText(refusal);
		return;
	}
	const QString chosen = kind->currentData().toString();
	/* **The fields a kind cannot do without.** netcfgd would refuse these too,
	 * and saying it here puts the sentence beside the field it is about --
	 * which is the difference between "this dialog is wrong" and "this line is
	 * wrong". */
	const struct {
		const char *kind;
		QString     value;
		const char *said;
	} required[] = {
		{ "vlan", parent_link->text().trimmed(), "a vlan needs a parent link" },
		{ "macvlan", parent_link->text().trimmed(), "a macvlan needs a parent link" },
		{ "veth", peer->text().trimmed(), "a veth pair needs the other end's name" },
	};
	for (const auto &one : required) {
		if (chosen == QLatin1String(one.kind) && one.value.isEmpty()) {
			note->setText(QString::fromLatin1(one.said));
			return;
		}
	}
	if (chosen == QLatin1String("vrf") && vrf_table->value() == 0) {
		note->setText(QStringLiteral("a vrf needs the routing table it owns"));
		return;
	}
	if (qdisc_kind->currentData().toString().isEmpty()
	    && (bandwidth->value() > 0 || ingress_bandwidth->value() > 0)) {
		note->setText(QStringLiteral("a shaped rate needs a scheduler to shape with: "
		              "pick one under `queueing`"));
		return;
	}
	/* The compiler's own rule, said beside the field: ingress shaping puts
	 * `cake` on an `ifb` device, so the scheduler has to be `cake`. */
	if (ingress_bandwidth->value() > 0
	    && qdisc_kind->currentData().toString() != QLatin1String("cake")) {
		note->setText(QStringLiteral("only `cake` can shape arriving traffic: netcfgd puts "
		              "it on the `ifb` device it makes for this link"));
		return;
	}
	if (chosen == QLatin1String("pppoe")) {
		if (parent_link->text().trimmed().isEmpty()) {
			note->setText(QStringLiteral("a pppoe session needs the ethernet link it "
			              "runs over"));
			return;
		}
		if (username->text().trimmed().isEmpty()) {
			note->setText(QStringLiteral("a pppoe session needs the username the "
			              "provider gave you"));
			return;
		}
		if (!password->text().trimmed().startsWith(QLatin1String("@secret:"))) {
			note->setText(QStringLiteral("the password is a reference, not the password: "
			              "`@secret:isp`, with `ncfg secret set isp` to put one there"));
			return;
		}
	}
	if (chosen == QLatin1String("openvpn")) {
		/* The model requires an absolute path: netcfgd hands it to OpenVPN as
		 * given, and a relative one would be resolved against whatever
		 * directory the daemon happens to be in. */
		if (!config->text().trimmed().startsWith(QLatin1Char('/'))) {
			note->setText(QStringLiteral("an openvpn tunnel needs the absolute path to "
			              "the .ovpn file OpenVPN reads"));
			return;
		}
		if (!password->text().trimmed().isEmpty()
		    && !password->text().trimmed().startsWith(QLatin1String("@secret:"))) {
			note->setText(QStringLiteral("the password is a reference, not the password: "
			              "`@secret:vpn`, with `ncfg secret set vpn` to put one there"));
			return;
		}
	}
	if (chosen == QLatin1String("wireguard")) {
		/* **A reference, and it has to look like one.** The document type
		 * cannot hold key material at all, so a key pasted here would be
		 * refused by the compiler with a message about a secret name -- said
		 * beside the field instead, where the mistake is. */
		if (!private_key->text().trimmed().startsWith(QLatin1String("@secret:"))) {
			note->setText(QStringLiteral("the private key is a reference, not the key: "
			              "`@secret:wg0`, with `ncfg secret set wg0` to put one there"));
			return;
		}
		for (int row = 0; row < peers->rowCount(); row++) {
			if (peer_cell(row, 0).isEmpty() || peer_cell(row, 1).isEmpty()) {
				note->setText(QStringLiteral("every peer needs a name and a public key"));
				return;
			}
		}
	}

	const QLineEdit *values[] = { mac, regdom, portal_check, sim, apn, members, parent_link,
		peer, local, remote, private_key, username, password, service, ac, config, owner,
		group };
	for (const QLineEdit *value : values) {
		if (!safe_value(value->text())) {
			note->setText(QStringLiteral("a value cannot carry a quote, a backslash "
			              "or a newline"));
			return;
		}
	}
	if (unknown) {
		note->setText(QStringLiteral(
		    "netcfgd could not say how this device is configured, so saving would "
		    "overwrite something unknown. Check the daemon is running."));
		return;
	}
	if (!existing.unmodelled.isEmpty()) {
		note->setText(QStringLiteral(
		    "this device's configuration carries %1, which this dialog has no field "
		    "for -- saving would delete it.")
		        .arg(existing.unmodelled));
		return;
	}
	if (!regdom->text().trimmed().isEmpty() && regdom->text().trimmed().size() != 2) {
		/* The compiler says the same thing; saying it here costs one round
		 * trip less and puts the sentence beside the field it is about. */
		note->setText(QStringLiteral("a regulatory domain is a two-letter country code, "
		              "such as SE or US"));
		return;
	}

	QString error;
	const QString written = name->text().trimmed();
	if (!connection->config_put(QStringLiteral("device-%1").arg(written), block_text(), true,
	        &error)) {
		note->setText(error);
		return;
	}
	summary = QStringLiteral("wrote device-%1: netcfgd re-read its configuration. "
	              "Run apply to make the machine match it.")
	          .arg(written);
	accept();
}
