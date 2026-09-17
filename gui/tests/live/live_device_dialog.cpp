/*
 * live_device_dialog.cpp -- configuring hardware, against a daemon.
 *
 * WHY THIS EXISTS
 *   `device_block` checks the text. What it cannot check is whether netcfgd
 *   made anything of it: a block can be well formed, name a key the compiler
 *   spells differently, and be refused -- with the dialog reporting success in
 *   a screenshot nobody was reading.
 *
 *   So this asserts the compiled document afterwards, read back through the
 *   daemon's own answer about the device. That goes through the compiler, so a
 *   block this editor wrote and netcfgd could not parse fails here.
 *
 * THE OTHER HALF, WHICH IS WHY THE DEVICE TAB EXISTS AT ALL
 *   The MTU used to be written by the *interface* editor, as a `device` block
 *   inside `interface-<name>.conf`. Two screens writing one block into two
 *   drop-ins is a duplicate the loader refuses, so the move is not a tidy-up:
 *   this probe writes `device-<name>` and the interface probe asserts its own
 *   drop-in no longer carries one.
 */

#include "../../src/device_dialog.h"
#include "../../src/ncfg_connection.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QGroupBox>
#include <QLabel>
#include <QSpinBox>
#include <QTableWidget>

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

	/* A name of this probe's own, for the reason `live_interface_dialog`
	 * records: these probes share one daemon and one configuration, and a
	 * device block left on the radio would change what every probe after this
	 * one sees. */
	const QString name = QStringLiteral("gui-dev0");

	{
		ncfg_device_dialog dialog(&connection, name);
		auto *managed = dialog.findChild<QCheckBox *>(QStringLiteral("device_managed"));
		auto *mtu = dialog.findChild<QSpinBox *>(QStringLiteral("device_mtu"));
		auto *mac = dialog.findChild<QLineEdit *>(QStringLiteral("device_mac"));
		auto *autoneg = dialog.findChild<QComboBox *>(QStringLiteral("device_autoneg"));
		auto *gro = dialog.findChild<QComboBox *>(QStringLiteral("device_gro"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("device_save"));
		if (!managed || !mtu || !mac || !autoneg || !gro || !save) {
			check("the dialog has the fields it needs", false);
			return 1;
		}
		check("the dialog has the fields it needs", true);
		/* A device the document has never mentioned opens on defaults rather
		 * than on nothing: managing is what netcfgd does unless told not to. */
		check("a device with no block opens as managed", managed->isChecked());

		mtu->setValue(9000);
		mac->setText(QStringLiteral("02:00:00:00:00:01"));
		autoneg->setCurrentIndex(autoneg->findData(QStringLiteral("on")));
		gro->setCurrentIndex(gro->findData(QStringLiteral("off")));
		save->click();
		check("saving says where it went", dialog.outcome().contains(name),
		    dialog.outcome());
	}

	/* netcfgd compiled it -- which is the whole point of asking the daemon
	 * rather than reading back the file this program just wrote. */
	{
		ncfg_device_config written;
		check("netcfgd compiled the device block",
		    connection.device_config(name, &written, &error), error);
		check("and reports the block as present", written.present);
		check("with the mtu it was given", written.mtu == 9000,
		    QString::number(written.mtu));
		check("and the mac", written.mac == QStringLiteral("02:00:00:00:00:01"),
		    written.mac);
		/* Three-valued, and the two that are not "leave alone" both survive:
		 * a toggle that came back `unmanaged` would mean the block said
		 * nothing about it. */
		check("and autonegotiation on", written.autoneg == 1,
		    QString::number(written.autoneg));
		check("and an offload turned off, which is not the same as left alone",
		    written.gro == 2, QString::number(written.gro));
		check("while a toggle nobody touched stays left alone", written.gso == 0,
		    QString::number(written.gso));
	}

	/* Re-opening loads what was written. A dialog that saves and does not load
	 * is the fault `interface_load` exists for: every field back at its
	 * default, and save replaces the block with that. */
	{
		ncfg_device_dialog dialog(&connection, name);
		auto *mtu = dialog.findChild<QSpinBox *>(QStringLiteral("device_mtu"));
		auto *gro = dialog.findChild<QComboBox *>(QStringLiteral("device_gro"));
		check("re-opening loads the mtu", mtu && mtu->value() == 9000,
		    QString::number(mtu ? mtu->value() : -1));
		check("and the offload it turned off",
		    gro && gro->currentData().toString() == QStringLiteral("off"),
		    gro ? gro->currentData().toString() : QString());
	}

	/* The device list, which is the tab's own question: the union of what the
	 * kernel has and what the document describes. */
	{
		QList<ncfg_device_row> rows;
		check("the daemon lists devices", connection.devices(&rows, &error), error);
		bool described = false;
		bool hardware = false;
		for (const ncfg_device_row &row : rows) {
			if (row.name == name) {
				described = row.configured && !row.present;
			}
			if (row.name == QStringLiteral("radio0")) {
				hardware = row.present;
			}
		}
		check("including one the document describes and the kernel does not have",
		    described);
		check("and one the kernel has", hardware);
	}

	/* **Making a link, which is the other half of a device.** A bridge is not
	 * hardware netcfgd finds: it is a link netcfgd creates, and until the form
	 * carried a kind there was no way to ask for one except by writing the
	 * block. What this asserts is the compiled document afterwards -- a
	 * `bridge` block netcfgd could not parse fails here. */
	{
		ncfg_device_dialog dialog(&connection, QString());
		auto *made = dialog.findChild<QLineEdit *>(QStringLiteral("device_name"));
		auto *kind = dialog.findChild<QComboBox *>(QStringLiteral("device_kind"));
		auto *members = dialog.findChild<QLineEdit *>(QStringLiteral("device_members"));
		auto *stp = dialog.findChild<QCheckBox *>(QStringLiteral("device_stp"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("device_save"));
		if (!made || !kind || !members || !stp || !save) {
			check("the new-device dialog has the fields it needs", false);
			return 1;
		}
		check("the new-device dialog has the fields it needs", true);
		check("and lets the name be typed, unlike an existing device's",
		    !made->isReadOnly());
		/* **And offers no radio or modem policy for a link being made.** Those
		 * groups belong to a device the daemon says has one; a bridge being
		 * invented has no block to read, so nothing had hidden them and the
		 * form offered a regulatory domain for a bridge. */
		auto *radio = dialog.findChild<QGroupBox *>(QStringLiteral("device_wifi"));
		auto *modem = dialog.findChild<QGroupBox *>(QStringLiteral("device_modem"));
		check("and offers no radio policy for a link being made",
		    radio && radio->isHidden());
		check("nor a modem one", modem && modem->isHidden());

		made->setText(QStringLiteral("gui-br0"));
		kind->setCurrentIndex(kind->findData(QStringLiteral("bridge")));
		members->setText(QStringLiteral("gui-set-a gui-set-b"));
		stp->setChecked(true);
		save->click();
		check("saving says where it went", dialog.outcome().contains(QStringLiteral("gui-br0")),
		    dialog.outcome());

		ncfg_device_config bridge;
		check("netcfgd compiled the bridge",
		    connection.device_config(QStringLiteral("gui-br0"), &bridge, &error), error);
		check("as a bridge", bridge.kind == QStringLiteral("bridge"), bridge.kind);
		check("with both members", bridge.members == QStringLiteral("gui-set-a gui-set-b"),
		    bridge.members);
		check("and spanning tree on", bridge.stp);
		/* And it is editable afterwards: the refusal that used to fire for
		 * every kind but `physical` was "a form of these fields would delete
		 * the members", which is only true while the form has no members. */
		check("and the block is editable rather than refused",
		    bridge.unmodelled.isEmpty(), bridge.unmodelled);
	}

	/* And re-opening the bridge loads its kind and its members.
	 *
	 * **A form that saved a kind and did not load it would quietly unmake the
	 * link**: every field back at its default is `physical`, and saving that
	 * over a bridge deletes the bridge. The same fault `interface_load` exists
	 * for, one block along. */
	{
		ncfg_device_dialog dialog(&connection, QStringLiteral("gui-br0"));
		auto *kind = dialog.findChild<QComboBox *>(QStringLiteral("device_kind"));
		auto *members = dialog.findChild<QLineEdit *>(QStringLiteral("device_members"));
		check("re-opening a bridge says it is a bridge",
		    kind && kind->currentData().toString() == QStringLiteral("bridge"),
		    kind ? kind->currentData().toString() : QString());
		check("and loads its members",
		    members && members->text() == QStringLiteral("gui-set-a gui-set-b"),
		    members ? members->text() : QString());
	}

	/* A VLAN, because it is the kind whose fields are two and whose absence is
	 * a refusal rather than a bad block: netcfgd requires a parent and an id. */
	{
		ncfg_device_dialog dialog(&connection, QString());
		auto *made = dialog.findChild<QLineEdit *>(QStringLiteral("device_name"));
		auto *kind = dialog.findChild<QComboBox *>(QStringLiteral("device_kind"));
		auto *parent = dialog.findChild<QLineEdit *>(QStringLiteral("device_parent"));
		auto *id = dialog.findChild<QSpinBox *>(QStringLiteral("device_vlan_id"));
		auto *note = dialog.findChild<QLabel *>(QStringLiteral("device_note"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("device_save"));

		made->setText(QStringLiteral("gui-br0.42"));
		kind->setCurrentIndex(kind->findData(QStringLiteral("vlan")));
		id->setValue(42);
		/* No parent: refused here, beside the field, rather than by the daemon
		 * after a round trip.
		 *
		 * **The dialog's own sentence, not the word "parent".** netcfgd
		 * refuses a parentless vlan too and says so with that word in it, so
		 * an assertion on the word passed whether the check here existed or
		 * not -- measured, by removing the check and watching this stay
		 * green. What separates them is whose sentence it is. */
		save->click();
		check("a vlan with no parent is refused before anything is sent",
		    note && note->text() == QStringLiteral("a vlan needs a parent link"),
		    note ? note->text() : QString());

		parent->setText(QStringLiteral("gui-br0"));
		save->click();

		ncfg_device_config vlan;
		check("netcfgd compiled the vlan",
		    connection.device_config(QStringLiteral("gui-br0.42"), &vlan, &error), error);
		check("as a vlan on its parent", vlan.kind == QStringLiteral("vlan") &&
		        vlan.parent == QStringLiteral("gui-br0"),
		    QStringLiteral("%1 on %2").arg(vlan.kind, vlan.parent));
		check("with the tag it was given", vlan.vlan_id == 42,
		    QString::number(vlan.vlan_id));
	}

	/* **WireGuard, which is the kind that carries a credential and a list.**
	 * It was refused outright until this round -- and refused by a name that
	 * never matched, because the document spells the kind `wire_guard` and the
	 * language spells it `wireguard`: a WireGuard device therefore looked like
	 * a physical one to the editor, and saving would have written a `device`
	 * block with no tunnel in it. */
	{
		ncfg_device_dialog dialog(&connection, QString());
		auto *made = dialog.findChild<QLineEdit *>(QStringLiteral("device_name"));
		auto *kind = dialog.findChild<QComboBox *>(QStringLiteral("device_kind"));
		auto *key = dialog.findChild<QLineEdit *>(QStringLiteral("device_private_key"));
		auto *listen = dialog.findChild<QSpinBox *>(QStringLiteral("device_listen_port"));
		auto *peers = dialog.findChild<QTableWidget *>(QStringLiteral("device_peers"));
		auto *add = dialog.findChild<QPushButton *>(QStringLiteral("device_peer_add"));
		auto *note = dialog.findChild<QLabel *>(QStringLiteral("device_note"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("device_save"));
		if (!made || !kind || !key || !listen || !peers || !add || !save) {
			check("the wireguard fields are there", false);
			return 1;
		}
		check("the wireguard fields are there", true);

		made->setText(QStringLiteral("gui-wg0"));
		kind->setCurrentIndex(kind->findData(QStringLiteral("wireguard")));
		listen->setValue(51820);

		/* A key pasted where a reference belongs: refused here, beside the
		 * field, because the document type cannot hold key material at all. */
		key->setText(QStringLiteral("QF4lQ0Iw6cP7f0cQDZQwqz0m0h2wJ3vJ7l5b1kR9Umc="));
		save->click();
		/* **The dialog's own sentence, not the word "reference".** netcfgd
		 * refuses a pasted key too and says so with that word in it, so an
		 * assertion on the word passes whether this check exists or not --
		 * which is exactly how the vlan-parent check above was found to be
		 * vacuous. Twice in one campaign is a pattern, not an accident: a
		 * refusal test has to name whose refusal it is. */
		check("a private key pasted instead of a reference is refused here",
		    note && note->text().startsWith(
		                QStringLiteral("the private key is a reference, not the key")),
		    note ? note->text() : QString());

		key->setText(QStringLiteral("@secret:gui-wg0"));
		add->click();
		peers->setItem(0, 0, new QTableWidgetItem(QStringLiteral("office")));
		peers->setItem(0, 1, new QTableWidgetItem(
		    QStringLiteral("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=")));
		peers->setItem(0, 2, new QTableWidgetItem(QStringLiteral("vpn.example.com:51820")));
		peers->setItem(0, 3, new QTableWidgetItem(QStringLiteral("10.9.0.0/24")));
		peers->setItem(0, 4, new QTableWidgetItem(QStringLiteral("25")));
		save->click();
		check("and a whole one is written", dialog.outcome().contains(QStringLiteral("gui-wg0")),
		    QStringLiteral("%1 / %2").arg(dialog.outcome(),
		        note ? note->text() : QString()));
	}

	{
		ncfg_device_config wg;
		check("netcfgd compiled the wireguard device",
		    connection.device_config(QStringLiteral("gui-wg0"), &wg, &error), error);
		check("as wireguard, spelled as the language spells it",
		    wg.kind == QStringLiteral("wireguard"), wg.kind);
		check("with the private key as a reference",
		    wg.private_key == QStringLiteral("@secret:gui-wg0"), wg.private_key);
		check("and its listen port", wg.listen_port == 51820,
		    QString::number(wg.listen_port));
		check("and the peer", wg.peers.size() == 1,
		    QString::number(wg.peers.size()));
		if (wg.peers.size() == 1) {
			check("named", wg.peers[0].name == QStringLiteral("office"), wg.peers[0].name);
			check("with its public key and endpoint",
			    wg.peers[0].public_key.startsWith(QStringLiteral("xTIBA5")) &&
			        wg.peers[0].endpoint == QStringLiteral("vpn.example.com:51820"),
			    wg.peers[0].endpoint);
			check("and its allowed prefixes",
			    wg.peers[0].allowed_ips == QStringLiteral("10.9.0.0/24"),
			    wg.peers[0].allowed_ips);
		}
		/* And it is editable rather than refused, which is the whole of what
		 * changed for this kind. */
		check("and the block is editable rather than refused", wg.unmodelled.isEmpty(),
		    wg.unmodelled);
	}

	/* **PPPoE and OpenVPN, the last two kinds a form could hold.** `openvpn`
	 * was refused by a name that never matched -- the document spells the kind
	 * `open_vpn` -- so an OpenVPN device looked physical to the editor and a
	 * save would have written a `device` block with no tunnel in it, exactly as
	 * `wire_guard` did one round earlier. Both spellings are translated in one
	 * table now, and this is the check that the second one is translated. */
	{
		ncfg_device_dialog dialog(&connection, QString());
		auto *made = dialog.findChild<QLineEdit *>(QStringLiteral("device_name"));
		auto *kind = dialog.findChild<QComboBox *>(QStringLiteral("device_kind"));
		auto *parent = dialog.findChild<QLineEdit *>(QStringLiteral("device_parent"));
		auto *user = dialog.findChild<QLineEdit *>(QStringLiteral("device_username"));
		auto *secret = dialog.findChild<QLineEdit *>(QStringLiteral("device_password"));
		auto *note = dialog.findChild<QLabel *>(QStringLiteral("device_note"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("device_save"));
		if (!made || !kind || !parent || !user || !secret || !save) {
			check("the pppoe fields are there", false);
			return 1;
		}
		check("the pppoe fields are there", true);

		made->setText(QStringLiteral("gui-ppp0"));
		kind->setCurrentIndex(kind->findData(QStringLiteral("pppoe")));
		parent->setText(QStringLiteral("gui-set-a"));
		user->setText(QStringLiteral("user@isp.example"));
		/* A password typed where a reference belongs, refused beside the
		 * field: the document type cannot hold one. */
		secret->setText(QStringLiteral("hunter2"));
		save->click();
		check("a pppoe password typed instead of a reference is refused here",
		    note && note->text().startsWith(
		                QStringLiteral("the password is a reference, not the password")),
		    note ? note->text() : QString());

		secret->setText(QStringLiteral("@secret:gui-isp"));
		save->click();
		check("and a whole session is written",
		    dialog.outcome().contains(QStringLiteral("gui-ppp0")),
		    QStringLiteral("%1 / %2").arg(dialog.outcome(),
		        note ? note->text() : QString()));

		ncfg_device_config written;
		check("netcfgd compiled the pppoe session",
		    connection.device_config(QStringLiteral("gui-ppp0"), &written, &error), error);
		check("as pppoe on its parent", written.kind == QStringLiteral("pppoe")
		        && written.parent == QStringLiteral("gui-set-a"),
		    QStringLiteral("%1 on %2").arg(written.kind, written.parent));
		check("with the login and the password as a reference",
		    written.username == QStringLiteral("user@isp.example")
		        && written.password == QStringLiteral("@secret:gui-isp"),
		    written.password);
	}

	{
		ncfg_device_dialog dialog(&connection, QString());
		auto *made = dialog.findChild<QLineEdit *>(QStringLiteral("device_name"));
		auto *kind = dialog.findChild<QComboBox *>(QStringLiteral("device_kind"));
		auto *file = dialog.findChild<QLineEdit *>(QStringLiteral("device_config"));
		auto *note = dialog.findChild<QLabel *>(QStringLiteral("device_note"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("device_save"));

		made->setText(QStringLiteral("gui-tun0"));
		kind->setCurrentIndex(kind->findData(QStringLiteral("openvpn")));
		file->setText(QStringLiteral("client.conf"));
		save->click();
		check("a relative openvpn config path is refused here",
		    note && note->text().startsWith(QStringLiteral("an openvpn tunnel needs the "
		                                              "absolute path")),
		    note ? note->text() : QString());

		file->setText(QStringLiteral("/etc/openvpn/client.conf"));
		save->click();

		ncfg_device_config written;
		check("netcfgd compiled the openvpn tunnel",
		    connection.device_config(QStringLiteral("gui-tun0"), &written, &error), error);
		/* **The spelling, which is the whole point of this pair of checks.**
		 * `open_vpn` in the document and `openvpn` in the language: untranslated,
		 * this comes back as a kind the form has never heard of. */
		check("as openvpn, spelled as the language spells it",
		    written.kind == QStringLiteral("openvpn"), written.kind);
		check("naming the file OpenVPN reads",
		    written.config == QStringLiteral("/etc/openvpn/client.conf"), written.config);
		check("and the block is editable rather than refused",
		    written.unmodelled.isEmpty(), written.unmodelled);
	}

	/* **A tun device, which netcfgd could not make at all until 0254.** The
	 * refusal list carried `tun` because the kind needed an ioctl nothing in
	 * the tree had; it has one now, so what is checked here is the other half:
	 * that the form writes the block the compiler takes, with the mode as the
	 * block's own name. */
	{
		ncfg_device_dialog dialog(&connection, QString());
		auto *made = dialog.findChild<QLineEdit *>(QStringLiteral("device_name"));
		auto *kind = dialog.findChild<QComboBox *>(QStringLiteral("device_kind"));
		auto *owner = dialog.findChild<QLineEdit *>(QStringLiteral("device_owner"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("device_save"));
		if (!made || !kind || !owner || !save) {
			check("the tun fields are there", false);
			return 1;
		}
		check("the tun fields are there", true);
		check("and both modes are offered as kinds of their own",
		    kind->findData(QStringLiteral("tun")) >= 0
		        && kind->findData(QStringLiteral("tap")) >= 0);

		made->setText(QStringLiteral("gui-tap0"));
		kind->setCurrentIndex(kind->findData(QStringLiteral("tap")));
		owner->setText(QStringLiteral("root"));
		save->click();

		ncfg_device_config written;
		check("netcfgd compiled the tap device",
		    connection.device_config(QStringLiteral("gui-tap0"), &written, &error), error);
		/* **The kind is `tun` for both modes**, which is the kernel's own
		 * naming and the reason the mode is a field beside it. A form that
		 * read the kind alone would open a tap as a tun and save it as one. */
		check("as a tun kind carrying the tap mode",
		    written.kind == QStringLiteral("tun")
		        && written.tun_mode == QStringLiteral("tap"),
		    QStringLiteral("%1 / %2").arg(written.kind, written.tun_mode));
		check("with the owner it was given", written.owner == QStringLiteral("root"),
		    written.owner);
		check("and the block is editable rather than refused",
		    written.unmodelled.isEmpty(), written.unmodelled);
	}

	/* And re-opening it puts the two back together: the document says `tun`
	 * with a mode beside it, the form offers two kinds, and a tap that opened
	 * as a tun would be saved as one. */
	{
		ncfg_device_dialog dialog(&connection, QStringLiteral("gui-tap0"));
		auto *kind = dialog.findChild<QComboBox *>(QStringLiteral("device_kind"));
		check("re-opening a tap device says tap",
		    kind && kind->currentData().toString() == QStringLiteral("tap"),
		    kind ? kind->currentData().toString() : QString());
	}

	/* **Shaping, and the `ifb` device netcfgd makes out of it.**
	 *
	 * There is no `ifb` to write: the language refuses `kind = "ifb"`, and one
	 * is synthesised per interface that asks for `ingress_bandwidth` because
	 * the kernel cannot queue on the way in. So what this checks is that the
	 * form writes the rate, that netcfgd turns it into the pair, and that the
	 * pair comes back as one block -- the operator wrote one. */
	{
		ncfg_device_dialog dialog(&connection, QString());
		auto *made = dialog.findChild<QLineEdit *>(QStringLiteral("device_name"));
		auto *scheduler = dialog.findChild<QComboBox *>(QStringLiteral("device_qdisc_kind"));
		auto *out = dialog.findChild<QSpinBox *>(QStringLiteral("device_bandwidth"));
		auto *in = dialog.findChild<QSpinBox *>(QStringLiteral("device_ingress_bandwidth"));
		auto *note = dialog.findChild<QLabel *>(QStringLiteral("device_note"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("device_save"));
		if (!made || !scheduler || !out || !in || !save) {
			check("the queueing fields are there", false);
			return 1;
		}
		check("the queueing fields are there", true);

		made->setText(QStringLiteral("gui-shaped0"));
		/* A dummy, so the device exists to be shaped without needing hardware. */
		auto *kind = dialog.findChild<QComboBox *>(QStringLiteral("device_kind"));
		kind->setCurrentIndex(kind->findData(QStringLiteral("dummy")));
		scheduler->setCurrentIndex(scheduler->findData(QStringLiteral("fq_codel")));
		out->setValue(20000);
		in->setValue(8000);
		save->click();
		/* The compiler's rule, said beside the field rather than after a round
		 * trip: ingress shaping puts `cake` on the `ifb`, so it has to be
		 * `cake`. */
		check("shaping arriving traffic with anything but cake is refused here",
		    note && note->text().startsWith(QStringLiteral("only `cake` can shape arriving")),
		    note ? note->text() : QString());

		scheduler->setCurrentIndex(scheduler->findData(QStringLiteral("cake")));
		save->click();
		check("and with cake it is written",
		    dialog.outcome().contains(QStringLiteral("gui-shaped0")),
		    QStringLiteral("%1 / %2").arg(dialog.outcome(),
		        note ? note->text() : QString()));
	}

	{
		ncfg_device_config shaped;
		check("netcfgd compiled the shaped device",
		    connection.device_config(QStringLiteral("gui-shaped0"), &shaped, &error), error);
		check("with the scheduler", shaped.qdisc_kind == QStringLiteral("cake"),
		    shaped.qdisc_kind);
		check("and the rate going out", shaped.bandwidth_kbit == 20000,
		    QString::number(shaped.bandwidth_kbit));
		/* **The join.** This number is not on this device in the document: it
		 * is on the `ifb` netcfgd synthesised, and the client puts the halves
		 * back together so the form shows the one block that was written. */
		check("and the rate arriving, which lives on the ifb netcfgd made",
		    shaped.ingress_bandwidth_kbit == 8000,
		    QString::number(shaped.ingress_bandwidth_kbit));

		QList<ncfg_device_row> rows;
		check("the daemon lists devices", connection.devices(&rows, &error), error);
		bool synthesised = false;
		for (const ncfg_device_row &row : rows) {
			if (row.name == QStringLiteral("ifb-gui-shaped0")) {
				synthesised = row.kind == QStringLiteral("ifb");
			}
		}
		check("and the ifb appears in the device list as netcfgd's own", synthesised);

		/* Which is not editable here, and says why rather than offering a form
		 * for something the language refuses to take. */
		ncfg_device_config made;
		check("the ifb can be read",
		    connection.device_config(QStringLiteral("ifb-gui-shaped0"), &made, &error), error);
		check("and says netcfgd makes it rather than offering to edit it",
		    made.unmodelled.contains(QStringLiteral("netcfgd makes this one")),
		    made.unmodelled);
	}

	{
		QString removed;
		connection.config_delete(QStringLiteral("device-gui-shaped0"), &removed);
		connection.config_delete(QStringLiteral("device-gui-tap0"), &removed);
		connection.config_delete(QStringLiteral("device-gui-ppp0"), &removed);
		connection.config_delete(QStringLiteral("device-gui-tun0"), &removed);
		connection.config_delete(QStringLiteral("device-gui-wg0"), &removed);
		check("the block can be removed again",
		    connection.config_delete(QStringLiteral("device-%1").arg(name), &removed),
		    removed);
		/* The made links go too: these probes share one daemon, and a bridge
		 * left behind is a link every probe after this one would see. The
		 * vlan first -- it names the bridge, and a configuration naming a
		 * parent that is not there does not compile. */
		connection.config_delete(QStringLiteral("device-gui-br0.42"), &removed);
		connection.config_delete(QStringLiteral("device-gui-br0"), &removed);
		ncfg_device_config gone;
		check("and the bridge with it",
		    connection.device_config(QStringLiteral("gui-br0"), &gone, &error)
		        && !gone.present,
		    error);
	}

	if (failures == 0) {
		printf("live_device_dialog: all checks passed\n");
	} else {
		printf("live_device_dialog: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
