/*
 * live_network_dialog.cpp -- viewing and changing a network, against a daemon.
 *
 * WHY THIS EXISTS
 *   `live_add_dialog` covers adding what a scan found. This dialog does the
 *   two things that one cannot: open a network the document already holds, and
 *   write one that is not in range. Both compose a configuration block rather
 *   than sending a typed request, so the thing worth checking is what netcfgd
 *   made of the text -- a block can be well formed and mean something else.
 *
 * WHAT IT ASSERTS
 *   The compiled document afterwards, read back through `saved_networks()`.
 *   That goes through the compiler, so a block netcfgd wrote and could not
 *   parse fails here rather than passing.
 *
 *   And that editing does not disturb the credential. netcfgd keeps the
 *   passphrase in the secret store and the block keeps an `@secret:` reference,
 *   so an edit with the passphrase field left blank must leave that reference
 *   in place -- a rewrite that dropped it would take the network off the air at
 *   the next apply, with nothing on screen to say so.
 */

#include "../../src/network_dialog.h"
#include "../../src/ncfg_connection.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QFile>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QSpinBox>

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

static bool saved_named(ncfg_connection *connection, const QString &id,
    ncfg_saved_network_row *out)
{
	QList<ncfg_saved_network_row> rows;
	QString error;
	if (!connection->saved_networks(&rows, &error)) {
		return false;
	}
	for (const ncfg_saved_network_row &row : rows) {
		if (row.id == id) {
			*out = row;
			return true;
		}
	}
	return false;
}

int main(int argc, char **argv)
{
	QApplication app(argc, argv);
	const QString conf = QString::fromUtf8(qgetenv("NCFG_CONFIG_DIR")) + "/conf.d/";

	ncfg_connection connection;
	QString error;
	if (!connection.open(QString(), &error)) {
		printf("FAIL the dialog's connection reaches netcfgd\n       %s\n",
		    error.toUtf8().constData());
		return 1;
	}
	check("the dialog's connection reaches netcfgd", true);

	/* 1. A network written by hand, which is the case no scan can reach. */
	{
		ncfg_network_dialog dialog(&connection, ncfg_saved_network_row());
		auto *id = dialog.findChild<QLineEdit *>(QStringLiteral("network_id"));
		auto *security = dialog.findChild<QComboBox *>(QStringLiteral("network_security"));
		auto *credential =
		    dialog.findChild<QLineEdit *>(QStringLiteral("network_credential"));
		auto *metric = dialog.findChild<QSpinBox *>(QStringLiteral("network_metric"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("network_save"));
		if (!id || !security || !credential || !metric || !save) {
			check("the dialog has the fields it needs", false);
			return 1;
		}
		check("the dialog has the fields it needs", true);

		id->setText(QStringLiteral("by-hand"));
		security->setCurrentIndex(security->findData(QStringLiteral("psk")));
		credential->setText(QStringLiteral("hunter2hunter2"));
		metric->setValue(42);
		/* Pinned to WPA3, which is the state an edit can silently widen. */
		auto *proto = dialog.findChild<QComboBox *>(QStringLiteral("network_proto"));
		if (proto) {
			proto->setCurrentIndex(proto->findData(QStringLiteral("wpa3")));
		}
		check("and will not save a network it cannot write", save->isEnabled());
		save->click();

		ncfg_saved_network_row written;
		check("netcfgd compiled the hand-written network",
		    saved_named(&connection, QStringLiteral("by-hand"), &written));
		check("with the metric it was given", written.metric == 42,
		    QString::number(written.metric));
		check("and its security type", written.security == QStringLiteral("psk"),
		    written.security);
		check("and the generation it was pinned to", written.proto == QStringLiteral("wpa3"),
		    written.proto);
	}

	/* 2. Opening it again and changing one thing, with the passphrase left
	 *    blank -- which is what editing anything else looks like. */
	{
		ncfg_saved_network_row existing;
		if (!saved_named(&connection, QStringLiteral("by-hand"), &existing)) {
			check("the network is there to edit", false);
			return 1;
		}
		ncfg_network_dialog dialog(&connection, existing);
		auto *id = dialog.findChild<QLineEdit *>(QStringLiteral("network_id"));
		auto *metric = dialog.findChild<QSpinBox *>(QStringLiteral("network_metric"));
		auto *autoconnect =
		    dialog.findChild<QCheckBox *>(QStringLiteral("network_autoconnect"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("network_save"));

		/* The id is the block's name and the file's: changing it would write a
		 * second network and leave the first. */
		check("the name of an existing network cannot be edited", id->isReadOnly());
		check("and the dialog opens on what is set", metric->value() == 42,
		    QString::number(metric->value()));

		/* **The generation the document holds, put back in the combo.** This
		 * is the check the bug needed: the dialog restored the security kind
		 * and not the generation, so it opened at "negotiate WPA2 and WPA3"
		 * for a network that refused WPA2 -- and `block_text` writes the
		 * generation only when the combo names one, so pressing save widened
		 * the network without saying anything. Nothing else here touches it,
		 * which is what makes the assertion after the save meaningful. */
		auto *proto = dialog.findChild<QComboBox *>(QStringLiteral("network_proto"));
		check("the dialog opens on the generation the document holds",
		    proto && proto->currentData().toString() == QStringLiteral("wpa3"),
		    proto ? proto->currentData().toString() : QStringLiteral("<no combo>"));

		metric->setValue(7);
		autoconnect->setChecked(false);
		save->click();

		ncfg_saved_network_row after;
		check("the change reached the document",
		    saved_named(&connection, QStringLiteral("by-hand"), &after) &&
		        after.metric == 7,
		    QString::number(after.metric));
		check("and so did the other one", after.autoconnect == false);
		check("and editing did not widen the generation",
		    after.proto == QStringLiteral("wpa3"), after.proto);
	}

	/* 3. The credential survived, which is the failure that would be silent.
	 *    Read from the file rather than the document: the document carries a
	 *    reference by design and never the secret, so the block is where a
	 *    dropped reference would show. */
	{
		QFile written(conf + QStringLiteral("wifi-by-hand.conf"));
		check("the drop-in is there", written.exists(), written.fileName());
		if (written.open(QIODevice::ReadOnly)) {
			const QString text = QString::fromUtf8(written.readAll());
			check("an edit with a blank passphrase keeps the secret reference",
			    text.contains(QStringLiteral("@secret:by-hand")), text);
			check("and never writes the passphrase into the configuration",
			    !text.contains(QStringLiteral("hunter2")), text);
			written.close();
		}
	}

	/* 4. What the dialog does not show (10.606). It saves the block whole, so
	 *    it must open on what the document holds for the fields it has --
	 *    addressing and metered were not loaded at all -- and refuse where the
	 *    block carries something it has no field for. */
	{
		QString why;
		check("a metered DHCP network is written by hand",
		    connection.config_put(QStringLiteral("wifi-metered"),
		        QStringLiteral("network \"metered\" {\n\twifi { psk = \"@secret:metered\" }\n"
		                       "\tmetered = true\n\tconfig = \"dhcp\"\n}\n"),
		        true, &why),
		    why);
		ncfg_saved_network_row existing;
		check("and netcfgd says the dialog can carry all of it",
		    saved_named(&connection, QStringLiteral("metered"), &existing) &&
		        existing.unmodelled.isEmpty(),
		    existing.unmodelled);
		ncfg_network_dialog dialog(&connection, existing);
		auto *addressing = dialog.findChild<QListWidget *>(QStringLiteral("network_sources"));
		auto *metered = dialog.findChild<QCheckBox *>(QStringLiteral("network_metered"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("network_save"));
		check("the dialog opens on its addressing",
		    addressing && addressing->count() == 1 &&
		        addressing->item(0)->data(Qt::UserRole).toString() == QStringLiteral("dhcp"),
		    addressing ? QString::number(addressing->count()) : QString());
		check("and on its being metered", metered && metered->isChecked());
		save->click();
		ncfg_saved_network_row after;
		check("and saving it unchanged keeps both",
		    saved_named(&connection, QStringLiteral("metered"), &after) && after.metered &&
		        after.sources.size() == 1 && after.sources[0].source == QStringLiteral("dhcp4"),
		    QString::number(after.sources.size()));
		/* Taken away again: the probes share one daemon, and a network left
		 * here is one the next probe's radio would try to join. */
		(void)connection.config_delete(QStringLiteral("wifi-metered"), &why);
	}
	/* 5. What the dialog refused until 10.612 and carries now: pinned access
	 *    points, roaming, a route and a resolver scope. Opened on all of it,
	 *    a changed metric saved with all of it. And two addressing sources,
	 *    refused until 10.615 when the dialog gained the interface's list. */
	{
		QString why;
		check("a network pinned to two access points, roaming, with a route and dns, is "
		      "written by hand",
		    connection.config_put(QStringLiteral("wifi-pinned"),
		        QStringLiteral("network \"pinned\" {\n\twifi {\n\t\tpsk = \"@secret:pinned\"\n"
		                       "\t\troam { signal = -72; interval = 20; slow_interval = 200 }\n"
		                       "\t}\n\tbssid = [\"00:11:22:33:44:55\", \"00:11:22:33:44:66\"]\n"
		                       "\troutes = [\"10.9.0.0/24 via 192.168.1.1 metric 5\"]\n"
		                       "\tdns { mode = \"write_resolv_conf\"; servers = [\"192.168.1.53\"] }\n"
		                       "}\n"),
		        true, &why),
		    why);
		ncfg_saved_network_row existing;
		check("and netcfgd says the dialog can carry all of it",
		    saved_named(&connection, QStringLiteral("pinned"), &existing) &&
		        existing.unmodelled.isEmpty(),
		    existing.unmodelled);
		ncfg_network_dialog dialog(&connection, existing);
		auto *pinned = dialog.findChild<QLineEdit *>(QStringLiteral("network_bssid"));
		auto *roam = dialog.findChild<QCheckBox *>(QStringLiteral("network_roam"));
		auto *metric = dialog.findChild<QSpinBox *>(QStringLiteral("network_metric"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("network_save"));
		check("the dialog opens on its access points and its roaming",
		    pinned && pinned->text() == QStringLiteral("00:11:22:33:44:55 00:11:22:33:44:66") &&
		        roam && roam->isChecked(),
		    pinned ? pinned->text() : QString());
		metric->setValue(20);
		save->click();
		ncfg_saved_network_row after;
		check("and Save keeps all of it",
		    !dialog.outcome().isEmpty() && saved_named(&connection, QStringLiteral("pinned"), &after) &&
		        after.metric == 20 &&
		        after.bssid == QStringLiteral("00:11:22:33:44:55 00:11:22:33:44:66") && after.roam &&
		        after.roam_signal == -72 && after.roam_interval == 20 &&
		        after.roam_slow_interval == 200 && after.routes.size() == 1 &&
		        after.routes[0].destination == QStringLiteral("10.9.0.0/24") &&
		        after.routes[0].via == QStringLiteral("192.168.1.1") && after.routes[0].metric == 5 &&
		        after.dns_mode == QStringLiteral("write_resolv_conf") &&
		        after.dns_servers == QStringLiteral("192.168.1.53"),
		    after.bssid + QStringLiteral(" / ") + after.dns_servers);
		(void)connection.config_delete(QStringLiteral("wifi-pinned"), &why);
	}
	{
		QString why;
		const QString text = QStringLiteral(
		    "network \"twice\" {\n\twifi { psk = \"@secret:twice\" }\n"
		    "\tconfig = [\"dhcp\", \"dhcp6 pd pd_length 60\"]\n"
		    "\troutes = [\"10.8.0.0/24 via 192.168.1.1 src 192.168.1.20 table 7 onlink\"]\n}\n");
		check("a network addressed twice, with a route from a source address, is written "
		      "by hand",
		    connection.config_put(QStringLiteral("wifi-twice"), text, true, &why), why);
		ncfg_saved_network_row existing;
		check("and netcfgd says the dialog can carry all of it",
		    saved_named(&connection, QStringLiteral("twice"), &existing) &&
		        existing.unmodelled.isEmpty(),
		    existing.unmodelled);
		ncfg_network_dialog dialog(&connection, existing);
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("network_save"));
		save->click();
		QFile file(conf + QStringLiteral("wifi-twice.conf"));
		QString kept;
		if (file.open(QIODevice::ReadOnly)) {
			kept = QString::fromUtf8(file.readAll());
		}
		check("so Save writes both sources, the delegation request and the whole route",
		    !dialog.outcome().isEmpty() &&
		        kept.contains(QStringLiteral("config = [\"dhcp\", \"dhcp6 pd pd_length 60\"]")) &&
		        kept.contains(QStringLiteral("\"10.8.0.0/24 via 192.168.1.1 src 192.168.1.20 "
		                                    "table 7 onlink\"")),
		    kept);
		(void)connection.config_delete(QStringLiteral("wifi-twice"), &why);
	}

	/* 5c. A network with a hook, refused until 10.616 on the belief that the
	 *    GUI could not read a network's hooks. It opens with the hook in its
	 *    list, and Save writes the script back byte for byte. */
	{
		QString why;
		const QString body = QStringLiteral("#!/bin/sh\nlogger joined the hooked network\n");
		check("a network with a hook is written by hand",
		    connection.config_put(QStringLiteral("wifi-hooked"),
		        QStringLiteral("network \"hooked\" {\n\twifi { psk = \"@secret:hooked\" }\n"
		                       "\tpost_up {\n") + body + QStringLiteral("}\n}\n"),
		        true, &why),
		    why);
		ncfg_saved_network_row existing;
		check("and netcfgd says the dialog can carry it, counting one hook",
		    saved_named(&connection, QStringLiteral("hooked"), &existing) &&
		        existing.unmodelled.isEmpty() && existing.hook_count == 1,
		    existing.unmodelled + QStringLiteral(" / ") + QString::number(existing.hook_count));
		ncfg_network_dialog dialog(&connection, existing);
		auto *list = dialog.findChild<QListWidget *>(QStringLiteral("network_hooks"));
		auto *metric = dialog.findChild<QSpinBox *>(QStringLiteral("network_metric"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("network_save"));
		check("the dialog opens with the hook in its list",
		    list && list->count() == 1 &&
		        list->item(0)->text() == QStringLiteral("post_up -- logger joined the hooked network"),
		    list && list->count() ? list->item(0)->text() : QString());
		metric->setValue(30);
		save->click();
		QString text;
		QList<ncfg_hook_script> scripts;
		if (connection.hook_scripts(&scripts, &why)) {
			for (const ncfg_hook_script &one : scripts) {
				if (one.network == QStringLiteral("hooked")) {
					text = one.text;
				}
			}
		}
		check("and Save keeps the script, byte for byte", !dialog.outcome().isEmpty() &&
		        text == body, dialog.outcome().isEmpty() ? QStringLiteral("<not saved>") : text);
		(void)connection.config_delete(QStringLiteral("wifi-hooked"), &why);
	}

	/* 6. An enterprise network, and a passphrase the keyring holds (10.611).
	 *    The dialog opened both with empty fields and rebuilt each reference
	 *    from the network's id, so Save lost the identity and certificates
	 *    and repointed the credential; then it refused them outright. Now it
	 *    opens on them and writes them back as they were. */
	{
		QString why;
		check("an enterprise network is written by hand",
		    connection.config_put(QStringLiteral("wifi-campus"),
		        QStringLiteral("network \"campus\" {\n\twifi {\n\t\teap = \"peap\"\n"
		                       "\t\tidentity = \"me@uni.example\"\n"
		                       "\t\tpassword = \"@secret:uni-login\"\n"
		                       "\t\tca_cert = \"/etc/ssl/uni-ca.pem\"\n"
		                       "\t\tdomain_suffix_match = \"radius.uni.example\"\n"
		                       "\t\tphase2 = \"mschapv2\"\n\t}\n}\n"),
		        true, &why),
		    why);
		ncfg_saved_network_row existing;
		check("and netcfgd says the dialog can carry all of it",
		    saved_named(&connection, QStringLiteral("campus"), &existing) &&
		        existing.unmodelled.isEmpty(),
		    existing.unmodelled);
		ncfg_network_dialog dialog(&connection, existing);
		auto *identity = dialog.findChild<QLineEdit *>(QStringLiteral("network_identity"));
		auto *ca = dialog.findChild<QLineEdit *>(QStringLiteral("network_ca_cert"));
		auto *server = dialog.findChild<QLineEdit *>(QStringLiteral("network_domain_suffix_match"));
		auto *metric = dialog.findChild<QSpinBox *>(QStringLiteral("network_metric"));
		auto *save = dialog.findChild<QPushButton *>(QStringLiteral("network_save"));
		check("the dialog opens on its identity, certificate and server name",
		    identity && identity->text() == QStringLiteral("me@uni.example") && ca &&
		        ca->text() == QStringLiteral("/etc/ssl/uni-ca.pem") && server &&
		        server->text() == QStringLiteral("radius.uni.example"),
		    identity ? identity->text() : QString());
		metric->setValue(30);
		save->click();
		ncfg_saved_network_row after;
		check("and Save keeps all of it, the password still under its own name",
		    !dialog.outcome().isEmpty() &&
		        saved_named(&connection, QStringLiteral("campus"), &after) &&
		        after.metric == 30 && after.identity == QStringLiteral("me@uni.example") &&
		        after.ca_cert == QStringLiteral("/etc/ssl/uni-ca.pem") &&
		        after.domain_suffix_match == QStringLiteral("radius.uni.example") &&
		        after.phase2 == QStringLiteral("mschapv2") && after.eap_method == QStringLiteral("peap") &&
		        after.credential_reference == QStringLiteral("@secret:uni-login"),
		    after.credential_reference + QStringLiteral(" ") + after.identity);
		(void)connection.config_delete(QStringLiteral("wifi-campus"), &why);
	}
	{
		QString why;
		check("a network whose passphrase the keyring holds is written by hand",
		    connection.config_put(QStringLiteral("wifi-house"),
		        QStringLiteral("network \"house\" {\n\twifi { psk = \"@secret:keyring:house-psk\" }\n}\n"),
		        true, &why),
		    why);
		ncfg_saved_network_row existing;
		check("  its reference read as written",
		    saved_named(&connection, QStringLiteral("house"), &existing) &&
		        existing.credential_reference == QStringLiteral("@secret:keyring:house-psk"),
		    existing.credential_reference);
		{
			ncfg_network_dialog dialog(&connection, existing);
			auto *metric = dialog.findChild<QSpinBox *>(QStringLiteral("network_metric"));
			auto *save = dialog.findChild<QPushButton *>(QStringLiteral("network_save"));
			metric->setValue(40);
			save->click();
		}
		ncfg_saved_network_row after;
		check("  and Save keeps it pointing at the keyring",
		    saved_named(&connection, QStringLiteral("house"), &after) && after.metric == 40 &&
		        after.credential_reference == QStringLiteral("@secret:keyring:house-psk"),
		    after.credential_reference);
		{
			ncfg_network_dialog dialog(&connection, after);
			auto *credential = dialog.findChild<QLineEdit *>(QStringLiteral("network_credential"));
			auto *save = dialog.findChild<QPushButton *>(QStringLiteral("network_save"));
			credential->setText(QStringLiteral("a-new-passphrase"));
			save->click();
			check("  and a new passphrase for it is refused, naming where to change it",
			    dialog.outcome().isEmpty());
		}
		(void)connection.config_delete(QStringLiteral("wifi-house"), &why);
	}

	printf("\n");
	if (failures) {
		printf("live_network_dialog: %d failed\n", failures);
		return 1;
	}
	printf("live_network_dialog: all checks passed\n");
	return 0;
}
