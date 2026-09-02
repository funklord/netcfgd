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
		check("and will not save a network it cannot write", save->isEnabled());
		save->click();

		ncfg_saved_network_row written;
		check("netcfgd compiled the hand-written network",
		    saved_named(&connection, QStringLiteral("by-hand"), &written));
		check("with the metric it was given", written.metric == 42,
		    QString::number(written.metric));
		check("and its security type", written.security == QStringLiteral("psk"),
		    written.security);
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

		metric->setValue(7);
		autoconnect->setChecked(false);
		save->click();

		ncfg_saved_network_row after;
		check("the change reached the document",
		    saved_named(&connection, QStringLiteral("by-hand"), &after) &&
		        after.metric == 7,
		    QString::number(after.metric));
		check("and so did the other one", after.autoconnect == false);
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

	printf("\n");
	if (failures) {
		printf("live_network_dialog: %d failed\n", failures);
		return 1;
	}
	printf("live_network_dialog: all checks passed\n");
	return 0;
}
