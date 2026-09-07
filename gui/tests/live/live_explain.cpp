/*
 * live_explain.cpp -- the explanation dialog against a real daemon.
 *
 * WHY THIS EXISTS
 *   `explain` is the one question this program can ask that `ip addr` cannot,
 *   and until now no window could ask it: the request has been the daemon's
 *   since the beginning and the client library had no call for it. A probe
 *   that only checked the parse would not have caught the fault that actually
 *   happened while writing it -- the subject was sent as
 *   `{"kind":"interface"}` and the daemon answered "missing field `subject`",
 *   because the enum is serde-tagged on the field name `subject` and the
 *   member holding it is spelled the same. That is a join between a C string
 *   literal and a Rust attribute, and only a real daemon has an opinion.
 *
 * WHAT IT ASSERTS
 *   That the dialog reaches the daemon, that it draws the facts it was given
 *   rather than an error, and that a fact carrying a place shows the place.
 *   The last is the point of the feature: "declared in the configuration" is
 *   worth little without the file and line beside it.
 *
 *   Offscreen, and `isVisible()` is never asked -- a widget in a window nobody
 *   showed is not visible whatever it was told, which live_wifi's header
 *   records as an afternoon lost.
 */
#include "../../src/explain_dialog.h"
#include "../../src/ncfg_connection.h"
#include "../../src/table_view.h"

#include <QApplication>
#include <QLabel>
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

/* Every cell of the drawn table, joined. What is asserted below is presence of
 * a fact and of a source, and a probe that reached into one column by index
 * would be pinning the column order rather than the content. */
static QString drawn(QWidget *of)
{
	QString all;
	const QTableWidget *grid = of->findChild<QTableWidget *>();
	if (!grid) {
		return all;
	}
	for (int r = 0; r < grid->rowCount(); r++) {
		for (int c = 0; c < grid->columnCount(); c++) {
			if (grid->item(r, c)) {
				all += grid->item(r, c)->text() + QStringLiteral("\n");
			}
		}
	}
	return all;
}

static QString note_of(QWidget *of)
{
	const QLabel *note = of->findChild<QLabel *>(QStringLiteral("explain_note"));
	return note ? note->text() : QString();
}

int main(int argc, char **argv)
{
	QApplication app(argc, argv);

	ncfg_connection connection;
	QString error;
	if (!connection.open(QString(), &error)) {
		printf("FAIL the explain dialog can reach netcfgd\n       %s\n",
		    error.toUtf8().constData());
		return 1;
	}
	check("the explain dialog can reach netcfgd", true);

	/* `lo` rather than an interface the harness made: every machine has one,
	 * the daemon has an opinion about it whether or not the configuration
	 * mentions it, and a probe that needed a fixture would be testing the
	 * fixture. */
	ncfg_explain_dialog dialog(&connection, QStringLiteral("lo"));
	const QString shown = drawn(&dialog);

	check("it draws something rather than a refusal", !shown.isEmpty(),
	    QStringLiteral("note was: %1").arg(note_of(&dialog)));
	/* The daemon answers about an interface it does not manage as readily as
	 * one it does -- "not mentioned in the configuration" is a fact. What is
	 * asserted is a topic the protocol names, not a particular sentence. */
	check("and the facts carry the daemon's own topics",
	    shown.contains(QStringLiteral("desired")) || shown.contains(QStringLiteral("observed")),
	    shown);
	check("and the note explains what the table is",
	    note_of(&dialog).contains(QStringLiteral("lo")), note_of(&dialog));

	/* **The one that says the feature is worth having**, and it needs an
	 * interface the configuration actually names. The harness starts with an
	 * empty `netcfgd.conf` on purpose -- "the state the report came from" --
	 * so this writes its own drop-in rather than depending on another probe
	 * having run first. The runner walks `*.pro` in directory order, which is
	 * not an ordering anything should rely on.
	 *
	 * Through `config_put`, which is how a client is supposed to write
	 * configuration (0127): the daemon puts it where it belongs and reloads,
	 * so the explanation that follows is of a document netcfgd compiled
	 * rather than of a file this probe dropped somewhere. */
	QString why;
	check("a probe can write the interface it wants explained",
	    connection.config_put(QStringLiteral("live-explain"),
	        QStringLiteral("device explain0 { kind = \"dummy\" }\n"
	                   "interface explain0 { config = \"192.0.2.77/24\" }\n"),
	        true, &why),
	    why);

	ncfg_explain_dialog configured(&connection, QStringLiteral("explain0"));
	const QString about = drawn(&configured);
	check("an interface the configuration names is explained too", !about.isEmpty());
	/* Without a place beside it, "declared in the configuration" is an
	 * assertion with no provenance -- which is what every other tab already
	 * shows. The file and line are the feature. */
	check("and a fact that has a place shows the place",
	    about.contains(QStringLiteral("live-explain")), about);
	check("and the address it was given is in there",
	    about.contains(QStringLiteral("192.0.2.77/24")), about);

	/* **Put back what this probe changed, and assert that it went.**
	 *
	 * The drop-in above is not inert: it declares a `device`, so netcfgd
	 * *creates* `explain0` in the namespace and keeps it. Every probe the
	 * runner starts after this one -- `live_wifi` among them -- then runs
	 * against a machine with an extra interface and a document this probe
	 * wrote, which is a fixture nobody asked for and one nothing would name
	 * if it caused a failure. Measured before this was added: the interface
	 * is there and the drop-in is on disk when the probe exits.
	 *
	 * Asserted rather than merely attempted, for the reason `evidence.md`
	 * gives about cleanups: a removal nobody checks is indistinguishable from
	 * one that silently did nothing, and the symptom arrives in somebody
	 * else's test. */
	check("the probe takes its own drop-in away again",
	    connection.config_delete(QStringLiteral("live-explain"), &why), why);

	ncfg_explain_dialog after(&connection, QStringLiteral("explain0"));
	const QString left = drawn(&after);
	check("and netcfgd stops calling it configured",
	    !left.contains(QStringLiteral("live-explain")), left);

	printf("\n");
	if (failures) {
		printf("live_explain: %d failed\n", failures);
		return 1;
	}
	printf("live_explain: all checks passed\n");
	return 0;
}
