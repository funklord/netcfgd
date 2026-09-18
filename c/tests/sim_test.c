/*
 * sim_test.c -- which SIM source netcfgd wants, and the file a hook reads.
 *
 * NOTHING HERE GOES NEAR THE MACHINE'S OWN `/run`
 *   Every run directory below is inside a directory `testdir.h` made with
 *   `mkdtemp` and removes at the end. `ncfg_sims_sync` has no default path at
 *   all, which is the point of it having none: the real netcfgd publishes its
 *   selections under `/run/netcfgd/modem` on the machine these tests are built
 *   on, and a module that filled the path in for itself would be one mistake
 *   away from a test driving somebody's modem.
 *
 *   No process is started here. This module writes files and nothing else.
 *
 * WHICH HOOK SINK, AND WHY IT IS THE SAME ONE EVERYWHERE HERE
 *   **Every compile in this file is a compile to read.** Each turns a `device`
 *   block into a document so this module can be driven by it, none of them is
 *   going to run anything, and none has anywhere to put a script -- so every
 *   one passes `ncfg_hook_sink_unwritten()`, which is the sink 0258 exists for.
 *   The refusing sink is right at none of these sites, and
 *   `probe_test.c`'s last case is where the difference between the two is
 *   demonstrated rather than asserted.
 *
 * WHERE THE FIXTURES COME FROM
 *   Compiled from configuration text rather than built as struct literals, the
 *   way `probe_test.c` does it, so a `modem` block that stopped lowering would
 *   fail here rather than passing against a document the parser can no longer
 *   produce.
 */
#include "ncfg/apply.h"
#include "ncfg/base.h"
#include "ncfg/daemon.h"
#include "ncfg/hooks.h"
#include "ncfg/lower.h"
#include "ncfg/parse.h"

#include "testdir.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static void detail(const char *label, const char *text)
{
	printf("       %s: %s\n", label, text ? text : "(none)");
}

/* ---------------------------------------------------------- the fixtures */

/*
 * The document this text compiles to, read rather than acted on.
 *
 * `ncfg_hook_sink_unwritten()`: see the header comment. The question is "what
 * does this configuration say", never "put the scripts somewhere".
 */
static ncfg_document_t *compiled(const char *text)
{
	ncfg_ast_file_t *file = NULL;
	ncfg_source_t    source;
	ncfg_document_t *document;
	char             err[NCFG_ERROR_MAX];

	if (!ncfg_parse(text, strlen(text), &file, NULL, err, sizeof(err))) {
		printf("the fixture did not parse: %s\n%s", err, text);
		exit(1);
	}
	source.name = "netcfgd.conf";
	source.file = file;
	document = ncfg_compile(&source, 1u, ncfg_hook_sink_unwritten(), NULL, err, sizeof(err));
	ncfg_ast_file_free(file);
	if (!document) {
		printf("the fixture did not compile: %s\n%s", err, text);
		exit(1);
	}
	return document;
}

/* One `wwan0` with a modem policy. `sim` is a config list already spelled, or
 * NULL for a `modem` block that lists no source at all. */
static ncfg_document_t *modem_document(const char *sim, const char *apn)
{
	char text[1024];

	(void)snprintf(text, sizeof(text),
	    "device wwan0 {\n"
	    "\tmodem {\n"
	    "%s%s%s"
	    "%s%s%s"
	    "\t}\n"
	    "}\n",
	    sim ? "\t\tsim = [" : "", sim ? sim : "", sim ? "]\n" : "",
	    apn ? "\t\tapn = \"" : "", apn ? apn : "", apn ? "\"\n" : "");
	return compiled(text);
}

/* A run directory of this test's own, made fresh. */
static const char *run_directory(const char *base, const char *leaf, char *out, size_t out_size)
{
	(void)testdir_in(base, leaf, out, out_size);
	if (mkdir(out, 0755) != 0 && testdir_mode(out) < 0) {
		printf("could not make the run directory %s\n", out);
		exit(1);
	}
	return out;
}

/* What was published for `wwan0`, or NULL. The caller frees it. */
static char *published(const char *run_dir)
{
	char path[1024];

	(void)snprintf(path, sizeof(path), "%s/modem/wwan0", run_dir);
	return testdir_read(path, NULL);
}

/* Whether the published selection contains this line. */
static int says(const char *run_dir, const char *needle)
{
	char *body = published(run_dir);
	int   found = body && strstr(body, needle) != NULL;

	free(body);
	return found;
}

static ncfg_sims_t *sims_new(void)
{
	char         err[NCFG_ERROR_MAX];
	ncfg_sims_t *sims = ncfg_sims_new(err, sizeof(err));

	if (!sims) {
		printf("no SIM selection: %s\n", err);
		exit(1);
	}
	return sims;
}

/* Sync, which must not fail: every run directory here is one this test made. */
static void sync_it(ncfg_sims_t *sims, const ncfg_document_t *document, const char *run_dir)
{
	char err[NCFG_ERROR_MAX];

	if (!ncfg_sims_sync(sims, document, run_dir, err, sizeof(err))) {
		printf("the selection could not be published: %s\n", err);
		failures++;
	}
}

/* Advance, reporting the source it moved to or NULL. The call itself must
 * succeed; `*worked` says whether it did. */
static const char *advance(ncfg_sims_t *sims, const ncfg_document_t *document,
    const char *run_dir, int *worked)
{
	char        err[NCFG_ERROR_MAX];
	const char *moved = NULL;

	*worked = ncfg_sims_advance(sims, document, "wwan0", run_dir, &moved, err, sizeof(err));
	if (!*worked) {
		detail("refused", err);
	}
	return moved;
}

/* A report carrying only what a modem helper writes. The strings are
 * borrowed; nothing here outlives the call it is passed to. */
static ncfg_observed_report_t report_of(const char *interface, const char *iccid,
    const char *sim)
{
	ncfg_observed_report_t report;

	memset(&report, 0, sizeof(report));
	report.interface = (char *)(uintptr_t)(const void *)interface;
	report.iccid = (char *)(uintptr_t)(const void *)iccid;
	report.sim = (char *)(uintptr_t)(const void *)sim;
	return report;
}

static void observe(ncfg_sims_t *sims, const ncfg_document_t *document,
    const ncfg_observed_report_t *report)
{
	char err[NCFG_ERROR_MAX];

	if (!ncfg_sims_observe(sims, document, report, 1u, err, sizeof(err))) {
		printf("a report could not be taken in: %s\n", err);
		failures++;
	}
}

/* The status of the one modem, which every case below has exactly one of. */
static ncfg_proto_modem_t *status_of(const ncfg_sims_t *sims, const ncfg_document_t *document,
    size_t *count_out)
{
	char                err[NCFG_ERROR_MAX];
	ncfg_proto_modem_t *modems = NULL;

	if (!ncfg_sims_status(sims, document, &modems, count_out, err, sizeof(err))) {
		printf("the status could not be built: %s\n", err);
		failures++;
	}
	return modems;
}

/* A journal holding one record for `wwan0` with the given outcome. */
static void one_record(ncfg_journal_t *journal, const char *interface, int outcome)
{
	ncfg_record_t record;

	memset(&record, 0, sizeof(record));
	record.id = 1;
	record.op = "link.down";
	record.interface = interface;
	record.reason.interface = interface;
	record.reason.field = "modem.sim";
	record.reason.desired = "b";
	record.reason.observed = "<absent>";
	record.outcome = outcome;
	ncfg_journal_push(journal, &record);
}

/* ------------------------------------------------------- what is published */

static void the_first_source_is_chosen_and_published(const char *base)
{
	char             run[1024];
	ncfg_document_t *document = modem_document("\"esim\", \"socket\"", "im.cxn");
	ncfg_sims_t     *sims = sims_new();
	char            *body;

	sync_it(sims, document, run_directory(base, "first", run, sizeof(run)));
	body = published(run);
	check(body != NULL, "a modem device gets a selection file");
	check(says(run, "sim=esim"), "  naming the first source in the operator's list");
	check(says(run, "apn=im.cxn"), "  and the APN beside it");
	detail("published", body);
	free(body);

	ncfg_sims_free(sims);
	ncfg_document_free(document);
}

/*
 * A modem block with no sources still publishes, so a hook can read the file
 * unconditionally rather than having to tell "not written yet" from "this
 * device has no modem policy".
 */
static void a_modem_with_no_sources_still_publishes_its_apn(const char *base)
{
	char             run[1024];
	ncfg_document_t *document = modem_document(NULL, "im.cxn");
	ncfg_sims_t     *sims = sims_new();
	char            *body;

	sync_it(sims, document, run_directory(base, "sourceless", run, sizeof(run)));
	body = published(run);
	check(body != NULL, "a modem that lists no source still publishes a file");
	check(says(run, "apn=im.cxn"), "  with the APN");
	check(body && !strstr(body, "sim="), "  and no `sim` line, because there is no source");
	detail("published", body);
	free(body);

	ncfg_sims_free(sims);
	ncfg_document_free(document);
}

/*
 * The write leaves nothing behind.
 *
 * `ncfg_write_atomically` stages under a dotted name carrying the writer's pid
 * and a sequence number and renames it into place, so the only thing in the
 * directory afterwards is the selection itself. The Rust stages at
 * `<name>.tmp`, a fixed path every writer shares -- which is the defect
 * `state.h` records, and this is the check that would notice it coming back.
 */
static void publishing_leaves_no_staging_file_behind(const char *base)
{
	char             run[1024];
	/* Room for the run directory and a leaf, so the gate's truncation warning
	 * is answered rather than silenced. */
	char             directory[2048];
	ncfg_document_t *document = modem_document("\"esim\", \"socket\"", NULL);
	ncfg_sims_t     *sims = sims_new();
	DIR             *open_dir;
	const struct dirent *found;
	int              others = 0;
	int              worked;

	sync_it(sims, document, run_directory(base, "staging", run, sizeof(run)));
	(void)advance(sims, document, run, &worked);
	sync_it(sims, document, run);

	(void)snprintf(directory, sizeof(directory), "%s/modem", run);
	open_dir = opendir(directory);
	check(open_dir != NULL, "the selections live in a `modem` directory");
	while (open_dir && (found = readdir(open_dir)) != NULL) {
		if (strcmp(found->d_name, ".") == 0 || strcmp(found->d_name, "..") == 0 ||
		    strcmp(found->d_name, "wwan0") == 0) {
			continue;
		}
		others++;
		detail("left behind", found->d_name);
	}
	if (open_dir) {
		(void)closedir(open_dir);
	}
	check(others == 0, "  and three writes leave the selection and nothing else");

	ncfg_sims_free(sims);
	ncfg_document_free(document);
}

/* ------------------------------------------------------------ advancing */

/* The whole of 0152's second answer: the last source is where it stops. */
static void advancing_stops_at_the_last_source_rather_than_wrapping(const char *base)
{
	char             run[1024];
	ncfg_document_t *document = modem_document("\"esim\", \"socket\"", NULL);
	ncfg_sims_t     *sims = sims_new();
	const char      *moved;
	int              worked;

	sync_it(sims, document, run_directory(base, "advance", run, sizeof(run)));

	moved = advance(sims, document, run, &worked);
	check(worked && moved && strcmp(moved, "socket") == 0, "advancing moves to the next source");
	check(says(run, "sim=socket"), "  and publishes it");

	/* And again: nowhere to go, and it stays where it ended rather than
	 * returning to `esim` and resetting the modem for ever. */
	moved = advance(sims, document, run, &worked);
	check(worked, "advancing off the end is an answer rather than a failure");
	check(moved == NULL, "  which names no source");
	check(ncfg_sims_current(sims, document, "wwan0") &&
	        strcmp(ncfg_sims_current(sims, document, "wwan0"), "socket") == 0,
	    "  and leaves it on the last source");

	ncfg_sims_free(sims);
	ncfg_document_free(document);
}

/* A single source is a list of one, not a special case. */
static void one_source_has_nowhere_to_advance_to(const char *base)
{
	char             run[1024];
	ncfg_document_t *document = modem_document("\"socket\"", NULL);
	ncfg_sims_t     *sims = sims_new();
	const char      *moved;
	int              worked;

	sync_it(sims, document, run_directory(base, "one", run, sizeof(run)));
	moved = advance(sims, document, run, &worked);
	check(worked && moved == NULL, "one source is a list of one and has nowhere to go");

	ncfg_sims_free(sims);
	ncfg_document_free(document);
}

/*
 * **A device this configuration gives no modem policy is refused by name.**
 *
 * The Rust answers `None` here, to the same caller and in the same word it
 * uses for "there is nowhere to go" -- so a typo in a device name reads as a
 * modem that has run out of SIMs, which is the one thing a caller acts on. The
 * two are separate answers here.
 */
static void advancing_a_device_with_no_modem_policy_is_refused_by_name(const char *base)
{
	char             run[1024];
	ncfg_document_t *document = modem_document("\"esim\", \"socket\"", NULL);
	ncfg_sims_t     *sims = sims_new();
	const char      *moved = NULL;
	char             err[NCFG_ERROR_MAX];

	sync_it(sims, document, run_directory(base, "stranger", run, sizeof(run)));
	check(!ncfg_sims_advance(sims, document, "wwan9", run, &moved, err, sizeof(err)),
	    "advancing a device the configuration does not describe is refused");
	check(moved == NULL, "  with no source named");
	check(strstr(err, "wwan9") != NULL, "  and the refusal says which device");
	detail("refusal", err);

	ncfg_sims_free(sims);
	ncfg_document_free(document);
}

/* ------------------------------------------------------------- reloading */

/* A reload must not take a machine back to the first source: that would be a
 * SIM switch nobody asked for, triggered by an unrelated edit. */
static void a_reload_keeps_the_source_that_is_in_use(const char *base)
{
	char             run[1024];
	ncfg_document_t *document = modem_document("\"esim\", \"socket\"", NULL);
	ncfg_sims_t     *sims = sims_new();
	int              worked;

	sync_it(sims, document, run_directory(base, "reload", run, sizeof(run)));
	(void)advance(sims, document, run, &worked);

	sync_it(sims, document, run);
	check(ncfg_sims_current(sims, document, "wwan0") &&
	        strcmp(ncfg_sims_current(sims, document, "wwan0"), "socket") == 0,
	    "a reload keeps the source that is in use");
	check(says(run, "sim=socket"), "  and republishes it rather than the first");

	ncfg_sims_free(sims);
	ncfg_document_free(document);
}

/* Shortening the list moves a device to the last source that still exists,
 * rather than silently back to the first. */
static void a_shortened_list_clamps_rather_than_resetting(const char *base)
{
	char             run[1024];
	ncfg_document_t *lengthy = modem_document("\"esim\", \"socket\", \"spare\"", NULL);
	ncfg_document_t *shorter = modem_document("\"esim\", \"socket\"", NULL);
	ncfg_sims_t     *sims = sims_new();
	int              worked;

	sync_it(sims, lengthy, run_directory(base, "clamp", run, sizeof(run)));
	(void)advance(sims, lengthy, run, &worked);
	(void)advance(sims, lengthy, run, &worked);
	check(ncfg_sims_current(sims, lengthy, "wwan0") &&
	        strcmp(ncfg_sims_current(sims, lengthy, "wwan0"), "spare") == 0,
	    "two advances reach the third source");

	sync_it(sims, shorter, run);
	check(ncfg_sims_current(sims, shorter, "wwan0") &&
	        strcmp(ncfg_sims_current(sims, shorter, "wwan0"), "socket") == 0,
	    "  and shortening the list clamps to the last that still exists");
	check(says(run, "sim=socket"), "  which is what the hook reads");

	ncfg_sims_free(sims);
	ncfg_document_free(lengthy);
	ncfg_document_free(shorter);
}

/* A device that loses its modem block takes its file with it. A stale
 * selection is read as current by a hook that has no other source. */
static void a_device_that_leaves_the_document_loses_its_file(const char *base)
{
	char                   run[1024];
	/* Room for the run directory and a leaf. */
	char                   path[2048];
	ncfg_document_t       *document = modem_document("\"esim\", \"socket\"", NULL);
	ncfg_document_t       *empty = compiled("global {\n\thostname = \"box\"\n}\n");
	ncfg_sims_t           *sims = sims_new();
	ncfg_observed_report_t seen = report_of("wwan0", "8946000000000000006", "esim");
	ncfg_proto_modem_t    *modems;
	size_t                 count = 0;

	sync_it(sims, document, run_directory(base, "gone", run, sizeof(run)));
	observe(sims, document, &seen);
	(void)snprintf(path, sizeof(path), "%s/modem/wwan0", run);
	check(testdir_exists(path), "a modem device has a selection file");

	sync_it(sims, empty, run);
	check(!testdir_exists(path), "  and loses it when it leaves the document");

	/*
	 * **And its cards go with it.** The Rust removes the selection and the
	 * cycle note and leaves `cards` alone, so a device edited out and put back
	 * comes back carrying an ICCID read before it left -- which is a confident
	 * wrong answer to the one question this table exists to settle, since a
	 * card can be swapped while a device is out of the configuration. The
	 * cards are derived state about hardware this daemon has stopped tracking,
	 * and they are derived again the first time a helper reports one.
	 */
	sync_it(sims, document, run);
	modems = status_of(sims, document, &count);
	check(modems && count == 1u && modems[0].card_count == 0u,
	    "  and a device that comes back does not bring an old card with it");
	ncfg_sims_status_free(modems, count);

	ncfg_sims_free(sims);
	ncfg_document_free(document);
	ncfg_document_free(empty);
}

/* ---------------------------------------------------------------- cards */

/*
 * A report naming its source is what pairs a card with a SIM.
 *
 * **And the pairing must not come from the current selection.** netcfgd
 * publishes a new source the instant it advances, while the module is still
 * reading the old card -- so a status that paired its own selection with
 * whatever ICCID last appeared would file one card under the other's name at
 * exactly the moment a source changed, which is the only moment anyone looks.
 * This drives that window directly: advance to `socket`, then deliver a report
 * that still says `esim`, and check the card lands on `esim`.
 */
static void a_card_is_filed_under_the_source_the_report_names(const char *base)
{
	char                   run[1024];
	ncfg_document_t       *document = modem_document("\"esim\", \"socket\"", NULL);
	ncfg_sims_t           *sims = sims_new();
	ncfg_observed_report_t stale = report_of("wwan0", "8946000000000000001", "esim");
	ncfg_observed_report_t fresh = report_of("wwan0", "8946000000000000002", "socket");
	ncfg_proto_modem_t    *modems;
	size_t                 count = 0;
	int                    worked;

	sync_it(sims, document, run_directory(base, "cards", run, sizeof(run)));
	observe(sims, document, &stale);

	/* The advance happens, and the module has not caught up with it. */
	(void)advance(sims, document, run, &worked);
	check(ncfg_sims_current(sims, document, "wwan0") &&
	        strcmp(ncfg_sims_current(sims, document, "wwan0"), "socket") == 0,
	    "the selection has moved on");
	observe(sims, document, &stale);

	modems = status_of(sims, document, &count);
	check(count == 1u && modems, "one modem is reported");
	if (modems && count == 1u) {
		check(modems[0].card_count == 1u, "  one card seen, not one per listed source");
		check(modems[0].card_count == 1u &&
		        ncfg_proto_str_equals(modems[0].cards[0].source, "esim"),
		    "  and it is filed under the source the report named, not the current one");
		check(modems[0].card_count == 1u &&
		        ncfg_proto_str_equals(modems[0].cards[0].iccid, "8946000000000000001"),
		    "  with the ICCID the helper read");
	}
	ncfg_sims_status_free(modems, count);

	/* And once the module does catch up, the second card joins the first
	 * rather than replacing it: both are now known, which is the whole point
	 * of remembering them. */
	observe(sims, document, &fresh);
	modems = status_of(sims, document, &count);
	check(modems && count == 1u && modems[0].card_count == 2u,
	    "a card in the other source joins the first rather than replacing it");
	if (modems && count == 1u && modems[0].card_count == 2u) {
		check(ncfg_proto_str_equals(modems[0].cards[0].source, "esim") &&
		        ncfg_proto_str_equals(modems[0].cards[1].source, "socket"),
		    "  in the document's order, so two runs print the same thing");
	}
	ncfg_sims_status_free(modems, count);

	ncfg_sims_free(sims);
	ncfg_document_free(document);
}

/*
 * An unpaired card is not guessed at, and a source not in the document is not
 * resurrected by a stale report.
 */
static void a_card_with_no_source_and_a_source_with_no_entry_are_both_ignored(const char *base)
{
	char                   run[1024];
	ncfg_document_t       *document = modem_document("\"esim\", \"socket\"", NULL);
	ncfg_sims_t           *sims = sims_new();
	ncfg_observed_report_t unpaired = report_of("wwan0", "8946000000000000003", NULL);
	ncfg_observed_report_t forgotten = report_of("wwan0", "8946000000000000004", "spare");
	ncfg_observed_report_t control = report_of("wwan0", "8946000000000000005", "socket");
	ncfg_proto_modem_t    *modems;
	size_t                 count = 0;

	sync_it(sims, document, run_directory(base, "unpaired", run, sizeof(run)));

	/* An older helper reports the card and not the source. Nothing to do with
	 * it: an ICCID with no idea which source it belongs to is a fact netcfgd
	 * cannot use, and the current selection is not the answer. */
	observe(sims, document, &unpaired);
	modems = status_of(sims, document, &count);
	check(modems && count == 1u && modems[0].card_count == 0u,
	    "a card with no source is not guessed at");
	ncfg_sims_status_free(modems, count);

	/* A source the document no longer lists, which is what a report left
	 * behind by an earlier configuration looks like. */
	observe(sims, document, &forgotten);
	modems = status_of(sims, document, &count);
	check(modems && count == 1u && modems[0].card_count == 0u,
	    "  and a source the document does not list is not resurrected");
	ncfg_sims_status_free(modems, count);

	/* The control, from the other side: the same call with a source that *is*
	 * listed does record, so the two refusals above are about the input rather
	 * than about `observe` never working. */
	observe(sims, document, &control);
	modems = status_of(sims, document, &count);
	check(modems && count == 1u && modems[0].card_count == 1u,
	    "  while a listed source is recorded, so neither refusal is vacuous");
	ncfg_sims_status_free(modems, count);

	ncfg_sims_free(sims);
	ncfg_document_free(document);
}

/* --------------------------------------------------------------- status */

/*
 * What the socket answers: the preference and the selection as separate facts.
 *
 * Collapsing them into one "current SIM" would lose the question an operator
 * actually has when a modem will not attach -- whether it is on the source they
 * asked for, or has fallen through to a spare.
 */
static void the_status_reports_the_preference_and_the_choice_apart(const char *base)
{
	char                run[1024];
	ncfg_document_t    *document = modem_document("\"esim\", \"socket\"", "im.cxn");
	ncfg_sims_t        *sims = sims_new();
	ncfg_proto_modem_t *modems;
	size_t              count = 0;
	int                 worked;

	sync_it(sims, document, run_directory(base, "status", run, sizeof(run)));

	modems = status_of(sims, document, &count);
	check(count == 1u && modems && ncfg_proto_str_equals(modems[0].device, "wwan0"),
	    "the status names the device");
	if (modems && count == 1u) {
		check(modems[0].sim.count == 2u &&
		        ncfg_proto_str_equals(modems[0].sim.items[0], "esim") &&
		        ncfg_proto_str_equals(modems[0].sim.items[1], "socket"),
		    "  and carries the operator's list in the operator's order");
		check(ncfg_proto_str_equals(modems[0].selected, "esim"), "  with the selection apart");
		check(ncfg_proto_str_equals(modems[0].apn, "im.cxn"), "  and the APN");
		check(!modems[0].cycle_pending, "  and nothing waiting to be cycled");
	}
	ncfg_sims_status_free(modems, count);

	(void)advance(sims, document, run, &worked);
	modems = status_of(sims, document, &count);
	if (modems && count == 1u) {
		/* The preference has not moved and must not: it is the operator's, and
		 * constraint 1 is that netcfgd never rewrites it. */
		check(modems[0].sim.count == 2u &&
		        ncfg_proto_str_equals(modems[0].sim.items[0], "esim") &&
		        ncfg_proto_str_equals(modems[0].sim.items[1], "socket"),
		    "an advance leaves the operator's list exactly as it was");
		check(ncfg_proto_str_equals(modems[0].selected, "socket"),
		    "  and moves only the selection");
		/* Advanced but not yet cycled, which is "netcfgd wants the other SIM"
		 * rather than "the machine is on it". */
		check(modems[0].cycle_pending != 0, "  with the cycle still pending");
	}
	ncfg_sims_status_free(modems, count);

	ncfg_sims_free(sims);
	ncfg_document_free(document);
}

/* A daemon that has not compiled a document yet answers with a list rather
 * than an error: no configuration is a state. */
static void the_status_of_no_document_is_empty(void)
{
	ncfg_sims_t        *sims = sims_new();
	ncfg_proto_modem_t *modems = NULL;
	size_t              count = 1u;
	char                err[NCFG_ERROR_MAX];

	check(ncfg_sims_status(sims, NULL, &modems, &count, err, sizeof(err)),
	    "the status of no document is an answer rather than an error");
	check(count == 0u && modems == NULL, "  and it is empty");
	ncfg_sims_status_free(modems, count);
	ncfg_sims_free(sims);
}

/* --------------------------------------------------------------- cycling */

/*
 * A cycle that failed keeps its note, so the next apply tries again.
 *
 * Both Rust call sites cleared every note the moment `apply` returned, and
 * `apply` returns a journal rather than a result -- so a `link.down` that
 * failed forgot the note and nothing retried, leaving the modem on its old
 * source with the new one published and `pre_up` never fired.
 */
static void a_cycle_that_failed_keeps_its_note(const char *base)
{
	char             run[1024];
	ncfg_document_t *document = modem_document("\"a\", \"b\"", NULL);
	ncfg_sims_t     *sims = sims_new();
	ncfg_journal_t   journal;
	const char      *waiting[4];
	size_t           count;
	size_t           at;
	const char      *moved;
	int              worked;

	sync_it(sims, document, run_directory(base, "cycle", run, sizeof(run)));
	moved = advance(sims, document, run, &worked);
	check(worked && moved && strcmp(moved, "b") == 0, "an advance leaves a note");

	/* The list the reconcile loop takes before it plans, which points straight
	 * into this module's own storage -- exactly the aliasing `ncfg_sims_cycled`
	 * is written to survive. */
	count = ncfg_sims_pending_count(sims);
	check(count == 1u, "  and the note is the one thing waiting");
	for (at = 0; at < count && at < 4u; at++) {
		waiting[at] = ncfg_sims_pending_at(sims, at);
	}
	check(count == 1u && waiting[0] && strcmp(waiting[0], "wwan0") == 0,
	    "  named as the device");

	ncfg_journal_init(&journal);
	one_record(&journal, "wwan0", NCFG_OUTCOME_FAILED);
	ncfg_sims_cycled(sims, waiting, count, &journal);
	check(ncfg_sims_is_pending(sims, "wwan0"),
	    "a cycle whose link.down failed is still waiting");
	ncfg_journal_free(&journal);

	/* And the note goes once the cycle really happened, or every later apply
	 * would take a working link down and up again. */
	ncfg_journal_init(&journal);
	one_record(&journal, "wwan0", NCFG_OUTCOME_DONE);
	ncfg_sims_cycled(sims, waiting, count, &journal);
	check(!ncfg_sims_is_pending(sims, "wwan0"), "  and a cycle that ran is finished with");
	check(ncfg_sims_pending_count(sims) == 0u, "  with nothing left waiting");
	ncfg_journal_free(&journal);

	ncfg_sims_free(sims);
	ncfg_document_free(document);
}

/*
 * An unrelated failure elsewhere in the plan does not hold the note.
 *
 * The condition is per device rather than per plan: clearing on a whole-plan
 * success would keep the note alive whenever a wifi backend or an unrelated
 * address failed, and every apply after would flap a link that had already
 * switched.
 */
static void a_failure_on_another_interface_does_not_hold_the_note(const char *base)
{
	char             run[1024];
	ncfg_document_t *document = modem_document("\"a\", \"b\"", NULL);
	ncfg_sims_t     *sims = sims_new();
	ncfg_journal_t   journal;
	const char      *waiting[1];
	ncfg_record_t    other;
	int              worked;

	sync_it(sims, document, run_directory(base, "mixed", run, sizeof(run)));
	(void)advance(sims, document, run, &worked);
	waiting[0] = ncfg_sims_pending_at(sims, 0);

	ncfg_journal_init(&journal);
	one_record(&journal, "wwan0", NCFG_OUTCOME_DONE);
	memset(&other, 0, sizeof(other));
	other.id = 2;
	other.op = "backend.start";
	other.interface = "wlan0";
	other.reason.interface = "wlan0";
	other.reason.field = "backend";
	other.reason.desired = "supplicant";
	other.reason.observed = "<absent>";
	other.outcome = NCFG_OUTCOME_FAILED;
	other.error = "no supplicant";
	ncfg_journal_push(&journal, &other);

	ncfg_sims_cycled(sims, waiting, 1u, &journal);
	check(!ncfg_sims_is_pending(sims, "wwan0"),
	    "another interface's failure is not this one's, and the note goes");
	ncfg_journal_free(&journal);

	ncfg_sims_free(sims);
	ncfg_document_free(document);
}

/*
 * A device with no records at all clears.
 *
 * That is the right answer rather than an oversight: the planner emits a cycle
 * only for a link that is *up*, because a link that is down runs `pre_up` on
 * its way up regardless. No records means no cycle was needed.
 */
static void a_device_no_record_mentions_clears_its_note(const char *base)
{
	char             run[1024];
	ncfg_document_t *document = modem_document("\"a\", \"b\"", NULL);
	ncfg_sims_t     *sims = sims_new();
	ncfg_journal_t   journal;
	const char      *waiting[1];
	int              worked;

	sync_it(sims, document, run_directory(base, "empty", run, sizeof(run)));
	(void)advance(sims, document, run, &worked);
	waiting[0] = ncfg_sims_pending_at(sims, 0);

	ncfg_journal_init(&journal);
	ncfg_sims_cycled(sims, waiting, 1u, &journal);
	check(!ncfg_sims_is_pending(sims, "wwan0"),
	    "a device an empty journal does not mention needed no cycle, so the note goes");
	ncfg_journal_free(&journal);

	ncfg_sims_free(sims);
	ncfg_document_free(document);
}

int main(void)
{
	const char *base = testdir_make("sim");

	the_first_source_is_chosen_and_published(base);
	a_modem_with_no_sources_still_publishes_its_apn(base);
	publishing_leaves_no_staging_file_behind(base);

	advancing_stops_at_the_last_source_rather_than_wrapping(base);
	one_source_has_nowhere_to_advance_to(base);
	advancing_a_device_with_no_modem_policy_is_refused_by_name(base);

	a_reload_keeps_the_source_that_is_in_use(base);
	a_shortened_list_clamps_rather_than_resetting(base);
	a_device_that_leaves_the_document_loses_its_file(base);

	a_card_is_filed_under_the_source_the_report_names(base);
	a_card_with_no_source_and_a_source_with_no_entry_are_both_ignored(base);

	the_status_reports_the_preference_and_the_choice_apart(base);
	the_status_of_no_document_is_empty();

	a_cycle_that_failed_keeps_its_note(base);
	a_failure_on_another_interface_does_not_hold_the_note(base);
	a_device_no_record_mentions_clears_its_note(base);

	testdir_remove(base);
	if (failures == 0) {
		printf("sim_test: all checks passed\n");
	} else {
		printf("sim_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
