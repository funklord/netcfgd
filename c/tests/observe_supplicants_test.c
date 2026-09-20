/*
 * observe_supplicants_test.c -- what a running supplicant holds, and whether
 * it answers.
 *
 * THE THREE ANSWERS, AND WHY THE THIRD MATTERS MOST
 *   `answering` and `networks_match` are this pass's own. The third --
 *   `ncfg_observed_link_t::network` -- is the one other rules were already
 *   written against: `ncfg_observed_effective_metric` decides a route's metric
 *   from the network a radio is associated to, and nothing in this port wrote
 *   that field, so the rule always fell through to the interface's
 *   `preference`. A case here drives it end to end.
 *
 * WHAT THE FAKE IS POINTED AT
 *   `NCFG_WPA_CTRL_DIR`, which exists for exactly this: a network namespace is
 *   not a mount namespace, so without it a test would share
 *   `/run/wpa_supplicant` with whatever the machine is running. The fake is
 *   `hostapdfake.h`'s -- one stand-in for the control protocol, because the two
 *   daemons speak it and two fakes would be two beliefs about it.
 */
#include "ncfg/base.h"
#include "ncfg/observe.h"
#include "ncfg/service.h"
#include "ncfg/supplicant.h"

#include "hostapdfake.h"
#include "testdir.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks;
static int failures;

static void check(int condition, const char *what)
{
	checks++;
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static const char *base;
static char        run_dir[512];
static char        ctrl_dir[512];

#define PATIENCE_MS 400

/* `cafe`, as the model spells an SSID: lowercase hex of the octets. */
#define CAFE_HEX "63616665"

static ncfg_observed_t *observed_of(const char *body)
{
	char             text[1024];
	char             message[NCFG_ERROR_MAX];
	ncfg_observed_t *observed;

	(void)snprintf(text, sizeof(text), "{%s}", body);
	message[0] = '\0';
	observed = ncfg_observed_read(text, strlen(text), message, sizeof(message));
	if (!observed) {
		printf("  fixture observation did not read: %s\n", message);
	}
	return observed;
}

/* One supplicant on `wlan0`, with a link for it to write a network onto. */
#define ONE_SUPPLICANT \
	"\"links\":[{\"name\":\"wlan0\",\"index\":2,\"mtu\":1500,\"up\":true," \
	"\"carrier\":true,\"ownership\":\"unknown\"}]," \
	"\"backends\":[{\"kind\":\"supplicant\",\"interface\":\"wlan0\",\"running\":true}]"

static ncfg_document_t *document_of(const char *networks)
{
	char             text[2048];
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document;

	(void)snprintf(text, sizeof(text),
	    "{\"schema_version\":{\"major\":1,\"minor\":1},\"generated_by\":\"supplicants_test\","
	    "\"globals\":{},\"devices\":[{\"name\":\"wlan0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[],\"networks\":[%s]}", networks);
	message[0] = '\0';
	document = ncfg_document_read(text, strlen(text), message, sizeof(message));
	if (!document) {
		printf("  fixture document did not read: %s\n", message);
	}
	return document;
}

#define CAFE_NETWORK \
	"{\"id\":\"cafe\",\"ssid\":\"" CAFE_HEX "\",\"security\":{\"type\":\"open\"}," \
	"\"metric\":100}"

/*
 * Write the record the executor would have written.
 *
 * Through `ncfg_supplicant_fingerprint` and `ncfg_service_radio_policy`, which
 * is what the executor uses -- so this fixture cannot disagree with it about
 * what was handed over, which is the whole property `networks_match` rests on.
 */
static int record_for(const ncfg_document_t *document, const char *text)
{
	char path[640];
	char dir[640];
	char digest[NCFG_SUPPLICANT_SSID_HEX_SIZE];
	int  mac_policy = 0;
	int  randomise = 0;
	int  joins = 0;

	(void)snprintf(dir, sizeof(dir), "%s/supplicant", run_dir);
	testdir_mkdirp(dir);
	if (!ncfg_service_networks_record_path(run_dir, "wlan0", path, sizeof(path), NULL, 0)) {
		return 0;
	}
	if (text) {
		return testdir_write(path, text, strlen(text));
	}
	ncfg_service_radio_policy(document, "wlan0", &mac_policy, &randomise, &joins);
	if (!ncfg_supplicant_fingerprint(document->networks, document->network_count, mac_policy,
	    randomise, joins, NULL, digest, NULL, 0)) {
		return 0;
	}
	return testdir_write(path, digest, strlen(digest));
}

static void forget_record(void)
{
	char path[640];

	if (ncfg_service_networks_record_path(run_dir, "wlan0", path, sizeof(path), NULL, 0)) {
		(void)unlink(path);
	}
}

static const ncfg_observed_backend_t *only(const ncfg_observed_t *observed)
{
	return observed && observed->backend_count >= 1u ? &observed->backends[0] : NULL;
}

/* ------------------------------------------------------------------------ *
 * The cases
 * ------------------------------------------------------------------------ */

static void a_supplicant_holding_what_the_document_asks_for(void)
{
	ncfg_observed_t *observed = observed_of(ONE_SUPPLICANT);
	ncfg_document_t *document = document_of(CAFE_NETWORK);
	char             message[NCFG_ERROR_MAX];

	if (!observed || !document) {
		check(0, "the fixtures for a matching supplicant read");
		ncfg_observed_free(observed);
		ncfg_document_free(document);
		return;
	}
	memset(&fake_config, 0, sizeof(fake_config));
	(void)snprintf(fake_config.networks[0], sizeof(fake_config.networks[0]), "cafe");
	fake_config.network_count = 1u;
	check(fake_start(ctrl_dir, "wlan0") && record_for(document, NULL),
	    "a fake supplicant is listening and netcfgd's record is beside it");

	message[0] = '\0';
	check(ncfg_observe_supplicants(observed, run_dir, NULL, document, PATIENCE_MS, message,
	    sizeof(message)), "the round runs");
	check(only(observed) && only(observed)->answering.has && only(observed)->answering.value,
	    "  a supplicant that answers is recorded as answering");
	/*
	 * **The check that stops the rest being vacuous.** The record is a digest
	 * of what the executor would hand over, computed here the same way -- if
	 * the two ever stopped agreeing, `networks_match` would be false for ever
	 * and the planner would re-hand the whole set on every reconcile.
	 */
	check(only(observed) && only(observed)->networks_match.has &&
	    only(observed)->networks_match.value,
	    "  and the record says it is holding what the document asks for");
	fake_stop();
	ncfg_observed_free(observed);
	ncfg_document_free(document);
}

static void a_record_of_some_other_set_does_not_match(void)
{
	ncfg_observed_t *observed = observed_of(ONE_SUPPLICANT);
	ncfg_document_t *document = document_of(CAFE_NETWORK);
	char             message[NCFG_ERROR_MAX];

	if (!observed || !document) {
		check(0, "the fixtures for a stale record read");
		ncfg_observed_free(observed);
		ncfg_document_free(document);
		return;
	}
	memset(&fake_config, 0, sizeof(fake_config));
	(void)snprintf(fake_config.networks[0], sizeof(fake_config.networks[0]), "cafe");
	fake_config.network_count = 1u;
	(void)fake_start(ctrl_dir, "wlan0");
	/* A digest of something else entirely, which is what the record of an
	 * earlier document looks like from here. */
	(void)record_for(document, "0000000000000000000000000000000000000000000000000000000000000000");
	message[0] = '\0';
	(void)ncfg_observe_supplicants(observed, run_dir, NULL, document, PATIENCE_MS, message,
	    sizeof(message));
	check(only(observed) && only(observed)->networks_match.has &&
	    !only(observed)->networks_match.value,
	    "a record of some other set is reported as not matching");
	fake_stop();
	ncfg_observed_free(observed);
	ncfg_document_free(document);
}

static void an_emptied_supplicant_refutes_its_own_record(void)
{
	ncfg_observed_t *observed = observed_of(ONE_SUPPLICANT);
	ncfg_document_t *document = document_of(CAFE_NETWORK);
	char             message[NCFG_ERROR_MAX];

	if (!observed || !document) {
		check(0, "the fixtures for an emptied supplicant read");
		ncfg_observed_free(observed);
		ncfg_document_free(document);
		return;
	}
	/*
	 * **0237's measurement.** The record is what netcfgd *did*, and it cannot
	 * see a supplicant emptied afterwards while staying reachable --
	 * `RECONFIGURE` re-reads a file which, for the one netcfgd writes, names
	 * no networks. So the record says "matching" and `LIST_NETWORKS` says the
	 * supplicant holds nothing, and the supplicant wins.
	 */
	memset(&fake_config, 0, sizeof(fake_config));
	fake_config.network_count = 0u;
	(void)fake_start(ctrl_dir, "wlan0");
	check(record_for(document, NULL), "the record still says netcfgd handed the set over");
	message[0] = '\0';
	(void)ncfg_observe_supplicants(observed, run_dir, NULL, document, PATIENCE_MS, message,
	    sizeof(message));
	check(only(observed) && only(observed)->networks_match.has &&
	    !only(observed)->networks_match.value,
	    "  and a supplicant holding nothing refutes it, which the record cannot");
	fake_stop();
	ncfg_observed_free(observed);
	ncfg_document_free(document);
}

static void no_record_says_nothing(void)
{
	ncfg_observed_t *observed = observed_of(ONE_SUPPLICANT);
	ncfg_document_t *document = document_of(CAFE_NETWORK);
	char             message[NCFG_ERROR_MAX];

	if (!observed || !document) {
		check(0, "the fixtures for a supplicant with no record read");
		ncfg_observed_free(observed);
		ncfg_document_free(document);
		return;
	}
	memset(&fake_config, 0, sizeof(fake_config));
	(void)snprintf(fake_config.networks[0], sizeof(fake_config.networks[0]), "cafe");
	fake_config.network_count = 1u;
	(void)fake_start(ctrl_dir, "wlan0");
	forget_record();
	message[0] = '\0';
	(void)ncfg_observe_supplicants(observed, run_dir, NULL, document, PATIENCE_MS, message,
	    sizeof(message));
	/* A supplicant netcfgd adopted rather than started, or a `/run` cleared
	 * under a running one, or a write that `record_networks` says is
	 * deliberately best effort. None of those is "differs". */
	check(only(observed) && !only(observed)->networks_match.has,
	    "a supplicant with no record says nothing, rather than that it differs");
	check(only(observed) && only(observed)->answering.has && only(observed)->answering.value,
	    "  and is still reported as answering, which is a different question");
	fake_stop();
	ncfg_observed_free(observed);
	ncfg_document_free(document);
}

static void the_network_a_radio_is_associated_to_is_written_down(void)
{
	ncfg_observed_t *observed = observed_of(ONE_SUPPLICANT);
	ncfg_document_t *document = document_of(CAFE_NETWORK);
	char             message[NCFG_ERROR_MAX];
	const ncfg_observed_link_t *link;

	if (!observed || !document) {
		check(0, "the fixtures for an associated radio read");
		ncfg_observed_free(observed);
		ncfg_document_free(document);
		return;
	}
	memset(&fake_config, 0, sizeof(fake_config));
	(void)snprintf(fake_config.associated, sizeof(fake_config.associated), "cafe");
	(void)fake_start(ctrl_dir, "wlan0");
	message[0] = '\0';
	(void)ncfg_observe_supplicants(observed, run_dir, NULL, document, PATIENCE_MS, message,
	    sizeof(message));
	link = ncfg_observed_link(observed, "wlan0");
	/*
	 * **The field three rules were already written against.**
	 * `ncfg_observed_effective_metric` decides a route's metric from it,
	 * `inventory.c` names the network an interface is on, and `derive.c` reads
	 * it -- and nothing in this port wrote it, so a route took the interface's
	 * `preference` where its network named a metric.
	 */
	check(link && link->network && strcmp(link->network, "cafe") == 0,
	    "the network a radio is associated to is written onto its link");
	fake_stop();
	ncfg_observed_free(observed);
	ncfg_document_free(document);
}

static void a_network_the_document_does_not_have_is_not_named(void)
{
	ncfg_observed_t *observed = observed_of(ONE_SUPPLICANT);
	ncfg_document_t *document = document_of(CAFE_NETWORK);
	char             message[NCFG_ERROR_MAX];
	const ncfg_observed_link_t *link;

	if (!observed || !document) {
		check(0, "the fixtures for an unknown association read");
		ncfg_observed_free(observed);
		ncfg_document_free(document);
		return;
	}
	memset(&fake_config, 0, sizeof(fake_config));
	(void)snprintf(fake_config.associated, sizeof(fake_config.associated), "somebody-elses");
	(void)fake_start(ctrl_dir, "wlan0");
	message[0] = '\0';
	(void)ncfg_observe_supplicants(observed, run_dir, NULL, document, PATIENCE_MS, message,
	    sizeof(message));
	link = ncfg_observed_link(observed, "wlan0");
	/* Every reader of this field asks it about a network the document has, so
	 * naming one it does not would be a value nothing can resolve. */
	check(link && link->network == NULL,
	    "a radio on a network the document does not describe names none");
	fake_stop();
	ncfg_observed_free(observed);
	ncfg_document_free(document);
}

static void the_answer_lands_on_the_supplicant_and_not_the_client(void)
{
	/*
	 * **By kind as well as by interface.** One interface carries several
	 * backends, and matching on the name alone puts the supplicant's answer on
	 * whichever sorts first -- which the Rust records having done. The DHCP
	 * client is listed first here on purpose.
	 */
	ncfg_observed_t *observed = observed_of(
	    "\"links\":[],\"backends\":["
	    "{\"kind\":\"dhcp4\",\"interface\":\"wlan0\",\"running\":true},"
	    "{\"kind\":\"supplicant\",\"interface\":\"wlan0\",\"running\":true}]");
	ncfg_document_t *document = document_of(CAFE_NETWORK);
	char             message[NCFG_ERROR_MAX];

	if (!observed || !document) {
		check(0, "the fixtures for two backends on one interface read");
		ncfg_observed_free(observed);
		ncfg_document_free(document);
		return;
	}
	memset(&fake_config, 0, sizeof(fake_config));
	(void)fake_start(ctrl_dir, "wlan0");
	message[0] = '\0';
	(void)ncfg_observe_supplicants(observed, run_dir, NULL, document, PATIENCE_MS, message,
	    sizeof(message));
	check(observed->backend_count == 2u && observed->backends[1].answering.has &&
	    observed->backends[1].answering.value,
	    "the supplicant on the interface is the one recorded as answering");
	check(observed->backend_count == 2u && !observed->backends[0].answering.has,
	    "  and the DHCP client beside it is left alone, though it sorts first");
	fake_stop();
	ncfg_observed_free(observed);
	ncfg_document_free(document);
}

static void nothing_listening_is_not_answering(void)
{
	ncfg_observed_t *observed = observed_of(ONE_SUPPLICANT);
	ncfg_document_t *document = document_of(CAFE_NETWORK);
	char             message[NCFG_ERROR_MAX];

	if (!observed || !document) {
		check(0, "the fixtures for an absent supplicant read");
		ncfg_observed_free(observed);
		ncfg_document_free(document);
		return;
	}
	(void)record_for(document, NULL);
	message[0] = '\0';
	check(ncfg_observe_supplicants(observed, run_dir, NULL, document, PATIENCE_MS, message,
	    sizeof(message)), "a supplicant nothing is listening for is not a failure");
	check(only(observed) && only(observed)->answering.has && !only(observed)->answering.value,
	    "  and is reported as not answering");
	/* And nothing is concluded about what it holds. The record is there and
	 * says "matching" -- but a daemon netcfgd cannot reach is not one whose
	 * contents are worth reporting. */
	check(only(observed) && !only(observed)->networks_match.has,
	    "  and nothing is concluded about what it holds, record or no record");
	ncfg_observed_free(observed);
	ncfg_document_free(document);
}

static void the_round_refuses_what_it_cannot_be_asked(void)
{
	ncfg_observed_t *observed = observed_of(ONE_SUPPLICANT);
	char             message[NCFG_ERROR_MAX];

	message[0] = '\0';
	check(!ncfg_observe_supplicants(NULL, run_dir, NULL, NULL, PATIENCE_MS, message,
	    sizeof(message)) && message[0] != '\0',
	    "no observation at all is refused with a sentence");
	message[0] = '\0';
	check(observed && !ncfg_observe_supplicants(observed, NULL, NULL, NULL, PATIENCE_MS,
	    message, sizeof(message)) && strstr(message, "run directory") != NULL,
	    "and so is a round with no run directory, naming what was missing");
	ncfg_observed_free(observed);
}

int main(void)
{
	const char *made = testdir_make("supplicants");

	base = made;
	hostapdfake_log_dir = base;
	(void)snprintf(run_dir, sizeof(run_dir), "%s/run", base);
	(void)snprintf(ctrl_dir, sizeof(ctrl_dir), "%s/ctrl", base);
	testdir_mkdirp(run_dir);
	testdir_mkdirp(ctrl_dir);
	/*
	 * The override `supplicant.h` publishes for exactly this: a network
	 * namespace is not a mount namespace, so without it this would share
	 * `/run/wpa_supplicant` with whatever the machine is running.
	 */
	(void)setenv(NCFG_SUPPLICANT_CTRL_DIR_ENV, ctrl_dir, 1);
	printf("== observe_supplicants_test in %s\n", base);

	a_supplicant_holding_what_the_document_asks_for();
	a_record_of_some_other_set_does_not_match();
	an_emptied_supplicant_refutes_its_own_record();
	no_record_says_nothing();
	the_network_a_radio_is_associated_to_is_written_down();
	a_network_the_document_does_not_have_is_not_named();
	the_answer_lands_on_the_supplicant_and_not_the_client();
	nothing_listening_is_not_answering();
	the_round_refuses_what_it_cannot_be_asked();

	fake_stop();
	testdir_remove(made);
	printf("observe_supplicants_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("observe_supplicants_test: all checks passed\n");
	} else {
		printf("observe_supplicants_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
