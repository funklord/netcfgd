/*
 * observe_currency_test.c -- whether a running daemon still holds what the
 * document asks for.
 *
 * WHAT THESE CASES ARE ABOUT
 *   A passphrase and a `.ovpn` are handed to a daemon once, when it starts, and
 *   the daemon never looks again. So the answers here are the only way anything
 *   can decide to restart one -- and the cases that matter most are the ones
 *   that say **nothing**, because "differs" from a file that is merely missing
 *   restarts a working daemon on a guess, and "matches" leaves a rotated
 *   credential unused for ever.
 *
 * NOTHING HERE PRINTS A SECRET, AND ONE CHECK IS ABOUT THAT
 *   The passphrase comparison has both values in this process at once. The
 *   fixture uses a canary so the last case can sweep everything the pass wrote
 *   for it -- which is `observe_wireguard_test.c`'s arrangement and is here for
 *   its reason: a guarantee nobody checks is a comment.
 */
#include "ncfg/base.h"
#include "ncfg/hooks.h"
#include "ncfg/hostapd.h"
#include "ncfg/observe.h"
#include "ncfg/openvpn.h"
#include "ncfg/secrets.h"

#include "testdir.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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
static char        secrets_dir[512];

/* The value nothing this pass writes may repeat. */
#define CANARY "canary-passphrase-9x"

static ncfg_secret_resolver_t resolver;

/* One backend record, as the prior state would carry it. */
static ncfg_observed_t *observed_with(const char *kind, const char *iface, int running)
{
	char             text[512];
	char             message[NCFG_ERROR_MAX];
	ncfg_observed_t *observed;

	(void)snprintf(text, sizeof(text),
	    "{\"links\":[],\"backends\":[{\"kind\":\"%s\",\"interface\":\"%s\","
	    "\"running\":%s}]}", kind, iface, running ? "true" : "false");
	message[0] = '\0';
	observed = ncfg_observed_read(text, strlen(text), message, sizeof(message));
	if (!observed) {
		printf("  fixture observation did not read: %s\n", message);
	}
	return observed;
}

/* A document with one access point on `wlan0`, or one openvpn device. */
static ncfg_document_t *document_of(const char *devices, const char *extra)
{
	char             text[2048];
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document;

	(void)snprintf(text, sizeof(text),
	    "{\"schema_version\":{\"major\":1,\"minor\":1},\"generated_by\":\"currency_test\","
	    "\"globals\":{},\"devices\":[%s],\"interfaces\":[],\"networks\":[]%s%s}",
	    devices, extra && extra[0] ? "," : "", extra ? extra : "");
	message[0] = '\0';
	document = ncfg_document_read(text, strlen(text), message, sizeof(message));
	if (!document) {
		printf("  fixture document did not read: %s\n", message);
	}
	return document;
}

#define AP_DEVICE "{\"name\":\"wlan0\",\"kind\":{\"kind\":\"physical\"}}"
#define AP_BLOCK(secret) \
	"\"access_points\":[{\"id\":\"home\",\"ssid\":\"686f6d65\"," \
	"\"device\":\"wlan0\",\"security\":{\"type\":\"psk\"," \
	"\"passphrase\":{\"provider\":\"file\",\"name\":\"" secret "\"}}}]"

/* Write the generated `hostapd.conf` netcfgd would have written. */
static int write_hostapd(const char *device, const char *passphrase)
{
	char path[640];
	char dir[640];
	char body[512];

	(void)snprintf(dir, sizeof(dir), "%s/hostapd", run_dir);
	testdir_mkdirp(dir);
	if (!ncfg_hostapd_config_path(run_dir, device, path, sizeof(path), NULL, 0)) {
		return 0;
	}
	(void)snprintf(body, sizeof(body),
	    "interface=%s\nssid=home\nwpa=2\n%s%s%s", device,
	    passphrase ? "wpa_passphrase=" : "", passphrase ? passphrase : "",
	    passphrase ? "\n" : "");
	return testdir_write(path, body, strlen(body));
}

/* Put a credential in the store, at the mode the resolver insists on. */
static int store(const char *name, const char *value)
{
	char path[640];

	testdir_mkdirp(secrets_dir);
	(void)snprintf(path, sizeof(path), "%s/%s", secrets_dir, name);
	if (!testdir_write(path, value, strlen(value))) {
		return 0;
	}
	return chmod(path, (mode_t)0600) == 0;
}

static ncfg_optbool_t secret_answer(const ncfg_observed_t *observed)
{
	ncfg_optbool_t none = { 0, 0 };

	return observed->backend_count == 1u ? observed->backends[0].secret_matches : none;
}

/* ------------------------------------------------------------------------ *
 * The passphrase
 * ------------------------------------------------------------------------ */

static void a_passphrase_that_has_not_changed_matches(void)
{
	ncfg_observed_t *observed = observed_with("access_point", "wlan0", 1);
	ncfg_document_t *document = document_of(AP_DEVICE, AP_BLOCK("home-psk"));
	char             message[NCFG_ERROR_MAX];
	ncfg_optbool_t   answer;

	if (!observed || !document) {
		check(0, "the fixtures for an unchanged passphrase read");
		ncfg_observed_free(observed);
		ncfg_document_free(document);
		return;
	}
	check(store("home-psk", CANARY) && write_hostapd("wlan0", CANARY),
	    "a credential in the store and the same one in the generated file");
	message[0] = '\0';
	check(ncfg_observe_currency(observed, run_dir, &resolver, document, message,
	    sizeof(message)), "the currency round runs");
	answer = secret_answer(observed);
	/*
	 * **The check that stops the rest being vacuous.** If neither value
	 * reached the comparison, every assertion around it would pass while
	 * proving nothing -- which is `secrets_test.c`'s own sentence about its
	 * canary.
	 */
	check(answer.has && answer.value,
	    "  and a passphrase that has not changed is reported as current");
	ncfg_observed_free(observed);
	ncfg_document_free(document);
}

static void a_rotated_passphrase_is_noticed(void)
{
	ncfg_observed_t *observed = observed_with("access_point", "wlan0", 1);
	ncfg_document_t *document = document_of(AP_DEVICE, AP_BLOCK("home-psk"));
	char             message[NCFG_ERROR_MAX];
	ncfg_optbool_t   answer;

	if (!observed || !document) {
		check(0, "the fixtures for a rotated passphrase read");
		ncfg_observed_free(observed);
		ncfg_document_free(document);
		return;
	}
	/* The store moved on; hostapd is still holding what it was started with,
	 * because it read its file once and never looks again. */
	(void)store("home-psk", "the-new-one-entirely");
	(void)write_hostapd("wlan0", CANARY);
	message[0] = '\0';
	(void)ncfg_observe_currency(observed, run_dir, &resolver, document, message,
	    sizeof(message));
	answer = secret_answer(observed);
	check(answer.has && !answer.value,
	    "a passphrase the store has rotated is reported as no longer current");
	ncfg_observed_free(observed);
	ncfg_document_free(document);
	(void)store("home-psk", CANARY);
}

static void what_cannot_be_compared_says_nothing(void)
{
	ncfg_observed_t *observed;
	ncfg_document_t *document;
	char             message[NCFG_ERROR_MAX];

	/*
	 * No generated file: a `/run` cleared under a running daemon.
	 *
	 * **The document names an access point on this very device**, which is
	 * what makes the missing file the thing being checked. A first draft put
	 * the daemon on `wlan-gone` and the block on `wlan0`, so the *block* was
	 * what declined it -- and a sabotage that answered "differs" from a
	 * missing file turned nothing red.
	 */
	observed = observed_with("access_point", "wlan-gone", 1);
	document = document_of("{\"name\":\"wlan-gone\",\"kind\":{\"kind\":\"physical\"}}",
	    "\"access_points\":[{\"id\":\"home\",\"ssid\":\"686f6d65\","
	    "\"device\":\"wlan-gone\",\"security\":{\"type\":\"psk\","
	    "\"passphrase\":{\"provider\":\"file\",\"name\":\"home-psk\"}}}]");
	message[0] = '\0';
	(void)ncfg_observe_currency(observed, run_dir, &resolver, document, message,
	    sizeof(message));
	check(!secret_answer(observed).has,
	    "a generated file that is gone says nothing, rather than that it differs");
	ncfg_observed_free(observed);
	ncfg_document_free(document);

	/* A credential the store cannot answer for. `secrets.h` reports it without
	 * disclosing anything, and this pass concludes nothing from it. */
	observed = observed_with("access_point", "wlan0", 1);
	document = document_of(AP_DEVICE, AP_BLOCK("no-such-credential"));
	message[0] = '\0';
	(void)ncfg_observe_currency(observed, run_dir, &resolver, document, message,
	    sizeof(message));
	check(!secret_answer(observed).has,
	    "and a store that cannot answer says nothing either");
	ncfg_observed_free(observed);
	ncfg_document_free(document);

	/* An open network has nothing to compare rather than something that
	 * differs. */
	observed = observed_with("access_point", "wlan0", 1);
	document = document_of(AP_DEVICE,
	    "\"access_points\":[{\"id\":\"guest\",\"ssid\":\"6775657374\","
	    "\"device\":\"wlan0\",\"security\":{\"type\":\"open\"}}]");
	message[0] = '\0';
	(void)ncfg_observe_currency(observed, run_dir, &resolver, document, message,
	    sizeof(message));
	check(!secret_answer(observed).has, "and an open network has no passphrase to be stale");
	ncfg_observed_free(observed);
	ncfg_document_free(document);

	/* And a daemon the record says is not running is not asked at all. */
	observed = observed_with("access_point", "wlan0", 0);
	document = document_of(AP_DEVICE, AP_BLOCK("home-psk"));
	message[0] = '\0';
	(void)ncfg_observe_currency(observed, run_dir, &resolver, document, message,
	    sizeof(message));
	check(!secret_answer(observed).has, "and a daemon that is not running is not asked");
	ncfg_observed_free(observed);
	ncfg_document_free(document);
}

/* ------------------------------------------------------------------------ *
 * The tunnel
 * ------------------------------------------------------------------------ */

#define VPN_DEVICE(path) \
	"{\"name\":\"vpn0\",\"kind\":{\"kind\":\"open_vpn\",\"config\":\"" path "\"}}"

static int write_hash_record(const char *iface, const char *digest)
{
	char path[640];
	char dir[640];
	char body[128];

	(void)snprintf(dir, sizeof(dir), "%s/openvpn", run_dir);
	testdir_mkdirp(dir);
	if (!ncfg_openvpn_config_hash_path(run_dir, iface, path, sizeof(path), NULL, 0)) {
		return 0;
	}
	(void)snprintf(body, sizeof(body), "%s\n", digest);
	return testdir_write(path, body, strlen(body));
}

static void a_tunnel_started_from_this_file_is_current(void)
{
	char             ovpn[640];
	char             digest[NCFG_SHA256_HEX_SIZE];
	char             devices[1024];
	ncfg_observed_t *observed = observed_with("open_vpn", "vpn0", 1);
	ncfg_document_t *document;
	char             message[NCFG_ERROR_MAX];

	(void)snprintf(ovpn, sizeof(ovpn), "%s/work.ovpn", base);
	check(testdir_write(ovpn, "remote vpn.example 1194\n", 24u),
	    "an operator's `.ovpn` is on disk");
	(void)snprintf(devices, sizeof(devices), VPN_DEVICE("%s"), ovpn);
	document = document_of(devices, "");
	if (!observed || !document) {
		check(0, "the fixtures for a current tunnel read");
		ncfg_observed_free(observed);
		ncfg_document_free(document);
		return;
	}
	check(ncfg_openvpn_hash_of(ovpn, digest, sizeof(digest)),
	    "  and netcfgd can digest it, which is all it ever does to it");
	(void)write_hash_record("vpn0", digest);
	message[0] = '\0';
	(void)ncfg_observe_currency(observed, run_dir, &resolver, document, message,
	    sizeof(message));
	check(observed->backends[0].config_present.has &&
	    observed->backends[0].config_present.value,
	    "  the file the document names can be read");
	check(observed->backends[0].config_matches.has &&
	    observed->backends[0].config_matches.value,
	    "  and the tunnel is running from that very file");

	/* Edit it, and the next observation notices -- which is what makes an
	 * edited `.ovpn` something a reconcile can act on at all (0053). */
	(void)testdir_write(ovpn, "remote other.example 1194\n", 26u);
	ncfg_observed_free(observed);
	observed = observed_with("open_vpn", "vpn0", 1);
	(void)ncfg_observe_currency(observed, run_dir, &resolver, document, message,
	    sizeof(message));
	check(observed->backends[0].config_matches.has &&
	    !observed->backends[0].config_matches.value,
	    "and an edited `.ovpn` is noticed, which is the whole point of the digest");
	ncfg_observed_free(observed);
	ncfg_document_free(document);
}

static void a_file_the_document_names_and_nobody_can_read(void)
{
	char             devices[1024];
	ncfg_observed_t *observed = observed_with("open_vpn", "vpn0", 1);
	ncfg_document_t *document;
	char             message[NCFG_ERROR_MAX];

	(void)snprintf(devices, sizeof(devices), VPN_DEVICE("%s/no-such.ovpn"), base);
	document = document_of(devices, "");
	if (!observed || !document) {
		check(0, "the fixtures for an unreadable `.ovpn` read");
		ncfg_observed_free(observed);
		ncfg_document_free(document);
		return;
	}
	message[0] = '\0';
	(void)ncfg_observe_currency(observed, run_dir, &resolver, document, message,
	    sizeof(message));
	/*
	 * **Answered separately, and that is the point of the field.** Without it
	 * a document pointing at a file that is not there produced `nothing to do`
	 * on every apply, for ever, while the daemon went on running what it was
	 * started with.
	 */
	check(observed->backends[0].config_present.has &&
	    !observed->backends[0].config_present.value,
	    "a `.ovpn` the document names and nobody can read is reported as absent");
	check(!observed->backends[0].config_matches.has,
	    "  and `matches` says nothing, because a restart cannot fix a missing file");
	ncfg_observed_free(observed);
	ncfg_document_free(document);
}

/* ------------------------------------------------------------------------ *
 * What must never leave this pass
 * ------------------------------------------------------------------------ */

static void nothing_that_identifies_a_passphrase_is_written_down(void)
{
	ncfg_observed_t *observed = observed_with("access_point", "wlan0", 1);
	ncfg_document_t *document = document_of(AP_DEVICE, AP_BLOCK("home-psk"));
	ncfg_buf_t       written;
	char             message[NCFG_ERROR_MAX];

	if (!observed || !document) {
		check(0, "the fixtures for the canary sweep read");
		ncfg_observed_free(observed);
		ncfg_document_free(document);
		return;
	}
	(void)store("home-psk", CANARY);
	(void)write_hostapd("wlan0", CANARY);
	message[0] = '\0';
	(void)ncfg_observe_currency(observed, run_dir, &resolver, document, message,
	    sizeof(message));
	/*
	 * The observation is what goes to `/run/netcfgd/observed.json` and out of
	 * `ncfg status --json`, so it is the thing that has to be swept. 0052's
	 * design is that the answer is a boolean; this is the check that the
	 * design held.
	 */
	ncfg_buf_init(&written, 0);
	check(ncfg_observed_write(observed, &written, message, sizeof(message)),
	    "the observation this pass filled in writes out");
	check(strstr(ncfg_buf_text(&written), CANARY) == NULL,
	    "  and carries nothing of the passphrase it compared");
	check(strstr(message, CANARY) == NULL, "  nor does the sentence beside it");
	ncfg_buf_free(&written);
	ncfg_observed_free(observed);
	ncfg_document_free(document);
}

int main(void)
{
	const char *made = testdir_make("currency");

	base = made;
	(void)snprintf(run_dir, sizeof(run_dir), "%s/run", base);
	(void)snprintf(secrets_dir, sizeof(secrets_dir), "%s/secrets", base);
	testdir_mkdirp(run_dir);
	memset(&resolver, 0, sizeof(resolver));
	resolver.secrets_dir = secrets_dir;
	printf("== observe_currency_test in %s\n", base);

	a_passphrase_that_has_not_changed_matches();
	a_rotated_passphrase_is_noticed();
	what_cannot_be_compared_says_nothing();
	a_tunnel_started_from_this_file_is_current();
	a_file_the_document_names_and_nobody_can_read();
	nothing_that_identifies_a_passphrase_is_written_down();

	testdir_remove(made);
	printf("observe_currency_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("observe_currency_test: all checks passed\n");
	} else {
		printf("observe_currency_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
