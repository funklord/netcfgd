/*
 * observe_access_control_test.c -- what a running access point is admitting,
 * and whether it is answering.
 *
 * WHAT IS DRIVEN, AND AGAINST WHAT
 *   A real control socket, served by `hostapdfake.h` -- the same stand-in the
 *   executor's own tests use, because two fakes of one daemon is two beliefs
 *   about its protocol and what would drift is the thing both sides of netcfgd
 *   are written against.
 *
 *   The case that matters most is `answering`. 0078 keeps it apart from
 *   `running` because a wedged hostapd holds its socket, holds its pid, serves
 *   nobody, and answered `running: true` to everything netcfgd had. The fake
 *   can be wedged on purpose, which is the only way to produce that state.
 */
#include "ncfg/base.h"
#include "ncfg/hostapd.h"
#include "ncfg/observe.h"

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

/* How long a case gives the socket. Short, because every one of these is
 * meant to answer at once or not at all, and a wedged fake is the whole
 * subject of one of them. */
#define PATIENCE_MS 400

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

static const ncfg_observed_backend_t *only(const ncfg_observed_t *observed)
{
	return observed && observed->backend_count == 1u ? &observed->backends[0] : NULL;
}

/* The list a backend carries, joined, so a mismatch prints readably. */
static int holds(char *const *list, size_t count, const char *expected)
{
	char   written[256];
	size_t length = 0;
	size_t at;

	written[0] = '\0';
	for (at = 0; at < count && length < sizeof(written); at++) {
		length += (size_t)snprintf(written + length, sizeof(written) - length, "%s%s",
		    length ? " " : "", list[at]);
	}
	if (strcmp(written, expected) == 0) {
		return 1;
	}
	printf("  it holds [%s]; expected [%s]\n", written, expected);
	return 0;
}

/* ------------------------------------------------------------------------ *
 * The cases
 * ------------------------------------------------------------------------ */

static void both_lists_are_read_and_the_daemon_is_answering(void)
{
	ncfg_observed_t *observed = observed_with("access_point", "wlan0", 1);
	char             message[NCFG_ERROR_MAX];

	if (!observed) {
		check(0, "the fixture for a live access point reads");
		return;
	}
	memset(&fake_config, 0, sizeof(fake_config));
	/*
	 * **Lowercase, because that is what both sides produce.** The compiler's
	 * `ncfg_normalize_station` writes a lowercase table and
	 * `ncfg_hostapd_parse_acl_show` lowercases what hostapd printed -- so the
	 * document and the observation compare equal. A first draft expected upper
	 * case here, and it was the expectation that was wrong rather than either
	 * normaliser. (`ncfg_hardware_address_strict` uppercases, and is a
	 * different field: a device's own address, where BlueZ sets the case.)
	 */
	(void)snprintf(fake_config.deny_list[0], sizeof(fake_config.deny_list[0]),
	    "aa:bb:cc:dd:ee:ff");
	fake_config.deny_count = 1u;
	/*
	 * **The other list is not empty either, and that is the point of asking
	 * for both.** The document names only one (0039), so an operator who
	 * flipped the policy under a running access point leaves entries in the
	 * list netcfgd is not managing -- and the only way to see that from
	 * outside is to have asked.
	 */
	(void)snprintf(fake_config.accept_list[0], sizeof(fake_config.accept_list[0]),
	    "11:22:33:44:55:66");
	fake_config.accept_count = 1u;
	check(fake_start(ctrl_dir, "wlan0"), "a fake hostapd is listening on wlan0");

	message[0] = '\0';
	check(ncfg_observe_access_control(observed, run_dir, PATIENCE_MS, message,
	    sizeof(message)), "the round runs");
	check(only(observed) && only(observed)->answering.has && only(observed)->answering.value,
	    "  a daemon that answers is recorded as answering");
	check(only(observed) && only(observed)->access_control &&
	    holds(only(observed)->access_control->denied,
	    only(observed)->access_control->denied_count, "aa:bb:cc:dd:ee:ff"),
	    "  the deny list is what hostapd is holding");
	check(only(observed) && only(observed)->access_control &&
	    holds(only(observed)->access_control->accepted,
	    only(observed)->access_control->accepted_count, "11:22:33:44:55:66"),
	    "  and so is the accept list, which the document does not name");
	fake_stop();
	ncfg_observed_free(observed);
}

static void a_daemon_that_answers_nothing_is_not_answering(void)
{
	ncfg_observed_t *observed = observed_with("access_point", "wlan-wedged", 1);
	char             message[NCFG_ERROR_MAX];

	if (!observed) {
		check(0, "the fixture for a wedged access point reads");
		return;
	}
	/*
	 * **0078's state, and nothing else here produces it.** The socket is
	 * bound, so the record's `running` is right and a connection succeeds --
	 * and then nothing comes back. Until this field existed netcfgd already
	 * knew and nothing wrote it down.
	 */
	memset(&fake_config, 0, sizeof(fake_config));
	fake_config.wedged = 1;
	check(fake_start(ctrl_dir, "wlan-wedged"), "a fake hostapd is bound and silent");

	message[0] = '\0';
	check(ncfg_observe_access_control(observed, run_dir, PATIENCE_MS, message,
	    sizeof(message)), "the round runs against it and is not a failure");
	check(only(observed) && only(observed)->answering.has && !only(observed)->answering.value,
	    "  a daemon holding its socket and serving nobody is not answering");
	/*
	 * And the lists say nothing rather than "denies nobody". Those are
	 * different answers and only the second may be reconciled against: an
	 * empty list read as a fact would have the planner add every station the
	 * document names, to a daemon that is not listening.
	 */
	check(only(observed) && only(observed)->access_control == NULL,
	    "  and the lists say nothing, rather than that it admits everybody");
	fake_stop();
	ncfg_observed_free(observed);
}

static void a_daemon_that_connects_and_then_will_not_answer(void)
{
	ncfg_observed_t *observed = observed_with("access_point", "wlan-deaf", 1);
	char             message[NCFG_ERROR_MAX];

	if (!observed) {
		check(0, "the fixture for a half-answering access point reads");
		return;
	}
	/*
	 * **Where `wedged` fails at the connect, this fails after it.** The client
	 * pings and gets `PONG`, so netcfgd has a connection; the command it
	 * actually wanted goes unanswered. That path had no case until the fake
	 * could produce this state, and two sabotages of it turned nothing red.
	 */
	memset(&fake_config, 0, sizeof(fake_config));
	fake_config.deaf = 1;
	(void)snprintf(fake_config.deny_list[0], sizeof(fake_config.deny_list[0]),
	    "aa:bb:cc:dd:ee:ff");
	fake_config.deny_count = 1u;
	check(fake_start(ctrl_dir, "wlan-deaf"), "a fake hostapd answers PING and nothing else");

	message[0] = '\0';
	check(ncfg_observe_access_control(observed, run_dir, PATIENCE_MS, message,
	    sizeof(message)), "the round runs against it and is not a failure");
	check(only(observed) && only(observed)->answering.has && !only(observed)->answering.value,
	    "  a daemon that connects and then will not answer is not answering");
	/*
	 * And **half its lists are not a smaller answer to the same question**:
	 * the deny list came back and the accept list did not, so neither is
	 * stored. Storing the half that arrived would report an access point as
	 * admitting everybody on the list it was never told about.
	 */
	check(only(observed) && only(observed)->access_control == NULL,
	    "  and neither list is stored, because half of them is not an answer");
	fake_stop();
	ncfg_observed_free(observed);
}

static void nothing_listening_is_the_same_answer(void)
{
	ncfg_observed_t *observed = observed_with("access_point", "wlan-gone", 1);
	char             message[NCFG_ERROR_MAX];

	if (!observed) {
		check(0, "the fixture for an absent socket reads");
		return;
	}
	message[0] = '\0';
	check(ncfg_observe_access_control(observed, run_dir, PATIENCE_MS, message,
	    sizeof(message)), "a socket nothing is bound to is not a failure either");
	/* The record says running and the socket says otherwise; the socket is
	 * closer to the truth. */
	check(only(observed) && only(observed)->answering.has && !only(observed)->answering.value,
	    "  and a daemon nothing is listening for is not answering");
	ncfg_observed_free(observed);
}

static void what_the_access_point_was_started_with_is_read_back(void)
{
	ncfg_observed_t *observed = observed_with("access_point", "wlan0", 1);
	char             path[640];
	char             dir[640];
	char             body[512];
	char             message[NCFG_ERROR_MAX];

	if (!observed) {
		check(0, "the fixture for a started access point reads");
		return;
	}
	(void)snprintf(dir, sizeof(dir), "%s/hostapd", run_dir);
	testdir_mkdirp(dir);
	if (!ncfg_hostapd_config_path(run_dir, "wlan0", path, sizeof(path), NULL, 0)) {
		check(0, "the generated configuration could be named");
		ncfg_observed_free(observed);
		return;
	}
	/*
	 * `ssid2=` is hex, which is what the model holds: an SSID is 0..32
	 * arbitrary octets and never guaranteed text. `686f6d65` is `home`.
	 */
	(void)snprintf(body, sizeof(body),
	    "interface=wlan0\nssid2=686f6d65\nhw_mode=g\nchannel=6\n"
	    "wpa_key_mgmt=WPA-PSK\nignore_broadcast_ssid=1\ncountry_code=SE\n");
	check(testdir_write(path, body, strlen(body)),
	    "the configuration netcfgd generated is on disk");
	memset(&fake_config, 0, sizeof(fake_config));
	check(fake_start(ctrl_dir, "wlan0"), "and a fake hostapd is listening");

	message[0] = '\0';
	(void)ncfg_observe_access_control(observed, run_dir, PATIENCE_MS, message,
	    sizeof(message));
	check(only(observed) && only(observed)->started_with &&
	    only(observed)->started_with->ssid.has &&
	    only(observed)->started_with->ssid.length == 4u &&
	    memcmp(only(observed)->started_with->ssid.bytes, "home", 4u) == 0,
	    "the SSID it was started with is read back out of the hex");
	check(only(observed) && only(observed)->started_with &&
	    only(observed)->started_with->channel.has &&
	    only(observed)->started_with->channel.value == 6,
	    "  and the channel");
	/*
	 * **The generation, which nothing used to notice changing.** hostapd reads
	 * its file once, so an access point started as WPA2 goes on offering WPA2
	 * however the document is edited -- and the passphrase comparison says
	 * nothing about it, because changing the generation changes no secret.
	 */
	check(only(observed) && only(observed)->started_with &&
	    only(observed)->started_with->key_mgmt &&
	    strcmp(only(observed)->started_with->key_mgmt, "WPA-PSK") == 0,
	    "  and the generation, which no secret comparison would have caught");
	/* Upper case, as hostapd spells it: comparing a document's `se` against a
	 * file's `SE` would restart the access point on every pass. */
	check(only(observed) && only(observed)->started_with &&
	    only(observed)->started_with->regdom &&
	    strcmp(only(observed)->started_with->regdom, "SE") == 0,
	    "  and the regulatory domain, in the case hostapd writes");
	check(only(observed) && only(observed)->started_with && only(observed)->started_with->hidden,
	    "  and whether it is hidden");
	fake_stop();
	ncfg_observed_free(observed);
}

static void only_a_running_access_point_is_asked(void)
{
	ncfg_observed_t *stopped = observed_with("access_point", "wlan0", 0);
	ncfg_observed_t *other = observed_with("supplicant", "wlan0", 1);
	char             message[NCFG_ERROR_MAX];

	if (!stopped || !other) {
		check(0, "the fixtures for the two that are not asked read");
		ncfg_observed_free(stopped);
		ncfg_observed_free(other);
		return;
	}
	/* Nothing is listening, so anything that *did* ask would answer
	 * `answering: false` -- which is what makes this check the record and not
	 * the socket. */
	message[0] = '\0';
	(void)ncfg_observe_access_control(stopped, run_dir, PATIENCE_MS, message,
	    sizeof(message));
	check(only(stopped) && !only(stopped)->answering.has,
	    "a daemon the record says is not running is not asked at all");
	(void)ncfg_observe_access_control(other, run_dir, PATIENCE_MS, message, sizeof(message));
	check(only(other) && !only(other)->answering.has,
	    "and neither is a backend of another kind on the same interface");
	ncfg_observed_free(stopped);
	ncfg_observed_free(other);
}

static void the_round_refuses_what_it_cannot_be_asked(void)
{
	ncfg_observed_t *observed = observed_with("access_point", "wlan0", 1);
	char             message[NCFG_ERROR_MAX];

	message[0] = '\0';
	check(!ncfg_observe_access_control(NULL, run_dir, PATIENCE_MS, message, sizeof(message)) &&
	    message[0] != '\0', "no observation at all is refused with a sentence");
	message[0] = '\0';
	check(observed && !ncfg_observe_access_control(observed, NULL, PATIENCE_MS, message,
	    sizeof(message)) && strstr(message, "run directory") != NULL,
	    "and so is a round with no run directory, naming what was missing");
	ncfg_observed_free(observed);
}

int main(void)
{
	const char *made = testdir_make("access-control");

	base = made;
	hostapdfake_log_dir = base;
	(void)snprintf(run_dir, sizeof(run_dir), "%s/run", base);
	testdir_mkdirp(run_dir);
	if (!ncfg_hostapd_ctrl_dir(run_dir, ctrl_dir, sizeof(ctrl_dir), NULL, 0)) {
		printf("the control directory could not be named\n");
		return 1;
	}
	testdir_mkdirp(ctrl_dir);
	printf("== observe_access_control_test in %s\n", base);

	both_lists_are_read_and_the_daemon_is_answering();
	a_daemon_that_answers_nothing_is_not_answering();
	a_daemon_that_connects_and_then_will_not_answer();
	nothing_listening_is_the_same_answer();
	what_the_access_point_was_started_with_is_read_back();
	only_a_running_access_point_is_asked();
	the_round_refuses_what_it_cannot_be_asked();

	/* Named pids only: `fake_stop` kills what this file recorded starting. */
	fake_stop();
	testdir_remove(made);
	printf("observe_access_control_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("observe_access_control_test: all checks passed\n");
	} else {
		printf("observe_access_control_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
