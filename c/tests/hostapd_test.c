/*
 * hostapd_test.c -- the file hostapd reads, and the credential that must not
 * leave it.
 *
 * WHAT THESE CASES ARE FOR
 *   The rendering cases are the Rust's, each keeping the sentence that says
 *   which defect it is about. The ones that are not obvious:
 *
 *   * **Only the arms that write `wpa_passphrase` are length-checked** (0205).
 *     Asked of hostapd 2.10 with 70 characters, `wpa_passphrase` gives "invalid
 *     WPA passphrase length 70 (expected 8..63)" and `sae_password` is parsed
 *     without complaint -- so netcfgd was refusing a WPA3 access point that
 *     hostapd would have run, and telling the operator it was WPA's rule.
 *   * **A channel in no band is refused even with no band declared.** Inferring
 *     a band from the channel and then not checking it is how channel 20 became
 *     `hw_mode=a`: a 5 GHz mode on a channel that only exists in 2.4 GHz.
 *   * **A regdom is advertised as well as recorded**, and brings radar
 *     detection with it (0232) -- hostapd defaults DFS support off and
 *     documents it as "required on outdoor 5 GHz channels in most countries of
 *     the world", and the pair travels together because hostapd says
 *     `ieee80211h` "can be used only with ieee80211d=1".
 *   * **Transition mode still protects SAE.** Without `sae_require_mfp` an
 *     attacker could downgrade every client to WPA2, which is the thing
 *     transition mode is accused of.
 *   * **The record is short enough that hostapd reads it as one line.**
 *     `hostapd_config_read_maclist` reads with `fgets` into a 128-byte buffer
 *     and treats a line as a comment only when its first byte is `#`; a longer
 *     record would arrive split, and the tail would be parsed as an address,
 *     fail, and take the access point down at startup.
 *   * **A rewritten configuration is still only readable by root.**
 *     `.mode()` applies when `open(2)` creates the file and not otherwise, so
 *     rewriting one that already exists kept whatever mode it had -- measured:
 *     a file left at 0644 stayed 0644 through exactly the write that put the
 *     passphrase in it. The pre-existing file here is 0644 deliberately, since
 *     the first write is the case that always worked.
 *   * **The reply parsers' cases**, which came from reading hostapd's own
 *     source rather than its documentation: an empty reply is an answer, a
 *     station with no driver statistics is still a station, and a VLAN
 *     assignment is still an address.
 *
 * AND THE SWEEP
 *   `secrets_test.c`'s method, applied to the one module whose whole risk is a
 *   credential: one `CANARY` passphrase, every failure this module can produce
 *   driven with it, and three channels then read back for the value -- every
 *   `err` buffer, this process' whole standard error, and the redacted
 *   rendering. **And the sweep is checked for being vacuous**: the canary is
 *   asserted to be in the real file first, so the channels really are empty
 *   rather than the material never having been in this process.
 *
 * NOTHING OUTSIDE ITS OWN DIRECTORY, AND NO RADIO
 *   The real netcfgd is running here. Every path is under one `mkdtemp`
 *   directory and is passed explicitly; the secrets directory is one this test
 *   made, never `/etc/netcfgd/secrets`; and the program started is a shell
 *   script this test wrote. Nothing here runs hostapd or touches a radio.
 */
#include "ncfg/base.h"
#include "ncfg/document.h"
#include "ncfg/hostapd.h"
#include "ncfg/observed.h"
#include "ncfg/secrets.h"

#include "testdir.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The value nothing may repeat. Distinctive enough that finding it in a buffer
 * is never a coincidence, and 48 octets so it fits `wpa_passphrase`. */
#define CANARY "zq7-CANARY-hostapd-passphrase-never-printed-4f1e"

static int    failures;
static char   every_message[64u * 1024u];
static size_t every_message_length;

static void check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* Keep a diagnostic for the sweep, and hand it back for a caller that wants to
 * look at it now. */
static const char *kept(const char *message)
{
	size_t length = strlen(message);

	if (every_message_length + length + 2u < sizeof(every_message)) {
		memcpy(every_message + every_message_length, message, length);
		every_message_length += length;
		every_message[every_message_length++] = '\n';
		every_message[every_message_length] = '\0';
	}
	return message;
}

static void check_text(const char *got, const char *want, const char *what)
{
	int same = got != NULL && strcmp(got, want) == 0;

	check(same, what);
	if (!same) {
		printf("  wanted: %s\n  got:    %s\n", want, got ? got : "(null)");
	}
}

/* ------------------------------------------------------------- fixtures */

static ncfg_access_point_t point_of(int security_kind, int proto)
{
	ncfg_access_point_t point;

	memset(&point, 0, sizeof(point));
	point.id = (char *)(void *)"guest";
	point.ssid.has = 1;
	point.ssid.length = 5u;
	memcpy(point.ssid.bytes, "guest", 5u);
	point.device = (char *)(void *)"wlan0";
	point.security.kind = security_kind;
	point.security.psk.proto = proto;
	point.security.psk.passphrase.provider = NCFG_SECRET_PROVIDER_FILE;
	point.security.psk.passphrase.name = (char *)(void *)"guest";
	point.channel.has = 1;
	point.channel.value = 6;
	return point;
}

/* Render, and complain rather than crash where a fixture was supposed to
 * render and did not. */
static int rendered(const ncfg_access_point_t *point, const char *passphrase,
    ncfg_hostapd_lines_t *out)
{
	char message[NCFG_ERROR_MAX];
	int  ok;

	message[0] = '\0';
	ok = ncfg_hostapd_config(point, "/run/netcfgd/hostapd", passphrase, out, NULL, message,
	    sizeof(message));
	if (!ok) {
		printf("  this access point was expected to render: %s\n", kept(message));
	}
	return ok;
}

/* Render, expecting a refusal, and say which one it was. */
static int refused(const ncfg_access_point_t *point, const char *passphrase,
    ncfg_hostapd_unsupported_t want, const char *what)
{
	ncfg_hostapd_lines_t       lines;
	ncfg_hostapd_unsupported_t why = NCFG_HOSTAPD_OK;
	char                       message[NCFG_ERROR_MAX];
	int                        ok;

	message[0] = '\0';
	ok = ncfg_hostapd_config(point, "/run", passphrase, &lines, &why, message,
	    sizeof(message));
	if (ok) {
		ncfg_hostapd_lines_free(&lines);
	}
	(void)kept(message);
	check(!ok && why == want, what);
	if (ok || why != want) {
		printf("  said: %s\n", message);
	}
	return !ok;
}

/* --------------------------------------------------------- the rendering */

static void an_open_network_carries_no_wpa_lines(void)
{
	ncfg_access_point_t  point = point_of(NCFG_SECURITY_OPEN, NCFG_PSK_PROTO_WPA2);
	ncfg_hostapd_lines_t lines;

	if (!rendered(&point, NULL, &lines)) {
		check(0, "an open network renders");
		return;
	}
	check_text(ncfg_hostapd_value_of(&lines, "ssid2"), "6775657374",
	    "an SSID goes in as bare hex, because `ssid=` is text and an SSID is octets");
	check_text(ncfg_hostapd_value_of(&lines, "hw_mode"), "g", "channel 6 is 2.4 GHz");
	check_text(ncfg_hostapd_value_of(&lines, "channel"), "6", "and the channel is the one asked "
	                             "for");
	check(ncfg_hostapd_value_of(&lines, "wpa") == NULL &&
	    ncfg_hostapd_value_of(&lines, "wpa_key_mgmt") == NULL,
	    "an open network carries no wpa lines at all");
	ncfg_hostapd_lines_free(&lines);
}

static void wpa2_uses_a_passphrase_and_wpa3_uses_sae(void)
{
	ncfg_access_point_t  point = point_of(NCFG_SECURITY_PSK, NCFG_PSK_PROTO_WPA2);
	ncfg_hostapd_lines_t lines;

	if (rendered(&point, CANARY, &lines)) {
		check_text(ncfg_hostapd_value_of(&lines, "wpa_key_mgmt"), "WPA-PSK", "WPA2 is WPA-PSK");
		check_text(ncfg_hostapd_value_of(&lines, "wpa_passphrase"), CANARY,
		    "and the passphrase goes in exactly as the operator wrote it");
		check(ncfg_hostapd_value_of(&lines, "sae_password") == NULL,
		    "with no sae_password beside it");
		/* WPA2 must not require management frame protection: a client that
		 * cannot do it is the entire reason somebody chose WPA2. */
		check(ncfg_hostapd_value_of(&lines, "ieee80211w") == NULL,
		    "and no ieee80211w, since a client that cannot do it is why WPA2 was chosen");
		ncfg_hostapd_lines_free(&lines);
	}

	point.security.psk.proto = NCFG_PSK_PROTO_WPA3;
	if (rendered(&point, CANARY, &lines)) {
		check_text(ncfg_hostapd_value_of(&lines, "wpa_key_mgmt"), "SAE", "WPA3 is SAE");
		check_text(ncfg_hostapd_value_of(&lines, "sae_password"), CANARY,
		    "carried in sae_password");
		check(ncfg_hostapd_value_of(&lines, "wpa_passphrase") == NULL,
		    "and not in wpa_passphrase");
		check_text(ncfg_hostapd_value_of(&lines, "ieee80211w"), "2",
		    "with management frame protection required, which WPA3 is not WPA3 without");
		check_text(ncfg_hostapd_value_of(&lines, "wpa"), "2",
		    "and `wpa=2`, because there is no wpa=3 -- the generation is the key management");
		ncfg_hostapd_lines_free(&lines);
	}
}

static void transition_mode_offers_both_and_still_protects_sae(void)
{
	ncfg_access_point_t  point = point_of(NCFG_SECURITY_PSK, NCFG_PSK_PROTO_WPA2_WPA3);
	ncfg_hostapd_lines_t lines;

	if (!rendered(&point, CANARY, &lines)) {
		check(0, "transition mode renders");
		return;
	}
	check_text(ncfg_hostapd_value_of(&lines, "wpa_key_mgmt"), "WPA-PSK SAE",
	    "transition mode offers both key managements");
	check_text(ncfg_hostapd_value_of(&lines, "wpa_passphrase"), CANARY, "with both fields set");
	check_text(ncfg_hostapd_value_of(&lines, "sae_password"), CANARY, "from the one value");
	check_text(ncfg_hostapd_value_of(&lines, "ieee80211w"), "1",
	    "protection optional overall, since a WPA2 client cannot do it");
	check_text(ncfg_hostapd_value_of(&lines, "sae_require_mfp"), "1",
	    "and required for whoever negotiates SAE, or the mode is a downgrade for everybody");
	ncfg_hostapd_lines_free(&lines);
}

/*
 * The length limit is `wpa_passphrase`'s, and only two arms emit one.
 *
 * 0205 settled this for the station and left the access point enforcing 8..=63
 * for all three, under a comment saying hostapd checks it anyway. It does --
 * for the field it checks.
 */
static void only_the_arms_that_write_wpa_passphrase_are_length_checked(void)
{
	ncfg_access_point_t  point = point_of(NCFG_SECURITY_PSK, NCFG_PSK_PROTO_WPA3);
	ncfg_hostapd_lines_t lines;
	char                 very_long[71];

	memset(very_long, 'a', sizeof(very_long) - 1u);
	very_long[sizeof(very_long) - 1u] = '\0';

	/* WPA3 alone writes `sae_password` and nothing else, so nothing downstream
	 * limits it and neither does this. */
	if (rendered(&point, very_long, &lines)) {
		check_text(ncfg_hostapd_value_of(&lines, "sae_password"), very_long,
		    "a 70-octet WPA3 passphrase is rendered, because hostapd takes one");
		check(ncfg_hostapd_value_of(&lines, "wpa_passphrase") == NULL,
		    "and nothing writes it into the field that is length-checked");
		ncfg_hostapd_lines_free(&lines);
	}

	/* Transition mode keeps the limit, because it writes `wpa_passphrase` too. */
	point.security.psk.proto = NCFG_PSK_PROTO_WPA2_WPA3;
	(void)refused(&point, very_long, NCFG_HOSTAPD_PASSPHRASE_LENGTH,
	    "transition mode keeps the limit, because it writes wpa_passphrase too");
	point.security.psk.proto = NCFG_PSK_PROTO_WPA2;
	(void)refused(&point, very_long, NCFG_HOSTAPD_PASSPHRASE_LENGTH,
	    "and plain WPA2, which is the case the rule was written for");

	/* The short end is not special-cased either way: SAE has no minimum in
	 * hostapd, and the two arms that carry `wpa_passphrase` do. */
	point.security.psk.proto = NCFG_PSK_PROTO_WPA2_WPA3;
	(void)refused(&point, "short", NCFG_HOSTAPD_PASSPHRASE_LENGTH,
	    "the short end is checked for the same two arms");
	point.security.psk.proto = NCFG_PSK_PROTO_WPA3;
	if (rendered(&point, "short", &lines)) {
		check_text(ncfg_hostapd_value_of(&lines, "sae_password"), "short",
		    "and not for WPA3, which has no minimum in hostapd either");
		ncfg_hostapd_lines_free(&lines);
	}
}

static void owe_needs_no_secret(void)
{
	ncfg_access_point_t  point = point_of(NCFG_SECURITY_OWE, NCFG_PSK_PROTO_WPA2);
	ncfg_hostapd_lines_t lines;

	if (!rendered(&point, NULL, &lines)) {
		check(0, "an OWE network renders");
		return;
	}
	check_text(ncfg_hostapd_value_of(&lines, "wpa_key_mgmt"), "OWE", "OWE needs no secret");
	check_text(ncfg_hostapd_value_of(&lines, "ieee80211w"), "2",
	    "and requires management frame protection");
	ncfg_hostapd_lines_free(&lines);
}

static void an_ssid_that_is_not_text_survives_as_hex(void)
{
	ncfg_access_point_t  point = point_of(NCFG_SECURITY_OPEN, NCFG_PSK_PROTO_WPA2);
	ncfg_hostapd_lines_t lines;

	/* 802.11 places no encoding requirement on an SSID, and real networks ship
	 * ones that are not valid UTF-8. `ssid2=` takes bare hex, which is exactly
	 * what the model already holds. */
	point.ssid.length = 3u;
	point.ssid.bytes[0] = 0x00;
	point.ssid.bytes[1] = 0xff;
	point.ssid.bytes[2] = 0x20;
	if (!rendered(&point, NULL, &lines)) {
		check(0, "an SSID that is not text renders");
		return;
	}
	check_text(ncfg_hostapd_value_of(&lines, "ssid2"), "00ff20",
	    "an SSID that is not text survives as hex, including a NUL and a space");
	ncfg_hostapd_lines_free(&lines);
}

static void the_band_follows_the_channel_when_nothing_says_otherwise(void)
{
	ncfg_access_point_t  point = point_of(NCFG_SECURITY_OPEN, NCFG_PSK_PROTO_WPA2);
	ncfg_hostapd_lines_t lines;

	point.channel.value = 36;
	if (rendered(&point, NULL, &lines)) {
		check_text(ncfg_hostapd_value_of(&lines, "hw_mode"), "a", "channel 36 is 5 GHz");
		ncfg_hostapd_lines_free(&lines);
	}
	point.channel.value = 11;
	if (rendered(&point, NULL, &lines)) {
		check_text(ncfg_hostapd_value_of(&lines, "hw_mode"), "g", "channel 11 is 2.4 GHz");
		ncfg_hostapd_lines_free(&lines);
	}
}

static void no_channel_asks_hostapd_to_choose(void)
{
	ncfg_access_point_t  point = point_of(NCFG_SECURITY_OPEN, NCFG_PSK_PROTO_WPA2);
	ncfg_hostapd_lines_t lines;

	point.channel.has = 0;
	if (rendered(&point, NULL, &lines)) {
		check_text(ncfg_hostapd_value_of(&lines, "channel"), "0",
		    "no channel is written as 0, which asks hostapd to survey and choose");
		check_text(ncfg_hostapd_value_of(&lines, "hw_mode"), "g",
		    "in 2.4 GHz, which every radio has");
		ncfg_hostapd_lines_free(&lines);
	}
	point.band = (char *)(void *)"5";
	if (rendered(&point, NULL, &lines)) {
		check_text(ncfg_hostapd_value_of(&lines, "channel"), "0", "a band with no channel still "
		                               "chooses");
		check_text(ncfg_hostapd_value_of(&lines, "hw_mode"), "a", "but within the band stated");
		ncfg_hostapd_lines_free(&lines);
	}
}

static void a_channel_that_contradicts_its_band_is_refused(void)
{
	ncfg_access_point_t point = point_of(NCFG_SECURITY_OPEN, NCFG_PSK_PROTO_WPA2);

	point.band = (char *)(void *)"5";
	point.channel.value = 6;
	(void)refused(&point, NULL, NCFG_HOSTAPD_CHANNEL_NOT_IN_BAND,
	    "a channel that contradicts its stated band is refused");
}

/*
 * The gap between the bands is nobody's channel.
 *
 * Inferring a band from the channel and then not checking it is how channel 20
 * became `hw_mode=a`: a 5 GHz mode on a channel that only exists in 2.4 GHz,
 * which hostapd would have refused much later and much less clearly.
 */
static void a_channel_in_no_band_is_refused_even_with_no_band_declared(void)
{
	ncfg_access_point_t point = point_of(NCFG_SECURITY_OPEN, NCFG_PSK_PROTO_WPA2);

	point.channel.value = 20;
	(void)refused(&point, NULL, NCFG_HOSTAPD_CHANNEL_NOT_IN_BAND,
	    "channel 20 is in no band, and is refused rather than inferred into 5 GHz");
	point.channel.value = 200;
	(void)refused(&point, NULL, NCFG_HOSTAPD_CHANNEL_NOT_IN_BAND,
	    "and so is channel 200, past the top of the 5 GHz range");
}

static void six_gigahertz_and_unknown_bands_are_refused_differently(void)
{
	ncfg_access_point_t point = point_of(NCFG_SECURITY_OPEN, NCFG_PSK_PROTO_WPA2);

	/* "A band this build cannot do" stays a different answer from "not a band",
	 * which is why the compiler accepts `6` deliberately. */
	point.band = (char *)(void *)"6";
	(void)refused(&point, NULL, NCFG_HOSTAPD_SIX_GIGAHERTZ,
	    "6 GHz is refused as a band this build cannot render");
	point.band = (char *)(void *)"5g";
	(void)refused(&point, NULL, NCFG_HOSTAPD_UNKNOWN_BAND,
	    "and `5g` is refused as not a band at all, which is a different answer");
}

static void a_regdom_is_advertised_as_well_as_recorded(void)
{
	ncfg_access_point_t  point = point_of(NCFG_SECURITY_OPEN, NCFG_PSK_PROTO_WPA2);
	ncfg_hostapd_lines_t lines;

	point.regdom = (char *)(void *)"se";
	if (rendered(&point, NULL, &lines)) {
		check_text(ncfg_hostapd_value_of(&lines, "country_code"), "SE",
		    "a regulatory domain is uppercased");
		check_text(ncfg_hostapd_value_of(&lines, "ieee80211d"), "1",
		    "and advertised, or clients never learn which domain they are in");
		check_text(ncfg_hostapd_value_of(&lines, "ieee80211h"), "1",
		    "with radar detection, without which half of 5 GHz cannot be used (0232)");
		ncfg_hostapd_lines_free(&lines);
	}

	/* Neither line without a country, because hostapd says `ieee80211h` "can be
	 * used only with ieee80211d=1" -- so the pair travels together or not at
	 * all. */
	point.regdom = NULL;
	if (rendered(&point, NULL, &lines)) {
		check(ncfg_hostapd_value_of(&lines, "ieee80211d") == NULL &&
		    ncfg_hostapd_value_of(&lines, "ieee80211h") == NULL,
		    "and neither line appears without a country, since the pair travels together");
		ncfg_hostapd_lines_free(&lines);
	}

	point.regdom = (char *)(void *)"SWE";
	(void)refused(&point, NULL, NCFG_HOSTAPD_MALFORMED_REGDOM,
	    "a three-letter country is refused: it is an ISO 3166-1 alpha-2 code");
}

static void enterprise_is_refused_by_name(void)
{
	ncfg_access_point_t point = point_of(NCFG_SECURITY_EAP, NCFG_PSK_PROTO_WPA2);

	point.security.eap.method = NCFG_EAP_METHOD_PEAP;
	point.security.eap.identity = (char *)(void *)"someone";
	(void)refused(&point, NULL, NCFG_HOSTAPD_ENTERPRISE_NEEDS_RADIUS,
	    "EAP is refused by name: an `eap` block is a client's end of the exchange");
}

/*
 * A passphrase that would break the file is refused.
 *
 * Only two bytes are a problem, and neither is one hostapd rejects -- they end
 * the line, so hostapd would read a *different* passphrase, or a stray key,
 * without either end noticing. `#`, spaces and quotes are ordinary passphrase
 * characters and are kept.
 */
static void a_passphrase_that_would_break_the_file_is_refused(void)
{
	ncfg_access_point_t  point = point_of(NCFG_SECURITY_PSK, NCFG_PSK_PROTO_WPA2);
	ncfg_hostapd_lines_t lines;

	(void)refused(&point, "good enough\nssid2=deadbeef", NCFG_HOSTAPD_PASSPHRASE_NOT_WRITABLE,
	    "a passphrase carrying a newline is refused, since it would smuggle a second key");
	(void)refused(&point, NULL, NCFG_HOSTAPD_MISSING_PASSPHRASE,
	    "and a psk network with nothing resolved for it is refused by name");

	if (rendered(&point, "a pass#word", &lines)) {
		check_text(ncfg_hostapd_value_of(&lines, "wpa_passphrase"), "a pass#word",
		    "a `#` is not a comment once the line has a key, and a space is not a separator");
		ncfg_hostapd_lines_free(&lines);
	}
}

static void the_redacted_form_keeps_everything_that_is_not_the_secret(void)
{
	ncfg_access_point_t  point = point_of(NCFG_SECURITY_PSK, NCFG_PSK_PROTO_WPA2);
	ncfg_hostapd_lines_t lines;
	char                 message[NCFG_ERROR_MAX];
	char                *safe;
	char                *real;

	if (!rendered(&point, CANARY, &lines)) {
		check(0, "a psk network renders");
		return;
	}
	safe = ncfg_hostapd_to_redacted("guest", &lines, message, sizeof(message));
	check(safe != NULL && strstr(safe, "wpa_passphrase=<redacted>") != NULL,
	    "the redacted form replaces the passphrase");
	check(safe != NULL && strstr(safe, CANARY) == NULL, "and carries no trace of the value");
	/* Per line rather than per file: an operator debugging an access point
	 * wants to see these, and "the file has a secret so here is nothing" is how
	 * people end up reading the real file with `cat` instead. */
	check(safe != NULL && strstr(safe, "hw_mode=g") != NULL &&
	    strstr(safe, "channel=6") != NULL,
	    "while keeping everything that is not the secret");
	free(safe);

	real = ncfg_hostapd_to_file("guest", &lines, message, sizeof(message));
	check(real != NULL && strstr(real, "wpa_passphrase=" CANARY) != NULL,
	    "and the real file carries the value, which is what its 0600 is for");
	if (real) {
		memset(real, 0, strlen(real));
	}
	free(real);
	ncfg_hostapd_lines_free(&lines);
}

/* ------------------------------------------------------ the station list */

static void the_acl_files_are_alternatives(void)
{
	ncfg_access_point_t   point = point_of(NCFG_SECURITY_OPEN, NCFG_PSK_PROTO_WPA2);
	ncfg_access_control_t control;
	char                 *stations[] = { (char *)(void *)"aa:bb:cc:dd:ee:ff" };
	ncfg_hostapd_lines_t  lines;

	memset(&control, 0, sizeof(control));
	control.policy = NCFG_ACL_POLICY_DENY;
	control.stations = stations;
	control.station_count = 1u;
	point.access_control = &control;

	if (rendered(&point, NULL, &lines)) {
		check_text(ncfg_hostapd_value_of(&lines, "macaddr_acl"), "0", "a deny list is "
		                                "macaddr_acl=0");
		check_text(ncfg_hostapd_value_of(&lines, "deny_mac_file"),
		    "/run/netcfgd/hostapd/wlan0.acl", "and names the deny file beside the config");
		/* The two files are alternatives in hostapd, so naming both would leave
		 * one of them silently unread. */
		check(ncfg_hostapd_value_of(&lines, "accept_mac_file") == NULL,
		    "and never the accept file too, which hostapd would silently not read");
		ncfg_hostapd_lines_free(&lines);
	}

	control.policy = NCFG_ACL_POLICY_ALLOW;
	if (rendered(&point, NULL, &lines)) {
		check_text(ncfg_hostapd_value_of(&lines, "macaddr_acl"), "1", "an allow list is "
		                                "macaddr_acl=1");
		check_text(ncfg_hostapd_value_of(&lines, "accept_mac_file"),
		    "/run/netcfgd/hostapd/wlan0.acl", "and names the accept file");
		check(ncfg_hostapd_value_of(&lines, "deny_mac_file") == NULL, "and not the deny file");
		ncfg_hostapd_lines_free(&lines);
	}

	/* Not `macaddr_acl=0`: an access point that never mentions an ACL and one
	 * whose deny list is empty behave the same, but only the second should
	 * leave a file behind for somebody to find and believe. */
	point.access_control = NULL;
	if (rendered(&point, NULL, &lines)) {
		check(ncfg_hostapd_value_of(&lines, "macaddr_acl") == NULL,
		    "no access_control block says nothing about ACLs at all");
		ncfg_hostapd_lines_free(&lines);
	}
}

static void the_station_file_records_its_policy_above_the_list(void)
{
	ncfg_access_control_t control;
	char                 *stations[] = { (char *)(void *)"aa:bb:cc:dd:ee:ff",
		(char *)(void *)"00:11:22:33:44:55" };
	char                  message[NCFG_ERROR_MAX];
	char                 *text;
	int                   policy = -1;

	memset(&control, 0, sizeof(control));
	control.policy = NCFG_ACL_POLICY_DENY;
	/* An empty list is still a file, and still records its policy: hostapd
	 * refuses to start when `deny_mac_file` points at nothing, so "nobody is
	 * denied" has to be spelled rather than left out (0039). */
	text = ncfg_hostapd_acl_contents(&control, message, sizeof(message));
	check_text(text, "# netcfgd policy: deny\n", "an empty deny list is still a file with a "
	                        "policy");
	/* `hostapd_config_read_maclist` reads with `fgets` into a 128-byte buffer
	 * and treats a line as a comment only when its first byte is `#`. A longer
	 * record would arrive split and its tail parsed as an address. */
	check(text != NULL && strlen(text) < 127u && text[0] == '#',
	    "and is short enough, and starts at byte zero, that hostapd reads it as one comment");
	free(text);

	control.policy = NCFG_ACL_POLICY_ALLOW;
	control.stations = stations;
	control.station_count = 2u;
	text = ncfg_hostapd_acl_contents(&control, message, sizeof(message));
	check_text(text, "# netcfgd policy: allow\naa:bb:cc:dd:ee:ff\n00:11:22:33:44:55\n",
	    "and a filled list is one address per line under the record");
	check(text != NULL && ncfg_hostapd_policy_in(text, &policy) &&
	    policy == NCFG_ACL_POLICY_ALLOW,
	    "the policy is read back out of the file that records it");
	free(text);

	/* A list written by an older netcfgd, or by something that is not netcfgd.
	 * Guessing here would be guessing which list a running hostapd reads, and
	 * getting that wrong opens a network. */
	check(!ncfg_hostapd_policy_in("aa:bb:cc:dd:ee:ff\n", NULL),
	    "a file with no record claims no policy");
	check(!ncfg_hostapd_policy_in("", NULL), "and nor does an empty one");
	check(!ncfg_hostapd_policy_in("# netcfgd policy: whatever\n", NULL),
	    "nor one whose record says something else");
	check(!ncfg_hostapd_policy_in(" # netcfgd policy: deny\n", NULL),
	    "nor an indented one, which hostapd would not treat as a comment either");
}

/* ----------------------------------------------------- the reply parsers */

static void an_acl_show_reply_is_read(void)
{
	char **found = NULL;
	size_t count = 0;
	char   message[NCFG_ERROR_MAX];

	/* Exactly what `hostapd_ctrl_iface_acl_show_mac` prints: `MACSTR
	 * " VLAN_ID=%d\n"` per entry, and hostapd's own default vlan of 0. */
	check(ncfg_hostapd_parse_acl_show(
	      "00:11:22:33:44:55 VLAN_ID=0\naa:bb:cc:dd:ee:ff VLAN_ID=0\n", &found, &count,
	      message, sizeof(message)) &&
	    count == 2u && strcmp(found[0], "00:11:22:33:44:55") == 0 &&
	    strcmp(found[1], "aa:bb:cc:dd:ee:ff") == 0,
	    "a SHOW reply is read, and the VLAN suffix dropped");
	ncfg_hostapd_stations_free(found, count);

	/* Not an error and not a failure: the printer returns zero bytes when there
	 * is nothing to print, so this is what "denies nobody" looks like. */
	check(ncfg_hostapd_parse_acl_show("", &found, &count, message, sizeof(message)) &&
	    count == 0u,
	    "an empty list is an empty reply, not a failure");
	ncfg_hostapd_stations_free(found, count);
	check(ncfg_hostapd_parse_acl_show("\n", &found, &count, message, sizeof(message)) &&
	    count == 0u,
	    "and so is a reply that is only a newline");
	ncfg_hostapd_stations_free(found, count);

	/* hostapd prints a nonzero VLAN_ID for a list netcfgd did not write. The
	 * address still names a station, and dropping it would leave netcfgd unable
	 * to see an entry it then could not remove. */
	check(ncfg_hostapd_parse_acl_show("aa:bb:cc:dd:ee:ff VLAN_ID=7\n", &found, &count, message,
	      sizeof(message)) &&
	    count == 1u && strcmp(found[0], "aa:bb:cc:dd:ee:ff") == 0,
	    "a VLAN assignment is still a station");
	ncfg_hostapd_stations_free(found, count);

	/* Sorted and deduplicated, or a plan would differ on ordering alone and
	 * never converge. */
	check(ncfg_hostapd_parse_acl_show("aa:bb:cc:dd:ee:ff VLAN_ID=0\n"
	                  "00:11:22:33:44:55 VLAN_ID=0\n"
	                  "AA:BB:CC:DD:EE:FF VLAN_ID=0\n",
	      &found, &count, message, sizeof(message)) &&
	    count == 2u && strcmp(found[0], "00:11:22:33:44:55") == 0 &&
	    strcmp(found[1], "aa:bb:cc:dd:ee:ff") == 0,
	    "the list comes back sorted and deduplicated, case-folded first");
	ncfg_hostapd_stations_free(found, count);

	/* `FAIL`, `UNKNOWN COMMAND` and a truncated line all reach here as text.
	 * None of them may become an entry netcfgd then tries to delete. */
	check(ncfg_hostapd_parse_acl_show("FAIL\nUNKNOWN COMMAND\naa:bb:cc VLAN_ID=0\n", &found,
	      &count, message, sizeof(message)) &&
	    count == 0u,
	    "what is not an address is not a station");
	ncfg_hostapd_stations_free(found, count);
}

static void a_station_reply_is_read(void)
{
	/* Exactly what hostapd 2.10 prints, in its order, taken from
	 * `hostapd_ctrl_iface_sta_mib` and `hostapd_get_sta_info`. */
	static const char FULL[] = "aa:bb:cc:dd:ee:ff\n"
	               "flags=[AUTH][ASSOC][AUTHORIZED][SHORT_PREAMBLE][WMM][HT]\n"
	               "aid=1\n"
	               "capability=0x431\n"
	               "listen_interval=10\n"
	               "supported_rates=02 04 0b 16 0c 12 18 24 30 48 60 6c\n"
	               "timeout_next=NULLFUNC POLL\n"
	               "rx_packets=1234\n"
	               "tx_packets=5678\n"
	               "rx_bytes=100000\n"
	               "tx_bytes=200000\n"
	               "inactive_msec=40\n"
	               "signal=-52\n"
	               "rx_rate_info=650 mcs 7 shortGI\n"
	               "tx_rate_info=650 mcs 7 shortGI\n"
	               "connected_time=3600\n";
	/* `hostapd_get_sta_info` writes nothing at all when the driver read fails,
	 * so this is a normal reply. A parser that required `signal=` would drop a
	 * client that is really there. */
	static const char BARE[] = "aa:bb:cc:dd:ee:ff\n"
	               "flags=[AUTH][ASSOC]\n"
	               "aid=1\n"
	               "capability=0x431\n"
	               "listen_interval=10\n"
	               "supported_rates=02 04\n"
	               "timeout_next=NULLFUNC POLL\n";
	ncfg_hostapd_station_t station;

	check(ncfg_hostapd_parse_station(FULL, &station) &&
	    strcmp(station.address, "aa:bb:cc:dd:ee:ff") == 0 && station.authorized &&
	    station.signal_dbm.has && station.signal_dbm.value == -52 &&
	    station.connected_seconds.has && station.connected_seconds.value == 3600 &&
	    station.inactive_msec.has && station.inactive_msec.value == 40 &&
	    station.rx_bytes.has && station.rx_bytes.value == 100000 &&
	    station.tx_bytes.has && station.tx_bytes.value == 200000,
	    "a full station reply is read, every field");

	check(ncfg_hostapd_parse_station(BARE, &station) &&
	    strcmp(station.address, "aa:bb:cc:dd:ee:ff") == 0 && !station.signal_dbm.has &&
	    !station.rx_bytes.has && !station.authorized,
	    "a station with no driver statistics is still a station, and not authorized yet");

	/* Both spellings hostapd uses for "no more": an empty reply from a null
	 * station, and FAIL for an address it does not know. */
	check(!ncfg_hostapd_parse_station("", &station), "an empty reply is the end of the walk");
	check(!ncfg_hostapd_parse_station("\n", &station), "and so is a bare newline");
	check(!ncfg_hostapd_parse_station("FAIL\n", &station), "and so is FAIL");
	check(!ncfg_hostapd_parse_station("UNKNOWN COMMAND\n", &station),
	    "and a reply whose first line is not an address is not trusted into the list");

	/* So that a station read back from hostapd compares equal to one written in
	 * an `access_control` block, which is what makes "deny the one I can see" a
	 * string comparison. */
	check(ncfg_hostapd_parse_station("AA-BB-CC-DD-EE-FF\nflags=[AUTH]\n", &station) &&
	    strcmp(station.address, "aa:bb:cc:dd:ee:ff") == 0,
	    "the address is normalised like every other station address");
	check(!ncfg_hostapd_normalize_station("aabbccddeeff", station.address,
	      sizeof(station.address), NULL, 0),
	    "and a bare twelve digits is refused, because an ACL is the wrong place to guess");
}

/* ------------------------------------------------------------- the files */

static void a_rewritten_configuration_is_still_only_readable_by_root(const char *run)
{
	ncfg_access_point_t     point = point_of(NCFG_SECURITY_PSK, NCFG_PSK_PROTO_WPA2);
	ncfg_secret_resolver_t  resolver;
	char                    secret[512];
	char                    path[NCFG_HOSTAPD_PATH_MAX];
	char                    message[NCFG_ERROR_MAX];
	char                   *body;

	memset(&resolver, 0, sizeof(resolver));
	resolver.secrets_dir = run;
	(void)testdir_in(run, "guest", secret, sizeof(secret));
	check(testdir_write(secret, CANARY "\n", strlen(CANARY) + 1u) && chmod(secret, 0600) == 0,
	    "a secret of this test's own, never the machine's");

	message[0] = '\0';
	check(ncfg_hostapd_write_config(run, &point, &resolver, path, sizeof(path), message,
	      sizeof(message)),
	    "the first write");
	if (message[0] != '\0') {
		printf("  said: %s\n", kept(message));
	}
	check(testdir_mode(path) == 0600, "leaves the configuration readable only by root");

	/* Something -- an older netcfgd, another tool, a hand -- leaves it
	 * world-readable, and netcfgd writes over it. This is the case that was
	 * broken: `open`'s mode applies only when the call creates the file. */
	check(chmod(path, 0644) == 0, "and something widens it");
	message[0] = '\0';
	check(ncfg_hostapd_write_config(run, &point, &resolver, path, sizeof(path), message,
	      sizeof(message)),
	    "the second write");
	check(testdir_mode(path) == 0600, "narrows it again, which is the defect this exists for");

	/* And the thing the mode is for is in fact in the file, so this is not
	 * passing over an empty one. */
	body = testdir_read(path, NULL);
	check(body != NULL && strstr(body, CANARY) != NULL,
	    "the passphrase is what the mode protects, and it really is in there");
	if (body) {
		memset(body, 0, strlen(body));
	}
	free(body);
}

static void the_access_point_is_told_where_to_record_its_pid(void)
{
	const char *argv[8];
	size_t      count;
	char        pid[NCFG_HOSTAPD_PATH_MAX];
	char        other[NCFG_HOSTAPD_PATH_MAX];
	char        config[NCFG_HOSTAPD_PATH_MAX];

	check(ncfg_hostapd_pid_path("/run/netcfgd", "ap0", pid, sizeof(pid), NULL, 0) &&
	    strcmp(pid, "/run/netcfgd/hostapd/ap0.pid") == 0,
	    "the pid file sits beside the socket and the configuration, named for the device");
	check(ncfg_hostapd_pid_path("/run/netcfgd", "ap1", other, sizeof(other), NULL, 0) &&
	    strcmp(pid, other) != 0,
	    "and two devices never collide");
	check(ncfg_hostapd_config_path("/run/netcfgd", "ap0", config, sizeof(config), NULL, 0),
	    "the config path");

	count = ncfg_hostapd_start_args("/usr/sbin/hostapd", pid, config, argv,
	    sizeof(argv) / sizeof(argv[0]));
	/* The pid path is asserted as a whole string rather than "contains -P",
	 * because the path is not decoration: it is the marker the liveness check
	 * looks for in `/proc/<pid>/cmdline`, so a `-P` pointing somewhere netcfgd
	 * does not read would satisfy a looser check and tell netcfgd nothing. */
	check(count == 5u && strcmp(argv[0], "/usr/sbin/hostapd") == 0 &&
	    strcmp(argv[1], "-B") == 0 && strcmp(argv[2], "-P") == 0 &&
	    strcmp(argv[3], "/run/netcfgd/hostapd/ap0.pid") == 0 &&
	    strcmp(argv[4], "/run/netcfgd/hostapd/ap0.conf") == 0 && argv[5] == NULL,
	    "both flags in hostapd's order, with the pid file netcfgd chose");
}

/*
 * The station list's lifecycle, and the three answers a recorded policy has.
 *
 * The two ways of finding no policy mean opposite things, and confusing them
 * either restarts an access point over a permissions problem or converges a
 * list netcfgd does not know hostapd reads.
 */
static void the_station_list_lives_and_dies_with_its_block(const char *run)
{
	ncfg_access_point_t    point = point_of(NCFG_SECURITY_OPEN, NCFG_PSK_PROTO_WPA2);
	ncfg_access_control_t  control;
	char                  *stations[] = { (char *)(void *)"aa:bb:cc:dd:ee:ff" };
	ncfg_observed_policy_t seen;
	char                   acl[NCFG_HOSTAPD_PATH_MAX];
	char                   message[NCFG_ERROR_MAX];
	char                   dir[NCFG_HOSTAPD_PATH_MAX];

	point.device = (char *)(void *)"aptest";
	memset(&control, 0, sizeof(control));
	control.policy = NCFG_ACL_POLICY_DENY;
	control.stations = stations;
	control.station_count = 1u;
	point.access_control = &control;

	check(ncfg_hostapd_ctrl_dir(run, dir, sizeof(dir), NULL, 0) &&
	    (mkdir(dir, 0755) == 0 || testdir_exists(dir)),
	    "the control directory exists");
	check(ncfg_hostapd_acl_path(run, "aptest", acl, sizeof(acl), NULL, 0), "the acl path");

	ncfg_hostapd_recorded_policy(run, "aptest", &seen);
	check(seen.kind == NCFG_OBSERVED_POLICY_UNSET,
	    "no file at all is `unset`: hostapd was started with no macaddr_acl");

	message[0] = '\0';
	check(ncfg_hostapd_write_acl(run, &point, message, sizeof(message)), "the list is written");
	if (message[0] != '\0') {
		printf("  said: %s\n", kept(message));
	}
	/* 0644, because a list of MAC addresses only root can read is a list nobody
	 * debugging an access point can read either. */
	check(testdir_mode(acl) == 0644, "at 0644, since it holds no secret");
	ncfg_hostapd_recorded_policy(run, "aptest", &seen);
	check(seen.kind == NCFG_OBSERVED_POLICY_SET && seen.policy == NCFG_ACL_POLICY_DENY,
	    "and the policy hostapd was started with is read back out of it");

	check(testdir_write(acl, "aa:bb:cc:dd:ee:ff\n", 18u), "a list from an older netcfgd");
	ncfg_hostapd_recorded_policy(run, "aptest", &seen);
	check(seen.kind == NCFG_OBSERVED_POLICY_UNKNOWN,
	    "a file with no record is `unknown`, and nothing may be converged from there");

	/* A block that was there and is not any more. Leaving the file would leave
	 * a list that nothing reads, which is worse than no file: the next person
	 * to look would find an ACL and believe it. */
	point.access_control = NULL;
	check(ncfg_hostapd_write_acl(run, &point, message, sizeof(message)) &&
	    !testdir_exists(acl),
	    "a block that went takes its file with it");
	check(ncfg_hostapd_write_acl(run, &point, message, sizeof(message)),
	    "and removing one that is already gone is not an error");
}

/*
 * A daemon that refuses the configuration is quoted, not summarised.
 *
 * hostapd announces the problem and then narrates its shutdown, so the last
 * three lines of a failed start are `AP-DISABLED`, `CTRL-EVENT-TERMINATING` and
 * `Interface ap0 wasn't started` -- all true, none of them the reason. The
 * stand-in below writes exactly that shape.
 */
static void a_daemon_that_will_not_start_is_quoted(const char *run)
{
	ncfg_access_point_t    point = point_of(NCFG_SECURITY_OPEN, NCFG_PSK_PROTO_WPA2);
	ncfg_secret_resolver_t resolver;
	char                   fake[512];
	char                   body[1024];
	char                   message[NCFG_ERROR_MAX];

	memset(&resolver, 0, sizeof(resolver));
	resolver.secrets_dir = run;
	point.device = (char *)(void *)"apangry";

	(void)testdir_in(run, "fake-hostapd", fake, sizeof(fake));
	(void)snprintf(body, sizeof(body),
	    "#!/bin/sh\n"
	    "echo 'Configuration file: /run/netcfgd/hostapd/apangry.conf'\n"
	    "echo 'Line 6: unknown configuration item'\n"
	    "echo 'apangry: AP-DISABLED'\n"
	    "echo 'apangry: CTRL-EVENT-TERMINATING'\n"
	    "echo \"Interface apangry wasn't started\"\n"
	    "exit 1\n");
	check(testdir_write(fake, body, strlen(body)) && chmod(fake, 0755) == 0,
	    "the stand-in daemon is written and executable");

	message[0] = '\0';
	check(!ncfg_hostapd_start(run, &point, &resolver, fake, message, sizeof(message)),
	    "a daemon that refuses the configuration fails the start");
	(void)kept(message);
	check(strstr(message, "Line 6: unknown configuration item") != NULL,
	    "and the refusal quotes the line hostapd objected to");
	check(strstr(message, "wasn't started") == NULL && strstr(message, "AP-DISABLED") == NULL,
	    "rather than the tail, which is hostapd narrating its own shutdown");
	check(strstr(message, ".log") != NULL, "and says where the rest of the output is");
}

/* --------------------------------------------------------------- the sweep */

/*
 * Every channel a passphrase could leak through, read back for the canary.
 *
 * `secrets_test.c`'s method. The vacuity check comes first: the canary must be
 * shown to have been in this process at all, or every sweep below would pass
 * while proving nothing.
 */
static void the_credential_reaches_no_diagnostic(const char *run, const char *stderr_path)
{
	ncfg_access_point_t    point = point_of(NCFG_SECURITY_PSK, NCFG_PSK_PROTO_WPA2_WPA3);
	ncfg_secret_resolver_t resolver;
	char                   secret[512];
	char                   path[NCFG_HOSTAPD_PATH_MAX];
	char                   message[NCFG_ERROR_MAX];
	char                  *written;
	char                  *errors;

	memset(&resolver, 0, sizeof(resolver));
	resolver.secrets_dir = run;
	point.device = (char *)(void *)"apsweep";
	(void)testdir_in(run, "guest", secret, sizeof(secret));

	message[0] = '\0';
	check(ncfg_hostapd_write_config(run, &point, &resolver, path, sizeof(path), message,
	      sizeof(message)),
	    "the sweep's configuration is written");
	if (message[0] != '\0') {
		printf("  said: %s\n", kept(message));
	}
	written = testdir_read(path, NULL);
	check(written != NULL && strstr(written, CANARY) != NULL,
	    "the canary really was in this process, so the sweeps below are not vacuous");
	if (written) {
		memset(written, 0, strlen(written));
	}
	free(written);

	/* Every failure path this module has, driven with the canary in hand. */
	(void)refused(&point, CANARY "\nssid2=deadbeef", NCFG_HOSTAPD_PASSPHRASE_NOT_WRITABLE,
	    "a canary with a newline is refused");
	{
		ncfg_access_point_t bad = point;
		/* Two canaries, which is 96 octets and past `wpa_passphrase`'s 63 --
		 * and still the canary, so the refusal it produces is swept. */
		static const char too_long[] = CANARY CANARY;

		(void)refused(&bad, too_long, NCFG_HOSTAPD_PASSPHRASE_LENGTH,
		    "a canary too long for the field is refused");
		bad.band = (char *)(void *)"5";
		(void)refused(&bad, CANARY, NCFG_HOSTAPD_CHANNEL_NOT_IN_BAND,
		    "a canary on a channel outside its band is refused");
		bad.band = (char *)(void *)"6";
		(void)refused(&bad, CANARY, NCFG_HOSTAPD_SIX_GIGAHERTZ,
		    "a canary on 6 GHz is refused");
		bad.band = NULL;
		bad.regdom = (char *)(void *)"SWE";
		(void)refused(&bad, CANARY, NCFG_HOSTAPD_MALFORMED_REGDOM,
		    "a canary with a malformed regdom is refused");
	}

	check(strstr(every_message, CANARY) == NULL,
	    "and no `err` buffer this file has filled carries the passphrase");

	(void)fflush(stderr);
	errors = testdir_read(stderr_path, NULL);
	check(errors != NULL && strstr(errors, CANARY) == NULL,
	    "nor does this process' whole standard error");
	free(errors);
}

int main(void)
{
	const char *run = testdir_make("hostapd");
	char        stderr_path[512];
	int         saved;
	int         redirected;

	/* Standard error to a file for the length of the run, which is where a log
	 * line would land -- and where a secret helper's own diagnostics would land
	 * if anything let them through. */
	(void)testdir_in(run, "stderr", stderr_path, sizeof(stderr_path));
	saved = dup(STDERR_FILENO);
	redirected = open(stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (redirected >= 0) {
		(void)dup2(redirected, STDERR_FILENO);
		(void)close(redirected);
	}

	an_open_network_carries_no_wpa_lines();
	wpa2_uses_a_passphrase_and_wpa3_uses_sae();
	transition_mode_offers_both_and_still_protects_sae();
	only_the_arms_that_write_wpa_passphrase_are_length_checked();
	owe_needs_no_secret();
	an_ssid_that_is_not_text_survives_as_hex();
	the_band_follows_the_channel_when_nothing_says_otherwise();
	no_channel_asks_hostapd_to_choose();
	a_channel_that_contradicts_its_band_is_refused();
	a_channel_in_no_band_is_refused_even_with_no_band_declared();
	six_gigahertz_and_unknown_bands_are_refused_differently();
	a_regdom_is_advertised_as_well_as_recorded();
	enterprise_is_refused_by_name();
	a_passphrase_that_would_break_the_file_is_refused();
	the_redacted_form_keeps_everything_that_is_not_the_secret();

	the_acl_files_are_alternatives();
	the_station_file_records_its_policy_above_the_list();

	an_acl_show_reply_is_read();
	a_station_reply_is_read();

	a_rewritten_configuration_is_still_only_readable_by_root(run);
	the_access_point_is_told_where_to_record_its_pid();
	the_station_list_lives_and_dies_with_its_block(run);
	a_daemon_that_will_not_start_is_quoted(run);
	the_credential_reaches_no_diagnostic(run, stderr_path);

	if (saved >= 0) {
		(void)fflush(stderr);
		(void)dup2(saved, STDERR_FILENO);
		(void)close(saved);
	}
	testdir_remove(run);
	if (failures > 0) {
		printf("hostapd: %d check(s) failed\n", failures);
		return 1;
	}
	printf("hostapd: every check passed\n");
	return 0;
}
