/*
 * supplicant_test.c -- the control protocol's text and the configuration it
 * carries, checked without a radio.
 *
 * WHAT IS HERE AND WHAT IS NEXT DOOR
 *   All of this runs without a radio, without root and without
 *   `wpa_supplicant` installed: it is the port of
 *   `backend/netcfgd-supplicant/tests/protocol.rs`, case for case, and each
 *   keeps the sentence saying which defect it is about. The socket is
 *   `supplicant_client_test.c`, which drives a fake of its own making -- and
 *   the credential canary lives there, because a credential's whole journey is
 *   what has to be swept.
 *
 * NOTHING OUTSIDE ITS OWN DIRECTORY
 *   This machine has a real `/etc/netcfgd/secrets` with real credentials in
 *   it, and a real `wpa_supplicant` on its radio. Every path here is under one
 *   `mkdtemp` directory and no default is ever reached; nothing here opens a
 *   socket at all.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/secrets.h"
#include "ncfg/supplicant.h"

#include "testdir.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/*
 * A writable copy of a literal, from a fixed arena.
 *
 * The document's fields are `char *` and under `-Wwrite-strings` a literal is
 * not one. An arena rather than `strdup` because these run under ASan, where a
 * fixture nobody frees is a failure -- and a fixture built on the stack has no
 * `ncfg_document_free` to hand it to.
 */
static char   arena[32u * 1024u];
static size_t arena_used;

static char *text(const char *value)
{
	size_t length = strlen(value) + 1u;
	char  *out;

	if (arena_used + length > sizeof(arena)) {
		printf("the fixture arena is full; this test needs a bigger one\n");
		exit(1);
	}
	out = arena + arena_used;
	memcpy(out, value, length);
	arena_used += length;
	return out;
}

/* ------------------------------------------------------------- the fixtures */

static void a_network(ncfg_wifi_network_t *out, const char *id, const char *ssid)
{
	memset(out, 0, sizeof(*out));
	out->id = text(id);
	if (ssid) {
		out->ssid.has = 1;
		out->ssid.length = strlen(ssid);
		memcpy(out->ssid.bytes, ssid, out->ssid.length);
	}
	out->autoconnect = 1;
	out->security.kind = NCFG_SECURITY_OPEN;
}

static void psk_security(ncfg_security_t *out, const char *name, int proto)
{
	memset(out, 0, sizeof(*out));
	out->kind = NCFG_SECURITY_PSK;
	out->psk.passphrase.provider = NCFG_SECRET_PROVIDER_FILE;
	out->psk.passphrase.name = text(name);
	out->psk.proto = proto;
}

static void stored_source(ncfg_cert_source_t *out, const char *name)
{
	memset(out, 0, sizeof(*out));
	out->has = 1;
	out->kind = NCFG_CERT_SOURCE_STORED;
	out->stored.provider = NCFG_SECRET_PROVIDER_FILE;
	out->stored.name = text(name);
}

static void path_source(ncfg_cert_source_t *out, const char *path)
{
	memset(out, 0, sizeof(*out));
	out->has = 1;
	out->kind = NCFG_CERT_SOURCE_PATH;
	out->path = text(path);
}

/* A secret the `file` provider will accept: 0600, and nothing else may read
 * it -- which the resolver checks and refuses. */
static void write_secret(const char *dir, const char *name, const char *body)
{
	char path[512];

	(void)snprintf(path, sizeof(path), "%s/%s", dir, name);
	if (!testdir_write(path, body, strlen(body)) || chmod(path, (mode_t)0600) != 0) {
		printf("could not write the fixture secret %s\n", path);
		exit(1);
	}
}

/* ------------------------------------------------------------ the rendering */

/*
 * Every command a network renders to, one per line and the whole thing opening
 * with a newline, so a whole-line search cannot match the tail of a longer
 * line. The Rust's `rendered()` helper, with the boundary made explicit.
 */
static int render(const ncfg_wifi_network_t *network, int policy,
    const ncfg_secret_resolver_t *resolver, ncfg_buf_t *out, char *err, size_t err_size)
{
	ncfg_supplicant_settings_t settings;
	size_t                     index;
	int                        built = 1;

	ncfg_buf_init(out, 0);
	if (!ncfg_supplicant_settings(network, NULL, policy, resolver, &settings, err,
	    err_size)) {
		return 0;
	}
	/* Whatever is appended below may carry a credential, so a caller that
	 * fails halfway still owes the buffer a wipe -- and gets one either way,
	 * because a failure here leaves it empty rather than half-built. */
	ncfg_buf_add_char(out, '\n');
	for (index = 0; built && index < settings.count; index++) {
		ncfg_buf_t line;

		ncfg_buf_init(&line, 0);
		built = ncfg_supplicant_setting_command(&settings.items[index], 0, resolver, &line,
		    err, err_size);
		if (built) {
			ncfg_buf_add_text(out, ncfg_buf_text(&line));
			ncfg_buf_add_char(out, '\n');
		}
		ncfg_supplicant_buf_wipe(&line);
	}
	ncfg_supplicant_settings_free(&settings);
	if (!built) {
		ncfg_supplicant_buf_wipe(out);
		ncfg_buf_init(out, 0);
	}
	return built;
}

static int line_present(const ncfg_buf_t *rendered, const char *line)
{
	char wanted[1024];

	(void)snprintf(wanted, sizeof(wanted), "\n%s\n", line);
	return strstr(ncfg_buf_text(rendered), wanted) != NULL;
}

static int somewhere(const ncfg_buf_t *rendered, const char *fragment)
{
	return strstr(ncfg_buf_text(rendered), fragment) != NULL;
}

static const ncfg_supplicant_setting_t *setting_named(const ncfg_supplicant_settings_t *settings,
    const char *variable)
{
	size_t index;

	for (index = 0; index < settings->count; index++) {
		if (strcmp(settings->items[index].variable, variable) == 0) {
			return &settings->items[index];
		}
	}
	return NULL;
}

/* ================================================================= protocol */

static void ok_fail_and_data_are_distinguished(void)
{
	char one[64];

	(void)snprintf(one, sizeof(one), "OK\n");
	check(ncfg_supplicant_reply_parse(one) == NCFG_SUPPLICANT_REPLY_OK &&
	    strcmp(one, "OK") == 0, "`OK` is an acknowledgement, with its newline gone");
	(void)snprintf(one, sizeof(one), "FAIL\n");
	check(ncfg_supplicant_reply_parse(one) == NCFG_SUPPLICANT_REPLY_FAIL, "`FAIL` is a refusal");
	/* A build without a feature answers this, and it is a refusal rather than
	 * a body a caller would carry around as a value. */
	(void)snprintf(one, sizeof(one), "UNKNOWN COMMAND\n");
	check(ncfg_supplicant_reply_parse(one) == NCFG_SUPPLICANT_REPLY_FAIL,
	    "and so is `UNKNOWN COMMAND`");
	(void)snprintf(one, sizeof(one), "PONG\n");
	check(ncfg_supplicant_reply_parse(one) == NCFG_SUPPLICANT_REPLY_DATA &&
	    strcmp(one, "PONG") == 0, "anything else is a body");
	/* The supplicant NUL-terminates some replies, which a C string has
	 * already ended at. */
	(void)snprintf(one, sizeof(one), "OK\n");
	one[3] = '\0';
	check(ncfg_supplicant_reply_parse(one) == NCFG_SUPPLICANT_REPLY_OK,
	    "and a NUL after the newline changes nothing");
}

/*
 * A reply arriving as an event would be acted on as the answer to whatever
 * command was outstanding. Telling them apart is the whole reason the client
 * loops rather than reading once.
 */
static void events_are_not_mistaken_for_replies(void)
{
	check(ncfg_supplicant_is_event("<3>CTRL-EVENT-CONNECTED - Connection to 00:11 completed"),
	    "a priority in angle brackets is an event");
	check(ncfg_supplicant_is_event("<2>CTRL-EVENT-SCAN-RESULTS "), "and so is a bare one");
	check(!ncfg_supplicant_is_event("OK"), "`OK` is not");
	check(!ncfg_supplicant_is_event("PONG"), "nor is `PONG`");
	/* A scan result row starts with a BSSID, never a priority. */
	check(!ncfg_supplicant_is_event(
	    "00:11:22:33:44:55\t2412\t-40\t[WPA2-PSK-CCMP][ESS]\thome"),
	    "nor a scan row, which opens with an address");
	/* Not an event just because it opens with a bracket a long way from a
	 * close: a network name could. */
	check(!ncfg_supplicant_is_event("<this is not a priority>"),
	    "and not a line that merely opens with a bracket");
}

static void an_event_keeps_its_priority_and_name(void)
{
	ncfg_supplicant_event_t event;
	char                    name[64];

	check(ncfg_supplicant_event_parse(
	    "<3>CTRL-EVENT-DISCONNECTED bssid=00:11:22:33:44:55 reason=3", &event) &&
	    event.priority == 3, "an event keeps its priority");
	check(strcmp(ncfg_supplicant_event_name(&event, name, sizeof(name)),
	    "CTRL-EVENT-DISCONNECTED") == 0, "and its name is its first word");
	check(!ncfg_supplicant_event_parse("OK", &event), "and a reply is not an event");
}

static void scan_results_parse(void)
{
	ncfg_supplicant_scan_t *rows = NULL;
	size_t                  count = 0;
	char                    message[NCFG_ERROR_MAX];

	check(ncfg_supplicant_parse_scan_results(
	    "bssid / frequency / signal level / flags / ssid\n"
	    "00:11:22:33:44:55\t2412\t-40\t[WPA2-PSK-CCMP][ESS]\thome\n"
	    "66:77:88:99:aa:bb\t5180\t-72\t[ESS]\tcafe wifi\n",
	    &rows, &count, message, sizeof(message)) && count == 2u,
	    "a scan with a header and two rows gives two results");
	if (count == 2u) {
		check(rows[0].frequency == 2412 && rows[0].signal == -40,
		    "with the frequency and the signal as numbers");
		check(rows[0].ssid.length == 4u && memcmp(rows[0].ssid.bytes, "home", 4u) == 0,
		    "and the name as octets");
		check(ncfg_supplicant_scan_is_secured(&rows[0]) &&
		    !ncfg_supplicant_scan_is_secured(&rows[1]),
		    "and the flags say which needs a credential");
		check(rows[1].ssid.length == 9u &&
		    memcmp(rows[1].ssid.bytes, "cafe wifi", 9u) == 0,
		    "a space in a name is not a separator");
	}
	ncfg_supplicant_scans_free(rows, count);
}

/*
 * The supplicant does not return the octets it was given: it escapes a quote,
 * a backslash, the usual control characters, and **every byte outside
 * printable ASCII**. A reader that takes the field literally shows
 * `caf\xc3\xa9` to somebody looking for their coffee shop -- so this is wrong
 * for every network name that is not plain ASCII, which is most of them
 * outside the English-speaking world.
 *
 * The escapes below are copied from what a real `wpa_supplicant` 2.10
 * produced, not from its documentation, which does not mention any of this.
 */
static void escaped_ssids_are_decoded(void)
{
	struct {
		const char   *escaped;
		unsigned char expected[16];
		size_t        length;
	} cases[] = {
		{ "home", { 'h', 'o', 'm', 'e' }, 4u },
		{ "caf\\xc3\\xa9", { 'c', 'a', 'f', 0xc3, 0xa9 }, 5u },
		{ "\\xe2\\x8c\\x98", { 0xe2, 0x8c, 0x98 }, 3u },
		{ "\\xff\\x00\\x80a", { 0xff, 0x00, 0x80, 'a' }, 4u },
		{ "\\\"", { '"' }, 1u },
		{ "\\\\", { '\\' }, 1u },
		{ "\\n", { '\n' }, 1u },
		{ "\\t", { '\t' }, 1u },
		{ "with space", { 'w', 'i', 't', 'h', ' ', 's', 'p', 'a', 'c', 'e' }, 10u }
	};
	size_t which;
	int    all = 1;

	for (which = 0; which < sizeof(cases) / sizeof(cases[0]); which++) {
		char                    body[256];
		ncfg_supplicant_scan_t *rows = NULL;
		size_t                  count = 0;
		char                    message[NCFG_ERROR_MAX];

		(void)snprintf(body, sizeof(body),
		    "header\n00:11:22:33:44:55\t2412\t-40\t[ESS]\t%s\n", cases[which].escaped);
		if (!ncfg_supplicant_parse_scan_results(body, &rows, &count, message,
		    sizeof(message)) || count != 1u ||
		    rows[0].ssid.length != cases[which].length ||
		    memcmp(rows[0].ssid.bytes, cases[which].expected,
		    cases[which].length) != 0) {
			all = 0;
		}
		ncfg_supplicant_scans_free(rows, count);
	}
	check(all, "every escape a real supplicant produces decodes back to its octets");
}

/*
 * Because a tab inside a name arrives escaped, the line and field structure is
 * never ambiguous -- which is the property that makes a line-oriented parser
 * safe here at all.
 */
static void a_tab_or_newline_in_a_name_cannot_break_the_row_structure(void)
{
	ncfg_supplicant_scan_t *rows = NULL;
	size_t                  count = 0;
	char                    message[NCFG_ERROR_MAX];

	check(ncfg_supplicant_parse_scan_results(
	    "header\n00:11:22:33:44:55\t2412\t-40\t[ESS]\tone\\ttwo\\nthree\n", &rows, &count,
	    message, sizeof(message)) && count == 1u,
	    "one row, whatever the name contains");
	check(count == 1u && rows[0].ssid.length == 13u &&
	    memcmp(rows[0].ssid.bytes, "one\ttwo\nthree", 13u) == 0,
	    "and the tab and newline in it are the name's, not the format's");
	ncfg_supplicant_scans_free(rows, count);
}

/* A malformed escape must not lose the rest of the name. */
static void a_truncated_escape_is_not_fatal(void)
{
	unsigned char out[16];

	check(ncfg_supplicant_printf_decode("a\\xzz", out, sizeof(out)) == 5u &&
	    memcmp(out, "a\\xzz", 5u) == 0, "`\\xzz` is four characters of a name, not a failure");
	check(ncfg_supplicant_printf_decode("trailing\\", out, sizeof(out)) == 9u &&
	    memcmp(out, "trailing\\", 9u) == 0, "and a trailing backslash is kept, as it is there");
}

/*
 * One unparseable row from a misbehaving access point must not cost the
 * operator the whole scan.
 */
static void a_malformed_scan_row_is_skipped_not_fatal(void)
{
	ncfg_supplicant_scan_t *rows = NULL;
	size_t                  count = 0;
	char                    message[NCFG_ERROR_MAX];

	check(ncfg_supplicant_parse_scan_results(
	    "header\ngarbage\n00:11:22:33:44:55\t2412\t-40\t[ESS]\tgood\n\tnot\tenough\n", &rows,
	    &count, message, sizeof(message)) && count == 1u,
	    "a row that makes no sense is skipped rather than failing the scan");
	check(count == 1u && rows[0].ssid.length == 4u &&
	    memcmp(rows[0].ssid.bytes, "good", 4u) == 0, "and the good one is still there");
	ncfg_supplicant_scans_free(rows, count);
}

static void network_lists_and_status_parse(void)
{
	ncfg_supplicant_entry_t       *entries = NULL;
	ncfg_supplicant_status_pair_t *status = NULL;
	size_t                         count = 0;
	char                           message[NCFG_ERROR_MAX];

	check(ncfg_supplicant_parse_network_list(
	    "network id / ssid / bssid / flags\n0\thome\tany\t[CURRENT]\n1\twork\tany\t[DISABLED]\n",
	    &entries, &count, message, sizeof(message)) && count == 2u,
	    "`LIST_NETWORKS` gives one entry per row");
	if (count == 2u) {
		check(entries[0].id == 0u && entries[0].ssid.length == 4u &&
		    memcmp(entries[0].ssid.bytes, "home", 4u) == 0, "with its id and its name");
		check(ncfg_supplicant_entry_is_current(&entries[0]) &&
		    !ncfg_supplicant_entry_is_current(&entries[1]),
		    "and the flags say which one is selected");
	}
	ncfg_supplicant_entries_free(entries, count);

	count = 0;
	check(ncfg_supplicant_parse_status("wpa_state=COMPLETED\nssid=home\nip_address=192.0.2.5\n",
	    &status, &count, message, sizeof(message)) && count == 3u,
	    "`STATUS` is key and value per line");
	check(ncfg_supplicant_status_field(status, count, "wpa_state") &&
	    strcmp(ncfg_supplicant_status_field(status, count, "wpa_state"), "COMPLETED") == 0,
	    "and a field can be asked for by name");
	check(ncfg_supplicant_status_field(status, count, "absent") == NULL,
	    "one that is not there is absent rather than empty");
	ncfg_supplicant_status_free(status, count);
}

/*
 * An entry with no flags column is normal -- a network that is neither current
 * nor disabled has nothing there -- and must not be dropped.
 */
static void a_network_with_no_flags_still_parses(void)
{
	ncfg_supplicant_entry_t *entries = NULL;
	size_t                   count = 0;
	char                     message[NCFG_ERROR_MAX];

	check(ncfg_supplicant_parse_network_list("header\n0\thome\tany\n", &entries, &count,
	    message, sizeof(message)) && count == 1u && strcmp(entries[0].flags, "") == 0,
	    "a network with no flags is a network, with no flags");
	ncfg_supplicant_entries_free(entries, count);
}

/*
 * The reason SSIDs go out as hex: a network name is 32 arbitrary octets chosen
 * by whoever named it, and a quoted one would be a place where those octets
 * become protocol syntax.
 */
static void an_ssid_cannot_inject_a_command(void)
{
	ncfg_ssid_t hostile;
	char        argument[NCFG_SUPPLICANT_SSID_HEX_SIZE];
	size_t      index;
	int         hex_only = 1;

	memset(&hostile, 0, sizeof(hostile));
	hostile.has = 1;
	hostile.length = strlen("\"; REMOVE_NETWORK all; \"");
	memcpy(hostile.bytes, "\"; REMOVE_NETWORK all; \"", hostile.length);

	check(ncfg_supplicant_ssid_argument(&hostile, argument, sizeof(argument)),
	    "a network with a silly name still renders");
	for (index = 0; argument[index] != '\0'; index++) {
		hex_only = hex_only && ((argument[index] >= '0' && argument[index] <= '9') ||
		    (argument[index] >= 'a' && argument[index] <= 'f'));
	}
	check(hex_only, "an SSID argument is hex and nothing else");
	check(!strstr(argument, "REMOVE") && !strchr(argument, '"') && !strchr(argument, ' '),
	    "so a name that reads like a command is a name");
}

/*
 * Hex also means a name that is not text at all survives intact, which a
 * quoted encoding would have had to mangle or refuse.
 */
static void a_non_utf8_ssid_round_trips(void)
{
	ncfg_ssid_t ssid;
	char        argument[NCFG_SUPPLICANT_SSID_HEX_SIZE];

	memset(&ssid, 0, sizeof(ssid));
	ssid.has = 1;
	ssid.length = 4u;
	ssid.bytes[0] = 0xff;
	ssid.bytes[1] = 0x00;
	ssid.bytes[2] = 0x80;
	ssid.bytes[3] = 'a';
	check(ncfg_supplicant_ssid_argument(&ssid, argument, sizeof(argument)) &&
	    strcmp(argument, "ff008061") == 0,
	    "a name with no text in it goes out whole, including its NUL");
}

/*
 * A passphrase must be quoted, so the escaping is the control rather than an
 * encoding detail.
 */
static void a_passphrase_cannot_escape_its_quotes(void)
{
	ncfg_buf_t quoted;
	size_t     index;
	size_t     quotes = 0;

	ncfg_buf_init(&quoted, 0);
	ncfg_supplicant_quote(&quoted, "a\"; REMOVE_NETWORK all; b");
	for (index = 0; ncfg_buf_text(&quoted)[index] != '\0'; index++) {
		if (ncfg_buf_text(&quoted)[index] == '"') {
			quotes++;
		}
	}
	check(quotes == 3u, "two delimiters and one escaped, so the string ends where it should");
	check(strstr(ncfg_buf_text(&quoted), "\\\"") != NULL, "the inner quote is escaped");
	ncfg_buf_free(&quoted);

	/* A trailing backslash must not escape the closing quote. */
	ncfg_buf_init(&quoted, 0);
	ncfg_supplicant_quote(&quoted, "pass\\");
	check(strcmp(ncfg_buf_text(&quoted), "\"pass\\\\\"") == 0,
	    "and a trailing backslash cannot escape the delimiter");
	ncfg_buf_free(&quoted);
}

/*
 * The four security shapes a scan row can be, told apart.
 *
 * **OWE is the one that had no answer.** `is_secured` asks whether joining
 * needs a credential, and OWE needs none -- so it answers false, exactly as it
 * does for a genuinely open network, and every client stopped there and called
 * it open. They are not the same network to join: OWE is its own key
 * management with management frame protection required, and an open profile
 * against one does not associate. 0227.
 */
static void a_scan_row_says_which_of_the_four_security_shapes_it_is(void)
{
	ncfg_supplicant_scan_t *rows = NULL;
	size_t                  count = 0;
	char                    message[NCFG_ERROR_MAX];
	size_t                  index;
	int                     shapes = 1;
	int                     names = 1;

	(void)ncfg_supplicant_parse_scan_results(
	    "bssid / frequency / signal level / flags / ssid\n"
	    "00:00:00:00:00:01\t2412\t-40\t[WPA2-PSK-CCMP][ESS]\tpsk\n"
	    "00:00:00:00:00:02\t2412\t-40\t[WPA2-EAP-CCMP][ESS]\tcorp\n"
	    "00:00:00:00:00:03\t2412\t-40\t[ESS]\topen\n"
	    "00:00:00:00:00:04\t2412\t-40\t[RSN-OWE-CCMP][ESS]\tguest\n"
	    "00:00:00:00:00:05\t2412\t-40\t[WPA2-PSK+SAE-CCMP][ESS]\ttransition\n"
	    "00:00:00:00:00:06\t2412\t-40\t[WEP][ESS]\told\n",
	    &rows, &count, message, sizeof(message));
	check(count == 6u, "six rows of six different shapes");
	for (index = 0; index < count; index++) {
		int secured = ncfg_supplicant_scan_is_secured(&rows[index]);
		int enterprise = ncfg_supplicant_scan_is_enterprise(&rows[index]);
		int owe = ncfg_supplicant_scan_is_owe(&rows[index]);
		int want_secured = 1;
		int want_enterprise = 0;
		int want_owe = 0;

		if (memcmp(rows[index].ssid.bytes, "corp", 4u) == 0) {
			/* Enterprise is secured too: what differs is which credential,
			 * and a client that cannot tell asks for the wrong one. */
			want_enterprise = 1;
		} else if (memcmp(rows[index].ssid.bytes, "open", 4u) == 0) {
			want_secured = 0;
		} else if (memcmp(rows[index].ssid.bytes, "guest", 5u) == 0) {
			/* The one this exists for: not secured -- nothing is asked for --
			 * and not open either. */
			want_secured = 0;
			want_owe = 1;
		}
		shapes = shapes && secured == want_secured && enterprise == want_enterprise &&
		    owe == want_owe;
	}
	check(shapes, "each row says which of the four it is, and OWE is not open");

	/*
	 * And the same six rows as the document's own vocabulary, which is what a
	 * listing hands `ncfg_wifi_network_for` so that an access point is
	 * credited to the block describing it rather than to whichever of two
	 * same-named blocks sorts first.
	 */
	for (index = 0; index < count; index++) {
		int         got = ncfg_supplicant_scan_security(&rows[index]);
		const char *name = (const char *)rows[index].ssid.bytes;
		int         want = NCFG_SECURITY_PSK;
		char        what[96];

		if (memcmp(name, "corp", 4u) == 0) {
			want = NCFG_SECURITY_EAP;
		} else if (memcmp(name, "open", 4u) == 0) {
			want = NCFG_SECURITY_OPEN;
		} else if (memcmp(name, "guest", 5u) == 0) {
			want = NCFG_SECURITY_OWE;
		} else if (memcmp(name, "old", 3u) == 0) {
			/* **WEP is unstated, not `psk`.** No `network` block can express
			 * it, so naming one would credit this access point to a block
			 * that does not describe it. */
			want = NCFG_WIFI_SECURITY_UNSTATED;
		}
		(void)snprintf(what, sizeof(what), "  `%.*s` reads as the kind a document would name",
		    (int)rows[index].ssid.length, name);
		check(got == want, what);
	}
	ncfg_supplicant_scans_free(rows, count);

	/* **A name is not a flag.** There is an access point called
	 * `OWNIT_24GHz_8A41A0` in range of the machine this was written on, and a
	 * check that searched the whole row rather than the flags field would
	 * call it OWE. */
	count = 0;
	(void)ncfg_supplicant_parse_scan_results(
	    "bssid / frequency / signal level / flags / ssid\n"
	    "00:00:00:00:00:07\t2412\t-56\t[WPA2-PSK-CCMP][ESS]\tOWNIT_24GHz_8A41A0\n"
	    "00:00:00:00:00:08\t2412\t-56\t[WPA2-PSK-CCMP][ESS]\tOWE guest\n",
	    &rows, &count, message, sizeof(message));
	for (index = 0; index < count; index++) {
		names = names && !ncfg_supplicant_scan_is_owe(&rows[index]) &&
		    ncfg_supplicant_scan_is_secured(&rows[index]);
	}
	check(count == 2u && names, "a name containing `OWE` is a name, not a key management mode");
	ncfg_supplicant_scans_free(rows, count);
}

/*
 * The mobility domain, read from a `BSS <bssid>` reply.
 *
 * 802.11r: access points an operator configured into one roaming domain
 * advertise the same id. It is **not** a trust signal, because the element is
 * unauthenticated bytes in a beacon. netcfgd shows it and does not group by
 * it, which is the distinction this pins by existing.
 */
static void the_mobility_domain_is_read_where_there_is_one(void)
{
	char id[64];

	check(ncfg_supplicant_parse_mobility_domain(
	    "bssid=f0:9f:c2:7d:bd:7d\nfreq=2412\nmdid=a1b2\nssid=OpenPC.se\n", id, sizeof(id)) &&
	    strcmp(id, "a1b2") == 0, "a BSS that does fast transition names its domain");
	check(!ncfg_supplicant_parse_mobility_domain(
	    "bssid=00:11:22:33:44:55\nfreq=2437\nssid=Cafe\n", id, sizeof(id)),
	    "and one that does not has no element, which is absent rather than empty");
	check(!ncfg_supplicant_parse_mobility_domain("mdid=\n", id, sizeof(id)),
	    "an empty one is absent too, because an empty id is something a caller prints");
}

/*
 * Fast transition is read from the flags, which cost nothing.
 *
 * The cheap test that decides whether asking for the domain is worth a round
 * trip. With fifty networks in range, asking every one would make a scan
 * slower to serve something almost none of them have.
 */
static void fast_transition_is_visible_in_the_scan_flags(void)
{
	ncfg_supplicant_scan_t *rows = NULL;
	size_t                  count = 0;
	char                    message[NCFG_ERROR_MAX];

	(void)ncfg_supplicant_parse_scan_results(
	    "bssid / frequency / signal level / flags / ssid\n"
	    "f0:9f:c2:7d:bd:7d\t2412\t-40\t[WPA2-FT/PSK-CCMP][ESS]\tOpenPC.se\n"
	    "00:11:22:33:44:55\t2437\t-35\t[WPA2-PSK-CCMP][ESS]\tCafe\n",
	    &rows, &count, message, sizeof(message));
	check(count == 2u && ncfg_supplicant_scan_does_fast_transition(&rows[0]) &&
	    !ncfg_supplicant_scan_does_fast_transition(&rows[1]),
	    "`FT/` in the flags is what says a BSS can fast-transition");
	check(count == 2u && ncfg_supplicant_scan_is_secured(&rows[0]) &&
	    ncfg_supplicant_scan_is_secured(&rows[1]),
	    "and both are secured, so that is not what is being read");
	ncfg_supplicant_scans_free(rows, count);
}

/*
 * A roam is a `CONNECTED` naming a different access point.
 *
 * The format string is `wpa_supplicant`'s own, read out of the binary:
 * `CTRL-EVENT-CONNECTED - Connection to %02x:...:%02x completed [id=%d
 * id_str=%s%s]`. Decision 0091.
 */
static void a_connected_event_names_the_access_point(void)
{
	ncfg_supplicant_event_t event;
	char                    address[32];
	const char             *others[] = {
		"<3>CTRL-EVENT-DISCONNECTED bssid=aa:bb:cc:dd:ee:ff reason=3",
		"<3>CTRL-EVENT-SCAN-STARTED ",
		"<3>CTRL-EVENT-CONNECTED - Connection to nonsense completed [id=0 id_str=]",
		/* The one that reaches the *name* check rather than the shape check.
		 * Without it the three above pass with the name check deleted --
		 * their fifth word is either absent or not an address -- and the
		 * guard that says "only a connect is a move" would be exercised by
		 * nothing. Synthetic, and deliberately: what it stands for is any
		 * future event with an address in that position. */
		"<3>CTRL-EVENT-SOMETHING-ELSE a b c aa:bb:cc:dd:ee:ff"
	};
	size_t which;
	int    quiet = 1;

	check(ncfg_supplicant_event_parse(
	    "<3>CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed [id=0 id_str=]",
	    &event) && ncfg_supplicant_event_connected_bssid(&event, address, sizeof(address)) &&
	    strcmp(address, "aa:bb:cc:dd:ee:ff") == 0,
	    "a connect names the access point in its fifth word");
	for (which = 0; which < sizeof(others) / sizeof(others[0]); which++) {
		quiet = quiet && ncfg_supplicant_event_parse(others[which], &event) &&
		    !ncfg_supplicant_event_connected_bssid(&event, address, sizeof(address));
	}
	check(quiet, "and every other event says nothing, including a disconnect carrying one");
}

/*
 * And it names which configured network, which is what tells a roam apart.
 *
 * A station moving between access points on one network keeps this id and a
 * station leaving for another network does not -- and both arrive as a
 * `CONNECTED` naming an address that is not the last one. 0239.
 */
static void a_connected_event_names_the_network_as_well(void)
{
	ncfg_supplicant_event_t event;
	uint32_t                id = 999;
	const char             *absent[] = {
		/* `-1` is what the supplicant writes when the association has no
		 * configured network behind it. Not a number this returns, and not a
		 * separate case in the code either: it is simply not unsigned. */
		"<3>CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed "
		"[id=-1 id_str=]",
		/* Every other event, including the disconnect that carries an `id=`
		 * of its own -- a reader that took any id it found would compare the
		 * wrong networks. */
		"<3>CTRL-EVENT-SSID-TEMP-DISABLED id=3 ssid=\"home\" auth_failures=1",
		"<3>CTRL-EVENT-DISCONNECTED bssid=aa:bb:cc:dd:ee:ff reason=3",
		/* A connect whose shape is not the format string's. */
		"<3>CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed"
	};
	size_t which;
	int    quiet = 1;

	check(ncfg_supplicant_event_parse(
	    "<3>CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed [id=7 id_str=]",
	    &event) && ncfg_supplicant_event_network_id(&event, &id) && id == 7u,
	    "a connect names the configured network it joined");
	/* The id is not always a single digit, and reading one character would
	 * have passed every check above. */
	check(ncfg_supplicant_event_parse(
	    "<3>CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed "
	    "[id=12 id_str=home]", &event) &&
	    ncfg_supplicant_event_network_id(&event, &id) && id == 12u,
	    "and an id of more than one digit is read whole");
	for (which = 0; which < sizeof(absent) / sizeof(absent[0]); which++) {
		quiet = quiet && ncfg_supplicant_event_parse(absent[which], &event) &&
		    !ncfg_supplicant_event_network_id(&event, &id);
	}
	check(quiet, "and `-1`, another event's `id=`, and a connect of another shape say nothing");
}

/*
 * The `key=value` fields of a supplicant event, on the real texts.
 *
 * All the samples are copied out of a machine's journal rather than invented,
 * because the fields are the supplicant's own format strings and a test
 * written from the documentation would be testing the documentation.
 */
static void an_event_gives_up_its_fields(void)
{
	ncfg_supplicant_event_t event;
	char                    value[128];

	check(ncfg_supplicant_event_parse(
	    "<3>CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"OpenPC.se\" auth_failures=2 "
	    "duration=20 reason=CONN_FAILED", &event), "a temp-disable parses");
	check(ncfg_supplicant_event_field(&event, "ssid", value, sizeof(value)) &&
	    strcmp(value, "OpenPC.se") == 0, "its quoted name comes out unquoted");
	check(ncfg_supplicant_event_field(&event, "auth_failures", value, sizeof(value)) &&
	    strcmp(value, "2") == 0, "and the count beside it");
	check(ncfg_supplicant_event_field(&event, "reason", value, sizeof(value)) &&
	    strcmp(value, "CONN_FAILED") == 0, "and the reason, which is worth more than a sentence");
	check(!ncfg_supplicant_event_field(&event, "bssid", value, sizeof(value)),
	    "a field that is not there is absent");

	check(ncfg_supplicant_event_parse(
	    "<3>CTRL-EVENT-DISCONNECTED bssid=a0:a4:7f:23:9a:cf reason=3 locally_generated=1",
	    &event), "a disconnect parses");
	check(ncfg_supplicant_event_field(&event, "bssid", value, sizeof(value)) &&
	    strcmp(value, "a0:a4:7f:23:9a:cf") == 0, "with its address");
	check(ncfg_supplicant_event_field(&event, "reason", value, sizeof(value)) &&
	    strcmp(value, "3") == 0, "and its reason");
	/* `id` is a suffix of `bssid` in this very event, and a reader that did
	 * not require a field boundary answers `id` with the tail of the address.
	 * The boundary is what makes the short keys usable at all. */
	check(!ncfg_supplicant_event_field(&event, "id", value, sizeof(value)),
	    "and `id` is not answered with the tail of `bssid`");

	check(ncfg_supplicant_event_parse(
	    "<3>CTRL-EVENT-AUTH-REJECT f0:9f:c2:7e:bd:7d auth_type=3 auth_transaction=2 "
	    "status_code=1", &event), "an auth reject parses");
	check(ncfg_supplicant_event_field(&event, "status_code", value, sizeof(value)) &&
	    strcmp(value, "1") == 0, "with the status the access point gave");
	/* A field with no `=` after it is not a field. The address above is
	 * positional, and answering it to a question about a key that is not
	 * there would be worse than answering nothing. */
	check(!ncfg_supplicant_event_field(&event, "bssid", value, sizeof(value)),
	    "and a positional address is not a field");
}

/*
 * A network whose name has a space in it, which is what a router ships with.
 *
 * The whitespace-split reader this replaced reported the network as `"Guest`
 * and lost the failure count behind it -- the two things the event is read for.
 * `printf_encode` escapes bytes outside printable ASCII and leaves a space
 * alone, so the quotes are the only delimiter there is.
 */
static void a_quoted_name_runs_to_its_closing_quote(void)
{
	ncfg_supplicant_event_t event;
	char                    value[128];

	check(ncfg_supplicant_event_parse(
	    "<3>CTRL-EVENT-SSID-TEMP-DISABLED id=1 ssid=\"Guest Wifi\" auth_failures=45 "
	    "duration=60 reason=CONN_FAILED", &event), "a name with a space in it parses");
	check(ncfg_supplicant_event_field(&event, "ssid", value, sizeof(value)) &&
	    strcmp(value, "Guest Wifi") == 0, "and runs to its closing quote");
	check(ncfg_supplicant_event_field(&event, "auth_failures", value, sizeof(value)) &&
	    strcmp(value, "45") == 0, "with the count behind it still readable");
}

/* ============================================================ configuration */

/*
 * WPA3 personal is SAE with management frame protection required. Sending
 * `WPA-PSK` for a network the operator asked to be WPA3 would associate
 * successfully and silently be WPA2, which is the kind of downgrade nobody
 * notices.
 */
static void wpa3_is_sae_with_protected_management_frames(const ncfg_secret_resolver_t *resolver)
{
	ncfg_wifi_network_t network;
	ncfg_buf_t          lines;
	char                message[NCFG_ERROR_MAX];

	a_network(&network, "test", "home");
	psk_security(&network.security, "pass", NCFG_PSK_PROTO_WPA3);
	check(render(&network, NCFG_MAC_POLICY_PERMANENT, resolver, &lines, message,
	    sizeof(message)), "a WPA3 network renders");
	check(line_present(&lines, "SET_NETWORK 0 key_mgmt SAE FT-SAE"), "as SAE");
	check(line_present(&lines, "SET_NETWORK 0 ieee80211w 2"),
	    "with management frame protection required, without which it is not WPA3");
	check(!somewhere(&lines, "WPA-PSK"),
	    "and never offering the WPA2 key management, which would be a silent downgrade");
	ncfg_supplicant_buf_wipe(&lines);
}

/*
 * Every mode that can fast-transition offers it, and the open one does not.
 *
 * The property is easy to lose by accident, because losing it breaks nothing:
 * a network with no `FT-` mode in its `key_mgmt` associates exactly as well and
 * roams slowly, so the only thing that would notice is this test. 802.11r is
 * negotiated at association, so a supplicant that did not offer it cannot
 * change its mind at the first roam.
 */
static void fast_transition_is_offered_wherever_it_can_be(const ncfg_secret_resolver_t *resolver)
{
	struct {
		int         proto;
		const char *expected;
	} cases[] = {
		{ NCFG_PSK_PROTO_WPA2, "SET_NETWORK 0 key_mgmt WPA-PSK FT-PSK" },
		{ NCFG_PSK_PROTO_WPA3, "SET_NETWORK 0 key_mgmt SAE FT-SAE" },
		{ NCFG_PSK_PROTO_WPA2_WPA3, "SET_NETWORK 0 key_mgmt WPA-PSK SAE FT-PSK FT-SAE" }
	};
	size_t which;
	int    all = 1;

	for (which = 0; which < sizeof(cases) / sizeof(cases[0]); which++) {
		ncfg_wifi_network_t network;
		ncfg_buf_t          lines;
		char                message[NCFG_ERROR_MAX];

		a_network(&network, "test", "home");
		psk_security(&network.security, "pass", cases[which].proto);
		all = all && render(&network, NCFG_MAC_POLICY_PERMANENT, resolver, &lines, message,
		    sizeof(message)) && line_present(&lines, cases[which].expected);
		ncfg_supplicant_buf_wipe(&lines);
	}
	check(all, "every generation offers fast transition beside what it already offered");
}

/*
 * Transitional mode has to work against both, and `ieee80211w` is the field
 * where getting it wrong excludes one of them.
 */
static void transitional_mode_can_reach_both_generations(const ncfg_secret_resolver_t *resolver)
{
	ncfg_wifi_network_t network;
	ncfg_buf_t          lines;
	char                message[NCFG_ERROR_MAX];

	a_network(&network, "test", "home");
	psk_security(&network.security, "pass", NCFG_PSK_PROTO_WPA2_WPA3);
	check(render(&network, NCFG_MAC_POLICY_PERMANENT, resolver, &lines, message,
	    sizeof(message)) && line_present(&lines, "SET_NETWORK 0 ieee80211w 1"),
	    "transitional takes 1, since 2 excludes WPA2 access points and 0 excludes SAE");
	ncfg_supplicant_buf_wipe(&lines);
}

/* OWE without management frame protection is not OWE. */
static void owe_requires_protected_management_frames(const ncfg_secret_resolver_t *resolver)
{
	ncfg_wifi_network_t network;
	ncfg_buf_t          lines;
	char                message[NCFG_ERROR_MAX];

	a_network(&network, "test", "cafe");
	network.security.kind = NCFG_SECURITY_OWE;
	check(render(&network, NCFG_MAC_POLICY_PERMANENT, resolver, &lines, message,
	    sizeof(message)) && line_present(&lines, "SET_NETWORK 0 key_mgmt OWE") &&
	    line_present(&lines, "SET_NETWORK 0 ieee80211w 2"),
	    "OWE is its own key management, with the protection that makes it OWE");
	ncfg_supplicant_buf_wipe(&lines);
}

/*
 * A hidden network is never probed for without this, so it simply never
 * appears -- with nothing anywhere saying why.
 */
static void a_hidden_network_is_probed_for(const ncfg_secret_resolver_t *resolver)
{
	ncfg_wifi_network_t network;
	ncfg_buf_t          lines;
	char                message[NCFG_ERROR_MAX];

	a_network(&network, "test", "secret");
	network.hidden = 1;
	check(render(&network, NCFG_MAC_POLICY_PERMANENT, resolver, &lines, message,
	    sizeof(message)) && line_present(&lines, "SET_NETWORK 0 scan_ssid 1"),
	    "a hidden network is probed for, or it never appears at all");
	ncfg_supplicant_buf_wipe(&lines);

	a_network(&network, "test", "secret");
	check(render(&network, NCFG_MAC_POLICY_PERMANENT, resolver, &lines, message,
	    sizeof(message)) && !somewhere(&lines, "scan_ssid"),
	    "and one that is not hidden is not, which costs airtime for nothing");
	ncfg_supplicant_buf_wipe(&lines);
}

/*
 * A BSSID reaches the command line unquoted, and the set of valid values is
 * small enough to check exactly rather than escape.
 */
static void a_bssid_is_validated_rather_than_quoted(const ncfg_secret_resolver_t *resolver)
{
	const char *hostile[] = {
		"00:11:22:33:44:55 \nREMOVE_NETWORK all",
		"not-a-mac",
		"00:11:22:33:44",
		"00:11:22:33:44:55:66",
		"gg:11:22:33:44:55"
	};
	ncfg_wifi_network_t network;
	ncfg_buf_t          lines;
	char               *one[1];
	char                message[NCFG_ERROR_MAX];
	size_t              which;
	int                 all = 1;

	a_network(&network, "test", "home");
	one[0] = text("00:11:22:33:44:55");
	network.bssid = one;
	network.bssid_count = 1u;
	check(render(&network, NCFG_MAC_POLICY_PERMANENT, resolver, &lines, message,
	    sizeof(message)) && line_present(&lines, "SET_NETWORK 0 bssid 00:11:22:33:44:55"),
	    "an address that is one goes out as it stands");
	ncfg_supplicant_buf_wipe(&lines);

	for (which = 0; which < sizeof(hostile) / sizeof(hostile[0]); which++) {
		ncfg_supplicant_settings_t settings;

		one[0] = text(hostile[which]);
		message[0] = '\0';
		all = all && !ncfg_supplicant_settings(&network, NULL, NCFG_MAC_POLICY_PERMANENT,
		    resolver, &settings, message, sizeof(message)) &&
		    strstr(message, "is not a MAC address") != NULL;
	}
	check(all, "and anything that is not is refused by name rather than escaped");
}

/*
 * `FAIL` with no detail is what the supplicant answers to a short passphrase,
 * and a stray space is a common enough mistake to deserve better.
 */
static void a_passphrase_of_the_wrong_length_is_refused_with_its_length(const char *secrets_dir,
    const ncfg_secret_resolver_t *resolver)
{
	/* Five octets and sixty-four: one either side of the field's 8..=63, which
	 * is the rule being reported rather than WPA's. */
	static const char sixty_four[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
	struct {
		const char *passphrase;
		const char *length;
	} cases[2];
	size_t which;
	int    all = 1;

	cases[0].passphrase = "short";
	cases[0].length = " is 5 ";
	cases[1].passphrase = sixty_four;
	cases[1].length = " is 64 ";

	for (which = 0; which < sizeof(cases) / sizeof(cases[0]); which++) {
		ncfg_wifi_network_t        network;
		ncfg_supplicant_settings_t settings;
		char                       message[NCFG_ERROR_MAX];

		write_secret(secrets_dir, "wrong-length", cases[which].passphrase);
		a_network(&network, "test", "home");
		psk_security(&network.security, "wrong-length", NCFG_PSK_PROTO_WPA2);
		message[0] = '\0';
		all = all && !ncfg_supplicant_settings(&network, NULL, NCFG_MAC_POLICY_PERMANENT,
		    resolver, &settings, message, sizeof(message)) &&
		    strstr(message, cases[which].length) != NULL &&
		    /* The length is safe to report; the value is not. */
		    strstr(message, cases[which].passphrase) == NULL;
	}
	check(all, "a passphrase the `psk` field cannot carry is refused with its length, not itself");
}

/*
 * The failing command gets reported when a setting is refused, and the one most
 * likely to be refused is the one carrying the passphrase.
 */
static void a_secret_setting_redacts_itself(const ncfg_secret_resolver_t *resolver)
{
	ncfg_wifi_network_t              network;
	ncfg_supplicant_settings_t       settings;
	const ncfg_supplicant_setting_t *secret;
	const ncfg_supplicant_setting_t *plain;
	ncfg_buf_t                       shown;
	ncfg_buf_t                       whole;
	char                             message[NCFG_ERROR_MAX];

	a_network(&network, "test", "home");
	psk_security(&network.security, "pass", NCFG_PSK_PROTO_WPA2);
	if (!ncfg_supplicant_settings(&network, NULL, NCFG_MAC_POLICY_PERMANENT, resolver,
	    &settings, message, sizeof(message))) {
		check(0, "a WPA2 network renders");
		return;
	}
	secret = setting_named(&settings, "psk");
	plain = setting_named(&settings, "key_mgmt");
	check(secret && secret->sensitive, "the passphrase setting says it is one");
	/* **And it holds no value at all**, which is the divergence from the Rust
	 * and the whole of how a credential stays out of a list that is passed
	 * around, formatted and freed. */
	check(secret && secret->value == NULL && secret->secret != NULL,
	    "and carries the reference rather than the material");

	ncfg_buf_init(&shown, 0);
	ncfg_supplicant_setting_redacted(secret, 0, &shown);
	check(!somewhere(&shown, "hunter2hunter2") && somewhere(&shown, "<redacted>"),
	    "what may be printed says `<redacted>` and nothing else");

	ncfg_buf_init(&whole, 0);
	check(ncfg_supplicant_setting_command(secret, 0, resolver, &whole, message,
	    sizeof(message)) && somewhere(&whole, "hunter2hunter2"),
	    "while the line that goes on the wire really does carry it");
	ncfg_supplicant_buf_wipe(&whole);

	/* And an ordinary setting is not hidden, or a plan is unreadable. */
	ncfg_buf_free(&shown);
	ncfg_buf_init(&shown, 0);
	ncfg_supplicant_setting_redacted(plain, 0, &shown);
	check(strcmp(ncfg_buf_text(&shown), "SET_NETWORK 0 key_mgmt WPA-PSK FT-PSK") == 0,
	    "an ordinary setting prints as it is sent");
	ncfg_buf_free(&shown);
	ncfg_supplicant_settings_free(&settings);
}

/*
 * The `mac_addr` mapping, which is the whole of the MAC randomization feature
 * at this layer.
 *
 * **The numbers are not guessable from the names, and this test held the wrong
 * one in place (0230).** `per_connection` asserted 2, and
 * `wpa_supplicant.conf` documents 2 as "like 1, but maintain OUI (with local
 * admin bit set)" -- so for the policy netcfgd documents as the strongest it
 * was sending the one value that says who made the radio.
 */
static void the_mac_policy_maps_to_the_documented_numbers(void)
{
	check(strcmp(ncfg_supplicant_mac_addr_value(NCFG_MAC_POLICY_PERMANENT), "0") == 0,
	    "`permanent` is the hardware address");
	check(strcmp(ncfg_supplicant_mac_addr_value(NCFG_MAC_POLICY_PER_NETWORK), "1") == 0,
	    "`per_network` is a random address per ESS connection");
	check(strcmp(ncfg_supplicant_mac_addr_value(NCFG_MAC_POLICY_PER_CONNECTION), "1") == 0,
	    "and so is `per_connection` -- not 2, which keeps the manufacturer prefix");
	/* **What actually separates the two randomising policies**, since both
	 * are `mac_addr 1`: whether the previous address is still in date when
	 * the radio rejoins. The supplicant's default is 60 seconds. */
	check(strcmp(ncfg_supplicant_rand_addr_lifetime_value(NCFG_MAC_POLICY_PER_CONNECTION),
	    "0") == 0, "a fresh address every time is a lifetime of zero");
	check(strcmp(ncfg_supplicant_rand_addr_lifetime_value(NCFG_MAC_POLICY_PER_NETWORK),
	    "60") == 0, "and the other keeps one for the supplicant's own minute");
	check(strcmp(ncfg_supplicant_rand_addr_lifetime_value(NCFG_MAC_POLICY_PER_CONNECTION),
	    ncfg_supplicant_rand_addr_lifetime_value(NCFG_MAC_POLICY_PER_NETWORK)) != 0,
	    "the two policies have to differ somewhere, and this is the only place left");
}

/*
 * It is sent for every policy including `permanent`, because leaving it unset
 * inherits the supplicant's global -- and a privacy property that depends on
 * somebody else's default is not a property.
 */
static void the_mac_policy_is_always_sent(const ncfg_secret_resolver_t *resolver)
{
	int    policies[] = { NCFG_MAC_POLICY_PERMANENT, NCFG_MAC_POLICY_PER_NETWORK,
		NCFG_MAC_POLICY_PER_CONNECTION };
	size_t which;
	int    all = 1;

	for (which = 0; which < sizeof(policies) / sizeof(policies[0]); which++) {
		ncfg_wifi_network_t network;
		ncfg_buf_t          lines;
		char                message[NCFG_ERROR_MAX];
		char                wanted[64];

		a_network(&network, "test", "home");
		(void)snprintf(wanted, sizeof(wanted), "SET_NETWORK 0 mac_addr %s",
		    ncfg_supplicant_mac_addr_value(policies[which]));
		all = all && render(&network, policies[which], resolver, &lines, message,
		    sizeof(message)) && line_present(&lines, wanted);
		ncfg_supplicant_buf_wipe(&lines);
	}
	check(all, "every policy, `permanent` included, states itself rather than inheriting one");
}

/*
 * Roaming reaches `wpa_supplicant` as the module it understands.
 *
 * An ESS is several access points sharing one SSID, and a station moves to
 * whichever it hears best. `wpa_supplicant` does that itself, but only while a
 * `bgscan` module is asking it to look. netcfgd set none, so a laptop
 * re-selected only after the link had already gone -- which is roaming by first
 * losing the network.
 */
static void a_roaming_network_asks_the_supplicant_to_keep_looking(
    const ncfg_secret_resolver_t *resolver)
{
	ncfg_wifi_network_t network;
	ncfg_roam_policy_t  roam;
	ncfg_buf_t          lines;
	char                message[NCFG_ERROR_MAX];

	a_network(&network, "test", "Corridor");
	psk_security(&network.security, "pass", NCFG_PSK_PROTO_WPA2_WPA3);
	roam.signal = -68;
	roam.interval = 20;
	roam.slow_interval = 240;
	network.roam = &roam;
	/* The order is the module's own: short interval, threshold, long
	 * interval. Getting the first two the wrong way round is a station that
	 * scans every -68 seconds above a 20 dBm signal, which is a
	 * plausible-looking string and no roaming at all. */
	check(render(&network, NCFG_MAC_POLICY_PERMANENT, resolver, &lines, message,
	    sizeof(message)) &&
	    line_present(&lines, "SET_NETWORK 0 bgscan \"simple:20:-68:240\""),
	    "a roam policy reaches the supplicant as its own module specification");
	ncfg_supplicant_buf_wipe(&lines);

	/* And a network that did not ask for it says nothing at all: a background
	 * scan costs airtime and interrupts traffic, so a router with a radio, or
	 * anything that never moves, must not be made to pay for it. */
	a_network(&network, "test", "Fixed");
	psk_security(&network.security, "pass", NCFG_PSK_PROTO_WPA2_WPA3);
	check(render(&network, NCFG_MAC_POLICY_PERMANENT, resolver, &lines, message,
	    sizeof(message)) && !somewhere(&lines, "bgscan"),
	    "and a network that does not roam is given no background scan");
	ncfg_supplicant_buf_wipe(&lines);
}

/*
 * One access point pins; several are a choice among them.
 *
 * `wpa_supplicant` spells those differently and the difference is the whole
 * feature: `bssid` refuses every other access point, `bssid_accept` limits
 * selection to the set and picks among them by signal. Rendering a list as a
 * pin would join one of them and never move (0090).
 */
static void one_access_point_pins_and_several_are_a_choice(
    const ncfg_secret_resolver_t *resolver)
{
	ncfg_wifi_network_t network;
	ncfg_buf_t          lines;
	char               *addresses[2];
	char                message[NCFG_ERROR_MAX];

	addresses[0] = text("aa:bb:cc:dd:ee:ff");
	addresses[1] = text("11:22:33:44:55:66");

	a_network(&network, "test", "Site");
	psk_security(&network.security, "pass", NCFG_PSK_PROTO_WPA2_WPA3);
	network.bssid = addresses;
	network.bssid_count = 1u;
	check(render(&network, NCFG_MAC_POLICY_PERMANENT, resolver, &lines, message,
	    sizeof(message)) && line_present(&lines, "SET_NETWORK 0 bssid aa:bb:cc:dd:ee:ff") &&
	    !somewhere(&lines, "bssid_accept"), "one access point pins");
	ncfg_supplicant_buf_wipe(&lines);

	network.bssid_count = 2u;
	/* Masked, because that is the form wpa_supplicant parses, and every bit
	 * set is one specific address. */
	check(render(&network, NCFG_MAC_POLICY_PERMANENT, resolver, &lines, message,
	    sizeof(message)) && line_present(&lines, "SET_NETWORK 0 bssid_accept "
	    "aa:bb:cc:dd:ee:ff/ff:ff:ff:ff:ff:ff 11:22:33:44:55:66/ff:ff:ff:ff:ff:ff") &&
	    !somewhere(&lines, " bssid a"), "and several are a choice among them");
	ncfg_supplicant_buf_wipe(&lines);
}

/*
 * A network whose name was never resolved is refused rather than sent.
 *
 * Sending it would mean an empty SSID, which associates with anything. The
 * caller skipped a step and says so.
 */
static void a_network_with_no_resolved_name_is_refused(const ncfg_secret_resolver_t *resolver)
{
	ncfg_wifi_network_t        network;
	ncfg_supplicant_settings_t settings;
	char                      *one[1];
	char                       message[NCFG_ERROR_MAX];

	a_network(&network, "test", NULL);
	network.security.kind = NCFG_SECURITY_OWE;
	one[0] = text("aa:bb:cc:dd:ee:ff");
	network.bssid = one;
	network.bssid_count = 1u;
	message[0] = '\0';
	check(!ncfg_supplicant_settings(&network, NULL, NCFG_MAC_POLICY_PERMANENT, resolver,
	    &settings, message, sizeof(message)) &&
	    strstr(message, "never read off a scan") != NULL,
	    "a network with no name is a caller that skipped a step, and says so");
}

/*
 * The join order the supplicant is given runs opposite to the metric.
 *
 * **The relationship, not either number.** What must hold is that a network an
 * operator prefers -- the lower metric -- is the one the supplicant tries
 * first, which for it means the *higher* priority. Pinning the two values
 * would pass just as happily against a ceiling somebody changed for good
 * reason, and would say nothing about the inversion, which is the whole risk in
 * 0154: getting it backwards is silent, because the machine still joins a
 * network and still comes up. It just prefers the wrong one.
 */
static void a_lower_metric_becomes_a_higher_join_priority(const ncfg_secret_resolver_t *resolver)
{
	long long values[2] = { 0, 0 };
	size_t    which;
	int       read_both = 1;

	for (which = 0; which < 2u; which++) {
		ncfg_wifi_network_t network;
		ncfg_buf_t          lines;
		char                message[NCFG_ERROR_MAX];
		const char         *found;

		a_network(&network, "test", "home");
		psk_security(&network.security, "pass", NCFG_PSK_PROTO_WPA2_WPA3);
		network.metric.has = 1;
		network.metric.value = which == 0u ? 50 : 600;
		if (!render(&network, NCFG_MAC_POLICY_PERMANENT, resolver, &lines, message,
		    sizeof(message))) {
			read_both = 0;
		} else {
			found = strstr(ncfg_buf_text(&lines), "\nSET_NETWORK 0 priority ");
			if (found) {
				values[which] = atoll(found + strlen("\nSET_NETWORK 0 priority "));
			} else {
				read_both = 0;
			}
		}
		ncfg_supplicant_buf_wipe(&lines);
	}
	check(read_both && values[0] > values[1],
	    "metric 50 outranks metric 600 for joining, which is the inversion 0154 turns on");

	{
		ncfg_wifi_network_t network;
		ncfg_buf_t          lines;
		char                message[NCFG_ERROR_MAX];

		a_network(&network, "test", "home");
		psk_security(&network.security, "pass", NCFG_PSK_PROTO_WPA2_WPA3);
		/* A network the document did not rank is told nothing, rather than
		 * being handed the ceiling and silently becoming the most preferred
		 * thing on the machine. */
		check(render(&network, NCFG_MAC_POLICY_PERMANENT, resolver, &lines, message,
		    sizeof(message)) && !somewhere(&lines, "priority"),
		    "and an unranked network states no priority at all");
		ncfg_supplicant_buf_wipe(&lines);
	}
}

/*
 * WPA3 takes `sae_password`, and with it a password the `psk` field refuses.
 *
 * **The 8..=63 rule belongs to `psk`, not to WPA.** netcfgd sent every
 * passphrase in that field, including for SAE, so a WPA3 network with a longer
 * password could not be joined -- and the refusal said "a WPA passphrase is 8 to
 * 63 characters", which states a rule SAE does not have. Decision 0205.
 */
static void wpa3_alone_sends_sae_password_and_takes_a_longer_one(const char *secrets_dir,
    const ncfg_secret_resolver_t *resolver)
{
	char                long_one[80];
	ncfg_wifi_network_t network;
	ncfg_buf_t          lines;
	char                message[NCFG_ERROR_MAX];
	int                 protos[2] = { NCFG_PSK_PROTO_WPA2, NCFG_PSK_PROTO_WPA2_WPA3 };
	size_t              which;
	int                 all = 1;

	memset(long_one, 'a', 70u);
	long_one[70] = '\0';
	write_secret(secrets_dir, "long", long_one);

	a_network(&network, "test", "home");
	psk_security(&network.security, "long", NCFG_PSK_PROTO_WPA3);
	check(render(&network, NCFG_MAC_POLICY_PERMANENT, resolver, &lines, message,
	    sizeof(message)) && somewhere(&lines, "sae_password") && !somewhere(&lines, " psk "),
	    "WPA3 takes `sae_password`, which has no length rule, and not `psk`, which has");
	ncfg_supplicant_buf_wipe(&lines);

	/* **Both other generations keep `psk` and keep the limit**, because the
	 * WPA2 half reads that field and cannot read the other one. */
	for (which = 0; which < 2u; which++) {
		ncfg_supplicant_settings_t settings;

		a_network(&network, "test", "home");
		psk_security(&network.security, "pass", protos[which]);
		all = all && render(&network, NCFG_MAC_POLICY_PERMANENT, resolver, &lines, message,
		    sizeof(message)) && somewhere(&lines, " psk ") &&
		    !somewhere(&lines, "sae_password");
		ncfg_supplicant_buf_wipe(&lines);

		psk_security(&network.security, "long", protos[which]);
		all = all && !ncfg_supplicant_settings(&network, NULL, NCFG_MAC_POLICY_PERMANENT,
		    resolver, &settings, message, sizeof(message));
	}
	check(all, "and both other generations keep `psk`, and keep its limit with it");
}

/* ---------------------------------------------------------------- 802.1X */

static void an_eap_network(ncfg_wifi_network_t *out, const char *id, int method,
    const char *identity, const char *password_name)
{
	a_network(out, id, "corp");
	memset(&out->security, 0, sizeof(out->security));
	out->security.kind = NCFG_SECURITY_EAP;
	out->security.eap.method = method;
	out->security.eap.identity = text(identity);
	if (password_name) {
		out->security.eap.password = malloc(sizeof(*out->security.eap.password));
		if (!out->security.eap.password) {
			exit(1);
		}
		out->security.eap.password->provider = NCFG_SECRET_PROVIDER_FILE;
		out->security.eap.password->name = text(password_name);
	}
}

/*
 * An EAP identity is a username. It goes out redacted for the same reason a
 * passphrase does -- it is half of a credential -- and quoted for the same
 * reason: a RADIUS realm is text somebody else chose.
 */
static void eap_settings_quote_and_redact_the_identity(const ncfg_secret_resolver_t *resolver)
{
	ncfg_wifi_network_t              network;
	ncfg_supplicant_settings_t       settings;
	const ncfg_supplicant_setting_t *identity;
	const ncfg_supplicant_setting_t *password;
	ncfg_buf_t                       shown;
	char                             message[NCFG_ERROR_MAX];

	an_eap_network(&network, "test", NCFG_EAP_METHOD_PEAP,
	    "user\"; REMOVE_NETWORK all; \"", "password");
	network.security.eap.anonymous_identity = text("anonymous@example.net");
	network.security.eap.phase2 = text("auth=MSCHAPV2");
	path_source(&network.security.eap.ca_cert, "/etc/ssl/certs/corporate.pem");

	if (!ncfg_supplicant_settings(&network, NULL, NCFG_MAC_POLICY_PERMANENT, resolver,
	    &settings, message, sizeof(message))) {
		check(0, "an enterprise network renders");
		free(network.security.eap.password);
		return;
	}
	check(setting_named(&settings, "key_mgmt") &&
	    strcmp(setting_named(&settings, "key_mgmt")->value, "WPA-EAP FT-EAP") == 0,
	    "an enterprise network offers EAP and fast transition over it");
	check(setting_named(&settings, "eap") &&
	    strcmp(setting_named(&settings, "eap")->value, "PEAP") == 0, "and names its method");
	check(setting_named(&settings, "phase2") &&
	    strcmp(setting_named(&settings, "phase2")->value, "\"auth=MSCHAPV2\"") == 0,
	    "and quotes its inner method");
	identity = setting_named(&settings, "identity");
	check(identity && strcmp(identity->value, "\"user\\\"; REMOVE_NETWORK all; \\\"\"") == 0,
	    "an identity that reads like a command is quoted into a name");
	check(identity && identity->sensitive, "and an identity is half a credential");

	ncfg_buf_init(&shown, 0);
	ncfg_supplicant_setting_redacted(identity, 0, &shown);
	check(!somewhere(&shown, "REMOVE_NETWORK"), "so what may be printed does not carry it");
	ncfg_buf_free(&shown);

	password = setting_named(&settings, "password");
	ncfg_buf_init(&shown, 0);
	ncfg_supplicant_setting_redacted(password, 0, &shown);
	check(password && !somewhere(&shown, "corporate"),
	    "and neither does the password's printable form");
	ncfg_buf_free(&shown);
	ncfg_supplicant_settings_free(&settings);
	free(network.security.eap.password);
}

/*
 * A method that needs a password and has none fails here, naming the field,
 * rather than at association time with a `FAIL`.
 */
static void an_eap_method_missing_its_credential_says_which(
    const ncfg_secret_resolver_t *resolver)
{
	ncfg_wifi_network_t        network;
	ncfg_supplicant_settings_t settings;
	char                       message[NCFG_ERROR_MAX];

	an_eap_network(&network, "test", NCFG_EAP_METHOD_TTLS, "user", NULL);
	message[0] = '\0';
	check(!ncfg_supplicant_settings(&network, NULL, NCFG_MAC_POLICY_PERMANENT, resolver,
	    &settings, message, sizeof(message)) &&
	    strstr(message, "needs `password`") != NULL,
	    "a method with no password says which field it wanted");

	an_eap_network(&network, "test", NCFG_EAP_METHOD_TLS, "user", NULL);
	path_source(&network.security.eap.client_cert, "/etc/ssl/client.pem");
	message[0] = '\0';
	check(!ncfg_supplicant_settings(&network, NULL, NCFG_MAC_POLICY_PERMANENT, resolver,
	    &settings, message, sizeof(message)) &&
	    strstr(message, "needs `private_key`") != NULL,
	    "and EAP-TLS with no key says the same about that one");
}

/*
 * **A network that pins no CA gets no `ca_cert` line, and this is the fault the
 * project was opened for.**
 *
 * `wpa_supplicant` opens every one of these as a file, so `ca_cert=""` is a
 * filename of zero length -- OpenSSL refuses it and PEAP never reaches an inner
 * method. Measured on the reporting machine's corporate network, which pins
 * nothing:
 *
 *     OpenSSL: tls_connection_ca_cert - Failed to load root certificates
 *     EAP-PEAP: Failed to initialize SSL.
 *     CTRL-EVENT-SSID-TEMP-DISABLED ... auth_failures=45 reason=CONN_FAILED
 *
 * NetworkManager joined the same network on the same laptop minutes later,
 * writing no `ca_cert` at all. An omitted setting is how "verify nothing" is
 * spelled. Decision 0189.
 */
static void a_network_that_pins_no_ca_certificate_sends_no_ca_cert_at_all(
    const ncfg_secret_resolver_t *resolver)
{
	ncfg_wifi_network_t        network;
	ncfg_supplicant_settings_t settings;
	char                       message[NCFG_ERROR_MAX];

	an_eap_network(&network, "test", NCFG_EAP_METHOD_PEAP, "someone@example.com", "password");
	if (!ncfg_supplicant_settings(&network, NULL, NCFG_MAC_POLICY_PERMANENT, resolver,
	    &settings, message, sizeof(message))) {
		check(0, "a network with a password and no pinned CA is renderable");
		free(network.security.eap.password);
		return;
	}
	check(setting_named(&settings, "ca_cert") == NULL,
	    "an empty `ca_cert` is a filename wpa_supplicant cannot open, so there is no line");
	/* The rest of the network still has to be there: a test that passes
	 * because nothing was rendered would be no test. */
	check(setting_named(&settings, "key_mgmt") && setting_named(&settings, "eap") &&
	    setting_named(&settings, "identity"),
	    "and the rest of the network is still rendered, which is what makes that a check");
	ncfg_supplicant_settings_free(&settings);
	free(network.security.eap.password);
}

/* And a network that *does* pin one still says so, with the path. */
static void a_network_that_pins_a_ca_certificate_still_names_the_file(
    const ncfg_secret_resolver_t *resolver)
{
	ncfg_wifi_network_t        network;
	ncfg_supplicant_settings_t settings;
	char                       message[NCFG_ERROR_MAX];

	an_eap_network(&network, "test", NCFG_EAP_METHOD_PEAP, "someone@example.com", "password");
	path_source(&network.security.eap.ca_cert, "/etc/ssl/certs/corporate.pem");
	if (!ncfg_supplicant_settings(&network, NULL, NCFG_MAC_POLICY_PERMANENT, resolver,
	    &settings, message, sizeof(message))) {
		check(0, "a pinned CA is renderable");
		free(network.security.eap.password);
		return;
	}
	check(setting_named(&settings, "ca_cert") &&
	    strstr(setting_named(&settings, "ca_cert")->value, "/etc/ssl/certs/corporate.pem"),
	    "a pinned issuer reaches the supplicant as the path it will open");
	ncfg_supplicant_settings_free(&settings);
	free(network.security.eap.password);
}

/*
 * A pinned issuer says who signed the certificate; this says who it is for.
 *
 * **`ca_cert` alone accepts every certificate that issuer ever signed.** That
 * is right when the issuer is the organisation's own CA and nearly worthless
 * when it is a public one -- and a commercial certificate on a RADIUS server is
 * ordinary. There, anybody who can buy one from the same CA raises an access
 * point with the right name, is believed, and takes whatever the inner method
 * sends. Decision 0206.
 */
static void a_server_name_is_checked_when_the_document_asks_for_it(
    const ncfg_secret_resolver_t *resolver)
{
	ncfg_wifi_network_t network;
	ncfg_buf_t          lines;
	char                message[NCFG_ERROR_MAX];

	an_eap_network(&network, "test", NCFG_EAP_METHOD_PEAP, "user@example.com", "password");
	path_source(&network.security.eap.ca_cert, "/etc/ssl/certs/corporate.pem");
	network.security.eap.phase2 = text("auth=MSCHAPV2");
	network.security.eap.domain_suffix_match = text("radius.example.com");
	check(render(&network, NCFG_MAC_POLICY_PERMANENT, resolver, &lines, message,
	    sizeof(message)) &&
	    somewhere(&lines, "domain_suffix_match \"radius.example.com\""),
	    "the server name reaches the supplicant, quoted");
	ncfg_supplicant_buf_wipe(&lines);

	/* **Not an empty one.** The absent case sends no line, so the supplicant
	 * keeps its own default rather than being handed a name nothing matches
	 * -- which is 0189's fault in a different field. */
	network.security.eap.domain_suffix_match = NULL;
	check(render(&network, NCFG_MAC_POLICY_PERMANENT, resolver, &lines, message,
	    sizeof(message)) && !somewhere(&lines, "domain_suffix_match") &&
	    somewhere(&lines, "ca_cert"),
	    "and absent means no line at all, with the issuer still pinned either way");
	ncfg_supplicant_buf_wipe(&lines);
	free(network.security.eap.password);
}

/*
 * Stored certificates and a stored key become real files, and paths.
 *
 * `wpa_supplicant` opens all three as files, so everything reaching it has to
 * be a path -- and before this the only way to have one was to put the file
 * there yourself, which a desktop client cannot do (0127).
 *
 * The old behaviour is worth remembering: `private_key` was sent as the
 * secret's *value*, so an EAP-TLS network rendered
 * `private_key "-----BEGIN PRIVATE KEY-----` followed by a newline -- a
 * filename that does not exist, and a newline that terminated the line-based
 * `SET_NETWORK` command in the middle.
 */
static void stored_certificates_are_materialised_and_sent_as_paths(const char *secrets_dir,
    const char *run_dir)
{
	ncfg_secret_resolver_t resolver;
	ncfg_wifi_network_t    network;
	ncfg_buf_t             lines;
	char                   certs[320];
	char                   message[NCFG_ERROR_MAX];
	struct {
		const char *field;
		const char *file;
	} wanted[] = {
		{ "ca_cert", "corp-ca.ca.pem" },
		{ "client_cert", "corp-crt.client.pem" },
		{ "private_key", "corp-key.client.key" }
	};
	size_t which;
	int    paths = 1;
	int    written = 1;
	int    tight = 1;

	write_secret(secrets_dir, "corp-ca", "-----BEGIN CERTIFICATE-----\nCA==\n");
	write_secret(secrets_dir, "corp-crt", "-----BEGIN CERTIFICATE-----\nCRT==\n");
	write_secret(secrets_dir, "corp-key", "-----BEGIN PRIVATE KEY-----\nKEY==\n");
	(void)snprintf(certs, sizeof(certs), "%s/certs", run_dir);
	resolver.secrets_dir = secrets_dir;
	resolver.materialise_dir = certs;

	an_eap_network(&network, "test", NCFG_EAP_METHOD_TLS, "user@corp.example", NULL);
	stored_source(&network.security.eap.ca_cert, "corp-ca");
	stored_source(&network.security.eap.client_cert, "corp-crt");
	stored_source(&network.security.eap.private_key, "corp-key");
	if (!render(&network, NCFG_MAC_POLICY_PERMANENT, &resolver, &lines, message,
	    sizeof(message))) {
		check(0, "an EAP-TLS network with stored material renders");
		return;
	}
	for (which = 0; which < sizeof(wanted) / sizeof(wanted[0]); which++) {
		char fragment[640];
		char path[512];

		(void)snprintf(path, sizeof(path), "%s/%s", certs, wanted[which].file);
		(void)snprintf(fragment, sizeof(fragment), "%s \"%s\"", wanted[which].field, path);
		paths = paths && somewhere(&lines, fragment);
		written = written && testdir_exists(path);
		tight = tight && testdir_mode(path) == 0600;
	}
	check(paths, "each is sent as a path, named after the credential and not after its role");
	check(written, "and each file was really written");
	check(tight, "at 0600, by the open rather than after it");
	/* And nothing rendered carries the key material itself, which is the
	 * failure the old code had and the one worth asserting against by name. */
	check(!somewhere(&lines, "BEGIN PRIVATE KEY"),
	    "and no key material reached the control socket");
	ncfg_supplicant_buf_wipe(&lines);
}

/*
 * A certificate given as a path is sent unchanged, and nothing is written.
 *
 * An operator with certificates already in `/etc/ssl` should not have to hand
 * them to netcfgd to use them, so a `path` source passes straight through --
 * and materialising one would be netcfgd copying a file it was only asked to
 * name.
 */
static void a_certificate_given_as_a_path_is_sent_unchanged(const char *secrets_dir,
    const char *run_dir)
{
	ncfg_secret_resolver_t resolver;
	ncfg_wifi_network_t    network;
	ncfg_buf_t             lines;
	char                   certs[320];
	char                   message[NCFG_ERROR_MAX];

	(void)snprintf(certs, sizeof(certs), "%s/untouched", run_dir);
	resolver.secrets_dir = secrets_dir;
	resolver.materialise_dir = certs;

	an_eap_network(&network, "test", NCFG_EAP_METHOD_TLS, "user@corp.example", NULL);
	path_source(&network.security.eap.ca_cert, "/etc/ssl/ca.pem");
	path_source(&network.security.eap.client_cert, "/etc/ssl/client.pem");
	path_source(&network.security.eap.private_key, "/etc/ssl/private/client.key");
	check(render(&network, NCFG_MAC_POLICY_PERMANENT, &resolver, &lines, message,
	    sizeof(message)) &&
	    somewhere(&lines, "private_key \"/etc/ssl/private/client.key\"") &&
	    somewhere(&lines, "ca_cert \"/etc/ssl/ca.pem\""),
	    "a path passes through exactly as the operator wrote it");
	check(!testdir_exists(certs),
	    "and a path source made netcfgd write nothing it was only asked to name");
	ncfg_supplicant_buf_wipe(&lines);
}

/*
 * Two networks with different stored CAs get two files.
 *
 * **The defect this pins is not a collision of names, it is a collision of
 * trust.** Every stored certificate was written to one `ca.pem` and every
 * network's `ca_cert=` pointed at it, while one supplicant is handed every
 * network in a single loop -- so the last one rendered won for all of them, and
 * a machine with a work network and a university network validated both servers
 * against whichever CA happened to be written last.
 */
static void two_networks_with_different_cas_do_not_share_one_file(const char *secrets_dir,
    const char *run_dir)
{
	ncfg_secret_resolver_t resolver;
	char                   certs[320];
	char                   work_path[512];
	char                   uni_path[512];
	char                   message[NCFG_ERROR_MAX];
	char                  *body;
	size_t                 length = 0;
	size_t                 which;
	int                    rendered_both = 1;

	write_secret(secrets_dir, "work-ca", "-----BEGIN CERTIFICATE-----\nWORK==\n");
	write_secret(secrets_dir, "uni-ca", "-----BEGIN CERTIFICATE-----\nUNI==\n");
	(void)snprintf(certs, sizeof(certs), "%s/two-cas", run_dir);
	resolver.secrets_dir = secrets_dir;
	resolver.materialise_dir = certs;

	for (which = 0; which < 2u; which++) {
		ncfg_wifi_network_t network;
		ncfg_buf_t          lines;

		an_eap_network(&network, which == 0u ? "work" : "uni", NCFG_EAP_METHOD_PEAP,
		    "user", "pass");
		stored_source(&network.security.eap.ca_cert, which == 0u ? "work-ca" : "uni-ca");
		rendered_both = rendered_both && render(&network, NCFG_MAC_POLICY_PERMANENT,
		    &resolver, &lines, message, sizeof(message));
		ncfg_supplicant_buf_wipe(&lines);
		free(network.security.eap.password);
	}
	(void)snprintf(work_path, sizeof(work_path), "%s/work-ca.ca.pem", certs);
	(void)snprintf(uni_path, sizeof(uni_path), "%s/uni-ca.ca.pem", certs);
	check(rendered_both && testdir_exists(work_path) && testdir_exists(uni_path),
	    "two networks with different stored CAs get two files");
	/* And each file still holds its own certificate after both were rendered,
	 * which is the half a distinct name alone would not prove. */
	body = testdir_read(work_path, &length);
	check(body && strstr(body, "WORK==") != NULL, "and work's CA holds work's certificate");
	free(body);
	body = testdir_read(uni_path, &length);
	check(body && strstr(body, "UNI==") != NULL, "and the university's holds its own");
	free(body);
}

/*
 * A resolver with nowhere to write refuses rather than choosing a directory.
 *
 * The safe direction: a resolver that invented somewhere would put key material
 * in a place its caller did not pick.
 */
static void a_stored_certificate_with_nowhere_to_go_is_refused(const char *secrets_dir)
{
	ncfg_secret_resolver_t     resolver;
	ncfg_wifi_network_t        network;
	ncfg_supplicant_settings_t settings;
	char                       message[NCFG_ERROR_MAX];

	resolver.secrets_dir = secrets_dir;
	resolver.materialise_dir = NULL;
	an_eap_network(&network, "test", NCFG_EAP_METHOD_TLS, "user@corp.example", NULL);
	path_source(&network.security.eap.ca_cert, "/etc/ssl/ca.pem");
	stored_source(&network.security.eap.private_key, "corp-key");
	check(!ncfg_supplicant_settings(&network, NULL, NCFG_MAC_POLICY_PERMANENT, &resolver,
	    &settings, message, sizeof(message)),
	    "a stored key with nowhere to be written is refused rather than put somewhere");
}

/*
 * A wired 802.1X port is not a wifi EAP network.
 *
 * The difference is the one that matters: wired uses `key_mgmt = IEEE8021X`,
 * bare EAPOL with no WPA handshake wrapped around it. Sending `WPA-EAP` to a
 * `wired` driver produces a network the supplicant accepts and never
 * authenticates with, which is the worst available outcome -- everything looks
 * configured and the port stays blocked. 0008.
 */
static void a_wired_port_is_not_a_radio(const ncfg_secret_resolver_t *resolver)
{
	ncfg_wifi_network_t        carrier;
	ncfg_supplicant_settings_t settings;
	char                       message[NCFG_ERROR_MAX];

	an_eap_network(&carrier, "test", NCFG_EAP_METHOD_PEAP, "port@example.com", "password");
	if (!ncfg_supplicant_wired_settings(&carrier.security.eap, resolver, &settings, message,
	    sizeof(message))) {
		check(0, "a wired 802.1X port renders");
		free(carrier.security.eap.password);
		return;
	}
	check(setting_named(&settings, "key_mgmt") &&
	    strcmp(setting_named(&settings, "key_mgmt")->value, "IEEE8021X") == 0,
	    "a wired port authenticates with bare EAPOL, not with a WPA handshake");
	/* Without this the supplicant tries to install WEP keys the switch never
	 * sends, and the port authenticates and then goes quiet. */
	check(setting_named(&settings, "eapol_flags") &&
	    strcmp(setting_named(&settings, "eapol_flags")->value, "0") == 0,
	    "and asks for no WEP keys, which a switch never sends");
	/* The method, the identity and the certificates are shared rather than
	 * duplicated, which is the whole reason 0008 puts wired here. */
	check(setting_named(&settings, "eap") && setting_named(&settings, "identity") &&
	    setting_named(&settings, "password"),
	    "while the method, the identity and the credential are the same code");
	ncfg_supplicant_settings_free(&settings);
	free(carrier.security.eap.password);
}

/* ================================================================ pick_ssid */

/* The scan every case below reads a name out of. */
static int a_site(ncfg_supplicant_scan_t **out, size_t *count, const char *body)
{
	char message[NCFG_ERROR_MAX];

	return ncfg_supplicant_parse_scan_results(body, out, count, message, sizeof(message));
}

/*
 * A network named by address learns what it is called from a scan.
 *
 * WPA derives its key from the passphrase *and* the SSID, so the name has to be
 * read before anything can be sent -- `wpa_supplicant`'s wildcard, which matches
 * any name, is documented as working for plaintext access points only, and for
 * that reason. Decision 0090.
 */
static void a_network_named_by_address_learns_its_name(void)
{
	ncfg_supplicant_scan_t *seen = NULL;
	size_t                  count = 0;
	ncfg_wifi_network_t     network;
	ncfg_ssid_t             learned;
	char                   *addresses[2];
	char                    message[NCFG_ERROR_MAX];

	(void)a_site(&seen, &count,
	    "bssid / frequency / signal level / flags / ssid\n"
	    "aa:bb:cc:dd:ee:ff\t2412\t-40\t[WPA2-PSK-CCMP][ESS]\tlobby\n"
	    "11:22:33:44:55:66\t2437\t-60\t[WPA2-PSK-CCMP][ESS]\tlobby\n"
	    "99:99:99:99:99:99\t2462\t-70\t[ESS]\tsomeone-else\n");

	a_network(&network, "by-bssid", NULL);
	network.security.kind = NCFG_SECURITY_OWE;
	/* Upper case on purpose: an address an operator typed and one a driver
	 * reported differ in case often enough that comparing them exactly is a
	 * bug waiting for a capital letter. */
	addresses[0] = text("AA:BB:CC:DD:EE:FF");
	network.bssid = addresses;
	network.bssid_count = 1u;
	check(ncfg_supplicant_pick_ssid(&network, seen, count, &learned, message,
	    sizeof(message)) && learned.length == 5u && memcmp(learned.bytes, "lobby", 5u) == 0,
	    "a network named by address reads its name off the last scan, whatever the case");

	/* Several that agree is the ordinary site: one network, two radios. */
	addresses[0] = text("aa:bb:cc:dd:ee:ff");
	addresses[1] = text("11:22:33:44:55:66");
	network.bssid_count = 2u;
	check(ncfg_supplicant_pick_ssid(&network, seen, count, &learned, message,
	    sizeof(message)) && learned.length == 5u,
	    "and two radios on one network agree about what it is called");

	/* One in range and one not is still answerable: the absent one says
	 * nothing, rather than making the whole network unreachable. */
	addresses[1] = text("de:ad:be:ef:00:00");
	check(ncfg_supplicant_pick_ssid(&network, seen, count, &learned, message,
	    sizeof(message)) && learned.length == 5u,
	    "and one of them being out of range does not make the network unreachable");
	ncfg_supplicant_scans_free(seen, count);
}

/*
 * A hidden access point is in range and still cannot say what it is called.
 *
 * **It used to resolve to a zero-octet SSID**, which was then sent as
 * `ssid ""`. That matches nothing, and for anything but an open network it
 * cannot even derive the right key -- WPA derives it from the passphrase *and*
 * the SSID. No error anywhere said why. 0223.
 */
static void a_hidden_access_point_is_not_resolved_to_an_empty_name(void)
{
	ncfg_supplicant_scan_t *seen = NULL;
	size_t                  count = 0;
	ncfg_wifi_network_t     network;
	ncfg_ssid_t             learned;
	char                   *addresses[2];
	char                    message[NCFG_ERROR_MAX];

	(void)a_site(&seen, &count,
	    "bssid / frequency / signal level / flags / ssid\n"
	    "aa:bb:cc:dd:ee:ff\t2462\t-40\t[WPA2-PSK-CCMP][ESS]\t\n"
	    "11:22:33:44:55:66\t2437\t-55\t[WPA2-PSK-CCMP][ESS]\tlobby\n");
	/* The scan really does carry an empty name for it, which is the fact the
	 * rest of this rests on. */
	check(count == 2u && seen[0].ssid.length == 0u,
	    "a hidden access point advertises no name at all");

	a_network(&network, "pinned", NULL);
	addresses[0] = text("aa:bb:cc:dd:ee:ff");
	addresses[1] = text("11:22:33:44:55:66");
	network.bssid = addresses;
	network.bssid_count = 1u;
	message[0] = '\0';
	check(!ncfg_supplicant_pick_ssid(&network, seen, count, &learned, message,
	    sizeof(message)) && strstr(message, "hidden") != NULL &&
	    strstr(message, "aa:bb:cc:dd:ee:ff") != NULL && strstr(message, "ssid = ") != NULL,
	    "so it is refused, saying what is wrong, which radio, and what to do instead");

	/* **A hidden one beside a named one does not disagree with it.** It
	 * declines to say, so it is dropped rather than compared -- comparing them
	 * reported "they are on different networks", which is wrong and
	 * unactionable. */
	network.bssid_count = 2u;
	check(ncfg_supplicant_pick_ssid(&network, seen, count, &learned, message,
	    sizeof(message)) && learned.length == 5u && memcmp(learned.bytes, "lobby", 5u) == 0,
	    "and the one that does advertise a name answers for both");

	/* And "not in range" still reads differently from "in range and hidden",
	 * because they need different things done about them. */
	addresses[0] = text("de:ad:be:ef:00:00");
	network.bssid_count = 1u;
	message[0] = '\0';
	check(!ncfg_supplicant_pick_ssid(&network, seen, count, &learned, message,
	    sizeof(message)) && strstr(message, "is in range") != NULL &&
	    strstr(message, "hidden") == NULL,
	    "while an absent access point is not a hidden one, and does not read like one");
	ncfg_supplicant_scans_free(seen, count);
}

/*
 * None of them in range is a failure that names the addresses.
 *
 * "Network not found", about a network identified by address, is not a sentence
 * anybody can act on.
 */
static void an_absent_access_point_is_reported_with_its_address(void)
{
	ncfg_supplicant_scan_t *seen = NULL;
	size_t                  count = 0;
	ncfg_wifi_network_t     network;
	ncfg_ssid_t             learned;
	char                   *one[1];
	char                    message[NCFG_ERROR_MAX];

	(void)a_site(&seen, &count,
	    "bssid / frequency / signal level / flags / ssid\n"
	    "99:99:99:99:99:99\t2462\t-70\t[ESS]\tsomeone-else\n");
	a_network(&network, "Lobby", NULL);
	one[0] = text("aa:bb:cc:dd:ee:ff");
	network.bssid = one;
	network.bssid_count = 1u;
	message[0] = '\0';
	check(!ncfg_supplicant_pick_ssid(&network, seen, count, &learned, message,
	    sizeof(message)) && strstr(message, "aa:bb:cc:dd:ee:ff") != NULL &&
	    strstr(message, "Lobby") != NULL,
	    "an access point out of range is named, and so is the block that wanted it");
	ncfg_supplicant_scans_free(seen, count);
}

/*
 * Access points advertising different names are different networks.
 *
 * One passphrase cannot be right for both -- WPA's key is derived per SSID -- so
 * picking either would be netcfgd choosing for the operator.
 */
static void access_points_on_different_networks_are_refused(void)
{
	ncfg_supplicant_scan_t *seen = NULL;
	size_t                  count = 0;
	ncfg_wifi_network_t     network;
	ncfg_ssid_t             learned;
	char                   *addresses[2];
	char                    message[NCFG_ERROR_MAX];

	(void)a_site(&seen, &count,
	    "bssid / frequency / signal level / flags / ssid\n"
	    "aa:bb:cc:dd:ee:ff\t2412\t-40\t[WPA2-PSK-CCMP][ESS]\tlobby\n"
	    "11:22:33:44:55:66\t2437\t-60\t[WPA2-PSK-CCMP][ESS]\twarehouse\n");
	a_network(&network, "Site", NULL);
	addresses[0] = text("aa:bb:cc:dd:ee:ff");
	addresses[1] = text("11:22:33:44:55:66");
	network.bssid = addresses;
	network.bssid_count = 2u;
	message[0] = '\0';
	check(!ncfg_supplicant_pick_ssid(&network, seen, count, &learned, message,
	    sizeof(message)) && strstr(message, "different networks") != NULL &&
	    strstr(message, "aa:bb:cc:dd:ee:ff") != NULL &&
	    strstr(message, "11:22:33:44:55:66") != NULL,
	    "two names is two networks, and both addresses are named so the operator can see");
	ncfg_supplicant_scans_free(seen, count);
}

/* ============================================================== fingerprint */

/*
 * Turning the scanning address on changes the record; leaving it off does not.
 *
 * **The asymmetry is the migration, not an oversight.** This digest decides
 * whether a *running* supplicant still matches the document, and a mismatch
 * replaces its whole network set -- which drops the association. If the off
 * state were encoded as a line, every machine that has never used this would
 * get a different digest from the one it has, and the first apply after an
 * upgrade would disconnect all of them to record a setting none of them asked
 * for. 0220.
 */
static void the_scanning_address_changes_the_record_only_when_it_is_on(
    const ncfg_secret_resolver_t *resolver)
{
	ncfg_wifi_network_t networks[1];
	char                off[NCFG_SUPPLICANT_SSID_HEX_SIZE];
	char                on[NCFG_SUPPLICANT_SSID_HEX_SIZE];
	char                again[NCFG_SUPPLICANT_SSID_HEX_SIZE];
	char                message[NCFG_ERROR_MAX];

	a_network(&networks[0], "Corp", "Corp");
	check(ncfg_supplicant_fingerprint(networks, 1u, NCFG_MAC_POLICY_PERMANENT, 0, 1, resolver,
	    off, message, sizeof(message)) &&
	    ncfg_supplicant_fingerprint(networks, 1u, NCFG_MAC_POLICY_PERMANENT, 1, 1, resolver,
	    on, message, sizeof(message)) &&
	    ncfg_supplicant_fingerprint(networks, 1u, NCFG_MAC_POLICY_PERMANENT, 0, 1, resolver,
	    again, message, sizeof(message)), "an ordinary network fingerprints, on and off");
	check(strcmp(off, again) == 0,
	    "the off state is stable, or applying the new build disconnects every machine");
	check(strcmp(off, on) != 0,
	    "and turning it on is noticed, which is the point of putting it in");
}

/*
 * **One network named by BSSID must not void the record for all of them.**
 *
 * Where the digest is absent the record is *removed*, and `kernel.rs` says what
 * that costs in as many words -- "changing a passphrase, pinning a bssid,
 * adding a network or deleting one all planned nothing, measured, and the
 * supplicant kept the original credentials indefinitely". A network with no
 * SSID yet is not an error and not an unknown: the document names its access
 * points and the name is read from a scan at the moment it is sent, so one such
 * network turned change detection off for the whole radio, permanently and
 * silently.
 */
static void a_network_named_by_bssid_does_not_void_the_whole_fingerprint(
    const ncfg_secret_resolver_t *resolver)
{
	ncfg_wifi_network_t networks[2];
	char               *first[1];
	char               *second[1];
	char                alone[NCFG_SUPPLICANT_SSID_HEX_SIZE];
	char                together[NCFG_SUPPLICANT_SSID_HEX_SIZE];
	char                moved[NCFG_SUPPLICANT_SSID_HEX_SIZE];
	char                message[NCFG_ERROR_MAX];

	a_network(&networks[0], "Corp", "Corp");
	a_network(&networks[1], "by-bssid", NULL);
	first[0] = text("02:00:00:00:00:01");
	networks[1].bssid = first;
	networks[1].bssid_count = 1u;

	check(ncfg_supplicant_fingerprint(networks, 1u, NCFG_MAC_POLICY_PERMANENT, 0, 1, resolver,
	    alone, message, sizeof(message)), "an ordinary network fingerprints");
	check(ncfg_supplicant_fingerprint(networks, 2u, NCFG_MAC_POLICY_PERMANENT, 0, 1, resolver,
	    together, message, sizeof(message)),
	    "and a bssid-named network beside it still fingerprints, rather than voiding it");
	check(strcmp(alone, together) != 0,
	    "adding it is a change, because it is part of what the radio was given");

	second[0] = text("02:00:00:00:00:02");
	networks[1].bssid = second;
	check(ncfg_supplicant_fingerprint(networks, 2u, NCFG_MAC_POLICY_PERMANENT, 0, 1, resolver,
	    moved, message, sizeof(message)) && strcmp(together, moved) != 0,
	    "and pinning a different access point is the one edit this kind of network is made of");
}

/*
 * Changing `autoconnect` has to be a change the digest can see.
 *
 * **It drives `ENABLE_NETWORK`, not a `SET_NETWORK`, so it never reached the
 * digest (0236).** Editing it left the digest identical, so the planner saw no
 * drift, so the supplicant was never repopulated -- a network the operator had
 * just marked automatic stayed disabled until something else forced a
 * population. Both flags, because there are two: the network's and the radio's.
 */
static void autoconnect_reaches_the_digest_on_both_levels(const ncfg_secret_resolver_t *resolver)
{
	ncfg_wifi_network_t joined;
	ncfg_wifi_network_t manual;
	char                automatic[NCFG_SUPPLICANT_SSID_HEX_SIZE];
	char                by_hand[NCFG_SUPPLICANT_SSID_HEX_SIZE];
	char                radio_off[NCFG_SUPPLICANT_SSID_HEX_SIZE];
	char                stable[NCFG_SUPPLICANT_SSID_HEX_SIZE];
	char                message[NCFG_ERROR_MAX];

	a_network(&joined, "Corp", "Corp");
	a_network(&manual, "Corp", "Corp");
	manual.autoconnect = 0;

	check(ncfg_supplicant_fingerprint(&joined, 1u, NCFG_MAC_POLICY_PERMANENT, 0, 1, resolver,
	    automatic, message, sizeof(message)) &&
	    ncfg_supplicant_fingerprint(&manual, 1u, NCFG_MAC_POLICY_PERMANENT, 0, 1, resolver,
	    by_hand, message, sizeof(message)) && strcmp(automatic, by_hand) != 0,
	    "a network that is no longer joined automatically is a different set");
	check(ncfg_supplicant_fingerprint(&joined, 1u, NCFG_MAC_POLICY_PERMANENT, 0, 0, resolver,
	    radio_off, message, sizeof(message)) && strcmp(automatic, radio_off) != 0,
	    "and a radio told not to join anything was given a different thing");
	/* **The asymmetry that keeps an upgrade quiet.** The digest gains a line
	 * only where the non-default is in play, so a machine whose radio and
	 * networks all join automatically is byte-identical to what the previous
	 * build recorded. */
	check(ncfg_supplicant_fingerprint(&joined, 1u, NCFG_MAC_POLICY_PERMANENT, 0, 1, resolver,
	    stable, message, sizeof(message)) && strcmp(automatic, stable) == 0,
	    "while the ordinary machine's digest does not move at all");
}

/* ===================================================================== main */

int main(void)
{
	const char            *work_dir = testdir_make("supplicant");
	char                   secrets_dir[512];
	ncfg_secret_resolver_t resolver;

	printf("== supplicant_test in %s\n", work_dir);
	(void)snprintf(secrets_dir, sizeof(secrets_dir), "%s/secrets", work_dir);
	if (mkdir(secrets_dir, (mode_t)0700) != 0) {
		printf("could not make a secrets directory to work in\n");
		return 1;
	}
	write_secret(secrets_dir, "pass", "hunter2hunter2");
	write_secret(secrets_dir, "password", "corporate");
	resolver.secrets_dir = secrets_dir;
	resolver.materialise_dir = NULL;

	ok_fail_and_data_are_distinguished();
	events_are_not_mistaken_for_replies();
	an_event_keeps_its_priority_and_name();
	scan_results_parse();
	escaped_ssids_are_decoded();
	a_tab_or_newline_in_a_name_cannot_break_the_row_structure();
	a_truncated_escape_is_not_fatal();
	a_malformed_scan_row_is_skipped_not_fatal();
	network_lists_and_status_parse();
	a_network_with_no_flags_still_parses();
	an_ssid_cannot_inject_a_command();
	a_non_utf8_ssid_round_trips();
	a_passphrase_cannot_escape_its_quotes();
	a_scan_row_says_which_of_the_four_security_shapes_it_is();
	the_mobility_domain_is_read_where_there_is_one();
	fast_transition_is_visible_in_the_scan_flags();
	a_connected_event_names_the_access_point();
	a_connected_event_names_the_network_as_well();
	an_event_gives_up_its_fields();
	a_quoted_name_runs_to_its_closing_quote();

	wpa3_is_sae_with_protected_management_frames(&resolver);
	fast_transition_is_offered_wherever_it_can_be(&resolver);
	transitional_mode_can_reach_both_generations(&resolver);
	owe_requires_protected_management_frames(&resolver);
	a_hidden_network_is_probed_for(&resolver);
	a_bssid_is_validated_rather_than_quoted(&resolver);
	a_passphrase_of_the_wrong_length_is_refused_with_its_length(secrets_dir, &resolver);
	a_secret_setting_redacts_itself(&resolver);
	the_mac_policy_maps_to_the_documented_numbers();
	the_mac_policy_is_always_sent(&resolver);
	a_roaming_network_asks_the_supplicant_to_keep_looking(&resolver);
	one_access_point_pins_and_several_are_a_choice(&resolver);
	a_network_with_no_resolved_name_is_refused(&resolver);
	a_lower_metric_becomes_a_higher_join_priority(&resolver);
	wpa3_alone_sends_sae_password_and_takes_a_longer_one(secrets_dir, &resolver);
	eap_settings_quote_and_redact_the_identity(&resolver);
	an_eap_method_missing_its_credential_says_which(&resolver);
	a_network_that_pins_no_ca_certificate_sends_no_ca_cert_at_all(&resolver);
	a_network_that_pins_a_ca_certificate_still_names_the_file(&resolver);
	a_server_name_is_checked_when_the_document_asks_for_it(&resolver);
	stored_certificates_are_materialised_and_sent_as_paths(secrets_dir, work_dir);
	a_certificate_given_as_a_path_is_sent_unchanged(secrets_dir, work_dir);
	two_networks_with_different_cas_do_not_share_one_file(secrets_dir, work_dir);
	a_stored_certificate_with_nowhere_to_go_is_refused(secrets_dir);
	a_wired_port_is_not_a_radio(&resolver);

	a_network_named_by_address_learns_its_name();
	a_hidden_access_point_is_not_resolved_to_an_empty_name();
	an_absent_access_point_is_reported_with_its_address();
	access_points_on_different_networks_are_refused();

	the_scanning_address_changes_the_record_only_when_it_is_on(&resolver);
	a_network_named_by_bssid_does_not_void_the_whole_fingerprint(&resolver);
	autoconnect_reaches_the_digest_on_both_levels(&resolver);

	testdir_remove(work_dir);
	if (failures == 0) {
		printf("supplicant_test: all checks passed\n");
	} else {
		printf("supplicant_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
