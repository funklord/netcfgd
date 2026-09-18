/*
 * tui_test.c -- `ncfg tui`, with no terminal anywhere.
 *
 * WHY THERE IS NO PTY IN HERE
 *   The Rust's own comment says where its painting is checked: "covered by
 *   `tests/live/tui.py` against a real pty". That is a test that needs a
 *   terminal, a `TERM` ncurses recognises and a process to drive it, and the
 *   project's notes record it failing fourteen ways in a container for reasons
 *   of its own. **A test that needs a terminal is a test that does not run.**
 *
 *   So the C port puts the whole frame -- the cursor moves, the reverse video,
 *   every padded row -- into an `ncfg_buf_t`, and this file reads those bytes.
 *   Nothing here opens a descriptor, nothing changes a terminal's mode, and the
 *   session that is running this test keeps the one it has.
 *
 * WHERE THE SUBJECTS COME FROM
 *   `doc/schema/`, which is the daemon's own bytes. The Rust's tests carry the
 *   reason and it is worth repeating: they used to carry fixtures written by
 *   hand, and one of them was wrong for as long as it existed -- the plan
 *   fixture said `"op": {"op": "addr.add"}` where the wire said `addr_add`, so
 *   the pane drew a word the test never saw and the test passed anyway. A
 *   fixture written to match what somebody believed agrees with itself and
 *   proves nothing.
 *
 *   `socket.json` pins the *envelopes*, one object per line; `observed.json` and
 *   `plan.json` hold the content with no envelope. The daemon sends the content
 *   flattened under the tag, so `under_envelope` composes exactly that -- and
 *   `the_envelopes_these_tests_compose_are_the_ones_the_socket_pins` is why
 *   composing it is a reading of the witnesses rather than a guess about them.
 *
 * WHAT IS WRITTEN BY HAND, AND WHY EACH
 *   Four scans and a station list. The witness pins one scan and one station,
 *   and the cases that matter are combinations of members it does not carry:
 *   two radios of one access point, one SSID with three kinds of security, a
 *   station with no statistics. The member *names* still come from the witness
 *   -- the fixtures below use the spellings `socket.json` uses and nothing else
 *   -- so a renamed member breaks these rather than quietly rendering dashes.
 */
#include "ncfg/cli.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* ------------------------------------------------------------------------ *
 * The witnesses
 * ------------------------------------------------------------------------ */

/*
 * A witness, from wherever this was run.
 *
 * The same candidate list `cli_test.c` uses: the tests run from `c/` under the
 * Makefile and from elsewhere under a sanitizer build, and a path that is wrong
 * produces a *vacuous* pass -- the whole file is skipped and the run is green.
 * So a witness that cannot be opened is a failure, named.
 */
static char *witness(const char *name, size_t *length_out)
{
	static const char *const roots[] = { "../doc/schema/", "doc/schema/",
		"../../doc/schema/" };
	size_t at;

	for (at = 0; at < sizeof(roots) / sizeof(roots[0]); at++) {
		char  path[512];
		FILE *file;
		long  size;
		char *text;

		(void)snprintf(path, sizeof(path), "%s%s", roots[at], name);
		file = fopen(path, "rb");
		if (!file) {
			continue;
		}
		(void)fseek(file, 0, SEEK_END);
		size = ftell(file);
		(void)fseek(file, 0, SEEK_SET);
		if (size < 0) {
			(void)fclose(file);
			continue;
		}
		text = malloc((size_t)size + 1);
		if (!text) {
			(void)fclose(file);
			continue;
		}
		*length_out = fread(text, 1, (size_t)size, file);
		text[*length_out] = '\0';
		(void)fclose(file);
		return text;
	}
	return NULL;
}

/*
 * One response line from the socket witness, by its tag.
 *
 * `socket.json` pins the envelopes, one JSON object per line. Several are
 * complete answers on their own -- a scan, a station list -- and those are used
 * here exactly as they are. `after` skips lines that came before, since two
 * `wifi_scan` envelopes are pinned and the second is the stale one.
 */
static char *socket_witness(const char *tag, size_t skip, size_t *length_out)
{
	size_t whole = 0;
	char  *text = witness("socket.json", &whole);
	char  *at;
	char   needle[64];

	*length_out = 0;
	if (!text) {
		return NULL;
	}
	(void)snprintf(needle, sizeof(needle), "\"response\":\"%s\"", tag);
	at = text;
	while (at && *at) {
		char  *end = strchr(at, '\n');
		size_t run = end ? (size_t)(end - at) : strlen(at);

		if (run > 0 && at[0] != '#' && memchr(at, '"', run) &&
		    strstr(at, needle) && strstr(at, needle) < at + run) {
			if (skip > 0) {
				skip--;
			} else {
				char *line = malloc(run + 1);

				if (line) {
					memcpy(line, at, run);
					line[run] = '\0';
					*length_out = run;
				}
				free(text);
				return line;
			}
		}
		if (!end) {
			break;
		}
		at = end + 1;
	}
	free(text);
	return NULL;
}

/*
 * Content under its envelope.
 *
 * The two answers the panes lean on hardest are pinned in two places and
 * neither is enough alone: `socket.json` has the `status` and `plan` envelopes
 * but with every list empty, and `observed.json` and `plan.json` have the
 * content but no envelope. The daemon sends the content flattened under the
 * tag, so that is what this composes.
 */
static char *under_envelope(const char *tag, const char *content, size_t *length_out)
{
	const char *open = content ? strchr(content, '{') : NULL;
	ncfg_buf_t  out;
	char       *text;

	*length_out = 0;
	if (!open) {
		return NULL;
	}
	ncfg_buf_init(&out, 0);
	ncfg_buf_addf(&out, "{\"response\":\"%s\",", tag);
	ncfg_buf_add_text(&out, open + 1);
	text = ncfg_buf_take(&out, length_out);
	ncfg_buf_free(&out);
	return text;
}

/* ------------------------------------------------------------------------ *
 * Driving the panes
 * ------------------------------------------------------------------------ */

static ncfg_tui_t       tui;
static ncfg_tui_lines_t body;

/* The pane's lines, into the file's one list. Freed by the next call. */
static void draw(ncfg_tui_pane_t pane, size_t width)
{
	ncfg_tui_lines_free(&body);
	tui.pane = pane;
	ncfg_tui_body(&tui, width, &body);
}

/* Whether any line holds `needle`. */
static int any_line_has(const char *needle)
{
	size_t at;

	for (at = 0; at < body.count; at++) {
		if (strstr(ncfg_tui_line(&body, at), needle)) {
			return 1;
		}
	}
	return 0;
}

/* How many lines hold `needle`. */
static size_t lines_with(const char *needle)
{
	size_t at;
	size_t found = 0;

	for (at = 0; at < body.count; at++) {
		if (strstr(ncfg_tui_line(&body, at), needle)) {
			found++;
		}
	}
	return found;
}

/*
 * A counted protocol string as one this file can print.
 *
 * `cli_internal.h` has the same helper and is private to `src/cli/`, which is
 * right: a test drives the public face, and copying four lines is cheaper than
 * widening a header so that a test can reach inside.
 */
static const char *proto_text(ncfg_proto_str_t text, char *out, size_t out_size)
{
	size_t length = text.bytes ? text.length : 0;

	if (length > out_size - 1) {
		length = out_size - 1;
	}
	if (text.bytes) {
		memcpy(out, text.bytes, length);
	}
	out[length] = '\0';
	return out;
}

/* Characters, counted the way `fit` counts them. */
static size_t characters(const char *text)
{
	size_t at = 0;
	size_t count = 0;

	while (text[at] != '\0') {
		unsigned char lead = (unsigned char)text[at];

		at++;
		while ((unsigned char)text[at] >= 0x80u && (unsigned char)text[at] < 0xc0u &&
		    lead >= 0xc0u) {
			at++;
		}
		count++;
	}
	return count;
}

/* An answer, or a named failure rather than a pane drawn from nothing. */
static void give(ncfg_tui_answer_t *answer, const char *json, const char *what)
{
	if (!ncfg_tui_answer_read(&tui, answer, json, strlen(json))) {
		check(0, what);
		detail("the daemon said", tui.message);
	}
}

/* ------------------------------------------------------------------------ *
 * The fixtures written by hand, and why each one exists
 * ------------------------------------------------------------------------ */

/*
 * One access point, two radios, with a mobility domain on each.
 *
 * **The weaker radio is listed first, deliberately.** The daemon sorts
 * strongest-first, so in practice the first member of a group is its strongest
 * and taking either would look right -- which is exactly why a fixture in that
 * order proves nothing. Replacing the heading's strongest-member choice with
 * "the first one" passes against a sorted fixture and fails against this, which
 * is the difference between a test and a decoration.
 */
static const char TWO_RADIO_SCAN[] =
    "{\"response\":\"wifi_scan\",\"interface\":\"wlan0\",\"access_points\":["
    "{\"bssid\":\"f0:9f:c2:7e:bd:7d\",\"frequency\":5220,\"signal\":-45,"
    "\"secured\":true,\"owe\":false,\"enterprise\":false,"
    "\"ssid\":\"4f70656e50432e7365\",\"name\":\"OpenPC.se\","
    "\"mobility_domain\":\"a1b2\"},"
    "{\"bssid\":\"f0:9f:c2:7d:bd:7d\",\"frequency\":2412,\"signal\":-40,"
    "\"secured\":true,\"owe\":false,\"enterprise\":false,"
    "\"ssid\":\"4f70656e50432e7365\",\"name\":\"OpenPC.se\","
    "\"mobility_domain\":\"a1b2\"}]}";

/*
 * One SSID carrying an open, a passphrase and an enterprise network.
 *
 * A real arrangement rather than a curiosity: a site offering a guest network,
 * a staff one and 802.1X under one name is ordinary, and it is the case the
 * grouping key was too coarse for. When the key was "is it secured" the
 * passphrase network and the enterprise one merged, under a heading that said
 * "secured" and described only one of them -- so an operator selecting that row
 * got whichever came first.
 */
static const char THREE_SECURITIES_SCAN[] =
    "{\"response\":\"wifi_scan\",\"interface\":\"wlan0\",\"access_points\":["
    "{\"bssid\":\"f0:9f:c2:7d:bd:7d\",\"frequency\":2412,\"signal\":-40,"
    "\"secured\":true,\"owe\":false,\"enterprise\":false,\"ssid\":\"4f70656e50432e7365\","
    "\"name\":\"OpenPC.se\"},"
    "{\"bssid\":\"00:11:22:33:44:55\",\"frequency\":2437,\"signal\":-35,"
    "\"secured\":false,\"owe\":false,\"enterprise\":false,\"ssid\":\"4f70656e50432e7365\","
    "\"name\":\"OpenPC.se\"},"
    "{\"bssid\":\"00:11:22:33:44:66\",\"frequency\":5180,\"signal\":-50,"
    "\"secured\":true,\"owe\":false,\"enterprise\":true,\"ssid\":\"4f70656e50432e7365\","
    "\"name\":\"OpenPC.se\"}]}";

/*
 * Two groups, the first of which has two radios.
 *
 * The fixture the line-versus-entry regression needs: with `Office` drawn as a
 * heading and two detail rows, the third *line* is the second group's heading
 * and the third *entry* is one of `Office`'s radios. A `use` that indexed the
 * entries by the line would join `Office` while the highlight sat on `Cafe`.
 */
static const char TWO_GROUP_SCAN[] =
    "{\"response\":\"wifi_scan\",\"interface\":\"wlan0\",\"access_points\":["
    "{\"bssid\":\"00:00:00:00:00:01\",\"frequency\":2412,\"signal\":-30,"
    "\"secured\":true,\"owe\":false,\"enterprise\":false,\"ssid\":\"4f6666696365\",\"name\":\"Office\","
    "\"configured\":\"office\"},"
    "{\"bssid\":\"00:00:00:00:00:02\",\"frequency\":5180,\"signal\":-50,"
    "\"secured\":true,\"owe\":false,\"enterprise\":false,\"ssid\":\"4f6666696365\",\"name\":\"Office\","
    "\"configured\":\"office\"},"
    "{\"bssid\":\"00:00:00:00:00:03\",\"frequency\":2437,\"signal\":-60,"
    "\"secured\":true,\"owe\":false,\"enterprise\":false,\"ssid\":\"43616665\",\"name\":\"Cafe\","
    "\"configured\":\"cafe\"}]}";

/* One network nothing in the configuration describes, which `c` may not join. */
static const char UNCONFIGURED_SCAN[] =
    "{\"response\":\"wifi_scan\",\"interface\":\"wlan0\",\"access_points\":["
    "{\"bssid\":\"00:00:00:00:00:09\",\"frequency\":2412,\"signal\":-30,"
    "\"secured\":true,\"owe\":false,\"enterprise\":false,\"ssid\":\"537472616e676572\",\"name\":\"Stranger\"}]}";

/*
 * A station list with one of each case that renders differently.
 *
 * The witness pins one station -- on the list, authorized, with statistics --
 * and the pane has three cases. The other two are written with the witness's
 * own member names and different values, and the "no statistics" case is made
 * by leaving out the members the daemon omits when it has none.
 */
static const char THREE_STATIONS[] =
    "{\"response\":\"ap_stations\",\"interface\":\"wlan0\",\"access_point\":\"home\","
    "\"access_control\":\"deny\",\"stations\":["
    "{\"address\":\"00:11:22:33:44:55\",\"authorized\":true,\"listed\":true,"
    "\"signal\":-52,\"connected_seconds\":184,\"inactive_msec\":120,"
    "\"rx_bytes\":4096,\"tx_bytes\":8192},"
    "{\"address\":\"aa:bb:cc:dd:ee:ff\",\"authorized\":true,\"listed\":false},"
    "{\"address\":\"66:77:88:99:aa:bb\",\"authorized\":false,\"listed\":false,"
    "\"signal\":-70,\"connected_seconds\":60}]}";

/* ------------------------------------------------------------------------ *
 * The wifi pane
 * ------------------------------------------------------------------------ */

/*
 * Two radios of one access point are one row, with the radios under it.
 *
 * The case that produced this: an operator saw two `OpenPC.se` rows and asked
 * whether somebody was spoofing them. Both were real -- one access point,
 * 2.4 GHz and 5 GHz -- and the pane had drawn them as two lines identical but
 * for a few dBm, which is also what an evil twin looks like. Grouping answers
 * the question the flat list raised, and the detail rows keep the evidence a
 * reader needs to check it.
 */
static void two_radios_group_under_one_heading(void)
{
	size_t details = 0;
	size_t at;
	size_t first = 0;
	size_t second = 0;

	ncfg_tui_answer_free(&tui.scan);
	give(&tui.scan, TWO_RADIO_SCAN, "the two-radio scan parses");
	draw(NCFG_TUI_PANE_WIFI, NCFG_TUI_ROW_COUNT_WIDTH);

	check(lines_with("OpenPC.se") == 1, "two radios of one access point are one heading");
	check(any_line_has("2 radios"), "the heading says how many radios it stands for");
	for (at = 0; at < body.count; at++) {
		if (strncmp(ncfg_tui_line(&body, at), "    ", 4) == 0) {
			if (details == 0) {
				first = at;
			} else {
				second = at;
			}
			details++;
		}
	}
	check(details == 2, "both radios are still there, one detail row each");
	if (details == 2) {
		const char *one = ncfg_tui_line(&body, first);
		const char *other = ncfg_tui_line(&body, second);

		/* In the order the scan gave them, which the fixture deliberately does
		 * not sort. */
		check(strstr(one, "5GHz") && strstr(one, "f0:9f:c2:7e:bd:7d"),
		    "the first detail row is the 5GHz radio the scan sent first");
		check(strstr(other, "2.4GHz") && strstr(other, "f0:9f:c2:7d:bd:7d"),
		    "the second detail row is the 2.4GHz radio");
		/* The mobility domain is shown as a claim beside the address. */
		check(strstr(one, "ft:a1b2") != NULL,
		    "the mobility domain is shown beside the address, as a claim");
		detail("the first detail row", one);
	}
}

/* One SSID carrying three kinds of security is three rows. */
static void three_securities_are_three_rows(void)
{
	ncfg_tui_answer_free(&tui.scan);
	give(&tui.scan, THREE_SECURITIES_SCAN, "the three-security scan parses");
	draw(NCFG_TUI_PANE_WIFI, NCFG_TUI_ROW_COUNT_WIDTH);

	check(lines_with("OpenPC.se") == 3, "one name with three securities stays three rows");
	check(any_line_has("enterprise"), "the 802.1X network is named enterprise");
	check(any_line_has("secured"), "the passphrase network is named secured");
	check(any_line_has("open"), "the open network is named open");
}

/*
 * Same name, different security, is two networks and stays two.
 *
 * An open clone of a secured network is the evil twin that can actually take
 * your traffic, and collapsing it into the real one would hide the single
 * difference a person should act on.
 */
static void the_same_name_with_different_security_is_not_grouped(void)
{
	static const char scan[] =
	    "{\"response\":\"wifi_scan\",\"interface\":\"wlan0\",\"access_points\":["
	    "{\"bssid\":\"f0:9f:c2:7d:bd:7d\",\"frequency\":2412,\"signal\":-40,"
	    "\"secured\":true,\"owe\":false,\"enterprise\":false,"
	    "\"ssid\":\"4f70656e50432e7365\",\"name\":\"OpenPC.se\"},"
	    "{\"bssid\":\"00:11:22:33:44:55\",\"frequency\":2437,\"signal\":-35,"
	    "\"secured\":false,\"owe\":false,\"enterprise\":false,"
	    "\"ssid\":\"4f70656e50432e7365\",\"name\":\"OpenPC.se\"}]}";

	ncfg_tui_answer_free(&tui.scan);
	give(&tui.scan, scan, "the evil-twin scan parses");
	draw(NCFG_TUI_PANE_WIFI, NCFG_TUI_ROW_COUNT_WIDTH);

	check(lines_with("OpenPC.se") == 2, "an open clone of a secured network is not hidden");
	check(any_line_has("secured") && any_line_has("open"),
	    "both securities are named on their own row");
}

/*
 * A radio nobody has activated is offered, and the offer is actionable.
 *
 * The state the machine that reported this was in: a radio, no `device` block,
 * and a wifi pane that said "no wireless device in the configuration" and
 * stopped -- describing the problem to somebody standing in front of the fix.
 */
static void an_unactivated_radio_is_offered(void)
{
	static const char radios[] = "{\"response\":\"radios\",\"radios\":["
	    "{\"interface\":\"wlan0\",\"activated\":false,\"supplicant\":false}]}";
	size_t at;
	int    offered = 0;

	ncfg_tui_answer_free(&tui.scan);
	ncfg_tui_answer_free(&tui.radios);
	give(&tui.radios, radios, "the radio list parses");
	draw(NCFG_TUI_PANE_WIFI, NCFG_TUI_ROW_COUNT_WIDTH);

	for (at = 0; at < body.count; at++) {
		const ncfg_tui_row_t *row = ncfg_tui_row(&body, at);

		if (row->kind == NCFG_TUI_ROW_RADIO && strcmp(row->interface, "wlan0") == 0) {
			offered = 1;
			check(strstr(ncfg_tui_line(&body, at), "wlan0") != NULL,
			    "the offered row names the radio");
			check(strstr(ncfg_tui_line(&body, at), "press c") != NULL,
			    "the offered row says how to act on it");
		}
	}
	check(offered, "a radio nobody has activated is offered on the wifi pane");
}

/*
 * A radio another manager holds is shown and is *not* actionable.
 *
 * The state that wastes somebody's afternoon: pressing `c` would ask netcfgd to
 * take a radio it declines to take while the other manager is running, so the
 * row says who to stop instead of offering an action that cannot work.
 */
static void a_radio_another_manager_holds_is_not_offered(void)
{
	static const char radios[] = "{\"response\":\"radios\",\"radios\":["
	    "{\"interface\":\"wlan0\",\"activated\":false,\"supplicant\":true}]}";
	size_t at;
	int    shown = 0;

	ncfg_tui_answer_free(&tui.scan);
	ncfg_tui_answer_free(&tui.radios);
	give(&tui.radios, radios, "the held-radio list parses");
	draw(NCFG_TUI_PANE_WIFI, NCFG_TUI_ROW_COUNT_WIDTH);

	for (at = 0; at < body.count; at++) {
		if (!strstr(ncfg_tui_line(&body, at), "wlan0")) {
			continue;
		}
		shown = 1;
		check(strstr(ncfg_tui_line(&body, at), "another manager") != NULL,
		    "a radio another manager holds says so");
		check(ncfg_tui_row(&body, at)->kind != NCFG_TUI_ROW_RADIO,
		    "a radio that cannot be taken is not offered anyway");
	}
	check(shown, "a radio another manager holds is still shown");
}

/*
 * A machine whose radios are all working shows networks and nothing else.
 *
 * The other half, and the reason the list is conditional: hardware above the
 * networks on every machine that is already working would push the useful part
 * down the screen for ever.
 */
static void a_working_radio_is_not_listed(void)
{
	static const char radios[] = "{\"response\":\"radios\",\"radios\":["
	    "{\"interface\":\"wlan0\",\"activated\":true,\"supplicant\":true}]}";

	ncfg_tui_answer_free(&tui.radios);
	ncfg_tui_answer_free(&tui.scan);
	give(&tui.radios, radios, "the working-radio list parses");
	give(&tui.scan, TWO_RADIO_SCAN, "the scan beside it parses");
	draw(NCFG_TUI_PANE_WIFI, NCFG_TUI_ROW_COUNT_WIDTH);

	check(!any_line_has("wlan0"), "a working radio is not cluttering the pane");
	check(lines_with("radios") == 1,
	    "no empty radio section is drawn, and `2 radios` is the only match");
}

/*
 * The selected line names the entry it is about.
 *
 * Grouping made the nth line stop being the nth entry, and joining indexed the
 * entries by the line -- so selecting a heading below the first group would
 * have joined some other network. That is the worst kind of list bug: it acts,
 * confidently, on the wrong thing. This walks every line and asserts the entry
 * it names is the one it displays.
 */
static void every_line_names_the_entry_it_is_about(void)
{
	const ncfg_proto_scan_t *scan;
	size_t                   at;

	ncfg_tui_answer_free(&tui.radios);
	ncfg_tui_answer_free(&tui.scan);
	give(&tui.scan, TWO_RADIO_SCAN, "the two-radio scan parses again");
	draw(NCFG_TUI_PANE_WIFI, NCFG_TUI_ROW_COUNT_WIDTH);
	check(body.count >= 3, "the pane has a heading and two detail rows");

	scan = &tui.scan.message.u.response.u.wifi_scan;
	for (at = 0; at < body.count; at++) {
		const ncfg_tui_row_t *row = ncfg_tui_row(&body, at);
		const char           *line = ncfg_tui_line(&body, at);
		char                  bssid[64];

		if (row->kind != NCFG_TUI_ROW_NETWORK) {
			continue;
		}
		check(row->entry < scan->access_point_count, "the index is in range");
		if (row->entry >= scan->access_point_count) {
			continue;
		}
		(void)proto_text(scan->access_points[row->entry].bssid, bssid,
		    sizeof(bssid));
		if (strncmp(line, "    ", 4) == 0) {
			/* A detail row names its own radio. */
			check(strstr(line, bssid) != NULL, "a detail row names its own radio");
		} else {
			/* A heading stands for its strongest member, which is the one a
			 * client would associate with. */
			check(scan->access_points[row->entry].signal == -40,
			    "the heading points at the strongest radio, not the first");
		}
	}
}

/* The wifi pane reads the field the daemon sends, from the socket witness. */
static void the_wifi_pane_reads_the_field_the_daemon_sends(void)
{
	size_t length = 0;
	char  *pinned = socket_witness("wifi_scan", 0, &length);

	if (!pinned) {
		check(0, "the socket witness pins a `wifi_scan` response");
		return;
	}
	ncfg_tui_answer_free(&tui.radios);
	ncfg_tui_answer_free(&tui.scan);
	give(&tui.scan, pinned, "the pinned scan parses");
	draw(NCFG_TUI_PANE_WIFI, 60);

	/*
	 * `ScanReport`'s list is `access_points`; the Rust pane asked for `entries`,
	 * so every scan rendered as "(no scan)" from the day the TUI was written.
	 * This is the witness, so the pane is checked against what the socket pins
	 * rather than against somebody's second reading of the type.
	 */
	check(body.count > 0 && strstr(ncfg_tui_line(&body, 0), "home") != NULL,
	    "the first row is the access point the witness names");
	check(any_line_has("-40"), "its signal is the witness's own number");
	detail("the first row", ncfg_tui_line(&body, 0));
	free(pinned);
}

/* An empty scan says so rather than drawing nothing. */
static void an_empty_scan_says_so(void)
{
	static const char empty[] =
	    "{\"response\":\"wifi_scan\",\"interface\":\"wlan0\",\"access_points\":[]}";

	ncfg_tui_answer_free(&tui.radios);
	ncfg_tui_answer_free(&tui.scan);
	give(&tui.scan, empty, "an empty scan parses");
	draw(NCFG_TUI_PANE_WIFI, 60);
	check(body.count == 1 && strstr(ncfg_tui_line(&body, 0), "no scan") != NULL,
	    "an empty scan with no radios listed says how to rescan");
}

/* ------------------------------------------------------------------------ *
 * What `c` acts on
 * ------------------------------------------------------------------------ */

/*
 * `c` joins the network the selected line is about, not the nth entry.
 *
 * The regression the grouping introduced, asserted on the shape that produces
 * it: two groups, the first with two radios, so the second group's heading is
 * line 3 while entry 3 belongs to the first group.
 */
static void use_follows_the_line_and_not_the_entry(void)
{
	ncfg_tui_use_t chosen;
	char           err[NCFG_ERROR_MAX];
	size_t         at;
	size_t         cafe_line = 0;
	int            found = 0;

	ncfg_tui_answer_free(&tui.radios);
	ncfg_tui_answer_free(&tui.scan);
	give(&tui.scan, TWO_GROUP_SCAN, "the two-group scan parses");
	draw(NCFG_TUI_PANE_WIFI, NCFG_TUI_ROW_COUNT_WIDTH);

	for (at = 0; at < body.count; at++) {
		if (strstr(ncfg_tui_line(&body, at), "Cafe")) {
			cafe_line = at;
			found = 1;
		}
	}
	check(found, "the second group has a heading of its own");
	check(cafe_line >= 3, "it is below the first group's heading and its two radios");

	tui.pane = NCFG_TUI_PANE_WIFI;
	tui.selected = cafe_line;
	check(ncfg_tui_use(&tui, &chosen, err, sizeof(err)) == 1, "`c` on that line decides");
	check(chosen.kind == NCFG_TUI_USE_NETWORK, "it decides to join a network");
	check(strcmp(chosen.network, "cafe") == 0,
	    "it joins the network the highlighted line is about");
	detail("the network `c` chose", chosen.network);
	check(strcmp(chosen.interface, "wlan0") == 0,
	    "it joins it on the radio the status answer names");
}

/* `c` on a network the configuration does not describe says the boundary. */
static void use_on_an_unconfigured_network_says_the_boundary(void)
{
	ncfg_tui_use_t chosen;
	char           err[NCFG_ERROR_MAX];

	ncfg_tui_answer_free(&tui.radios);
	ncfg_tui_answer_free(&tui.scan);
	give(&tui.scan, UNCONFIGURED_SCAN, "the unconfigured scan parses");
	draw(NCFG_TUI_PANE_WIFI, NCFG_TUI_ROW_COUNT_WIDTH);

	tui.pane = NCFG_TUI_PANE_WIFI;
	tui.selected = 0;
	err[0] = '\0';
	check(ncfg_tui_use(&tui, &chosen, err, sizeof(err)) == 0,
	    "`c` on a network the config does not describe refuses");
	check(strstr(err, "not in the configuration") != NULL,
	    "and says so before the daemon has to");
	detail("what it said", err);
}

/* `c` on a radio row hands that radio over. */
static void use_on_a_radio_row_activates_it(void)
{
	static const char radios[] = "{\"response\":\"radios\",\"radios\":["
	    "{\"interface\":\"wlan0\",\"activated\":false,\"supplicant\":false}]}";
	ncfg_tui_use_t chosen;
	char           err[NCFG_ERROR_MAX];
	size_t         at;

	ncfg_tui_answer_free(&tui.radios);
	ncfg_tui_answer_free(&tui.scan);
	give(&tui.radios, radios, "the radio list parses for `c`");
	draw(NCFG_TUI_PANE_WIFI, NCFG_TUI_ROW_COUNT_WIDTH);

	for (at = 0; at < body.count; at++) {
		if (ncfg_tui_row(&body, at)->kind == NCFG_TUI_ROW_RADIO) {
			break;
		}
	}
	tui.pane = NCFG_TUI_PANE_WIFI;
	tui.selected = at;
	check(ncfg_tui_use(&tui, &chosen, err, sizeof(err)) == 1, "`c` on a radio decides");
	check(chosen.kind == NCFG_TUI_USE_RADIO && strcmp(chosen.interface, "wlan0") == 0,
	    "it hands netcfgd the radio the row names");

	/* And a heading is not an action. */
	tui.selected = 0;
	check(ncfg_tui_use(&tui, &chosen, err, sizeof(err)) == 1 &&
	    chosen.kind == NCFG_TUI_USE_NOTHING, "`c` on the `radios` heading does nothing");
}

/* ------------------------------------------------------------------------ *
 * The other panes
 * ------------------------------------------------------------------------ */

/* The device pane shows the interface, its state and its addresses. */
static void the_device_pane_draws_what_the_kernel_has(void)
{
	draw(NCFG_TUI_PANE_DEVICES, 132);

	check(any_line_has("eth0"), "the device pane names the interface the witness has");
	check(any_line_has("192.168.0.1/24"),
	    "and the address the witness gives that interface");
	check(any_line_has("carrier"), "and whether the cable is in");
	check(any_line_has("mtu 1500"), "and the MTU");
	/* `ownership` as the wire spells it, which is what reading the JSON gives
	 * and is deliberately not `ncfg status`'s capitalised word. */
	check(any_line_has("[ours]"), "an address carries its ownership as the wire spells it");
	check(any_line_has("dhcp4: running"), "a backend netcfgd started says so");
	detail("the first device row", ncfg_tui_line(&body, 0));
}

/*
 * A backend whose file has changed says it will be restarted.
 *
 * The witness has one -- `open_vpn` on `vpn0` with `config_matches` false --
 * and its link table has no `vpn0`, which is right and means the line is in the
 * pane nowhere. So the interface is added, with the witness's own member names,
 * rather than the backend being invented.
 */
static void a_stale_backend_says_it_will_be_restarted(void)
{
	static const char status[] = "{\"response\":\"status\",\"links\":["
	    "{\"name\":\"vpn0\",\"index\":9,\"up\":true,\"carrier\":true,\"mtu\":1420}],"
	    "\"addresses\":[],\"backends\":[{\"kind\":\"open_vpn\",\"interface\":\"vpn0\","
	    "\"running\":true,\"config_matches\":false}],"
	    "\"reports\":[{\"interface\":\"vpn0\",\"addresses\":[\"10.8.0.2/24\"],"
	    "\"gateways\":[\"10.8.0.1\"],\"nameservers\":[\"10.0.0.53\"]}]}";
	ncfg_tui_answer_t held = tui.status;

	memset(&tui.status, 0, sizeof(tui.status));
	give(&tui.status, status, "the stale-backend observation parses");
	draw(NCFG_TUI_PANE_DEVICES, 132);

	check(any_line_has("its configuration file has changed; it will be restarted"),
	    "a backend whose file changed says why it will be restarted");
	/*
	 * `[reported]` is the distinction the format exists to carry: what
	 * something outside netcfgd published is shown as reported, because it is
	 * not applied. An operator who cannot see the difference between "the
	 * bearer is up" and "netcfgd configured the interface" has no way to tell
	 * which half is broken.
	 */
	check(any_line_has("10.8.0.2/24 [reported]"), "a reported address is marked reported");
	check(any_line_has("via 10.8.0.1 [reported]"), "so is a reported gateway");
	check(any_line_has("dns 10.0.0.53 [reported]"), "so are reported nameservers");

	ncfg_tui_answer_free(&tui.status);
	tui.status = held;
}

/*
 * The plan pane shows the reason, not just the op.
 *
 * An action list without reasons is the black box this project exists to not
 * be, and the pane is where an operator reads it.
 *
 * **The op is read out of the witness rather than written here.** That is the
 * assertion the Rust file most needed: it read `addr.add` from a hand-written
 * fixture while the pane drew `addr_add` from the wire, for as long as both
 * existed (0083), and a fixture that agrees with itself proves nothing.
 */
static void the_plan_pane_shows_why(void)
{
	size_t           length = 0;
	char            *text = witness("plan.json", &length);
	ncfg_json_doc_t *doc;
	char             err[NCFG_ERROR_MAX];
	char             op[128];
	char             observed[128];
	char             desired[128];
	char             warning[256];
	char             reason[320];
	uint32_t         action;
	uint32_t         why;

	if (!text) {
		check(0, "the plan witness can be opened");
		return;
	}
	doc = ncfg_json_parse(text, length, err, sizeof(err));
	if (!doc) {
		check(0, "the plan witness parses");
		detail("the reader said", err);
		free(text);
		return;
	}
	action = ncfg_json_at(doc, ncfg_json_member(doc, ncfg_json_root(doc), "actions"), 0);
	why = ncfg_json_member(doc, action, "reason");
	(void)ncfg_json_copy_member(doc, ncfg_json_member(doc, action, "op"), "op", op,
	    sizeof(op));
	(void)ncfg_json_copy_member(doc, why, "observed", observed, sizeof(observed));
	(void)ncfg_json_copy_member(doc, why, "desired", desired, sizeof(desired));
	(void)ncfg_json_copy_member(doc,
	    ncfg_json_at(doc, ncfg_json_member(doc, ncfg_json_root(doc), "warnings"), 0),
	    "message", warning, sizeof(warning));
	(void)snprintf(reason, sizeof(reason), "%s -> %s", observed, desired);

	draw(NCFG_TUI_PANE_PLAN, 132);
	check(op[0] != '\0' && any_line_has(op),
	    "the plan pane draws the op the witness spells");
	check(any_line_has(reason), "and the two sides of the field that differs");
	check(warning[0] != '\0' && any_line_has(warning), "and the warnings it carries");
	detail("the first plan row", ncfg_tui_line(&body, 0));
	ncfg_json_free(doc);
	free(text);
}

/* An empty plan says so rather than drawing a blank pane. */
static void an_empty_plan_says_so(void)
{
	size_t            length = 0;
	char             *pinned = socket_witness("plan", 0, &length);
	ncfg_tui_answer_t held = tui.plan;

	if (!pinned) {
		check(0, "the socket witness pins a `plan` response");
		return;
	}
	memset(&tui.plan, 0, sizeof(tui.plan));
	give(&tui.plan, pinned, "the pinned empty plan parses");
	draw(NCFG_TUI_PANE_PLAN, 80);
	check(any_line_has("nothing to do"), "an empty plan says so");

	ncfg_tui_answer_free(&tui.plan);
	tui.plan = held;
	free(pinned);
}

/* The clients pane marks a station the access control should have stopped. */
static void the_clients_pane_marks_what_the_acl_should_have_stopped(void)
{
	ncfg_tui_answer_free(&tui.stations);
	give(&tui.stations, THREE_STATIONS, "the station list parses");
	draw(NCFG_TUI_PANE_CLIENTS, 60);

	check(body.count == 3, "one row per station");
	if (body.count != 3) {
		return;
	}
	/* On the deny list and connected anyway: hostapd was never told the list
	 * changed. That is the marker worth having on screen. */
	check(strncmp(ncfg_tui_line(&body, 0), "! 00:11:22:33:44:55", 19) == 0,
	    "a station on the deny list that is connected anyway is marked `!`");
	check(strncmp(ncfg_tui_line(&body, 1), "  aa:bb:cc:dd:ee:ff", 19) == 0,
	    "an ordinary station is not marked");
	check(strncmp(ncfg_tui_line(&body, 2), "? 66:77:88:99:aa:bb", 19) == 0,
	    "a station that associated without authorizing is marked `?`");
	/* A station hostapd could not read statistics for still gets a line, with
	 * dashes where the numbers would be. */
	check(strstr(ncfg_tui_line(&body, 1), "--") != NULL,
	    "a station with no statistics still gets a line, with dashes");
	check(strstr(ncfg_tui_line(&body, 0), "-52") != NULL,
	    "and one that has them shows them rather than dashes");
	detail("the marked row", ncfg_tui_line(&body, 0));
}

/* An empty station list says so rather than drawing nothing. */
static void an_empty_station_list_says_so(void)
{
	static const char empty[] = "{\"response\":\"ap_stations\",\"interface\":\"wlan0\","
	    "\"access_point\":\"home\",\"access_control\":\"deny\",\"stations\":[]}";

	ncfg_tui_answer_free(&tui.stations);
	give(&tui.stations, empty, "an empty station list parses");
	draw(NCFG_TUI_PANE_CLIENTS, 60);
	check(body.count == 1 && any_line_has("nobody associated"),
	    "an empty station list says so rather than drawing nothing");
}

/* ------------------------------------------------------------------------ *
 * The frame
 * ------------------------------------------------------------------------ */

/* The tab bar marks exactly the pane that is showing. */
static void the_tab_bar_marks_one_pane(void)
{
	int pane;

	for (pane = 0; pane < (int)NCFG_TUI_PANE_COUNT; pane++) {
		ncfg_buf_t  bar;
		const char *text;
		const char *at;
		size_t      marks = 0;
		char        wanted[32];

		tui.pane = (ncfg_tui_pane_t)pane;
		ncfg_buf_init(&bar, 0);
		ncfg_tui_tabs(&tui, 80, &bar);
		text = ncfg_buf_text(&bar);
		for (at = text; *at; at++) {
			if (*at == '[') {
				marks++;
			}
		}
		(void)snprintf(wanted, sizeof(wanted), "[%s]",
		    ncfg_tui_pane_title((ncfg_tui_pane_t)pane));
		check(marks == 1 && strstr(text, wanted) != NULL,
		    "the tab bar marks exactly the pane that is showing");
		check(characters(text) == 80, "and is exactly the width it was given");
		ncfg_buf_free(&bar);
	}
}

/*
 * Every line is at most the pane's width.
 *
 * A line *longer* than the window wraps and pushes everything below it down a
 * row, which on a full-screen client scrolls the footer away. A short line is
 * not a display bug, because the frame pads every row to the width.
 */
static void no_line_exceeds_the_width(void)
{
	static const size_t widths[] = { 80, 132, 40 };
	static const ncfg_tui_pane_t panes[] = { NCFG_TUI_PANE_DEVICES, NCFG_TUI_PANE_WIFI,
		NCFG_TUI_PANE_CLIENTS, NCFG_TUI_PANE_PLAN, NCFG_TUI_PANE_EVENTS };
	size_t which;
	int    over = 0;

	for (which = 0; which < sizeof(widths) / sizeof(widths[0]); which++) {
		size_t pane;

		for (pane = 0; pane < sizeof(panes) / sizeof(panes[0]); pane++) {
			size_t at;

			tui.selected = 0;
			draw(panes[pane], widths[which]);
			for (at = 0; at < body.count; at++) {
				if (characters(ncfg_tui_line(&body, at)) > widths[which]) {
					over++;
					detail("too wide", ncfg_tui_line(&body, at));
				}
			}
		}
	}
	check(over == 0, "no pane draws a line wider than the window it was given");
}

/* Truncation and padding both land on the width. */
static void the_frame_pads_and_truncates(void)
{
	ncfg_buf_t bar;

	ncfg_buf_init(&bar, 0);
	ncfg_tui_tabs(&tui, 4, &bar);
	check(strcmp(ncfg_buf_text(&bar), "ncfg") == 0, "a narrow window truncates rather "
	    "than wrapping");
	ncfg_buf_free(&bar);

	ncfg_buf_init(&bar, 0);
	ncfg_tui_tabs(&tui, 200, &bar);
	check(characters(ncfg_buf_text(&bar)) == 200, "a wide window is padded to its width");
	ncfg_buf_free(&bar);
}

/* How many times `needle` occurs. */
static size_t occurrences(const char *text, const char *needle)
{
	size_t      found = 0;
	const char *at = text;

	while ((at = strstr(at, needle)) != NULL) {
		found++;
		at += strlen(needle);
	}
	return found;
}

/*
 * The frame is one positioned row per terminal row, and the emphasis is on the
 * three rows that carry it.
 */
static void the_frame_is_one_row_per_terminal_row(void)
{
	ncfg_buf_t  frame;
	const char *text;

	ncfg_tui_answer_free(&tui.radios);
	ncfg_tui_answer_free(&tui.scan);
	give(&tui.scan, TWO_GROUP_SCAN, "the two-group scan parses for the frame");
	tui.pane = NCFG_TUI_PANE_WIFI;
	tui.selected = 0;
	tui.no_color = 0;

	ncfg_buf_init(&frame, 0);
	ncfg_tui_frame(&tui, 24, 80, &frame);
	text = ncfg_buf_text(&frame);

	check(occurrences(text, "\033[") - occurrences(text, "\033[7m") -
	    occurrences(text, "\033[27m") == 24,
	    "a 24-row terminal gets 24 positioned rows and no more");
	check(occurrences(text, "\033[7m") == 3 && occurrences(text, "\033[27m") == 3,
	    "the tab bar, the selected row and the key line are the emphasis");
	check(strstr(text, "\033[1;1H") != NULL && strstr(text, "\033[24;1H") != NULL,
	    "the first and last rows are addressed by number");
	/*
	 * **The footer is 81 characters and an 80-column terminal is 80**, so the
	 * last one is cut -- which is the Rust's behaviour too, since `fit` is what
	 * keeps a long line from wrapping and scrolling the footer away. Asserted
	 * as a prefix rather than quietly widened here, so that shortening the
	 * string later is a decision somebody takes rather than one this test hides.
	 */
	check(strncmp(strstr(text, "d devices") ? strstr(text, "d devices") : "",
	    ncfg_tui_keys(), 80) == 0, "the keys are always on screen, as far as they fit");
	check(strstr(text, tui.message) != NULL, "and so is the status line");
	ncfg_buf_free(&frame);
}

/* `$NO_COLOR` turns off even reverse video. */
static void no_color_turns_off_even_reverse_video(void)
{
	ncfg_buf_t frame;

	tui.no_color = 1;
	ncfg_buf_init(&frame, 0);
	ncfg_tui_frame(&tui, 24, 80, &frame);
	check(strstr(ncfg_buf_text(&frame), "\033[7m") == NULL,
	    "NO_COLOR leaves the frame with no emphasis at all");
	check(occurrences(ncfg_buf_text(&frame), "\033[") == 24,
	    "and with nothing but the row moves");
	ncfg_buf_free(&frame);
	tui.no_color = 0;
}

/*
 * The selection is on screen, whatever row it is on.
 *
 * **The Rust's is not, and this is the case that shows it.** It scrolls by
 * `lines.len().min(64)` -- the length of the list rather than the height of the
 * window -- so on an 80x24 terminal a pane with more than 21 and fewer than 65
 * rows never scrolls: pressing `j` walks the highlight past the last drawn row,
 * `Pane::draw` marks nothing because the row it was given is off the window, and
 * `c` goes on acting on a line nobody can see. Here the first visible row comes
 * from the body height, so the selected row is always drawn and always marked.
 */
static void the_selection_is_always_on_screen(void)
{
	ncfg_buf_t  frame;
	const char *text;
	const char *marked;
	size_t      selected;
	char        wanted[NCFG_TUI_WIDTH_MAX];

	draw(NCFG_TUI_PANE_DEVICES, 80);
	check(body.count > 21,
	    "the witness observation draws more rows than a 24-row terminal's body");
	if (body.count <= 21) {
		return;
	}
	selected = body.count - 1;
	(void)snprintf(wanted, sizeof(wanted), "%s", ncfg_tui_line(&body, selected));

	tui.pane = NCFG_TUI_PANE_DEVICES;
	tui.selected = selected;
	tui.no_color = 0;
	ncfg_buf_init(&frame, 0);
	ncfg_tui_frame(&tui, 24, 80, &frame);
	text = ncfg_buf_text(&frame);

	/*
	 * **The last body row, addressed by number, rather than "the text is in
	 * there somewhere".** A pane draws `access_point: running` under more than
	 * one interface, so a `strstr` for the selected line passes against a frame
	 * that is showing a *different* row with the same words -- which is exactly
	 * what the Rust's scrolling produces, and a check that cannot tell those
	 * apart is a decoration. Row 22 is the last of the 21 body rows on a 24-row
	 * terminal, and with the selection on the last line it has to be that line.
	 */
	marked = strstr(text, "\033[22;1H");
	check(marked != NULL && strncmp(marked + 7, "\033[7m", 4) == 0 &&
	    strncmp(marked + 11, wanted, strlen(wanted)) == 0,
	    "the selected row is the last row a short terminal draws");
	marked = strstr(text, "\033[7m");
	/* Three emphases: the tab bar, the selected row, the keys. The second is
	 * the one that has to be the selection. */
	marked = marked ? strstr(marked + 4, "\033[7m") : NULL;
	check(marked != NULL && strncmp(marked + 4, wanted, strlen(wanted)) == 0,
	    "and it is the row the emphasis is on");
	if (marked) {
		char shown[64];

		(void)snprintf(shown, sizeof(shown), "%.40s", marked + 4);
		detail("the emphasised row", shown);
	}
	ncfg_buf_free(&frame);
	tui.selected = 0;
}

/* ------------------------------------------------------------------------ *
 * The keyboard
 * ------------------------------------------------------------------------ */

/*
 * The highlight cannot be moved off the end of the list.
 *
 * Reported from a real terminal: holding the down key selected blank rows past
 * the last device, because adding one and stopping at the largest `size_t` is
 * not a list length.
 *
 * Every pane, because the bound is one line of code and the reason to test all
 * five is that each builds its rows differently -- the one that breaks will be
 * the one nobody thought about. Events is included even though it draws no
 * highlight: the index still moves, and a pane that starts drawing one later
 * should not inherit the bug.
 */
static void the_highlight_stops_at_the_last_row(void)
{
	int pane;

	for (pane = 0; pane < (int)NCFG_TUI_PANE_COUNT; pane++) {
		size_t rows;
		size_t press;
		int    stopped;
		int    reached;

		tui.pane = (ncfg_tui_pane_t)pane;
		tui.selected = 0;
		draw((ncfg_tui_pane_t)pane, NCFG_TUI_ROW_COUNT_WIDTH);
		rows = body.count;

		/* Further than any pane here has rows, so the clamp is what stops it
		 * rather than the loop running out. */
		for (press = 0; press < rows + 25; press++) {
			(void)ncfg_tui_key(&tui, NCFG_TUI_KEY_DOWN);
		}
		stopped = tui.selected < (rows > 0 ? rows : 1);
		/* And the pair: it still reaches the last row. A clamp that pinned the
		 * highlight at 0 would pass the assertion above and make the pane
		 * useless. */
		reached = tui.selected == (rows > 0 ? rows - 1 : 0);
		check(stopped && reached, "the highlight stops at the last row and reaches it");
		if (!stopped || !reached) {
			detail("pane", ncfg_tui_pane_title((ncfg_tui_pane_t)pane));
		}

		for (press = 0; press < rows + 25; press++) {
			(void)ncfg_tui_key(&tui, NCFG_TUI_KEY_UP);
		}
		check(tui.selected == 0, "and comes back to the first without going below it");
	}
	tui.selected = 0;
}

/* Every key the footer and the help promise does what they say. */
static void every_key_does_what_the_footer_says(void)
{
	tui.pane = NCFG_TUI_PANE_DEVICES;

	check(ncfg_tui_key(&tui, 'q') == NCFG_TUI_ACT_QUIT, "`q` leaves");
	check(ncfg_tui_key(&tui, 0x03) == NCFG_TUI_ACT_QUIT,
	    "and so does `^C`, which raw mode delivers as a key rather than a signal");

	check(ncfg_tui_key(&tui, 'w') == NCFG_TUI_ACT_REFRESH &&
	    tui.pane == NCFG_TUI_PANE_WIFI, "`w` shows the wifi pane and refetches");
	check(ncfg_tui_key(&tui, 's') == NCFG_TUI_ACT_REFRESH &&
	    tui.pane == NCFG_TUI_PANE_CLIENTS, "`s` shows the clients pane");
	check(ncfg_tui_key(&tui, 'p') == NCFG_TUI_ACT_REFRESH &&
	    tui.pane == NCFG_TUI_PANE_PLAN, "`p` shows the plan pane");
	check(ncfg_tui_key(&tui, 'e') == NCFG_TUI_ACT_REFRESH &&
	    tui.pane == NCFG_TUI_PANE_EVENTS, "`e` shows the events pane");
	check(ncfg_tui_key(&tui, 'd') == NCFG_TUI_ACT_REFRESH &&
	    tui.pane == NCFG_TUI_PANE_DEVICES, "`d` shows the devices pane");

	check(ncfg_tui_key(&tui, 'y') == NCFG_TUI_ACT_CONFIRM, "`y` keeps an applied change");
	check(ncfg_tui_key(&tui, 'n') == NCFG_TUI_ACT_REVERT, "`n` undoes one now");

	/*
	 * **`a` only on the plan pane, `c` only on the wifi pane.** Offering an
	 * apply from a pane that is not showing what would change is offering it
	 * blind.
	 */
	tui.pane = NCFG_TUI_PANE_DEVICES;
	check(ncfg_tui_key(&tui, 'a') == NCFG_TUI_ACT_NONE, "`a` does nothing off the plan");
	check(ncfg_tui_key(&tui, 'c') == NCFG_TUI_ACT_NONE, "`c` does nothing off the wifi");
	tui.pane = NCFG_TUI_PANE_PLAN;
	check(ncfg_tui_key(&tui, 'a') == NCFG_TUI_ACT_APPLY, "`a` applies from the plan pane");
	tui.pane = NCFG_TUI_PANE_WIFI;
	check(ncfg_tui_key(&tui, 'c') == NCFG_TUI_ACT_USE, "`c` uses from the wifi pane");

	check(ncfg_tui_key(&tui, 'r') == NCFG_TUI_ACT_REFRESH &&
	    strcmp(tui.message, "refreshed") == 0, "`r` refetches and says so");
	(void)ncfg_tui_key(&tui, '?');
	check(strcmp(tui.message, ncfg_tui_help()) == 0, "`?` says what the footer cannot");
	/*
	 * Not a repeat of the footer. A help key that prints what is already on the
	 * screen teaches the operator that help is useless.
	 */
	check(strcmp(ncfg_tui_help(), ncfg_tui_keys()) != 0,
	    "and says something the footer does not already");
	check(ncfg_tui_key(&tui, 'Z') == NCFG_TUI_ACT_NONE, "a key nothing is bound to does "
	    "nothing rather than something");

	tui.pane = NCFG_TUI_PANE_DEVICES;
	(void)snprintf(tui.message, sizeof(tui.message), "? for keys");
}

/*
 * The escape sequences the arrows arrive as.
 *
 * The Rust gets this from terminfo and says why the hand-rolled version failed:
 * it had no escape decoding at all, so arrow keys did nothing. This table is
 * small on purpose -- two keys -- and everything else it recognises it
 * recognises in order to *ignore*, which is the part that keeps an unknown
 * sequence from arriving as three keystrokes.
 */
static void the_arrow_keys_are_decoded(void)
{
	int    key = 0;
	size_t used = 0;

	check(ncfg_tui_key_decode("j", 1, &key, &used) == NCFG_TUI_INPUT_READY &&
	    key == 'j' && used == 1, "an ordinary byte is the key it is");

	check(ncfg_tui_key_decode("\033[A", 3, &key, &used) == NCFG_TUI_INPUT_READY &&
	    key == NCFG_TUI_KEY_UP && used == 3, "`ESC [ A` is the up arrow");
	check(ncfg_tui_key_decode("\033[B", 3, &key, &used) == NCFG_TUI_INPUT_READY &&
	    key == NCFG_TUI_KEY_DOWN && used == 3, "`ESC [ B` is the down arrow");
	/*
	 * A terminal in application cursor mode sends `ESC O A` for the same key. A
	 * client that knew only one form has arrows that work until somebody runs
	 * it under something else.
	 */
	check(ncfg_tui_key_decode("\033OA", 3, &key, &used) == NCFG_TUI_INPUT_READY &&
	    key == NCFG_TUI_KEY_UP && used == 3, "and so is `ESC O A`, in application mode");

	check(ncfg_tui_key_decode("\033", 1, &key, &used) == NCFG_TUI_INPUT_PARTIAL &&
	    used == 0, "a lone ESC asks for more rather than being a key");
	check(ncfg_tui_key_decode("\033[", 2, &key, &used) == NCFG_TUI_INPUT_PARTIAL,
	    "and so does a sequence that has begun and not finished");
	check(ncfg_tui_key_decode("", 0, &key, &used) == NCFG_TUI_INPUT_NONE,
	    "and an empty buffer is neither");

	/* A bracketed paste some terminals send unasked: six bytes, one key, and
	 * the key is nothing. */
	check(ncfg_tui_key_decode("\033[200~", 6, &key, &used) == NCFG_TUI_INPUT_READY &&
	    key == NCFG_TUI_KEY_OTHER && used == 6,
	    "a sequence nothing is bound to is consumed whole and does nothing");
	check(ncfg_tui_key(&tui, NCFG_TUI_KEY_OTHER) == NCFG_TUI_ACT_NONE,
	    "and an unbound key is not mapped to the wrong action");

	/* `ESC` then an ordinary byte is Escape, and the byte is the next key. */
	check(ncfg_tui_key_decode("\033q", 2, &key, &used) == NCFG_TUI_INPUT_READY &&
	    key == 0x1b && used == 1, "`ESC` before an ordinary byte is Escape itself");

	/* A burst decodes one key at a time out of the same buffer. */
	{
		const char burst[] = "jj\033[Bk";
		size_t     at = 0;
		int        keys[4];
		size_t     found = 0;

		while (at < sizeof(burst) - 1 && found < 4) {
			if (ncfg_tui_key_decode(burst + at, sizeof(burst) - 1 - at, &key,
			    &used) != NCFG_TUI_INPUT_READY) {
				break;
			}
			keys[found++] = key;
			at += used;
		}
		check(found == 4 && keys[0] == 'j' && keys[1] == 'j' &&
		    keys[2] == NCFG_TUI_KEY_DOWN && keys[3] == 'k',
		    "a burst is decoded a key at a time, with the arrow kept whole");
	}
}

/* ------------------------------------------------------------------------ *
 * Events, answers and the ceiling
 * ------------------------------------------------------------------------ */

/* The ring keeps the newest and drops the oldest. */
static void the_event_ring_keeps_the_newest(void)
{
	size_t at;

	for (at = 0; at < NCFG_TUI_EVENT_HISTORY + 50; at++) {
		char line[64];

		(void)snprintf(line, sizeof(line), "event %zu", at);
		ncfg_tui_event_push(&tui, line);
	}
	check(tui.event_count == NCFG_TUI_EVENT_HISTORY,
	    "the ring is bounded, because this runs for days on a server");
	check(strcmp(ncfg_tui_event(&tui, 0), "event 50") == 0,
	    "and it is the oldest that goes, not the newest");
	check(strcmp(ncfg_tui_event(&tui, NCFG_TUI_EVENT_HISTORY - 1),
	    "event 249") == 0, "the last one pushed is the last one there");
	check(strcmp(ncfg_tui_event(&tui, NCFG_TUI_EVENT_HISTORY), "") == 0,
	    "and reading past the end is the empty string rather than a read past it");

	draw(NCFG_TUI_PANE_EVENTS, 80);
	check(body.count == NCFG_TUI_EVENT_HISTORY, "the events pane draws every one it has");
}

/* An events pane with nothing in it says so. */
static void an_empty_events_pane_says_so(void)
{
	ncfg_tui_t empty;

	ncfg_tui_init(&empty);
	empty.pane = NCFG_TUI_PANE_EVENTS;
	ncfg_tui_lines_free(&body);
	ncfg_tui_body(&empty, 80, &body);
	check(body.count == 1 && any_line_has("waiting for events"),
	    "an events pane with nothing in it says it is waiting");
	ncfg_tui_free(&empty);
}

/* One event as the line a monitor shows. */
static void an_event_renders_as_one_line(void)
{
	static const char *const lines[] = {
		"{\"event\":\"observed\",\"summary\":\"eth0 up\"}",
		"{\"event\":\"reloaded\",\"ok\":true}",
		"{\"event\":\"drift\",\"interface\":\"eth0\",\"summary\":\"mtu\","
		    "\"action\":\"link_set\"}",
		"{\"event\":\"confirm_armed\",\"seconds\":60}",
		"{\"event\":\"confirm_resolved\",\"confirmed\":true}"
	};
	static const char *const wanted[] = {
		"observed  eth0 up",
		"reloaded  the configuration compiled",
		"drift     eth0: mtu (link_set)",
		"confirm   window open for 60s",
		"confirm   confirmed; the change stands"
	};
	size_t at;

	for (at = 0; at < sizeof(lines) / sizeof(lines[0]); at++) {
		ncfg_proto_message_t message;
		char                 err[NCFG_ERROR_MAX];
		char                 text[NCFG_TUI_EVENT_MAX];

		if (!ncfg_proto_response_read(lines[at], strlen(lines[at]), &message, err,
		    sizeof(err))) {
			check(0, "an event line parses");
			detail("the reader said", err);
			continue;
		}
		(void)ncfg_cli_event_text(&message.u.event, lines[at], strlen(lines[at]), text,
		    sizeof(text));
		check(strcmp(text, wanted[at]) == 0, "an event renders as the line it always has");
		if (strcmp(text, wanted[at]) != 0) {
			detail("drew", text);
			detail("wanted", wanted[at]);
		}
		ncfg_proto_message_free(&message);
	}
	{
		char text[NCFG_TUI_EVENT_MAX];

		/* A kind this build does not know is shown whole rather than refused:
		 * a monitor that printed nothing for a newer daemon's event would be
		 * useless for the ones it does understand. */
		(void)ncfg_cli_event_text(NULL, "{\"event\":\"from_the_future\"}", 27, text,
		    sizeof(text));
		check(strcmp(text, "{\"event\":\"from_the_future\"}") == 0,
		    "an event this build does not know is shown whole rather than dropped");
	}
}

/*
 * A refusal is an answer, and it goes on the status line.
 *
 * The sentence names the tier that would have been needed; the pane keeps
 * drawing whatever it had rather than being emptied by a permission problem.
 */
static void a_refusal_leaves_the_pane_alone(void)
{
	static const char refused[] =
	    "{\"response\":\"error\",\"message\":\"the `admin` tier is required\"}";
	ncfg_tui_answer_t answer;

	memset(&answer, 0, sizeof(answer));
	check(ncfg_tui_answer_read(&tui, &answer, refused, strlen(refused)) == 0,
	    "a refusal is not taken as a pane's answer");
	check(strcmp(tui.message, "the `admin` tier is required") == 0,
	    "and the daemon's own sentence is what the status line shows");
	check(answer.present == 0, "the pane is left with what it had");
	detail("the status line", tui.message);

	check(ncfg_tui_answer_read(&tui, &answer, "not json", 8) == 0,
	    "a line that will not parse is not taken either");
	check(strstr(tui.message, "offset") != NULL || tui.message[0] != '\0',
	    "and says what was wrong with it");
	ncfg_tui_answer_free(&answer);
	(void)snprintf(tui.message, sizeof(tui.message), "? for keys");
}

/*
 * A pane with more rows than the ceiling keeps the ceiling and counts the rest.
 *
 * 0263's shape, and the reason it is not the Rust's `Vec`: the rows here are
 * built from what a socket sent, and a renderer with no bound is one whose size
 * whoever is on the other end chooses. `total` is what keeps the fact from
 * being lost -- "256 of 400" says more than 400 rows nobody scrolls through.
 */
static void the_row_ceiling_counts_what_it_drops(void)
{
	ncfg_tui_t over;
	size_t     at;

	ncfg_tui_init(&over);
	for (at = 0; at < NCFG_TUI_ROWS_MAX + 44; at++) {
		char line[64];

		(void)snprintf(line, sizeof(line), "event %zu", at);
		ncfg_tui_event_push(&over, line);
	}
	over.pane = NCFG_TUI_PANE_EVENTS;
	ncfg_tui_lines_free(&body);
	ncfg_tui_body(&over, 80, &body);
	/* The ring is the smaller of the two bounds, so the ceiling is exercised by
	 * making the ring bigger than it. */
	check(body.count <= NCFG_TUI_ROWS_MAX, "no pane draws more rows than the ceiling");
	check(body.total >= body.count, "and `total` never says less than was drawn");
	check(strcmp(ncfg_tui_line(&body, body.count), "") == 0,
	    "a line past the count is the empty string");
	ncfg_tui_free(&over);
}

/* The status answer is where the radio comes from. */
static void the_radio_comes_from_the_status_answer(void)
{
	char name[NCFG_TUI_NAME_MAX];

	check(ncfg_tui_radio(&tui, name, sizeof(name)) == 1 && strcmp(name, "wlan0") == 0,
	    "the radio is the first link the kernel calls one");
	detail("the radio", name);
	{
		ncfg_tui_t none;

		ncfg_tui_init(&none);
		check(ncfg_tui_radio(&none, name, sizeof(name)) == 0 && name[0] == '\0',
		    "and a machine with no status answer has no radio rather than a guess");
		ncfg_tui_free(&none);
	}
}

/*
 * The envelopes these tests compose are the ones the socket pins.
 *
 * Every member of the pinned envelope has to be in the composed one, or these
 * tests are feeding the panes an object no daemon would produce -- which is the
 * mistake they exist to avoid. The reverse is not required: `socket.json` pins
 * an *empty* observation, and a member that is skipped when it is empty is
 * absent there and present here.
 */
static void the_envelopes_these_tests_compose_are_the_ones_the_socket_pins(void)
{
	static const char *const tags[] = { "status", "plan" };
	static const char *const files[] = { "observed.json", "plan.json" };
	size_t which;

	for (which = 0; which < 2; which++) {
		size_t           pinned_length = 0;
		size_t           composed_length = 0;
		size_t           content_length = 0;
		char            *pinned = socket_witness(tags[which], 0, &pinned_length);
		char            *content = witness(files[which], &content_length);
		char            *composed = NULL;
		ncfg_json_doc_t *one;
		ncfg_json_doc_t *other;
		char             err[NCFG_ERROR_MAX];
		uint32_t         count;
		uint32_t         at;
		int              missing = 0;

		if (!pinned || !content) {
			check(0, "the witnesses for this envelope can be opened");
			free(pinned);
			free(content);
			continue;
		}
		composed = under_envelope(tags[which], content, &composed_length);
		one = ncfg_json_parse(pinned, pinned_length, err, sizeof(err));
		other = composed
		    ? ncfg_json_parse(composed, composed_length, err, sizeof(err)) : NULL;
		if (!one || !other) {
			check(0, "the pinned envelope and the composed one both parse");
			detail("the reader said", err);
		} else {
			count = ncfg_json_count(one, ncfg_json_root(one));
			for (at = 0; at < count; at++) {
				uint32_t    member = ncfg_json_at(one, ncfg_json_root(one), at);
				size_t      length = 0;
				const char *key = ncfg_json_key(one, member, &length);
				char        name[128];

				(void)snprintf(name, sizeof(name), "%.*s", (int)length,
				    key ? key : "");
				if (ncfg_json_member(other, ncfg_json_root(other), name) ==
				    NCFG_JSON_NONE) {
					missing++;
					detail("the composed envelope has no", name);
				}
			}
			check(missing == 0, "the composed envelope is the one the socket pins");
		}
		ncfg_json_free(one);
		ncfg_json_free(other);
		free(composed);
		free(pinned);
		free(content);
	}
}

/* ------------------------------------------------------------------------ *
 * The run
 * ------------------------------------------------------------------------ */

int main(void)
{
	size_t observed_length = 0;
	size_t plan_length = 0;
	size_t length = 0;
	char  *observed_text = witness("observed.json", &observed_length);
	char  *plan_text = witness("plan.json", &plan_length);
	char  *status_line;
	char  *plan_line;

	printf("== tui\n");
	if (!observed_text || !plan_text) {
		printf("the schema witnesses could not be opened from here\n");
		free(observed_text);
		free(plan_text);
		return 1;
	}
	status_line = under_envelope("status", observed_text, &length);
	plan_line = under_envelope("plan", plan_text, &plan_length);
	free(observed_text);
	free(plan_text);
	if (!status_line || !plan_line) {
		printf("the witnesses could not be composed under their envelopes\n");
		free(status_line);
		free(plan_line);
		return 1;
	}

	ncfg_tui_init(&tui);
	ncfg_tui_lines_init(&body);
	give(&tui.status, status_line, "the composed status answer parses");
	give(&tui.plan, plan_line, "the composed plan answer parses");
	free(status_line);
	free(plan_line);

	the_device_pane_draws_what_the_kernel_has();
	a_stale_backend_says_it_will_be_restarted();
	the_plan_pane_shows_why();
	an_empty_plan_says_so();

	two_radios_group_under_one_heading();
	three_securities_are_three_rows();
	the_same_name_with_different_security_is_not_grouped();
	an_unactivated_radio_is_offered();
	a_radio_another_manager_holds_is_not_offered();
	a_working_radio_is_not_listed();
	every_line_names_the_entry_it_is_about();
	the_wifi_pane_reads_the_field_the_daemon_sends();
	an_empty_scan_says_so();

	use_follows_the_line_and_not_the_entry();
	use_on_an_unconfigured_network_says_the_boundary();
	use_on_a_radio_row_activates_it();

	the_clients_pane_marks_what_the_acl_should_have_stopped();
	an_empty_station_list_says_so();

	the_tab_bar_marks_one_pane();
	the_frame_pads_and_truncates();
	no_line_exceeds_the_width();
	the_frame_is_one_row_per_terminal_row();
	no_color_turns_off_even_reverse_video();
	the_selection_is_always_on_screen();

	the_highlight_stops_at_the_last_row();
	every_key_does_what_the_footer_says();
	the_arrow_keys_are_decoded();

	the_event_ring_keeps_the_newest();
	an_empty_events_pane_says_so();
	an_event_renders_as_one_line();
	a_refusal_leaves_the_pane_alone();
	the_row_ceiling_counts_what_it_drops();
	the_radio_comes_from_the_status_answer();
	the_envelopes_these_tests_compose_are_the_ones_the_socket_pins();

	ncfg_tui_lines_free(&body);
	ncfg_tui_free(&tui);

	if (failures > 0) {
		printf("tui: %d check(s) failed\n", failures);
		return 1;
	}
	printf("tui: every check passed\n");
	return 0;
}
