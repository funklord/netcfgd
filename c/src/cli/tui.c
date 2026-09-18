/*
 * tui.c -- `ncfg tui`, everything except the terminal.
 *
 * WHAT THIS FILE IS NOT ALLOWED TO DO
 *   **Open anything.** There is no `write`, no `poll`, no `getenv` and no
 *   descriptor in this file, and that is the whole design rather than a
 *   tidiness: a test that needs a terminal is a test that does not run, and the
 *   Rust says so itself -- its pane renderers are pure and its painting is
 *   "covered by `tests/live/tui.py` against a real pty", which is to say
 *   covered somewhere nobody runs by accident. Here the frame *including the
 *   escape sequences* is composed into an `ncfg_buf_t`, so which row is
 *   highlighted and what it says are assertions rather than a pty.
 *
 * IT SPEAKS THE PUBLIC SOCKET AND NOTHING ELSE
 *   Principle 9, and it is the Rust's sentence. There is no private request, no
 *   shortcut through the compiler, and nothing here a third-party client could
 *   not do. That is not politeness -- it is the test that keeps the socket
 *   honest, because a pane that needed something the socket could not express
 *   would mean the socket gets it, publicly.
 *
 * WHERE THE ANSWERS COME FROM
 *   Through `proto.h`, which is the one reader (0263). The Rust reads
 *   `serde_json::Value` instead, and says why: the derived deserialiser for the
 *   full document is hundreds of kilobytes against a 1.75 MB install. That
 *   reason is Rust's and does not carry -- `proto.h` decodes every response
 *   already and costs nothing per pane -- so the scan, the radios and the
 *   station list are read as the typed shapes. `status` and `plan` are the
 *   exception, and not by preference: they are `ncfg_proto_payload_t`, a parsed
 *   object this wave has no typed reader for, so those two panes read the JSON
 *   the way the Rust reads all five. 0263 records both halves.
 *
 * DEGRADES AS SECTION 7.2 REQUIRES
 *   80x24, no mouse, no colour and no unicode. Emphasis is reverse video, which
 *   every terminal back to a VT100 has, and `$NO_COLOR` turns even that off.
 */
#include "cli_internal.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ *
 * The small things every pane needs
 * ------------------------------------------------------------------------ */

/*
 * Pad or truncate to exactly `width` columns, counted in characters.
 *
 * The Rust counts `char`s, which is right for the ASCII this project restricts
 * itself to and wrong for double-width glyphs -- an SSID can contain anything.
 * **Counting bytes here would be a third answer and a worse one**: it would cut
 * a UTF-8 sequence in half and put the remainder on somebody's terminal, so
 * this advances a sequence at a time and counts one per sequence, which is the
 * Rust's number for every input that is valid UTF-8 and a byte each for one
 * that is not.
 *
 * Truncation is what keeps a wide name from wrapping and pushing the rest of
 * the frame down a line.
 */
static void fit(ncfg_buf_t *out, const char *text, size_t width)
{
	size_t at = 0;
	size_t drawn = 0;

	if (width > NCFG_TUI_WIDTH_MAX) {
		width = NCFG_TUI_WIDTH_MAX;
	}
	while (text && text[at] != '\0' && drawn < width) {
		unsigned char lead = (unsigned char)text[at];
		size_t        run = 1;
		size_t        there = 0;

		if (lead >= 0xf0u) {
			run = 4;
		} else if (lead >= 0xe0u) {
			run = 3;
		} else if (lead >= 0xc0u) {
			run = 2;
		}
		/* A sequence cut short by the end of the string is the bytes that are
		 * there, counted one at a time, not a read past them. */
		while (there < run && text[at + there] != '\0') {
			there++;
		}
		ncfg_buf_add(out, text + at, there);
		at += there;
		drawn++;
	}
	while (drawn < width) {
		ncfg_buf_add_char(out, ' ');
		drawn++;
	}
}

/*
 * A string member, or the empty string.
 *
 * Into a caller's buffer rather than handed out, because a JSON string is
 * counted rather than terminated and every call site here wants one it can
 * print.
 */
static const char *string_of(const ncfg_json_doc_t *doc, uint32_t object, const char *name,
    char *out, size_t out_size)
{
	if (!out || out_size == 0) {
		return "";
	}
	out[0] = '\0';
	if (doc) {
		(void)ncfg_json_copy_member(doc, object, name, out, out_size);
	}
	return out;
}

/* Whether a member is a string equal to `other`. */
static int member_is(const ncfg_json_doc_t *doc, uint32_t object, const char *name,
    const char *other)
{
	if (!doc) {
		return 0;
	}
	return ncfg_json_string_equals(doc, ncfg_json_member(doc, object, name), other);
}

/* A boolean member, with the caller's default for the absent case. */
static int bool_of(const ncfg_json_doc_t *doc, uint32_t object, const char *name, int fallback)
{
	if (!doc) {
		return fallback;
	}
	return ncfg_json_bool(doc, ncfg_json_member(doc, object, name), fallback);
}

/* An integer member, with the caller's default. */
static int64_t int_of(const ncfg_json_doc_t *doc, uint32_t object, const char *name,
    int64_t fallback)
{
	if (!doc) {
		return fallback;
	}
	return ncfg_json_int(doc, ncfg_json_member(doc, object, name), fallback);
}

/* An array member, or `NCFG_JSON_NONE` for anything that is not one. */
static uint32_t array_of(const ncfg_json_doc_t *doc, uint32_t object, const char *name)
{
	uint32_t found;

	if (!doc) {
		return NCFG_JSON_NONE;
	}
	found = ncfg_json_member(doc, object, name);
	if (ncfg_json_type(doc, found) != NCFG_JSON_ARRAY) {
		return NCFG_JSON_NONE;
	}
	return found;
}

/* ------------------------------------------------------------------------ *
 * The answers
 * ------------------------------------------------------------------------ */

/*
 * The parsed object a `status` or a `plan` carries.
 *
 * Those two are `ncfg_proto_payload_t` -- named by `proto.h` and owned by
 * modules this wave does not have -- so the object is handed over whole and
 * these panes read it. Any other answer has a typed shape and does not come
 * through here.
 */
static uint32_t payload_of(const ncfg_tui_answer_t *answer, const ncfg_json_doc_t **doc_out)
{
	*doc_out = NULL;
	if (!answer || !answer->present ||
	    answer->message.kind != NCFG_PROTO_MESSAGE_RESPONSE) {
		return NCFG_JSON_NONE;
	}
	if (answer->message.u.response.kind != NCFG_PROTO_RESP_STATUS &&
	    answer->message.u.response.kind != NCFG_PROTO_RESP_PLAN) {
		return NCFG_JSON_NONE;
	}
	*doc_out = answer->message.u.response.u.payload.doc;
	return answer->message.u.response.u.payload.object;
}

/* The scan an answer carries, or NULL. */
static const ncfg_proto_scan_t *scan_of(const ncfg_tui_answer_t *answer)
{
	if (!answer || !answer->present ||
	    answer->message.kind != NCFG_PROTO_MESSAGE_RESPONSE ||
	    answer->message.u.response.kind != NCFG_PROTO_RESP_WIFI_SCAN) {
		return NULL;
	}
	return &answer->message.u.response.u.wifi_scan;
}

/* The station list an answer carries, or NULL. */
static const ncfg_proto_stations_t *stations_of(const ncfg_tui_answer_t *answer)
{
	if (!answer || !answer->present ||
	    answer->message.kind != NCFG_PROTO_MESSAGE_RESPONSE ||
	    answer->message.u.response.kind != NCFG_PROTO_RESP_AP_STATIONS) {
		return NULL;
	}
	return &answer->message.u.response.u.ap_stations;
}

void ncfg_tui_answer_free(ncfg_tui_answer_t *answer)
{
	if (!answer) {
		return;
	}
	if (answer->present) {
		ncfg_proto_message_free(&answer->message);
	}
	memset(answer, 0, sizeof(*answer));
}

int ncfg_tui_answer_take(ncfg_tui_t *tui, ncfg_tui_answer_t *answer,
    ncfg_proto_message_t *message)
{
	if (!tui || !answer || !message) {
		return 0;
	}
	/*
	 * **A refusal is an answer**, and it replaces the status line rather than
	 * the pane: the sentence names the tier that would have been needed, and
	 * the pane goes on showing what it had. The Rust's `fetch` is this.
	 */
	if (message->kind == NCFG_PROTO_MESSAGE_RESPONSE &&
	    message->u.response.kind == NCFG_PROTO_RESP_ERROR) {
		(void)ncfg_cli_text(message->u.response.u.error.message, tui->message,
		    sizeof(tui->message));
		ncfg_proto_message_free(message);
		return 0;
	}
	if (message->kind != NCFG_PROTO_MESSAGE_RESPONSE) {
		(void)snprintf(tui->message, sizeof(tui->message),
		    "the daemon sent something that is not a response");
		ncfg_proto_message_free(message);
		return 0;
	}
	ncfg_tui_answer_free(answer);
	answer->message = *message;
	answer->present = 1;
	memset(message, 0, sizeof(*message));
	return 1;
}

int ncfg_tui_answer_read(ncfg_tui_t *tui, ncfg_tui_answer_t *answer, const char *line,
    size_t length)
{
	ncfg_proto_message_t message;
	char                 err[NCFG_ERROR_MAX];

	if (!tui || !answer) {
		return 0;
	}
	if (!ncfg_proto_response_read(line, length, &message, err, sizeof(err))) {
		(void)snprintf(tui->message, sizeof(tui->message), "%s", err);
		return 0;
	}
	return ncfg_tui_answer_take(tui, answer, &message);
}

/* ------------------------------------------------------------------------ *
 * The line list
 * ------------------------------------------------------------------------ */

void ncfg_tui_lines_init(ncfg_tui_lines_t *lines)
{
	if (!lines) {
		return;
	}
	memset(lines, 0, sizeof(*lines));
	ncfg_buf_init(&lines->text, 0);
}

void ncfg_tui_lines_free(ncfg_tui_lines_t *lines)
{
	if (!lines) {
		return;
	}
	ncfg_buf_free(&lines->text);
	memset(lines, 0, sizeof(*lines));
}

const char *ncfg_tui_line(const ncfg_tui_lines_t *lines, size_t at)
{
	if (!lines || at >= lines->count || ncfg_buf_failed(&lines->text)) {
		return "";
	}
	return ncfg_buf_text(&lines->text) + lines->offsets[at];
}

const ncfg_tui_row_t *ncfg_tui_row(const ncfg_tui_lines_t *lines, size_t at)
{
	static const ncfg_tui_row_t nothing = { NCFG_TUI_ROW_NOTHING, { 0 }, 0 };

	if (!lines || at >= lines->count) {
		return &nothing;
	}
	return &lines->rows[at];
}

/*
 * Start a line, and say what it is about.
 *
 * Returns 0 once the ceiling is reached, and `total` goes on counting -- so
 * "256 of 400" is a fact the caller still has, which is more than a renderer
 * that silently drew the first 256 would leave anybody.
 */
static int line_open(ncfg_tui_lines_t *lines, const ncfg_tui_row_t *row)
{
	lines->total++;
	if (lines->count >= NCFG_TUI_ROWS_MAX) {
		return 0;
	}
	lines->offsets[lines->count] = lines->text.length;
	memset(&lines->rows[lines->count], 0, sizeof(lines->rows[lines->count]));
	if (row) {
		lines->rows[lines->count] = *row;
	}
	return 1;
}

/* Finish it: the NUL that separates it from the next. */
static void line_close(ncfg_tui_lines_t *lines)
{
	ncfg_buf_add_char(&lines->text, '\0');
	lines->count++;
}

/*
 * One whole line, fitted, about nothing.
 *
 * **Every line goes through this, which the Rust does not do.** It fits most of
 * its rows and leaves a handful unfitted -- an address under an interface, the
 * radio rows, the "nothing to do" line -- on the reasoning that they are short.
 * A radio row is `"  {name:<16} {state}"` and the longest state is 34
 * characters, so on a 40-column terminal it is not short: it wraps, and a wrap
 * pushes everything below it down a row, which on a full-screen client scrolls
 * the footer off the bottom. One rule is also one thing to test, and
 * `no_line_exceeds_the_width` is only worth having if it covers every row.
 */
static void line_fit(ncfg_tui_lines_t *lines, const char *text, size_t width)
{
	if (!line_open(lines, NULL)) {
		return;
	}
	fit(&lines->text, text, width);
	line_close(lines);
}

/* ------------------------------------------------------------------------ *
 * The events ring
 * ------------------------------------------------------------------------ */

void ncfg_tui_init(ncfg_tui_t *tui)
{
	if (!tui) {
		return;
	}
	memset(tui, 0, sizeof(*tui));
	tui->pane = NCFG_TUI_PANE_DEVICES;
	(void)snprintf(tui->message, sizeof(tui->message), "? for keys");
}

void ncfg_tui_free(ncfg_tui_t *tui)
{
	size_t at;

	if (!tui) {
		return;
	}
	ncfg_tui_answer_free(&tui->status);
	ncfg_tui_answer_free(&tui->plan);
	ncfg_tui_answer_free(&tui->scan);
	ncfg_tui_answer_free(&tui->radios);
	ncfg_tui_answer_free(&tui->stations);
	for (at = 0; at < NCFG_TUI_EVENT_HISTORY; at++) {
		free(tui->events[at]);
		tui->events[at] = NULL;
	}
	tui->event_first = 0;
	tui->event_count = 0;
}

void ncfg_tui_event_push(ncfg_tui_t *tui, const char *line)
{
	size_t slot;
	size_t length;
	char  *kept;

	if (!tui || !line) {
		return;
	}
	length = strlen(line);
	if (length > NCFG_TUI_EVENT_MAX - 1) {
		length = NCFG_TUI_EVENT_MAX - 1;
	}
	kept = malloc(length + 1);
	if (!kept) {
		/* A library never exits, and an event nobody could hold is one line
		 * of history rather than a reason to end a session somebody is
		 * watching the network through. */
		return;
	}
	memcpy(kept, line, length);
	kept[length] = '\0';

	if (tui->event_count == NCFG_TUI_EVENT_HISTORY) {
		free(tui->events[tui->event_first]);
		tui->events[tui->event_first] = NULL;
		tui->event_first = (tui->event_first + 1) % NCFG_TUI_EVENT_HISTORY;
		tui->event_count--;
	}
	slot = (tui->event_first + tui->event_count) % NCFG_TUI_EVENT_HISTORY;
	tui->events[slot] = kept;
	tui->event_count++;
}

const char *ncfg_tui_event(const ncfg_tui_t *tui, size_t at)
{
	size_t slot;

	if (!tui || at >= tui->event_count) {
		return "";
	}
	slot = (tui->event_first + at) % NCFG_TUI_EVENT_HISTORY;
	return tui->events[slot] ? tui->events[slot] : "";
}

/* ------------------------------------------------------------------------ *
 * The tab bar and the footer
 * ------------------------------------------------------------------------ */

const char *ncfg_tui_pane_title(ncfg_tui_pane_t pane)
{
	switch (pane) {
	case NCFG_TUI_PANE_DEVICES:
		return "devices";
	case NCFG_TUI_PANE_WIFI:
		return "wifi";
	case NCFG_TUI_PANE_CLIENTS:
		return "clients";
	case NCFG_TUI_PANE_PLAN:
		return "plan";
	case NCFG_TUI_PANE_EVENTS:
		return "events";
	case NCFG_TUI_PANE_COUNT:
	default:
		/* value.h's rule: a plausible word for a value that is not one is
		 * worse than no word. */
		return NULL;
	}
}

const char *ncfg_tui_keys(void)
{
	return "d devices  w wifi  p plan  e events | j/k move  r refresh  a apply  "
	    "c use  q quit";
}

const char *ncfg_tui_help(void)
{
	return "d w s p e switch panes (s is clients). a applies with a 60s window: y "
	    "keeps it, n undoes it now, nothing reverts it. `c` uses the selected row: "
	    "it joins a network the config can join (marked `c`), or hands netcfgd a "
	    "radio nobody has given it. `!` marks a station the access point should "
	    "not be talking to.";
}

void ncfg_tui_tabs(const ncfg_tui_t *tui, size_t width, ncfg_buf_t *out)
{
	ncfg_buf_t bar;
	int        pane;

	ncfg_buf_init(&bar, NCFG_TUI_WIDTH_MAX * 4u);
	ncfg_buf_add_text(&bar, "ncfg  ");
	for (pane = 0; pane < (int)NCFG_TUI_PANE_COUNT; pane++) {
		const char *title = ncfg_tui_pane_title((ncfg_tui_pane_t)pane);

		if (tui && (int)tui->pane == pane) {
			ncfg_buf_addf(&bar, "[%s]", title);
		} else {
			ncfg_buf_addf(&bar, " %s ", title);
		}
	}
	fit(out, ncfg_buf_text(&bar), width);
	ncfg_buf_free(&bar);
}

/* ------------------------------------------------------------------------ *
 * The devices pane
 * ------------------------------------------------------------------------ */

/*
 * What something outside netcfgd reported for this interface, and did not
 * apply.
 *
 * `ncfg status` has marked these since the modem work and this pane did not,
 * which made the TUI the one view where a bearer that is up and an interface
 * that is configured look the same. The difference is the whole question when
 * a modem is not working: "the network gave us nothing" and "netcfgd has not
 * acted on it" send somebody to different places.
 */
static void reported_on(const ncfg_json_doc_t *doc, uint32_t status, const char *interface,
    size_t width, ncfg_tui_lines_t *out)
{
	uint32_t reports = array_of(doc, status, "reports");
	uint32_t count = ncfg_json_count(doc, reports);
	uint32_t at;

	for (at = 0; at < count; at++) {
		uint32_t report = ncfg_json_at(doc, reports, at);
		uint32_t list;
		uint32_t many;
		uint32_t one;
		char     line[NCFG_TUI_WIDTH_MAX];

		if (!member_is(doc, report, "interface", interface)) {
			continue;
		}
		list = array_of(doc, report, "addresses");
		many = ncfg_json_count(doc, list);
		for (one = 0; one < many; one++) {
			size_t      length = 0;
			const char *address = ncfg_json_string(doc, ncfg_json_at(doc, list, one),
			    &length);

			(void)snprintf(line, sizeof(line), "    %.*s [reported]", (int)length,
			    address ? address : "");
			line_fit(out, line, width);
		}
		list = array_of(doc, report, "gateways");
		many = ncfg_json_count(doc, list);
		for (one = 0; one < many; one++) {
			size_t      length = 0;
			const char *gateway = ncfg_json_string(doc, ncfg_json_at(doc, list, one),
			    &length);

			(void)snprintf(line, sizeof(line), "    via %.*s [reported]", (int)length,
			    gateway ? gateway : "");
			line_fit(out, line, width);
		}
		list = array_of(doc, report, "nameservers");
		many = ncfg_json_count(doc, list);
		if (many > 0) {
			ncfg_buf_t servers;

			ncfg_buf_init(&servers, NCFG_TUI_WIDTH_MAX * 4u);
			for (one = 0; one < many; one++) {
				size_t      length = 0;
				const char *server = ncfg_json_string(doc,
				    ncfg_json_at(doc, list, one), &length);

				if (one > 0) {
					ncfg_buf_add_char(&servers, ' ');
				}
				ncfg_buf_add(&servers, server ? server : "", length);
			}
			(void)snprintf(line, sizeof(line), "    dns %s [reported]",
			    ncfg_buf_text(&servers));
			ncfg_buf_free(&servers);
			line_fit(out, line, width);
		}
		/* The Rust takes the first report for an interface and stops; a second
		 * one for the same name would be the writer's fault, and printing both
		 * would make one bearer look like two. */
		return;
	}
}

/*
 * What netcfgd started here, and whether it is still what the document says.
 *
 * The plan pane shows the restart while it is pending; this shows the reason it
 * is pending, on the interface, where somebody looking at a radio is already
 * looking. Only the answers that mean something is wrong -- decisions 0052 and
 * 0053 -- because a line every reader skips is how the one that matters gets
 * skipped with it.
 */
static void backends_on(const ncfg_json_doc_t *doc, uint32_t status, const char *interface,
    size_t width, ncfg_tui_lines_t *out)
{
	uint32_t backends = array_of(doc, status, "backends");
	uint32_t count = ncfg_json_count(doc, backends);
	uint32_t at;

	for (at = 0; at < count; at++) {
		uint32_t    backend = ncfg_json_at(doc, backends, at);
		const char *said = NULL;
		char        kind[NCFG_TUI_NAME_MAX];
		char        line[NCFG_TUI_WIDTH_MAX];

		if (!member_is(doc, backend, "interface", interface)) {
			continue;
		}
		if (!bool_of(doc, backend, "running", 0)) {
			continue;
		}
		if (!bool_of(doc, backend, "secret_matches", 1)) {
			said = "the passphrase has changed";
		} else if (!bool_of(doc, backend, "config_matches", 1)) {
			said = "its configuration file has changed";
		}
		(void)string_of(doc, backend, "kind", kind, sizeof(kind));
		if (said) {
			(void)snprintf(line, sizeof(line),
			    "    %s: running, %s; it will be restarted", kind, said);
		} else {
			(void)snprintf(line, sizeof(line), "    %s: running", kind);
		}
		line_fit(out, line, width);
	}
}

static void devices(const ncfg_tui_t *tui, size_t width, ncfg_tui_lines_t *out)
{
	const ncfg_json_doc_t *doc;
	uint32_t               status = payload_of(&tui->status, &doc);
	uint32_t               links = array_of(doc, status, "links");
	uint32_t               addresses;
	uint32_t               count;
	uint32_t               at;

	if (links == NCFG_JSON_NONE) {
		line_fit(out, "(no status yet)", width);
		return;
	}
	addresses = array_of(doc, status, "addresses");
	count = ncfg_json_count(doc, links);

	for (at = 0; at < count; at++) {
		uint32_t link = ncfg_json_at(doc, links, at);
		uint32_t many = ncfg_json_count(doc, addresses);
		uint32_t one;
		char     name[NCFG_TUI_NAME_MAX];
		char     line[NCFG_TUI_WIDTH_MAX];

		(void)string_of(doc, link, "name", name, sizeof(name));
		(void)snprintf(line, sizeof(line), "%-14s %-5s %-10s mtu %lld", name,
		    bool_of(doc, link, "up", 0) ? "up" : "down",
		    bool_of(doc, link, "carrier", 0) ? "carrier" : "no carrier",
		    (long long)int_of(doc, link, "mtu", 0));
		line_fit(out, line, width);

		for (one = 0; one < many; one++) {
			uint32_t address = ncfg_json_at(doc, addresses, one);
			char     text[NCFG_TUI_NAME_MAX * 2];
			char     ownership[NCFG_TUI_NAME_MAX];

			if (!member_is(doc, address, "interface", name)) {
				continue;
			}
			(void)snprintf(line, sizeof(line), "    %s [%s]",
			    string_of(doc, address, "address", text, sizeof(text)),
			    string_of(doc, address, "ownership", ownership, sizeof(ownership)));
			line_fit(out, line, width);
		}
		reported_on(doc, status, name, width, out);
		backends_on(doc, status, name, width, out);
	}
	if (out->count == 0) {
		line_fit(out, "(no interfaces)", width);
	}
}

/* ------------------------------------------------------------------------ *
 * The wifi pane
 * ------------------------------------------------------------------------ */

/*
 * The band a centre frequency is in, as a person names it.
 *
 * Not the channel number, which is what the kernel and every scan tool report:
 * a reader trying to tell two rows apart wants "these are the two radios of one
 * access point", and `2.4GHz` beside `5GHz` says that where `1` beside `44`
 * does not.
 *
 * An unrecognised frequency is printed as its megahertz rather than guessed at
 * or blanked. A band this does not know is one worth seeing the number for, and
 * a blank column would read as missing data.
 */
static const char *band_of(int64_t frequency, char *out, size_t out_size)
{
	if (frequency == 0) {
		(void)snprintf(out, out_size, "%s", "");
	} else if (frequency >= 2400 && frequency <= 2500) {
		(void)snprintf(out, out_size, "2.4GHz");
	} else if (frequency >= 4900 && frequency <= 5895) {
		(void)snprintf(out, out_size, "5GHz");
	} else if (frequency >= 5925 && frequency <= 7125) {
		(void)snprintf(out, out_size, "6GHz");
	} else {
		(void)snprintf(out, out_size, "%lldM", (long long)frequency);
	}
	return out;
}

/* The name and the security word one scan entry is grouped by. */
typedef struct {
	char        name[NCFG_TUI_NAME_MAX];
	const char *security;
} scan_key_t;

/*
 * The key a scan entry groups under.
 *
 * **The security word rather than the booleans behind it**, so the key cannot
 * be coarser than what a reader sees. A key of "is it secured" would merge a
 * passphrase network and an enterprise one sharing an SSID -- which is a real
 * arrangement, not a curiosity -- under a heading that then described only one
 * of them.
 */
static void key_of(const ncfg_proto_scan_entry_t *entry, scan_key_t *out)
{
	char name_text[NCFG_TUI_NAME_MAX];
	char ssid_text[NCFG_TUI_NAME_MAX * 2];

	(void)ncfg_cli_access_point_name(
	    ncfg_proto_str_present(entry->name)
	    ? ncfg_cli_text(entry->name, name_text, sizeof(name_text))
	    : NULL,
	    ncfg_cli_text(entry->ssid, ssid_text, sizeof(ssid_text)), out->name,
	    sizeof(out->name));
	out->security = ncfg_cli_access_point_security(entry->secured, entry->enterprise,
	    entry->owe);
}

static int key_same(const scan_key_t *one, const scan_key_t *other)
{
	return strcmp(one->name, other->name) == 0 &&
	    strcmp(one->security, other->security) == 0;
}

/*
 * The radios worth showing, which is not always all of them.
 *
 * **Only when there is something to do about one.** A machine whose radios are
 * all activated and answering wants its wifi pane to be networks, and a list of
 * hardware above them is clutter that pushes the useful part down the screen. A
 * radio that is not activated, or activated with nothing answering, is a reason
 * the pane is emptier than expected -- and that is exactly when it has to be
 * visible.
 */
static void radio_rows(const ncfg_tui_t *tui, size_t width, ncfg_tui_lines_t *out)
{
	const ncfg_proto_radio_t *radios = NULL;
	size_t                    count = 0;
	size_t                    unfinished = 0;
	size_t                    at;

	if (tui->radios.present && tui->radios.message.kind == NCFG_PROTO_MESSAGE_RESPONSE &&
	    tui->radios.message.u.response.kind == NCFG_PROTO_RESP_RADIOS) {
		radios = tui->radios.message.u.response.u.radios.items;
		count = tui->radios.message.u.response.u.radios.count;
	}
	for (at = 0; at < count; at++) {
		if (!radios[at].activated || !radios[at].supplicant) {
			unfinished++;
		}
	}
	if (unfinished == 0) {
		return;
	}
	line_fit(out, "radios", width);
	for (at = 0; at < count; at++) {
		ncfg_tui_row_t row;
		const char    *state;
		char           name[NCFG_TUI_NAME_MAX];
		char           line[NCFG_TUI_WIDTH_MAX];

		if (radios[at].activated && radios[at].supplicant) {
			continue;
		}
		if (!ncfg_proto_str_present(radios[at].interface)) {
			(void)snprintf(name, sizeof(name), "?");
		} else {
			(void)ncfg_cli_text(radios[at].interface, name, sizeof(name));
		}
		memset(&row, 0, sizeof(row));
		if (!radios[at].activated && radios[at].supplicant) {
			/* The one a person gets stuck in: another manager holds this
			 * radio, so activating changes nothing until that stops. Said
			 * here rather than discovered by pressing `c` and waiting. */
			state = "another manager's -- stop it first";
		} else if (!radios[at].activated) {
			state = "not activated -- press c";
			row.kind = NCFG_TUI_ROW_RADIO;
			(void)snprintf(row.interface, sizeof(row.interface), "%s", name);
		} else {
			state = "activated, no supplicant answering";
		}
		(void)snprintf(line, sizeof(line), "  %-16s %s", name, state);
		if (line_open(out, &row)) {
			fit(&out->text, line, width);
			line_close(out);
		}
	}
	line_fit(out, "", width);
}

/*
 * The wifi pane, with the scan entry each line stands for.
 *
 * **One grouping, not two.** The pane groups radios under a network, so the nth
 * *line* stopped being the nth *entry* -- and joining indexed the entries by
 * the selected line. Selecting a heading below the first group would have
 * joined some other network entirely, which is the worst kind of bug a list can
 * have: it does something, confidently, to the wrong thing.
 *
 * So the grouping happens once and says what each line means. A heading carries
 * its group's strongest entry, which is the one a client would associate with;
 * a detail row carries its own, so pressing `c` on a radio joins the network
 * that radio belongs to.
 *
 * **Grouped by name and security and by nothing cleverer, on purpose.**
 * Adjacent addresses and a shared manufacturer prefix say "one access point" to
 * a reader and are convention rather than fact, and the mobility domain is
 * unauthenticated -- grouping on either would be the display asserting
 * something it cannot know. The members are shown instead, and the reader draws
 * the conclusion with the evidence in front of them.
 */
static void wifi(const ncfg_tui_t *tui, size_t width, ncfg_tui_lines_t *out)
{
	const ncfg_proto_scan_t *scan = scan_of(&tui->scan);
	size_t                   total = scan ? scan->access_point_count : 0;
	size_t                   done = 0;
	size_t                   at;

	radio_rows(tui, width, out);
	if (total == 0) {
		/* With radios listed above, an empty scan is explained by them rather
		 * than being a second mystery. */
		line_fit(out, out->count == 0 ? "(no scan; press r to rescan)"
		    : "(nothing scanned yet)", width);
		return;
	}

	/*
	 * One pass per group rather than a map: the Rust keeps three hash maps
	 * keyed on the pair, which in C would be a hash table for a list that is
	 * fifty long at its worst. Walking the entries again per group is the same
	 * answer with nothing to allocate, and `done` is what stops a group being
	 * emitted twice.
	 */
	for (at = 0; at < total && done < total; at++) {
		scan_key_t     key;
		ncfg_tui_row_t row;
		size_t         members = 0;
		size_t         strongest = at;
		size_t         earlier;
		size_t         one;
		int64_t        signal = 0;
		int            have_signal = 0;
		int            seen = 0;
		char           configured[NCFG_TUI_NAME_MAX];
		char           block[NCFG_TUI_NAME_MAX + 8];
		char           radios[32];
		char           line[NCFG_TUI_WIDTH_MAX];

		key_of(&scan->access_points[at], &key);
		for (earlier = 0; earlier < at; earlier++) {
			scan_key_t before;

			key_of(&scan->access_points[earlier], &before);
			if (key_same(&key, &before)) {
				seen = 1;
				break;
			}
		}
		if (seen) {
			continue;
		}

		configured[0] = '\0';
		block[0] = '\0';
		for (one = at; one < total; one++) {
			const ncfg_proto_scan_entry_t *entry = &scan->access_points[one];
			scan_key_t                     mine;

			key_of(entry, &mine);
			if (!key_same(&key, &mine)) {
				continue;
			}
			members++;
			done++;
			/*
			 * The strongest member speaks for the group, because that is the
			 * one a client would associate with and the number a reader is
			 * judging. `>=` rather than `>`: Rust's `max_by_key` keeps the
			 * last of several equal maxima, and a heading that pointed at a
			 * different radio than the Rust's would be a silent difference in
			 * what `c` joins.
			 */
			if (!have_signal || entry->signal >= signal) {
				signal = entry->signal;
				have_signal = 1;
				strongest = one;
			}
			if (configured[0] == '\0' && ncfg_proto_str_present(entry->configured)) {
				(void)ncfg_cli_text(entry->configured, configured,
				    sizeof(configured));
				(void)snprintf(block, sizeof(block), "  [%s]", configured);
			}
		}

		radios[0] = '\0';
		if (members > 1) {
			(void)snprintf(radios, sizeof(radios), "%zu radios", members);
		}
		memset(&row, 0, sizeof(row));
		row.kind = NCFG_TUI_ROW_NETWORK;
		row.entry = strongest;
		(void)snprintf(line, sizeof(line), "%s %-28s %4lld dBm  %-7s  %-8s%s",
		    configured[0] != '\0' ? "c" : " ", key.name, (long long)signal,
		    key.security, radios, block);
		if (line_open(out, &row)) {
			fit(&out->text, line, width);
			line_close(out);
		}

		/* The detail, and only where there is something to tell apart. One
		 * radio adds a line that says what the heading already said. */
		if (members < 2) {
			continue;
		}
		for (one = at; one < total; one++) {
			const ncfg_proto_scan_entry_t *entry = &scan->access_points[one];
			scan_key_t                     mine;
			char                           bssid[NCFG_TUI_NAME_MAX];
			char                           band[16];
			char                           domain[NCFG_TUI_NAME_MAX + 8];

			key_of(entry, &mine);
			if (!key_same(&key, &mine)) {
				continue;
			}
			domain[0] = '\0';
			if (ncfg_proto_str_present(entry->mobility_domain)) {
				char id[NCFG_TUI_NAME_MAX];

				/* The mobility domain where the access point claims one. It
				 * says the operator configured these to roam as one, which is
				 * worth knowing when they do not -- and it is unauthenticated,
				 * so it is shown as a claim beside the address rather than
				 * used to group. */
				(void)snprintf(domain, sizeof(domain), "  ft:%s",
				    ncfg_cli_text(entry->mobility_domain, id, sizeof(id)));
			}
			memset(&row, 0, sizeof(row));
			row.kind = NCFG_TUI_ROW_NETWORK;
			row.entry = one;
			(void)snprintf(line, sizeof(line), "    %-7s %-17s  %4lld dBm%s",
			    band_of(entry->frequency, band, sizeof(band)),
			    ncfg_cli_text(entry->bssid, bssid, sizeof(bssid)),
			    (long long)entry->signal, domain);
			if (line_open(out, &row)) {
				fit(&out->text, line, width);
				line_close(out);
			}
		}
	}
}

/* ------------------------------------------------------------------------ *
 * The clients pane
 * ------------------------------------------------------------------------ */

/*
 * Who is on the access point.
 *
 * The marker column is the point of showing this next to a station list at all:
 * `!` means the document's `access_control` block and what hostapd is enforcing
 * disagree, which happens because hostapd reads the list once at startup
 * (decision 0039).
 */
static void clients(const ncfg_tui_t *tui, size_t width, ncfg_tui_lines_t *out)
{
	const ncfg_proto_stations_t *report = stations_of(&tui->stations);
	size_t                       at;

	if (!report || report->station_count == 0) {
		line_fit(out, "(nobody associated; press r to refresh)", width);
		return;
	}
	for (at = 0; at < report->station_count; at++) {
		const ncfg_proto_station_t *station = &report->stations[at];
		const char                 *marker;
		char                        address[NCFG_TUI_NAME_MAX];
		char                        signal[16];
		char                        connected[32];
		char                        line[NCFG_TUI_WIDTH_MAX];

		if (!ncfg_proto_str_present(station->address)) {
			(void)snprintf(address, sizeof(address), "<no address>");
		} else {
			(void)ncfg_cli_text(station->address, address, sizeof(address));
		}
		if (station->signal.present) {
			(void)snprintf(signal, sizeof(signal), "%4lld ",
			    (long long)station->signal.value);
		} else {
			(void)snprintf(signal, sizeof(signal), "  -- ");
		}
		if (station->connected_seconds.present) {
			(void)snprintf(connected, sizeof(connected), "%lldm",
			    (long long)(station->connected_seconds.value / 60));
		} else {
			(void)snprintf(connected, sizeof(connected), "--");
		}
		if ((ncfg_proto_str_equals(report->access_control, "deny") && station->listed) ||
		    (ncfg_proto_str_equals(report->access_control, "allow") &&
		    !station->listed)) {
			marker = "!";
		} else if (!station->authorized) {
			marker = "?";
		} else {
			marker = " ";
		}
		(void)snprintf(line, sizeof(line), "%s %-19s %sdBm  %6s", marker, address,
		    signal, connected);
		line_fit(out, line, width);
	}
}

/* ------------------------------------------------------------------------ *
 * The plan pane
 * ------------------------------------------------------------------------ */

static void plan(const ncfg_tui_t *tui, size_t width, ncfg_tui_lines_t *out)
{
	const ncfg_json_doc_t *doc;
	uint32_t               object = payload_of(&tui->plan, &doc);
	uint32_t               actions;
	uint32_t               list;
	uint32_t               count;
	uint32_t               at;
	char                   line[NCFG_TUI_WIDTH_MAX];

	if (!doc) {
		line_fit(out, "(no plan yet)", width);
		return;
	}
	actions = array_of(doc, object, "actions");
	count = ncfg_json_count(doc, actions);
	if (count == 0) {
		line_fit(out, "nothing to do -- the machine matches the configuration", width);
	}
	for (at = 0; at < count; at++) {
		uint32_t action = ncfg_json_at(doc, actions, at);
		uint32_t reason = ncfg_json_member(doc, action, "reason");
		char     op[NCFG_TUI_NAME_MAX];
		char     interface[NCFG_TUI_NAME_MAX];
		char     field[NCFG_TUI_NAME_MAX * 2];
		char     desired[NCFG_TUI_NAME_MAX * 2];
		char     observed[NCFG_TUI_NAME_MAX * 2];

		(void)string_of(doc, ncfg_json_member(doc, action, "op"), "op", op, sizeof(op));
		if (op[0] == '\0') {
			(void)snprintf(op, sizeof(op), "?");
		}
		(void)snprintf(line, sizeof(line), "%-22s %-12s %s: %s -> %s", op,
		    string_of(doc, reason, "interface", interface, sizeof(interface)),
		    string_of(doc, reason, "field", field, sizeof(field)),
		    string_of(doc, reason, "observed", observed, sizeof(observed)),
		    string_of(doc, reason, "desired", desired, sizeof(desired)));
		line_fit(out, line, width);
	}

	list = array_of(doc, object, "warnings");
	count = ncfg_json_count(doc, list);
	for (at = 0; at < count; at++) {
		char message[NCFG_TUI_WIDTH_MAX];

		(void)snprintf(line, sizeof(line), "! %s",
		    string_of(doc, ncfg_json_at(doc, list, at), "message", message,
		    sizeof(message)));
		line_fit(out, line, width);
	}
	list = array_of(doc, object, "refusals");
	count = ncfg_json_count(doc, list);
	for (at = 0; at < count; at++) {
		uint32_t refusal = ncfg_json_at(doc, list, at);
		char     op[NCFG_TUI_NAME_MAX];
		char     interface[NCFG_TUI_NAME_MAX];
		char     guard[NCFG_TUI_NAME_MAX * 2];

		(void)snprintf(line, sizeof(line), "refused %s on %s: %s",
		    string_of(doc, refusal, "op", op, sizeof(op)),
		    string_of(doc, refusal, "interface", interface, sizeof(interface)),
		    string_of(doc, refusal, "guard", guard, sizeof(guard)));
		line_fit(out, line, width);
	}
}

/* ------------------------------------------------------------------------ *
 * The events pane
 * ------------------------------------------------------------------------ */

static void events(const ncfg_tui_t *tui, size_t width, ncfg_tui_lines_t *out)
{
	size_t at;

	if (tui->event_count == 0) {
		line_fit(out, "(waiting for events)", width);
		return;
	}
	for (at = 0; at < tui->event_count; at++) {
		line_fit(out, ncfg_tui_event(tui, at), width);
	}
}

/* ------------------------------------------------------------------------ *
 * The body, and how many rows it has
 * ------------------------------------------------------------------------ */

void ncfg_tui_body(const ncfg_tui_t *tui, size_t width, ncfg_tui_lines_t *out)
{
	if (!out) {
		return;
	}
	ncfg_tui_lines_init(out);
	if (!tui) {
		return;
	}
	switch (tui->pane) {
	case NCFG_TUI_PANE_DEVICES:
		devices(tui, width, out);
		return;
	case NCFG_TUI_PANE_WIFI:
		wifi(tui, width, out);
		return;
	case NCFG_TUI_PANE_CLIENTS:
		clients(tui, width, out);
		return;
	case NCFG_TUI_PANE_PLAN:
		plan(tui, width, out);
		return;
	case NCFG_TUI_PANE_EVENTS:
		events(tui, width, out);
		return;
	case NCFG_TUI_PANE_COUNT:
	default:
		return;
	}
}

size_t ncfg_tui_last_row(const ncfg_tui_t *tui)
{
	ncfg_tui_lines_t lines;
	size_t           count;

	ncfg_tui_body(tui, NCFG_TUI_ROW_COUNT_WIDTH, &lines);
	count = lines.count;
	ncfg_tui_lines_free(&lines);
	return count > 0 ? count - 1 : 0;
}

/* ------------------------------------------------------------------------ *
 * The keyboard
 * ------------------------------------------------------------------------ */

/*
 * Whether a byte ends a CSI sequence.
 *
 * ECMA-48's final byte range. Consuming to it rather than to a letter this
 * file happens to know is what keeps `ESC [ 2 0 0 ~` -- a bracketed paste some
 * terminals send unasked -- from being read as five keystrokes.
 */
static int csi_final(unsigned char byte)
{
	return byte >= 0x40u && byte <= 0x7eu;
}

ncfg_tui_input_t ncfg_tui_key_decode(const char *bytes, size_t length, int *key_out,
    size_t *used_out)
{
	size_t at;

	if (key_out) {
		*key_out = 0;
	}
	if (used_out) {
		*used_out = 0;
	}
	if (!bytes || length == 0) {
		return NCFG_TUI_INPUT_NONE;
	}
	if (bytes[0] != 0x1b) {
		if (key_out) {
			*key_out = (unsigned char)bytes[0];
		}
		if (used_out) {
			*used_out = 1;
		}
		return NCFG_TUI_INPUT_READY;
	}
	if (length == 1) {
		return NCFG_TUI_INPUT_PARTIAL;
	}
	/*
	 * `ESC [` and `ESC O` alike. A terminal in application cursor mode sends
	 * the second for the arrows and the first otherwise, and a client that
	 * knew only one has arrow keys that work until somebody runs it under
	 * something else -- which is the hand-maintained table's failure, met on
	 * the one sequence it cannot afford to get wrong.
	 */
	if (bytes[1] != '[' && bytes[1] != 'O') {
		/* `ESC` followed by anything else is Escape itself, and the byte after
		 * it is the next key rather than part of this one. */
		if (key_out) {
			*key_out = 0x1b;
		}
		if (used_out) {
			*used_out = 1;
		}
		return NCFG_TUI_INPUT_READY;
	}
	for (at = 2; at < length; at++) {
		if (!csi_final((unsigned char)bytes[at])) {
			continue;
		}
		if (key_out) {
			if (bytes[at] == 'A') {
				*key_out = NCFG_TUI_KEY_UP;
			} else if (bytes[at] == 'B') {
				*key_out = NCFG_TUI_KEY_DOWN;
			} else {
				*key_out = NCFG_TUI_KEY_OTHER;
			}
		}
		if (used_out) {
			*used_out = at + 1;
		}
		return NCFG_TUI_INPUT_READY;
	}
	return NCFG_TUI_INPUT_PARTIAL;
}

/* A pane change: the pane, the top of the list, and a refetch. */
static ncfg_tui_action_t go(ncfg_tui_t *tui, ncfg_tui_pane_t pane)
{
	tui->pane = pane;
	tui->selected = 0;
	return NCFG_TUI_ACT_REFRESH;
}

ncfg_tui_action_t ncfg_tui_key(ncfg_tui_t *tui, int key)
{
	int byte = (key >= 0 && key <= 0xff) ? key : 0;

	if (!tui) {
		return NCFG_TUI_ACT_NONE;
	}
	/*
	 * **`q` and `^C` are the same thing.** The terminal is in raw mode with
	 * `ISIG` off, so `^C` arrives as a key, and treating it as anything but
	 * "leave" would strand somebody whose reflex it is.
	 */
	if (byte == 'q' || byte == 0x03) {
		return NCFG_TUI_ACT_QUIT;
	}
	switch (byte) {
	case 'd':
		return go(tui, NCFG_TUI_PANE_DEVICES);
	case 'w':
		return go(tui, NCFG_TUI_PANE_WIFI);
	/* `s` for stations rather than `c`, which is already `use` on the wifi
	 * pane. A pane key that works everywhere except one pane is worse than a
	 * letter that does not match the tab name. */
	case 's':
		return go(tui, NCFG_TUI_PANE_CLIENTS);
	case 'p':
		return go(tui, NCFG_TUI_PANE_PLAN);
	case 'e':
		return go(tui, NCFG_TUI_PANE_EVENTS);
	case 'r':
		(void)snprintf(tui->message, sizeof(tui->message), "refreshed");
		return NCFG_TUI_ACT_REFRESH;
	case 'y':
		return NCFG_TUI_ACT_CONFIRM;
	case 'n':
		return NCFG_TUI_ACT_REVERT;
	case '?':
		(void)snprintf(tui->message, sizeof(tui->message), "%s", ncfg_tui_help());
		return NCFG_TUI_ACT_NONE;
	default:
		break;
	}
	if (key == NCFG_TUI_KEY_DOWN || byte == 'j') {
		/*
		 * Clamped to the last row there is. Adding one and stopping at the
		 * largest `size_t` is not a list length, so holding the key walked the
		 * highlight off the end of the list and into blank space -- where `c`
		 * on the wifi pane had nothing to join and the operator had no way to
		 * tell an empty row from a real one.
		 */
		size_t last = ncfg_tui_last_row(tui);

		tui->selected = tui->selected + 1 < last ? tui->selected + 1 : last;
		return NCFG_TUI_ACT_NONE;
	}
	if (key == NCFG_TUI_KEY_UP || byte == 'k') {
		if (tui->selected > 0) {
			tui->selected--;
		}
		return NCFG_TUI_ACT_NONE;
	}
	if (byte == 'a' && tui->pane == NCFG_TUI_PANE_PLAN) {
		return NCFG_TUI_ACT_APPLY;
	}
	if (byte == 'c' && tui->pane == NCFG_TUI_PANE_WIFI) {
		return NCFG_TUI_ACT_USE;
	}
	return NCFG_TUI_ACT_NONE;
}

/* ------------------------------------------------------------------------ *
 * What `c` acts on
 * ------------------------------------------------------------------------ */

int ncfg_tui_radio(const ncfg_tui_t *tui, char *out, size_t out_size)
{
	const ncfg_json_doc_t *doc;
	uint32_t               status;
	uint32_t               links;
	uint32_t               count;
	uint32_t               at;

	if (!out || out_size == 0) {
		return 0;
	}
	out[0] = '\0';
	if (!tui) {
		return 0;
	}
	status = payload_of(&tui->status, &doc);
	links = array_of(doc, status, "links");
	count = ncfg_json_count(doc, links);
	for (at = 0; at < count; at++) {
		uint32_t link = ncfg_json_at(doc, links, at);
		char     kind[NCFG_TUI_NAME_MAX];
		char     name[NCFG_TUI_NAME_MAX];

		(void)string_of(doc, link, "kind", kind, sizeof(kind));
		(void)string_of(doc, link, "name", name, sizeof(name));
		if (!ncfg_cli_is_radio(kind, name)) {
			continue;
		}
		/* The Rust takes the name of the first link that looks like a radio
		 * and stops, so a radio with no name is no radio rather than a reason
		 * to keep looking. Kept, because a link the kernel reported without a
		 * name is a fault worth seeing rather than routing around. */
		if (name[0] == '\0') {
			return 0;
		}
		(void)snprintf(out, out_size, "%s", name);
		return 1;
	}
	return 0;
}

int ncfg_tui_use(const ncfg_tui_t *tui, ncfg_tui_use_t *out, char *err, size_t err_size)
{
	ncfg_tui_lines_t      lines;
	const ncfg_tui_row_t *row;
	ncfg_tui_row_t        chosen;
	const ncfg_proto_scan_t *scan;

	if (!out) {
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!tui) {
		return 1;
	}
	ncfg_tui_body(tui, NCFG_TUI_ROW_COUNT_WIDTH, &lines);
	row = ncfg_tui_row(&lines, tui->selected);
	chosen = *row;
	ncfg_tui_lines_free(&lines);

	if (chosen.kind == NCFG_TUI_ROW_RADIO) {
		/*
		 * The same key as joining a network, because it is the same intent
		 * from the operator's side: use this one. What differs is which row
		 * the highlight is on, and the pane says so on the row itself.
		 */
		out->kind = NCFG_TUI_USE_RADIO;
		(void)snprintf(out->interface, sizeof(out->interface), "%s", chosen.interface);
		return 1;
	}
	if (chosen.kind != NCFG_TUI_ROW_NETWORK) {
		return 1;
	}
	scan = scan_of(&tui->scan);
	if (!scan || chosen.entry >= scan->access_point_count) {
		return 1;
	}
	if (!ncfg_proto_str_present(scan->access_points[chosen.entry].configured)) {
		/* Decision 0013's boundary, said before it is hit rather than
		 * discovered as a refusal. */
		ncfg_error_set(err, err_size, "that network is not in the configuration; "
		    "`ncfg` cannot join it until it is");
		return 0;
	}
	if (!ncfg_tui_radio(tui, out->interface, sizeof(out->interface))) {
		/* No radio and a scan on screen is not a state the daemon produces --
		 * the scan was taken on one -- so this is the Rust's silent return
		 * rather than a sentence invented for a case nobody can reach. */
		return 1;
	}
	out->kind = NCFG_TUI_USE_NETWORK;
	(void)ncfg_cli_text(scan->access_points[chosen.entry].configured, out->network,
	    sizeof(out->network));
	return 1;
}

/* ------------------------------------------------------------------------ *
 * The frame
 * ------------------------------------------------------------------------ */

/*
 * Reverse video, which is the only emphasis this client has.
 *
 * `wstandout`'s two sequences by hand. `$NO_COLOR` turns even this off, which
 * the caller has already read into `no_color`.
 */
static void standout(ncfg_buf_t *out, int on, int no_color)
{
	if (no_color) {
		return;
	}
	ncfg_buf_add_text(out, on ? "\033[7m" : "\033[27m");
}

/* Put the cursor at the start of row `row`, counted from 1. */
static void at_row(ncfg_buf_t *out, size_t row)
{
	ncfg_buf_addf(out, "\033[%zu;1H", row);
}

void ncfg_tui_frame(const ncfg_tui_t *tui, size_t rows, size_t columns, ncfg_buf_t *out)
{
	ncfg_tui_lines_t lines;
	size_t           width = columns < NCFG_TUI_WIDTH_MIN ? NCFG_TUI_WIDTH_MIN : columns;
	size_t           body_rows;
	size_t           first = 0;
	size_t           at;
	int              no_color;

	if (!out) {
		return;
	}
	if (width > NCFG_TUI_WIDTH_MAX) {
		width = NCFG_TUI_WIDTH_MAX;
	}
	/* Header, footer and a status line are fixed; the body takes the rest. A
	 * terminal too short for all of them still gets one body row rather than
	 * an arithmetic underflow. */
	body_rows = rows >= 4 ? rows - 3 : 1;
	no_color = tui ? tui->no_color : 1;

	ncfg_tui_body(tui, width, &lines);

	/*
	 * **Scrolled by the height of the window, not by the length of the list.**
	 * The Rust computes the first visible row from `lines.len().min(64)`,
	 * which is the content rather than the screen -- so on an 80x24 terminal a
	 * pane with 30 lines never scrolls at all, and the highlight walks past
	 * row 21 into rows the window does not draw. `Pane::draw` only marks the
	 * row it is given when that row is on screen, so the selection then has no
	 * marker anywhere while `c` goes on acting on it. 0263 records this.
	 */
	if (tui && tui->selected >= body_rows) {
		first = tui->selected - body_rows + 1;
	}

	at_row(out, 1);
	standout(out, 1, no_color);
	ncfg_tui_tabs(tui, width, out);
	standout(out, 0, no_color);

	for (at = 0; at < body_rows; at++) {
		size_t index = first + at;
		int    highlight = tui && tui->pane != NCFG_TUI_PANE_EVENTS &&
		    index == tui->selected && index < lines.count;

		at_row(out, at + 2);
		if (highlight) {
			standout(out, 1, no_color);
		}
		fit(out, index < lines.count ? ncfg_tui_line(&lines, index) : "", width);
		if (highlight) {
			standout(out, 0, no_color);
		}
	}

	at_row(out, body_rows + 2);
	fit(out, tui ? tui->message : "", width);
	at_row(out, body_rows + 3);
	standout(out, 1, no_color);
	fit(out, ncfg_tui_keys(), width);
	standout(out, 0, no_color);

	ncfg_tui_lines_free(&lines);
}

/* ------------------------------------------------------------------------ *
 * One event as a line
 * ------------------------------------------------------------------------ */

const char *ncfg_cli_event_text(const ncfg_proto_event_t *event, const char *raw,
    size_t raw_length, char *out, size_t out_size)
{
	char summary[NCFG_CLI_TEXT_MAX];
	char interface[NCFG_CLI_TEXT_MAX];
	char action[NCFG_CLI_TEXT_MAX];

	if (!out || out_size == 0) {
		return "";
	}
	if (!event) {
		(void)snprintf(out, out_size, "%.*s", (int)raw_length, raw ? raw : "");
		return out;
	}
	switch (event->kind) {
	case NCFG_PROTO_EVENT_OBSERVED:
		(void)snprintf(out, out_size, "observed  %s",
		    ncfg_cli_text(event->summary, summary, sizeof(summary)));
		return out;
	case NCFG_PROTO_EVENT_RELOADED:
		if (event->ok) {
			(void)snprintf(out, out_size, "reloaded  the configuration compiled");
		} else {
			(void)snprintf(out, out_size, "reloaded  FAILED\n%s",
			    ncfg_cli_text(event->diagnostics, summary, sizeof(summary)));
		}
		return out;
	case NCFG_PROTO_EVENT_DRIFT:
		(void)snprintf(out, out_size, "drift     %s: %s (%s)",
		    ncfg_cli_text(event->interface, interface, sizeof(interface)),
		    ncfg_cli_text(event->summary, summary, sizeof(summary)),
		    ncfg_cli_text(event->action, action, sizeof(action)));
		return out;
	case NCFG_PROTO_EVENT_CONFIRM_ARMED:
		(void)snprintf(out, out_size, "confirm   window open for %llds",
		    (long long)event->seconds);
		return out;
	case NCFG_PROTO_EVENT_CONFIRM_RESOLVED:
		if (event->confirmed) {
			(void)snprintf(out, out_size, "confirm   confirmed; the change stands");
		} else {
			(void)snprintf(out, out_size,
			    "confirm   reverted to the last-good configuration");
		}
		return out;
	case NCFG_PROTO_EVENT_COUNT:
	default:
		(void)snprintf(out, out_size, "%.*s", (int)raw_length, raw ? raw : "");
		return out;
	}
}
