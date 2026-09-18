/*
 * json_write_test.c -- the JSON writer, against the reader it writes for.
 *
 * WHY THIS EXISTS
 *   A writer is only correct with respect to a reader, so the checks that
 *   matter here are not "it emitted the bytes I expected" but "the reader
 *   this project already ships gets back what went in". Both are here, and
 *   the second is the one that would catch an escape that is valid JSON and
 *   means something else.
 *
 *   The round-trip lines are copied out of doc/schema/socket.json, which is
 *   the witness file of real daemon traffic. A writer that cannot reproduce
 *   those lines byte for byte cannot replace the snprintf that builds them.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/json_write.h"

#include "ncfg_json.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-58s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* Parse what the writer just produced. NULL where the reader refused it. */
static ncfg_json_doc_t *parse_back(const ncfg_buf_t *buf)
{
	const char *text = ncfg_buf_text(buf);

	return ncfg_json_parse(text, strlen(text), NULL, 0);
}

/* The bytes of a string member, compared against a counted literal. */
static int member_bytes_equal(const ncfg_json_doc_t *doc, uint32_t object, const char *name,
    const char *want, size_t want_length)
{
	size_t length = 0;
	const char *text = ncfg_json_string(doc, ncfg_json_member(doc, object, name), &length);

	return text && length == want_length && memcmp(text, want, want_length) == 0;
}

/*
 * Copy one string member straight from the reader into the writer.
 *
 * Counted rather than through `ncfg_json_write_member_string`, because the
 * reader's strings are not terminated: they sit end to end in one buffer, so
 * `strlen` on `"hello"` would run on into the next member's bytes. This is
 * the case the counted call exists for.
 */
static void copy_string_member(ncfg_json_writer_t *writer, const char *name,
    const ncfg_json_doc_t *doc, uint32_t object)
{
	size_t length = 0;
	const char *text = ncfg_json_string(doc, ncfg_json_member(doc, object, name), &length);

	ncfg_json_write_key(writer, name);
	ncfg_json_write_string_bytes(writer, text, length);
}

/*
 * Re-emit a `hello` response out of whatever the reader made of one.
 *
 * The member names are written out here because the reader hands values out
 * by name and never hands the names back -- that is its shape, since a
 * response's keys are a schema rather than data.
 */
static void reemit_hello(ncfg_json_writer_t *writer, const ncfg_json_doc_t *doc)
{
	uint32_t root = ncfg_json_root(doc);
	uint32_t tiers = ncfg_json_member(doc, root, "tiers");
	const char *pair[2];
	uint32_t i;
	size_t at;

	pair[0] = "protocol";
	pair[1] = "schema";

	ncfg_json_write_object_begin(writer);
	copy_string_member(writer, "response", doc, root);
	for (at = 0; at < 2u; at++) {
		uint32_t version = ncfg_json_member(doc, root, pair[at]);

		ncfg_json_write_key(writer, pair[at]);
		ncfg_json_write_object_begin(writer);
		ncfg_json_write_member_int(writer, "major",
		    ncfg_json_int(doc, ncfg_json_member(doc, version, "major"), -1));
		ncfg_json_write_member_int(writer, "minor",
		    ncfg_json_int(doc, ncfg_json_member(doc, version, "minor"), -1));
		ncfg_json_write_object_end(writer);
	}
	ncfg_json_write_key(writer, "tiers");
	ncfg_json_write_array_begin(writer);
	for (i = 0; i < ncfg_json_count(doc, tiers); i++) {
		size_t length = 0;
		const char *text = ncfg_json_string(doc, ncfg_json_at(doc, tiers, i), &length);

		ncfg_json_write_string_bytes(writer, text, length);
	}
	ncfg_json_write_array_end(writer);
	ncfg_json_write_object_end(writer);
}

int main(void)
{
	/* **Escaping.** The quote and the backslash are what a passphrase or an
	 * SSID name brings; the newline is what a `config_put` body brings, and
	 * emitting it raw would split one message into two. */
	{
		ncfg_buf_t buf;
		ncfg_json_writer_t writer;
		ncfg_json_doc_t *doc;
		static const char awkward[] = "a\"b\\c\nd\te\x01" "f\x7f";

		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_member_string(&writer, "text", awkward);
		ncfg_json_write_object_end(&writer);
		check(strcmp(ncfg_buf_text(&buf),
		        "{\"text\":\"a\\\"b\\\\c\\nd\\te\\u0001f\x7f\"}") == 0,
		    "a quote, a backslash and the short forms are escaped");
		check(ncfg_json_write_done(&writer), "and the document is complete");

		doc = parse_back(&buf);
		check(doc != NULL, "the reader takes the escaped form back");
		check(doc && member_bytes_equal(doc, ncfg_json_root(doc), "text", awkward,
		        sizeof(awkward) - 1u),
		    "and gets back exactly the bytes that went in");
		ncfg_json_free(doc);
		ncfg_buf_free(&buf);
	}

	/* A NUL is data in a JSON string and the reader keeps it, so the writer
	 * has to be able to produce one -- which needs the counted call, since
	 * strlen would stop at it. */
	{
		ncfg_buf_t buf;
		ncfg_json_writer_t writer;
		ncfg_json_doc_t *doc;

		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		ncfg_json_write_string_bytes(&writer, "ab\0cd", 5u);
		check(strcmp(ncfg_buf_text(&buf), "\"ab\\u0000cd\"") == 0,
		    "a NUL inside a string is an escape, not an end");
		doc = parse_back(&buf);
		check(doc && ncfg_json_type(doc, ncfg_json_root(doc)) == NCFG_JSON_STRING,
		    "and reads back as one string");
		{
			size_t length = 0;
			const char *text = ncfg_json_string(doc, ncfg_json_root(doc), &length);

			check(text && length == 5u && memcmp(text, "ab\0cd", 5u) == 0,
			    "of the same five bytes");
		}
		ncfg_json_free(doc);
		ncfg_buf_free(&buf);
	}

	/* **UTF-8 that is valid goes through as itself**, rather than as \u
	 * escapes: the reader would unescape them to the same bytes, but a
	 * diagnostic full of \u00e5 escapes is one nobody can read against the
	 * config file it came from. */
	{
		ncfg_buf_t buf;
		ncfg_json_writer_t writer;
		ncfg_json_doc_t *doc;
		static const char text[] = "k\xc3\xa5" "ffe \xe2\x82\xac \xf0\x9f\x93\xb6";

		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		ncfg_json_write_string(&writer, text);
		check(strcmp(ncfg_buf_text(&buf), "\"k\xc3\xa5" "ffe \xe2\x82\xac \xf0\x9f\x93\xb6\"") == 0,
		    "two, three and four byte UTF-8 pass through raw");
		doc = parse_back(&buf);
		check(doc != NULL, "and the reader parses the result");
		check(doc && ncfg_json_string_equals(doc, ncfg_json_root(doc), text),
		    "reading back the same bytes");
		ncfg_json_free(doc);
		ncfg_buf_free(&buf);
	}

	/* **And UTF-8 that is not valid is refused**, in each of the four ways a
	 * byte string can fail to be it. See json_write.h for why refusing beats
	 * every repair that was available. */
	{
		static const struct {
			const char *bytes;
			size_t      length;
			const char *what;
		} bad[] = {
			{ "\xff", 1u, "a byte no UTF-8 sequence starts with is refused" },
			{ "\xe2\x82", 2u, "a sequence that stops early is refused" },
			{ "\xc0\xaf", 2u, "an overlong encoding is refused" },
			{ "\xed\xa0\x80", 3u, "a surrogate half spelled in UTF-8 is refused" },
		};
		size_t at;

		for (at = 0; at < sizeof(bad) / sizeof(bad[0]); at++) {
			ncfg_buf_t buf;
			ncfg_json_writer_t writer;

			ncfg_buf_init(&buf, 0);
			ncfg_json_write_init(&writer, &buf);
			ncfg_json_write_string_bytes(&writer, bad[at].bytes, bad[at].length);
			check(ncfg_json_write_failed(&writer) &&
			        ncfg_json_write_failure(&writer) != NULL, bad[at].what);
			check(ncfg_buf_text(&buf)[0] == '\0',
			    "and the buffer hands out nothing, not a part");
			ncfg_buf_free(&buf);
		}
	}

	/* **Nesting and separators, which are the writer's job.** Every comma in
	 * this line was decided by the writer; a caller has no call that emits
	 * one. */
	{
		ncfg_buf_t buf;
		ncfg_json_writer_t writer;

		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_member_string(&writer, "request", "apply");
		ncfg_json_write_member_int(&writer, "confirm", 90);
		ncfg_json_write_key(&writer, "allow_disruption");
		ncfg_json_write_array_begin(&writer);
		ncfg_json_write_string(&writer, "eth0");
		ncfg_json_write_string(&writer, "wg0");
		ncfg_json_write_array_end(&writer);
		ncfg_json_write_key(&writer, "restart_wedged");
		ncfg_json_write_array_begin(&writer);
		ncfg_json_write_array_end(&writer);
		ncfg_json_write_key(&writer, "nested");
		ncfg_json_write_array_begin(&writer);
		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_member_bool(&writer, "on", 1);
		ncfg_json_write_key(&writer, "off");
		ncfg_json_write_bool(&writer, 0);
		ncfg_json_write_key(&writer, "neither");
		ncfg_json_write_null(&writer);
		ncfg_json_write_object_end(&writer);
		ncfg_json_write_uint(&writer, UINT64_MAX);
		ncfg_json_write_int(&writer, INT64_MIN);
		ncfg_json_write_array_end(&writer);
		ncfg_json_write_object_end(&writer);
		check(strcmp(ncfg_buf_text(&buf),
		        "{\"request\":\"apply\",\"confirm\":90,"
		        "\"allow_disruption\":[\"eth0\",\"wg0\"],\"restart_wedged\":[],"
		        "\"nested\":[{\"on\":true,\"off\":false,\"neither\":null},"
		        "18446744073709551615,-9223372036854775808]}") == 0,
		    "containers, commas and the number extremes come out right");
		check(ncfg_json_write_done(&writer), "and that document is complete");
		{
			ncfg_json_doc_t *doc = parse_back(&buf);

			check(doc != NULL, "and the reader accepts it");
			ncfg_json_free(doc);
		}
		ncfg_buf_free(&buf);
	}

	/* **Misuse is a value, not a crash.** Each of these is a caller bug that
	 * a `snprintf` builder would have turned into a line the daemon refuses
	 * with a byte offset and no name. */
	{
		ncfg_buf_t buf;
		ncfg_json_writer_t writer;

		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		ncfg_json_write_key(&writer, "request");
		check(ncfg_json_write_failed(&writer), "a member name outside an object fails");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		ncfg_json_write_array_begin(&writer);
		ncfg_json_write_key(&writer, "request");
		check(ncfg_json_write_failed(&writer), "and so does one inside an array");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_string(&writer, "apply");
		check(ncfg_json_write_failed(&writer), "a value where a member name belongs fails");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_key(&writer, "request");
		ncfg_json_write_key(&writer, "again");
		check(ncfg_json_write_failed(&writer), "a second name before the value fails");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_key(&writer, "request");
		ncfg_json_write_object_end(&writer);
		check(ncfg_json_write_failed(&writer), "closing an object that owes a value fails");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_array_end(&writer);
		check(ncfg_json_write_failed(&writer), "closing an object as an array fails");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		ncfg_json_write_object_end(&writer);
		check(ncfg_json_write_failed(&writer), "and closing what was never opened fails");
		ncfg_buf_free(&buf);

		/* The framing is one value per line, and the reader refuses
		 * anything after the first. */
		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		ncfg_json_write_string(&writer, "one");
		ncfg_json_write_string(&writer, "two");
		check(ncfg_json_write_failed(&writer), "a second value in one document fails");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		ncfg_json_write_string(&writer, NULL);
		check(ncfg_json_write_failed(&writer), "and a string that is a null pointer fails");
		ncfg_buf_free(&buf);
	}

	/* An object left open is not a failure -- nothing is wrong yet -- but it
	 * is not a document either, which is what `done` is for. */
	{
		ncfg_buf_t buf;
		ncfg_json_writer_t writer;

		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_member_int(&writer, "confirm", 90);
		check(!ncfg_json_write_failed(&writer), "an unclosed object has not failed");
		check(!ncfg_json_write_done(&writer), "but it is not a finished document");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		check(!ncfg_json_write_done(&writer), "and an empty one is not a document at all");
		ncfg_buf_free(&buf);
	}

	/* Sticky, so that forty calls need one check -- and the buffer is failed
	 * with the writer, so a caller that checks neither gets "" rather than
	 * the half of a request that would otherwise be sent. */
	{
		ncfg_buf_t buf;
		ncfg_json_writer_t writer;
		const char *first;

		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_string(&writer, "apply");
		first = ncfg_json_write_failure(&writer);
		check(first != NULL, "the first misuse is named");
		ncfg_json_write_member_string(&writer, "request", "apply");
		ncfg_json_write_object_end(&writer);
		check(ncfg_json_write_failure(&writer) == first,
		    "and every call after it changes nothing");
		check(ncfg_buf_failed(&buf), "the buffer failed with the writer");
		check(ncfg_buf_text(&buf)[0] == '\0', "and hands out nothing");
		check(!ncfg_json_write_done(&writer), "a failed document is never done");
		ncfg_buf_free(&buf);
	}

	/* The buffer's ceiling is this document's failure too, whichever of the
	 * two is asked. */
	{
		ncfg_buf_t buf;
		ncfg_json_writer_t writer;

		ncfg_buf_init(&buf, 16u);
		ncfg_json_write_init(&writer, &buf);
		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_member_string(&writer, "text",
		    "a configuration file rather longer than sixteen bytes");
		check(ncfg_json_write_failed(&writer), "a document past the buffer's limit fails");
		ncfg_json_write_object_end(&writer);
		check(ncfg_json_write_failure(&writer) != NULL, "and says the buffer is why");
		ncfg_buf_free(&buf);
	}

	/* **The depth cap is the reader's**, taken from its header rather than
	 * copied, so what this can write is what that can read -- including at
	 * the boundary, which is the part a copied number gets wrong. */
	{
		ncfg_buf_t buf;
		ncfg_json_writer_t writer;
		ncfg_json_doc_t *doc;
		int i;

		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		for (i = 0; i < NCFG_JSON_MAX_DEPTH; i++) {
			ncfg_json_write_array_begin(&writer);
		}
		for (i = 0; i < NCFG_JSON_MAX_DEPTH; i++) {
			ncfg_json_write_array_end(&writer);
		}
		check(ncfg_json_write_done(&writer), "nesting to the cap is written");
		doc = parse_back(&buf);
		check(doc != NULL, "and the reader reads back what the cap allows");
		ncfg_json_free(doc);
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		for (i = 0; i <= NCFG_JSON_MAX_DEPTH; i++) {
			ncfg_json_write_array_begin(&writer);
		}
		check(ncfg_json_write_failed(&writer), "and one deeper is refused here, not there");
		ncfg_buf_free(&buf);
	}

	/*
	 * **Real traffic, byte for byte.** These four lines are copied out of
	 * doc/schema/socket.json. Reproducing them exactly is what says this can
	 * replace the format strings that build them today -- an equivalent
	 * document with the members in another order would parse the same and
	 * still break every test that diffs against the witness.
	 */
	{
		ncfg_buf_t buf;
		ncfg_json_writer_t writer;

		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_member_string(&writer, "request", "probe_put");
		ncfg_json_write_member_string(&writer, "name", "office");
		ncfg_json_write_member_string(&writer, "text", "#!/bin/sh\nexit 0\n");
		ncfg_json_write_member_bool(&writer, "replace", 1);
		ncfg_json_write_object_end(&writer);
		check(strcmp(ncfg_buf_text(&buf),
		        "{\"request\":\"probe_put\",\"name\":\"office\","
		        "\"text\":\"#!/bin/sh\\nexit 0\\n\",\"replace\":true}") == 0,
		    "a probe_put request comes out as the witness has it");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_member_string(&writer, "response", "wifi_scan");
		ncfg_json_write_member_string(&writer, "interface", "wlan0");
		ncfg_json_write_key(&writer, "access_points");
		ncfg_json_write_array_begin(&writer);
		ncfg_json_write_array_end(&writer);
		ncfg_json_write_member_string(&writer, "stale",
		    "the supplicant could not scan (ret=-16)");
		ncfg_json_write_object_end(&writer);
		check(strcmp(ncfg_buf_text(&buf),
		        "{\"response\":\"wifi_scan\",\"interface\":\"wlan0\","
		        "\"access_points\":[],"
		        "\"stale\":\"the supplicant could not scan (ret=-16)\"}") == 0,
		    "and so does an empty scan with its reason");
		ncfg_buf_free(&buf);
	}

	/*
	 * **The round trip that matters**: the reader's output fed back through
	 * the writer. A `hello` is the line every client sends first, and it has
	 * an object inside an object and an array of strings, which is every
	 * shape the protocol uses.
	 */
	{
		static const char witness[] =
		    "{\"response\":\"hello\",\"protocol\":{\"major\":1,\"minor\":3},"
		    "\"schema\":{\"major\":1,\"minor\":1},\"tiers\":[\"observe\",\"admin\"]}";
		ncfg_buf_t buf;
		ncfg_json_writer_t writer;
		ncfg_json_doc_t *first;
		ncfg_json_doc_t *again;

		first = ncfg_json_parse(witness, sizeof(witness) - 1u, NULL, 0);
		check(first != NULL, "the witness hello parses");

		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		reemit_hello(&writer, first);
		check(ncfg_json_write_done(&writer), "and re-emitting what it holds completes");
		check(strcmp(ncfg_buf_text(&buf), witness) == 0,
		    "as the same line it arrived as");

		again = parse_back(&buf);
		check(again != NULL, "the re-emitted line parses");
		check(again && ncfg_json_string_equals(again,
		        ncfg_json_member(again, ncfg_json_root(again), "response"), "hello"),
		    "with the same response name");
		check(again && ncfg_json_int(again, ncfg_json_member(again,
		        ncfg_json_member(again, ncfg_json_root(again), "protocol"), "minor"), -1) ==
		        ncfg_json_int(first, ncfg_json_member(first,
		        ncfg_json_member(first, ncfg_json_root(first), "protocol"), "minor"), -2),
		    "the same protocol minor");
		check(again && ncfg_json_count(again,
		        ncfg_json_member(again, ncfg_json_root(again), "tiers")) == 2u,
		    "and both tiers, in order");
		check(again && ncfg_json_string_equals(again, ncfg_json_at(again,
		        ncfg_json_member(again, ncfg_json_root(again), "tiers"), 1u), "admin"),
		    "the second of them still being admin");
		ncfg_json_free(first);
		ncfg_json_free(again);
		ncfg_buf_free(&buf);
	}

	/*
	 * The same trip for the numbers, which is where a writer that went
	 * through a double would lose one: an `ap_stations` row carries a
	 * negative signal and byte counts.
	 */
	{
		static const char witness[] =
		    "{\"response\":\"ap_stations\",\"interface\":\"wlan0\","
		    "\"access_point\":\"home\",\"access_control\":\"deny\","
		    "\"stations\":[{\"address\":\"00:11:22:33:44:55\",\"authorized\":true,"
		    "\"listed\":true,\"signal\":-52,\"connected_seconds\":184,"
		    "\"inactive_msec\":120,\"rx_bytes\":4096,\"tx_bytes\":8192}]}";
		ncfg_buf_t buf;
		ncfg_json_writer_t writer;
		ncfg_json_doc_t *first;
		ncfg_json_doc_t *again;
		uint32_t stations;
		uint32_t station;
		uint32_t i;
		static const char *counts[] = { "connected_seconds", "inactive_msec",
		    "rx_bytes", "tx_bytes" };

		first = ncfg_json_parse(witness, sizeof(witness) - 1u, NULL, 0);
		check(first != NULL, "the witness ap_stations parses");
		stations = ncfg_json_member(first, ncfg_json_root(first), "stations");
		station = ncfg_json_at(first, stations, 0u);

		ncfg_buf_init(&buf, 0);
		ncfg_json_write_init(&writer, &buf);
		ncfg_json_write_object_begin(&writer);
		copy_string_member(&writer, "response", first, ncfg_json_root(first));
		copy_string_member(&writer, "interface", first, ncfg_json_root(first));
		copy_string_member(&writer, "access_point", first, ncfg_json_root(first));
		copy_string_member(&writer, "access_control", first, ncfg_json_root(first));
		ncfg_json_write_key(&writer, "stations");
		ncfg_json_write_array_begin(&writer);
		ncfg_json_write_object_begin(&writer);
		copy_string_member(&writer, "address", first, station);
		ncfg_json_write_member_bool(&writer, "authorized",
		    ncfg_json_bool(first, ncfg_json_member(first, station, "authorized"), 0));
		ncfg_json_write_member_bool(&writer, "listed",
		    ncfg_json_bool(first, ncfg_json_member(first, station, "listed"), 0));
		ncfg_json_write_member_int(&writer, "signal",
		    ncfg_json_int(first, ncfg_json_member(first, station, "signal"), 0));
		for (i = 0; i < 4u; i++) {
			/* Unsigned on the way out: a byte count has no negative
			 * half, and the reader gives both back as the same text. */
			ncfg_json_write_key(&writer, counts[i]);
			ncfg_json_write_uint(&writer, (uint64_t)ncfg_json_int(first,
			    ncfg_json_member(first, station, counts[i]), 0));
		}
		ncfg_json_write_object_end(&writer);
		ncfg_json_write_array_end(&writer);
		ncfg_json_write_object_end(&writer);
		check(strcmp(ncfg_buf_text(&buf), witness) == 0,
		    "an ap_stations row re-emits as the line it came from");

		again = parse_back(&buf);
		check(again != NULL, "which parses again");
		{
			uint32_t twin = ncfg_json_at(again,
			    ncfg_json_member(again, ncfg_json_root(again), "stations"), 0u);

			check(again && ncfg_json_int(again, ncfg_json_member(again, twin,
			        "signal"), 0) == -52,
			    "with the negative signal still negative");
			check(again && ncfg_json_int(again, ncfg_json_member(again, twin,
			        "tx_bytes"), 0) == 8192,
			    "and the byte count unchanged");
			check(again && ncfg_json_bool(again, ncfg_json_member(again, twin,
			        "authorized"), 0) == 1,
			    "and the booleans still true");
		}
		ncfg_json_free(first);
		ncfg_json_free(again);
		ncfg_buf_free(&buf);
	}

	if (failures == 0) {
		printf("json_write_test: all checks passed\n");
	} else {
		printf("json_write_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
