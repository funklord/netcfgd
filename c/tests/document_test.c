/*
 * document_test.c -- the desired-state document, against the frozen witness.
 *
 * WHAT THE WITNESS ROUND TRIP PROVES, AND HOW
 *   `doc/schema/document.json` is one complete document with every field
 *   populated -- every interface kind, every addressing source, every
 *   security choice, every optional member present at least once. Reading it
 *   and writing it back is the whole of this module exercised at once.
 *
 *   The comparison is **byte for byte against the witness with its whitespace
 *   removed**, and that is the strongest form available here: the Rust writes
 *   it with `serde_json::to_string_pretty` and this port's writer is compact,
 *   so the two differ by indentation and by nothing else if the port is
 *   right. Same members, same order, same values, same escaping -- and a
 *   member silently dropped, one written that should have been omitted, or an
 *   integer that lost a digit all show up as a byte that does not match, with
 *   the offset printed.
 *
 *   Stripping whitespace is not parsing: the stripper below knows only that a
 *   `"` starts a string and a `\` inside one escapes the next byte. It is
 *   twenty lines with no structure in it, so a defect in the model cannot
 *   hide behind a matching defect in the check.
 *
 *   The witness is pure ASCII and carries no escape sequence at all, which is
 *   asserted rather than assumed -- otherwise "same escaping" would be a
 *   claim this test does not actually make.
 *
 * WHAT ELSE IS HERE
 *   The cases the Rust carries beside the model, each naming a defect that
 *   shipped: an unknown member refused *and named*, a duplicate name, a hook
 *   path that is not absolute, a DNS scope a mode cannot express, and the
 *   Bluetooth sort that was missed for as long as the field existed.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/document.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-62s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* ------------------------------------------------------------------------ *
 * The witness
 * ------------------------------------------------------------------------ */

static char *slurp(const char *path, size_t *length_out)
{
	FILE  *file = fopen(path, "rb");
	char  *text;
	long   size;
	size_t got;

	if (!file) {
		return NULL;
	}
	if (fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) < 0 ||
	    fseek(file, 0, SEEK_SET) != 0) {
		fclose(file);
		return NULL;
	}
	text = malloc((size_t)size + 1u);
	if (!text) {
		fclose(file);
		return NULL;
	}
	got = fread(text, 1u, (size_t)size, file);
	fclose(file);
	text[got] = '\0';
	*length_out = got;
	return text;
}

/*
 * The same bytes with the whitespace between tokens removed.
 *
 * Deliberately not a parser: it tracks whether it is inside a string and
 * whether the last byte was a backslash, and nothing else. A checker that
 * understood the document could agree with a wrong model about what the
 * document means; this one cannot, because it does not know.
 */
static char *minify(const char *text, size_t length, size_t *length_out)
{
	char  *out = malloc(length + 1u);
	size_t at = 0;
	size_t i;
	int    in_string = 0;
	int    escaped = 0;

	if (!out) {
		return NULL;
	}
	for (i = 0; i < length; i++) {
		char c = text[i];

		if (in_string) {
			out[at++] = c;
			if (escaped) {
				escaped = 0;
			} else if (c == '\\') {
				escaped = 1;
			} else if (c == '"') {
				in_string = 0;
			}
			continue;
		}
		if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
			continue;
		}
		out[at++] = c;
		if (c == '"') {
			in_string = 1;
		}
	}
	out[at] = '\0';
	*length_out = at;
	return out;
}

/* Where two texts part, printed, because "they differ" is not a diagnostic. */
static void report_difference(const char *want, size_t want_length, const char *got,
    size_t got_length)
{
	size_t at = 0;
	size_t from;

	while (at < want_length && at < got_length && want[at] == got[at]) {
		at++;
	}
	from = at > 60u ? at - 60u : 0u;
	printf("  they part at byte %zu (witness %zu bytes, written %zu)\n", at, want_length,
	    got_length);
	printf("  witness: ...%.*s\n", (int)(want_length - from > 120u ? 120u : want_length - from),
	    want + from);
	printf("  written: ...%.*s\n", (int)(got_length - from > 120u ? 120u : got_length - from),
	    got + from);
}

static const char *witness_path(int argc, char **argv)
{
	static const char *const candidates[] = { "../doc/schema/document.json",
		"doc/schema/document.json", "../../doc/schema/document.json" };
	size_t i;

	if (argc > 1) {
		return argv[1];
	}
	for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
		FILE *file = fopen(candidates[i], "rb");

		if (file) {
			fclose(file);
			return candidates[i];
		}
	}
	return candidates[0];
}

/* ------------------------------------------------------------------------ *
 * Small documents, for the cases that are about one rule each
 * ------------------------------------------------------------------------ */

/* `generated_by` is here rather than left out because it is a string, and the
 * refusal that names an unknown member needs one somewhere in the object to
 * locate the reader's string buffer -- see `field.c`. A real document always
 * has several; a four-line test document may have none, and then the refusal
 * gives a position rather than a name. */
#define DOCUMENT_HEAD \
	"{\"schema_version\":{\"major\":1,\"minor\":1},\"generated_by\":\"test\",\"globals\":{},"

static ncfg_document_t *read_text(const char *text, char *err, size_t err_size)
{
	return ncfg_document_read(text, strlen(text), err, err_size);
}

/* Refused, *and* with something said. A failure carrying no sentence is what
 * base.h's convention exists to prevent, and it is invisible to a test that
 * only checks the return value. */
static int refused_saying(const char *text, const char *expected)
{
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document;

	message[0] = '\0';
	document = read_text(text, message, sizeof(message));
	if (document) {
		ncfg_document_free(document);
		printf("  accepted a document that should have been refused\n");
		return 0;
	}
	if (!strstr(message, expected)) {
		printf("  refused, but said `%s`\n", message);
		return 0;
	}
	return 1;
}

static char *write_document(ncfg_document_t *document, size_t *length_out)
{
	ncfg_buf_t buf;
	char       message[NCFG_ERROR_MAX];
	char      *text;

	ncfg_buf_init(&buf, 0);
	if (!ncfg_document_write(document, &buf, message, sizeof(message))) {
		printf("  could not write: %s\n", message);
		ncfg_buf_free(&buf);
		return NULL;
	}
	text = ncfg_buf_take(&buf, length_out);
	ncfg_buf_free(&buf);
	return text;
}

int main(int argc, char **argv)
{
	/* ---- the witness ---- */
	{
		const char      *path = witness_path(argc, argv);
		size_t           raw_length = 0;
		char            *raw = slurp(path, &raw_length);
		char             message[NCFG_ERROR_MAX];
		ncfg_document_t *document = NULL;

		check(raw != NULL, "the frozen witness is there to be read");
		if (raw) {
			size_t i;
			int    plain = 1;

			for (i = 0; i < raw_length; i++) {
				if (raw[i] == '\\' || (unsigned char)raw[i] >= 0x80u) {
					plain = 0;
				}
			}
			check(plain, "and carries no escape and no byte outside ASCII");

			message[0] = '\0';
			document = ncfg_document_read(raw, raw_length, message, sizeof(message));
			if (!document) {
				printf("  refused the witness: %s\n", message);
			}
			check(document != NULL, "the witness is read, and validates");
		}
		if (document && raw) {
			size_t written_length = 0;
			char  *written = write_document(document, &written_length);
			size_t wanted_length = 0;
			char  *wanted = minify(raw, raw_length, &wanted_length);
			int    same = written && wanted && written_length == wanted_length &&
			    memcmp(written, wanted, written_length) == 0;

			if (!same && written && wanted) {
				report_difference(wanted, wanted_length, written, written_length);
			}
			check(same, "and is written back byte for byte, member for member");

			/* Canonical already: the witness is what the Rust's own
			 * `to_json_canonical` produced, so sorting it must move nothing. */
			if (written) {
				size_t again_length = 0;
				char  *again;

				ncfg_document_canonicalize(document);
				again = write_document(document, &again_length);
				check(again && again_length == written_length &&
				    memcmp(again, written, again_length) == 0,
				    "canonicalising the witness moves nothing");
				free(again);
			}

			/* And what was written reads back as the same document. */
			if (written) {
				ncfg_document_t *second;

				message[0] = '\0';
				second = ncfg_document_read(written, written_length, message,
				    sizeof(message));
				if (!second) {
					printf("  could not read back: %s\n", message);
				}
				if (second) {
					size_t third_length = 0;
					char  *third = write_document(second, &third_length);

					check(third && third_length == written_length &&
					    memcmp(third, written, third_length) == 0,
					    "reading what was written writes the same bytes again");
					free(third);
					ncfg_document_free(second);
				} else {
					check(0, "reading what was written writes the same bytes again");
				}
			}
			free(written);
			free(wanted);
		}
		ncfg_document_free(document);
		free(raw);
	}

	/* ---- deny_unknown_fields, and the member named ---- */
	{
		check(refused_saying(DOCUMENT_HEAD
		    "\"devices\":[],\"interfaces\":[{\"name\":\"eth0\",\"bogus\":1}],\"networks\":[]}",
		    "bogus"),
		    "a member this build does not know is refused, and named");
		check(refused_saying(DOCUMENT_HEAD
		    "\"devices\":[],\"interfaces\":[],\"networks\":[],\"observed\":{}}", "observed"),
		    "and so is one at the top of the document");
		check(refused_saying(DOCUMENT_HEAD
		    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"bond\",\"members\":[],"
		    "\"miimon\":100,\"stp\":true}}],\"interfaces\":[],\"networks\":[]}", "stp"),
		    "a member of the wrong variant of a kind is refused too");
		/* The reader's refusal rather than this module's, and it has to reach
		 * the caller intact: a document that stops in the middle is a framing
		 * failure and the sentence is what says which of two programs is
		 * wrong. */
		check(refused_saying(DOCUMENT_HEAD "\"devices\":[],\"interfaces\":[],\"networks\":[]",
		    ""),
		    "a document that stops in the middle is refused, with something said");
		check(refused_saying("{\"schema_version\":{\"major\":1,\"minor\":1},"
		    "\"generated_by\":\"test\",\"devices\":[],\"interfaces\":[],\"networks\":[]}",
		    "globals"),
		    "a required member that is absent is refused, and named");
	}

	/* ---- the two spellings that are the document's and not the language's ---- */
	{
		const char *wireguard = ncfg_interface_kind_name(NCFG_KIND_WIREGUARD);
		const char *openvpn = ncfg_interface_kind_name(NCFG_KIND_OPENVPN);

		/* Asserted as literals, as `value_test.c` asserts every word it owns:
		 * the enum is C's and the word is the document's, and nothing but a
		 * test holds the two together. These two are the pair this project has
		 * already shipped wrong, in the other direction. */
		check(wireguard && strcmp(wireguard, "wire_guard") == 0 && openvpn &&
		    strcmp(openvpn, "open_vpn") == 0,
		    "a wireguard kind is spelled `wire_guard` in the document");
		check(ncfg_interface_kind_name(NCFG_KIND_IFB) != NULL &&
		    strcmp(ncfg_interface_kind_name(NCFG_KIND_IFB), "ifb") == 0 &&
		    ncfg_interface_kind_name(-1) == NULL,
		    "and a kind outside the set has no word at all");
		check(refused_saying(DOCUMENT_HEAD "\"devices\":[{\"name\":\"wg0\",\"kind\":"
		    "{\"kind\":\"wireguard\"}}],\"interfaces\":[],\"networks\":[]}", "wireguard"),
		    "so the language's spelling is refused where the document's belongs");
	}

	/* ---- validation ---- */
	{
		check(refused_saying(DOCUMENT_HEAD "\"devices\":[],\"interfaces\":"
		    "[{\"name\":\"eth0\"},{\"name\":\"eth0\"}],\"networks\":[]}",
		    "duplicate interface entry: eth0"),
		    "two interfaces of one name are refused");
		check(refused_saying(DOCUMENT_HEAD "\"devices\":[{\"name\":\"eth0\"},"
		    "{\"name\":\"eth0\"}],\"interfaces\":[],\"networks\":[]}",
		    "duplicate device entry"),
		    "and two devices of one name");
		check(refused_saying(DOCUMENT_HEAD "\"devices\":[],\"interfaces\":[{\"name\":\"eth0\","
		    "\"hooks\":[{\"phase\":\"up\",\"path\":\"bring-up.sh\",\"sha256\":\"00\"}]}],"
		    "\"networks\":[]}", "hook path bring-up.sh is not absolute"),
		    "a hook path that is not absolute is refused");
		check(refused_saying(DOCUMENT_HEAD "\"devices\":[],\"interfaces\":[{\"name\":\"eth0\","
		    "\"addressing\":[{\"source\":\"dhcp4\"},{\"source\":\"dhcp4\"}]}],\"networks\":[]}",
		    "names dhcp4 more than once"),
		    "two dhcp clients on one link are refused");
		/* And the other half of that rule: any number of static addresses is
		 * legitimate, because the list is a composition rather than a set of
		 * alternatives. */
		{
			ncfg_document_t *document = read_text(DOCUMENT_HEAD "\"devices\":[],\"interfaces\":"
			    "[{\"name\":\"eth0\",\"addressing\":[{\"source\":\"static\",\"address\":"
			    "\"192.0.2.1/24\"},{\"source\":\"static\",\"address\":\"192.0.2.2/24\"}]}],"
			    "\"networks\":[]}", NULL, 0);

			check(document != NULL, "while two static addresses are not");
			ncfg_document_free(document);
		}
		check(refused_saying("{\"schema_version\":{\"major\":2,\"minor\":0},\"globals\":{},"
		    "\"devices\":[],\"interfaces\":[],\"networks\":[]}",
		    "is not readable by this build"),
		    "a document from a later major schema is refused");
		/*
		 * Decision 0007's capability check, asked of the mode that will
		 * actually deliver the scope. `resolv.conf` has no per-domain server
		 * concept, and flattening the request would send internal queries to a
		 * public resolver.
		 */
		check(refused_saying("{\"schema_version\":{\"major\":1,\"minor\":1},\"globals\":"
		    "{\"dns\":{\"mode\":\"write_resolv_conf\"}},\"devices\":[],\"interfaces\":"
		    "[{\"name\":\"vpn0\",\"dns\":{\"domains\":[{\"suffix\":\"corp.example\"}]}}],"
		    "\"networks\":[]}",
		    "which mode write_resolv_conf cannot express"),
		    "a scope asking a flat mode to route is refused");
		/*
		 * And the config the recommended documentation writes is accepted. The
		 * interface states no mode of its own, so the host's is the one that
		 * will deliver it -- asking this of `none` refused the split-DNS
		 * configuration netcfgd's own manual recommends, naming a mode nobody
		 * wrote.
		 */
		{
			ncfg_document_t *document = read_text("{\"schema_version\":{\"major\":1,"
			    "\"minor\":1},\"globals\":{\"dns\":{\"mode\":\"dnsmasq\"}},\"devices\":[],"
			    "\"interfaces\":[{\"name\":\"vpn0\",\"dns\":{\"domains\":"
			    "[{\"suffix\":\"corp.example\"}]}}],\"networks\":[]}", NULL, 0);

			check(document != NULL,
			    "while a scope that inherits a routing mode is accepted");
			ncfg_document_free(document);
		}
	}

	/* ---- ranges, and the words a closed set does not have ---- */
	{
		check(refused_saying(DOCUMENT_HEAD "\"devices\":[{\"name\":\"eth0\",\"mtu\":9999999999}],"
		    "\"interfaces\":[],\"networks\":[]}", "range"),
		    "a number outside the width the Rust gave it is refused");
		check(refused_saying(DOCUMENT_HEAD "\"devices\":[{\"name\":\"eth0\",\"mtu\":1.5}],"
		    "\"interfaces\":[],\"networks\":[]}", "whole number"),
		    "and one that is not whole");
		check(refused_saying(DOCUMENT_HEAD "\"devices\":[],\"interfaces\":[],\"networks\":[],"
		    "\"bluetooth\":[{\"id\":\"a\",\"address\":\"AA:BB:CC:DD:EE:FF\",\"profile\":"
		    "\"a2dp_sink\",\"autoconnect\":true}]}", "a2dp_sink"),
		    "a kebab-cased word written with underscores is refused");
		/* An ssid is lowercase hex and uppercase is refused rather than
		 * accepted: two spellings of one ssid would break the byte-identical
		 * guarantee. */
		check(refused_saying(DOCUMENT_HEAD "\"devices\":[],\"interfaces\":[],\"networks\":"
		    "[{\"id\":\"n\",\"ssid\":\"48454C4C4F\",\"security\":{\"type\":\"open\"}}]}",
		    "lowercase hex"),
		    "an ssid in uppercase hex is refused");
		check(refused_saying(DOCUMENT_HEAD "\"devices\":[],\"interfaces\":[{\"name\":\"eth0\","
		    "\"routes\":[{\"destination\":\"default\",\"via\":\"192.0.2.1/24\"}]}],"
		    "\"networks\":[]}", "prefix length"),
		    "a next hop carrying a prefix length is refused");
	}

	/* ---- canonicalisation ---- */
	{
		const char *unsorted = DOCUMENT_HEAD
		    "\"devices\":[{\"name\":\"eth1\"},{\"name\":\"eth0\"}],"
		    "\"interfaces\":[{\"name\":\"wlan0\"},{\"name\":\"eth0\"}],"
		    "\"networks\":[{\"id\":\"work\",\"security\":{\"type\":\"open\"}},"
		    "{\"id\":\"cafe\",\"security\":{\"type\":\"open\"}}],"
		    "\"bluetooth\":[{\"id\":\"speaker\",\"address\":\"AA:BB:CC:DD:EE:FF\","
		    "\"profile\":\"a2dp-sink\",\"autoconnect\":true},"
		    "{\"id\":\"headphones\",\"address\":\"11:22:33:44:55:66\","
		    "\"profile\":\"hfp\",\"autoconnect\":false}],"
		    "\"rules\":[{\"id\":\"b\",\"priority\":200},{\"id\":\"a\",\"priority\":100}],"
		    "\"linksets\":[{\"name\":\"uplink\",\"members\":[\"eth0\",\"wlan0\"]},"
		    "{\"name\":\"office\",\"members\":[\"eth1\"]}]}";
		char             message[NCFG_ERROR_MAX];
		ncfg_document_t *document = read_text(unsorted, message, sizeof(message));

		if (!document) {
			printf("  refused: %s\n", message);
		}
		check(document != NULL, "an unsorted document is read as it was written");
		if (document) {
			ncfg_document_canonicalize(document);
			check(strcmp(document->devices[0].name, "eth0") == 0 &&
			    strcmp(document->interfaces[0].name, "eth0") == 0 &&
			    strcmp(document->networks[0].id, "cafe") == 0,
			    "devices, interfaces and networks sort by the key the schema names");
			/*
			 * **The case that was missed for as long as the field existed.**
			 * It went unnoticed because the document's equality omitted
			 * `bluetooth` as well: with neither walk covering it, order could
			 * not produce a spurious difference because no difference was
			 * visible at all -- two documents differing only in a Bluetooth
			 * device compared equal, so `ncfg profile save` accepted a
			 * snapshot that did not reproduce the machine.
			 */
			check(document->bluetooth_count == 2u &&
			    strcmp(document->bluetooth[0].id, "headphones") == 0,
			    "and so do bluetooth devices, which nothing sorted for a milestone");
			check(document->rules[0].priority == 100 &&
			    strcmp(document->linksets[0].name, "office") == 0,
			    "rules sort by priority and linksets by name");
			/* **A linkset's members deliberately do not sort.** They are a
			 * ranked list, and sorting them would rewrite which of two equally
			 * ranked links the operator said they would rather be on. */
			check(document->linkset_count == 2u &&
			    strcmp(document->linksets[1].members[0], "eth0") == 0,
			    "while the members of a linkset keep the order they were given");
			ncfg_document_free(document);
		}
	}

	/* ---- a station list is a set, and is deduplicated ---- */
	{
		ncfg_document_t *document = read_text(DOCUMENT_HEAD
		    "\"devices\":[],\"interfaces\":[],\"networks\":[],\"access_points\":"
		    "[{\"id\":\"ap\",\"ssid\":\"6170\",\"device\":\"wlan0\",\"security\":"
		    "{\"type\":\"open\"},\"access_control\":{\"policy\":\"deny\",\"stations\":"
		    "[\"bb:bb:bb:bb:bb:bb\",\"aa:aa:aa:aa:aa:aa\",\"bb:bb:bb:bb:bb:bb\"]}}]}",
		    NULL, 0);

		check(document != NULL, "an access point with a station list is read");
		if (document) {
			ncfg_document_canonicalize(document);
			check(document->access_points[0].access_control->station_count == 2u &&
			    strcmp(document->access_points[0].access_control->stations[0],
			    "aa:aa:aa:aa:aa:aa") == 0,
			    "its stations are sorted and the repeat is dropped");
			ncfg_document_free(document);
		}
	}

	/* ---- the defaults that are not C's zero ---- */
	{
		ncfg_document_t *document = ncfg_document_new(NULL, 0);

		check(document != NULL, "an empty document can be built");
		if (document) {
			/*
		 * **`reconcile`, and it is not the zero value.** A calloc'd document
		 * would mean `report` -- a daemon that watches its configuration go
		 * unimplemented and changes nothing, which is what every symptom of
		 * that milestone looked like: a configuration written, a correct plan,
		 * and nothing that ran it.
		 */
			check(document && document->globals.on_drift_default == NCFG_DRIFT_POLICY_RECONCILE,
			    "and drift defaults to reconcile rather than to report");
			check(document &&
			    document->globals.connectivity.ignore_count ==
			    ncfg_connectivity_default_ignore_count &&
			    strcmp(document->globals.connectivity.ignore[0], "docker*") == 0,
			    "and the links a verdict ignores are there without being written");
			check(document && document->schema_version.major == NCFG_SCHEMA_MAJOR &&
			    document->schema_version.minor == NCFG_SCHEMA_MINOR,
			    "and it carries the schema version this build speaks");
			if (document) {
				ncfg_buf_t buf;
				char       message[NCFG_ERROR_MAX];

				ncfg_buf_init(&buf, 0);
				check(ncfg_document_write(document, &buf, message, sizeof(message)) &&
				    strstr(ncfg_buf_text(&buf), "\"on_drift_default\":\"reconcile\"") != NULL &&
				    strstr(ncfg_buf_text(&buf), "\"connectivity\"") == NULL,
				    "an empty document writes its defaults, and omits the one at its default");
				ncfg_buf_free(&buf);
			}
		}
		ncfg_document_free(document);
	}

	/* ---- what the writer does with a value that is outside its set ---- */
	{
		ncfg_document_t *document = read_text(DOCUMENT_HEAD
		    "\"devices\":[{\"name\":\"eth1\"},{\"name\":\"eth0\"}],\"interfaces\":[],"
		    "\"networks\":[]}", NULL, 0);
		ncfg_buf_t       buf;
		char             message[NCFG_ERROR_MAX];

		check(document != NULL, "a document can be written canonically");
		if (document) {
			ncfg_buf_init(&buf, 0);
			check(ncfg_document_write_canonical(document, &buf, message, sizeof(message)) &&
			    strstr(ncfg_buf_text(&buf), "\"eth0\"") <
			    strstr(ncfg_buf_text(&buf), "\"eth1\""),
			    "and it sorts on the way out");
			ncfg_buf_free(&buf);

			/*
			 * **A plausible word for a value that is not one is worse than no
			 * word**, which is `value.h`'s rule and is why nothing is written
			 * here at all -- and the writer's own rule then makes the document
			 * unfinishable rather than letting half of one be sent.
			 */
			document->globals.networking = 99;
			ncfg_buf_init(&buf, 0);
			message[0] = '\0';
			check(!ncfg_document_write(document, &buf, message, sizeof(message)) &&
			    message[0] != '\0',
			    "a closed set holding a value outside it writes no document");
			ncfg_buf_free(&buf);
			ncfg_document_free(document);
		}
	}

	/* **The member the witness cannot check.** `confirm_default` is the only
	 * `Option` in the model without `skip_serializing_if`, so the Rust writes
	 * `null` for it on a machine that states no window -- and the witness
	 * states 90, so its absent form appears nowhere in the file every other
	 * check here is made against. Found by running this writer beside the
	 * installed Rust `ncfg show`. */
	{
		char err[NCFG_ERROR_MAX];
		ncfg_document_t *document = ncfg_document_new(err, sizeof(err));
		ncfg_buf_t written;

		ncfg_buf_init(&written, 0u);
		check(document != NULL, "a document with nothing stated can be made");
		if (document && ncfg_document_write(document, &written, err, sizeof(err))) {
			check(strstr(ncfg_buf_text(&written), "\"confirm_default\":null") != NULL,
			    "a confirm window nobody stated is written as null, not omitted");
			/* **And read back.** The first version of this check asserted the
			 * write and stopped, so the reader went two commits not knowing
			 * that `null` means absent -- and a document stating no window,
			 * which is nearly every document, could not be read by the
			 * reader that had just written it. A round trip is the whole
			 * claim; half of one is how this got in. */
			{
				ncfg_document_t *back = ncfg_document_read(
				    ncfg_buf_text(&written), written.length, err, sizeof(err));

				check(back != NULL, "and read back by the reader that wrote it");
				if (back) {
					check(!back->globals.confirm_default.has,
					    "with the window still absent rather than zero");
					ncfg_document_free(back);
				}
			}
		} else {
			check(0, "a document with nothing stated can be written");
		}
		ncfg_buf_free(&written);
		ncfg_document_free(document);
	}

	if (failures == 0) {
		printf("document_test: all checks passed\n");
	} else {
		printf("document_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
