/*
 * observed_test.c -- the observation, against the frozen witness.
 *
 * WHAT THE WITNESS ROUND TRIP PROVES, AND HOW
 *   `doc/schema/observed.json` is one complete observation with every field
 *   populated -- every ownership, every origin, every backend kind, every
 *   access-point policy, every optional member present at least once. Reading
 *   it and writing it back is the whole of this module exercised at once.
 *
 *   The comparison is **byte for byte against the witness with its whitespace
 *   removed**, and that is the strongest form available here: the Rust writes
 *   it with `serde_json::to_string_pretty` and this port's writer is compact,
 *   so the two differ by indentation and by nothing else if the port is right.
 *   Same members, same order, same values, same escaping -- and a member
 *   silently dropped, one written that should have been omitted, or an integer
 *   that lost a digit all show up as a byte that does not match, with the
 *   offset printed.
 *
 *   Stripping whitespace is not parsing: the stripper below knows only that a
 *   `"` starts a string and a `\` inside one escapes the next byte. It is
 *   twenty lines with no structure in it, so a defect in the model cannot hide
 *   behind a matching defect in the check.
 *
 *   The witness is pure ASCII and carries no escape sequence at all, which is
 *   asserted rather than assumed -- otherwise "same escaping" would be a claim
 *   this test does not actually make.
 *
 *   It is also what holds the four tables this module had to copy out of
 *   `document.c` -- an address, a key, an SSID and the whole DNS policy -- to
 *   the originals. The witness carries one of each, so a member added on that
 *   side and missed here is a byte that does not match. See `observed.c`.
 *
 * WHAT ELSE IS HERE
 *   The cases the Rust carries beside the model: `link.rs`'s six tests, each
 *   naming a defect that shipped or one declined in advance, and the helpers
 *   `observed.rs` publishes -- a DHCP lease read from the route and never the
 *   address, and the rfkill remedy whose two halves must not be swapped.
 *   Plus an unknown member refused *and named*, as the document module does
 *   it.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/observed.h"

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
 * understood the observation could agree with a wrong model about what the
 * observation means; this one cannot, because it does not know.
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
	static const char *const candidates[] = { "../doc/schema/observed.json",
		"doc/schema/observed.json", "../../doc/schema/observed.json" };
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
 * Small observations, for the cases that are about one rule each
 * ------------------------------------------------------------------------ */

/*
 * A link, built from JSON, which is `link.rs`'s own `fn link` and for its
 * reason: an observed link has no default, and a literal would have to be
 * edited every time it gains a field. Everything but the five required members
 * is left out on purpose, so a member that quietly became required fails here.
 */
static ncfg_observed_t *one_link(const char *name, const char *kind, int wireless,
    const char *extra)
{
	char             text[512];
	char             message[NCFG_ERROR_MAX];
	ncfg_observed_t *observed;

	snprintf(text, sizeof(text),
	    "{\"links\":[{\"name\":\"%s\",\"index\":1,\"kind\":\"%s\",\"wireless\":%s,"
	    "\"up\":true,\"carrier\":true,\"mtu\":1500%s%s}]}",
	    name, kind, wireless ? "true" : "false", extra ? "," : "", extra ? extra : "");
	message[0] = '\0';
	observed = ncfg_observed_read(text, strlen(text), message, sizeof(message));
	if (!observed) {
		printf("  could not build a link: %s\n", message);
	}
	return observed;
}

static ncfg_observed_t *read_text(const char *text, char *err, size_t err_size)
{
	return ncfg_observed_read(text, strlen(text), err, err_size);
}

/* Refused, *and* with something said. A failure carrying no sentence is what
 * base.h's convention exists to prevent, and it is invisible to a test that
 * only checks the return value. */
static int refused_saying(const char *text, const char *expected)
{
	char             message[NCFG_ERROR_MAX];
	ncfg_observed_t *observed;

	message[0] = '\0';
	observed = read_text(text, message, sizeof(message));
	if (observed) {
		ncfg_observed_free(observed);
		printf("  accepted an observation that should have been refused\n");
		return 0;
	}
	if (!strstr(message, expected)) {
		printf("  refused, but said `%s`\n", message);
		return 0;
	}
	return 1;
}

static char *write_observed(const ncfg_observed_t *observed, size_t *length_out)
{
	ncfg_buf_t buf;
	char       message[NCFG_ERROR_MAX];
	char      *text;

	ncfg_buf_init(&buf, 0);
	if (!ncfg_observed_write(observed, &buf, message, sizeof(message))) {
		printf("  could not write: %s\n", message);
		ncfg_buf_free(&buf);
		return NULL;
	}
	text = ncfg_buf_take(&buf, length_out);
	ncfg_buf_free(&buf);
	return text;
}

/* The category of a link described by three facts, which is `category_of`'s
 * whole signature once the observation has been built around it. */
static int category_of(const char *name, const char *kind, int wireless,
    const ncfg_document_t *document)
{
	ncfg_observed_t *observed = one_link(name, kind, wireless, NULL);
	int              category = -1;

	if (observed && observed->link_count == 1u) {
		category = ncfg_link_category_of(&observed->links[0], document);
	}
	ncfg_observed_free(observed);
	return category;
}

int main(int argc, char **argv)
{
	/* ---- the witness ---- */
	{
		const char      *path = witness_path(argc, argv);
		size_t           raw_length = 0;
		char            *raw = slurp(path, &raw_length);
		char             message[NCFG_ERROR_MAX];
		ncfg_observed_t *observed = NULL;

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
			observed = ncfg_observed_read(raw, raw_length, message, sizeof(message));
			if (!observed) {
				printf("  refused the witness: %s\n", message);
			}
			check(observed != NULL, "the witness is read");
		}
		if (observed && raw) {
			size_t written_length = 0;
			char  *written = write_observed(observed, &written_length);
			size_t wanted_length = 0;
			char  *wanted = minify(raw, raw_length, &wanted_length);
			int    same = written && wanted && written_length == wanted_length &&
			    memcmp(written, wanted, written_length) == 0;

			if (!same && written && wanted) {
				report_difference(wanted, wanted_length, written, written_length);
			}
			check(same, "and is written back byte for byte, member for member");

			/*
			 * **The witness is a coverage fixture and is deliberately not
			 * canonical**, which is where it differs from the document's: a
			 * document has a `to_json_canonical` that produced its witness,
			 * and an observation has no such thing. This one names every
			 * variant in the order a reader reads best -- its routes are three
			 * on `eth1` and then one on `eth0` -- so sorting it *does* move
			 * something, and a test asserting otherwise would have been
			 * asserting the fixture rather than the code.
			 *
			 * What is asserted instead is what canonicalisation is for: the
			 * order it produces, and that a second pass is a no-op. An
			 * unstable sort would fail the second half on a list with two
			 * equal keys, which is the failure `observed_link.c` explains.
			 */
			if (written) {
				size_t sorted_length = 0;
				char  *sorted;
				size_t again_length = 0;
				char  *again;

				ncfg_observed_canonicalize(observed);
				sorted = write_observed(observed, &sorted_length);
				check(observed->route_count > 0u &&
				    strcmp(observed->routes[0].interface, "eth0") == 0,
				    "canonicalising the witness puts its routes in interface order");
				ncfg_observed_canonicalize(observed);
				again = write_observed(observed, &again_length);
				check(sorted && again && again_length == sorted_length &&
				    memcmp(again, sorted, again_length) == 0,
				    "and canonicalising what is already sorted moves nothing");
				free(sorted);
				free(again);
			}

			/* And what was written reads back as the same observation. */
			if (written) {
				ncfg_observed_t *second;

				message[0] = '\0';
				second = ncfg_observed_read(written, written_length, message,
				    sizeof(message));
				if (!second) {
					printf("  could not read back: %s\n", message);
				}
				if (second) {
					size_t third_length = 0;
					char  *third = write_observed(second, &third_length);

					check(third && third_length == written_length &&
					    memcmp(third, written, third_length) == 0,
					    "reading what was written writes the same bytes again");
					free(third);
					ncfg_observed_free(second);
				} else {
					check(0, "reading what was written writes the same bytes again");
				}
			}
			free(written);
			free(wanted);
		}
		ncfg_observed_free(observed);
		free(raw);
	}

	/* ---- deny_unknown_fields, and the member named ---- */
	{
		check(refused_saying("{\"hostname\":\"h\",\"desired\":{}}", "desired"),
		    "a member this build does not know is refused, and named");
		check(refused_saying("{\"links\":[{\"name\":\"eth0\",\"index\":1,\"up\":true,"
		    "\"carrier\":true,\"mtu\":1500,\"bogus\":1}]}", "bogus"),
		    "and so is one inside a link");
		check(refused_saying("{\"backends\":[{\"kind\":\"dhcp4\",\"interface\":\"eth0\","
		    "\"running\":true,\"pid\":7}]}", "pid"),
		    "and one inside a backend");
		/* The reader's refusal rather than this module's, and it has to reach
		 * the caller intact. */
		check(refused_saying("{\"hostname\":\"h\"", ""),
		    "an observation that stops in the middle is refused, with something said");
		check(refused_saying("{\"links\":[{\"index\":1,\"up\":true,\"carrier\":true,"
		    "\"mtu\":1500}]}", "name"),
		    "a required member that is absent is refused, and named");
		/* **The top-level struct is `#[serde(default)]` and every member of it
		 * is therefore optional**, which is the Rust's choice and not this
		 * port's: a bare netlink snapshot carries a handful of these. */
		{
			ncfg_observed_t *empty = read_text("{}", NULL, 0);

			check(empty != NULL, "while an observation that says nothing at all is read");
			ncfg_observed_free(empty);
		}
	}

	/* ---- the two spellings that are the document's and not the language's -- */
	{
		const char *wireguard = ncfg_backend_kind_name(NCFG_BACKEND_WIREGUARD);
		const char *openvpn = ncfg_backend_kind_name(NCFG_BACKEND_OPENVPN);

		/* Asserted as literals, as `value_test.c` asserts every word it owns:
		 * the enum is C's and the word is the wire's, and nothing but a test
		 * holds the two together. This is the same pair `document.h` carries
		 * and the one this project has already shipped wrong twice. */
		check(wireguard && strcmp(wireguard, "wire_guard") == 0 && openvpn &&
		    strcmp(openvpn, "open_vpn") == 0,
		    "a wireguard backend is spelled `wire_guard` on the wire");
		check(ncfg_backend_kind_name(-1) == NULL,
		    "and a backend kind outside the set has no word at all");
		check(refused_saying("{\"backends\":[{\"kind\":\"wireguard\",\"interface\":\"wg0\","
		    "\"running\":true}]}", "wireguard"),
		    "so the language's spelling is refused where the wire's belongs");
	}

	/* ---- ownership, and the one decision that may remove something ---- */
	{
		check(ncfg_ownership_may_remove(NCFG_OWNERSHIP_OURS) &&
		    !ncfg_ownership_may_remove(NCFG_OWNERSHIP_FOREIGN) &&
		    !ncfg_ownership_may_remove(NCFG_OWNERSHIP_UNKNOWN),
		    "only what netcfgd installed may be removed");
		check(ncfg_ownership_name(NCFG_OWNERSHIP_UNKNOWN) != NULL &&
		    strcmp(ncfg_ownership_name(NCFG_OWNERSHIP_UNKNOWN), "unknown") == 0 &&
		    ncfg_ownership_name(3) == NULL,
		    "and the three words are the wire's, with nothing outside the set");
		/*
		 * **A link's ownership defaults to `unknown`, which is not the zero
		 * value of this enum.** A calloc'd link would mean `ours` -- and a
		 * link nobody has a record of would be one the planner may delete,
		 * which is the exact inversion 0002 exists to prevent. Netlink has no
		 * protocol field for links, so this default is the whole safety.
		 */
		{
			ncfg_observed_t *observed = one_link("eth0", "", 0, NULL);

			check(observed && observed->link_count == 1u &&
			    observed->links[0].ownership == NCFG_OWNERSHIP_UNKNOWN,
			    "a link that says nothing is unknown, and never ours");
			ncfg_observed_free(observed);
		}
		/* An address says so or it is not read: unlike a link, somebody has
		 * decided, by `IFA_PROTO` or by the `/run` fallback. */
		check(refused_saying("{\"addresses\":[{\"interface\":\"eth0\","
		    "\"address\":\"192.0.2.1/24\"}]}", "ownership"),
		    "while an address with no ownership is refused");
	}

	/* ---- the words the wire carries, and the words a column shows ---- */
	{
		check(ncfg_origin_name(NCFG_ORIGIN_LINK_LOCAL) != NULL &&
		    strcmp(ncfg_origin_name(NCFG_ORIGIN_LINK_LOCAL), "link_local") == 0 &&
		    ncfg_link_category_name(NCFG_LINK_CATEGORY_WIREGUARD) != NULL &&
		    strcmp(ncfg_link_category_name(NCFG_LINK_CATEGORY_WIREGUARD), "wireguard") == 0 &&
		    ncfg_presence_name(NCFG_PRESENCE_UNKNOWN) != NULL &&
		    strcmp(ncfg_presence_name(NCFG_PRESENCE_UNKNOWN), "unknown") == 0 &&
		    ncfg_subject_name(NCFG_SUBJECT_LINKSET) != NULL &&
		    strcmp(ncfg_subject_name(NCFG_SUBJECT_LINKSET), "linkset") == 0 &&
		    ncfg_rung_name(NCFG_RUNG_ROUTED) != NULL &&
		    strcmp(ncfg_rung_name(NCFG_RUNG_ROUTED), "routed") == 0,
		    "every vocabulary word is the one the wire carries");
		/*
		 * **And `ncfg_ineligible_name` deliberately answers with different
		 * words.** `no_carrier` is what the JSON holds and `no carrier` is
		 * what a status line says; one table for both would mean a reader that
		 * accepted `probe failed` in a file, which the Rust refuses.
		 */
		check(ncfg_ineligible_name(NCFG_INELIGIBLE_NO_CARRIER) != NULL &&
		    strcmp(ncfg_ineligible_name(NCFG_INELIGIBLE_NO_CARRIER), "no carrier") == 0 &&
		    ncfg_ineligible_name(NCFG_INELIGIBLE_PROBE) != NULL &&
		    strcmp(ncfg_ineligible_name(NCFG_INELIGIBLE_PROBE), "probe failed") == 0 &&
		    ncfg_ineligible_name(9) == NULL,
		    "while a reason reads as a sentence and is not the wire's word");
		check(refused_saying("{\"linksets\":[{\"name\":\"uplink\",\"members\":"
		    "[{\"name\":\"eth0\",\"ineligible\":\"no carrier\"}]}]}", "ineligibility"),
		    "and the sentence is not accepted where the wire's word belongs");
	}

	/* ---- link.rs: the three the kernel cannot tell apart ---- */
	{
		/*
		 * **This is the whole reason the vocabulary exists.** `enp0s31f6`,
		 * `wlp0s20f3` and `lo` all report an empty kind on the reporting
		 * machine, so a filter built on kind puts a wired card, a radio and
		 * the loopback in one bucket -- and a dropdown offering "ethernet"
		 * would show the radio.
		 */
		check(category_of("enp0s31f6", "", 0, NULL) == NCFG_LINK_CATEGORY_ETHERNET,
		    "an empty kind on a wired card is ethernet");
		check(category_of("wlp0s20f3", "", 1, NULL) == NCFG_LINK_CATEGORY_WIFI,
		    "the same empty kind on a radio is wifi");
		check(category_of("lo", "", 0, NULL) == NCFG_LINK_CATEGORY_LOOPBACK,
		    "and on the loopback it is loopback");
	}

	/* ---- link.rs: everything else comes from the kernel's kind, coarsened -- */
	{
		static const struct {
			const char *kind;
			int         wanted;
		} cases[] = { { "bridge", NCFG_LINK_CATEGORY_BRIDGE },
			{ "bond", NCFG_LINK_CATEGORY_BOND }, { "vlan", NCFG_LINK_CATEGORY_VLAN },
			{ "macvlan", NCFG_LINK_CATEGORY_VLAN },
			{ "wireguard", NCFG_LINK_CATEGORY_WIREGUARD },
			{ "gre", NCFG_LINK_CATEGORY_TUNNEL }, { "sit", NCFG_LINK_CATEGORY_TUNNEL },
			{ "vxlan", NCFG_LINK_CATEGORY_TUNNEL }, { "tun", NCFG_LINK_CATEGORY_TUNNEL },
			{ "ppp", NCFG_LINK_CATEGORY_TUNNEL }, { "veth", NCFG_LINK_CATEGORY_VIRTUAL },
			{ "dummy", NCFG_LINK_CATEGORY_VIRTUAL } };
		size_t i;
		int    all = 1;

		for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
			if (category_of("x0", cases[i].kind, 0, NULL) != cases[i].wanted) {
				printf("  kind %s landed in %d\n", cases[i].kind,
				    category_of("x0", cases[i].kind, 0, NULL));
				all = 0;
			}
		}
		check(all, "the kernel's kinds map onto words an operator filters by");
		/* **A kind this list has never heard of is `other`, not nothing.** A
		 * kernel gains link kinds faster than this does, and a row in no
		 * category vanishes from every filtered list -- which is the failure
		 * that would be hardest to notice. */
		check(category_of("x0", "a-kind-from-2031", 0, NULL) == NCFG_LINK_CATEGORY_OTHER,
		    "and a kind from the future is other rather than nothing");
	}

	/* ---- link.rs: a modem is known from the document and nowhere else ---- */
	{
		/* The document built from one device rather than spelled out: a whole
		 * literal here would have to be edited every time a document gains a
		 * required member. */
		static const char text[] =
		    "{\"schema_version\":{\"major\":1,\"minor\":1},\"globals\":{},\"devices\":"
		    "[{\"name\":\"wwan0\",\"modem\":{\"sim\":[]}}],\"interfaces\":[],"
		    "\"networks\":[]}";
		char             message[NCFG_ERROR_MAX];
		ncfg_document_t *modem;

		message[0] = '\0';
		modem = ncfg_document_read(text, sizeof(text) - 1u, message, sizeof(message));
		if (!modem) {
			printf("  refused the document: %s\n", message);
		}

		check(modem != NULL, "a document naming a modem device is read");
		/* Without the document it is whatever it looks like, which is an
		 * honest answer rather than a guess. */
		check(category_of("wwan0", "", 0, NULL) == NCFG_LINK_CATEGORY_ETHERNET,
		    "a modem's link looks ordinary with no document to say otherwise");
		/* With it, the document wins -- and it has to be asked first, since a
		 * modem's link looks ordinary to the kernel. */
		check(modem && category_of("wwan0", "", 0, modem) == NCFG_LINK_CATEGORY_MODEM,
		    "and the document is what makes it a modem");
		check(modem && category_of("enp0s31f6", "", 0, modem) == NCFG_LINK_CATEGORY_ETHERNET,
		    "while a device with no modem block is not made one by the document existing");
		ncfg_document_free(modem);
	}

	/* ---- link.rs: the whole reason presence is not a boolean ---- */
	{
		/* Looked, with a method that would have worked, and it was not there. */
		check(ncfg_presence_of_network(0, 0, 1, 0) == NCFG_PRESENCE_ABSENT,
		    "a network a scan looked for and missed is absent");
		/* The same evidence about a hidden network is not evidence at all: a
		 * hidden access point beacons with an empty name, so a network that is
		 * right there would otherwise be reported gone. */
		check(ncfg_presence_of_network(1, 0, 1, 0) == NCFG_PRESENCE_UNKNOWN,
		    "while a hidden one is unknown and not absent");
		/* Nobody looked. Not the same as looking and finding nothing. */
		check(ncfg_presence_of_network(0, 0, 0, 0) == NCFG_PRESENCE_UNKNOWN,
		    "and a network nobody scanned for is unknown too");
		/* Association settles it either way, and outranks a stale scan. */
		check(ncfg_presence_of_network(0, 1, 0, 0) == NCFG_PRESENCE_PRESENT &&
		    ncfg_presence_of_network(1, 1, 1, 0) == NCFG_PRESENCE_PRESENT &&
		    ncfg_presence_of_network(0, 0, 1, 1) == NCFG_PRESENCE_PRESENT,
		    "association settles it, and outranks a scan that disagrees");
	}

	/* ---- link.rs: an interface has no third answer ---- */
	{
		ncfg_observed_t *observed = one_link("eth0", "", 0, NULL);

		check(observed && ncfg_presence_of_interface("eth0", observed) == NCFG_PRESENCE_PRESENT,
		    "an interface the kernel has is present");
		/* The kernel's link table is complete: an interface netcfgd cannot
		 * find is one that does not exist, so there is no question it was
		 * unable to ask. */
		check(observed && ncfg_presence_of_interface("eth1", observed) == NCFG_PRESENCE_ABSENT,
		    "and one it does not is absent, never unknown");
		ncfg_observed_free(observed);
	}

	/* ---- the `String` the Rust does not hold as an `Option` ---- */
	{
		/*
		 * **A link's `kind` is written even when it is empty.** An observation
		 * of a plain ethernet card carries `"kind": ""`, because the Rust's
		 * field is a `String` with a default and not an `Option<String>` --
		 * and a reader that omitted it would write something the Rust reads
		 * back as a different observation. `wireless`, `offloads` and
		 * `ownership` are the same shape and the same rule.
		 */
		ncfg_observed_t *observed = read_text("{\"links\":[{\"name\":\"eth0\",\"index\":1,"
		    "\"up\":true,\"carrier\":true,\"mtu\":1500}]}", NULL, 0);
		size_t           length = 0;
		char            *written = observed ? write_observed(observed, &length) : NULL;

		check(written && strstr(written, "\"kind\":\"\"") != NULL &&
		    strstr(written, "\"offloads\":[]") != NULL &&
		    strstr(written, "\"ownership\":\"unknown\"") != NULL,
		    "a member with a default and no skip is written at its default");
		/* And the ones the Rust does skip stay out, or an upgrade would look
		 * like a configuration change to everything downstream. */
		check(written && strstr(written, "\"category\"") == NULL &&
		    strstr(written, "\"inventory\"") == NULL &&
		    strstr(written, "\"bluetooth\"") == NULL,
		    "while the ones it skips when empty are left out");
		free(written);
		ncfg_observed_free(observed);
	}

	/* ---- a lease is a route, and never an address ---- */
	{
		/*
		 * **The route and not the address.** `IFA_PROTO` -- the same stamp on
		 * an address -- arrived in Linux 5.18 and is absent on plenty of
		 * running kernels: measured on the reporting machine, a DHCP address
		 * came back with no proto while its route said 16. So an address
		 * carrying the DHCP origin proves nothing and the route is the answer.
		 */
		ncfg_observed_t *observed = read_text(
		    "{\"addresses\":[{\"interface\":\"eth9\",\"address\":\"192.0.2.9/24\","
		    "\"ownership\":\"ours\",\"origin\":\"dhcp4\"}],"
		    "\"routes\":[{\"interface\":\"eth0\",\"destination\":\"default\",\"proto\":16,"
		    "\"ownership\":\"ours\"},"
		    "{\"interface\":\"eth1\",\"destination\":\"default\",\"proto\":110,"
		    "\"ownership\":\"ours\"}]}", NULL, 0);

		check(observed && ncfg_observed_has_dhcp_lease(observed, "eth0"),
		    "an interface whose route carries RTPROT_DHCP has a lease");
		check(observed && !ncfg_observed_has_dhcp_lease(observed, "eth1"),
		    "one whose route is netcfgd's own does not");
		check(observed && !ncfg_observed_has_dhcp_lease(observed, "eth9"),
		    "and neither does one with only a DHCP-origin address");
		ncfg_observed_free(observed);
	}

	/* ---- the rest of what an observation is asked ---- */
	{
		ncfg_observed_t *observed = read_text(
		    "{\"delegations\":[{\"interface\":\"wan0\",\"prefixes\":[\"2001:db8::/56\"]}],"
		    "\"dns\":[{\"scope\":\"globals\",\"policy\":{\"mode\":\"dnsmasq\"}}],"
		    "\"backends\":[{\"kind\":\"dhcp4\",\"interface\":\"eth0\",\"running\":true},"
		    "{\"kind\":\"open_vpn\",\"interface\":\"vpn0\",\"running\":false}],"
		    "\"backend_restarts\":[[\"open_vpn\",\"vpn0\",7]]}", NULL, 0);
		const ncfg_delegation_t *delegation =
		    ncfg_observed_delegation(observed, "wan0");
		const ncfg_dns_policy_t *policy = ncfg_observed_dns_for(observed, "globals");

		check(delegation && delegation->prefix_count == 1u &&
		    strcmp(delegation->prefixes[0], "2001:db8::/56") == 0 &&
		    ncfg_observed_delegation(observed, "wan1") == NULL,
		    "a delegation is found by the interface whose lease carries it");
		check(policy && policy->mode.mode == NCFG_DNS_MODE_DNSMASQ &&
		    ncfg_observed_dns_for(observed, "eth0") == NULL,
		    "and a delivered dns scope by its name");
		/* `running` is a fact about a process, and the question is asked of
		 * one kind on one interface -- 0078's distinction, kept. */
		check(observed && ncfg_observed_backend_running(observed, NCFG_BACKEND_DHCP4, "eth0") &&
		    !ncfg_observed_backend_running(observed, NCFG_BACKEND_OPENVPN, "vpn0") &&
		    !ncfg_observed_backend_running(observed, NCFG_BACKEND_DHCP6, "eth0"),
		    "a backend is running only where its own kind and interface say so");
		/* A daemon that dies as fast as it is started would otherwise be
		 * started again on every reconcile for ever -- 181 starts in twelve
		 * seconds, measured (0079). */
		check(observed &&
		    ncfg_observed_backend_restarts(observed, NCFG_BACKEND_OPENVPN, "vpn0") == 7 &&
		    ncfg_observed_backend_restarts(observed, NCFG_BACKEND_DHCP4, "eth0") == 0,
		    "and a restart count is zero for a backend nothing has recorded");
		ncfg_observed_free(observed);
	}

	/* ---- the rfkill sentence, whose two halves must not be swapped ---- */
	{
		ncfg_observed_t *soft = one_link("wlan0", "", 1,
		    "\"rfkill\":{\"switch\":\"phy0\",\"soft\":true}");
		ncfg_observed_t *hard = one_link("wlan0", "", 1,
		    "\"rfkill\":{\"switch\":\"phy0\",\"hard\":true}");
		ncfg_observed_t *clear = one_link("wlan0", "", 1,
		    "\"rfkill\":{\"switch\":\"phy0\"}");
		char             sentence[NCFG_ERROR_MAX];

		check(soft && ncfg_rfkill_blocked(soft->links[0].rfkill) && hard &&
		    ncfg_rfkill_blocked(hard->links[0].rfkill) && clear &&
		    !ncfg_rfkill_blocked(clear->links[0].rfkill),
		    "a radio is off by either switch and on by neither");
		/*
		 * **Telling somebody to run a command against a slider wastes their
		 * evening.** A soft block is software and one command clears it; a
		 * hard block is a physical switch and nothing in software will move
		 * it, so the two sentences are not interchangeable.
		 */
		check(soft && ncfg_rfkill_remedy(soft->links[0].rfkill, sentence, sizeof(sentence)) &&
		    strstr(sentence, "rfkill unblock wifi") != NULL &&
		    strstr(sentence, "phy0") != NULL,
		    "a soft block names the command that clears it");
		check(hard && ncfg_rfkill_remedy(hard->links[0].rfkill, sentence, sizeof(sentence)) &&
		    strstr(sentence, "rfkill unblock") == NULL &&
		    strstr(sentence, "nothing in software") != NULL,
		    "and a hard block names no command at all");
		/* Half a sentence that still looks like one is refused, which is
		 * `ncfg_buf_t`'s rule applied to the one string built here. */
		check(hard && ncfg_rfkill_remedy(hard->links[0].rfkill, sentence, 10u) == NULL,
		    "a remedy that would not fit is refused rather than truncated");
		ncfg_observed_free(soft);
		ncfg_observed_free(hard);
		ncfg_observed_free(clear);
	}

	/* ---- the access point policy, whose three answers are not two ---- */
	{
		ncfg_observed_t *observed = read_text(
		    "{\"backends\":[{\"kind\":\"access_point\",\"interface\":\"wlan0\","
		    "\"running\":true,\"access_control\":{\"policy\":{\"set\":\"allow\"},"
		    "\"denied\":[\"aa:aa:aa:aa:aa:aa\"],\"accepted\":[\"bb:bb:bb:bb:bb:bb\"]}}]}",
		    NULL, 0);
		const ncfg_observed_access_control_t *control =
		    observed && observed->backend_count == 1u ?
		    observed->backends[0].access_control : NULL;
		size_t                                count = 0;
		char *const                          *list;

		check(control && control->policy.kind == NCFG_OBSERVED_POLICY_SET &&
		    control->policy.policy == NCFG_ACL_POLICY_ALLOW,
		    "a policy that was set carries which one it is");
		/* hostapd holds both lists regardless of which `macaddr_acl` selects,
		 * so the one the policy does not read is observed anyway -- it is the
		 * only way to see, from outside, that an operator flipped the policy
		 * under a running access point. */
		list = ncfg_observed_access_control_list(control, NCFG_ACL_POLICY_ALLOW, &count);
		check(list && count == 1u && strcmp(list[0], "bb:bb:bb:bb:bb:bb") == 0,
		    "and the list that policy reads is the one handed back");
		list = ncfg_observed_access_control_list(control, NCFG_ACL_POLICY_DENY, &count);
		check(list && count == 1u && strcmp(list[0], "aa:aa:aa:aa:aa:aa") == 0,
		    "while the other list is kept rather than thrown away");
		ncfg_observed_free(observed);

		/* **The two ways of having no policy lead to opposite actions.**
		 * `unset` may be reported and converged against; `unknown` may not,
		 * because emptying a list without knowing which one hostapd reads
		 * either opens a network or closes it. */
		observed = read_text("{\"backends\":[{\"kind\":\"access_point\","
		    "\"interface\":\"wlan0\",\"running\":true,\"access_control\":"
		    "{\"policy\":\"unknown\",\"denied\":[],\"accepted\":[]}}]}", NULL, 0);
		check(observed && observed->backend_count == 1u &&
		    observed->backends[0].access_control &&
		    observed->backends[0].access_control->policy.kind ==
		    NCFG_OBSERVED_POLICY_UNKNOWN,
		    "a policy nobody recorded is unknown and not unset");
		ncfg_observed_free(observed);
		check(refused_saying("{\"backends\":[{\"kind\":\"access_point\","
		    "\"interface\":\"wlan0\",\"running\":true,\"access_control\":"
		    "{\"policy\":\"deny\",\"denied\":[],\"accepted\":[]}}]}", "unset"),
		    "and a bare policy word is not one of the three");
	}

	/* ---- canonicalisation ---- */
	{
		ncfg_observed_t *observed = read_text(
		    "{\"links\":[{\"name\":\"wlan0\",\"index\":2,\"up\":true,\"carrier\":true,"
		    "\"mtu\":1500},{\"name\":\"eth0\",\"index\":1,\"up\":true,\"carrier\":true,"
		    "\"mtu\":1500}],"
		    "\"addresses\":[{\"interface\":\"eth0\",\"address\":\"192.0.2.2/24\","
		    "\"ownership\":\"ours\"},{\"interface\":\"eth0\",\"address\":\"192.0.2.1/24\","
		    "\"ownership\":\"ours\"}],"
		    "\"routes\":[{\"interface\":\"eth0\",\"destination\":\"default\",\"metric\":100,"
		    "\"ownership\":\"ours\"},{\"interface\":\"eth0\",\"destination\":\"default\","
		    "\"ownership\":\"ours\"}],"
		    "\"backends\":[{\"kind\":\"dhcp6\",\"interface\":\"eth0\",\"running\":true},"
		    "{\"kind\":\"dhcp4\",\"interface\":\"eth0\",\"running\":true}],"
		    "\"dns\":[{\"scope\":\"globals\",\"policy\":{}},"
		    "{\"scope\":\"eth0\",\"policy\":{}}],"
		    "\"reports\":[{\"interface\":\"b\",\"addresses\":[],\"gateways\":[],"
		    "\"nameservers\":[]},{\"interface\":\"a\",\"addresses\":[],\"gateways\":[],"
		    "\"nameservers\":[]}]}", NULL, 0);

		check(observed != NULL, "an unsorted observation is read as it was written");
		if (observed) {
			ncfg_observed_canonicalize(observed);
			check(strcmp(observed->links[0].name, "eth0") == 0 &&
			    strcmp(observed->addresses[0].address, "192.0.2.1/24") == 0,
			    "links sort by name and addresses by interface then address");
			/* Absent sorts before present, as `None` does in Rust: an
			 * unnumbered route is the kernel's own default and the strongest,
			 * and a comparison that put it last would make two observations of
			 * one machine disagree. */
			check(!observed->routes[0].metric.has && observed->routes[1].metric.has,
			    "and routes by destination then metric, with absent first");
			/* The kind by declaration order, which is what Rust's derived
			 * `Ord` compares and is not the alphabetical order of the words. */
			check(observed->backends[0].kind == NCFG_BACKEND_DHCP4 &&
			    strcmp(observed->dns[0].scope, "eth0") == 0,
			    "backends by interface then kind, and dns scopes by name");
			/*
			 * **And nothing else moves.** `Observed::canonicalize` sorts five
			 * lists; the rest arrive in an order somebody chose -- a report's
			 * addresses are the order the far end offered them -- and sorting
			 * one here would be this port deciding something the Rust does
			 * not, which nothing downstream could see.
			 */
			check(observed->report_count == 2u &&
			    strcmp(observed->reports[0].interface, "b") == 0,
			    "while the lists the Rust leaves alone keep the order they had");
			ncfg_observed_free(observed);
		}
	}

	/* ---- what the writer does with a value that is outside its set ---- */
	{
		ncfg_observed_t *observed = ncfg_observed_new(NULL, 0);
		ncfg_buf_t       buf;
		char             message[NCFG_ERROR_MAX];

		check(observed != NULL, "an empty observation can be built");
		if (observed) {
			ncfg_buf_init(&buf, 0);
			check(ncfg_observed_write_canonical(observed, &buf, message, sizeof(message)) &&
			    strcmp(ncfg_buf_text(&buf),
			    "{\"links\":[],\"addresses\":[],\"routes\":[],\"backends\":[],\"dns\":[],"
			    "\"rules\":[],\"bridge_vlans\":[],\"delegations\":[],\"reports\":[],"
			    "\"qdisc_applied\":[],\"ingress_applied\":[],\"privacy_applied\":[],"
			    "\"backend_restarts\":[],\"accept_ra_applied\":[],"
			    "\"forwarding_applied\":[],\"nat\":[],\"nat_conflicts\":[],"
			    "\"hook_state\":[],\"address_proto_supported\":false}") == 0,
			    "and writes exactly the members the Rust does not skip");
			ncfg_buf_free(&buf);

			/*
			 * **A plausible word for a value that is not one is worse than no
			 * word**, which is `value.h`'s rule and is why nothing is written
			 * here at all -- and the writer's own rule then makes the
			 * observation unfinishable rather than letting half of one be
			 * sent.
			 */
			observed->links = calloc(1, sizeof(*observed->links));
			if (observed->links) {
				observed->link_count = 1u;
				observed->links[0].ownership = 99;
				ncfg_buf_init(&buf, 0);
				message[0] = '\0';
				check(!ncfg_observed_write(observed, &buf, message, sizeof(message)) &&
				    message[0] != '\0',
				    "a closed set holding a value outside it writes no observation");
				ncfg_buf_free(&buf);
			}
			ncfg_observed_free(observed);
		}
	}

	if (failures == 0) {
		printf("observed_test: all checks passed\n");
	} else {
		printf("observed_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
