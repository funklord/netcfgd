/*
 * render_test.c -- the document back as configuration text, and what it refuses.
 *
 * THE ROUND TRIP IS THE CENTRE, AND IT IS WRITTEN FROM TEXT
 *   Compile one file of configuration, render the document, compile the
 *   result, and the two documents must be the same one. Every `round_trips`
 *   case below is that.
 *
 *   Written as text in and text out rather than by building model values by
 *   hand, because it then also proves the renderer against **what the parser
 *   actually accepts** -- a rendering the compiler rejects fails here loudly
 *   instead of at somebody's next `ncfg apply`. That is why a rendering is
 *   never asserted only as a string where a round trip is available: a string
 *   check agrees with a renderer that writes a key the language does not have.
 *
 *   The comparison is the canonical JSON of both documents, byte for byte,
 *   which is `document.h`'s own notion of equality. Both sides come out of
 *   `ncfg_compile`, so `generated_by` is the same on both and needs no special
 *   handling.
 *
 * WHERE A STRING ASSERTION IS STILL THE RIGHT CHECK
 *   Two places, and both are named where they appear:
 *
 *   * **A spelling that has more than one accepted form.** A round trip cannot
 *     tell `wpa2+wpa3` from `wpa2wpa3`, nor a value written from one omitted
 *     -- a written default compiles equal to an absent one. Where the spelling
 *     itself is the defect, the text is asserted beside the round trip.
 *   * **A refusal that cannot be reached from a config file.** Six model
 *     fields have no words in the configuration language at all, so a document
 *     carrying one can only arrive as JSON. Those cases read a JSON document
 *     with `ncfg_document_read` and assert on the refusal list.
 *
 * THE WITNESS
 *   `doc/schema/document.json` carries every interface kind, every addressing
 *   source and every optional member, so rendering it exercises the whole
 *   refusal list at once. It must refuse, and it must name every part it
 *   carries that has no rendering -- which is the "list the fields, list the
 *   ones the renderer mentions, diff the two" audit run by the data rather
 *   than by a grep that matched a field name shared between two types.
 *
 * THE DEFECTS
 *   Each case names the defect it exists for. The three from `project.md`
 *   section 10 are grouped and labelled: a device whose only setting was
 *   `on_unmanage` vanishing from the profile entirely, `on_unmanage` itself
 *   being neither rendered nor refused, and a wireless network silently
 *   dropping its `bssid` pins, its `roam` policy and its own `config`,
 *   `routes` and `dns`.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/lower.h"
#include "ncfg/parse.h"
#include "ncfg/value.h"
#include "ncfg/render.h"

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

/* ------------------------------------------------------------------------ *
 * Compiling, rendering, and the round trip
 * ------------------------------------------------------------------------ */

/*
 * Compile one file of configuration.
 *
 * NULL with the diagnostics printed rather than a panic, because a library
 * test that aborted would take every later case with it -- and how much is
 * broken is the thing worth knowing.
 */
static ncfg_document_t *compiled(const char *text, const char *whose)
{
	char                message[NCFG_ERROR_MAX];
	ncfg_ast_file_t    *file = NULL;
	ncfg_source_t       source;
	ncfg_lower_diags_t  diags = { 0 };
	ncfg_document_t    *document;

	message[0] = '\0';
	if (!ncfg_parse(text, strlen(text), &file, NULL, message, sizeof(message))) {
		printf("  %s did not parse: %s\n%s\n", whose, message, text);
		return NULL;
	}
	source.name = "test.conf";
	source.file = file;
	document = ncfg_compile(&source, 1, ncfg_hook_sink_refusing(), &diags, message,
	    sizeof(message));
	if (!document) {
		size_t i;

		printf("  %s did not compile: %s\n", whose, message);
		for (i = 0; i < diags.count; i++) {
			char rendered[NCFG_ERROR_MAX];

			ncfg_lower_diag_render(&diags.at[i], rendered, sizeof(rendered));
			printf("    %s\n", rendered);
		}
		printf("%s\n", text);
	}
	ncfg_lower_diags_free(&diags);
	ncfg_ast_file_free(file);
	return document;
}

/* The canonical JSON of a document, which is `document.h`'s own equality. */
static char *canonical(ncfg_document_t *document)
{
	char       message[NCFG_ERROR_MAX];
	ncfg_buf_t buf;
	char      *out = NULL;

	ncfg_buf_init(&buf, 0);
	message[0] = '\0';
	if (ncfg_document_write_canonical(document, &buf, message, sizeof(message))) {
		out = ncfg_buf_take(&buf, NULL);
	} else {
		printf("  a document could not be written back: %s\n", message);
	}
	ncfg_buf_free(&buf);
	return out;
}

/*
 * Render a document, expecting success.
 *
 * NULL when it refused, with the refusals printed -- a case that silently got
 * nothing would otherwise satisfy every `strstr` it makes, which is the
 * vacuous form of this whole file.
 */
static char *render_document(const ncfg_document_t *document)
{
	char                message[NCFG_ERROR_MAX];
	ncfg_buf_t          text;
	ncfg_unrenderable_t missing;
	char               *out = NULL;

	ncfg_buf_init(&text, 0);
	ncfg_unrenderable_init(&missing);
	message[0] = '\0';
	if (ncfg_render(document, NULL, &text, &missing, message, sizeof(message))) {
		out = ncfg_buf_take(&text, NULL);
	} else {
		size_t i;

		printf("  expected a rendering and got a refusal: %s\n", message);
		for (i = 0; i < missing.count; i++) {
			printf("    * %s\n", missing.items[i]);
		}
	}
	ncfg_unrenderable_free(&missing);
	ncfg_buf_free(&text);
	return out;
}

/* Compile a config file and render what it compiled to, for the cases that
 * assert on the text as well as on the round trip. */
static char *rendering_of(const char *text)
{
	ncfg_document_t *document = compiled(text, "a case's own configuration");
	char            *out;

	if (!document) {
		return NULL;
	}
	out = render_document(document);
	ncfg_document_free(document);
	return out;
}

/*
 * **The gate this module exists behind**: render, read it back, and the
 * document must be the same one.
 */
static void round_trips(const char *text, const char *what)
{
	ncfg_document_t *before = compiled(text, "a case's own configuration");
	ncfg_document_t *after = NULL;
	char            *rendered = NULL;
	char            *want = NULL;
	char            *got = NULL;
	int              same = 0;

	if (before) {
		rendered = render_document(before);
	}
	if (rendered) {
		after = compiled(rendered, "the rendering");
	}
	if (after) {
		want = canonical(before);
		got = canonical(after);
		same = want && got && strcmp(want, got) == 0;
		if (!same && want && got) {
			printf("  the document changed across the round trip\n"
			    "  rendered as:\n%s\n  before: %s\n  after:  %s\n",
			    rendered, want, got);
		}
	}
	check(same, what);
	free(want);
	free(got);
	free(rendered);
	ncfg_document_free(after);
	ncfg_document_free(before);
}

/* `text` holds `needle`, and the text is printed when it does not -- "they
 * differ" is not a diagnostic, and a rendering is short enough to read. */
static int holds(const char *text, const char *needle)
{
	if (text && strstr(text, needle)) {
		return 1;
	}
	printf("  looked for `%s` and did not find it in:\n%s\n", needle,
	    text ? text : "(nothing)");
	return 0;
}

static int lacks(const char *text, const char *needle)
{
	if (text && !strstr(text, needle)) {
		return 1;
	}
	printf("  found `%s` and should not have, in:\n%s\n", needle, text ? text : "(nothing)");
	return 0;
}

/*
 * The refusals a config file produces, joined by newlines.
 *
 * NULL when it *rendered*, because a case asserting on a refusal that quietly
 * stopped happening would otherwise pass by finding no text it was looking for
 * in an empty string.
 */
static char *refusals_for(ncfg_document_t *document)
{
	char                message[NCFG_ERROR_MAX];
	ncfg_buf_t          text;
	ncfg_unrenderable_t missing;
	char               *out = NULL;

	ncfg_buf_init(&text, 0);
	ncfg_unrenderable_init(&missing);
	message[0] = '\0';
	if (ncfg_render(document, NULL, &text, &missing, message, sizeof(message))) {
		printf("  expected a refusal and it rendered\n");
	} else {
		ncfg_buf_t joined;
		size_t     i;

		ncfg_buf_init(&joined, 0);
		for (i = 0; i < missing.count; i++) {
			ncfg_buf_add_text(&joined, missing.items[i]);
			ncfg_buf_add_char(&joined, '\n');
		}
		out = ncfg_buf_take(&joined, NULL);
		ncfg_buf_free(&joined);
	}
	ncfg_unrenderable_free(&missing);
	ncfg_buf_free(&text);
	return out;
}

/*
 * There is no `refusals_of_config` any more, and its absence is a fact worth
 * leaving a note for rather than a tidy-up.
 *
 * It compiled a config file and collected the refusals, and it had users while
 * `wireguard` and `openvpn` were refused. **Hooks are now the only refusal a
 * config file can reach**: every other one names something the language has no
 * words for, or something netcfgd synthesises, so the way to reach them is a
 * document that arrived as JSON -- which is what `refusals_of_json` below is
 * for. Anything new that is refused and reachable wants this helper back.
 */

/* For a file carrying hooks, which need a sink that accepts them before the
 * renderer ever sees one. `record_hook` is below. */
static char *refusals_with_hooks(const char *text);

/*
 * The same, for a document that can only arrive as JSON.
 *
 * Six model fields have no words in the configuration language, so the
 * refusals for them cannot be reached from a config file at all. They are kept
 * anyway -- this takes a document rather than a file, and a refusal that
 * cannot fire costs nothing while a missing one costs a silent drop -- and
 * these cases are how they are checked.
 *
 * `globals`, `devices`, `interfaces` and `networks` are required members, so a
 * case that is about one of them still names the others.
 */
#define DOC(body) "{\"schema_version\":{\"major\":1,\"minor\":1},\"generated_by\":\"test\"," body "}"
#define PLAIN_GLOBALS "\"globals\":{},"
#define NO_DEVICES "\"devices\":[],"
#define NO_INTERFACES "\"interfaces\":[],"
#define NO_NETWORKS "\"networks\":[]"

static char *refusals_of_json(const char *json)
{
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document;
	char            *out;

	message[0] = '\0';
	document = ncfg_document_read(json, strlen(json), message, sizeof(message));
	if (!document) {
		printf("  the case's own document was refused: %s\n", message);
		return NULL;
	}
	out = refusals_for(document);
	ncfg_document_free(document);
	return out;
}

/* ------------------------------------------------------------------------ *
 * The witness, whole
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

static void render_the_witness(int argc, char **argv)
{
	/* Every one names a thing the witness carries and this cannot write. The
	 * kinds are spelled the *language's* way on purpose: `wire_guard` and
	 * `open_vpn` are the document's words, and a refusal that used them would
	 * send an operator to write a block the parser does not have. */
	static const char *const expected[] = {
		/* `kind wireguard`, `kind openvpn`, `kind tunnel` and `kind tun` were
		 * here and render now. `ifb` is the only kind left, and it is refused
		 * because netcfgd synthesises it rather than because nothing writes
		 * it. */
		/* `routing rule(s)` was here and renders now. */
		/* `access_point block(s)` was here and renders now. */
		"kind ifb",
		/* `a wifi policy` was here and is rendered now, so it is no longer
		 * refused. Removed rather than left: this list's job is to name what
		 * has no rendering, and an entry for something that renders would make
		 * the next reader think the gap is still open. */
		/* `ethtool settings` and the blanket `qdisc` were here and render now; the
		 * ingress-metering half of a qdisc is still refused and is below. */
		"a match block", "a qdisc metering arriving traffic",
		/* `ingress_redirect` was a blanket refusal and is now a specific
		 * one: the shaper is undone where the pair is the shape this build
		 * makes, and named where it is not. Every device in the witness
		 * redirects to `ifb-eth0` and the witness has no such device, so each
		 * is refused -- correctly, and saying why. */
		"an ingress redirect to `ifb-eth0`, which is not a device this build "
		"would have made for it",
		"global: dns options", "global: dnssec",
		"global: dns transport", "global: a dns server with a port or sni",
		/* `interface d-0: advertise` was here and renders now. */
		/* `interface d-0: guard` was here and renders now. */
		"interface d-0: hooks",
		/* `an address with lifetimes or a peer` was here. All three of those
		 * modifiers are in the language, so that refusal was reachable from an
		 * ordinary config file and is closed. */
		/* `delegated addressing` and `reported addressing` were here and
		 * render now, which leaves every address source the model has with
		 * a rendering. */
		"a route with a scope", "a route with a proto",
		"a dhcp lease's client id", "a dhcp lease's requested options",
		"network n-eap: dns options" };
	const char         *path = witness_path(argc, argv);
	size_t              raw_length = 0;
	char               *raw = slurp(path, &raw_length);
	char                message[NCFG_ERROR_MAX];
	ncfg_document_t    *document = NULL;
	ncfg_buf_t          text;
	ncfg_unrenderable_t missing;
	size_t              i;
	int                 all_named = 1;

	check(raw != NULL, "the frozen witness is there to be read");
	if (!raw) {
		return;
	}
	message[0] = '\0';
	document = ncfg_document_read(raw, raw_length, message, sizeof(message));
	if (!document) {
		printf("  refused the witness: %s\n", message);
	}
	check(document != NULL, "the witness is read, and validates");
	free(raw);
	if (!document) {
		return;
	}

	ncfg_buf_init(&text, 0);
	ncfg_unrenderable_init(&missing);
	message[0] = '\0';
	check(!ncfg_render(document, NULL, &text, &missing, message, sizeof(message)),
	    "the witness cannot be rendered whole, and says so rather than dropping");
	/* On a refusal the text is emptied, which is the module's own rule: half a
	 * profile that looks whole is worse than none. */
	check(ncfg_buf_text(&text)[0] == '\0', "and the half-written text is not handed out");

	for (i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
		size_t j;
		int    found = 0;

		for (j = 0; j < missing.count && !found; j++) {
			found = strstr(missing.items[j], expected[i]) != NULL;
		}
		if (!found) {
			printf("  nothing in the refusal list named `%s`\n", expected[i]);
			all_named = 0;
		}
	}
	check(all_named, "and every part of it with no rendering is named");
	/* A list that lost an entry to a failed allocation would be a shorter list
	 * of real refusals, which is this module's own defect turned on itself. */
	check(!missing.failed, "and the list itself did not quietly lose an entry");

	ncfg_unrenderable_free(&missing);
	ncfg_buf_free(&text);
	ncfg_document_free(document);
}

/* ------------------------------------------------------------------------ *
 * The three defects named in project.md section 10
 * ------------------------------------------------------------------------ */

/*
 * **Defect 1: a device whose only setting was `on_unmanage` vanished from the
 * profile entirely.** `render_device` returned early when its body was empty,
 * and the key was written after that check, so the whole block went with it.
 *
 * **Defect 2: `on_unmanage` was neither rendered nor refused.** `clear` is
 * what an operator chooses when the hardware is leaving their hands, and the
 * default it silently reverted to is `leave` -- so a machine restored from a
 * saved profile would walk away from a device without removing what netcfgd
 * had put on it, stranding a WireGuard key in the kernel and a supplicant's
 * passphrases.
 */
static void the_unmanage_policy_defects(void)
{
	char *alone;
	char *with_managed;
	char *leave;

	round_trips("device wlan1 { on_unmanage = \"clear\" }\n",
	    "a device whose only setting is on_unmanage survives a round trip");
	round_trips("device wlan0 {\n\tmanaged = false\n\ton_unmanage = \"clear\"\n}\n",
	    "and so does one that is also unmanaged");

	alone = rendering_of("device wlan1 { on_unmanage = \"clear\" }\n");
	with_managed = rendering_of("device wlan0 {\n\tmanaged = false\n"
	    "\ton_unmanage = \"clear\"\n}\n");
	leave = rendering_of("device wlan0 {\n\tmanaged = false\n\ton_unmanage = \"leave\"\n}\n");

	check(holds(alone, "\ndevice wlan1 {") && holds(alone, "\ton_unmanage = \"clear\"\n"),
	    "a device with nothing else to say still gets its block, and the key in it");
	check(holds(with_managed, "\tmanaged = false\n"),
	    "and the unmanaged flag is beside it rather than instead of it");
	/* The default is not written, which is this module's convention -- and the
	 * assertion is here so the cases above cannot be satisfied by writing the
	 * key unconditionally, which a round trip alone cannot tell apart. */
	check(lacks(leave, "on_unmanage"), "and `leave`, being the default, is left unwritten");
	free(alone);
	free(with_managed);
	free(leave);
}

/*
 * **Defect 3: a wireless network silently dropped its `bssid` pins, its `roam`
 * policy, and its own `config`, `routes` and `dns`.**
 *
 * The network ones are the worst of the set: a `network` block taking its own
 * addressing and resolver is how a machine says "on this SSID use this static
 * address and this nameserver", so a profile that lost them brought the
 * machine back on DHCP against the wrong resolver -- which looks like a
 * working network until something internal fails to resolve. Losing the bssid
 * list widens the network to any radio broadcasting the same name, which is
 * exactly what the key exists to prevent.
 */
/*
 * A network named by its access points says which state that is.
 *
 * **Absent is a statement, not an absence**, and `document.h` says so where the
 * field is declared: absent means "whatever the access points in `bssid` call
 * themselves", while omitting the key makes the SSID the block's label. Three
 * states, and `render_network_keys` wrote nothing for the third -- so
 * `ssid = "@bssid"` vanished, the document came back as a network named after
 * its own label, and `ncfg profile save` refused on any machine with a network
 * pinned by access point.
 *
 * Found on the Rust side and fixed in both: the two renderers were written
 * independently and carried the same hole, which is the reason a finding over
 * there is worth checking here rather than assumed to be that language's.
 *
 * The three states are kept apart deliberately. A renderer that wrote the
 * marker for all three, or omitted all three, satisfies no two of these at
 * once -- and a label-equal SSID must stay omitted, because that is what
 * omitting it means and the shorter form is the faithful one.
 */
/*
 * A name the kernel allows and the lexer will not read bare.
 *
 * **`ncfg profile save` refused on a machine with an interface named `4g0`.**
 * `interface` and `device` labels were always written bare, the lexer reads a
 * bare label as an identifier, and an identifier may not begin with a digit --
 * so the snapshot rendered to text that does not compile, and the operator got
 * no profile and a complaint about the renderer.
 *
 * The names were checked against the kernel rather than reasoned about:
 * `ip link add .th0 type dummy` succeeds and so does `2eth`, while `eth0:1` is
 * refused by the kernel and is not at issue. A leading digit is an ordinary way
 * to name a mobile interface, which is the case worth caring about rather than
 * the leading dot that found it.
 *
 * The control is `eth0.42`, which must stay bare: a dot is legal inside an
 * identifier and not at its start, and that is the spelling Linux gives every
 * VLAN interface. A renderer that quoted everything would rewrite every profile
 * this tree writes, so both directions are asserted.
 */
/*
 * The hostname policy renders the spelling the language takes.
 *
 * **It wrote `from_dhcp` and the language only accepts `dhcp`.**
 * `lower_global` compares against `"dhcp"`; anything else falls through to the
 * hostname check, where `from_dhcp` is refused outright because an underscore
 * is not legal in a hostname. So the renderer produced a document that does not
 * compile, and `ncfg profile save` refused on any machine with
 * `global { hostname = "dhcp" }` -- which is an ordinary thing to have.
 *
 * Found by round-tripping the 78 documents `lower_test.c` already compiles: a
 * corpus written to exercise lowering, with no reason to ask about rendering,
 * and the renderer's own suite had no case for this policy at all. The same
 * defect was found in the Rust renderer earlier the same day; the two were
 * written from one understanding and inherited the same mistake.
 *
 * The control is the static form beside it. A renderer that wrote `dhcp` for
 * every hostname would pass the first check and fail the second.
 */
/*
 * A radio's own policy round-trips, every field of it.
 *
 * **Refused wholesale until now, which meant no machine with a radio could
 * save a profile.** `ncfg wifi activate` writes `device wlan0 { wifi {
 * autoconnect = true } }`, so a laptop that has ever joined a network from the
 * client has one, and `ncfg profile save` answered that it could not render a
 * wifi policy. That is the same shape as the `bluetooth` block being refused
 * wholesale: a refusal costing more than the rendering does.
 *
 * Every field in one document rather than one case each, because the seven are
 * written by one function and a case covering two would leave the other five
 * free to go quiet. The non-default value is chosen for each, since a renderer
 * that wrote nothing would round-trip a document whose defaults happened to
 * match.
 *
 * **And `wifi { }` present and empty is its own case.** `device->wifi` being
 * non-NULL is what makes a device a radio netcfgd manages, so an empty block
 * has to come back as an empty block rather than as nothing -- 10.21's lesson,
 * which this renderer has now met three times.
 */
/*
 * A routing rule round-trips, including the two that exclude each other.
 *
 * **Refused wholesale until now**, so a machine with any policy routing could
 * not save a profile -- and a rule is not written by accident, so the refusal
 * fell on exactly the configurations somebody had thought hardest about.
 *
 * `lookup` and `l3mdev` are the pair worth a case each. A VRF supplies the
 * table, so the compiler refuses a rule carrying both -- and refuses one with
 * no lookup, no action and no `l3mdev` at all. A renderer that dropped `l3mdev`
 * would turn a valid VRF rule into a document that does not compile, which is
 * exactly what the Rust renderer did until a round trip caught it.
 *
 * Every field in one rule for the reason the wifi policy's case gives: a
 * fixture that sampled one would leave the rest free to go quiet, and a
 * non-default value for each is what catches a word written from the wrong
 * table.
 */
/*
 * An `access_point` block round-trips, including its station list.
 *
 * **Refused wholesale until now**, so a machine running a hotspot could not save
 * a profile -- and that configuration is one somebody set up deliberately, which
 * is the worst kind to lose.
 *
 * The `access_control` list is the case worth most: which key it sits under IS
 * the policy, the compiler refusing a block that carries both an `allow` and a
 * `deny`, so a renderer that wrote the wrong key inverts the meaning of the
 * block rather than losing a line. Both policies are exercised for that reason.
 *
 * An SSID equal to the label stays unwritten, as a network's does, and one that
 * differs comes back as hex -- an SSID being arbitrary octets while a label is
 * text.
 */
/*
 * `ethtool` and `qdisc` round-trip, in both of the qdisc's two forms.
 *
 * **Both refused wholesale until now**, so a machine with any link setting or
 * any shaped queue could not save a profile -- and these are settings somebody
 * chose against a specific NIC or a specific uplink, which makes them the least
 * guessable things in a document.
 *
 * **A toggle has three values and `off` is not the absence of one.** `unmanaged`
 * is the default and means netcfgd leaves the driver's own answer alone, so it
 * is omitted; `on` and `off` are both written. A renderer that treated `off` as
 * nothing would turn "switch this offload off" into "do not touch it", which is
 * the opposite instruction.
 *
 * The qdisc has two shapes and which one it takes is a property of the policy,
 * not a style: a kind with no rate is the bare `qdisc = "fq_codel"` a person
 * would have written, and one with a rate needs the block. Both are asserted,
 * because a renderer that always wrote the block would round-trip and still be
 * wrong about what a profile looks like.
 *
 * `render_rate` picks the largest suffix that divides exactly, so a rate comes
 * back as `100mbit` rather than `100000kbit`.
 */
static void ethtool_and_qdisc_round_trip(void)
{
	char *toggles;
	char *bare;
	char *shaped;

	round_trips("device eth0 {\n\tethtool {\n"
	    "\t\tautoneg = \"off\"\n"
	    "\t\tgro = \"on\"\n"
	    "\t\tgso = \"off\"\n"
	    "\t\ttso = \"on\"\n"
	    "\t\trx_checksum = \"off\"\n"
	    "\t\ttx_checksum = \"on\"\n"
	    "\t\tspeed = 1000\n"
	    "\t\tduplex = \"full\"\n"
	    "\t\twol = \"g\"\n"
	    "\t\trx_ring = 4096\n"
	    "\t\ttx_ring = 2048\n"
	    "\t}\n}\n",
	    "every field of an ethtool block survives a round trip");

	/* Both halves of the toggle, because `off` and unmentioned are different
	 * instructions to the driver. */
	toggles = rendering_of("device eth0 { ethtool { gro = \"off\"; tso = \"on\" } }\n");
	check(toggles && strstr(toggles, "gro = \"off\"") != NULL,
	    "an offload switched off says so, rather than reading as untouched");
	check(toggles && strstr(toggles, "tso = \"on\"") != NULL &&
	        strstr(toggles, "unmanaged") == NULL,
	    "and one switched on says that, while the default is left unwritten");
	free(toggles);

	round_trips("device eth0 {\n\tqdisc = \"fq_codel\"\n}\n",
	    "a qdisc with no rate survives a round trip");
	bare = rendering_of("device eth0 {\n\tqdisc = \"fq_codel\"\n}\n");
	check(bare && strstr(bare, "qdisc = \"fq_codel\"") != NULL,
	    "and comes back in the short form a person would have written");
	free(bare);

	round_trips("device eth0 {\n\tqdisc {\n\t\tkind = \"cake\"\n"
	    "\t\tbandwidth = \"100mbit\"\n\t}\n}\n",
	    "and a shaped one survives in the block form it needs");
	shaped = rendering_of("device eth0 {\n\tqdisc {\n\t\tkind = \"cake\"\n"
	    "\t\tbandwidth = \"100mbit\"\n\t}\n}\n");
	check(shaped && strstr(shaped, "bandwidth = \"100mbit\"") != NULL,
	    "with the rate under the largest suffix that divides it exactly");
	free(shaped);
}

static void an_access_point_round_trips(void)
{
	char *allowed;
	char *denied;
	char *plain;

	/* No `device wlan0 { }` beside it, and deliberately so: an access point
	 * needs none, and an empty device block is currently dropped by
	 * `render_device` -- a separate open question (10.408) that would make this
	 * case fail for a reason that has nothing to do with access points. */
	round_trips("access_point \"guests\" {\n"
	    "\tdevice = \"wlan0\"\n"
	    "\tchannel = 6\n"
	    "\tband = \"2.4\"\n"
	    "\tregdom = \"SE\"\n"
	    "\thidden = true\n"
	    "\twifi { psk = \"@secret:ap\"; proto = \"wpa2+wpa3\" }\n"
	    "\taccess_control { deny = [\"aa:bb:cc:dd:ee:ff\"] }\n"
	    "}\n",
	    "every field of an access point survives a round trip");

	denied = rendering_of("access_point \"a\" {\n"
	    "\tdevice = \"wlan0\"\n\twifi { psk = \"@secret:ap\" }\n"
	    "\taccess_control { deny = [\"aa:bb:cc:dd:ee:ff\"] }\n}\n");
	check(denied && strstr(denied, "deny = [") != NULL,
	    "a deny list comes back under `deny`");
	free(denied);

	/* The other policy, because writing the wrong key inverts the block rather
	 * than losing a line. */
	allowed = rendering_of("access_point \"a\" {\n"
	    "\tdevice = \"wlan0\"\n\twifi { psk = \"@secret:ap\" }\n"
	    "\taccess_control { allow = [\"aa:bb:cc:dd:ee:ff\", \"11:22:33:44:55:66\"] }\n}\n");
	check(allowed && strstr(allowed, "allow = [") != NULL &&
	        strstr(allowed, "deny") == NULL,
	    "and an allow list under `allow`, never the other way about");
	check(allowed && strstr(allowed, "\"11:22:33:44:55:66\"") != NULL,
	    "with every station in it, not just the first");
	free(allowed);

	/* The label-equal SSID stays unwritten, as a network's does. */
	plain = rendering_of("access_point \"home\" {\n"
	    "\tdevice = \"wlan0\"\n\twifi { psk = \"@secret:ap\" }\n}\n");
	check(plain && strstr(plain, "ssid =") == NULL,
	    "while an SSID equal to the label is left unsaid");
	free(plain);
}

static void a_routing_rule_round_trips(void)
{
	char *full;

	round_trips("rule \"from-lan\" {\n"
	    "\tpriority = 100\n"
	    "\tfamily = \"inet6\"\n"
	    "\tfrom = \"2001:db8::/64\"\n"
	    "\tto = \"2001:db8:1::/64\"\n"
	    "\tiif = \"lan0\"\n"
	    "\toif = \"wan0\"\n"
	    "\tfwmark = 42\n"
	    "\tfwmask = 255\n"
	    "\tlookup = 200\n"
	    "\tsuppress_prefixlength = 0\n"
	    "\tinvert = true\n"
	    "}\n",
	    "every field of a routing rule survives a round trip");

	full = rendering_of("rule \"blocked\" {\n\tpriority = 50\n\taction = \"blackhole\"\n}\n");
	/* The spelling comes from `ncfg_rule_action_name`, which the lowerer's
	 * `..._from_name` inverts, so there is no table here to misorder. */
	check(full && strstr(full, "action = \"blackhole\"") != NULL,
	    "and an action that is not the default is named");
	free(full);

	/* `lookup` is written as `lookup` though the model calls it `table`: the
	 * compiler reads both and a profile is read by people. */
	full = rendering_of("rule \"t\" {\n\tpriority = 7\n\ttable = 9\n}\n");
	check(full && strstr(full, "lookup = 9") != NULL,
	    "and the table is written as `lookup`, the spelling the manual teaches");
	free(full);

	/* The VRF rule, which has no lookup because the VRF supplies the table --
	 * and which therefore does not compile at all if `l3mdev` is dropped. */
	round_trips("rule \"vrf-local\" {\n\tpriority = 1000\n\tl3mdev = true\n}\n",
	    "a rule whose table comes from a VRF survives one too");
	full = rendering_of("rule \"vrf-local\" {\n\tpriority = 1000\n\tl3mdev = true\n}\n");
	check(full && strstr(full, "l3mdev = true") != NULL,
	    "because `l3mdev` is written, without which it would not compile");
	free(full);
}

static void a_radios_own_policy_round_trips(void)
{
	char *full;
	char *empty;

	round_trips("device wlan0 {\n\twifi {\n"
	    "\t\tbackend = \"wpa_supplicant\"\n"
	    "\t\tautoconnect = false\n"
	    "\t\tportal_check = \"http://example.com/generate_204\"\n"
	    "\t\tregdom = \"SE\"\n"
	    "\t\tpowersave = \"off\"\n"
	    "\t\tmac_policy = \"per_network\"\n"
	    "\t\tscan_randomization = true\n"
	    "\t}\n}\n",
	    "every field of a radio's policy survives a round trip");

	full = rendering_of("device wlan0 {\n\twifi {\n"
	    "\t\tbackend = \"iwd\"\n"
	    "\t\tpowersave = \"on\"\n"
	    "\t\tmac_policy = \"per_connection\"\n"
	    "\t}\n}\n");
	/* `iwd` is written like any other backend. The compiler accepts it and
	 * netcfgd refuses it at use (0014), so dropping it would turn a
	 * configuration netcfgd explains itself about into one it approves. */
	check(full && strstr(full, "backend = \"iwd\"") != NULL,
	    "including a backend this build refuses at use, rather than dropping it");
	check(full && strstr(full, "powersave = \"on\"") != NULL &&
	        strstr(full, "mac_policy = \"per_connection\"") != NULL,
	    "and the two words that are not the first in their table");
	free(full);

	/* The default side: a policy at every default writes an empty block, not a
	 * block restating defaults, and not nothing at all. */
	round_trips("device wlan0 { wifi { } }\n",
	    "a radio declared with no policy at all survives one too");
	empty = rendering_of("device wlan0 { wifi { } }\n");
	check(empty && strstr(empty, "wifi {") != NULL,
	    "and the block is still written, because present and empty is not absent");
	check(empty && strstr(empty, "autoconnect") == NULL,
	    "while a default is left unsaid rather than restated");
	free(empty);
}

static void the_hostname_policy_round_trips(void)
{
	char *from_dhcp;
	char *stated;

	round_trips("global { hostname = \"dhcp\" }\n",
	    "a hostname taken from DHCP survives a round trip");
	from_dhcp = rendering_of("global { hostname = \"dhcp\" }\n");
	check(from_dhcp && strstr(from_dhcp, "hostname = \"dhcp\"") != NULL,
	    "and is written as the one spelling the language takes");
	free(from_dhcp);

	round_trips("global { hostname = \"router\" }\n",
	    "and a stated hostname survives one too");
	stated = rendering_of("global { hostname = \"router\" }\n");
	check(stated && strstr(stated, "hostname = \"router\"") != NULL,
	    "written as itself, not as the policy");
	free(stated);
}

static void a_label_the_lexer_cannot_read_bare(void)
{
	static const char *const quoted[] = { ".th0", "2eth", "4g0" };
	static const char *const bare[] = { "eth0", "eth0.42", "br-lan" };
	size_t                   i;

	for (i = 0u; i < sizeof(quoted) / sizeof(quoted[0]); i++) {
		char  config[128];
		char  wanted[64];
		char *out;

		snprintf(config, sizeof(config), "device \"%s\" {\n\tmtu = 1400\n}\n", quoted[i]);
		round_trips(config, "a label the lexer cannot read bare survives a round trip");
		snprintf(wanted, sizeof(wanted), "device \"%s\" {", quoted[i]);
		out = rendering_of(config);
		check(out && strstr(out, wanted) != NULL,
		    "and is written quoted rather than bare");
		free(out);
	}

	for (i = 0u; i < sizeof(bare) / sizeof(bare[0]); i++) {
		char  config[128];
		char  wanted[64];
		char *out;

		snprintf(config, sizeof(config), "device %s {\n\tmtu = 1400\n}\n", bare[i]);
		round_trips(config, "a label that is an identifier survives a round trip");
		snprintf(wanted, sizeof(wanted), "device %s {", bare[i]);
		out = rendering_of(config);
		check(out && strstr(out, wanted) != NULL,
		    "and stays bare, because quoting every label would rewrite every profile");
		free(out);
	}
}

static void a_network_named_by_its_access_points(void)
{
	char *pinned;
	char *plain;

	round_trips("network \"Lobby\" {\n"
	    "\tbssid = \"aa:bb:cc:dd:ee:ff\"\n"
	    "\tssid = \"@bssid\"\n"
	    "\twifi { psk = \"@secret:lobby\" }\n}\n",
	    "a network whose name is the access points' survives a round trip");

	pinned = rendering_of("network \"Lobby\" {\n"
	    "\tbssid = \"aa:bb:cc:dd:ee:ff\"\n"
	    "\tssid = \"@bssid\"\n"
	    "\twifi { psk = \"@secret:lobby\" }\n}\n");
	check(pinned && strstr(pinned, "ssid = \"@bssid\"") != NULL,
	    "and the marker is written rather than left to be guessed");
	free(pinned);

	/* The control. An SSID equal to the label is what omitting the key means,
	 * so stating it would be noise -- and a renderer that wrote the marker
	 * unconditionally would fail here. */
	plain = rendering_of("network \"Cafe\" {\n\twifi { psk = \"@secret:cafe\" }\n}\n");
	check(plain && strstr(plain, "ssid =") == NULL,
	    "while a network named by its own label states no ssid at all");
	free(plain);
}

static void the_wireless_network_drops(void)
{
	char *pinned;
	char *scoped;

	round_trips("network \"Office\" {\n"
	    "\tbssid = [\"00:11:22:33:44:55\", \"00:11:22:33:44:66\"]\n"
	    "\twifi {\n"
	    "\t\tpsk = \"@secret:office\"\n"
	    "\t\troam {\n\t\t\tsignal = -65\n\t\t\tinterval = 20\n\t\t\tslow_interval = 240\n\t\t}\n"
	    "\t}\n}\n",
	    "a network's pinned access points and its roam policy survive a round trip");
	round_trips("network \"Lab\" {\n"
	    "\tconfig = \"10.4.0.9/24\"\n"
	    "\troutes = \"default via 10.4.0.1\"\n"
	    "\tdns {\n\t\tmode = \"write_resolv_conf\"\n\t\tservers = [\"10.4.0.53\"]\n"
	    "\t\tsearch = [\"lab.example\"]\n\t}\n"
	    "\twifi { psk = \"@secret:lab\" }\n}\n",
	    "and so do its own addressing, routes and resolver");

	pinned = rendering_of("network \"Office\" {\n"
	    "\tbssid = [\"00:11:22:33:44:55\", \"00:11:22:33:44:66\"]\n"
	    "\twifi {\n\t\tpsk = \"@secret:office\"\n"
	    "\t\troam { signal = -65; interval = 20; slow_interval = 240 }\n\t}\n}\n");
	scoped = rendering_of("network \"Lab\" {\n\tconfig = \"10.4.0.9/24\"\n"
	    "\troutes = \"default via 10.4.0.1\"\n"
	    "\tdns { mode = \"write_resolv_conf\"; servers = [\"10.4.0.53\"] }\n"
	    "\twifi { psk = \"@secret:lab\" }\n}\n");

	check(holds(pinned, "\tbssid = [\"00:11:22:33:44:55\", \"00:11:22:33:44:66\"]\n"),
	    "the pins are written beside `wifi`, where the parser reads them");
	check(holds(pinned, "\t\troam {\n\t\t\tsignal = -65\n\t\t\tinterval = 20\n"
	    "\t\t\tslow_interval = 240\n\t\t}\n"),
	    "and the roam policy inside it, where the parser reads that");
	check(holds(scoped, "\tconfig = \"10.4.0.9/24\"\n") &&
	    holds(scoped, "\troutes = \"default via 10.4.0.1\"\n") &&
	    holds(scoped, "\tdns {\n\t\tmode = \"write_resolv_conf\"\n"
	        "\t\tservers = [\"10.4.0.53\"]\n\t}\n"),
	    "and a network's own scope is written with an interface's own keys");
	free(pinned);
	free(scoped);
}

/*
 * A roam block whose every value is the parser's default. It must still render
 * as a block: the defaults are what an *absent* block means, so rendering
 * nothing would turn "roam with the usual settings" into "do not roam", which
 * is a different document.
 */
static void a_default_roam_block_survives(void)
{
	round_trips("network \"Cafe\" {\n\twifi {\n\t\tpsk = \"@secret:cafe\"\n"
	    "\t\troam { signal = -70; interval = 30; slow_interval = 300 }\n\t}\n}\n",
	    "a roam block at every default survives, because absent means something else");
}

/* ------------------------------------------------------------------------ *
 * The rest of render.rs's own cases, each with the defect it names
 * ------------------------------------------------------------------------ */

static void the_ordinary_interfaces(void)
{
	round_trips("interface eth0 {\n\tconfig = \"dhcp\"\n}\n", "a dhcp interface round trips");
	round_trips("interface eth0 {\n"
	    "\tconfig = [\"192.0.2.10/24\", \"2001:db8::10/64\"]\n"
	    "\troutes = [\"default via 192.0.2.1\", \"default via 2001:db8::1\"]\n}\n",
	    "an address and its routes round trip");
	round_trips("interface eth0 {\n\tconfig = \"192.0.2.10/24\"\n"
	    "\troutes = \"10.0.0.0/8 via 192.0.2.1 metric 300 table 42\"\n}\n",
	    "a route with a metric and a table round trips");
}

/*
 * A route's `src` and `onlink`, both dropped in silence.
 *
 * `onlink` is the one with teeth: it exempts the route from the ordering rule
 * that installs addresses before routes, so a route that needs it simply fails
 * to install. `src` decides which address the machine is seen as coming from,
 * which moves traffic to another identity rather than breaking it.
 */
static void a_routes_source_and_onlink_round_trip(void)
{
	const char *text = "interface eth0 {\n\tconfig = \"192.0.2.10/24\"\n"
	    "\troutes = [\"default via 192.0.2.1 src 192.0.2.10 metric 100\", "
	    "\"198.51.100.0/24 via 192.0.2.99 onlink\"]\n}\n";
	char       *rendered;

	round_trips(text, "a route's preferred source and its onlink flag round trip");
	rendered = rendering_of(text);
	check(holds(rendered, "\"default via 192.0.2.1 src 192.0.2.10 metric 100\""),
	    "and the phrase keeps the parser's own word order");
	check(holds(rendered, "\"198.51.100.0/24 via 192.0.2.99 onlink\""),
	    "with `onlink` as a bare keyword at the end");
	free(rendered);
}

/*
 * A static address's three modifiers, which were refused as one.
 *
 * The refusal read "an address with lifetimes or a peer" and covered a case
 * that can arrive from a config file and a case that cannot -- the lifetimes
 * and the peer are all three in the language, so **a point-to-point link could
 * not save a profile**, and the wording did not say which half was which.
 *
 * `peer` and `pointopoint` are two spellings the parser takes for one field, so
 * the second of these round trips while its text comes back as the first. That
 * is the round trip doing its job rather than a loss: what must survive is the
 * document, and the document has one field.
 */
static void an_address_modifiers_round_trip(void)
{
	const char *text = "interface eth0 {\n\tconfig = \"192.0.2.1/32 peer 192.0.2.2\"\n}\n";
	const char *both = "interface eth0 {\n"
	    "\tconfig = \"2001:db8::1/64 preferred_lft 1800 valid_lft 3600\"\n}\n";
	char       *rendered;

	round_trips(text, "an address with a point-to-point peer round trips");
	rendered = rendering_of(text);
	check(holds(rendered, "\"192.0.2.1/32 peer 192.0.2.2\""),
	    "and the peer is beside the address, in the value the parser reads back");
	free(rendered);

	round_trips(both, "an address with both lifetimes round trips");
	rendered = rendering_of(both);
	check(holds(rendered, "preferred_lft 1800"), "with the preferred lifetime in seconds");
	check(holds(rendered, "valid_lft 3600"), "and the valid one after it");
	free(rendered);

	round_trips("interface eth0 {\n"
	    "\tconfig = \"192.0.2.1/32 pointopoint 192.0.2.2\"\n}\n",
	    "and so does the other spelling of a peer");

	/* `forever` is how the language says "no lifetime", and `set_lifetime`
	 * stores it as absent -- so it must come back as nothing at all rather
	 * than as a number. A renderer writing a sentinel here would produce a
	 * document that compiles to something else. */
	round_trips("interface eth0 {\n\tconfig = \"2001:db8::1/64 valid_lft forever\"\n}\n",
	    "an address whose lifetime is `forever` round trips");
	rendered = rendering_of("interface eth0 {\n"
	    "\tconfig = \"2001:db8::1/64 valid_lft forever\"\n}\n");
	check(!holds(rendered, "valid_lft"),
	    "and says nothing, because absent is what `forever` compiles to");
	free(rendered);
}

/*
 * `advertise { }`, which decides whether anything behind this machine can
 * configure itself at all.
 *
 * Losing it leaves a router that no longer tells the hosts on its LAN what their
 * prefix is, so every one of them falls back to link-local and the network looks
 * broken from the inside while the router itself is fine.
 *
 * **`dns` defaults to true and the other two flags to false**, so the three are
 * not written the same way: `dns` appears only when it is off, `managed` and
 * `other_config` only when they are on. A renderer treating all three alike
 * produces a document that compiles and says something else.
 */
static void an_advertise_block_round_trips(void)
{
	const char *text = "interface wan0 {\n\tconfig = \"dhcp6 pd\"\n}\n"
	    "interface lan0 {\n\tconfig = \"192.0.2.1/24\"\n"
	    "\tadvertise {\n\t\tbackend = \"radvd\"\n"
	    "\t\tprefixes = [\"@pd:wan0\", \"@pd:wan0/3\"]\n"
	    "\t\tmanaged = true\n\t\tother_config = true\n"
	    "\t\tdns = false\n\t\tlifetime = 1800\n\t}\n}\n";
	const char *plain = "interface wan0 {\n\tconfig = \"dhcp6 pd\"\n}\n"
	    "interface lan0 {\n\tconfig = \"192.0.2.1/24\"\n"
	    "\tadvertise { prefixes = [\"@pd:wan0\"] }\n}\n";
	char       *rendered;

	round_trips(text, "every field of an advertise block survives a round trip");
	rendered = rendering_of(text);
	check(holds(rendered, "backend = \"radvd\""),
	    "and the backend is the daemon the policy named, not the one beside it in the enum");
	check(holds(rendered, "prefixes = [\"@pd:wan0\", \"@pd:wan0/3\"]"),
	    "with both prefix references, the subnet selector kept on the one that has it");
	check(holds(rendered, "dns = false"),
	    "and `dns` is stated, because true is its default and absence would mean that");
	check(holds(rendered, "lifetime = 1800"), "and the lifetime it was given");
	free(rendered);

	/* The other direction: a policy at every default must write none of the
	 * three flags, or a profile acquires lines that say what it already said. */
	round_trips(plain, "a policy with nothing but a prefix survives one too");
	rendered = rendering_of(plain);
	check(!holds(rendered, "dns ="), "while `dns` at its default is left unsaid");
	check(!holds(rendered, "managed"), "and so is `managed`");
	check(!holds(rendered, "backend"), "and the backend, which is `auto`");
	check(holds(rendered, "advertise {"), "though the block itself is still written");
	free(rendered);
}

/*
 * The ingress shaper, undone -- which was three refusals for one setting.
 *
 * `lower.c` turns `qdisc { ingress_bandwidth = ... }` into an
 * `ingress_redirect` plus a synthesised `ifb` carrying the rate, and all three
 * of those were refused: the redirect, the `ifb`'s kind, and the `ifb`'s
 * ingress-metering qdisc. **So no machine shaping arriving traffic could save a
 * profile**, and the refusal's own comment said the rate was gone -- it is on
 * the `ifb`.
 *
 * The round trip is the whole assertion here: the rendering has to compile back
 * to the same document, which means the expansion must run again and produce
 * the same pair. A rendering that wrote the redirect would make a second `ifb`
 * and fail it.
 */
static void an_ingress_shaper_is_undone(void)
{
	const char *text = "device eth0 {\n\tqdisc {\n\t\tkind = \"cake\"\n"
	    "\t\tingress_bandwidth = \"50mbit\"\n\t}\n}\n";
	char       *rendered;

	round_trips(text, "a device shaping arriving traffic round trips");
	rendered = rendering_of(text);
	check(holds(rendered, "ingress_bandwidth = \"50mbit\""),
	    "and the rate comes back, read off the `ifb` the expansion put it on");
	check(lacks(rendered, "ifb-eth0"),
	    "while the device that expansion made is written nowhere at all");
	check(lacks(rendered, "ingress_redirect"),
	    "and the redirect is not written, which would synthesise a second one");
	free(rendered);

	/* Both rates at once, because they go to different places: the egress one
	 * stays on the device's own qdisc and the ingress one travels to the
	 * `ifb`. A renderer reading the wrong one would pass the case above. */
	round_trips("device eth0 {\n\tqdisc {\n\t\tkind = \"cake\"\n"
	    "\t\tbandwidth = \"100mbit\"\n\t\tingress_bandwidth = \"50mbit\"\n\t}\n}\n",
	    "a device shaping both directions round trips");
	rendered = rendering_of("device eth0 {\n\tqdisc {\n\t\tkind = \"cake\"\n"
	    "\t\tbandwidth = \"100mbit\"\n\t\tingress_bandwidth = \"50mbit\"\n\t}\n}\n");
	check(holds(rendered, "bandwidth = \"100mbit\"") &&
	    holds(rendered, "ingress_bandwidth = \"50mbit\""),
	    "with each rate on the key it came from, which are not interchangeable");
	free(rendered);
}

/*
 * And what the inversion must NOT do, which is the half that makes it safe.
 *
 * A redirect this build did not make is the operator's, and undoing it would
 * throw their `ifb` away. These arrive as documents rather than config files,
 * because the language has no `ingress_redirect` key -- which is exactly why
 * the refusals are kept for a document that came some other way.
 */
static void a_redirect_this_build_did_not_make_is_refused(void)
{
	char *missing_target = refusals_of_json(DOC(PLAIN_GLOBALS
	    "\"devices\":[{\"name\":\"eth0\",\"managed\":true,\"on_unmanage\":\"leave\","
	    "\"kind\":{\"kind\":\"physical\"},\"qdisc\":{\"kind\":\"cake\"},"
	    "\"ingress_redirect\":\"ifb-eth0\"}],"
	    NO_INTERFACES NO_NETWORKS));
	char *wrong_name = refusals_of_json(DOC(PLAIN_GLOBALS
	    "\"devices\":[{\"name\":\"eth0\",\"managed\":true,\"on_unmanage\":\"leave\","
	    "\"kind\":{\"kind\":\"physical\"},\"qdisc\":{\"kind\":\"cake\"},"
	    "\"ingress_redirect\":\"shaper0\"},"
	    "{\"name\":\"shaper0\",\"managed\":true,\"on_unmanage\":\"leave\","
	    "\"kind\":{\"kind\":\"ifb\"},\"qdisc\":{\"kind\":\"cake\","
	    "\"bandwidth_bits\":50000000,\"ingress\":true}}],"
	    NO_INTERFACES NO_NETWORKS));
	char *not_bare = refusals_of_json(DOC(PLAIN_GLOBALS
	    "\"devices\":[{\"name\":\"eth0\",\"managed\":true,\"on_unmanage\":\"leave\","
	    "\"kind\":{\"kind\":\"physical\"},\"qdisc\":{\"kind\":\"cake\"},"
	    "\"ingress_redirect\":\"ifb-eth0\"},"
	    "{\"name\":\"ifb-eth0\",\"managed\":true,\"on_unmanage\":\"leave\","
	    "\"mtu\":9000,\"kind\":{\"kind\":\"ifb\"},\"qdisc\":{\"kind\":\"cake\","
	    "\"bandwidth_bits\":50000000,\"ingress\":true}}],"
	    NO_INTERFACES NO_NETWORKS));

	check(holds(missing_target, "an ingress redirect to `ifb-eth0`"),
	    "a redirect onto a device that is not there is refused, and named");
	check(holds(wrong_name, "an ingress redirect to `shaper0`"),
	    "and so is one onto an ifb this build would not have named that");
	check(holds(not_bare, "an ingress redirect to `ifb-eth0`"),
	    "and one whose ifb carries a field of the operator's, which undoing would lose");
	free(missing_target);
	free(wrong_name);
	free(not_bare);
}

/*
 * A tunnel whose endpoint is the wrong address family, which the renderer used
 * to write and the compiler then refused.
 *
 * `lower_tunnel` requires `local` and `remote` to agree with the encapsulation
 * -- a v6 `remote` on an `ipip` is a link the kernel will not build -- so no
 * config file produces this and only a document that arrived as JSON can carry
 * it. The renderer wrote it anyway, and `ncfg profile save` then refused with
 * "would not reproduce what this machine is running", which says nothing about
 * the tunnel.
 *
 * **Found by round-tripping the plan suites' fixtures**, which is a corpus with
 * no reason to ask about rendering. The refusal asks `ncfg_tunnel_is_v6` rather
 * than restating the rule, so the two cannot drift.
 */
static void a_tunnel_of_the_wrong_family_is_refused(void)
{
	char *geneve = refusals_of_json(DOC(PLAIN_GLOBALS
	    "\"devices\":[{\"name\":\"gnv0\",\"managed\":true,\"on_unmanage\":\"leave\","
	    "\"kind\":{\"kind\":\"tunnel\",\"mode\":\"geneve\","
	    "\"remote\":\"2001:db8::9\"}}],"
	    NO_INTERFACES NO_NETWORKS));
	char *ip6gre = refusals_of_json(DOC(PLAIN_GLOBALS
	    "\"devices\":[{\"name\":\"gre6\",\"managed\":true,\"on_unmanage\":\"leave\","
	    "\"kind\":{\"kind\":\"tunnel\",\"mode\":\"ip6gre\","
	    "\"local\":\"192.0.2.1\"}}],"
	    NO_INTERFACES NO_NETWORKS));

	check(holds(geneve, "a geneve tunnel whose remote is the other address family"),
	    "a geneve tunnel with an IPv6 remote is refused rather than written");
	check(holds(ip6gre, "a ip6gre tunnel whose local is the other address family"),
	    "and an ip6gre with an IPv4 local, which is the same rule the other way");
	free(geneve);
	free(ip6gre);
}

/*
 * `guard`, whose loss is the most consequential in this file.
 *
 * The reason string is the whole value -- "eth0: nfs root" tells a reader what
 * to go and stop, where a bare flag would not -- and an interface saved without
 * its guard comes back as one netcfgd may take down. It was refused rather than
 * dropped, so no machine with a guard could save a profile; this is the same
 * fact with the refusal closed.
 */
static void a_guard_round_trips(void)
{
	const char *text = "interface eth0 {\n\tconfig = \"dhcp\"\n"
	    "\tguard = \"eth0: nfs root\"\n}\n";
	char       *rendered;

	round_trips(text, "an interface's guard round trips");
	rendered = rendering_of(text);
	check(holds(rendered, "guard = \"eth0: nfs root\""),
	    "and the reason is kept whole, because the reason is the whole value");
	free(rendered);

	/* A reason carrying the character the text ends with. Nothing validates a
	 * reason, so it is the renderer's to escape. */
	round_trips("interface eth0 {\n\tconfig = \"dhcp\"\n"
	    "\tguard = \"the \\\"lab\\\" uplink\"\n}\n",
	    "and so does one whose reason carries a quote");
}

/*
 * The two address sources that had no rendering, which completes the set.
 *
 * `@pd:` is how a machine gives itself an address out of a prefix its ISP
 * delegated, and is the other half of `advertise`: that block tells the hosts
 * behind the machine what their prefix is, and this gives the machine its own
 * address in it. A router has both, so either one refused was enough to stop it
 * saving a profile.
 *
 * The suffix defaults to `::1/64`, so the form that omits it and the form that
 * states it are the same document and only one of them is written.
 */
static void the_remaining_address_sources_round_trip(void)
{
	const char *full = "interface lan0 {\n\tconfig = \"@pd:wan0/2=::5/64\"\n}\n";
	const char *bare = "interface lan0 {\n\tconfig = \"@pd:wan0\"\n}\n";
	char       *rendered;

	round_trips(full, "a delegated address with a subnet and a suffix round trips");
	rendered = rendering_of(full);
	check(holds(rendered, "\"@pd:wan0/2=::5/64\""),
	    "and keeps the spelling the parser reads back, selector and suffix both");
	free(rendered);

	round_trips(bare, "a delegated address with neither round trips too");
	rendered = rendering_of(bare);
	check(holds(rendered, "\"@pd:wan0\""),
	    "with the default suffix left unwritten, as every other default here is");
	free(rendered);

	round_trips("interface eth0 {\n\tconfig = \"@pd:wan0=::1/64\"\n}\n",
	    "and so does one that states the default suffix, which is the same document");

	/* `reported` says netcfgd must not manage this interface's addresses and
	 * must report what it finds. Rendering it as anything else would turn an
	 * observation into an instruction. */
	round_trips("interface eth0 {\n\tconfig = \"reported\"\n}\n",
	    "a reported address source round trips");
	rendered = rendering_of("interface eth0 {\n\tconfig = \"reported\"\n}\n");
	check(holds(rendered, "config = \"reported\""),
	    "and is the bare word, which is all the language has for it");
	free(rendered);
}

/*
 * The four device kinds that had no rendering, which leaves only `ifb`.
 *
 * `ifb` stays refused because it is synthesised -- netcfgd makes one per
 * interface asking for `ingress_bandwidth` -- so rendering it would put a
 * derived device into a profile as though somebody had asked for it. That is a
 * property of the thing and not work left undone.
 *
 * **The spelling assertions are the ones that were paid for twice.** The
 * document says `wire_guard` and `open_vpn`; the language says `wireguard` and
 * `openvpn`, and a block written with the document's word cannot compile. This
 * used to be asserted of the refusal text and is now asserted of the rendering,
 * which is where it does more good.
 */
static void the_remaining_kinds_round_trip(void)
{
	const char *wireguard = "device wg0 {\n\twireguard {\n"
	    "\t\tprivate_key = \"@secret:wg\"\n\t\tlisten_port = 51820\n"
	    "\t\tfwmark = 42\n\t\tpeer \"office\" {\n"
	    "\t\t\tpublic_key = \"0000000000000000000000000000000000000000000=\"\n"
	    "\t\t\tpreshared_key = \"@secret:psk\"\n"
	    "\t\t\tendpoint = \"vpn.example:51820\"\n"
	    "\t\t\tallowed_ips = [\"0.0.0.0/0\", \"::/0\"]\n"
	    "\t\t\tkeepalive = 25\n\t\t}\n\t}\n}\n";
	const char *openvpn = "device vpn0 {\n\topenvpn {\n"
	    "\t\tconfig = \"/etc/openvpn/work.ovpn\"\n\t\tusername = \"u\"\n"
	    "\t\tpassword = \"@secret:vpn\"\n\t}\n}\n";
	const char *tunnel = "device gre0 {\n\ttunnel {\n\t\tmode = \"gretap\"\n"
	    "\t\tlocal = \"192.0.2.1\"\n\t\tremote = \"198.51.100.1\"\n"
	    "\t\tparent = \"eth0\"\n\t\tttl = 64\n\t\tkey = 42\n\t}\n}\n";
	char       *rendered;

	round_trips(wireguard, "a wireguard device and its peer round trip");
	rendered = rendering_of(wireguard);
	check(holds(rendered, "wireguard {") && lacks(rendered, "wire_guard"),
	    "and the block is the language's word, never the document's `wire_guard`");
	check(holds(rendered, "private_key = \"@secret:wg\""),
	    "with the private key written as a reference, which is all the model has");
	check(holds(rendered, "public_key = \"0000000000000000000000000000000000000000000=\""),
	    "and the peer's public key in the one spelling the model keeps octets for");
	check(holds(rendered, "allowed_ips = [\"0.0.0.0/0\", \"::/0\"]"),
	    "and every allowed prefix, not just the first");
	free(rendered);

	round_trips(openvpn, "an openvpn tunnel round trips");
	rendered = rendering_of(openvpn);
	check(holds(rendered, "openvpn {") && lacks(rendered, "open_vpn"),
	    "and is spelled the language's way too, which is the same pair of words");
	check(holds(rendered, "password = \"@secret:vpn\""),
	    "with the password as a reference and never as a value");
	/* `config`/`file` and `username`/`user` are both accepted, so the round
	 * trip cannot tell the two spellings apart. Assert the canonical one. */
	check(holds(rendered, "config = \"/etc/openvpn/work.ovpn\""),
	    "and `config` rather than `file`, which the parser also takes");
	check(holds(rendered, "username = \"u\""),
	    "and `username` rather than `user`, for the same reason");
	free(rendered);
	round_trips("device vpn0 {\n\topenvpn {\n"
	    "\t\tconfig = \"/etc/openvpn/work.ovpn\"\n\t}\n}\n",
	    "and so does one with no login, which is the commoner shape");

	round_trips(tunnel, "a tunnel round trips with every key it has");
	rendered = rendering_of(tunnel);
	check(holds(rendered, "mode = \"gretap\""),
	    "and the encapsulation is the one named, not its neighbour in the table");
	check(holds(rendered, "ttl = 64"), "with the ttl it was given");
	/* Three more pairs the parser accepts either of: `mode`/`kind` above,
	 * `parent`/`dev`, and `key`/`vni`. */
	check(holds(rendered, "parent = \"eth0\""),
	    "and `parent` rather than `dev`, which would round trip just as well");
	check(holds(rendered, "key = 42"), "and `key` rather than `vni`");
	free(rendered);

	/* The mode is the block's name rather than a key, so a tap device written
	 * as `tun { mode = "tap" }` would not compile at all. */
	round_trips("device tap0 {\n\ttap {\n\t\towner = \"bob\"\n"
	    "\t\tgroup = \"vpn\"\n\t}\n}\n", "a tap device round trips");
	rendered = rendering_of("device tap0 {\n\ttap {\n\t\towner = \"bob\"\n\t}\n}\n");
	check(holds(rendered, "tap {"), "and is written as `tap`, which is where its mode lives");
	free(rendered);
	round_trips("device tun0 {\n\ttun {\n\t\towner = \"bob\"\n\t}\n}\n",
	    "and a tun device round trips as `tun`");
	rendered = rendering_of("device tun0 {\n\ttun {\n\t\towner = \"bob\"\n\t}\n}\n");
	check(holds(rendered, "tun {") && lacks(rendered, "tap"),
	    "which is a different block from the one above, not a key apart");
	free(rendered);
}

/*
 * Per-port VLAN membership, which was being dropped in silence.
 *
 * It was neither rendered nor refused, so `ncfg profile save` wrote a switch
 * port's configuration back without its VLANs and reported success -- and
 * nothing caught it because no round trip had ever carried a `vlans` key,
 * which is a real gate over an absent case. The consequence is not cosmetic: a
 * port whose PVID is lost takes untagged ingress to a different VLAN than it
 * did before.
 */
static void per_port_vlans_round_trip(void)
{
	const char *text = "device eth0 {\n\tvlans = [\"10 pvid untagged\", \"20\", "
	    "\"30 untagged\"]\n}\ninterface eth0 {\n\tconfig = \"192.0.2.10/24\"\n}\n";
	char       *rendered = rendering_of(text);

	round_trips(text, "a switch port's VLAN membership round trips, PVID and tagging included");
	check(holds(rendered, "\tvlans = [\"10 pvid untagged\", \"20\", \"30 untagged\"]\n"),
	    "and `tagged`, being the parser's default, is not written back as noise");
	free(rendered);
}

/*
 * **Every PSK generation, because the default is the permissive one.** `proto`
 * was dropped here until the audit, and it is the one wifi field whose loss
 * weakens a network: the default is WPA2 and WPA3 together, so a
 * `proto = "wpa3"` network came back accepting WPA2 -- a downgrade the
 * operator had deliberately excluded.
 *
 * **How far the spelling check looks.** The round trip cannot tell a written
 * default from an absent one, so the text is asserted beside it: the key is
 * written for the two generations that are not the default, not written for
 * the one that is, and the document's `wpa2_wpa3` -- which the parser does not
 * read -- never appears. What no case here can reach is the renderer's word
 * for the combined generation, because that value *is* the default and a
 * default is not written. Sabotaging the table's third entry does not turn
 * this red, and saying so is better than leaving a reader to assume it would;
 * `render_link.c` carries the same note.
 */
static void every_psk_generation_round_trips(void)
{
	static const char *const generations[] = { "wpa2", "wpa3", "wpa2+wpa3" };
	size_t i;
	int    every = 1;

	for (i = 0; i < sizeof(generations) / sizeof(generations[0]); i++) {
		char  text[256];
		char  wanted[64];
		char *rendered;

		snprintf(text, sizeof(text),
		    "network \"H\" {\n\twifi { psk = \"@secret:h\"; proto = \"%s\" }\n}\n",
		    generations[i]);
		round_trips(text, "a PSK generation round trips");
		rendered = rendering_of(text);
		if (i + 1u == sizeof(generations) / sizeof(generations[0])) {
			every = every && lacks(rendered, "proto");
		} else {
			snprintf(wanted, sizeof(wanted), "\t\tproto = \"%s\"\n", generations[i]);
			every = every && holds(rendered, wanted);
		}
		every = every && lacks(rendered, "wpa2_wpa3");
		free(rendered);
	}
	check(every, "and each is written with the language's spelling, never the document's");
}

/*
 * **An empty `dns { }` is a statement, not an absence.** On an interface or a
 * network it says "use the nameservers this network hands out" -- 0007 makes a
 * per-interface policy a scope in its own right -- so the block being present
 * and empty differs from its being absent, and a profile that lost it would
 * come back ignoring the lease's resolvers. Writing nothing when every field
 * is at its default is right for `global` and was wrong for these two.
 */
static void an_empty_dns_block_survives_where_it_means_something(void)
{
	char *in_globals;

	round_trips("interface eth0 {\n\tconfig = \"dhcp\"\n\tdns { }\n}\n",
	    "an empty dns block on an interface survives");
	round_trips("network \"H\" {\n\twifi { open = true }\n\tdns { }\n}\n",
	    "and on a network, where it says the same thing");

	in_globals = rendering_of("interface eth0 {\n\tconfig = \"dhcp\"\n}\n");
	check(lacks(in_globals, "dns"),
	    "and is not invented in `global`, where the block carries no meaning of its own");
	free(in_globals);
}

/*
 * The per-interface keys a laptop's profile is actually about.
 *
 * `preference` is which uplink wins and `probe` is how the link is judged to
 * be working -- the two settings whose whole purpose is to differ between the
 * office and home, and so the two a profile most needs to be able to save.
 * Both were refused.
 */
static void the_interface_keys_round_trip(void)
{
	round_trips("interface eth0 {\n\tconfig = \"dhcp\"\n\tpreference = 100\n\tnat = true\n"
	    "\tipv6_token = \"::5\"\n\tprobe {\n\t\tcommand = \"/usr/bin/ping\"\n"
	    "\t\targs = [\"-c\", \"1\", \"-I\", \"eth0\", \"198.51.100.1\"]\n"
	    "\t\tinterval = 15\n\t\ttimeout = 3\n\t\tdown_after = 5\n\t\tup_after = 3\n"
	    "\t\thold_down = 60\n\t}\n}\n",
	    "an interface's preference, nat, token and probe round trip");
}

/* A probe with nothing but its command, so the defaults stay unwritten and the
 * block still compiles -- `command` is unconditional because the parser
 * refuses a probe without one. */
static void a_bare_probe_round_trips(void)
{
	const char *text = "interface eth1 {\n\tconfig = \"dhcp\"\n"
	    "\tprobe { command = \"/usr/bin/true\" }\n}\n";
	char       *rendered = rendering_of(text);

	round_trips(text, "a probe with nothing but its command round trips");
	check(holds(rendered, "\tprobe {\n\t\tcommand = \"/usr/bin/true\"\n\t}\n"),
	    "and writes its command and nothing else");
	free(rendered);
}

/*
 * 802.1X on a wired port, which shares its eight keys with a wireless
 * network's EAP -- the parser shares `WifiKeys` between them, so the renderer
 * shares one function for the same reason.
 *
 * `domain_suffix_match` is here because the Rust dropped it in silence and it
 * weakens a network: `ca_cert` alone answers "who signed this", not "who is
 * this", so without it any certificate the pinned issuer signed is accepted
 * (0206).
 */
static void a_wired_dot1x_port_round_trips(void)
{
	const char *text = "interface eth2 {\n\tconfig = \"dhcp\"\n\tdot1x {\n\t\teap = \"tls\"\n"
	    "\t\tidentity = \"desk.corp\"\n"
	    "\t\tdomain_suffix_match = \"radius.example.com\"\n"
	    "\t\tca_cert = \"/etc/ssl/certs/corp.pem\"\n"
	    "\t\tclient_cert = \"/etc/ssl/certs/desk.pem\"\n"
	    "\t\tprivate_key = \"@secret:desk-key\"\n\t}\n}\n";
	char       *rendered = rendering_of(text);

	round_trips(text, "a wired 802.1X port round trips, domain_suffix_match included");
	check(holds(rendered, "\t\tdomain_suffix_match = \"radius.example.com\"\n"),
	    "and the server name its certificate must carry is in the text");
	free(rendered);
}

/*
 * A stored certificate and a path are told apart by the `@secret:` prefix
 * alone, so rendering one as the other is a silent corruption rather than a
 * compile error: stored content written bare comes back as a filename that
 * does not exist, and a path written through the secret spelling comes back as
 * a lookup that fails. The round trip is what catches it.
 */
static void a_stored_certificate_stays_stored(void)
{
	const char *text = "network \"Corp\" {\n\twifi {\n\t\teap = \"tls\"\n"
	    "\t\tidentity = \"laptop.corp\"\n\t\tca_cert = \"/etc/ssl/certs/corp.pem\"\n"
	    "\t\tprivate_key = \"@secret:laptop-key\"\n\t}\n}\n";
	char       *rendered = rendering_of(text);

	round_trips(text, "a stored key and a certificate path round trip as different things");
	check(holds(rendered, "\t\tca_cert = \"/etc/ssl/certs/corp.pem\"\n"),
	    "a certificate that is a path is written as one");
	check(holds(rendered, "\t\tprivate_key = \"@secret:laptop-key\"\n"),
	    "and one netcfgd holds is written as a reference, never as a filename");
	free(rendered);
}

/* The tunnelled methods with everything optional set, and EAP-PWD, which
 * carries neither a certificate nor a phase 2 -- so the optional keys are
 * proved genuinely optional rather than written empty. */
static void the_enterprise_networks_round_trip(void)
{
	char *pwd;

	round_trips("network \"Campus\" {\n\twifi {\n\t\teap = \"peap\"\n"
	    "\t\tidentity = \"someone@example.ac.uk\"\n"
	    "\t\tanonymous_identity = \"anonymous@example.ac.uk\"\n"
	    "\t\tpassword = \"@secret:campus\"\n"
	    "\t\tca_cert = \"/etc/ssl/certs/campus.pem\"\n\t\tphase2 = \"mschapv2\"\n\t}\n}\n",
	    "a tunnelled enterprise network round trips with every key it set");
	round_trips("network \"Corp\" {\n\twifi {\n\t\teap = \"tls\"\n"
	    "\t\tidentity = \"laptop.corp\"\n\t\tca_cert = \"/etc/ssl/certs/corp.pem\"\n"
	    "\t\tclient_cert = \"/etc/ssl/certs/laptop.pem\"\n"
	    "\t\tprivate_key = \"@secret:laptop-key\"\n\t}\n}\n",
	    "and so does one that presents a certificate instead of a password");
	round_trips("network \"Pwd\" {\n\twifi {\n\t\teap = \"pwd\"\n\t\tidentity = \"someone\"\n"
	    "\t\tpassword = \"@secret:pwd\"\n\t}\n}\n",
	    "and EAP-PWD, which carries neither a certificate nor a phase 2");

	pwd = rendering_of("network \"Pwd\" {\n\twifi {\n\t\teap = \"pwd\"\n"
	    "\t\tidentity = \"someone\"\n\t\tpassword = \"@secret:pwd\"\n\t}\n}\n");
	check(lacks(pwd, "ca_cert") && lacks(pwd, "client_cert") && lacks(pwd, "phase2"),
	    "and acquires no empty certificate lines that say nothing and invite an answer");
	free(pwd);
}

/* A name that is not a bare word, and one with a quote in it. The escape is
 * what stops a rendered profile ending a string early and taking every other
 * block in the file with it -- the loader compiles the directory as one
 * document. */
static void a_name_needing_escapes_round_trips(void)
{
	round_trips("network \"say \\\"hello\\\"\" {\n\twifi {\n\t\topen = true\n\t}\n}\n",
	    "a quote in a name survives, so the string does not end early");
}

/*
 * The topology kinds, each with every key it has set.
 *
 * One document rather than one per kind, because the thing most likely to go
 * wrong is a block written at the wrong nesting or without its closing brace,
 * and that breaks the *next* block rather than its own.
 */
static void the_link_kinds_round_trip(void)
{
	round_trips("device br0 {\n\tbridge {\n\t\tmembers = [\"eth0\", \"eth1\"]\n"
	    "\t\tstp = true\n\t\tforward_delay = 4\n\t\thello_time = 2\n"
	    "\t\tageing_time = 300\n\t\tpriority = 4096\n\t\tvlan_filtering = true\n\t}\n}\n"
	    "device bond0 {\n\tbond {\n\t\tmembers = [\"eth2\", \"eth3\"]\n"
	    "\t\tmode = \"802.3ad\"\n\t\tmiimon = 100\n\t}\n}\n"
	    "device vlan10 {\n\tvlan { parent = \"eth0\"; id = 10 }\n}\n"
	    "device vx0 {\n\tvxlan { id = 42; parent = \"eth0\" }\n}\n"
	    "device mgmt {\n\tvrf { table = 100 }\n}\n"
	    "device mv0 {\n\tmacvlan { parent = \"eth0\"; mode = \"bridge\" }\n}\n"
	    "interface br0 {\n\tconfig = \"192.0.2.10/24\"\n}\n"
	    "interface bond0 {\n\tconfig = \"dhcp\"\n}\n",
	    "the topology kinds round trip with every key they have set");

	/*
	 * The same kinds with no optional key, which is the case nobody writes --
	 * **and the one a renderer gets wrong in the other direction.** A model
	 * default and a language default are not the same fact: `active-backup` is
	 * the model's default for a bond, so the rule used everywhere else here
	 * (write a value only when it differs) would omit `mode` from a bond that
	 * used it -- and the parser *requires* `mode`, so that profile would not
	 * compile at all.
	 */
	round_trips("device br1 {\n\tbridge { members = \"eth4\" }\n}\n"
	    "device bond1 {\n\tbond { members = \"eth5\"; mode = \"active-backup\" }\n}\n"
	    "device vlan20 {\n\tvlan { parent = \"eth0\"; id = 20 }\n}\n"
	    "device mv1 {\n\tmacvlan { parent = \"eth0\"; mode = \"private\" }\n}\n"
	    "interface br1 { config = \"null\" }\n",
	    "and so do they with nothing optional set, which is the harder direction");
}

static void a_bond_at_its_default_mode_still_writes_the_key(void)
{
	char *rendered = rendering_of("device bond1 {\n"
	    "\tbond { members = \"eth5\"; mode = \"active-backup\" }\n}\n");

	check(holds(rendered, "\t\tmode = \"active-backup\"\n"),
	    "a bond writes its mode even at the model's default, because the parser demands it");
	check(holds(rendered, "\t\tmembers = \"eth5\"\n"),
	    "and a single member is a bare value rather than a list of one");
	free(rendered);
}

/*
 * A PPPoE session, with and without the optional provider names.
 *
 * Refused wholesale until the audit, so `ncfg profile save` failed outright on
 * any machine whose WAN is DSL or fibre -- not the WAN saved wrongly, the whole
 * save refused. The password is asserted as a reference in both provider
 * spellings, because the one thing a snapshot must never do is carry the
 * value, and `@secret:` and `@secret:keyring:` are references to different
 * stores.
 */
static void a_pppoe_session_round_trips(void)
{
	const char *full = "device ppp0 {\n\tpppoe {\n\t\tparent = \"e0\"\n"
	    "\t\tusername = \"u\"\n\t\tpassword = \"@secret:keyring:p\"\n"
	    "\t\tservice = \"svc\"\n\t\tac = \"conc\"\n\t}\n}\n";
	char       *bare;
	char       *rendered;

	round_trips("device ppp0 {\n\tpppoe {\n\t\tparent = \"e0\"\n\t\tusername = \"u\"\n"
	    "\t\tpassword = \"@secret:p\"\n\t}\n}\n", "a pppoe session round trips");
	round_trips(full, "and so does one naming a service, a concentrator and another store");

	bare = rendering_of("device ppp0 {\n\tpppoe {\n\t\tparent = \"e0\"\n"
	    "\t\tusername = \"u\"\n\t\tpassword = \"@secret:p\"\n\t}\n}\n");
	rendered = rendering_of(full);
	check(holds(bare, "\t\tpassword = \"@secret:p\"\n"),
	    "the password is written as a reference and never as a value");
	check(holds(rendered, "\t\tpassword = \"@secret:keyring:p\"\n"),
	    "and a different store is a different reference, not the same one");
	free(bare);
	free(rendered);
}

/*
 * Every Bluetooth profile, and both sides of `autoconnect` (0149).
 *
 * The block was refused wholesale until the audit, so `ncfg profile save`
 * could not save a machine with headphones written down -- which is exactly a
 * laptop, which is what profiles are for. Five profiles is a closed set worth
 * walking rather than sampling: the spellings are BlueZ's and hyphenated,
 * which is the kind of detail a renderer gets subtly wrong.
 */
static void every_bluetooth_profile_round_trips(void)
{
	static const char *const profiles[] = { "a2dp-sink", "a2dp-source", "hfp", "pan", "nap" };
	size_t i;
	int    every = 1;
	char  *off;

	for (i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++) {
		char  text[256];
		char  wanted[64];
		char *rendered;

		snprintf(text, sizeof(text), "bluetooth \"d\" {\n"
		    "\taddress = \"AA:BB:CC:DD:EE:FF\"\n\tprofile = \"%s\"\n}\n", profiles[i]);
		round_trips(text, "a Bluetooth device round trips");
		rendered = rendering_of(text);
		snprintf(wanted, sizeof(wanted), "\tprofile = \"%s\"\n", profiles[i]);
		every = every && holds(rendered, wanted);
		free(rendered);
	}
	check(every, "and every profile keeps BlueZ's own hyphenated spelling");

	round_trips("bluetooth \"d\" {\n\taddress = \"AA:BB:CC:DD:EE:FF\"\n\tprofile = \"pan\"\n"
	    "\tautoconnect = false\n}\n", "and a device that does not autoconnect round trips");
	off = rendering_of("bluetooth \"d\" {\n\taddress = \"AA:BB:CC:DD:EE:FF\"\n"
	    "\tprofile = \"pan\"\n\tautoconnect = false\n}\n");
	check(holds(off, "\tautoconnect = false\n"),
	    "with autoconnect written only because it is off, which is not its default");
	free(off);
}

/*
 * A linkset, whose one interesting property is that the order survives.
 *
 * A snapshot is what `ncfg profile save` writes, so a set rendered with its
 * members in some other order would describe a machine that fails over the
 * other way round -- and nothing downstream could tell.
 */
static void a_linkset_round_trips_in_its_own_order(void)
{
	const char *text = "interface eth0 {\n\tconfig = \"dhcp\"\n}\n"
	    "interface wwan0 {\n\tconfig = \"dhcp\"\n}\n"
	    "linkset \"uplink\" {\n\tmembers = [\"wwan0\", \"eth0\"]\n}\n";
	char       *rendered = rendering_of(text);

	round_trips(text, "a linkset round trips in its own order");
	check(holds(rendered, "\tmembers = [\"wwan0\", \"eth0\"]\n"),
	    "and the ranking is neither sorted nor folded to a scalar");
	free(rendered);
}

/* A modem's SIM order and APN (0150), and the ordinary single-SIM board, where
 * the list is a list of one rather than a different shape. */
static void a_modem_policy_round_trips(void)
{
	char *one;

	round_trips("device wwan0 {\n\tmodem {\n\t\tsim = [\"esim\", \"socket\"]\n"
	    "\t\tapn = \"im.cxn\"\n\t}\n}\n", "a modem's SIM order and APN round trip");
	round_trips("device wwan0 { modem { sim = \"socket\" } }\n",
	    "and so does a single-SIM board");

	one = rendering_of("device wwan0 { modem { sim = \"socket\" } }\n");
	check(holds(one, "\t\tsim = \"socket\"\n"),
	    "with one source written bare rather than as a list of one");
	free(one);
}

/* The adapter's settings round-trip from the device block 0155 moved them to.
 * Worth its own case because a field that moved type and was not taught to the
 * renderer is silently dropped from every saved profile. */
static void a_devices_hardware_settings_round_trip(void)
{
	round_trips("device eth0 {\n\tmtu = 9000\n\tmac = \"02:00:00:00:00:01\"\n}\n"
	    "interface eth0 {\n\tconfig = \"dhcp\"\n}\n",
	    "a device's MTU and MAC round trip from the block they moved to");
}

static void the_globals_round_trip(void)
{
	char *rendered;

	round_trips("global {\n\thostname = \"host.example\"\n\tconfirm = 90\n"
	    "\ton_drift = \"reconcile\"\n"
	    "\tdns {\n\t\tmode = \"resolved\"\n"
	    "\t\tservers = [\"192.0.2.53\", \"2001:db8::53\"]\n"
	    "\t\tsearch = [\"example.invalid\"]\n\t}\n"
	    "\tcontrol {\n\t\tobserve = \"any\"\n\t\twifi = \"group:netdev\"\n"
	    "\t\tadmin = \"root\"\n\t}\n}\n",
	    "the globals round trip");
	/* The off switch survives a save: a profile that turns networking off is
	 * exactly the profile somebody most needs to come back unchanged. */
	round_trips("global {\n\tnetworking = \"off\"\n}\ninterface eth0 {\n"
	    "\tconfig = \"dhcp\"\n}\n", "and so does a profile that turns networking off");

	rendered = rendering_of("global {\n\ton_drift = \"reconcile\"\n\tconfirm = 90\n}\n");
	/* `reconcile` is the document's default and is *not* C's zero value, so a
	 * renderer comparing against zero would write it. */
	check(lacks(rendered, "on_drift") && holds(rendered, "\tconfirm = 90\n"),
	    "and `reconcile`, being the default, is left unwritten");
	free(rendered);
}

/*
 * `remote.agent` and `connectivity`, both of which the Rust this ports left
 * out of the text *and* out of the refusal list.
 *
 * `agent` says who on this machine may hold the other end of the remote socket
 * and decides that socket's mode and group (0159); `connectivity.ignore`
 * replaces the default list, which is how a wired-only machine with no network
 * came to report itself connected by naming `docker0` (0243). Both are
 * reachable from the configuration language, so neither had any business being
 * dropped.
 */
static void the_globals_two_silent_drops_round_trip(void)
{
	const char *text = "global {\n\tremote {\n\t\tobserve = true\n\t\twifi = false\n"
	    "\t\tadmin = false\n\t\tagent = \"group:netcfgd-agent\"\n\t}\n"
	    "\tconnectivity {\n\t\trequires = \"probe\"\n\t\tignore = [\"docker0\"]\n\t}\n}\n";
	char       *rendered = rendering_of(text);

	round_trips(text, "the remote agent and the connectivity policy round trip");
	check(holds(rendered, "\t\tagent = \"group:netcfgd-agent\"\n"),
	    "and who may act as the agent is in the text");
	check(holds(rendered, "\tconnectivity {\n\t\trequires = \"probe\"\n"
	    "\t\tignore = \"docker0\"\n\t}\n"),
	    "and so is what counts as connected and what is ignored");
	free(rendered);
}

/*
 * A lease's own settings, which the Rust wrote as a bare word and dropped.
 *
 * `slaac privacy` is the one worth naming on its own: losing it puts a machine
 * back on stable addresses, which is a privacy property the operator chose and
 * which nothing downstream would report.
 */
static void a_leases_own_settings_round_trip(void)
{
	const char *text = "interface eth0 {\n\tconfig = [\"slaac privacy prefer_temporary\", "
	    "\"dhcp6 pd_hint 2001:db8:: pd_length 56\"]\n}\n";
	char       *rendered = rendering_of(text);

	round_trips(text, "a slaac privacy setting and a delegation request round trip");
	check(holds(rendered, "\"slaac privacy prefer_temporary\""),
	    "and the modifiers are written in the words the parser reads back");
	check(holds(rendered, "\"dhcp6 pd pd_hint 2001:db8:: pd_length 56\""),
	    "with `pd` written out, which each of the other two implies");
	free(rendered);
}

/* ------------------------------------------------------------------------ *
 * The refusals, which are the other half of the contract
 * ------------------------------------------------------------------------ */

/*
 * A sink that turns a hook body into a reference, so the hooks case can reach
 * the renderer at all.
 *
 * `ncfg_hook_sink_refusing` refuses every hook, which is right for a caller
 * with nowhere to put them and useless here: the case is about the *renderer*
 * refusing a hook the compiler accepted, so the compile has to succeed first.
 * The path and the hash are the shape `lower.h` describes and nothing is
 * written to disk, which is that module's whole point.
 */
static int record_hook(void *state, int phase, const char *owner, const char *body,
    size_t body_length, ncfg_hook_ref_t *out, char *err, size_t err_size)
{
	char path[256];

	(void)state;
	(void)body;
	(void)body_length;
	(void)err;
	(void)err_size;
	snprintf(path, sizeof(path), "/run/netcfgd/hooks/%s.%s", owner ? owner : "x",
	    ncfg_hook_phase_name((ncfg_hook_phase_t)phase));
	out->phase = phase;
	out->path = strdup(path);
	out->sha256 = strdup("0000000000000000000000000000000000000000000000000000000000000000");
	return out->path != NULL && out->sha256 != NULL;
}

static char *refusals_with_hooks(const char *text)
{
	static const ncfg_hook_sink_t sink = { record_hook, NULL };
	char                          message[NCFG_ERROR_MAX];
	ncfg_ast_file_t              *file = NULL;
	ncfg_source_t                 source;
	ncfg_lower_diags_t            diags = { 0 };
	ncfg_document_t              *document;
	char                         *out = NULL;

	message[0] = '\0';
	if (!ncfg_parse(text, strlen(text), &file, NULL, message, sizeof(message))) {
		printf("  a case's own configuration did not parse: %s\n", message);
		return NULL;
	}
	source.name = "test.conf";
	source.file = file;
	document = ncfg_compile(&source, 1, &sink, &diags, message, sizeof(message));
	if (!document) {
		printf("  a case's own configuration did not compile: %s\n", message);
	} else {
		out = refusals_for(document);
	}
	ncfg_document_free(document);
	ncfg_lower_diags_free(&diags);
	ncfg_ast_file_free(file);
	return out;
}

/*
 * What is still refused and reachable from a config file, which is hooks alone.
 *
 * `wireguard` and `openvpn` were asserted here as refused by name. Both render
 * now, and the property that mattered about those refusals -- that the word is
 * the language's `wireguard` and never the document's `wire_guard`, the pair
 * this project has shipped wrong twice -- moved to
 * `the_remaining_kinds_round_trip`, where it is asserted of the rendered block
 * instead. That is the stronger place for it: a refusal naming the right word
 * helps an operator write the block by hand, and a rendering spelled the right
 * way means they do not have to.
 */
static void what_cannot_be_rendered_is_named(void)
{
	char *hooks = refusals_with_hooks("interface eth0 {\n\tconfig = \"dhcp\"\n"
	    "\tpost_up {\n\t\techo hello\n\t}\n}\n");

	check(holds(hooks, "interface eth0: hooks"),
	    "an interface's hooks are refused rather than dropped");
	free(hooks);
}

/*
 * The refusals that cannot be reached from a config file at all.
 *
 * These are the model fields the configuration language has no words for, so
 * only a document that arrived some other way -- over the socket, or off disk
 * -- can carry one. They are kept because this takes a document rather than a
 * file: a refusal that cannot fire costs nothing, and a missing one costs a
 * silent drop.
 */
static void the_refusals_no_config_file_can_reach(void)
{
	char *dns = refusals_of_json(DOC("\"globals\":{\"dns\":{\"mode\":\"resolved\","
	    "\"servers\":[{\"addr\":\"192.0.2.53\",\"port\":853,\"sni\":\"dns.example\"}],"
	    "\"options\":[\"ndots:2\"],\"dnssec\":\"yes\",\"transport\":\"tls\"}},"
	    NO_DEVICES NO_INTERFACES NO_NETWORKS));
	char *device = refusals_of_json(DOC(PLAIN_GLOBALS "\"devices\":[{\"name\":\"eth0\","
	    "\"match\":{\"driver\":\"e1000e\"},\"ingress_redirect\":\"ifb-eth0\","
	    "\"qdisc\":{\"kind\":\"cake\"}}]," NO_INTERFACES NO_NETWORKS));
	char *lease = refusals_of_json(DOC(PLAIN_GLOBALS NO_DEVICES
	    "\"interfaces\":[{\"name\":\"eth0\",\"addressing\":[{\"source\":\"dhcp4\","
	    "\"client_id\":\"01:02\",\"backend\":\"dhcpcd\",\"metric\":100}]}],"
	    NO_NETWORKS));

	check(holds(dns, "global: dns options") && holds(dns, "global: dnssec") &&
	    holds(dns, "global: dns transport") &&
	    holds(dns, "global: a dns server with a port or sni"),
	    "a DNS scope's four unwritable facts are each named");
	/* The qdisc was named here too. It renders now -- this fixture's `cake`
	 * carries no rate and no ingress flag, so it comes back as the short form
	 * -- and only what is still unrenderable is asserted.
	 *
	 * The redirect's refusal is specific now rather than blanket: this fixture
	 * points at `ifb-eth0` and declares no such device, so the shaper cannot
	 * be undone and the message says which device is missing. A pair this
	 * build would have made is undone instead, which
	 * `an_ingress_shaper_is_undone` covers. */
	check(holds(device, "device eth0: a match block") &&
	    holds(device, "device eth0: an ingress redirect to `ifb-eth0`") &&
	    lacks(device, "device eth0: qdisc"),
	    "and a device's match, and a redirect onto a device that is not there");
	check(holds(lease, "interface eth0: a dhcp lease's client id") &&
	    holds(lease, "interface eth0: a dhcp lease's backend") &&
	    holds(lease, "interface eth0: a dhcp lease's metric"),
	    "and a dhcp lease's settings, which `dhcp` takes no modifiers for");
	free(dns);
	free(device);
	free(lease);
}

/*
 * A block the base defines is written as `override`, and one it does not is
 * not: `override` with nothing to override is a compile error, so getting this
 * wrong makes a profile that cannot load at all.
 */
static void override_is_written_only_where_the_caller_says(void)
{
	const char         *text = "interface eth0 {\n\tconfig = \"dhcp\"\n}\n";
	char                message[NCFG_ERROR_MAX];
	ncfg_document_t    *document = compiled(text, "a case's own configuration");
	ncfg_overrides_t    overrides;
	ncfg_buf_t          buf;
	ncfg_unrenderable_t missing;
	char               *plain;

	if (!document) {
		check(0, "override is written only where the caller says");
		return;
	}
	plain = render_document(document);
	check(holds(plain, "\ninterface eth0 {"),
	    "a block the base does not define is written plainly");
	free(plain);

	ncfg_overrides_init(&overrides);
	check(ncfg_overrides_add(&overrides, "interface", "eth0", message, sizeof(message)),
	    "the caller can say which blocks the base already defines");
	check(ncfg_overrides_has(&overrides, "interface", "eth0") &&
	    !ncfg_overrides_has(&overrides, "interface", "eth1") &&
	    !ncfg_overrides_has(&overrides, "device", "eth0"),
	    "and the key is kind and name together, so neither alone matches");

	ncfg_buf_init(&buf, 0);
	ncfg_unrenderable_init(&missing);
	if (ncfg_render(document, &overrides, &buf, &missing, message, sizeof(message))) {
		check(holds(ncfg_buf_text(&buf), "\noverride interface eth0 {"),
		    "and a block it does define is written as an override");
	} else {
		check(0, "and a block it does define is written as an override");
	}
	ncfg_unrenderable_free(&missing);
	ncfg_buf_free(&buf);
	ncfg_overrides_free(&overrides);
	ncfg_document_free(document);
}

/*
 * A caller with nowhere to put the refusals is refused.
 *
 * This is the module's discipline pointed at its own API: every named defect
 * here was a *silent* drop, and a `missing` of NULL is the same drop one level
 * up -- a caller that renders a document and never learns what was left out.
 */
static void a_caller_that_discards_the_refusals_is_refused(void)
{
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document = compiled("interface eth0 {\n\tconfig = \"dhcp\"\n}\n",
	    "a case's own configuration");
	ncfg_buf_t       buf;

	if (!document) {
		check(0, "a render with nowhere to report refusals is refused");
		return;
	}
	ncfg_buf_init(&buf, 0);
	message[0] = '\0';
	check(!ncfg_render(document, NULL, &buf, NULL, message, sizeof(message)) &&
	    strstr(message, "could not render") != NULL,
	    "a render with nowhere to report refusals is refused, and says why");
	ncfg_buf_free(&buf);
	ncfg_document_free(document);
}

int main(int argc, char **argv)
{
	render_the_witness(argc, argv);

	the_unmanage_policy_defects();
	the_wireless_network_drops();
	a_network_named_by_its_access_points();
	a_label_the_lexer_cannot_read_bare();
	the_hostname_policy_round_trips();
	a_radios_own_policy_round_trips();
	a_routing_rule_round_trips();
	an_access_point_round_trips();
	ethtool_and_qdisc_round_trip();
	a_default_roam_block_survives();

	the_ordinary_interfaces();
	a_routes_source_and_onlink_round_trip();
	an_address_modifiers_round_trip();
	an_advertise_block_round_trips();
	an_ingress_shaper_is_undone();
	a_redirect_this_build_did_not_make_is_refused();
	a_tunnel_of_the_wrong_family_is_refused();
	a_guard_round_trips();
	the_remaining_address_sources_round_trip();
	the_remaining_kinds_round_trip();
	per_port_vlans_round_trip();
	every_psk_generation_round_trips();
	an_empty_dns_block_survives_where_it_means_something();
	the_interface_keys_round_trip();
	a_bare_probe_round_trips();
	a_wired_dot1x_port_round_trips();
	a_stored_certificate_stays_stored();
	the_enterprise_networks_round_trip();
	a_name_needing_escapes_round_trips();
	the_link_kinds_round_trip();
	a_bond_at_its_default_mode_still_writes_the_key();
	a_pppoe_session_round_trips();
	every_bluetooth_profile_round_trips();
	a_linkset_round_trips_in_its_own_order();
	a_modem_policy_round_trips();
	a_devices_hardware_settings_round_trip();
	the_globals_round_trip();
	the_globals_two_silent_drops_round_trip();
	a_leases_own_settings_round_trip();

	what_cannot_be_rendered_is_named();
	the_refusals_no_config_file_can_reach();
	override_is_written_only_where_the_caller_says();
	a_caller_that_discards_the_refusals_is_refused();

	if (failures) {
		printf("render: %d check(s) failed\n", failures);
		return 1;
	}
	printf("render: every check passed\n");
	return 0;
}
