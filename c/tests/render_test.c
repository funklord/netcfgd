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
#include "ncfg/config.h"
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
 * Compile, serialise, read back, render -- which is the path, not a model of
 * it: `host/profile_save.c` round trips a document through json to drop what
 * the base already says, and `daemon/confirm.c` reads one off disk after a
 * revert. A reader cannot know what the lowering knew, so this is a different
 * document for the same machine.
 */
static char *rendering_after_a_json_round_trip(const char *text)
{
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document = compiled(text, "a case's own configuration");
	ncfg_document_t *reread;
	ncfg_buf_t       json;
	char            *out;

	if (!document) {
		return NULL;
	}
	message[0] = '\0';
	ncfg_buf_init(&json, 0);
	if (!ncfg_document_write(document, &json, message, sizeof(message))) {
		printf("  the case's own document would not serialise: %s\n", message);
		ncfg_buf_free(&json);
		ncfg_document_free(document);
		return NULL;
	}
	ncfg_document_free(document);
	reread = ncfg_document_read(ncfg_buf_text(&json), strlen(ncfg_buf_text(&json)), message,
	    sizeof(message));
	ncfg_buf_free(&json);
	if (!reread) {
		printf("  the case's own document would not read back: %s\n", message);
		return NULL;
	}
	out = render_document(reread);
	ncfg_document_free(reread);
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
	char             why[NCFG_ERROR_MAX];
	int              same = 0;

	why[0] = '\0';

	if (before) {
		rendered = render_document(before);
	}
	if (rendered) {
		after = compiled(rendered, "the rendering");
	}
	if (after) {
		/*
		 * **The verdict is production's equality, not a text comparison.**
		 * This compared the two canonical forms, which is the document's
		 * *identity* -- everything the writer writes, provenance included.
		 * That was adequate only while no provenance field ever differed.
		 * `declared` does: a synthesised member device carries a `master`, so
		 * the renderer writes it and the recompile reads a block somebody
		 * wrote. `ncfg_config_round_trips` asks the host's own comparison,
		 * which leaves provenance out exactly as `profile save` does, so a
		 * case here cannot disagree with the operation it stands for.
		 *
		 * The canonical pair is still computed, for the printout: it is what
		 * says *where* two documents differ, and identity is the right thing
		 * to show a reader even when it is the wrong thing to judge on.
		 */
		want = canonical(before);
		got = canonical(after);
		same = ncfg_config_round_trips(before, why, sizeof(why));
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

	/* No `device wlan0 { }` beside it, because an access point needs none.
	 * It used to say more: an empty device block was dropped by
	 * `render_device`, so one here would have failed this case for a reason
	 * with nothing to do with access points. 10.437 closed that, and
	 * `the_empty_device_block_round_trips` is the case for it. */
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

	/*
	 * **The one field of nine this renderer wrote nothing for.** Every other
	 * probe key is written when it differs from a fallback of zero or a
	 * number; `require_lease` is the only one whose default is `true`, so it
	 * needed the opposite test and did not have it. A profile saved from a
	 * cellular machine came back requiring a lease the link never gets, which
	 * the example file's own prose says "would hold a working link down for
	 * ever".
	 *
	 * Found by round-tripping `doc/netcfgd.conf.example`, which nothing had
	 * asked about rendering before. Asserted here as well, so the fix does not
	 * depend on that file keeping the `wwan0` block.
	 */
	text = "interface wwan0 {\n\tconfig = \"dhcp\"\n"
	    "\tprobe { command = \"/usr/bin/true\"; require_lease = false }\n}\n";
	round_trips(text, "a probe that does not require a lease round trips");
	rendered = rendering_of(text);
	check(holds(rendered, "require_lease = false"),
	    "and says so, because absence means it does require one");
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


/*
 * The five spellings the language accepts and the renderer does not write.
 *
 * `tool/key_coverage_gate.py` proves every key the lowering accepts is one the
 * renderer writes, and waives these five because each is an alias of a key it
 * does write: a document setting the alias comes back spelled the other way
 * and compiles to the same document. That was a sentence in a waiver file, and
 * two measurements agreed it was the only thing holding them up -- the five
 * keys set by no corpus in this tree are exactly the five waived.
 *
 * So nothing exercised the alias at all. If `dev` stopped reaching the same
 * field as `parent`, every test here would still pass and the gate would still
 * be green, because the gate reads source text and the corpora read documents
 * that use the canonical name.
 *
 * `doc/interface-report.md` writes `global { dns { dns_mode = "dnsmasq" } }`
 * as an example, so the untested spelling is one the documentation hands to a
 * reader.
 *
 * Each case asserts both halves: the document survives the round trip, AND the
 * rendering carries the canonical spelling rather than the alias. The second is
 * what makes the waiver file's reason a check -- without it, a renderer that
 * preserved the alias would pass the round trip and quietly make the waiver
 * wrong.
 */
static void the_alias_spellings_round_trip(void)
{
	char *macvlan;
	char *vxlan;
	char *tunnel;
	char *dns;
	char *advertise;
	char *pppoe;
	char *openvpn;

	round_trips("device mv0 {\n\tmacvlan {\n\t\tdev = \"eth0\"\n"
	    "\t\tmode = \"bridge\"\n\t}\n}\n",
	    "a macvlan named by `dev` rather than `parent` round trips");
	macvlan = rendering_of("device mv0 { macvlan { dev = \"eth0\" } }\n");
	check(macvlan && holds(macvlan, "parent = \"eth0\"") &&
	        lacks(macvlan, "dev ="),
	    "and comes back as `parent`, which is the spelling the renderer writes");
	free(macvlan);

	round_trips("device vx0 {\n\tvxlan {\n\t\tvni = 100\n"
	    "\t\tdev = \"eth0\"\n\t}\n}\n",
	    "a vxlan named by `vni` and `dev` round trips");
	vxlan = rendering_of("device vx0 { vxlan { vni = 100; dev = \"eth0\" } }\n");
	check(vxlan && holds(vxlan, "id = 100") && holds(vxlan, "parent = \"eth0\"") &&
	        lacks(vxlan, "vni"),
	    "and comes back as `id` and `parent`, both canonical");
	free(vxlan);

	/* `vni` is an alias of `key` in a tunnel and of `id` in a vxlan -- one
	 * word reaching two different canonical names, which is the case a single
	 * waiver line could most easily be wrong about. */
	round_trips("device gt0 {\n\ttunnel {\n\t\tmode = \"gretap\"\n"
	    "\t\tlocal = \"192.0.2.10\"\n\t\tremote = \"198.51.100.10\"\n"
	    "\t\tvni = 7\n\t}\n}\n",
	    "and a tunnel's `vni` round trips, where it means `key` instead");
	tunnel = rendering_of("device gt0 { tunnel { mode = \"gretap\"; "
	    "local = \"192.0.2.10\"; remote = \"198.51.100.10\"; vni = 7 } }\n");
	check(tunnel && holds(tunnel, "key = 7") && lacks(tunnel, "vni"),
	    "as `key`, not as the `id` the same word means one block over");
	free(tunnel);

	round_trips("global {\n\tdns {\n\t\tdns_mode = \"dnsmasq\"\n"
	    "\t\tdns_search = [\"example.com\"]\n"
	    "\t\tdns_domains = [\"corp.example.com\"]\n\t}\n}\n",
	    "the three flat `dns_` spellings round trip inside a dns block");
	dns = rendering_of("global { dns { dns_mode = \"dnsmasq\"; "
	    "dns_search = [\"example.com\"]; dns_domains = [\"corp.example.com\"] } }\n");
	check(dns && holds(dns, "mode = \"dnsmasq\"") && holds(dns, "search") &&
	        holds(dns, "domains") && lacks(dns, "dns_mode") &&
	        lacks(dns, "dns_search") && lacks(dns, "dns_domains"),
	    "and come back as `mode`, `search` and `domains`");
	free(dns);

	/*
	 * The four found by tightening the gate rather than by the corpus count.
	 * Each was passing the loose word test for the wrong reason -- `prefix`
	 * because two refusal sentences mention a prefix, `user` because
	 * `render.c` spells a principal `"user:%s"` -- so each is both an alias
	 * worth exercising and a verdict the gate used to reach by luck.
	 */
	round_trips("interface wan0 {\n\tconfig = \"dhcp6 pd\"\n}\n"
	    "interface lan0 {\n\tconfig = \"192.0.2.1/24\"\n"
	    "\tadvertise {\n\t\tprefix = [\"@pd:wan0\"]\n"
	    "\t\tother = true\n\t}\n}\n",
	    "an advertise block using `prefix` and `other` round trips");
	advertise = rendering_of("interface wan0 { config = \"dhcp6 pd\" }\n"
	    "interface lan0 { config = \"192.0.2.1/24\"\n"
	    "\tadvertise { prefix = [\"@pd:wan0\"]; other = true } }\n");
	check(advertise && holds(advertise, "prefixes") &&
	        holds(advertise, "other_config = true") && lacks(advertise, "prefix ="),
	    "and comes back as `prefixes` and `other_config`");
	free(advertise);

	round_trips("device ppp0 {\n\tpppoe {\n\t\tparent = \"e0\"\n"
	    "\t\tuser = \"u\"\n\t\tpassword = \"@secret:p\"\n\t}\n}\n",
	    "a pppoe session naming `user` rather than `username` round trips");
	pppoe = rendering_of("device ppp0 { pppoe { parent = \"e0\"; user = \"u\"; "
	    "password = \"@secret:p\" } }\n");
	check(pppoe && holds(pppoe, "username = \"u\"") && lacks(pppoe, "user ="),
	    "and comes back as `username`");
	free(pppoe);

	round_trips("device vpn0 {\n\topenvpn {\n"
	    "\t\tfile = \"/etc/openvpn/work.ovpn\"\n\t\tuser = \"u\"\n"
	    "\t\tpassword = \"@secret:vpn\"\n\t}\n}\n",
	    "an openvpn tunnel naming `file` and `user` round trips");
	openvpn = rendering_of("device vpn0 { openvpn { file = \"/etc/openvpn/work.ovpn\"; "
	    "user = \"u\"; password = \"@secret:vpn\" } }\n");
	check(openvpn && holds(openvpn, "config = \"/etc/openvpn/work.ovpn\"") &&
	        holds(openvpn, "username = \"u\"") && lacks(openvpn, "file ="),
	    "and comes back as `config` and `username`");
	free(openvpn);
}


/*
 * A vlan's `protocol`, which was the one key no round trip reached.
 *
 * Found by counting rather than by suspicion. Of the 141 keys the lowering
 * accepts, every one is set by some corpus in this tree -- and `protocol` was
 * set by exactly one, `doc/schema/document.json`, which `render_the_witness`
 * asserts a refusal list against rather than round tripping. So the only
 * document naming this key was the one document never asked whether it comes
 * back.
 *
 * It is also the `require_lease` shape: written only when it differs from the
 * default, so the interesting case is the one a sweep over the struct with a
 * single comparison would skip. Both directions are asserted here -- `dot1ad`
 * written out, and `dot1q` deliberately absent -- because an omission is a
 * claim about the parser's default and is wrong if that default moves.
 *
 * `vlan_protocol_words` is in enum order, which is checked here by rendering
 * the non-default value and reading the word: `NCFG_VLAN_PROTOCOL_DOT1Q` then
 * `DOT1AD` against `{ "dot1q", "dot1ad" }`. A table written the other way round
 * renders `dot1q` for a dot1ad vlan, which still compiles and silently changes
 * the device.
 */
static void a_vlans_protocol_round_trips(void)
{
	char *tagged;
	char *plain;
	char *alias;

	round_trips("device v0 {\n\tvlan {\n\t\tparent = \"eth0\"\n"
	    "\t\tid = 10\n\t\tprotocol = \"dot1ad\"\n\t}\n}\n",
	    "a vlan carrying the non-default protocol round trips");
	tagged = rendering_of("device v0 { vlan { parent = \"eth0\"; id = 10; "
	    "protocol = \"dot1ad\" } }\n");
	check(tagged && holds(tagged, "protocol = \"dot1ad\""),
	    "and names `dot1ad`, not the word one place along in the table");
	free(tagged);

	round_trips("device v1 {\n\tvlan {\n\t\tparent = \"eth0\"\n\t\tid = 11\n\t}\n}\n",
	    "and one at the default protocol round trips without the key");
	plain = rendering_of("device v1 { vlan { parent = \"eth0\"; id = 11 } }\n");
	check(plain && lacks(plain, "protocol"),
	    "which is left unwritten, because absent means dot1q");
	free(plain);

	/* The wire spellings the lowering also takes, which no corpus used either. */
	round_trips("device v2 {\n\tvlan {\n\t\tparent = \"eth0\"\n"
	    "\t\tid = 12\n\t\tprotocol = \"802.1ad\"\n\t}\n}\n",
	    "and the `802.1ad` spelling round trips");
	alias = rendering_of("device v2 { vlan { parent = \"eth0\"; id = 12; "
	    "protocol = \"802.1ad\" } }\n");
	check(alias && holds(alias, "protocol = \"dot1ad\"") &&
	        lacks(alias, "802.1ad"),
	    "coming back as `dot1ad`, which is the word the renderer writes");
	free(alias);
}


/*
 * Four writes `gcov` says no corpus reaches.
 *
 * The key-counting instruments of 10.427 to 10.429 answered "is every key
 * handled" four ways and agreed. **That frame cannot see a write no document
 * triggers**, because it reads source text rather than asking what ran.
 *
 * Built with `--coverage` from `git archive HEAD` and driven by all five test
 * binaries that touch the renderer -- this one, `lower_test`, `config_test`,
 * `proto_test` and `cli_control_test` -- the three renderer modules execute
 * 95.66% of 1130 lines. The other three contribute nothing the first two do
 * not, measured rather than assumed: the figure is identical with two suites
 * and with five. Of the 49 lines that never ran, the rest are
 * allocation-failure arms and refusals the lowering makes unreachable; these
 * four are conditional writes nothing exercises.
 *
 * Two are the `require_lease` shape a fourth and fifth time: a value written
 * only when it differs from a default, so the case that reaches it is the one
 * a corpus assembled from ordinary configurations never contains.
 *
 * The access point's `ssid` is the one worth the most. `render_link` carries
 * that comparison TWICE -- once for a network at line 757 and once for an
 * access point at 834 -- and only the network copy had a test. The network
 * copy is there because dropping it was a real shipped defect: `ssid =
 * "@bssid"` vanished and the document came back as a network named after its
 * label, so `profile save` refused on any machine with a network pinned by
 * access point. The second copy of a construct that has already bitten once
 * was the untested one.
 */
static void the_writes_no_corpus_reached(void)
{
	char *point;
	char *network;
	char *ignore;
	char *odd;

	/*
	 * An access point whose SSID is not its label. An ssid is given as hex,
	 * which is why the renderer has a `quote_ssid` at all -- the bytes need
	 * not be text. `4775657374` is `Guest` and `677565737473` is `guests`,
	 * so the pair below is a differing ssid and a label-equal one, and both
	 * states are asserted because omission is what equality means.
	 */
	round_trips("access_point \"guests\" {\n\tdevice = \"wlan0\"\n"
	    "\tssid = \"4775657374\"\n\tchannel = 6\n"
	    "\twifi { psk = \"@secret:ap\" }\n}\n",
	    "an access point whose ssid differs from its label round trips");
	point = rendering_of("access_point \"guests\" { device = \"wlan0\"; "
	    "ssid = \"4775657374\"; wifi { psk = \"@secret:ap\" } }\n");
	check(point && holds(point, "ssid = \"4775657374\""),
	    "and keeps the ssid, which is not recoverable from the label");
	free(point);
	point = rendering_of("access_point \"guests\" { device = \"wlan0\"; "
	    "ssid = \"677565737473\"; wifi { psk = \"@secret:ap\" } }\n");
	check(point && lacks(point, "ssid ="),
	    "while a label-equal ssid stays omitted, the shorter form being faithful");
	free(point);

	/* `autoconnect` defaults to 1 in `lower_network`, so the renderer writes
	 * it only when off -- the same polarity that hid `require_lease`. */
	round_trips("network \"office\" {\n\twifi {\n\t\tpsk = \"@secret:office\"\n"
	    "\t\tautoconnect = false\n\t}\n}\n",
	    "a network that must not be joined automatically round trips");
	network = rendering_of("network \"office\" { wifi { psk = \"@secret:office\"; "
	    "autoconnect = false } }\n");
	check(network && holds(network, "autoconnect = false"),
	    "and says so, because absent means it joins by itself");
	free(network);

	/* `ignore` REPLACES the default list, so an empty one is an instruction
	 * and not an absence: `[]` means consult every interface. */
	round_trips("global {\n\tconnectivity {\n\t\trequires = \"probe\"\n"
	    "\t\tignore = []\n\t}\n}\n",
	    "a connectivity policy ignoring nothing round trips");
	ignore = rendering_of("global { connectivity { requires = \"probe\"; "
	    "ignore = [] } }\n");
	check(ignore && holds(ignore, "ignore = []"),
	    "and keeps the empty list, which is not the same as leaving it out");
	free(ignore);

	/* The rate units run gbit, mbit, kbit and stop; a rate no suffix divides
	 * falls through to a bare `bit`, which the parser's own table takes. */
	round_trips("device eth0 {\n\tqdisc {\n\t\tkind = \"cake\"\n"
	    "\t\tbandwidth = \"1500bit\"\n\t}\n}\n",
	    "a rate no suffix divides evenly round trips");
	odd = rendering_of("device eth0 { qdisc { kind = \"cake\"; "
	    "bandwidth = \"1500bit\" } }\n");
	check(odd && holds(odd, "bandwidth = \"1500bit\""),
	    "staying in bits rather than being rounded to the nearest kbit");
	free(odd);
}


/*
 * The other side of a write that chooses between two words or two shapes.
 *
 * `gcov -b` on the same coverage build is one notch sharper than the line
 * coverage that found the four above: a line can execute every run while one
 * side of its condition never does. Of 704 branches in the three renderer
 * modules, 81% to 91% are taken at least once, and after the error arms and
 * the unreachable refusals the residue is conditions whose other side no
 * corpus produces.
 *
 * **`nat` and `forwarding` looked like the `vlan_protocol_words` fault and are
 * not, and the correction is the useful part of this entry.** Each is written
 * `value ? "true" : "false"` and every corpus sets them true, so the string
 * `false` had never once been rendered for either. The conclusion drawn from
 * that -- that an inverted ternary would pass every test -- was wrong, and the
 * control said so: inverting both fails five checks, and one of the five is the
 * PRE-EXISTING `nat = true` round trip here, with `lower_test`'s guard failing
 * on `forwarding = true` as well.
 *
 * The reason is worth carrying. A round trip compares DOCUMENTS, so a wrong
 * word recompiles to a wrong value and the fixture that sets `true` catches an
 * inversion from its own side. **A never-taken branch is therefore not
 * automatically an undetected-defect window**: where the branch chooses
 * between two renderings of a value the document holds, one polarity is enough
 * to police both.
 *
 * What these two cases buy is narrower and still real: the `false` arm had
 * never executed, so a fault that only manifests while rendering it -- a
 * quoting slip, a crash, output the parser cannot read -- had nothing watching.
 * Unlike the vlan word table, where the two orderings are both parseable and
 * only the text assertion separates them.
 *
 * The other three cases are not polarity but SHAPE, and there the round trip
 * from the other side covers nothing: a route carrying a gateway does not
 * exercise the gatewayless arm at all.
 *
 * **What these five cases are worth was measured rather than argued, and one
 * of them is worth nothing at branch level.** Re-running `gcov -b` with them
 * in moves `render_device.c` from 88.76% to 89.16% and `render_link.c` from
 * 90.87% to 92.31%, which is four branches: `nat = false`, `forwarding =
 * false`, the gatewayless route and the peer with no keepalive.
 *
 * The delegated suffix added none, and the reason is a misreading worth
 * recording. Line 209 is `suffix && strcmp(suffix, default) != 0`, which gcov
 * reports as several branches, and the untaken one is the NULL test rather
 * than the comparison -- an existing case already renders a non-default
 * suffix. Dropping the write proves it: four checks fail and two of them are
 * that older case. **"A never-taken branch on line N" does not say which
 * clause of a compound condition it belongs to**, and attributing it is a
 * guess that reads like a measurement.
 *
 * It is kept because the older case carries a subnet as well, so this remains
 * the only `@pd:source=suffix` document with no subnet in it -- a shape rather
 * than a branch, and said so rather than left looking like coverage.
 */
static void the_other_side_of_a_two_way_write(void)
{
	char *off;
	char *bare;
	char *suffix;
	char *peer;

	off = rendering_of("interface eth0 { config = \"dhcp\"; nat = false }\n");
	check(off && holds(off, "nat = false"),
	    "`nat = false` renders as false, not as the other word of the pair");
	free(off);
	round_trips("interface eth0 {\n\tconfig = \"dhcp\"\n\tnat = false\n}\n",
	    "and an interface told not to translate round trips");

	off = rendering_of("interface eth0 { config = \"dhcp\"; forwarding = false }\n");
	check(off && holds(off, "forwarding = false"),
	    "and `forwarding = false`, which asks netcfgd to hold the sysctl down");
	free(off);
	round_trips("interface eth0 {\n\tconfig = \"dhcp\"\n\tforwarding = false\n}\n",
	    "and an interface told not to forward round trips");

	/* A route is a destination and then optional keywords, so one with no
	 * `via` is an ordinary on-link route and the `if (route->via)` arm has a
	 * second side. Every routes fixture in this suite had a gateway. */
	round_trips("interface eth0 {\n\tconfig = \"192.0.2.1/24\"\n"
	    "\troutes = \"198.51.100.0/24\"\n}\n",
	    "a route with no gateway round trips");
	bare = rendering_of("interface eth0 { config = \"192.0.2.1/24\"; "
	    "routes = \"198.51.100.0/24\" }\n");
	check(bare && holds(bare, "routes = \"198.51.100.0/24\"") &&
	        lacks(bare, "via"),
	    "and stays gatewayless rather than acquiring one");
	free(bare);

	/* `@pd:source=suffix` omits the suffix when it is the default `::1/64`,
	 * so the written form had never been produced. */
	round_trips("interface wan0 {\n\tconfig = \"dhcp6 pd\"\n}\n"
	    "interface lan0 {\n\tconfig = \"@pd:wan0=::2/64\"\n}\n",
	    "a delegated address with a non-default suffix round trips");
	suffix = rendering_of("interface wan0 { config = \"dhcp6 pd\" }\n"
	    "interface lan0 { config = \"@pd:wan0=::2/64\" }\n");
	check(suffix && holds(suffix, "=::2/64"),
	    "and carries the suffix, which the default form leaves unwritten");
	free(suffix);

	/* The wireguard fixture sets `keepalive`, so the omission arm was unrun. */
	round_trips("device wg0 {\n\twireguard {\n\t\tprivate_key = \"@secret:wg\"\n"
	    "\t\tpeer \"office\" {\n"
	    "\t\t\tpublic_key = \"0000000000000000000000000000000000000000000=\"\n"
	    "\t\t\tallowed_ips = [\"0.0.0.0/0\"]\n"
	    "\t\t}\n\t}\n}\n",
	    "a wireguard peer with no keepalive round trips");
	peer = rendering_of("device wg0 { wireguard { private_key = \"@secret:wg\"; "
	    "peer \"office\" { "
	    "public_key = \"0000000000000000000000000000000000000000000=\"; "
	    "allowed_ips = [\"0.0.0.0/0\"] } } }\n");
	check(peer && lacks(peer, "keepalive"),
	    "without acquiring one, since absent is not the same as zero");
	free(peer);
}


/*
 * A block at every default is omitted, which no round trip can check.
 *
 * `render_control` returns before writing anything when all three tiers are
 * root, and `render_remote` likewise when no tier is enabled and the agent is
 * root. Both arms were among the never-taken branches of 10.431, and this is
 * the one place that mattered.
 *
 * **Delete both early returns and every check in `render_test` and
 * `lower_test` still passes.** That is not a corpus gap: a redundant
 * `control { observe = "root"; wifi = "root"; admin = "root" }` compiles to
 * exactly the document it came from, so the round trip is structurally unable
 * to see it. Only a text assertion can -- the same shape as the alias
 * normalisation of 10.428, where a renderer preserving `dev` instead of
 * `parent` also round trips.
 *
 * What it would cost is not data: it is that every profile `ncfg profile save`
 * writes would gain blocks stating defaults, where the convention this module
 * follows everywhere else is to emit the short form a person would have
 * written. A convention nothing checks is one that drifts in the direction of
 * whoever edits next.
 *
 * The other direction is covered already and deliberately left to the corpora:
 * a non-default `control` or `remote` block appears in all four of them, so an
 * omission arm that fired when it should not would drop real data and fail a
 * round trip loudly.
 */
static void a_block_at_every_default_is_left_out(void)
{
	char *plain;

	plain = rendering_of("interface eth0 { config = \"dhcp\" }\n");
	check(plain && lacks(plain, "control {"),
	    "a document with no control policy gains no control block");
	check(plain && lacks(plain, "remote {"),
	    "and no remote block either, both tiers being at their defaults");
	free(plain);

	/* And the positive half, so the assertions above cannot pass by the
	 * renderer having lost the blocks altogether. */
	plain = rendering_of("global {\n\tcontrol { wifi = \"group:netdev\" }\n}\n");
	check(plain && holds(plain, "control {") && holds(plain, "wifi = \"group:netdev\""),
	    "while one that sets a tier keeps the block and the tier");
	free(plain);
}

/*
 * The connectivity policy's three unexercised arms, all one family.
 *
 * `render_connectivity` is the third member of the omit-at-default family
 * 10.432 found in `render_control` and `render_remote`, and it carries two
 * more arms nothing reached.
 *
 * **The element-wise ignore comparison ran 40,210 times and had never once
 * been asked a question it could get wrong.** The first version of this
 * comment said it had never run at all, which `gcov` disproves on the very
 * line: every document with no explicit `ignore` is given the default
 * five-member list by the lowering, so
 *
 *     ignore_differs = count != default_count;
 *     for (i = 0; !ignore_differs && i < count; i++)
 *             ignore_differs = strcmp(ignore[i], default_ignore[i]) != 0;
 *
 * runs its five comparisons on every one of them -- and every comparison is
 * between a member and itself. Replace the whole loop with the count test
 * alone and **both suites still pass**, because for a list that is equal and
 * for a list of a different length the two give the same answer.
 *
 * **The only input that separates them is a list of the SAME LENGTH that is
 * not equal**, and no corpus had one: every `ignore` in the tree has nought
 * or one member against a default of five. A five-member list differing only
 * in its last is what makes the comparison decide something, and if it were
 * wrong those five custom patterns would be read as the default and
 * **replaced by it**.
 *
 * So this one is invisible to line coverage and to branch coverage alike --
 * the line runs, every branch on it is taken -- and the lesson is that a high
 * execution count is not evidence of being tested. It was found by reading the
 * condition and asking which input could make it answer differently, which is
 * the question neither instrument asks.
 */
static void the_connectivity_policys_unreached_arms(void)
{
	char *same_length;
	char *no_requires;
	char *defaults;

	/* Five patterns, four of them the shipped ones, differing in the last --
	 * so `ignore_differs` can only come out right by comparing contents, and
	 * the loop must reach its final index to do it. */
	round_trips("global {\n\tconnectivity {\n\t\tignore = [\"docker*\", \"br-*\", "
	    "\"veth*\", \"virbr*\", \"tap*\"]\n\t}\n}\n",
	    "an ignore list as long as the default but not equal to it round trips");
	same_length = rendering_of("global { connectivity { ignore = [\"docker*\", "
	    "\"br-*\", \"veth*\", \"virbr*\", \"tap*\"] } }\n");
	check(same_length && holds(same_length, "tap*"),
	    "and keeps the member that differs, rather than taking the default list");
	check(same_length && lacks(same_length, "vnet*"),
	    "with the default's own last member absent, which is what replacing means");
	free(same_length);

	/* `requires` is omitted at its default, so a policy that only sets
	 * `ignore` writes the block without it -- the arm the existing case
	 * cannot reach, because it sets both. */
	no_requires = rendering_of("global { connectivity { ignore = [\"wg0\"] } }\n");
	check(no_requires && holds(no_requires, "connectivity {") &&
	        holds(no_requires, "wg0") && lacks(no_requires, "requires"),
	    "a policy setting only `ignore` writes no `requires`, that being default");
	free(no_requires);

	/* And the whole block goes when nothing in it differs, which no round
	 * trip can check: an empty `connectivity { }` compiles to these same
	 * defaults, so only the text says whether it was written. */
	defaults = rendering_of("global { connectivity { requires = \"route\" } }\n");
	check(defaults && lacks(defaults, "connectivity"),
	    "and a policy at every default is left out altogether");
	free(defaults);
}

/*
 * The two escapes nothing exercised, and the agreement that makes them work.
 *
 * The lexer takes four escapes in a string -- `\"`, `\\`, `\n` and `\t` -- and
 * `ncfg_render_quote` writes back only two of them, escaping a backslash and a
 * quote and passing a newline or a tab through **raw**. That round trips for
 * one reason: `lex_string` lets a string run to its closing quote *across
 * lines*, which it says in an error message and nowhere else.
 *
 * **What this case uniquely holds was measured, not assumed, and it is the text
 * assertion rather than the round trips.** Two sabotages:
 *
 *     renderer escapes the newline   only the text assertion here fails;
 *                                    `lower_test` and `config_test` pass
 *     lexer refuses a raw newline    this round trip fails -- and so do two
 *                                    checks in `lower_test`
 *
 * The second is already guarded, because a string carrying newlines is a
 * documented LIST form in this language and `lower_test` compiles one. What
 * nothing else watches is the renderer's choice: an escaped `\n` re-lexes to
 * the same value, so every round trip in the tree passes either way and only
 * the output's bytes say which was written.
 *
 * That is the third instance of one shape -- **output wrong, meaning right,
 * round trip blind** -- after the alias normalisation of 10.428 and the
 * omit-at-default family of 10.432. A test comparing documents cannot be made
 * sensitive to any of them by adding documents.
 */
static void the_other_two_escapes_round_trip(void)
{
	char *rendered;

	round_trips("network \"two\\tcolumns\" {\n\twifi {\n\t\topen = true\n\t}\n}\n",
	    "a tab in a name survives the round trip");
	round_trips("network \"two\\nlines\" {\n\twifi {\n\t\topen = true\n\t}\n}\n",
	    "and so does a newline, which the renderer writes raw");

	/* The raw half is the claim, so read it: an escaped `\n` in the output
	 * would round trip too, and only the text says which was written. */
	rendered = rendering_of("network \"two\\nlines\" { wifi { open = true } }\n");
	check(rendered && strstr(rendered, "two\nlines") != NULL,
	    "written as a real newline inside the quotes, not as an escape");
	free(rendered);
}


/*
 * A `device` block somebody wrote and left empty, which used to be lost.
 *
 * **The reproduction from 10.418, which stood open as the renderer's last
 * hole.** `device wlan0 { }` has nothing to recreate its entry: an access
 * point naming the device does not make the compiler invent one, so the
 * document went in with a device and came back without:
 *
 *     devices before: [{"name": "wlan0", "managed": true, ...}]
 *     devices after:  []
 *
 * `ncfg profile save` therefore refused on such a machine, having failed to
 * reproduce what was running -- the same shape as the `4g0` label, a snapshot
 * the renderer could not write.
 *
 * **The same case with an `interface wlan0` beside it passed, and passed for
 * the wrong reason**, which is why this one is written without it: rendering
 * the interface makes the recompile invent the device entry again, so the
 * documents matched by coincidence and a probe would have read as a pass.
 *
 * The fix is `declared`, because nothing else separates the two: an invented
 * all-default device is byte-identical to a written empty one. The other half
 * is below -- the common case must stay skipped, or every profile gains
 * `override device eth0 { }` for a block the base never had.
 */
static void the_empty_device_block_round_trips(void)
{
	char *written;
	char *common;

	round_trips("device wlan0 { }\n"
	    "access_point \"ap\" {\n\tdevice = \"wlan0\"\n\tssid = \"686f6d65\"\n"
	    "\twifi { psk = \"@secret:ap\" }\n}\n",
	    "a written empty device with nothing else to recreate it round trips");
	written = rendering_of("device wlan0 { }\n"
	    "access_point \"ap\" { device = \"wlan0\"; ssid = \"686f6d65\"; "
	    "wifi { psk = \"@secret:ap\" } }\n");
	check(written && holds(written, "device wlan0 {"),
	    "and the block is in the text, which is the only way it survives");
	free(written);

	/*
	 * And the invented one stays out. `interface eth0 { config = "dhcp" }`
	 * declares no device and the document carries one, so writing it is what
	 * broke `master`: `override device eth0 { }` for a block the base config
	 * never had, which does not compile.
	 */
	common = rendering_of("interface eth0 { config = \"dhcp\" }\n");
	check(common && lacks(common, "device eth0"),
	    "while a device nobody wrote stays out of the profile altogether");
	free(common);

	/*
	 * And the same question for every other block that can be declared empty,
	 * which is one: `interface eth0 { }`. Probed against the program rather
	 * than guessed -- `network`, `linkset`, `bluetooth`, `access_point` and
	 * `rule` are each refused empty for want of a required key, and `global`
	 * is a singleton whose empty form carries nothing. An interface is the
	 * only one that compiles with nothing in it, and it had no case.
	 */
	round_trips("interface eth0 { }\n",
	    "an interface declared with nothing in it round trips");
	common = rendering_of("interface eth0 { }\n");
	check(common && holds(common, "interface eth0"),
	    "and is in the text, the device it implies still being left out");
	free(common);
}


/*
 * `declared` survives a json round trip, which is what serialising it bought.
 *
 * **This case used to assert the opposite.** The field began outside the wire
 * form, on the argument that provenance is not desired state and that adding
 * it would re-bless the frozen witness for no change in what the machine does.
 * That left one carry-over site in `host/profile_save.c` and a second route it
 * could not reach: `daemon/confirm.c` assigns the last-good document, read off
 * disk, straight to `state->desired`, which is what `main/daemon_answer.c`
 * hands to `ncfg_profile_save` -- so a save taken after a commit-confirm
 * revert saw nothing declared and refused.
 *
 * The holder's decision was to serialise it, which closes both routes and
 * retires the carry-over. **No version bump**: 0038 holds the schema version
 * until the first release, there being no consumer built against the old one,
 * and what makes the change visible is that the witness moved under a
 * deliberate `make schema-bless`.
 *
 * The case is kept pointing the other way rather than deleted, because the
 * property it asserts is the one the fix depends on and nothing else states
 * it: the path is real, not a model of it, since write-and-read-back is the
 * idiom `daemon_answer.c` uses for its own deep copy.
 */
static void declared_survives_a_json_round_trip(void)
{
	char *rendered;

	/* The control first: compiled and rendered directly. */
	rendered = rendering_of("device wlan0 { }\n");
	check(rendered && holds(rendered, "device wlan0"),
	    "a written empty device survives while the document stays in one process");
	free(rendered);

	rendered = rendering_after_a_json_round_trip("device wlan0 { }\n");
	check(rendered != NULL, "and the same document survives a json round trip");
	check(rendered && holds(rendered, "device wlan0"),
	    "  with the block still there, `declared` being in the wire form now");
	free(rendered);
}

/*
 * A document a build speaking an older minor wrote still round trips.
 *
 * `canonical.c` refuses a document whose MAJOR this build does not speak and
 * accepts any minor, which is what a minor version is for: 1.0 is readable
 * here. The renderer cannot write `schema_version` -- the configuration
 * language has no key for it, and `render.c` says so at the walk -- so the
 * recompiled document carries whatever this build stamps rather than what the
 * original said.
 *
 * `document_compare.c` leaves out `generated_by` and `declared` for exactly
 * that reason and does not leave out this member, so a document from an older
 * minor compiles to a DIFFERENT document by the only member the renderer was
 * never able to carry -- and `ncfg profile save` refuses to save a machine
 * whose desired state came from one.
 *
 * **It has never been able to fire, and not because the comparison is right.**
 * `NCFG_SCHEMA_MINOR` has never moved off its first value (decision 0038 keeps
 * it there until a release), so there is one minor in existence and no
 * document can disagree with it. That is a claim about the version counter,
 * not about the round trip, and the counter is going to move.
 */
static void an_older_minor_still_round_trips(void)
{
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document = compiled("device wlan0 { }\n", "a case's own configuration");
	ncfg_document_t *reread = NULL;
	ncfg_buf_t       json;
	char            *older = NULL;
	char            *at = NULL;

	/* Not a bare return: a fixture that stops compiling would make every
	 * assertion below vanish and the case pass by saying nothing. */
	check(document != NULL, "the case's own configuration compiles");
	if (!document) {
		return;
	}
	message[0] = '\0';
	ncfg_buf_init(&json, 0);
	if (ncfg_document_write(document, &json, message, sizeof(message))) {
		older = strdup(ncfg_buf_text(&json));
	}
	ncfg_buf_free(&json);
	ncfg_document_free(document);
	check(older != NULL, "the case's own document serialises");

	/* The first `minor` in the document is the schema version's: the writer puts
	 * `schema_version` first, which `doc/schema/document.json` shows.
	 *
	 * The separator is stepped over rather than spelled, because this writer is
	 * the compact one and the witness is the pretty-printed one -- searching for
	 * the witness's `"minor": ` found nothing here, the mutation silently did not
	 * happen, and the round trip then passed on an unmodified document. */
	at = older ? strstr(older, "\"minor\"") : NULL;
	if (at) {
		at += sizeof("\"minor\"") - 1u;
		while (*at == ' ' || *at == '\t' || *at == '\n' || *at == ':') {
			at++;
		}
		if (*at < '0' || *at > '9') {
			at = NULL;
		}
	}
	check(at != NULL, "  and states a minor version as a number");
	if (at) {
		/* One digit, `NCFG_SCHEMA_MINOR` being one; the assertion on the reread
		 * document is what would catch this having written the wrong thing. */
		*at = '0';
	}

	message[0] = '\0';
	reread = older ? ncfg_document_read(older, strlen(older), message, sizeof(message)) : NULL;
	if (!reread && older) {
		printf("  a 1.0 document would not read back: %s\n", message);
	}
	check(reread != NULL, "  and a 1.0 document is readable by this build");
	if (reread) {
		check(reread->schema_version.major == NCFG_SCHEMA_MAJOR
		    && reread->schema_version.minor == 0,
		    "  with the older minor kept rather than restamped");
		message[0] = '\0';
		if (!ncfg_config_round_trips(reread, message, sizeof(message))) {
			printf("  %s\n", message);
		}
		message[0] = '\0';
		check(ncfg_config_round_trips(reread, message, sizeof(message)),
		    "  and it still round trips, the renderer never having written the version");
	}
	free(older);
	ncfg_document_free(reread);
}

/*
 * A document carrying provenance round trips.
 *
 * `round_trip.c`'s header says this is the case it exists for -- the writer
 * emits `generated_by` and the renderer deliberately does not, so the
 * recompiled document has none -- and names
 * `ncfg_config_documents_agree` as where the exclusion is implemented. It was
 * not: the exclusion skipped the member in the walk while the root member
 * TALLY counted it, so it held only when both documents carried the member and
 * a document with provenance was unequal to the same document without. Every
 * document with provenance failed the round trip, and no suite had one.
 */
static void a_document_carrying_provenance_round_trips(void)
{
	ncfg_document_t *document = compiled("device wlan0 { }\n", "a case's own configuration");
	char             why[NCFG_ERROR_MAX];

	check(document != NULL, "the case's own configuration compiles");
	if (!document) {
		return;
	}
	free(document->generated_by);
	document->generated_by = strdup("netcfgd, in a test");
	check(document->generated_by != NULL, "  and provenance can be put on it");
	why[0] = '\0';
	if (document->generated_by && !ncfg_config_round_trips(document, why, sizeof(why))) {
		printf("  %s\n", why);
	}
	why[0] = '\0';
	check(document->generated_by && ncfg_config_round_trips(document, why, sizeof(why)),
	    "  and it still round trips, the renderer never having written that either");
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
	the_alias_spellings_round_trip();
	a_vlans_protocol_round_trips();
	the_writes_no_corpus_reached();
	the_other_side_of_a_two_way_write();
	a_block_at_every_default_is_left_out();
	the_connectivity_policys_unreached_arms();
	the_other_two_escapes_round_trip();
	the_empty_device_block_round_trips();
	declared_survives_a_json_round_trip();
	an_older_minor_still_round_trips();
	a_document_carrying_provenance_round_trips();

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
