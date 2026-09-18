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

static char *refusals_of_config(const char *text)
{
	ncfg_document_t *document = compiled(text, "a case's own configuration");
	char            *out;

	if (!document) {
		return NULL;
	}
	out = refusals_for(document);
	ncfg_document_free(document);
	return out;
}

/* The same, for a file carrying hooks, which need a sink that accepts them
 * before the renderer ever sees one. `record_hook` is below. */
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
	static const char *const expected[] = { "kind wireguard", "kind openvpn", "kind tunnel",
		"kind tun", "kind ifb", "routing rule(s)", "access_point block(s)",
		"a match block", "a wifi policy", "ethtool settings", "qdisc",
		"ingress_redirect", "global: dns options", "global: dnssec",
		"global: dns transport", "global: a dns server with a port or sni",
		"interface d-0: hooks", "interface d-0: advertise", "interface d-0: guard",
		"an address with lifetimes or a peer", "delegated addressing",
		"reported addressing", "a route with a scope", "a route with a proto",
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
 * A wireguard device has no rendering here, and saying so by name is the whole
 * difference between a partial renderer and a lossy one -- **and the name is
 * the language's**, not the document's `wire_guard`.
 */
static void what_cannot_be_rendered_is_named(void)
{
	char *wireguard = refusals_of_config("device wg0 {\n\twireguard {\n"
	    "\t\tprivate_key = \"@secret:wg\"\n\t}\n}\ninterface wg0 {\n"
	    "\tconfig = \"10.0.0.2/32\"\n}\n");
	char *openvpn = refusals_of_config("device tun0 {\n\topenvpn {\n"
	    "\t\tconfig = \"/etc/openvpn/work.ovpn\"\n\t}\n}\n");
	char *hooks = refusals_with_hooks("interface eth0 {\n\tconfig = \"dhcp\"\n"
	    "\tpost_up {\n\t\techo hello\n\t}\n}\n");
	char *rules = refusals_of_config("interface eth0 {\n\tconfig = \"dhcp\"\n}\n"
	    "rule r {\n\tpriority = 100\n\tfrom = \"192.0.2.0/24\"\n\tlookup = 42\n}\n");

	check(holds(wireguard, "device wg0: kind wireguard"),
	    "a wireguard device is refused by name, with the language's spelling");
	check(lacks(wireguard, "wire_guard"),
	    "and never with the document's, which is not a word an operator can write");
	check(holds(openvpn, "device tun0: kind openvpn") && lacks(openvpn, "open_vpn"),
	    "and the same for openvpn, the other word this project has shipped wrong");
	check(holds(hooks, "interface eth0: hooks"),
	    "an interface's hooks are refused rather than dropped");
	check(holds(rules, "1 routing rule(s)"), "and a routing rule is refused, and counted");
	free(wireguard);
	free(openvpn);
	free(hooks);
	free(rules);
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
	check(holds(device, "device eth0: a match block") &&
	    holds(device, "device eth0: qdisc") &&
	    holds(device, "device eth0: ingress_redirect"),
	    "and a device's match, qdisc and synthesised redirect");
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
	a_default_roam_block_survives();

	the_ordinary_interfaces();
	a_routes_source_and_onlink_round_trip();
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
