/*
 * lower_test.c -- drop-in precedence, and what the language means.
 *
 * WHY THIS EXISTS, AND WHAT IT IS HELD AGAINST
 *   The lowering is the largest thing in the compiler and almost all of it is
 *   judgement: which words a key accepts, which combinations are refused, and
 *   what the refusal says. None of that is checkable by reading the types, so
 *   the cases are the specification.
 *
 *   Three sources, and each is here for a different reason.
 *
 *   **`doc/netcfgd.conf.example` is the acceptance test.** The file calls
 *   itself "every feature, with the syntax to use it" and the postinst points
 *   an operator at it as the thing to read on a machine with no network. Every
 *   commented top-level block in it is uncommented and compiled here, exactly
 *   as `tool/example_gate.py` does it for the Rust -- and the extraction
 *   refuses to pass if it finds fewer blocks than it should, because a sweep
 *   over an empty list reports success exactly as loudly as a real one.
 *
 *   **The cases from `crates/netcfgd-compile/tests/compile.rs`** that belong to
 *   lowering: the diagnostics, the refusals, the defaults and the canonical
 *   spellings. Most of them name a defect that shipped, and the case is the
 *   expensive half to rediscover.
 *
 *   **Precedence**, which has no other home: a drop-in overriding a scalar, a
 *   block redefined without `override` refused naming both places, `override`
 *   replacing wholesale rather than merging, and `global` accumulating from
 *   several files.
 *
 * WHAT A CHECK LOOKS AT
 *   A refusal is checked by the *words* of its message rather than by the fact
 *   that it failed, because "it did not compile" is satisfied by a compiler
 *   that refuses everything. Where the Rust's test asserted on a phrase, the
 *   same phrase is asserted here.
 */
#include "ncfg/ast.h"
#include "ncfg/base.h"
#include "ncfg/document.h"
#include "ncfg/lower.h"
#include "ncfg/parse.h"
#include "ncfg/state.h"
#include "ncfg/value.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-70s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* ------------------------------------------------------------------------ *
 * A hook sink that records instead of writing
 *
 * The compiler needs `{phase, path, sha256}` and cannot produce them without
 * touching a filesystem, so the caller supplies this. A fake keeps the whole
 * front end pure, which is the property that lets these cases run from strings
 * with no directory anywhere.
 * ------------------------------------------------------------------------ */

typedef struct {
	int  count;
	int  phases[16];
	char owners[16][32];
	char bodies[16][256];
} fake_hooks_t;

static int record_hook(void *state, int phase, const char *owner, const char *body,
    size_t body_length, ncfg_hook_ref_t *out, char *err, size_t err_size)
{
	fake_hooks_t *seen = state;
	char          path[64];
	char          sha[65];
	int           index = seen->count;
	int           i;

	if (index >= 16) {
		ncfg_error_set(err, err_size, "too many hooks for this fixture");
		return 0;
	}
	seen->phases[index] = phase;
	(void)snprintf(seen->owners[index], sizeof(seen->owners[index]), "%s", owner);
	(void)snprintf(seen->bodies[index], sizeof(seen->bodies[index]), "%.*s",
	    (int)(body_length < 255u ? body_length : 255u), body);
	seen->count++;

	(void)snprintf(path, sizeof(path), "/run/netcfgd/hooks/%s.%d", owner, index);
	for (i = 0; i < 64; i++) {
		sha[i] = '0';
	}
	sha[64] = '\0';
	sha[63] = (char)('0' + (index % 10));
	out->phase = phase;
	out->path = malloc(strlen(path) + 1u);
	out->sha256 = malloc(65u);
	if (!out->path || !out->sha256) {
		free(out->path);
		free(out->sha256);
		out->path = NULL;
		out->sha256 = NULL;
		ncfg_error_set(err, err_size, "out of memory recording a hook");
		return 0;
	}
	memcpy(out->path, path, strlen(path) + 1u);
	memcpy(out->sha256, sha, 65u);
	return 1;
}

static fake_hooks_t hooks_seen;

static const ncfg_hook_sink_t recording_sink = { record_hook, &hooks_seen };

/* ------------------------------------------------------------------------ *
 * Compiling a fixture
 * ------------------------------------------------------------------------ */

typedef struct {
	const char *name;
	const char *text;
} fixture_t;

/* Every diagnostic the last compile produced, rendered and newline-joined.
 * One buffer rather than a returned string, because every caller wants to
 * `strstr` it and nobody wants to free it. */
static char said[8192];

/*
 * Compile `count` files in precedence order.
 *
 * Returns the document, or NULL with every diagnostic in `said`. The hook sink
 * is the recording one unless `sink` says otherwise; `hooks_seen` is reset on
 * every call so a case can look at what its own hooks did.
 */
static ncfg_document_t *build_recording(const fixture_t *files, size_t count,
    const ncfg_hook_sink_t *sink, ncfg_provenance_t *provenance)
{
	ncfg_source_t      sources[4];
	ncfg_ast_file_t   *trees[4] = { NULL, NULL, NULL, NULL };
	ncfg_lower_diags_t diags = { 0 };
	ncfg_document_t   *document = NULL;
	char               err[NCFG_ERROR_MAX];
	size_t             at = 0;
	size_t             i;

	said[0] = '\0';
	memset(&hooks_seen, 0, sizeof(hooks_seen));
	if (count > 4) {
		(void)snprintf(said, sizeof(said), "too many files for this fixture");
		return NULL;
	}
	for (i = 0; i < count; i++) {
		ncfg_diags_t parse_diags = { 0 };

		if (!ncfg_parse(files[i].text, strlen(files[i].text), &trees[i], &parse_diags, err,
		    sizeof(err))) {
			char line[NCFG_ERROR_MAX + 64];

			ncfg_diag_render(parse_diags.count ? &parse_diags.at[0] : NULL, files[i].name,
			    line, sizeof(line));
			(void)snprintf(said, sizeof(said), "%s\n", parse_diags.count ? line : err);
			ncfg_diags_free(&parse_diags);
			goto done;
		}
		ncfg_diags_free(&parse_diags);
		sources[i].name = files[i].name;
		sources[i].file = trees[i];
	}

	document = ncfg_compile_with_provenance(sources, count, sink ? sink : &recording_sink,
	    provenance, &diags, err, sizeof(err));
	for (i = 0; i < diags.count; i++) {
		char line[NCFG_ERROR_MAX + 64];

		ncfg_lower_diag_render(&diags.at[i], line, sizeof(line));
		at += (size_t)snprintf(said + at, sizeof(said) - at, "%s\n", line);
		if (at >= sizeof(said)) {
			break;
		}
	}
	if (!document && diags.count == 0) {
		(void)snprintf(said, sizeof(said), "%s", err);
	}
	ncfg_lower_diags_free(&diags);

done:
	for (i = 0; i < count; i++) {
		ncfg_ast_file_free(trees[i]);
	}
	return document;
}

/* Compile with nowhere to put the positions, which is what every case but the
 * provenance ones wants. */
static ncfg_document_t *build(const fixture_t *files, size_t count, const ncfg_hook_sink_t *sink)
{
	return build_recording(files, count, sink, NULL);
}

/* One file, called `netcfgd.conf`, which is what most cases need. */
static ncfg_document_t *build_one(const char *text)
{
	fixture_t file = { "netcfgd.conf", NULL };

	file.text = text;
	return build(&file, 1u, NULL);
}

/* Compiles, and the caller goes on to look at the document. */
static ncfg_document_t *compiles(const char *text, const char *what)
{
	ncfg_document_t *document = build_one(text);

	if (!document) {
		printf("%-70s %s\n", what, "FAILED");
		printf("    expected success, got:\n%s", said);
		failures++;
		return NULL;
	}
	return document;
}

/* Refused, and the message says `needle`. Both halves matter: "it did not
 * compile" is satisfied by a compiler that refuses everything. */
static void refuses(const char *text, const char *needle, const char *what)
{
	ncfg_document_t *document = build_one(text);
	int              ok;

	if (document) {
		printf("%-70s %s\n", what, "FAILED");
		printf("    expected a refusal, but it compiled\n");
		failures++;
		ncfg_document_free(document);
		return;
	}
	ok = strstr(said, needle) != NULL;
	check(ok, what);
	if (!ok) {
		printf("    wanted `%s`, said:\n%s", needle, said);
	}
}

static const ncfg_interface_t *interface_named(const ncfg_document_t *document, const char *name)
{
	size_t i;

	for (i = 0; i < document->interface_count; i++) {
		if (strcmp(document->interfaces[i].name, name) == 0) {
			return &document->interfaces[i];
		}
	}
	return NULL;
}

static const ncfg_device_t *device_named(const ncfg_document_t *document, const char *name)
{
	size_t i;

	for (i = 0; i < document->device_count; i++) {
		if (strcmp(document->devices[i].name, name) == 0) {
			return &document->devices[i];
		}
	}
	return NULL;
}

/* ------------------------------------------------------------------------ *
 * Addressing
 * ------------------------------------------------------------------------ */

static void addressing_cases(void)
{
	ncfg_document_t        *document;
	const ncfg_interface_t *interface;

	document = compiles("interface eth0 {\n\tconfig = \"192.0.2.10/24\"\n"
	    "\troutes = \"default via 192.0.2.1\"\n}\n", "a static ethernet interface compiles");
	if (document) {
		interface = interface_named(document, "eth0");
		check(interface && interface->addressing_count == 1u &&
		    interface->addressing[0].kind == NCFG_ADDRESS_SOURCE_STATIC &&
		    strcmp(interface->addressing[0].static_address.address, "192.0.2.10/24") == 0,
		    "  the address reaches the model");
		check(interface && interface->route_count == 1u &&
		    strcmp(interface->routes[0].destination, "default") == 0 &&
		    interface->routes[0].via && strcmp(interface->routes[0].via, "192.0.2.1") == 0,
		    "  and so does the default route");
		/* **Every interface names hardware, so every interface gets a
		 * device.** An operator who wrote only an interface has said nothing
		 * about the adapter, and the honest reading is a physical device with
		 * defaults rather than the absence of one. */
		check(device_named(document, "eth0") != NULL,
		    "  an interface with no device block gets one anyway");
		ncfg_document_free(document);
	}

	document = compiles("interface eth0 { config = \"dhcp\" }\n",
	    "dhcp is spelled as a config value");
	if (document) {
		interface = interface_named(document, "eth0");
		check(interface && interface->addressing_count == 1u &&
		    interface->addressing[0].kind == NCFG_ADDRESS_SOURCE_DHCP4,
		    "  and becomes a dhcp4 source");
		ncfg_document_free(document);
	}

	document = compiles("interface eth0 { config = [\"dhcp\", \"slaac\", \"192.0.2.10/24\"] }\n",
	    "several sources compose rather than choosing");
	if (document) {
		interface = interface_named(document, "eth0");
		check(interface && interface->addressing_count == 3u,
		    "  all three entries contribute");
		ncfg_document_free(document);
	}

	/* netifrc separates addresses with spaces and uses newlines only when an
	 * entry carries modifiers that contain spaces. Splitting on newlines alone
	 * treats the first line as one malformed address. */
	document = compiles("interface eth0 { config = \"192.0.2.2/24 192.0.2.3/24\" }\n",
	    "several addresses on one line are separate entries");
	if (document) {
		interface = interface_named(document, "eth0");
		check(interface && interface->addressing_count == 2u, "  two of them");
		ncfg_document_free(document);
	}

	document = compiles("interface eth0 {\n\tconfig = \"192.168.0.2/24 192.168.0.3/24\n"
	    "4321:0:1:2:3:4:567:89ab/64\"\n}\n", "spaces and newlines both separate entries");
	if (document) {
		interface = interface_named(document, "eth0");
		check(interface && interface->addressing_count == 3u,
		    "  three entries across two lines");
		ncfg_document_free(document);
	}

	/* Without the modifier table this splits into two addresses, because a
	 * netmask is itself address-shaped. */
	document = compiles("interface eth0 { config = \"192.168.0.2 netmask 255.255.255.0\" }\n",
	    "a netmask does not start a second address");
	if (document) {
		interface = interface_named(document, "eth0");
		check(interface && interface->addressing_count == 1u &&
		    strcmp(interface->addressing[0].static_address.address, "192.168.0.2/24") == 0,
		    "  and is converted to a prefix length");
		ncfg_document_free(document);
	}

	refuses("interface eth0 { config = \"192.168.0.2 netmask 255.0.255.0\" }\n",
	    "is not a contiguous netmask", "a non-contiguous netmask is refused");
	refuses("interface eth0 { config = \"192.168.0.2/24 netmask 255.255.255.0\" }\n",
	    "not both", "a prefix length and a netmask together are refused");

	document = compiles("interface eth0 {\n\tconfig = \"192.0.2.2/24 peer 192.0.2.3 "
	    "preferred_lft 1800 valid_lft 3600\"\n}\n", "the supported modifiers reach the model");
	if (document) {
		interface = interface_named(document, "eth0");
		check(interface && interface->addressing[0].static_address.peer &&
		    strcmp(interface->addressing[0].static_address.peer, "192.0.2.3") == 0 &&
		    interface->addressing[0].static_address.preferred_lifetime.value == 1800 &&
		    interface->addressing[0].static_address.valid_lifetime.value == 3600,
		    "  peer and both lifetimes");
		ncfg_document_free(document);
	}

	/* Section 2's rule about unknown fields is a rule about the language too:
	 * acting on a subset of what the author wrote is the failure mode, and it
	 * is worse here than in the document because the author is looking at the
	 * line. */
	refuses("interface eth0 { config = \"192.0.2.2/24 scope host\" }\n",
	    "is not supported by this build", "an unsupported modifier is named, not ignored");
	refuses("interface eth0 { config = \"dhcp4 preferred_lft 60\" }\n",
	    "is not something `dhcp4` takes",
	    "a modifier a keyword source does not take is refused");

	document = compiles("interface eth0 { config = \"null\" }\n",
	    "null yields no addressing at all");
	if (document) {
		interface = interface_named(document, "eth0");
		check(interface && interface->addressing_count == 0, "  and is not an error");
		ncfg_document_free(document);
	}

	refuses("interface eth0 { config = \"noop\" }\n", "reconciled model",
	    "noop is refused with the reason");
	refuses("interface eth0 { config = \"wombat\" }\n", "is not an address or keyword",
	    "a word that is neither an address nor a keyword is refused");
	refuses("interface eth0 { config = \"192.0.2.10\" }\n", "is not an address",
	    "an address without a prefix length is refused");
	refuses("interface eth0 { config = \"192.0.2.10/64\" }\n", "is not between 0 and 32",
	    "an impossible prefix length is refused");

	/*
	 * The kernel's spelling, not the operator's. `2001:0db8::1/64` was an
	 * address that added and deleted itself on every apply, for ever, because
	 * the comparison against what the kernel reports is a string comparison.
	 */
	document = compiles("interface eth0 { config = \"2001:0DB8::1/64\" }\n",
	    "an address is stored in the kernel's spelling");
	if (document) {
		interface = interface_named(document, "eth0");
		check(interface &&
		    strcmp(interface->addressing[0].static_address.address, "2001:db8::1/64") == 0,
		    "  compressed and lowercased");
		ncfg_document_free(document);
	}

	document = compiles("interface eth0 { config = \"slaac privacy prefer_temporary\" }\n",
	    "slaac takes a privacy setting");
	if (document) {
		interface = interface_named(document, "eth0");
		check(interface &&
		    interface->addressing[0].slaac.privacy == NCFG_SLAAC_PRIVACY_PREFER_TEMPORARY,
		    "  and RFC 4941 reaches the model");
		ncfg_document_free(document);
	}
	refuses("interface eth0 { config = \"slaac privacy sometimes\" }\n",
	    "is not a privacy setting", "an unknown privacy setting is refused");

	document = compiles("interface wan0 { config = \"dhcp6\" }\n",
	    "a plain dhcp6 asks for no prefix");
	if (document) {
		interface = interface_named(document, "wan0");
		check(interface && interface->addressing[0].dhcp6.prefix_delegation == NULL,
		    "  no delegation is requested");
		ncfg_document_free(document);
	}

	/* Each of these implies `pd`, so a length with no `pd` beside it is not
	 * silently inert. */
	document = compiles("interface wan0 { config = \"dhcp6 pd_length 60\" }\n",
	    "a prefix length alone still asks for delegation");
	if (document) {
		interface = interface_named(document, "wan0");
		check(interface && interface->addressing[0].dhcp6.prefix_delegation &&
		    interface->addressing[0].dhcp6.prefix_delegation->length.value == 60,
		    "  and carries the length");
		ncfg_document_free(document);
	}
	refuses("interface wan0 { config = \"dhcp6 pd_length 200\" }\n", "between 0 and 128",
	    "a prefix length that is not one is refused");

	/* The prefix is a reference because no config file could contain a block
	 * an ISP has not handed out yet. */
	document = compiles("interface lan0 { config = \"@pd:wan0/2\" }\n",
	    "a delegated prefix is a reference");
	if (document) {
		interface = interface_named(document, "lan0");
		check(interface && interface->addressing[0].kind == NCFG_ADDRESS_SOURCE_DELEGATED &&
		    strcmp(interface->addressing[0].delegated.prefix.source, "wan0") == 0 &&
		    interface->addressing[0].delegated.prefix.subnet == 2,
		    "  naming the interface and the sub-prefix");
		ncfg_document_free(document);
	}
}

/* ------------------------------------------------------------------------ *
 * Routes
 * ------------------------------------------------------------------------ */

static void route_cases(void)
{
	ncfg_document_t        *document;
	const ncfg_interface_t *interface;

	/*
	 * **A route destination is `default` or a network, and a typo is neither.**
	 * The check let any word through on the grounds that `default` is not a
	 * prefix, so a misspelling compiled, planned, and failed at `route.add` --
	 * after three other actions had been carried out, leaving a machine half
	 * configured over a spelling.
	 */
	refuses("interface eth0 {\n\tconfig = \"10.0.0.1/24\"\n"
	    "\troutes = [\"not-a-prefix via 10.0.0.254\"]\n}\n",
	    "is not a route destination", "a destination that is neither is refused");
	refuses("interface eth0 {\n\tconfig = \"10.0.0.1/24\"\n"
	    "\troutes = [\"not-a-prefix via 10.0.0.254\"]\n}\n",
	    "not-a-prefix", "  and the message names it");

	document = compiles("interface eth0 {\n\tconfig = \"10.0.0.1/24\"\n"
	    "\troutes = [\"default via 10.0.0.254\", \"10.50.0.0/16 via 10.0.0.254\"]\n}\n",
	    "default and a network are both route destinations");
	if (document) {
		interface = interface_named(document, "eth0");
		check(interface && interface->route_count == 2u, "  both survive");
		ncfg_document_free(document);
	}

	/*
	 * `ip route add 10.1.2.3/8` is refused outright with `EINVAL`, and
	 * `2001:db8:1::5/64` is stored masked -- so the desired text never matches
	 * what comes back and the second apply fails `EEXIST`. Refused rather than
	 * masked, because masking would change what the operator wrote into
	 * something else and say nothing.
	 */
	refuses("interface eth0 {\n\tconfig = \"10.0.0.1/24\"\n"
	    "\troutes = [\"10.1.2.3/8 via 10.0.0.254\"]\n}\n",
	    "has host bits set", "a destination with host bits set is refused");
	refuses("interface eth0 {\n\tconfig = \"10.0.0.1/24\"\n"
	    "\troutes = [\"10.1.2.3/8 via 10.0.0.254\"]\n}\n",
	    "10.0.0.0/8", "  and the message shows the network it names");

	refuses("interface eth0 { config = \"dhcp\"; routes = \"default via wombat\" }\n",
	    "needs an IP address", "`via` without an address is refused");
	refuses("interface eth0 { config = \"dhcp\"; routes = \"default via 10.0.0.1 wombat\" }\n",
	    "unknown route keyword", "an unknown route keyword is refused");

	document = compiles("interface eth0 {\n\tconfig = \"10.0.0.1/24\"\n"
	    "\troutes = \"10.9.0.0/24 via 10.0.0.2 metric 50 table 100 onlink\"\n}\n",
	    "a route carries metric, table and onlink");
	if (document) {
		interface = interface_named(document, "eth0");
		check(interface && interface->routes[0].metric.value == 50 &&
		    interface->routes[0].table.value == 100 && interface->routes[0].onlink,
		    "  all three reach the model");
		ncfg_document_free(document);
	}
}

/* ------------------------------------------------------------------------ *
 * Precedence
 * ------------------------------------------------------------------------ */

static void precedence_cases(void)
{
	ncfg_document_t *document;
	fixture_t        files[3];

	files[0].name = "netcfgd.conf";
	files[0].text = "hostname = \"first\"\n";
	files[1].name = "conf.d/10-later.conf";
	files[1].text = "hostname = \"second\"\n";
	document = build(files, 2u, NULL);
	if (!document) {
		check(0, "a later drop-in wins for a scalar");
		printf("    said:\n%s", said);
	} else {
		check(document->globals.hostname_policy.kind == NCFG_HOSTNAME_POLICY_STATIC &&
		    strcmp(document->globals.hostname_policy.name, "second") == 0,
		    "a later drop-in wins for a scalar");
		ncfg_document_free(document);
	}

	/*
	 * Naming the file, not just the line. The two definitions are usually in
	 * different files -- that is what drop-ins are for -- and "line 1" on its
	 * own sends the reader to the wrong file.
	 */
	files[0].text = "interface eth0 { config = \"dhcp\" }\n";
	files[1].text = "interface eth0 { config = \"192.0.2.1/24\" }\n";
	document = build(files, 2u, NULL);
	check(document == NULL, "redefining a block without override is an error");
	check(strstr(said, "is already defined") != NULL, "  it says so");
	check(strstr(said, "netcfgd.conf:1") != NULL, "  and names the first definition's file");
	check(strstr(said, "conf.d/10-later.conf:1:") != NULL, "  and the second's");
	check(strstr(said, "write `override interface eth0`") != NULL, "  and what to write");
	ncfg_document_free(document);

	/* `override` replaces wholesale rather than merging keys. Merging would
	 * make the result depend on which keys the earlier block happened to set,
	 * which is exactly the unpredictability the keyword exists to remove. */
	files[0].text = "interface eth0 {\n\tconfig = \"192.0.2.1/24\"\n\tpreference = 50\n}\n";
	files[1].text = "override interface eth0 {\n\tconfig = \"dhcp\"\n}\n";
	document = build(files, 2u, NULL);
	if (!document) {
		check(0, "override replaces a block entirely");
		printf("    said:\n%s", said);
	} else {
		const ncfg_interface_t *interface = interface_named(document, "eth0");

		check(interface && interface->addressing_count == 1u &&
		    interface->addressing[0].kind == NCFG_ADDRESS_SOURCE_DHCP4,
		    "override replaces a block entirely");
		check(interface && !interface->preference.has,
		    "  the key the replaced block carried is gone");
		ncfg_document_free(document);
	}

	files[0].text = "interface eth0 { config = \"dhcp\" }\n";
	files[1].text = "override interface eth1 { config = \"dhcp\" }\n";
	document = build(files, 2u, NULL);
	check(document == NULL && strstr(said, "has nothing to override") != NULL,
	    "override with nothing to override is an error");
	ncfg_document_free(document);

	/*
	 * **`global` is a singleton several independent things contribute to**,
	 * and a drop-in model has no other way to say so: `ncfg control set` writes
	 * one sub-block and the gui writes another.
	 */
	files[0].text = "global {\n\tdns { mode = \"resolved\" }\n}\n";
	files[1].text = "global {\n\tcontrol { observe = \"group:netdev\" }\n}\n";
	document = build(files, 2u, NULL);
	if (!document) {
		check(0, "two files may each contribute to global");
		printf("    said:\n%s", said);
	} else {
		check(document->globals.dns.mode.mode == NCFG_DNS_MODE_RESOLVED &&
		    document->globals.control.observe.kind == NCFG_PRINCIPAL_GROUP &&
		    strcmp(document->globals.control.observe.name, "netdev") == 0,
		    "two files may each contribute to global");
		ncfg_document_free(document);
	}

	/* A sub-block both files set is a real disagreement and gets the same
	 * error any other duplicate would. */
	files[0].text = "global {\n\tdns { mode = \"resolved\" }\n}\n";
	files[1].text = "global {\n\tdns { mode = \"dnsmasq\" }\n}\n";
	document = build(files, 2u, NULL);
	check(document == NULL && strstr(said, "is already set in `global`") != NULL,
	    "two files setting the same thing in global is still an error");
	ncfg_document_free(document);

	/* A scalar directly in `global` is a key, and later wins for a key. */
	files[0].text = "global {\n\tconfirm = 30\n}\n";
	files[1].text = "global {\n\tconfirm = 120\n}\n";
	document = build(files, 2u, NULL);
	if (!document) {
		check(0, "a scalar in global is a key, so later wins");
		printf("    said:\n%s", said);
	} else {
		check(document->globals.confirm_default.value == 120,
		    "a scalar in global is a key, so later wins");
		ncfg_document_free(document);
	}

	files[0].text = "post_up {\necho hi\n}\n";
	document = build(files, 1u, NULL);
	check(document == NULL && strstr(said, "must be inside an interface block") != NULL,
	    "a hook at the top level is refused");
	ncfg_document_free(document);

	files[0].text = "include \"/etc/netcfgd/site.conf\"\n";
	document = build(files, 1u, NULL);
	check(document == NULL && strstr(said, "include was not resolved") != NULL,
	    "an unresolved include is an error");
	ncfg_document_free(document);
}

/* ------------------------------------------------------------------------ *
 * global
 * ------------------------------------------------------------------------ */

static void global_cases(void)
{
	ncfg_document_t *document;

	document = compiles("global { hostname = \"dhcp\" }\n", "`hostname = dhcp` is a policy");
	if (document) {
		check(document->globals.hostname_policy.kind == NCFG_HOSTNAME_POLICY_FROM_DHCP,
		    "  and not a name");
		ncfg_document_free(document);
	}
	document = compiles("global { hostname = \"kitchen-pi\" }\n", "a hostname is pinned");
	if (document) {
		check(document->globals.hostname_policy.kind == NCFG_HOSTNAME_POLICY_STATIC,
		    "  as a static policy");
		ncfg_document_free(document);
	}
	/* Checked here because the kernel's refusal arrives at apply time as
	 * `EINVAL` on a file write, which names neither the key nor the line. */
	refuses("global { hostname = \"-nope\" }\n", "is not a hostname",
	    "a leading hyphen is not a hostname");
	refuses("global { hostname = \"a..b\" }\n", "is not a hostname",
	    "an empty label is not a hostname");

	/* **The document default is `reconcile`, which is not C's zero value.**
	 * Every symptom of the milestone was a configuration written, a correct
	 * plan, and nothing that ran it. */
	document = compiles("interface eth0 { config = \"dhcp\" }\n",
	    "the drift default is reconcile without being written");
	if (document) {
		check(document->globals.on_drift_default == NCFG_DRIFT_POLICY_RECONCILE,
		    "  which is not the zero value");
		ncfg_document_free(document);
	}
	document = compiles("global { on_drift = \"report\" }\n", "on_drift is sayable");
	if (document) {
		check(document->globals.on_drift_default == NCFG_DRIFT_POLICY_REPORT, "  as report");
		ncfg_document_free(document);
	}
	refuses("global { on_drift = \"maybe\" }\n", "unknown drift policy",
	    "an unknown drift policy is refused");

	/*
	 * A host-wide "no networking" is applied at compile time rather than by
	 * the planner, so that `ncfg show` and `ncfg plan` say what netcfgd
	 * actually wants.
	 */
	document = compiles("global { networking = \"off\" }\n"
	    "interface eth0 { config = \"dhcp\" }\n"
	    "interface eth1 { config = \"dhcp\" }\n", "networking off disables every interface");
	if (document) {
		check(document->interface_count == 2u && !document->interfaces[0].enabled &&
		    !document->interfaces[1].enabled, "  both of them");
		ncfg_document_free(document);
	}
	document = compiles("interface eth0 { config = \"dhcp\" }\n",
	    "networking on is the default");
	if (document) {
		check(document->globals.networking == NCFG_NETWORKING_ON &&
		    document->interfaces[0].enabled, "  and the interface stays enabled");
		ncfg_document_free(document);
	}
	refuses("global { networking = \"maybe\" }\n", "is not a networking setting",
	    "an unknown networking setting is refused");

	refuses("global { profile = \"../escape\" }\n", "cannot be a profile name",
	    "a profile name carrying a separator is refused");

	document = compiles("global {\n\tcontrol {\n\t\tobserve = \"group:netcfgd\"\n"
	    "\t\twifi = \"any\"\n\t\tadmin = \"root\"\n\t}\n}\n", "the control tiers compile");
	if (document) {
		check(document->globals.control.wifi.kind == NCFG_PRINCIPAL_ANY &&
		    document->globals.control.admin.kind == NCFG_PRINCIPAL_ROOT,
		    "  each as its own principal");
		ncfg_document_free(document);
	}
	refuses("global { control { observe = \"wombat\" } }\n", "user:NAME or group:NAME",
	    "a principal that is not one is refused");
	refuses("global { control { wombat = \"root\" } }\n", "unknown control key",
	    "an unknown control key is refused");

	/*
	 * Booleans, where `control` takes principals, and the asymmetry is 0128's
	 * point: a remote caller arrives as the agent, so `user:alice` here would
	 * be a sentence the daemon cannot evaluate.
	 */
	document = compiles("global {\n\tremote {\n\t\tobserve = true\n\t\tadmin = false\n"
	    "\t\tagent = \"user:alice\"\n\t}\n}\n", "the remote tiers are booleans");
	if (document) {
		check(document->globals.remote.observe && !document->globals.remote.admin &&
		    document->globals.remote.agent.kind == NCFG_PRINCIPAL_USER,
		    "  and `agent` is a principal");
		ncfg_document_free(document);
	}
	refuses("global { remote { observe = \"user:alice\" } }\n",
	    "no principal to check", "a principal on a remote tier is refused with the reason");

	/* **Writing `ignore` replaces the default list rather than adding to
	 * it.** `docker0` is why `ignore` exists at all. */
	document = compiles("interface eth0 { config = \"dhcp\" }\n",
	    "the connectivity ignore list has defaults");
	if (document) {
		check(document->globals.connectivity.ignore_count ==
		    ncfg_connectivity_default_ignore_count, "  the shipped families");
		ncfg_document_free(document);
	}
	document = compiles("global { connectivity { ignore = [\"wg*\"] } }\n",
	    "writing ignore replaces the default list");
	if (document) {
		check(document->globals.connectivity.ignore_count == 1u &&
		    strcmp(document->globals.connectivity.ignore[0], "wg*") == 0,
		    "  rather than adding to it");
		ncfg_document_free(document);
	}
	document = compiles("global { connectivity { requires = \"probe\" } }\n",
	    "connectivity can require a probe");
	if (document) {
		check(document->globals.connectivity.requires_ == NCFG_REQUIRES_PROBE,
		    "  for a machine behind a captive portal");
		ncfg_document_free(document);
	}
	refuses("global { connectivity { requires = \"vibes\" } }\n",
	    "is not something to require", "an unknown connectivity requirement is refused");

	refuses("global { wombat = true }\n", "unknown top-level key",
	    "an unknown key in global is refused");
	refuses("global { wombat { } }\n", "is not valid inside `global`",
	    "an unknown block in global is refused");
	refuses("wombat eth0 { }\n", "unknown top-level block `wombat`",
	    "an unknown top-level block is an error rather than ignored");
}

/* ------------------------------------------------------------------------ *
 * DNS
 * ------------------------------------------------------------------------ */

static void dns_cases(void)
{
	ncfg_document_t *document;

	document = compiles("global {\n\tdns {\n\t\tmode = \"write_resolv_conf\"\n"
	    "\t\tservers = [\"192.0.2.53\", \"2001:db8::53\"]\n\t\tsearch = [\"example.com\"]\n"
	    "\t}\n}\n", "a global dns scope compiles");
	if (document) {
		check(document->globals.dns.mode.mode == NCFG_DNS_MODE_WRITE_RESOLV_CONF &&
		    document->globals.dns.server_count == 2u &&
		    document->globals.dns.search_count == 1u, "  mode, servers and search");
		ncfg_document_free(document);
	}

	/* `lower.rs` accepts the file's own name for `write_resolv_conf`, which is
	 * what an operator reaches for, and the document renders the underscored
	 * spelling back. */
	document = compiles("global { dns { mode = \"resolv.conf\" } }\n",
	    "the file's own name is a spelling of write_resolv_conf");
	if (document) {
		check(document->globals.dns.mode.mode == NCFG_DNS_MODE_WRITE_RESOLV_CONF,
		    "  and means the same mode");
		ncfg_document_free(document);
	}
	/*
	 * `exec` is a mode the model has and the language cannot write: it carries
	 * a command, and accepting the word would compile a mode with nothing to
	 * run.
	 */
	refuses("global { dns { mode = \"exec\" } }\n", "unknown dns mode",
	    "`exec` is a document mode the language cannot write");
	refuses("global { dns { mode = \"wombat\" } }\n", "unknown dns mode",
	    "an unknown dns mode is refused");
	refuses("global { dns { servers = [\"not-an-address\"] } }\n", "is not an IP address",
	    "a nameserver that is not an address is refused");
	refuses("global { dns { wombat = true } }\n", "unknown dns key",
	    "an unknown dns key is refused");

	/*
	 * A config that asks a flat mode for routing domains is an error rather
	 * than something to flatten, because flattening sends internal queries to
	 * a public resolver. The refusal is the document's, which is why there is
	 * no second validator here.
	 */
	refuses("interface eth0 {\n\tconfig = \"dhcp\"\n\tdns { domains = [\"corp.example\"] }\n}\n",
	    "cannot express", "routing domains under a flat mode are refused");

	document = compiles("global { dns { mode = \"openresolv\" } }\n"
	    "interface eth0 {\n\tconfig = \"dhcp\"\n"
	    "\tdns { servers = [\"192.0.2.53\"]; domains = [\"corp.example\", \"~vpn.example\"] }\n"
	    "}\n", "routing domains under a mode that can route compile");
	if (document) {
		const ncfg_interface_t *interface = interface_named(document, "eth0");

		/* A leading `~` is resolved's spelling for a routing-only domain:
		 * accepted, with the flag stored rather than the sigil. */
		check(interface && interface->dns && interface->dns->domain_count == 2u &&
		    !interface->dns->domains[0].exclusive,
		    "  and the tilde becomes a flag rather than a character");
		ncfg_document_free(document);
	}
}

/* ------------------------------------------------------------------------ *
 * Wireless
 * ------------------------------------------------------------------------ */

static void network_cases(void)
{
	ncfg_document_t *document;

	document = compiles("network \"Cafe Wifi\" {\n\twifi { psk = \"@secret:cafe\" }\n}\n",
	    "a psk network compiles");
	if (document) {
		check(document->network_count == 1u &&
		    document->networks[0].security.kind == NCFG_SECURITY_PSK &&
		    strcmp(document->networks[0].security.psk.passphrase.name, "cafe") == 0,
		    "  and the passphrase is a reference");
		/* The default is transition mode: offer both and let the access point
		 * choose, which is what joins a network in transition without being
		 * told about it. */
		check(document->networks[0].security.psk.proto == NCFG_PSK_PROTO_WPA2_WPA3,
		    "  the WPA generation defaults to transitional");
		ncfg_document_free(document);
	}

	/*
	 * The whole point of the indirection is that a config file stays safe to
	 * commit. Accepting a bare string would make that a convention rather than
	 * a property.
	 */
	refuses("network \"Cafe\" { wifi { psk = \"hunter2\" } }\n",
	    "must be a secret reference", "an inline passphrase is refused");
	refuses("network \"Cafe\" { wifi { psk = \"@secret:wombat:name\" } }\n",
	    "is not a secret provider", "an unknown secret provider is refused");

	refuses("network \"Cafe\" { wifi { psk = \"@secret:c\"; open = true } }\n",
	    "one kind of security", "a network has one kind of security");

	/*
	 * **Exactly one means at least one.** Three spellings walked past both
	 * guards and compiled to `security: open`; the middle one is why this is a
	 * refusal rather than a warning -- an operator who writes the word `false`
	 * against `open` has said the opposite of what they got.
	 */
	refuses("network \"Cafe\" { wifi { } }\n", "names no security",
	    "an empty wifi block names no security");
	refuses("network \"Cafe\" { wifi { open = false } }\n", "not which it is",
	    "`open = false` says which kind it is not");
	refuses("network \"Cafe\" { wifi { owe = false } }\n", "names no security",
	    "and so does `owe = false`");
	refuses("network \"Cafe\" { metric = 100 }\n", "so it is an open network",
	    "a network with no wifi block must say so");

	document = compiles("network \"guest\" { wifi { owe = true } }\n",
	    "owe is a third answer to \"is this network secured\"");
	if (document) {
		check(document->networks[0].security.kind == NCFG_SECURITY_OWE,
		    "  and not the same as open");
		ncfg_document_free(document);
	}

	/* **A network with no name is one nothing can join.** An SSID may be empty
	 * -- a hidden access point beacons a zero-length one -- but an operator
	 * cannot configure a network by that name. */
	refuses("network \"\" { wifi { open = true } }\n", "needs a name",
	    "a network block with no name is refused");

	document = compiles("network \"Home\" { ssid = \"66006f6f\"; wifi { open = true } }\n",
	    "a non-text ssid can be given as hex");
	if (document) {
		check(document->networks[0].ssid.has && document->networks[0].ssid.length == 4u &&
		    document->networks[0].ssid.bytes[1] == 0, "  including the NUL in the middle");
		ncfg_document_free(document);
	}
	/* Uppercase is refused, because two spellings of one SSID would break the
	 * byte-identical guarantee. */
	refuses("network \"Home\" { ssid = \"66006F6F\"; wifi { open = true } }\n",
	    "not a usable ssid", "an uppercase hex ssid is refused");

	/* **One entry pins; several choose.** A network pinned to one access point
	 * has nowhere to roam. */
	refuses("network \"Home\" {\n\tbssid = \"00:11:22:33:44:55\"\n"
	    "\twifi { psk = \"@secret:h\"; roam { } }\n}\n",
	    "pinned to one access point", "a pinned network cannot also roam");
	document = compiles("network \"Home\" {\n"
	    "\tbssid = [\"00:11:22:33:44:55\", \"00:11:22:33:44:66\"]\n"
	    "\twifi { psk = \"@secret:h\"; roam { } }\n}\n",
	    "several access points may be roamed between");
	if (document) {
		check(document->networks[0].roam && document->networks[0].roam->signal == -70 &&
		    document->networks[0].roam->interval == 30 &&
		    document->networks[0].roam->slow_interval == 300,
		    "  and a roam block has defaults worth having");
		ncfg_document_free(document);
	}
	/* Looking *less* often when the signal is bad than when it is good is the
	 * policy inverted, and it reads as a plausible pair of numbers. */
	refuses("network \"C\" { wifi { psk = \"@secret:c\"; roam { interval = 600 } } }\n",
	    "cannot be longer than `slow_interval`",
	    "a short interval longer than the long one is refused");
	refuses("network \"C\" { wifi { psk = \"@secret:c\"; roam { signal = 70 } } }\n",
	    "is not a signal strength", "a positive dBm is not a signal strength");

	/* A bare string is one address and is not split on whitespace, unlike
	 * every other list-shaped key: the count is what tells a pin from a
	 * choice. */
	document = compiles("network \"Home\" { bssid = \"00:11:22:33:44:55\"; "
	    "wifi { psk = \"@secret:h\" } }\n", "one bssid is a pin");
	if (document) {
		check(document->networks[0].bssid_count == 1u, "  and a string is one entry");
		ncfg_document_free(document);
	}

	/* A name read off a scan needs somewhere to read it from. */
	refuses("network \"Nowhere\" { ssid = \"@bssid\"; wifi { psk = \"@secret:n\" } }\n",
	    "lists none", "a discovered name with no access points is refused");
	document = compiles("network \"Site\" {\n\tssid = \"@bssid\"\n"
	    "\tbssid = \"00:11:22:33:44:55\"\n\twifi { psk = \"@secret:s\" }\n}\n",
	    "a network can be named by its access points");
	if (document) {
		check(!document->networks[0].ssid.has, "  and carries no ssid of its own");
		ncfg_document_free(document);
	}

	/*
	 * Retired by 0154, and named rather than left to "unknown wifi key". The
	 * replacement runs the OTHER WAY UP, so the one thing an operator must not
	 * do is copy the number across.
	 */
	refuses("network \"Home\" { wifi { psk = \"@secret:h\"; priority = 5 } }\n",
	    "ranks the other way up", "`priority` names its replacement and the inversion");

	/* No `ca_cert` check: netcfgd refusing a deployment other tools configure
	 * fine is how it gets replaced by one of them. It is a plan warning. */
	document = compiles("network \"eduroam\" {\n\twifi {\n\t\teap = \"peap\"\n"
	    "\t\tidentity = \"you@example.ac.uk\"\n\t\tpassword = \"@secret:eduroam\"\n"
	    "\t\tphase2 = \"auth=MSCHAPV2\"\n\t}\n}\n",
	    "eap without a ca certificate still compiles");
	if (document) {
		check(document->networks[0].security.kind == NCFG_SECURITY_EAP &&
		    document->networks[0].security.eap.method == NCFG_EAP_METHOD_PEAP &&
		    document->networks[0].security.eap.password != NULL,
		    "  method, identity and password");
		ncfg_document_free(document);
	}
	refuses("network \"e\" { wifi { eap = \"peap\"; password = \"@secret:e\" } }\n",
	    "needs an `identity`", "an EAP network needs an identity");
	refuses("network \"e\" { wifi { eap = \"wombat\"; identity = \"a\" } }\n",
	    "is not an EAP method", "an unknown EAP method is refused");

	/* A path is an instruction to open a file as root; a stored reference
	 * grants nothing the caller did not already give netcfgd. */
	document = compiles("network \"corp\" {\n\twifi {\n\t\teap = \"tls\"\n"
	    "\t\tidentity = \"you@corp.example\"\n\t\tca_cert = \"@secret:corp-ca\"\n"
	    "\t\tclient_cert = \"/etc/netcfgd/certs/you.pem\"\n"
	    "\t\tprivate_key = \"@secret:corp-key\"\n\t}\n}\n",
	    "a certificate is a path or stored content");
	if (document) {
		check(document->networks[0].security.eap.ca_cert.kind == NCFG_CERT_SOURCE_STORED &&
		    document->networks[0].security.eap.client_cert.kind == NCFG_CERT_SOURCE_PATH,
		    "  and the two are told apart by the sigil");
		ncfg_document_free(document);
	}

	refuses("network \"Home\" { wifi { psk = \"@secret:h\" }; wombat { } }\n",
	    "is not valid inside `network`", "an unknown block inside a network is refused");
	refuses("network \"Home\" { wifi { psk = \"@secret:h\"; wombat = 1 } }\n",
	    "unknown wifi key", "an unknown wifi key is refused");
}

static void access_point_cases(void)
{
	ncfg_document_t *document;

	document = compiles("access_point \"Home\" {\n\tdevice = \"wlan0\"\n\tchannel = 36\n"
	    "\tband = \"5\"\n\tregdom = \"se\"\n\twifi { psk = \"@secret:ap\" }\n}\n",
	    "an access point compiles and names its radio");
	if (document) {
		check(document->access_point_count == 1u &&
		    strcmp(document->access_points[0].device, "wlan0") == 0, "  bound to one device");
		/* **Uppercased on the way in**, so the document holds one spelling of
		 * a code that is conventionally capitals. And `"se"` compiles: until
		 * 0221 the device's copy of this check demanded capitals and the
		 * access point's did not, so one file disagreed with itself. */
		check(strcmp(document->access_points[0].regdom, "SE") == 0,
		    "  and a lowercase regdom is accepted and uppercased");
		ncfg_document_free(document);
	}

	refuses("access_point \"Home\" { wifi { psk = \"@secret:ap\" } }\n",
	    "does not say which radio", "an access point without a device is refused");
	refuses("access_point \"Home\" { device = \"wlan0\" }\n", "so it would be open",
	    "an access point without a wifi block is refused");

	/*
	 * `band = "2.4"` with `channel = 36` used to compile and plan cleanly and
	 * fail at `ncfg apply` with the interface already up. It also kept the
	 * example gate blind, because that gate compiles each block and a
	 * render-time refusal is invisible to it.
	 */
	refuses("access_point \"Home\" {\n\tdevice = \"wlan0\"\n\tband = \"2.4\"\n"
	    "\tchannel = 36\n\twifi { psk = \"@secret:ap\" }\n}\n",
	    "is not in the 2.4 GHz band", "a channel outside its band is refused at compile time");
	/* `channel = 0` is hostapd's spelling of "survey and choose", which an
	 * absent `channel` already says. */
	refuses("access_point \"Home\" {\n\tdevice = \"wlan0\"\n\tchannel = 0\n"
	    "\twifi { psk = \"@secret:ap\" }\n}\n", "is not in the 2.4 GHz band",
	    "channel 0 is in no band");
	/* **`6` is accepted here and refused by the renderer**, deliberately: "not
	 * a band" and "a band this build cannot do" are different answers. */
	document = compiles("access_point \"Home\" {\n\tdevice = \"wlan0\"\n\tband = \"6\"\n"
	    "\tchannel = 5\n\twifi { psk = \"@secret:ap\" }\n}\n",
	    "band 6 compiles so the renderer can refuse it in its own words");
	if (document) {
		ncfg_document_free(document);
	}
	refuses("access_point \"Home\" {\n\tdevice = \"wlan0\"\n\tband = \"5g\"\n"
	    "\twifi { psk = \"@secret:ap\" }\n}\n", "is not a band",
	    "a band that is not one is refused at compile time");
	refuses("access_point \"Home\" {\n\tdevice = \"wlan0\"\n\tregdom = \"Sweden\"\n"
	    "\twifi { psk = \"@secret:ap\" }\n}\n", "is not a regulatory domain",
	    "a malformed regulatory domain is refused");

	document = compiles("access_point \"Home\" {\n\tdevice = \"wlan0\"\n"
	    "\twifi { psk = \"@secret:ap\" }\n"
	    "\taccess_control { deny = [\"AA:BB:CC:DD:EE:FF\"] }\n}\n",
	    "an access control block carries one station list");
	if (document) {
		/* Lowercase, sorted and deduplicated, so a comparison against what
		 * hostapd reports is a string comparison rather than a parse. */
		check(document->access_points[0].access_control &&
		    document->access_points[0].access_control->policy == NCFG_ACL_POLICY_DENY &&
		    strcmp(document->access_points[0].access_control->stations[0],
		        "aa:bb:cc:dd:ee:ff") == 0, "  lowercased on the way in");
		ncfg_document_free(document);
	}
	/* hostapd reads one file or the other and never both; a precedence rule
	 * would mean an operator's deny list quietly did nothing. */
	refuses("access_point \"Home\" {\n\tdevice = \"wlan0\"\n"
	    "\twifi { psk = \"@secret:ap\" }\n"
	    "\taccess_control { deny = [\"aa:bb:cc:dd:ee:ff\"]; allow = [\"11:22:33:44:55:66\"] }\n"
	    "}\n", "not both an allow and a deny",
	    "an access point has one station list rather than two");
	refuses("access_point \"Home\" {\n\tdevice = \"wlan0\"\n"
	    "\twifi { psk = \"@secret:ap\" }\n\taccess_control { deny = [\"nonsense\"] }\n}\n",
	    "six colon-separated octets", "a malformed station address is refused");
}

/* ------------------------------------------------------------------------ *
 * Devices and link kinds
 * ------------------------------------------------------------------------ */

static void device_cases(void)
{
	ncfg_document_t     *document;
	const ncfg_device_t *device;

	/*
	 * **An interface name reaches the filesystem all over this tree**, and
	 * `join` with an absolute path replaces the base rather than extending it.
	 * Measured before the check existed: `device "../../etc/evil"` compiled and
	 * planned `link.create ../../etc/evil`.
	 */
	refuses("device \"../../etc/evil\" { kind = \"dummy\" }\n", "is not an interface name",
	    "a device label that is a path is refused");
	refuses("device \"abcdefghijklmnopq\" { kind = \"dummy\" }\n",
	    "at most 15 characters", "a device label too long for the kernel is refused");
	refuses("device br0 { bridge { members = [\"eth0/x\"] } }\n", "cannot contain `/`",
	    "a member that is a path is refused");
	/* The accepted list is not decoration: a rule that refused `wlan0` would
	 * satisfy every rejection above and break the machine. */
	document = compiles("interface eth0.100 { config = \"dhcp\" }\n",
	    "an interface name may contain a dot");
	if (document) {
		ncfg_document_free(document);
	}

	document = compiles("device eth1 { managed = false; on_unmanage = \"clear\" }\n",
	    "a device can say what to do when it stops being managed");
	if (document) {
		device = device_named(document, "eth1");
		check(device && !device->managed && device->on_unmanage == NCFG_ON_UNMANAGE_CLEAR,
		    "  leaving is a policy, not an action");
		ncfg_document_free(document);
	}
	refuses("device eth1 { on_unmanage = \"wombat\" }\n", "is not an `on_unmanage` policy",
	    "an unknown unmanage policy is refused");

	document = compiles("device wlan0 {\n\twifi {\n\t\tbackend = \"iwd\"\n"
	    "\t\tmac_policy = \"per_network\"\n\t\tscan_randomization = true\n"
	    "\t\tpowersave = \"off\"\n\t\tportal_check = \"http://example.com/generate_204\"\n"
	    "\t}\n}\n", "a radio's policy compiles");
	if (document) {
		device = device_named(document, "wlan0");
		/* `iwd` is accepted by the compiler and refused at use, so the
		 * diagnostic can explain the reason rather than reading as a typo. */
		check(device && device->wifi && device->wifi->backend == NCFG_WIFI_BACKEND_IWD &&
		    device->wifi->mac_policy == NCFG_MAC_POLICY_PER_NETWORK &&
		    device->wifi->scan_randomization &&
		    device->wifi->powersave == NCFG_POWERSAVE_OFF,
		    "  including the backend this build refuses at use");
		ncfg_document_free(document);
	}
	document = compiles("device wlan0 { wifi { } }\n", "mac_policy defaults to permanent");
	if (document) {
		device = device_named(document, "wlan0");
		check(device && device->wifi &&
		    device->wifi->mac_policy == NCFG_MAC_POLICY_PERMANENT &&
		    device->wifi->portal_check == NULL && device->wifi->autoconnect,
		    "  and a device that names no url is not probed");
		ncfg_document_free(document);
	}
	/* A portal works by intercepting the request, which is the one thing TLS
	 * prevents -- so an `https` probe reports no portal on exactly the networks
	 * it is for. */
	refuses("device wlan0 { wifi { portal_check = \"https://example.com/x\" } }\n",
	    "cannot use `https`", "an https portal check is refused with the reason");
	refuses("device wlan0 { wifi { portal_check = \"example.com\" } }\n",
	    "is not an `http://` URL", "a portal check that is not a URL is refused");
	refuses("device wlan0 { wifi { mac_policy = \"random\" } }\n", "is not a MAC policy",
	    "the mac_policy the example once documented is refused");

	document = compiles("device eth0 {\n\tethtool {\n\t\tautoneg = \"on\"\n\t\tgro = \"off\"\n"
	    "\t\tduplex = \"full\"\n\t\tspeed = 1000\n\t}\n}\n", "ethtool settings compile");
	if (document) {
		device = device_named(document, "eth0");
		check(device && device->link_settings &&
		    device->link_settings->autoneg == NCFG_TOGGLE_ON &&
		    device->link_settings->gro == NCFG_TOGGLE_OFF &&
		    device->link_settings->speed.value == 1000, "  even though nothing applies them");
		ncfg_document_free(document);
	}
	document = compiles("device eth0 { ethtool { } }\n",
	    "an empty ethtool block produces nothing");
	if (document) {
		device = device_named(document, "eth0");
		check(device && device->link_settings == NULL, "  rather than a structure of defaults");
		ncfg_document_free(document);
	}
	refuses("device eth0 { ethtool { gro = \"maybe\" } }\n", "is not a toggle",
	    "a toggle that is not one is refused");

	document = compiles("device wwan0 { modem { sim = [\"esim\", \"socket\"]; "
	    "apn = \"im.cxn\" } }\n", "a modem block carries the sim order and the apn");
	if (document) {
		device = device_named(document, "wwan0");
		check(device && device->modem && device->modem->sim_count == 2u &&
		    strcmp(device->modem->sim[0], "esim") == 0 &&
		    strcmp(device->modem->apn, "im.cxn") == 0, "  ordered, not a preference");
		ncfg_document_free(document);
	}
	refuses("device wwan0 { modem { sim = [\"esim\", \"esim\"] } }\n", "is listed twice",
	    "a repeated sim source is refused");
	/* These reach a helper that interpolates the APN into
	 * `AT+CGDCONT=1,"IP","<apn>"`, where a quote ends the command early. */
	refuses("device wwan0 { modem { apn = \"im.\\\"cxn\" } }\n", "quote, a backslash",
	    "an apn that would break an AT command is refused");
	refuses("device wwan0 { modem { imsi = \"1234\" } }\n", "unknown modem key",
	    "an unknown modem key is refused");

	refuses("device eth0 { wombat = 1 }\n", "unknown device key",
	    "an unknown device key is refused");
	refuses("device eth0 { wombat { } }\n", "is not valid inside `device`",
	    "an unknown block inside a device is refused");
	refuses("device eth0 {\npost_up {\necho hi\n}\n}\n", "not to a device",
	    "a hook inside a device is refused");

	/* Named rather than left to "unknown interface key": an operator who wrote
	 * one had a working configuration. */
	refuses("interface eth0 { mtu = 1500 }\n", "belongs in the `device` block now",
	    "`mtu` on an interface names where it moved to");
	refuses("interface eth0 { bridge { members = \"eth1\" } }\n",
	    "belongs in the `device` block now", "and so does a `bridge` block");
	refuses("interface eth0 { ethtool { } }\n", "belongs in the `device` block now",
	    "and so does `ethtool`");
	refuses("interface eth0 { wombat = 1 }\n", "unknown interface key",
	    "an unknown interface key is refused");
}

static void kind_cases(void)
{
	ncfg_document_t     *document;
	const ncfg_device_t *device;

	/*
	 * Before this existed the `members` list was accepted and ignored: a
	 * bridge would be created empty and the apply would report success, which
	 * is the worst way for a feature to be missing.
	 */
	document = compiles("device br0 {\n\tbridge {\n\t\tmembers = [\"eth0\", \"eth1\"]\n"
	    "\t\tstp = true\n\t\tforward_delay = 4\n\t\tvlan_filtering = false\n\t}\n}\n",
	    "bridge members become masters");
	if (document) {
		device = device_named(document, "eth0");
		check(device && device->master && strcmp(device->master, "br0") == 0,
		    "  a member with no block of its own gets a device");
		device = device_named(document, "br0");
		check(device && device->kind.kind == NCFG_KIND_BRIDGE && device->kind.bridge.stp &&
		    device->kind.bridge.forward_delay.value == 4,
		    "  and the bridge parameters survive");
		ncfg_document_free(document);
	}
	/* Said twice, differently. One of them is wrong and guessing which would
	 * put an interface in the wrong bridge. */
	refuses("device br0 { bridge { members = \"eth0\" } }\n"
	    "device eth0 { master = \"br1\" }\n", "has one master",
	    "a contradictory membership is refused");
	refuses("device br0 { bridge { members = \"br0\" } }\n", "lists itself as a member",
	    "a bridge that lists itself is refused");
	refuses("device br0 { bridge { wombat = 1 } }\n", "unknown bridge key",
	    "an unknown bridge key is refused");

	/*
	 * A closed set rather than the string it used to be: a string accepts
	 * `activebackup`, which the kernel rejects at apply time -- so the config
	 * compiles, the plan looks right, and the failure arrives with the
	 * interface half-built.
	 */
	document = compiles("device bond0 { bond { members = [\"eth0\"]; mode = \"802.3ad\"; "
	    "miimon = 100 } }\n", "a bonding mode is checked at compile time");
	if (document) {
		device = device_named(document, "bond0");
		check(device && device->kind.kind == NCFG_KIND_BOND &&
		    device->kind.bond.mode == NCFG_BOND_MODE_IEEE_8023AD,
		    "  and `802.3ad` is the spelling iproute2 uses");
		ncfg_document_free(document);
	}
	refuses("device bond0 { bond { members = \"eth0\"; mode = \"activebackup\" } }\n",
	    "is not a bonding mode", "a mode the kernel would reject is refused here");
	refuses("device bond0 { bond { members = \"eth0\" } }\n", "a bond needs a `mode`",
	    "a bond with no mode is refused");

	document = compiles("device vlan10 { vlan { parent = \"eth0\"; id = 10 } }\n",
	    "a vlan block sets the kind");
	if (document) {
		device = device_named(document, "vlan10");
		check(device && device->kind.kind == NCFG_KIND_VLAN && device->kind.vlan.id == 10 &&
		    device->kind.vlan.protocol == NCFG_VLAN_PROTOCOL_DOT1Q,
		    "  with 802.1Q as the default protocol");
		ncfg_document_free(document);
	}
	refuses("device vlan10 { vlan { parent = \"eth0\" } }\n", "needs both `parent` and `id`",
	    "a vlan with no id is refused");

	document = compiles("device vx0 { vxlan { id = 100; parent = \"eth0\"; "
	    "local = \"192.0.2.10\"; remote = \"198.51.100.10\"; port = 4789 } }\n",
	    "vxlan compiles");
	if (document) {
		device = device_named(document, "vx0");
		check(device && device->kind.kind == NCFG_KIND_VXLAN && device->kind.vxlan.id == 100 &&
		    device->kind.vxlan.port.value == 4789, "  with its VNI and port");
		ncfg_document_free(document);
	}
	/* A VNI above 24 bits is silently truncated by the kernel, so two tunnels
	 * that look distinct in the config become one. */
	refuses("device vx0 { vxlan { id = 16777216 } }\n", "24 bits",
	    "a VNI wider than 24 bits is refused");
	refuses("device vx0 { vxlan { id = 1; local = \"192.0.2.1\"; remote = \"2001:db8::1\" } }\n",
	    "same address family", "a vxlan with mixed families is refused");
	refuses("device vx0 { vxlan { } }\n", "a vxlan needs an `id`",
	    "a vxlan with no id is refused");

	document = compiles("device veth0 { veth { peer = \"veth1\" } }\n", "veth compiles");
	if (document) {
		device = device_named(document, "veth0");
		check(device && device->kind.kind == NCFG_KIND_VETH &&
		    strcmp(device->kind.veth.peer, "veth1") == 0, "  and names both ends");
		ncfg_document_free(document);
	}
	refuses("device veth0 { veth { } }\n", "a veth needs a `peer`",
	    "a veth with no peer is refused");

	refuses("device mgmt { vrf { } }\n", "a vrf needs a `table`", "a vrf needs a table");
	document = compiles("device mgmt { vrf { table = 100 } }\n", "a vrf compiles");
	if (document) {
		device = device_named(document, "mgmt");
		check(device && device->kind.kind == NCFG_KIND_VRF && device->kind.vrf.table == 100,
		    "  with its table");
		ncfg_document_free(document);
	}

	document = compiles("device mv0 { macvlan { parent = \"eth0\"; mode = \"bridge\" } }\n",
	    "macvlan compiles");
	if (document) {
		device = device_named(document, "mv0");
		check(device && device->kind.macvlan.mode == NCFG_MACVLAN_MODE_BRIDGE, "  in a mode");
		ncfg_document_free(document);
	}
	refuses("device mv0 { macvlan { mode = \"bridge\" } }\n", "needs a `parent`",
	    "a macvlan with no parent is refused");

	document = compiles("device gre0 { tunnel { mode = \"gre\"; local = \"192.0.2.10\"; "
	    "remote = \"198.51.100.10\"; ttl = 64 } }\n", "a gre tunnel compiles");
	if (document) {
		device = device_named(document, "gre0");
		check(device && device->kind.kind == NCFG_KIND_TUNNEL &&
		    device->kind.tunnel.mode == NCFG_TUNNEL_KIND_GRE &&
		    device->kind.tunnel.ttl.value == 64, "  with its endpoints");
		ncfg_document_free(document);
	}
	/* There is no attribute for an underlay in geneve's netlink family and
	 * `ip` offers no `dev` for it either, so a `parent` could only ever be
	 * dropped -- and it was, silently. */
	refuses("device gv0 { tunnel { mode = \"geneve\"; parent = \"eth0\" } }\n",
	    "no underlay interface", "a geneve tunnel has no parent");
	/* A v6 remote on an `ipip` produces a link the kernel refuses to build,
	 * with an error naming neither. */
	refuses("device t0 { tunnel { mode = \"ipip\"; remote = \"2001:db8::1\" } }\n",
	    "outer header", "a tunnel endpoint must match its encapsulation");
	refuses("device t0 { tunnel { local = \"192.0.2.1\" } }\n", "a tunnel needs a `mode`",
	    "a tunnel with no mode is refused");

	document = compiles("device tun0 { tun { owner = \"openvpn\" } }\n",
	    "a tun device compiles");
	if (document) {
		device = device_named(document, "tun0");
		check(device && device->kind.kind == NCFG_KIND_TUN &&
		    device->kind.tun.mode == NCFG_TUN_MODE_TUN, "  and `tap` is the other spelling");
		ncfg_document_free(document);
	}
	document = compiles("device tap0 { tap { } }\n", "a tap device compiles");
	if (document) {
		device = device_named(document, "tap0");
		check(device && device->kind.tun.mode == NCFG_TUN_MODE_TAP, "  as ethernet frames");
		ncfg_document_free(document);
	}

	document = compiles("device dummy0 { kind = \"dummy\" }\n",
	    "the kinds with no parameters are said as a key");
	if (document) {
		device = device_named(document, "dummy0");
		check(device && device->kind.kind == NCFG_KIND_DUMMY, "  `dummy` being the one");
		ncfg_document_free(document);
	}
	refuses("device d0 { kind = \"wombat\" }\n", "is not a device kind",
	    "an unknown device kind is refused");

	document = compiles("device ppp0 { pppoe { parent = \"eth0\"; username = \"u\"; "
	    "password = \"@secret:isp\" } }\n", "pppoe compiles");
	if (document) {
		device = device_named(document, "ppp0");
		check(device && device->kind.kind == NCFG_KIND_PPPOE &&
		    strcmp(device->kind.pppoe.password.name, "isp") == 0,
		    "  and the password is a reference");
		ncfg_document_free(document);
	}
	refuses("device ppp0 { pppoe { parent = \"eth0\"; username = \"u\"; "
	    "password = \"hunter2\" } }\n", "must be a secret reference",
	    "a pppoe password must be a secret");
	refuses("device ppp0 { pppoe { username = \"u\"; password = \"@secret:i\" } }\n",
	    "needs a `parent`", "a pppoe session with no parent is refused");

	/* Decision 0046: `openvpn --help` lists 253 top-level options, so netcfgd
	 * expressing the surface would be a second configuration language
	 * permanently behind the first. */
	document = compiles("device tun0 { openvpn { config = \"/etc/openvpn/w.ovpn\"; "
	    "username = \"you\"; password = \"@secret:vpn\" } }\n", "openvpn compiles");
	if (document) {
		device = device_named(document, "tun0");
		check(device && device->kind.kind == NCFG_KIND_OPENVPN &&
		    device->kind.openvpn.password != NULL, "  as a path and a login");
		ncfg_document_free(document);
	}
	refuses("device tun0 { openvpn { config = \"w.ovpn\" } }\n", "is not an absolute path",
	    "a relative .ovpn path is refused");
	/* OpenVPN prompts on the console for whichever is missing, and a daemon
	 * netcfgd started has no console to prompt on. */
	refuses("device tun0 { openvpn { config = \"/x.ovpn\"; username = \"you\" } }\n",
	    "or neither", "an openvpn login needs both halves");
	refuses("device tun0 { openvpn { config = \"/x.ovpn\"; cipher = \"aes\" } }\n",
	    "unknown openvpn key", "another openvpn option is refused by name");

	document = compiles("device wg0 {\n\twireguard {\n\t\tprivate_key = \"@secret:wg0\"\n"
	    "\t\tlisten_port = 51820\n\t\tpeer \"office\" {\n"
	    "\t\t\tpublic_key = \"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\"\n"
	    "\t\t\tendpoint = \"vpn.example.com:51820\"\n"
	    "\t\t\tallowed_ips = [\"10.9.0.0/24\"]\n\t\t\tkeepalive = 25\n\t\t}\n\t}\n}\n",
	    "wireguard compiles");
	if (document) {
		device = device_named(document, "wg0");
		check(device && device->kind.kind == NCFG_KIND_WIREGUARD &&
		    device->kind.wireguard.peer_count == 1u &&
		    device->kind.wireguard.listen_port.value == 51820, "  with one peer");
		ncfg_document_free(document);
	}
	refuses("device wg0 { wireguard { private_key = \"@secret:w\"; "
	    "peer \"a\" { public_key = \"nope\"; allowed_ips = \"0.0.0.0/0\" } } }\n",
	    "is not a public key", "a malformed public key is refused at compile time");
	refuses("device wg0 { wireguard { private_key = \"hunter2\" } }\n",
	    "must be a secret reference", "a wireguard private key must be a secret");
	refuses("device wg0 { wireguard { } }\n", "needs a `private_key`",
	    "a wireguard device with no key is refused");
	/* A peer with no allowed IPs receives nothing and is routed nothing. It is
	 * legal to the kernel and never what anybody meant. */
	refuses("device wg0 { wireguard { private_key = \"@secret:w\"; peer \"a\" { "
	    "public_key = \"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\" } } }\n",
	    "nothing would route to it", "a peer with no allowed_ips is refused");
	/* The key is the peer's identity, so the kernel would keep whichever came
	 * last and the other's allowed IPs would silently vanish. */
	refuses("device wg0 { wireguard { private_key = \"@secret:w\"\n"
	    "peer \"a\" { public_key = \"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\"; "
	    "allowed_ips = \"10.0.0.0/8\" }\n"
	    "peer \"b\" { public_key = \"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\"; "
	    "allowed_ips = \"10.1.0.0/16\" } } }\n", "share the public key",
	    "two peers may not share a public key");
}

/* ------------------------------------------------------------------------ *
 * Queueing and bridge VLANs
 * ------------------------------------------------------------------------ */

static void qdisc_cases(void)
{
	ncfg_document_t     *document;
	const ncfg_device_t *device;

	/* Decimal multipliers, as `tc` uses them: `kbit` is 1000 bits, not 1024. */
	document = compiles("device eth0 { qdisc { kind = \"cake\"; bandwidth = \"100mbit\" } }\n",
	    "a shaped rate is converted to bits");
	if (document) {
		device = device_named(document, "eth0");
		check(device && device->qdisc && device->qdisc->bandwidth_bits.value == 100000000,
		    "  a hundred million of them");
		ncfg_document_free(document);
	}
	/* Decision 0023 keeps netcfgd to the root qdisc, and an open string would
	 * make that line invisible: `htb` would compile, apply, and produce a
	 * class-less shaper that drops everything. */
	refuses("device eth0 { qdisc { kind = \"htb\" } }\n", "classful schedulers like `htb`",
	    "a classful scheduler is refused with the reason");
	/* A rate on `fq_codel` is somebody expecting their line to be shaped, and
	 * silently dropping it would leave them with an unshaped uplink and a
	 * config that says otherwise. */
	refuses("device eth0 { qdisc { kind = \"fq_codel\"; bandwidth = \"10mbit\" } }\n",
	    "cannot shape to a rate", "a rate on a scheduler that cannot shape is refused");
	refuses("device eth0 { qdisc { kind = \"cake\"; bandwidth = \"wombat\" } }\n",
	    "is not a rate", "a malformed rate is reported");
	refuses("device eth0 { qdisc { kind = \"cake\"; bandwidth = \"0mbit\" } }\n",
	    "would pass nothing", "a shaped rate of zero is refused");
	refuses("device eth0 { qdisc { bandwidth = \"10mbit\" } }\n", "needs a `kind`",
	    "a qdisc block with no kind is refused");
	document = compiles("device eth0 { qdisc = \"fq_codel\" }\n",
	    "the shorthand spelling sets the scheduler");
	if (document) {
		device = device_named(document, "eth0");
		check(device && device->qdisc && device->qdisc->kind == NCFG_QDISC_FQ_CODEL,
		    "  for a scheduler that needs no parameters");
		ncfg_document_free(document);
	}

	/*
	 * The kernel cannot queue traffic on the way in, so the standard answer --
	 * and the only one -- is to redirect it onto an intermediate device, where
	 * it becomes egress and can be shaped like anything else.
	 */
	document = compiles("device eth0 { qdisc { kind = \"cake\"; "
	    "ingress_bandwidth = \"50mbit\" } }\n",
	    "ingress shaping expands into a device and a redirect");
	if (document) {
		device = device_named(document, "eth0");
		check(device && device->ingress_redirect &&
		    strcmp(device->ingress_redirect, "ifb-eth0") == 0, "  the redirect is named");
		device = device_named(document, "ifb-eth0");
		check(device && device->kind.kind == NCFG_KIND_IFB && device->qdisc &&
		    device->qdisc->ingress && device->qdisc->bandwidth_bits.value == 50000000,
		    "  and the ifb carries the rate");
		ncfg_document_free(document);
	}
	refuses("device abcdefghijkl { qdisc { kind = \"cake\"; "
	    "ingress_bandwidth = \"50mbit\" } }\n", "too long a name",
	    "an interface too long to shape arrivals on is refused");
	refuses("device eth0 { qdisc { kind = \"fq_codel\"; ingress_bandwidth = \"50mbit\" } }\n",
	    "cannot shape arriving traffic", "ingress shaping needs cake");
	/* Refused rather than merged: netcfgd would otherwise take over a device
	 * somebody else declared, and the generic duplicate check says nothing
	 * about the ingress shaping that needs the name. */
	refuses("device eth0 { qdisc { kind = \"cake\"; ingress_bandwidth = \"50mbit\" } }\n"
	    "device ifb-eth0 { kind = \"dummy\" }\n", "needs to create a device of that name",
	    "a colliding ifb name is refused");

	/* Ranges are expanded here rather than carried in the model: the kernel
	 * compresses consecutive ids on the way out and this expands them on the
	 * way in. */
	document = compiles("device eth0 { vlans = \"10 pvid untagged\n20-22\" }\n",
	    "bridge vlans compile");
	if (document) {
		device = device_named(document, "eth0");
		check(device && device->bridge_vlan_count == 4u && device->bridge_vlans[0].pvid &&
		    device->bridge_vlans[0].untagged, "  a range expands and a pvid is one");
		ncfg_document_free(document);
	}
	refuses("device eth0 { vlans = \"4095\" }\n", "is not a VLAN id",
	    "an impossible vlan id is refused");
	refuses("device eth0 { vlans = \"0\" }\n", "is not a VLAN id", "and so is zero");
	/* A PVID is where untagged ingress lands, so a range of them would mean
	 * several answers to one question. */
	refuses("device eth0 { vlans = \"10-19 pvid\" }\n", "range cannot be the pvid",
	    "a range cannot be the pvid");
	refuses("device eth0 { vlans = \"20-10\" }\n", "counts backwards",
	    "a range that counts backwards is refused");
	refuses("device eth0 { vlans = \"10 wombat\" }\n", "is not a vlan option",
	    "an unknown vlan option is refused");
}

/* ------------------------------------------------------------------------ *
 * Rules, linksets, bluetooth
 * ------------------------------------------------------------------------ */

static void rule_cases(void)
{
	ncfg_document_t *document;

	document = compiles("rule \"vpn-subnet\" {\n\tfamily = \"ipv4\"\n"
	    "\tfrom = \"192.168.50.0/24\"\n\tlookup = 100\n\tpriority = 1000\n}\n",
	    "policy routing rules compile");
	if (document) {
		check(document->rule_count == 1u && document->rules[0].priority == 1000 &&
		    document->rules[0].table.value == 100 &&
		    document->rules[0].family == NCFG_RULE_FAMILY_INET,
		    "  and `ipv4` is a spelling of `inet`");
		ncfg_document_free(document);
	}
	/* Canonicalised for the same reason an address is: `2001:0DB8::/32` was a
	 * rule torn down and reinstalled on every apply, with a window in between
	 * where it did not exist. */
	document = compiles("rule \"v6\" { family = \"ipv6\"; from = \"2001:0DB8::/32\"; "
	    "lookup = 100; priority = 100 }\n", "a rule selector is canonicalised");
	if (document) {
		check(strcmp(document->rules[0].from, "2001:db8::/32") == 0,
		    "  into the kernel's spelling");
		ncfg_document_free(document);
	}
	document = compiles("rule \"q\" { from = \"192.168.99.0/24\"; action = \"unreachable\"; "
	    "priority = 1100 }\n", "a rule can refuse traffic rather than redirect it");
	if (document) {
		check(document->rules[0].action == NCFG_RULE_ACTION_UNREACHABLE, "  by naming an action");
		ncfg_document_free(document);
	}
	/* The kernel will assign a priority, but an unnumbered rule lands wherever
	 * it puts one and two applies can produce different orders. */
	refuses("rule \"a\" { from = \"10.0.0.0/8\"; lookup = 100 }\n", "has no `priority`",
	    "a rule without a priority is refused");
	refuses("rule \"a\" { from = \"10.0.0.0/8\"; priority = 100 }\n",
	    "looks up no table and names no action", "a rule that does nothing is refused");
	refuses("rule \"a\" { fwmask = 255; lookup = 1; priority = 100 }\n",
	    "`fwmask` but no `fwmark`", "a mask without a mark is refused");
	refuses("rule \"a\" { action = \"wombat\"; priority = 100 }\n", "is not a rule action",
	    "an unknown rule action is refused");
	refuses("rule \"a\" { family = \"ipx\"; lookup = 1; priority = 1 }\n",
	    "is not an address family", "an unknown address family is refused");
	refuses("rule \"a\" { wombat = 1; lookup = 1; priority = 1 }\n", "unknown rule key",
	    "an unknown rule key is refused");
	refuses("rule { lookup = 1; priority = 1 }\n", "needs a name",
	    "a rule with no label is refused");
}

static void linkset_cases(void)
{
	ncfg_document_t *document;

	document = compiles("interface eth0 { config = \"dhcp\"; preference = 100 }\n"
	    "interface wwan0 { config = \"dhcp\"; preference = 700 }\n"
	    "network \"office\" { wifi { psk = \"@secret:o\" }; config = \"dhcp\" }\n"
	    "linkset \"uplink\" { members = [\"eth0\", \"office\", \"wwan0\"] }\n",
	    "a linkset names links that have to exist");
	if (document) {
		check(document->linkset_count == 1u && document->linksets[0].member_count == 3u &&
		    strcmp(document->linksets[0].members[0], "eth0") == 0,
		    "  and the order is the ranking, so nothing sorts it");
		ncfg_document_free(document);
	}
	/* An `uplink` naming an interface this configuration does not describe
	 * answers "disconnected" for ever with nothing saying why. */
	refuses("linkset \"uplink\" { members = [\"eth0\"] }\n",
	    "which this configuration does not describe", "a member that resolves to nothing");
	refuses("linkset \"uplink\" { members = [] }\n", "has no members",
	    "a linkset with no members is refused");
	refuses("interface eth0 { config = \"dhcp\" }\n"
	    "linkset \"eth0\" { members = [\"eth0\"] }\n", "already the name of a link",
	    "a linkset may not share a name with a link");
	refuses("interface eth0 { config = \"dhcp\" }\n"
	    "linkset \"a\" { members = [\"eth0\", \"eth0\"] }\n", "is listed twice",
	    "a member said twice is refused rather than deduplicated");
	refuses("interface eth0 { config = \"dhcp\" }\n"
	    "linkset \"a\" { members = [\"b\"] }\n"
	    "linkset \"b\" { members = [\"a\"] }\n", "contains itself",
	    "a linkset that contains itself through another is refused");
	refuses("linkset \"a\" { wombat = 1 }\n", "is not a `linkset` setting",
	    "an unknown linkset key is refused");
	/* A set composes into another set, which is what makes the group a link in
	 * its own right. */
	document = compiles("interface eth0 { config = \"dhcp\" }\n"
	    "interface eth1 { config = \"dhcp\" }\n"
	    "linkset \"wired\" { members = [\"eth0\", \"eth1\"] }\n"
	    "linkset \"uplink\" { members = [\"wired\"] }\n",
	    "a linkset composes but does not contain itself");
	if (document) {
		ncfg_document_free(document);
	}
}

static void bluetooth_cases(void)
{
	ncfg_document_t *document;

	document = compiles("bluetooth \"headphones\" {\n\taddress = \"aa:bb:cc:dd:ee:ff\"\n"
	    "\tprofile = \"a2dp-sink\"\n}\n", "a bluetooth device compiles");
	if (document) {
		/* Uppercased rather than accepted as written, because the same address
		 * in two cases is two strings to everything downstream. BlueZ prints
		 * uppercase. */
		check(document->bluetooth_count == 1u &&
		    strcmp(document->bluetooth[0].address, "AA:BB:CC:DD:EE:FF") == 0 &&
		    document->bluetooth[0].profile == NCFG_BLUETOOTH_PROFILE_A2DP_SINK &&
		    document->bluetooth[0].autoconnect, "  uppercased, and autoconnect by default");
		ncfg_document_free(document);
	}
	/* **Kebab-cased, and the only set here that is.** The rest of the language
	 * spells its words with underscores. */
	refuses("bluetooth \"h\" { address = \"AA:BB:CC:DD:EE:FF\"; profile = \"a2dp_sink\" }\n",
	    "is not a Bluetooth profile", "the underscored spelling of a profile is refused");
	refuses("bluetooth \"h\" { address = \"AA-BB-CC-DD-EE-FF\"; profile = \"hfp\" }\n",
	    "is not a Bluetooth address", "a dashed address is refused by the language");
	refuses("bluetooth \"h\" { profile = \"hfp\" }\n", "names no address",
	    "a bluetooth device needs an address");
	refuses("bluetooth \"h\" { address = \"AA:BB:CC:DD:EE:FF\" }\n", "names no profile",
	    "and a profile");
	refuses("bluetooth \"h\" { address = \"AA:BB:CC:DD:EE:FF\"; profile = \"hfp\"; "
	    "paired = true }\n", "unknown bluetooth key", "an unknown bluetooth key is refused");
}

/* ------------------------------------------------------------------------ *
 * Interfaces: hooks, probes, dot1x, advertise
 * ------------------------------------------------------------------------ */

static void interface_cases(void)
{
	ncfg_document_t        *document;
	const ncfg_interface_t *interface;

	/*
	 * A hook body ends at the first line that is nothing but a closing brace,
	 * and braces inside the shell DO matter, because netcfgd does not parse
	 * what is in a hook and so cannot tell your braces from its own.
	 */
	document = compiles("interface eth0 {\n\tconfig = \"dhcp\"\n\tpost_up {\n"
	    "greet() { echo hello; }\ngreet\n}\n}\n", "a hook body survives braces in the shell");
	if (document) {
		interface = interface_named(document, "eth0");
		check(interface && interface->hook_count == 1u &&
		    interface->hooks[0].phase == NCFG_HOOK_PHASE_POST_UP, "  as one post_up hook");
		check(hooks_seen.count == 1 && strstr(hooks_seen.bodies[0], "greet() { echo hello; }"),
		    "  and the sink is handed the shell unchanged");
		ncfg_document_free(document);
	}

	/* Six are written bare and five only after `on`. */
	document = compiles("interface eth0 {\n\tconfig = \"dhcp\"\n"
	    "\ton carrier {\ntrue\n}\n\ton drift {\ntrue\n}\n}\n",
	    "`on` names the remaining phases");
	if (document) {
		interface = interface_named(document, "eth0");
		check(interface && interface->hook_count == 2u, "  both of them");
		ncfg_document_free(document);
	}

	/* Refusing loudly beats silently dropping the hooks and producing a
	 * document that describes a system nobody asked for. */
	{
		fixture_t file = { "netcfgd.conf",
			"interface eth0 { config = \"dhcp\"\npost_up {\ntrue\n}\n}\n" };
		ncfg_document_t *refused = build(&file, 1u, ncfg_hook_sink_refusing());

		check(refused == NULL && strstr(said, "cannot accept hooks") != NULL,
		    "a sink that will not carry hooks refuses loudly");
		ncfg_document_free(refused);
	}
	refuses("interface eth0 { config = \"dhcp\"\nwombat { key = 1 }\n}\n",
	    "is not valid inside `interface`", "an unknown block inside an interface is refused");

	document = compiles("interface eth0 {\n\tconfig = \"dhcp\"\n\tprobe {\n"
	    "\t\tcommand = \"/usr/share/netcfgd/probe/default\"\n\t\targs = [\"eth0\"]\n"
	    "\t\tinterval = 30\n\t\tdown_after = 3\n\t\tup_after = 2\n\t\thold_down = 60\n"
	    "\t}\n}\n", "a probe compiles");
	if (document) {
		interface = interface_named(document, "eth0");
		check(interface && interface->probe && interface->probe->arg_count == 1u &&
		    interface->probe->down_after == 3 && interface->probe->require_lease,
		    "  and `require_lease` is on unless turned off");
		ncfg_document_free(document);
	}
	/* A probe runs as root, so it is named by path and not found on PATH. */
	refuses("interface eth0 { config = \"dhcp\"; probe { command = \"ping\" } }\n",
	    "is not an absolute path", "a probe command must be absolute");
	/* A zero count would mean "change my mind on no evidence". */
	refuses("interface eth0 { config = \"dhcp\"; probe { command = \"/bin/true\"; "
	    "up_after = 0 } }\n", "at least 1", "a zero result count is refused");
	refuses("interface eth0 { config = \"dhcp\"; probe { command = \"/bin/true\"; "
	    "wombat = 1 } }\n", "is not valid inside `probe`", "an unknown probe key is refused");

	/*
	 * A token is an interface identifier, so the prefix bits must be zero. The
	 * kernel accepts a full address and silently uses only the host part,
	 * which means a config that looks like it pins a whole address quietly
	 * pins half of one.
	 */
	document = compiles("interface eth0 { config = \"slaac\"; ipv6_token = \"::10\" }\n",
	    "an ipv6 token compiles");
	if (document) {
		interface = interface_named(document, "eth0");
		check(interface && interface->ipv6_token &&
		    strcmp(interface->ipv6_token, "::10") == 0, "  as the host part only");
		ncfg_document_free(document);
	}
	refuses("interface eth0 { config = \"slaac\"; ipv6_token = \"2001:db8::5\" }\n",
	    "bits set in the prefix half", "an ipv6 token must be host bits only");
	refuses("interface eth0 { config = \"slaac\"; ipv6_token = \"10.0.0.1\" }\n",
	    "is not an IPv6 address", "an ipv4 token is refused");

	/*
	 * Decision 0008 puts 802.1X on the interface rather than inside a wifi
	 * profile, because port-based access control predates radios and nesting
	 * it under an SSID made the wired case inexpressible.
	 */
	document = compiles("interface eth0 {\n\tconfig = \"dhcp\"\n\tdot1x {\n"
	    "\t\teap = \"tls\"\n\t\tidentity = \"host/machine.corp\"\n"
	    "\t\tca_cert = \"/etc/ssl/corp.pem\"\n\t}\n}\n", "a wired port can carry dot1x");
	if (document) {
		interface = interface_named(document, "eth0");
		check(interface && interface->dot1x &&
		    interface->dot1x->method == NCFG_EAP_METHOD_TLS, "  as an EAP configuration");
		ncfg_document_free(document);
	}
	refuses("interface eth0 { config = \"dhcp\"; dot1x { psk = \"@secret:x\" } }\n",
	    "means nothing on a wired port", "wireless-only keys are refused on a wired port");
	refuses("interface eth0 { config = \"dhcp\"; dot1x { identity = \"a\" } }\n",
	    "needs an `eap` method", "dot1x without a method is refused");

	/* The prefix is a reference for the same reason the address was: no config
	 * file could contain a block an ISP has not handed out yet. */
	document = compiles("interface lan0 {\n\tconfig = \"192.168.1.1/24\"\n\tadvertise {\n"
	    "\t\tbackend = \"radvd\"\n\t\tprefixes = [\"@pd:wan0/1\"]\n\t\tlifetime = 1800\n"
	    "\t}\n}\n", "an interface can advertise a delegated prefix");
	if (document) {
		interface = interface_named(document, "lan0");
		check(interface && interface->advertise && interface->advertise->prefix_count == 1u &&
		    strcmp(interface->advertise->prefixes[0].source, "wan0") == 0 &&
		    interface->advertise->prefixes[0].subnet == 1, "  naming a subnet of it");
		check(interface && interface->advertise->dns,
		    "  and `dns` defaults to true rather than false");
		ncfg_document_free(document);
	}
	refuses("interface lan0 { advertise { prefixes = [\"2001:db8::/64\"] } }\n",
	    "is not a prefix reference", "an advertised prefix must be a reference");
	refuses("interface lan0 { advertise { managed = true } }\n",
	    "needs a prefix to advertise", "an advertise block needs something to advertise");
	refuses("interface lan0 { advertise { prefixes = [\"@pd:w\"]; backend = \"wombat\" } }\n",
	    "router advertisement backend", "an unknown advertise backend is refused");

	document = compiles("interface eth0 {\n\tconfig = \"dhcp\"\n\tenabled = true\n"
	    "\tpreference = 100\n\tforwarding = true\n\tnat = true\n\ton_drift = \"ignore\"\n"
	    "\tguard = \"nfs root\"\n}\n", "the rest of an interface compiles");
	if (document) {
		interface = interface_named(document, "eth0");
		check(interface && interface->preference.value == 100 &&
		    interface->forwarding.has && interface->forwarding.value &&
		    interface->nat.has && interface->on_drift.has &&
		    interface->on_drift.value == NCFG_DRIFT_POLICY_IGNORE,
		    "  and absent is different from false throughout");
		/* The reason is a string rather than a flag because the refusal text is
		 * the whole value: "eth0 is critical" sends the reader looking. */
		check(interface && interface->guard &&
		    strcmp(interface->guard->reason, "nfs root") == 0, "  a guard carries its reason");
		ncfg_document_free(document);
	}
}

/* ------------------------------------------------------------------------ *
 * The example file, which is the acceptance test
 * ------------------------------------------------------------------------ */

#define EXAMPLE_PATH "../doc/netcfgd.conf.example"

/*
 * The blocks in the example that are expected NOT to compile alone, named
 * rather than skipped by pattern so that a fourth joining them is a failure.
 *
 *   - `override interface` needs the block it overrides.
 *   - one `interface eth0` carries a per-interface `dns` scope with routing
 *     domains, which needs the `global` block whose `dns_mode` can express
 *     them; alone it compiles against the default mode `none` and is refused.
 *   - the `linkset` names the links it chooses between, and a member that
 *     resolves to nothing is refused on purpose.
 *
 * All three are correct as documentation and meaningless in isolation. A gate
 * that silently tolerated "anything that does not compile" would tolerate the
 * next real error too.
 *
 * `tool/example_gate.py`'s own header says "TWO BLOCKS ARE EXPECTED NOT TO
 * COMPILE ALONE" and then names three; the list is the authority, and the
 * count in the prose is stale.
 */
static const char *const expected_incomplete[] = {
	"override interface eth0 {",
	"interface eth0 {\n\tconfig = \"dhcp\"\n\tdns {",
	"linkset \"uplink\" {"
};

/* Every top-level block head this build accepts. The example calls itself
 * "every feature, with the syntax to use it", and a block that is missing
 * entirely is invisible to a gate that only compiles what is there --
 * `bluetooth` was in the language from 0149 and in that file never. */
static const char *const block_heads[] = { "global", "interface", "device", "network",
	"access_point", "rule", "linkset", "bluetooth" };

static char *read_example(size_t *length_out)
{
	FILE  *handle = fopen(EXAMPLE_PATH, "rb");
	char  *text;
	long   size;
	size_t got;

	if (!handle) {
		return NULL;
	}
	if (fseek(handle, 0, SEEK_END) != 0 || (size = ftell(handle)) < 0) {
		(void)fclose(handle);
		return NULL;
	}
	rewind(handle);
	text = malloc((size_t)size + 1u);
	if (!text) {
		(void)fclose(handle);
		return NULL;
	}
	got = fread(text, 1u, (size_t)size, handle);
	(void)fclose(handle);
	text[got] = '\0';
	*length_out = got;
	return text;
}

/* Whether a line, minus its leading `#`, ends a statement with `{` once
 * trailing whitespace is gone. This is `example_gate.py`'s `body.strip()
 * .endswith("{")`, byte for byte. */
static int opens_block(const char *body, size_t length)
{
	while (length > 0 && (body[length - 1u] == ' ' || body[length - 1u] == '\t' ||
	    body[length - 1u] == '\r')) {
		length--;
	}
	return length > 0 && body[length - 1u] == '{';
}

static int brace_delta(const char *body, size_t length)
{
	int    delta = 0;
	size_t i;

	for (i = 0; i < length; i++) {
		if (body[i] == '{') {
			delta++;
		} else if (body[i] == '}') {
			delta--;
		}
	}
	return delta;
}

static void example_cases(void)
{
	size_t length = 0;
	char  *text = read_example(&length);
	char  *cursor;
	char   block[8192];
	size_t block_length = 0;
	int    depth = 0;
	size_t number = 0;
	size_t start = 0;
	size_t found = 0;
	size_t allowed = 0;
	size_t bad = 0;
	size_t head;

	if (!text) {
		/* A gate that cannot find its corpus must fail rather than pass
		 * quietly: a sweep over nothing reports success exactly as loudly as a
		 * real one. */
		check(0, "the example file is readable from the test's directory");
		printf("    could not open %s\n", EXAMPLE_PATH);
		return;
	}

	cursor = text;
	while (*cursor) {
		char  *newline = strchr(cursor, '\n');
		size_t line_length = newline ? (size_t)(newline - cursor) : strlen(cursor);
		char  *body = cursor + 1;
		size_t body_length = line_length ? line_length - 1u : 0;

		number++;
		if (cursor[0] != '#') {
			goto next;
		}
		if (depth == 0) {
			if (!opens_block(body, body_length)) {
				goto next;
			}
			block_length = 0;
			start = number;
			depth = brace_delta(body, body_length);
			if (body_length + 1u < sizeof(block)) {
				memcpy(block, body, body_length);
				block_length = body_length;
				block[block_length++] = '\n';
			}
			goto next;
		}
		if (block_length + body_length + 2u < sizeof(block)) {
			memcpy(block + block_length, body, body_length);
			block_length += body_length;
			block[block_length++] = '\n';
		}
		depth += brace_delta(body, body_length);
		if (depth == 0) {
			ncfg_document_t *document;
			int              expected = 0;
			size_t           i;

			block[block_length] = '\0';
			found++;
			for (i = 0; i < sizeof(expected_incomplete) / sizeof(expected_incomplete[0]); i++) {
				if (strncmp(block, expected_incomplete[i],
				    strlen(expected_incomplete[i])) == 0) {
					expected = 1;
				}
			}
			document = build_one(block);
			if (document && expected) {
				printf("%s:%zu: compiles alone now; take it off the list\n", EXAMPLE_PATH,
				    start);
				bad++;
			} else if (!document && !expected) {
				char first[96];

				(void)snprintf(first, sizeof(first), "%.*s",
				    (int)(strchr(block, '\n') - block), block);
				printf("%s:%zu: %s\n", EXAMPLE_PATH, start, first);
				printf("    %s", said);
				bad++;
			} else if (!document) {
				allowed++;
			}
			ncfg_document_free(document);
		}

	next:
		if (!newline) {
			break;
		}
		cursor = newline + 1;
	}

	/*
	 * The extractor silently finding nothing is the failure mode this gate
	 * shares with every other. Fifty is `example_gate.py`'s floor and the file
	 * currently carries ninety-three.
	 */
	check(found >= 50u, "the example extractor finds the blocks it should");
	if (found < 50u) {
		printf("    only %zu blocks found in %s; the extractor is broken, not the file\n",
		    found, EXAMPLE_PATH);
	}
	check(bad == 0, "every block in the example compiles, or is a named exception");
	if (bad == 0) {
		printf("    %zu blocks compiled, %zu known-incomplete and named\n", found, allowed);
	}
	check(allowed == sizeof(expected_incomplete) / sizeof(expected_incomplete[0]),
	    "each named exception is still one");

	/* Every block the language accepts is written down in the example. A
	 * feature nobody can find is not far from a feature nobody has. */
	for (head = 0; head < sizeof(block_heads) / sizeof(block_heads[0]); head++) {
		char  wanted[32];
		char *at = text;
		int   seen = 0;

		(void)snprintf(wanted, sizeof(wanted), "\n#%s ", block_heads[head]);
		seen = strstr(text, wanted) != NULL;
		if (!seen) {
			(void)snprintf(wanted, sizeof(wanted), "\n#%s{", block_heads[head]);
			seen = strstr(text, wanted) != NULL;
		}
		if (!seen) {
			(void)snprintf(wanted, sizeof(wanted), "\n#override %s ", block_heads[head]);
			seen = strstr(text, wanted) != NULL;
		}
		(void)at;
		if (!seen) {
			printf("    the language has a `%s` block and %s has none\n", block_heads[head],
			    EXAMPLE_PATH);
		}
		check(seen, block_heads[head]);
	}

	free(text);
}

/* ------------------------------------------------------------------------ *
 * Diagnostics themselves
 * ------------------------------------------------------------------------ */

static void diagnostic_cases(void)
{
	fixture_t        file = { "conf.d/20-wifi.conf", NULL };
	ncfg_document_t *document;

	/* A diagnostic names the file, the line and the column, or the reader
	 * searches a directory of drop-ins for the line that was meant. */
	file.text = "interface eth0 {\n\tconfig = \"dhcp\"\n\twombat = 1\n}\n";
	document = build(&file, 1u, NULL);
	check(document == NULL && strstr(said, "conf.d/20-wifi.conf:3:") != NULL,
	    "a diagnostic names its file, line and column");
	ncfg_document_free(document);

	/* A configuration with four errors should take one edit round rather than
	 * four. */
	file.text = "interface eth0 {\n\twombat = 1\n\tbadger = 2\n\tstoat = 3\n}\n";
	document = build(&file, 1u, NULL);
	check(document == NULL && strstr(said, "wombat") && strstr(said, "badger") &&
	    strstr(said, "stoat"), "every mistake is reported, not only the first");
	ncfg_document_free(document);

	/*
	 * Past `NCFG_DIAGS_MAX` the count goes on rising and nothing more is kept:
	 * a diagnostic per line is a file-sized allocation bought with a malformed
	 * file, and nobody reads the sixty-fifth.
	 */
	{
		static char many[16384];
		ncfg_source_t      source;
		ncfg_ast_file_t   *tree = NULL;
		ncfg_lower_diags_t diags = { 0 };
		char               err[NCFG_ERROR_MAX];
		size_t             at = 0;
		int                i;

		at += (size_t)snprintf(many + at, sizeof(many) - at, "interface eth0 {\n");
		for (i = 0; i < 100; i++) {
			at += (size_t)snprintf(many + at, sizeof(many) - at, "\tkey%d = 1\n", i);
		}
		(void)snprintf(many + at, sizeof(many) - at, "}\n");

		check(ncfg_parse(many, strlen(many), &tree, NULL, err, sizeof(err)),
		    "a file with a hundred unknown keys parses");
		source.name = "netcfgd.conf";
		source.file = tree;
		document = ncfg_compile(&source, 1u, NULL, &diags, err, sizeof(err));
		check(document == NULL && diags.count == NCFG_DIAGS_MAX && diags.total == 100u,
		    "  and the diagnostics are capped with the total kept");
		ncfg_document_free(document);
		ncfg_lower_diags_free(&diags);
		ncfg_ast_file_free(tree);
	}
}

/* ------------------------------------------------------------------------ *
 * Ownership
 * ------------------------------------------------------------------------ */

static void ownership_cases(void)
{
	ncfg_lower_diags_t diags = { 0 };
	ncfg_merged_t     *merged = NULL;
	ncfg_source_t      source;
	ncfg_ast_file_t   *tree = NULL;
	char               err[NCFG_ERROR_MAX];
	const char        *text = "interface eth0 { config = \"dhcp\" }\n";

	/* Freeing something that was never filled in is nothing, which is the rule
	 * every error path in this module is written on. */
	ncfg_lower_diags_free(&diags);
	ncfg_merged_free(NULL);
	ncfg_document_free(NULL);
	check(1, "freeing what was never filled in is nothing");

	check(ncfg_parse(text, strlen(text), &tree, NULL, err, sizeof(err)), "a fixture parses");
	source.name = "netcfgd.conf";
	source.file = tree;
	check(ncfg_merge(&source, 1u, &merged, &diags, err, sizeof(err)) && merged != NULL,
	    "merge hands back a result on its own");
	{
		ncfg_document_t *document = ncfg_lower(merged, NULL, &diags, err, sizeof(err));

		/* `ncfg_lower` stops short of canonicalising and validating, which is
		 * what `ncfg_compile` adds. */
		check(document != NULL, "lower hands back a document on its own");
		ncfg_document_free(document);
	}
	ncfg_merged_free(merged);
	ncfg_lower_diags_free(&diags);
	ncfg_ast_file_free(tree);
}


/* ------------------------------------------------------------------------ *
 * Where each field was written
 *
 * The producer half of `ncfg explain`. What these cases hold the lowering to
 * is not that it records *something* but that it records **the key the
 * consumer asks for**: `explain.c` builds `interfaces[eth0].addressing[0]` and
 * looks it up, so a table keyed any other way is worse than no table -- every
 * lookup misses while the table looks full, and the notice that would have
 * said "no positions here" is gone because the table is not empty.
 *
 * The file name is the other half. `lex.h`'s span carries no source id (0263),
 * so the name cannot come out of the span the way the Rust's does; it comes
 * from beside it, out of the merged item or the merged block. The two-file
 * fixture is what makes that assertable rather than assumed.
 * ------------------------------------------------------------------------ */

/* The one fixture the key case reads, with a field of every recorded kind. */
static const char *const provenance_main =
    "device eth0 {\n"
    "\tmtu = 1400\n"
    "}\n"
    "interface eth0 {\n"
    "\tconfig = [\"10.0.0.2/24\", \"10.0.0.3/24\"]\n"
    "\troutes = [\"default via 10.0.0.1\", \"192.168.9.0/24 via 10.0.0.9\"]\n"
    "\tguard = \"the office link\"\n"
    "\tpreference = 10\n"
    "\tdns = \"10.0.0.1\"\n"
    "}\n"
    "rule \"r1\" {\n"
    "\tpriority = 100\n"
    "\tfrom = \"10.0.0.0/8\"\n"
    "\tlookup = 100\n"
    "}\n"
    "linkset \"office\" {\n"
    "\tmembers = \"eth0\"\n"
    "}\n"
    "access_point \"Home\" {\n"
    "\tdevice = \"wlan0\"\n"
    "\tchannel = 36\n"
    "\tband = \"5\"\n"
    "\twifi { psk = \"@secret:ap\" }\n"
    "}\n";

/* And a drop-in, so that "which file" has an answer that can be wrong. */
static const char *const provenance_dropin =
    "interface eth1 {\n"
    "\tconfig = \"dhcp\"\n"
    "}\n";

/* `file:line:column` for `path`, or a sentence saying it is not there. */
static const char *located(const ncfg_provenance_t *provenance, const char *path)
{
	static char where[NCFG_ERROR_MAX];
	const ncfg_provenance_entry_t *entry = ncfg_provenance_lookup(provenance, path);

	if (!entry) {
		(void)snprintf(where, sizeof(where), "<nothing recorded>");
		return where;
	}
	ncfg_provenance_location(entry, where, sizeof(where));
	return where;
}

static void at(const ncfg_provenance_t *provenance, const char *path, const char *expected)
{
	char what[160];

	(void)snprintf(what, sizeof(what), "%s is at %s", path, expected);
	check(strcmp(located(provenance, path), expected) == 0, what);
	if (strcmp(located(provenance, path), expected) != 0) {
		printf("    got %s\n", located(provenance, path));
	}
}

static void the_keys_are_the_ones_explain_asks_for(void)
{
	fixture_t         files[2];
	ncfg_provenance_t provenance;
	ncfg_document_t  *document;
	size_t            i;
	int               ordered = 1;

	files[0].name = "netcfgd.conf";
	files[0].text = provenance_main;
	files[1].name = "conf.d/10-lan.conf";
	files[1].text = provenance_dropin;
	memset(&provenance, 0, sizeof(provenance));
	document = build_recording(files, 2u, NULL, &provenance);
	if (!document) {
		check(0, "a configuration with a field of every recorded kind compiles");
		printf("    %s", said);
		ncfg_provenance_free(&provenance);
		return;
	}

	/* The interface block, which is what `explain` looks up first and the one
	 * entry whose file name comes from the block rather than from an item. */
	at(&provenance, "interfaces[eth0]", "netcfgd.conf:4:1");
	/* The MTU is recorded on the `device` block and keyed under the interface
	 * (0155 pass 1a), which is the one key whose two halves come from
	 * different blocks -- and exactly what `explain.c` asks for. */
	at(&provenance, "interfaces[eth0].mtu", "netcfgd.conf:2:2");
	/* Per entry rather than per assignment: two addresses on one line are two
	 * fields, and a reader sent to the line learns which line and not which
	 * address. */
	at(&provenance, "interfaces[eth0].addressing[0]", "netcfgd.conf:5:12");
	at(&provenance, "interfaces[eth0].addressing[1]", "netcfgd.conf:5:27");
	/* Keyed by destination, because `ncfg_document_canonicalize` sorts routes
	 * and an index would name whichever one sorted into that slot. */
	at(&provenance, "interfaces[eth0].routes[default]", "netcfgd.conf:6:12");
	at(&provenance, "interfaces[eth0].routes[192.168.9.0/24]", "netcfgd.conf:6:36");
	at(&provenance, "interfaces[eth0].guard", "netcfgd.conf:7:2");
	at(&provenance, "interfaces[eth0].preference", "netcfgd.conf:8:2");
	at(&provenance, "interfaces[eth0].dns", "netcfgd.conf:9:2");
	/* The four blocks that have a name and no recorded fields. */
	at(&provenance, "rule.r1", "netcfgd.conf:11:1");
	at(&provenance, "linkset.office", "netcfgd.conf:16:1");
	at(&provenance, "access_point.Home", "netcfgd.conf:19:1");

	/* And the drop-in's own file, which is the whole of what a span with no
	 * source id costs: the name travels beside the position or not at all. */
	at(&provenance, "interfaces[eth1]", "conf.d/10-lan.conf:1:1");
	at(&provenance, "interfaces[eth1].addressing[0]", "conf.d/10-lan.conf:2:11");

	/* Fourteen and no more, so that a key quietly added or dropped is a failed
	 * check rather than a table nobody counted. */
	check(provenance.count == 14u, "the table holds exactly the fourteen positions above");

	for (i = 1u; i < provenance.count; i++) {
		if (strcmp(provenance.entries[i - 1u].path, provenance.entries[i].path) >= 0) {
			ordered = 0;
		}
	}
	check(ordered, "and is ordered by path, so two compiles give one file");

	ncfg_provenance_free(&provenance);
	ncfg_document_free(document);
}

/*
 * Four keys write one path, and the first of them is what a reader is sent to.
 *
 * `dns`, `dns_search`, `dns_mode` and `dns_domains` are one policy, and the
 * position worth having is where that policy started being written rather than
 * wherever the last of them happens to sit. `ncfg_provenance_canonicalize`
 * keeps the first record for a path and `state.h` says why; this is the case
 * that would notice if it stopped.
 */
static void repeated_records_for_one_path_keep_the_first(void)
{
	fixture_t         file;
	ncfg_provenance_t provenance;
	ncfg_document_t  *document;
	size_t            i;
	size_t            seen = 0;

	file.name = "netcfgd.conf";
	file.text = "interface eth0 {\n"
	            "\tconfig = \"dhcp\"\n"
	            "\tdns_mode = \"resolvconf\"\n"
	            "\tdns_search = \"example.com\"\n"
	            "\tdns = \"10.0.0.1\"\n"
	            "}\n";
	memset(&provenance, 0, sizeof(provenance));
	document = build_recording(&file, 1u, NULL, &provenance);
	if (!document) {
		check(0, "an interface writing its DNS policy four ways compiles");
		printf("    %s", said);
		ncfg_provenance_free(&provenance);
		return;
	}
	for (i = 0; i < provenance.count; i++) {
		if (strcmp(provenance.entries[i].path, "interfaces[eth0].dns") == 0) {
			seen++;
		}
	}
	check(seen == 1u, "four DNS keys leave one entry, not four");
	at(&provenance, "interfaces[eth0].dns", "netcfgd.conf:3:2");
	ncfg_provenance_free(&provenance);
	ncfg_document_free(document);
}

/*
 * A `network` block's addressing is recorded under no path at all.
 *
 * It has one: `interfaces[...]` names an interface, and a wireless profile is
 * not one. Recording it under the network's own name would be a key nothing
 * looks up, which is the cheaper half of the same mistake -- so the block is
 * recorded and its addressing is not, which is the Rust's arrangement.
 */
static void a_network_records_its_name_and_not_its_addressing(void)
{
	fixture_t         file;
	ncfg_provenance_t provenance;
	ncfg_document_t  *document;
	size_t            i;
	int               stray = 0;

	file.name = "netcfgd.conf";
	file.text = "network \"office\" {\n"
	            "\tconfig = \"10.0.0.2/24\"\n"
	            "\twifi {\n"
	            "\t\tpsk = \"@secret:office\"\n"
	            "\t}\n"
	            "}\n";
	memset(&provenance, 0, sizeof(provenance));
	document = build_recording(&file, 1u, NULL, &provenance);
	if (!document) {
		check(0, "a network block compiles");
		printf("    %s", said);
		ncfg_provenance_free(&provenance);
		return;
	}
	at(&provenance, "network.office", "netcfgd.conf:1:1");
	for (i = 0; i < provenance.count; i++) {
		if (strncmp(provenance.entries[i].path, "interfaces[", 11u) == 0) {
			stray = 1;
		}
	}
	check(!stray, "and its addressing is under no interface path");
	check(provenance.count == 1u, "so the block's name is the only thing recorded");
	ncfg_provenance_free(&provenance);
	ncfg_document_free(document);
}

/*
 * A configuration that was refused leaves nothing behind.
 *
 * Half a table for a document nobody got is a set of paths into nothing, and
 * the caller that asked is the one that would write it to `/run` beside a
 * document from the compile before.
 */
static void a_refused_configuration_records_no_positions(void)
{
	fixture_t         file;
	ncfg_provenance_t provenance;
	ncfg_document_t  *document;

	file.name = "netcfgd.conf";
	/* The interface lowers and records, and the unknown block after it is what
	 * refuses the compile -- so this is a table that really was filled in and
	 * then given up, rather than one that was never written to. */
	file.text = "interface eth0 {\n"
	            "\tconfig = \"dhcp\"\n"
	            "}\n"
	            "nonsense \"x\" {\n"
	            "}\n";
	memset(&provenance, 0, sizeof(provenance));
	document = build_recording(&file, 1u, NULL, &provenance);
	check(document == NULL, "a configuration with an unknown block is refused");
	check(provenance.count == 0u, "and the positions it had already recorded are given up");
	ncfg_provenance_free(&provenance);
	ncfg_document_free(document);
}

/*
 * The table is bounded and the configuration is not.
 *
 * `NCFG_PROVENANCE_MAX` is the other list a compile produces whose length is
 * chosen by whoever writes the directory. Past it nothing more is recorded and
 * **the compile is unaffected**, which is the half worth pinning: a bound that
 * refused the configuration would make a large machine uncompilable to buy an
 * explanation nobody asked for. The bound is read from the header rather than
 * spelled here, so a test cannot go on passing against a number that moved.
 */
static void the_table_is_bounded_and_the_configuration_is_not(void)
{
	/* Two entries per interface -- the block and its one addressing entry --
	 * so this asks for a quarter more than the bound allows. */
	const size_t      wanted = (NCFG_PROVENANCE_MAX / 2u) + (NCFG_PROVENANCE_MAX / 8u);
	fixture_t         file;
	ncfg_provenance_t provenance;
	ncfg_document_t  *document;
	char             *text;
	size_t            at_byte = 0;
	size_t            i;

	text = malloc(wanted * 48u + 1u);
	if (!text) {
		check(0, "the bound fixture could be built");
		return;
	}
	for (i = 0; i < wanted; i++) {
		at_byte += (size_t)snprintf(text + at_byte, wanted * 48u + 1u - at_byte,
		    "interface eth%zu { config = \"dhcp\" }\n", i);
	}
	file.name = "netcfgd.conf";
	file.text = text;
	memset(&provenance, 0, sizeof(provenance));
	document = build_recording(&file, 1u, NULL, &provenance);
	if (!document) {
		check(0, "a configuration with more fields than the table holds still compiles");
		printf("    %s", said);
		ncfg_provenance_free(&provenance);
		free(text);
		return;
	}
	check(document->interface_count == wanted,
	    "a configuration past the position bound compiles whole");
	check(provenance.count == NCFG_PROVENANCE_MAX,
	    "and the table stops at NCFG_PROVENANCE_MAX rather than growing with it");
	/* What a short table costs is a gap per field, which is the state
	 * `explain.h` already describes: the first interface is still located and
	 * the last simply is not. */
	check(ncfg_provenance_lookup(&provenance, "interfaces[eth0]") != NULL,
	    "what it did record is still there");
	ncfg_provenance_free(&provenance);
	ncfg_document_free(document);
	free(text);
}

/*
 * A key too long to spell records nothing, rather than the part that fitted.
 *
 * A truncated key is the one failure the consumer cannot see: `explain` asks
 * for the whole path, misses, and says nothing -- because the table has
 * entries, so the "no positions in this build" notice is correctly silent. A
 * missing entry reads as a field nobody wrote; a truncated one reads the same
 * way and has quietly claimed a path belonging to nothing.
 */
static void a_key_that_does_not_fit_is_not_recorded_by_halves(void)
{
	fixture_t         file;
	ncfg_provenance_t provenance;
	ncfg_document_t  *document;
	char              text[1024];
	char              label[512];
	size_t            i;
	int               stray = 0;

	for (i = 0; i < sizeof(label) - 1u; i++) {
		label[i] = 'r';
	}
	label[sizeof(label) - 1u] = '\0';
	(void)snprintf(text, sizeof(text),
	    "rule \"%s\" { priority = 100; from = \"10.0.0.0/8\"; lookup = 100 }\n"
	    "interface eth0 { config = \"dhcp\" }\n",
	    label);
	file.name = "netcfgd.conf";
	file.text = text;
	memset(&provenance, 0, sizeof(provenance));
	document = build_recording(&file, 1u, NULL, &provenance);
	if (!document) {
		check(0, "a rule with a very long name compiles");
		printf("    %s", said);
		ncfg_provenance_free(&provenance);
		return;
	}
	for (i = 0; i < provenance.count; i++) {
		if (strncmp(provenance.entries[i].path, "rule.", 5u) == 0) {
			stray = 1;
		}
	}
	check(!stray, "a key too long to spell records nothing rather than a prefix of itself");
	check(ncfg_provenance_lookup(&provenance, "interfaces[eth0]") != NULL,
	    "and the fields around it are recorded as usual");
	ncfg_provenance_free(&provenance);
	ncfg_document_free(document);
}

static void provenance_cases(void)
{
	the_keys_are_the_ones_explain_asks_for();
	repeated_records_for_one_path_keep_the_first();
	a_network_records_its_name_and_not_its_addressing();
	a_refused_configuration_records_no_positions();
	the_table_is_bounded_and_the_configuration_is_not();
	a_key_that_does_not_fit_is_not_recorded_by_halves();
}

int main(void)
{
	addressing_cases();
	route_cases();
	precedence_cases();
	global_cases();
	dns_cases();
	network_cases();
	access_point_cases();
	device_cases();
	kind_cases();
	qdisc_cases();
	rule_cases();
	linkset_cases();
	bluetooth_cases();
	interface_cases();
	diagnostic_cases();
	ownership_cases();
	example_cases();
	provenance_cases();

	if (failures) {
		printf("\n%d check(s) failed\n", failures);
		return 1;
	}
	printf("\nevery check passed\n");
	return 0;
}
