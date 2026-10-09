/*
 * render_link.c -- interfaces and wireless networks, as configuration text.
 *
 * The two are one file because they share three things and must go on sharing
 * them. A `network` block takes the same `config`, `routes` and `dns` keys an
 * interface does -- that is how a machine says "on this SSID, use this static
 * address and this resolver" -- and the parser shares `WifiKeys` between a
 * wired port's `dot1x` and a network's EAP, so the eight keys are one function
 * here for the same reason.
 *
 * **The network side used to render none of the first three**, and that is the
 * defect this arrangement exists to prevent rather than a tidiness argument: a
 * profile that lost them brought the machine back on DHCP against the wrong
 * nameserver, which looks like a working network right up until something
 * internal fails to resolve. Writing a second copy is how the two would come
 * to disagree about what `slaac` spells.
 */
#include "lower_internal.h"
#include "render_private.h"

#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/value.h"

#include <stdio.h>
#include <string.h>

/* The same words on both sides, from `netcfgd-model/src/security.rs`. */
static const char *const eap_method_words[] = { "peap", "ttls", "tls", "pwd" };

/*
 * **`wpa2+wpa3`, and not the document's `wpa2_wpa3`.** The parser reads
 * `wpa2`, `wpa3`, `wpa2+wpa3` and `wpa2wpa3`; the underscored spelling the
 * JSON uses is not one of them, so writing it produces a profile the compiler
 * refuses. `wpa2+wpa3` of the two accepted spellings because it is the one the
 * example file and the diagnostics use.
 *
 * Losing this key is the one wifi field whose loss *weakens* a network rather
 * than merely changing it: the default is WPA2 and WPA3 together, so a
 * `proto = "wpa3"` network that came back without it would accept WPA2 again
 * -- a downgrade the operator had deliberately excluded.
 *
 * **The third entry cannot be reached from `ncfg_render` today, and is written
 * out anyway.** The permissive generation is the model's default, and a value
 * equal to the default is not written, so the arm that would emit
 * `wpa2+wpa3` is dead while that stays true. `render_test.c` says the same
 * thing where it tests this, because a gap named is worth more than a case
 * that looks like it covers one. The word is here rather than left blank
 * because the day somebody hardens that default -- WPA3 only, which is the
 * plausible change -- the arm goes live, and a table filled in that day would
 * be filled in from the document's spelling.
 */
static const char *const psk_proto_words[] = { "wpa2", "wpa3", "wpa2+wpa3" };

/* ------------------------------------------------------------------------ *
 * Addressing, shared by an interface and by a wireless network
 * ------------------------------------------------------------------------ */

/*
 * `dhcp6` and `slaac` carry settings the language expresses as modifiers after
 * the word, and `dhcp` carries settings it cannot express at all.
 *
 * The modifiers are written; what has no words is named. `slaac privacy` is
 * worth the distinction on its own: losing it puts a machine back on stable
 * addresses, which is a privacy property the operator chose and which nothing
 * downstream would report.
 *
 * ~~The Rust this ports wrote the bare word and dropped every one of them in
 * silence.~~ **Measured 2026-10-09 and no longer true**, by saving a profile
 * from both programs over a configuration carrying `slaac privacy
 * prefer_temporary`, a static address with `peer` and both lifetimes, and
 * `dhcp6 pd pd_length 56`: the two profiles agree on every modifier. The claim
 * was a reason to write this function and had become a claim about another
 * implementation that nobody re-took.
 *
 * **One divergence survives and it is presentational.** This writes `dhcp6 pd
 * pd_length 56` and the Rust writes `dhcp6 pd_length 56`; both compile to the
 * same document, `pd_length` implying `pd`, and writing `pd` out is this
 * module's own choice rather than a correction. 10.441 has the measurement.
 */
static void render_lease_modifiers(const ncfg_address_source_t *source, ncfg_buf_t *slot,
    ncfg_unrenderable_t *missing, const char *scope, const char *name)
{
	if (source->kind == NCFG_ADDRESS_SOURCE_DHCP4) {
		const ncfg_dhcp4_t *lease = &source->dhcp4;

		/* `dhcp` takes no modifiers at all -- `no_modifiers` in `lower.rs`
		 * refuses every one -- so each of these is a fact the language has
		 * nowhere to put. Unreachable from a compiled document, where the
		 * lease is always the default, and kept for a document that arrived
		 * some other way. */
		if (lease->hostname_mode != NCFG_HOSTNAME_MODE_NONE) {
			ncfg_render_refuse(missing, scope, name, "a dhcp lease's hostname mode");
		}
		if (lease->client_id) {
			ncfg_render_refuse(missing, scope, name, "a dhcp lease's client id");
		}
		if (lease->metric.has) {
			ncfg_render_refuse(missing, scope, name, "a dhcp lease's metric");
		}
		if (lease->request_option_count > 0) {
			ncfg_render_refuse(missing, scope, name, "a dhcp lease's requested options");
		}
		if (lease->backend != NCFG_DHCP4_BACKEND_AUTO) {
			ncfg_render_refuse(missing, scope, name, "a dhcp lease's backend");
		}
		return;
	}
	if (source->kind == NCFG_ADDRESS_SOURCE_DHCP6) {
		const ncfg_dhcp6_t *lease = &source->dhcp6;

		if (lease->mode != NCFG_DHCP6_MODE_MANAGED) {
			ncfg_render_refuse(missing, scope, name, "a dhcp6 lease's mode");
		}
		if (lease->rapid_commit) {
			ncfg_render_refuse(missing, scope, name, "a dhcp6 lease's rapid commit");
		}
		if (lease->prefix_delegation) {
			/* `pd` alone asks for whatever the ISP offers; the other two say
			 * what to ask for, and each implies `pd` -- so `pd` is written
			 * first whichever of them is set. */
			ncfg_buf_add_text(slot, " pd");
			if (lease->prefix_delegation->hint) {
				ncfg_buf_addf(slot, " pd_hint %s", lease->prefix_delegation->hint);
			}
			if (lease->prefix_delegation->length.has) {
				ncfg_buf_addf(slot, " pd_length %lld",
				    (long long)lease->prefix_delegation->length.value);
			}
		}
		return;
	}
	if (source->kind == NCFG_ADDRESS_SOURCE_SLAAC &&
	    source->slaac.privacy == NCFG_SLAAC_PRIVACY_PREFER_TEMPORARY) {
		ncfg_buf_add_text(slot, " privacy prefer_temporary");
	}
}

/*
 * One statically configured address, with whatever modifiers it carries.
 *
 * `ncfg_static_t` holds four things and all four are written here, which is
 * what makes this complete rather than a sample: the compiler refuses every
 * modifier it cannot keep -- `netmask` is folded into the prefix, and `scope`,
 * `label`, `nodad` and the rest are named as unsupported rather than dropped --
 * so a compiled address can carry an address, a peer and the two lifetimes and
 * nothing else.
 *
 * **A lifetime of `forever` is the absence of one**, because `set_lifetime`
 * stores it as unset. So writing nothing where `has` is clear is not a gap: it
 * is the same statement in fewer words, and the round trip holds because the
 * document being compared against holds an unset field too.
 *
 * The whole value is built and then quoted once rather than written between two
 * literal quote characters. A peer is not checked as an address -- it is kept as
 * the token the author wrote -- so it is the one part here that could carry a
 * character the text has to escape, and escaping is what `ncfg_render_quote`
 * is for.
 */
/*
 * **The model's parser decides, not a shape written here.** A static address
 * is `NCFG_F_STR` in the field tables, so a document read from JSON holds text
 * that is not an address; `lower_address.c` refuses it on the way in and this
 * wrote it back out. Measured: an `address` of `not-an-address` rendered and
 * then failed its own round trip. `ncfg_address_canonical` takes CIDR and bare
 * alike and refuses garbage and an out-of-range prefix, which is the same test
 * the compiler applies.
 */
static void render_static_address(const ncfg_static_t *address, const char *scope,
    const char *name, ncfg_buf_t *slot, ncfg_unrenderable_t *missing)
{
	ncfg_buf_t value;
	char       canonical[NCFG_ADDRESS_MAX];

	if (!ncfg_address_canonical(address->address ? address->address : "", canonical,
	    sizeof(canonical), NULL, 0)) {
		ncfg_render_refuse(missing, scope, name, "an address `%s`, which is not one",
		    address->address ? address->address : "");
		return;
	}
	if (address->peer && !ncfg_address_canonical(address->peer, canonical,
	    sizeof(canonical), NULL, 0)) {
		ncfg_render_refuse(missing, scope, name, "a `peer` address `%s`, which is not one",
		    address->peer);
		return;
	}
	ncfg_buf_init(&value, 0);
	ncfg_buf_add_text(&value, address->address ? address->address : "");
	if (address->peer) {
		ncfg_buf_addf(&value, " peer %s", address->peer);
	}
	/* The parser reads these in any order; this is the table's own, which is
	 * also the order `ip addr` documents them in. */
	if (address->preferred_lifetime.has) {
		ncfg_buf_addf(&value, " preferred_lft %lld",
		    (long long)address->preferred_lifetime.value);
	}
	if (address->valid_lifetime.has) {
		ncfg_buf_addf(&value, " valid_lft %lld",
		    (long long)address->valid_lifetime.value);
	}
	ncfg_render_quote(slot, ncfg_buf_text(&value));
	ncfg_buf_free(&value);
}

/*
 * `@pd:wan0`, `@pd:wan0/2` and `@pd:wan0=::5/64` -- an address built from a
 * prefix the ISP delegates.
 *
 * The counterpart of `advertise`: that block tells the hosts behind this machine
 * what their prefix is, and this is how the machine gives itself an address out
 * of the same delegation. A router has both, so refusing either one was enough
 * to stop it saving a profile.
 *
 * **The suffix defaults to `::1/64` and is left unwritten when it is that**,
 * which is this file's rule for every default -- and it is safe here only
 * because the default is a constant in `delegated_source` rather than something
 * derived from the prefix.
 *
 * A prefix's `index` is hardcoded to 0 on the way in, the spelling having no
 * third part, so a non-zero one is named rather than dropped. Same reasoning as
 * `render_advertise`, and the same refusal would be wrong to share: these are
 * two different things a document can carry and an operator fixes them in two
 * different places.
 */
static void render_delegated(const ncfg_delegated_t *delegated, const char *scope,
    const char *name, ncfg_buf_t *slot, ncfg_unrenderable_t *missing)
{
	static const char *const default_suffix = "::1/64";
	ncfg_buf_t               value;

	if (delegated->prefix.index != 0) {
		ncfg_render_refuse(missing, scope, name,
		    "a delegated address naming which delegation it is");
		return;
	}
	ncfg_buf_init(&value, 0);
	ncfg_buf_addf(&value, "@pd:%s",
	    delegated->prefix.source ? delegated->prefix.source : "");
	if (delegated->prefix.subnet != 0) {
		ncfg_buf_addf(&value, "/%lld", (long long)delegated->prefix.subnet);
	}
	if (delegated->suffix && strcmp(delegated->suffix, default_suffix) != 0) {
		ncfg_buf_addf(&value, "=%s", delegated->suffix);
	}
	ncfg_render_quote(slot, ncfg_buf_text(&value));
	ncfg_buf_free(&value);
}

static void render_addressing(const ncfg_address_source_t *sources, size_t count,
    const char *scope, const char *name, ncfg_buf_t *body, ncfg_unrenderable_t *missing)
{
	ncfg_render_list_t config;
	size_t             i;

	ncfg_render_list_init(&config);
	for (i = 0; i < count; i++) {
		const ncfg_address_source_t *source = &sources[i];
		const char                  *word;
		ncfg_buf_t                  *slot;

		switch (source->kind) {
		case NCFG_ADDRESS_SOURCE_STATIC:
			render_static_address(&source->static_address, scope, name,
			    ncfg_render_list_next(&config), missing);
			continue;
		case NCFG_ADDRESS_SOURCE_DHCP4:
			word = "dhcp";
			break;
		case NCFG_ADDRESS_SOURCE_DHCP6:
			word = "dhcp6";
			break;
		case NCFG_ADDRESS_SOURCE_SLAAC:
			word = "slaac";
			break;
		case NCFG_ADDRESS_SOURCE_LINK_LOCAL:
			word = "link_local";
			break;
		case NCFG_ADDRESS_SOURCE_REPORTED:
			/* `reported` takes no modifiers -- `no_modifiers` refuses every
			 * one -- so the word is the whole source. */
			word = "reported";
			break;
		case NCFG_ADDRESS_SOURCE_DELEGATED:
			render_delegated(&source->delegated, scope, name,
			    ncfg_render_list_next(&config), missing);
			continue;
		default:
			ncfg_render_refuse(missing, scope, name, "%s addressing",
			    ncfg_render_word_or_gap(
			        ncfg_address_source_kind_name(source->kind)));
			continue;
		}
		slot = ncfg_render_list_next(&config);
		ncfg_buf_add_char(slot, '"');
		ncfg_buf_add_text(slot, word);
		render_lease_modifiers(source, slot, missing, scope, name);
		ncfg_buf_add_char(slot, '"');
	}
	ncfg_render_list_emit(body, "\t", "config", &config, 0);
	ncfg_render_list_free(&config);
}

/* ------------------------------------------------------------------------ *
 * Routes, shared for the reason addressing is
 * ------------------------------------------------------------------------ */

static void render_routes(const ncfg_route_t *routes, size_t count, const char *scope,
    const char *name, ncfg_buf_t *body, ncfg_unrenderable_t *missing)
{
	ncfg_render_list_t phrases;
	size_t             i;

	ncfg_render_list_init(&phrases);
	for (i = 0; i < count; i++) {
		const ncfg_route_t *route = &routes[i];
		ncfg_buf_t          phrase;

		ncfg_buf_init(&phrase, 0);
		ncfg_buf_add_text(&phrase, route->destination ? route->destination : "");
		if (route->via) {
			ncfg_buf_addf(&phrase, " via %s", route->via);
		}
		/* Was dropped in silence. A preferred source decides which address a
		 * machine with several is seen as coming from, so losing it moves
		 * traffic to a different identity rather than breaking it -- the kind
		 * of change nothing notices until a firewall somewhere else does. */
		if (route->src) {
			ncfg_buf_addf(&phrase, " src %s", route->src);
		}
		if (route->metric.has) {
			ncfg_buf_addf(&phrase, " metric %lld", (long long)route->metric.value);
		}
		if (route->table.has) {
			ncfg_buf_addf(&phrase, " table %lld", (long long)route->table.value);
		}
		/* Also dropped in silence, and not merely descriptive: it exempts the
		 * route from the ordering rule that installs addresses before routes,
		 * so a route that needs it fails to install without it. */
		if (route->onlink) {
			ncfg_buf_add_text(&phrase, " onlink");
		}
		/* No route phrase can express these two -- the keywords are `via`,
		 * `metric`, `table`, `src` and `onlink` -- so they are named rather
		 * than written. Reachable only from a document some other producer
		 * built, which is exactly when a silent drop would be hardest to
		 * trace. */
		if (route->scope.has) {
			ncfg_render_refuse(missing, scope, name, "a route with a scope");
		}
		if (route->proto.has) {
			ncfg_render_refuse(missing, scope, name, "a route with a proto");
		}
		ncfg_render_quote(ncfg_render_list_next(&phrases), ncfg_buf_text(&phrase));
		ncfg_buf_free(&phrase);
	}
	ncfg_render_list_emit(body, "\t", "routes", &phrases, 0);
	ncfg_render_list_free(&phrases);
}

/* ------------------------------------------------------------------------ *
 * 802.1X, shared by a wired port and a wireless network
 * ------------------------------------------------------------------------ */

/*
 * A certificate or key as the document names it.
 *
 * The two sources read back differently and the parser tells them apart by the
 * `@secret:` prefix alone, so a stored one must go through the secret spelling
 * and a path must not: a path that happened to begin with `@secret:` would
 * come back as stored content, and stored content written bare would come back
 * as a filename that does not exist. Neither is a compile error, which is why
 * the round trip rather than the parser is what catches it.
 */
static void quote_cert_source(ncfg_buf_t *out, const ncfg_cert_source_t *source)
{
	if (source->kind == NCFG_CERT_SOURCE_STORED) {
		ncfg_render_quote_secret(out, &source->stored);
	} else {
		ncfg_render_quote(out, source->path);
	}
}

/*
 * The keys of an 802.1X configuration, inside an open `wifi` or `dot1x` block.
 *
 * Every value is quoted rather than written bare. An identity is
 * `you@example.ac.uk` and a certificate is a path, and neither is guaranteed to
 * be a word the lexer reads back as itself.
 *
 * `identity` is unconditional because the model requires it -- no method
 * authenticates without one. The rest are written only when set, so a PEAP
 * network does not acquire empty `ca_cert` and `client_cert` lines that say
 * nothing and invite an answer.
 */
static void render_eap(const ncfg_eap_config_t *eap, ncfg_buf_t *body)
{
	static const char *const keys[] = { "ca_cert", "client_cert", "private_key" };
	const ncfg_cert_source_t *sources[3];
	/* Paired, as above. */
	_Static_assert(NCFG_COUNT_OF(keys) == NCFG_COUNT_OF(sources),
	    "a sources per keys");
	const char               *method;
	size_t                    i;

	method = ncfg_render_word(eap_method_words, NCFG_COUNT_OF(eap_method_words), eap->method);
	ncfg_buf_addf(body, "\t\teap = \"%s\"\n", ncfg_render_word_or_gap(method));
	ncfg_buf_add_text(body, "\t\tidentity = ");
	ncfg_render_quote(body, eap->identity);
	ncfg_buf_add_char(body, '\n');
	if (eap->anonymous_identity) {
		ncfg_buf_add_text(body, "\t\tanonymous_identity = ");
		ncfg_render_quote(body, eap->anonymous_identity);
		ncfg_buf_add_char(body, '\n');
	}
	if (eap->password) {
		ncfg_buf_add_text(body, "\t\tpassword = ");
		ncfg_render_quote_secret(body, eap->password);
		ncfg_buf_add_char(body, '\n');
	}
	/*
	 * **Why it is written at all, and it weakens a network to lose it.**
	 * `ca_cert` alone answers "who signed this", not "who is this": it accepts
	 * any certificate the pinned issuer signed, which is nearly worthless when
	 * that issuer is a public CA -- and a commercial certificate on a RADIUS
	 * server is ordinary (0206). The lowering reads the key on both a `dot1x`
	 * block and a network's `wifi`, so there is nothing to decide and nothing
	 * stopping it being written.
	 *
	 * ~~Dropped in silence by the Rust this ports.~~ **Re-taken 2026-10-09 and
	 * no longer true**: saving a profile from both programs over a `wifi` block
	 * carrying `domain_suffix_match` produces byte-identical profiles. The
	 * reason to write it is the paragraph above and does not need the other
	 * implementation to be wrong.
	 */
	if (eap->domain_suffix_match) {
		ncfg_buf_add_text(body, "\t\tdomain_suffix_match = ");
		ncfg_render_quote(body, eap->domain_suffix_match);
		ncfg_buf_add_char(body, '\n');
	}
	sources[0] = &eap->ca_cert;
	sources[1] = &eap->client_cert;
	sources[2] = &eap->private_key;
	for (i = 0; i < NCFG_COUNT_OF(keys); i++) {
		if (!sources[i]->has) {
			continue;
		}
		ncfg_buf_addf(body, "\t\t%s = ", keys[i]);
		quote_cert_source(body, sources[i]);
		ncfg_buf_add_char(body, '\n');
	}
	if (eap->phase2) {
		ncfg_buf_add_text(body, "\t\tphase2 = ");
		ncfg_render_quote(body, eap->phase2);
		ncfg_buf_add_char(body, '\n');
	}
}

/* ------------------------------------------------------------------------ *
 * Interfaces
 * ------------------------------------------------------------------------ */

/*
 * How the link is judged to be working, as its own block.
 *
 * The numbers are omitted where they equal the parser's own defaults, which is
 * this module's convention. `command` is unconditional because a probe without
 * one is not a probe: the parser refuses the block outright, so a rendered
 * profile that left it out would be one that no longer compiles.
 *
 * `require_lease` is the exception and reads inverted: it is written only when
 * it is OFF, because its default is on. The reasoning is at the write itself,
 * along with how the omission was found.
 */
static void render_probe(const ncfg_probe_policy_t *probe, const char *scope,
    const char *name, ncfg_buf_t *body, ncfg_unrenderable_t *missing)
{
	/*
	 * **`least` is the lowering's own floor, not a second opinion.**
	 * `lower_interface.c` refuses `interval` below 1 ("has to be at least 1
	 * second") and `up_after` and `down_after` below 1 ("consecutive-result
	 * counts; zero would switch on no result"), while the document's range for
	 * all three is `R_U32`, low zero -- so a document read from JSON can hold a
	 * zero the language will not take back. Measured: a probe with
	 * `interval` 0 read, rendered `interval = 0`, and failed its own round trip
	 * on the lowerer's words. `timeout` and `hold_down` have no floor there and
	 * none here.
	 */
	static const struct {
		const char *key;
		int64_t     fallback;
		int64_t     least;
	} numbers[] = { { "interval", 30, 1 }, { "timeout", 5, 0 }, { "down_after", 3, 1 },
		{ "up_after", 2, 1 }, { "hold_down", 0, 0 } };
	int64_t            values[5];
	/* Paired, as above. */
	_Static_assert(NCFG_COUNT_OF(numbers) == NCFG_COUNT_OF(values),
	    "a values per numbers");
	ncfg_render_list_t args;
	size_t             i;

	/* `lower_interface.c` requires the command to be absolute -- a probe runs as
	 * root, so where it is from is not a thing to leave to a search path -- and
	 * the member is `NCFG_F_STR`, which says nothing about that. */
	if (!probe->command || probe->command[0] != '/') {
		ncfg_render_refuse(missing, scope, name, "a probe command `%s`, which is not an"
		    " absolute path", probe->command ? probe->command : "");
		return;
	}
	ncfg_buf_add_text(body, "\tprobe {\n");
	ncfg_buf_add_text(body, "\t\tcommand = ");
	ncfg_render_quote(body, probe->command);
	ncfg_buf_add_char(body, '\n');
	ncfg_render_list_init(&args);
	for (i = 0; i < probe->arg_count; i++) {
		ncfg_render_quote(ncfg_render_list_next(&args), probe->args[i]);
	}
	ncfg_render_list_emit(body, "\t\t", "args", &args, 0);
	ncfg_render_list_free(&args);

	values[0] = probe->interval;
	values[1] = probe->timeout;
	values[2] = probe->down_after;
	values[3] = probe->up_after;
	values[4] = probe->hold_down;
	for (i = 0; i < NCFG_COUNT_OF(numbers); i++) {
		if (values[i] == numbers[i].fallback) {
			continue;
		}
		if (values[i] < numbers[i].least) {
			ncfg_render_refuse(missing, scope, name, "a probe `%s` of %lld, which is"
			    " below the %lld the language takes", numbers[i].key,
			    (long long)values[i], (long long)numbers[i].least);
			continue;
		}
		ncfg_buf_addf(body, "\t\t%s = %lld\n", numbers[i].key, (long long)values[i]);
	}
	/*
	 * **The one field of nine this wrote nothing for**, and the only one whose
	 * default is `true`, which is why it was the one missed: every other key
	 * here is written when it differs from a fallback of zero or a number, and
	 * a boolean that is on by default needs the opposite test.
	 *
	 * `doc/netcfgd.conf.example` is where it surfaced -- its `wwan0` probe sets
	 * `require_lease = false`, and the example's own prose says why: a cellular
	 * link gets no DHCP lease, so requiring one "would hold a working link down
	 * for ever". A profile saved from such a machine came back requiring a
	 * lease, which is the probe's precondition inverted and nothing downstream
	 * would report it.
	 *
	 * Written only when off, because absence means on -- 0191's reasoning, that
	 * `require_lease = false` reads as a decision where `skip_lease_check =
	 * true` reads as a workaround.
	 */
	if (!probe->require_lease) {
		ncfg_buf_add_text(body, "\t\trequire_lease = false\n");
	}
	ncfg_buf_add_text(body, "\t}\n");
}

/*
 * The interface keys that are neither addressing nor topology.
 *
 * Grouped into a function because `ncfg_render_interface` has a line limit,
 * which is the same reason its siblings are functions -- not because these
 * belong together as an idea.
 */
static void render_interface_keys(const ncfg_interface_t *interface, ncfg_buf_t *body,
    ncfg_unrenderable_t *missing)
{
	if (interface->preference.has) {
		ncfg_buf_addf(body, "\tpreference = %lld\n", (long long)interface->preference.value);
	}
	if (interface->ipv6_token) {
		ncfg_buf_add_text(body, "\tipv6_token = ");
		ncfg_render_quote(body, interface->ipv6_token);
		ncfg_buf_add_char(body, '\n');
	}
	if (interface->nat.has) {
		ncfg_buf_addf(body, "\tnat = %s\n", interface->nat.value ? "true" : "false");
	}
	if (interface->dot1x) {
		/* The same eight keys a wireless network's EAP uses, which is why the
		 * parser shares `WifiKeys` between them -- so this shares `render_eap`
		 * for the same reason, and the two cannot drift into spelling one
		 * thing two ways. The nesting depth is a network's `wifi` block's, so
		 * `render_eap`'s indentation is already right. */
		ncfg_buf_add_text(body, "\tdot1x {\n");
		render_eap(interface->dot1x, body);
		ncfg_buf_add_text(body, "\t}\n");
	}
	if (interface->probe) {
		render_probe(interface->probe, "interface", interface->name, body, missing);
	}
}

/*
 * What an interface tells the hosts behind it.
 *
 * **In the enum's order, which is not the order the parser's own diagnostic
 * lists**: the enum is auto, odhcpd, radvd, exec and the message says "auto,
 * radvd, odhcpd". A table written from the message would name the wrong daemon
 * for every policy that sets one, and a document naming the wrong daemon
 * compiles -- so nothing downstream would report it.
 */
static const char *const ra_backend_words[] = { "auto", "odhcpd", "radvd", "exec" };

/*
 * `advertise { }`, which was refused whole.
 *
 * Two of this policy's fields cannot come from a config file and are named
 * rather than written. `exec` is in the backend enum and `lower_advertise`
 * accepts only auto, radvd and odhcpd, so a policy carrying it arrived some
 * other way and its command has nowhere to go. A prefix's `index` is likewise
 * hardcoded to 0 on the way in -- the reference syntax is `@pd:<interface>` with
 * an optional `/<subnet>` and has no third part -- so a non-zero one would be
 * dropped in silence, which is what this refuses to do.
 *
 * **An empty prefix list is refused rather than written**, because a document
 * needs one: `lower_advertise` rejects a block without `prefixes`, so writing
 * `advertise { }` would produce a profile that does not compile. A refusal says
 * that; a written block would make it the operator's problem to discover.
 *
 * `dns` defaults to **true**, so it is written only when it is off. The other
 * two flags default to false and are written only when on. Getting that
 * backwards is a silent change of meaning rather than a parse error.
 */
static void render_advertise(const ncfg_ra_policy_t *policy, const char *name, ncfg_buf_t *body,
    ncfg_unrenderable_t *missing)
{
	ncfg_render_list_t prefixes;
	size_t             i;

	if (policy->backend.kind == NCFG_RA_BACKEND_EXEC) {
		ncfg_render_refuse(missing, "interface", name, "an advertise backend of exec");
		return;
	}
	if (policy->prefix_count == 0) {
		ncfg_render_refuse(missing, "interface", name, "an advertise block with no prefix");
		return;
	}

	ncfg_render_list_init(&prefixes);
	for (i = 0; i < policy->prefix_count; i++) {
		const ncfg_prefix_ref_t *prefix = &policy->prefixes[i];
		ncfg_buf_t               reference;

		if (prefix->index != 0) {
			ncfg_render_refuse(missing, "interface", name,
			    "an advertised prefix naming which delegation it is");
			continue;
		}
		ncfg_buf_init(&reference, 0);
		ncfg_buf_addf(&reference, "@pd:%s", prefix->source ? prefix->source : "");
		if (prefix->subnet != 0) {
			ncfg_buf_addf(&reference, "/%lld", (long long)prefix->subnet);
		}
		ncfg_render_quote(ncfg_render_list_next(&prefixes), ncfg_buf_text(&reference));
		ncfg_buf_free(&reference);
	}
	if (prefixes.count == 0) {
		ncfg_render_list_free(&prefixes);
		return;
	}

	ncfg_buf_add_text(body, "\tadvertise {\n");
	if (policy->backend.kind != NCFG_RA_BACKEND_AUTO) {
		ncfg_buf_addf(body, "\t\tbackend = \"%s\"\n",
		    ncfg_render_word_or_gap(ncfg_render_word(ra_backend_words,
		        NCFG_COUNT_OF(ra_backend_words), policy->backend.kind)));
	}
	ncfg_render_list_emit(body, "\t", "\tprefixes", &prefixes, 1);
	if (policy->managed) {
		ncfg_buf_add_text(body, "\t\tmanaged = true\n");
	}
	if (policy->other_config) {
		ncfg_buf_add_text(body, "\t\tother_config = true\n");
	}
	if (!policy->dns) {
		ncfg_buf_add_text(body, "\t\tdns = false\n");
	}
	if (policy->lifetime.has) {
		ncfg_buf_addf(body, "\t\tlifetime = %lld\n", (long long)policy->lifetime.value);
	}
	ncfg_buf_add_text(body, "\t}\n");
	ncfg_render_list_free(&prefixes);
}

void ncfg_render_interface(const ncfg_interface_t *interface, const ncfg_overrides_t *overrides,
    ncfg_buf_t *text, ncfg_unrenderable_t *missing)
{
	const char *name = interface->name;
	ncfg_buf_t  body;
	/*
	 * A hook is the one thing here that cannot be rendered in principle
	 * rather than not yet. The language takes a phase block of **inline
	 * shell**, which the compiler materialises into a file; the document
	 * carries a path and a hash and no shell at all, deliberately, because a
	 * document that could carry shell would be remote code execution with
	 * extra steps. So there is nothing in the document to write the block
	 * back from, and recovering it would mean reading the file off disk --
	 * which would make a profile depend on something outside the config
	 * files, against 0009. Named rather than attempted, and whether that
	 * trade is worth revisiting is a design question rather than this
	 * function's.
	 */
	if (interface->hook_count > 0) {
		ncfg_render_refuse(missing, "interface", name, "hooks");
	}

	ncfg_buf_init(&body, 0);
	render_interface_keys(interface, &body, missing);
	if (!interface->enabled) {
		ncfg_buf_add_text(&body, "\tenabled = false\n");
	}
	if (interface->forwarding.has) {
		ncfg_buf_addf(&body, "\tforwarding = %s\n",
		    interface->forwarding.value ? "true" : "false");
	}
	if (interface->on_drift.has) {
		ncfg_buf_addf(&body, "\ton_drift = \"%s\"\n", ncfg_render_word_or_gap(
		    ncfg_drift_policy_name((ncfg_drift_policy_t)interface->on_drift.value)));
	}
	/*
	 * **The most expensive line in this file to lose.** A guard is why an
	 * interface must not be disrupted, and the reason string is the whole
	 * value: a profile saved without it comes back as an interface netcfgd
	 * may take down, and the thing it was guarding -- an NFS root, a lab
	 * uplink -- goes with it. It was refused, so every machine with one
	 * could not save a profile at all; the only consolation is that a
	 * refusal is not a drop.
	 */
	if (interface->guard) {
		ncfg_buf_add_text(&body, "\tguard = ");
		ncfg_render_quote(&body, interface->guard->reason);
		ncfg_buf_add_char(&body, '\n');
	}
	render_addressing(interface->addressing, interface->addressing_count, "interface", name,
	    &body, missing);
	render_routes(interface->routes, interface->route_count, "interface", name, &body, missing);
	if (interface->dns &&
	    !ncfg_render_dns(interface->dns, "\t", &body, missing, "interface", name)) {
		/* See `ncfg_render_dns`: present and empty is not the same document as
		 * absent, and the difference is whether a lease's resolvers are taken
		 * or ignored. */
		ncfg_buf_add_text(&body, "\tdns { }\n");
	}
	if (interface->advertise) {
		render_advertise(interface->advertise, name, &body, missing);
	}

	ncfg_render_opening(text, "interface", name, overrides);
	ncfg_render_label(text, name);
	ncfg_buf_addf(text, " {\n%s}\n", ncfg_buf_text(&body));
	ncfg_buf_free(&body);
}

/* ------------------------------------------------------------------------ *
 * Wireless networks
 * ------------------------------------------------------------------------ */

/* An SSID is bytes rather than text, and the language reads it back as
 * lowercase hex. Uppercase would be a second spelling of one SSID, which the
 * byte-identical guarantee does not survive. */
static void quote_ssid(ncfg_buf_t *body, const ncfg_ssid_t *ssid)
{
	static const char digits[] = "0123456789abcdef";
	size_t            i;

	ncfg_buf_add_char(body, '"');
	for (i = 0; i < ssid->length; i++) {
		ncfg_buf_add_char(body, digits[ssid->bytes[i] >> 4]);
		ncfg_buf_add_char(body, digits[ssid->bytes[i] & 0x0fu]);
	}
	ncfg_buf_add_char(body, '"');
}

static void render_security(const ncfg_security_t *security, ncfg_buf_t *body)
{
	switch (security->kind) {
	case NCFG_SECURITY_OWE:
		ncfg_buf_add_text(body, "\t\towe = true\n");
		break;
	case NCFG_SECURITY_PSK:
		ncfg_buf_add_text(body, "\t\tpsk = ");
		ncfg_render_quote_secret(body, &security->psk.passphrase);
		ncfg_buf_add_char(body, '\n');
		/* See `psk_proto_words`: the default is the permissive generation, so
		 * an omitted `proto` is a downgrade rather than a tidier file. */
		if (security->psk.proto != NCFG_PSK_PROTO_WPA2_WPA3) {
			ncfg_buf_addf(body, "\t\tproto = \"%s\"\n",
			    ncfg_render_word_or_gap(ncfg_render_word(psk_proto_words,
			        NCFG_COUNT_OF(psk_proto_words), security->psk.proto)));
		}
		break;
	case NCFG_SECURITY_EAP:
		render_eap(&security->eap, body);
		break;
	default:
		ncfg_buf_add_text(body, "\t\topen = true\n");
		break;
	}
}

/* The keys that sit beside `wifi` rather than inside it. A function of its own
 * because the block's two halves are written by two functions and the split is
 * where a key ends up at the wrong nesting. */
static void render_network_keys(const ncfg_wifi_network_t *network, ncfg_buf_t *body)
{
	size_t i;

	/* **Absent is a statement, not an absence**, which is what the first
	 * version of this read it as. `document.h` says so where the field is
	 * declared: absent means "whatever the access points in `bssid` call
	 * themselves", while omitting the key makes the SSID the block's label.
	 * Three states, and writing nothing for the third collapsed it into the
	 * first -- `ssid = "@bssid"` vanished and the document came back as a
	 * network named after its own label, so `ncfg profile save` refused on any
	 * machine with a network pinned by access point.
	 *
	 * Found on the Rust side first and fixed there as well; the two renderers
	 * were written independently and had the same hole. The marker's spelling
	 * comes from the lowerer that defines it rather than being retyped here. */
	if (network->ssid.has) {
		size_t length = strlen(network->id ? network->id : "");

		/* The id is the SSID unless they differ, in which case the bytes are
		 * written and the id stays a handle. */
		if (length != network->ssid.length ||
		    memcmp(network->id, network->ssid.bytes, length) != 0) {
			ncfg_buf_add_text(body, "\tssid = ");
			quote_ssid(body, &network->ssid);
			ncfg_buf_add_char(body, '\n');
		}
	} else {
		ncfg_buf_add_text(body, "\tssid = ");
		ncfg_render_quote(body, ncfg_ssid_from_bssid);
		ncfg_buf_add_char(body, '\n');
	}
	if (network->hidden) {
		ncfg_buf_add_text(body, "\thidden = true\n");
	}
	if (network->metered) {
		ncfg_buf_add_text(body, "\tmetered = true\n");
	}
	/* Network level, beside `metered`, and deliberately not inside `wifi`
	 * where the supplicant's own ranking used to sit. The two are different
	 * scales running opposite ways: this is the kernel's metric, lower wins,
	 * and it ranks this network's routes against every other link once joined.
	 * A profile keeping only one would come back ranking differently from the
	 * machine it was saved on (0154). */
	if (network->metric.has) {
		ncfg_buf_addf(body, "\tmetric = %lld\n", (long long)network->metric.value);
	}
	/* Was dropped in silence. A bssid list is how an operator pins a network
	 * to the access points that are actually theirs, so losing it widens the
	 * network to any radio broadcasting the same name -- which is the thing
	 * the key exists to prevent. */
	if (network->bssid_count > 0) {
		ncfg_render_list_t pins;

		ncfg_render_list_init(&pins);
		for (i = 0; i < network->bssid_count; i++) {
			ncfg_render_quote(ncfg_render_list_next(&pins), network->bssid[i]);
		}
		ncfg_render_list_emit(body, "\t", "bssid", &pins, 0);
		ncfg_render_list_free(&pins);
	}
}

/*
 * One `access_point` block: a radio this machine runs as an AP.
 *
 * **Refused wholesale until now**, so a machine running a hotspot could not save
 * a profile -- and the configuration is one somebody set up deliberately, which
 * is the worst kind to lose.
 *
 * Here rather than in `render.c` because it reuses two statics this file already
 * has: `render_security`, which a network's `wifi` block uses, and `quote_ssid`.
 * A second copy of either would be a second place for the key-management
 * spellings to drift, which is the argument that put networks and interfaces in
 * one file to begin with.
 *
 * The label is the SSID unless the document said otherwise, exactly as a
 * network's is -- and then it is hex, because an SSID is 0 to 32 arbitrary
 * octets while a label is text.
 *
 * **One list, and which key it is under IS the policy.** The compiler refuses a
 * block carrying both an `allow` and a `deny`, so there is no separate value to
 * write; the key says it. The list is bracketed even for one station, because
 * `access_control` is where a reader most needs to see that it is a list rather
 * than a single permitted address.
 */
void ncfg_render_access_point(const ncfg_access_point_t *point, const ncfg_overrides_t *overrides,
    ncfg_buf_t *text, ncfg_unrenderable_t *missing)
{
	ncfg_buf_t body;
	size_t     length;

	ncfg_buf_init(&body, 0);
	ncfg_buf_add_text(&body, "\tdevice = ");
	ncfg_render_quote(&body, point->device);
	ncfg_buf_add_char(&body, '\n');

	length = strlen(point->id ? point->id : "");
	if (length != point->ssid.length ||
	    memcmp(point->id, point->ssid.bytes, length) != 0) {
		ncfg_buf_add_text(&body, "\tssid = ");
		quote_ssid(&body, &point->ssid);
		ncfg_buf_add_char(&body, '\n');
	}
	if (point->channel.has) {
		/*
		 * **The model's test, not a copy.** That is the rule `check_channel_in_band`
		 * states after the compiler grew its own pair of statics: one implementation of
		 * which channels are in which band, in the model, used by the compiler, by the
		 * hostapd renderer and now by this.
		 *
		 * The document's range for a channel is `R_U16` while the language takes 1 to 14
		 * or 36 to 177 depending on the band, so a document read from JSON holds
		 * channels this cannot write back. Measured: 0, 20, 300 and 65535 each rendered
		 * and then failed the round trip in the compiler's own words.
		 *
		 * A band with no channel range of its own -- `6`, which the compiler accepts
		 * deliberately -- writes the channel as it stands. Band 6 is refused by the
		 * hostapd renderer, which is where it belongs: the configuration language reads
		 * `band = "6"` back perfectly well, so refusing it here would stop a profile
		 * saving over something this file can in fact write.
		 */
		const char *band = ncfg_access_point_effective_band(point->band,
		    &point->channel);

		if (band && !ncfg_channel_in_band(band, point->channel.value)) {
			ncfg_render_refuse(missing, "access_point", point->id,
			    "channel %lld, which is not in the %s GHz band",
			    (long long)point->channel.value, band);
		} else {
			ncfg_buf_addf(&body, "\tchannel = %lld\n",
			    (long long)point->channel.value);
		}
	}
	if (point->band) {
		ncfg_buf_add_text(&body, "\tband = ");
		ncfg_render_quote(&body, point->band);
		ncfg_buf_add_char(&body, '\n');
	}
	if (point->regdom) {
		ncfg_buf_add_text(&body, "\tregdom = ");
		ncfg_render_quote(&body, point->regdom);
		ncfg_buf_add_char(&body, '\n');
	}
	if (point->hidden) {
		ncfg_buf_add_text(&body, "\thidden = true\n");
	}
	ncfg_buf_add_text(&body, "\twifi {\n");
	render_security(&point->security, &body);
	ncfg_buf_add_text(&body, "\t}\n");

	if (point->access_control) {
		size_t i;

		ncfg_buf_addf(&body, "\taccess_control { %s = [",
		    point->access_control->policy == NCFG_ACL_POLICY_ALLOW ? "allow" : "deny");
		for (i = 0; i < point->access_control->station_count; i++) {
			if (i) {
				ncfg_buf_add_text(&body, ", ");
			}
			ncfg_render_quote(&body, point->access_control->stations[i]);
		}
		ncfg_buf_add_text(&body, "] }\n");
	}

	ncfg_render_opening(text, "access_point", point->id, overrides);
	ncfg_render_quote(text, point->id);
	ncfg_buf_addf(text, " {\n%s}\n", ncfg_buf_text(&body));
	ncfg_buf_free(&body);
}

void ncfg_render_network(const ncfg_wifi_network_t *network, const ncfg_overrides_t *overrides,
    ncfg_buf_t *text, ncfg_unrenderable_t *missing)
{
	const char *id = network->id;
	ncfg_buf_t  body;

	ncfg_buf_init(&body, 0);
	render_network_keys(network, &body);

	ncfg_buf_add_text(&body, "\twifi {\n");
	render_security(&network->security, &body);
	if (!network->autoconnect) {
		ncfg_buf_add_text(&body, "\t\tautoconnect = false\n");
	}
	/* Also dropped in silence, and it lives inside `wifi` rather than beside
	 * it. **Every value is written whenever the block exists**, because the
	 * parser supplies its defaults when the block is *absent* -- a roam block
	 * that rendered only its non-defaults could come back empty, and an empty
	 * block is not the same document as no block at all. */
	if (network->roam) {
		/*
		 * **Both of the compiler's own tests, from the model**, because the
		 * members' ranges are wider than the language: `signal` is `R_I32` and
		 * dBm is negative, and the two intervals are each `R_U32` with an order
		 * between them that neither range can express. A document read from JSON
		 * holds such a policy, and before this it was written out and then
		 * rejected by the program that wrote it.
		 *
		 * Found by a sweep over every numeric leaf of a renderable document
		 * rather than by reading the lowering: these two messages say "is not a
		 * signal strength" and "cannot be longer than", so the grep that
		 * enumerated the other six constraints by their wording missed both.
		 */
		if (!ncfg_roam_signal_in_range(network->roam->signal)) {
			ncfg_render_refuse(missing, "network", id,
			    "a roam signal of %lld, which is not dBm (%d to %d)",
			    (long long)network->roam->signal, NCFG_ROAM_SIGNAL_MIN,
			    NCFG_ROAM_SIGNAL_MAX);
		} else if (!ncfg_roam_intervals_ordered(network->roam->interval,
		    network->roam->slow_interval)) {
			ncfg_render_refuse(missing, "network", id,
			    "a roam `interval` of %lld longer than its `slow_interval` of %lld",
			    (long long)network->roam->interval,
			    (long long)network->roam->slow_interval);
		} else {
			ncfg_buf_addf(&body,
			    "\t\troam {\n\t\t\tsignal = %lld\n\t\t\tinterval = %lld\n"
			    "\t\t\tslow_interval = %lld\n\t\t}\n",
			    (long long)network->roam->signal, (long long)network->roam->interval,
			    (long long)network->roam->slow_interval);
		}
	}
	ncfg_buf_add_text(&body, "\t}\n");

	/* All three were dropped in silence, and they are the worst of the set: a
	 * `network` block takes the same `config`, `routes` and `dns` an interface
	 * does, so a profile that lost them brought the machine back on DHCP
	 * against the wrong nameserver. */
	render_addressing(network->addressing, network->addressing_count, "network", id, &body,
	    missing);
	render_routes(network->routes, network->route_count, "network", id, &body, missing);
	if (network->dns && !ncfg_render_dns(network->dns, "\t", &body, missing, "network", id)) {
		/* Present and empty says the same thing here as on an interface. */
		ncfg_buf_add_text(&body, "\tdns { }\n");
	}
	/* Refused for the reason `ncfg_render_interface` gives at the same
	 * refusal, and it is the same reason rather than a matching one: the
	 * document holds a hook's path and hash and never its shell, so there is
	 * nothing here to write a phase block back from. Not "yet". */
	if (network->hook_count > 0) {
		ncfg_render_refuse(missing, "network", id, "hooks");
	}

	/* An empty label renders as `network "" {` and the lowering refuses it: the
	 * label is the SSID, so there is nothing to call the network. */
	if (!id || id[0] == '\0') {
		ncfg_render_refuse(missing, "network", NULL,
		    "a network with no name, which the language has no way to write");
		ncfg_buf_free(&body);
		return;
	}
	ncfg_render_opening(text, "network", id, overrides);
	ncfg_render_quote(text, id);
	ncfg_buf_addf(text, " {\n%s}\n", ncfg_buf_text(&body));
	ncfg_buf_free(&body);
}
