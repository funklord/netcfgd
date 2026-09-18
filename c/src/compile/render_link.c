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
 * **The Rust this ports wrote the bare word and dropped every one of them in
 * silence**, which is the defect this module exists to refuse rather than a
 * rendering choice. The modifiers are written; what has no words is named.
 * `slaac privacy` is worth the distinction on its own: losing it puts a
 * machine back on stable addresses, which is a privacy property the operator
 * chose and which nothing downstream would report.
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
			/* The language has `peer`, `preferred_lft` and `valid_lft` as
			 * modifiers and this does not write them, so they are named.
			 * A refusal is not a drop; closing it is a separate piece of
			 * work with its own round trip. */
			if (source->static_address.peer ||
			    source->static_address.preferred_lifetime.has ||
			    source->static_address.valid_lifetime.has) {
				ncfg_render_refuse(missing, scope, name,
				    "an address with lifetimes or a peer");
			}
			ncfg_render_quote(ncfg_render_list_next(&config),
			    source->static_address.address);
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
	 * **Dropped in silence by the Rust this ports, and it weakens a network.**
	 * `ca_cert` alone answers "who signed this", not "who is this": it accepts
	 * any certificate the pinned issuer signed, which is nearly worthless when
	 * that issuer is a public CA -- and a commercial certificate on a RADIUS
	 * server is ordinary (0206). `lower.rs` reads the key on both a `dot1x`
	 * block and a network's `wifi`, so there is nothing to decide and nothing
	 * stopping it being written.
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
 * `require_lease` is deliberately not written. It defaults on, the
 * configuration language has no key for it, and there is therefore nothing an
 * operator could have chosen for a snapshot to preserve.
 */
static void render_probe(const ncfg_probe_policy_t *probe, ncfg_buf_t *body)
{
	static const struct {
		const char *key;
		int64_t     fallback;
	} numbers[] = { { "interval", 30 }, { "timeout", 5 }, { "down_after", 3 },
		{ "up_after", 2 }, { "hold_down", 0 } };
	int64_t            values[5];
	ncfg_render_list_t args;
	size_t             i;

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
		if (values[i] != numbers[i].fallback) {
			ncfg_buf_addf(body, "\t\t%s = %lld\n", numbers[i].key,
			    (long long)values[i]);
		}
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
static void render_interface_keys(const ncfg_interface_t *interface, ncfg_buf_t *body)
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
		render_probe(interface->probe, body);
	}
}

void ncfg_render_interface(const ncfg_interface_t *interface, const ncfg_overrides_t *overrides,
    ncfg_buf_t *text, ncfg_unrenderable_t *missing)
{
	const char *name = interface->name;
	ncfg_buf_t  body;

	/* Each of these has a block or a key of its own that this does not write
	 * yet. Named so the operator knows what to keep by hand. */
	if (interface->hook_count > 0) {
		ncfg_render_refuse(missing, "interface", name, "hooks");
	}
	if (interface->advertise) {
		ncfg_render_refuse(missing, "interface", name, "advertise");
	}
	if (interface->guard) {
		ncfg_render_refuse(missing, "interface", name, "guard");
	}

	ncfg_buf_init(&body, 0);
	render_interface_keys(interface, &body);
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

	ncfg_render_opening(text, "interface", name, overrides);
	ncfg_buf_addf(text, "%s {\n%s}\n", name ? name : "", ncfg_buf_text(&body));
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
		ncfg_buf_addf(&body,
		    "\t\troam {\n\t\t\tsignal = %lld\n\t\t\tinterval = %lld\n"
		    "\t\t\tslow_interval = %lld\n\t\t}\n",
		    (long long)network->roam->signal, (long long)network->roam->interval,
		    (long long)network->roam->slow_interval);
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
	/* Refused rather than rendered, matching an interface's hooks: the phase
	 * blocks have a shape of their own and neither side writes them yet. */
	if (network->hook_count > 0) {
		ncfg_render_refuse(missing, "network", id, "hooks");
	}

	ncfg_render_opening(text, "network", id, overrides);
	ncfg_render_quote(text, id);
	ncfg_buf_addf(text, " {\n%s}\n", ncfg_buf_text(&body));
	ncfg_buf_free(&body);
}
