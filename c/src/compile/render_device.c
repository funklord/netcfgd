/*
 * render_device.c -- devices, link kinds, bluetooth and linksets.
 *
 * A `device` is what netcfgd creates and what it is a port of, plus the
 * settings of the hardware itself. Decision 0155 moved both halves here from
 * `interface`, and a field that moves type and is not taught to the renderer
 * is silently dropped from every saved profile -- which is the failure that
 * move most easily creates, and which it did create twice.
 */
#include "lower_internal.h"
#include "render_private.h"

#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/value.h"

#include <stdio.h>
#include <string.h>


/* `iproute2`'s spellings, the same on both sides, from
 * `netcfgd-model/src/interface.rs`. `802.3ad` is what every piece of bonding
 * documentation calls LACP, and a tidier word would be a bond the kernel
 * refuses. */
static const char *const bond_mode_words[] = { "balance-rr", "active-backup", "balance-xor",
	"broadcast", "802.3ad", "balance-tlb", "balance-alb" };
static const char *const vlan_protocol_words[] = { "dot1q", "dot1ad" };
static const char *const macvlan_mode_words[] = { "private", "vepa", "bridge", "passthru" };

/* A radio's own policy, spelled as `lower_device` reads each back. `iwd` is
 * rendered like any other: the compiler accepts it and netcfgd refuses it at
 * use (0014), so a profile that dropped it would turn a configuration netcfgd
 * explains itself about into one it silently approves. */
/*
 * **In `ncfg_wifi_backend_t`'s order, because it is indexed by it.** AUTO, IWD,
 * WPA_SUPPLICANT. A table out of step with the enum it is indexed by renders
 * `wpa_supplicant` as `iwd` and vice versa, which is a configuration this
 * build refuses at use reported as one it serves -- so read the order from
 * `document.h` rather than from anywhere else.
 *
 * ~~Which is not the Rust enum's: the Rust one is Auto, WpaSupplicant, Iwd.~~
 * **That was never true.** `WifiBackend` has been Auto, Iwd, WpaSupplicant
 * since the commit that created it, checked with `git show`, so this is an
 * invented claim rather than one that went stale -- and a dangerous one, since
 * it invites somebody to "correct" the table into the bug the paragraph warns
 * about. The invariant that matters is the local one above and needs no
 * comparison to state.
 */
static const char *const wifi_backend_words[] = { "auto", "iwd", "wpa_supplicant" };
static const char *const powersave_words[] = { "default", "on", "off" };
static const char *const mac_policy_words[] = { "permanent", "per_network", "per_connection" };

/* ------------------------------------------------------------------------ *
 * What kind of thing a device is
 * ------------------------------------------------------------------------ */

static void render_bridge(const ncfg_bridge_config_t *bridge, ncfg_buf_t *body)
{
	static const char *const keys[] = { "forward_delay", "hello_time", "ageing_time",
		"priority" };
	const ncfg_optint_t *values[4];
	ncfg_render_list_t   members;
	size_t               i;

	ncfg_buf_add_text(body, "\tbridge {\n");
	ncfg_render_list_init(&members);
	for (i = 0; i < bridge->member_count; i++) {
		ncfg_render_quote(ncfg_render_list_next(&members), bridge->members[i]);
	}
	ncfg_render_list_emit(body, "\t\t", "members", &members, 0);
	ncfg_render_list_free(&members);
	if (bridge->stp) {
		ncfg_buf_add_text(body, "\t\tstp = true\n");
	}
	values[0] = &bridge->forward_delay;
	values[1] = &bridge->hello_time;
	values[2] = &bridge->ageing_time;
	values[3] = &bridge->priority;
	for (i = 0; i < NCFG_COUNT_OF(keys); i++) {
		if (values[i]->has) {
			ncfg_buf_addf(body, "\t\t%s = %lld\n", keys[i], (long long)values[i]->value);
		}
	}
	if (bridge->vlan_filtering) {
		ncfg_buf_add_text(body, "\t\tvlan_filtering = true\n");
	}
	ncfg_buf_add_text(body, "\t}\n");
}

static void render_bond(const ncfg_bond_config_t *bond, ncfg_buf_t *body)
{
	ncfg_render_list_t members;
	size_t             i;

	ncfg_buf_add_text(body, "\tbond {\n");
	ncfg_render_list_init(&members);
	for (i = 0; i < bond->member_count; i++) {
		ncfg_render_quote(ncfg_render_list_next(&members), bond->members[i]);
	}
	ncfg_render_list_emit(body, "\t\t", "members", &members, 0);
	ncfg_render_list_free(&members);
	/* **Always, unlike every other default here.** The *parser* requires a
	 * mode even though the model has one, so a bond whose mode happened to
	 * equal the default would render as a block that no longer compiles. A
	 * model default and a language default are not the same fact, and this is
	 * the one place in this module where they differ. Caught by testing each
	 * kind twice, once with every optional key set and once with none -- the
	 * second being the case nobody writes. */
	ncfg_buf_addf(body, "\t\tmode = \"%s\"\n", ncfg_render_word_or_gap(
	    ncfg_render_word(bond_mode_words, NCFG_COUNT_OF(bond_mode_words), bond->mode)));
	if (bond->miimon.has) {
		ncfg_buf_addf(body, "\t\tmiimon = %lld\n", (long long)bond->miimon.value);
	}
	ncfg_buf_add_text(body, "\t}\n");
}

static void render_vxlan(const ncfg_vxlan_config_t *vxlan, ncfg_buf_t *body)
{
	static const char *const keys[] = { "parent", "local", "remote" };
	const char              *values[3];
	size_t                   i;

	ncfg_buf_addf(body, "\tvxlan {\n\t\tid = %lld\n", (long long)vxlan->id);
	values[0] = vxlan->parent;
	values[1] = vxlan->local;
	values[2] = vxlan->remote;
	for (i = 0; i < NCFG_COUNT_OF(keys); i++) {
		if (values[i]) {
			ncfg_buf_addf(body, "\t\t%s = ", keys[i]);
			ncfg_render_quote(body, values[i]);
			ncfg_buf_add_char(body, '\n');
		}
	}
	if (vxlan->port.has) {
		ncfg_buf_addf(body, "\t\tport = %lld\n", (long long)vxlan->port.value);
	}
	ncfg_buf_add_text(body, "\t}\n");
}

/*
 * A PPPoE session.
 *
 * **Refused wholesale for a while, on the reasoning that a kind carrying a
 * secret needs a decision about what a snapshot may contain** -- and for an
 * `ncfg_secret_ref_t` that decision was already made and already relied on: a
 * network's `psk` renders as `@secret:name`, because the type is incapable of
 * carrying the value. A password here is the same type and gets the same
 * answer. The refusal cost a whole `ncfg profile save` on any machine whose
 * WAN is DSL or fibre, which is exactly the machine profiles exist for.
 */
static void render_pppoe(const ncfg_pppoe_config_t *pppoe, ncfg_buf_t *body)
{
	ncfg_buf_add_text(body, "\tpppoe {\n\t\tparent = ");
	ncfg_render_quote(body, pppoe->parent);
	ncfg_buf_add_text(body, "\n\t\tusername = ");
	ncfg_render_quote(body, pppoe->username);
	ncfg_buf_add_text(body, "\n\t\tpassword = ");
	ncfg_render_quote_secret(body, &pppoe->password);
	ncfg_buf_add_char(body, '\n');
	if (pppoe->service) {
		ncfg_buf_add_text(body, "\t\tservice = ");
		ncfg_render_quote(body, pppoe->service);
		ncfg_buf_add_char(body, '\n');
	}
	if (pppoe->ac) {
		ncfg_buf_add_text(body, "\t\tac = ");
		ncfg_render_quote(body, pppoe->ac);
		ncfg_buf_add_char(body, '\n');
	}
	ncfg_buf_add_text(body, "\t}\n");
}

/*
 * An OpenVPN tunnel: a path, and optionally a login for it.
 *
 * 0046 is why there is so little here -- `openvpn --help` lists 253 top-level
 * options, so netcfgd names the operator's `.ovpn` and does not express its
 * surface. That makes this the smallest of the kinds and the one whose absence
 * was least excusable.
 *
 * **Username and password are both or neither**, which `lower_openvpn` enforces,
 * so a document holding one of them arrived some other way and is named rather
 * than written: rendering half of a login produces a profile that does not
 * compile, and the operator would meet that instead of this.
 */
static void render_openvpn(const ncfg_openvpn_config_t *openvpn, const char *name,
    ncfg_buf_t *body, ncfg_unrenderable_t *missing)
{
	if (!openvpn->config) {
		ncfg_render_refuse(missing, "device", name, "an openvpn tunnel with no config file");
		return;
	}
	if ((openvpn->username != NULL) != (openvpn->password != NULL)) {
		ncfg_render_refuse(missing, "device", name,
		    "an openvpn tunnel with only half of a login");
		return;
	}
	ncfg_buf_add_text(body, "\topenvpn {\n\t\tconfig = ");
	ncfg_render_quote(body, openvpn->config);
	ncfg_buf_add_char(body, '\n');
	if (openvpn->username) {
		ncfg_buf_add_text(body, "\t\tusername = ");
		ncfg_render_quote(body, openvpn->username);
		ncfg_buf_add_text(body, "\n\t\tpassword = ");
		ncfg_render_quote_secret(body, openvpn->password);
		ncfg_buf_add_char(body, '\n');
	}
	ncfg_buf_add_text(body, "\t}\n");
}

/*
 * A tun or tap device.
 *
 * **The mode is the block's name, not a key inside it.** `lower_tun` is reached
 * from `tun { }` and from `tap { }` and sets the mode from which head it saw, so
 * writing `tun { mode = "tap" }` would be an unknown key rather than a tap
 * device. One model type, two spellings, and the spelling is the whole
 * difference.
 */
static void render_tun(const ncfg_tun_config_t *tun, ncfg_buf_t *body)
{
	ncfg_buf_addf(body, "\t%s {\n", tun->mode == NCFG_TUN_MODE_TAP ? "tap" : "tun");
	if (tun->owner) {
		ncfg_buf_add_text(body, "\t\towner = ");
		ncfg_render_quote(body, tun->owner);
		ncfg_buf_add_char(body, '\n');
	}
	if (tun->group) {
		ncfg_buf_add_text(body, "\t\tgroup = ");
		ncfg_render_quote(body, tun->group);
		ncfg_buf_add_char(body, '\n');
	}
	ncfg_buf_add_text(body, "\t}\n");
}

/*
 * A tunnel of whichever encapsulation.
 *
 * One model type for seven kernel link kinds, which take the same parameters and
 * differ only in the name sent to the kernel -- so this is one block with a
 * `mode`, which is what the language has too. **The field is called `mode` and
 * not `kind`** for the serialisation reason `document.h` records, and the
 * language accepts either spelling; `mode` is written, being the model's.
 */
static void render_tunnel(const ncfg_tunnel_config_t *tunnel, const char *name,
    ncfg_buf_t *body, ncfg_unrenderable_t *missing)
{
	size_t end;

	/*
	 * **What `lower_tunnel` refuses, this refuses**, by asking the same
	 * function rather than restating the rule. An endpoint has to agree with
	 * the encapsulation -- a v6 `remote` on an `ipip` is a link the kernel
	 * will not build -- so a document carrying the disagreement is one no
	 * config file could have produced, and writing it back produces a profile
	 * that does not compile.
	 *
	 * Found by round-tripping the plan suites' fixtures: the renderer wrote
	 * `tunnel { mode = "geneve"; remote = "2001:db8::9" }` and the compiler
	 * answered "a `geneve` tunnel carries an IPv4 outer header, and `remote`
	 * is IPv6". Unreachable from a config file, and kept for the reason every
	 * other such refusal is kept -- this takes a document rather than a file,
	 * and a refusal that cannot fire costs nothing while writing something
	 * uncompilable costs the save.
	 */
	for (end = 0; end < 2u; end++) {
		const char *address = end ? tunnel->remote : tunnel->local;

		if (address && (strchr(address, ':') != NULL) != (ncfg_tunnel_is_v6(tunnel->mode) != 0)) {
			ncfg_render_refuse(missing, "device", name,
			    "a %s tunnel whose %s is the other address family",
			    ncfg_render_word_or_gap(ncfg_tunnel_mode_name(tunnel->mode)),
			    end ? "remote" : "local");
			return;
		}
	}

	ncfg_buf_addf(body, "\ttunnel {\n\t\tmode = \"%s\"\n",
	    ncfg_render_word_or_gap(ncfg_tunnel_mode_name(tunnel->mode)));
	if (tunnel->local) {
		ncfg_buf_add_text(body, "\t\tlocal = ");
		ncfg_render_quote(body, tunnel->local);
		ncfg_buf_add_char(body, '\n');
	}
	if (tunnel->remote) {
		ncfg_buf_add_text(body, "\t\tremote = ");
		ncfg_render_quote(body, tunnel->remote);
		ncfg_buf_add_char(body, '\n');
	}
	if (tunnel->parent) {
		ncfg_buf_add_text(body, "\t\tparent = ");
		ncfg_render_quote(body, tunnel->parent);
		ncfg_buf_add_char(body, '\n');
	}
	/* `ttl` of zero means inherit from the inner packet, which is a value and
	 * not an absence -- so it is written whenever the field is set. */
	if (tunnel->ttl.has) {
		ncfg_buf_addf(body, "\t\tttl = %lld\n", (long long)tunnel->ttl.value);
	}
	if (tunnel->key.has) {
		ncfg_buf_addf(body, "\t\tkey = %lld\n", (long long)tunnel->key.value);
	}
	ncfg_buf_add_text(body, "\t}\n");
}

/*
 * A WireGuard device and its peers.
 *
 * The private key and each preshared key are written as **references**, never as
 * material: that is what `ncfg_secret_ref_t` is for, and the document is
 * incapable of carrying the key itself. So saving a profile from a WireGuard
 * machine does not copy its keys anywhere, and the rendering could not leak one
 * if it tried.
 *
 * **A peer's public key goes out through `ncfg_key_render` rather than any
 * spelling of this function's own.** Base64 has more than one spelling of one
 * 32-octet key -- the final character carries four significant bits -- and the
 * model keeps octets precisely so that two spellings compare equal. Rendering
 * them by hand would reintroduce the second spelling at the one point where the
 * whole arrangement is meant to produce the first.
 *
 * Its status is read, and a key that will not render is named rather than
 * written as the empty string it leaves behind: an `ncfg_key_render` that
 * refused and a peer with no key look identical in the output otherwise.
 */
static void render_wireguard(const ncfg_wireguard_config_t *wireguard, const char *name,
    ncfg_buf_t *body, ncfg_unrenderable_t *missing)
{
	size_t i;

	ncfg_buf_add_text(body, "\twireguard {\n\t\tprivate_key = ");
	ncfg_render_quote_secret(body, &wireguard->private_key);
	ncfg_buf_add_char(body, '\n');
	if (wireguard->listen_port.has) {
		ncfg_buf_addf(body, "\t\tlisten_port = %lld\n",
		    (long long)wireguard->listen_port.value);
	}
	if (wireguard->fwmark.has) {
		ncfg_buf_addf(body, "\t\tfwmark = %lld\n", (long long)wireguard->fwmark.value);
	}
	for (i = 0; i < wireguard->peer_count; i++) {
		const ncfg_wg_peer_t *peer = &wireguard->peers[i];
		char                  text[NCFG_KEY_TEXT_SIZE];
		ncfg_render_list_t    allowed;
		size_t                at;

		/* No error buffer: the only way `ncfg_key_render` refuses is a buffer
		 * too small for the text, which `NCFG_KEY_TEXT_SIZE` is not, so there
		 * is no sentence to relay that this refusal does not already say. The
		 * status is still read -- it empties `out` on a refusal, and an empty
		 * key written into a peer block is indistinguishable from a peer that
		 * has none. */
		if (!ncfg_key_render(peer->public_key, text, sizeof(text), NULL, 0)) {
			ncfg_render_refuse(missing, "device", name,
			    "a wireguard peer whose public key will not render");
			continue;
		}
		ncfg_buf_add_text(body, "\t\tpeer ");
		ncfg_render_label(body, peer->name);
		ncfg_buf_addf(body, " {\n\t\t\tpublic_key = \"%s\"\n", text);
		if (peer->preshared_key) {
			ncfg_buf_add_text(body, "\t\t\tpreshared_key = ");
			ncfg_render_quote_secret(body, peer->preshared_key);
			ncfg_buf_add_char(body, '\n');
		}
		if (peer->endpoint) {
			ncfg_buf_add_text(body, "\t\t\tendpoint = ");
			ncfg_render_quote(body, peer->endpoint);
			ncfg_buf_add_char(body, '\n');
		}
		ncfg_render_list_init(&allowed);
		for (at = 0; at < peer->allowed_ip_count; at++) {
			ncfg_render_quote(ncfg_render_list_next(&allowed), peer->allowed_ips[at]);
		}
		ncfg_render_list_emit(body, "\t\t", "\tallowed_ips", &allowed, 1);
		ncfg_render_list_free(&allowed);
		if (peer->keepalive.has) {
			ncfg_buf_addf(body, "\t\t\tkeepalive = %lld\n",
			    (long long)peer->keepalive.value);
		}
		ncfg_buf_add_text(body, "\t\t}\n");
	}
	ncfg_buf_add_text(body, "\t}\n");
}

/*
 * What kind of link this is, as its own block.
 *
 * Every kind the model has renders except `ifb`, which is synthesised: netcfgd
 * creates one per interface asking for `ingress_bandwidth`, so it is never
 * written by hand and rendering it back would put a derived device into a
 * profile as though somebody had asked for it. That is the same reason the
 * metering half of a qdisc and `ingress_redirect` are refused, and it is a
 * property of the thing rather than work left undone.
 */
static void render_kind(const ncfg_interface_kind_t *kind, const char *name, ncfg_buf_t *body,
    ncfg_unrenderable_t *missing)
{
	switch (kind->kind) {
	case NCFG_KIND_PHYSICAL:
		break;
	case NCFG_KIND_DUMMY:
		ncfg_buf_add_text(body, "\tkind = \"dummy\"\n");
		break;
	case NCFG_KIND_BRIDGE:
		render_bridge(&kind->bridge, body);
		break;
	case NCFG_KIND_BOND:
		render_bond(&kind->bond, body);
		break;
	case NCFG_KIND_VLAN:
		ncfg_buf_add_text(body, "\tvlan {\n\t\tparent = ");
		ncfg_render_quote(body, kind->vlan.parent);
		ncfg_buf_addf(body, "\n\t\tid = %lld\n", (long long)kind->vlan.id);
		if (kind->vlan.protocol != NCFG_VLAN_PROTOCOL_DOT1Q) {
			ncfg_buf_addf(body, "\t\tprotocol = \"%s\"\n",
			    ncfg_render_word_or_gap(ncfg_render_word(vlan_protocol_words,
			        NCFG_COUNT_OF(vlan_protocol_words), kind->vlan.protocol)));
		}
		ncfg_buf_add_text(body, "\t}\n");
		break;
	case NCFG_KIND_VXLAN:
		render_vxlan(&kind->vxlan, body);
		break;
	case NCFG_KIND_MACVLAN:
		ncfg_buf_add_text(body, "\tmacvlan {\n\t\tparent = ");
		ncfg_render_quote(body, kind->macvlan.parent);
		ncfg_buf_add_char(body, '\n');
		if (kind->macvlan.mode != NCFG_MACVLAN_MODE_PRIVATE) {
			ncfg_buf_addf(body, "\t\tmode = \"%s\"\n",
			    ncfg_render_word_or_gap(ncfg_render_word(macvlan_mode_words,
			        NCFG_COUNT_OF(macvlan_mode_words), kind->macvlan.mode)));
		}
		ncfg_buf_add_text(body, "\t}\n");
		break;
	case NCFG_KIND_VRF:
		ncfg_buf_addf(body, "\tvrf { table = %lld }\n", (long long)kind->vrf.table);
		break;
	case NCFG_KIND_VETH:
		ncfg_buf_add_text(body, "\tveth { peer = ");
		ncfg_render_quote(body, kind->veth.peer);
		ncfg_buf_add_text(body, " }\n");
		break;
	case NCFG_KIND_PPPOE:
		render_pppoe(&kind->pppoe, body);
		break;
	case NCFG_KIND_OPENVPN:
		render_openvpn(&kind->openvpn, name, body, missing);
		break;
	case NCFG_KIND_TUN:
		render_tun(&kind->tun, body);
		break;
	case NCFG_KIND_TUNNEL:
		render_tunnel(&kind->tunnel, name, body, missing);
		break;
	case NCFG_KIND_WIREGUARD:
		render_wireguard(&kind->wireguard, name, body, missing);
		break;
	default:
		/* The scope is `device` and not `interface`, which is where 0155 pass
		 * 1b moved the kind to -- a refusal naming the wrong block sends the
		 * operator to write the key where the parser no longer reads it. */
		/* The language's word and not the document's: the refusal exists so
		 * an operator knows which block to write by hand, and naming a word
		 * the language does not have sends them to write one that cannot
		 * compile. The table is the model's -- `document.h` says why there is
		 * only one of it. */
		ncfg_render_refuse(missing, "device", name, "kind %s",
		    ncfg_render_word_or_gap(ncfg_interface_kind_language_name(kind->kind)));
		break;
	}
}

/*
 * A radio's own policy: what the device is told to do, not what it may join.
 *
 * **Refused wholesale until now, which meant no machine with a radio could save
 * a profile.** `ncfg wifi activate` writes `device wlan0 { wifi { autoconnect =
 * true } }`, so a laptop that has ever joined a network from the client has one
 * -- and `ncfg profile save` answered that it could not render a wifi policy.
 * The seven fields are the whole of `ncfg_wifi_device_policy_t`.
 *
 * **Present and empty is not absent**, as it is for `dns` (10.21) and the
 * device block itself: `device->wifi` being non-NULL is what makes a device a
 * radio netcfgd manages, so the block is opened even when every field sits at
 * its default and `wifi { }` comes back as `wifi { }` rather than as nothing.
 *
 * Only what differs from a default is written, which is this renderer's rule
 * everywhere: a block restating every default is one nobody can read for what
 * is unusual. `regdom` is already uppercase, `lower_device` having upcased it on
 * the way in, so it reads back as the same value rather than one the parser
 * would normalise again.
 */
static void render_wifi_device(const ncfg_wifi_device_policy_t *wifi, ncfg_buf_t *body)
{
	if (!wifi) {
		return;
	}
	ncfg_buf_add_text(body, "\twifi {\n");
	if (wifi->backend != NCFG_WIFI_BACKEND_AUTO) {
		ncfg_buf_addf(body, "\t\tbackend = \"%s\"\n",
		    ncfg_render_word_or_gap(ncfg_render_word(wifi_backend_words,
		        NCFG_COUNT_OF(wifi_backend_words), wifi->backend)));
	}
	/* `autoconnect` defaults to true, so only `false` is worth a line. */
	if (!wifi->autoconnect) {
		ncfg_buf_add_text(body, "\t\tautoconnect = false\n");
	}
	if (wifi->portal_check) {
		ncfg_buf_add_text(body, "\t\tportal_check = ");
		ncfg_render_quote(body, wifi->portal_check);
		ncfg_buf_add_char(body, '\n');
	}
	if (wifi->regdom) {
		ncfg_buf_add_text(body, "\t\tregdom = ");
		ncfg_render_quote(body, wifi->regdom);
		ncfg_buf_add_char(body, '\n');
	}
	if (wifi->powersave != NCFG_POWERSAVE_DEFAULT) {
		ncfg_buf_addf(body, "\t\tpowersave = \"%s\"\n",
		    ncfg_render_word_or_gap(ncfg_render_word(powersave_words,
		        NCFG_COUNT_OF(powersave_words), wifi->powersave)));
	}
	if (wifi->mac_policy != NCFG_MAC_POLICY_PERMANENT) {
		ncfg_buf_addf(body, "\t\tmac_policy = \"%s\"\n",
		    ncfg_render_word_or_gap(ncfg_render_word(mac_policy_words,
		        NCFG_COUNT_OF(mac_policy_words), wifi->mac_policy)));
	}
	if (wifi->scan_randomization) {
		ncfg_buf_add_text(body, "\t\tscan_randomization = true\n");
	}
	ncfg_buf_add_text(body, "\t}\n");
}

/* A toggle's three spellings, in `ncfg_toggle_t`'s order: UNMANAGED, ON, OFF.
 * Read from `document.h`, not carried over -- the lesson the wifi backend table
 * paid for. */
static const char *const toggle_words[] = { "unmanaged", "on", "off" };

/* One toggle, written only where it is not `unmanaged` -- which is the default
 * and means netcfgd leaves the driver's own answer alone. `on` and `off` are
 * both written, because the difference between `off` and not-mentioned is the
 * whole point of a three-valued toggle. */
static void render_toggle(ncfg_buf_t *body, const char *key, int value)
{
	if (value == NCFG_TOGGLE_UNMANAGED) {
		return;
	}
	ncfg_buf_addf(body, "\t\t%s = \"%s\"\n", key,
	    ncfg_render_word_or_gap(ncfg_render_word(toggle_words,
	        NCFG_COUNT_OF(toggle_words), value)));
}

/*
 * The `ethtool` block: what the driver is told about the link itself.
 *
 * **Refused wholesale until now**, so a machine with any link setting could not
 * save a profile -- and these are settings somebody chose against a specific
 * NIC, which makes them the least guessable thing in a document.
 *
 * `unmanaged` is a toggle's default and means netcfgd leaves the driver's own
 * answer alone, so it is omitted; `on` and `off` are both written, because the
 * difference between "off" and "not mentioned" is the whole point of a three-
 * valued toggle (0023's shape, and the same argument `dns { }` turns on).
 */
static void render_ethtool(const ncfg_link_settings_t *settings, ncfg_buf_t *body)
{
	ncfg_buf_add_text(body, "\tethtool {\n");
	/* Named one at a time rather than walked by offset: the pointer arithmetic
	 * a table would need is the kind of thing that goes wrong silently in a
	 * renderer, and six lines are cheaper than being clever here. */
	render_toggle(body, "autoneg", settings->autoneg);
	render_toggle(body, "gro", settings->gro);
	render_toggle(body, "gso", settings->gso);
	render_toggle(body, "tso", settings->tso);
	render_toggle(body, "rx_checksum", settings->rx_checksum);
	render_toggle(body, "tx_checksum", settings->tx_checksum);
	if (settings->speed.has) {
		ncfg_buf_addf(body, "\t\tspeed = %lld\n", (long long)settings->speed.value);
	}
	if (settings->duplex) {
		ncfg_buf_add_text(body, "\t\tduplex = ");
		ncfg_render_quote(body, settings->duplex);
		ncfg_buf_add_char(body, '\n');
	}
	if (settings->wol) {
		ncfg_buf_add_text(body, "\t\twol = ");
		ncfg_render_quote(body, settings->wol);
		ncfg_buf_add_char(body, '\n');
	}
	if (settings->rx_ring.has) {
		ncfg_buf_addf(body, "\t\trx_ring = %lld\n", (long long)settings->rx_ring.value);
	}
	if (settings->tx_ring.has) {
		ncfg_buf_addf(body, "\t\ttx_ring = %lld\n", (long long)settings->tx_ring.value);
	}
	ncfg_buf_add_text(body, "\t}\n");
}

/*
 * A rate, in the suffixed form the parser reads back.
 *
 * The largest suffix that divides exactly, so `100000000` comes back as
 * `100mbit` rather than `100000kbit`. A rate that divides by none is written in
 * bits, which the parser also takes.
 */
static void render_rate(ncfg_buf_t *body, int64_t bits)
{
	static const struct {
		const char *suffix;
		int64_t     multiplier;
	} units[] = {
		{ "gbit", 1000000000 },
		{ "mbit", 1000000 },
		{ "kbit", 1000 },
	};
	size_t i;

	for (i = 0; i < NCFG_COUNT_OF(units); i++) {
		if (bits % units[i].multiplier == 0) {
			ncfg_buf_addf(body, "\"%lld%s\"", (long long)(bits / units[i].multiplier),
			    units[i].suffix);
			return;
		}
	}
	ncfg_buf_addf(body, "\"%lldbit\"", (long long)bits);
}

/* ------------------------------------------------------------------------ *
 * Undoing the ingress shaper
 * ------------------------------------------------------------------------ */

/*
 * `lower.c` turns `qdisc { ingress_bandwidth = ... }` on a device into two
 * things: an `ingress_redirect` naming `ifb-<device>`, and a synthesised `ifb`
 * device whose own cake qdisc carries the rate and meters arriving traffic.
 *
 * Both halves were refused, so **a machine with ingress shaping could not save
 * a profile** -- three refusals for one setting, which is how it was found. The
 * comment at the refusal said what a snapshot would have to write back "is the
 * `ingress_bandwidth` it came from, which the document no longer holds by the
 * time this sees it". That was wrong: the document holds it, on the `ifb`.
 *
 * Computed from the document on demand rather than collected into a side
 * table. There are a handful of devices, the walk is cheap, and a parallel
 * structure would be a second thing to keep in step with the document -- which
 * is the fault this file has already paid for twice in word tables.
 */

/* The name this build would give the `ifb` for `shaped`, without building it:
 * a buffer here would need `lower.c`'s private `IFNAMSIZ_MAX`, and a second
 * copy of a constant is a second thing to be wrong. */
static int our_ifb_name(const char *name, const char *shaped)
{
	return name && shaped && strncmp(name, "ifb-", 4u) == 0 &&
	    strcmp(name + 4, shaped) == 0;
}

/*
 * Whether this `ifb` is one `lower.c` would have made, and nothing more.
 *
 * `expand_ingress_shapers` sets four things -- the kind, and a cake qdisc with
 * the rate and `ingress` -- and leaves the rest at `push_device`'s defaults.
 * Anything else being set is an operator's own `device ifb-eth0 { }`, and
 * inverting past it would discard their field in silence, which is what the
 * unrenderable list exists to prevent.
 *
 * **The enumeration is what rots, so the rot is made loud.** A field added to
 * `ncfg_device_t` is one this stops looking at, and the symptom would be a
 * profile that quietly dropped it. The assertion below fires when the struct
 * grows and sends whoever grew it here.
 *
 * **Every clause here is defence rather than a gap, and that was measured** --
 * so do not go writing a case per field, which is the obvious next step and is
 * wasted. No document the renderer is asked to write can carry an `ifb` that
 * is not the shape above: `ifb` is not a kind the configuration language has,
 * an operator's own `device ifb-e0 { }` beside a shaped interface is refused
 * by `lower.c` as a duplicate, and every document reaching the renderer comes
 * from the lowering -- directly, or through the JSON round trip
 * `host/profile_save.c` does, which filters globals and leaves devices alone.
 * The clauses stay because the assertion above cannot see a field that is
 * merely unexamined, and because the cost of being wrong here is silence.
 */
#define NCFG_RENDER_DEVICE_SIZE 592u /* measured, x86-64, 2026-10-09 */
_Static_assert(sizeof(ncfg_device_t) == NCFG_RENDER_DEVICE_SIZE,
    "ncfg_device_t changed shape: bare_ifb() enumerates its fields, so re-read it");

static int bare_ifb(const ncfg_device_t *device, int64_t *rate)
{
	/*
	 * **The direct form of the question the rest of this asks indirectly.**
	 * `declared` arrived for 10.418 and the assertion above sent whoever added
	 * it here, which is what it is for. It belongs at the front: every clause
	 * below is a field that, if set, means an operator wrote this block, and
	 * this says so outright.
	 *
	 * Unreachable today -- `lower.c` refuses an operator's `device ifb-e0 { }`
	 * beside a shaped interface as a duplicate entry, so no written device can
	 * carry this kind. Kept because it fails in the safe direction: a declared
	 * `ifb` stops being undone and is refused by name instead, which is this
	 * module's rule rather than a silent drop.
	 */
	if (device->declared) {
		return 0;
	}
	if (device->kind.kind != NCFG_KIND_IFB || !device->qdisc) {
		return 0;
	}
	/* The qdisc the expansion makes. A different one is the operator's, even
	 * on a device of the right name. */
	if (device->qdisc->kind != NCFG_QDISC_CAKE || !device->qdisc->ingress ||
	    !device->qdisc->bandwidth_bits.has || device->qdisc->ingress_bandwidth_bits.has) {
		return 0;
	}
	/* What it leaves alone, and what must still be alone. */
	if (!device->managed || device->on_unmanage != NCFG_ON_UNMANAGE_LEAVE ||
	    device->match || device->wifi || device->modem || device->mtu.has ||
	    device->mac || device->link_settings || device->master ||
	    device->ingress_redirect || device->bridge_vlan_count > 0) {
		return 0;
	}
	*rate = device->qdisc->bandwidth_bits.value;
	return 1;
}

/* The rate `shaped`'s redirect can be undone to, or 0 where it cannot. */
static int64_t shaper_rate(const ncfg_document_t *document, const ncfg_device_t *shaped)
{
	size_t i;

	if (!document || !shaped->ingress_redirect || !shaped->qdisc) {
		return 0;
	}
	for (i = 0; i < document->device_count; i++) {
		const ncfg_device_t *candidate = &document->devices[i];
		int64_t              rate = 0;

		if (!candidate->name || strcmp(candidate->name, shaped->ingress_redirect) != 0) {
			continue;
		}
		/* The name as well as the shape: a redirect onto somebody else's
		 * `ifb` is theirs, whatever that device looks like. */
		if (our_ifb_name(candidate->name, shaped->name) && bare_ifb(candidate, &rate)) {
			return rate;
		}
		return 0;
	}
	return 0;
}

/* Whether this device is one some other device's shaping synthesised, and so
 * is not written at all -- the half that keeps a derived device out of a
 * profile. */
static int derived_ifb(const ncfg_document_t *document, const ncfg_device_t *device)
{
	size_t i;

	if (!document || device->kind.kind != NCFG_KIND_IFB) {
		return 0;
	}
	for (i = 0; i < document->device_count; i++) {
		const ncfg_device_t *shaped = &document->devices[i];

		if (shaped->ingress_redirect && device->name &&
		    strcmp(shaped->ingress_redirect, device->name) == 0 &&
		    shaper_rate(document, shaped) != 0) {
			return 1;
		}
	}
	return 0;
}

/*
 * A device's root qdisc, in whichever of its two forms the document needs.
 *
 * **Refused wholesale until now.** `qdisc = "fq_codel"` is the shorthand for a
 * scheduler carrying no rate, and the block form is for one that does -- so a
 * policy with no bandwidth at all comes back as the short form, which is what
 * a person would have written.
 *
 * The kind's spelling comes from `ncfg_qdisc_kind_name`, which the lowerer owns
 * and `ncfg_qdisc_kind` inverts: a kind rendered under the wrong name is a
 * document that compiles and describes a different scheduler, so the closed set
 * has one home rather than a copy here.
 *
 * **The ingress half stays refused**, as it is in the Rust. A policy metering
 * arriving traffic is served by building an `ifb` and redirecting to it, and
 * the `ifb` is derived rather than written -- so rendering it back would mean
 * recovering an `ingress_bandwidth` the document no longer holds, which is the
 * same reason `ingress_redirect` is refused a few lines below.
 */
static void render_qdisc(const ncfg_qdisc_policy_t *qdisc, const char *name, int64_t ingress,
    ncfg_buf_t *body, ncfg_unrenderable_t *missing)
{
	if (qdisc->ingress) {
		ncfg_render_refuse(missing, "device", name, "a qdisc metering arriving traffic");
	}
	/* `ingress` is the rate recovered from this device's `ifb`, which
	 * `expand_ingress_shapers` moved off the field below. Nonzero means the
	 * block form is needed whatever the rest of the policy says. */
	if (!qdisc->bandwidth_bits.has && !qdisc->ingress_bandwidth_bits.has && ingress == 0) {
		ncfg_buf_addf(body, "\tqdisc = \"%s\"\n",
		    ncfg_render_word_or_gap(ncfg_qdisc_kind_name(qdisc->kind)));
		return;
	}
	ncfg_buf_add_text(body, "\tqdisc {\n");
	ncfg_buf_addf(body, "\t\tkind = \"%s\"\n",
	    ncfg_render_word_or_gap(ncfg_qdisc_kind_name(qdisc->kind)));
	if (qdisc->bandwidth_bits.has) {
		ncfg_buf_add_text(body, "\t\tbandwidth = ");
		render_rate(body, qdisc->bandwidth_bits.value);
		ncfg_buf_add_char(body, '\n');
	}
	/* The field, or the rate recovered from the `ifb` the expansion moved it
	 * to. Never both: the expansion clears the field as it moves it, and
	 * `bare_ifb` refuses an `ifb` whose own field is set. */
	if (qdisc->ingress_bandwidth_bits.has || ingress != 0) {
		ncfg_buf_add_text(body, "\t\tingress_bandwidth = ");
		render_rate(body, qdisc->ingress_bandwidth_bits.has
		    ? qdisc->ingress_bandwidth_bits.value : ingress);
		ncfg_buf_add_char(body, '\n');
	}
	ncfg_buf_add_text(body, "\t}\n");
}

/* ------------------------------------------------------------------------ *
 * The device block
 * ------------------------------------------------------------------------ */

/*
 * A port's VLAN membership, as the phrases the parser reads back.
 *
 * One phrase per VLAN rather than the ranges the parser also accepts: a range
 * is expanded on the way in, so the individual ids are all this has to write.
 *
 * **A function of its own because this is the field that was being dropped in
 * silence.** It was neither rendered nor refused, so `ncfg profile save` wrote
 * a switch port's configuration back without its VLANs and reported success --
 * and no round trip caught it because none had ever carried a `vlans` key,
 * which is a real gate over an absent case. The consequence is not cosmetic: a
 * port whose PVID is lost takes untagged ingress to a different VLAN than it
 * did before, and the kernel accepts a second PVID and moves it without
 * reporting anything.
 */
static void render_bridge_vlans(const ncfg_bridge_vlan_t *vlans, size_t count, ncfg_buf_t *body)
{
	ncfg_render_list_t phrases;
	size_t             i;

	ncfg_render_list_init(&phrases);
	for (i = 0; i < count; i++) {
		char phrase[48];

		/* `tagged` is the absence of `untagged` and the parser's default, so
		 * writing it would be noise that reads as a setting. */
		snprintf(phrase, sizeof(phrase), "%lld%s%s", (long long)vlans[i].vid,
		    vlans[i].pvid ? " pvid" : "", vlans[i].untagged ? " untagged" : "");
		ncfg_render_quote(ncfg_render_list_next(&phrases), phrase);
	}
	ncfg_render_list_emit(body, "\t", "vlans", &phrases, 0);
	ncfg_render_list_free(&phrases);
}

/*
 * Cellular policy (0150).
 *
 * Rendered from the day the field arrived rather than joining the list of
 * things a profile silently loses: a cellular machine is the one most likely
 * to want a profile at all, since the APN differs per SIM and the SIM order is
 * the whole point of switching between them.
 */
static void render_modem(const ncfg_modem_policy_t *modem, ncfg_buf_t *body)
{
	ncfg_render_list_t sources;
	size_t             i;

	ncfg_buf_add_text(body, "\tmodem {\n");
	ncfg_render_list_init(&sources);
	for (i = 0; i < modem->sim_count; i++) {
		ncfg_render_quote(ncfg_render_list_next(&sources), modem->sim[i]);
	}
	ncfg_render_list_emit(body, "\t\t", "sim", &sources, 0);
	ncfg_render_list_free(&sources);
	if (modem->apn) {
		ncfg_buf_add_text(body, "\t\tapn = ");
		ncfg_render_quote(body, modem->apn);
		ncfg_buf_add_char(body, '\n');
	}
	ncfg_buf_add_text(body, "\t}\n");
}

/*
 * Whether this device would be written at all.
 *
 * Exposed because a suite needs to ask it, and must not answer it for itself:
 * a predicate spelling out "at every default" elsewhere would enumerate
 * `ncfg_device_t` and go stale the next time it grew, which is the same
 * argument `bare_ifb` carries an assertion for. This renders and reports
 * whether anything came out, so it cannot disagree with the renderer.
 *
 * A caller wanting this is usually asking whether a document can round trip:
 * a device the operator declared and left at every default is written nowhere,
 * so such a document does not survive. 10.418 has why writing it instead broke
 * `ncfg profile save`.
 */
int ncfg_render_device_writes_nothing(const ncfg_device_t *device,
    const ncfg_document_t *document)
{
	ncfg_buf_t          text;
	ncfg_unrenderable_t missing;
	int                 silent;

	ncfg_buf_init(&text, 0);
	ncfg_unrenderable_init(&missing);
	ncfg_render_device(device, NULL, document, &text, &missing);
	silent = ncfg_buf_text(&text)[0] == '\0';
	ncfg_unrenderable_free(&missing);
	ncfg_buf_free(&text);
	return silent;
}

void ncfg_render_device(const ncfg_device_t *device, const ncfg_overrides_t *overrides,
    const ncfg_document_t *document, ncfg_buf_t *text, ncfg_unrenderable_t *missing)
{
	const char *name = device->name;
	ncfg_buf_t  body;
	int64_t     ingress;

	/* **A device this build synthesised is written nowhere.** It exists so an
	 * egress qdisc can shape what arrived; putting it in a profile would make
	 * the next compile create a second one beside it, and the setting it was
	 * made from goes out on the device that asked for it instead. */
	if (derived_ifb(document, device)) {
		return;
	}
	ingress = shaper_rate(document, device);

	/* `match` is one of the six the model has and the configuration language
	 * cannot reach -- `lower_device` never assigns it -- so this refusal
	 * cannot fire from a compiled document. It is kept for the reason the DNS
	 * ones are. */
	if (device->match) {
		ncfg_render_refuse(missing, "device", name, "a match block");
	}

	ncfg_buf_init(&body, 0);
	if (!device->managed) {
		ncfg_buf_add_text(&body, "\tmanaged = false\n");
	}
	render_kind(&device->kind, name, &body, missing);
	if (device->master) {
		ncfg_buf_add_text(&body, "\tmaster = ");
		ncfg_render_quote(&body, device->master);
		ncfg_buf_add_char(&body, '\n');
	}
	render_bridge_vlans(device->bridge_vlans, device->bridge_vlan_count, &body);
	/*
	 * **It is still not a config key, and it is no longer refused.** The
	 * comment here used to say the `ingress_bandwidth` it came from "is not
	 * held by the document by the time this sees it", and that was wrong: it
	 * is on the `ifb`, which is what `shaper_rate` reads. Writing the redirect
	 * itself would still be the bug it described -- the next compile would
	 * synthesise a second `ifb` on top of the first -- so what goes out is the
	 * setting, not the derivation.
	 *
	 * Refused only where the pair is not the shape this build makes, and then
	 * by name: a redirect onto somebody else's device, or onto an `ifb`
	 * carrying a field of their own, is theirs to keep rather than this
	 * function's to unpick.
	 */
	if (device->ingress_redirect && shaper_rate(document, device) == 0) {
		ncfg_render_refuse(missing, "device", name,
		    "an ingress redirect to `%s`, which is not a device this build would have "
		    "made for it", device->ingress_redirect);
	}
	/* Settings of the adapter, which moved here from `interface` with 0155
	 * pass 1a. Rendered from the day they arrived rather than joining the list
	 * of things a profile silently loses. */
	if (device->mtu.has) {
		ncfg_buf_addf(&body, "\tmtu = %lld\n", (long long)device->mtu.value);
	}
	if (device->mac) {
		ncfg_buf_add_text(&body, "\tmac = ");
		ncfg_render_quote(&body, device->mac);
		ncfg_buf_add_char(&body, '\n');
	}
	/*
	 * **Was dropped in silence, and this is the expensive one to lose.**
	 * `clear` exists because walking away from a device otherwise strands
	 * credentials -- a WireGuard key stays loaded in the kernel, a supplicant
	 * keeps its passphrases, a running hostapd keeps its generated
	 * configuration. A profile that lost it would put the machine back on
	 * `leave`, the default and the opposite intent, with nothing said.
	 *
	 * It is written *before* the emptiness check below, and that ordering is
	 * the other half of the same defect: the early return used to run first,
	 * so a device whose only setting was `on_unmanage` vanished from the
	 * profile entirely rather than losing one line.
	 */
	if (device->on_unmanage != NCFG_ON_UNMANAGE_LEAVE) {
		ncfg_buf_add_text(&body, "\ton_unmanage = \"clear\"\n");
	}
	/* Before `modem` for no reason beyond reading order: a radio's policy and a
	 * modem's are the two device-level backends, and a device has one or the
	 * other. */
	render_wifi_device(device->wifi, &body);
	if (device->link_settings) {
		render_ethtool(device->link_settings, &body);
	}
	if (device->qdisc) {
		render_qdisc(device->qdisc, name, ingress, &body, missing);
	}
	if (device->modem) {
		render_modem(device->modem, &body);
	}

	/*
	 * A device with nothing to say is not written -- **unless somebody wrote
	 * it**, and the two were indistinguishable until `declared` existed.
	 *
	 * The lowering invents a device for every interface, so skipping the empty
	 * ones is what stops a profile saying `override device eth0 { }` for a
	 * block the base config never had, which does not compile. That is 10.418,
	 * and `master` once removed this skip and broke `ncfg profile save` on
	 * `interface eth0 { config = "dhcp" }`.
	 *
	 * It also lost a block an operator had written. `device wlan0 { }` beside
	 * an `access_point` naming it has nothing else to recreate its entry, so
	 * the save refused: the profile did not reproduce the machine. The same
	 * case with an `interface wlan0` beside it passed, and passed for the
	 * wrong reason -- rendering the interface makes the recompile invent the
	 * entry again, so the documents matched by coincidence.
	 *
	 * `declared` separates them, and nothing else can: an invented all-default
	 * device is byte-identical to a written empty one.
	 */
	if (ncfg_buf_text(&body)[0] != '\0' || device->declared) {
		ncfg_render_opening(text, "device", name, overrides);
		ncfg_render_label(text, name);
		ncfg_buf_addf(text, " {\n%s}\n", ncfg_buf_text(&body));
	}
	ncfg_buf_free(&body);
}

/* ------------------------------------------------------------------------ *
 * Bluetooth and linksets
 * ------------------------------------------------------------------------ */

/*
 * One `bluetooth` block (0149).
 *
 * **Refused wholesale for a while**, which meant `ncfg profile save` could not
 * save any machine that had one -- and a machine with a pair of headphones
 * written down is exactly a laptop, which is what profiles are for. Four
 * fields and a closed set of five profiles, so the refusal was costing more
 * than the rendering does.
 *
 * The profile spellings are BlueZ's and hyphenated, which is the kind of
 * detail a renderer gets subtly wrong -- so the test walks all five rather
 * than sampling one. `autoconnect` defaults to true, like a network's, so only
 * `false` is written: a block that restated every default would be one nobody
 * can read for what is unusual.
 */
void ncfg_render_bluetooth(const ncfg_bluetooth_device_t *device,
    const ncfg_overrides_t *overrides, ncfg_buf_t *text)
{
	ncfg_render_opening(text, "bluetooth", device->id, overrides);
	ncfg_render_quote(text, device->id);
	ncfg_buf_add_text(text, " {\n\taddress = ");
	ncfg_render_quote(text, device->address);
	ncfg_buf_addf(text, "\n\tprofile = \"%s\"\n", ncfg_render_word_or_gap(
	    ncfg_bluetooth_profile_name((ncfg_bluetooth_profile_t)device->profile)));
	if (!device->autoconnect) {
		ncfg_buf_add_text(text, "\tautoconnect = false\n");
	}
	ncfg_buf_add_text(text, "}\n");
}

/*
 * A `linkset`, which is a name and a ranked list.
 *
 * **The list is written in its own order**, not sorted and not folded to a
 * scalar when there is one member: the order is the ranking, and a snapshot
 * that reordered it would describe a machine that fails over the other way
 * round, with nothing downstream able to tell.
 */
void ncfg_render_linkset(const ncfg_linkset_t *set, const ncfg_overrides_t *overrides,
    ncfg_buf_t *text)
{
	ncfg_render_list_t members;
	size_t             i;

	ncfg_render_opening(text, "linkset", set->name, overrides);
	ncfg_render_quote(text, set->name);
	ncfg_buf_add_text(text, " {\n");
	ncfg_render_list_init(&members);
	for (i = 0; i < set->member_count; i++) {
		ncfg_render_quote(ncfg_render_list_next(&members), set->members[i]);
	}
	ncfg_buf_addf(text, "\tmembers = [%s]\n}\n", ncfg_buf_text(&members.joined));
	ncfg_render_list_free(&members);
}
