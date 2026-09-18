/*
 * render_device.c -- devices, link kinds, bluetooth and linksets.
 *
 * A `device` is what netcfgd creates and what it is a port of, plus the
 * settings of the hardware itself. Decision 0155 moved both halves here from
 * `interface`, and a field that moves type and is not taught to the renderer
 * is silently dropped from every saved profile -- which is the failure that
 * move most easily creates, and which it did create twice.
 */
#include "render_private.h"

#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/value.h"

#include <stdio.h>

/*
 * **The configuration language's word for a link kind, which is not always the
 * document's.** `ncfg_interface_kind_name` answers with the document's,
 * because that is what the JSON carries: it says `wire_guard` and `open_vpn`,
 * and an operator writes `wireguard` and `openvpn`.
 *
 * Only the refusal message uses it, and that is exactly why it has to be
 * right: the refusal exists so an operator knows which block to write by hand,
 * and naming a word the language does not have sends them to write a block
 * that cannot compile. This project has shipped that pair of words the wrong
 * way round twice.
 */
static const char *const language_kind_words[] = { "physical", "bridge", "bond", "vlan", "vxlan",
	"wireguard", "pppoe", "openvpn", "dummy", "veth", "vrf", "macvlan", "tunnel", "tun",
	"ifb" };

/* `iproute2`'s spellings, the same on both sides, from
 * `netcfgd-model/src/interface.rs`. `802.3ad` is what every piece of bonding
 * documentation calls LACP, and a tidier word would be a bond the kernel
 * refuses. */
static const char *const bond_mode_words[] = { "balance-rr", "active-backup", "balance-xor",
	"broadcast", "802.3ad", "balance-tlb", "balance-alb" };
static const char *const vlan_protocol_words[] = { "dot1q", "dot1ad" };
static const char *const macvlan_mode_words[] = { "private", "vepa", "bridge", "passthru" };

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
 * What kind of link this is, as its own block.
 *
 * The topology kinds are here and `pppoe` with them. What is refused is
 * `wireguard`, whose peer list and private key are a bigger question than more
 * keys; `openvpn`, which names an operator's file; and `tunnel`, `tun` and
 * `ifb`. The split is by what a block *carries* rather than by effort -- the
 * kinds that render say who they are made of and nothing secret.
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
	default:
		/* The scope is `device` and not `interface`, which is where 0155 pass
		 * 1b moved the kind to -- a refusal naming the wrong block sends the
		 * operator to write the key where the parser no longer reads it. */
		ncfg_render_refuse(missing, "device", name, "kind %s",
		    ncfg_render_word_or_gap(ncfg_render_word(language_kind_words,
		        NCFG_COUNT_OF(language_kind_words), kind->kind)));
		break;
	}
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

void ncfg_render_device(const ncfg_device_t *device, const ncfg_overrides_t *overrides,
    ncfg_buf_t *text, ncfg_unrenderable_t *missing)
{
	const char *name = device->name;
	ncfg_buf_t  body;

	/* `match` is one of the six the model has and the configuration language
	 * cannot reach -- `lower_device` never assigns it -- so this refusal
	 * cannot fire from a compiled document. It is kept for the reason the DNS
	 * ones are. */
	if (device->match) {
		ncfg_render_refuse(missing, "device", name, "a match block");
	}
	if (device->wifi) {
		ncfg_render_refuse(missing, "device", name, "a wifi policy");
	}
	if (device->link_settings) {
		ncfg_render_refuse(missing, "device", name, "ethtool settings");
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
	if (device->qdisc) {
		ncfg_render_refuse(missing, "device", name, "qdisc");
	}
	if (device->ingress_redirect) {
		/* **Refused, and it must stay refused**, which is different from the
		 * rest of the list. It is not a config key: the compiler synthesises
		 * it and the `ifb` it points at from `ingress_bandwidth`, so rendering
		 * it would make the next compile synthesise a second one on top of the
		 * first. What a snapshot would have to write back is the
		 * `ingress_bandwidth` it came from, which the document no longer holds
		 * by the time this sees it. A derived field is not a missing feature,
		 * and treating it as one would be the bug. */
		ncfg_render_refuse(missing, "device", name, "ingress_redirect");
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
	if (device->modem) {
		render_modem(device->modem, &body);
	}

	/* A device with nothing to say is not written at all, which is right --
	 * and see the paragraph above for what has to be written before this runs. */
	if (ncfg_buf_text(&body)[0] != '\0') {
		ncfg_render_opening(text, "device", name, overrides);
		ncfg_buf_addf(text, "%s {\n%s}\n", name ? name : "", ncfg_buf_text(&body));
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
