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
/* **In the enum's order, which is not the Rust enum's.** `ncfg_wifi_backend_t`
 * is AUTO, IWD, WPA_SUPPLICANT; the Rust one is Auto, WpaSupplicant, Iwd. A
 * table written from the other language's order renders `wpa_supplicant` as
 * `iwd` and vice versa, which is a configuration this build refuses at use
 * reported as one it serves. Read from `document.h` rather than carried over. */
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
static void render_qdisc(const ncfg_qdisc_policy_t *qdisc, const char *name, ncfg_buf_t *body,
    ncfg_unrenderable_t *missing)
{
	if (qdisc->ingress) {
		ncfg_render_refuse(missing, "device", name, "a qdisc metering arriving traffic");
	}
	if (!qdisc->bandwidth_bits.has && !qdisc->ingress_bandwidth_bits.has) {
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
	if (qdisc->ingress_bandwidth_bits.has) {
		ncfg_buf_add_text(body, "\t\tingress_bandwidth = ");
		render_rate(body, qdisc->ingress_bandwidth_bits.value);
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
	/* Before `modem` for no reason beyond reading order: a radio's policy and a
	 * modem's are the two device-level backends, and a device has one or the
	 * other. */
	render_wifi_device(device->wifi, &body);
	if (device->link_settings) {
		render_ethtool(device->link_settings, &body);
	}
	if (device->qdisc) {
		render_qdisc(device->qdisc, name, &body, missing);
	}
	if (device->modem) {
		render_modem(device->modem, &body);
	}

	/* A device with nothing to say is not written at all, which is right --
	 * and see the paragraph above for what has to be written before this runs. */
	if (ncfg_buf_text(&body)[0] != '\0') {
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
