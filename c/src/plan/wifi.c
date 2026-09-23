/*
 * wifi.c -- the networks a supplicant is given, the station lists an access
 * point enforces, and the radio settings this build stores and does not act
 * on.
 *
 * WHAT A RUNNING SUPPLICANT IS NOT
 *   **Running is not the same as holding what the document says.** The Rust
 *   returned from its backend pass as soon as a supplicant was up, and the
 *   call that hands the networks over had one caller -- the `backend.start`
 *   arm -- so a supplicant that was already running was never given anything
 *   again. Measured there: changing a passphrase, pinning a `bssid`, adding a
 *   network and deleting one each planned `nothing to do`, and the supplicant
 *   kept the original credentials indefinitely. 0015 says netcfgd's next
 *   reconcile removes a network the document does not contain; this is that
 *   reconcile.
 *
 *   The question is asked of the observation rather than of the document:
 *   `networks_match` is the answer the observer computed, and absent is not
 *   false -- not a supplicant, no record of what netcfgd handed over, or a
 *   network that names access points instead of an SSID all leave it
 *   unanswered, and an unanswered question is not a reason to re-send.
 *
 * WHY BOTH STATION LISTS, ALWAYS
 *   hostapd's `hostapd_check_acl` consults the accept list *first* and the
 *   deny list second, whatever `macaddr_acl` says -- that value decides only
 *   what happens to an address in neither. So a station left on the accept
 *   list overrides the deny list that is supposed to be refusing it, and
 *   leaving the unused list alone would be leaving the failure this feature
 *   exists to remove.
 *
 * AND WHY A POLICY THAT MOVED IS NOT CONVERGED
 *   `macaddr_acl` cannot be changed over hostapd's control socket, so a
 *   document that went from `deny` to `allow` needs the access point
 *   restarted. Converging the lists without that would enforce the new list
 *   under the old default -- every unlisted station accepted, reported as
 *   applied. **This sentence used to end "and this build plans no backend
 *   actions, so it says so and converges nothing"**, which `access_point.c`
 *   made untrue: the restart is planned, and the lists are left to the hostapd
 *   that comes back. What is still converged by nothing is the case below it,
 *   where netcfgd has no record of which policy the running access point was
 *   started with -- emptying a list without knowing which one hostapd reads
 *   either opens a network or closes it.
 *
 * THE TWO RADIO SETTINGS THAT REACH NOTHING, AND WHOSE GAP THEY ARE
 *   `regdom` and `powersave` on a `device`'s `wifi` block are planned by
 *   nothing: no pass reads either, and `wifi.set_regdom` is an op nothing
 *   constructs. They are parsed, kept in the document and rendered back by
 *   `ncfg profile save`, which is the shape 0061 exists to prevent. Said only
 *   where the document states them: a radio at its defaults is not asking for
 *   anything.
 *
 *   **This heading said THREE and named two**, which is 10.182's failure --
 *   a count that never matched the list beneath it. The third was
 *   `scan_randomization`, and it is the Rust's sentence rather than this
 *   port's: this build writes it as the supplicant's `preassoc_mac_addr`
 *   (`c/src/apply/wifi_ops.c:443` and
 *   `c/src/backend/supplicant/network.c:749`), so naming it here would have
 *   told an operator their setting was inert while netcfgd was applying it.
 *
 *   **And "no executor writes them" is the Rust's sentence too, and is false
 *   here.** `ncfg_service_set_regdom` (`c/src/apply/wifi_ops.c:712`) sends
 *   `SET country` to the supplicant and is tested; the Rust has no arm for
 *   `WifiSetRegdom` at all and refuses it as "not implemented in this build"
 *   (`crates/netcfgd-apply/src/kernel.rs:1919`). So this port is *ahead* on
 *   the half that was copied across as a shared gap, and what is missing on
 *   both sides is the producer. 0263 records it.
 */
#include "plan_internal.h"

#include "ncfg/base.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ------------------------------------------------------------------------ *
 * What this build holds and does not act on
 * ------------------------------------------------------------------------ */

/*
 * Say which radio settings are stored and acted on by nothing, and whose gap
 * that is.
 *
 * **The clause used to be fixed -- "nothing sets the regulatory domain or the
 * power-saving mode" -- and the first half was false.** hostapd's own
 * documentation calls `country_code` the way a regulatory domain is set, and
 * netcfgd writes that from an *access point's* `regdom`, so a plan could warn
 * that nothing sets the domain in the same breath as starting the thing that
 * sets it (0221). So the reason is gathered beside the name, and the sentence
 * says it about the settings that were actually written.
 *
 * **What was still wrong is the frame the reasons sit in.** "Not acted on by
 * this build ... when the code arrives" is 10.180's promise, and a radio's
 * `regdom` and a `powersave` are the case that helper was published for:
 * neither is read by any pass in either language. Settled against `crates/`
 * field by field rather than assumed --
 *
 *   * `regdom`: `WifiSetRegdom` is an `Op` variant with no constructor
 *     anywhere in `crates/`, which the Rust's own doc comment says of itself
 *     at `crates/netcfgd-plan/src/lib.rs:749`. The access point's regdom is a
 *     different field and does reach hostapd, which is what the reason below
 *     now says in the same breath rather than leaving an operator to find out.
 *   * `powersave`: outside the model and `lower.rs`, the only mention in
 *     `crates/` is the matching warning at
 *     `crates/netcfgd-plan/src/lib.rs:955`.
 *
 * So this is `warn_unbuilt`'s sentence, and the tail it supplies replaces the
 * one that was written out here -- which is the point of having the sentence
 * in one place: there is no second copy to go stale.
 */
static void warn_device_policy(ncfg_builder_t *builder, const ncfg_device_t *device)
{
	const ncfg_wifi_device_policy_t *wifi = device->wifi;
	const char                      *stated[2];
	const char                      *because[2];
	size_t                           count = 0;
	ncfg_buf_t                       names;
	ncfg_buf_t                       reasons;
	ncfg_buf_t                       block;
	size_t                           i;

	if (wifi->regdom) {
		stated[count] = "`regdom`";
		because[count] = "a radio's `regdom` is read by no pass, and an access "
		    "point's is the only one netcfgd carries -- as hostapd's `country_code`";
		count++;
	}
	if (wifi->powersave != NCFG_POWERSAVE_DEFAULT) {
		stated[count] = "`powersave`";
		because[count] = "nothing sets the power-saving mode";
		count++;
	}
	/* `scan_randomization` is deliberately not here: it sets the supplicant's
	 * `preassoc_mac_addr`, which is the address in probe requests (0220). */
	if (count == 0u) {
		return;
	}
	ncfg_buf_init(&names, 0);
	ncfg_buf_init(&reasons, 0);
	for (i = 0; i < count; i++) {
		ncfg_buf_addf(&names, "%s%s", i ? " and " : "", stated[i]);
		ncfg_buf_addf(&reasons, "%s%s", i ? "; and " : "", because[i]);
	}
	/* Both fields, the longest device name a kernel takes and `warn_unbuilt`'s
	 * tail come to 442 of `NCFG_ERROR_MAX`, and `plan_wifi_test.c` asserts the
	 * last words rather than a fragment near the front -- a check on the
	 * subject of a sentence this long cannot fail, because the subject is the
	 * half a cut keeps. */
	ncfg_buf_init(&block, 0);
	ncfg_buf_addf(&block, "%s on %s %s read and acted on by nothing: %s",
	    ncfg_buf_text(&names), device->name, count == 1u ? "is" : "are",
	    ncfg_buf_text(&reasons));
	ncfg_plan_warn_unbuilt(builder, device->name, ncfg_buf_text(&block));
	ncfg_buf_free(&block);
	ncfg_buf_free(&names);
	ncfg_buf_free(&reasons);
}

/*
 * A fixed `mac` on a radio whose `mac_policy` replaces it.
 *
 * **netcfgd does both, and the second one wins.** The configured address is
 * written to the link, and then the supplicant applies a randomised one when
 * it associates, over whatever the link is carrying -- so the fixed address
 * holds until the radio joins a network and not after. An operator who set it
 * for MAC-based admission gets admitted exactly once, before the first
 * association, and then stops being admitted for a reason nothing reports.
 *
 * `mac_policy = "permanent"` is what keeps a fixed address, and the sentence
 * says so rather than leaving the reader to work out which of the two to
 * remove.
 */
static void warn_mac_contradiction(ncfg_builder_t *builder)
{
	size_t i;

	for (i = 0; i < builder->desired->device_count; i++) {
		const ncfg_device_t *device = &builder->desired->devices[i];

		if (!device->mac || !device->wifi ||
		    device->wifi->mac_policy == NCFG_MAC_POLICY_PERMANENT) {
			continue;
		}
		ncfg_plan_warnf(builder->plan, device->name,
		    "%s sets `mac` to %s and a `mac_policy` of `%s`, which replaces it: the "
		    "supplicant applies a randomised address when it associates, over "
		    "whatever the link is carrying. netcfgd does both, so the configured "
		    "address holds until the radio joins a network and not after. If the "
		    "fixed address is for MAC-based admission, `mac_policy = \"permanent\"` "
		    "is what keeps it",
		    device->name, device->mac,
		    ncfg_mac_policy_name(device->wifi->mac_policy));
	}
}

/*
 * EAP that trusts whatever answers, in the two degrees it comes in.
 *
 * **`ca_cert` says who signed the server's certificate; `domain_suffix_match`
 * says who the certificate is for.** With neither, the supplicant believes any
 * server that replies, and the inner method hands it the credential. With only
 * the first, every certificate that issuer ever signed is accepted -- which is
 * fine for an organisation's own CA and nearly worthless for a public one, and
 * a commercial certificate on a RADIUS server is an ordinary arrangement.
 * Decision 0206.
 *
 * Two sentences rather than one with a clause, because the remedies differ:
 * the first case needs an issuer pinned at all, the second needs a name.
 *
 * **No interface is named.** A network is not an interface -- the same profile
 * can be handed to every radio on the machine -- so naming one would be a
 * guess dressed as a fact.
 */
static void warn_eap_without_ca(ncfg_builder_t *builder)
{
	size_t i;

	for (i = 0; i < builder->desired->network_count; i++) {
		const ncfg_wifi_network_t *network = &builder->desired->networks[i];
		const ncfg_eap_config_t *eap = &network->security.eap;

		if (network->security.kind != NCFG_SECURITY_EAP) {
			continue;
		}
		if (eap->ca_cert.has && eap->domain_suffix_match) {
			continue;
		}
		if (eap->ca_cert.has) {
			ncfg_plan_warnf(builder->plan, NULL,
			    "network `%s` pins a `ca_cert` and no `domain_suffix_match`, so it "
			    "accepts any server certificate that issuer signed. Where the "
			    "issuer is a public CA that is anybody who can buy one: they raise "
			    "an access point with this name, are believed, and take what the "
			    "inner method sends. Set `domain_suffix_match` to the server's "
			    "name, such as `radius.example.com`", network->id);
			continue;
		}
		ncfg_plan_warnf(builder->plan, NULL,
		    "network `%s` authenticates with EAP and pins no `ca_cert`, so it will "
		    "trust any server that answers -- which is how the credential is taken. "
		    "Set `ca_cert` to the issuer's certificate, or `ncfg wifi add ... "
		    "--ca-cert PATH`, and `domain_suffix_match` to the server's name",
		    network->id);
	}
}

/*
 * A `phase2` that pins no inner method, wherever 802.1X is configured.
 *
 * **Warned rather than refused, and the asymmetry is the argument.** The value
 * is inert at the supplicant, not invalid: a network carrying one works today,
 * and the protection it looks like it adds was never there. Refusing it at
 * compile time would take the wifi off every machine carrying one -- netcfgd
 * runs with no document when one will not compile -- to fix something that was
 * already absent. That is 0189: a check that stops a network working teaches
 * an operator to use something else.
 *
 * **netcfgd's own example told them to write it.** `phase2 = "mschapv2"` is
 * exactly the inert form, so the configurations carrying one were written by
 * following the documentation.
 *
 * Both places 802.1X can live, because the model has two: a wifi network's EAP
 * security, and a wired interface's `dot1x` (0008).
 */
static void warn_phase2_that_pins_nothing(ncfg_builder_t *builder)
{
	static const char *const sentence =
	    "`phase2 = \"%s\"` on %s pins no inner method: wpa_supplicant reads this as "
	    "`key=value` and ignores anything else, so the server proposes the inner "
	    "method and the supplicant accepts it -- including one that sends the "
	    "password in clear inside the tunnel. Write `auth=MSCHAPV2`, or `autheap=` "
	    "where the inner method is itself EAP";
	size_t i;

	for (i = 0; i < builder->desired->network_count; i++) {
		const ncfg_wifi_network_t *network = &builder->desired->networks[i];
		char                    where[NCFG_ERROR_MAX];

		if (network->security.kind != NCFG_SECURITY_EAP ||
		    !network->security.eap.phase2 ||
		    !ncfg_phase2_pins_nothing(network->security.eap.phase2)) {
			continue;
		}
		(void)snprintf(where, sizeof(where), "network `%s`", network->id);
		ncfg_plan_warnf(builder->plan, NULL, sentence,
		    network->security.eap.phase2, where);
	}
	for (i = 0; i < builder->desired->interface_count; i++) {
		const ncfg_interface_t *interface = &builder->desired->interfaces[i];
		char                    where[NCFG_ERROR_MAX];

		if (!interface->dot1x || !interface->dot1x->phase2 ||
		    !ncfg_phase2_pins_nothing(interface->dot1x->phase2)) {
			continue;
		}
		(void)snprintf(where, sizeof(where), "`%s`", interface->name);
		ncfg_plan_warnf(builder->plan, interface->name, sentence,
		    interface->dot1x->phase2, where);
	}
}

/*
 * Say where a regulatory domain was written and will not arrive.
 *
 * **The language spells `regdom` twice and only one of them does anything.** A
 * radio's is stored and not acted on, and the warning above says so; an access
 * point's becomes hostapd's `country_code`. So the setting that looks like it
 * belongs to the radio is the inert one, and the one an operator adds almost
 * as an afterthought to an access point is the one that takes effect.
 *
 * Warned only where a *radio* names one, which is what keeps this quiet: an
 * access point with a `regdom` and a radio with none is the ordinary
 * arrangement and asks nothing, and an access point with neither is a machine
 * that has not been told about regulatory domains.
 *
 * Compared case-insensitively, because the compiler uppercases both and a
 * document can reach the planner without passing through it.
 */
static void warn_regdom(ncfg_builder_t *builder)
{
	size_t i;

	for (i = 0; i < builder->desired->access_point_count; i++) {
		const ncfg_access_point_t *point = &builder->desired->access_points[i];
		const ncfg_device_t       *device =
		    ncfg_plan_device(builder->desired, point->device);
		const char                *radio =
		    (device && device->wifi) ? device->wifi->regdom : NULL;

		if (!radio) {
			continue;
		}
		if (point->regdom && strcasecmp(point->regdom, radio) == 0) {
			continue;
		}
		if (point->regdom) {
			ncfg_plan_warnf(builder->plan, point->device,
			    "`%s` and the access point `%s` running on it name different "
			    "regulatory domains -- the radio says `%s` and the access point "
			    "says `%s` -- and the access point's is the one netcfgd writes, as "
			    "hostapd's `country_code`. The radio's is stored and not acted on, "
			    "so this machine gets `%s`",
			    point->device, point->id, radio, point->regdom, point->regdom);
			continue;
		}
		ncfg_plan_warnf(builder->plan, point->device,
		    "`%s` names `regdom = \"%s\"` and the access point `%s` running on it names "
		    "none, so nothing carries it to hostapd: a radio's `regdom` is stored and "
		    "not acted on, and an access point's is the only one that becomes a "
		    "`country_code`. Write `regdom = \"%s\"` in the access point as well",
		    point->device, radio, point->id, radio);
	}
}

/*
 * What a `network` block states that no pass applies, told apart by whose gap
 * it is.
 *
 * **One sentence used to cover five things and had the blame wrong for four of
 * them.** It said a network's addressing, routes, `dns` policy, hooks and
 * metric were "carried in the document and this build of the planner does not
 * act on them", which reads as a port that has not caught up yet. Settled
 * against `crates/` rather than assumed, one field at a time:
 *
 *   * **addressing, `routes` and a `dns` policy** are acted on by nothing in
 *     either language. Every `.addressing` the Rust's planner and executor
 *     read is an *interface*'s, and `netcfgd_model::dns::scopes` builds its
 *     scope list from the globals and the interfaces alone. The only readers
 *     on either side are the canonicaliser, which sorts and validates them,
 *     and the renderer `ncfg profile save` writes them back through.
 *   * **hooks** are run by nothing either, and the Rust says so itself:
 *     `warn_unfired_hooks` warns per network that "a hook on a network is not
 *     run by this build at any phase". This build collects a network's hooks
 *     into the list an executor verifies a script's hash against, so that a
 *     `hook.run` naming one could be carried out -- and no pass emits that op
 *     for a network, which is the same state one step further on.
 *   * **`metric` was the one real port gap of the five, and it is closed.**
 *     The Rust's planner applies `netcfgd_model::wifi::effective_metric` to
 *     the routes an interface declares and restarts a DHCP client that was
 *     started with the old one; both are here, as
 *     `ncfg_observed_effective_metric` -- which `address.c` fills a route's
 *     metric from and the daemon starts a client with -- and
 *     `ncfg_plan_metric_restart`. So it has no warning here any more, which is
 *     `build.c`'s rule rather than an omission.
 *
 * So the first four get `ncfg_plan_warn_unbuilt`'s sentence and the fifth does
 * not, which is what 10.180 published that helper for: "this port has not got
 * there yet" and "there is nothing to wait for" are the same sentence to a
 * reader and different facts, and only one of them is worth waiting on.
 *
 * **The old clause's tail was false as well.** "Only the set of network ids is
 * handed to a running supplicant" describes the op, which carries ids; what is
 * handed over is every network in the document, read from the document the
 * plan was built against -- and the metric among them, since
 * `ncfg_supplicant_add_network` writes it as `priority`.
 *
 * Said only where a network states the thing, which is `warn_device_policy`'s
 * rule one function up: a network that asks for none of this is not asking for
 * anything, and a sentence on every saved SSID is noise rather than news.
 */
static void warn_networks_held(ncfg_builder_t *builder)
{
	size_t i;

	for (i = 0; i < builder->desired->network_count; i++) {
		const ncfg_wifi_network_t *network = &builder->desired->networks[i];
		const char                *stated[4];
		size_t                     count = 0;
		ncfg_buf_t                 names;
		ncfg_buf_t                 block;
		size_t                     j;

		if (network->addressing_count != 0u) {
			stated[count] = "addressing";
			count++;
		}
		if (network->route_count != 0u) {
			stated[count] = "`routes`";
			count++;
		}
		if (network->dns) {
			stated[count] = "a `dns` policy";
			count++;
		}
		if (network->hook_count != 0u) {
			stated[count] = "hooks";
			count++;
		}
		if (count != 0u) {
			ncfg_buf_init(&names, 0);
			for (j = 0; j < count; j++) {
				ncfg_buf_addf(&names, "%s%s",
				    j == 0u ? "" : (j + 1u == count ? " and " : ", "), stated[j]);
			}
			ncfg_buf_init(&block, 0);
			/*
			 * **Kept short enough that the whole of it arrives**, which is
			 * not a matter of taste here: `ncfg_plan_warnf` formats into
			 * `NCFG_ERROR_MAX` and says nothing when the sentence does not
			 * fit, so a warning can be cut off mid-word and still be
			 * reported as a warning. The first draft of this one was, at 511
			 * of 512 characters -- the operator got "still means t". The id
			 * is the part that can be long: an SSID is up to 32 octets and a
			 * network that names one not valid as text carries it as 64 hex
			 * characters, so that is the width this has to fit around and
			 * `plan_gaps_test.c` checks it at exactly that width.
			 */
			ncfg_buf_addf(&block,
			    "the `network` block `%s` states %s, and nothing applies %s: "
			    "netcfgd plans addressing, routes, `dns` and hooks from an "
			    "`interface` block, and a network's own only round-trip through "
			    "`ncfg profile save`",
			    network->id, ncfg_buf_text(&names), count == 1u ? "it" : "them");
			ncfg_plan_warn_unbuilt(builder, NULL, ncfg_buf_text(&block));
			ncfg_buf_free(&block);
			ncfg_buf_free(&names);
		}
		/*
		 * **`metric` had a warning here and no longer does.** It was the one
		 * of the five that was this port's to finish, and both halves have:
		 * `address.c` fills a route's metric from
		 * `ncfg_observed_effective_metric` while the radio is associated, the
		 * daemon starts a DHCP client with it, and `ncfg_plan_metric_restart`
		 * restarts a client already running with the old one. `build.c`'s rule
		 * is that a pass landing takes its warning out in the same commit, and
		 * a warning that outlives the gap it describes is the other way this
		 * goes wrong -- an operator told a number is inert when it is not.
		 */
	}
}

/*
 * The half of the wireless configuration no pass here reads.
 *
 * `build.c`'s `warn_unported` carried one sentence per block and this is what
 * three of its arms became: the passes below act on part of each, so a blanket
 * "nothing in the plan above is about it" would now be false, and deleting the
 * arms outright would make a plan quieter than the configuration it was given
 * -- which is the hazard that function exists for.
 */
static void warn_held(ncfg_builder_t *builder)
{
	size_t i;

	for (i = 0; i < builder->desired->device_count; i++) {
		const ncfg_device_t *device = &builder->desired->devices[i];

		if (!device->wifi) {
			continue;
		}
		warn_device_policy(builder, device);
	}
	/*
	 * **What used to stand in the loop above said the supplicant serving a
	 * radio was not started by this build, which plans no backend actions at
	 * all, and `radio.c` makes both halves untrue.** A supplicant is started
	 * as the radio's prerequisite, kept while the document still asks for one
	 * and stopped when it does not -- and the second half had already stopped
	 * being true when `dot1x.c`, `advertise.c` and `access_point.c` landed.
	 * What survives is the one arrangement in which nothing still happens, and
	 * it is said where its own condition is checked rather than to every radio
	 * on the machine.
	 */
	ncfg_plan_radio_warn(builder);
	warn_mac_contradiction(builder);
	warn_eap_without_ca(builder);
	warn_phase2_that_pins_nothing(builder);
	warn_regdom(builder);
	warn_networks_held(builder);
	/*
	 * **What used to stand here said no access point was started, configured
	 * or restarted, and `access_point.c` makes that untrue.** hostapd is
	 * started as the radio's prerequisite, restarted when what it was started
	 * with stops matching the document, and stopped when no block asks for it.
	 * The half that is still true is narrower than a sentence about every
	 * document: it is the one arrangement where nothing happens, and the two
	 * places where netcfgd cannot see what a running access point holds. Each
	 * is said where its own condition is checked rather than to everybody.
	 */
	ncfg_plan_access_point_warn(builder);
}

/* ------------------------------------------------------------------------ *
 * The networks a supplicant holds
 * ------------------------------------------------------------------------ */

/* The running backend of this kind on this interface, or NULL. */
static const ncfg_observed_backend_t *backend_of(const ncfg_observed_t *observed, int kind,
    const char *interface)
{
	size_t i;

	for (i = 0; i < observed->backend_count; i++) {
		const ncfg_observed_backend_t *backend = &observed->backends[i];

		if (backend->kind == kind && backend->running && backend->interface &&
		    strcmp(backend->interface, interface) == 0) {
			return backend;
		}
	}
	return NULL;
}

/*
 * Hand the document's networks to every supplicant that is holding something
 * else.
 *
 * Driven from the observation's backend list rather than from the devices,
 * because what makes this actionable is a supplicant that is *running*: a
 * radio with none gets one from `radio.c`, as the interface's prerequisite,
 * and a wired 802.1X port reaches the same supplicant by the same route
 * (0008). **A supplicant this plan starts is not one this pass hands anything
 * to, and that is not a gap here**: filling a new supplicant is part of
 * starting it, which the Rust does in its executor rather than its planner --
 * `populate_supplicant`, called from the `backend.start` arm -- so this pass
 * reads `networks_match` about processes that were already running when the
 * machine was observed, which is every one it can say anything about.
 * `ncfg_builder_push` drops anything on an unmanaged device, so the
 * `managed = false` rule is honoured without asking here.
 */
static void plan_profiles(ncfg_builder_t *builder)
{
	const char    **profiles;
	ncfg_plan_ids_t gate = { NULL, 0, 0 };
	ncfg_op_t       op;
	ncfg_reason_t   reason;
	size_t          i;

	profiles = NULL;
	if (builder->desired->network_count != 0u) {
		profiles = calloc(builder->desired->network_count, sizeof(*profiles));
		if (!profiles) {
			builder->plan->failed = 1;
			return;
		}
		for (i = 0; i < builder->desired->network_count; i++) {
			profiles[i] = builder->desired->networks[i].id;
		}
	}
	for (i = 0; i < builder->observed->backend_count; i++) {
		const ncfg_observed_backend_t *backend = &builder->observed->backends[i];

		if (backend->kind != NCFG_BACKEND_SUPPLICANT || !backend->running ||
		    !backend->interface) {
			continue;
		}
		/* Absent is not false: see the header. */
		if (!backend->networks_match.has || backend->networks_match.value) {
			continue;
		}
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_WIFI_SET_PROFILES;
		op.u.set_profiles.device = backend->interface;
		op.u.set_profiles.profiles = profiles;
		op.u.set_profiles.profile_count = builder->desired->network_count;
		reason = ncfg_plan_reason_differs(backend->interface, "networks",
		    "the document's", "what the supplicant was given");
		ncfg_builder_gate(builder, backend->interface, &gate);
		/*
		 * No inverse: what it replaced is not recorded anywhere a revert
		 * could read, and 0015's whole point is that the supplicant holds
		 * nothing netcfgd is not the author of. A revert re-plans against the
		 * last-good document and hands them over again.
		 */
		(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count, NULL);
		ncfg_plan_ids_free(&gate);
	}
	free(profiles);
}

void ncfg_plan_wifi(ncfg_builder_t *builder)
{
	warn_held(builder);
	plan_profiles(builder);
}

/* ------------------------------------------------------------------------ *
 * The station lists an access point enforces
 * ------------------------------------------------------------------------ */

static int lists(char *const *list, size_t count, const char *station)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (list[i] && strcmp(list[i], station) == 0) {
			return 1;
		}
	}
	return 0;
}

/* Add and remove until one of hostapd's lists holds what the document says. */
static void converge_list(ncfg_builder_t *builder, const char *device, int list,
    char *const *want, size_t want_count, char *const *live, size_t live_count)
{
	static const char *const field = "access_point.access_control.stations";
	ncfg_op_t                op;
	ncfg_op_t                inverse;
	ncfg_reason_t            reason;
	size_t                   i;

	for (i = 0; i < want_count; i++) {
		if (lists(live, live_count, want[i])) {
			continue;
		}
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_ACCESS_CONTROL_ADD;
		op.u.access_control.iface = device;
		op.u.access_control.list = list;
		op.u.access_control.station = want[i];
		memset(&inverse, 0, sizeof(inverse));
		inverse.kind = NCFG_OP_ACCESS_CONTROL_DEL;
		inverse.u.access_control.iface = device;
		inverse.u.access_control.list = list;
		inverse.u.access_control.station = want[i];
		reason = ncfg_plan_reason_absent(device, field,
		    ncfg_plan_internf(builder->plan, "%s (%s)", want[i],
		    ncfg_plan_acl_policy_word(list)));
		(void)ncfg_builder_push(builder, &op, &reason, NULL, 0, &inverse);
	}
	for (i = 0; i < live_count; i++) {
		if (lists(want, want_count, live[i])) {
			continue;
		}
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_ACCESS_CONTROL_DEL;
		op.u.access_control.iface = device;
		op.u.access_control.list = list;
		op.u.access_control.station = live[i];
		memset(&inverse, 0, sizeof(inverse));
		inverse.kind = NCFG_OP_ACCESS_CONTROL_ADD;
		inverse.u.access_control.iface = device;
		inverse.u.access_control.list = list;
		inverse.u.access_control.station = live[i];
		reason = ncfg_plan_reason_unwanted(device, field,
		    ncfg_plan_internf(builder->plan, "%s (%s)", live[i],
		    ncfg_plan_acl_policy_word(list)));
		(void)ncfg_builder_push(builder, &op, &reason, NULL, 0, &inverse);
	}
}

void ncfg_plan_access_control(ncfg_builder_t *builder)
{
	size_t at;

	for (at = 0; at < builder->desired->access_point_count; at++) {
		const ncfg_access_point_t            *point =
		    &builder->desired->access_points[at];
		const char                           *device = point->device;
		const ncfg_observed_backend_t        *running;
		const ncfg_observed_access_control_t *live;
		const ncfg_access_control_t          *wanted;
		int                                   policy = 0;
		int                                   has_policy = 0;
		size_t                                i;

		/*
		 * One radio is one BSS in this build, and the one that runs is the
		 * first by id -- the same answer the executor gives. Without this the
		 * *second* access point on a radio compares its own identity against
		 * what the first started with, finds a difference that is not one,
		 * and converges for ever. `access_points` is sorted by id, so "the
		 * first" is a stable answer.
		 */
		for (i = 0; i < builder->desired->access_point_count; i++) {
			if (strcmp(builder->desired->access_points[i].device, device) == 0) {
				break;
			}
		}
		if (i != at) {
			continue;
		}
		running = backend_of(builder->observed, NCFG_BACKEND_ACCESS_POINT, device);
		if (!running) {
			continue;
		}
		/*
		 * Before the station lists, because a restart makes them moot: the
		 * access point comes back with the whole configuration rebuilt, and
		 * converging a list on a hostapd that is about to be replaced is work
		 * that fails or is undone.
		 */
		if (ncfg_plan_access_point_restart_identity(builder, point, running)) {
			continue;
		}
		if (!running->access_control) {
			continue;
		}
		live = running->access_control;
		wanted = point->access_control;

		if (live->policy.kind == NCFG_OBSERVED_POLICY_UNKNOWN) {
			/*
			 * No record, so netcfgd does not know which list this hostapd
			 * consults by default. Nothing may be converged from here: under
			 * `deny` an empty accept list is nothing, and under `allow` it is
			 * a network nobody can join. Converging against a guess is how an
			 * access point ends up closed at three in the morning.
			 */
			ncfg_plan_warnf(builder->plan, device,
			    "netcfgd has no record of which access control policy the access "
			    "point running on %s was started with, so its station list is left "
			    "alone. Restarting it writes the record",
			    device);
			continue;
		}
		if (live->policy.kind == NCFG_OBSERVED_POLICY_SET && wanted &&
		    live->policy.policy == wanted->policy) {
			/* Running what the document asks for: the ordinary case, and the
			 * one the whole feature is for. */
			policy = wanted->policy;
			has_policy = 1;
		} else if (live->policy.kind == NCFG_OBSERVED_POLICY_UNSET && !wanted) {
			has_policy = 0;
		} else {
			/*
			 * A policy change, which hostapd will not take over the control
			 * socket -- and converging the lists without it would enforce the
			 * new list under the old default, so a document changed from
			 * `deny` to `allow` would leave every unlisted station accepted,
			 * reported as applied. The access point is restarted instead,
			 * which is honest about what it costs.
			 */
			ncfg_plan_access_point_restart_policy(builder, device, &live->policy,
			    wanted);
			continue;
		}

		/* Both lists, always. See the header. */
		{
			static const int both[] = { NCFG_ACL_POLICY_DENY, NCFG_ACL_POLICY_ALLOW };

			for (i = 0; i < sizeof(both) / sizeof(both[0]); i++) {
				size_t       live_count = 0;
				char *const *held = ncfg_observed_access_control_list(live,
				    both[i], &live_count);
				int          mine = has_policy && policy == both[i];

				converge_list(builder, device, both[i],
				    mine && wanted ? wanted->stations : NULL,
				    mine && wanted ? wanted->station_count : 0u, held,
				    live_count);
			}
		}
	}
}
