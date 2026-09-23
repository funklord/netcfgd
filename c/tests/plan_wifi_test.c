/*
 * plan_wifi_test.c -- the networks a supplicant holds, the station lists an
 * access point enforces, and the radio settings that reach nothing.
 *
 * WHAT THESE ARE FOR
 *   **Running is not the same as holding what the document says.** The pass
 *   that hands the networks over had one caller in the Rust -- the
 *   `backend.start` arm -- so a supplicant that was already up was never given
 *   anything again: changing a passphrase, pinning a `bssid`, adding a network
 *   and deleting one each planned `nothing to do`, measured, and the
 *   supplicant kept the original credentials indefinitely.
 *
 *   The access control half is the opposite hazard. hostapd consults its
 *   accept list first and its deny list second whatever `macaddr_acl` says, so
 *   both lists have to be converged; and `macaddr_acl` itself cannot be
 *   changed over the control socket, so a policy that moved must **not** be
 *   converged -- enforcing the new list under the old default is how an access
 *   point ends up open, reported as applied.
 */
#include "planfix.h"

#include <stdio.h>

static int failures;
static int checks;

static void check(int condition, const char *what)
{
	checks++;
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

#define RADIO(body) \
	"{\"name\":\"wlan0\",\"kind\":{\"kind\":\"physical\"},\"wifi\":{" body "}}"
#define NETWORK(id) "{\"id\":\"" id "\",\"security\":{\"type\":\"open\"}}"
#define SUPPLICANT(body) \
	"{\"kind\":\"supplicant\",\"interface\":\"wlan0\",\"running\":true" body "}"
#define ACCESS_POINT(body) \
	"{\"kind\":\"access_point\",\"interface\":\"wlan0\",\"running\":true," body "}"
#define AP_DEVICE \
	"{\"name\":\"wlan0\",\"kind\":{\"kind\":\"physical\"}}"

/* ------------------------------------------------------------------------ *
 * The networks a supplicant holds
 * ------------------------------------------------------------------------ */

static void a_supplicant_holding_something_else_is_handed_the_document(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(RADIO("\"backend\":\"auto\""), "",
	    NETWORK("home") "," NETWORK("office"), "",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "],"
	    "\"backends\":[" SUPPLICANT(",\"networks_match\":false") "]",
	    &document, &observed);
	const ncfg_action_t *action = plan ? planfix_action(plan, "wifi.set_profiles") : NULL;

	check(action != NULL, "a running supplicant holding something else is given the networks");
	check(action && action->op.u.set_profiles.profile_count == 2u &&
	    strcmp(action->op.u.set_profiles.profiles[0], "home") == 0 &&
	    strcmp(action->op.u.set_profiles.profiles[1], "office") == 0,
	    "and it is handed every network id, in document order");
	check(action && !action->has_inverse,
	    "with no inverse: what it replaced is recorded nowhere a revert could read");
	planfix_release(plan, document, observed);
}

/*
 * Absent is not false. `networks_match` is unanswered for a backend that is
 * not a supplicant, for one netcfgd has no record of handing anything to, and
 * for a network resolved from a scan -- and none of those is a reason to send.
 */
static void an_unanswered_networks_question_sends_nothing(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(RADIO("\"backend\":\"auto\""), "",
	    NETWORK("home"), "",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "],"
	    "\"backends\":[" SUPPLICANT("") "]", &document, &observed);

	check(plan && !planfix_action(plan, "wifi.set_profiles"),
	    "an unanswered `networks_match` hands over nothing");
	planfix_release(plan, document, observed);

	plan = planfix_plan(RADIO("\"backend\":\"auto\""), "", NETWORK("home"), "",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "],"
	    "\"backends\":[" SUPPLICANT(",\"networks_match\":true") "]", &document, &observed);
	check(plan && !planfix_action(plan, "wifi.set_profiles"),
	    "and a supplicant already holding the document's networks is left alone");
	planfix_release(plan, document, observed);
}

/* A supplicant that is not running is the backend pass's business, and that
 * pass plans nothing in this build -- so there is nothing to hand over to. */
static void nothing_is_handed_to_a_supplicant_that_is_not_running(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(RADIO("\"backend\":\"auto\""), "",
	    NETWORK("home"), "",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "],"
	    "\"backends\":[{\"kind\":\"supplicant\",\"interface\":\"wlan0\","
	    "\"running\":false,\"networks_match\":false}]", &document, &observed);

	check(plan && !planfix_action(plan, "wifi.set_profiles"),
	    "a supplicant that is not running is handed nothing");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * What this build holds and does not act on
 * ------------------------------------------------------------------------ */

/*
 * `regdom` and `powersave` on a radio are read by no pass and reach nothing --
 * `wifi.set_regdom` is an op nothing constructs, in either language. They are
 * parsed, kept and rendered back, which is the shape 0061 exists to prevent.
 *
 * **And whose gap that is, is the part that was wrong.** The sentence ended
 * "not acted on by this build ... when the code arrives", which is a promise
 * that a later release of *this port* applies them. Settled against `crates/`:
 * `WifiSetRegdom` has no constructor anywhere there either, and `powersave`'s
 * only mention outside the model is the matching warning. So there is no
 * release to wait for, and this goes through `ncfg_plan_warn_unbuilt` like the
 * other blocks nobody is going to write.
 *
 * Checked by the sentence's **last** words rather than its first. It is 437
 * characters at the widest device name a kernel takes, `ncfg_plan_warnf` marks
 * what it cuts at the end, and a check on "`regdom` and `powersave` on wlan0"
 * would go on passing through a cut that removed the whole of the marking.
 */
static void the_radio_settings_that_reach_nothing_are_named(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(
	    RADIO("\"backend\":\"auto\",\"regdom\":\"SE\",\"powersave\":\"off\""), "", "", "",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "]",
	    &document, &observed);

	check(plan && planfix_warned(plan,
	    "`regdom` and `powersave` on wlan0 are read and acted on by nothing"),
	    "a radio's `regdom` and `powersave` are named as stored and acted on by nothing");
	check(planfix_whole(planfix_warning_with(plan, "are read and acted on by nothing"),
	    PLANFIX_UNBUILT_TAIL),
	    "and the whole of it arrives, marked as nobody's gap rather than this port's");
	check(plan && planfix_warned(plan, "an access point's is the only one netcfgd carries"),
	    "and the spelling that does reach hostapd is named in the same breath");
	check(plan && !planfix_warned(plan, "not acted on by this build"),
	    "and no longer as a release this port owes anybody");
	planfix_release(plan, document, observed);

	plan = planfix_plan(RADIO("\"backend\":\"auto\",\"regdom\":\"SE\""), "", "", "",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "]",
	    &document, &observed);
	check(plan && planfix_warned(plan, "`regdom` on wlan0 is read and acted on by nothing"),
	    "a radio naming one of the two is told about that one, in the singular");
	check(plan && !planfix_warned(plan, "power-saving"),
	    "and not about the one it did not write");
	planfix_release(plan, document, observed);

	plan = planfix_plan(RADIO("\"backend\":\"auto\""), "", "", "",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "]",
	    &document, &observed);
	check(plan && !planfix_warned(plan, "read and acted on by nothing"),
	    "and a radio at its defaults is not asking for anything, so nothing is said");
	planfix_release(plan, document, observed);
}

/*
 * The language spells `regdom` twice and only one of them does anything: an
 * access point's becomes hostapd's `country_code` and a radio's reaches
 * nothing. Both ways that bites are said.
 */
static void a_regulatory_domain_written_in_the_wrong_place_is_said(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(
	    RADIO("\"backend\":\"auto\",\"regdom\":\"SE\""), "", "",
	    ",\"access_points\":[{\"id\":\"home\",\"ssid\":\"686f6d65\",\"device\":\"wlan0\","
	    "\"security\":{\"type\":\"open\"},\"regdom\":\"US\"}]",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "]",
	    &document, &observed);

	check(plan && planfix_warned(plan, "name different regulatory domains"),
	    "a radio and its access point naming different domains is said, and which wins");
	planfix_release(plan, document, observed);

	plan = planfix_plan(RADIO("\"backend\":\"auto\",\"regdom\":\"SE\""), "", "",
	    ",\"access_points\":[{\"id\":\"home\",\"ssid\":\"686f6d65\",\"device\":\"wlan0\","
	    "\"security\":{\"type\":\"open\"}}]",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "]",
	    &document, &observed);
	check(plan && planfix_warned(plan, "nothing carries it to hostapd"),
	    "and a domain written only on the radio is said to reach nothing");
	planfix_release(plan, document, observed);

	plan = planfix_plan(RADIO("\"backend\":\"auto\""), "", "",
	    ",\"access_points\":[{\"id\":\"home\",\"ssid\":\"686f6d65\",\"device\":\"wlan0\","
	    "\"security\":{\"type\":\"open\"},\"regdom\":\"SE\"}]",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "]",
	    &document, &observed);
	check(plan && !planfix_warned(plan, "regulatory domain"),
	    "while the ordinary arrangement -- the access point alone naming one -- is quiet");
	planfix_release(plan, document, observed);

	plan = planfix_plan(RADIO("\"backend\":\"auto\",\"regdom\":\"SE\""), "", "",
	    ",\"access_points\":[{\"id\":\"home\",\"ssid\":\"686f6d65\",\"device\":\"wlan0\","
	    "\"security\":{\"type\":\"open\"},\"regdom\":\"se\"}]",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "]",
	    &document, &observed);
	/* Case-insensitively, because the compiler uppercases both and a document
	 * can reach the planner without passing through it. */
	check(plan && !planfix_warned(plan, "regulatory domain"),
	    "and two spellings of one domain are one domain, so nothing is said");
	planfix_release(plan, document, observed);
}

/*
 * The four sentences this port did not say.
 *
 * Found by giving both programs one document and comparing the warnings:
 * `ncfg plan` here emitted five and the Rust six, then four, then three. Each
 * is about a configuration that is legal, compiles, plans actions, and does
 * something other than what it looks like -- which is the only kind of mistake
 * a warning can catch, because every other kind is a refusal.
 */
static void a_device_nobody_asked_to_configure_is_said(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(
	    "{\"name\":\"spare0\",\"kind\":{\"kind\":\"dummy\"}}", "", "", "",
	    "\"links\":[" PLANFIX_LINK("spare0", "") "]", &document, &observed);

	/* 0186: an operator with a `device` block, a `network` block and no
	 * `interface` block was told `nothing to do`. */
	check(plan && planfix_warned(plan, "has a `device` block and no `interface` block"),
	    "a device block with no interface block is said to plan nothing");
	check(plan && planfix_warned(plan, "config = \"dhcp\" }` is what makes it netcfgd's"),
	    "  and the sentence names the line that would make it live");
	planfix_release(plan, document, observed);

	plan = planfix_plan("{\"name\":\"spare0\",\"kind\":{\"kind\":\"dummy\"}}",
	    "{\"name\":\"spare0\",\"addressing\":[{\"source\":\"static\","
	    "\"address\":\"10.0.0.1/24\"}]}", "", "",
	    "\"links\":[" PLANFIX_LINK("spare0", "") "]", &document, &observed);
	check(plan && !planfix_warned(plan, "and no `interface` block"),
	    "and the same device with one is quiet");
	planfix_release(plan, document, observed);
}

static void a_fixed_mac_the_supplicant_replaces_is_said(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(
	    "{\"name\":\"wlan0\",\"kind\":{\"kind\":\"physical\"},"
	    "\"mac\":\"02:00:00:00:00:01\","
	    "\"wifi\":{\"backend\":\"auto\",\"mac_policy\":\"per_network\"}}", "", "", "",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "]", &document, &observed);

	check(plan && planfix_warned(plan, "which replaces it"),
	    "a fixed mac under a policy that randomises it is said");
	check(plan && planfix_warned(plan, "`mac_policy = \"permanent\"` is what keeps it"),
	    "  and the sentence says which of the two to change");
	planfix_release(plan, document, observed);

	/* The arrangement that is not a contradiction: a fixed address kept. */
	plan = planfix_plan("{\"name\":\"wlan0\",\"kind\":{\"kind\":\"physical\"},"
	    "\"mac\":\"02:00:00:00:00:01\","
	    "\"wifi\":{\"backend\":\"auto\",\"mac_policy\":\"permanent\"}}", "", "", "",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "]", &document, &observed);
	check(plan && !planfix_warned(plan, "which replaces it"),
	    "and `permanent` beside a fixed mac is the arrangement that works, so nothing "
	    "is said");
	planfix_release(plan, document, observed);

	/* And a policy with no `mac`: nothing to contradict. */
	plan = planfix_plan(RADIO("\"backend\":\"auto\",\"mac_policy\":\"per_network\""),
	    "", "", "", "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "]",
	    &document, &observed);
	check(plan && !planfix_warned(plan, "which replaces it"),
	    "and a randomising policy on its own is the ordinary one");
	planfix_release(plan, document, observed);
}

/* The two degrees of trusting whatever answers (0206). */
static void eap_that_believes_any_server_is_said(void)
{
	static const char *const eap_head =
	    "{\"id\":\"corp\",\"security\":{\"type\":\"eap\","
	    "\"method\":\"peap\",\"identity\":\"someone\"";
	ncfg_document_t         *document;
	ncfg_observed_t         *observed;
	ncfg_plan_t             *plan;
	char                     extra[1024];

	(void)snprintf(extra, sizeof(extra), "%s}}", eap_head);
	plan = planfix_plan(RADIO("\"backend\":\"auto\""), "", extra, "",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "]", &document, &observed);
	check(plan && planfix_warned(plan, "pins no `ca_cert`, so it will trust any server"),
	    "EAP with no issuer pinned is said to trust whatever answers");
	planfix_release(plan, document, observed);

	/* An issuer and no name: the half-answer, which used to read as the whole
	 * one. Every certificate that issuer ever signed is accepted. */
	(void)snprintf(extra, sizeof(extra),
	    "%s,\"ca_cert\":{\"path\":\"/etc/ssl/ca.pem\"}}}", eap_head);
	plan = planfix_plan(RADIO("\"backend\":\"auto\""), "", extra, "",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "]", &document, &observed);
	check(plan && planfix_warned(plan, "and no `domain_suffix_match`"),
	    "and an issuer with no name is said to accept anything that issuer signed");
	check(plan && !planfix_warned(plan, "pins no `ca_cert`"),
	    "  and is not also told it pinned nothing, which is the other case");
	planfix_release(plan, document, observed);

	(void)snprintf(extra, sizeof(extra),
	    "%s,\"ca_cert\":{\"path\":\"/etc/ssl/ca.pem\"},"
	    "\"domain_suffix_match\":\"radius.example.com\"}}", eap_head);
	plan = planfix_plan(RADIO("\"backend\":\"auto\""), "", extra, "",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "]", &document, &observed);
	check(plan && !planfix_warned(plan, "server certificate"),
	    "and both together are the arrangement that answers who the server is");
	planfix_release(plan, document, observed);
}

/* 0189: warned and not refused, because the value is inert rather than wrong
 * and netcfgd's own example told people to write it. */
static void a_phase2_that_pins_nothing_is_said(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan;
	size_t           at;
	unsigned         said = 0;
	unsigned         quiet = 0;
	/* The inert forms and the pinning ones, through the model's own rule. */
	static const char *const pins_nothing[] = { "mschapv2", "auth", "MSCHAPV2 ", "=x", "y=" };
	static const char *const pins[] = { "auth=MSCHAPV2", "autheap=MSCHAPV2",
		"mschapv2 auth=MSCHAPV2" };

	for (at = 0; at < sizeof(pins_nothing) / sizeof(pins_nothing[0]); at++) {
		said += ncfg_phase2_pins_nothing(pins_nothing[at]) ? 1u : 0u;
	}
	for (at = 0; at < sizeof(pins) / sizeof(pins[0]); at++) {
		quiet += ncfg_phase2_pins_nothing(pins[at]) ? 0u : 1u;
	}
	check(said == sizeof(pins_nothing) / sizeof(pins_nothing[0]),
	    "a phase2 with no `key=value` token pins nothing, including a lone key and a "
	    "lone value");
	check(quiet == sizeof(pins) / sizeof(pins[0]),
	    "  and one with a whole token pins something, wherever in the value it sits");
	check(ncfg_phase2_pins_nothing(NULL),
	    "  and an absent one pins nothing, which is the same answer");

	plan = planfix_plan(RADIO("\"backend\":\"auto\""), "",
	    "{\"id\":\"corp\",\"security\":{\"type\":\"eap\","
	    "\"method\":\"peap\",\"identity\":\"someone\",\"phase2\":\"mschavp2\","
	    "\"ca_cert\":{\"path\":\"/etc/ssl/ca.pem\"},"
	    "\"domain_suffix_match\":\"radius.example.com\"}}", "",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "]", &document, &observed);
	check(plan && planfix_warned(plan, "pins no inner method"),
	    "a network whose phase2 pins nothing is said");
	check(plan && planfix_warned(plan, "Write `auth=MSCHAPV2`"),
	    "  and told the form that would pin one");
	planfix_release(plan, document, observed);

	/* The wired half, which is the other place 802.1X lives (0008). */
	plan = planfix_plan("{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}",
	    "{\"name\":\"eth0\",\"dot1x\":{\"method\":\"peap\",\"identity\":\"someone\","
	    "\"phase2\":\"mschapv2\",\"ca_cert\":{\"path\":\"/etc/ssl/ca.pem\"},"
	    "\"domain_suffix_match\":\"radius.example.com\"}}", "", "",
	    "\"links\":[" PLANFIX_LINK("eth0", "") "]", &document, &observed);
	check(plan && planfix_warned(plan, "pins no inner method"),
	    "and so is a wired `dot1x` that does the same thing");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * The station lists
 * ------------------------------------------------------------------------ */

static const ncfg_action_t *acl(const ncfg_plan_t *plan, const char *name, const char *station)
{
	size_t i;

	for (i = 0; i < plan->action_count; i++) {
		if (strcmp(ncfg_op_name(&plan->actions[i].op), name) != 0) {
			continue;
		}
		if (strcmp(plan->actions[i].op.u.access_control.station, station) == 0) {
			return &plan->actions[i];
		}
	}
	return NULL;
}

static void a_station_list_is_converged_in_both_directions(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(AP_DEVICE, "", "",
	    ",\"access_points\":[{\"id\":\"home\",\"ssid\":\"686f6d65\",\"device\":\"wlan0\","
	    "\"security\":{\"type\":\"open\"},\"access_control\":{\"policy\":\"deny\","
	    "\"stations\":[\"aa:bb:cc:dd:ee:01\"]}}]",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "],"
	    "\"backends\":[" ACCESS_POINT("\"access_control\":{\"policy\":{\"set\":\"deny\"},"
	    "\"denied\":[\"aa:bb:cc:dd:ee:02\"],\"accepted\":[]}") "]", &document, &observed);
	const ncfg_action_t *action;

	action = plan ? acl(plan, "access_control.add", "aa:bb:cc:dd:ee:01") : NULL;
	check(action && action->op.u.access_control.list == NCFG_ACL_POLICY_DENY,
	    "a station the document lists and hostapd does not is added to the right list");
	action = plan ? acl(plan, "access_control.del", "aa:bb:cc:dd:ee:02") : NULL;
	check(action != NULL, "and one hostapd holds and the document does not is removed");
	check(action && action->has_inverse, "and each can be undone");
	planfix_release(plan, document, observed);
}

/*
 * Both lists, always. hostapd's `hostapd_check_acl` consults the accept list
 * first whatever `macaddr_acl` says, so a station left on the accept list
 * overrides the deny list that is supposed to be refusing it.
 */
static void the_list_the_policy_does_not_select_is_emptied_too(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(AP_DEVICE, "", "",
	    ",\"access_points\":[{\"id\":\"home\",\"ssid\":\"686f6d65\",\"device\":\"wlan0\","
	    "\"security\":{\"type\":\"open\"},\"access_control\":{\"policy\":\"deny\","
	    "\"stations\":[]}}]",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "],"
	    "\"backends\":[" ACCESS_POINT("\"access_control\":{\"policy\":{\"set\":\"deny\"},"
	    "\"denied\":[],\"accepted\":[\"aa:bb:cc:dd:ee:03\"]}") "]", &document, &observed);
	const ncfg_action_t *action = plan ?
	    acl(plan, "access_control.del", "aa:bb:cc:dd:ee:03") : NULL;

	check(action && action->op.u.access_control.list == NCFG_ACL_POLICY_ALLOW,
	    "a station on the list the policy does not select is removed from it too");
	planfix_release(plan, document, observed);
}

/*
 * No record, so netcfgd does not know which list this hostapd consults by
 * default. Under `deny` an empty accept list is nothing, and under `allow` it
 * is a network nobody can join -- so nothing may be converged from here.
 */
static void an_unknown_policy_converges_nothing_and_says_so(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(AP_DEVICE, "", "",
	    ",\"access_points\":[{\"id\":\"home\",\"ssid\":\"686f6d65\",\"device\":\"wlan0\","
	    "\"security\":{\"type\":\"open\"},\"access_control\":{\"policy\":\"deny\","
	    "\"stations\":[\"aa:bb:cc:dd:ee:01\"]}}]",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "],"
	    "\"backends\":[" ACCESS_POINT("\"access_control\":{\"policy\":\"unknown\","
	    "\"denied\":[],\"accepted\":[]}") "]", &document, &observed);

	check(plan && planfix_warned(plan, "has no record of which access control policy"),
	    "an access point netcfgd has no policy record for is reported");
	check(plan && !planfix_action(plan, "access_control.add"),
	    "and its station lists are left exactly alone");
	planfix_release(plan, document, observed);
}

/*
 * `macaddr_acl` cannot be changed over the control socket, so converging the
 * lists without a restart would enforce the new list under the old default --
 * every unlisted station accepted, reported as applied. The restart that
 * applies it instead is `access_point.c`'s and is checked there; what this
 * file owes is the half it owns, which is that **nothing is converged here**.
 */
static void a_policy_that_moved_converges_no_station(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(AP_DEVICE, "", "",
	    ",\"access_points\":[{\"id\":\"home\",\"ssid\":\"686f6d65\",\"device\":\"wlan0\","
	    "\"security\":{\"type\":\"open\"},\"access_control\":{\"policy\":\"allow\","
	    "\"stations\":[\"aa:bb:cc:dd:ee:01\"]}}]",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "],"
	    "\"backends\":[" ACCESS_POINT("\"access_control\":{\"policy\":{\"set\":\"deny\"},"
	    "\"denied\":[],\"accepted\":[]}") "]", &document, &observed);

	check(plan && planfix_warned(plan, "hostapd only reads at startup, so the access point is restarted"),
	    "a policy the document moved is reported, and what the fix costs is said");
	check(plan && !planfix_action(plan, "access_control.add"),
	    "and no station is enforced under the wrong default");
	planfix_release(plan, document, observed);
}

/*
 * One radio is one BSS in this build, and the one that runs is the first by
 * id. Without this the *second* access point on a radio compares its own list
 * against what the first started with, finds a difference that is not one, and
 * converges for ever.
 */
static void only_the_first_access_point_on_a_radio_is_converged(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(AP_DEVICE, "", "",
	    ",\"access_points\":[{\"id\":\"a-first\",\"ssid\":\"6131\",\"device\":\"wlan0\","
	    "\"security\":{\"type\":\"open\"},\"access_control\":{\"policy\":\"deny\","
	    "\"stations\":[\"aa:bb:cc:dd:ee:01\"]}},"
	    "{\"id\":\"b-second\",\"ssid\":\"6232\",\"device\":\"wlan0\",\"security\":{\"type\":\"open\"},"
	    "\"access_control\":{\"policy\":\"deny\",\"stations\":[\"aa:bb:cc:dd:ee:09\"]}}]",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "],"
	    "\"backends\":[" ACCESS_POINT("\"access_control\":{\"policy\":{\"set\":\"deny\"},"
	    "\"denied\":[\"aa:bb:cc:dd:ee:01\"],\"accepted\":[]}") "]", &document, &observed);

	check(plan && !planfix_action(plan, "access_control.add") &&
	    !planfix_action(plan, "access_control.del"),
	    "the second access point on a radio is not converged against the first's hostapd");
	planfix_release(plan, document, observed);
}

/* An access point with no `access_control` block, running one that was started
 * without one, is converged and there is nothing to converge. */
static void an_access_point_that_already_agrees_plans_nothing(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(AP_DEVICE, "", "",
	    ",\"access_points\":[{\"id\":\"home\",\"ssid\":\"686f6d65\",\"device\":\"wlan0\","
	    "\"security\":{\"type\":\"open\"}}]",
	    "\"links\":[" PLANFIX_LINK("wlan0", ",\"wireless\":true") "],"
	    "\"backends\":[" ACCESS_POINT("\"access_control\":{\"policy\":\"unset\","
	    "\"denied\":[],\"accepted\":[]}") "]", &document, &observed);

	check(plan && ncfg_plan_is_empty(plan),
	    "an access point with no station lists, running without any, plans nothing");
	planfix_release(plan, document, observed);
}

int main(void)
{
	a_supplicant_holding_something_else_is_handed_the_document();
	an_unanswered_networks_question_sends_nothing();
	nothing_is_handed_to_a_supplicant_that_is_not_running();
	the_radio_settings_that_reach_nothing_are_named();
	a_regulatory_domain_written_in_the_wrong_place_is_said();
	a_device_nobody_asked_to_configure_is_said();
	a_fixed_mac_the_supplicant_replaces_is_said();
	eap_that_believes_any_server_is_said();
	a_phase2_that_pins_nothing_is_said();
	a_station_list_is_converged_in_both_directions();
	the_list_the_policy_does_not_select_is_emptied_too();
	an_unknown_policy_converges_nothing_and_says_so();
	a_policy_that_moved_converges_no_station();
	only_the_first_access_point_on_a_radio_is_converged();
	an_access_point_that_already_agrees_plans_nothing();

	printf("plan_wifi_test: %d checks, %d failed\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
