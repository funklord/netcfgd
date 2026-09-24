/*
 * plan_access_point_test.c -- the hostapd a radio runs: started, restarted and
 * stopped.
 *
 * WHAT THESE ARE FOR
 *   **Nearly every check here is about a plan that must be empty.** An access
 *   point is the one backend netcfgd cannot hand anything to while it runs, so
 *   every disagreement between the document and what hostapd was started with
 *   is a stop and a start -- and a comparison that is wrong in the permissive
 *   direction is therefore not a missed edit but a permanent deauthentication
 *   loop, on a radio nobody has touched, at whatever rate the daemon
 *   reconciles. The Rust shipped that twice, from both directions, and 0222
 *   records both.
 *
 *   So the cases that pin this down are the pairs: an absent `channel` against
 *   the `channel=0` the renderer writes plans nothing, while an absent
 *   `channel` against `36` restarts; an absent `band` with channel 36 against
 *   a file saying `5` plans nothing, while a deleted `band = "5"` restarts.
 *   Each half without the other is a hole this file exists to keep shut.
 *
 * WHAT A FIXTURE IS
 *   `planfix.h`'s: two JSON documents and nothing else. Nothing here starts
 *   hostapd, touches a radio or writes a file -- a plan is a pure function of
 *   a document and an observation, which is what lets this suite run on a
 *   workstation whose network must not be disturbed.
 */
#include "ncfg/hostapd.h"

#include "planfix.h"

#include <stdio.h>

static int failures;
static int checks;

static void check(int condition, const char *what)
{
	checks++;
	printf("%-74s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* A plan that should have nothing in it, printing what it had if it does. */
static int quiet(const ncfg_plan_t *plan)
{
	char names[512];

	if (plan && ncfg_plan_is_empty(plan)) {
		return 1;
	}
	if (plan) {
		planfix_names(plan, names, sizeof(names));
		printf("  expected nothing to do; the plan is [%s]\n", names);
	}
	return 0;
}

#define RADIO "{\"name\":\"wlan0\",\"kind\":{\"kind\":\"physical\"}}"
#define RADIO_INTERFACE "{\"name\":\"wlan0\",\"addressing\":[]}"
#define ADDRESSED_RADIO \
	"{\"name\":\"wlan0\",\"addressing\":[{\"source\":\"static\"," \
	"\"address\":\"192.168.4.1/24\"}]}"

/* A radio the kernel has and has not brought up, so that `link.up` is planned
 * and something can be shown to wait for it. */
#define DOWN_LINK \
	"{\"name\":\"wlan0\",\"index\":2,\"mtu\":1500,\"up\":false,\"carrier\":true," \
	"\"ownership\":\"unknown\",\"wireless\":true}"
#define UP_LINK PLANFIX_LINK("wlan0", ",\"wireless\":true")

#define POINT(body) \
	",\"access_points\":[{\"id\":\"home\",\"ssid\":\"686f6d65\",\"device\":\"wlan0\"" \
	body "}]"
#define OPEN_POINT POINT(",\"security\":{\"type\":\"open\"}")

/* A running hostapd, with whatever netcfgd recorded about it. */
#define RUNNING(body) \
	"\"backends\":[{\"kind\":\"access_point\",\"interface\":\"wlan0\"," \
	"\"running\":true" body "}]"
/* What it was started with, in the model's vocabulary rather than hostapd's. */
#define STARTED_WITH(body) ",\"started_with\":{\"ssid\":\"686f6d65\"" body "}"
/*
 * The rest of what `OPEN_POINT` would have been started as, **as the renderer
 * writes it rather than as the document spells it**. An absent `channel` is
 * `channel=0`, and an access point naming neither a band nor a channel comes
 * up on 2.4 GHz -- every radio has it, and automatic channel selection can
 * then choose within it. A fixture that left these out would be a converged
 * machine that restarts, which is the loop this file is mostly about.
 */
#define AS_WRITTEN ",\"channel\":0,\"band\":\"2.4\""

/* ------------------------------------------------------------------------ *
 * The start
 * ------------------------------------------------------------------------ */

static void a_radio_the_document_gives_an_access_point_starts_hostapd(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(RADIO, RADIO_INTERFACE, "", OPEN_POINT,
	    "\"links\":[" DOWN_LINK "]", &document, &observed);
	const ncfg_action_t *start = plan ? planfix_action(plan, "backend.start") : NULL;
	const ncfg_action_t *up = plan ? planfix_action(plan, "link.up") : NULL;

	check(start != NULL, "an `access_point` block starts hostapd on the device it names");
	check(start && start->op.u.backend.kind == NCFG_BACKEND_ACCESS_POINT,
	    "as an access point rather than some other backend");
	check(start && start->reason.field && strcmp(start->reason.field, "access_point") == 0,
	    "and the reason names the block an operator would go and edit");
	/* Rule 3: a radio that is down has no interface for hostapd to attach to. */
	check(start && up && planfix_depends_on(start, up->id),
	    "and it waits for `link.up`, there being no interface to attach to before that");
	check(start && start->has_inverse &&
	    start->inverse.kind == NCFG_OP_BACKEND_STOP,
	    "and it can be undone, which is what commit-confirm reverts with");
	planfix_release(plan, document, observed);
}

/*
 * The whole reason the call site is `ncfg_plan_interface_contents` and not
 * `build.c`'s sequence. `plan.h` says the action list is itself a valid
 * execution order, so "the access point comes before the addressing" has to
 * mean *earlier in the list* -- and hostapd puts the radio into AP mode, which
 * the kernel takes only on a link that is down, so an address added first is
 * one that may not be there afterwards.
 */
static void the_addressing_waits_for_the_access_point(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(RADIO, ADDRESSED_RADIO, "", OPEN_POINT,
	    "\"links\":[" DOWN_LINK "]", &document, &observed);
	const ncfg_action_t *start = plan ? planfix_action(plan, "backend.start") : NULL;
	const ncfg_action_t *address = plan ? planfix_action(plan, "addr.add") : NULL;

	check(start && address, "a radio with an access point and an address plans both");
	check(start && address && planfix_depends_on(address, start->id),
	    "and the address waits for the access point, which takes the radio down to "
	    "change mode");
	check(start && address && start->id < address->id,
	    "and comes first in the list, which is itself the execution order");
	planfix_release(plan, document, observed);
}

static void hostapd_that_is_already_running_is_not_started_again(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(RADIO, RADIO_INTERFACE, "", OPEN_POINT,
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN)), &document, &observed);

	check(quiet(plan), "applying an `access_point` block twice plans nothing the second time");
	planfix_release(plan, document, observed);
}

/*
 * One prerequisite per interface, and the supplicant is first. An interface
 * carrying a `dot1x` block takes that arm and no other, which is the Rust
 * returning at the first prerequisite it finds.
 */
static void a_port_that_authenticates_takes_the_supplicant_and_not_hostapd(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(RADIO,
	    "{\"name\":\"wlan0\",\"addressing\":[],\"dot1x\":{\"method\":\"peap\","
	    "\"identity\":\"dave\",\"password\":{\"provider\":\"file\",\"name\":\"d\"}}}", "",
	    OPEN_POINT, "\"links\":[" DOWN_LINK "]", &document, &observed);
	const ncfg_action_t *start = plan ? planfix_for_field(plan, "backend.start", "dot1x") : NULL;

	check(start != NULL, "an interface with a `dot1x` block starts its supplicant");
	check(plan && !planfix_for_field(plan, "backend.start", "access_point"),
	    "and not also an access point, one interface taking one prerequisite");
	planfix_release(plan, document, observed);
}

/*
 * hostapd is started as an interface's prerequisite, and an interface that is
 * not in the document is never passed over. This is the one arrangement in
 * which nothing happens, and it is what the blanket sentence about access
 * points narrowed to.
 */
static void an_access_point_on_a_device_with_no_interface_block_is_said(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(RADIO, "", "", OPEN_POINT,
	    "\"links\":[" DOWN_LINK "]", &document, &observed);

	check(plan && !planfix_action(plan, "backend.start"),
	    "an access point on a device with no `interface` block starts nothing");
	check(plan && planfix_warned(plan, "which has no `interface` block"),
	    "and the plan says so, naming what to add rather than going quiet");
	planfix_release(plan, document, observed);

	plan = planfix_plan(RADIO, RADIO_INTERFACE, "", OPEN_POINT,
	    "\"links\":[" DOWN_LINK "]", &document, &observed);
	check(plan && !planfix_warned(plan, "which has no `interface` block"),
	    "while the ordinary arrangement is not told about a problem it does not have");
	check(plan && !planfix_warned(plan, "does not act on"),
	    "and no longer hears that nothing starts, configures or restarts hostapd");
	planfix_release(plan, document, observed);
}

/* 0079: a daemon that dies as fast as netcfgd starts it produced 181 starts in
 * twelve seconds. netcfgd tries, and then stops trying and says so. */
static void an_access_point_that_will_not_stay_up_stops_being_started(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(RADIO, RADIO_INTERFACE, "", OPEN_POINT,
	    "\"links\":[" UP_LINK "],\"backend_restarts\":[[\"access_point\",\"wlan0\",5]]",
	    &document, &observed);

	check(plan && !planfix_action(plan, "backend.start"),
	    "an access point started five times that did not stay up is not started again");
	check(plan && planfix_warned(plan, "not starting it again"),
	    "and the plan says so rather than going quiet about a radio with no beacon");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * The teardown
 * ------------------------------------------------------------------------ */

/*
 * **The rule that keeps an access point is the rule that starts one.** Wrong
 * in the permissive direction leaves a hostapd nobody owns; wrong in the other
 * direction is netcfgd starting one and killing it on every reconcile.
 */
static void hostapd_the_document_stopped_naming_is_stopped(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(RADIO, RADIO_INTERFACE, "", "",
	    "\"links\":[" UP_LINK "]," RUNNING(""), &document, &observed);
	const ncfg_action_t *stop = plan ? planfix_action(plan, "backend.stop") : NULL;

	check(stop != NULL, "an access point whose `access_point` block went is stopped");
	check(stop && stop->reason.field && strcmp(stop->reason.field, "access_point") == 0,
	    "and the reason names that block rather than the backend's own name");
	check(stop && stop->op.u.backend.kind == NCFG_BACKEND_ACCESS_POINT,
	    "and it is the access point that is stopped");
	planfix_release(plan, document, observed);
}

/* **Not \"this device is a radio\"**: a radio whose `access_point` block was
 * deleted is exactly the case that has to stop hostapd, and it is still a
 * radio. So the question is asked of the block and not of the hardware. */
static void hostapd_the_document_still_names_is_left_alone(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(RADIO, RADIO_INTERFACE, "", OPEN_POINT,
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN)), &document, &observed);

	check(plan && !planfix_action(plan, "backend.stop"),
	    "an access point the document still names is not stopped");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * The restart, and the loops it must not become
 * ------------------------------------------------------------------------ */

/* The stop and the start of one restart, or NULLs. */
static void restart_pair(const ncfg_plan_t *plan, const ncfg_action_t **stop_out,
    const ncfg_action_t **start_out)
{
	*stop_out = plan ? planfix_action(plan, "backend.stop") : NULL;
	*start_out = plan ? planfix_action(plan, "backend.start") : NULL;
}

static void an_edited_ssid_restarts_the_access_point(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(RADIO, RADIO_INTERFACE, "",
	    POINT(",\"security\":{\"type\":\"open\"}"),
	    "\"links\":[" UP_LINK "]," RUNNING(",\"started_with\":{\"ssid\":\"6f6c64\"" AS_WRITTEN "}"),
	    &document, &observed);
	const ncfg_action_t *stop;
	const ncfg_action_t *start;

	restart_pair(plan, &stop, &start);
	check(stop && start, "an access point whose ssid was edited is stopped and started");
	check(stop && start && planfix_depends_on(start, stop->id),
	    "and the start waits for the stop, a restart being a pair rather than two actions");
	check(stop && stop->reason.field &&
	    strcmp(stop->reason.field, "access_point.ssid") == 0,
	    "and the reason names the field that moved");
	check(stop && stop->reason.desired && strcmp(stop->reason.desired, "686f6d65") == 0 &&
	    stop->reason.observed && strcmp(stop->reason.observed, "6f6c64") == 0,
	    "in hex, an ssid being 0 to 32 arbitrary octets rather than text");
	check(plan && planfix_warned(plan, "deauthenticated and reconnects"),
	    "and the plan says what a restart costs, which hostapd having no reload makes "
	    "unavoidable");
	planfix_release(plan, document, observed);
}

/*
 * **The number this build would write, against the number in the file it
 * wrote.** An absent `channel` is hostapd's `channel=0` -- survey and choose
 * -- so the two are one statement. Comparing them as the document spells them
 * restarted an access point on every reconcile, for ever (0222).
 */
static void an_absent_channel_and_the_zero_it_writes_are_one_statement(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(RADIO, RADIO_INTERFACE, "", OPEN_POINT,
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN)),
	    &document, &observed);

	check(quiet(plan),
	    "an access point naming no channel, running `channel=0`, plans nothing");
	planfix_release(plan, document, observed);
}

/*
 * The other half, and the hole the first fix for the loop above opened. An
 * operator who deletes `channel = 36` to get automatic selection back must not
 * be left pinned to 36 with nothing in the plan to say the edit did not take.
 */
static void a_deleted_channel_is_still_an_edit(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(RADIO, RADIO_INTERFACE, "", OPEN_POINT,
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(",\"channel\":36,\"band\":\"5\"")),
	    &document, &observed);
	const ncfg_action_t *stop = plan ? planfix_action(plan, "backend.stop") : NULL;

	check(stop != NULL, "an access point pinned to 36 whose `channel` line went is restarted");
	check(stop && stop->reason.field &&
	    strcmp(stop->reason.field, "access_point.channel") == 0 &&
	    stop->reason.desired && strcmp(stop->reason.desired, "<absent>") == 0,
	    "and the reason says the channel is absent rather than printing a bare `0`");
	planfix_release(plan, document, observed);
}

/*
 * A band is derived before it is compared, for the channel's reason: an absent
 * `band` means "work it out from the channel", and the file records what was
 * worked out.
 */
static void a_band_worked_out_from_the_channel_is_not_a_change(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(RADIO, RADIO_INTERFACE, "",
	    POINT(",\"security\":{\"type\":\"open\"},\"channel\":36"),
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(",\"channel\":36,\"band\":\"5\"")),
	    &document, &observed);

	check(quiet(plan),
	    "an access point on channel 36 naming no band, running 5 GHz, plans nothing");
	planfix_release(plan, document, observed);
}

/*
 * And the hole the guard against that loop opened, which is the same shape as
 * the channel's. An access point with `band = "5"` and no channel whose `band`
 * line is then deleted means 2.4 GHz from that moment -- every radio has it,
 * and it is what an undeclared band with no channel to infer from resolves to.
 */
static void a_deleted_band_is_still_an_edit_and_names_the_band_it_moves_to(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(RADIO, RADIO_INTERFACE, "", OPEN_POINT,
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(",\"channel\":0,\"band\":\"5\"")),
	    &document, &observed);
	const ncfg_action_t *stop = plan ? planfix_action(plan, "backend.stop") : NULL;

	check(stop && stop->reason.field &&
	    strcmp(stop->reason.field, "access_point.band") == 0,
	    "an access point whose `band = \"5\"` line went is restarted");
	/* The Rust compares the derived band and then prints the *stated* one, so
	 * this reason is empty there. project.md records it. */
	check(stop && stop->reason.desired && strcmp(stop->reason.desired, "2.4") == 0,
	    "and the reason names the band it is moving to rather than an empty field");
	planfix_release(plan, document, observed);
}

/*
 * **The generation, which nothing else notices changing.** hostapd reads its
 * file once, so an access point started as WPA2 goes on offering WPA2 however
 * the document is edited -- and the secret comparison says nothing about it,
 * because changing `proto` with the same passphrase changes no secret.
 */
static void an_edited_generation_restarts_the_access_point(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(RADIO, RADIO_INTERFACE, "",
	    POINT(",\"security\":{\"type\":\"psk\",\"passphrase\":{\"provider\":\"file\","
	    "\"name\":\"home\"},\"proto\":\"wpa3\"}"),
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN ","
	    "\"key_mgmt\":\"WPA-PSK\"")), &document, &observed);
	const ncfg_action_t *stop = plan ? planfix_action(plan, "backend.stop") : NULL;

	check(stop && stop->reason.field &&
	    strcmp(stop->reason.field, "access_point.wifi.proto") == 0,
	    "a document that says WPA3 against a radio running WPA2 restarts it");
	check(stop && stop->reason.desired && strcmp(stop->reason.desired, "SAE") == 0,
	    "and names the generation as the renderer spells it, from the one function "
	    "that spells it");
	planfix_release(plan, document, observed);

	plan = planfix_plan(RADIO, RADIO_INTERFACE, "",
	    POINT(",\"security\":{\"type\":\"psk\",\"passphrase\":{\"provider\":\"file\","
	    "\"name\":\"home\"},\"proto\":\"wpa2\"}"),
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN ","
	    "\"key_mgmt\":\"WPA-PSK\"")), &document, &observed);
	check(quiet(plan), "and a document that agrees with it plans nothing");
	planfix_release(plan, document, observed);
}

/* Compared case-insensitively and printed upper case, which is what the
 * renderer writes: `se` against a file saying `SE` is the same access point. */
static void two_spellings_of_one_regulatory_domain_are_one_domain(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(RADIO, RADIO_INTERFACE, "",
	    POINT(",\"security\":{\"type\":\"open\"},\"regdom\":\"se\""),
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN ","
	    "\"regdom\":\"SE\"")), &document, &observed);
	const ncfg_action_t *stop;

	check(quiet(plan), "a document saying `se` and a file saying `SE` plan nothing");
	planfix_release(plan, document, observed);

	plan = planfix_plan(RADIO, RADIO_INTERFACE, "",
	    POINT(",\"security\":{\"type\":\"open\"},\"regdom\":\"us\""),
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN ","
	    "\"regdom\":\"SE\"")), &document, &observed);
	stop = plan ? planfix_action(plan, "backend.stop") : NULL;
	check(stop && stop->reason.field &&
	    strcmp(stop->reason.field, "access_point.regdom") == 0,
	    "while a domain that really moved restarts the access point");
	check(stop && stop->reason.desired && strcmp(stop->reason.desired, "US") == 0,
	    "and is printed upper case, which is the `country_code` that will be written");
	planfix_release(plan, document, observed);
}

static void a_hidden_network_that_stopped_being_hidden_restarts(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(RADIO, RADIO_INTERFACE, "", OPEN_POINT,
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN ","
	    "\"hidden\":true")), &document, &observed);
	const ncfg_action_t *stop = plan ? planfix_action(plan, "backend.stop") : NULL;

	check(stop && stop->reason.field &&
	    strcmp(stop->reason.field, "access_point.hidden") == 0,
	    "an access point that was started hidden and no longer is is restarted");
	planfix_release(plan, document, observed);
}

/*
 * The value is not here and must not be. What the observation carries is the
 * *answer*, computed where both halves were already in hand (0052) -- so the
 * reason names the field and nothing in the plan can print a passphrase.
 */
static void an_edited_passphrase_restarts_without_the_passphrase_reaching_the_plan(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(RADIO, RADIO_INTERFACE, "",
	    POINT(",\"security\":{\"type\":\"psk\",\"passphrase\":{\"provider\":\"file\","
	    "\"name\":\"home\"},\"proto\":\"wpa2\"}"),
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN ","
	    "\"key_mgmt\":\"WPA-PSK\"") ",\"secret_matches\":false"), &document, &observed);
	const ncfg_action_t *stop = plan ? planfix_action(plan, "backend.stop") : NULL;

	check(stop && stop->reason.field &&
	    strcmp(stop->reason.field, "access_point.wifi.psk") == 0,
	    "an access point holding a secret the store no longer has is restarted");
	check(plan && !planfix_mentions(plan, "home\","),
	    "and nothing anywhere in the plan is the secret or its file");
	planfix_release(plan, document, observed);

	plan = planfix_plan(RADIO, RADIO_INTERFACE, "",
	    POINT(",\"security\":{\"type\":\"psk\",\"passphrase\":{\"provider\":\"file\","
	    "\"name\":\"home\"},\"proto\":\"wpa2\"}"),
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN ","
	    "\"key_mgmt\":\"WPA-PSK\"") ",\"secret_matches\":true"), &document, &observed);
	check(quiet(plan), "and one still holding the store's plans nothing");
	planfix_release(plan, document, observed);
}

/*
 * With no record there is nothing to compare the document against, so an
 * edited identity plans nothing and hostapd goes on offering what it has --
 * which looks exactly like a converged machine. Said rather than passed over.
 */
static void an_access_point_netcfgd_has_no_record_for_is_said_rather_than_guessed_at(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(RADIO, RADIO_INTERFACE, "", OPEN_POINT,
	    "\"links\":[" UP_LINK "]," RUNNING(""), &document, &observed);

	check(plan && planfix_warned(plan, "has no record of what the access point running"),
	    "an access point netcfgd has no record of starting is reported");
	check(plan && !planfix_action(plan, "backend.stop"),
	    "and is not restarted on a guess about what it might be running");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * The restart and the station lists
 * ------------------------------------------------------------------------ */

/*
 * `macaddr_acl` cannot be changed over the control socket, so converging the
 * lists without a restart would enforce the new list under the old default: a
 * document changed from `deny` to `allow` would leave every unlisted station
 * accepted, reported as applied.
 */
static void a_policy_that_moved_restarts_rather_than_being_half_applied(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(RADIO, RADIO_INTERFACE, "",
	    POINT(",\"security\":{\"type\":\"open\"},\"access_control\":{\"policy\":\"allow\","
	    "\"stations\":[\"aa:bb:cc:dd:ee:01\"]}"),
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN)
	    ",\"access_control\":{\"policy\":{\"set\":\"deny\"},\"denied\":[],\"accepted\":[]}"),
	    &document, &observed);
	const ncfg_action_t *stop = plan ? planfix_action(plan, "backend.stop") : NULL;

	check(stop && stop->reason.field &&
	    strcmp(stop->reason.field, "access_point.access_control.policy") == 0,
	    "an access control policy the document moved restarts the access point");
	check(stop && stop->reason.desired && strcmp(stop->reason.desired, "allow") == 0 &&
	    stop->reason.observed && strcmp(stop->reason.observed, "deny") == 0,
	    "and the reason names both policies in the words the document uses");
	check(plan && !planfix_action(plan, "access_control.add"),
	    "and no station is enforced under the default the restart is replacing");
	planfix_release(plan, document, observed);
}

/*
 * Before the station lists, because a restart makes them moot: the access
 * point comes back with the whole configuration rebuilt, and converging a list
 * on a hostapd that is about to be replaced is work that fails or is undone.
 */
static void a_restarted_access_point_has_its_station_lists_left_alone(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(RADIO, RADIO_INTERFACE, "",
	    POINT(",\"security\":{\"type\":\"open\"},\"access_control\":{\"policy\":\"deny\","
	    "\"stations\":[\"aa:bb:cc:dd:ee:01\"]}"),
	    "\"links\":[" UP_LINK "]," RUNNING(",\"started_with\":{\"ssid\":\"6f6c64\"" AS_WRITTEN "}"
	    ",\"access_control\":{\"policy\":{\"set\":\"deny\"},\"denied\":[],\"accepted\":[]}"),
	    &document, &observed);

	check(plan && planfix_action(plan, "backend.stop"),
	    "an access point whose ssid moved is restarted although its lists differ too");
	check(plan && !planfix_action(plan, "access_control.add"),
	    "and nothing is added to the lists of a hostapd that is about to be replaced");
	planfix_release(plan, document, observed);
}

/*
 * One radio is one BSS in this build, and the one that runs is the first by
 * id. Without this the *second* access point on a radio compares its own
 * identity against what the first started with, finds a difference that is not
 * one, and restarts for ever.
 */
static void only_the_first_access_point_on_a_radio_is_restarted(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(RADIO, RADIO_INTERFACE, "",
	    ",\"access_points\":[{\"id\":\"a-first\",\"ssid\":\"686f6d65\",\"device\":\"wlan0\","
	    "\"security\":{\"type\":\"open\"}},"
	    "{\"id\":\"b-second\",\"ssid\":\"6f7468\",\"device\":\"wlan0\","
	    "\"security\":{\"type\":\"open\"}}]",
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN)),
	    &document, &observed);

	check(quiet(plan),
	    "the second access point on a radio does not restart the first's hostapd");
	/*
	 * **And it is said.** The block is read, kept and never started -- both
	 * halves at once needs a second virtual interface on the phy, which
	 * netcfgd does not create -- so a plan that quietly starts the first looks
	 * exactly like a plan that did everything asked of it.
	 *
	 * Said once, by the block that runs, naming the ones that do not: three
	 * blocks on one radio told three times would never say which one won.
	 */
	check(plan && planfix_warned(plan, "has more than one access point"),
	    "  and the one that will not run is said, rather than silently dropped");
	check(plan && planfix_warned(plan, "so `a-first` is started and `b-second` is not"),
	    "  naming which one runs and which does not");
	planfix_release(plan, document, observed);

	plan = planfix_plan(RADIO, RADIO_INTERFACE, "",
	    ",\"access_points\":[{\"id\":\"a-first\",\"ssid\":\"686f6d65\","
	    "\"device\":\"wlan0\",\"security\":{\"type\":\"open\"}}]",
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN)),
	    &document, &observed);
	check(plan && !planfix_warned(plan, "has more than one access point"),
	    "and one access point on a radio is the ordinary arrangement, so nothing is said");
	planfix_release(plan, document, observed);
}

/*
 * A DFS channel, where hostapd comes up and says nothing for a while.
 *
 * The radio has to listen before it may beacon, so everything netcfgd reports
 * says the access point is running while a scan finds nothing -- which is
 * exactly when somebody goes looking for a fault that is not there.
 */
static void an_access_point_that_has_to_listen_first_is_said(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(RADIO, RADIO_INTERFACE, "",
	    ",\"access_points\":[{\"id\":\"home\",\"ssid\":\"686f6d65\","
	    "\"device\":\"wlan0\",\"security\":{\"type\":\"open\"},\"channel\":52}]",
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN)), &document, &observed);

	check(plan && planfix_warned(plan, "shared with radar"),
	    "an access point on a DFS channel is said to be silent at first");
	check(plan && planfix_warned(plan, "Channels 36 to 48 and 149 upwards need no such wait"),
	    "  and told which channels do not wait");
	planfix_release(plan, document, observed);

	/* The bounds, from both ends of both ranges and one channel outside each.
	 * A range written as `>= 52 && <= 64` is one typo away from `> 52`, and a
	 * single sample in the middle cannot tell. */
	{
		static const int inside[] = { 52, 64, 100, 144 };
		static const int outside[] = { 48, 65, 99, 149 };
		size_t           at;
		unsigned         said = 0;
		unsigned         quiet_count = 0;

		for (at = 0; at < sizeof(inside) / sizeof(inside[0]); at++) {
			said += ncfg_channel_needs_radar_detection(inside[at]) ? 1u : 0u;
		}
		for (at = 0; at < sizeof(outside) / sizeof(outside[0]); at++) {
			quiet_count +=
			    ncfg_channel_needs_radar_detection(outside[at]) ? 0u : 1u;
		}
		check(said == 4u, "  the two DFS ranges include both of their ends");
		check(quiet_count == 4u, "  and the channels either side of them are not DFS");
	}

	plan = planfix_plan(RADIO, RADIO_INTERFACE, "",
	    ",\"access_points\":[{\"id\":\"home\",\"ssid\":\"686f6d65\","
	    "\"device\":\"wlan0\",\"security\":{\"type\":\"open\"},\"channel\":36}]",
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN)), &document, &observed);
	check(plan && !planfix_warned(plan, "shared with radar"),
	    "and one that beacons straight away is not");
	planfix_release(plan, document, observed);

	/* An absent channel is hostapd surveying and choosing, which this cannot
	 * answer for and must not warn about. */
	plan = planfix_plan(RADIO, RADIO_INTERFACE, "",
	    ",\"access_points\":[{\"id\":\"home\",\"ssid\":\"686f6d65\","
	    "\"device\":\"wlan0\",\"security\":{\"type\":\"open\"}}]",
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN)), &document, &observed);
	check(plan && !planfix_warned(plan, "shared with radar"),
	    "and an access point with no channel at all is hostapd's to choose, so nothing "
	    "is said");
	planfix_release(plan, document, observed);
}

/*
 * hostapd running is not an access point working.
 *
 * `an_access_point_on_a_device_with_no_interface_block_is_said` covers the
 * warning that tells an operator `interface wlan0 { }` is enough -- and it is,
 * enough to bring the radio up and start hostapd. Following it exactly plans
 * `link.up` and `backend.start` and no address, so the SSID beacons, a station
 * associates, and there is nothing on this end to talk to. netcfgd serves no
 * DHCP either, which is why the sentence has two halves.
 *
 * **The control is the addressed radio and it comes first**: a warning that
 * fired on every access point would tell nobody anything, and this one was
 * measured firing on a correct bridged arrangement when the Rust first wrote
 * it (0202).
 */
static void an_access_point_with_no_address_is_said(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(RADIO, ADDRESSED_RADIO, "", OPEN_POINT,
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN)), &document, &observed);

	check(plan && !planfix_warned(plan, "nothing here to talk to"),
	    "an access point whose interface has an address is not warned about");
	planfix_release(plan, document, observed);

	plan = planfix_plan(RADIO, RADIO_INTERFACE, "", OPEN_POINT,
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN)), &document, &observed);
	check(plan && planfix_warned(plan, "nothing here to talk to"),
	    "one with an empty `addressing` list is");
	check(plan && planfix_warned(plan, "serves no DHCP"),
	    "  and is told the half an address alone does not fix");
	planfix_release(plan, document, observed);

	/*
	 * **The bridged access point, which is the case that made this warning
	 * wrong once.** Its address belongs to the bridge, so the radio having
	 * none is the correct arrangement rather than the fault. Both spellings
	 * are checked, because a document may name members from the bridge or a
	 * master from the member and they mean the same thing.
	 */
	plan = planfix_plan(RADIO ",{\"name\":\"br0\",\"kind\":{\"kind\":\"bridge\","
	    "\"members\":[\"wlan0\"]}}",
	    RADIO_INTERFACE ",{\"name\":\"br0\",\"addressing\":[{\"source\":\"static\","
	    "\"address\":\"192.168.4.1/24\"}]}",
	    "", OPEN_POINT, "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN)),
	    &document, &observed);
	check(plan && !planfix_warned(plan, "nothing here to talk to"),
	    "and a bridged access point is not, because the address is the bridge's");
	planfix_release(plan, document, observed);

	plan = planfix_plan("{\"name\":\"wlan0\",\"kind\":{\"kind\":\"physical\"},"
	    "\"master\":\"br0\"},{\"name\":\"br0\",\"kind\":{\"kind\":\"bridge\"}}",
	    RADIO_INTERFACE, "", OPEN_POINT,
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN)), &document, &observed);
	check(plan && !planfix_warned(plan, "nothing here to talk to"),
	    "and neither is one whose own block names the master");
	planfix_release(plan, document, observed);
}

/*
 * An `allow` list with nothing in it.
 *
 * A legitimate thing to write -- it is how an access point is closed without
 * taking it down -- and an easy thing to arrive at by deleting the last
 * station from a list. It compiles either way, so the difference between the
 * two is said rather than refused.
 *
 * The control is the same block with a station in it, and a `deny` list with
 * none: an empty `deny` is "nobody is barred", which is what an access point
 * with no `access_control` block already means.
 */
static void an_empty_allow_list_is_said(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(RADIO, ADDRESSED_RADIO, "",
	    POINT(",\"security\":{\"type\":\"open\"},\"access_control\":{\"policy\":\"allow\","
	          "\"stations\":[]}"),
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN)), &document, &observed);

	check(plan && planfix_warned(plan, "empty `allow` list"),
	    "an empty allow list is said to shut everybody out");
	check(plan && planfix_warned(plan, "Remove the `access_control` block"),
	    "  and told what to do about it");
	planfix_release(plan, document, observed);

	plan = planfix_plan(RADIO, ADDRESSED_RADIO, "",
	    POINT(",\"security\":{\"type\":\"open\"},\"access_control\":{\"policy\":\"allow\","
	          "\"stations\":[\"aa:bb:cc:dd:ee:ff\"]}"),
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN)), &document, &observed);
	check(plan && !planfix_warned(plan, "empty `allow` list"),
	    "and one with a station in it is not");
	planfix_release(plan, document, observed);

	plan = planfix_plan(RADIO, ADDRESSED_RADIO, "",
	    POINT(",\"security\":{\"type\":\"open\"},\"access_control\":{\"policy\":\"deny\","
	          "\"stations\":[]}"),
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN)), &document, &observed);
	check(plan && !planfix_warned(plan, "empty `allow` list"),
	    "and an empty `deny` list bars nobody, which is not the same thing");
	planfix_release(plan, document, observed);
}

/*
 * A radio joining networks cannot be a bridge port (0202).
 *
 * **Two opposite arrangements that both put a radio in a bridge**, and the
 * whole of the difference is which end holds the associations. The serving end
 * is fine and is the ordinary way to put wireless clients on the wired subnet;
 * the joining end cannot work, because a station associates in 802.11's
 * three-address mode.
 *
 * So the control is the same bridge with an `access_point` on the member, and
 * it is the case the condition is actually about: a test that only showed the
 * warning firing would pass on a build that warned about every radio in every
 * bridge.
 */
static void a_station_radio_in_a_bridge_is_said(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan;

#define BRIDGED_RADIO \
	"{\"name\":\"wlan0\",\"kind\":{\"kind\":\"physical\"},\"managed\":true," \
	"\"wifi\":{}},{\"name\":\"br0\",\"kind\":{\"kind\":\"bridge\"," \
	"\"members\":[\"wlan0\"]}}"

	plan = planfix_plan(BRIDGED_RADIO, RADIO_INTERFACE, "", "",
	    "\"links\":[" UP_LINK "]", &document, &observed);
	check(plan && planfix_warned(plan, "is a radio joining networks"),
	    "a station radio in a bridge is warned about");
	check(plan && planfix_warned(plan, "Four-address mode"),
	    "  and told what does bridge one");
	planfix_release(plan, document, observed);

	plan = planfix_plan(BRIDGED_RADIO, RADIO_INTERFACE, "", OPEN_POINT,
	    "\"links\":[" UP_LINK "]," RUNNING(STARTED_WITH(AS_WRITTEN)), &document, &observed);
	check(plan && !planfix_warned(plan, "is a radio joining networks"),
	    "and the serving end of the same bridge is not, because it is not a station");
	planfix_release(plan, document, observed);

	/* And an interface the kernel says is not wireless, which is the other
	 * half of the two-facts-from-two-places rule: a `wifi { }` block is not a
	 * statement that the interface IS a radio. */
	plan = planfix_plan(BRIDGED_RADIO, RADIO_INTERFACE, "", "",
	    "\"links\":[" PLANFIX_LINK("wlan0", "") "]", &document, &observed);
	check(plan && !planfix_warned(plan, "is a radio joining networks"),
	    "and a bridge member the kernel does not call wireless is not warned about");
	planfix_release(plan, document, observed);
#undef BRIDGED_RADIO
}

int main(void)
{
	a_radio_the_document_gives_an_access_point_starts_hostapd();
	the_addressing_waits_for_the_access_point();
	hostapd_that_is_already_running_is_not_started_again();
	a_port_that_authenticates_takes_the_supplicant_and_not_hostapd();
	an_access_point_on_a_device_with_no_interface_block_is_said();
	an_access_point_that_will_not_stay_up_stops_being_started();
	hostapd_the_document_stopped_naming_is_stopped();
	hostapd_the_document_still_names_is_left_alone();
	an_edited_ssid_restarts_the_access_point();
	an_absent_channel_and_the_zero_it_writes_are_one_statement();
	a_deleted_channel_is_still_an_edit();
	a_band_worked_out_from_the_channel_is_not_a_change();
	a_deleted_band_is_still_an_edit_and_names_the_band_it_moves_to();
	an_edited_generation_restarts_the_access_point();
	two_spellings_of_one_regulatory_domain_are_one_domain();
	a_hidden_network_that_stopped_being_hidden_restarts();
	an_edited_passphrase_restarts_without_the_passphrase_reaching_the_plan();
	an_access_point_netcfgd_has_no_record_for_is_said_rather_than_guessed_at();
	a_policy_that_moved_restarts_rather_than_being_half_applied();
	a_restarted_access_point_has_its_station_lists_left_alone();
	only_the_first_access_point_on_a_radio_is_restarted();
	an_access_point_that_has_to_listen_first_is_said();
	an_access_point_with_no_address_is_said();
	an_empty_allow_list_is_said();
	a_station_radio_in_a_bridge_is_said();

	printf("plan access point: %d checks, %d failed\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
