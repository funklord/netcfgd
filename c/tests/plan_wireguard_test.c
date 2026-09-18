/*
 * plan_wireguard_test.c -- the device's own settings and its peer list.
 *
 * WHAT THESE ARE FOR
 *   The kernel reports the port, the mark and every peer for free on the
 *   request that answers "is a private key loaded", and netcfgd threw all of
 *   it away for as long as WireGuard has existed here -- so an edited port and
 *   a **deleted peer** each planned nothing at all (0054). Half the cases
 *   below are that; the other half are the ways a comparison that noticed too
 *   much would replace the peer list of a working tunnel on every reconcile.
 *
 *   **Nothing secret may appear in a plan**, which is constraint 5 and is
 *   checked here rather than assumed: a plan goes to `/run` and over the
 *   control socket, and the two questions that are about secrets are answered
 *   by the observer as booleans. `planfix_mentions` is what says the op
 *   carries a reference and the reason carries a sentence.
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

/* Thirty-two octets of 0x01 and of 0x02, which is all a public key has to be
 * here: it identifies a peer and is not secret. */
#define PEER_ONE "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
#define PEER_TWO "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="

#define WG_DEVICE(body) \
	"{\"name\":\"wg0\",\"kind\":{\"kind\":\"wire_guard\"," \
	"\"private_key\":{\"provider\":\"keyring\",\"name\":\"wg\"}," body "}}"
#define WG_LINK(body) \
	PLANFIX_LINK("wg0", ",\"kind\":\"wireguard\",\"private_key_loaded\":true," \
	"\"wireguard\":{" body "}")

static ncfg_plan_t *one(const char *device, const char *observation,
    ncfg_document_t **document, ncfg_observed_t **observed)
{
	return planfix_plan(device, "", "", "", observation, document, observed);
}

static int quiet(const ncfg_plan_t *plan)
{
	char names[512];

	if (ncfg_plan_is_empty(plan)) {
		return 1;
	}
	planfix_names(plan, names, sizeof(names));
	printf("  expected nothing to do; the plan is [%s]\n", names);
	return 0;
}

/* ------------------------------------------------------------------------ *
 * The device
 * ------------------------------------------------------------------------ */

static void an_edited_listen_port_is_corrected_and_can_be_put_back(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = one(WG_DEVICE("\"listen_port\":51821,\"peers\":[]"),
	    "\"links\":[" WG_LINK("\"listen_port\":51820,\"peers\":[]") "]",
	    &document, &observed);
	const ncfg_action_t *action = plan ?
	    planfix_for_field(plan, "wg.set_device", "wireguard.listen_port") : NULL;

	check(action != NULL, "an edited listen port plans wg.set_device");
	check(action && action->has_inverse &&
	    action->inverse.u.wg_device.listen_port.has &&
	    action->inverse.u.wg_device.listen_port.value == 51820,
	    "and the inverse puts back the port the observation was read from");
	check(action && action->op.u.wg_device.private_key_ref &&
	    strcmp(action->op.u.wg_device.private_key_ref, "wg") == 0,
	    "and the op carries the secret's name, never a key");
	planfix_release(plan, document, observed);
}

/*
 * A port the document does not state is the kernel's to choose.
 *
 * 0052's trap, which restarted an access point on every reconcile until the
 * document's silence was read as silence. A document saying nothing against a
 * kernel that chose 51820 is agreement.
 */
static void a_port_the_document_does_not_state_is_agreement(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(WG_DEVICE("\"peers\":[]"),
	    "\"links\":[" WG_LINK("\"listen_port\":51820,\"fwmark\":7,\"peers\":[]") "]",
	    &document, &observed);

	check(plan && quiet(plan),
	    "a port and a mark the document does not state are the kernel's to choose");
	planfix_release(plan, document, observed);
}

/*
 * Zero is how a document asks for an ephemeral port, and the kernel answers
 * with the one it chose. So a `listen_port = 0` has to arrive at the
 * comparison the same way an absent one does, or it differs for ever.
 */
static void a_listen_port_of_zero_means_let_the_kernel_choose(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(WG_DEVICE("\"listen_port\":0,\"peers\":[]"),
	    "\"links\":[" WG_LINK("\"listen_port\":51820,\"peers\":[]") "]",
	    &document, &observed);

	check(plan && quiet(plan), "`listen_port = 0` against a chosen port is agreement");
	planfix_release(plan, document, observed);
}

/*
 * A rotated private key is noticed through the observer's answer, and the plan
 * says which way it went without printing anything.
 */
static void a_rotated_private_key_is_noticed_and_never_printed(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = one(WG_DEVICE("\"peers\":[]"),
	    "\"links\":[" WG_LINK("\"key_matches\":false,\"peers\":[]") "]",
	    &document, &observed);
	const ncfg_action_t *action = plan ?
	    planfix_for_field(plan, "wg.set_device", "wireguard.private_key") : NULL;

	check(action != NULL, "a private key the store has rotated plans wg.set_device");
	check(action && action->reason.desired &&
	    strcmp(action->reason.desired, "the secret store's") == 0,
	    "and the reason is an answer rather than either value");
	planfix_release(plan, document, observed);
}

/* Absent is not false: a device netcfgd did not configure, and a secret that
 * will not resolve, both leave the question unanswered -- and an unanswered
 * question is not a reason to rekey a working tunnel. */
static void an_unanswered_key_question_rekeys_nothing(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(WG_DEVICE("\"peers\":[]"),
	    "\"links\":[" WG_LINK("\"peers\":[]") "]", &document, &observed);

	check(plan && quiet(plan), "an unanswered `key_matches` rekeys nothing");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * The peers
 * ------------------------------------------------------------------------ */

#define DOC_PEER(key, ips) \
	"{\"name\":\"hub\",\"public_key\":\"" key "\",\"allowed_ips\":[" ips "]}"
#define SEEN_PEER(key, body) "{\"public_key\":\"" key "\"," body "}"

/* The defect 0054 is about: a peer deleted from the document planned nothing
 * at all, on a tunnel that looked configured. */
static void a_deleted_peer_is_noticed(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = one(
	    WG_DEVICE("\"peers\":[" DOC_PEER(PEER_ONE, "\"10.0.0.0/24\"") "]"),
	    "\"links\":[" WG_LINK("\"peers\":["
	    SEEN_PEER(PEER_ONE, "\"preshared_key\":false,\"allowed_ips\":[\"10.0.0.0/24\"]") ","
	    SEEN_PEER(PEER_TWO, "\"preshared_key\":false,\"allowed_ips\":[\"10.0.1.0/24\"]")
	    "]") "]", &document, &observed);
	const ncfg_action_t *action = plan ?
	    planfix_for_field(plan, "wg.set_peers", "wireguard.peers") : NULL;

	check(action != NULL, "a peer the document no longer names plans wg.set_peers");
	check(action && action->reason.observed && strstr(action->reason.observed, PEER_TWO),
	    "and the reason names which peers the kernel holds");
	planfix_release(plan, document, observed);
}

/*
 * A peer roams and the kernel rewrites its endpoint from the packets it
 * receives, so the endpoint is not part of the comparison. Leaving it in made
 * every peer that has ever handshaken differ for ever -- and the Rust's live
 * test could not see it, because its peers have no endpoint and so agreed for
 * the wrong reason.
 */
static void a_peer_that_has_roamed_is_still_the_same_peer(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(
	    WG_DEVICE("\"peers\":[{\"name\":\"hub\",\"public_key\":\"" PEER_ONE "\","
	    "\"endpoint\":\"vpn.example:51820\",\"allowed_ips\":[\"10.0.0.0/24\"]}]"),
	    "\"links\":[" WG_LINK("\"peers\":[" SEEN_PEER(PEER_ONE,
	    "\"preshared_key\":false,\"endpoint\":\"198.51.100.7:41234\","
	    "\"allowed_ips\":[\"10.0.0.0/24\"]") "]") "]", &document, &observed);

	check(plan && quiet(plan), "a peer whose endpoint the kernel rewrote plans nothing");
	planfix_release(plan, document, observed);
}

/*
 * The prefixes are canonicalised and sorted on both sides.
 *
 * The kernel prints its own spelling and in its own order; the operator writes
 * theirs. Comparing the two as written is 10.169's defect in a second place,
 * and it would replace the peer list of a working tunnel for ever.
 */
static void allowed_prefixes_are_compared_as_addresses_and_in_one_order(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(
	    WG_DEVICE("\"peers\":[" DOC_PEER(PEER_ONE,
	    "\"2001:0DB8:0000::/64\",\"10.0.0.0/24\"") "]"),
	    "\"links\":[" WG_LINK("\"peers\":[" SEEN_PEER(PEER_ONE,
	    "\"preshared_key\":false,\"allowed_ips\":[\"10.0.0.0/24\",\"2001:db8::/64\"]")
	    "]") "]", &document, &observed);

	check(plan && quiet(plan),
	    "prefixes in another spelling and another order are the same prefixes");
	planfix_release(plan, document, observed);

	plan = one(WG_DEVICE("\"peers\":[" DOC_PEER(PEER_ONE,
	    "\"10.0.0.0/24\",\"10.0.2.0/24\"") "]"),
	    "\"links\":[" WG_LINK("\"peers\":[" SEEN_PEER(PEER_ONE,
	    "\"preshared_key\":false,\"allowed_ips\":[\"10.0.0.0/24\"]") "]") "]",
	    &document, &observed);
	check(plan && planfix_for_field(plan, "wg.set_peers", "wireguard.peers"),
	    "and a prefix that is genuinely new is still noticed");
	planfix_release(plan, document, observed);
}

/* A peer with no keepalive reports 0, and a document saying 0 means the same
 * thing -- so the two have to arrive at the comparison the same way. */
static void a_keepalive_of_zero_is_no_keepalive(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(
	    WG_DEVICE("\"peers\":[{\"name\":\"hub\",\"public_key\":\"" PEER_ONE "\","
	    "\"allowed_ips\":[],\"keepalive\":0}]"),
	    "\"links\":[" WG_LINK("\"peers\":[" SEEN_PEER(PEER_ONE,
	    "\"preshared_key\":false,\"allowed_ips\":[]") "]") "]", &document, &observed);

	check(plan && quiet(plan), "`keepalive = 0` and no keepalive are the same thing");
	planfix_release(plan, document, observed);
}

/*
 * A rotated preshared key is not a difference between the two lists -- both
 * say "this peer has one" -- so it is asked separately, and the answer is the
 * observer's. What it produces is the same op, because the kernel takes a peer
 * list: replacing one peer means sending the list.
 */
static void a_rotated_preshared_key_replaces_the_list_and_names_the_peer(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = one(
	    WG_DEVICE("\"peers\":[{\"name\":\"hub\",\"public_key\":\"" PEER_ONE "\","
	    "\"preshared_key\":{\"provider\":\"pass\",\"name\":\"psk\"},"
	    "\"allowed_ips\":[]}]"),
	    "\"links\":[" WG_LINK("\"peers\":[" SEEN_PEER(PEER_ONE,
	    "\"preshared_key\":true,\"preshared_matches\":false,\"allowed_ips\":[]") "]") "]",
	    &document, &observed);
	const ncfg_action_t *action = plan ?
	    planfix_for_field(plan, "wg.set_peers", "wireguard.peers.preshared_key") : NULL;

	check(action != NULL, "a rotated preshared key plans wg.set_peers");
	check(action && action->reason.observed && strstr(action->reason.observed, PEER_ONE),
	    "and the reason names the peer by its public key");
	check(plan && !planfix_mentions(plan, "psk"),
	    "and the secret's own name is not in the sentence");
	planfix_release(plan, document, observed);
}

/* A preshared key netcfgd could not compare is not a reason to replace a peer
 * list either. */
static void an_unanswered_preshared_question_replaces_nothing(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(
	    WG_DEVICE("\"peers\":[{\"name\":\"hub\",\"public_key\":\"" PEER_ONE "\","
	    "\"preshared_key\":{\"provider\":\"pass\",\"name\":\"psk\"},"
	    "\"allowed_ips\":[]}]"),
	    "\"links\":[" WG_LINK("\"peers\":[" SEEN_PEER(PEER_ONE,
	    "\"preshared_key\":true,\"allowed_ips\":[]") "]") "]", &document, &observed);

	check(plan && quiet(plan), "an unanswered `preshared_matches` replaces nothing");
	planfix_release(plan, document, observed);
}

/* The peers are sorted by the one field both sides have, so the kernel's own
 * order -- which is the order it happens to hold them in -- is not a
 * difference. */
static void the_kernels_peer_order_is_not_a_difference(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(
	    WG_DEVICE("\"peers\":[{\"name\":\"b-later\",\"public_key\":\"" PEER_TWO "\","
	    "\"allowed_ips\":[]},{\"name\":\"a-first\",\"public_key\":\"" PEER_ONE "\","
	    "\"allowed_ips\":[]}]"),
	    "\"links\":[" WG_LINK("\"peers\":["
	    SEEN_PEER(PEER_ONE, "\"preshared_key\":false,\"allowed_ips\":[]") ","
	    SEEN_PEER(PEER_TWO, "\"preshared_key\":false,\"allowed_ips\":[]") "]") "]",
	    &document, &observed);

	check(plan && quiet(plan), "neither side's order is a difference: both are sorted by the one shared field");
	planfix_release(plan, document, observed);
}

/* Nothing is planned for a WireGuard device the observation says nothing
 * about: the kind pass reads the kernel's answer, and there is none. */
static void a_device_the_kernel_has_not_answered_for_plans_nothing(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(WG_DEVICE("\"listen_port\":51821,\"peers\":[]"),
	    "\"links\":[" PLANFIX_LINK("wg0", ",\"kind\":\"wireguard\"") "]",
	    &document, &observed);

	check(plan && !planfix_action(plan, "wg.set_device"),
	    "a WireGuard device the kernel has not answered for is not corrected");
	planfix_release(plan, document, observed);
}

int main(void)
{
	an_edited_listen_port_is_corrected_and_can_be_put_back();
	a_port_the_document_does_not_state_is_agreement();
	a_listen_port_of_zero_means_let_the_kernel_choose();
	a_rotated_private_key_is_noticed_and_never_printed();
	an_unanswered_key_question_rekeys_nothing();
	a_deleted_peer_is_noticed();
	a_peer_that_has_roamed_is_still_the_same_peer();
	allowed_prefixes_are_compared_as_addresses_and_in_one_order();
	a_keepalive_of_zero_is_no_keepalive();
	a_rotated_preshared_key_replaces_the_list_and_names_the_peer();
	an_unanswered_preshared_question_replaces_nothing();
	the_kernels_peer_order_is_not_a_difference();
	a_device_the_kernel_has_not_answered_for_plans_nothing();

	printf("plan_wireguard_test: %d checks, %d failed\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
