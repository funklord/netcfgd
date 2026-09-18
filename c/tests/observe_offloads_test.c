/*
 * observe_offloads_test.c -- which driver offloads each interface has on.
 *
 * WHAT THIS IS FOR
 *   `plan/offload.c` has been able to correct an offload the driver disagrees
 *   with since the `ethtool` block existed, and on every machine it did the
 *   same thing on every pass: nothing filled `ncfg_observed_link_t.offloads`,
 *   so the comparison was against an empty list, `link.set_offloads` was
 *   planned for ever, and the op's *inverse* -- built out of that same list --
 *   would have turned every named feature off rather than putting back what
 *   was there.
 *
 *   So the last case here is the one this pass exists for, and it is asserted
 *   in **both** directions: a machine whose offloads already agree plans
 *   nothing, and the same machine observed without the seam plans the op. A
 *   convergence check with only the quiet half passes just as loudly over a
 *   planner that stopped planning anything at all.
 *
 * WHY THE PLANNER IS IN A TEST ABOUT THE OBSERVER
 *   `plan_tc_test.c` already checks that offloads which agree plan nothing --
 *   against an observation a fixture wrote by hand. That proves the planner,
 *   and it is exactly the check that went on passing through every wave in
 *   which no machine ever produced such an observation. What is new here is
 *   the join: kernel bytes, through the observer, into the planner, with
 *   nobody hand-writing the list in the middle. That is the property that was
 *   false, and it cannot be checked on either side alone.
 *
 * THE SPELLINGS ARE NOT WRITTEN DOWN HERE EITHER
 *   Every feature name a case expects comes from `ncfg_offload_field_names`,
 *   which is the model's table and the one thing the planner and the observer
 *   have to agree about. A test that spelled `rx-gro` itself would be a third
 *   copy of the list, and would go on passing if the model's changed -- which
 *   is the entire failure this table was moved out of `src/plan/` to prevent.
 *   The names a device reports that netcfgd does **not** manage are literals,
 *   because their whole point is to be outside the model.
 *
 * NO KERNEL IN HERE, BAR THE ONE CHECK THAT SAYS SO
 *   `collect_test.c`'s arrangement, unchanged: this suite runs on the
 *   workstation netcfgd configures, so every exchange below is a replay over
 *   bytes this file wrote and nothing opens a socket, reads a file or writes
 *   one. The single exception is `the_live_check`, which is behind
 *   `NCFG_OBSERVE_LIVE=1`, sends nothing but `GET`s, and is the only thing in
 *   the suite that can say whether the model's feature names are the kernel's.
 */
#include "planfix.h"

#include "ncfg/ethtool.h"
#include "ncfg/genl.h"
#include "ncfg/netlink.h"
#include "ncfg/observe.h"
#include "ncfg/wire.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/genetlink.h>
#include <linux/netlink.h>

static int failures;
static int checks;

static int check(int condition, const char *what)
{
	checks++;
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
	return condition;
}

static void detail(const char *what, const char *value)
{
	printf("  %s: %s\n", what, value ? value : "(none)");
}

/* The runtime id this file's controller hands out for `ethtool`. Any number
 * but zero: `ncfg_genl_build_request` refuses that one, which is what makes a
 * controller reply nobody parsed look like a malformed request instead. */
#define ETHTOOL_FAMILY_ID 23u

/* ------------------------------------------------------------------------ *
 * The names, taken from the model rather than spelled again
 * ------------------------------------------------------------------------ */

/* The first feature name of one offload field, or NULL. Every expectation
 * below is built out of this, so the model's table is the only place any of
 * these strings exists. */
static const char *name_of(int field)
{
	size_t             count = 0;
	const char *const *names = ncfg_offload_field_names(field, &count);

	return (names && count > 0) ? names[0] : NULL;
}

/* The list a link carries, joined, so a mismatch prints readably. */
static void joined(const ncfg_observed_link_t *link, char *out, size_t out_size)
{
	size_t at;
	size_t length = 0;

	out[0] = '\0';
	for (at = 0; link && at < link->offload_count && length < out_size; at++) {
		length += (size_t)snprintf(out + length, out_size - length, "%s%s",
		    length ? " " : "", link->offloads[at] ? link->offloads[at] : "(null)");
	}
}

static int carries(const ncfg_observed_t *observed, const char *device, const char *expected)
{
	const ncfg_observed_link_t *link = ncfg_observed_link(observed, device);
	char                        written[256];

	joined(link, written, sizeof(written));
	if (strcmp(written, expected) == 0) {
		return 1;
	}
	printf("  %s carries [%s]; expected [%s]\n", device, written, expected);
	return 0;
}

/* ------------------------------------------------------------------------ *
 * The bytes an ethtool kernel would send
 * ------------------------------------------------------------------------ */

static void append_message(ncfg_buf_t *out, uint16_t kind, const ncfg_buf_t *body)
{
	ncfg_buf_t one;

	ncfg_buf_init(&one, 0);
	if (!ncfg_wire_build_request(&one, kind, 0, 0, body, NULL, NULL, 0)) {
		out->failed = 1;
	} else {
		ncfg_buf_add(out, one.data, one.length);
	}
	ncfg_buf_free(&one);
}

/* What the controller answers a `GETFAMILY` for `ethtool` with. */
static void append_family(ncfg_buf_t *out, const char *name, uint16_t id)
{
	ncfg_genl_header_t header;
	ncfg_buf_t         payload;

	header.cmd = CTRL_CMD_NEWFAMILY;
	header.version = 2;
	ncfg_buf_init(&payload, 0);
	ncfg_genl_header_encode(&header, &payload);
	ncfg_wire_attr_put(&payload, CTRL_ATTR_FAMILY_ID, &id, sizeof(id));
	ncfg_wire_attr_put_str(&payload, CTRL_ATTR_FAMILY_NAME, name);
	append_message(out, GENL_ID_CTRL, &payload);
	ncfg_buf_free(&payload);
}

/*
 * One `FEATURES_GET` reply.
 *
 * `count` of 0 writes the message the kernel sends about a device it has more
 * to say about than fits one: a header and no active set, which adds nothing
 * and is not a failure.
 *
 * The bitset carries `NOMASK` because `ACTIVE` is a **list** -- a bit that
 * appears is on. `ethtool.h` spends a paragraph on what reading the other form
 * as a list would mean, and `ethtool_test.c` drives it; what matters here is
 * that this fixture writes the form a kernel writes.
 */
static void append_features(ncfg_buf_t *out, const char *device, const char *const *names,
    size_t count, int with_active)
{
	ncfg_genl_header_t header;
	ncfg_buf_t         payload;
	ncfg_buf_t         nest;
	ncfg_buf_t         bitset;
	ncfg_buf_t         bits;
	size_t             at;

	header.cmd = ETHTOOL_MSG_FEATURES_GET_REPLY;
	header.version = 1;
	ncfg_buf_init(&payload, 0);
	ncfg_genl_header_encode(&header, &payload);
	ncfg_buf_init(&nest, 0);
	ncfg_wire_attr_put_str(&nest, ETHTOOL_A_HEADER_DEV_NAME, device);
	ncfg_wire_attr_put_nested(&payload, ETHTOOL_A_FEATURES_HEADER, &nest);
	if (with_active) {
		ncfg_buf_init(&bits, 0);
		for (at = 0; at < count; at++) {
			ncfg_buf_t bit;

			ncfg_buf_init(&bit, 0);
			ncfg_wire_attr_put_str(&bit, ETHTOOL_A_BITSET_BIT_NAME, names[at]);
			ncfg_wire_attr_put_nested(&bits, ETHTOOL_A_BITSET_BITS_BIT, &bit);
			ncfg_buf_free(&bit);
		}
		ncfg_buf_init(&bitset, 0);
		ncfg_wire_attr_put(&bitset, ETHTOOL_A_BITSET_NOMASK, NULL, 0);
		ncfg_wire_attr_put_nested(&bitset, ETHTOOL_A_BITSET_BITS, &bits);
		ncfg_wire_attr_put_nested(&payload, ETHTOOL_A_FEATURES_ACTIVE, &bitset);
		ncfg_buf_free(&bits);
		ncfg_buf_free(&bitset);
	}
	append_message(out, ETHTOOL_FAMILY_ID, &payload);
	ncfg_buf_free(&nest);
	ncfg_buf_free(&payload);
}

/* An `NLMSG_ERROR`: the negated errno, then the header of the request that drew
 * it. `EOPNOTSUPP` is what a device with no ethtool operations answers, which
 * is most virtual interfaces. */
static void append_error(ncfg_buf_t *out, int32_t code)
{
	ncfg_buf_t         body;
	ncfg_wire_header_t original;
	uint32_t           bits;
	int32_t            negated = -code;

	ncfg_buf_init(&body, 0);
	memcpy(&bits, &negated, sizeof(bits));
	ncfg_buf_add(&body, &bits, sizeof(bits));
	memset(&original, 0, sizeof(original));
	original.len = NCFG_WIRE_NLMSG_HDR_LEN;
	original.kind = ETHTOOL_FAMILY_ID;
	ncfg_wire_header_encode(&original, &body);
	append_message(out, NLMSG_ERROR, &body);
	ncfg_buf_free(&body);
}

/* ------------------------------------------------------------------------ *
 * The fake datagram source
 * ------------------------------------------------------------------------ */

#define QUEUED_MAX 8u

typedef struct {
	const uint8_t *bytes;
	size_t         length;
} queued_t;

typedef struct {
	queued_t at[QUEUED_MAX];
	size_t   count;
	size_t   next;
} script_t;

static ssize_t script_recv(void *context, void *bytes, size_t length, int peek, uint32_t *from)
{
	script_t       *script = context;
	const queued_t *one;
	size_t          copy;

	*from = UINT32_MAX;
	if (script->next >= script->count) {
		errno = EAGAIN;
		return -1;
	}
	one = &script->at[script->next];
	*from = 0u;
	copy = one->length < length ? one->length : length;
	if (copy) {
		memcpy(bytes, one->bytes, copy);
	}
	if (peek) {
		return (ssize_t)one->length;
	}
	script->next++;
	return (ssize_t)one->length;
}

static void queue(script_t *script, const ncfg_buf_t *buffer)
{
	if (script->count < QUEUED_MAX) {
		script->at[script->count].bytes = (const uint8_t *)buffer->data;
		script->at[script->count].length = buffer->length;
		script->count++;
	}
}

static void kernel_of(ncfg_observe_kernel_t *kernel, ncfg_observe_replay_t *replay,
    script_t *script)
{
	memset(replay, 0, sizeof(*replay));
	replay->recv = script_recv;
	replay->context = script;
	memset(kernel, 0, sizeof(*kernel));
	kernel->exchange = ncfg_observe_exchange_replay;
	kernel->context = replay;
}

/* ------------------------------------------------------------------------ *
 * One machine: two interfaces, in the order an observation sorts them
 * ------------------------------------------------------------------------ */

#define MACHINE \
	"\"links\":[" \
	PLANFIX_LINK("eth0", "") "," \
	PLANFIX_LINK("eth1", ",\"kind\":\"veth\"") "]"

/* The same, with a list already on `eth0`, so a case can tell "nothing was
 * read" from "what was there was left alone". */
#define MACHINE_WITH_STALE_LIST \
	"\"links\":[" \
	PLANFIX_LINK("eth0", ",\"offloads\":[\"rx-gro\"]") "," \
	PLANFIX_LINK("eth1", ",\"kind\":\"veth\"") "]"

/* ------------------------------------------------------------------------ *
 * The cases
 * ------------------------------------------------------------------------ */

/*
 * What a device reports, filtered to what the model can say.
 *
 * A driver offers dozens of features and `observed.h` says why storing them
 * all would be a page of driver detail in `/run` for five fields. The three
 * unmanaged names here are literals on purpose: their whole point is to be
 * outside `ncfg_offload_field_names`, so deriving them from it would be
 * deriving the thing under test.
 */
static void only_the_offloads_the_model_can_express(void)
{
	script_t              script;
	ncfg_observe_replay_t replay;
	ncfg_observe_kernel_t kernel;
	ncfg_buf_t            family;
	ncfg_buf_t            first;
	ncfg_buf_t            second;
	ncfg_observed_t      *observed = planfix_observed(MACHINE);
	const char           *reported[5];
	char                  expected[128];
	char                  err[NCFG_ERROR_MAX];

	if (!check(observed != NULL, "the machine reads")) {
		return;
	}
	reported[0] = "tx-scatter-gather";
	reported[1] = name_of(NCFG_OFFLOAD_TX_CHECKSUM);
	reported[2] = "rx-vlan-hw-parse";
	reported[3] = name_of(NCFG_OFFLOAD_GRO);
	reported[4] = "rx-hashing";

	memset(&script, 0, sizeof(script));
	ncfg_buf_init(&family, 0);
	ncfg_buf_init(&first, 0);
	ncfg_buf_init(&second, 0);
	append_family(&family, NCFG_ETHTOOL_FAMILY, ETHTOOL_FAMILY_ID);
	append_features(&first, "eth0", reported, 5u, 1);
	append_features(&second, "eth1", NULL, 0u, 1);
	queue(&script, &family);
	queue(&script, &first);
	queue(&script, &second);
	kernel_of(&kernel, &replay, &script);

	err[0] = '\0';
	if (check(ncfg_observe_offloads_from(&kernel, observed, err, sizeof(err)),
	    "a round of ethtool requests fills in what each interface has on")) {
		/* Sorted, because `ncfg_ethtool_names_t` inserts in order -- which is
		 * not tidiness: the planner searches the list rather than comparing
		 * it, but two observations of one machine have to compare equal or
		 * `ncfg status --json` changes on every tick. */
		(void)snprintf(expected, sizeof(expected), "%s %s", name_of(NCFG_OFFLOAD_GRO),
		    name_of(NCFG_OFFLOAD_TX_CHECKSUM));
		check(carries(observed, "eth0", expected),
		    "the two the model manages are kept, sorted");
		check(carries(observed, "eth1", ""),
		    "and a device with nothing on carries nothing");
	} else {
		detail("it said", err);
	}
	ncfg_observed_free(observed);
	ncfg_buf_free(&family);
	ncfg_buf_free(&first);
	ncfg_buf_free(&second);
}

/*
 * The kernel answers about one device in more than one message.
 *
 * Only one of them carries the active set, which is why a message without one
 * adds nothing rather than failing -- and why the messages that do have to be
 * folded rather than the first one taken. A repeat across two of them is the
 * `dedup` the Rust has for the same reason.
 */
static void several_messages_about_one_device_fold_into_one_list(void)
{
	script_t              script;
	ncfg_observe_replay_t replay;
	ncfg_observe_kernel_t kernel;
	ncfg_buf_t            family;
	ncfg_buf_t            first;
	ncfg_buf_t            second;
	ncfg_observed_t      *observed = planfix_observed(MACHINE);
	const char           *early[2];
	const char           *late[2];
	char                  expected[192];
	char                  err[NCFG_ERROR_MAX];

	if (!check(observed != NULL, "the machine reads")) {
		return;
	}
	early[0] = name_of(NCFG_OFFLOAD_TSO);
	early[1] = name_of(NCFG_OFFLOAD_GRO);
	late[0] = name_of(NCFG_OFFLOAD_GRO);
	late[1] = name_of(NCFG_OFFLOAD_GSO);

	memset(&script, 0, sizeof(script));
	ncfg_buf_init(&family, 0);
	ncfg_buf_init(&first, 0);
	ncfg_buf_init(&second, 0);
	append_family(&family, NCFG_ETHTOOL_FAMILY, ETHTOOL_FAMILY_ID);
	/* Three messages in one datagram: two carrying an active set and one
	 * carrying none, which is the shape that made the Rust iterate. */
	append_features(&first, "eth0", early, 2u, 1);
	append_features(&first, "eth0", NULL, 0u, 0);
	append_features(&first, "eth0", late, 2u, 1);
	append_features(&second, "eth1", NULL, 0u, 1);
	queue(&script, &family);
	queue(&script, &first);
	queue(&script, &second);
	kernel_of(&kernel, &replay, &script);

	err[0] = '\0';
	if (check(ncfg_observe_offloads_from(&kernel, observed, err, sizeof(err)),
	    "every message about one device is read, not just the first")) {
		(void)snprintf(expected, sizeof(expected), "%s %s %s", name_of(NCFG_OFFLOAD_GRO),
		    name_of(NCFG_OFFLOAD_GSO), name_of(NCFG_OFFLOAD_TSO));
		check(carries(observed, "eth0", expected),
		    "and the name in two of them appears once");
	} else {
		detail("it said", err);
	}
	ncfg_observed_free(observed);
	ncfg_buf_free(&family);
	ncfg_buf_free(&first);
	ncfg_buf_free(&second);
}

/*
 * A device the kernel refuses costs that device and nothing else.
 *
 * `EOPNOTSUPP` is what a device with no ethtool operations answers and is most
 * virtual interfaces, so an observation that refused over one would be an
 * `ncfg status` that fails on any machine with a veth on it. The interface
 * beside it is still read, which is the half that would be lost by failing the
 * round.
 */
static void a_device_the_kernel_refuses_does_not_cost_the_round(void)
{
	script_t              script;
	ncfg_observe_replay_t replay;
	ncfg_observe_kernel_t kernel;
	ncfg_buf_t            family;
	ncfg_buf_t            refused;
	ncfg_buf_t            answered;
	ncfg_observed_t      *observed = planfix_observed(MACHINE_WITH_STALE_LIST);
	const char           *reported[1];
	char                  err[NCFG_ERROR_MAX];

	if (!check(observed != NULL, "the machine reads")) {
		return;
	}
	reported[0] = name_of(NCFG_OFFLOAD_RX_CHECKSUM);

	memset(&script, 0, sizeof(script));
	ncfg_buf_init(&family, 0);
	ncfg_buf_init(&refused, 0);
	ncfg_buf_init(&answered, 0);
	append_family(&family, NCFG_ETHTOOL_FAMILY, ETHTOOL_FAMILY_ID);
	append_error(&refused, EOPNOTSUPP);
	append_features(&answered, "eth1", reported, 1u, 1);
	queue(&script, &family);
	queue(&script, &refused);
	queue(&script, &answered);
	kernel_of(&kernel, &replay, &script);

	err[0] = '\0';
	if (check(ncfg_observe_offloads_from(&kernel, observed, err, sizeof(err)),
	    "a device that answers EOPNOTSUPP does not fail the observation")) {
		/* **And the list it was carrying is gone**, rather than left for the
		 * planner to compare against. What the fixture put there is a
		 * previous observation's answer, and reporting it as this one's is
		 * how a machine that stopped answering goes on looking converged. */
		check(carries(observed, "eth0", ""),
		    "the device that was refused reports nothing, not what it had");
		check(carries(observed, "eth1", name_of(NCFG_OFFLOAD_RX_CHECKSUM)),
		    "and the interface beside it is still read");
	} else {
		detail("it said", err);
	}
	ncfg_observed_free(observed);
	ncfg_buf_free(&family);
	ncfg_buf_free(&refused);
	ncfg_buf_free(&answered);
}

/*
 * A kernel with no `ethtool` family, and a seam that was never installed.
 *
 * The first is every kernel older than 5.6 and the second is every test that
 * is not about offloads. Both answer the same way -- no offload on anything --
 * and neither is a failure, which is what stops an observation being refused
 * over a feature nobody asked for.
 */
static void a_machine_that_cannot_be_asked_is_not_a_failure(void)
{
	script_t              script;
	ncfg_observe_replay_t replay;
	ncfg_observe_kernel_t kernel;
	ncfg_buf_t            nothing;
	ncfg_observed_t      *observed = planfix_observed(MACHINE_WITH_STALE_LIST);
	char                  err[NCFG_ERROR_MAX];

	if (!check(observed != NULL, "the machine reads")) {
		return;
	}
	/* A controller that answers and names no family: the reply arrived, so
	 * this is not a refused lookup, and reading a family id of zero out of it
	 * would fail five seconds later about the wrong thing. */
	memset(&script, 0, sizeof(script));
	ncfg_buf_init(&nothing, 0);
	append_message(&nothing, NLMSG_DONE, NULL);
	queue(&script, &nothing);
	kernel_of(&kernel, &replay, &script);

	err[0] = '\0';
	if (check(ncfg_observe_offloads_from(&kernel, observed, err, sizeof(err)),
	    "a kernel with no ethtool family is a note rather than a refusal")) {
		check(carries(observed, "eth0", ""),
		    "and nothing is claimed about any interface's offloads");
	} else {
		detail("it said", err);
	}
	ncfg_observed_free(observed);
	ncfg_buf_free(&nothing);

	/* And the seam left out entirely. */
	observed = planfix_observed(MACHINE_WITH_STALE_LIST);
	if (!check(observed != NULL, "the machine reads again")) {
		return;
	}
	err[0] = '\0';
	if (check(ncfg_observe_offloads_from(NULL, observed, err, sizeof(err)),
	    "a source with no generic netlink seam asks nothing")) {
		check(carries(observed, "eth0", ""),
		    "and clears what a previous observation left, rather than keeping it");
	} else {
		detail("it said", err);
	}
	ncfg_observed_free(observed);

	check(!ncfg_observe_offloads_from(NULL, NULL, err, sizeof(err)),
	    "and an observation that does not exist is refused");
}

/* ------------------------------------------------------------------------ *
 * The convergence this pass exists for
 * ------------------------------------------------------------------------ */

#define ETHTOOL_DEVICE(body) \
	"{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"},\"link_settings\":{" body "}}"

/*
 * A machine whose offloads already agree is planned nothing -- observed rather
 * than asserted.
 *
 * Both halves, and the second is not decoration: without it this case would go
 * on passing over a planner that had stopped emitting `link.set_offloads` at
 * all, which is the shape of pass `evidence.md` is about. So the same document
 * and the same links are observed twice, once through a kernel that reports
 * the feature on and once through no seam at all, and the two plans are
 * compared against each other.
 */
static void a_machine_whose_offloads_already_agree_plans_nothing(void)
{
	script_t              script;
	ncfg_observe_replay_t replay;
	ncfg_observe_kernel_t kernel;
	ncfg_buf_t            family;
	ncfg_buf_t            answer;
	ncfg_buf_t            empty;
	ncfg_document_t      *document = planfix_document(ETHTOOL_DEVICE("\"gro\":\"on\""), "", "",
	    "");
	ncfg_observed_t      *seen = planfix_observed(MACHINE);
	ncfg_observed_t      *unseen = planfix_observed(MACHINE);
	ncfg_plan_t          *quiet = NULL;
	ncfg_plan_t          *busy = NULL;
	const char           *reported[1];
	char                  err[NCFG_ERROR_MAX];

	if (!check(document && seen && unseen, "the document and the machine read")) {
		planfix_release(NULL, document, seen);
		ncfg_observed_free(unseen);
		return;
	}
	reported[0] = name_of(NCFG_OFFLOAD_GRO);

	memset(&script, 0, sizeof(script));
	ncfg_buf_init(&family, 0);
	ncfg_buf_init(&answer, 0);
	ncfg_buf_init(&empty, 0);
	append_family(&family, NCFG_ETHTOOL_FAMILY, ETHTOOL_FAMILY_ID);
	append_features(&answer, "eth0", reported, 1u, 1);
	append_features(&empty, "eth1", NULL, 0u, 1);
	queue(&script, &family);
	queue(&script, &answer);
	queue(&script, &empty);
	kernel_of(&kernel, &replay, &script);

	err[0] = '\0';
	if (!check(ncfg_observe_offloads_from(&kernel, seen, err, sizeof(err)),
	    "the machine is observed through a kernel that reports the offload on")) {
		detail("it said", err);
	}
	err[0] = '\0';
	quiet = ncfg_plan_build(document, seen, NULL, err, sizeof(err));
	if (!check(quiet != NULL, "and a plan is built against it")) {
		detail("it said", err);
	}
	check(quiet && planfix_count(quiet, "link.set_offloads") == 0u,
	    "an interface whose offloads already agree is planned nothing");

	/* The same document against the same machine observed without the seam,
	 * which is what every pass before this one saw. */
	err[0] = '\0';
	(void)ncfg_observe_offloads_from(NULL, unseen, err, sizeof(err));
	err[0] = '\0';
	busy = ncfg_plan_build(document, unseen, NULL, err, sizeof(err));
	if (!check(busy != NULL, "and one against the same machine unobserved")) {
		detail("it said", err);
	}
	check(busy && planfix_count(busy, "link.set_offloads") == 1u,
	    "which is planned the offload on every pass, as it was before this pass");

	ncfg_plan_free(quiet);
	planfix_release(busy, document, unseen);
	ncfg_observed_free(seen);
	ncfg_buf_free(&family);
	ncfg_buf_free(&answer);
	ncfg_buf_free(&empty);
}

/* ------------------------------------------------------------------------ *
 * The one check that opens a socket, behind `NCFG_OBSERVE_LIVE=1`
 * ------------------------------------------------------------------------ */

/*
 * The names in the model's table against the ones a real driver reports.
 *
 * **This is the check the replays above cannot make.** Every expectation in
 * them is derived from `ncfg_offload_field_names`, so a table that spelled a
 * feature the kernel has never heard of would satisfy all of them -- and the
 * cost of that spelling is silent: an offload absent from the active set reads
 * as off, so netcfgd would turn it on, read it back as off, and plan the same
 * action for ever. `plan_tc_test.c` pins the spellings against literals; only a
 * kernel can say whether the literals are the kernel's.
 *
 * It sends `FEATURES_GET` and nothing else, which changes nothing, and it
 * asserts nothing about *which* offloads this machine has on -- that is a fact
 * about somebody's hardware. What it asserts is that at least one interface
 * answered and that what came back is inside the model's set, which is all
 * that is true of every Linux machine.
 */
static void the_live_check(void)
{
	ncfg_observe_source_t source;
	ncfg_observed_t      *observed = NULL;
	const char           *live = getenv("NCFG_OBSERVE_LIVE");
	size_t                answered = 0;
	size_t                at;
	char                  err[NCFG_ERROR_MAX];

	if (!live || strcmp(live, "1") != 0) {
		check(1, "the live ethtool round is skipped; set NCFG_OBSERVE_LIVE=1 to run it");
		return;
	}
	if (!check(ncfg_observe_source_machine(&source, NULL, NULL, err, sizeof(err)),
	    "a source for this machine")) {
		detail("it said", err);
		return;
	}
	err[0] = '\0';
	if (!check(ncfg_observe_source_observe(&source, NULL, &observed, err, sizeof(err)) &&
	    observed, "a live observation, offloads and all")) {
		detail("it said", err);
		return;
	}
	for (at = 0; at < observed->link_count; at++) {
		char written[256];

		joined(&observed->links[at], written, sizeof(written));
		printf("  %s: %s\n", observed->links[at].name,
		    written[0] ? written : "(none of the five reported on)");
		if (observed->links[at].offload_count > 0) {
			answered++;
		}
	}
	check(answered > 0,
	    "at least one interface on this machine has an offload the model names");
	ncfg_observed_free(observed);
}

int main(void)
{
	only_the_offloads_the_model_can_express();
	several_messages_about_one_device_fold_into_one_list();
	a_device_the_kernel_refuses_does_not_cost_the_round();
	a_machine_that_cannot_be_asked_is_not_a_failure();
	a_machine_whose_offloads_already_agree_plans_nothing();
	the_live_check();

	printf("observe_offloads_test: %d check(s)\n", checks);
	if (failures) {
		printf("observe_offloads_test: %d FAILED\n", failures);
		return 1;
	}
	printf("observe_offloads_test: all checks passed\n");
	return 0;
}
