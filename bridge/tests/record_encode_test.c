/*
 * record_encode_test.c -- what the encoder refuses, that two interfaces no
 * longer share a cell, and that what it accepts is a record fuzznet verifies.
 *
 * WHAT IS WORTH CHECKING
 *   Not that the fields come back. What separates a right encoder from a
 *   wrong one:
 *
 *     * **two instances of one block differ**, which is the whole of what
 *       folding the instance into the subject was for -- and the case the
 *       first version got wrong while every other assertion passed;
 *     * **a host-private key is refused, by its own code**, the one failure
 *       that cannot be recalled once a value is signed and admitted;
 *     * **the stream is derived from the scope and the root from the block**,
 *       which are two questions the first version asked as one;
 *     * **the components cannot be run together**, because a label can be an
 *       SSID and an SSID is arbitrary bytes;
 *     * **the bound is fuzznet's**, tested at the boundary rather than near
 *       it.
 *
 * AND THE CONTROL, WHICH IS THE POINT OF THE FILE
 *   Every check above compares this encoder against this tree's own tables --
 *   one witness twice. So the last case takes the fields through
 *   `fzn_record_sign`, `fzn_record_open` and `fzn_record_verify`, and reads
 *   the kind, stream, subject and body back out of the signed bytes. That is
 *   the only assertion here that could fail because fuzznet disagrees rather
 *   than because netcfgd does.
 */
#include "../record_encode.h"

#include "chain/sign_monocypher.h"
#include "session/hash_monocypher.h"

#include <stdio.h>
#include <string.h>

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

static fzn_hash_ops_t hash;

static ncfg_block_t block_named(const char *name)
{
	ncfg_block_t which;

	if (!ncfg_block_from_name(name, &which)) {
		return (ncfg_block_t)NCFG_BLOCK_COUNT; /* cannot happen below */
	}
	return which;
}

/* Two machines, told apart by their keys the way the estate tells them apart. */
static uint8_t HOST_A[FZN_PUBKEY_LEN];
static uint8_t HOST_B[FZN_PUBKEY_LEN];

static void keys_init(void)
{
	size_t at;

	for (at = 0u; at < sizeof(HOST_A); at++) {
		HOST_A[at] = (uint8_t)(0x10u + at);
		HOST_B[at] = (uint8_t)(0x90u + at);
	}
}

static ncfg_record_rootref_t host_root(const uint8_t *key)
{
	ncfg_record_rootref_t root;

	memset(&root, 0, sizeof(root));
	root.kind = NCFG_ROOT_HOST;
	root.key = key;
	return root;
}

static ncfg_record_rootref_t named_root(ncfg_record_root_t kind, const char *name)
{
	ncfg_record_rootref_t root;

	memset(&root, 0, sizeof(root));
	root.kind = kind;
	root.name = name;
	return root;
}

/*
 * **THE CASE THE DECISION WAS TAKEN FOR.** With a host for a subject, these
 * two were one cell: same kind, same subject, second write wins, every host in
 * the estate agreeing about the wrong answer. project.md 10.328 measured it
 * and 10.329 is the fix.
 */
static void two_interfaces_no_longer_share_a_cell(void)
{
	ncfg_record_rootref_t root = host_root(HOST_A);
	ncfg_record_fields_t  wlan;
	ncfg_record_fields_t  eth;

	check(ncfg_record_encode(&hash, block_named("interface"), &root, "wlan0", 5u, "mtu",
	          "1500", 4u, &wlan) == NCFG_RECORD_OK,
	    "wlan0's MTU encodes");
	check(ncfg_record_encode(&hash, block_named("interface"), &root, "eth0", 4u, "mtu",
	          "9000", 4u, &eth) == NCFG_RECORD_OK,
	    "and so does eth0's, on the same host");
	check(wlan.kind == eth.kind,
	    "both carry the same number, because the number names the key");
	check(memcmp(wlan.subject, eth.subject, sizeof(wlan.subject)) != 0,
	    "and DIFFERENT subjects, so they are two cells rather than one");
	check(wlan.stream == eth.stream, "in one stream, both being host-scoped");
}

/* The same link name on two machines is two objects, which is the other half
 * of the same property: `wlan0` is not a global name. */
static void one_link_name_on_two_machines_is_two_objects(void)
{
	ncfg_record_rootref_t a = host_root(HOST_A);
	ncfg_record_rootref_t b = host_root(HOST_B);
	uint8_t               here[FZN_SUBJECT_LEN];
	uint8_t               there[FZN_SUBJECT_LEN];

	check(ncfg_record_subject_of(&hash, block_named("interface"), &a, "wlan0", 5u, here) ==
	        NCFG_RECORD_OK,
	    "this machine's wlan0 has a subject");
	check(ncfg_record_subject_of(&hash, block_named("interface"), &b, "wlan0", 5u,
	          there) == NCFG_RECORD_OK,
	    "and so does another machine's");
	check(memcmp(here, there, sizeof(here)) != 0, "and they are not the same object");
}

/* And one label under two blocks on one machine. */
static void one_label_under_two_blocks_is_two_objects(void)
{
	ncfg_record_rootref_t root = host_root(HOST_A);
	uint8_t               as_interface[FZN_SUBJECT_LEN];
	uint8_t               as_linkset[FZN_SUBJECT_LEN];

	check(ncfg_record_subject_of(&hash, block_named("interface"), &root, "uplink", 6u,
	          as_interface) == NCFG_RECORD_OK,
	    "an interface called uplink has a subject");
	check(ncfg_record_subject_of(&hash, block_named("linkset"), &root, "uplink", 6u,
	          as_linkset) == NCFG_RECORD_OK,
	    "and a linkset of the same name has one too");
	check(memcmp(as_interface, as_linkset, sizeof(as_interface)) != 0,
	    "and they differ, the block's own spelling being in the transcript");
}

/*
 * The components separate, and **a NUL separator would have separated these
 * too** -- which is the sabotage refusing to fail and is worth the paragraph.
 *
 * Replacing the length prefix with a trailing NUL leaves this file green. The
 * reason is that only the LABEL is taken with a length: a root name arrives as
 * a C string, so it cannot contain a NUL, and the label is the last component,
 * where a trailing separator cannot be confused with the start of anything.
 * The ambiguity a separator scheme is vulnerable to needs a NUL inside a
 * component that is not last, and no caller can construct one today.
 *
 * So the length prefix is kept as unconditional robustness rather than as a
 * fix for a reachable fault: it costs two bytes per component and stays
 * correct if a root ever becomes length-taken, or if a fourth component is
 * added after the label. **What is asserted below is that these inputs do not
 * collide, which is true and useful; the choice of scheme is not what makes it
 * true, and no test here shows otherwise.** project.md 10.329.
 */
static void the_components_separate(void)
{
	ncfg_record_rootref_t left = named_root(NCFG_ROOT_ESTATE, "roof");
	ncfg_record_rootref_t right = named_root(NCFG_ROOT_ESTATE, "roofnet");
	ncfg_block_t          network = block_named("network");
	uint8_t               a[FZN_SUBJECT_LEN];
	uint8_t               b[FZN_SUBJECT_LEN];
	uint8_t               with_nul[FZN_SUBJECT_LEN];
	uint8_t               without[FZN_SUBJECT_LEN];

	check(ncfg_record_subject_of(&hash, network, &left, "netguest", 8u, a) ==
	        NCFG_RECORD_OK,
	    "estate `roof`, network `netguest`");
	check(ncfg_record_subject_of(&hash, network, &right, "guest", 5u, b) == NCFG_RECORD_OK,
	    "and estate `roofnet`, network `guest`");
	check(memcmp(a, b, sizeof(a)) != 0,
	    "differ, although the two run together to the same bytes");

	/* A label carrying the byte a separator scheme would have used. It is
	 * accepted -- an SSID is arbitrary bytes -- and is its own object. */
	check(ncfg_record_subject_of(&hash, network, &left, "gu\0est", 6u, with_nul) ==
	        NCFG_RECORD_OK,
	    "a label containing a NUL derives at all");
	check(ncfg_record_subject_of(&hash, network, &left, "gu", 2u, without) ==
	        NCFG_RECORD_OK,
	    "as does its prefix");
	check(memcmp(with_nul, without, sizeof(with_nul)) != 0,
	    "and the two are different objects");
}

/*
 * The root is a property of the BLOCK, not of the key's scope. That is the
 * conflation the first version shipped: it asked what a key's scope was and
 * required a matching subject, so an estate-scoped key about one link on one
 * machine was inexpressible.
 */
static void the_root_comes_from_the_block(void)
{
	ncfg_record_rootref_t as_host = host_root(HOST_A);
	ncfg_record_rootref_t as_estate = named_root(NCFG_ROOT_ESTATE, "home");
	ncfg_record_fields_t  fields;
	uint8_t               subject[FZN_SUBJECT_LEN];

	check(ncfg_record_root_of(block_named("interface")) == NCFG_ROOT_HOST,
	    "an interface is a thing on a machine");
	check(ncfg_record_root_of(block_named("network")) == NCFG_ROOT_ESTATE,
	    "a network is a thing in the estate");
	check(ncfg_record_root_of(block_named("rule")) == NCFG_ROOT_GROUP,
	    "and a rule is a thing in a zone");
	check(ncfg_record_root_of(block_named("device")) == NCFG_ROOT_HOST,
	    "a host-private block roots at the host, having nowhere else to be");

	check(ncfg_record_subject_of(&hash, block_named("interface"), &as_estate, "wlan0", 5u,
	          subject) == NCFG_RECORD_ERR_SUBJECT,
	    "an interface rooted at the estate is refused");
	check(ncfg_record_subject_of(&hash, block_named("network"), &as_host, "home", 4u,
	          subject) == NCFG_RECORD_ERR_SUBJECT,
	    "and a network rooted at a host");

	/* The case the conflation made unsayable: an estate-scoped key about
	 * one link on one machine. */
	check(ncfg_record_encode(&hash, block_named("interface"), &as_host, "wlan0", 5u, "dns",
	          "[\"1.1.1.1\"]", 11u, &fields) == NCFG_RECORD_OK,
	    "an estate-scoped key about this host's wlan0 encodes");
	check(fields.scope == NCFG_SCOPE_ESTATE && fields.stream == NCFG_STREAM_ESTATE,
	    "travelling estate-wide while being about one link on one machine");
}

/*
 * **The refusal whose failure cannot be undone.** A host-private value that
 * reaches a record is signed, replicated and held by everyone who admitted
 * it; there is no recall. It is refused by its own code rather than as
 * "unregistered", so a log says which of the two happened.
 */
static void a_host_private_key_is_refused_as_such(void)
{
	ncfg_record_rootref_t root = host_root(HOST_A);
	ncfg_record_fields_t  fields;

	check(ncfg_record_encode(&hash, block_named("interface"), &root, "wlan0", 5u, "mac",
	          "\"aa:bb\"", 7u, &fields) == NCFG_RECORD_ERR_HOST_PRIVATE,
	    "a MAC cannot become a record, and is refused as host-private");
	check(ncfg_record_encode(&hash, block_named("interface"), &root, "wlan0", 5u,
	          "probe.command", "\"/usr/bin/ping\"", 15u, &fields) ==
	        NCFG_RECORD_ERR_HOST_PRIVATE,
	    "and neither can a program's path");
	check(ncfg_record_encode(&hash, block_named("device"), &root, "eth0", 4u, "mtu",
	          "1500", 4u, &fields) == NCFG_RECORD_ERR_HOST_PRIVATE,
	    "nor anything in a host-private block");
	/* The three cert keys, which are estate-wide and unregistered on
	 * purpose: they must read as unregistered rather than as private, or
	 * the reason in 10.327 is lost. */
	check(ncfg_record_encode(&hash, block_named("interface"), &root, "wlan0", 5u,
	          "dot1x.ca_cert", "\"@secret:ca\"", 12u, &fields) ==
	        NCFG_RECORD_ERR_UNREGISTERED,
	    "a deliberately unnumbered key is refused as unregistered, not as private");
}

static void a_key_nobody_registered_cannot_be_said(void)
{
	ncfg_record_rootref_t root = host_root(HOST_A);
	ncfg_record_fields_t  fields;

	check(ncfg_record_encode(&hash, block_named("interface"), &root, "wlan0", 5u,
	          "a_key_that_does_not_exist", "x", 1u, &fields) ==
	        NCFG_RECORD_ERR_UNREGISTERED,
	    "a key with no number cannot be a record yet");
}

/*
 * **The stream is derived, so a caller cannot choose it.** Nothing in the
 * signature offers one, and this is the assertion that says the absence is
 * deliberate rather than an argument somebody forgot.
 */
static void the_stream_comes_from_the_scope(void)
{
	ncfg_record_rootref_t here = host_root(HOST_A);
	ncfg_record_rootref_t estate = named_root(NCFG_ROOT_ESTATE, "home");
	ncfg_record_fields_t  host_key;
	ncfg_record_fields_t  group_key;
	ncfg_record_fields_t  estate_key;

	check(ncfg_record_encode(&hash, block_named("interface"), &here, "wlan0", 5u, "mtu",
	          "1500", 4u, &host_key) == NCFG_RECORD_OK,
	    "an interface's MTU is about this host");
	check(ncfg_record_encode(&hash, block_named("interface"), &here, "wlan0", 5u,
	          "advertise.prefix", "\"2001:db8::/64\"", 15u, &group_key) == NCFG_RECORD_OK,
	    "a prefix it announces is the segment's");
	check(ncfg_record_encode(&hash, block_named("network"), &estate, "home", 4u, "ssid",
	          "\"office\"", 8u, &estate_key) == NCFG_RECORD_OK,
	    "and an SSID is the estate's");

	check(host_key.stream == NCFG_STREAM_HOST && group_key.stream == NCFG_STREAM_GROUP &&
	        estate_key.stream == NCFG_STREAM_ESTATE,
	    "each lands in its scope's own stream");
	check(host_key.stream != group_key.stream && group_key.stream != estate_key.stream,
	    "and the three tracks are distinct, so entitlement can differ per track");
	check(ncfg_record_stream_of(NCFG_SCOPE_HOST_PRIVATE) == 0u,
	    "a scope that does not travel names no track at all");
	check(host_key.stream >= FZN_STREAM_RESERVED,
	    "and every track sits above fuzznet's reserved range");
	/* Two scopes on ONE object: the subject is the block's and the stream
	 * is the key's, which is the separation this design turns on. */
	check(memcmp(host_key.subject, group_key.subject, sizeof(host_key.subject)) == 0 &&
	        host_key.stream != group_key.stream,
	    "two keys on one object share a subject and take different tracks");
}

/* Nothing half-written on a refusal, so a caller that ignores the code cannot
 * sign something it was told not to make. */
static void a_refusal_leaves_the_fields_alone(void)
{
	ncfg_record_rootref_t root = host_root(HOST_A);
	ncfg_record_fields_t  fields;

	memset(&fields, 0xa5, sizeof(fields));
	(void)ncfg_record_encode(&hash, block_named("interface"), &root, "wlan0", 5u, "mac",
	    "x", 1u, &fields);
	check(fields.kind == 0xa5a5a5a5u && fields.stream == 0xa5a5a5a5u,
	    "a refusal writes nothing, so a caller cannot half-make a record");
}

static void the_bound_is_fuzznet_s(void)
{
	ncfg_record_rootref_t root = named_root(NCFG_ROOT_ESTATE, "home");
	ncfg_record_fields_t  fields;
	static char           big[(size_t)FZN_RECORD_BODY_MAX + 1u];

	memset(big, 'x', sizeof(big));
	check(ncfg_record_encode(&hash, block_named("network"), &root, "home", 4u, "ssid", big,
	          (size_t)FZN_RECORD_BODY_MAX, &fields) == NCFG_RECORD_OK,
	    "a value of exactly the largest body is carried");
	check(ncfg_record_encode(&hash, block_named("network"), &root, "home", 4u, "ssid", big,
	          (size_t)FZN_RECORD_BODY_MAX + 1u, &fields) == NCFG_RECORD_ERR_TOO_LARGE,
	    "and one byte more is refused, at the boundary rather than near it");
	/* A label longer than a transcript component carries is the same kind
	 * of answer and not a caller's bug. */
	check(ncfg_record_encode(&hash, block_named("network"), &root, "home", 512u, "ssid",
	          "\"x\"", 3u, &fields) == NCFG_RECORD_ERR_TOO_LARGE,
	    "so is a label longer than a subject transcript carries");
}

/*
 * **A newline is a value, not an injection**, which was checked in `lex.c`
 * rather than assumed: a string "runs to its closing quote, across lines if
 * need be", because the netifrc spelling puts several addresses in one value.
 * A refusal written on the obvious guess would have refused a whole class of
 * real configuration.
 */
static void a_multi_line_value_is_ordinary_and_a_nul_is_not(void)
{
	ncfg_record_rootref_t root = host_root(HOST_A);
	ncfg_record_fields_t  fields;
	static const char     lines[] = "\"192.0.2.1/24\n192.0.2.2/24\"";
	static const char     nul[] = "1500\0extra";

	check(ncfg_record_encode(&hash, block_named("interface"), &root, "wlan0", 5u, "config",
	          lines, sizeof(lines) - 1u, &fields) == NCFG_RECORD_OK,
	    "a value spanning lines is ordinary, as the netifrc spelling needs");
	check(ncfg_record_encode(&hash, block_named("interface"), &root, "wlan0", 5u, "mtu",
	          nul, sizeof(nul) - 1u, &fields) == NCFG_RECORD_ERR_NOT_TEXT,
	    "while a NUL is refused: it would truncate on the way back out");
}

static void a_subject_is_stable_and_a_bad_call_is_a_bad_call(void)
{
	ncfg_record_rootref_t root = host_root(HOST_A);
	ncfg_record_rootref_t keyless = host_root(NULL);
	uint8_t               once[FZN_SUBJECT_LEN];
	uint8_t               twice[FZN_SUBJECT_LEN];
	int                   derived;

	memset(once, 0, sizeof(once));
	memset(twice, 0, sizeof(twice));
	derived = ncfg_record_subject_of(&hash, block_named("interface"), &root, "wlan0", 5u,
	              once) == NCFG_RECORD_OK &&
	    ncfg_record_subject_of(&hash, block_named("interface"), &root, "wlan0", 5u,
	        twice) == NCFG_RECORD_OK;
	check(derived, "one object derives twice");
	check(derived && memcmp(once, twice, sizeof(once)) == 0,
	    "to the same subject, or two hosts address different cells");
	check(ncfg_record_subject_of(NULL, block_named("interface"), &root, "wlan0", 5u,
	          once) == NCFG_RECORD_ERR_MALFORMED,
	    "no hash binding is the caller's bug");
	check(ncfg_record_subject_of(&hash, block_named("interface"), &keyless, "wlan0", 5u,
	          once) == NCFG_RECORD_ERR_MALFORMED,
	    "and so is a host root with no key");
	/* A block that takes no label still derives, the zero length being the
	 * answer rather than a missing component. */
	check(ncfg_record_subject_of(&hash, block_named("global"), &root, NULL, 0u, once) ==
	        NCFG_RECORD_OK,
	    "a block that takes no label derives from its root and its name");
}

/*
 * THE CONTROL. Everything above asks netcfgd about netcfgd. This signs the
 * fields and asks fuzznet to open and verify the result, then reads each
 * field back out of the bytes the signature covered.
 */
static void the_fields_make_a_record_fuzznet_accepts(void)
{
	fzn_sign_monocypher_t state;
	fzn_sign_ops_t        sign;
	fzn_sign_seat_t       seat;
	uint8_t               seed[FZN_SIGN_SEED_LEN];
	uint8_t               issuer[FZN_PUBKEY_LEN];
	ncfg_record_rootref_t root = named_root(NCFG_ROOT_ESTATE, "home");
	ncfg_record_fields_t  fields;
	uint8_t               bytes[FZN_RECORD_MAX_LEN];
	size_t                len = 0u;
	fzn_record_t          opened;
	uint8_t               expected[FZN_SUBJECT_LEN];
	static const char     value[] = "\"office\"";
	size_t                at;

	for (at = 0u; at < sizeof(seed); at++) {
		seed[at] = (uint8_t)(0x40u + at);
	}
	fzn_sign_monocypher_init(&sign, &state);
	fzn_sign_monocypher_seat_init(&seat, &state);
	check(seat.install(seat.ctx, seed, issuer) != 0, "a signer is seated with a test seed");

	check(ncfg_record_encode(&hash, block_named("network"), &root, "home", 4u, "ssid",
	          value, sizeof(value) - 1u, &fields) == NCFG_RECORD_OK,
	    "an SSID on the estate's `home` network encodes");

	check(fzn_record_sign(issuer, fields.subject, fields.stream, fields.kind, 1u,
	          1759000000u, fields.body, fields.body_len, &sign, bytes, sizeof(bytes),
	          &len) == FZN_RECORD_OK,
	    "the fields sign into a record");
	check(fzn_record_open(bytes, len, &opened) == FZN_RECORD_OK,
	    "which fuzznet opens: the shape is one it knows");
	check(fzn_record_verify(opened, &sign) == FZN_RECORD_OK,
	    "and verifies against the issuer that signed it");

	/* **Against the registry, the constant and an independently derived
	 * subject -- not against `fields`.** A comparison with the struct this
	 * encoder just filled would agree with whatever it put there, which is
	 * the same witness twice one call further along. */
	check(fzn_record_kind(opened) == ncfg_kind_of(block_named("network"), "ssid"),
	    "the kind reads back as the number the registry gives that key");
	check(fzn_record_stream(opened) == NCFG_STREAM_ESTATE,
	    "the stream reads back as the estate track, which the scope chose");
	check(ncfg_record_subject_of(&hash, block_named("network"), &root, "home", 4u,
	          expected) == NCFG_RECORD_OK,
	    "the object's subject derives on its own");
	check(memcmp(fzn_record_subject(opened), expected, sizeof(expected)) == 0,
	    "and the record carries that subject, byte for byte");
	check(fzn_record_body_len(opened) == fields.body_len &&
	        memcmp(fzn_record_body(opened), value, sizeof(value) - 1u) == 0,
	    "with the body the value exactly as the language spells it");

	fzn_sign_monocypher_wipe(&state);
}

int main(void)
{
	keys_init();
	fzn_hash_monocypher_init(&hash);

	two_interfaces_no_longer_share_a_cell();
	one_link_name_on_two_machines_is_two_objects();
	one_label_under_two_blocks_is_two_objects();
	the_components_separate();
	the_root_comes_from_the_block();
	a_host_private_key_is_refused_as_such();
	a_key_nobody_registered_cannot_be_said();
	the_stream_comes_from_the_scope();
	a_refusal_leaves_the_fields_alone();
	the_bound_is_fuzznet_s();
	a_multi_line_value_is_ordinary_and_a_nul_is_not();
	a_subject_is_stable_and_a_bad_call_is_a_bad_call();
	the_fields_make_a_record_fuzznet_accepts();

	printf("record_encode_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("record_encode_test: all checks passed\n");
	} else {
		printf("record_encode_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
