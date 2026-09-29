/*
 * record_encode_test.c -- what the encoder refuses, and that what it accepts
 * is a record fuzznet will open and verify.
 *
 * WHAT IS WORTH CHECKING
 *   Not that the fields come back. What separates a right encoder from a
 *   wrong one:
 *
 *     * **a host-private key is refused, by its own code**, which is the one
 *       failure that would be silent and permanent -- a value that must not
 *       leave the machine, signed and replicated, cannot be recalled;
 *     * **the stream is derived from the scope**, so an estate-wide value
 *       cannot be put in the host track by any argument a caller controls;
 *     * **the subject must match the scope**, because 32 opaque bytes cannot
 *       say what they are about and nothing downstream will ask;
 *     * **a group and an estate of the same name differ**, which is what the
 *       domain separation is for and what a bare hash would get wrong;
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

static ncfg_block_t block_named(const char *name)
{
	ncfg_block_t which;

	if (!ncfg_block_from_name(name, &which)) {
		return (ncfg_block_t)NCFG_BLOCK_COUNT; /* cannot happen below */
	}
	return which;
}

/* A subject of no particular meaning, for the cases that are not about
 * subjects. */
static void some_subject(uint8_t out[FZN_SUBJECT_LEN])
{
	size_t at;

	for (at = 0u; at < (size_t)FZN_SUBJECT_LEN; at++) {
		out[at] = (uint8_t)(at + 1u);
	}
}

/*
 * **The refusal whose failure cannot be undone.** A host-private value that
 * reaches a record is signed, replicated and held by everyone who admitted
 * it; there is no recall. It is refused by its own code rather than as
 * "unregistered", so a log says which of the two happened.
 */
static void a_host_private_key_is_refused_as_such(void)
{
	ncfg_record_fields_t fields;
	uint8_t              subject[FZN_SUBJECT_LEN];

	some_subject(subject);
	check(ncfg_record_encode(block_named("interface"), "mac", NCFG_RECORD_SUBJECT_HOST,
	          subject, "aa:bb:cc:dd:ee:ff", 17u, &fields) == NCFG_RECORD_ERR_HOST_PRIVATE,
	    "a MAC cannot become a record, and is refused as host-private");
	check(ncfg_record_encode(block_named("interface"), "probe.command",
	          NCFG_RECORD_SUBJECT_HOST, subject, "/usr/bin/ping", 13u, &fields) ==
	        NCFG_RECORD_ERR_HOST_PRIVATE,
	    "and neither can a program's path");
	check(ncfg_record_encode(block_named("device"), "mtu", NCFG_RECORD_SUBJECT_HOST,
	          subject, "1500", 4u, &fields) == NCFG_RECORD_ERR_HOST_PRIVATE,
	    "nor anything in a host-private block");
	/* The three cert keys, which are estate-wide and unregistered on
	 * purpose: they must read as unregistered rather than as private, or
	 * the reason in 10.327 is lost. */
	check(ncfg_record_encode(block_named("interface"), "dot1x.ca_cert",
	          NCFG_RECORD_SUBJECT_ESTATE, subject, "@secret:ca", 10u, &fields) ==
	        NCFG_RECORD_ERR_UNREGISTERED,
	    "a deliberately unnumbered key is refused as unregistered, not as private");
}

static void a_key_nobody_registered_cannot_be_said(void)
{
	ncfg_record_fields_t fields;
	uint8_t              subject[FZN_SUBJECT_LEN];

	some_subject(subject);
	check(ncfg_record_encode(block_named("interface"), "a_key_that_does_not_exist",
	          NCFG_RECORD_SUBJECT_HOST, subject, "x", 1u, &fields) ==
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
	ncfg_record_fields_t host;
	ncfg_record_fields_t group;
	ncfg_record_fields_t estate;
	uint8_t              subject[FZN_SUBJECT_LEN];

	some_subject(subject);
	check(ncfg_record_encode(block_named("interface"), "mtu", NCFG_RECORD_SUBJECT_HOST,
	          subject, "1500", 4u, &host) == NCFG_RECORD_OK,
	    "an interface's MTU is about this host");
	check(ncfg_record_encode(block_named("interface"), "advertise.prefix",
	          NCFG_RECORD_SUBJECT_GROUP, subject, "2001:db8::/64", 13u, &group) ==
	        NCFG_RECORD_OK,
	    "a prefix it announces is about the segment");
	check(ncfg_record_encode(block_named("network"), "ssid", NCFG_RECORD_SUBJECT_ESTATE,
	          subject, "\"office\"", 8u, &estate) == NCFG_RECORD_OK,
	    "and an SSID is about the estate");

	check(host.stream == NCFG_STREAM_HOST && group.stream == NCFG_STREAM_GROUP &&
	        estate.stream == NCFG_STREAM_ESTATE,
	    "each lands in its scope's own stream");
	check(host.stream != group.stream && group.stream != estate.stream,
	    "and the three tracks are distinct, so entitlement can differ per track");
	check(ncfg_record_stream_of(NCFG_SCOPE_HOST_PRIVATE) == 0u,
	    "a scope that does not travel names no track at all");
	check(host.stream >= FZN_STREAM_RESERVED,
	    "and every track sits above fuzznet's reserved range");
}

/*
 * A subject is 32 opaque bytes. Nothing downstream can say what they are
 * about, so this is the only place the pairing can be checked at all.
 */
static void a_subject_must_match_the_scope(void)
{
	ncfg_record_fields_t fields;
	uint8_t              subject[FZN_SUBJECT_LEN];

	some_subject(subject);
	check(ncfg_record_encode(block_named("network"), "ssid", NCFG_RECORD_SUBJECT_HOST,
	          subject, "\"office\"", 8u, &fields) == NCFG_RECORD_ERR_SUBJECT,
	    "an estate-wide key refuses a host subject");
	check(ncfg_record_encode(block_named("interface"), "mtu", NCFG_RECORD_SUBJECT_ESTATE,
	          subject, "1500", 4u, &fields) == NCFG_RECORD_ERR_SUBJECT,
	    "and a host-scoped key refuses the estate's");
	check(ncfg_record_encode(block_named("interface"), "advertise.prefix",
	          NCFG_RECORD_SUBJECT_ESTATE, subject, "2001:db8::/64", 13u, &fields) ==
	        NCFG_RECORD_ERR_SUBJECT,
	    "a group-scoped key refuses it too, so the middle scope is not a synonym");
}

/* Nothing half-written on a refusal, so a caller that ignores the code cannot
 * sign something it was told not to make. */
static void a_refusal_leaves_the_fields_alone(void)
{
	ncfg_record_fields_t fields;
	uint8_t              subject[FZN_SUBJECT_LEN];

	some_subject(subject);
	memset(&fields, 0xa5, sizeof(fields));
	(void)ncfg_record_encode(block_named("interface"), "mac", NCFG_RECORD_SUBJECT_HOST,
	    subject, "x", 1u, &fields);
	check(fields.kind == 0xa5a5a5a5u && fields.stream == 0xa5a5a5a5u,
	    "a refusal writes nothing, so a caller cannot half-make a record");
}

static void the_bound_is_fuzznet_s(void)
{
	ncfg_record_fields_t fields;
	uint8_t              subject[FZN_SUBJECT_LEN];
	static char          big[(size_t)FZN_RECORD_BODY_MAX + 1u];

	some_subject(subject);
	memset(big, 'x', sizeof(big));
	check(ncfg_record_encode(block_named("network"), "ssid", NCFG_RECORD_SUBJECT_ESTATE,
	          subject, big, (size_t)FZN_RECORD_BODY_MAX, &fields) == NCFG_RECORD_OK,
	    "a value of exactly the largest body is carried");
	check(ncfg_record_encode(block_named("network"), "ssid", NCFG_RECORD_SUBJECT_ESTATE,
	          subject, big, (size_t)FZN_RECORD_BODY_MAX + 1u, &fields) ==
	        NCFG_RECORD_ERR_TOO_LARGE,
	    "and one byte more is refused, at the boundary rather than near it");
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
	ncfg_record_fields_t fields;
	uint8_t              subject[FZN_SUBJECT_LEN];
	static const char    lines[] = "\"192.0.2.1/24\n192.0.2.2/24\"";
	static const char    nul[] = "1500\0extra";

	some_subject(subject);
	check(ncfg_record_encode(block_named("interface"), "config", NCFG_RECORD_SUBJECT_HOST,
	          subject, lines, sizeof(lines) - 1u, &fields) == NCFG_RECORD_OK,
	    "a value spanning lines is ordinary, as the netifrc spelling needs");
	check(ncfg_record_encode(block_named("interface"), "mtu", NCFG_RECORD_SUBJECT_HOST,
	          subject, nul, sizeof(nul) - 1u, &fields) == NCFG_RECORD_ERR_NOT_TEXT,
	    "while a NUL is refused: it would truncate on the way back out");
}

/*
 * **Every comparison here is gated on the derivation having succeeded**, and
 * that is not defensive style. The first version compared buffers the failing
 * call had never written: "the derivation is stable" and "an estate differs"
 * both PASSED against uninitialised stack while three checks beside them
 * failed -- a difference of two stack slots away from agreeing for nothing.
 */
static void a_name_becomes_a_subject_and_the_scope_is_in_it(void)
{
	fzn_hash_ops_t hash;
	uint8_t        group[FZN_SUBJECT_LEN];
	uint8_t        estate[FZN_SUBJECT_LEN];
	uint8_t        again[FZN_SUBJECT_LEN];
	uint8_t        other[FZN_SUBJECT_LEN];
	int            derived;

	fzn_hash_monocypher_init(&hash);
	memset(group, 0, sizeof(group));
	memset(again, 0, sizeof(again));
	memset(estate, 0, sizeof(estate));
	memset(other, 0, sizeof(other));

	derived = ncfg_record_subject_of_name(&hash, NCFG_RECORD_SUBJECT_GROUP, "roof",
	              group) == NCFG_RECORD_OK &&
	    ncfg_record_subject_of_name(&hash, NCFG_RECORD_SUBJECT_GROUP, "roof", again) ==
	        NCFG_RECORD_OK &&
	    ncfg_record_subject_of_name(&hash, NCFG_RECORD_SUBJECT_ESTATE, "roof", estate) ==
	        NCFG_RECORD_OK &&
	    ncfg_record_subject_of_name(&hash, NCFG_RECORD_SUBJECT_GROUP, "roo", other) ==
	        NCFG_RECORD_OK;
	check(derived, "four names derive subjects");
	/* Zeroed above, so an unwritten buffer is all-zero rather than whatever
	 * the last frame left -- which is what made the first version pass. */
	check(derived && memcmp(group, again, sizeof(group)) == 0,
	    "the derivation is stable, or two hosts address different cells");
	check(derived && memcmp(group, estate, sizeof(group)) != 0,
	    "an estate of the same name differs, which the scope byte in the tag is for");
	check(derived && memcmp(group, other, sizeof(group)) != 0,
	    "a shorter name is a different subject, so the separator is doing its job");
	check(ncfg_record_subject_of_name(&hash, NCFG_RECORD_SUBJECT_HOST, "me", other) ==
	        NCFG_RECORD_ERR_SUBJECT,
	    "a host is named by its key, so deriving one from a name is refused");
	check(ncfg_record_subject_of_name(NULL, NCFG_RECORD_SUBJECT_GROUP, "roof", group) ==
	        NCFG_RECORD_ERR_MALFORMED,
	    "and no binding at all is the caller's bug, not a subject");
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
	fzn_hash_ops_t        hash;
	uint8_t               seed[FZN_SIGN_SEED_LEN];
	uint8_t               issuer[FZN_PUBKEY_LEN];
	uint8_t               subject[FZN_SUBJECT_LEN];
	ncfg_record_fields_t  fields;
	uint8_t               bytes[FZN_RECORD_MAX_LEN];
	size_t                len = 0u;
	fzn_record_t          opened;
	static const char     value[] = "\"office\"";
	size_t                at;

	for (at = 0u; at < sizeof(seed); at++) {
		seed[at] = (uint8_t)(0x40u + at);
	}
	fzn_sign_monocypher_init(&sign, &state);
	fzn_sign_monocypher_seat_init(&seat, &state);
	fzn_hash_monocypher_init(&hash);
	check(seat.install(seat.ctx, seed, issuer) != 0, "a signer is seated with a test seed");

	check(ncfg_record_subject_of_name(&hash, NCFG_RECORD_SUBJECT_ESTATE, "home", subject) ==
	        NCFG_RECORD_OK,
	    "the estate's subject derives");
	check(ncfg_record_encode(block_named("network"), "ssid", NCFG_RECORD_SUBJECT_ESTATE,
	          subject, value, sizeof(value) - 1u, &fields) == NCFG_RECORD_OK,
	    "and an SSID encodes against it");

	check(fzn_record_sign(issuer, fields.subject, fields.stream, fields.kind, 1u,
	          1759000000u, fields.body, fields.body_len, &sign, bytes, sizeof(bytes),
	          &len) == FZN_RECORD_OK,
	    "the fields sign into a record");
	check(fzn_record_open(bytes, len, &opened) == FZN_RECORD_OK,
	    "which fuzznet opens: the shape is one it knows");
	check(fzn_record_verify(opened, &sign) == FZN_RECORD_OK,
	    "and verifies against the issuer that signed it");

	/* **Against the registry and the constant, not against `fields`.** A
	 * comparison with the struct this encoder just filled would agree with
	 * whatever it put there, which is the same witness twice one call
	 * further along. */
	check(fzn_record_kind(opened) == ncfg_kind_of(block_named("network"), "ssid"),
	    "the kind reads back as the number the registry gives that key");
	check(fzn_record_stream(opened) == NCFG_STREAM_ESTATE,
	    "the stream reads back as the estate track, which the scope chose");
	check(memcmp(fzn_record_subject(opened), fields.subject, (size_t)FZN_SUBJECT_LEN) == 0,
	    "the subject reads back byte for byte");
	check(fzn_record_body_len(opened) == fields.body_len &&
	        memcmp(fzn_record_body(opened), value, sizeof(value) - 1u) == 0,
	    "and the body is the value exactly as the language spells it");

	fzn_sign_monocypher_wipe(&state);
}

int main(void)
{
	a_host_private_key_is_refused_as_such();
	a_key_nobody_registered_cannot_be_said();
	the_stream_comes_from_the_scope();
	a_subject_must_match_the_scope();
	a_refusal_leaves_the_fields_alone();
	the_bound_is_fuzznet_s();
	a_multi_line_value_is_ordinary_and_a_nul_is_not();
	a_name_becomes_a_subject_and_the_scope_is_in_it();
	the_fields_make_a_record_fuzznet_accepts();

	printf("record_encode_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("record_encode_test: all checks passed\n");
	} else {
		printf("record_encode_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
