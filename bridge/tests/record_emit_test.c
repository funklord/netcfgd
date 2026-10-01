/*
 * record_emit_test.c -- what a configuration would replicate, and what it
 * would not.
 *
 * WHAT IS WORTH CHECKING
 *   Not that records come out. What separates a right join from a wrong one:
 *
 *     * **the tally adds up**, because a key counted in no column is a key
 *       that silently neither travelled nor was withheld -- the failure mode
 *       of a sweep that drops things;
 *     * **a value too large is refused and counted apart**, because the walker
 *       checks the key and not the value, so this is the only place a document
 *       that grew a list stops being replicable;
 *     * **an absent root refuses rather than invents**, which is the one
 *       mistake a subject cannot recover from;
 *     * **every record carries the number the registry gives its key**, which
 *       is what makes the join a join rather than two things run in sequence.
 */
#include "../record_emit.h"

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
static uint8_t        HOST_KEY[FZN_PUBKEY_LEN];

/* A configuration of the shape the reporting machine runs: a radio, a wired
 * link, two networks and the global resolver policy. */
static const char SOURCE[] =
    "global {\n"
    "\tdns = [\"1.1.1.1\"]\n"
    "\thostname = \"desk\"\n"
    "}\n"
    "device wlan0 {\n"
    "\twifi { autoconnect = true }\n"
    "}\n"
    "interface wlan0 {\n"
    "\tconfig = \"dhcp\"\n"
    "\tmtu = 1500\n"
    "\tmac = \"aa:bb:cc:dd:ee:ff\"\n"
    /* Estate-scoped and deliberately unregistered -- the three cert keys that
     * accept either a stored secret or a root-readable path, which 10.327
     * leaves without a number until an encoder can refuse the path form. The
     * one key in the language that is neither host-private nor numbered, and
     * so the only way this fixture can tell those two columns apart. */
    "\tdot1x {\n"
    "\t\teap = \"peap\"\n"
    "\t\tca_cert = \"@secret:ca\"\n"
    "\t}\n"
    "}\n"
    "network \"home\" {\n"
    "\tssid = \"home\"\n"
    "\tmetric = 100\n"
    "}\n";

typedef struct {
	size_t seen;
	size_t with_a_number;
	char   first_path[64];
} kept_t;

static int keep(void *ctx, const ncfg_walk_item_t *key, const ncfg_record_fields_t *fields)
{
	kept_t *kept = ctx;

	if (kept->seen == 0u) {
		(void)snprintf(kept->first_path, sizeof(kept->first_path), "%s", key->path);
	}
	kept->seen++;
	/* Against the registry rather than against the struct the encoder filled,
	 * which would agree with whatever it put there. */
	if (fields->kind == ncfg_kind_of(key->block, key->path) &&
	    fields->kind != NCFG_KIND_NONE) {
		kept->with_a_number++;
	}
	return 1;
}

static ncfg_record_rootref_t host_root(void)
{
	ncfg_record_rootref_t root;

	memset(&root, 0, sizeof(root));
	root.kind = NCFG_ROOT_HOST;
	root.key = HOST_KEY;
	return root;
}

static ncfg_record_rootref_t named(ncfg_record_root_t kind, const char *name)
{
	ncfg_record_rootref_t root;

	memset(&root, 0, sizeof(root));
	root.kind = kind;
	root.name = name;
	return root;
}

static size_t total(const ncfg_emit_tally_t *tally)
{
	size_t sum = tally->emitted + tally->refused;
	size_t at;

	for (at = 0u; at < NCFG_EMIT_REASONS; at++) {
		sum += tally->withheld[at];
	}
	return sum;
}

/*
 * **The liveness check and the arithmetic in one.** Every statement the walk
 * reports lands in exactly one column, so a key that fell out of the join
 * entirely shows up as a total that does not match.
 */
static void every_key_lands_in_exactly_one_column(void)
{
	ncfg_record_rootref_t h = host_root();
	ncfg_record_rootref_t g = named(NCFG_ROOT_GROUP, "zone");
	ncfg_record_rootref_t e = named(NCFG_ROOT_ESTATE, "home");
	ncfg_emit_roots_t     roots = { &h, &g, &e };
	ncfg_emit_tally_t     tally;
	kept_t                kept;
	char                  err[512];

	memset(&kept, 0, sizeof(kept));
	check(ncfg_records_of(SOURCE, strlen(SOURCE), &hash, &roots, keep, &kept, &tally, err,
	          sizeof(err)) == 1,
	    "the configuration walks");
	/* global: dns, hostname. wlan0 device: wifi.autoconnect. wlan0 interface:
	 * config, mtu, mac, dot1x.eap, dot1x.ca_cert. network home: ssid, metric. */
	check(total(&tally) == 10u, "ten statements, every one of them counted once");
	check(tally.emitted > 0u, "and some of them travel");
	check(tally.emitted == kept.seen, "the sink saw exactly what the tally counted");
	check(kept.seen == kept.with_a_number,
	    "every record carries the number the registry gives its key");
}

/* The columns are the answer, not the total: "almost nothing is registered"
 * and "almost all of it is host-private" are different findings. */
static void the_reasons_are_kept_apart(void)
{
	ncfg_record_rootref_t h = host_root();
	ncfg_record_rootref_t g = named(NCFG_ROOT_GROUP, "zone");
	ncfg_record_rootref_t e = named(NCFG_ROOT_ESTATE, "home");
	ncfg_emit_roots_t     roots = { &h, &g, &e };
	ncfg_emit_tally_t     tally;
	char                  err[512];

	(void)ncfg_records_of(SOURCE, strlen(SOURCE), &hash, &roots, NULL, NULL, &tally, err,
	    sizeof(err));
	check(tally.withheld[NCFG_WITHHELD_HOST_PRIVATE] >= 2u,
	    "a MAC and a global hostname are withheld as host-private");
	check(tally.withheld[NCFG_WITHHELD_UNREGISTERED] >= 1u,
	    "and a key with no wire number is withheld as unregistered, separately");
	check(tally.refused == 0u, "nothing here is refused for its value");
}

/*
 * **A passphrase written out never reaches the encoder.**
 *
 * The walker proves the verdict; this proves the consequence, which is the only
 * thing a caller of the join can see. The sink counts what it is offered, so a
 * literal that was withheld and a literal that was emitted differ here by a
 * number rather than by a verdict nobody reads.
 *
 * Its own text and not `SOURCE`, because the case above counts every statement
 * in that fixture and a key added to it makes an unrelated assertion fail.
 */
static void a_written_passphrase_never_reaches_the_encoder(void)
{
	static const char TEXT[] =
	    "network \"Written\" {\n"
	    "\tssid = \"Written\"\n"
	    "\twifi {\n"
	    "\t\tpsk = \"a-literal-passphrase\"\n"
	    "\t}\n"
	    "}\n";
	ncfg_record_rootref_t h = host_root();
	ncfg_record_rootref_t g = named(NCFG_ROOT_GROUP, "zone");
	ncfg_record_rootref_t e = named(NCFG_ROOT_ESTATE, "home");
	ncfg_emit_roots_t     roots = { &h, &g, &e };
	ncfg_emit_tally_t     tally;
	kept_t                kept;
	char                  err[512];

	memset(&kept, 0, sizeof(kept));
	check(ncfg_records_of(TEXT, strlen(TEXT), &hash, &roots, keep, &kept, &tally, err,
	          sizeof(err)) == 1,
	    "a document holding a written passphrase still walks");
	check(tally.withheld[NCFG_WITHHELD_PLAINTEXT] == 1u,
	    "the passphrase is counted as withheld plaintext");
	check(tally.emitted == 1u && kept.seen == 1u,
	    "and the ssid beside it travels, so the document is not simply refused");
	check(total(&tally) == 2u, "two statements, both counted once");
}

/*
 * **The one the walker cannot catch.** It checks the key; a body over
 * `FZN_RECORD_BODY_MAX` is a property of the value, which a document acquires
 * by growing a list with nothing about the key changing.
 */
static void a_value_too_large_for_a_body_is_refused_and_counted_apart(void)
{
	ncfg_record_rootref_t h = host_root();
	ncfg_emit_roots_t     roots = { &h, NULL, NULL };
	ncfg_emit_tally_t     tally;
	char                  err[512];
	static char           text[FZN_RECORD_BODY_MAX + 256u];
	size_t                at;
	int                   wrote;

	/* One `config` whose quoted value alone exceeds the body bound. */
	wrote = snprintf(text, sizeof(text), "interface wlan0 {\n\tconfig = \"");
	for (at = 0u; at < (size_t)FZN_RECORD_BODY_MAX && (size_t)wrote < sizeof(text) - 8u;
	    at++) {
		text[wrote++] = 'x';
	}
	wrote += snprintf(text + wrote, sizeof(text) - (size_t)wrote, "\"\n}\n");

	(void)ncfg_records_of(text, (size_t)wrote, &hash, &roots, NULL, NULL, &tally, err,
	    sizeof(err));
	check(tally.refused == 1u, "a value larger than a record body is refused");
	check(tally.last_refusal == NCFG_RECORD_ERR_TOO_LARGE, "and says it was the size");
	check(tally.emitted == 0u, "and does not also count as emitted");
}

/*
 * A document names no estate. Inventing one would put records under a subject
 * nobody chose, and every host would invent a different one.
 */
static void a_missing_root_refuses_rather_than_inventing_one(void)
{
	ncfg_record_rootref_t h = host_root();
	ncfg_emit_roots_t     roots = { &h, NULL, NULL };
	ncfg_emit_tally_t     tally;
	char                  err[512];

	(void)ncfg_records_of(SOURCE, strlen(SOURCE), &hash, &roots, NULL, NULL, &tally, err,
	    sizeof(err));
	check(tally.refused >= 1u, "an estate-wide key with no estate named is refused");
	check(tally.last_refusal == NCFG_RECORD_ERR_SUBJECT, "for want of a subject");
}

/* A document that does not compile is not a document somebody wrote, so the
 * tally is about nothing and says so. */
static void a_broken_document_counts_nothing(void)
{
	ncfg_record_rootref_t h = host_root();
	ncfg_emit_roots_t     roots = { &h, NULL, NULL };
	ncfg_emit_tally_t     tally;
	char                  err[512];
	static const char     broken[] = "interface wlan0 {\n\tmtu = \n";

	err[0] = '\0';
	check(ncfg_records_of(broken, strlen(broken), &hash, &roots, NULL, NULL, &tally, err,
	          sizeof(err)) == 0,
	    "a document with a mistake in it is refused");
	check(total(&tally) == 0u, "and the tally is zero rather than part-counted");
	check(err[0] != '\0', "with a sentence saying why");
}

int main(void)
{
	size_t at;

	for (at = 0u; at < sizeof(HOST_KEY); at++) {
		HOST_KEY[at] = (uint8_t)(at + 1u);
	}
	fzn_hash_monocypher_init(&hash);

	every_key_lands_in_exactly_one_column();
	the_reasons_are_kept_apart();
	a_written_passphrase_never_reaches_the_encoder();
	a_value_too_large_for_a_body_is_refused_and_counted_apart();
	a_missing_root_refuses_rather_than_inventing_one();
	a_broken_document_counts_nothing();

	printf("record_emit_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("record_emit_test: all checks passed\n");
	} else {
		printf("record_emit_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
