/*
 * walk_test.c -- every key found, nothing skipped quietly, and the slice
 * re-parses to what it came from.
 *
 * WHAT IS WORTH CHECKING
 *   Not that a walk returns items. What separates a right walk from a wrong
 *   one:
 *
 *     * **the count**, because a walk that emitted half a document would look
 *       exactly like one that emitted all of a smaller one -- and the failure
 *       it causes is a host whose configuration silently half-replicated;
 *     * **a hook is reported, not skipped**, since a caller mirroring a file
 *       has to know the file holds something the estate will never see;
 *     * **a credential written as a path is withheld and the same key written
 *       `@secret:` is not**, which is the refusal `record_encode.c` could not
 *       make and the reason this layer exists;
 *     * **the label is carried**, because two interfaces have the same keys
 *       and only the label tells them apart;
 *     * **the value slice re-parses to the value it came from**, which is what
 *       makes "no second value encoder" a property rather than a claim.
 */
#include "ncfg/walk.h"

#include "ncfg/ast.h"
#include "ncfg/buf.h"
#include "ncfg/parse.h"

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

/*
 * A document with one of everything this file asserts about, written out here
 * rather than rendered from a model: what is under test is the reading of
 * text an operator could type.
 */
static const char SOURCE[] =
    "global {\n"
    "\tdns = [\"1.1.1.1\", \"8.8.8.8\"]\n"
    "\thostname = \"desk\"\n"
    "}\n"
    "interface \"wlan0\" {\n"
    "\tmtu = 1500\n"
    "\tmac = \"aa:bb:cc:dd:ee:ff\"\n"
    "\tadvertise {\n"
    "\t\tprefix = \"2001:db8::/64\"\n"
    "\t}\n"
    "\tdot1x {\n"
    "\t\tca_cert = \"/etc/ssl/certs/ca.pem\"\n"
    "\t\tclient_cert = \"@secret:client\"\n"
    "\t\tidentity = \"desk\"\n"
    "\t}\n"
    "\tpre_up {\n"
    "\t\techo hello\n"
    "\t}\n"
    "}\n"
    "interface \"eth0\" {\n"
    "\tmtu = 9000\n"
    "}\n"
    "porcupine \"spiky\" {\n"
    "\tquills = 12\n"
    "}\n";

/* Every item the walk hands back, copied, because the walk's pointers are
 * borrowed and die with the visit. */
typedef struct {
	ncfg_walk_what_t what;
	ncfg_withheld_t  withheld;
	char             block[32];
	char             label[64];
	size_t           label_len;
	char             path[64];
	char             value[128];
	size_t           value_len;
	ncfg_scope_t     scope;
	unsigned         kind;
} seen_t;

typedef struct {
	seen_t at[64];
	size_t count;
	/* Zero after this many, for the stop case. */
	size_t budget;
} collected_t;

static void copy_into(char *out, size_t cap, const char *from, size_t len)
{
	if (!from) {
		out[0] = '\0';
		return;
	}
	if (len >= cap) {
		len = cap - 1u;
	}
	memcpy(out, from, len);
	out[len] = '\0';
}

static int collect(void *ctx, const ncfg_walk_item_t *item)
{
	collected_t *into = ctx;
	seen_t      *slot;

	if (into->count >= sizeof(into->at) / sizeof(into->at[0])) {
		return 0;
	}
	slot = &into->at[into->count++];
	memset(slot, 0, sizeof(*slot));
	slot->what = item->what;
	slot->withheld = item->withheld;
	copy_into(slot->block, sizeof(slot->block), item->block_name,
	    item->block_name ? strlen(item->block_name) : 0u);
	copy_into(slot->label, sizeof(slot->label), item->label, item->label_len);
	slot->label_len = item->label_len;
	copy_into(slot->path, sizeof(slot->path), item->path,
	    item->path ? strlen(item->path) : 0u);
	copy_into(slot->value, sizeof(slot->value), item->value, item->value_len);
	slot->value_len = item->value_len;
	slot->scope = item->scope;
	slot->kind = item->kind;

	if (into->budget > 0u && into->count >= into->budget) {
		return 0;
	}
	return 1;
}

static const seen_t *find(const collected_t *all, const char *label, const char *path)
{
	size_t at;

	for (at = 0u; at < all->count; at++) {
		if (strcmp(all->at[at].path, path) != 0) {
			continue;
		}
		if (label && strcmp(all->at[at].label, label) != 0) {
			continue;
		}
		return &all->at[at];
	}
	return NULL;
}

static int walked(collected_t *into, const char *text)
{
	char err[512];

	memset(into, 0, sizeof(*into));
	return ncfg_walk(text, strlen(text), collect, into, err, sizeof(err));
}

/*
 * **The liveness half, and it goes first.** Every assertion below looks up one
 * path; a walk that found three things would answer most of them with "not
 * there" and fail in a way that reads like a missing feature. The count is
 * written out, so adding a key to the fixture is a deliberate edit here.
 */
static void the_walk_reaches_every_statement(void)
{
	collected_t all;

	check(walked(&all, SOURCE), "the fixture walks");
	/* global: dns, hostname. wlan0: mtu, mac, advertise.prefix,
	 * dot1x.ca_cert, dot1x.client_cert, dot1x.identity, pre_up.
	 * eth0: mtu. And the block this build does not know. */
	check(all.count == 11u, "eleven statements, counted rather than assumed");
}

static void a_key_that_travels_carries_its_number_and_scope(void)
{
	collected_t   all;
	const seen_t *mtu;

	(void)walked(&all, SOURCE);
	mtu = find(&all, "wlan0", "mtu");
	check(mtu != NULL, "an interface's MTU is found");
	check(mtu && mtu->what == NCFG_WALK_EMIT, "and travels");
	check(mtu && mtu->scope == NCFG_SCOPE_HOST, "about this host");
	check(mtu && mtu->kind != NCFG_KIND_NONE, "under a number from the registry");
	check(mtu && mtu->value_len == 4u && memcmp(mtu->value, "1500", 4u) == 0,
	    "with the value exactly as it was written");
}

/*
 * Two interfaces have the same keys, so the label is the only thing that tells
 * their values apart. Nothing downstream can recover it.
 */
static void the_label_tells_two_instances_apart(void)
{
	collected_t   all;
	const seen_t *wlan;
	const seen_t *eth;

	(void)walked(&all, SOURCE);
	wlan = find(&all, "wlan0", "mtu");
	eth = find(&all, "eth0", "mtu");
	check(wlan && eth, "both interfaces' MTU is found");
	check(wlan && eth && strcmp(wlan->value, eth->value) != 0,
	    "they carry different values");
	check(wlan && eth && wlan->kind == eth->kind,
	    "under the SAME number, because the number names the key and not the link");
	check(wlan && strcmp(wlan->label, "wlan0") == 0 && eth &&
	        strcmp(eth->label, "eth0") == 0,
	    "so the label is the only thing that separates them, and it is carried");
}

/*
 * **A label arrives with its length**, because a network's label is an SSID
 * and an SSID is 32 arbitrary bytes. `bridge/record_encode.h` hashes it into a
 * subject and takes it the same way; handing over the pointer alone would
 * shorten a network whose name holds a NUL, and two of those would share a
 * cell -- the fault 10.329 exists to close, arriving by a second route.
 */
static void a_label_arrives_with_its_length(void)
{
	collected_t   all;
	const seen_t *mtu;

	(void)walked(&all, SOURCE);
	mtu = find(&all, "wlan0", "mtu");
	check(mtu != NULL && mtu->label_len == 5u,
	    "a label's length is carried, not recomputed from the pointer");
	check(mtu != NULL && strlen(mtu->label) == mtu->label_len,
	    "and agrees with the bytes for a label that is ordinary text");
}

static void a_hook_is_reported_rather_than_passed_over(void)
{
	collected_t   all;
	const seen_t *hook;

	(void)walked(&all, SOURCE);
	hook = find(&all, "wlan0", "pre_up");
	check(hook != NULL, "a hook is reported");
	check(hook && hook->what == NCFG_WALK_WITHHELD &&
	        hook->withheld == NCFG_WITHHELD_PROGRAM,
	    "as a program, which never travels");
}

static void a_host_private_key_is_withheld_as_one(void)
{
	collected_t   all;
	const seen_t *mac;

	(void)walked(&all, SOURCE);
	mac = find(&all, "wlan0", "mac");
	check(mac != NULL, "a MAC is reported");
	check(mac && mac->what == NCFG_WALK_WITHHELD &&
	        mac->withheld == NCFG_WITHHELD_HOST_PRIVATE,
	    "and withheld as host-private rather than emitted");
}

/*
 * **The refusal this layer exists for.** `record_encode.c` takes bytes and has
 * no document model, so it cannot tell a stored secret from a path. Here the
 * written value is in hand, and the two spellings of one key separate.
 */
static void a_credential_written_as_a_path_is_withheld(void)
{
	collected_t   all;
	const seen_t *path_form;
	const seen_t *stored_form;

	(void)walked(&all, SOURCE);
	path_form = find(&all, "wlan0", "dot1x.ca_cert");
	stored_form = find(&all, "wlan0", "dot1x.client_cert");
	check(path_form != NULL && stored_form != NULL, "both cert keys are reported");
	check(path_form && path_form->withheld == NCFG_WITHHELD_PRIVILEGED,
	    "a bare path is withheld as privileged: it is a file to open as root");
	check(stored_form && stored_form->withheld != NCFG_WITHHELD_PRIVILEGED,
	    "while `@secret:` under the same key is not");
	/* The stored form is still unregistered, and must say so rather than
	 * inheriting the other's reason -- 10.327 turns on the difference. */
	check(stored_form && stored_form->withheld == NCFG_WITHHELD_UNREGISTERED,
	    "it is withheld for the other reason, which is the one that will change");
}

static void a_block_this_build_does_not_know_is_one_report(void)
{
	collected_t   all;
	const seen_t *unknown;
	size_t        at;
	int           from_it = 0;

	(void)walked(&all, SOURCE);
	unknown = find(&all, "spiky", "");
	check(unknown != NULL, "an unknown block is reported");
	check(unknown && unknown->withheld == NCFG_WITHHELD_UNKNOWN_BLOCK,
	    "as a block this build cannot read");
	for (at = 0u; at < all.count; at++) {
		if (strcmp(all.at[at].block, "porcupine") == 0 && all.at[at].path[0] != '\0') {
			from_it++;
		}
	}
	check(from_it == 0,
	    "and nothing inside it is named, because nothing here knows what it means");
}

static void a_visit_that_stops_stops_the_walk(void)
{
	collected_t all;
	char        err[512];

	memset(&all, 0, sizeof(all));
	all.budget = 3u;
	check(ncfg_walk(SOURCE, strlen(SOURCE), collect, &all, err, sizeof(err)) == 1,
	    "a caller that has seen enough has not met a broken document");
	check(all.count == 3u, "and the walk stopped where it was told to");
}

static void a_document_that_does_not_parse_visits_nothing(void)
{
	collected_t all;
	char        err[512];
	static const char broken[] = "interface \"wlan0\" {\n\tmtu = \n";

	memset(&all, 0, sizeof(all));
	err[0] = '\0';
	check(ncfg_walk(broken, strlen(broken), collect, &all, err, sizeof(err)) == 0,
	    "a document with a mistake in it is refused");
	check(all.count == 0u, "and nothing is visited, so half of it cannot be replicated");
	check(err[0] != '\0', "with a sentence saying why");
}

/*
 * THE PROPERTY, RATHER THAN A TABLE
 *
 * Rebuild a document from what the walk emitted -- `key = <slice>` under the
 * block and label it came from -- and walk that. If a slice were not the
 * value's own spelling, the second walk would differ: a value that re-parsed
 * to something else would come back spelled differently, and one that did not
 * re-parse at all would take the whole document down.
 *
 * This is what makes "there is no second value encoder here" checkable.
 */
static void a_slice_reparses_to_the_value_it_came_from(void)
{
	collected_t all;
	size_t      at;
	int         emitted = 0;
	int         round_tripped = 0;

	(void)walked(&all, SOURCE);
	for (at = 0u; at < all.count; at++) {
		const seen_t     *one = &all.at[at];
		ncfg_buf_t        wrapped;
		ncfg_ast_file_t  *file = NULL;
		char              err[512];
		const char       *slice;
		size_t            slice_len;

		if (one->what != NCFG_WALK_EMIT) {
			continue;
		}
		emitted++;

		/* The value alone, under a key of no interest, in the only
		 * place the grammar accepts one. */
		ncfg_buf_init(&wrapped, 0);
		ncfg_buf_addf(&wrapped, "global {\n\tdns_mode = %s\n}\n", one->value);
		if (!ncfg_parse(ncfg_buf_text(&wrapped), wrapped.length, &file, NULL, err,
		        sizeof(err))) {
			printf("       %s did not re-parse: %s\n", one->path, err);
			ncfg_buf_free(&wrapped);
			continue;
		}
		/* And it must come back spelled the same. Re-parsing is the
		 * weaker half: a slice that lost a character could still parse,
		 * as a shorter value nobody would see was short. */
		{
			const ncfg_ast_item_t *block = file->items.at[0];
			const ncfg_ast_item_t *line = block->as.block.items.at[0];

			slice = ncfg_buf_text(&wrapped) + line->as.assignment.value->span.offset;
			slice_len = line->as.assignment.value->span.length;
			if (slice_len == one->value_len &&
			    memcmp(slice, one->value, slice_len) == 0) {
				round_tripped++;
			} else {
				printf("       %s came back as [%.*s], not [%s]\n", one->path,
				    (int)slice_len, slice, one->value);
			}
		}
		ncfg_ast_file_free(file);
		ncfg_buf_free(&wrapped);
	}
	check(emitted > 0, "the fixture emits something to round-trip");
	check(emitted == round_tripped,
	    "every emitted slice re-parses, and comes back spelled the same");
}

/*
 * A list is the node whose span had to be fixed for any of this to work. It is
 * asserted separately because it is the one case a slice silently truncated,
 * and it would have truncated to something that still parses -- `[` does not,
 * which is the only reason it was noticed at all.
 */
static void a_list_slices_to_the_whole_list(void)
{
	collected_t   all;
	const seen_t *dns;

	(void)walked(&all, SOURCE);
	dns = find(&all, NULL, "dns");
	check(dns != NULL, "global's resolver list is found");
	check(dns && strcmp(dns->value, "[\"1.1.1.1\", \"8.8.8.8\"]") == 0,
	    "and slices to the whole list, brackets and entries");
}

int main(void)
{
	the_walk_reaches_every_statement();
	a_key_that_travels_carries_its_number_and_scope();
	the_label_tells_two_instances_apart();
	a_label_arrives_with_its_length();
	a_hook_is_reported_rather_than_passed_over();
	a_host_private_key_is_withheld_as_one();
	a_credential_written_as_a_path_is_withheld();
	a_block_this_build_does_not_know_is_one_report();
	a_visit_that_stops_stops_the_walk();
	a_document_that_does_not_parse_visits_nothing();
	a_slice_reparses_to_the_value_it_came_from();
	a_list_slices_to_the_whole_list();

	printf("walk_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("walk_test: all checks passed\n");
	} else {
		printf("walk_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
