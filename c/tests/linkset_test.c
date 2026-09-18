/*
 * linkset_test.c -- failover, and the list it appears in.
 *
 * WHAT IS HERE
 *   `crates/netcfgd-model/src/linkset.rs`'s eight tests, each of which names a
 *   case that matters rather than a line of code: the best working member
 *   winning, a network standing on its radio rather than on itself, a tie
 *   going to the order the document wrote, a set composing into a set, a set
 *   that names itself being reported instead of followed, the four ways a
 *   member can be unusable told apart, a link naming its sets under either of
 *   its two spellings, and a document with no such set having no answer.
 *
 * AND THE THREE THE C NEEDS AND THE RUST DOES NOT
 *   * **Two sets that name each other**, which the Rust's one self-naming test
 *     does not cover: the guard is a list of names, and a list is only tested
 *     by a cycle longer than one.
 *   * **A chain deeper than the bound.** Rust would abort on a stack overflow;
 *     C would run off the stack and corrupt something on the way, so the bound
 *     is the difference between a bad document and a bad machine. Both chains
 *     are built from `NCFG_LINKSET_MAX_DEPTH` rather than from the number 8,
 *     so they move with it -- a test that spelled the number itself would go
 *     on passing after the bound changed.
 *   * **Freeing what was never filled in**, which is base.h's third convention
 *     and is a rule here rather than a type.
 *
 * THE FIXTURES ARE JSON, AS THE RUST'S ARE
 *   `linkset.rs` builds its links and blocks with `serde_json::from_value` and
 *   says why: these structs have no default, and a literal would have to be
 *   edited every time one gains a field. The same argument holds harder here,
 *   where nothing would warn. What a fixture states is what the case is about;
 *   everything else is whatever the schema says.
 */
#include "ncfg/base.h"
#include "ncfg/document.h"
#include "ncfg/linkset.h"
#include "ncfg/observed.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-62s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* ------------------------------------------------------------------------ *
 * The fixtures
 * ------------------------------------------------------------------------ */

/*
 * A document carrying these interfaces, networks and linksets.
 *
 * The scaffold is the four members the reader requires and nothing else, so a
 * member that quietly became required fails here rather than in a module that
 * depends on this one. The schema version comes from the header: a test that
 * wrote the numbers itself would have to be edited on every bump, and would
 * then be asserting its own copy of them.
 */
static ncfg_document_t *document_of(const char *interfaces, const char *networks,
    const char *linksets)
{
	char             text[8192];
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document;

	snprintf(text, sizeof(text),
	    "{\"schema_version\":{\"major\":%d,\"minor\":%d},\"globals\":{},\"devices\":[],"
	    "\"interfaces\":[%s],\"networks\":[%s],\"linksets\":[%s]}",
	    NCFG_SCHEMA_MAJOR, NCFG_SCHEMA_MINOR, interfaces, networks, linksets);
	message[0] = '\0';
	document = ncfg_document_read(text, strlen(text), message, sizeof(message));
	if (!document) {
		printf("  could not build a document: %s\n", message);
	}
	return document;
}

static ncfg_observed_t *observed_of(const char *links)
{
	char             text[8192];
	char             message[NCFG_ERROR_MAX];
	ncfg_observed_t *observed;

	snprintf(text, sizeof(text), "{\"links\":[%s]}", links);
	message[0] = '\0';
	observed = ncfg_observed_read(text, strlen(text), message, sizeof(message));
	if (!observed) {
		printf("  could not build an observation: %s\n", message);
	}
	return observed;
}

/*
 * `linkset.rs`'s own `fn link`, written as text and appended to a list.
 *
 * `wireless` follows from a network being named, exactly as the Rust's helper
 * has it: a member that stands on a radio has to be carried by one.
 */
static void add_link(char *text, size_t size, const char *name, int up, int carrier,
    const char *network)
{
	size_t at = strlen(text);

	snprintf(text + at, size - at,
	    "%s{\"name\":\"%s\",\"index\":1,\"kind\":\"\",\"wireless\":%s,\"up\":%s,"
	    "\"carrier\":%s,\"mtu\":1500%s%s%s}",
	    at > 0u ? "," : "", name, network ? "true" : "false", up ? "true" : "false",
	    carrier ? "true" : "false", network ? ",\"network\":\"" : "",
	    network ? network : "", network ? "\"" : "");
}

static void add_text(char *text, size_t size, const char *piece)
{
	size_t at = strlen(text);

	snprintf(text + at, size - at, "%s%s", at > 0u ? "," : "", piece);
}

/* The link by this name, to be changed: the Rust assigns into
 * `observed.links[0]`, and the index it uses is not one this port can promise
 * a reader kept. */
static ncfg_observed_link_t *changeable_link(ncfg_observed_t *observed, const char *name)
{
	size_t i;

	for (i = 0; observed && i < observed->link_count; i++) {
		if (observed->links[i].name && strcmp(observed->links[i].name, name) == 0) {
			return &observed->links[i];
		}
	}
	printf("  the fixture has no link called `%s`\n", name);
	return NULL;
}

static ncfg_interface_t *changeable_interface(ncfg_document_t *document, const char *name)
{
	size_t i;

	for (i = 0; document && i < document->interface_count; i++) {
		if (document->interfaces[i].name &&
		    strcmp(document->interfaces[i].name, name) == 0) {
			return &document->interfaces[i];
		}
	}
	printf("  the fixture has no interface called `%s`\n", name);
	return NULL;
}

/* ------------------------------------------------------------------------ *
 * Asking the questions
 * ------------------------------------------------------------------------ */

/*
 * The choice, or NULL where the document has no set by that name.
 *
 * A failure is a third answer and is printed rather than quietly becoming the
 * second -- which is the whole reason this port answers through an
 * out-parameter instead of returning the pointer.
 */
static ncfg_chosen_t *choice_of(const ncfg_document_t *document, const ncfg_observed_t *observed,
    const char *name)
{
	char           message[NCFG_ERROR_MAX];
	ncfg_chosen_t *chosen = NULL;

	message[0] = '\0';
	if (!ncfg_linkset_choose(document, observed, name, &chosen, message, sizeof(message))) {
		printf("  could not choose within `%s`: %s\n", name, message);
		return NULL;
	}
	return chosen;
}

static int text_is(const char *text, const char *expected)
{
	if (!text || !expected) {
		return text == expected;
	}
	return strcmp(text, expected) == 0;
}

static int active_is(const ncfg_chosen_t *chosen, const char *name)
{
	return chosen && text_is(chosen->active, name);
}

static int carried_by(const ncfg_chosen_t *chosen, const char *name)
{
	return chosen && text_is(chosen->interface, name);
}

/* The reason member `index` gives, or -1 where it gives none. */
static int reason_of(const ncfg_chosen_t *chosen, size_t index)
{
	if (!chosen || index >= chosen->member_count) {
		return -2;
	}
	return chosen->members[index].ineligible.has ?
	    (int)chosen->members[index].ineligible.value : -1;
}

static const ncfg_link_entry_t *row_named(const ncfg_link_entry_t *entries, size_t count,
    const char *name)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (text_is(entries[i].name, name)) {
			return &entries[i];
		}
	}
	return NULL;
}

static int row_is_in_set(const ncfg_link_entry_t *row, const char *set)
{
	size_t i;

	for (i = 0; row && i < row->set_count; i++) {
		if (text_is(row->sets[i], set)) {
			return 1;
		}
	}
	return 0;
}

int main(void)
{
	/* ---- the whole point, in one assertion: two links that work, one in use ---- */
	{
		ncfg_document_t *document = document_of(
		    "{\"name\":\"eth0\",\"preference\":100},{\"name\":\"wwan0\",\"preference\":700}",
		    "", "{\"name\":\"" NCFG_LINKSET_UPLINK "\",\"members\":[\"eth0\",\"wwan0\"]}");
		char             links[1024] = "";
		ncfg_observed_t *observed;
		ncfg_chosen_t   *chosen;
		int              every_member_eligible = 1;
		size_t           i;

		add_link(links, sizeof(links), "eth0", 1, 1, NULL);
		add_link(links, sizeof(links), "wwan0", 1, 1, NULL);
		observed = observed_of(links);

		chosen = choice_of(document, observed, NCFG_LINKSET_UPLINK);
		check(active_is(chosen, "eth0") && carried_by(chosen, "eth0"),
		    "the best working member is the one in use");
		for (i = 0; chosen && i < chosen->member_count; i++) {
			if (chosen->members[i].ineligible.has) {
				every_member_eligible = 0;
			}
		}
		check(every_member_eligible, "and while both work, neither is refused");
		ncfg_chosen_free(chosen);

		/* The cable comes out and the modem takes over, with no configuration
		 * change at all. This is the sentence the whole thing exists to say. */
		if (changeable_link(observed, "eth0")) {
			changeable_link(observed, "eth0")->carrier = 0;
		}
		chosen = choice_of(document, observed, NCFG_LINKSET_UPLINK);
		check(active_is(chosen, "wwan0"),
		    "the cable comes out and the modem takes over, unconfigured");
		check(reason_of(chosen, 0) == NCFG_INELIGIBLE_NO_CARRIER,
		    "and it says why the cable lost");
		ncfg_chosen_free(chosen);

		ncfg_document_free(document);
		ncfg_observed_free(observed);
	}

	/* ---- a network is a member like any other, and stands on its radio ---- */
	{
		ncfg_document_t *document = document_of("{\"name\":\"eth0\",\"preference\":100}",
		    "{\"id\":\"office\",\"security\":{\"type\":\"open\"},\"metric\":50}",
		    "{\"name\":\"" NCFG_LINKSET_UPLINK "\",\"members\":[\"eth0\",\"office\"]}");
		char             links[1024] = "";
		ncfg_observed_t *observed;
		ncfg_chosen_t   *chosen;

		add_link(links, sizeof(links), "eth0", 1, 1, NULL);
		add_link(links, sizeof(links), "wlan0", 1, 1, "office");
		observed = observed_of(links);

		/* The network wins on metric, and what carries it is the radio --
		 * which `preference` could not express at all, because it lives on an
		 * interface and a network is not one. */
		chosen = choice_of(document, observed, NCFG_LINKSET_UPLINK);
		check(active_is(chosen, "office") && carried_by(chosen, "wlan0"),
		    "a network is a member, and stands on the radio that joined it");
		ncfg_chosen_free(chosen);

		/* A saved network nothing is on is unjoined rather than absent: the
		 * network is fine, there is simply no radio on it. */
		ncfg_observed_free(observed);
		links[0] = '\0';
		add_link(links, sizeof(links), "eth0", 1, 1, NULL);
		observed = observed_of(links);
		chosen = choice_of(document, observed, NCFG_LINKSET_UPLINK);
		check(active_is(chosen, "eth0"), "and with no radio on it the cable wins");
		check(reason_of(chosen, 1) == NCFG_INELIGIBLE_UNJOINED &&
		    chosen->members[1].interface == NULL,
		    "a configured network nothing is on is unjoined, not absent");
		ncfg_chosen_free(chosen);

		ncfg_document_free(document);
		ncfg_observed_free(observed);
	}

	/* ---- ties, and the metric rule that looks backwards ---- */
	{
		ncfg_document_t *document = document_of("{\"name\":\"eth0\"},{\"name\":\"eth1\"}", "",
		    "{\"name\":\"office\",\"members\":[\"eth1\",\"eth0\"]}");
		char              links[1024] = "";
		ncfg_observed_t  *observed;
		ncfg_chosen_t    *chosen;
		ncfg_interface_t *eth1;

		add_link(links, sizeof(links), "eth0", 1, 1, NULL);
		add_link(links, sizeof(links), "eth1", 1, 1, NULL);
		observed = observed_of(links);

		chosen = choice_of(document, observed, "office");
		check(active_is(chosen, "eth1"),
		    "members that cannot be told apart go in the order written");
		ncfg_chosen_free(chosen);

		/*
		 * **An absent metric reads as 0, which is the strongest**, so writing
		 * a metric on one member and not on the other demotes the one that was
		 * written. That looks backwards and is the only answer that keeps the
		 * set and the kernel agreeing: an unnumbered route goes in at metric 0
		 * too, so a set that ranked the unnumbered member last would pick one
		 * link while the routing table used the other.
		 */
		eth1 = changeable_interface(document, "eth1");
		if (eth1) {
			eth1->preference.has = 1;
			eth1->preference.value = 10;
		}
		chosen = choice_of(document, observed, "office");
		check(active_is(chosen, "eth0"), "an absent metric beats a stated one, and must");
		ncfg_chosen_free(chosen);

		ncfg_document_free(document);
		ncfg_observed_free(observed);
	}

	/* ---- a set is a link, so a set composes into a set ---- */
	{
		ncfg_document_t *document = document_of(
		    "{\"name\":\"eth0\",\"preference\":100},{\"name\":\"eth1\",\"preference\":200},"
		    "{\"name\":\"wwan0\",\"preference\":700}",
		    "",
		    "{\"name\":\"office\",\"members\":[\"eth0\",\"eth1\"]},"
		    "{\"name\":\"" NCFG_LINKSET_UPLINK "\",\"members\":[\"office\",\"wwan0\"]}");
		char             links[1024] = "";
		ncfg_observed_t *observed;
		ncfg_chosen_t   *chosen;

		add_link(links, sizeof(links), "eth0", 1, 0, NULL);
		add_link(links, sizeof(links), "eth1", 1, 1, NULL);
		add_link(links, sizeof(links), "wwan0", 1, 1, NULL);
		observed = observed_of(links);

		chosen = choice_of(document, observed, NCFG_LINKSET_UPLINK);
		check(active_is(chosen, "office") && carried_by(chosen, "eth1"),
		    "a nested set is carried by its own answer");
		check(chosen && chosen->members[0].metric.has &&
		    chosen->members[0].metric.value == 200,
		    "and competes on its winner's metric, not on one of its own");
		ncfg_chosen_free(chosen);

		/* The inner set empties, and the outer one says so rather than
		 * pretending it is absent -- two different things to do about it. */
		if (changeable_link(observed, "eth1")) {
			changeable_link(observed, "eth1")->carrier = 0;
		}
		chosen = choice_of(document, observed, NCFG_LINKSET_UPLINK);
		check(active_is(chosen, "wwan0") && reason_of(chosen, 0) == NCFG_INELIGIBLE_EMPTY,
		    "a nested set with nothing usable is empty, not absent");
		ncfg_chosen_free(chosen);

		ncfg_document_free(document);
		ncfg_observed_free(observed);
	}

	/* ---- a set that names itself is reported and not followed ---- */
	{
		ncfg_document_t *document = document_of("{\"name\":\"eth0\"}", "",
		    "{\"name\":\"a\",\"members\":[\"b\"]},"
		    "{\"name\":\"b\",\"members\":[\"a\",\"eth0\"]}");
		char             links[1024] = "";
		ncfg_observed_t *observed;
		ncfg_chosen_t   *chosen;

		add_link(links, sizeof(links), "eth0", 1, 1, NULL);
		observed = observed_of(links);

		/* `b` is reachable through `a`, and inside it `a` is refused -- so the
		 * cycle costs the machine nothing: `eth0` still wins. */
		chosen = choice_of(document, observed, "a");
		check(active_is(chosen, "b") && carried_by(chosen, "eth0"),
		    "a cycle costs the machine nothing: the working link still wins");
		ncfg_chosen_free(chosen);
		ncfg_document_free(document);
		ncfg_observed_free(observed);

		document = document_of("", "", "{\"name\":\"a\",\"members\":[\"a\"]}");
		observed = observed_of("");
		chosen = choice_of(document, observed, "a");
		check(active_is(chosen, NULL) && reason_of(chosen, 0) == NCFG_INELIGIBLE_CYCLE,
		    "a set that names itself is reported as a cycle, not followed");
		ncfg_chosen_free(chosen);
		ncfg_document_free(document);
		ncfg_observed_free(observed);
	}

	/* ---- two sets that name each other ---- */
	{
		/* A cycle longer than one, which the self-naming case above does not
		 * reach: the guard walks a list of the sets in progress, and a list
		 * with one entry is not a list. What is asserted is the outcome, from
		 * either end -- it stops, and has nothing to offer. Which of the two
		 * guards stopped it is not visible from out here, because only the
		 * outer set's answer comes back; the self-naming case is what pins the
		 * reason to `cycle`. */
		ncfg_document_t *document = document_of("", "",
		    "{\"name\":\"a\",\"members\":[\"b\"]},{\"name\":\"b\",\"members\":[\"a\"]}");
		ncfg_observed_t *observed = observed_of("");
		ncfg_chosen_t   *chosen = choice_of(document, observed, "a");

		check(active_is(chosen, NULL) && reason_of(chosen, 0) == NCFG_INELIGIBLE_EMPTY,
		    "two sets naming each other stop, with nothing to offer");
		ncfg_chosen_free(chosen);
		chosen = choice_of(document, observed, "b");
		check(active_is(chosen, NULL) && reason_of(chosen, 0) == NCFG_INELIGIBLE_EMPTY,
		    "and the same asked from the other end");
		ncfg_chosen_free(chosen);

		ncfg_document_free(document);
		ncfg_observed_free(observed);
	}

	/* ---- a chain deeper than the bound ---- */
	{
		/*
		 * A document that arrives over the socket or out of `/run` has not
		 * been through the compiler, and a chain that nests forever without
		 * ever repeating a name is not a cycle the list can catch. In Rust
		 * this would end at a stack overflow; in C it would run off the stack
		 * and damage something on the way, so the bound is the difference
		 * between a bad document and a bad machine.
		 *
		 * Both chains are built from the bound itself: the longest one that
		 * still reaches its link, and one set deeper.
		 */
		char             reachable[2048] = "";
		char             too_deep[2048] = "";
		char             links[256] = "";
		size_t           i;
		ncfg_document_t *document;
		ncfg_observed_t *observed;
		ncfg_chosen_t   *chosen;

		add_link(links, sizeof(links), "eth0", 1, 1, NULL);
		observed = observed_of(links);
		for (i = 0; i < NCFG_LINKSET_MAX_DEPTH; i++) {
			char set[128];

			if (i + 1u < NCFG_LINKSET_MAX_DEPTH) {
				snprintf(set, sizeof(set),
				    "{\"name\":\"s%zu\",\"members\":[\"s%zu\"]}", i, i + 1u);
			} else {
				snprintf(set, sizeof(set),
				    "{\"name\":\"s%zu\",\"members\":[\"eth0\"]}", i);
			}
			add_text(reachable, sizeof(reachable), set);
		}
		document = document_of("", "", reachable);
		chosen = choice_of(document, observed, "s0");
		check(active_is(chosen, "s1") && carried_by(chosen, "eth0"),
		    "a chain the bound allows still reaches the link at the end of it");
		ncfg_chosen_free(chosen);
		ncfg_document_free(document);

		for (i = 0; i <= NCFG_LINKSET_MAX_DEPTH; i++) {
			char set[128];

			if (i < NCFG_LINKSET_MAX_DEPTH) {
				snprintf(set, sizeof(set),
				    "{\"name\":\"s%zu\",\"members\":[\"s%zu\"]}", i, i + 1u);
			} else {
				snprintf(set, sizeof(set),
				    "{\"name\":\"s%zu\",\"members\":[\"eth0\"]}", i);
			}
			add_text(too_deep, sizeof(too_deep), set);
		}
		document = document_of("", "", too_deep);
		/* It answers at all, which is the assertion: the set past the bound is
		 * refused as a cycle, so the one above it has nothing usable and the
		 * answer arrives instead of the stack running out. */
		chosen = choice_of(document, observed, "s0");
		check(active_is(chosen, NULL) && reason_of(chosen, 0) == NCFG_INELIGIBLE_EMPTY,
		    "one set deeper stops, and the link beyond the bound is not used");
		ncfg_chosen_free(chosen);

		/* Asked from one set further in, the same chain reaches the link --
		 * so what stopped it was the depth and not the document. */
		chosen = choice_of(document, observed, "s1");
		check(active_is(chosen, "s2") && carried_by(chosen, "eth0"),
		    "and the same chain asked one set in reaches it, so it was the depth");
		ncfg_chosen_free(chosen);

		ncfg_document_free(document);
		ncfg_observed_free(observed);
	}

	/* ---- the states that are not "working", told apart ---- */
	{
		ncfg_document_t *document = document_of(
		    "{\"name\":\"down0\"},{\"name\":\"cut0\"},{\"name\":\"dark0\"}", "",
		    "{\"name\":\"s\",\"members\":[\"down0\",\"cut0\",\"dark0\",\"gone0\"]}");
		char                  links[1024] = "";
		ncfg_observed_t      *observed;
		ncfg_chosen_t        *chosen;
		ncfg_observed_link_t *dark;

		add_link(links, sizeof(links), "down0", 0, 0, NULL);
		add_link(links, sizeof(links), "cut0", 1, 0, NULL);
		add_link(links, sizeof(links), "dark0", 1, 1, NULL);
		observed = observed_of(links);
		dark = changeable_link(observed, "dark0");
		if (dark) {
			dark->reachable.has = 1;
			dark->reachable.value = 0;
		}

		chosen = choice_of(document, observed, "s");
		check(active_is(chosen, NULL), "a set where nothing works has no active member");
		/* Down and cut both read as no carrier, deliberately: a set does not
		 * act on `up`, because a plan is usually in the middle of setting it
		 * and a machine would need two applies to come up. */
		check(reason_of(chosen, 0) == NCFG_INELIGIBLE_NO_CARRIER &&
		    reason_of(chosen, 1) == NCFG_INELIGIBLE_NO_CARRIER &&
		    reason_of(chosen, 2) == NCFG_INELIGIBLE_PROBE &&
		    reason_of(chosen, 3) == NCFG_INELIGIBLE_ABSENT,
		    "and each member says which kind of cannot it is");
		ncfg_chosen_free(chosen);

		/* A link nobody probed keeps its standing, which is the other half of
		 * the probe rule and the half that breaks every machine when it is got
		 * wrong: absent is not false. */
		if (dark) {
			dark->reachable.has = 0;
		}
		chosen = choice_of(document, observed, "s");
		check(active_is(chosen, "dark0"), "a link nobody probed keeps its standing");
		ncfg_chosen_free(chosen);

		/* **A link that is down but has carrier is usable**, and it is first
		 * in the list so it takes over here. That is the state every interface
		 * is in between netcfgd deciding to bring it up and having done so,
		 * and a set that refused it would plan no routes on the first pass and
		 * every route on the second. */
		if (changeable_link(observed, "down0")) {
			changeable_link(observed, "down0")->carrier = 1;
		}
		chosen = choice_of(document, observed, "s");
		check(active_is(chosen, "down0"), "a link that is down but has carrier is usable");
		ncfg_chosen_free(chosen);

		ncfg_document_free(document);
		ncfg_observed_free(observed);
	}

	/* ---- which sets a link is in, under either of its names ---- */
	{
		ncfg_document_t *document = document_of("{\"name\":\"eth0\"}",
		    "{\"id\":\"office\",\"security\":{\"type\":\"open\"}}",
		    "{\"name\":\"" NCFG_LINKSET_UPLINK "\",\"members\":[\"eth0\",\"office\"]}");
		char             links[1024] = "";
		ncfg_observed_t *observed;
		char             message[NCFG_ERROR_MAX];
		size_t           i;
		static const char *const asked[] = { "eth0", "office", "wlan0" };
		int              all_uplink = 1;

		add_link(links, sizeof(links), "eth0", 1, 1, NULL);
		add_link(links, sizeof(links), "wlan0", 1, 1, "office");
		observed = observed_of(links);

		for (i = 0; i < sizeof(asked) / sizeof(asked[0]); i++) {
			char **names = NULL;
			size_t count = 0;

			message[0] = '\0';
			if (!ncfg_linkset_sets_containing(document, observed, asked[i], &names, &count,
			    message, sizeof(message))) {
				printf("  could not list the sets `%s` is in: %s\n", asked[i], message);
				all_uplink = 0;
			} else if (count != 1u || !text_is(names[0], NCFG_LINKSET_UPLINK)) {
				printf("  `%s` answered %zu sets\n", asked[i], count);
				all_uplink = 0;
			}
			ncfg_linkset_names_free(names, count);
		}
		/* The radio carrying a member network is in the set too: a caller
		 * holding an interface and a caller holding a row must not have to
		 * join the two lists themselves, which is how they come to disagree. */
		check(all_uplink, "a link names its sets under the network's name and the radio's");

		{
			char **names = NULL;
			size_t count = 0;
			int    ok;

			message[0] = '\0';
			ok = ncfg_linkset_sets_containing(document, observed, "docker0", &names, &count,
			    message, sizeof(message));
			check(ok && count == 0u && names == NULL,
			    "and a link in no set answers none, rather than failing");
			ncfg_linkset_names_free(names, count);
		}

		ncfg_document_free(document);
		ncfg_observed_free(observed);
	}

	/* ---- a document with no set by that name has no answer ---- */
	{
		ncfg_document_t *document = document_of("", "", "");
		ncfg_observed_t *observed = observed_of("");
		char             message[NCFG_ERROR_MAX];
		ncfg_chosen_t   *chosen = NULL;
		int              ok;

		message[0] = '\0';
		ok = ncfg_linkset_choose(document, observed, NCFG_LINKSET_UPLINK, &chosen, message,
		    sizeof(message));
		/* **Not a failure**, which is the distinction the out-parameter buys:
		 * a caller that read "no such set" as "something went wrong" would
		 * report a machine with no uplink on a machine that has one. */
		check(ok && chosen == NULL, "a document with no set by that name has no answer");
		ncfg_chosen_free(chosen);
		ncfg_document_free(document);
		ncfg_observed_free(observed);
	}

	/* ---- the inventory, which is where choosing and presence meet ---- */
	{
		ncfg_document_t *document = document_of(
		    "{\"name\":\"eth0\",\"preference\":100},{\"name\":\"gone0\"}",
		    "{\"id\":\"office\",\"security\":{\"type\":\"open\"},\"metric\":50}",
		    "{\"name\":\"" NCFG_LINKSET_UPLINK "\",\"members\":[\"eth0\",\"office\"]}");
		char                     links[1024] = "";
		ncfg_observed_t         *observed;
		char                     message[NCFG_ERROR_MAX];
		ncfg_link_entry_t       *entries = NULL;
		size_t                   count = 0;
		const ncfg_link_entry_t *row;

		add_link(links, sizeof(links), "eth0", 1, 1, NULL);
		add_link(links, sizeof(links), "wlan0", 1, 1, "office");
		add_link(links, sizeof(links), "wlan1", 1, 1, "someone-elses");
		add_link(links, sizeof(links), "docker0", 1, 1, NULL);
		observed = observed_of(links);

		message[0] = '\0';
		if (!ncfg_link_inventory(document, observed, &entries, &count, message,
		    sizeof(message))) {
			printf("  could not build the inventory: %s\n", message);
		}
		/*
		 * **A radio carrying a configured network does not get a row of its
		 * own**, because the network's row is that connection: it holds the
		 * state, the addresses and the lease. Naming the same thing twice put
		 * all the detail on one row and all the meaning on the other.
		 */
		row = row_named(entries, count, "office");
		check(row_named(entries, count, "wlan0") == NULL && row &&
		    row->subject == NCFG_SUBJECT_NETWORK && text_is(row->carrier, "wlan0"),
		    "a radio carrying a configured network appears once, as the network");
		/* And a radio joined to something nobody configured still appears as
		 * itself: there is no other row for it to hide behind. */
		row = row_named(entries, count, "wlan1");
		check(row && row->category == NCFG_LINK_CATEGORY_WIFI && !row->configured,
		    "while a radio on a network nobody configured keeps its own row");

		/* The set is a row in its own right, beside the members it chose
		 * between -- an operator who groups two links has made a third thing
		 * the list has to show. */
		row = row_named(entries, count, NCFG_LINKSET_UPLINK);
		check(row && row->subject == NCFG_SUBJECT_LINKSET &&
		    row->category == NCFG_LINK_CATEGORY_LINKSET &&
		    row->presence == NCFG_PRESENCE_PRESENT && text_is(row->carrier, "wlan0"),
		    "a linkset is a row, carried by whatever it settled on");
		check(row_is_in_set(row_named(entries, count, "eth0"), NCFG_LINKSET_UPLINK) &&
		    row_is_in_set(row_named(entries, count, "office"), NCFG_LINKSET_UPLINK),
		    "and its members say, on their own rows, that it is deciding for them");

		/* The three provenances, which is why neither half of the union will
		 * do on its own. */
		row = row_named(entries, count, "gone0");
		check(row && row->presence == NCFG_PRESENCE_ABSENT && row->configured,
		    "an interface the document names and the kernel has not is listed absent");
		row = row_named(entries, count, "docker0");
		check(row && row->presence == NCFG_PRESENCE_PRESENT && !row->configured,
		    "and a link nobody configured is listed rather than hidden");
		check(count == 6u, "six rows: four links, one of them folded, plus two blocks");

		{
			size_t i;
			int    sorted = 1;

			for (i = 1u; i < count; i++) {
				if (strcmp(entries[i - 1u].name, entries[i].name) > 0) {
					sorted = 0;
				}
			}
			/* Sorted by name, so two calls on one machine compare equal and a
			 * list does not reorder itself under somebody reading it. */
			check(sorted, "and the list is in name order");
		}
		ncfg_link_inventory_free(entries, count);

		/* With no document there is no network block to fold a radio into, so
		 * the radio is a row again -- and nothing knows about the sets. */
		entries = NULL;
		count = 0;
		message[0] = '\0';
		if (!ncfg_link_inventory(NULL, observed, &entries, &count, message,
		    sizeof(message))) {
			printf("  could not build the inventory: %s\n", message);
		}
		row = row_named(entries, count, "wlan0");
		check(count == 4u && row && row->set_count == 0u,
		    "with no document the list is what the kernel has, and nothing more");
		ncfg_link_inventory_free(entries, count);

		ncfg_document_free(document);
		ncfg_observed_free(observed);
	}

	/* ---- freeing what was never filled in ---- */
	{
		/* base.h's third convention. The Rust had ownership in the type
		 * system; here it is a rule, so it is tested rather than assumed. */
		ncfg_chosen_free(NULL);
		ncfg_link_inventory_free(NULL, 0);
		ncfg_linkset_names_free(NULL, 0);
		check(1, "freeing something that was never filled in is nothing");
	}

	if (failures > 0) {
		printf("linkset: %d check%s failed\n", failures, failures == 1 ? "" : "s");
		return 1;
	}
	printf("linkset: every check passed\n");
	return 0;
}
