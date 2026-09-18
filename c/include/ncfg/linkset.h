/*
 * linkset.h -- which link of a named group is in use, and the flattened list a
 * client shows.
 *
 * FAILOVER, SAID ONCE, FOR LINKS OF ANY KIND
 *   A laptop with a cable and two saved wifi networks, a router with a fibre
 *   uplink and an LTE modem behind it, a machine that prefers its VPN while
 *   the VPN is up: all three are the same sentence -- *these links can reach
 *   the same place, use the best one that actually works* -- and netcfgd could
 *   not say it. What it had was an interface's `preference`, which is the
 *   mechanism and not the idea: nothing named the group, nothing said only one
 *   of them is in use, and a wifi network could not be in it at all, because a
 *   `preference` lives on an interface and a network is not one. 0248.
 *
 *   **A linkset is itself a link**, which is the property the shape was chosen
 *   for: a set composes into another set, so an operator can say "the office
 *   pair, or failing that the modem" without a second mechanism. It is not a
 *   kernel device -- no index, no address, no row in the link table -- so what
 *   a set contributes to the machine is entirely the member it picked.
 *
 *   `NCFG_LINKSET_UPLINK` is special by its name and nothing else, and
 *   `document.h` owns that spelling.
 *
 * WHY THIS IS NOT IN `observed.h`, WHICH OWNS THE TYPES
 *   `ncfg_chosen_t`, `ncfg_standing_t`, `ncfg_ineligible_t` and
 *   `ncfg_link_entry_t` are results that travel in an observation, so they are
 *   declared where the observation is read and written. Working them out needs
 *   the document, the nesting rules and the depth bound below, and every path
 *   through the inventory calls `ncfg_linkset_choose` -- so the rules are
 *   here and the vocabulary is there. The three rules that need no set
 *   (`ncfg_link_category_of`, `ncfg_presence_of_interface`,
 *   `ncfg_presence_of_network`) stay in `observed.h` and are called from here
 *   rather than written a second time.
 *
 * WHERE THIS DIFFERS FROM `crates/netcfgd-model/src/linkset.rs`, ON PURPOSE
 *   0263 is where the port's divergences are collected; these are this
 *   module's.
 *
 *   * **`choose` answers through an out-parameter.** The Rust returns
 *     `Option<Chosen>` and cannot fail; the C can fail to allocate, and one
 *     pointer cannot carry both "the document has no set by that name" and
 *     "something went wrong" -- a caller that conflated them would report a
 *     machine with no uplink on a machine that has one. So: 1 with a choice,
 *     1 with `NULL` where there is no such set, 0 with a sentence.
 *     `ncfg_linkset_find` answers the first question on its own and allocates
 *     nothing.
 *   * **The cycle guard borrows names instead of owning them.** Rust carries a
 *     `Vec<String>` of the sets in progress; this carries pointers into the
 *     document in an array of `NCFG_LINKSET_MAX_DEPTH`, which the bound below
 *     already limits. The document outlives the call, and a guard that cannot
 *     fail to allocate is a guard that is always there -- one that could fail
 *     would fail exactly on the malformed input it exists for.
 *   * **The depth bound is published.** The Rust keeps `MAX_DEPTH` private;
 *     its test does not need the number and the C test does, and a test that
 *     spelled `8` itself would go on passing after the bound moved.
 *   * **A list of names is a counted array with a free beside it**, which is
 *     base.h's third convention applied to `Vec<String>`.
 */
#ifndef NCFG_LINKSET_H
#define NCFG_LINKSET_H

#include <stddef.h>

#include "ncfg/document.h"
#include "ncfg/observed.h"

/*
 * How deep a set may nest before netcfgd stops following it.
 *
 * **A document that arrives over the socket or out of `/run` has not
 * necessarily been through the compiler**, and the compiler is where a cycle
 * is diagnosed. This is the model refusing to hang on one anyway: a set naming
 * itself, directly or through a chain, stops here and reports
 * `NCFG_INELIGIBLE_CYCLE` rather than recursing until the stack runs out.
 */
#define NCFG_LINKSET_MAX_DEPTH 8

/* The set by this name, if the document has one. NULL otherwise, and for a
 * NULL document, which is a document with no sets. */
const ncfg_linkset_t *ncfg_linkset_find(const ncfg_document_t *document, const char *name);

/*
 * Work out which member of a set is in use.
 *
 * Eligible members ranked by metric -- an interface's `preference`, a
 * network's `metric` -- lowest wins, ties going to the order the document
 * lists them in. **An absent metric reads as 0, the strongest.** It looks
 * backwards, and it is the only answer that keeps the set and the kernel
 * agreeing: an unnumbered route goes into the table at metric 0 as well, so a
 * set that ranked the unnumbered member last would choose one link while the
 * routing table used the other.
 *
 * A member is eligible when the link carrying it has carrier and has not
 * failed its probe. `up` is deliberately not consulted; see
 * `NCFG_INELIGIBLE_NO_CARRIER`.
 *
 * Returns 1 with `*chosen_out` set, or 1 with `*chosen_out` NULL where the
 * document has no set by that name. Returns 0 with a sentence in `err`.
 *
 * A set whose members are all unusable answers with no active member and every
 * member's reason, which is the answer an operator needs when nothing works.
 */
int ncfg_linkset_choose(const ncfg_document_t *document, const ncfg_observed_t *observed,
    const char *name, ncfg_chosen_t **chosen_out, char *err, size_t err_size);

/* Free a choice. A NULL one, and one never filled in, are nothing. */
void ncfg_chosen_free(ncfg_chosen_t *chosen);

/*
 * Every set a link is a member of, by the name the document used for it.
 *
 * **Both spellings**, because a wifi member is named by its `network` block
 * and carried by a radio: asking with either the network's id or the radio's
 * name answers the same set. That is what a caller has -- the planner holds an
 * interface, a list holds a row -- and making each of them join the two lists
 * itself is how two callers come to disagree.
 *
 * Returns 1 with a counted array in `names_out`, which is NULL and zero-long
 * where the link is in no set.
 */
int ncfg_linkset_sets_containing(const ncfg_document_t *document,
    const ncfg_observed_t *observed, const char *link, char ***names_out, size_t *count_out,
    char *err, size_t err_size);

/* Free a name list. A NULL one is nothing. */
void ncfg_linkset_names_free(char **names, size_t count);

/*
 * Every link this machine has or has been told about, sorted by name.
 *
 * **A union of two sets that do not coincide**, which is why neither half
 * alone will do. Three provenances (0245):
 *
 *   * configured and present -- the ordinary case;
 *   * configured and not present -- a saved network out of range, an
 *     `interface` whose card is not plugged in. These have no kernel link at
 *     all, so an observation-only list cannot show them;
 *   * present and not configured -- `docker0`, a card another manager owns. A
 *     document-only list would hide something demonstrably on the machine.
 *
 * `document` may be NULL, which lists what the kernel has and nothing else.
 *
 * **Wifi presence is unknown here unless a radio is on the network**, and that
 * is honest rather than lazy: narrowing it to absent needs a scan, an
 * observation carries none, and for a hidden network no scan could settle it
 * anyway. A caller holding scan results asks `ncfg_presence_of_network`.
 *
 * Returns 1 with a counted array in `entries_out`, or 0 with a sentence.
 */
int ncfg_link_inventory(const ncfg_document_t *document, const ncfg_observed_t *observed,
    ncfg_link_entry_t **entries_out, size_t *count_out, char *err, size_t err_size);

/* Free an inventory. A NULL one is nothing. */
void ncfg_link_inventory_free(ncfg_link_entry_t *entries, size_t count);

#endif /* NCFG_LINKSET_H */
