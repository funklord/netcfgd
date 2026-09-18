/*
 * inventory.c -- the flattened list of links a client shows.
 *
 * A UNION OF TWO SETS THAT DO NOT COINCIDE
 *   Neither half alone will do, and the three provenances are why (0245):
 *   configured and present is the ordinary case; configured and not present --
 *   a saved network out of range, an `interface` whose card is not plugged in
 *   -- has no kernel link at all, so an observation-only list cannot show it;
 *   present and not configured -- `docker0`, a card another manager owns --
 *   would be hidden by a document-only list, and hiding something demonstrably
 *   on the machine is worse than showing something netcfgd does not manage.
 *
 * WHY IT IS HERE AND NOT BESIDE `ncfg_link_category_of`
 *   Every path through it calls `ncfg_linkset_choose`: a set is a row in its
 *   own right, and every other row carries the sets it is a member of. The
 *   category and presence rules need no document beyond one lookup and stay in
 *   `observed.c`; this needs the nesting rules and the depth bound, so it sits
 *   with them.
 *
 * WHY A RADIO CAN VANISH FROM THE LIST
 *   A radio carrying a network the document describes gets no row of its own,
 *   because the network's row *is* that connection: it holds the state, the
 *   addresses and the lease. Naming the same thing twice put all the detail on
 *   one row and all the meaning on the other. A radio joined to something
 *   nobody configured still appears as itself -- there is no other row for it
 *   to hide behind.
 */
#include "ncfg/linkset.h"

#include "ncfg/base.h"

#include <stdlib.h>
#include <string.h>

/* Ordering, and equality read off it, for a name a reader may have left
 * NULL. Absent sorts before present, as `None` does in Rust. */
static int compare_text(const char *left, const char *right)
{
	if (!left || !right) {
		return (left ? 1 : 0) - (right ? 1 : 0);
	}
	return strcmp(left, right);
}

static int same_text(const char *left, const char *right)
{
	if (!left || !right) {
		return left == right;
	}
	return strcmp(left, right) == 0;
}

static int copy_text(const char *text, char **out)
{
	size_t length;
	char  *copy;

	*out = NULL;
	if (!text) {
		return 1;
	}
	length = strlen(text);
	copy = malloc(length + 1u);
	if (!copy) {
		return 0;
	}
	memcpy(copy, text, length + 1u);
	*out = copy;
	return 1;
}

void ncfg_link_inventory_free(ncfg_link_entry_t *entries, size_t count)
{
	size_t i;

	if (!entries) {
		return;
	}
	for (i = 0; i < count; i++) {
		free(entries[i].name);
		free(entries[i].carrier);
		ncfg_linkset_names_free(entries[i].sets, entries[i].set_count);
	}
	free(entries);
}

/*
 * A row's name, plus the sets it is in, which every row carries.
 *
 * **A member is not an independent link while its set is choosing**, which is
 * what that column is for: an operator looking at a list of links needs to see
 * which of them something else is already deciding about.
 */
static int name_row(const ncfg_document_t *document, const ncfg_observed_t *observed,
    const char *name, ncfg_link_entry_t *entry, char *err, size_t err_size)
{
	if (!copy_text(name, &entry->name)) {
		ncfg_error_set(err, err_size, "out of memory listing the links of this machine");
		return 0;
	}
	return ncfg_linkset_sets_containing(document, observed, name, &entry->sets,
	    &entry->set_count, err, err_size);
}

/* Whether this link is a radio carrying a network the document describes.
 * Split out because it decides whether a row exists at all. */
static int carries_a_configured_network(const ncfg_observed_link_t *link,
    const ncfg_document_t *document)
{
	size_t i;

	if (!link->network || !document) {
		return 0;
	}
	for (i = 0; i < document->network_count; i++) {
		if (same_text(document->networks[i].id, link->network)) {
			return 1;
		}
	}
	return 0;
}

static int document_names_interface(const ncfg_document_t *document, const char *name)
{
	size_t i;

	if (!document) {
		return 0;
	}
	for (i = 0; i < document->interface_count; i++) {
		if (same_text(document->interfaces[i].name, name)) {
			return 1;
		}
	}
	return 0;
}

/*
 * By name, and stable.
 *
 * `observed_link.c` states the argument for the whole port and it holds here:
 * the key is not the whole value, so where two rows share a name a stable sort
 * leaves them in the order they were built and an unstable one leaves them in
 * whatever order the algorithm happened to produce -- which can differ between
 * two runs on the same input, and this list is written into `/run` and
 * compared.
 */
static void sort_by_name(ncfg_link_entry_t *entries, size_t count)
{
	size_t i;

	for (i = 1u; i < count; i++) {
		size_t j;

		for (j = i; j > 0u; j--) {
			ncfg_link_entry_t held;

			/* Strictly greater, which is what keeps this stable: two rows with
			 * an equal name are never swapped. */
			if (compare_text(entries[j - 1u].name, entries[j].name) <= 0) {
				break;
			}
			held = entries[j - 1u];
			entries[j - 1u] = entries[j];
			entries[j] = held;
		}
	}
}

int ncfg_link_inventory(const ncfg_document_t *document, const ncfg_observed_t *observed,
    ncfg_link_entry_t **entries_out, size_t *count_out, char *err, size_t err_size)
{
	ncfg_link_entry_t *entries;
	size_t             capacity = 0;
	size_t             count = 0;
	size_t             i;

	if (!entries_out || !count_out) {
		ncfg_error_set(err, err_size, "an inventory was asked for with nowhere to put it");
		return 0;
	}
	*entries_out = NULL;
	*count_out = 0;
	/* Every row this walk can produce, counted before any is built: the rows
	 * come from four fixed lists and none of them grows while it runs, so one
	 * allocation is the whole of it. */
	if (observed) {
		capacity += observed->link_count;
	}
	if (document) {
		capacity += document->interface_count + document->network_count +
		    document->linkset_count;
	}
	if (capacity == 0u) {
		return 1;
	}
	entries = calloc(capacity, sizeof(*entries));
	if (!entries) {
		ncfg_error_set(err, err_size, "out of memory listing the links of this machine");
		return 0;
	}

	for (i = 0; observed && i < observed->link_count; i++) {
		const ncfg_observed_link_t *link = &observed->links[i];
		ncfg_link_entry_t          *entry = &entries[count];

		if (carries_a_configured_network(link, document)) {
			continue;
		}
		if (!name_row(document, observed, link->name, entry, err, err_size)) {
			ncfg_link_inventory_free(entries, count + 1u);
			return 0;
		}
		/* The link's own category where the observation has worked one out,
		 * and the rule again where it has not -- a bare netlink snapshot has
		 * no category, and a row with no kind falls out of every filter. */
		entry->category = link->category.has ? (int)link->category.value :
		    ncfg_link_category_of(link, document);
		entry->presence = NCFG_PRESENCE_PRESENT;
		entry->configured = document_names_interface(document, link->name);
		entry->subject = NCFG_SUBJECT_INTERFACE;
		/* An interface carries itself; there is nothing else to name. */
		entry->carrier = NULL;
		count++;
	}
	if (!document) {
		sort_by_name(entries, count);
		*entries_out = entries;
		*count_out = count;
		return 1;
	}

	/* An interface the document names and the kernel does not have. */
	for (i = 0; i < document->interface_count; i++) {
		const char        *name = document->interfaces[i].name;
		ncfg_link_entry_t *entry = &entries[count];

		if (ncfg_observed_link(observed, name)) {
			continue;
		}
		if (!name_row(document, observed, name, entry, err, err_size)) {
			ncfg_link_inventory_free(entries, count + 1u);
			return 0;
		}
		/* Nothing to read a kind from: the link does not exist, so there is no
		 * kernel kind and no `wireless` flag. Other rather than a guess from
		 * the name, which is the convention -- `eth0` is not a fact. */
		entry->category = NCFG_LINK_CATEGORY_OTHER;
		entry->presence = ncfg_presence_of_interface(name, observed);
		entry->configured = 1;
		entry->subject = NCFG_SUBJECT_INTERFACE;
		entry->carrier = NULL;
		count++;
	}

	/*
	 * Every configured network, which is a link whether or not a radio is on
	 * it. Where a radio is on one, the radio's own row was skipped above and
	 * this is the only row for the pair: the network is the thing an operator
	 * configured, the thing a linkset would hold, and -- through `carrier` --
	 * the thing that says which hardware is carrying it.
	 */
	for (i = 0; i < document->network_count; i++) {
		const ncfg_wifi_network_t  *network = &document->networks[i];
		ncfg_link_entry_t          *entry = &entries[count];
		const ncfg_observed_link_t *carrier = NULL;
		size_t                      j;

		for (j = 0; observed && j < observed->link_count; j++) {
			if (same_text(observed->links[j].network, network->id)) {
				carrier = &observed->links[j];
				break;
			}
		}
		if (!name_row(document, observed, network->id, entry, err, err_size)) {
			ncfg_link_inventory_free(entries, count + 1u);
			return 0;
		}
		entry->category = NCFG_LINK_CATEGORY_WIFI;
		/* **Unknown unless a radio is on it**, and that is honest rather than
		 * lazy: narrowing it to absent needs a scan, an observation carries
		 * none, and for a hidden network no scan could settle it anyway. */
		entry->presence = ncfg_presence_of_network(network->hidden, carrier != NULL, 0, 0);
		entry->configured = 1;
		entry->subject = NCFG_SUBJECT_NETWORK;
		if (carrier && !copy_text(carrier->name, &entry->carrier)) {
			ncfg_error_set(err, err_size, "out of memory naming the radio on `%s`",
			    network->id);
			ncfg_link_inventory_free(entries, count + 1u);
			return 0;
		}
		count++;
	}

	/* And the sets themselves, which are links in their own right: a set can
	 * be a member of a set, and an operator who groups two links has made a
	 * third thing that the list has to show. */
	for (i = 0; i < document->linkset_count; i++) {
		const char        *name = document->linksets[i].name;
		ncfg_link_entry_t *entry = &entries[count];
		ncfg_chosen_t     *chosen = NULL;

		if (!name_row(document, observed, name, entry, err, err_size)) {
			ncfg_link_inventory_free(entries, count + 1u);
			return 0;
		}
		if (!ncfg_linkset_choose(document, observed, name, &chosen, err, err_size)) {
			ncfg_link_inventory_free(entries, count + 1u);
			return 0;
		}
		/* The interface its chosen member is running on, so the row can borrow
		 * that link's state exactly as a network's row does. */
		if (chosen && !copy_text(chosen->interface, &entry->carrier)) {
			ncfg_error_set(err, err_size, "out of memory naming what `%s` settled on", name);
			ncfg_chosen_free(chosen);
			ncfg_link_inventory_free(entries, count + 1u);
			return 0;
		}
		ncfg_chosen_free(chosen);
		entry->category = NCFG_LINK_CATEGORY_LINKSET;
		/* **A set is present when something in it works.** It has no hardware
		 * of its own to be absent, so what its presence can mean is whether it
		 * currently has anything to offer -- which is the question an operator
		 * reading a row called `uplink` is asking. */
		entry->presence = entry->carrier ? NCFG_PRESENCE_PRESENT : NCFG_PRESENCE_ABSENT;
		entry->configured = 1;
		entry->subject = NCFG_SUBJECT_LINKSET;
		count++;
	}

	/* Sorted by name, so two calls on one machine compare equal and a list
	 * does not reorder itself under somebody reading it. */
	sort_by_name(entries, count);
	*entries_out = entries;
	*count_out = count;
	return 1;
}
