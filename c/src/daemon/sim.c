/*
 * sim.c -- which SIM source netcfgd wants, per modem device.
 *
 * 0150 puts the choice here and the hardware poke in a `pre_up` hook; 0152
 * answers the three things 0150 left open, and this file is that answer: the
 * probe decides when a source has failed, the last source is where it stops,
 * and a working source is kept.
 *
 * **The choice lives in `/run` and the preference lives in the document.** The
 * ordered list is the operator's intent and is never written to -- that is
 * constraint 1, and it is what the component that solved this on one board had
 * to rediscover. What moves is the index, which is derived and disposable and
 * gone after a reboot, so a cold start begins at the preference again.
 *
 * WHAT THIS FILE WRITES, AND WHERE
 *   One file per modem device, at `<run_dir>/modem/<device>`, and nothing else
 *   anywhere. The directory is the caller's: nothing here has a default, for
 *   `daemon.h`'s reason -- the real netcfgd's `/run/netcfgd` is on the machine
 *   this is built on.
 *
 *   Written through `ncfg_write_atomically`, which stages under a name carrying
 *   the writer's pid and a sequence number. The Rust stages at `<name>.tmp`,
 *   which is a fixed path every writer shares; `state.h` records what that cost
 *   when two writers met on one, and this module is not making a second copy of
 *   the mistake.
 */
#include "ncfg/daemon.h"

#include "ncfg/state.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* One source a helper has actually reported a card for. */
typedef struct {
	char *source;
	char *iccid;
} card_t;

/* What this module holds about one modem device. */
typedef struct {
	char   *name;
	/* Which source it is on, as an index into the document's list. */
	size_t  chosen;
	/*
	 * Advanced, and the link has not been cycled yet.
	 *
	 * Publishing the choice is not applying it: a `pre_up` hook is what acts on
	 * the file, and `pre_up` fires on the way up. So an advance leaves a note
	 * here, the reconcile turns it into a plan's cycle list, and it is cleared
	 * once a plan carrying that cycle has been applied.
	 */
	int     pending;
	/* Set while `ncfg_sims_cycled` is deciding, and cleared before it returns.
	 * A field rather than a value in `pending`, so nothing that reads `pending`
	 * can ever see a third state. */
	int     clearing;
	/*
	 * The card seen in each source.
	 *
	 * **Derived and disposable, like `chosen` above.** Rebuilt as sources are
	 * used and gone after a reboot, which is right: a card can be swapped while
	 * the machine is off, and a remembered ICCID that outlived the card it
	 * named would be a confident wrong answer to the one question this exists
	 * to settle.
	 *
	 * Filled in only for sources a helper has reported a card for. A source
	 * netcfgd has never been on has no entry, and that absence is the honest
	 * answer -- the mux shows the module one SIM at a time, so learning what is
	 * in the other socket costs a switch, a modem reset and the link.
	 */
	card_t *cards;
	size_t  card_count;
	size_t  card_capacity;
} device_t;

struct ncfg_sims {
	/* Sorted by name, so `pending` answers in a stable order and two runs on
	 * one machine print the same thing. */
	device_t *at;
	size_t    count;
	size_t    capacity;
};

/* ------------------------------------------------------------------------ *
 * Small things
 * ------------------------------------------------------------------------ */

static char *duplicate(const char *text)
{
	size_t length;
	char  *copy;

	if (!text) {
		return NULL;
	}
	length = strlen(text) + 1u;
	copy = malloc(length);
	if (copy) {
		memcpy(copy, text, length);
	}
	return copy;
}

/* The modem policy of the device of this name, or NULL. */
static const ncfg_modem_policy_t *policy_of(const ncfg_document_t *document, const char *name)
{
	size_t i;

	if (!document || !name) {
		return NULL;
	}
	for (i = 0; i < document->device_count; i++) {
		if (document->devices[i].modem && document->devices[i].name &&
		    strcmp(document->devices[i].name, name) == 0) {
			return document->devices[i].modem;
		}
	}
	return NULL;
}

/* Whether `source` is one the document lists for this device. */
static int listed(const ncfg_modem_policy_t *policy, const char *source)
{
	size_t i;

	for (i = 0; i < policy->sim_count; i++) {
		if (policy->sim[i] && strcmp(policy->sim[i], source) == 0) {
			return 1;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------------ *
 * The devices
 * ------------------------------------------------------------------------ */

static void device_release(device_t *device)
{
	size_t i;

	free(device->name);
	for (i = 0; i < device->card_count; i++) {
		free(device->cards[i].source);
		free(device->cards[i].iccid);
	}
	free(device->cards);
	memset(device, 0, sizeof(*device));
}

/* Where `name` is, or would be. `*found` says which. */
static size_t device_place(const ncfg_sims_t *sims, const char *name, int *found)
{
	size_t at;

	*found = 0;
	for (at = 0; at < sims->count; at++) {
		int order = strcmp(sims->at[at].name, name);

		if (order == 0) {
			*found = 1;
			return at;
		}
		if (order > 0) {
			return at;
		}
	}
	return sims->count;
}

static device_t *device_find(const ncfg_sims_t *sims, const char *name)
{
	int    found;
	size_t at;

	if (!sims || !name) {
		return NULL;
	}
	at = device_place(sims, name, &found);
	return found ? (device_t *)&sims->at[at] : NULL;
}

/* The record for `name`, made if it is not there. NULL only on no memory. */
static device_t *device_for(ncfg_sims_t *sims, const char *name, char *err, size_t err_size)
{
	int    found;
	size_t at = device_place(sims, name, &found);
	char  *copy;

	if (found) {
		return &sims->at[at];
	}
	if (sims->count == sims->capacity) {
		size_t    want = sims->capacity ? sims->capacity * 2u : 4u;
		device_t *grown = realloc(sims->at, want * sizeof(*grown));

		if (!grown) {
			ncfg_error_set(err, err_size, "there was no memory for a modem's selection");
			return NULL;
		}
		sims->at = grown;
		sims->capacity = want;
	}
	copy = duplicate(name);
	if (!copy) {
		ncfg_error_set(err, err_size, "there was no memory for a modem's selection");
		return NULL;
	}
	memmove(&sims->at[at + 1u], &sims->at[at], (sims->count - at) * sizeof(*sims->at));
	memset(&sims->at[at], 0, sizeof(sims->at[at]));
	sims->at[at].name = copy;
	sims->count++;
	return &sims->at[at];
}

static void device_remove(ncfg_sims_t *sims, size_t at)
{
	device_release(&sims->at[at]);
	memmove(&sims->at[at], &sims->at[at + 1u], (sims->count - at - 1u) * sizeof(*sims->at));
	sims->count--;
}

/* ------------------------------------------------------------------------ *
 * Publishing
 * ------------------------------------------------------------------------ */

/* `<run_dir>/modem/<device>`, allocated. NULL where memory ran out. */
static char *selection_path(const char *run_dir, const char *device)
{
	size_t size = strlen(run_dir) + strlen(device) + sizeof("/modem/");
	char  *path = malloc(size);

	if (!path) {
		return NULL;
	}
	(void)snprintf(path, size, "%s/modem/%s", run_dir, device);
	return path;
}

/*
 * Write the selection where a `pre_up` hook can read it.
 *
 * Written for every device with a `modem` block, **including one that lists no
 * source at all**, so a hook can read the file unconditionally rather than
 * having to tell "not written yet" from "this device has no modem policy".
 *
 * Atomic through a temporary and a rename, like everything netcfgd publishes in
 * `/run`: a hook reading a half-written selection would drive the mux to a
 * truncated source name.
 */
static int publish(const char *run_dir, const char *device, const char *sim, const char *apn,
    char *err, size_t err_size)
{
	ncfg_buf_t body;
	char      *path = selection_path(run_dir, device);
	int        written;

	if (!path) {
		ncfg_error_set(err, err_size, "there was no memory to name %s's selection", device);
		return 0;
	}
	ncfg_buf_init(&body, 0);
	ncfg_buf_addf(&body, "# %s, netcfgd's SIM selection\n", device);
	if (sim) {
		ncfg_buf_addf(&body, "sim=%s\n", sim);
	}
	if (apn) {
		ncfg_buf_addf(&body, "apn=%s\n", apn);
	}
	if (ncfg_buf_failed(&body)) {
		ncfg_buf_free(&body);
		free(path);
		ncfg_error_set(err, err_size, "%s's selection could not be built", device);
		return 0;
	}
	written = ncfg_write_atomically(path, ncfg_buf_text(&body), body.length, 0644u, err,
	    err_size);
	ncfg_buf_free(&body);
	free(path);
	return written;
}

/* ------------------------------------------------------------------------ *
 * The module
 * ------------------------------------------------------------------------ */

ncfg_sims_t *ncfg_sims_new(char *err, size_t err_size)
{
	ncfg_sims_t *sims = calloc(1u, sizeof(*sims));

	if (!sims) {
		ncfg_error_set(err, err_size, "there was no memory for the SIM selection");
	}
	return sims;
}

void ncfg_sims_free(ncfg_sims_t *sims)
{
	size_t i;

	if (!sims) {
		return;
	}
	for (i = 0; i < sims->count; i++) {
		device_release(&sims->at[i]);
	}
	free(sims->at);
	free(sims);
}

int ncfg_sims_sync(ncfg_sims_t *sims, const ncfg_document_t *document, const char *run_dir,
    char *err, size_t err_size)
{
	size_t i;
	size_t at = 0;
	int    ok = 1;
	char   why[NCFG_ERROR_MAX];

	if (!sims || !document || !run_dir || !run_dir[0]) {
		ncfg_error_set(err, err_size,
		    "a SIM selection needs a document and a run directory, and neither has a "
		    "default here");
		return 0;
	}
	why[0] = '\0';
	for (i = 0; i < document->device_count; i++) {
		const ncfg_device_t *device = &document->devices[i];
		device_t            *state;
		size_t               last;

		if (!device->modem || !device->name) {
			continue;
		}
		state = device_for(sims, device->name, err, err_size);
		if (!state) {
			return 0;
		}
		/*
		 * Clamped rather than reset, so shortening the list of a device already
		 * on a later source moves it to the last one that still exists instead
		 * of silently taking it back to the first -- which would be a SIM
		 * switch nobody asked for, arriving through an edit to an unrelated
		 * part of the list.
		 */
		last = device->modem->sim_count ? device->modem->sim_count - 1u : 0u;
		if (state->chosen > last) {
			state->chosen = last;
		}
		if (!publish(run_dir, device->name,
		        state->chosen < device->modem->sim_count ?
		            device->modem->sim[state->chosen] : NULL,
		        device->modem->apn, ok ? why : NULL, ok ? sizeof(why) : 0u)) {
			/* The first failure is the one reported: a run directory that
			 * cannot be written fails the same way for every device, and five
			 * copies of one sentence is four fewer facts than it looks. */
			ok = 0;
		}
	}

	/*
	 * A device that loses its modem block, or leaves the document, has its file
	 * removed rather than left behind to be read as current by a hook that has
	 * no other way of knowing -- and its cards go with it, because they are
	 * derived state about hardware this daemon has stopped tracking.
	 */
	while (at < sims->count) {
		if (policy_of(document, sims->at[at].name)) {
			at++;
			continue;
		}
		{
			char *path = selection_path(run_dir, sims->at[at].name);

			if (path) {
				(void)unlink(path);
				free(path);
			}
		}
		device_remove(sims, at);
	}
	if (!ok) {
		ncfg_error_set(err, err_size, "%s", why);
	}
	return ok;
}

int ncfg_sims_advance(ncfg_sims_t *sims, const ncfg_document_t *document, const char *device,
    const char *run_dir, const char **moved_to, char *err, size_t err_size)
{
	const ncfg_modem_policy_t *policy = policy_of(document, device);
	device_t                  *state;

	if (moved_to) {
		*moved_to = NULL;
	}
	if (!sims || !device || !run_dir || !run_dir[0]) {
		ncfg_error_set(err, err_size,
		    "advancing a SIM source needs a device and a run directory");
		return 0;
	}
	if (!policy) {
		ncfg_error_set(err, err_size, "`%s` is not a device this configuration gives a "
		    "modem policy", device);
		return 0;
	}
	state = device_for(sims, device, err, err_size);
	if (!state) {
		return 0;
	}
	/*
	 * One source is a list, not a special case, and it has nowhere to go. 0152
	 * stops at the last rather than wrapping: a machine whose subscription has
	 * lapsed would otherwise reset its modem for ever and be permanently
	 * offline rather than offline until somebody looked.
	 */
	if (state->chosen + 1u >= policy->sim_count) {
		return 1;
	}
	state->chosen++;
	state->pending = 1;
	/* The index moves whether or not the file could be written, and the note
	 * stays: `ncfg_sims_sync` republishes from the index on the next reload, so
	 * a `/run` that was full for a moment catches up rather than leaving this
	 * module and the file permanently disagreeing. */
	if (!publish(run_dir, device, policy->sim[state->chosen], policy->apn, err, err_size)) {
		return 0;
	}
	if (moved_to) {
		*moved_to = policy->sim[state->chosen];
	}
	return 1;
}

size_t ncfg_sims_pending_count(const ncfg_sims_t *sims)
{
	size_t i;
	size_t count = 0;

	if (!sims) {
		return 0;
	}
	for (i = 0; i < sims->count; i++) {
		if (sims->at[i].pending) {
			count++;
		}
	}
	return count;
}

const char *ncfg_sims_pending_at(const ncfg_sims_t *sims, size_t at)
{
	size_t i;
	size_t seen = 0;

	if (!sims) {
		return NULL;
	}
	for (i = 0; i < sims->count; i++) {
		if (!sims->at[i].pending) {
			continue;
		}
		if (seen == at) {
			return sims->at[i].name;
		}
		seen++;
	}
	return NULL;
}

int ncfg_sims_is_pending(const ncfg_sims_t *sims, const char *device)
{
	const device_t *state = device_find(sims, device);

	return state ? state->pending : 0;
}

/* Whether every record the journal holds for this device says it was done. An
 * empty set is true, which is the right answer rather than an oversight: the
 * planner emits a cycle only for a link that is *up*, so no records means no
 * cycle was needed. */
static int the_cycle_happened(const ncfg_journal_t *journal, const char *device)
{
	size_t i;

	if (!journal) {
		return 0;
	}
	for (i = 0; i < journal->record_count; i++) {
		const ncfg_record_t *record = &journal->records[i];

		if (!record->interface || strcmp(record->interface, device) != 0) {
			continue;
		}
		if (record->outcome != NCFG_OUTCOME_DONE) {
			return 0;
		}
	}
	return 1;
}

void ncfg_sims_cycled(ncfg_sims_t *sims, const char *const *devices, size_t device_count,
    const ncfg_journal_t *journal)
{
	size_t i;

	if (!sims || !devices) {
		return;
	}
	/*
	 * **Decided in full before anything is dropped.** `devices` is very often
	 * the list a caller read straight out of `ncfg_sims_pending_at`, so it
	 * points into this module's own storage -- clearing as the walk went would
	 * be reading a name this call had already freed. Marking first and clearing
	 * second costs a second pass over a list that is almost always empty.
	 */
	for (i = 0; i < sims->count; i++) {
		size_t which;

		sims->at[i].clearing = 0;
		for (which = 0; which < device_count; which++) {
			if (devices[which] && strcmp(devices[which], sims->at[i].name) == 0 &&
			    the_cycle_happened(journal, sims->at[i].name)) {
				sims->at[i].clearing = 1;
				break;
			}
		}
	}
	for (i = 0; i < sims->count; i++) {
		if (sims->at[i].clearing) {
			sims->at[i].pending = 0;
			sims->at[i].clearing = 0;
		}
	}
}

int ncfg_sims_observe(ncfg_sims_t *sims, const ncfg_document_t *document,
    const ncfg_observed_report_t *reports, size_t report_count, char *err, size_t err_size)
{
	size_t i;

	if (!sims) {
		ncfg_error_set(err, err_size, "there is no SIM selection to observe into");
		return 0;
	}
	if (!document || !reports) {
		return 1;
	}
	for (i = 0; i < document->device_count; i++) {
		const ncfg_device_t *device = &document->devices[i];
		const char          *iccid = NULL;
		const char          *source = NULL;
		device_t            *state;
		size_t               which;

		if (!device->modem || !device->name) {
			continue;
		}
		for (which = 0; which < report_count; which++) {
			if (reports[which].interface &&
			    strcmp(reports[which].interface, device->name) == 0) {
				iccid = reports[which].iccid;
				source = reports[which].sim;
				break;
			}
		}
		/*
		 * A report without a `sim` field contributes nothing. It is not an
		 * error, and older helpers write exactly that: an ICCID with no idea
		 * which source it belongs to is a fact netcfgd cannot use, and guessing
		 * from the current selection is the mistake this module exists to
		 * refuse. A source the document does not list is refused too, so a
		 * stale report cannot resurrect one that has been edited out.
		 */
		if (!iccid || !source || !listed(device->modem, source)) {
			continue;
		}
		state = device_for(sims, device->name, err, err_size);
		if (!state) {
			return 0;
		}
		for (which = 0; which < state->card_count; which++) {
			if (strcmp(state->cards[which].source, source) == 0) {
				char *fresh = duplicate(iccid);

				if (!fresh) {
					ncfg_error_set(err, err_size,
					    "there was no memory to record %s's card", device->name);
					return 0;
				}
				free(state->cards[which].iccid);
				state->cards[which].iccid = fresh;
				break;
			}
		}
		if (which < state->card_count) {
			continue;
		}
		if (state->card_count == state->card_capacity) {
			size_t  want = state->card_capacity ? state->card_capacity * 2u : 2u;
			card_t *grown = realloc(state->cards, want * sizeof(*grown));

			if (!grown) {
				ncfg_error_set(err, err_size,
				    "there was no memory to record %s's card", device->name);
				return 0;
			}
			state->cards = grown;
			state->card_capacity = want;
		}
		state->cards[state->card_count].source = duplicate(source);
		state->cards[state->card_count].iccid = duplicate(iccid);
		if (!state->cards[state->card_count].source ||
		    !state->cards[state->card_count].iccid) {
			free(state->cards[state->card_count].source);
			free(state->cards[state->card_count].iccid);
			ncfg_error_set(err, err_size, "there was no memory to record %s's card",
			    device->name);
			return 0;
		}
		state->card_count++;
	}
	return 1;
}

/* The ICCID this device has shown in this source, or NULL. */
static const char *card_in(const device_t *state, const char *source)
{
	size_t i;

	if (!state) {
		return NULL;
	}
	for (i = 0; i < state->card_count; i++) {
		if (strcmp(state->cards[i].source, source) == 0) {
			return state->cards[i].iccid;
		}
	}
	return NULL;
}

void ncfg_sims_status_free(ncfg_proto_modem_t *modems, size_t count)
{
	size_t i;

	if (!modems) {
		return;
	}
	for (i = 0; i < count; i++) {
		/* The strings are borrowed from the document and from `sims`; only the
		 * two arrays were this call's. */
		free((void *)(uintptr_t)(const void *)modems[i].sim.items);
		free((void *)(uintptr_t)(const void *)modems[i].cards);
	}
	free(modems);
}

int ncfg_sims_status(const ncfg_sims_t *sims, const ncfg_document_t *document,
    ncfg_proto_modem_t **out, size_t *count_out, char *err, size_t err_size)
{
	ncfg_proto_modem_t *modems = NULL;
	size_t              modem_count = 0;
	size_t              i;

	if (!out || !count_out) {
		ncfg_error_set(err, err_size, "nowhere to put the modem status");
		return 0;
	}
	*out = NULL;
	*count_out = 0;
	if (!document) {
		/* A daemon that has not compiled a document yet answers with a list
		 * rather than an error: no configuration is a state. */
		return 1;
	}
	for (i = 0; i < document->device_count; i++) {
		if (document->devices[i].modem && document->devices[i].name) {
			modem_count++;
		}
	}
	if (modem_count == 0u) {
		return 1;
	}
	modems = calloc(modem_count, sizeof(*modems));
	if (!modems) {
		ncfg_error_set(err, err_size, "there was no memory for the modem status");
		return 0;
	}
	modem_count = 0;
	for (i = 0; i < document->device_count; i++) {
		const ncfg_device_t       *device = &document->devices[i];
		const ncfg_modem_policy_t *policy = device->modem;
		const device_t            *state;
		ncfg_proto_modem_t        *one;
		ncfg_proto_str_t          *sources = NULL;
		ncfg_proto_sim_card_t     *cards = NULL;
		size_t                     card_count = 0;
		size_t                     which;

		if (!policy || !device->name) {
			continue;
		}
		state = device_find(sims, device->name);
		if (policy->sim_count) {
			sources = calloc(policy->sim_count, sizeof(*sources));
			cards = calloc(policy->sim_count, sizeof(*cards));
			if (!sources || !cards) {
				free(sources);
				free(cards);
				ncfg_sims_status_free(modems, modem_count);
				ncfg_error_set(err, err_size,
				    "there was no memory for the modem status");
				return 0;
			}
		}
		/*
		 * Ordered by the document's own list rather than by whatever order this
		 * module happens to hold its cards in, so two runs on one machine print
		 * the same thing and a source the operator put first reads first.
		 */
		for (which = 0; which < policy->sim_count; which++) {
			const char *iccid;

			sources[which] = ncfg_proto_str(policy->sim[which]);
			iccid = policy->sim[which] ? card_in(state, policy->sim[which]) : NULL;
			if (!iccid) {
				continue;
			}
			cards[card_count].source = ncfg_proto_str(policy->sim[which]);
			cards[card_count].iccid = ncfg_proto_str(iccid);
			card_count++;
		}

		one = &modems[modem_count++];
		one->device = ncfg_proto_str(device->name);
		one->sim.items = sources;
		one->sim.count = policy->sim_count;
		/* The preference and the selection as separate facts. Collapsing them
		 * into one "current SIM" would lose the question an operator actually
		 * has when a modem will not attach -- whether it is on the source they
		 * asked for, or has fallen through to a spare. */
		one->selected = ncfg_proto_str_none();
		if (state && state->chosen < policy->sim_count) {
			one->selected = ncfg_proto_str(policy->sim[state->chosen]);
		} else if (!state && policy->sim_count) {
			one->selected = ncfg_proto_str(policy->sim[0]);
		}
		one->apn = policy->apn ? ncfg_proto_str(policy->apn) : ncfg_proto_str_none();
		/* Advanced but not yet cycled, which is "netcfgd wants the other SIM"
		 * rather than "the machine is on it". */
		one->cycle_pending = (unsigned char)(state && state->pending ? 1 : 0);
		one->cards = cards;
		one->card_count = card_count;
	}
	*out = modems;
	*count_out = modem_count;
	return 1;
}

const char *ncfg_sims_current(const ncfg_sims_t *sims, const ncfg_document_t *document,
    const char *device)
{
	const ncfg_modem_policy_t *policy = policy_of(document, device);
	const device_t            *state = device_find(sims, device);
	size_t                     chosen = state ? state->chosen : 0u;

	if (!policy || chosen >= policy->sim_count) {
		return NULL;
	}
	return policy->sim[chosen];
}
