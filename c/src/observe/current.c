/*
 * current.c -- the four calls that stand between the kernel and an
 * observation, performed once.
 *
 * WHY THIS IS A FILE AND NOT A PARAGRAPH IN TWO CALLERS
 *   `collect`, `build`, `augment_host` and `derive` are four public calls with
 *   four different arguments, one of which -- the recorded prior -- is
 *   assembled out of three files and a pair of hand-overs. Written out at each
 *   call site that is a dozen lines the daemon and the command line would each
 *   have their own copy of, and this project has twice paid for two copies of
 *   one rule: the Rust's `netcfgd_host::prior_state` exists with that reason
 *   written above it, because the delegations had been folded in on one side
 *   and not the other.
 *
 * WHAT IS MOVED AND WHAT IS BORROWED, BECAUSE BOTH HAPPEN HERE
 *   `ncfg_observe_prior_t` says it: the name lists are borrowed and six
 *   aggregate lists are handed over. So the record read from `owned.json` goes
 *   on owning its five interface-name lists and its two object lists for the
 *   length of the `build`, and hands its restart tally and its hook state
 *   *away* -- which means clearing them on this side, or the record's free and
 *   the observation's free are two frees of one array. The moves are together
 *   in `read_record` and nowhere else for that reason.
 */
#include "ncfg/observe.h"

#include "ncfg/log.h"
#include "ncfg/state.h"

#include <stdlib.h>
#include <string.h>

/*
 * The record, held for exactly as long as the `build` that reads it.
 *
 * Two arrays beside the on-disk form, because `ncfg_owned_object_t` and
 * `ncfg_observe_owned_t` are the same three members and deliberately not the
 * same type -- `state.h` says why: one is a file format that has to stay
 * readable across versions and the other is what the observer consumes, and
 * changing one must not silently change the other. So the view is built rather
 * than cast; it is three assignments per object and it borrows every string.
 */
typedef struct {
	ncfg_owned_state_t    owned;
	ncfg_observe_owned_t *addresses;
	ncfg_observe_owned_t *routes;
} record_t;

static void record_free(record_t *record)
{
	if (!record) {
		return;
	}
	free(record->addresses);
	record->addresses = NULL;
	free(record->routes);
	record->routes = NULL;
	ncfg_owned_free(&record->owned);
}

/* The observer's view of one of the record's two object lists. */
static int borrow_objects(const ncfg_owned_object_t *from, size_t count,
    ncfg_observe_owned_t **out, const char *what, char *err, size_t err_size)
{
	ncfg_observe_owned_t *made;
	size_t                at;

	*out = NULL;
	if (count == 0) {
		return 1;
	}
	made = calloc(count, sizeof(*made));
	if (!made) {
		ncfg_error_set(err, err_size, "out of memory reading %zu recorded %s", count, what);
		return 0;
	}
	for (at = 0; at < count; at++) {
		made[at].interface = from[at].interface;
		made[at].key = from[at].key;
		made[at].origin = from[at].origin;
	}
	*out = made;
	return 1;
}

/*
 * Everything netcfgd wrote down, as the observer's input.
 *
 * `ncfg_owned_read` always answers with something usable and says loudly when
 * it had to forget a record, so an unreadable `owned.json` is not a failure
 * here either -- the worst case is netcfgd under-claiming what is its own,
 * which is the safe direction and is the reason that call is written the way
 * it is.
 *
 * The delegations and the reports are different and do fail the round. Neither
 * of them is something netcfgd did: a delegated prefix is what a DHCPv6 client
 * was given and a report is what a bearer or a tunnel came up with, and both
 * are addressing that exists on the machine and appears nowhere in the kernel
 * dumps. An observation quietly missing them is the case
 * `NCFG_OBSERVE_RECORDS_MAX` refuses a truncated dump for. Both fail only on an
 * allocation or a path this run directory makes too long; a missing directory
 * is an empty list and says so.
 */
static int read_record(const char *run_dir, record_t *record, ncfg_observe_prior_t *prior,
    char *err, size_t err_size)
{
	memset(record, 0, sizeof(*record));
	memset(prior, 0, sizeof(*prior));

	if (!ncfg_owned_read(run_dir, &record->owned, err, err_size)) {
		return 0;
	}
	/*
	 * Said once, here, because this is the one place that reads the record on
	 * behalf of somebody who is not going to write it back. `state.h` keeps
	 * the flag as well as the log line precisely so a caller can act on it;
	 * this caller cannot, and what it owes instead is not to let the fact go
	 * past in silence.
	 */
	if (record->owned.carried_more) {
		ncfg_log_emitf("observe", NCFG_LOG_WARNING,
		    "the ownership record carries members this build cannot read, so the "
		    "backends and the DNS scopes in it are not in this observation");
	}
	if (!borrow_objects(record->owned.addresses, record->owned.address_count,
	    &record->addresses, "address(es)", err, err_size)) {
		return 0;
	}
	if (!borrow_objects(record->owned.routes, record->owned.route_count, &record->routes,
	    "route(s)", err, err_size)) {
		return 0;
	}

	/* Borrowed: the record goes on owning every one of these. */
	prior->created_links = record->owned.created_links;
	prior->created_link_count = record->owned.created_link_count;
	prior->address_origins = record->addresses;
	prior->address_origin_count = record->owned.address_count;
	prior->route_origins = record->routes;
	prior->route_origin_count = record->owned.route_count;
	prior->forwarding = record->owned.forwarding;
	prior->forwarding_count = record->owned.forwarding_count;
	prior->privacy = record->owned.privacy;
	prior->privacy_count = record->owned.privacy_count;
	prior->accept_ra = record->owned.accept_ra;
	prior->accept_ra_count = record->owned.accept_ra_count;
	prior->qdisc = record->owned.qdisc;
	prior->qdisc_count = record->owned.qdisc_count;
	prior->ingress = record->owned.ingress;
	prior->ingress_count = record->owned.ingress_count;

	/*
	 * Handed over, and cleared on this side in the same two lines.
	 *
	 * `backends` and `dns` are the other two of the six and stay empty: they
	 * are not members of `ncfg_owned_state_t` at all in this build, which is
	 * what `carried_more` reports having met in a file somebody else wrote.
	 */
	prior->backend_restarts = record->owned.backend_restarts;
	prior->backend_restart_count = record->owned.backend_restart_count;
	record->owned.backend_restarts = NULL;
	record->owned.backend_restart_count = 0;
	prior->hook_state = record->owned.hook_state;
	prior->hook_state_count = record->owned.hook_state_count;
	record->owned.hook_state = NULL;
	record->owned.hook_state_count = 0;

	if (!ncfg_state_read_delegations(run_dir, &prior->delegations, &prior->delegation_count,
	    err, err_size)) {
		return 0;
	}
	return ncfg_state_read_reports(run_dir, &prior->reports, &prior->report_count, err,
	    err_size);
}

/*
 * What a round of dumps found worth mentioning, mentioned.
 *
 * Every one of these is a fact about the round rather than a failure of it --
 * `observe.h` argues each where the field is declared -- and the whole reason
 * the capture carries them is that a dump which came back empty having
 * discarded three datagrams is a different fact from one that came back empty.
 * A log line is where that difference can be acted on; dropping it here would
 * make the counts a field nothing ever reads.
 */
static void note_the_round(const ncfg_observe_capture_t *capture)
{
	if (capture->skipped) {
		ncfg_log_emitf("observe", NCFG_LOG_WARNING,
		    "%zu payload(s) in this round of dumps could not be decoded and were "
		    "skipped: %s", capture->skipped,
		    capture->note[0] ? capture->note : "no sentence was kept");
	}
	if (capture->redirects_unreadable) {
		ncfg_log_emitf("observe", NCFG_LOG_WARNING,
		    "%zu interface(s) carried an ingress hook whose filters could not be "
		    "read, so their redirects are not in this observation",
		    capture->redirects_unreadable);
	}
	if (capture->dropped) {
		ncfg_log_emitf("observe", NCFG_LOG_NOTE,
		    "%zu datagram(s) on the netlink socket did not come from the kernel and "
		    "were discarded", capture->dropped);
	}
}

int ncfg_observe_current_from(const ncfg_observe_kernel_t *kernel, const char *run_dir,
    const ncfg_observe_roots_t *roots, const ncfg_document_t *desired, ncfg_observed_t **out,
    char *err, size_t err_size)
{
	ncfg_observe_capture_t capture;
	record_t               record;
	ncfg_observe_prior_t   prior;
	ncfg_observed_t       *observed = NULL;
	int                    ok;

	if (!out) {
		ncfg_error_set(err, err_size,
		    "an observation was asked for with nowhere to put it");
		return 0;
	}
	*out = NULL;
	if (!kernel || !run_dir || !roots) {
		ncfg_error_set(err, err_size,
		    "an observation needs a round of dumps, a run directory and the three "
		    "roots to read under");
		return 0;
	}

	memset(&capture, 0, sizeof(capture));
	if (!ncfg_observe_collect_from(kernel, &capture, err, err_size)) {
		return 0;
	}
	note_the_round(&capture);

	if (!read_record(run_dir, &record, &prior, err, err_size)) {
		ncfg_observe_prior_free(&prior);
		record_free(&record);
		ncfg_observe_capture_free(&capture);
		return 0;
	}

	ok = ncfg_observe_build(&capture.snapshot, &prior, roots, &observed, err, err_size);
	/*
	 * Freed here rather than at the end, and in this order. `build` has taken
	 * the six aggregate lists and left the prior holding none of them --
	 * `ncfg_observe_prior_free` is correct on either answer, which is what
	 * makes the hand-over defensible -- and everything the observation kept
	 * from the *snapshot* is a copy, so the capture's arrays are nobody's
	 * input from this line on.
	 */
	ncfg_observe_prior_free(&prior);
	record_free(&record);
	ncfg_observe_capture_free(&capture);
	if (!ok) {
		return 0;
	}

	if (!ncfg_observe_augment_host(observed, roots, err, err_size) ||
	    !ncfg_observe_derive(observed, desired, err, err_size)) {
		/*
		 * **Half an observation is not a smaller answer to the same
		 * question.** An observation whose `derive` did not run names no
		 * linkset choice and no connectivity rung, and a caller cannot tell
		 * that from a machine that has neither -- which is the shape of
		 * answer 0263 spends its length refusing. So it is freed and a
		 * sentence comes back.
		 */
		ncfg_observed_free(observed);
		return 0;
	}
	*out = observed;
	return 1;
}

int ncfg_observe_current(const char *run_dir, const ncfg_observe_roots_t *roots,
    const ncfg_document_t *desired, ncfg_observed_t **out, char *err, size_t err_size)
{
	ncfg_netlink_t        netlink;
	ncfg_observe_kernel_t kernel;
	int                   ok;

	if (!out) {
		ncfg_error_set(err, err_size,
		    "an observation was asked for with nowhere to put it");
		return 0;
	}
	*out = NULL;
	if (!ncfg_netlink_open(&netlink, err, err_size)) {
		return 0;
	}
	/*
	 * The same timeout `ncfg_observe_collect` sets and for its reason: a
	 * receive with no timeout wedges the caller for ever, and a caller that
	 * had decided otherwise would be holding the socket itself.
	 */
	if (!ncfg_netlink_set_timeout(&netlink, NCFG_OBSERVE_TIMEOUT_SECONDS, err, err_size)) {
		ncfg_netlink_close(&netlink);
		return 0;
	}
	memset(&kernel, 0, sizeof(kernel));
	kernel.exchange = ncfg_observe_exchange_socket;
	kernel.context = &netlink;
	ok = ncfg_observe_current_from(&kernel, run_dir, roots, desired, out, err, err_size);
	ncfg_netlink_close(&netlink);
	return ok;
}

int ncfg_observe_source_machine(ncfg_observe_source_t *out, const char *run_dir, char *err,
    size_t err_size)
{
	if (!out) {
		ncfg_error_set(err, err_size, "a source was asked for with nowhere to put it");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	(void)ncfg_state_resolve_dir(run_dir, out->run_dir, sizeof(out->run_dir));
	return ncfg_observe_roots_default(&out->roots, err, err_size);
}

int ncfg_observe_source_observe(void *context, const ncfg_document_t *desired,
    ncfg_observed_t **out, char *err, size_t err_size)
{
	const ncfg_observe_source_t *source = context;

	if (!out) {
		ncfg_error_set(err, err_size,
		    "an observation was asked for with nowhere to put it");
		return 0;
	}
	*out = NULL;
	if (!source) {
		ncfg_error_set(err, err_size,
		    "this observer was installed with no source, so it does not know which "
		    "run directory to read the record out of");
		return 0;
	}
	if (!source->kernel.exchange) {
		return ncfg_observe_current(source->run_dir, &source->roots, desired, out, err,
		    err_size);
	}
	return ncfg_observe_current_from(&source->kernel, source->run_dir, &source->roots,
	    desired, out, err, err_size);
}
