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
 *   length of the `build`, and hands away four of its own -- the backends, the
 *   restart tally, the delivered DNS scopes and the hook state -- which means
 *   clearing each on this side, or the record's free and the observation's
 *   free are two frees of one array. The moves are together in `read_record`
 *   and nowhere else for that reason.
 */
#include "ncfg/observe.h"

#include "observe_internal.h"

#include "ncfg/log.h"
#include "ncfg/state.h"

#include <stdio.h>

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
	 * Handed over, and cleared on this side in the same two lines each.
	 *
	 * All six of them now. `backends` and `dns` were the two the record did
	 * not carry, so this hand-over was two lists short and `observed.backends`
	 * and `observed.dns` were empty on every machine -- which is what left six
	 * observation passes with nothing to walk and made the planner ask for a
	 * DNS delivery it had already made, for ever (project.md 10.183).
	 */
	prior->backends = record->owned.backends;
	prior->backend_count = record->owned.backend_count;
	record->owned.backends = NULL;
	record->owned.backend_count = 0;
	prior->backend_restarts = record->owned.backend_restarts;
	prior->backend_restart_count = record->owned.backend_restart_count;
	record->owned.backend_restarts = NULL;
	record->owned.backend_restart_count = 0;
	prior->dns = record->owned.dns;
	prior->dns_count = record->owned.dns_count;
	record->owned.dns = NULL;
	record->owned.dns_count = 0;
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

int ncfg_observe_current_from(const ncfg_observe_kernel_t *kernel,
    const ncfg_observe_kernel_t *netfilter, const ncfg_observe_kernel_t *genl,
    const char *run_dir, const ncfg_observe_roots_t *roots,
    const ncfg_secret_resolver_t *secrets, const ncfg_document_t *desired,
    ncfg_observed_t **out, char *err, size_t err_size)
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

	/*
	 * The nftables round and the offloads round before the files and after
	 * the record, in that order, which is where `augment` has the two of them
	 * -- `read_netfilter` then `read_offloads`. Nothing between them reads
	 * what any of them writes -- `derive` asks about neither NAT nor
	 * offloads -- so the position is the Rust's rather than load-bearing;
	 * what *is* load-bearing is that both come before the refusal below, so a
	 * round that failed costs the observation rather than leaving half of one
	 * behind.
	 *
	 * The offloads round is after `build` and not inside it for a reason that
	 * is load-bearing: it writes one list per *link*, so it needs the link
	 * table `build` produced to know which devices to ask about. The
	 * WireGuard round is the same shape on the same socket, and asks nothing
	 * at all where no link is one.
	 *
	 * **The currency question is the one order here that is load-bearing.**
	 * It fills in `key_matches` on the device states the round before it
	 * produced, so a machine whose generic netlink could not be read has
	 * nothing for it to write into -- which is right, and is why it walks the
	 * observation rather than the document. `augment` has the two in this
	 * order for the same reason (`host.rs:61-62`).
	 */
	/*
	 * **The liveness round is before `derive` and that is load-bearing.** It
	 * can only clear `running`, and `derive` reads the backend list to answer
	 * what this machine is doing -- so running it afterwards would leave one
	 * pass's conclusions drawn from a daemon the next pass knows is dead. It
	 * is after the record for the same reason the others are: the list it
	 * corrects is what `build` took out of the record.
	 */
	if (!ncfg_observe_netfilter_from(netfilter, observed, err, err_size) ||
	    !ncfg_observe_offloads_from(genl, observed, err, err_size) ||
	    !ncfg_observe_wireguard_from(genl, observed, err, err_size) ||
	    !ncfg_observe_wireguard_currency(observed, run_dir, secrets, desired, err,
	    err_size) ||
	    !ncfg_observe_backend_liveness(observed, run_dir, err, err_size) ||
	    !ncfg_observe_advertised(observed, run_dir, err, err_size) ||
	    !ncfg_observe_currency(observed, run_dir, secrets, desired, err, err_size) ||
	    /*
	     * **After the record has been read and before anything reads
	     * `observed.dns`.** This is the one pass that takes an answer away: it
	     * empties the delivered scopes where the file no longer holds what
	     * they say netcfgd put there, and the planner reads that list as
	     * "already delivered". Running it later would leave a pass concluding
	     * from a delivery that is not on the machine any more.
	     */
	    !ncfg_observe_resolv_currency(observed, roots ? roots->resolv_conf : NULL, err,
	    err_size) ||
	    /*
	     * **Last of the record readers, because it is the one that waits.**
	     * Every pass before it reads a file; this opens a control socket per
	     * running access point and gives each one `NCFG_SUPPLICANT_IMPATIENT_MS`
	     * -- so a wedged hostapd costs the observation that long and nothing
	     * before it is held up behind the wait.
	     */
	    !ncfg_observe_access_control(observed, run_dir, 0, err, err_size) ||
	    /*
	     * **Before `derive`, because `derive` reads the link's network.** So
	     * does `ncfg_observed_effective_metric`, and so does the inventory --
	     * this is the pass that fills it, and running it afterwards would
	     * leave all three drawing conclusions from a field nothing had
	     * written.
	     */
	    !ncfg_observe_supplicants(observed, run_dir, secrets, desired, 0, err, err_size) ||
	    !ncfg_observe_augment_host(observed, roots, err, err_size) ||
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
    const ncfg_secret_resolver_t *secrets, const ncfg_document_t *desired,
    ncfg_observed_t **out, char *err, size_t err_size)
{
	ncfg_netlink_t        netlink;
	ncfg_netlink_t        netfilter;
	ncfg_netlink_t        generic;
	ncfg_observe_kernel_t kernel;
	ncfg_observe_kernel_t nft;
	ncfg_observe_kernel_t genl;
	int                   have_nft;
	int                   have_genl;
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
	/*
	 * And the netfilter socket beside it, which is a second protocol rather
	 * than a second question on the first. One that will not open is the
	 * commonest way a kernel says it has no nftables, so the observation goes
	 * on without it and reports no NAT installed -- which is what a planner
	 * does with "no table" anyway.
	 */
	have_nft = observe_netfilter_open(&netfilter, &nft);
	/*
	 * And the generic netlink socket beside those two, which is a third
	 * protocol again. One that will not open costs this observation every
	 * link's offloads and nothing else, which `ncfg_observe_offloads_from`
	 * says is one of the three ordinary ways a machine declines to answer
	 * that question.
	 */
	have_genl = observe_genl_open(&generic, &genl);
	ok = ncfg_observe_current_from(&kernel, have_nft ? &nft : NULL,
	    have_genl ? &genl : NULL, run_dir, roots, secrets, desired, out, err, err_size);
	ncfg_netlink_close(&generic);
	ncfg_netlink_close(&netfilter);
	ncfg_netlink_close(&netlink);
	return ok;
}

int ncfg_observe_source_machine(ncfg_observe_source_t *out, const char *run_dir,
    const char *secrets_dir, char *err, size_t err_size)
{
	if (!out) {
		ncfg_error_set(err, err_size, "a source was asked for with nowhere to put it");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	(void)ncfg_state_resolve_dir(run_dir, out->run_dir, sizeof(out->run_dir));
	/*
	 * **An argument, and nothing is invented where it is absent.** The run
	 * directory has a resolver of its own because `state.h` owns that
	 * question; where the secrets are is `--config-dir`'s answer, and a
	 * source that reached `NCFG_SECRETS_DIR_DEFAULT` for itself would read
	 * the machine's real credentials on a daemon that had been pointed
	 * somewhere else entirely. A name too long for this is the same as none:
	 * the currency question goes unanswered, which is a question left open
	 * rather than one answered wrongly.
	 */
	if (secrets_dir && secrets_dir[0] &&
	    (size_t)snprintf(out->secrets_dir, sizeof(out->secrets_dir), "%s", secrets_dir) >=
	    sizeof(out->secrets_dir)) {
		out->secrets_dir[0] = '\0';
	}
	return ncfg_observe_roots_default(&out->roots, err, err_size);
}

int ncfg_observe_source_observe(void *context, const ncfg_document_t *desired,
    ncfg_observed_t **out, char *err, size_t err_size)
{
	const ncfg_observe_source_t  *source = context;
	const ncfg_secret_resolver_t *store;
	ncfg_secret_resolver_t        secrets;

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
	/*
	 * The store the currency question is asked of, or none.
	 *
	 * Empty means the question is not asked, which
	 * `ncfg_observe_wireguard_currency` reads as "nothing to ask" rather than
	 * as an answer. `materialise_dir` stays NULL for `secrets.h`'s reason:
	 * nothing in an observation writes a file, so a resolver here that could
	 * would carry a capability it has no use for.
	 */
	memset(&secrets, 0, sizeof(secrets));
	secrets.secrets_dir = source->secrets_dir[0] ? source->secrets_dir : NULL;
	store = source->secrets_dir[0] ? &secrets : NULL;
	if (!source->kernel.exchange) {
		return ncfg_observe_current(source->run_dir, &source->roots, store, desired, out,
		    err, err_size);
	}
	/*
	 * A source with a route exchange installed is a machine a test made up,
	 * and its netfilter and generic netlink seams are whatever that test
	 * installed -- absent, which asks nothing, or a replay. Opening a real
	 * socket for either here would be the half of that observation that
	 * reached the developer's own ruleset, or their own network card.
	 */
	return ncfg_observe_current_from(&source->kernel,
	    source->netfilter.exchange ? &source->netfilter : NULL,
	    source->genl.exchange ? &source->genl : NULL, source->run_dir, &source->roots,
	    store, desired, out, err, err_size);
}
