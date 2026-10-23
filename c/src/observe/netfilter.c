/*
 * netfilter.c -- netcfgd's own NAT, and anybody else's, read back from the
 * kernel.
 *
 * WHY THIS IS A ROUND OF ITS OWN
 *   `collect.c` takes seven dumps over one rtnetlink socket. nftables is
 *   `NETLINK_NETFILTER`, which is a different protocol on a different socket
 *   -- so it cannot join that round, and it is not a file either, which is
 *   what keeps it out of `host.c`. It is the third shape the observer has: a
 *   second exchange, asked two questions.
 *
 * WHAT IT ANSWERS, AND WHY BOTH HALVES MATTER
 *   `nat` is what netcfgd's own table currently masquerades, which is the
 *   observation half of the reconciliation: without it the planner compares
 *   the document against an empty list, emits `nat.replace` on every pass and
 *   never converges -- and its *inverse* is the observed list, so a revert
 *   would put back nothing rather than what was there. `nat_conflicts` is the
 *   other half of decision 0022: a second table doing source NAT at the same
 *   hook double-translates, which breaks return paths in ways that look like
 *   packet loss, and netcfgd reports it rather than touching it.
 *
 * NOTHING HERE FAILS AN OBSERVATION BECAUSE THE KERNEL WOULD NOT ANSWER
 *   A kernel with no `nf_tables`, a container whose netlink is denied, and a
 *   machine where netcfgd has simply never installed a table are all ordinary,
 *   and `observed.h` already says the planner treats them the same: no NAT is
 *   installed. So a dump that cannot be taken leaves both lists empty and says
 *   so in a note. What *is* refused is an answer larger than this will hold --
 *   the ceiling `collect.c` argues for, applied to the one list here that is
 *   input to a planner rather than to a report.
 *
 * WHERE THE NAMES COME FROM
 *   `nft.h` and nowhere else. No call in that header takes a table or a chain
 *   name, every read refuses a payload from another table, and both facts are
 *   what stop this file from being a second opinion about what netcfgd owns.
 */
#include "ncfg/observe.h"

#include "observe_internal.h"

#include "ncfg/log.h"
#include "ncfg/nft.h"
#include "ncfg/wire.h"

#include <stdlib.h>
#include <string.h>

/*
 * One dump, built by nft.c and performed by the caller's exchange.
 *
 * 0 is a request this port could not build, which is a fault in netcfgd; a
 * kernel that would not answer is 1 with an empty reply, which is not.
 */
static int dump(const ncfg_observe_kernel_t *kernel,
    int (*build)(ncfg_buf_t *, uint32_t, char *, size_t), const char *about,
    ncfg_netlink_reply_t *reply, char *err, size_t err_size)
{
	ncfg_buf_t message;
	ncfg_buf_t body;
	uint16_t   kind = 0;
	uint16_t   flags = 0;
	char       why[NCFG_ERROR_MAX];
	int        parts;
	int        answered;

	memset(reply, 0, sizeof(*reply));
	ncfg_buf_init(&message, 0);
	ncfg_buf_init(&body, 0);
	if (!build(&message, 0, err, err_size)) {
		ncfg_buf_free(&message);
		ncfg_buf_free(&body);
		return 0;
	}
	parts = ncfg_wire_request_parts(&message, "nftables", &kind, &flags, &body, err, err_size);
	ncfg_buf_free(&message);
	if (!parts) {
		ncfg_buf_free(&body);
		return 0;
	}
	why[0] = '\0';
	answered = kernel->exchange(kernel->context, kind, flags, &body, NULL, reply, why,
	    sizeof(why));
	ncfg_buf_free(&body);
	if (!answered) {
		/*
		 * **The one place this file is deliberately incurious.** `ENOENT` is
		 * a table that does not exist, `EPERM` is a netlink this process may
		 * not ask, `EPROTONOSUPPORT` is a kernel built without nftables --
		 * and all three mean the same thing to a planner, which `observed.h`
		 * says where the field is declared. The sentence is kept in a note so
		 * that a machine which stopped answering is not silent.
		 */
		ncfg_netlink_reply_free(reply);
		memset(reply, 0, sizeof(*reply));
		/*
		 * **`about` is why this says which dump, and it is not
		 * decoration.** There are two -- rules and chains -- and both
		 * fail together on a process that may not ask netlink, so an
		 * operator saw this sentence twice, identically, each copy
		 * claiming both outcomes. Two failures are two facts; a line
		 * that cannot be told from the one above it reads as a log
		 * repeating itself rather than as a second request refused.
		 * project.md 10.386, and the same shape as the resolv.conf
		 * episode count in 10.348.
		 */
		ncfg_log_emitf("observe", NCFG_LOG_NOTE,
		    "the nftables %s dump was not answered (%s), so this observation reports "
		    "nothing from it",
		    about, why[0] ? why : "no sentence was given");
	}
	return 1;
}

/*
 * The ruleset's generation, through the same exchange the dumps use.
 *
 * 1 with `*out` set, or 1 with `*have` cleared where the kernel would not
 * answer -- a generation netcfgd cannot read is not a reason to report no NAT,
 * it is a reason to stop claiming the two dumps describe one ruleset. 0 is a
 * request this port could not build, as everywhere else in this file.
 */
static int generation(const ncfg_observe_kernel_t *kernel, uint32_t *out, int *have, char *err,
    size_t err_size)
{
	ncfg_netlink_reply_t reply;
	ncfg_buf_t           message;
	ncfg_buf_t           body;
	uint16_t             kind = 0;
	uint16_t             flags = 0;
	char                 why[NCFG_ERROR_MAX];
	int                  parts;

	*have = 0;
	*out = 0;
	ncfg_buf_init(&message, 0);
	ncfg_buf_init(&body, 0);
	if (!ncfg_nft_build_gen_request(&message, 0, err, err_size)) {
		ncfg_buf_free(&message);
		ncfg_buf_free(&body);
		return 0;
	}
	parts = ncfg_wire_request_parts(&message, "nftables", &kind, &flags, &body, err, err_size);
	ncfg_buf_free(&message);
	if (!parts) {
		ncfg_buf_free(&body);
		return 0;
	}
	memset(&reply, 0, sizeof(reply));
	why[0] = '\0';
	if (kernel->exchange(kernel->context, kind, flags, &body, NULL, &reply, why, sizeof(why)) &&
	    reply.count != 0u &&
	    ncfg_nft_gen_read(reply.items[0].bytes, reply.items[0].length, out, NULL, 0)) {
		*have = 1;
	}
	ncfg_buf_free(&body);
	ncfg_netlink_reply_free(&reply);
	return 1;
}

/* Sorted already, so a repeat is the one before it. */
static size_t dedup(char **names, size_t count)
{
	size_t kept = 0;
	size_t at;

	for (at = 0; at < count; at++) {
		if (kept != 0 && names[kept - 1u] && names[at] &&
		    strcmp(names[kept - 1u], names[at]) == 0) {
			free(names[at]);
			names[at] = NULL;
			continue;
		}
		names[kept++] = names[at];
	}
	return kept;
}

/* The ceiling this round holds one list to. A field on the kernel struct for
 * `collect.c`'s reason: the kernel will not produce an oversized answer on
 * demand, so a test that could not lower it could never reach the refusal. */
static size_t ceiling_of(const ncfg_observe_kernel_t *kernel)
{
	return kernel->records_max ? kernel->records_max : NCFG_OBSERVE_RECORDS_MAX;
}

static int read_uplinks(const ncfg_observe_kernel_t *kernel, ncfg_observed_t *observed,
    char *err, size_t err_size)
{
	ncfg_netlink_reply_t reply;
	char               **found = NULL;
	size_t               count = 0;
	size_t               skipped = 0;
	size_t               at;
	/* The first sentence a payload was refused with, kept for the reason
	 * `collect.c` keeps one: a count with no sentence is a number nobody can
	 * act on, and a sentence per payload is a log nobody reads. */
	char                 note[NCFG_ERROR_MAX];

	note[0] = '\0';
	if (!dump(kernel, ncfg_nft_build_rule_dump, "rule", &reply, err, err_size)) {
		return 0;
	}
	for (at = 0; at < reply.count; at++) {
		char name[NCFG_NFT_IFNAME_MAX];
		char why[NCFG_ERROR_MAX];

		if (!ncfg_nft_rule_uplink(reply.items[at].bytes, reply.items[at].length, name,
		    sizeof(name), why, sizeof(why))) {
			/*
			 * A rule netcfgd did not write is not netcfgd's to describe, and
			 * `nft.h` refuses it rather than guessing. That is an ordinary
			 * answer here -- the kernel is asked for netcfgd's own chain and
			 * is not trusted to have honoured the filter -- so it is counted
			 * rather than failing the round.
			 */
			if (note[0] == '\0') {
				ncfg_error_set(note, sizeof(note), "%s", why);
			}
			skipped++;
			continue;
		}
		if (count >= ceiling_of(kernel)) {
			ncfg_error_set(err, err_size,
			    "netcfgd's nftables chain holds more than %zu masquerade rule(s), "
			    "which is more than an observation holds",
			    ceiling_of(kernel));
			observe_names_free(found, count);
			ncfg_netlink_reply_free(&reply);
			return 0;
		}
		if (!observe_list_add(&found, &count, name)) {
			ncfg_error_set(err, err_size, "out of memory recording the installed NAT");
			observe_names_free(found, count);
			ncfg_netlink_reply_free(&reply);
			return 0;
		}
	}
	ncfg_netlink_reply_free(&reply);
	if (skipped != 0) {
		ncfg_log_emitf("observe", NCFG_LOG_NOTE,
		    "%zu rule(s) in the nftables dump were not netcfgd's own masquerade and "
		    "were not read as uplinks: %s", skipped,
		    note[0] ? note : "no sentence was kept");
	}
	/*
	 * Sorted and deduplicated, which the planner depends on rather than
	 * merely likes: it sorts the document's uplinks and compares the two
	 * lists in order, so an unsorted observation would differ from a machine
	 * that is already right and replace the table on every pass.
	 */
	observe_list_sort(found, count);
	count = dedup(found, count);
	observe_names_free(observed->nat, observed->nat_count);
	observed->nat = found;
	observed->nat_count = count;
	return 1;
}

static int read_conflicts(const ncfg_observe_kernel_t *kernel, ncfg_observed_t *observed,
    char *err, size_t err_size)
{
	ncfg_netlink_reply_t reply;
	char               **found = NULL;
	size_t               count = 0;
	size_t               skipped = 0;
	size_t               at;
	char                 note[NCFG_ERROR_MAX];

	note[0] = '\0';
	if (!dump(kernel, ncfg_nft_build_chain_dump, "chain", &reply, err, err_size)) {
		return 0;
	}
	for (at = 0; at < reply.count; at++) {
		ncfg_nft_chain_t chain;
		char             why[NCFG_ERROR_MAX];

		if (!ncfg_nft_chain_read(reply.items[at].bytes, reply.items[at].length, &chain,
		    why, sizeof(why))) {
			if (note[0] == '\0') {
				ncfg_error_set(note, sizeof(note), "%s", why);
			}
			skipped++;
			continue;
		}
		if (!ncfg_nft_chain_is_source_nat(&chain) ||
		    strcmp(chain.table, NCFG_NFT_TABLE) == 0) {
			continue;
		}
		if (count >= ceiling_of(kernel)) {
			/*
			 * Reported rather than refused, which is the opposite of the
			 * uplinks above and is the difference between a planner's input
			 * and a warning's: this list is only ever printed, and a machine
			 * with a million NAT chains has a sentence to show either way.
			 */
			ncfg_log_emitf("observe", NCFG_LOG_WARNING,
			    "more than %zu table(s) do source NAT beside netcfgd's; the rest "
			    "are not in this observation", ceiling_of(kernel));
			break;
		}
		if (!observe_list_add(&found, &count, chain.table)) {
			ncfg_error_set(err, err_size,
			    "out of memory recording a conflicting nftables table");
			observe_names_free(found, count);
			ncfg_netlink_reply_free(&reply);
			return 0;
		}
	}
	ncfg_netlink_reply_free(&reply);
	if (skipped != 0) {
		ncfg_log_emitf("observe", NCFG_LOG_NOTE,
		    "%zu payload(s) in the nftables chain dump could not be read, so a table "
		    "doing NAT beside netcfgd's may be missing from this observation: %s",
		    skipped, note[0] ? note : "no sentence was kept");
	}
	observe_list_sort(found, count);
	count = dedup(found, count);
	observe_names_free(observed->nat_conflicts, observed->nat_conflict_count);
	observed->nat_conflicts = found;
	observed->nat_conflict_count = count;
	return 1;
}

int ncfg_observe_netfilter_from(const ncfg_observe_kernel_t *kernel, ncfg_observed_t *observed,
    char *err, size_t err_size)
{
	if (!observed) {
		ncfg_error_set(err, err_size, "there is no observation to read the NAT into");
		return 0;
	}
	if (!kernel || !kernel->exchange) {
		/*
		 * **A seam that is absent costs exactly what it says.** A caller with
		 * no netfilter exchange observes everything else and reports no NAT,
		 * which is `ncfg_reconcile_world_t`'s bargain and is what lets a test
		 * install only the seam its case is about. The lists are cleared
		 * rather than left, so a second observation through a source without
		 * one does not carry the first's answer.
		 */
		observe_names_free(observed->nat, observed->nat_count);
		observed->nat = NULL;
		observed->nat_count = 0;
		observe_names_free(observed->nat_conflicts, observed->nat_conflict_count);
		observed->nat_conflicts = NULL;
		observed->nat_conflict_count = 0;
		return 1;
	}
	/*
	 * **Taken between two readings of the generation, and taken again when it
	 * moved.**
	 *
	 * The two dumps below are separate requests, and docker, podman, libvirt
	 * and `firewalld` add and remove tables while netcfgd runs. A table that
	 * appears or vanishes between them makes the conflict report wrong in
	 * both directions -- naming one that has gone, or missing one that
	 * arrived -- and nothing in the dumps themselves can tell. The kernel's
	 * generation counter can: equal before and after means they describe one
	 * ruleset. nft.h has the argument, 0283 and 0284 the direction.
	 *
	 * **Bounded, and a bound that is reached is reported rather than hidden.**
	 * A machine whose ruleset changes faster than two dumps take is a real
	 * machine -- a container host starting a compose file is exactly that --
	 * and the honest answer there is the last observation plus a sentence
	 * saying it may be torn, not an unbounded retry inside a reconcile pass
	 * that has a deadline.
	 *
	 * Three attempts because the second catches the ordinary case of one
	 * change landing mid-observation, and a third that still disagrees is a
	 * machine busy enough that a fourth would not help.
	 */
	{
		int attempt;

		for (attempt = 0; attempt < 3; attempt++) {
			uint32_t before = 0;
			uint32_t after = 0;
			int      had_before = 0;
			int      had_after = 0;

			if (!generation(kernel, &before, &had_before, err, err_size)) {
				return 0;
			}
			/* The uplinks first, because they are the half a planner acts on:
			 * a conflict list that could not be built must not cost the
			 * observation the answer it reconciles against. */
			if (!read_uplinks(kernel, observed, err, err_size)) {
				return 0;
			}
			if (!read_conflicts(kernel, observed, err, err_size)) {
				return 0;
			}
			if (!generation(kernel, &after, &had_after, err, err_size)) {
				return 0;
			}
			/*
			 * **A kernel that will not say is not a kernel that moved.** No
			 * generation means no check -- an older kernel, or a netlink this
			 * process may not ask -- and the observation stands as it did
			 * before this check existed rather than being retried three times
			 * for nothing.
			 */
			if (!had_before || !had_after || before == after) {
				return 1;
			}
			ncfg_log_emitf("observe", NCFG_LOG_NOTE,
			    "the nftables ruleset changed while it was being read (generation %u "
			    "to %u), so this observation is being taken again",
			    (unsigned)before, (unsigned)after);
		}
		ncfg_log_emit("observe", NCFG_LOG_WARNING,
		    "the nftables ruleset is changing faster than it can be read, so the NAT "
		    "conflict list may name a table that has gone or miss one that arrived");
	}
	return 1;
}

int observe_netfilter_open(ncfg_netlink_t *socket, ncfg_observe_kernel_t *out)
{
	char why[NCFG_ERROR_MAX];

	ncfg_netlink_init(socket);
	memset(out, 0, sizeof(*out));
	why[0] = '\0';
	if (!ncfg_netlink_open_protocol(socket, NCFG_NFT_NETLINK_PROTOCOL, 0, why, sizeof(why)) ||
	    !ncfg_netlink_set_timeout(socket, NCFG_OBSERVE_TIMEOUT_SECONDS, why, sizeof(why))) {
		/*
		 * A kernel with no `nf_tables` has no socket to open, and that is the
		 * commonest reason this fails. It is the same "no NAT is installed"
		 * the dump itself answers with, so it is a note rather than a refusal
		 * -- and the observation goes on being taken.
		 */
		ncfg_netlink_close(socket);
		ncfg_log_emitf("observe", NCFG_LOG_NOTE,
		    "no netfilter socket could be opened (%s), so this observation reports no "
		    "NAT installed and no conflicting table", why);
		return 0;
	}
	/* Without a timeout a lost message wedges the caller for ever, which is
	 * `ncfg_observe_collect`'s argument and is asked above rather than here so
	 * that a socket which opened and could not be timed out is closed with the
	 * one that never opened. */
	out->exchange = ncfg_observe_exchange_socket;
	out->context = socket;
	return 1;
}
