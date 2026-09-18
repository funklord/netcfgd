/*
 * state.h -- `/run/netcfgd/`: what netcfgd knows about its own past, in
 * greppable files.
 *
 * Principle 2 in practice. Everything here is plain JSON that answers a
 * question without netcfgd running: what did it decide, what did it see, what
 * did it do, and which objects does it believe are its own.
 *
 * WHAT IS IN THE DIRECTORY
 *   `desired.json`      the whole-host document netcfgd compiled, and
 *   `desired/<if>.json` one file per interface, which are **projections for
 *                       convenience, not separate documents** (section 2).
 *   `provenance.json`   which file and line each field came from, so
 *                       `ncfg explain` can name one without recompiling.
 *   `owned.json`        what netcfgd installed and may therefore remove.
 *   `owned.lock`        never read and never renamed; see `ncfg_owned_update`.
 *   `prefixes/<if>`     what a DHCPv6 client was delegated, one prefix a line.
 *   `reported/<if>` and `reported.d/<if>/<source>`
 *                       what something that is **not** netcfgd was given.
 *
 * THE TWO FILES THAT ARE NOT JSON, AND WHY
 *   A delegation and a report are written by shell scripts -- the hook netcfgd
 *   generates for `odhcp6c`, a wrapper around `mbimcli`, whatever `openvpn`
 *   hands its values to. **A shell script that has to emit valid JSON is a
 *   shell script that will one day emit invalid JSON.** So they are lines of
 *   text it cannot get wrong, and `doc/interface-report.md` is the whole of
 *   the report contract: changing what is parsed here changes what somebody
 *   else's script has to write.
 *
 * WHAT IS DERIVED AND DISPOSABLE
 *   Constraint 1: everything under the run directory can be thrown away. So an
 *   unreadable file is treated as absent rather than fatal -- refusing to
 *   observe a machine because one file is bad is worse than observing the rest
 *   of it -- and the one case where that silence was wrong is now loud: see
 *   `ncfg_owned_read`.
 *
 * WHAT THIS MODULE DOES NOT CARRY YET, SAID OUT LOUD
 *   `owned.json` has two members this build can neither read nor write: the
 *   backends netcfgd started and the DNS scopes it delivered. Their element
 *   types are the observed model's (`ncfg_observed_backend_t`,
 *   `ncfg_applied_dns_t`), whose readers and writers are the field tables in
 *   `src/model/observed.c` -- and those are static. A second copy of a DNS
 *   policy codec here is exactly the duplication 0263 forbids, and it would be
 *   a hundred lines that drift. So they are **deferred, not dropped**:
 *   `ncfg_owned_read` says so through the log when it meets a file that
 *   carries them, because a record silently losing which daemons netcfgd
 *   started is the unsafe direction. They arrive when the model exports those
 *   two types, which is one line in a file this module does not own.
 *
 *   The journal of the last apply (`plan.last.json`) is `netcfgd-apply`'s type
 *   and lands with that module, and `OwnedState::absorb` -- the fold of an
 *   apply's effects into this record -- lands with it too, for the same
 *   reason: its argument is the effect list, which is apply's. The rules that
 *   fold depends on are here and tested: see `ncfg_owned_remember` and
 *   `ncfg_owned_note_hook_state`.
 */
#ifndef NCFG_STATE_H
#define NCFG_STATE_H

#include <stddef.h>
#include <stdint.h>

#include "ncfg/document.h"
#include "ncfg/observed.h"

/* Where runtime state lives when nothing says otherwise. */
#define NCFG_RUN_DIR_DEFAULT "/run/netcfgd"

/* What overrides it, for a test or for a second netcfgd on one machine. */
#define NCFG_RUN_DIR_ENV "NCFG_RUN_DIR"

/*
 * The run directory to use: the explicit one, then the environment, then the
 * default.
 *
 * Copies into `out` and returns it, so a caller has one buffer and no
 * ownership question. Never NULL.
 */
const char *ncfg_state_resolve_dir(const char *explicit_dir, char *out, size_t out_size);

/*
 * Write a file via a temporary and a rename.
 *
 * Design section 17 requires that a power cut during a write cannot leave an
 * unparseable file. Rename is atomic within a filesystem, so a reader sees
 * either the old contents or the new ones and never a half-written mixture.
 *
 * **One implementation, not two, and the temporary is named after the writer.**
 * This had its own, and the two had drifted in the direction that matters: one
 * named its temporary after the process that made it, and this one called
 * every temporary `<name>.tmp`. That is a fixed path two processes share, and
 * two processes do write here -- `ncfg apply` and the daemon both write
 * `owned.json`. Interleaved, one writer's content is renamed into place by the
 * *other* writer's rename and the loser's rename fails with `ENOENT`, which
 * five of the six call sites discarded. So the older copy was not atomic
 * between writers at all, only against readers. The process id alone is not
 * enough either: two threads of one process share it.
 *
 * `mode` is the mode the file is created with; the umask still applies, as it
 * does to any `open`.
 */
int ncfg_write_atomically(const char *path, const void *bytes, size_t length, unsigned int mode,
    char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * The ownership record
 * ------------------------------------------------------------------------ */

/* One object netcfgd installed, and which source asked for it. */
typedef struct {
	char *interface;
	/* The address in CIDR form, or the route destination. */
	char *key;
	int   origin; /* ncfg_origin_t, from observed.h */
} ncfg_owned_object_t;

/*
 * The on-disk form of what netcfgd recorded about its own actions.
 *
 * A type of its own rather than the working structure the observer consumes,
 * because this one is a **file format** and has to stay readable across
 * versions. Keeping them apart means changing one does not silently change
 * what is on disk.
 *
 * Declare one as `ncfg_owned_state_t owned = {0}` and free it with
 * `ncfg_owned_free`; freeing one never filled in is nothing.
 */
typedef struct {
	/*
	 * The boot this record was written during, from
	 * `/proc/sys/kernel/random/boot_id`.
	 *
	 * **A record that outlives its boot describes objects that no longer
	 * exist**, and the danger is not that it is useless -- it is that parts of
	 * it can match something new. It says netcfgd owns `10.0.0.5/24` on
	 * `eth0`; after the reboot an initramfs or an operator put that address
	 * there; netcfgd now believes it installed an address it did not, and may
	 * remove it (0138).
	 *
	 * The marks in the kernel make this moot for addresses, routes, links and
	 * `tc` objects (0002, 0136, 0137), because none of them consults the
	 * record first. **The sysctls are why this field exists**: they have no
	 * mark and no way to get one, so a stale record is the only thing that
	 * could make netcfgd revert a `forwarding` that `sysctl.d` set at boot.
	 *
	 * NULL where it could not be read, and NULL in a file written before this
	 * existed. Both mean "do not judge", never "discard".
	 */
	char  *boot;
	/* Links netcfgd created. */
	char **created_links;
	size_t created_link_count;
	/* Addresses netcfgd installed. */
	ncfg_owned_object_t *addresses;
	size_t               address_count;
	/* Routes netcfgd installed. */
	ncfg_owned_object_t *routes;
	size_t               route_count;
	/* Starts of a backend that did not stay up. Cleared the moment it is seen
	 * running, so a tunnel up for a week carries nothing from an incident last
	 * month (0079). */
	ncfg_backend_restart_t *backend_restarts;
	size_t                  backend_restart_count;
	/* Interfaces netcfgd turned IP forwarding on for. */
	char **forwarding;
	size_t forwarding_count;
	/* Interfaces netcfgd turned temporary addresses on for. */
	char **privacy;
	size_t privacy_count;
	/* Interfaces netcfgd wrote `accept_ra` for, so that one which stops asking
	 * for SLAAC is put back only where netcfgd changed it. */
	char **accept_ra;
	size_t accept_ra_count;
	/* What each event hook was last told, per interface and phase (0064, 0068). */
	ncfg_observed_hook_state_t *hook_state;
	size_t                      hook_state_count;
	/* Interfaces netcfgd set the root qdisc on. */
	char **qdisc;
	size_t qdisc_count;
	/* Interfaces netcfgd installed an ingress redirect on. */
	char **ingress;
	size_t ingress_count;
	/*
	 * Whether the file this was read from carried members this build cannot
	 * carry -- the backends and the DNS scopes; see the header comment.
	 * Reported rather than hidden, and the reason it is a field as well as a
	 * log line is that a caller about to write the record back is the one that
	 * would lose them.
	 */
	int carried_more;
} ncfg_owned_state_t;

/* Free everything it holds, leaving it usable and empty. */
void ncfg_owned_free(ncfg_owned_state_t *owned);

/*
 * Read the record, treating an absent or unreadable file as empty.
 *
 * An unreadable file must not stop netcfgd working -- the run directory is
 * derived and disposable by design (constraint 1) -- and the worst case of
 * treating it as empty is that netcfgd under-claims ownership, which is the
 * safe direction.
 *
 * **Absent and unreadable are treated the same and reported differently.** A
 * file that is there and will not parse is a record netcfgd is *forgetting*,
 * and what it forgets is which addresses and routes are its own to remove.
 * That is a downgrade's most likely shape: an older netcfgd meeting state a
 * newer one wrote. It carries on, because refusing to start would turn a
 * disposable file into an outage, and it says so, because "netcfgd stopped
 * claiming an address it had configured" is not something to work out from
 * behaviour (0189). Measured before that: the daemon started, stayed
 * configured, and said nothing at all.
 *
 * A record from a previous boot is discarded, loudly, for the reason `boot`
 * gives.
 *
 * Always returns 1 with something usable in `*out`; it fails only when it was
 * given nowhere to put the answer.
 */
int ncfg_owned_read(const char *run_dir, ncfg_owned_state_t *out, char *err, size_t err_size);

/*
 * Write the record.
 *
 * The boot id is stamped here rather than asked of every caller: a record that
 * forgot to say which boot it belongs to is one the read cannot judge, and it
 * would fail open.
 */
int ncfg_owned_write(const char *run_dir, const ncfg_owned_state_t *owned, char *err,
    size_t err_size);

/*
 * Change the record, with nobody else changing it in between.
 *
 * **This is how ownership is recorded. The read and the write as a pair are
 * not**, and the difference is the whole reason this exists.
 *
 * Six places did the pair by hand -- read, fold in what an apply just did,
 * write -- and two *processes* run them: `ncfg apply` builds a plan and drives
 * an executor in its own process, and the daemon converges on inotify, on
 * netlink events and on a socket request. Two read-modify-writes of one file
 * with nothing between them lose an update, and the direction that loses is
 * the dangerous one: a fold only ever adds what *this* apply did, so a pass
 * whose own effects are empty writes back whatever it read -- a stale read
 * therefore does not merely fail to record something, it **puts back** a
 * record the other process had just removed. netcfgd then believes it owns an
 * object it has already given up, and ownership is what decides whether
 * netcfgd may reset a qdisc, withdraw an address or delete a link at all.
 *
 * The lock is a separate file rather than `owned.json` itself, because
 * `owned.json` is replaced by a rename: a lock taken on it is a lock on an
 * inode the next writer unlinks, which is a lock two writers can hold at once.
 * `owned.lock` is never renamed and never read.
 *
 * A failure to take the lock is returned rather than swallowed. Carrying on
 * unlocked is exactly the behaviour this replaces, and a caller that wants it
 * can have it by ignoring the error -- deliberately, and in its own words.
 *
 * `change` is called with the record read under the lock, and `context` is the
 * caller's and untouched here. Returning 0 from it abandons the update without
 * writing, which is how a caller says "nothing to record after all".
 */
int ncfg_owned_update(const char *run_dir, int (*change)(ncfg_owned_state_t *owned, void *context),
    void *context, char *err, size_t err_size);

/*
 * Remember an interface netcfgd changed, or forget one it changed back.
 *
 * **Only the interfaces netcfgd switched *on* are recorded.** Switching one off
 * drops the record rather than storing false: the question this answers is "is
 * this ours to undo later", and once it has been undone the answer is no.
 *
 * One function because there are five lists of exactly this shape --
 * forwarding, privacy, accept_ra, qdisc, ingress -- and five copies of a
 * three-line rule is how two of them come to disagree about what "off" means.
 * `accept_ra` is the one whose "off" is not false: the value netcfgd writes to
 * give an interface back is 1, the kernel's own default, so that is what drops
 * the record (0073) -- which is the caller's comparison, not this function's.
 */
int ncfg_owned_remember(char ***list, size_t *count, const char *interface, int ours);

/*
 * Record what one event hook on one interface was last told.
 *
 * **One record per interface and phase, replaced rather than appended**: what
 * matters is what a hook was last told, and the previous answer is of no use
 * once a newer one exists.
 */
int ncfg_owned_note_hook_state(ncfg_owned_state_t *owned, const char *interface, int phase,
    const char *value);

/*
 * This boot's id, or NULL where the kernel does not offer one.
 *
 * `/proc/sys/kernel/random/boot_id` is a UUID the kernel generates once per
 * boot. It is read rather than derived from uptime because uptime is a moving
 * number and this needs an identity: two runs of netcfgd during one boot must
 * agree, and the same run either side of a reboot must not. The caller owns
 * what comes back.
 */
char *ncfg_state_boot_id(void);

/* ------------------------------------------------------------------------ *
 * Provenance
 * ------------------------------------------------------------------------ */

/* One field, and where it was written. */
typedef struct {
	/* Dotted path into the document, for example
	 * `interfaces[eth0].addressing[0]`. */
	char   *path;
	char   *file;
	int64_t line;   /* one-based */
	int64_t column; /* one-based */
} ncfg_provenance_entry_t;

/*
 * Every recorded field.
 *
 * **The document itself deliberately carries no spans**: it is the frozen
 * schema, it is written to the run directory and eventually transmitted, and
 * putting file offsets in it would make two compiles of one configuration
 * differ whenever a comment moved. So provenance is a side table, keyed by the
 * same dotted paths the planner uses -- which is what lets `ncfg explain`
 * answer "because `/etc/netcfgd/conf.d/10-lan.conf` line 4 says so" rather
 * than "because the configuration says so".
 *
 * **The type is declared here and not in the compiler**, where the Rust keeps
 * it, because in this port it is the shape of a file this module reads and
 * writes and nothing in `src/compile/` has one yet. A compiler that grows
 * provenance fills this in rather than declaring a second: two definitions of
 * one file format is how a reader and a writer come to disagree about a member
 * name.
 */
typedef struct {
	ncfg_provenance_entry_t *entries;
	size_t                   count;
} ncfg_provenance_t;

void ncfg_provenance_free(ncfg_provenance_t *provenance);

/* Record a field's position. The strings are copied. */
int ncfg_provenance_record(ncfg_provenance_t *provenance, const char *path, const char *file,
    int64_t line, int64_t column, char *err, size_t err_size);

/* Where a field was written, or NULL. */
const ncfg_provenance_entry_t *ncfg_provenance_lookup(const ncfg_provenance_t *provenance,
    const char *path);

/* `file:line:column`, which is what an editor and a person both want. Always
 * NUL-terminates. */
void ncfg_provenance_location(const ncfg_provenance_entry_t *entry, char *out, size_t out_size);

/* Put the entries in a stable order and drop repeated paths, so the file does
 * not change between compiles of one configuration. */
void ncfg_provenance_canonicalize(ncfg_provenance_t *provenance);

/* Write it, so `ncfg explain` can name a file and line without recompiling. */
int ncfg_state_write_provenance(const char *run_dir, ncfg_provenance_t *provenance, char *err,
    size_t err_size);

/* Read it back, treating an absent or unreadable file as empty -- an
 * explanation without file positions is still worth printing. */
int ncfg_state_read_provenance(const char *run_dir, ncfg_provenance_t *out, char *err,
    size_t err_size);

/* ------------------------------------------------------------------------ *
 * The desired document, and the observation
 * ------------------------------------------------------------------------ */

/*
 * Write the desired document, so `cat` can answer what netcfgd decided.
 *
 * Canonical, then one file per interface under `desired/`. The projections
 * exist so that `cat /run/netcfgd/desired/eth0.json` answers a question about
 * one interface without a reader having to find it inside the whole file.
 *
 * **Stale projections are removed first**, so an interface dropped from the
 * configuration does not leave a file claiming it is still configured:
 * principle 2 depends on what is in the run directory being true, not merely
 * once-true. No interfaces means no directory at all -- section 4.6, the
 * filesystem reflects use rather than capability.
 *
 * Canonicalises the document in place, which is what `ncfg_document_write_
 * canonical` does and what makes two documents comparable.
 */
int ncfg_state_write_desired(const char *run_dir, ncfg_document_t *document, char *err,
    size_t err_size);

/*
 * Write the observed model.
 *
 * The whole-host file only. **The per-link projections are deferred**, for the
 * reason the header comment gives about `owned.json`: one of those files is
 * `{link, addresses on it, routes on it}` and assembling it needs the observed
 * model's own writers, which are not exported. `observed.json` itself goes
 * through `ncfg_observed_write_canonical`, which is.
 */
int ncfg_state_write_observed(const char *run_dir, ncfg_observed_t *observed, char *err,
    size_t err_size);

/* ------------------------------------------------------------------------ *
 * What somebody else reported
 * ------------------------------------------------------------------------ */

/*
 * Read every delegation a DHCPv6 client has reported.
 *
 * One file per interface under `prefixes/`, one prefix per line, blank lines
 * and `#` comments ignored. A missing directory is not an error: it means no
 * client has reported one, which is the state of every machine that is not a
 * router. **An empty file means the lease expired and the hook recorded that**,
 * which differs from no file at all only in that it says so deliberately; both
 * produce no prefixes.
 *
 * Sorted by interface. The caller frees with `ncfg_state_delegations_free`.
 */
int ncfg_state_read_delegations(const char *run_dir, ncfg_delegation_t **out, size_t *count_out,
    char *err, size_t err_size);
void ncfg_state_delegations_free(ncfg_delegation_t *delegations, size_t count);

/*
 * Read every report that has been written.
 *
 * **Two places, one answer.** `reported/<interface>` is the single file the
 * contract documents, written by something that is not netcfgd;
 * `reported.d/<interface>/<source>` is one file per writer, which is what
 * netcfgd's own clients use because a dual-stack interface has two of them
 * (0086). The single file comes first and the fragments follow in name order,
 * so a DHCPv4 lease's nameservers precede a DHCPv6 lease's and the order is
 * the same on every machine and every boot rather than the filesystem's.
 *
 * Unreadable and malformed files are skipped rather than failing the
 * observation, and a staging file -- anything whose name begins with a dot --
 * is not a report: the contract tells every writer to build one in the
 * directory and rename it over the target, so the half-written file it exists
 * to hide is sitting right there, and without this it was read as a report for
 * an interface named after the temporary file (0113).
 *
 * Sorted by interface. The caller frees with `ncfg_state_reports_free`.
 */
int ncfg_state_read_reports(const char *run_dir, ncfg_observed_report_t **out, size_t *count_out,
    char *err, size_t err_size);
void ncfg_state_reports_free(ncfg_observed_report_t *reports, size_t count);

/* Free what one report holds, leaving it usable and empty. Here as well as the
 * list's free because `ncfg_state_parse_report` fills a caller's own, and a
 * caller with one on the stack cannot use the list's. */
void ncfg_state_report_free(ncfg_observed_report_t *report);

/*
 * One report, parsed.
 *
 * Split out so the format -- which is somebody else's to write -- is testable
 * without a filesystem.
 *
 * **Unknown keys are ignored, and that is a promise the contract makes.** It is
 * what lets a helper report `mtu=` or `operator=` before netcfgd knows what to
 * do with them, instead of every helper waiting on netcfgd to catch up. A
 * malformed value is skipped for the neighbouring reason: a bearer that came up
 * with a usable v4 address and a mangled v6 one should still get the v4.
 */
int ncfg_state_parse_report(const char *interface, const char *body, size_t length,
    ncfg_observed_report_t *out, char *err, size_t err_size);

#endif /* NCFG_STATE_H */
