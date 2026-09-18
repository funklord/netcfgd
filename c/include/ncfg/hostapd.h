/*
 * hostapd.h -- running an access point through `hostapd`.
 *
 * WHY A FILE AND NOT A SOCKET
 *   The shape differs from the supplicant in one way that drives everything
 *   here. A supplicant is filled over its control socket, so 0015 can say it
 *   holds no state; hostapd reads a file once at startup and offers no way to
 *   hand it a network afterwards. So netcfgd writes that file, into the run
 *   directory where derived state belongs (constraint 1), and regenerates it
 *   on every apply. **Nothing is read back out of it** -- the document remains
 *   the only authority, and the file is a rendering of the document rather
 *   than a second place a network can be defined.
 *
 * THE CREDENTIAL, WHICH IS THE WHOLE OF THIS MODULE'S RISK
 *   hostapd has no indirection for a passphrase: the generated configuration
 *   carries it in the clear. Three things follow, and all three are checked:
 *
 *   * **The passphrase arrives as an argument**, already resolved, rather than
 *     through a resolver this module holds. That is what keeps the rendering
 *     testable without fixtures -- a check that WPA3 spells its key management
 *     `SAE` should not have to lay out a secrets directory.
 *   * **It goes into the file exactly as the operator wrote it**, and nothing
 *     else does. `wpa_passphrase` and `sae_password` are the only lines marked
 *     sensitive, hostapd takes the rest of the line verbatim after the first
 *     `=`, and a value carrying a newline or a NUL is refused rather than
 *     written -- because those two end the line and hostapd would read a
 *     *different* passphrase, or a stray key, without either end noticing.
 *   * **It reaches no diagnostic at all.** `ncfg_hostapd_to_redacted` is what a
 *     log or an `ncfg plan` prints; the refusals below name lengths, bands and
 *     block ids and never a value.
 *
 * WHAT THIS BUILD DOES NOT CARRY YET
 *   `stop`, the live access-control convergence (0041) and the station walk
 *   (0040) all speak hostapd's `wpa_ctrl` control socket, and that client is
 *   the supplicant module's. **The parsers for both are here** --
 *   `ncfg_hostapd_parse_acl_show` and `ncfg_hostapd_parse_station` -- because
 *   they are pure and they are where the reply format was got wrong twice; what
 *   is missing is the round trip that carries a reply to them.
 *
 * WHERE THE BAND RULE LIVES, WHICH IS NOT SETTLED
 *   The Rust keeps `effective_band` and `channel_in_band` in `netcfgd-model`
 *   and says why in as many words (0222): the planner has to reach the same
 *   answer as the renderer and must not depend on a backend crate to do it,
 *   because an access point whose document and running configuration disagree
 *   about the band gets restarted -- so two copies of this rule is an access
 *   point that restarts for ever. The C model has not ported them. They are
 *   public here rather than private so that there is still exactly one
 *   implementation for both callers, and **they move to the model when it
 *   grows them**; a second copy appearing in the model is the failure this
 *   paragraph exists to prevent.
 */
#ifndef NCFG_HOSTAPD_H
#define NCFG_HOSTAPD_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "ncfg/document.h"
#include "ncfg/observed.h"
#include "ncfg/secrets.h"

/* Long enough for a run directory, a subdirectory and `<device>.conf`. */
#define NCFG_HOSTAPD_PATH_MAX 512

/*
 * Something the document asks for that this build cannot render.
 *
 * A code beside the sentence, because the sentence is for an operator and the
 * code is for a check: the Rust's cases compare an enum variant, and a port
 * that could only compare prose would pass against a refusal that names the
 * wrong thing in the right words.
 *
 * `NonUtf8CtrlDir` has no counterpart. A path in C is bytes and goes into the
 * file as bytes, so the question the Rust had to ask does not arise.
 */
typedef enum {
	NCFG_HOSTAPD_OK,
	/* `security { eap }` on an access point. An access point using EAP
	 * authenticates against a RADIUS server and the document has no field for
	 * one -- an `eap` block on an `access_point` describes a *client's*
	 * credentials, which is the wrong end of the exchange. */
	NCFG_HOSTAPD_ENTERPRISE_NEEDS_RADIUS,
	NCFG_HOSTAPD_MISSING_PASSPHRASE,
	/* Outside the 8..=63 range `wpa_passphrase` accepts. **The field's range
	 * and not WPA's** (0205): an access point that writes only `sae_password`
	 * has no such limit and is not checked against it. */
	NCFG_HOSTAPD_PASSPHRASE_LENGTH,
	NCFG_HOSTAPD_PASSPHRASE_NOT_WRITABLE,
	NCFG_HOSTAPD_UNKNOWN_BAND,
	NCFG_HOSTAPD_SIX_GIGAHERTZ,
	NCFG_HOSTAPD_CHANNEL_NOT_IN_BAND,
	NCFG_HOSTAPD_MALFORMED_REGDOM
} ncfg_hostapd_unsupported_t;

/*
 * One `key=value` line of the file.
 *
 * **Sensitivity is per line rather than per file.** An operator debugging an
 * access point wants to see `hw_mode` and `channel`, and a blanket "the
 * configuration contains a secret, so here is nothing" is how people end up
 * reading the real file with `cat` instead.
 */
typedef struct {
	char *key;   /* `ssid2`, `wpa_key_mgmt`, ... */
	char *value; /* exactly as it goes in the file */
	int   sensitive;
} ncfg_hostapd_line_t;

typedef struct {
	ncfg_hostapd_line_t *at;
	size_t               count;
	size_t               capacity;
} ncfg_hostapd_lines_t;

void ncfg_hostapd_lines_free(ncfg_hostapd_lines_t *lines);

/* The value of one key, or NULL. For a caller reading back what it rendered. */
const char *ncfg_hostapd_value_of(const ncfg_hostapd_lines_t *lines, const char *key);

/*
 * Render one access point.
 *
 * `passphrase` is the already-resolved secret, or NULL for a network that needs
 * none. `ctrl_dir` is where the control sockets and the station list live, and
 * is a parameter for the same reason the run directory is.
 *
 * 0 with the code in `*why` (which may be NULL) and a sentence in `err`. The
 * sentence never carries the passphrase -- a length is said, a value is not.
 */
int ncfg_hostapd_config(const ncfg_access_point_t *access_point, const char *ctrl_dir,
    const char *passphrase, ncfg_hostapd_lines_t *out, ncfg_hostapd_unsupported_t *why, char *err,
    size_t err_size);

/* The file, with secrets in it. **Never log this.** */
char *ncfg_hostapd_to_file(const char *id, const ncfg_hostapd_lines_t *lines, char *err,
    size_t err_size);

/* The file as it is safe to print: every sensitive value replaced, everything
 * else kept. */
char *ncfg_hostapd_to_redacted(const char *id, const ncfg_hostapd_lines_t *lines, char *err,
    size_t err_size);

/*
 * The station list as hostapd reads it, with the policy recorded above it.
 *
 * One address per line. hostapd accepts an optional VLAN id after the address,
 * which nothing here writes: putting a station on a VLAN is an `interface`
 * question and the document says it there.
 *
 * **The first line is the record 0041 needs.** `macaddr_acl` is not readable
 * over the control socket -- `GET_CONFIG` reports the SSID, the BSSID and the
 * ciphers and says nothing about it -- so without a record netcfgd could
 * converge the lists of a running access point without knowing which one it
 * reads, and an operator who flipped `deny` to `allow` would get an open
 * network reported as converged.
 *
 * It is a comment because `hostapd_config_read_maclist` skips a line whose
 * *first byte* is `#`, at column zero with no leading whitespace allowed. It is
 * short for a second reason from the same function: it reads with `fgets` into
 * a 128-byte buffer, so a longer line would arrive split, and the tail of a
 * comment is not a comment -- it would be parsed as an address, fail, and take
 * the access point down at startup.
 */
char *ncfg_hostapd_acl_contents(const ncfg_access_control_t *access_control, char *err,
    size_t err_size);

/*
 * Which policy a written station list records, if it records one.
 *
 * 0 for a file written before this record existed, and for one written by
 * something that is not netcfgd. Both mean "netcfgd does not know which list
 * this hostapd reads", which is a state the planner has to be able to say out
 * loud rather than guess at.
 */
int ncfg_hostapd_policy_in(const char *contents, int *policy_out);

/*
 * The band a `hw_mode` came from, as the document spells it.
 *
 * NULL for anything this build does not render, which is the honest answer
 * rather than a guess: a file with a mode netcfgd never writes was not written
 * by this netcfgd.
 */
const char *ncfg_hostapd_band_of_hw_mode(const char *hw_mode);

/*
 * Which band an access point will actually be brought up in, as the document
 * spells it -- `"2.4"`, `"5"`, or NULL for one this build cannot render.
 *
 * `band` decides when it is stated. When it is not, the channel decides, and
 * the split is at 14: 1..=14 is 2.4 GHz and nothing else, while the numbers
 * above belong to 5 GHz. An access point that states neither is 2.4 GHz, which
 * every radio has and which automatic channel selection can then choose within.
 *
 * See the header comment for why this is public.
 */
const char *ncfg_hostapd_effective_band(const char *band, const ncfg_optint_t *channel);

/*
 * Whether a channel number exists in a band at all.
 *
 * The 5 GHz list is a range rather than the exact set because which of those
 * channels are usable is a regulatory question the kernel answers, not a
 * spelling question this can answer -- 149 is legal in one country and not in
 * the next. What this rejects is a number that is in no band, which is a typo
 * rather than a regulatory refusal. Channel 0 is in no band: it is hostapd's
 * spelling of "survey and choose", which netcfgd writes from an *absent*
 * channel.
 */
int ncfg_hostapd_channel_in_band(const char *band, int64_t channel);

/* ------------------------------------------------------------- the files */

/*
 * The five paths one access point has, under `<run>/hostapd/`.
 *
 * Under netcfgd's own run directory rather than `/run/hostapd`, because a
 * socket in the distribution's location would be found by that distribution's
 * `hostapd_cli` and its init script, which would then be talking to an access
 * point netcfgd owns.
 */
int ncfg_hostapd_ctrl_dir(const char *run, char *out, size_t out_size, char *err,
    size_t err_size);
int ncfg_hostapd_config_path(const char *run, const char *device, char *out, size_t out_size,
    char *err, size_t err_size);
int ncfg_hostapd_acl_path(const char *run, const char *device, char *out, size_t out_size,
    char *err, size_t err_size);
int ncfg_hostapd_log_path(const char *run, const char *device, char *out, size_t out_size,
    char *err, size_t err_size);
/*
 * Where the access point on this device records its pid.
 *
 * netcfgd chooses the path and passes it as `-P`, which is what makes it a
 * usable marker: it names the interface and it lands in hostapd's command line,
 * so `/proc/<pid>/cmdline` can confirm that the pid belongs to *this* access
 * point rather than to whatever recycled the number (0080).
 */
int ncfg_hostapd_pid_path(const char *run, const char *device, char *out, size_t out_size,
    char *err, size_t err_size);

/*
 * Write the configuration for one access point, and say where it went.
 *
 * **Mode 0600, set on the open handle before a byte is written**, because the
 * file holds the passphrase in the clear. `open(2)`'s mode applies only when
 * the call creates the file, so rewriting one that already exists keeps
 * whatever mode it had -- measured: a file left at 0644 stayed 0644 through
 * exactly this call, and the passphrase went into it. The run directory
 * survives a restart by design, so "it cannot already exist" is not true
 * either.
 *
 * The station list is written *before* the configuration that names it:
 * hostapd refuses to start when `deny_mac_file` points at nothing, so a run
 * where this failed silently would take the access point down rather than leave
 * the list unenforced.
 */
int ncfg_hostapd_write_config(const char *run, const ncfg_access_point_t *access_point,
    const ncfg_secret_resolver_t *resolver, char *path_out, size_t path_size, char *err,
    size_t err_size);

/*
 * Write the station list, or remove it when the document asks for none.
 *
 * Mode 0644 rather than the configuration's 0600: this holds no secret, and a
 * list of MAC addresses that only root can read is a list nobody debugging an
 * access point can read either.
 *
 * **A block that was there and is not any more removes the file.** Leaving it
 * would leave a list that nothing reads, which is worse than no file: the next
 * person to look would find an ACL and believe it.
 */
int ncfg_hostapd_write_acl(const char *run, const ncfg_access_point_t *access_point, char *err,
    size_t err_size);

/*
 * Which policy the access point on this device was started with.
 *
 * Three answers, because the two ways of finding no policy mean opposite
 * things: **no file** is `UNSET`, since `ncfg_hostapd_write_acl` removes it when
 * the document carries no `access_control` block; **a file with no record** is
 * `UNKNOWN`, written by a netcfgd from before this existed; and a file with a
 * record is that policy. **Present and unreadable is `UNKNOWN` too** -- a file
 * netcfgd cannot open says nothing about what hostapd read out of it, and
 * reporting `UNSET` would have the planner restart an access point over a
 * permissions problem.
 *
 * This is only the truth about a *running* hostapd: the file is written by the
 * start and by nothing else, so once the process has exited it is a leftover.
 */
void ncfg_hostapd_recorded_policy(const char *run, const char *device,
    ncfg_observed_policy_t *out);

/*
 * How hostapd is invoked, as a list something can assert against.
 *
 * A function rather than four appends for the reason `udhcpc_start_args` is one
 * (0108): an argument list nothing can read back is one a rewrite can quietly
 * drop a flag from, and both flags here are load-bearing in ways no compiler
 * notices.
 *
 * `-B` daemonizes, which is what makes the exit status mean "hostapd started"
 * rather than "hostapd was launched" -- it forks only after the interface is
 * up, so a configuration it will not parse and a driver it cannot attach to
 * both come back as a failure rather than as a daemon that dies later.
 *
 * `-P` names the pid file, and without it an access point is the one backend
 * netcfgd can never tell has died: the liveness pass (0078) needs a handle, and
 * the recorded `running: true` would otherwise be the only account of a daemon
 * that crashed an hour ago -- so 0079's restart could not fire for it either
 * (0110).
 *
 * The order is hostapd's own usage, which puts the flags before the
 * configuration file.
 *
 * Writes at most `out_size` pointers, NULL-terminated, and returns how many
 * arguments were written excluding the terminator -- or 0 where they would not
 * fit. `argv[0]` is the program.
 */
size_t ncfg_hostapd_start_args(const char *program, const char *pid_path, const char *config_path,
    const char **out, size_t out_size);

/*
 * Start an access point.
 *
 * `program` is the hostapd to run; NULL searches `/usr/sbin` first, then
 * `PATH`. A caller that passes a path is why a check can exercise the whole
 * start without a radio and without hostapd installed.
 *
 * 0 with a message naming what failed: no hostapd installed, a document this
 * build cannot render, or hostapd refusing to start -- quoting the lines it
 * wrote rather than its exit status, because "unknown configuration item" and
 * "nl80211 driver initialization failed" send the operator to different places
 * and the *tail* of a failed start is neither of them.
 */
int ncfg_hostapd_start(const char *run, const ncfg_access_point_t *access_point,
    const ncfg_secret_resolver_t *resolver, const char *program, char *err, size_t err_size);

/* Find `hostapd`, `/usr/sbin` first. Allocated, or NULL. */
char *ncfg_hostapd_binary(void);

/* ------------------------------------------- what the control socket says */

/*
 * Parse a `DENY_ACL SHOW` or `ACCEPT_ACL SHOW` reply into the observation.
 *
 * `hostapd_ctrl_iface_acl_show_mac` prints one entry per line as
 * `MACSTR " VLAN_ID=%d"`, so the address arrives in exactly the normalised
 * form. **It is normalised anyway rather than trusted**: this is one daemon
 * reading another's output, the comparison it feeds decides whether a station
 * is denied, and a mismatched case would silently re-add an address that is
 * already there on every reconcile.
 *
 * Sorted and deduplicated, so that comparing against the document's stations --
 * which the compiler sorts and deduplicates (0039) -- is a comparison of two
 * lists rather than of two sets pretending to be lists. Without it a plan would
 * differ on ordering alone and never converge.
 *
 * An empty list is an empty reply: the printer returns zero bytes when there is
 * nothing to print, so "denies nobody" and "nothing to say" are one answer.
 *
 * The VLAN suffix is dropped. netcfgd never writes one (0039), so the only
 * value it can see is hostapd's default of 0, and carrying a field the document
 * cannot express would be state nothing could ever reconcile.
 */
int ncfg_hostapd_parse_acl_show(const char *reply, char ***out, size_t *count_out, char *err,
    size_t err_size);

void ncfg_hostapd_stations_free(char **stations, size_t count);

/*
 * One associated station, as hostapd reports it.
 *
 * **Every field but the address is optional because hostapd genuinely omits
 * them.** `hostapd_get_sta_info` writes nothing at all when
 * `hostapd_drv_read_sta_data` fails, so a station with no `signal=`, no
 * `rx_bytes=` and no `connected_time=` is a normal reply and not a malformed
 * one -- a parser that required `signal=` would drop a client that is really
 * there, which is the worst way for this feature to be wrong.
 */
typedef struct {
	char          address[18]; /* normalised the way an `access_control` list is */
	int           authorized;  /* finished authenticating, not merely associated */
	ncfg_optint_t signal_dbm;  /* closer to zero is stronger */
	ncfg_optint_t connected_seconds;
	ncfg_optint_t inactive_msec;
	ncfg_optint_t rx_bytes;
	ncfg_optint_t tx_bytes;
} ncfg_hostapd_station_t;

/*
 * One station's MIB block, or 0 at the end of the walk.
 *
 * **The walk ends on an empty reply.** `hostapd_ctrl_iface_sta_mib` returns
 * zero bytes for a null station, so `STA-FIRST` with nobody associated and
 * `STA-NEXT <last>` at the end of the list are the same answer -- and so is
 * `FAIL`, which is what hostapd answers for an address it does not know.
 * Neither is an error worth showing somebody.
 */
int ncfg_hostapd_parse_station(const char *reply, ncfg_hostapd_station_t *out);

/*
 * Parse and normalise one station address into `out`, which holds at least 18
 * bytes.
 *
 * Accepts the two spellings people actually write -- `aa:bb:cc:dd:ee:ff` and
 * `aa-bb-cc-dd-ee-ff`, in either case -- and produces the lowercase colon form,
 * which is what hostapd prints and therefore what a comparison against its live
 * list has to be in. **Bare `aabbccddeeff` is refused**: it is one transposition
 * away from being unreadable, and an ACL is the wrong place to guess.
 */
int ncfg_hostapd_normalize_station(const char *text, char *out, size_t out_size, char *err,
    size_t err_size);

#endif /* NCFG_HOSTAPD_H */
