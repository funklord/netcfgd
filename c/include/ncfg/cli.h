/*
 * cli.h -- `ncfg`: read the config, see what would change, change it.
 *
 * WHY THE ARGUMENT PARSING IS HAND-WRITTEN
 *   It is hand-written in the Rust and stays hand-written here, for the reason
 *   `netcfgd-cli`'s own header gives: `clap` is excellent and would be several
 *   hundred kilobytes against a 400 KB nano budget, for a command set this
 *   small. Section 6's size gate is the kind of constraint that has to bind on
 *   the first binary or it never binds at all -- and a C port that reached for
 *   a parser library would be spending the budget the Rust refused to spend.
 *
 * WHY THE RENDERERS ARE THE PUBLIC FACE
 *   **The output is the product.** `ncfg status` is what an operator reads at
 *   the moment something is wrong, and its wording, its columns and what it
 *   leaves out are decisions recorded in the Rust's comments rather than
 *   incidental formatting. So each one is a function with a name, callable
 *   from a test against a fixture -- which is the only way to assert the exact
 *   lines without a daemon, a kernel and somebody's real network.
 *
 * WHERE THIS PRINTS
 *   Every line goes through `ncfg_out_*` (log.h, decision 0261). A write whose
 *   reader has gone ends the process quietly at 141 rather than printing a
 *   crash report at somebody who ran `ncfg status | head -1`. **That makes
 *   these functions program code rather than library code**, even though they
 *   live in `libncfg.a`: they are `ncfg`'s own, they may end the process, and
 *   nothing else in this library may call them. log.h says which half is
 *   which.
 *
 * WHAT IS IN THIS WAVE AND WHAT IS NOT
 *   0263 puts `cli` last because it depends on everything. The loader and the
 *   observer that the verbs beginning with a local compile or a local
 *   observation are built on have landed since, and so has the `network` block
 *   writer the last three were waiting for: `ncfg wifi add`, `ncfg wifi forget`
 *   and `ncfg reset` are wired. What is left unwired is named at its own arm in
 *   `run.c` rather than in a list here, because a list of absences in a header
 *   is the thing that goes on saying a module is missing after it lands.
 *
 *   **Their output is still ported and still tested**, because the output is
 *   the part that is expensive to rediscover: `ncfg_cli_print_status`,
 *   `ncfg_cli_print_plan` and `ncfg_cli_print_document` render exactly what
 *   the Rust renders, driven from `doc/schema/`'s witnesses. A verb whose
 *   source module is missing says so and names the module, rather than
 *   printing a plausible answer from somewhere else -- reading the last
 *   observation out of `/run` would have made `ncfg status` answer with what
 *   was true when something else last ran, which is the one thing a status
 *   command must not do.
 *
 * WHERE THE C DIVERGES FROM THE RUST, DELIBERATELY
 *   * **`--json` prints the payload and never the response envelope**, where
 *     the Rust prints whatever `serde_json` makes of the value it happens to
 *     hold -- an object for a scan, a bare array for the radios and the
 *     modems, and nothing at all for the verbs that answer `ok`. One rule
 *     here: the answer's own object, compact, on one line. *The same answers,
 *     as JSON* below says where each member name comes from and why the tag
 *     is not among them.
 *   * **A repeatable option has a ceiling** (`NCFG_CLI_LIST_MAX`). Rust grows
 *     a `Vec`; a C parser that did would be allocating on a command line, and
 *     0263's buffer rule is that text with no ceiling is text a caller chooses
 *     the size of. The refusal names the flag and the bound.
 *   * **Nothing the parser produces is owned.** Every string points into
 *     `argv`, which outlives the parse, so there is no free to forget and no
 *     copy that can disagree with what was typed.
 *   * **The version and the copyright line are constants here.** The Rust
 *     reads them from `CARGO_PKG_VERSION` and `netcfgd_model::COPYRIGHT` so
 *     that the CLI and the daemon cannot come to disagree about a fact neither
 *     owns. The C port has no shared constant module yet, so they are named
 *     once, here, and the test asserts the shape rather than restating it.
 */
#ifndef NCFG_CLI_H
#define NCFG_CLI_H

#include "ncfg/apply.h"
#include "ncfg/document.h"
#include "ncfg/explain.h"
#include "ncfg/observed.h"
#include "ncfg/plan.h"
#include "ncfg/proto.h"

#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------------ *
 * What the program leaves with
 * ------------------------------------------------------------------------ */

/*
 * The exit codes the usage text promises, by name.
 *
 * Four rather than two, and the last two are the point: a script that saw a
 * guard's refusal as success would report convergence over the very change
 * that did not happen. `NCFG_CLI_EXIT_USAGE` is the fifth and is not in that
 * list, because `ncfg` with no arguments printing its usage is not a run of
 * anything.
 */
#define NCFG_CLI_EXIT_OK        0
#define NCFG_CLI_EXIT_FAILED    1
#define NCFG_CLI_EXIT_USAGE     2
#define NCFG_CLI_EXIT_REFUSED   3
#define NCFG_CLI_EXIT_STRANDED  4

/*
 * The version, and who holds the copyright.
 *
 * One of the three surfaces `harmonization.md` names for the holder, and the
 * first place a person looks. A version string is the kind of thing that is
 * edited for an unrelated reason and quietly loses a line, so the test asserts
 * that this one is recognisable as a copyright notice and carries a name and
 * an address -- rather than restating the string and agreeing with itself.
 */
#define NCFG_CLI_VERSION   "0.1.0"
#define NCFG_CLI_COPYRIGHT "Copyright (C) 2026 Nabeel Sowan <nabeel@vibes.se>"

/* ------------------------------------------------------------------------ *
 * The options
 * ------------------------------------------------------------------------ */

/*
 * How many times one repeatable option may be given.
 *
 * `--allow-disruption`, `--restart-wedged` and `--strand-credentials` each
 * name one interface and are repeated for several. A machine with more than
 * this many interfaces in one disruptive apply is not a case anybody has met;
 * a parser that allocated per flag on a command line is a case this project
 * refuses on principle. Exceeding it is an error naming the flag, never a
 * silent truncation -- a consent flag quietly dropped is consent nobody gave.
 */
#define NCFG_CLI_LIST_MAX 32

/*
 * `wifi add` only, and named for what the fields mean in the config file they
 * write rather than for the flag that set them.
 *
 * `proto` is the PSK generation a `--wpa2` or `--wpa3` pins, NULL for the
 * default which negotiates both. `eap` is one of the four methods and is
 * validated at the parse, not an hour later by the compiler: "unknown wifi
 * key" arriving after the network has been written is not the same sentence as
 * "`{other}` is not an EAP method".
 */
typedef struct {
	const char   *id;
	const char   *proto;
	const char   *eap;
	const char   *identity;
	const char   *anonymous_identity;
	const char   *ca_cert;
	const char   *client_cert;
	const char   *phase2;
	const char   *interface;
	int           open;
	int           hidden;
	ncfg_optint_t metric;
} ncfg_cli_wifi_t;

/*
 * What `ncfg control set` was asked to change.
 *
 * What is not named here is left alone, so a tier nobody mentioned keeps
 * whatever it had. NULL is that "not named", which is why these are pointers
 * rather than strings with an empty default: `--observe ""` would be a
 * principal nobody can be.
 */
typedef struct {
	const char *observe;
	const char *wifi;
	const char *admin;
} ncfg_cli_control_t;

/* A repeatable option's values, pointing into `argv`. */
typedef struct {
	const char *items[NCFG_CLI_LIST_MAX];
	size_t      count;
} ncfg_cli_list_t;

/*
 * Everything the option walk found.
 *
 * Zeroed by the parser before it starts, so an option nobody gave is already
 * absent. Nothing here is allocated and nothing is freed: every string points
 * into the `argv` the caller passed, which outlives the parse.
 */
typedef struct {
	const char     *config_dir;
	/* Where to look for `/sys/class/net`, for tests. Undocumented in the
	 * usage on purpose: it exists so a test can supply a radio without
	 * depending on what the developer's machine contains, and there is no
	 * reason for a person to set it. */
	const char     *sys_class_net;
	const char     *factory_dir;
	int             yes;
	/* `secret set` and `profile save`: overwrite one that already exists. */
	int             replace;
	const char     *run_dir;
	int             json;
	ncfg_optint_t   confirm;
	ncfg_cli_list_t allow_disruption;
	/* Interfaces whose wedged backend may be killed and restarted (0141). */
	ncfg_cli_list_t restart_wedged;
	ncfg_cli_list_t strand_credentials;
	ncfg_cli_wifi_t wifi;
	ncfg_cli_control_t control;
} ncfg_cli_options_t;

/*
 * One pass over the arguments: the options, and what was not an option.
 *
 * **One walk, because there used to be three** -- this function, a
 * `positional` helper with its own list of which flags take a value, and
 * `explain`'s own scan for the first `--`. The lists had already drifted:
 * `--factory-dir` and `--strand-credentials` were missing from the helper's,
 * so `ncfg wifi --factory-dir /some/dir scan` read the directory as a
 * subcommand, and `ncfg explain --json interface eth0` found no subject at
 * all. A single walk cannot disagree with itself.
 *
 * `positional` must have room for `count` entries, which is the most there can
 * be; the caller sizes it from its own `argc` rather than this inventing a
 * bound. Returns 1, or 0 with a sentence in `err`.
 */
int ncfg_cli_parse(int count, char *const *arguments, ncfg_cli_options_t *options,
    const char **positional, size_t *positional_count, char *err, size_t err_size);

/* The usage text, exactly as `ncfg --help` prints it, with its final newline. */
const char *ncfg_cli_usage(void);

/* ------------------------------------------------------------------------ *
 * The rules every client of this daemon spells the same way
 * ------------------------------------------------------------------------ */

/*
 * How an access point is named on a screen.
 *
 * **Three cases and not two, because the daemon sends three.** A name that
 * arrived is the name. A name that arrived *empty* is a hidden network, which
 * is a fact worth saying rather than a blank cell. A name that did not arrive
 * at all means the SSID is not valid UTF-8 -- the daemon omits it rather than
 * mangling it -- and then the hex is the only honest name there is, shown with
 * a prefix that stops anybody reading the hex as the name.
 *
 * Here rather than at each call site because it was at each call site: `ncfg
 * wifi scan` said `hex:...` and nothing for hidden, the TUI said `<not text>`
 * for one and nothing for the other, and the GUI grew a third spelling. Losing
 * the hex was worse than untidy -- two unprintable SSIDs became the same row.
 *
 * `client/`'s `ncfg_access_point_display()` is the identical rule in C for the
 * GUI, and `make conformance` diffs the two. That comparison cannot say
 * whether the shared answer is *right*, because both were written from each
 * other; the test beside this one is the independent witness.
 *
 * `name` is NULL where the SSID is not text. Writes into `out` and returns it.
 */
const char *ncfg_cli_access_point_name(const char *name, const char *ssid, char *out,
    size_t out_size);

/*
 * The one word a scan row uses for an access point's security.
 *
 * **Four shapes, four words.** "secured" on a corporate network sends an
 * operator looking for a passphrase that does not exist, so 802.1X is named.
 * And an access point doing opportunistic wireless encryption asks for no
 * credential, so `secured` is false for it exactly as for an open network --
 * yet they are different networks to join, and an open profile against an OWE
 * access point does not associate (0227). The TUI groups its rows by this
 * word, so a word coarser than what is displayed merges two networks under a
 * heading that describes one of them.
 */
const char *ncfg_cli_access_point_security(int secured, int enterprise, int owe);

/*
 * Whether a link with this kind and name is a radio.
 *
 * **The kernel's word first and the name only as a fallback**, which is a
 * fallback and not an *or*. The two differ exactly where the kernel gave a
 * kind that is not `wlan`, and that is precisely where the name is least
 * trustworthy: a kind is empty for a plain device and holds a word only for a
 * virtual one, so a non-empty kind means the kernel has already answered. A
 * VLAN on a radio is named `wlan0.10` and a bridge may be named anything, so
 * the *or* called both of them radios -- and a client picking "the radio" from
 * a name-sorted list would show `wl-br0` where `wlan0` belonged.
 *
 * `kind` may be NULL or empty, which is what the kernel reports for a real
 * NIC.
 */
int ncfg_cli_is_radio(const char *kind, const char *name);

/*
 * Whether the machine is online, in the sense `network-online.target` means.
 *
 * **A global address and a default route**, which is what the other
 * wait-online helpers wait for and what the services ordered after that target
 * actually need: docker, a mail spool, a package refresh. Not "every interface
 * the document names", which would keep a laptop waiting for a dock it is not
 * plugged into. Loopback is excluded because it is always there, and a
 * link-local address is not being online -- it is what a machine has when DHCP
 * did not answer.
 */
int ncfg_cli_is_online(const ncfg_observed_t *observed);

/*
 * How long `ncfg wait-online` waits when nobody says.
 *
 * Thirty seconds, which is what `NetworkManager-wait-online.service` uses:
 * long enough for DHCP on a slow switch with spanning tree, short enough that
 * a machine with no network still finishes booting.
 *
 * **The usage text is pasted together from this rather than restating it**,
 * which is `daemon_main.c`'s rule for the daemon's defaults and is here for
 * the same reason: the Rust writes `30 by default` as literal text beside a
 * `DEFAULT_WAIT_ONLINE` that holds the same number, and the help is the copy
 * nobody recompiles. `NCFG_CLI_SPELL` is the two-step stringify every C
 * project writes once -- one step expands the macro, the second turns it into
 * a literal, and doing it in one gives the macro's own name. **Spelled
 * `SPELL` rather than `TEXT`** because this file already has two meanings for
 * that word -- `ncfg_cli_text` converts a counted protocol string and
 * `NCFG_CLI_TEXT_MAX` is how long one may be -- and a third is how a reader
 * comes to believe a stringify is a length.
 */
#define NCFG_CLI_SPELL_(value) #value
#define NCFG_CLI_SPELL(value) NCFG_CLI_SPELL_(value)
#define NCFG_CLI_WAIT_ONLINE_DEFAULT 30

/* A duration a person reads at a glance rather than a seconds count. */
const char *ncfg_cli_duration(int64_t seconds, char *out, size_t out_size);

/*
 * Bytes in the units the number is actually in.
 *
 * Integer arithmetic rather than a float divide: a byte counter is 64 bits and
 * casting one to a double loses precision above 2^53. One decimal place is all
 * this shows anyway.
 */
const char *ncfg_cli_bytes(int64_t count, char *out, size_t out_size);

/* ------------------------------------------------------------------------ *
 * The output an operator reads
 * ------------------------------------------------------------------------ */

/* `ncfg --help`, and what `ncfg` with no arguments prints before exiting 2. */
void ncfg_cli_print_usage(void);

/* `ncfg --version`: the version, then the copyright line. */
void ncfg_cli_print_version(void);

/*
 * `ncfg status`: every link, and what is on it.
 *
 * Per link: the state and the MTU, then the addresses with their ownership,
 * the bridge VLANs, the settings that are worth a line only when they are set,
 * whatever something outside netcfgd reported about the interface, and the
 * routes. Then the linksets, and the two notes that are about the machine
 * rather than about any one interface.
 */
void ncfg_cli_print_status(const ncfg_observed_t *observed);

/*
 * `ncfg plan`: the actions, then everything that is not an action.
 *
 * An empty plan says `nothing to do` and still prints its warnings, refusals
 * and strandings: a guard that dropped the only action leaves a plan that is
 * empty and is not "nothing to do" in the sense anybody means.
 */
void ncfg_cli_print_plan(const ncfg_plan_t *plan);

/*
 * What a plan says that is not an action: its refusals and its strandings.
 *
 * Printed under a plan by `ncfg_cli_print_plan` and under a *journal* by
 * `ncfg apply`, which is why it is published rather than left static. Both
 * need it in the same words: a guard that stopped an action is the same fact
 * whether or not the rest of the plan then ran.
 */
void ncfg_cli_print_plan_notes(const ncfg_plan_t *plan);

/*
 * `ncfg apply`: what each action became, in the order they were attempted.
 *
 * One line per record, marked `ok`, `FAIL` or `skip`, and a failure's sentence
 * indented under it -- the record has carried that all along, and a path that
 * dropped it left an operator with `FAIL hook.run` and no reason.
 */
void ncfg_cli_print_journal(const ncfg_journal_t *journal);

/*
 * `ncfg show`: the compiled document, canonically, where `cat` can reach it.
 *
 * Returns 1, or 0 with a sentence in `err`. **Canonicalises in place**, for
 * document.h's reason: there is no caller who wanted the unsorted order back.
 */
/*
 * A rendered JSON document on stdout, laid out for a person.
 *
 * Every `--json` verb prints through this. See the definition for why the
 * port's compact convention stops at the terminal, and why there is one
 * function rather than four call sites each deciding for itself.
 */
void ncfg_cli_out_json(const ncfg_buf_t *rendered);

int ncfg_cli_print_document(ncfg_document_t *document, char *err, size_t err_size);

/* What a scan found, strongest first, as the daemon ordered them. */
void ncfg_cli_print_scan(const ncfg_proto_scan_t *scan);

/* What one radio is doing, and what it has stopped trying. */
void ncfg_cli_print_wifi_status(const ncfg_proto_wifi_status_t *state);

/*
 * Who is on an access point.
 *
 * A station hostapd could not read statistics for still appears, with dashes
 * where the numbers would be. Hiding it would be the worst way for this to be
 * wrong: the whole point is knowing who is connected, and a client that is
 * there matters more than the signal strength that is not.
 */
void ncfg_cli_print_stations(const ncfg_proto_stations_t *report);

/* The radios, and what netcfgd is doing about each. */
void ncfg_cli_print_radios(const ncfg_proto_radio_t *radios, size_t count);

/* Which SIM source each modem is on, and whether it is still switching. */
void ncfg_cli_print_modems(const ncfg_proto_modem_t *modems, size_t count);

/*
 * One line per event on a monitor stream.
 *
 * `raw` is the line the event arrived on, printed whole for a kind this build
 * does not recognise -- a monitor that prints an event it does not know is
 * more useful than one that refuses to parse it.
 */
void ncfg_cli_print_event(const ncfg_proto_event_t *event, const char *raw, size_t raw_length);

/* ------------------------------------------------------------------------ *
 * The same answers, as JSON
 * ------------------------------------------------------------------------ *
 *
 * WHAT `--json` PRINTS, AND WHY IT IS NOT THE RESPONSE ENVELOPE
 *   One object per answer, compact, on one line, rendered into a buffer the
 *   caller prints -- a library never prints. What the object holds is the
 *   *payload*: the members the control socket carries beside its `"response"`
 *   tag, with the tag itself left off.
 *
 *   The tag is left off because three of the seven answers are computed here
 *   rather than received, and two of those already have their shapes frozen:
 *   `doc/schema/observed.json` is what `ncfg status --json` prints and
 *   `doc/schema/plan.json` is what `ncfg plan --json` prints, and neither
 *   witness carries a `"response"` member. Tagging the socket-answered verbs
 *   and not the local ones would be two rules for one flag; tagging all of
 *   them would put `ncfg status --json` at odds with the witness that pins
 *   the observation. So there is no envelope anywhere -- and every member
 *   name, every spelling and every omission below comes from
 *   `doc/schema/socket.json`, which `cli_test.c` reads back line by line.
 *
 *   **An optional member that is absent is absent, not null.** `name` is
 *   missing from a scan entry whose octets are not text, `stale` is missing
 *   from a scan that is fresh, and `cycle_pending` is missing from a modem
 *   that is not switching. Writing `null` instead would be a third answer on
 *   a socket that already has three, and the witness does not have one.
 *
 * WHAT HAPPENS TO A NAME THAT IS NOT VALID UTF-8
 *   The JSON writer refuses it rather than repairing it (0263), so each of
 *   these answers 0 with a sentence and leaves the buffer empty -- never half
 *   an answer that looks whole. It is reachable: the JSON *reader* does not
 *   check a string's bytes, so a stray octet inside a `name` or a `configured`
 *   travels from the daemon into a decoded answer intact, and `subject` comes
 *   straight off `argv`. The caller says so and prints nothing; the same
 *   command without `--json` still renders it, because the table is text for
 *   a terminal and this is a document for a program.
 */

/* What a scan found: `interface`, `access_points`, and `stale` when it is. */
int ncfg_cli_json_scan(const ncfg_proto_scan_t *scan, ncfg_buf_t *out, char *err,
    size_t err_size);

/* What one radio is doing, and what it has stopped trying. */
int ncfg_cli_json_wifi_status(const ncfg_proto_wifi_status_t *state, ncfg_buf_t *out, char *err,
    size_t err_size);

/* Who is on an access point, and which way the list reads. */
int ncfg_cli_json_stations(const ncfg_proto_stations_t *report, ncfg_buf_t *out, char *err,
    size_t err_size);

/*
 * The radios, and the modems: each wrapped in the object the socket wraps it
 * in rather than written as a bare array.
 *
 * The Rust prints `[...]` for these two and an object for the three above it,
 * which is a divergence recorded in 0263: a bare array cannot grow a fact
 * beside it, and `wifi_scan` already carries `stale` beside its list. One
 * shape for all five is also one thing for a caller to learn.
 */
int ncfg_cli_json_radios(const ncfg_proto_radio_t *radios, size_t count, ncfg_buf_t *out,
    char *err, size_t err_size);
int ncfg_cli_json_modems(const ncfg_proto_modem_t *modems, size_t count, ncfg_buf_t *out,
    char *err, size_t err_size);

/*
 * An explanation: `subject`, `facts`, and `total`.
 *
 * `total` is this port's, and 0263 records it: the socket's `explanation`
 * carries the facts and no count, because the Rust's `Explanation` has no
 * bound to report. This one does -- `NCFG_EXPLAIN_FACTS_MAX` -- and the text
 * form ends with "showing 256 of 1202" when it bites. A machine-readable form
 * that dropped the count would be the one place `--json` says less than the
 * table, which is the fault this flag exists to avoid. It is written always
 * rather than only when it bites, so that a reader compares it against the
 * length of `facts` instead of having to know the member is sometimes there.
 */
int ncfg_cli_json_explanation(const ncfg_explanation_t *explanation, ncfg_buf_t *out, char *err,
    size_t err_size);

/*
 * `{"ok":true}` -- the whole answer of a verb whose answer is that it worked.
 *
 * `{"response":"ok"}` carries nothing beside its tag, so the payload rule
 * above would make this `{}`, which tells a script nothing it did not already
 * know from the exit status. `ok` is the protocol's own word for this fact --
 * a `reloaded` event spells it exactly so -- and a verb that printed a
 * sentence under `--json` would be the flag silently ignored.
 */
int ncfg_cli_json_ok(ncfg_buf_t *out, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * The socket conversation
 * ------------------------------------------------------------------------ */

/*
 * Send one request and read one answer.
 *
 * **Why this is here and not `ncfg_client_request`.** `client/` already talks
 * to this daemon and is not duplicated: what it hands back is the GUI's model
 * of an answer, and `ncfg`'s output needs the protocol's -- a radio's
 * `blocked` sentence, the networks the supplicant has stopped trying, a
 * station list and the policy it is read under. None of those are in the GUI's
 * shapes, and rendering the CLI from a second reader of the same format is the
 * drift 0263 refuses outright. So the transport is a socket and the reader is
 * `proto.h`, which is the one reader.
 *
 * On success `out` holds a message the caller frees with
 * `ncfg_proto_message_free`. Returns 0 with a sentence in `err`, which for a
 * refusal that arrived *before* the request went out is the daemon's own
 * sentence rather than the kernel's word for a closed socket.
 */
int ncfg_cli_ask(const char *socket_path, const ncfg_proto_request_t *request,
    ncfg_proto_message_t *out, char *err, size_t err_size);

/*
 * Where the socket is, for a given run directory.
 *
 * Writes `<run_dir>/netcfgd.sock` into `out` and returns it, or NULL where it
 * would not fit.
 */
const char *ncfg_cli_socket_path(const char *run_dir, char *out, size_t out_size);

/*
 * One event as the line a monitor shows.
 *
 * The same five sentences `ncfg_cli_print_event` prints, composed into a
 * caller's buffer instead of stdout, because the TUI's event pane needs the
 * text and a pane may not print. `raw` is the line the event arrived on and is
 * used whole for a kind this build does not recognise -- a monitor that shows
 * an event it does not know is more useful than one that refuses to parse it.
 *
 * Writes into `out` and returns it. An event whose rendering carries a newline
 * -- `reloaded FAILED` is the one -- keeps it, and the caller decides what a
 * line is; the TUI folds it, since a pane row is a row.
 */
const char *ncfg_cli_event_text(const ncfg_proto_event_t *event, const char *raw,
    size_t raw_length, char *out, size_t out_size);

/* ------------------------------------------------------------------------ *
 * `ncfg tui`: the full-screen client
 * ------------------------------------------------------------------------ *
 *
 * WHAT DRAWS IT, AND WHY IT IS NOT ncurses
 *   The Rust binds ncurses through `netcfgd-sys::curses` behind a default-on
 *   cargo feature, which is the one thing `ncfg` links beyond libc. C has no
 *   feature gate here -- `c/Makefile` builds every source under `src/` into one
 *   archive -- so linking it would make ncurses a **mandatory** dependency of a
 *   binary that has none, and constraint 3 is one of the claims this project
 *   is trying to prove. So the escapes are written here: the subset section 7.2
 *   already promises and nothing more, and 0263's divergence list says what the
 *   subset does not do.
 *
 * WHAT IS PURE AND WHAT TOUCHES THE TERMINAL
 *   **Everything named below is a function of the answers and the keystrokes,
 *   and writes into an `ncfg_buf_t`.** A test that needs a terminal is a test
 *   that does not run, so `tui.c` has no syscall in it at all: the frame,
 *   escapes included, is composed into a buffer that a test reads. `tui_term.c`
 *   is the only file that opens a descriptor, and the only thing it adds is
 *   putting those bytes where a person can see them.
 */

/* Which pane is showing. `COUNT` is the bound an exhaustive walk uses, in
 * place of the `match` the Rust is checked for. */
typedef enum {
	NCFG_TUI_PANE_DEVICES = 0,
	NCFG_TUI_PANE_WIFI,
	NCFG_TUI_PANE_CLIENTS,
	NCFG_TUI_PANE_PLAN,
	NCFG_TUI_PANE_EVENTS,
	NCFG_TUI_PANE_COUNT
} ncfg_tui_pane_t;

/* The word on the tab bar, or NULL outside the set. */
const char *ncfg_tui_pane_title(ncfg_tui_pane_t pane);

/*
 * How many events to keep, and how long one may be.
 *
 * A screenful on a tall terminal, and bounded because this runs for days on a
 * server and the ring is in RAM. The per-line ceiling is `buf.h`'s rule in a
 * ring: the text came off a socket and its length is whoever is on the other
 * end's choice.
 */
#define NCFG_TUI_EVENT_HISTORY 200
#define NCFG_TUI_EVENT_MAX     512

/*
 * How many rows one pane may produce, and how wide a line may be.
 *
 * `NCFG_DIAGS_MAX`'s shape: the rows past the ceiling are counted rather than
 * pretended away, so `total` says how many there were. The Rust grows a `Vec`,
 * which is right in a renderer that cannot be handed a hostile answer and
 * wrong in one that reads a socket -- a scan in a block of flats is fifty
 * networks and nothing bounds what a daemon may send.
 */
#define NCFG_TUI_ROWS_MAX  256
#define NCFG_TUI_WIDTH_MAX 512

/*
 * The narrowest terminal this composes for.
 *
 * The Rust's `max(20)`: a window narrower than this gets lines fitted to 20
 * columns and lets the terminal wrap them, rather than arithmetic that
 * underflows on the way to a negative width.
 */
#define NCFG_TUI_WIDTH_MIN 20

/*
 * The width [`ncfg_tui_last_row`] counts rows at.
 *
 * Any value gives the same count -- `fit` truncates and pads and never wraps,
 * so a pane produces one line per thing it has to say whatever the terminal is
 * -- so this is the terminal everybody has rather than a number with meaning.
 */
#define NCFG_TUI_ROW_COUNT_WIDTH 80

/* An interface name, a `network` block's id, and the status line. */
#define NCFG_TUI_NAME_MAX    64
#define NCFG_TUI_MESSAGE_MAX 512

/*
 * What a line in a pane stands for.
 *
 * Two kinds and a nothing, because the wifi pane shows two: the radios netcfgd
 * could be given, and the networks it can see with the ones it has. `c` acts
 * on the selected **row** rather than on the pane -- activating a radio and
 * joining a network are the same intent ("use this one"), so making them the
 * same key is the honest arrangement rather than a shortcut.
 */
typedef enum {
	/* A heading, a blank, or an explanation. `c` does nothing. */
	NCFG_TUI_ROW_NOTHING = 0,
	/* A radio, by interface name, that `c` would activate. */
	NCFG_TUI_ROW_RADIO,
	/* A network, by its index in the scan, that `c` would join. */
	NCFG_TUI_ROW_NETWORK
} ncfg_tui_row_kind_t;

typedef struct {
	ncfg_tui_row_kind_t kind;
	char                interface[NCFG_TUI_NAME_MAX];
	size_t              entry;
} ncfg_tui_row_t;

/*
 * One pane's worth of lines, and what each line is about.
 *
 * The text is one `ncfg_buf_t` with the lines end to end, and the index is an
 * **offset** rather than a pointer because the buffer moves as it grows. A
 * buffer that failed hands out the empty string, so every line of a failed
 * render reads empty rather than pointing into freed memory -- which is the
 * same promise `ncfg_buf_text` makes and the reason it is worth making here.
 */
typedef struct {
	ncfg_buf_t     text;
	size_t         offsets[NCFG_TUI_ROWS_MAX];
	ncfg_tui_row_t rows[NCFG_TUI_ROWS_MAX];
	/* Lines kept, and lines there were. They differ only at the ceiling. */
	size_t         count;
	size_t         total;
} ncfg_tui_lines_t;

void ncfg_tui_lines_init(ncfg_tui_lines_t *lines);
void ncfg_tui_lines_free(ncfg_tui_lines_t *lines);

/* Line `at`, never NULL: the empty string past the end or on a failed buffer. */
const char *ncfg_tui_line(const ncfg_tui_lines_t *lines, size_t at);

/* What line `at` is about. Never NULL; a row past the end is `NOTHING`. */
const ncfg_tui_row_t *ncfg_tui_row(const ncfg_tui_lines_t *lines, size_t at);

/*
 * One answer from the daemon, kept for as long as the pane draws it.
 *
 * `present` rather than a NULL pointer because the message is held by value:
 * an answer nobody asked for yet, an answer that was a refusal, and an answer
 * that arrived are three states, and a refusal leaves its sentence on the
 * status line rather than a half-filled struct behind it.
 */
typedef struct {
	int                  present;
	ncfg_proto_message_t message;
} ncfg_tui_answer_t;

void ncfg_tui_answer_free(ncfg_tui_answer_t *answer);

/*
 * Everything drawn, refetched when a pane is entered or `r` is pressed.
 *
 * Fields are public because the panes are pure functions of them and a test
 * drives them directly -- which is the whole reason this shape exists.
 */
typedef struct {
	ncfg_tui_pane_t   pane;
	size_t            selected;
	/* The last error or confirmation, shown on the status line until the next
	 * action replaces it. */
	char              message[NCFG_TUI_MESSAGE_MAX];
	ncfg_tui_answer_t status;
	ncfg_tui_answer_t plan;
	ncfg_tui_answer_t scan;
	/* The radios this machine has, and what netcfgd is doing about each.
	 * Fetched with the scan rather than once at startup: a USB radio can be
	 * plugged in while the pane is open, and a list taken at startup would go
	 * on saying it is not there. */
	ncfg_tui_answer_t radios;
	ncfg_tui_answer_t stations;
	/* A ring, oldest at `event_first`. Each line is owned. */
	char             *events[NCFG_TUI_EVENT_HISTORY];
	size_t            event_first;
	size_t            event_count;
	/* Emphasis is reverse video, which every terminal back to a VT100 has.
	 * `$NO_COLOR` turns even that off, and this is that answer read once
	 * rather than an environment lookup inside a renderer. */
	int               no_color;
} ncfg_tui_t;

void ncfg_tui_init(ncfg_tui_t *tui);
void ncfg_tui_free(ncfg_tui_t *tui);

/*
 * Take a decoded message as the answer to a pane's question.
 *
 * A refusal is an answer: the daemon's sentence goes to the status line and
 * the pane keeps drawing whatever it had, which is the Rust's `fetch`. Returns
 * 1 where the answer was kept, 0 where it was a refusal or the wrong shape --
 * in both cases with the sentence already on `tui->message`.
 *
 * **It consumes the message either way**, and leaves it zeroed, so a caller
 * has nothing to free and no way to free something now owned here.
 */
int ncfg_tui_answer_take(ncfg_tui_t *tui, ncfg_tui_answer_t *answer,
    ncfg_proto_message_t *message);

/* The same, from the bytes of one response line. */
int ncfg_tui_answer_read(ncfg_tui_t *tui, ncfg_tui_answer_t *answer, const char *line,
    size_t length);

/* Add one line to the ring, dropping the oldest where it is full. */
void ncfg_tui_event_push(ncfg_tui_t *tui, const char *line);

/* Event `at`, oldest first. Never NULL. */
const char *ncfg_tui_event(const ncfg_tui_t *tui, size_t at);

/* ------------------------------------------- what the panes draw */

/* The tab bar, fitted to `width`. */
void ncfg_tui_tabs(const ncfg_tui_t *tui, size_t width, ncfg_buf_t *out);

/*
 * Whichever pane's content is showing, with what each line is about.
 *
 * `out` is initialised here rather than by the caller, so a list is never
 * filled twice without being freed; the caller frees it with
 * `ncfg_tui_lines_free` when it has read what it wanted.
 */
void ncfg_tui_body(const ncfg_tui_t *tui, size_t width, ncfg_tui_lines_t *out);

/*
 * The index of the last row the current pane draws.
 *
 * Asked of `ncfg_tui_body`, which is what the renderer draws, so the two
 * cannot disagree about how many rows there are -- the alternative is a second
 * count per pane, and five of those would drift the first time a pane grew a
 * heading.
 */
size_t ncfg_tui_last_row(const ncfg_tui_t *tui);

/*
 * The whole frame for a terminal of this size, escapes included.
 *
 * **A buffer rather than a descriptor, which is the point.** Everything a test
 * needs to know -- which row is highlighted, what each row says, that no row
 * is wider than the window -- is in these bytes, and nothing has to own a
 * terminal to read them. `tui_term.c` writes the result and adds nothing.
 */
void ncfg_tui_frame(const ncfg_tui_t *tui, size_t rows, size_t columns, ncfg_buf_t *out);

/* The footer, always on screen, and what `?` adds to it. */
const char *ncfg_tui_keys(void);
const char *ncfg_tui_help(void);

/* ------------------------------------------- what a keystroke means */

/*
 * The keys above 255, decoded from the bytes rather than from terminfo.
 *
 * Only the two that are bound. An escape sequence this does not know reads as
 * `OTHER` and does nothing, rather than being mapped to the wrong action --
 * which is the failure a hand-maintained table has and terminfo does not, and
 * the reason the set is kept to what is used.
 */
#define NCFG_TUI_KEY_OTHER 0x100
#define NCFG_TUI_KEY_UP    0x101
#define NCFG_TUI_KEY_DOWN  0x102

/*
 * Three outcomes, not two.
 *
 * `PARTIAL` is an escape sequence that has begun and not finished, and one
 * boolean cannot tell it from "there is nothing here". Folding them is how a
 * lone `ESC` either blocks for ever or eats the next keystroke.
 */
typedef enum {
	NCFG_TUI_INPUT_NONE = 0,
	NCFG_TUI_INPUT_READY,
	NCFG_TUI_INPUT_PARTIAL
} ncfg_tui_input_t;

/*
 * Decode the first key in `bytes`.
 *
 * `used_out` says how many bytes it took, so a burst is decoded one key at a
 * time from the same buffer. A `PARTIAL` consumes nothing and asks for more.
 */
ncfg_tui_input_t ncfg_tui_key_decode(const char *bytes, size_t length, int *key_out,
    size_t *used_out);

/*
 * What a key asks the caller to do, once the state machine has moved.
 *
 * **The Rust's `App::key` does the socket work itself**, which makes the
 * keymap untestable without a daemon. Here the keystroke moves the state and
 * names an intent, and `tui_term.c` is what talks -- so a test can assert what
 * every key does to every pane with no socket anywhere.
 */
typedef enum {
	/* Redraw and nothing else. */
	NCFG_TUI_ACT_NONE = 0,
	NCFG_TUI_ACT_QUIT,
	NCFG_TUI_ACT_REFRESH,
	NCFG_TUI_ACT_APPLY,
	NCFG_TUI_ACT_CONFIRM,
	NCFG_TUI_ACT_REVERT,
	/* `c`: activate the selected radio, or join the selected network. */
	NCFG_TUI_ACT_USE
} ncfg_tui_action_t;

ncfg_tui_action_t ncfg_tui_key(ncfg_tui_t *tui, int key);

/*
 * The first interface whose observed link looks like a radio.
 *
 * From the status answer rather than from the config, because the pane is
 * drawing what the machine has. Returns 1 with the name in `out`.
 */
int ncfg_tui_radio(const ncfg_tui_t *tui, char *out, size_t out_size);

typedef enum {
	NCFG_TUI_USE_NOTHING = 0,
	NCFG_TUI_USE_RADIO,
	NCFG_TUI_USE_NETWORK
} ncfg_tui_use_kind_t;

typedef struct {
	ncfg_tui_use_kind_t kind;
	/* The radio to hand over, or the radio to join on. */
	char                interface[NCFG_TUI_NAME_MAX];
	/* `NETWORK` only: the `network` block's id. */
	char                network[NCFG_TUI_NAME_MAX];
} ncfg_tui_use_t;

/*
 * What `c` would do to the selected line.
 *
 * **The selected *line* rather than the selected entry.** The wifi pane groups
 * radios under a network, so the nth line stopped being the nth scan entry;
 * indexing the entries by the line joins whatever network happens to sit at
 * that position, which is the worst kind of bug a list can have -- it does
 * something, confidently, to the wrong thing. `ncfg_tui_body` says what each
 * line stands for and this reads that.
 *
 * Returns 1 with a decision, which may be `NOTHING`. Returns 0 with a sentence
 * for the boundary a person should be told about rather than refused at:
 * decision 0013's, a network the configuration does not describe.
 */
int ncfg_tui_use(const ncfg_tui_t *tui, ncfg_tui_use_t *out, char *err, size_t err_size);

/*
 * `ncfg tui`, from the options: the terminal, the socket and the loop.
 *
 * Returns the process's exit code. Refuses before touching the terminal where
 * standard input is not one, and where the daemon cannot be reached -- a
 * machine with no daemon gets a sentence rather than a cleared screen and a
 * sentence.
 */
int ncfg_tui_run(const ncfg_cli_options_t *options);

/* ------------------------------------------------------------------------ *
 * The verbs that change the configuration
 * ------------------------------------------------------------------------ *
 *
 * WHY THEY RETURN 1 AND 0 RATHER THAN AN EXIT CODE
 *   The Rust's four `run` functions return `Result<ExitCode, String>`, and
 *   every `Ok` arm in all four is `ExitCode::SUCCESS` -- the code carries
 *   nothing the `Result` does not. So they are 0263's convention exactly: 1,
 *   or 0 with a sentence the dispatch prints as `ncfg: ...`. What they print
 *   on the way to succeeding goes through `ncfg_out_*` like every other
 *   output here.
 *
 * WHAT `positional` IS
 *   What was left after the option walk, with the verb itself already off the
 *   front: `ncfg profile save office` arrives as `{"save", "office"}`. Nothing
 *   in it is owned -- every string points into `argv`.
 *
 * THE ORDER EVERY ONE OF THEM TAKES
 *   **The daemon first, and the directory only when nothing is listening.**
 *   0127 makes netcfgd the only writer of `/etc/netcfgd`, which is root's and
 *   which a client is not; the local route is for the machine being configured
 *   before netcfgd runs on it. A write refused locally says both halves --
 *   what the filesystem said, *and* that there was no daemon to ask -- because
 *   a reader told only the first goes looking for a mode to change when
 *   starting netcfgd would have done.
 */

/* `ncfg control show|set`: who may ask netcfgd for what (0118). */
int ncfg_cli_control(const ncfg_cli_options_t *options, const char **positional, size_t count,
    char *err, size_t err_size);

/* `ncfg config put|rm`: configuration netcfgd stores on a client's behalf. */
int ncfg_cli_config(const ncfg_cli_options_t *options, const char **positional, size_t count,
    char *err, size_t err_size);

/* `ncfg profile get|list|set|save|unset`: which set of drop-ins (0151). */
int ncfg_cli_profile(const ncfg_cli_options_t *options, const char **positional, size_t count,
    char *err, size_t err_size);

/*
 * `ncfg wifi add SSID`: one `network` block and its credential.
 *
 * The same shape as the four above and for the same reason, although the verb
 * sits under `ncfg wifi`: it writes the configuration, so it takes the
 * daemon-then-directory route and answers a sentence rather than an exit
 * status. `positional` is what followed `add`.
 */
int ncfg_cli_wifi_add(const ncfg_cli_options_t *options, const char **positional, size_t count,
    char *err, size_t err_size);

/* `ncfg wifi forget ID`: the same write backwards, credential included. */
int ncfg_cli_wifi_forget(const ncfg_cli_options_t *options, const char **positional,
    size_t count, char *err, size_t err_size);

/*
 * `ncfg reset`: discard the writable configuration layer.
 *
 * **The one verb here that only removes**, and the only one that is not a
 * write in the sense above: there is no daemon route, because what gates it is
 * the filesystem -- the configuration directory is root's, and anybody who can
 * delete these files can edit them. It prints what it would do and does
 * nothing unless `--yes`.
 */
int ncfg_cli_reset(const ncfg_cli_options_t *options, const char **positional, size_t count,
    char *err, size_t err_size);

/* `ncfg secret set`: store a credential the configuration refers to (0075). */
int ncfg_cli_secret(const ncfg_cli_options_t *options, const char **positional, size_t count,
    char *err, size_t err_size);

/*
 * What arrived when something else was expected, in one phrase.
 *
 * "a journal", "a profile list", "an error: ...". **Here rather than at each
 * call site**, because a client that quietly treats an unexpected answer as
 * success is the bug this project keeps refusing to write, and the sentence
 * that says what did arrive is the one somebody reports.
 *
 * Writes into `out` where it needs to and returns either it or a literal, so
 * the result is always printable.
 */
const char *ncfg_cli_describe_answer(const ncfg_proto_response_t *response, char *out,
    size_t out_size);

/*
 * Where this invocation's daemon socket would be.
 *
 * `--run-dir`, then `NCFG_RUN_DIR`, then the default, and `netcfgd.sock` under
 * it. NULL where the run directory makes a path too long to connect to, which
 * is refused rather than truncated: a shortened unix address connects to a
 * different path that may well exist.
 */
const char *ncfg_cli_daemon_socket(const ncfg_cli_options_t *options, char *out, size_t out_size);

/*
 * Whether there is something at that path to talk to.
 *
 * **Existence, and not "is it a socket"**, which is the question the Rust asks
 * and the branch every write verb takes. A stale plain file at the path is
 * then a failed connection with a sentence naming it, rather than a silent
 * fall back to writing `/etc/netcfgd` directly -- which on a machine that
 * *does* run netcfgd is the one thing 0127 says a client must not do.
 */
int ncfg_cli_daemon_listening(const char *socket_path);

/*
 * One request whose whole answer is `ok`.
 *
 * **A refusal and a transport failure are one arm on purpose**: both are a
 * sentence naming what went wrong, and no caller does anything different for
 * having been told which layer produced it. A refusal arrives unwrapped,
 * because it names the tier that would have been needed (0013) and that is the
 * part which says what to do. Anything else is named with
 * `ncfg_cli_describe_answer`, since a client that quietly treats an unexpected
 * answer as success is the bug this project keeps refusing to write.
 */
int ncfg_cli_ask_ok(const char *socket_path, const ncfg_proto_request_t *request, char *err,
    size_t err_size);

/* ------------------------------------------------------------------------ *
 * The pieces of `ncfg control` that are worth asserting on their own
 * ------------------------------------------------------------------------ */

/*
 * `root`, `any`, `user:NAME` or `group:NAME`, and back again.
 *
 * Four shapes, deliberately, and no expression language: every authorisation
 * system that grew one did so a reasonable extension at a time and ended up as
 * something operators copy from forums without understanding.
 *
 * **These are the model's in the Rust and cannot be here.** `document.h` is
 * final and carries neither, and the two implementations that exist -- the
 * lowerer's and the renderer's -- are `static` inside modules whose context
 * this has none of. So the rule is spelled once, here, and `cli_control_test.c`
 * asserts the round trip against what a rendered configuration file says: a
 * third spelling of `group:NAME` is exactly the drift 0263 refuses.
 *
 * The parse fills a principal the caller zeroed and hands it a name the caller
 * frees; the render writes into `out` and returns it.
 */
int ncfg_cli_principal_parse(const char *text, ncfg_principal_t *out, char *err, size_t err_size);
const char *ncfg_cli_principal_render(const ncfg_principal_t *principal, char *out,
    size_t out_size);

/*
 * The drop-in `ncfg control set` writes when no file defines `global` yet.
 *
 * A comment saying what it is and how to be rid of it, then the block.
 * Deleting the file restores the default, which is root only -- so the text is
 * ordinary netcfgd configuration an operator can read, diff and commit.
 */
void ncfg_cli_control_render(const ncfg_control_t *control, ncfg_buf_t *out);

/*
 * The same policy put into the `global` block of a file that already has one.
 *
 * A drop-in cannot do this: section 3 makes `override global` replace the
 * block *whole*, so a policy written that way silently takes every other
 * global setting with it -- measured, and it turned a machine's DNS mode from
 * `write_resolv_conf` into `none`.
 *
 * Text in, text out, and nothing else touched: an existing `control` block is
 * replaced in place and a missing one is inserted before the closing brace,
 * with the indentation the file already uses. **The proof that this did not
 * eat anything is in the caller**, which compiles before and after and refuses
 * to keep a result that differs anywhere but the control policy -- which is
 * why this is a function with a name and a test rather than a step inside one.
 *
 * Initialises `out`, which the caller frees either way. Returns 1, or 0 with a
 * sentence.
 */
int ncfg_cli_control_splice(const char *text, const ncfg_control_t *control, ncfg_buf_t *out,
    char *err, size_t err_size);

/*
 * One line of the privileged helper's protocol, and the whole grammar it has.
 *
 * [0120]: the red frame around an editor is a claim that something on the
 * other side of a process boundary holds root. This parser is what is on the
 * other side, so what matters is not that `set` works -- it is that nothing
 * else does, and that a refusal happens before anything is written. That is a
 * claim about a parser and is asserted as one, which is why this is reachable
 * without starting a helper.
 *
 * `set observe wifi admin`, three principals, nothing else. Returns 1 with the
 * file it wrote in `path_out`, or 0 with a sentence and nothing written.
 */
int ncfg_cli_control_command(const char *line, const ncfg_cli_options_t *options, char *path_out,
    size_t path_size, char *err, size_t err_size);

/*
 * A credential from the terminal with echo off, or from a redirect whole.
 *
 * **A terminal gives one line; a redirect gives a file**, and taking the first
 * line of a redirect is the defect this carries a test for: `ncfg secret set
 * corp-ca < corp.pem` stored the twenty-seven bytes `-----BEGIN
 * CERTIFICATE-----` and nothing else, and the only symptom was an association
 * failing with nothing from netcfgd. One trailing line terminator is stripped
 * and no other whitespace is, because a passphrase may legitimately end in a
 * space.
 *
 * On a terminal the prompt goes to standard error, echo is off for exactly as
 * long as the read takes, and the termination signals are blocked for exactly
 * that long -- so `^C` arrives after the terminal is restored rather than
 * instead of it.
 *
 * `*out` is the caller's to free, and is worth wiping before it is freed.
 * Returns 1, or 0 with a sentence that never contains what was typed.
 */
int ncfg_cli_read_secret(const char *prompt, char **out, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * The program
 * ------------------------------------------------------------------------ */

/*
 * How `ncfg apply` reaches the machine.
 *
 * **A seam because opening one opens a netlink socket and using one
 * reconfigures the machine this process is running on.** Every other verb in
 * this program reads; this is the one that changes something, and the library
 * half of it must not be able to do that by itself. `src/main/` installs the
 * implementation, which is the daemon's own world -- the apply lock, the
 * kernel socket, the service context, the hooks and the document -- opened for
 * one pass instead of for a loop, so there is one arrangement of those pieces
 * rather than two.
 *
 * **A test installs a recorder instead, and that is the point rather than a
 * convenience.** A check that drove the real thing would reconfigure the
 * machine the suite is built on. With no seam at all `ncfg apply` refuses by
 * name, so a program that embeds this library and forgets to install one
 * cannot apply by accident either.
 *
 * `executor_open` is given both directories this run resolved and the document
 * and observation the plan was built from. An implementation needs all four:
 * the run directory to take the lock and record what it did, the configuration
 * directory because the secrets and certificates it resolves live under it --
 * a run pointed at a scratch tree must not load the machine's key material --
 * and the other two for the ops that are not netlink. 0 with a sentence where
 * the machine could not be reached, which `ncfg apply` reports rather than
 * half-applying.
 */
typedef struct {
	/* Whatever the implementation keeps. Never touched by this module. */
	void *context;
	int  (*executor_open)(void *context, const char *config_dir, const char *run_dir,
	    const ncfg_document_t *desired, const ncfg_observed_t *observed,
	    ncfg_executor_t *out, char *err, size_t err_size);
	/* Release what `executor_open` filled in, and the lock it took. */
	void (*executor_close)(void *context, ncfg_executor_t *executor);
} ncfg_cli_machine_t;

/*
 * `ncfg`, from `argv`, with a way to reach the machine.
 *
 * The entry point a multi-call `main` calls rather than the runtime: both
 * programs live in one binary that dispatches on `argv[0]`, because they share
 * most of their code and shipping it twice cost 775 KB of the install.
 *
 * `machine` may be NULL, and then every verb but `apply` behaves exactly as it
 * does with one -- which is what makes the seam safe to leave out of a test.
 *
 * Returns the process's exit code. It may not return at all: a write whose
 * reader has gone leaves at 141 (0261).
 */
int ncfg_cli_main_on(int argc, char **argv, const ncfg_cli_machine_t *machine);

/* The same, reaching nothing. `ncfg apply` refuses by name. */
int ncfg_cli_main(int argc, char **argv);

#endif /* NCFG_CLI_H */
