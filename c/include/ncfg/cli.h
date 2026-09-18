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
 *   0263 puts `cli` last because it depends on everything. Two of the things
 *   it depends on are not ported yet -- the loader that turns `/etc/netcfgd`
 *   into a source set, and the observer that turns netlink into an
 *   `ncfg_observed_t` -- so the verbs that begin with a local compile or a
 *   local observation (`status`, `plan`, `show`, `apply`, `explain`,
 *   `control`, `config`, `profile`, `secret`, `reset`, `wait-online`, `wifi
 *   add`, `wifi forget`) have no source to read from and are not wired.
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
 *   * **`--json` is not in this wave.** The Rust hands `serde_json` the typed
 *     value; the C has a writer for a document, an observation and a plan and
 *     none for a protocol response. A verb given `--json` refuses and says so.
 *     Printing the human form while accepting the flag would be the fault the
 *     unknown-option arm exists to prevent, one level up.
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

#include "ncfg/document.h"
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
 * `ncfg show`: the compiled document, canonically, where `cat` can reach it.
 *
 * Returns 1, or 0 with a sentence in `err`. **Canonicalises in place**, for
 * document.h's reason: there is no caller who wanted the unsorted order back.
 */
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

/* ------------------------------------------------------------------------ *
 * The program
 * ------------------------------------------------------------------------ */

/*
 * `ncfg`, from `argv`.
 *
 * The entry point a multi-call `main` calls rather than the runtime: both
 * programs live in one binary that dispatches on `argv[0]`, because they share
 * most of their code and shipping it twice cost 775 KB of the install.
 *
 * Returns the process's exit code. It may not return at all: a write whose
 * reader has gone leaves at 141 (0261).
 */
int ncfg_cli_main(int argc, char **argv);

#endif /* NCFG_CLI_H */
