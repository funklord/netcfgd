/*
 * main_internal.h -- the three programs one image is, and what each leaves with.
 *
 * WHY A `main` IS NOT A LIBRARY, SAID OUT LOUD
 *   0263's third convention is that a library never exits, never asserts and
 *   never prints. Everything under `c/src/` obeys it and `libncfg.a` is built
 *   out of files that do -- which is only possible because *something* else
 *   decides what the process leaves with. That something is here. These four
 *   files are the one place in the port that calls `exit`, returns an exit
 *   status, and turns a sentence a module handed back into a line on a
 *   terminal; the asymmetry is deliberate and it is the whole reason
 *   `src/main/` is kept out of the archive (see `c/Makefile`'s SRCS).
 *
 *   The rule that survives is the other half of it: nothing here computes an
 *   answer. Each entry point parses a command line, calls into the library and
 *   renders what came back. A decision taken in this directory is a decision
 *   no test can reach, because a test cannot have two `main`s.
 *
 * WHY ONE IMAGE AND THREE NAMES
 *   `netcfgd` and `ncfg` share the model, the compiler, the planner, the
 *   executor and the netlink layer, which is nearly everything either of them
 *   is. Built as two binaries the Rust measured 775 KB duplicated between
 *   them against a 2.89 MB install, and merging them is most of what took the
 *   install to 1.75 MB (0024). So they are one file with two names, the way
 *   busybox does it: the binary is `netcfgd` and `ncfg` is a symlink to it.
 *
 *   The third name is never installed and is never a symlink. netcfgd execs
 *   its own image with `netcfgd-probe` in `argv[0]` to fetch a captive-portal
 *   check in a process that has given up every capability first, so the only
 *   way to arrive there is to be netcfgd -- and a hand-renamed copy resolves a
 *   URL and prints a status line with no privileges, which is what `curl`
 *   does. Decision 0162, and `portal.h` names the constant.
 *
 * WHERE THIS DIVERGES FROM THE RUST
 *   Each is in 0263's list with its reasoning; they are named here because
 *   this is the file a reader arrives at.
 *
 *     * `argv[0]` is made legible before it is printed back.
 *     * The name is the text after the last `/`, so a trailing slash resolves
 *       to no name at all rather than to the directory above it.
 *     * The version and the copyright are `cli.h`'s constants, read rather
 *       than restated.
 *     * `netcfgd` starts here and the assembly is `static`, so that no test in
 *       this tree can reach it.
 */
#ifndef NCFG_MAIN_INTERNAL_H
#define NCFG_MAIN_INTERNAL_H

#include "ncfg/document.h"

#include <stddef.h>

/* ------------------------------------------------------------------------ *
 * What a program leaves with
 * ------------------------------------------------------------------------ */

/*
 * The daemon's two, and the one the dispatcher owns.
 *
 * `ncfg`'s are `NCFG_CLI_EXIT_*` and are five; these are not those. The daemon
 * has never had more than "it ran" and "it would not start", because there is
 * no script reading a daemon's exit status for the shape of a refusal -- and
 * `NCFG_MAIN_EXIT_MISCALLED` is not the daemon's at all: it is the image
 * saying it does not know which of the three programs it was meant to be.
 */
#define NCFG_MAIN_EXIT_OK        0
#define NCFG_MAIN_EXIT_FAILED    1
#define NCFG_MAIN_EXIT_MISCALLED 2

/* ------------------------------------------------------------------------ *
 * Which program this is
 * ------------------------------------------------------------------------ */

/* The two names that are installed. The third is `portal.h`'s
 * `NCFG_PORTAL_HELPER_NAME`, which is not installed and is named where the
 * module that execs it can see the same constant. */
#define NCFG_MAIN_DAEMON_NAME "netcfgd"
#define NCFG_MAIN_CLIENT_NAME "ncfg"

/* How much of `argv[0]` is repeated back when it is neither name. A path
 * somebody chose, not a document: enough for `/usr/local/libexec/netcfgdd` to
 * arrive whole, and a refusal that names a ceiling rather than a wall of
 * somebody else's bytes. */
#define NCFG_MAIN_NAME_KEEP 96
#define NCFG_MAIN_NAME_MAX  (NCFG_MAIN_NAME_KEEP + 4)

typedef enum {
	/* Neither name. A build tree or a rename, and never a guess: guessing
	 * wrong starts a daemon for somebody who wanted a client. */
	NCFG_MAIN_PROGRAM_NONE = 0,
	NCFG_MAIN_PROGRAM_CLIENT,
	NCFG_MAIN_PROGRAM_DAEMON,
	NCFG_MAIN_PROGRAM_PROBE
} ncfg_main_program_t;

/*
 * `argv[0]` reduced to the text after its last `/`.
 *
 * A symlink invoked through `PATH` arrives as `ncfg`, one invoked by absolute
 * path as `/usr/bin/ncfg`, and one run from a build tree as `./c/ncfg`. NULL
 * and the empty string both answer the empty string, and so does a path ending
 * in `/` -- Rust's `file_name` answers the component above it there, which is
 * a directory being read as a program name, and answering nothing sends that
 * case to the arm that refuses rather than to one that acts.
 *
 * Points into `path`, which is `argv` and outlives everything here.
 */
const char *ncfg_main_basename(const char *path);

/* Which of the three a name asks for. Anything else is `NONE`. */
ncfg_main_program_t ncfg_main_program_for(const char *argv0);

/*
 * As much of a name as is safe to print back, into `out`.
 *
 * **`argv[0]` is chosen by whoever ran this**, and the refusal below repeats
 * it to a terminal. The Rust prints it raw; in C the same string is a fixed
 * array away from a byte that moves a cursor, clears a screen or sets a title,
 * and the one thing this program knows at that moment is that the name is
 * wrong. So: printable ASCII kept, everything else a dot,
 * `NCFG_MAIN_NAME_KEEP` characters and then an ellipsis. `out` is
 * `NCFG_MAIN_NAME_MAX` bytes and is always NUL-terminated.
 */
void ncfg_main_legible_name(const char *name, char *out, size_t out_size);

/*
 * Neither name: say what the two are, and leave.
 *
 * It says them rather than picking one, which is the Rust's arrangement and
 * the reason for it: this is a build tree or a rename, not an install, and a
 * wrong guess starts a network configuration daemon for somebody who typed a
 * client's name.
 */
int ncfg_main_miscalled(const char *called_as);

/* ------------------------------------------------------------------------ *
 * The programs
 * ------------------------------------------------------------------------ */

/*
 * `netcfgd`, from `argv`.
 *
 * Parses the command line, answers `--help` and `--version`, and then starts:
 * the state, the observation seam, the descriptors, the control socket, the
 * request dispatcher and the reconcile loop, in that order, until a signal
 * stops it. The assembly itself is `static` in `daemon_main.c` and has no
 * external name, which is what keeps it out of reach of a test -- see the
 * note above `ncfg_main_netcfgd_parse`.
 */
int ncfg_main_netcfgd(int argc, char **argv);

/*
 * The same, stopping before anything would be started.
 *
 * `main_test.c` calls this rather than the entry point above, and the reason
 * is a hazard rather than a preference: the tests run this program in their
 * own process, and the entry point now **starts a network configuration
 * daemon** -- it binds a control socket, takes the apply lock and begins
 * reconciling. Calling it from a test would do that inside `make check`, on
 * whoever's machine ran it.
 *
 * Two things keep that from happening and neither is a comment. The assembly
 * is `static`, so no test can name it; and the entry point is the only way to
 * reach it, so `main_test.c` reads its own source and refuses to contain a
 * call to that one symbol.
 *
 * `options_t` is this directory's own type, which is why this is here and not
 * in a public header: nothing outside `src/main/` has any business parsing
 * the daemon's command line.
 */
/*
 * What `netcfgd`'s command line parsed into.
 *
 * Here rather than in `daemon_main.c` because `main_test.c` holds one to drive
 * the parse without running the program -- see `ncfg_main_netcfgd_parse`.
 * Nothing here is owned: every string points into `argv`, which outlives the
 * parse, which is `options.c`'s rule for `ncfg` and holds for the same reason.
 */
typedef struct ncfg_main_options {
	const char *config_dir;
	const char *factory_dir;
	const char *run_dir;
	const char *socket;
	int         apply_on_start;
	int         poll_config;
} options_t;

int ncfg_main_netcfgd_parse(int argc, char **argv, struct ncfg_main_options *options, int *done,
    int *code);

/*
 * How long a path this program keeps.
 *
 * Four of them are directories somebody named on a command line or in the
 * environment, and one is a socket beside the run directory. Generous rather
 * than `PATH_MAX`, which is not a real bound on Linux and would put five
 * kilobytes on a stack for no reason.
 */
#define NCFG_MAIN_PATH_MAX 512

/*
 * Where this daemon reads, writes and listens, resolved once.
 *
 * **Once, at startup, rather than per use**, which is
 * `ncfg_observe_source_machine`'s rule applied to the rest of the program: a
 * daemon that re-read `$NCFG_CONFIG_DIR` on every reload would answer
 * differently depending on what had happened to the environment since it
 * started, and nothing would say so.
 */
typedef struct {
	char factory[NCFG_MAIN_PATH_MAX];
	char config[NCFG_MAIN_PATH_MAX];
	char run[NCFG_MAIN_PATH_MAX];
	char socket[NCFG_MAIN_PATH_MAX];
	/* Beside the socket, and bound only where the configuration opens remote
	 * access. See `ncfg_main_remote_is_open`. */
	char remote_socket[NCFG_MAIN_PATH_MAX];
	/* Where the `file` provider looks, which is `secrets.h`'s default spelled
	 * against this daemon's own configuration directory rather than against
	 * `/etc`. A daemon pointed at a scratch tree must not read the machine's
	 * real credentials. */
	char secrets[NCFG_MAIN_PATH_MAX];
	/* Where a stored certificate is materialised for a supplicant to open.
	 * `NULL` there means the resolver refuses rather than choosing, so this is
	 * resolved here or nothing 802.1X works. */
	char certs[NCFG_MAIN_PATH_MAX];
} ncfg_main_where_t;

/*
 * Resolve the four directories and the two socket paths from a command line.
 *
 * The explicit value, then the environment, then the default -- which is
 * `config.h`'s and `state.h`'s own order, called rather than restated. The
 * socket defaults to `netcfgd.sock` under the run directory, which is the one
 * place that name is written down here.
 *
 * 0 with a sentence where something did not fit, naming which. Truncating
 * would put a daemon's socket or its configuration somewhere nobody asked for,
 * which is worse than refusing to start.
 */
int ncfg_main_netcfgd_where(const struct ncfg_main_options *options, ncfg_main_where_t *out,
    char *err, size_t err_size);

/*
 * The control policy the sockets are bound under, owned by this program.
 *
 * **A copy and not a borrow**, and the reason is a lifetime the server cannot
 * see: `ncfg_daemon_serve_t` borrows the policies and they must outlive the
 * server, while `state->desired` is *replaced* by every reload. Pointing the
 * socket at the document's own block would leave it reading freed memory the
 * first time somebody wrote in the configuration directory.
 *
 * It also means the socket's permissions do not follow a reload, which is the
 * Rust's behaviour as well -- it clones the policy before binding -- and is
 * worth knowing rather than discovering: opening `control { observe = "any" }`
 * takes effect when the daemon is restarted.
 */
typedef struct {
	ncfg_control_t       control;
	ncfg_remote_policy_t remote;
} ncfg_main_policy_t;

/*
 * Take a copy of a document's control policy, or the default where there is
 * none.
 *
 * The default is every tier root, which is what a machine with no compiled
 * configuration must get: a daemon that could not read its own policy and
 * opened the socket to everybody would be the worst possible reading of an
 * unreadable file.
 */
int ncfg_main_policy_copy(const ncfg_document_t *document, ncfg_main_policy_t *out, char *err,
    size_t err_size);

/* The one free for it. Freeing one never filled in is nothing. */
void ncfg_main_policy_free(ncfg_main_policy_t *policy);

/* Whether a remote policy opens anything at all. A remote socket is bound only
 * where it does, because a listening socket that reaches the network is the
 * one thing about this daemon an operator should never find by accident. */
int ncfg_main_remote_is_open(const ncfg_remote_policy_t *remote);

/* The usage text, so that a test can walk it against the arms that dispatch
 * it -- `run.c` and `cli_test.c` do the same thing for `ncfg`, and for the
 * same reason: `reload` drifted for a milestone because nothing compared the
 * two lists. */
const char *ncfg_main_netcfgd_usage(void);

/*
 * `netcfgd-probe`, from `argv`.
 *
 * The one entry point here that is finished, because `ncfg_portal_helper` is:
 * that call is the body, it answers the exit status and the single line to
 * print, and this prints and leaves. 0263 puts the division exactly there --
 * it is the only difference between this and the Rust's `helper_main`.
 */
int ncfg_main_probe(int argc, char **argv);

#endif /* NCFG_MAIN_INTERNAL_H */

/*
 * Whether this build may reconcile a machine, which today is no.
 *
 * Reachable on its own so a test can assert the refusal without running the
 * entry point that would otherwise start a daemon. `daemon_main.c` carries the
 * reasoning and the two things that have to be true before it answers yes.
 */
int ncfg_main_netcfgd_may_reconcile(void);
