/*
 * daemon_main.c -- `netcfgd`'s command line, and the two things it waits for.
 *
 * WHAT IS HERE AND WHAT IS NOT
 *   Everything this file parses is real: the six options are the Rust's, spelt
 *   the same way, taking the same values, with the same defaults behind them.
 *   `--help` and `--version` are complete. What is not here is the step after
 *   the parse -- the daemon does not start -- and that is said by name rather
 *   than by starting and doing nothing.
 *
 *   **Two of the three pieces this refusal used to name have landed.** The
 *   observation is composed by `ncfg_observe_source_observe`, which is
 *   `ncfg_daemon_observe_fn` signature for signature; and this program's own
 *   half -- the netlink socket, the configuration watch, `/dev/rfkill`, the
 *   supplicant directory and the commit-confirm window's timer -- is opened by
 *   `ncfg_main_watchers_open` and waited on together by `ncfg_main_round`.
 *   See `loop_internal.h`.
 *
 *   **What is left is the request dispatcher.** Nothing under `c/src/`
 *   implements `ncfg_daemon_answer_fn`: `server.c` holds the type and
 *   `answer.c` writes the three responses the authorization path decides for
 *   itself, and that is all. Starting anyway is not an option that fails
 *   safely -- the daemon would bind the control socket, accept connections,
 *   pass authorization and then answer `error` to every request, which an
 *   operator reads as a request the daemon did not recognise rather than as a
 *   daemon that cannot act. It is the same thing 0263 keeps refusing: an
 *   answer nobody can tell from a true one, arriving on the socket somebody
 *   reaches for when the network is already broken.
 *
 * WHY THE USAGE TEXT IS BUILT FROM THE CONSTANTS
 *   The Rust writes `default /etc/netcfgd, or $NCFG_CONFIG_DIR` as literal
 *   text, which is the same path written in two places -- `config.h` holds the
 *   other, and the help is the copy nobody recompiles against. Here the
 *   defaults are pasted in from the constants that decide them, so a default
 *   that moves moves in the help as well or does not compile.
 */
#include "main_internal.h"

#include "ncfg/cli.h"
#include "ncfg/config.h"
#include "ncfg/log.h"
#include "ncfg/state.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/*
 * The text, and the six options the parser below has an arm for.
 *
 * Every option named here is dispatched, and `main_test.c` walks this string
 * looking for one that is not. `reload` drifted out of `ncfg` for a whole
 * milestone because nothing compared the help against the code, and a daemon's
 * help is read by exactly the person who has no other way to find out.
 */
static const char usage_text[] =
    NCFG_MAIN_DAEMON_NAME " -- network configuration daemon\n"
    "\n"
    "usage:\n"
    "  " NCFG_MAIN_DAEMON_NAME " [options]\n"
    "\n"
    "options:\n"
    "  --config-dir PATH      default " NCFG_CONFIG_DIR_DEFAULT ", or $"
        NCFG_CONFIG_DIR_ENV "\n"
    "  --factory-dir PATH     default " NCFG_FACTORY_DIR_DEFAULT ", or $"
        NCFG_FACTORY_DIR_ENV ".\n"
    "                         Read before --config-dir, which overrides it\n"
    "  --run-dir PATH         default " NCFG_RUN_DIR_DEFAULT ", or $NCFG_RUN_DIR\n"
    "  --socket PATH          default " NCFG_RUN_DIR_DEFAULT "/netcfgd.sock\n"
    "  --no-apply-on-start    observe and watch, but change nothing until asked\n"
    "  --poll-config          use mtime polling rather than inotify\n"
    "  -h, --help             this text\n"
    "  --version              the version, and who holds the copyright\n";

/*
 * What is missing, named as the thing rather than described.
 *
 * `ncfg_daemon_answer_fn` is a type in `daemon.h`, so this sentence points at
 * something that exists and can be looked up -- and `main_test.c` reads that
 * header to check the name is still spelt that way there. A refusal naming a
 * symbol that has since been renamed is a refusal sending somebody to look for
 * a module under a name nothing has.
 *
 * The audience is a developer rather than an operator, which is what makes an
 * identifier the right thing to say: nothing installs this program, so the
 * only way to have typed `netcfgd` here is to have built it.
 */
#define NCFG_MAIN_MISSING_SEAM "ncfg_daemon_answer_fn"

static const char waits_for[] =
    "an implementation of " NCFG_MAIN_MISSING_SEAM ", the seam a request is answered "
    "through";

const char *ncfg_main_netcfgd_usage(void)
{
	return usage_text;
}

const char *ncfg_main_netcfgd_waits_for(void)
{
	return waits_for;
}

/*
 * `netcfgd: <sentence>` on stderr, and what to leave with.
 *
 * The one message that is not the log's: it is what a person who typed
 * `netcfgd` sees when it will not start, printed before a level exists to
 * filter it and before there is a subsystem to attribute it to. Straight to
 * the stream rather than through a buffer, which is `run.c`'s reasoning -- a
 * sentence rendered into a fixed array first is one that can be truncated, and
 * the end is where these say what to do about it.
 */
static int fail(const char *message)
{
	(void)fprintf(stderr, NCFG_MAIN_DAEMON_NAME ": %s\n", message);
	return NCFG_MAIN_EXIT_FAILED;
}

/* The same, composed. */
static int failf(const char *format, ...)
{
	va_list args;

	(void)fprintf(stderr, NCFG_MAIN_DAEMON_NAME ": ");
	va_start(args, format);
	(void)vfprintf(stderr, format, args);
	va_end(args);
	(void)fputc('\n', stderr);
	return NCFG_MAIN_EXIT_FAILED;
}

/*
 * The whole of what a parsed command line is, so far.
 *
 * Nothing here is owned: every string points into `argv`, which outlives the
 * parse. That is `options.c`'s rule for `ncfg` and it holds for the same
 * reason -- there is no free to forget and no copy that can disagree with what
 * was typed.
 */
/* The type is `main_internal.h`'s, so `main_test.c` can hold one. */

/*
 * Whether anything follows, and what it is.
 *
 * An option at the end of the line with nothing after it is refused by name
 * rather than defaulted: `netcfgd --config-dir` with nothing behind it is
 * somebody's init script with an unexpanded variable in it, and a default
 * there would put the daemon on `/etc/netcfgd` and say nothing about the
 * directory that was meant.
 *
 * **What follows is taken whatever it looks like**, which is the Rust's and
 * is deliberate: `--config-dir --poll-config` is a wrong command line, but it
 * is the operator's, and a parser that decided a value beginning with `-`
 * could not have been meant would refuse `--config-dir -weird-name` on a
 * directory that exists.
 */
static int value_of(int argc, char **argv, int *at, const char **out)
{
	if (*at + 1 >= argc) {
		return 0;
	}
	*at += 1;
	*out = argv[*at];
	return 1;
}

/*
 * Parse, and say which of the three happened.
 *
 * 1 with `*done` clear is a command line to act on; 1 with `*done` set is
 * `--help` or `--version`, which have already printed and are a complete run
 * of the program. 0 is a command line that was wrong, and has already said so.
 */
static int parse(int argc, char **argv, options_t *options, int *done, int *code)
{
	int at;

	memset(options, 0, sizeof(*options));
	options->apply_on_start = 1;
	*done = 0;
	*code = NCFG_MAIN_EXIT_OK;

	for (at = 1; at < argc; at++) {
		const char *argument = argv[at];

		if (strcmp(argument, "-h") == 0 || strcmp(argument, "--help") == 0) {
			ncfg_out_write(usage_text);
			*done = 1;
			return 1;
		}
		/*
		 * The copyright surface `harmonization.md` names first, and it is
		 * `cli.h`'s constant rather than one of this file's. The Rust shares
		 * `CARGO_PKG_VERSION` and `netcfgd_model::COPYRIGHT` between the two
		 * programs precisely so they cannot drift apart about a fact neither
		 * of them owns; the C port has no constants module yet, so the one
		 * spelling that exists is the one that is read.
		 */
		if (strcmp(argument, "--version") == 0) {
			ncfg_out_writef(NCFG_MAIN_DAEMON_NAME " %s\n", NCFG_CLI_VERSION);
			ncfg_out_line(NCFG_CLI_COPYRIGHT);
			*done = 1;
			return 1;
		}
		if (strcmp(argument, "--config-dir") == 0) {
			if (!value_of(argc, argv, &at, &options->config_dir)) {
				*code = fail("--config-dir needs a value");
				return 0;
			}
		} else if (strcmp(argument, "--factory-dir") == 0) {
			if (!value_of(argc, argv, &at, &options->factory_dir)) {
				*code = fail("--factory-dir needs a value");
				return 0;
			}
		} else if (strcmp(argument, "--run-dir") == 0) {
			if (!value_of(argc, argv, &at, &options->run_dir)) {
				*code = fail("--run-dir needs a value");
				return 0;
			}
		} else if (strcmp(argument, "--socket") == 0) {
			if (!value_of(argc, argv, &at, &options->socket)) {
				*code = fail("--socket needs a value");
				return 0;
			}
		} else if (strcmp(argument, "--no-apply-on-start") == 0) {
			options->apply_on_start = 0;
		} else if (strcmp(argument, "--poll-config") == 0) {
			options->poll_config = 1;
		} else {
			/*
			 * Unknown rather than ignored, and it names what was typed. A
			 * daemon that skipped an option it did not know would run with
			 * `--no-apply-on-start` misspelt and apply on start, which is the
			 * one thing that flag exists to stop.
			 */
			char legible[NCFG_MAIN_NAME_MAX];

			ncfg_main_legible_name(argument, legible, sizeof(legible));
			*code = failf("unknown option `%s`", legible);
			return 0;
		}
	}
	return 1;
}

/*
 * The refusal, by name.
 *
 * Two lines, because there are two facts and the second is the one that keeps
 * somebody from reading the first as "this port is not written". `run.c`'s
 * `not_in_this_wave` is the same shape for the same reason: a command that
 * answered `unknown` for something its own help offers would be the drift the
 * dispatch list exists to refuse, and one that answered from somewhere else
 * would be worse, because it would look right.
 */
int ncfg_main_netcfgd_refuse(void)
{
	(void)failf("this build of the C port will not start: nothing here is %s, so it "
	    "would bind the control socket, let a client through and then answer `error` "
	    "to everything asked of it", waits_for);
	(void)fail("what this program owns is written -- the netlink socket, the "
	    "configuration watch, /dev/rfkill, the supplicant directory and the window "
	    "timer are opened by ncfg_main_watchers_open and waited on together by "
	    "ncfg_main_round -- and the observation, the reconcile pass, the confirm "
	    "window and the control socket are finished; what is missing is that one "
	    "seam");
	return NCFG_MAIN_EXIT_FAILED;
}

/*
 * Everything `netcfgd` does before it would start anything.
 *
 * **Split out so that the tests never call the other half**, and that is a
 * safety property rather than a tidiness one. `main_test.c` drives the option
 * parsing, the help text and the version by calling into this program in the
 * test's own process -- which is right, and is what the multi-call shape
 * buys. It is also one wiring commit away from starting a network
 * configuration daemon inside `make check`, on whatever machine the suite is
 * run on. That machine is a developer's workstation with a real network, and
 * a daemon that binds a control socket and starts reconciling is not
 * something a test suite should be able to do by accident.
 *
 * So the entry point below is parse-then-start, this is the parse, and the
 * tests call this one. When the assembly `ncfg_main_netcfgd_waits_for`
 * describes is written it goes in `start`, where no test reaches it, and the
 * arrangement that keeps it there is visible rather than remembered.
 */
int ncfg_main_netcfgd_parse(int argc, char **argv, struct ncfg_main_options *options,
    int *done, int *code)
{
	/* Before the parse, because a level that arrives late cannot filter what
	 * happened early -- and startup is exactly when somebody turns this up. */
	ncfg_log_accept_from_env();

	return parse(argc, argv, options, done, code);
}

int ncfg_main_netcfgd(int argc, char **argv)
{
	options_t options;
	int       done = 0;
	int       code = NCFG_MAIN_EXIT_OK;

	if (!ncfg_main_netcfgd_parse(argc, argv, &options, &done, &code)) {
		return code;
	}
	if (done) {
		return NCFG_MAIN_EXIT_OK;
	}
	/*
	 * Nothing is resolved, opened or written between here and the refusal, and
	 * that is deliberate. Resolving the three directories would be honest;
	 * `ncfg_daemon_state_init` followed by a reload would not, because a
	 * successful compile writes this document's hooks into the run directory,
	 * and a daemon that left hooks behind and then refused to start has
	 * changed the machine on its way to saying it did nothing.
	 */
	return ncfg_main_netcfgd_refuse();
}
