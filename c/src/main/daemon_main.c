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

#include "loop_internal.h"

#include "ncfg/cli.h"
#include "ncfg/config.h"
#include "ncfg/dhcp.h"
#include "ncfg/dns.h"
#include "ncfg/log.h"
#include "ncfg/observe.h"
#include "ncfg/rfkill.h"
#include "ncfg/secrets.h"
#include "ncfg/state.h"
#include "ncfg/supplicant.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
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

const char *ncfg_main_netcfgd_usage(void)
{
	return usage_text;
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
 * Everything `netcfgd` does before it would start anything.
 *
 * **Split out so that the tests never call the other half**, and that is a
 * safety property rather than a tidiness one. `main_test.c` drives the option
 * parsing, the help text and the version by calling into this program in the
 * test's own process -- which is right, and is what the multi-call shape
 * buys. It is also what the entry point below would otherwise make dangerous:
 * that one starts a network configuration daemon, and a test that called it
 * would do so inside `make check` on whatever machine ran the suite.
 */
int ncfg_main_netcfgd_parse(int argc, char **argv, struct ncfg_main_options *options,
    int *done, int *code)
{
	/* Before the parse, because a level that arrives late cannot filter what
	 * happened early -- and startup is exactly when somebody turns this up. */
	ncfg_log_accept_from_env();

	return parse(argc, argv, options, done, code);
}

/* ------------------------------------------------------------------------ *
 * Where this daemon reads, writes and listens
 * ------------------------------------------------------------------------ */

/* One path into a fixed array, refusing rather than truncating. A daemon
 * whose socket or configuration directory is a prefix of the one somebody
 * named is worse than one that will not start. */
static int path_is(char *out, size_t out_size, const char *what, const char *format,
    const char *first, const char *second, char *err, size_t err_size)
{
	int written = snprintf(out, out_size, format, first, second);

	if (written < 0 || (size_t)written >= out_size) {
		out[0] = '\0';
		ncfg_error_set(err, err_size, "the %s does not fit in %zu bytes", what, out_size - 1u);
		return 0;
	}
	return 1;
}

int ncfg_main_netcfgd_where(const struct ncfg_main_options *options, ncfg_main_where_t *out,
    char *err, size_t err_size)
{
	if (!options || !out) {
		ncfg_error_set(err, err_size, "there is nowhere to resolve a daemon's paths into");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	/*
	 * Each of the three is `config.h`'s or `state.h`'s own answer, called
	 * rather than restated: the explicit value, then the environment, then the
	 * default. Restating that order here is how the help text and the code
	 * came to disagree in the Rust.
	 */
	(void)ncfg_config_resolve_factory_dir(options->factory_dir, out->factory,
	    sizeof(out->factory));
	(void)ncfg_config_resolve_dir(options->config_dir, out->config, sizeof(out->config));
	(void)ncfg_state_resolve_dir(options->run_dir, out->run, sizeof(out->run));
	if (!out->factory[0] || !out->config[0] || !out->run[0]) {
		ncfg_error_set(err, err_size,
		    "one of the three directories did not fit in %d bytes", NCFG_MAIN_PATH_MAX);
		return 0;
	}
	if (options->socket) {
		if (!path_is(out->socket, sizeof(out->socket), "socket path", "%s%s",
		    options->socket, "", err, err_size)) {
			return 0;
		}
	} else if (!path_is(out->socket, sizeof(out->socket), "socket path", "%s/%s", out->run,
	    "netcfgd.sock", err, err_size)) {
		return 0;
	}
	/*
	 * Beside the socket rather than under the run directory, which is the
	 * Rust's `with_file_name` and matters for `--socket`: a daemon told to
	 * listen somewhere else would otherwise put its *remote* socket back in
	 * `/run/netcfgd`, which is the one place a second netcfgd on one machine
	 * must not write.
	 */
	{
		const char *slash = strrchr(out->socket, '/');
		size_t      keep = slash ? (size_t)(slash - out->socket) + 1u : 0u;

		if (keep + sizeof("remote.sock") > sizeof(out->remote_socket)) {
			ncfg_error_set(err, err_size,
			    "the remote socket path does not fit in %d bytes", NCFG_MAIN_PATH_MAX);
			return 0;
		}
		memcpy(out->remote_socket, out->socket, keep);
		memcpy(out->remote_socket + keep, "remote.sock", sizeof("remote.sock"));
	}
	/*
	 * The two credential directories, under the two this daemon was given
	 * rather than under `/etc` and `/run`. `secrets.h` and
	 * `netcfgd_apply::kernel` spell the same pair, and spelling them again
	 * here against a *default* would make a daemon pointed at a scratch tree
	 * read the machine's real credentials.
	 */
	if (!path_is(out->secrets, sizeof(out->secrets), "secrets directory", "%s/%s",
	        out->config, "secrets", err, err_size) ||
	    !path_is(out->certs, sizeof(out->certs), "certificate directory", "%s/%s", out->run,
	        "certs", err, err_size)) {
		return 0;
	}
	/*
	 * And the two the service-side executor writes through, each asked of the
	 * module that owns the files rather than spelled again here. The observer
	 * reads the sysctls this daemon writes, so a second spelling of that root
	 * is a value written where nothing looks for it; the supplicant's control
	 * directory is `supplicant.h`'s for the same reason.
	 *
	 * `ncfg_observe_roots_default` answers three roots and only one of them is
	 * this struct's business. Taking the whole answer and keeping one member is
	 * still one reading of the environment rather than two -- and a daemon that
	 * observed through one root and wrote through another is precisely the
	 * failure this is arranged to make impossible.
	 */
	{
		ncfg_observe_roots_t roots;

		if (!ncfg_observe_roots_default(&roots, err, err_size)) {
			return 0;
		}
		if (!path_is(out->proc, sizeof(out->proc), "proc root", "%s%s", roots.proc, "",
		        err, err_size)) {
			return 0;
		}
	}
	if (!ncfg_supplicant_ctrl_dir(out->supplicant, sizeof(out->supplicant), err, err_size)) {
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * The policy the sockets are bound under
 * ------------------------------------------------------------------------ */

static int principal_copy(const ncfg_principal_t *from, ncfg_principal_t *to)
{
	to->kind = from->kind;
	to->name = NULL;
	if (!from->name) {
		return 1;
	}
	to->name = strdup(from->name);
	return to->name != NULL;
}

int ncfg_main_policy_copy(const ncfg_document_t *document, ncfg_main_policy_t *out, char *err,
    size_t err_size)
{
	const ncfg_control_t       *control;
	const ncfg_remote_policy_t *remote;
	ncfg_control_t              root;
	ncfg_remote_policy_t        closed;

	if (!out) {
		ncfg_error_set(err, err_size, "there is nowhere to copy a control policy to");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	memset(&root, 0, sizeof(root));
	memset(&closed, 0, sizeof(closed));
	/*
	 * Root everywhere and nothing open where there is no document. A daemon
	 * that could not read its own policy and opened the socket to everybody
	 * would be the worst possible reading of an unreadable file, and
	 * `NCFG_PRINCIPAL_ROOT` is the zero value precisely so that this is what a
	 * memset gives.
	 */
	control = document ? &document->globals.control : &root;
	remote = document ? &document->globals.remote : &closed;

	out->remote.observe = remote->observe;
	out->remote.wifi = remote->wifi;
	out->remote.admin = remote->admin;
	if (!principal_copy(&control->observe, &out->control.observe) ||
	    !principal_copy(&control->wifi, &out->control.wifi) ||
	    !principal_copy(&control->admin, &out->control.admin) ||
	    !principal_copy(&remote->agent, &out->remote.agent)) {
		ncfg_main_policy_free(out);
		ncfg_error_set(err, err_size, "there was not enough memory for the control policy");
		return 0;
	}
	return 1;
}

void ncfg_main_policy_free(ncfg_main_policy_t *policy)
{
	if (!policy) {
		return;
	}
	free(policy->control.observe.name);
	free(policy->control.wifi.name);
	free(policy->control.admin.name);
	free(policy->remote.agent.name);
	memset(policy, 0, sizeof(*policy));
}

int ncfg_main_remote_is_open(const ncfg_remote_policy_t *remote)
{
	if (!remote) {
		return 0;
	}
	return remote->observe || remote->wifi || remote->admin;
}

/* ------------------------------------------------------------------------ *
 * Starting
 * ------------------------------------------------------------------------ */

/*
 * WHAT IS BELOW THIS LINE AND WHY IT IS `static`
 *   Everything above is a call taking values and answering one, and
 *   `main_test.c` drives all of it. Everything below opens a netlink socket,
 *   binds a control socket, takes the apply lock and starts reconciling the
 *   machine it is running on -- and the machine this suite is built on is a
 *   developer's workstation with a real network.
 *
 *   So it has **no external name at all**. A test cannot call what it cannot
 *   spell, and that is a guarantee rather than a convention somebody keeps:
 *   `main_internal.h` declares the parse, the usage and the entry point, and
 *   the entry point is the one symbol `main_test.c` is checked never to name.
 *   The arrangement `ncfg_main_netcfgd_refuse` used to hold open is now held
 *   by the linker.
 *
 *   What that costs is stated rather than hidden: the sequence below is not
 *   covered by anything. Each piece it calls is -- the paths, the policy copy,
 *   the world's seams, the dispatcher, the mailbox, the watchers, the round --
 *   and what is not is the order they are called in and the teardown.
 */

/* Say what went wrong and leave with the daemon's failure status. Split out
 * because every step below has the same two lines after it. */
static int cannot(const char *step, const char *why)
{
	return failf("%s: %s", step, why);
}

/*
 * Resolve a window left open by a daemon that is no longer running.
 *
 * **The window is read before an executor is opened**, which is
 * `release_contended`'s ordering in the one other place it applies: a revert
 * needs the apply lock and a netlink socket, and every ordinary start has no
 * window at all. Answers whether one was found and put back.
 */
static int resolve_any_window(ncfg_main_world_t *world, ncfg_daemon_state_t *state,
    ncfg_confirm_armed_t *armed, ncfg_main_subscribers_t *subscribers)
{
	ncfg_confirm_window_t window;
	ncfg_executor_t       executor;
	ncfg_proto_event_t    event;
	char                  message[NCFG_ERROR_MAX];
	int                   resolved = 0;

	if (!ncfg_confirm_read_window(state->paths.run, &window)) {
		return 0;
	}
	memset(&executor, 0, sizeof(executor));
	message[0] = '\0';
	if (!ncfg_main_world_executor_open(world, &executor, message, sizeof(message))) {
		ncfg_log_emitf("confirm", NCFG_LOG_ERROR,
		    "a confirm window was open at startup and cannot be reverted: %s", message);
		return 0;
	}
	memset(&event, 0, sizeof(event));
	message[0] = '\0';
	if (!ncfg_confirm_resolve_on_startup(state, armed, &executor, &resolved, &event, message,
	    sizeof(message))) {
		ncfg_log_emitf("confirm", NCFG_LOG_ERROR, "the window found at startup was not put "
		    "back: %s", message);
		resolved = 0;
	} else if (resolved) {
		ncfg_main_subscribers_tell(subscribers, &event);
	}
	ncfg_main_world_executor_close(world, &executor);
	return resolved;
}

/* Bind one socket, or say which and why. NULL with a sentence already said. */
static ncfg_daemon_server_t *bind_one(const char *path, ncfg_arrival_t arrival,
    const ncfg_principal_t *const *reach, size_t reach_count, const ncfg_main_policy_t *policy,
    ncfg_main_mailbox_t *mailbox)
{
	ncfg_daemon_serve_t  how;
	ncfg_daemon_server_t *server;
	char                  message[NCFG_ERROR_MAX];

	memset(&how, 0, sizeof(how));
	how.path = path;
	how.arrival = arrival;
	how.reach = reach;
	how.reach_count = reach_count;
	how.control = &policy->control;
	how.remote = &policy->remote;
	how.roots = ncfg_authz_roots_default();
	/*
	 * The mailbox rather than the dispatcher directly, and the difference is
	 * the whole of 0263's entry about it: the server calls this on a
	 * connection's own thread, and a request answered there would have the
	 * reconcile happen underneath it -- a pending window deferring a reconcile
	 * and an explicit apply releasing the hold are both decided by the pass
	 * that has the request in hand.
	 */
	how.answer = ncfg_main_mailbox_answer;
	/*
	 * And the same crossing for the one request that is not answered.
	 * `monitor` hands its connection over instead of getting a reply, and the
	 * list it is handed to holds no lock because every call on it happens on
	 * the loop's thread -- so the descriptor waits in the mailbox exactly as a
	 * request does rather than being added from the connection's own thread.
	 */
	how.stream = ncfg_main_mailbox_stream;
	how.context = mailbox;
	message[0] = '\0';
	server = ncfg_daemon_serve(&how, message, sizeof(message));
	if (!server) {
		(void)cannot("cannot bind the control socket", message);
	}
	return server;
}

static int start(const options_t *options)
{
	ncfg_main_where_t        where;
	ncfg_daemon_state_t      state;
	ncfg_observe_source_t    source;
	ncfg_main_policy_t       policy;
	ncfg_main_subscribers_t  subscribers;
	ncfg_main_watchers_t     watchers;
	ncfg_main_world_t        world;
	ncfg_main_world_where_t  world_where;
	ncfg_main_mailbox_t      mailbox;
	ncfg_main_desk_t         desk;
	ncfg_confirm_armed_t     armed;
	ncfg_reconcile_t         loop;
	ncfg_main_run_t          run;
	ncfg_main_watch_t        watch;
	ncfg_resolv_machine_t    resolv;
	ncfg_daemon_server_t    *local = NULL;
	ncfg_daemon_server_t    *remote = NULL;
	const ncfg_principal_t  *reach[3];
	const ncfg_principal_t  *agent[1];
	char                     ctrl_dir[NCFG_MAIN_PATH_MAX];
	char                     err[NCFG_ERROR_MAX];
	int                      code = NCFG_MAIN_EXIT_OK;
	int                      reverted;

	err[0] = '\0';
	if (!ncfg_main_netcfgd_where(options, &where, err, sizeof(err))) {
		return cannot("this daemon cannot work out where to read and write", err);
	}
	if (!ncfg_daemon_state_init(&state, where.factory, where.config, where.run, err,
	    sizeof(err))) {
		return cannot("this daemon cannot hold its own state", err);
	}

	/* The observation seam before the first reload, because a reload is the
	 * first thing that might want one. `ncfg_observe_source_observe` is
	 * `ncfg_daemon_observe_fn` signature for signature. */
	/* The store as well as the run directory, because an observation asks it
	 * one question: whether a WireGuard device is running the key its
	 * configuration names. `where.secrets` is under the directory this daemon
	 * was *given*, which is the reason that pair is resolved there and not
	 * from a default. */
	if (!ncfg_observe_source_machine(&source, where.run, where.secrets, err, sizeof(err))) {
		ncfg_daemon_state_free(&state);
		return cannot("this daemon cannot work out how to read the machine", err);
	}
	state.observe = ncfg_observe_source_observe;
	state.observe_context = &source;

	/*
	 * **A configuration that does not compile is not a reason to refuse to
	 * start**, which is `ncfg_daemon_state_reload`'s bargain: the daemon keeps
	 * watching, the diagnostics are said once here, and an operator fixing the
	 * file gets a working daemon without restarting it. Refusing instead would
	 * mean a typo in a drop-in takes the machine's network manager away.
	 */
	err[0] = '\0';
	if (!ncfg_daemon_state_reload(&state, err, sizeof(err))) {
		ncfg_log_emitf("config", NCFG_LOG_ERROR,
		    "the configuration does not compile, so this daemon is running with none:\n%s",
		    state.diagnostics ? state.diagnostics : err);
	}

	if (!ncfg_main_policy_copy(state.desired, &policy, err, sizeof(err))) {
		ncfg_daemon_state_free(&state);
		return cannot("this daemon cannot read its own control policy", err);
	}

	ncfg_main_subscribers_init(&subscribers);
	ncfg_main_watchers_init(&watchers);

	loop.probes = ncfg_probes_new(err, sizeof(err));
	loop.sims = ncfg_sims_new(err, sizeof(err));
	if (!loop.probes || !loop.sims) {
		ncfg_probes_free(loop.probes);
		ncfg_sims_free(loop.sims);
		ncfg_main_policy_free(&policy);
		ncfg_daemon_state_free(&state);
		return cannot("this daemon cannot hold what it has to count across ticks", err);
	}

	/* Zeroed first, so a member added to the seam later is absent -- which
	 * `ncfg_main_world_where_t` says refuses the ops that need it by name --
	 * rather than whatever was on the stack. */
	memset(&world_where, 0, sizeof(world_where));
	world_where.run_dir = where.run;
	world_where.proc_root = where.proc;
	world_where.supplicant_dir = where.supplicant;
	world_where.secrets_dir = where.secrets;
	world_where.certs_dir = where.certs;
	/* The machine's three, which `dns.h` owns. This is the one caller that
	 * should spell them: a daemon delivers to the machine it manages, and the
	 * seam exists so that nothing else does it by accident. */
	world_where.resolv_conf = NCFG_RESOLV_CONF;
	world_where.dnsmasq_conf = NCFG_DNSMASQ_CONF;
	world_where.unbound_conf = NCFG_UNBOUND_CONF;
	/* And dhcpcd's, which `dhcp.h` owns for the same reason. */
	ncfg_dhcp_machine(&world_where.dhcp);
	if (!ncfg_main_world_open(&world, &world_where, &state, &subscribers, &watchers, err,
	    sizeof(err))) {
		ncfg_probes_free(loop.probes);
		ncfg_sims_free(loop.sims);
		ncfg_main_policy_free(&policy);
		ncfg_daemon_state_free(&state);
		return cannot("this daemon cannot reach the machine it manages", err);
	}

	memset(&armed, 0, sizeof(armed));
	loop.state = &state;
	/*
	 * A record rather than NULL, because what an open window covers is what a
	 * revert puts back: a loop with no place to keep it arms a window whose
	 * revert falls back to the desired document, which `daemon.h` says may
	 * hold an edit that arrived inside the window and was never applied.
	 */
	loop.armed = &armed;
	loop.holding = 0;
	loop.reclaims = 0u;
	memset(&loop.world, 0, sizeof(loop.world));
	ncfg_main_world_seams(&world, &loop.world);
	/* The three the library implements for itself, and the machine the resolv
	 * sweep asks about processes. `now` stays NULL, which is
	 * `ncfg_confirm_now`. */
	loop.world.hook = ncfg_reconcile_hook_run;
	loop.world.portal = ncfg_reconcile_portal_probe;
	resolv = ncfg_resolv_machine_default();
	loop.world.resolv = &resolv;

	err[0] = '\0';
	if (!ncfg_supplicant_ctrl_dir(ctrl_dir, sizeof(ctrl_dir), err, sizeof(err))) {
		ctrl_dir[0] = '\0';
		ncfg_log_emitf("wifi", NCFG_LOG_WARNING,
		    "no supplicant control directory (%s), so no radio's events are watched", err);
	}
	memset(&watch, 0, sizeof(watch));
	watch.config_dir = where.config;
	watch.rfkill_device = NCFG_RFKILL_DEVICE;
	watch.supplicant_dir = ctrl_dir[0] ? ctrl_dir : NULL;
	watch.kernel = 1;
	watch.poll_config = options->poll_config;
	err[0] = '\0';
	if (!ncfg_main_watchers_open(&watchers, &watch, err, sizeof(err))) {
		code = cannot("this daemon cannot open the descriptors it watches", err);
		goto done;
	}
	/* After the watchers, because the handler writes to a pipe they own. */
	err[0] = '\0';
	if (!ncfg_main_signals_watch(&watchers, err, sizeof(err))) {
		code = cannot("this daemon cannot arrange to be stopped", err);
		goto done;
	}

	/*
	 * The desk before the mailbox, because the mailbox keeps its address and
	 * a connection thread may reach the seam the moment a socket is bound.
	 * Every path in it is this program's, resolved once: `daemon.h` gives the
	 * wifi directories no defaults for the reason `testdir.h` gives, which is
	 * that the default here is the machine this is built on.
	 */
	memset(&desk, 0, sizeof(desk));
	desk.state = &state;
	desk.where.ctrl_dir = ctrl_dir[0] ? ctrl_dir : NCFG_SUPPLICANT_CTRL_DIR;
	desk.where.class_net = source.roots.class_net;
	desk.where.run_dir = where.run;
	desk.secrets_dir = where.secrets;
	desk.certs_dir = where.certs;
	desk.subscribers = &subscribers;

	err[0] = '\0';
	if (!ncfg_main_mailbox_open(&mailbox, ncfg_main_answer, ncfg_main_stream, &desk,
	    watchers.nudge_write, err, sizeof(err))) {
		code = cannot("this daemon cannot take requests", err);
		goto done;
	}

	reach[0] = &policy.control.observe;
	reach[1] = &policy.control.wifi;
	reach[2] = &policy.control.admin;
	local = bind_one(where.socket, NCFG_ARRIVED_LOCAL, reach, 3u, &policy, &mailbox);
	if (!local) {
		code = NCFG_MAIN_EXIT_FAILED;
		goto shut;
	}
	if (ncfg_main_remote_is_open(&policy.remote)) {
		agent[0] = &policy.remote.agent;
		remote = bind_one(where.remote_socket, NCFG_ARRIVED_REMOTE, agent, 1u, &policy,
		    &mailbox);
		if (!remote) {
			code = NCFG_MAIN_EXIT_FAILED;
			goto shut;
		}
		/* Said out loud, because a listening socket that reaches the network
		 * is the one thing about this daemon an operator should never
		 * discover by finding the file. */
		ncfg_log_emitf("control", NCFG_LOG_NOTE,
		    "remote access is open on %s -- observe %d, wifi %d, admin %d",
		    where.remote_socket, policy.remote.observe, policy.remote.wifi,
		    policy.remote.admin);
	}
	ncfg_log_emitf("config", NCFG_LOG_INFO, "watching %s, socket %s", where.config,
	    ncfg_daemon_server_path(local));

	/* Before anything else acts: a window found here was opened by a daemon
	 * that is no longer running, so nobody can have confirmed it. */
	reverted = resolve_any_window(&world, &state, loop.armed, &subscribers);

	err[0] = '\0';
	if (!ncfg_reconcile_establish_last_good(&state, err, sizeof(err))) {
		/* Not fatal: what is lost is `apply --confirm-within` on a machine
		 * that has never applied, which is the case that call exists for and
		 * is still better than not starting. */
		ncfg_log_emitf("confirm", NCFG_LOG_WARNING,
		    "there is no last-good configuration and one could not be written (%s), so "
		    "a confirm window cannot be armed until the first apply", err);
	}
	err[0] = '\0';
	if (!ncfg_reconcile_start(&loop, options->apply_on_start, reverted, err, sizeof(err))) {
		/* The startup apply failing is a machine that needs looking at, not a
		 * daemon that should stop watching it. */
		ncfg_log_emitf("apply", NCFG_LOG_ERROR, "the configuration was not applied at "
		    "startup: %s", err);
	}

	memset(&run, 0, sizeof(run));
	run.loop = &loop;
	run.sources = &watchers.sources;
	run.mailbox = &mailbox;
	/* The same list the world announces through and the desk subscribes to,
	 * so that a stream the loop finds gone is one the pass stops writing to.
	 * A second list would be a second answer to how many streams are open, and
	 * the bound is what refuses the seventeenth `monitor`. */
	run.subscribers = &subscribers;
	run.refresh = ncfg_main_watchers_refresh;
	run.refresh_context = &watchers;
	err[0] = '\0';
	if (!ncfg_main_serve(&run, err, sizeof(err))) {
		code = cannot("this daemon stopped watching its descriptors", err);
	}

shut:
	/*
	 * **Shut the mailbox, stop the servers, then close it** -- the order is a
	 * requirement rather than tidiness. Closing destroys a mutex and a
	 * condition a connection thread may be about to lock, and what guarantees
	 * there is no such thread is `ncfg_daemon_server_stop` joining every one;
	 * shutting first is what lets that join finish, since a waiter is
	 * released by being answered.
	 */
	ncfg_main_mailbox_shut(&mailbox);
	ncfg_daemon_server_stop(remote);
	ncfg_daemon_server_stop(local);
	ncfg_main_mailbox_close(&mailbox);
done:
	ncfg_main_signals_restore();
	ncfg_main_watchers_close(&watchers);
	ncfg_main_world_close(&world);
	ncfg_main_subscribers_close(&subscribers);
	ncfg_probes_free(loop.probes);
	ncfg_sims_free(loop.sims);
	ncfg_confirm_armed_free(&armed);
	ncfg_main_policy_free(&policy);
	ncfg_daemon_state_free(&state);
	return code;
}

/*
 * Whether this build may be let loose on a machine.
 *
 * **The two facts that used to be here are closed, and this still answers 0.**
 * A created link now wears `NCFG_OBSERVE_ALTNAME_PREFIX` as an alternative
 * name (`kernel.c`'s `mark_as_ours`), and every apply and every revert folds
 * what it did into `owned.json` (`ncfg_apply_record`). So
 * `ncfg_observe_link_ownership` answers `ours` about a link this build made,
 * by the kernel's mark and by the record, and the change that had no way to be
 * undone can be undone.
 *
 * What is left is not bookkeeping and is not this directory's:
 *
 *   * **The planner still holds blocks rather than acting on them**, and warns
 *     by name for each one: `reported` addressing, `advertise`, `dot1x`, a
 *     `nat` setting, an `ipv6_token`, a `probe`, a `modem`, `on_unmanage =
 *     "clear"`, a `bluetooth` block and a `linkset` -- see `warn_unported` in
 *     `src/plan/build.c`, which is the list. A warning is what makes `ncfg
 *     plan` honest and is exactly what a reconcile on a timer would act past:
 *     it would converge part of a machine and report having converged it, to
 *     nobody who is reading.
 *   * **An op this executor cannot carry out is refused while the plan is
 *     running.** `ncfg_apply_supported` is asked by `execute`, one action at a
 *     time -- a `link.create` for a physical device, a pppoe session or an
 *     openvpn tunnel, and a `backend.start` for four of the nine backend
 *     kinds -- measured through `ncfg_apply_supported` rather than counted
 *     by reading its arms -- and `ncfg_apply` stops at the first failure.
 *     A plan mixing a
 *     supported op with an unsupported one therefore changes the machine and
 *     stops halfway. The link half of that list used to name a vlan, a bond, a
 *     macvlan and a tunnel; all four are created now, and the three left are
 *     ones `plan/link.c` declines by an earlier arm of its own.
 * The third fact that used to be here is closed too: `plan.last.json` is
 * written, by `ncfg_apply_write_journal`, after every apply and every revert,
 * so a plan that stopped halfway says under `/run` where it stopped. What is
 * left is the two above, and neither is bookkeeping.
 *
 * And the decision is the operator's rather than this function's. `on_drift =
 * reconcile` is the default, so starting this build on a machine is an apply
 * nobody typed -- against, on the machine this port is written on, a live
 * network somebody is working over. The rule the socket's own refusal states
 * is that one build must not refuse an apply at a terminal and accept one over
 * a socket; it must not accept one from a timer either, and `ncfg apply` is
 * still refused.
 *
 * Deleting this function is how the daemon is turned on, and the two facts
 * above are what has to be answered first.
 */
int ncfg_main_netcfgd_may_reconcile(void)
{
	return 0;
}

/*
 * Why it will not, in the words somebody typing `netcfgd` needs.
 */
static int will_not_reconcile(void)
{
	(void)fail("this build of the C port will not start. Its executor carries the half "
	    "that is not netlink -- `dns.apply` over every scope the machine has, the four "
	    "sysctls, the hostname, the six wifi ops and `backend.start` for five of the "
	    "nine backend kinds -- but one of those five refuses on arrival: an openvpn "
	    "tunnel's configuration file is an argument this daemon does not compose yet, "
	    "so a machine holding a tunnel would have its plan stop there, part converged, "
	    "with the links and addresses in front of it already changed");
	(void)fail("`ncfg apply` is refused here for the same reason, and a daemon "
	    "reconciling on drift is an apply nobody typed. What this build has stopped "
	    "waiting for is the liveness round: `running` in an observation is a fact "
	    "about a process now rather than this daemon's memory of having started one, "
	    "and a daemon it started and lost is noticed");
	return NCFG_MAIN_EXIT_FAILED;
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
	if (!ncfg_main_netcfgd_may_reconcile()) {
		return will_not_reconcile();
	}
	return start(&options);
}
