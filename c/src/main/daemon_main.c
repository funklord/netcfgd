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
    "  --supported            what this build carries out, as JSON lines, asked\n"
    "                         of the code that decides rather than listed\n"
    "  --try-the-c-daemon     run the loop anyway. This build refuses by\n"
    "                         default and prints why; read that first, and\n"
    "                         have something watching the machine when you\n"
    "                         use this -- tests/live/c_daemon_tryout.sh is\n"
    "                         what it was written for\n"
    "  -h, --help             this text\n"
    "  --version              the version, and who holds the copyright\n";

/*
 * The completeness ledger, derived rather than kept by hand.
 *
 * `doc/c-transition.md` section 5 asks for exactly this, and says why it may
 * not be a checklist: "a hand-written checklist of supported features is
 * exactly the shape this workspace has been burned by repeatedly -- a list
 * that quietly stops matching the thing it describes, under a name that claims
 * it is exhaustive."
 *
 * So nothing here is a list. Every line is produced by **asking the code that
 * decides**: `ncfg_apply_supported` about each of the forty-eight ops, and
 * `ncfg_proto_request_name` about each request kind. What is printed is what
 * this build would do, and it cannot drift from that because there is no
 * second copy of it to drift from.
 *
 * **A refusal prints its own sentence**, which is the half a checklist loses.
 * "not supported" and "created by the helper that connects it rather than by
 * a netlink message" are different facts, and only the second tells a reader
 * whether anything is actually missing.
 *
 * `link.create` is asked once per interface kind rather than once, because
 * that op's answer is a function of the kind: it is the one place where the
 * ledger has more rows than the op list. The same is true of the backend
 * family, which is asked once per backend kind.
 *
 * JSON lines, one object per subject, so `tool/ledger_gate.py` can diff it
 * against the frozen witnesses in `doc/schema/` without reading prose. On
 * stdout, because it is the answer to a question rather than a diagnostic
 * (0261).
 */
static void say_one(const char *subject, const char *name, int supported, const char *why)
{
	ncfg_buf_t        buf;
	ncfg_json_writer_t writer;

	ncfg_buf_init(&buf, 0);
	ncfg_json_write_init(&writer, &buf);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "subject", subject);
	ncfg_json_write_member_string(&writer, "name", name ? name : "?");
	ncfg_json_write_member_bool(&writer, "supported", supported);
	if (!supported && why && why[0]) {
		ncfg_json_write_member_string(&writer, "refusal", why);
	}
	ncfg_json_write_object_end(&writer);
	if (!ncfg_buf_failed(&buf)) {
		ncfg_out_line(ncfg_buf_text(&buf));
	}
	ncfg_buf_free(&buf);
}

void ncfg_main_netcfgd_supported(void)
{
	int kind;

	for (kind = 0; kind < (int)NCFG_PROTO_REQ_COUNT; kind++) {
		/* Named means the wire can carry it, and `daemon_answer.c` switches
		 * over the same enum with no `default`, so a kind that reaches the
		 * dispatcher without an arm does not compile. */
		say_one("request", ncfg_proto_request_name((ncfg_proto_request_kind_t)kind), 1,
		    NULL);
	}
	for (kind = 0; kind <= (int)NCFG_OP_COMMIT_REVERT; kind++) {
		ncfg_op_t op;
		char      why[NCFG_ERROR_MAX];
		int       ok;

		memset(&op, 0, sizeof(op));
		op.kind = kind;
		if (kind == (int)NCFG_OP_LINK_CREATE || kind == (int)NCFG_OP_BACKEND_START ||
		    kind == (int)NCFG_OP_BACKEND_STOP || kind == (int)NCFG_OP_BACKEND_RELOAD) {
			/* Asked per kind below, where the answer is decided. */
			continue;
		}
		why[0] = '\0';
		ok = ncfg_apply_supported(&op, why, sizeof(why));
		say_one("op", ncfg_op_name(&op), ok, why);
	}
	for (kind = 0; kind <= (int)NCFG_KIND_IFB; kind++) {
		ncfg_interface_kind_t created;
		ncfg_op_t             op;
		char                  why[NCFG_ERROR_MAX];
		int                   ok;

		memset(&created, 0, sizeof(created));
		created.kind = kind;
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_LINK_CREATE;
		op.u.link_create.name = "x";
		op.u.link_create.kind = &created;
		why[0] = '\0';
		ok = ncfg_apply_supported(&op, why, sizeof(why));
		say_one("link.create", ncfg_interface_kind_name(kind), ok, why);
	}
	for (kind = 0; kind <= (int)NCFG_BACKEND_DNS; kind++) {
		static const int verbs[] = { NCFG_OP_BACKEND_START, NCFG_OP_BACKEND_STOP,
			NCFG_OP_BACKEND_RELOAD };
		size_t           at;

		for (at = 0; at < sizeof(verbs) / sizeof(verbs[0]); at++) {
			ncfg_op_t op;
			char      why[NCFG_ERROR_MAX];
			char      subject[64];
			int       ok;

			memset(&op, 0, sizeof(op));
			op.kind = verbs[at];
			op.u.backend.kind = kind;
			op.u.backend.iface = "x";
			why[0] = '\0';
			ok = ncfg_apply_supported(&op, why, sizeof(why));
			(void)snprintf(subject, sizeof(subject), "%s", ncfg_op_name(&op));
			say_one(subject, ncfg_backend_kind_name(kind), ok, why);
		}
	}
}

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
		if (strcmp(argument, "--supported") == 0) {
			ncfg_main_netcfgd_supported();
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
		} else if (strcmp(argument, "--try-the-c-daemon") == 0) {
			options->try_the_c_daemon = 1;
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
	(void)ncfg_dns_resolve_conf_path(NULL, out->resolv, sizeof(out->resolv));
	(void)ncfg_dns_resolve_dnsmasq_path(NULL, out->dnsmasq, sizeof(out->dnsmasq));
	(void)ncfg_dns_resolve_unbound_path(NULL, out->unbound, sizeof(out->unbound));
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

/*
 * Where to watch for switch events, from the environment or the kernel's own.
 *
 * `rfkill.h` owns the spelling and deliberately reads nothing itself; this is
 * the one place a netcfgd resolves it, beside where it resolves the run
 * directory and the two daemon programs.
 */
static const char *rfkill_device_from_environment(void)
{
	const char *set = getenv(NCFG_RFKILL_DEVICE_ENV);

	return set && set[0] ? set : NCFG_RFKILL_DEVICE;
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
	/*
	 * And the resolver file, which `ncfg_observe_roots_t` leaves empty on
	 * purpose: an observation that was given no path says nothing about a
	 * delivery rather than reading whatever `/etc/resolv.conf` this machine
	 * has. This is the daemon, so it means the machine's -- `dns.h`'s
	 * constant, which is also what the executor's world is given further
	 * down, so that what is written and what is compared cannot come to be
	 * two files.
	 */
	(void)snprintf(source.roots.resolv_conf, sizeof(source.roots.resolv_conf), "%s",
	    where.resolv);
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
	world_where.resolv_conf = where.resolv;
	world_where.dnsmasq_conf = where.dnsmasq;
	world_where.unbound_conf = where.unbound;
	/* And dhcpcd's, which `dhcp.h` owns for the same reason. */
	ncfg_dhcp_machine(&world_where.dhcp);
	/* And the two programs a test may put in front of the conventional ones,
	 * which the modules that run them deliberately do not read for
	 * themselves. */
	ncfg_main_world_where_from_environment(&world_where);
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
	/* The dead reply sockets in that directory are swept by
	 * `ncfg_main_watchers_open`, which is the first thing here that lists it
	 * -- and is somewhere a test can drive. */
	memset(&watch, 0, sizeof(watch));
	watch.config_dir = where.config;
	/*
	 * **Asked for rather than assumed**, which is the same seam the two
	 * program paths take and was missing here in the same way: the constant
	 * on its own ignored `NCFG_RFKILL_DEV`, so a live script handing netcfgd
	 * a fifo was watched on `/dev/rfkill` instead and its events went
	 * nowhere. An empty value is no value, because a device path of "" is an
	 * open that fails for a reason nobody can read.
	 */
	watch.rfkill_device = rfkill_device_from_environment();
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
	/* 0117's path: where a `network` block this daemon is asked to write goes,
	 * and the layer it must not be shadowed by. Both resolved once, like every
	 * other path this daemon uses. */
	desk.config_dir = where.config;
	desk.factory_dir = where.factory;
	desk.subscribers = &subscribers;
	/* The machine's, and the same answer the reconcile pass gives a radio
	 * back on: two readings of "who else is managing this" would be two
	 * answers to one question. */
	ncfg_contention_machine(&desk.contention);
	/* The loop's own selection, borrowed rather than copied: a client is told
	 * where this daemon has got to, not where a second copy of the rule
	 * would. */
	desk.sims = loop.sims;
	/* And the loop itself, for the three requests that change the machine.
	 * The same one the pass runs: two loops would be two plans built against
	 * one machine, and they would take the apply lock from each other. */
	desk.loop = &loop;

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
 * Whether this build may be let loose on a machine, and what changed about the
 * answer.
 *
 * **Three facts stood here and all three are closed.** A created link wears
 * `NCFG_OBSERVE_ALTNAME_PREFIX` as an alternative name, every apply and every
 * revert folds what it did into `owned.json`, and `plan.last.json` says where
 * an apply stopped. The two that replaced them are closed too:
 *
 *   * **The executor refuses nothing that is a port gap.** What
 *     `ncfg_apply_supported` still declines is a physical device it cannot
 *     create, a plain `backend.start` for DHCPv6 that carries neither the
 *     delegation request nor the client (0050), and WireGuard and DNS, which
 *     are not daemons. The Rust declines each of those in the same words.
 *   * **The planner holds no block the Rust does not.** Every arm of
 *     `warn_unported`, of `wifi.c`'s held list and of `offload.c` carries
 *     `ncfg_plan_warn_unbuilt`'s sentence -- *nothing acts on it in the Rust
 *     either* -- and the two blocks that are read elsewhere say where. A
 *     reconcile here would converge exactly what a reconcile there converges.
 *
 * So the refusal stays, and its reason is now the one that cannot be closed by
 * writing code: **no netcfgd written in C has run a machine.** Every check in
 * this tree runs against a recorder, a scratch directory or a fake; the live
 * scripts read. A loop is the one part of this program that acts with nobody
 * at the keyboard, and the thing it would act on first, on the machine this is
 * written on, is the radio carrying the only route off it.
 *
 * **That is a reason to be told, not a reason to be talked out of.** So this
 * answers what the invocation said: `--try-the-c-daemon` is how somebody at
 * the keyboard says they are watching, and `tests/live/c_daemon_tryout.sh` is
 * what watches -- it hands the machine back to the Rust daemon when the
 * network goes, which is the evidence-gathering arrangement this was waiting
 * for. Nothing in any unit file passes that flag.
 */
/*
 * Whether *this invocation* was told to run anyway, and nothing else.
 *
 * **A latch rather than a parameter, so that the default is what a test can
 * ask about.** `main_test.c`'s subject is "this build does not reconcile
 * unless somebody says so", which is a question about the program rather than
 * about one call -- and a function taking the options would answer it only for
 * whatever options a test happened to build. Set once, by the parser, from a
 * flag that is not in any unit file.
 */
static int told_to_reconcile;

void ncfg_main_netcfgd_allow_reconcile(int allowed)
{
	told_to_reconcile = allowed ? 1 : 0;
}

int ncfg_main_netcfgd_may_reconcile(void)
{
	return told_to_reconcile;
}

/*
 * Why it will not, in the words somebody typing `netcfgd` needs.
 */
static int will_not_reconcile(void)
{
	/*
	 * **What this says had to change, because what was true stopped being
	 * true.** It named two things: ops the executor refused, and blocks the
	 * planner held. The first is closed -- `ncfg_apply_supported` refuses
	 * nothing that is a port gap. So is the second, in the only sense that
	 * distinguished this build from the Rust: every block the planner holds is
	 * one the Rust holds too, each carrying `warn_unbuilt`'s sentence, and the
	 * two that are not held here are read by the daemon instead.
	 *
	 * What is left is not a list of missing code. It is that **no netcfgd
	 * written in C has ever run a machine**, and a reconcile loop is the one
	 * part of this program that acts without anybody having typed anything.
	 * That is a different kind of reason and it is the honest one: the risk
	 * is the evidence nobody has, not a feature somebody can name.
	 */
	(void)fail("this build of the C port does not start its reconcile loop by default, "
	    "and the reason is no longer a list of missing code: the executor refuses "
	    "nothing that is a port gap, and every block this planner holds is one the "
	    "Rust holds too. What is missing is evidence -- no netcfgd written in C has "
	    "run a machine for any length of time -- and a loop is the one part of this "
	    "program that acts with nobody at the keyboard");
	(void)fail("`ncfg plan` changes nothing and says what this build would do on this "
	    "machine; `ncfg apply` does it, because somebody typed it. To run the loop "
	    "anyway, pass `--try-the-c-daemon`, and have something watching that can hand "
	    "the machine back -- `tests/live/c_daemon_tryout.sh` is that something, and it "
	    "falls back to the Rust daemon when the network goes");
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
	ncfg_main_netcfgd_allow_reconcile(options.try_the_c_daemon);
	if (!ncfg_main_netcfgd_may_reconcile()) {
		return will_not_reconcile();
	}
	/*
	 * **Said every time, at the level nothing filters.** Somebody who typed
	 * the flag knows what they did; the person who finds this in a log a week
	 * later, or inherits a machine running it, does not. It names the build,
	 * what is watching (nothing, from here -- that is the operator's to
	 * arrange) and how to stop.
	 */
	ncfg_log_emitf("daemon", NCFG_LOG_WARNING,
	    "starting the C port's reconcile loop because `--try-the-c-daemon` was given. "
	    "This build has never run a machine for long; the refusal it replaces is in "
	    "`netcfgd --help` and in daemon_main.c. Stop it with SIGTERM and start the Rust "
	    "daemon to hand the machine back");
	return start(&options);
}
