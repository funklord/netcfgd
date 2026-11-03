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

#include "ncfg/node.h"
#include "ncfg/buf.h"
#include "ncfg/caller_file.h"
#include "ncfg/proto.h"
#include "ncfg/watch.h"
#include "ncfg/seen.h"
#include "ncfg/cli.h"
#include "ncfg/config.h"
#include "ncfg/dhcp.h"
#include "ncfg/dns.h"
#include "ncfg/leftovers.h"
#include "ncfg/log.h"
#include "ncfg/observe.h"
#include "ncfg/hostapd.h"
#include "ncfg/rfkill.h"
#include "ncfg/secrets.h"
#include "ncfg/state.h"
#include "ncfg/supplicant.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
    "  --fuzznet-dir PATH     this node's fuzznet store, or $" NCFG_FUZZNET_DIR_ENV ";\n"
    "                         default fuzznet's own, for a daemon on the default\n"
    "                         --run-dir only. Empty for none\n"
    "  --fuzznet-arg ARG      one of fuzznet's own node options, for its loop\n"
    "  --no-apply-on-start    observe and watch, but change nothing until asked\n"
    "  --poll-config          use mtime polling rather than inotify\n"
    "  --supported            what this build carries out, as JSON lines, asked\n"
    "                         of the code that decides rather than listed\n"
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
static void say_one(const char *subject, const char *name, int supported, const char *why,
    const ncfg_op_t *op)
{
	ncfg_buf_t        buf;
	ncfg_json_writer_t writer;

	ncfg_buf_init(&buf, 0);
	ncfg_json_write_init(&writer, &buf);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "subject", subject);
	ncfg_json_write_member_string(&writer, "name", name ? name : "?");
	ncfg_json_write_member_bool(&writer, "supported", supported);
	/*
	 * **The two things about an action that a name cannot say**, for the rows
	 * that are about an op. `action.c` answers both out of a switch with no
	 * `default`, so this is the program saying what it decides rather than a
	 * document asserting it: `tool/ledger_gate.py` holds section 6.3 of
	 * `doc/socket-protocol.md` to these two columns, and an operator reading
	 * `ncfg plan` is told which actions can cut them off.
	 *
	 * A request row passes NULL and carries neither, because neither means
	 * anything about a verb somebody sent.
	 */
	if (op) {
		ncfg_json_write_member_bool(&writer, "disruptive", ncfg_op_is_disruptive(op));
		ncfg_json_write_member_bool(&writer, "host_wide",
		    ncfg_op_is_host_wide_config(op));
	}
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
		 * over the same enum with no `default`, so `-Wswitch` names a kind
		 * that reaches the dispatcher without an arm. A warning rather than a
		 * build failure; `apply.c` carries why. */
		say_one("request", ncfg_proto_request_name(kind), 1,
		    NULL, NULL);
	}
	/*
	 * Bounded by the name table rather than by the last member of the enum,
	 * and the three loops below are the same for the same reason. A bound
	 * written as `<= NCFG_BACKEND_DNS` was correct when it was written and
	 * silently went short the day a tenth kind arrived: the dump reported
	 * eight of ten, omitting `router_advert` entirely, and nothing failed --
	 * `ledger_gate.py` reads the witness and asks the C to answer for each
	 * name in it, so a kind the C has and the witness does not is a kind no
	 * gate is looking at. A name lookup answers for whatever the enum is
	 * now, which is the one bound that cannot rot.
	 */
	for (kind = 0;; kind++) {
		ncfg_op_t op;
		char      why[NCFG_ERROR_MAX];
		int       ok;

		memset(&op, 0, sizeof(op));
		op.kind = kind;
		if (ncfg_op_name(&op)[0] == '\0') {
			break;
		}
		if (kind == (int)NCFG_OP_LINK_CREATE || kind == (int)NCFG_OP_BACKEND_START ||
		    kind == (int)NCFG_OP_BACKEND_STOP || kind == (int)NCFG_OP_BACKEND_RELOAD) {
			/* Asked per kind below, where the answer is decided. */
			continue;
		}
		why[0] = '\0';
		ok = ncfg_apply_supported(&op, why, sizeof(why));
		say_one("op", ncfg_op_name(&op), ok, why, &op);
	}
	for (kind = 0; ncfg_interface_kind_name(kind) != NULL; kind++) {
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
		say_one("link.create", ncfg_interface_kind_name(kind), ok, why, &op);
	}
	for (kind = 0; ncfg_backend_kind_name(kind) != NULL; kind++) {
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
			say_one(subject, ncfg_backend_kind_name(kind), ok, why, &op);
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
		} else if (strcmp(argument, "--fuzznet-dir") == 0) {
			if (!value_of(argc, argv, &at, &options->fuzznet_dir)) {
				*code = fail("--fuzznet-dir needs a value");
				return 0;
			}
		} else if (strcmp(argument, "--fuzznet-serve") == 0) {
			/*
			 * **Accepted and retired** (decision 0311): a daemon with a
			 * node serves it, always. It was the opt-in while serving was a
			 * build option, and a script that still passes it is asking for
			 * what now happens anyway.
			 */
			options->fuzznet_serve = 1;
		} else if (strcmp(argument, "--fuzznet-arg") == 0) {
			if (options->fuzznet_arg_count >= 32u) {
				*code = fail("at most 32 --fuzznet-arg");
				return 0;
			}
			if (!value_of(argc, argv, &at,
			    &options->fuzznet_args[options->fuzznet_arg_count])) {
				*code = fail("--fuzznet-arg needs a value");
				return 0;
			}
			options->fuzznet_arg_count++;
		} else if (strcmp(argument, "--no-apply-on-start") == 0) {
			options->apply_on_start = 0;
		} else if (strcmp(argument, "--poll-config") == 0) {
			options->poll_config = 1;
		} else if (strcmp(argument, "--try-the-c-daemon") == 0) {
			/*
			 * **Accepted and retired**, which is why it is no longer in
			 * `usage_text`. It was the gate on this build's reconcile loop,
			 * and the loop runs by default now -- 0265. It is still taken
			 * rather than refused, because a flag documented as the way to run
			 * this daemon should not become a hard error in the same change
			 * that makes it unnecessary: a unit file carrying it would stop
			 * the daemon starting at all. The entry point says once that it
			 * did nothing, because a setting nobody can act on must not be
			 * silently ignored -- the house rule `log_shape.sh` applies to
			 * `NCFG_LOG`, applied here.
			 */
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

/*
 * Say at startup that the configuration directory cannot be written.
 *
 * **Written to rather than asked about.** `access(2)` and a `stat` answer
 * about the mode and walk straight past a read-only MOUNT, which is what
 * `ProtectSystem=` imposes and is the one case this exists for. So the probe
 * is a real `open` with `O_CREAT | O_EXCL`, removed again immediately.
 *
 * Said once here rather than once per write: 0127 makes netcfgd the only
 * writer of its own configuration, so this condition refuses every write verb
 * a client has -- one at a time, in front of whoever pressed the button. It is
 * true from the moment the daemon starts, so that is where it is reported,
 * into `systemctl status` and the journal, before anybody tries.
 *
 * The probe carries this process's pid so two daemons cannot collide, and it
 * is a dotfile so the config loader would ignore it even if a crash left one
 * behind (0121).
 *
 * **Called before the watchers open, and the call site says why**: creating
 * and unlinking this file moves the configuration directory's mtime, which is
 * part of the polling watcher's baseline.
 *
 * Only a refusal is reported. A full disk or a name that already exists is
 * some other problem, and guessing here would put a sentence about sandboxes
 * in front of somebody whose disk is full.
 */
static void report_writability(const char *config)
{
	char probe[NCFG_MAIN_PATH_MAX];
	int  fd;

	if (!config || config[0] == '\0') {
		return;
	}
	if (snprintf(probe, sizeof(probe), "%s/.netcfgd-write-probe.%ld", config,
	        (long)getpid()) >= (int)sizeof(probe)) {
		return;
	}
	fd = open(probe, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd >= 0) {
		(void)close(fd);
		(void)unlink(probe);
		return;
	}
	if (errno != EACCES && errno != EPERM && errno != EROFS) {
		return;
	}
	ncfg_log_emitf("config", NCFG_LOG_ERROR,
	    "cannot write %s (%s), so no client can store configuration: `ncfg wifi add`, "
	    "`ncfg config put`, `ncfg secret set`, `ncfg profile save` and the gui's write "
	    "buttons will all be refused", config, strerror(errno));
	ncfg_log_emitf("config", NCFG_LOG_ERROR,
	    "  netcfgd is the only writer of that directory (0127). Under systemd this is "
	    "`ProtectSystem=`, and the unit has to name the path in `ReadWritePaths=` -- "
	    "`systemctl cat netcfgd` shows what yours says");
}

/*
 * This daemon's fuzznet node (0308), or NULL -- and NULL is not a failure of
 * the daemon. `ncfg/node.h` says where the store is and why a daemon on
 * another run directory gets none unless one is named; what is said here is
 * the outcome, once, because a node that made itself a new identity is the
 * thing an operator most needs to find afterwards.
 */
static ncfg_node_t *open_node(const options_t *options, const ncfg_main_where_t *where)
{
	const char  *named = options->fuzznet_dir ? options->fuzznet_dir
	                                          : getenv(NCFG_FUZZNET_DIR_ENV);
	char         dir[NCFG_NODE_DIR_MAX];
	char         key[NCFG_NODE_KEY_HEX];
	char         err[NCFG_ERROR_MAX];
	int          made = 0;
	ncfg_node_t *node;

	err[0] = '\0';
	if (!ncfg_node_where(named, strcmp(where->run, NCFG_RUN_DIR_DEFAULT) == 0, dir, &made,
	    err, sizeof(err))) {
		if (err[0]) {
			ncfg_log_emitf("node", NCFG_LOG_WARNING, "no fuzznet node: %s", err);
		}
		return NULL;
	}
	node = ncfg_node_open(dir, made, err, sizeof(err));
	if (!node) {
		ncfg_log_emitf("node", NCFG_LOG_WARNING,
		    "no fuzznet node, and the network is configured as usual: %s", err);
		return NULL;
	}
	ncfg_node_key_hex(ncfg_node_key(node), key);
	if (ncfg_node_found(node) == NCFG_NODE_BESIDE_FACE) {
		ncfg_log_emitf("node", NCFG_LOG_INFO,
		    "fuzznet node %s, loaded from %s beside the process serving it", key, dir);
	} else {
		ncfg_log_emitf("node", NCFG_LOG_INFO, "fuzznet node %s, %s %s", key,
		    ncfg_node_created(node) ? "a new identity made in" : "loaded from", dir);
	}
	err[0] = '\0';
	if (!ncfg_node_publish(node, where->run, err, sizeof(err))) {
		ncfg_log_emitf("node", NCFG_LOG_WARNING, "%s", err);
	}
	return node;
}


/*
 * The round, driven from fuzznet's loop (10.676): the three calls
 * `ncfg_main_outside_*` make for any loop this daemon runs inside, over the
 * run `start` built for its own.
 */
typedef struct {
	const ncfg_main_run_t    *run;
	ncfg_main_outside_t       outside;
	ncfg_seen_t              *seen;
	/* What the 0309 verbs answer from and are judged by: the same policy the
	 * control socket's servers hold, read here on the loop's own thread. */
	const ncfg_main_policy_t *policy;
	ncfg_authz_roots_t        roots;
	/* Whether the `status` permit has been put in step with `observe`. */
	int                       permitted;
	/* `ask` (0312): the socket's dispatcher on this daemon's desk, and the
	 * answers kept for callers paging through them. */
	ncfg_main_ask_t           ask;
	/* Where the events told since the last tick wait to be published. */
	ncfg_main_subscribers_t  *subscribers;
} node_driven_t;

/*
 * fuzznet's `local/permit/status` in step with the `observe` tier (10.688):
 * without it, fuzznet calls the procedure for the node's own user alone, so
 * the GUI's users in netcfgd's group could not ask. `status` is netcfgd's
 * subject, so this setting follows netcfgd's configuration: written where
 * it differs, cleared where the tier is root's. Asked in-process on the
 * loop's first pass, because `fzn_daemon_local` answers only inside it.
 */
static void node_permit(const ncfg_principal_t *observe)
{
	static const char key[] = "host local/permit/status";
	char              grant[96];
	char              line[160];
	char              said[1100];
	int               want = ncfg_main_node_permit(observe, grant, sizeof(grant));
	size_t            n;

	if (want < 0) {
		ncfg_log_emitf("node", NCFG_LOG_INFO,
		    "fuzznet's permit for `status` is left alone: the observe tier is open to %s, "
		    "and a grant names a user or a group",
		    observe && observe->kind == NCFG_PRINCIPAL_ANY ? "any user" : "a name it cannot carry");
		return;
	}
	(void)snprintf(line, sizeof(line), "get setting %s", key);
	n = ncfg_node_local(line, said, sizeof(said) - 1u);
	said[n] = '\0';
	if (want == 0) {
		if (strncmp(said, "ok ", 3) != 0 || strncmp(said, "ok absent", 9) == 0) {
			return; /* none to clear: an absent setting answers `ok absent` */
		}
		(void)snprintf(line, sizeof(line), "remove setting %s", key);
	} else {
		const char *value = strchr(said + (n > 3u ? 3u : n), ' ');
		size_t      length = strlen(grant);

		if (strncmp(said, "ok ", 3) == 0 && value && strncmp(value + 1, grant, length) == 0 &&
		    (value[1 + length] == '\n' || value[1 + length] == '\0')) {
			return; /* in step already */
		}
		(void)snprintf(line, sizeof(line), "set setting %s %s", key, grant);
	}
	n = ncfg_node_local(line, said, sizeof(said) - 1u);
	said[n] = '\0';
	if (strncmp(said, "ok", 2) == 0) {
		ncfg_log_emitf("node", NCFG_LOG_INFO, "fuzznet's permit for `status`: %s",
		    want ? grant : "cleared, the observe tier being root's");
	} else {
		ncfg_log_emitf("node", NCFG_LOG_WARNING,
		    "fuzznet's permit for `status` could not be set: %.200s", n ? said : "no answer");
	}
}

/* An operator of the estate, over fuzznet's remote hop (`daemon_node.c`). */
static size_t node_remote(void *context, const uint8_t key[NCFG_NODE_KEY_LEN], int contact,
    const char *body, size_t length, char *reply, size_t cap)
{
	node_driven_t *driven = context;

	(void)key;
	return ncfg_main_node_remote(driven->policy,
	    driven->run->loop && driven->run->loop->state ? driven->run->loop->state->observed
	                                                  : NULL,
	    contact, body, length, reply, cap);
}

/*
 * A call of one of netcfgd's procedures through fuzznet (`call status
 * [FROM]`, 10.688): a caller on this machine judged by netcfgd's tiers as on
 * the socket, an operator of the estate by the `remote` block, the page as
 * `get status [FROM]` answers it over the remote type.
 */
static size_t node_call(void *context, const char *name, const uint8_t *key,
    const ncfg_peer_t *peer, const char *args, size_t length, char *answer, size_t cap,
    size_t escaped_cap)
{
	node_driven_t  *driven = context;
	struct timespec now;

	if (!key && !peer) {
		return 0u;
	}
	if (strcmp(name, NCFG_NODE_PROCEDURE_ASK_PART) == 0) {
		(void)clock_gettime(CLOCK_MONOTONIC, &now);
		return ncfg_main_ask_part(&driven->ask, key, key ? NULL : peer, args, length, answer,
		    cap, (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u);
	}
	if (strcmp(name, NCFG_NODE_PROCEDURE_ASK) == 0) {
		(void)clock_gettime(CLOCK_MONOTONIC, &now);
		return ncfg_main_ask(&driven->ask, key, key ? NULL : peer, args, length, answer, cap,
		    escaped_cap, (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u);
	}
	if (strcmp(name, NCFG_NODE_PROCEDURE_STATUS) != 0) {
		return 0u;
	}
	return ncfg_main_node_status(driven->policy,
	    driven->run->loop && driven->run->loop->state ? driven->run->loop->state->observed
	                                                  : NULL,
	    key ? NULL : peer, args, length, answer, cap, escaped_cap);
}

/*
 * 0309's first verb, on fuzznet's framing (its sec 843): `get status PATH`
 * writes the observation -- what the control socket's `status` answers -- to
 * PATH and answers `ok LENGTH`. Judged by netcfgd's own tiers against the
 * caller fuzznet read (`observe`, as on the socket), and written only where
 * that caller could have put it (`ncfg_caller_file_create`, 10.680), because
 * this daemon is root and the caller need not be. Answered on the loop's
 * thread between steps of fuzznet's loop, where the state is whole.
 */
static size_t node_answer(void *context, const ncfg_peer_t *peer, const char *line,
    char *reply, size_t cap)
{
	static const char    verb[] = "get status ";
	node_driven_t       *driven = context;
	ncfg_proto_request_t request;
	ncfg_buf_t           status;
	char                 err[NCFG_ERROR_MAX];
	const char          *path;
	int                  wrote;

	if (strncmp(line, verb, sizeof(verb) - 1u) != 0) {
		return 0u;
	}
	path = line + sizeof(verb) - 1u;
	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_STATUS;
	err[0] = '\0';
	if (!ncfg_authz_permitted(&driven->roots, &driven->policy->control,
	        &driven->policy->remote, NCFG_ARRIVED_LOCAL, peer, &request, err, sizeof(err))) {
		wrote = snprintf(reply, cap, "denied %s\n", err);
		return wrote > 0 && (size_t)wrote < cap ? (size_t)wrote : 0u;
	}
	ncfg_buf_init(&status, NCFG_PROTO_MAX_LINE);
	if (!driven->run->loop || !driven->run->loop->state ||
	    !ncfg_daemon_status_encode(driven->run->loop->state->observed, &status, err,
	        sizeof(err)) ||
	    !ncfg_caller_file_create(path, peer->uid, peer->gid, status.data, status.length, err,
	        sizeof(err))) {
		ncfg_buf_free(&status);
		wrote = snprintf(reply, cap, "error %s\n", err[0] ? err : "the status was not written");
		return wrote > 0 && (size_t)wrote < cap ? (size_t)wrote : 0u;
	}
	wrote = snprintf(reply, cap, "ok %zu\n", status.length);
	ncfg_buf_free(&status);
	return wrote > 0 && (size_t)wrote < cap ? (size_t)wrote : 0u;
}

/* A record written to the face's socket from inside the face's loop would
 * wait for an answer only that loop gives, so it is asked in-process: the
 * recorder runs in the pass, and the pass runs in the tick, where fuzznet
 * allows `fzn_daemon_local` (its sec 835). As a follower the same call is
 * asked of the face over its socket by fuzznet, within 5 s (sec 838). */
static void node_begin(void *context)
{
	node_driven_t *driven = context;

	ncfg_seen_in_process(driven->seen, ncfg_node_local);
	ncfg_log_emitf("node", NCFG_LOG_INFO,
	    "running in fuzznet's loop, as its store's face or beside the process that is");
}

static void node_end(void *context)
{
	node_driven_t *driven = context;

	ncfg_seen_in_process(driven->seen, NULL);
}

static size_t node_fds(void *context, int *out, size_t cap)
{
	node_driven_t *driven = context;

	return ncfg_main_outside_fds(driven->run, out, cap);
}

static void node_ready(void *context, int fd)
{
	node_driven_t *driven = context;

	ncfg_main_outside_ready(driven->run, &driven->outside, fd);
}

static int node_tick(void *context)
{
	node_driven_t           *driven = context;
	ncfg_main_round_report_t report;

	if (!driven->permitted) {
		driven->permitted = 1;
		node_permit(driven->policy ? &driven->policy->control.observe : NULL);
	}
	/* **netcfgd's events into fuzznet's** (10.703), from the tick, which is
	 * the one place fuzznet takes them: for another host reading `events`
	 * from a cursor, since no stream crosses the estate (fuzznet sec 866).
	 * Thin, as fuzznet's are: the subject says what to re-read. */
	if (driven->subscribers && driven->subscribers->unpublished) {
		static const char *const subject[] = {
			[NCFG_PROTO_EVENT_OBSERVED] = "net-observed",
			[NCFG_PROTO_EVENT_RELOADED] = "net-reloaded",
			[NCFG_PROTO_EVENT_DRIFT] = "net-drift",
			[NCFG_PROTO_EVENT_CONFIRM_ARMED] = "net-armed",
			[NCFG_PROTO_EVENT_CONFIRM_RESOLVED] = "net-resolved",
		};
		unsigned pending = driven->subscribers->unpublished;
		size_t   kind;

		/* A kind added to the protocol without a subject here would go
		 * unpublished without a word, so the build refuses instead. */
		_Static_assert(sizeof(subject) / sizeof(subject[0]) == NCFG_PROTO_EVENT_COUNT,
		    "every event kind needs a fuzznet subject");

		driven->subscribers->unpublished = 0;
		for (kind = 0; kind < sizeof(subject) / sizeof(subject[0]); kind++) {
			if ((pending & (1u << kind)) && subject[kind]) {
				(void)ncfg_node_publish_event(subject[kind]);
			}
		}
	}
	return ncfg_main_outside_tick(driven->run, &driven->outside, &report) && report.stopping;
}

/*
 * Serve the node, if asked to: 1 where the daemon ran in fuzznet's loop and
 * has been asked to stop, 0 where its own loop is to run -- because it was not
 * asked, or fuzznet's loop ended by itself, which is said.
 */
static int serve_node(ncfg_node_t *node, const options_t *options, const ncfg_main_run_t *run,
    ncfg_seen_t *seen, const ncfg_main_policy_t *policy, ncfg_main_desk_t *desk,
    const char *run_dir)
{
	/*
	 * **fuzznet's socket in the run directory, unless one is named**
	 * (10.683): `/run/netcfgd/fuzznet.sock` on a machine, beside the control
	 * socket it will replace. fuzznet's default is per user, so a non-root
	 * `ncfg` or GUI looking there would find its own runtime directory and
	 * never root's daemon -- and a client that had to be told where would be
	 * a client with configuration of its own, which the holder ruled out.
	 */
	static char        socket_arg[NCFG_NODE_DIR_MAX + 32u];
	static const char *args[33];
	size_t             arg_count = 0;
	size_t             at;
	int                named = 0;

	static node_driven_t driven;
	ncfg_node_loop_t     loop;
	char                 err[NCFG_ERROR_MAX];
	ncfg_node_serve_t    served;

	/* Whenever there is a node (decision 0311): fuzznet is this daemon's
	 * store and its protocols, not an option. A daemon with no node -- a
	 * test, a second instance on another run directory -- has its own loop. */
	if (!node) {
		return 0;
	}
	memset(&driven, 0, sizeof(driven));
	driven.run = run;
	ncfg_main_outside_begin(run, &driven.outside);
	driven.seen = seen;
	driven.policy = policy;
	driven.roots = ncfg_authz_roots_default();
	driven.ask.answer = ncfg_main_answer;
	driven.ask.context = desk;
	driven.ask.control = &policy->control;
	driven.ask.remote = &policy->remote;
	driven.ask.roots = driven.roots;
	driven.subscribers = desk->subscribers;
	loop.context = &driven;
	loop.begin = node_begin;
	loop.end = node_end;
	loop.fds = node_fds;
	loop.ready = node_ready;
	loop.tick = node_tick;
	loop.local = node_answer;
	loop.remote = node_remote;
	loop.call = node_call;
	for (at = 0; at < options->fuzznet_arg_count && arg_count < 32u; at++) {
		if (strncmp(options->fuzznet_args[at], "--socket", 8u) == 0) {
			named = 1;
		}
		args[arg_count++] = options->fuzznet_args[at];
	}
	if (!named && arg_count < 32u) {
		(void)snprintf(socket_arg, sizeof(socket_arg), "--socket=%s/fuzznet.sock", run_dir);
		args[arg_count++] = socket_arg;
	}
	err[0] = '\0';
	served = ncfg_node_serve(node, args, arg_count, options->argv, &loop, err, sizeof(err));
	ncfg_main_ask_free(&driven.ask);
	if (served == NCFG_NODE_SERVE_STOPPED) {
		return 1;
	}
	ncfg_log_emitf("node", NCFG_LOG_WARNING, "%s, so this daemon runs its own loop", err);
	return 0;
}

static int start(const options_t *options)
{
	uint64_t                 next_tick = 0;
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
	ncfg_node_t             *node = NULL;
	ncfg_watch_marks_t       compiled_from = { NULL, 0, 0 };
	int                      compiled_from_ok = 0;
	const ncfg_principal_t  *reach[3];
	char                     rendered[NCFG_MAIN_PATH_MAX];
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
	/* And the hostapd this daemon would start -- `ncfg_hostapd_binary`, the
	 * one the start runs, `/usr/sbin` first -- so what it was built with is
	 * asked of that one (10.600). `PATH` alone missed it where `/usr/sbin`
	 * is not on `PATH`, leaving 802.11ax off for no reason. */
	{
		char *hostapd = ncfg_hostapd_binary();

		(void)snprintf(source.roots.hostapd, sizeof(source.roots.hostapd), "%s",
		    hostapd ? hostapd : "");
		free(hostapd);
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
	/*
	 * **The probe first, and the configuration's fingerprint with it**, so
	 * that an edit made while this daemon starts is not lost. The compile
	 * below and the watch opened much further down are not one moment: an
	 * edit landing between them raises no event, and before this it was
	 * applied by nobody until the next edit. Measured under procd in an
	 * OpenWrt vm (project.md 10.672): a config edited as procd respawned the
	 * daemon was never applied. The fingerprint is taken again once the watch
	 * is open, and a difference is a second compile. The probe writes into
	 * the directory, so it runs before the first fingerprint and not between
	 * the two -- see its own comment below for what writing after the watch
	 * cost.
	 */
	report_writability(where.config);
	{
		char        conf_d[NCFG_MAIN_PATH_MAX + 8];
		const char *directories[2];

		(void)snprintf(conf_d, sizeof(conf_d), "%s/conf.d", where.config);
		directories[0] = where.config;
		directories[1] = conf_d;
		compiled_from_ok = ncfg_watch_fingerprint_of(directories, 2u, &compiled_from);
	}
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
	/* fuzznetd's own default socket for this user, or NCFG_FUZZNET_SOCKET
	 * where a test or an unusual layout names another (10.666). A recorder
	 * that could not be made records nothing; that is not a reason to stop. */
	loop.seen = ncfg_seen_new(getenv("NCFG_FUZZNET_SOCKET"));
	if (!loop.probes || !loop.sims) {
		ncfg_probes_free(loop.probes);
		ncfg_sims_free(loop.sims);
		ncfg_seen_free(loop.seen);
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
		ncfg_seen_free(loop.seen);
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
	/*
	 * **Before the watchers, because it writes into the directory they
	 * watch.** The probe is a real `open(O_CREAT|O_EXCL)` and an `unlink`,
	 * which bumps the configuration directory's own mtime -- and the
	 * polling watcher's baseline is the mtime of that directory and
	 * everything in it, taken when the watch opens. Probing afterwards left
	 * the baseline one modification behind the directory, so the first tick
	 * reported a configuration change that had not happened.
	 *
	 * Measured: with inotify exhausted (or `--poll-config`), the daemon
	 * recompiled on its first tick on every start -- `.netcfgd-write-probe`
	 * created and unlinked 4ms after the baseline, visible in `strace` and
	 * in the directory's mtime moving with nothing having touched it. The
	 * recompile re-materialises every hook under `<run>/hooks/`, which is
	 * how it was found: `tests/live/hooks.sh` tampers with a materialised
	 * hook and expects the content hash to refuse it, and the rewrite put
	 * the original back before the hash was ever read. 0063's control was
	 * silently disarmed on any machine without a spare inotify instance.
	 *
	 * So the invariant is the ordering: **nothing this daemon does may write
	 * into a watched directory after `ncfg_main_watchers_open`.** A refresh
	 * after the fact would hide a real edit made while the daemon was
	 * starting, which is the opposite mistake. So the probe now runs before
	 * the first compile, above, beside the fingerprint that catches that edit.
	 */

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
		ncfg_watch_marks_free(&compiled_from);
		code = cannot("this daemon cannot open the descriptors it watches", err);
		goto done;
	}
	/* What changed between the first compile and the watch, compiled now. */
	{
		char               conf_d[NCFG_MAIN_PATH_MAX + 8];
		const char        *directories[2];
		ncfg_watch_marks_t now;

		(void)snprintf(conf_d, sizeof(conf_d), "%s/conf.d", where.config);
		directories[0] = where.config;
		directories[1] = conf_d;
		if (compiled_from_ok && ncfg_watch_fingerprint_of(directories, 2u, &now)) {
			if (!ncfg_watch_marks_same(&compiled_from, &now)) {
				ncfg_log_emitf("config", NCFG_LOG_INFO,
				    "the configuration changed while this daemon was starting; compiling "
				    "it again");
				err[0] = '\0';
				if (!ncfg_daemon_state_reload(&state, err, sizeof(err))) {
					ncfg_log_emitf("config", NCFG_LOG_ERROR,
					    "the configuration does not compile:\n%s",
					    state.diagnostics ? state.diagnostics : err);
				}
			}
			ncfg_watch_marks_free(&now);
		}
		ncfg_watch_marks_free(&compiled_from);
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
	/* **The world's, not the machine's read a second time.**
	 *
	 * The same answer the reconcile pass gives a radio back on: two readings
	 * of "who else is managing this" would be two answers to one question.
	 * This said that and then called `ncfg_contention_machine` itself, which
	 * is the machine's `/run` and `/proc` and nothing else -- while the world
	 * had already layered `NCFG_RUN_ROOT` and `NCFG_PROC` over them for the
	 * reason `contention_roots_from_environment` gives. So under a fixture the
	 * two readings genuinely disagreed, in the direction that hides the
	 * finding: the pass saw the claim and every answer to a `plan` request
	 * said there was no other manager.
	 *
	 * What it cost is a banner. `gui/src/wifi_view.cpp` reads contention out
	 * of the plan rather than asking separately, so `live_wifi` asserting that
	 * a radio NetworkManager has claimed is called out by name -- with the
	 * `nmcli` command that hands it over -- failed against a daemon that had
	 * been told exactly where to look. Borrowing the field rather than
	 * recomputing it is what makes the sentence above true; `world` is opened
	 * further up this function and outlives the desk.
	 */
	desk.contention = world.contention;
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
		/*
		 * Said out loud, because a listening socket that reaches the network
		 * is the one thing about this daemon an operator should never
		 * discover by finding the file.
		 *
		 * **And it names who it is open to**, which this omitted. The three
		 * tier flags say what a caller may do and the agent says who the
		 * caller is allowed to be -- a line carrying only the first reports a
		 * socket open to everything without saying to whom, which is the half
		 * an operator reads the line for.
		 */
		ncfg_log_emitf("control", NCFG_LOG_NOTE,
		    "remote access is open on %s to `%s` -- observe %d, wifi %d, admin %d",
		    where.remote_socket,
		    ncfg_cli_principal_render(&policy.remote.agent, rendered, sizeof(rendered)),
		    policy.remote.observe, policy.remote.wifi, policy.remote.admin);
	}
	/* One line, carrying how the configuration is watched and where the
	 * daemon can be reached -- the shape the Rust emits. `has_watch` is false
	 * when the watch could not be opened, which `daemon_watchers.c` has
	 * already said in its own words; the line still names the directory,
	 * because what is being watched is true either way. */
	ncfg_log_emitf("config", NCFG_LOG_INFO, "watching %s via %s, socket %s", where.config,
	    watchers.has_watch
	        ? ncfg_watch_mechanism_name((int)ncfg_watch_mechanism(&watchers.watch))
	        : "nothing",
	    ncfg_daemon_server_path(local));

	/*
	 * **What was already here, before anything is adopted or applied.**
	 *
	 * systemd prints `Found left-over process N ... This usually indicates
	 * unclean termination of a previous run` on every start, because
	 * `KillMode=process` deliberately leaves the backends up (0134, 0142) --
	 * and measured on systemd 257, no unit setting suppresses it while a
	 * process of netcfgd's remains anywhere under the unit's cgroup. So the
	 * two sentences a real unclean stop produces are the two printed every
	 * ordinary restart, and 0177 is what that cost once.
	 *
	 * netcfgd can answer what systemd cannot: whose process it is. This reads
	 * the control group and says, of each survivor, whether the previous run
	 * wrote it down.
	 *
	 * **Here and not later**, because the question is what netcfgd inherited:
	 * adoption is what turns an inherited process back into netcfgd's, so a
	 * report after the first pass would call every survivor accounted for and
	 * could never see the case this exists for.
	 */
	ncfg_leftovers_report(where.run);

	/*
	 * **Observe once before anything reads the state**, which the Rust does
	 * inside `State::new` -- reload and reobserve together, so no caller ever
	 * meets a state that has a configuration and no machine.
	 *
	 * This did not, and the cost was the case commit-confirm exists for at
	 * its worst. A daemon that died inside a window restarted, found the
	 * window, announced the revert, and then refused it: "nothing has been
	 * observed of this machine, so the plan back to the last-good
	 * configuration did not run". The planner is right to refuse -- a revert
	 * with no observation is a plan against a machine nobody has looked at --
	 * so the fix is the observation, not the refusal. The change stayed live
	 * with no process left that could take it back, which is exactly what
	 * `apply --confirm-within` promises will not happen.
	 *
	 * A failure here is not fatal: the loop observes on its own first pass,
	 * and a daemon that cannot see the machine at startup has worse news to
	 * give than this. It is said, because the two callers below quietly do
	 * less without it.
	 */
	err[0] = '\0';
	if (!ncfg_daemon_state_reobserve(&state, NULL, err, sizeof(err))) {
		ncfg_log_emitf("observe", NCFG_LOG_WARNING,
		    "the machine could not be observed at startup (%s), so a confirm window "
		    "found here cannot be reverted until the first pass of the loop", err);
	}

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
	node = open_node(options, &where);
	/* The node's store names its face, which is where a record goes; a
	 * socket the environment names is a test's or an unusual layout's, and
	 * is left as it was. */
	if (node && loop.seen && !getenv("NCFG_FUZZNET_SOCKET")) {
		ncfg_seen_use_store(loop.seen, ncfg_node_dir(node));
	}

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
	/* Kept across rounds, so a daemon asked something every second still
	 * ticks (`ncfg_main_run_t::next_tick`, project.md 10.678). */
	run.next_tick = &next_tick;
	err[0] = '\0';
	if (!serve_node(node, options, &run, loop.seen, &policy, &desk, where.run) &&
	    !ncfg_main_serve(&run, err, sizeof(err))) {
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
	ncfg_seen_free(loop.seen);
	ncfg_node_close(node);
	ncfg_confirm_armed_free(&armed);
	ncfg_main_policy_free(&policy);
	ncfg_daemon_state_free(&state);
	return code;
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
	options.argv = argv;
	/*
	 * **No gate, and the loop runs.** 0265 settled it: this build reconciles
	 * when it is started, the way the Rust does. What stood here was a refusal
	 * and -- when the flag was given -- a notice saying the loop was starting
	 * anyway, and both were about a gate that no longer exists.
	 *
	 * A cautious start is `--no-apply-on-start`, which is the spelling the
	 * Rust uses for the same thing.
	 */
	if (options.try_the_c_daemon) {
		ncfg_log_emitf("control", NCFG_LOG_NOTE,
		    "`--try-the-c-daemon` is accepted and does nothing: this build's reconcile "
		    "loop runs by default. Nothing needs the flag, and `--no-apply-on-start` "
		    "is what asks a daemon to watch without changing anything");
	}
	return start(&options);
}
