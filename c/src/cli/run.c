/*
 * run.c -- which verb, and what it leaves with.
 *
 * WHY THE DISPATCH IS A LIST AND THE HELP IS A LIST
 *   `reload` drifted for a whole milestone: the request was in the protocol,
 *   in `doc/schema/socket.json` and in the authorisation table, and no shipped
 *   client could send it. Nothing was red, because nothing compared the two
 *   lists. So every command named in the usage text has an arm here, and the
 *   test walks the usage looking for one that does not.
 *
 * WHAT AN ARM CAN BE
 *   Three things. A verb this wave carries, which runs. A verb whose module is
 *   not ported, which says so and names the module -- `ncfg_cli_print_status`
 *   is finished and tested, and what is missing is the observer that would
 *   feed it, so the refusal says that rather than pretending the command does
 *   not exist. And a verb that is a refusal in the Rust too, like `ncfg secret
 *   get`, which keeps the Rust's sentence because the sentence is the point.
 *
 * WHY ERRORS GO TO stderr WITHOUT GOING THROUGH out.c
 *   0261 changed `println!` and left `eprintln!` alone deliberately: stderr is
 *   not usually the pipe that closes, and by the time it matters stdout has
 *   already ended the process. This is that rule, so a diagnostic is a plain
 *   write to stderr whose failure is ignored -- the same shape
 *   `ncfg_log_emit` has, without the daemon's prefix, because `ncfg: ` is what
 *   this program has always said.
 */
#include "cli_internal.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/config.h"
#include "ncfg/hooks.h"
#include "ncfg/lower.h"
#include "ncfg/log.h"
#include "ncfg/state.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* What arrived when something else was expected, in the Rust's words. */
static const char *describe_answer(const ncfg_proto_response_t *response, char *out,
    size_t out_size)
{
	switch (response->kind) {
	case NCFG_PROTO_RESP_OK:
		return "ok";
	case NCFG_PROTO_RESP_JOURNAL:
		return "a journal";
	case NCFG_PROTO_RESP_WIFI_SCAN:
		return "a scan";
	case NCFG_PROTO_RESP_WIFI_STATUS:
		return "a radio status";
	case NCFG_PROTO_RESP_AP_STATIONS:
		return "a station list";
	case NCFG_PROTO_RESP_RADIOS:
		return "a radio list";
	case NCFG_PROTO_RESP_MODEMS:
		return "a modem list";
	case NCFG_PROTO_RESP_PROFILES:
		return "a profile list";
	case NCFG_PROTO_RESP_ERROR: {
		char message[NCFG_CLI_TEXT_MAX];

		(void)snprintf(out, out_size, "an error: %s",
		    ncfg_cli_text(response->u.error.message, message, sizeof(message)));
		return out;
	}
	default:
		/*
		 * The Rust prints the raw JSON here, truncated -- it decodes into a
		 * narrow mirror and has nothing else to say about a kind outside it.
		 * This module decodes every kind, so the tag is the honest and
		 * shorter answer; a whole document in a diagnostic is not a
		 * diagnostic either way.
		 */
		(void)snprintf(out, out_size, "an unexpected answer: %s",
		    ncfg_proto_response_name(response->kind));
		return out;
	}
}

/* `ncfg: <sentence>` on stderr, which is what this program has always said. */
static int fail(const char *message)
{
	(void)fprintf(stderr, "ncfg: %s\n", message);
	return NCFG_CLI_EXIT_FAILED;
}

/*
 * The same, composed.
 *
 * **Straight to the stream rather than through a buffer**, which is the point:
 * a sentence rendered into a fixed array first is a sentence that can be
 * truncated, and the half that gets cut is the end -- which is where every one
 * of these says what to do about it.
 */
static int failf(const char *format, ...)
{
	va_list args;

	(void)fprintf(stderr, "ncfg: ");
	va_start(args, format);
	(void)vfprintf(stderr, format, args);
	va_end(args);
	(void)fputc('\n', stderr);
	return NCFG_CLI_EXIT_FAILED;
}

/*
 * A verb whose module has not landed, saying which one.
 *
 * **Named rather than hidden.** A command that answered `unknown command` for
 * something the usage text offers would be the drift this file exists to
 * refuse; one that answered from a different source -- the last observation in
 * `/run`, say -- would be worse, because it would look right.
 */
static int not_in_this_wave(const char *verb, const char *needs)
{
	return failf("`ncfg %s` is not in this wave of the C port: it needs %s, which is "
	    "not ported yet", verb, needs);
}

/* What the loader and the observer are called, so the two sentences agree. */
#define NEEDS_OBSERVER   "the netlink dump the observer is built from"
#define NEEDS_PROVENANCE "the provenance table, which 0263 does not port"
#define NEEDS_WRITERS    "the settings writer that puts a drop-in where netcfgd reads it"

/*
 * `--json` is not in this wave, and is refused rather than ignored.
 *
 * A flag silently ignored is the fault the parser's unknown-option arm exists
 * to prevent, one level up: somebody who passed `--json` and got a table would
 * read the table as the machine-readable form.
 */
static int json_not_in_this_wave(void)
{
	return fail("`--json` is not in this wave of the C port: there is no writer here "
	    "for the daemon's answers yet, and printing the human form while accepting "
	    "the flag would be a flag silently ignored");
}

/* ------------------------------------------------------------------------ *
 * The socket verbs
 * ------------------------------------------------------------------------ */

/* Where the socket is, from `--run-dir`, `NCFG_RUN_DIR` or the default. */
static const char *socket_for(const ncfg_cli_options_t *options, char *out, size_t out_size)
{
	char run_dir[NCFG_CLI_TEXT_MAX];

	(void)ncfg_state_resolve_dir(options->run_dir, run_dir, sizeof(run_dir));
	return ncfg_cli_socket_path(run_dir, out, out_size);
}

/*
 * Ask, and hand back the message, or print the refusal and say what to exit
 * with.
 *
 * **A refusal is an answer**, which is a different thing from not reaching the
 * daemon, and the sentence names the tier that would have been needed (0013).
 * Replacing it with wording of this program's own would throw away the part
 * that says what to do about it.
 */
static int ask_or_fail(const ncfg_cli_options_t *options, const ncfg_proto_request_t *request,
    ncfg_proto_message_t *out, int *code)
{
	char path[NCFG_CLI_TEXT_MAX];
	char err[NCFG_ERROR_MAX];

	if (!socket_for(options, path, sizeof(path))) {
		*code = fail("the run directory makes a socket path too long to connect to");
		return 0;
	}
	if (!ncfg_cli_ask(path, request, out, err, sizeof(err))) {
		*code = fail(err);
		return 0;
	}
	if (out->kind != NCFG_PROTO_MESSAGE_RESPONSE) {
		ncfg_proto_message_free(out);
		*code = fail("the daemon sent something that is not a response");
		return 0;
	}
	if (out->u.response.kind == NCFG_PROTO_RESP_ERROR) {
		char message[NCFG_ERROR_MAX];

		/* Copied out before the message is freed: the daemon's sentence
		 * points into the line the decoder owns, and the refusal is what the
		 * caller is about to print. */
		(void)ncfg_cli_text(out->u.response.u.error.message, message, sizeof(message));
		ncfg_proto_message_free(out);
		*code = fail(message);
		return 0;
	}
	return 1;
}

/*
 * One request whose whole answer is `ok`.
 *
 * What to say afterwards is the caller's, because every one of them says
 * something different about what it just did -- and the sentence names the
 * interface or the network it was given, which this does not have.
 */
static int ask_for_ok(const ncfg_cli_options_t *options, const ncfg_proto_request_t *request)
{
	ncfg_proto_message_t message;
	int                  code = NCFG_CLI_EXIT_FAILED;

	if (!ask_or_fail(options, request, &message, &code)) {
		return code;
	}
	if (message.u.response.kind != NCFG_PROTO_RESP_OK) {
		char what[NCFG_CLI_SENTENCE_MAX];

		code = failf("the daemon sent %s",
		    describe_answer(&message.u.response, what, sizeof(what)));
		ncfg_proto_message_free(&message);
		return code;
	}
	ncfg_proto_message_free(&message);
	return NCFG_CLI_EXIT_OK;
}

/*
 * Which wireless interface, when the command line did not say.
 *
 * Naming an interface every time is friction on the machine this is for -- a
 * laptop with one radio -- so where there is exactly one, that is the answer,
 * and where there are several the error lists them rather than picking.
 *
 * **The list comes from the daemon here and from the configuration in the
 * Rust**, which is a divergence and is why the sentences differ. The Rust
 * compiles the config and counts `device` blocks carrying a `wifi` section;
 * this wave has no loader, and `radios` is the same question asked of the
 * machine. Saying "no wireless device in the configuration" while having read
 * the kernel would be a sentence that sends somebody to edit a file about a
 * fact that came from somewhere else.
 */
static int wireless_interface(const ncfg_cli_options_t *options, const char *given, char *out,
    size_t out_size, int *code)
{
	ncfg_proto_request_t request;
	ncfg_proto_message_t message;
	ncfg_buf_t           listed;
	size_t               at;
	size_t               count;

	if (given) {
		(void)snprintf(out, out_size, "%s", given);
		return 1;
	}
	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_RADIOS;
	if (!ask_or_fail(options, &request, &message, code)) {
		return 0;
	}
	if (message.u.response.kind != NCFG_PROTO_RESP_RADIOS) {
		ncfg_proto_message_free(&message);
		*code = fail("the daemon sent something that is not a radio list");
		return 0;
	}
	count = message.u.response.u.radios.count;
	if (count == 1) {
		(void)ncfg_cli_text(message.u.response.u.radios.items[0].interface, out, out_size);
		ncfg_proto_message_free(&message);
		return 1;
	}
	ncfg_buf_init(&listed, 0);
	for (at = 0; at < count; at++) {
		char name[NCFG_CLI_TEXT_MAX];

		if (at > 0) {
			ncfg_buf_add_text(&listed, ", ");
		}
		ncfg_buf_add_text(&listed,
		    ncfg_cli_text(message.u.response.u.radios.items[at].interface, name,
		    sizeof(name)));
	}
	ncfg_proto_message_free(&message);
	if (count == 0) {
		*code = fail("no wireless device on this machine. Name the interface, or "
		    "`ncfg wifi radios` lists what netcfgd can see");
	} else {
		*code = failf("this machine has %zu wireless devices (%s); name the one you "
		    "mean", count, ncfg_buf_text(&listed));
	}
	ncfg_buf_free(&listed);
	return 0;
}

/*
 * `ncfg wifi activate|deactivate <radio>`.
 *
 * **The interface is named rather than defaulted**, unlike `scan` and
 * `status`. Those act on "the radio", which is unambiguous on a machine with
 * one. This decides *which* radio netcfgd takes on, and a machine with two is
 * exactly where that question is being asked -- defaulting would pick one of
 * them for somebody who has more than one for a reason.
 */
static int radio_set(const ncfg_cli_options_t *options, const char *subcommand,
    const char *interface)
{
	ncfg_proto_request_t request;
	int                  activate = strcmp(subcommand, "activate") == 0;
	int                  code;

	if (!interface) {
		return failf("`ncfg wifi %s` needs the name of a radio. `ncfg wifi radios` "
		    "lists them", subcommand);
	}
	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_RADIO_SET;
	request.u.radio_set.interface = ncfg_proto_str(interface);
	request.u.radio_set.activate = (unsigned char)(activate ? 1 : 0);
	code = ask_for_ok(options, &request);
	if (code != NCFG_CLI_EXIT_OK) {
		return code;
	}
	if (activate) {
		ncfg_out_writef("netcfgd manages `%s` now, and will run a supplicant on it. "
		    "`ncfg wifi scan %s` should find something\n", interface, interface);
	} else {
		ncfg_out_writef("`%s` is no longer netcfgd's\n", interface);
	}
	return NCFG_CLI_EXIT_OK;
}

static int command_wifi(const ncfg_cli_options_t *options, const char **positional,
    size_t count)
{
	const char          *subcommand;
	const char          *first = count > 1 ? positional[1] : NULL;
	char                 interface[NCFG_CLI_TEXT_MAX];
	ncfg_proto_request_t request;
	ncfg_proto_message_t message;
	int                  code = NCFG_CLI_EXIT_FAILED;

	if (count == 0) {
		/*
		 * **`clients` was missing from this list and not from the code.** It
		 * has worked since access points did, and `netcfgd.conf.example` tells
		 * the reader to use it -- so the one place somebody looks to find out
		 * what `ncfg wifi` can do was the only place that did not mention it.
		 * 0201.
		 */
		return fail("`ncfg wifi` needs a subcommand: radios, activate, deactivate, "
		    "scan, status, add, forget, connect, disconnect or clients");
	}
	subcommand = positional[0];

	/* `add` writes the configuration and `forget` is the same write backwards;
	 * both need the loader, and neither needs a daemon -- which is the point,
	 * since a machine with no network yet is a machine where nothing else is
	 * running either. */
	if (strcmp(subcommand, "add") == 0) {
		return not_in_this_wave("wifi add", NEEDS_WRITERS);
	}
	if (strcmp(subcommand, "forget") == 0) {
		return not_in_this_wave("wifi forget", NEEDS_WRITERS);
	}
	if (options->json) {
		return json_not_in_this_wave();
	}

	memset(&request, 0, sizeof(request));
	if (strcmp(subcommand, "radios") == 0) {
		request.kind = NCFG_PROTO_REQ_RADIOS;
	} else if (strcmp(subcommand, "activate") == 0 ||
	    strcmp(subcommand, "deactivate") == 0) {
		return radio_set(options, subcommand, first);
	} else if (strcmp(subcommand, "scan") == 0 || strcmp(subcommand, "status") == 0 ||
	    strcmp(subcommand, "disconnect") == 0 || strcmp(subcommand, "clients") == 0) {
		if (!wireless_interface(options, first, interface, sizeof(interface), &code)) {
			return code;
		}
		request.kind = strcmp(subcommand, "scan") == 0 ? NCFG_PROTO_REQ_WIFI_SCAN
		    : strcmp(subcommand, "status") == 0 ? NCFG_PROTO_REQ_WIFI_STATUS
		    : strcmp(subcommand, "disconnect") == 0 ? NCFG_PROTO_REQ_WIFI_DISCONNECT
		    : NCFG_PROTO_REQ_AP_STATIONS;
		request.u.interface = ncfg_proto_str(interface);
	} else if (strcmp(subcommand, "connect") == 0) {
		if (!first) {
			return fail("`ncfg wifi connect` needs the id of a `network` block. It "
			    "joins networks the configuration already describes; adding one "
			    "means editing the config.");
		}
		if (!wireless_interface(options, count > 2 ? positional[2] : NULL, interface,
		    sizeof(interface), &code)) {
			return code;
		}
		request.kind = NCFG_PROTO_REQ_WIFI_CONNECT;
		request.u.wifi_connect.interface = ncfg_proto_str(interface);
		request.u.wifi_connect.network = ncfg_proto_str(first);
	} else {
		return failf("unknown wifi subcommand `%s`; try scan, status, clients, add, "
		    "forget, connect or disconnect", subcommand);
	}

	if (request.kind == NCFG_PROTO_REQ_WIFI_DISCONNECT) {
		code = ask_for_ok(options, &request);
		if (code == NCFG_CLI_EXIT_OK) {
			ncfg_out_line("disconnected");
		}
		return code;
	}
	if (request.kind == NCFG_PROTO_REQ_WIFI_CONNECT) {
		code = ask_for_ok(options, &request);
		if (code == NCFG_CLI_EXIT_OK) {
			/* **It has joined by the time this prints.** Since 0197 the
			 * daemon waits for the association and reports what happened, so
			 * a failure arrives as an error and never reaches here. The old
			 * text -- "joining; `ncfg wifi status` says whether it worked" --
			 * was the program admitting it did not know the answer to the
			 * question it had just been asked. */
			ncfg_out_writef("joined `%s` on %s\n", first, interface);
		}
		return code;
	}

	if (!ask_or_fail(options, &request, &message, &code)) {
		return code;
	}
	switch (message.u.response.kind) {
	case NCFG_PROTO_RESP_WIFI_SCAN:
		ncfg_cli_print_scan(&message.u.response.u.wifi_scan);
		break;
	case NCFG_PROTO_RESP_WIFI_STATUS:
		ncfg_cli_print_wifi_status(&message.u.response.u.wifi_status);
		break;
	case NCFG_PROTO_RESP_AP_STATIONS:
		ncfg_cli_print_stations(&message.u.response.u.ap_stations);
		break;
	case NCFG_PROTO_RESP_RADIOS:
		ncfg_cli_print_radios(message.u.response.u.radios.items,
		    message.u.response.u.radios.count);
		break;
	default: {
		char what[NCFG_CLI_SENTENCE_MAX];

		code = failf("the daemon sent %s",
		    describe_answer(&message.u.response, what, sizeof(what)));
		ncfg_proto_message_free(&message);
		return code;
	}
	}
	ncfg_proto_message_free(&message);
	return NCFG_CLI_EXIT_OK;
}

/*
 * `ncfg modem` -- which SIM source each modem is on.
 *
 * One subcommand and it is the default, so `ncfg modem` on its own works. A
 * name that is not `status` is refused rather than ignored: silently listing
 * for `ncfg modem swtich` would read as the typo having worked.
 */
static int command_modem(const ncfg_cli_options_t *options, const char **positional,
    size_t count)
{
	ncfg_proto_request_t request;
	ncfg_proto_message_t message;
	int                  code = NCFG_CLI_EXIT_FAILED;

	if (count > 0 && strcmp(positional[0], "status") != 0) {
		return failf("unknown modem subcommand `%s`; `ncfg modem` and `ncfg modem "
		    "status` both report what each modem is on", positional[0]);
	}
	if (options->json) {
		return json_not_in_this_wave();
	}
	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_MODEM_LIST;
	if (!ask_or_fail(options, &request, &message, &code)) {
		return code;
	}
	if (message.u.response.kind != NCFG_PROTO_RESP_MODEMS) {
		char what[NCFG_CLI_SENTENCE_MAX];

		code = failf("the daemon sent %s",
		    describe_answer(&message.u.response, what, sizeof(what)));
		ncfg_proto_message_free(&message);
		return code;
	}
	ncfg_cli_print_modems(message.u.response.u.modems.items,
	    message.u.response.u.modems.count);
	ncfg_proto_message_free(&message);
	return NCFG_CLI_EXIT_OK;
}

/* Stream events from the daemon until interrupted. */
static int command_monitor(const ncfg_cli_options_t *options)
{
	char path[NCFG_CLI_TEXT_MAX];
	char err[NCFG_ERROR_MAX];

	if (options->json) {
		return json_not_in_this_wave();
	}
	if (!socket_for(options, path, sizeof(path))) {
		return fail("the run directory makes a socket path too long to connect to");
	}
	if (!ncfg_cli_stream(path, err, sizeof(err))) {
		return fail(err);
	}
	return NCFG_CLI_EXIT_OK;
}

/*
 * One request that is answered `ok` and nothing else: reload, confirm, revert.
 *
 * `reload` exits non-zero on a config that does not compile, and that is
 * deliberate: a config that does not compile leaves the last good state in
 * effect, so this is a report and not a failed change -- but the file on disk
 * is not what is running, and a script must not read that as success. The
 * daemon's own diagnostics, which name a file and a line, are the message.
 */
static int command_simple(const ncfg_cli_options_t *options, ncfg_proto_request_kind_t kind,
    const char *said)
{
	ncfg_proto_request_t request;
	int                  code;

	memset(&request, 0, sizeof(request));
	request.kind = kind;
	code = ask_for_ok(options, &request);
	if (code == NCFG_CLI_EXIT_OK) {
		ncfg_out_line(said);
	}
	return code;
}

/* ------------------------------------------------------------------------ *
 * The verbs that begin with a compile
 * ------------------------------------------------------------------------ */

/*
 * Compile the configuration, and hand back the document.
 *
 * **An empty config directory is not an error**, and used to be one. It is the
 * state a fresh install is in: the package ships no configuration and
 * `debian/postinst` says so, so every `ncfg` command that compiled met a fatal
 * `no configuration found` on a machine that was working exactly as designed.
 * The daemon has always disagreed -- it compiles the same empty source set to
 * the default document and serves a socket from it -- and two answers to "what
 * does an empty directory mean" is the drift `netcfgd-host` exists to prevent.
 *
 * **The hooks are recorded and not written.** Of the paths through here, only
 * `apply` needs the scripts on disk; every other one is read-only and used to
 * write them anyway, because the compiler did it on their behalf. `ncfg plan`'s
 * own help says it changes nothing.
 */
static ncfg_document_t *compile_config(const ncfg_cli_options_t *options, char *run_dir,
    size_t run_dir_size, char *err, size_t err_size)
{
	char                  config_dir[NCFG_CLI_TEXT_MAX];
	char                  factory_dir[NCFG_CLI_TEXT_MAX];
	ncfg_config_sources_t sources = { NULL, 0, 0 };
	ncfg_lower_diags_t    diags = { NULL, 0, 0, 0 };
	ncfg_pending_hooks_t *pending;
	ncfg_document_t      *document;

	(void)ncfg_config_resolve_dir(options->config_dir, config_dir, sizeof(config_dir));
	(void)ncfg_config_resolve_factory_dir(options->factory_dir, factory_dir,
	    sizeof(factory_dir));
	(void)ncfg_state_resolve_dir(options->run_dir, run_dir, run_dir_size);

	if (!ncfg_config_load_with_profile(factory_dir, config_dir, &sources, err, err_size)) {
		ncfg_config_sources_free(&sources);
		return NULL;
	}
	pending = ncfg_pending_hooks_new(run_dir, err, err_size);
	if (!pending) {
		ncfg_config_sources_free(&sources);
		return NULL;
	}
	document = ncfg_config_compile(&sources, ncfg_pending_hooks_sink(pending), &diags, err,
	    err_size);
	if (!document) {
		size_t at;

		/*
		 * **Every diagnostic, not just the first.** A configuration with three
		 * mistakes in it is three round trips if only one is reported, and
		 * each of the others is a file and a line somebody has to find again.
		 * `total` past `count` is said rather than dropped, because "64 of
		 * 100" is more than a hundred nobody scrolls through (0263).
		 */
		for (at = 0; at < diags.count; at++) {
			char rendered[NCFG_CLI_SENTENCE_MAX];

			ncfg_lower_diag_render(&diags.at[at], rendered, sizeof(rendered));
			(void)fprintf(stderr, "ncfg: %s\n", rendered);
		}
		if (diags.total > diags.count) {
			(void)fprintf(stderr, "ncfg: and %zu more\n", diags.total - diags.count);
		}
	}
	ncfg_lower_diags_free(&diags);
	ncfg_pending_hooks_free(pending);
	ncfg_config_sources_free(&sources);
	return document;
}

/*
 * `ncfg show`: the compiled desired-state document.
 *
 * The desired state is written to `/run` on the way past, as every path that
 * compiles does: answering "why is it like this?" from a file is the product,
 * and it should not require an apply first. A failure to write it is not a
 * failure of the command -- `/run` may be read-only in a container, and the
 * document the operator asked for is on stdout either way.
 */
static int command_show(const ncfg_cli_options_t *options)
{
	char             run_dir[NCFG_CLI_TEXT_MAX];
	char             err[NCFG_ERROR_MAX];
	ncfg_document_t *document = compile_config(options, run_dir, sizeof(run_dir), err,
	    sizeof(err));
	int              code;

	if (!document) {
		return fail(err);
	}
	(void)ncfg_state_write_desired(run_dir, document, err, sizeof(err));
	code = ncfg_cli_print_document(document, err, sizeof(err)) ? NCFG_CLI_EXIT_OK
	    : fail(err);
	ncfg_document_free(document);
	return code;
}

/* ------------------------------------------------------------------------ *
 * The program
 * ------------------------------------------------------------------------ */

/* Which verb, once the options are off the front. */
static int dispatch(const char *command, const ncfg_cli_options_t *options,
    const char **positional, size_t count)
{
	if (strcmp(command, "wifi") == 0) {
		return command_wifi(options, positional, count);
	}
	if (strcmp(command, "modem") == 0) {
		return command_modem(options, positional, count);
	}
	if (strcmp(command, "monitor") == 0) {
		return command_monitor(options);
	}
	if (strcmp(command, "reload") == 0) {
		return command_simple(options, NCFG_PROTO_REQ_RELOAD,
		    "reloaded; the configuration compiles");
	}
	if (strcmp(command, "confirm") == 0) {
		return command_simple(options, NCFG_PROTO_REQ_CONFIRM,
		    "confirmed; the change stands");
	}
	if (strcmp(command, "revert") == 0) {
		return command_simple(options, NCFG_PROTO_REQ_REVERT,
		    "reverted to the last-good configuration");
	}

	/* The verbs whose first step is a local compile or a local observation.
	 * Their output is ported and tested; what is missing is underneath them. */
	if (strcmp(command, "status") == 0) {
		return not_in_this_wave("status", NEEDS_OBSERVER);
	}
	if (strcmp(command, "plan") == 0) {
		return not_in_this_wave("plan", NEEDS_OBSERVER);
	}
	if (strcmp(command, "apply") == 0) {
		return not_in_this_wave("apply", NEEDS_OBSERVER);
	}
	if (strcmp(command, "show") == 0) {
		return command_show(options);
	}
	if (strcmp(command, "explain") == 0) {
		/* 0263 does not port the provenance side table -- a second record of
		 * the document is a second thing that has to go on agreeing with it --
		 * and `explain` is what reads it. */
		return not_in_this_wave("explain", NEEDS_PROVENANCE);
	}
	if (strcmp(command, "control") == 0 || strcmp(command, "config") == 0 ||
	    strcmp(command, "profile") == 0 || strcmp(command, "secret") == 0 ||
	    strcmp(command, "reset") == 0) {
		return not_in_this_wave(command, NEEDS_WRITERS);
	}
	if (strcmp(command, "wait-online") == 0) {
		return not_in_this_wave("wait-online", NEEDS_OBSERVER);
	}
	if (strcmp(command, "tui") == 0) {
		return fail("this build has no TUI");
	}

	return failf("unknown command `%s`; try `ncfg --help`", command);
}


int ncfg_cli_main(int argc, char **argv)
{
	ncfg_cli_options_t options;
	const char       **positional;
	const char        *command;
	size_t             count = 0;
	char               err[NCFG_ERROR_MAX];
	int                code;

	if (argc < 2) {
		ncfg_cli_print_usage();
		return NCFG_CLI_EXIT_USAGE;
	}
	command = argv[1];
	if (strcmp(command, "-h") == 0 || strcmp(command, "--help") == 0 ||
	    strcmp(command, "help") == 0) {
		ncfg_cli_print_usage();
		return NCFG_CLI_EXIT_OK;
	}
	if (strcmp(command, "--version") == 0 || strcmp(command, "version") == 0) {
		ncfg_cli_print_version();
		return NCFG_CLI_EXIT_OK;
	}

	/*
	 * Room for every remaining argument, because that is the most that can be
	 * positional. Sized from `argc` rather than from a constant this file
	 * would have to pick: a bound invented here is one that is wrong on
	 * somebody's machine, and `argv` is already bounded by `ARG_MAX`.
	 */
	positional = calloc((size_t)argc, sizeof(*positional));
	if (!positional) {
		return fail("out of memory reading the command line");
	}
	if (!ncfg_cli_parse(argc - 2, argv + 2, &options, positional, &count, err,
	    sizeof(err))) {
		free(positional);
		return fail(err);
	}
	code = dispatch(command, &options, positional, count);
	free(positional);
	return code;
}

void ncfg_cli_print_usage(void)
{
	ncfg_out_write(ncfg_cli_usage());
}

void ncfg_cli_print_version(void)
{
	ncfg_out_writef("ncfg %s\n", NCFG_CLI_VERSION);
	ncfg_out_line(NCFG_CLI_COPYRIGHT);
}
