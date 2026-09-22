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

#include "ncfg/apply.h"
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/config.h"
#include "ncfg/explain.h"
#include "ncfg/hooks.h"
#include "ncfg/lower.h"
#include "ncfg/log.h"
#include "ncfg/observe.h"
#include "ncfg/plan.h"
#include "ncfg/state.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * `describe_answer` lived here as a `static` copy of the table in `client.c`,
 * which is the same ten cases written twice. This tree has been bitten by two
 * lists of one thing more than once, and the copy was checked against the
 * public one case by case before it was deleted: they agreed exactly, which is
 * the only reason this is a deletion rather than a reconciliation.
 */

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
 * `not_in_this_wave` stood here, with `NEEDS_WRITERS` beside it: a refusal
 * that named the module a verb was waiting for -- "the settings writer that
 * puts a drop-in where netcfgd reads it" -- for the three that had none, `wifi
 * add`, `wifi forget` and `reset`. `wifi_profile.h` and `reset.c` landed and
 * they were its last callers, so both are gone rather than left pointing at
 * something that exists. That is what `NEEDS_OBSERVER` did before them and for
 * the reason written there: a refusal naming a module that is present is worse
 * than one naming a module that is absent, because it looks right. The next
 * verb to need one writes the sentence it needs.
 *
 * The three are dispatch arms now. `reset` reaches the adapter every write
 * verb goes through; the two under `ncfg wifi` carry their own error buffer
 * where they are dispatched, because that adapter is defined below
 * `command_wifi` and the local it would be declared over is called
 * `subcommand` too.
 */

/*
 * One JSON document on stdout, or the sentence saying why there is not one.
 *
 * **`--json` is answered rather than ignored**, which is what this arm used to
 * refuse it for: somebody who passed the flag and got a table would read the
 * table as the machine-readable form. Every verb below that renders something
 * now renders it both ways, and `cli.h` says what the object holds.
 *
 * **Nothing is printed when the render failed**, and that is the whole reason
 * this is one function rather than three lines repeated. `ncfg_buf_t` hands
 * out the empty string for a buffer that failed rather than the part that
 * fitted, so a caller that printed anyway would emit `{` and a newline and
 * exit 0 -- half a document that looks whole, which is the failure mode the
 * buffer's rule exists for. The refusal a reader actually meets here is the
 * JSON writer's: a name that is not valid UTF-8 is refused rather than
 * repaired (0263), because every repair -- the raw bytes, `\u00XX` per byte,
 * U+FFFD -- puts a value in front of somebody that nobody typed. So the
 * sentence says what could not be written and points at the form that can
 * still show it, which is the table.
 */
static int say_json(const ncfg_buf_t *rendered, int wrote, const char *err)
{
	if (!wrote) {
		return failf("%s.\nnothing is printed rather than a document with a value in "
		    "it that nobody typed; the same command without `--json` renders it as "
		    "text", err);
	}
	ncfg_out_line(ncfg_buf_text(rendered));
	return NCFG_CLI_EXIT_OK;
}

/* `{"ok":true}`, for a verb whose whole answer is that it worked. */
static int say_json_ok(void)
{
	ncfg_buf_t buf;
	char       err[NCFG_ERROR_MAX];
	int        code;

	ncfg_buf_init(&buf, 0);
	code = say_json(&buf, ncfg_cli_json_ok(&buf, err, sizeof(err)), err);
	ncfg_buf_free(&buf);
	return code;
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
		    ncfg_cli_describe_answer(&message.u.response, what, sizeof(what)));
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
	if (options->json) {
		return say_json_ok();
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
	if (strcmp(subcommand, "add") == 0 || strcmp(subcommand, "forget") == 0) {
		char err[NCFG_ERROR_MAX];
		int  wrote;

		err[0] = '\0';
		wrote = strcmp(subcommand, "add") == 0
		    ? ncfg_cli_wifi_add(options, positional + 1, count - 1, err, sizeof(err))
		    : ncfg_cli_wifi_forget(options, positional + 1, count - 1, err, sizeof(err));
		if (wrote) {
			return NCFG_CLI_EXIT_OK;
		}
		return fail(err[0] != '\0' ? err : "it did not say what went wrong");
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
			if (options->json) {
				return say_json_ok();
			}
			ncfg_out_line("disconnected");
		}
		return code;
	}
	if (request.kind == NCFG_PROTO_REQ_WIFI_CONNECT) {
		code = ask_for_ok(options, &request);
		if (code == NCFG_CLI_EXIT_OK) {
			if (options->json) {
				return say_json_ok();
			}
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
	/*
	 * **The same answer, rendered twice, from the same decoded structure.**
	 * Not two requests and not two readers: what the daemon sent is already an
	 * `ncfg_proto_*` value by this point, so the table and the document are two
	 * spellings of one thing rather than two ideas of what was asked.
	 */
	if (options->json) {
		ncfg_buf_t buf;
		char       said[NCFG_ERROR_MAX];
		int        wrote = 0;

		ncfg_buf_init(&buf, 0);
		switch (message.u.response.kind) {
		case NCFG_PROTO_RESP_WIFI_SCAN:
			wrote = ncfg_cli_json_scan(&message.u.response.u.wifi_scan, &buf, said,
			    sizeof(said));
			break;
		case NCFG_PROTO_RESP_WIFI_STATUS:
			wrote = ncfg_cli_json_wifi_status(&message.u.response.u.wifi_status,
			    &buf, said, sizeof(said));
			break;
		case NCFG_PROTO_RESP_AP_STATIONS:
			wrote = ncfg_cli_json_stations(&message.u.response.u.ap_stations, &buf,
			    said, sizeof(said));
			break;
		case NCFG_PROTO_RESP_RADIOS:
			wrote = ncfg_cli_json_radios(message.u.response.u.radios.items,
			    message.u.response.u.radios.count, &buf, said, sizeof(said));
			break;
		default:
			(void)ncfg_cli_describe_answer(&message.u.response, said, sizeof(said));
			code = failf("the daemon sent %s", said);
			ncfg_buf_free(&buf);
			ncfg_proto_message_free(&message);
			return code;
		}
		code = say_json(&buf, wrote, said);
		ncfg_buf_free(&buf);
		ncfg_proto_message_free(&message);
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
		    ncfg_cli_describe_answer(&message.u.response, what, sizeof(what)));
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
	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_MODEM_LIST;
	if (!ask_or_fail(options, &request, &message, &code)) {
		return code;
	}
	if (message.u.response.kind != NCFG_PROTO_RESP_MODEMS) {
		char what[NCFG_CLI_SENTENCE_MAX];

		code = failf("the daemon sent %s",
		    ncfg_cli_describe_answer(&message.u.response, what, sizeof(what)));
		ncfg_proto_message_free(&message);
		return code;
	}
	if (options->json) {
		ncfg_buf_t buf;
		char       said[NCFG_ERROR_MAX];
		int        wrote;

		ncfg_buf_init(&buf, 0);
		wrote = ncfg_cli_json_modems(message.u.response.u.modems.items,
		    message.u.response.u.modems.count, &buf, said, sizeof(said));
		code = say_json(&buf, wrote, said);
		ncfg_buf_free(&buf);
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

	if (!socket_for(options, path, sizeof(path))) {
		return fail("the run directory makes a socket path too long to connect to");
	}
	/*
	 * **The only `--json` here that writes nothing.** An event arrives as one
	 * JSON value on a line and that is already the machine-readable form, so
	 * the flag switches the rendering off rather than switching a writer on --
	 * which is also what keeps an event this build has never heard of whole,
	 * the one property `ncfg monitor` is argued for on.
	 */
	if (!ncfg_cli_stream(path, options->json, err, sizeof(err))) {
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
		/*
		 * **These three were ignoring `--json`, and the Rust still does.**
		 * They were not among the six arms that refused it, which made them
		 * the one place left where the flag was accepted and changed nothing
		 * -- a script that asked for a document and got "reloaded; the
		 * configuration compiles" is the fault those six refusals existed to
		 * prevent, arriving through the verbs nobody had looked at.
		 */
		if (options->json) {
			return say_json_ok();
		}
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
 *
 * **`provenance` is NULL for every caller but `explain`.** A positions table is
 * the one thing here a caller either wants entirely or not at all, and one
 * nobody reads is a second structure that has to go on agreeing with the
 * document. Zeroed by the caller, filled in here, and freed by the caller
 * however the compile ended.
 */
static ncfg_document_t *compile_config(const ncfg_cli_options_t *options, char *run_dir,
    size_t run_dir_size, ncfg_provenance_t *provenance, char *err, size_t err_size)
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
	document = ncfg_config_compile_with_provenance(&sources, ncfg_pending_hooks_sink(pending),
	    provenance, &diags, err, err_size);
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
	ncfg_document_t *document = compile_config(options, run_dir, sizeof(run_dir), NULL, err,
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
 * The verbs that begin with a local observation
 * ------------------------------------------------------------------------ */

/*
 * Read the machine.
 *
 * `ncfg_observe_current` is the whole of it -- the round of dumps, the record
 * in the run directory, the files the kernel cannot answer for and the derived
 * answers -- and the reason this program calls that rather than the four
 * underneath it is the reason it exists: the daemon takes the same observation
 * on every tick, and two assemblies of one sequence is how the two would come
 * to disagree about what netcfgd can see.
 *
 * `desired` may be NULL, and here that is not a failure mode but the ordinary
 * one: somebody runs `ncfg status` because something is wrong, and a
 * configuration that has stopped compiling is exactly when.
 */
static int observe_now(const ncfg_cli_options_t *options, const char *run_dir,
    const ncfg_document_t *desired, ncfg_observed_t **out, char *err, size_t err_size)
{
	ncfg_observe_roots_t   roots;
	ncfg_secret_resolver_t secrets;
	char                   secrets_dir[NCFG_CLI_TEXT_MAX];

	if (!ncfg_observe_roots_default(&roots, err, err_size)) {
		return 0;
	}
	/*
	 * The one question an observation asks the secret store, and it is asked
	 * **under the directory this invocation was given** rather than under a
	 * default: `--config-dir` is the whole of how somebody points `ncfg` at a
	 * tree that is not the machine's, and a status listing that read
	 * `/etc/netcfgd/secrets` anyway would be reading credentials nobody
	 * pointed it at. A name that does not fit leaves the question unasked,
	 * which is the honest answer rather than a wrong one.
	 */
	memset(&secrets, 0, sizeof(secrets));
	if (options && options->config_dir && options->config_dir[0] &&
	    (size_t)snprintf(secrets_dir, sizeof(secrets_dir), "%s/secrets",
	    options->config_dir) < sizeof(secrets_dir)) {
		secrets.secrets_dir = secrets_dir;
	}
	return ncfg_observe_current(run_dir, &roots, secrets.secrets_dir ? &secrets : NULL,
	    desired, out, err, err_size);
}

/*
 * `ncfg status`: what the machine is doing.
 *
 * **The document is wanted and not required.** It reaches the observation
 * through `ncfg_observe_derive`, which needs it to classify links the way the
 * configuration names them and to judge connectivity by the policy it states;
 * without one the links are classified by their kernel kind and the default
 * policy applies, which is a smaller answer rather than a wrong one.
 *
 * **The diagnostics are printed where the Rust swallows them.** `compile` there
 * is called through `.ok()` and a configuration that does not compile produces
 * a status listing with no hint that the desired half of the answer is missing.
 * This prints them and then answers anyway, which is `explain`'s arrangement in
 * the Rust already -- and the exit status stays 0, because the question asked
 * was about the kernel and the kernel answered.
 */
static int command_status(const ncfg_cli_options_t *options)
{
	char             run_dir[NCFG_CLI_TEXT_MAX];
	char             err[NCFG_ERROR_MAX];
	ncfg_document_t *document;
	ncfg_observed_t *observed = NULL;
	int              code = NCFG_CLI_EXIT_OK;

	document = compile_config(options, run_dir, sizeof(run_dir), NULL, err, sizeof(err));
	if (!observe_now(options, run_dir, document, &observed, err, sizeof(err))) {
		ncfg_document_free(document);
		return fail(err);
	}
	/* As every path that observes does: answering "why is it like this?" from
	 * a file is the product. A `/run` that will not take it is not a failure
	 * of the command -- the listing the operator asked for is on stdout. */
	(void)ncfg_state_write_observed(run_dir, observed, err, sizeof(err));
	if (options->json) {
		/*
		 * **The file that was just written, on stdout**, and deliberately the
		 * same writer: `observed.json` under the run directory and this are
		 * one document, and a second spelling of it so that a pipe looks
		 * different from a file is the drift 0263 spends its length refusing.
		 * `doc/schema/observed.json` is the witness for both.
		 */
		ncfg_buf_t buf;

		ncfg_buf_init(&buf, 0);
		code = say_json(&buf, ncfg_observed_write(observed, &buf, err, sizeof(err)),
		    err);
		ncfg_buf_free(&buf);
	} else {
		ncfg_cli_print_status(observed);
	}
	ncfg_observed_free(observed);
	ncfg_document_free(document);
	return code;
}

/*
 * Say that the configuration directory is empty, where that explains the plan.
 *
 * A bare `nothing to do` is ambiguous in the one case it matters: somebody who
 * pointed `--config-dir` at the wrong directory gets the same two words as
 * somebody whose machine genuinely has nothing to change. So the fact is a note
 * under the answer rather than instead of one.
 *
 * Unreadable rather than empty is silent, and `compile_config` has already
 * failed with the real error by then -- a second, vaguer sentence about the
 * same directory helps nobody.
 */
static void note_empty_config(const ncfg_cli_options_t *options)
{
	char                  config_dir[NCFG_CLI_TEXT_MAX];
	char                  factory_dir[NCFG_CLI_TEXT_MAX];
	char                  err[NCFG_ERROR_MAX];
	ncfg_config_sources_t sources = { NULL, 0, 0 };

	(void)ncfg_config_resolve_dir(options->config_dir, config_dir, sizeof(config_dir));
	(void)ncfg_config_resolve_factory_dir(options->factory_dir, factory_dir,
	    sizeof(factory_dir));
	if (!ncfg_config_load_with_profile(factory_dir, config_dir, &sources, err, sizeof(err))) {
		ncfg_config_sources_free(&sources);
		return;
	}
	if (sources.count == 0) {
		ncfg_out_line("");
		ncfg_out_writef("there is no configuration in %s, so netcfgd manages nothing "
		    "here.\n", config_dir);
		ncfg_out_line("`ncfg wifi add SSID` writes the first one; doc/first-run.md has "
		    "the");
		ncfg_out_line("wired case.");
	}
	ncfg_config_sources_free(&sources);
}

/*
 * Say so if another daemon manages an interface this plan touches.
 *
 * After the plan rather than as a plan warning: it is not a fact about the
 * plan, which is correct either way. It is a fact about the machine that makes
 * the plan unlikely to stick.
 */
static void warn_about_contention(const ncfg_document_t *document,
    const ncfg_observed_t *observed)
{
	ncfg_contention_where_t where;
	ncfg_interface_claim_t *claims;
	ncfg_contenders_t       found;
	char                    err[NCFG_ERROR_MAX];
	size_t                  count = 0;
	size_t                  at;

	if (!document || document->interface_count == 0) {
		return;
	}
	claims = calloc(document->interface_count, sizeof(*claims));
	if (!claims) {
		return;
	}
	for (at = 0; at < document->interface_count; at++) {
		const ncfg_observed_link_t *link =
		    ncfg_observed_link(observed, document->interfaces[at].name);

		/*
		 * Only the ones the machine actually has. A claim carries a kernel
		 * index, and an interface the document names and the kernel does not
		 * has none to compare against.
		 *
		 * **The index is checked rather than cast**, which is 0263's narrowing
		 * rule where the model's `int64_t` meets a field the width of the
		 * kernel's. An index outside the range is skipped rather than
		 * truncated: a claim carrying the low half of somebody else's number
		 * would match a contender against an interface nobody named.
		 */
		if (link && link->index > 0 && link->index <= (int64_t)UINT32_MAX) {
			claims[count].name = document->interfaces[at].name;
			claims[count].index = (uint32_t)link->index;
			count++;
		}
	}
	memset(&found, 0, sizeof(found));
	ncfg_contention_machine(&where);
	if (count > 0 && ncfg_contenders_find(&where, claims, count, &found, err, sizeof(err))) {
		for (at = 0; at < found.count; at++) {
			ncfg_buf_t said;

			ncfg_buf_init(&said, 0);
			if (ncfg_contender_describe(&found.at[at], &said, err, sizeof(err))) {
				ncfg_out_line("");
				ncfg_out_writef("warning: %s\n", ncfg_buf_text(&said));
			}
			ncfg_buf_free(&said);
		}
	}
	ncfg_contenders_free(&found);
	free(claims);
}

/*
 * What the planner is told, from what was typed.
 *
 * `revert_to` is deliberately absent: it is the hash of the document a window
 * would revert to, and this build arms no window. `ncfg_plan_confirm_window`
 * still answers from `global { confirm = ... }`, so the plan says a window
 * would be armed -- which is true of the plan and, in this build, of nothing
 * that happens afterwards. It is one more reason `apply` is refused below.
 */
static void plan_options_of(const ncfg_cli_options_t *options, ncfg_plan_options_t *out)
{
	memset(out, 0, sizeof(*out));
	out->confirm_window = options->confirm;
	out->allow_disruption = options->allow_disruption.items;
	out->allow_disruption_count = options->allow_disruption.count;
	/* The two consents that used to be parsed and dropped: `--strand-credentials`
	 * and `--restart-wedged` reached `ncfg_cli_options_t` and stopped there,
	 * so a plan refused a stranding the operator had consented to and declined
	 * to restart a backend they had named. `strand.c` and `wedged.c` read
	 * them. */
	out->strand_credentials = options->strand_credentials.items;
	out->strand_credentials_count = options->strand_credentials.count;
	out->restart_wedged = options->restart_wedged.items;
	out->restart_wedged_count = options->restart_wedged.count;
}

/* `ncfg plan`: what would change, changing nothing. */
static int command_plan(const ncfg_cli_options_t *options)
{
	char                run_dir[NCFG_CLI_TEXT_MAX];
	char                err[NCFG_ERROR_MAX];
	ncfg_document_t    *document;
	ncfg_observed_t    *observed = NULL;
	ncfg_plan_options_t how;
	ncfg_plan_t        *plan;
	int                 code = NCFG_CLI_EXIT_OK;

	document = compile_config(options, run_dir, sizeof(run_dir), NULL, err, sizeof(err));
	if (!document) {
		return fail(err);
	}
	if (!observe_now(options, run_dir, document, &observed, err, sizeof(err))) {
		ncfg_document_free(document);
		return fail(err);
	}
	/* Even a plan writes what it decided and what it saw. */
	(void)ncfg_state_write_desired(run_dir, document, err, sizeof(err));
	(void)ncfg_state_write_observed(run_dir, observed, err, sizeof(err));

	plan_options_of(options, &how);
	plan = ncfg_plan_build(document, observed, &how, err, sizeof(err));
	if (!plan) {
		ncfg_observed_free(observed);
		ncfg_document_free(document);
		return fail(err);
	}
	if (options->json) {
		/*
		 * **The plan alone, and neither note under it.** The empty-config
		 * note and the contention warning are sentences addressed to a person
		 * -- one says where to write a first configuration, the other says
		 * another daemon is fighting for an interface -- and both are facts
		 * about the machine rather than members of the plan. Printing them
		 * beside a JSON document would put two lines that are not JSON on a
		 * stream that promised to be one value. The Rust skips them here too.
		 */
		ncfg_buf_t buf;

		ncfg_buf_init(&buf, 0);
		code = say_json(&buf, ncfg_plan_write(plan, &buf, err, sizeof(err)), err);
		ncfg_buf_free(&buf);
	} else {
		ncfg_cli_print_plan(plan);
		note_empty_config(options);
		warn_about_contention(document, observed);
	}
	ncfg_plan_free(plan);
	ncfg_observed_free(observed);
	ncfg_document_free(document);
	return code;
}

/*
 * `ncfg explain`: why is it like this?
 *
 * **Deliberately not routed through the daemon.** Design section 4.4 makes
 * daemon-optional a property rather than a fallback, and this is exactly the
 * command somebody reaches for when things are broken -- which is when a daemon
 * is least likely to be running.
 *
 * **The compile here is the one that carries a positions table**, which is the
 * whole difference between "because the configuration says so" and "because
 * `/etc/netcfgd/conf.d/10-lan.conf` line 4 says so". Every other verb passes
 * NULL: a side table nobody reads is a second thing that has to go on agreeing
 * with the document.
 *
 * It is freed whether or not the compile succeeded, because a compile that
 * stopped part way still recorded what it had reached -- and where it produced
 * nothing at all, `ncfg_explain` says so as the first fact of its own output
 * rather than quietly naming no files, which a reader could not tell from a
 * configuration with nothing to name.
 */
static int command_explain(const ncfg_cli_options_t *options, const char **positional,
    size_t count)
{
	char                 run_dir[NCFG_CLI_TEXT_MAX];
	char                 err[NCFG_ERROR_MAX];
	ncfg_proto_subject_t subject;
	ncfg_document_t     *document;
	ncfg_observed_t     *observed = NULL;
	ncfg_explanation_t  *explanation;
	ncfg_provenance_t    provenance;
	ncfg_buf_t           rendered;
	int                  wrote;

	memset(&provenance, 0, sizeof(provenance));

	memset(&subject, 0, sizeof(subject));
	if (count == 2 && strcmp(positional[0], "interface") == 0) {
		subject.kind = NCFG_PROTO_SUBJECT_INTERFACE;
		subject.name = ncfg_proto_str(positional[1]);
	} else if (count == 3 && strcmp(positional[0], "address") == 0) {
		subject.kind = NCFG_PROTO_SUBJECT_ADDRESS;
		subject.interface = ncfg_proto_str(positional[1]);
		subject.address = ncfg_proto_str(positional[2]);
	} else if (count == 3 && strcmp(positional[0], "route") == 0) {
		subject.kind = NCFG_PROTO_SUBJECT_ROUTE;
		subject.interface = ncfg_proto_str(positional[1]);
		subject.destination = ncfg_proto_str(positional[2]);
	} else {
		return fail("explain what? try `ncfg explain interface eth0`, `ncfg explain "
		    "address eth0 10.0.0.1/24`, or `ncfg explain route eth0 default`");
	}
	/*
	 * Compiled fresh rather than read from `/run`, so the answer describes the
	 * configuration as it is now and not as it was when something last wrote
	 * there. One that no longer compiles is reported as such and the
	 * observation half of the answer is given anyway -- it is worth having on
	 * its own, and this is the command for the moment it is all there is.
	 */
	document = compile_config(options, run_dir, sizeof(run_dir), &provenance, err,
	    sizeof(err));
	if (!document) {
		(void)fprintf(stderr, "ncfg: the configuration does not compile, so this "
		    "explains what the machine is doing and not what was asked for\n");
	}
	if (!observe_now(options, run_dir, document, &observed, err, sizeof(err))) {
		ncfg_provenance_free(&provenance);
		ncfg_document_free(document);
		return fail(err);
	}
	explanation = ncfg_explain(&subject, document, observed, &provenance, err, sizeof(err));
	ncfg_provenance_free(&provenance);
	if (!explanation) {
		ncfg_observed_free(observed);
		ncfg_document_free(document);
		return fail(err);
	}
	ncfg_buf_init(&rendered, 0);
	if (options->json) {
		/*
		 * **The one answer here whose JSON is not what the socket sends.** An
		 * `explanation` response carries the facts and no count, because the
		 * Rust has no bound to report; this one is bounded at
		 * `NCFG_EXPLAIN_FACTS_MAX`, and the text form ends with "showing 256
		 * of 1202" when it bites. `cli.h` argues the extra member.
		 *
		 * **And the subject came off `argv`**, which is where the UTF-8
		 * refusal is actually met: `ncfg explain interface $'\xff'` reaches
		 * here with a name no JSON string may hold, and what it gets is a
		 * sentence rather than a document with a name in it nobody typed.
		 */
		wrote = ncfg_cli_json_explanation(explanation, &rendered, err, sizeof(err));
		if (wrote) {
			ncfg_out_line(ncfg_buf_text(&rendered));
		}
	} else {
		wrote = ncfg_explanation_render(explanation, &rendered, err, sizeof(err));
		if (wrote) {
			ncfg_out_write(ncfg_buf_text(&rendered));
		}
	}
	ncfg_buf_free(&rendered);
	ncfg_explanation_free(explanation);
	ncfg_observed_free(observed);
	ncfg_document_free(document);
	return wrote ? NCFG_CLI_EXIT_OK : fail(err);
}

/*
 * `ncfg wait-online [SECONDS]`.
 *
 * **This exists because netcfgd's selector masks the other ones.** Every
 * network manager ships a wait-online helper and `network-online.target` means
 * nothing without one, so until this there was nothing in their place (0190).
 *
 * A local observation rather than a request to the daemon, deliberately: this
 * runs while the machine is still coming up, and a helper that needed the
 * control socket to be listening could not report on the seconds before it is.
 * A failure to observe is not a failure to be online for the same reason -- the
 * netlink socket can be refused at exactly that moment -- so the loop keeps
 * going and the deadline is what ends it.
 *
 * **The configuration is compiled once, before the loop, where the Rust
 * recompiles inside it.** The document is here only so the observation is the
 * one `ncfg status` would show; recompiling the directory every 250ms for the
 * length of a DHCP timeout is a read of every configuration file forty times a
 * second, and the diagnostics of a config that does not compile would be
 * printed just as often into a boot log nobody is watching.
 */
static int command_wait_online(const ncfg_cli_options_t *options, const char **positional,
    size_t count)
{
	char             run_dir[NCFG_CLI_TEXT_MAX];
	char             err[NCFG_ERROR_MAX];
	ncfg_document_t *document;
	long             seconds = NCFG_CLI_WAIT_ONLINE_DEFAULT;
	struct timespec  deadline;
	struct timespec  pause;
	int              online = 0;
	ncfg_observed_t *last = NULL;

	if (count > 0) {
		char *end = NULL;

		errno = 0;
		seconds = strtol(positional[0], &end, 10);
		if (errno != 0 || !end || *end != '\0' || end == positional[0] || seconds < 0) {
			return failf("`%.*s` is not a number of seconds",
			    (int)NCFG_CLI_TEXT_MAX, positional[0]);
		}
	}
	document = compile_config(options, run_dir, sizeof(run_dir), NULL, err, sizeof(err));

	if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
		ncfg_document_free(document);
		return fail("this machine has no monotonic clock to wait against");
	}
	deadline.tv_sec += (time_t)seconds;
	pause.tv_sec = 0;
	pause.tv_nsec = 250L * 1000L * 1000L;

	for (;;) {
		struct timespec now;
		ncfg_observed_t *observed = NULL;

		if (observe_now(options, run_dir, document, &observed, err, sizeof(err))) {
			online = ncfg_cli_is_online(observed);
			ncfg_observed_free(last);
			last = observed;
			if (online) {
				break;
			}
		}
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
		    now.tv_sec > deadline.tv_sec ||
		    (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) {
			break;
		}
		(void)nanosleep(&pause, NULL);
	}
	ncfg_document_free(document);
	if (online) {
		ncfg_observed_free(last);
		return NCFG_CLI_EXIT_OK;
	}
	/*
	 * **Say which half is missing.** "Timed out" sends the reader to the wrong
	 * place half the time, and this runs at boot where nobody is watching: the
	 * journal line is the whole report. The observation reported on is the last
	 * one that succeeded rather than a fresh one, which is what makes the
	 * sentence describe the machine the loop actually gave up on.
	 */
	if (!last) {
		return failf("still not online after %lds: the machine could not be observed "
		    "at all. `ncfg status` says what each interface is doing, and `ncfg plan` "
		    "says what netcfgd would still do about it", seconds);
	}
	{
		size_t addresses = 0;
		int    routed = 0;
		size_t at;

		for (at = 0; at < last->address_count; at++) {
			if (last->addresses[at].interface &&
			    strcmp(last->addresses[at].interface, "lo") != 0) {
				addresses++;
			}
		}
		for (at = 0; at < last->route_count; at++) {
			if (last->routes[at].destination &&
			    strcmp(last->routes[at].destination, "default") == 0) {
				routed = 1;
				break;
			}
		}
		ncfg_observed_free(last);
		return failf("still not online after %lds: %zu address(es) outside loopback "
		    "and %s default route. `ncfg status` says what each interface is doing, "
		    "and `ncfg plan` says what netcfgd would still do about it", seconds,
		    addresses, routed ? "a" : "no");
	}
}

/*
 * `ncfg apply` is refused, and the refusal is the decision rather than a gap.
 *
 * The observer it was waiting for landed in this wave, so the sentence this arm
 * used to carry is no longer true -- and `status`, `plan` and `explain` are
 * wired on the strength of it. **This one is not, and the reason is not that
 * something under it is unported but that everything under it is unported in a
 * way an apply cannot survive.** Four facts, each of which is on its own enough:
 *
 *   * **The planner does not read every block a document can carry.** A plan
 *     from this build is not the whole change, so an apply would converge part
 *     of a machine and report having converged it. `warn_unported` in
 *     `src/plan/build.c` is the list, and it is named here rather than counted
 *     for the reason every other figure in this file was un-counted: a number
 *     has to be swept whenever a pass lands, and the ones that were written
 *     down here went stale inside a wave. The list is the thing a reader needs
 *     and it changes only when the fact does.
 *   * **The executor refuses what it cannot do while the plan is running,
 *     rather than before it.** It carries every op kind now; what it refuses
 *     is by *kind* -- a `link.create` for a physical device, a pppoe session
 *     or an openvpn tunnel, and `backend.start` for four of the nine backend
 *     kinds -- measured by asking `ncfg_apply_supported` about each, rather
 *     than by counting the arms that refuse. `ncfg_apply_supported` is asked by
 *     `execute`, one action at a time, and `ncfg_apply` stops at the first
 *     failure -- so a plan mixing a supported op with an unsupported one
 *     changes the machine and then stops halfway. A sweep of the plan before
 *     the first action would fix the *order* of that refusal and nothing else,
 *     which is why it is not what this arm does.
 *
 *     **The link half of that list is shorter than it was** -- a vlan, a bond,
 *     a macvlan and a tunnel are created now that `document.h` publishes the
 *     last of the four numberings -- and the three left are each covered by an
 *     earlier arm of `plan/link.c`, so nothing a document can express reaches
 *     this refusal through the planner any more. The `backend.start` half is
 *     what keeps the sentence true.
 *   * **Nothing under `ncfg` folds what an apply did into `owned.json`.** The
 *     fold itself has landed -- `ncfg_apply_record` takes a plan and a journal
 *     and is what the daemon's own apply paths call -- and the mark 0136 gives
 *     every link netcfgd creates is written by `create_link` now, so a link
 *     this build makes reads back as `ours` twice over. What is absent is this
 *     command: there is no apply path here to call either of them from, and a
 *     `ncfg apply` that changed a machine and recorded nothing would leave
 *     exactly the objects netcfgd may never remove again.
 *   * **There is no confirm window.** `ncfg_plan_confirm_window` answers from
 *     `global { confirm = ... }` as well as from `--confirm-within`, so a plan
 *     here carries `commit.arm` -- and the executor does nothing for it,
 *     correctly, because arming belongs to whoever owns the timer afterwards.
 *     Nothing here does. An apply that cut the machine off would say a window
 *     was open and never revert.
 *
 * So it says what it is waiting for, by name, and `ncfg plan` is offered
 * because it is the half that is ported: the same document against the same
 * observation, with every block this build is holding named, and nothing
 * changed.
 */
/*
 * `ncfg apply --confirm-within N`, which is the daemon's to carry out.
 *
 * **One implementation of the safety net, in the program that is still
 * running when the window expires.** A `ncfg` that armed one itself would have
 * to stay alive to resolve it, and two implementations of the mechanism that
 * saves a machine from a bad configuration is two chances to get it wrong --
 * with the one that ran depending on how it was invoked.
 *
 * So this sends the request and prints what came back. Where the daemon
 * refuses, its sentence is what an operator reads: this build's does, and says
 * why, which is a better answer than a second refusal composed here.
 */
static int apply_through_daemon(const ncfg_cli_options_t *options)
{
	ncfg_proto_request_t request;
	ncfg_proto_message_t message;
	int                  code = NCFG_CLI_EXIT_OK;

	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_APPLY;
	request.u.apply.confirm.present = 1u;
	request.u.apply.confirm.value = options->confirm.value;
	request.u.apply.allow_disruption.items = NULL;
	request.u.apply.allow_disruption.count = 0u;
	if (!ask_or_fail(options, &request, &message, &code)) {
		return code;
	}
	/*
	 * A journal is what an apply answers with. Nothing in this build encodes
	 * one yet, so reaching here means the daemon answered something else --
	 * which is a fact about the two halves disagreeing rather than about this
	 * machine, and is said as one.
	 */
	if (message.u.response.kind != NCFG_PROTO_RESP_JOURNAL) {
		ncfg_proto_message_free(&message);
		return fail("the daemon answered an apply with something that is not a "
		    "journal");
	}
	ncfg_proto_message_free(&message);
	return code;
}

/*
 * Where this program is allowed to reach the machine, or NULL.
 *
 * Set once by `ncfg_cli_main_on` before anything is dispatched. A file-scope
 * pointer rather than an argument threaded through `dispatch`: every other
 * verb would have to carry a parameter it never reads, and the one that does
 * read it is the one that must not be reachable by accident.
 */
static const ncfg_cli_machine_t *the_machine;

/*
 * The exit status a plan that did not fail leaves with.
 *
 * A refusal means the desired state was not reached, whether or not some
 * actions ran; exiting zero there would tell a script that convergence
 * happened when the very change it asked for is the one that did not.
 * Stranding is a separate code because it has a separate remedy, and refusal
 * wins when both apply -- it is the one where netcfgd did not do something it
 * was asked.
 */
static int outcome_of(const ncfg_plan_t *plan)
{
	if (ncfg_plan_was_refused(plan)) {
		return NCFG_CLI_EXIT_REFUSED;
	}
	if (ncfg_plan_strands_credentials(plan)) {
		return NCFG_CLI_EXIT_STRANDED;
	}
	return NCFG_CLI_EXIT_OK;
}

/* Where this run was told the configuration is, resolved once. The executor
 * resolves credentials under it, so it is part of what an apply is pointed at
 * rather than something the seam may answer for itself. */
static const char *config_dir_of(const ncfg_cli_options_t *options, char *out, size_t out_size)
{
	return ncfg_config_resolve_dir(options->config_dir, out, out_size);
}

/*
 * `ncfg apply`: make the machine match the configuration.
 *
 * **The order is observe, plan, act, and the lock covers all three.** Two
 * applies racing plan against a machine the other is changing: the Rust
 * measured two simultaneous runs producing a failed `route.add` every time,
 * because the second had planned against a route the first then installed
 * (0184). The lock is the executor seam's to take, which is why it is opened
 * before the plan is carried out and closed after the record is written.
 *
 * **What is recorded is written before what happened is printed.** A journal
 * that exists only in the terminal is no use to whoever finds the machine
 * afterwards, and the fold into `owned.json` is what decides whether netcfgd
 * may ever remove these objects again.
 *
 * **`--confirm-within` goes to the daemon**, and that is not a shortcut: the
 * window is a timer that outlives this process, so a `ncfg` that armed one
 * itself would have to stay alive to resolve it. One implementation of the
 * safety net, in the one program that is still running when it expires.
 */
static int command_apply(const ncfg_cli_options_t *options)
{
	char             run_dir[NCFG_CLI_TEXT_MAX];
	char             config_dir[NCFG_CLI_TEXT_MAX];
	char             err[NCFG_ERROR_MAX];
	ncfg_document_t *document;
	ncfg_observed_t *observed = NULL;
	ncfg_plan_options_t how;
	ncfg_plan_t     *plan;
	ncfg_journal_t   journal;
	ncfg_executor_t  executor;
	ncfg_dns_scopes_t      *scopes = NULL;
	const ncfg_dns_scope_t *delivered = NULL;
	size_t                  delivered_count = 0;
	int                     code;

	if (options->confirm.has) {
		return apply_through_daemon(options);
	}
	if (!the_machine || !the_machine->executor_open) {
		return fail("this build of `ncfg` was started with no way to reach the "
		    "machine, so it will not apply. That is the seam `src/main/` installs; a "
		    "program embedding this library without one can plan and explain and "
		    "cannot change anything");
	}
	document = compile_config(options, run_dir, sizeof(run_dir), NULL, err, sizeof(err));
	if (!document) {
		return fail(err);
	}
	if (!observe_now(options, run_dir, document, &observed, err, sizeof(err))) {
		ncfg_document_free(document);
		return fail(err);
	}
	(void)ncfg_state_write_desired(run_dir, document, err, sizeof(err));
	(void)ncfg_state_write_observed(run_dir, observed, err, sizeof(err));

	plan_options_of(options, &how);
	plan = ncfg_plan_build(document, observed, &how, err, sizeof(err));
	if (!plan) {
		ncfg_observed_free(observed);
		ncfg_document_free(document);
		return fail(err);
	}
	/*
	 * **An empty plan opens no socket.** Nothing to do is the ordinary answer
	 * on a converged machine, and reaching for netlink to discover that is
	 * both slower and a chance to fail where there was no work.
	 */
	if (ncfg_plan_is_empty(plan)) {
		if (!options->json) {
			if (ncfg_plan_was_refused(plan) || ncfg_plan_strands_credentials(plan)) {
				ncfg_cli_print_plan_notes(plan);
			} else {
				ncfg_out_line("nothing to do");
			}
		}
		code = outcome_of(plan);
		ncfg_plan_free(plan);
		ncfg_observed_free(observed);
		ncfg_document_free(document);
		return code;
	}

	err[0] = '\0';
	if (!the_machine->executor_open(the_machine->context, config_dir_of(options, config_dir,
	        sizeof(config_dir)), run_dir, document, observed, &executor, err, sizeof(err))) {
		ncfg_plan_free(plan);
		ncfg_observed_free(observed);
		ncfg_document_free(document);
		return failf("cannot start an apply: %s", err);
	}
	ncfg_journal_init(&journal);
	err[0] = '\0';
	(void)ncfg_apply(plan, &executor, &journal, err, sizeof(err));

	/*
	 * The scopes a `dns.apply` in this plan delivered, which is what the fold
	 * needs: `dns.apply` is the one op that is not its own effect. The same
	 * pure function on the same pair the executor was built from, so the
	 * record says what the delivery did.
	 */
	err[0] = '\0';
	scopes = ncfg_dns_scopes_of(document, observed, err, sizeof(err));
	if (scopes) {
		delivered = ncfg_dns_scopes_items(scopes, &delivered_count);
	}
	err[0] = '\0';
	if (!ncfg_apply_record(run_dir, plan, &journal, delivered, delivered_count, err,
	        sizeof(err))) {
		(void)failf("could not record ownership: %s", err);
	}
	ncfg_dns_scopes_free(scopes);
	err[0] = '\0';
	if (!ncfg_apply_write_journal(run_dir, &journal, err, sizeof(err))) {
		(void)failf("could not write the journal: %s", err);
	}
	if (the_machine->executor_close) {
		the_machine->executor_close(the_machine->context, &executor);
	}

	if (options->json) {
		ncfg_buf_t buf;

		ncfg_buf_init(&buf, 0);
		code = say_json(&buf, ncfg_journal_write(&journal, &buf, err, sizeof(err)), err);
		ncfg_buf_free(&buf);
		if (code != NCFG_CLI_EXIT_OK) {
			ncfg_journal_free(&journal);
			ncfg_plan_free(plan);
			ncfg_observed_free(observed);
			ncfg_document_free(document);
			return code;
		}
	} else {
		ncfg_cli_print_journal(&journal);
		ncfg_cli_print_plan_notes(plan);
	}

	code = outcome_of(plan);
	if (ncfg_journal_failure(&journal)) {
		const ncfg_record_t *failure = ncfg_journal_failure(&journal);

		if (!options->json) {
			(void)failf("stopped at action %u (%s); %zu done, %zu not attempted",
			    (unsigned)failure->id, failure->op ? failure->op : "an action",
			    ncfg_journal_done(&journal), ncfg_journal_skipped(&journal));
			(void)fail("re-run `ncfg apply` to resume from current state");
		}
		code = NCFG_CLI_EXIT_FAILED;
	}
	ncfg_journal_free(&journal);
	ncfg_plan_free(plan);
	ncfg_observed_free(observed);
	ncfg_document_free(document);
	return code;
}

/* ------------------------------------------------------------------------ *
 * The program
 * ------------------------------------------------------------------------ */

/*
 * The four subcommands that write, which share a shape `dispatch` does not.
 *
 * Each answers 1 or 0 with a sentence, because that is `base.h`'s convention
 * and they are library calls before they are commands. `dispatch` answers an
 * exit status. One adapter rather than four copies of the same `err` buffer:
 * the buffer is the part that is easy to get subtly wrong, and a wrong one is
 * a command that fails silently.
 */
static int subcommand(int (*run)(const ncfg_cli_options_t *, const char **, size_t,
    char *, size_t), const ncfg_cli_options_t *options, const char **positional, size_t count)
{
	char err[NCFG_ERROR_MAX];

	err[0] = '\0';
	if (run(options, positional, count, err, sizeof(err))) {
		return NCFG_CLI_EXIT_OK;
	}
	return fail(err[0] != '\0' ? err : "it did not say what went wrong");
}

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
	 * Four of them read the machine and print, and are wired; the fifth
	 * changes it, and `command_apply` is where that is argued out. */
	if (strcmp(command, "status") == 0) {
		return command_status(options);
	}
	if (strcmp(command, "plan") == 0) {
		return command_plan(options);
	}
	if (strcmp(command, "apply") == 0) {
		return command_apply(options);
	}
	if (strcmp(command, "show") == 0) {
		return command_show(options);
	}
	if (strcmp(command, "explain") == 0) {
		return command_explain(options, positional, count);
	}
	if (strcmp(command, "control") == 0) {
		return subcommand(ncfg_cli_control, options, positional, count);
	}
	if (strcmp(command, "config") == 0) {
		return subcommand(ncfg_cli_config, options, positional, count);
	}
	if (strcmp(command, "profile") == 0) {
		return subcommand(ncfg_cli_profile, options, positional, count);
	}
	if (strcmp(command, "secret") == 0) {
		return subcommand(ncfg_cli_secret, options, positional, count);
	}
	/* `reset` is `netcfgd-cli`'s own `lib.rs` rather than one of the four
	 * modules above, so it is `reset.c` here -- and it goes through the same
	 * adapter, because it answers a sentence like the rest of them. */
	if (strcmp(command, "reset") == 0) {
		return subcommand(ncfg_cli_reset, options, positional, count);
	}
	if (strcmp(command, "wait-online") == 0) {
		return command_wait_online(options, positional, count);
	}
	if (strcmp(command, "tui") == 0) {
		return ncfg_tui_run(options);
	}

	return failf("unknown command `%s`; try `ncfg --help`", command);
}


int ncfg_cli_main(int argc, char **argv)
{
	return ncfg_cli_main_on(argc, argv, NULL);
}

int ncfg_cli_main_on(int argc, char **argv, const ncfg_cli_machine_t *machine)
{
	ncfg_cli_options_t options;
	const char       **positional;
	const char        *command;
	size_t             count = 0;
	char               err[NCFG_ERROR_MAX];
	int                code;

	the_machine = machine;
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
