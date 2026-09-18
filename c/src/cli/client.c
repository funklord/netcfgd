/*
 * client.c -- where an answer comes from: the daemon when there is one, the
 * configuration directory when there is not.
 *
 * ONLY WHERE THE DAEMON IS GENUINELY REQUIRED
 *   Design section 4.4 makes daemon-optional a property rather than a
 *   fallback. The four writing verbs are the place that property is decided
 *   one way or the other on every run: `/etc/netcfgd` is root's and a client
 *   is not root (0127), so a write goes over the socket when something is
 *   listening and into the directory when nothing is -- which is the machine
 *   being configured before netcfgd runs on it.
 *
 * WHY THE TRANSPORT IS NOT HERE
 *   `ask.c` is the socket: it connects, frames, and recovers a refusal that
 *   arrived before the request went out (0183). This is the layer above it --
 *   which socket, is anything there, and what a caller says about an answer it
 *   did not expect. Splitting them that way is what lets `ncfg monitor` share
 *   the transport without sharing any of this.
 *
 * WHY `describe_answer` IS PUBLIC AND `run.c`'s IS NOT
 *   The same table is written `static` in `run.c` for the read-only verbs.
 *   Two lists of one thing have already drifted in this tree more than once,
 *   so this one is declared in `cli.h`, tested from `cli_control_test.c`, and
 *   `run.c`'s copy should call it rather than keep its own.
 */
#include "subcommand_internal.h"

#include "ncfg/base.h"
#include "ncfg/config.h"
#include "ncfg/hooks.h"
#include "ncfg/lower.h"
#include "ncfg/state.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

const char *ncfg_cli_describe_answer(const ncfg_proto_response_t *response, char *out,
    size_t out_size)
{
	if (!response) {
		return "nothing";
	}
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
		 * The Rust prints the raw JSON here, truncated at 120 characters --
		 * it decodes into a narrow mirror of the response type and has
		 * nothing else to say about a kind outside it. This module decodes
		 * every kind, so the tag is the honest and the shorter answer; a
		 * whole document in a diagnostic is not a diagnostic either way.
		 */
		(void)snprintf(out, out_size, "an unexpected answer: %s",
		    ncfg_proto_response_name(response->kind));
		return out;
	}
}

const char *ncfg_cli_daemon_socket(const ncfg_cli_options_t *options, char *out, size_t out_size)
{
	char run_dir[NCFG_CLI_PATH_MAX];

	(void)ncfg_state_resolve_dir(options ? options->run_dir : NULL, run_dir, sizeof(run_dir));
	return ncfg_cli_socket_path(run_dir, out, out_size);
}

int ncfg_cli_daemon_listening(const char *socket_path)
{
	struct stat about;

	return socket_path != NULL && stat(socket_path, &about) == 0;
}

int ncfg_cli_ask_ok(const char *socket_path, const ncfg_proto_request_t *request, char *err,
    size_t err_size)
{
	ncfg_proto_message_t message;

	if (!ncfg_cli_ask(socket_path, request, &message, err, err_size)) {
		return 0;
	}
	if (message.kind != NCFG_PROTO_MESSAGE_RESPONSE) {
		ncfg_proto_message_free(&message);
		ncfg_error_set(err, err_size, "the daemon sent something that is not a response");
		return 0;
	}
	if (message.u.response.kind == NCFG_PROTO_RESP_ERROR) {
		char said[NCFG_ERROR_MAX];

		/* Copied out before the message is freed: the daemon's sentence
		 * points into the line the decoder owns, and that sentence is the
		 * whole of what the caller is about to print. */
		(void)ncfg_cli_text(message.u.response.u.error.message, said, sizeof(said));
		ncfg_proto_message_free(&message);
		ncfg_error_set(err, err_size, "%s", said);
		return 0;
	}
	if (message.u.response.kind != NCFG_PROTO_RESP_OK) {
		char        what[NCFG_CLI_SENTENCE_MAX];
		char        said[NCFG_ERROR_MAX];
		const char *named;

		/* The **return value**, not the buffer: most kinds are a literal and
		 * never touch `what`, so reading the buffer would print whatever was
		 * last on the stack. Composed before the message is freed and copied
		 * out, because the error kind's phrase points into the decoded line. */
		named = ncfg_cli_describe_answer(&message.u.response, what, sizeof(what));
		(void)snprintf(said, sizeof(said), "the daemon sent %s", named);
		ncfg_proto_message_free(&message);
		ncfg_error_set(err, err_size, "%s", said);
		return 0;
	}
	ncfg_proto_message_free(&message);
	return 1;
}

ncfg_document_t *ncfg_cli_compile_to_read(const ncfg_cli_options_t *options, char *err,
    size_t err_size)
{
	char                  config_dir[NCFG_CLI_PATH_MAX];
	char                  factory_dir[NCFG_CLI_PATH_MAX];
	ncfg_config_sources_t sources = { NULL, 0, 0 };
	ncfg_lower_diags_t    diags = { NULL, 0, 0, 0 };
	ncfg_document_t      *document;

	(void)ncfg_config_resolve_dir(options ? options->config_dir : NULL, config_dir,
	    sizeof(config_dir));
	(void)ncfg_config_resolve_factory_dir(options ? options->factory_dir : NULL, factory_dir,
	    sizeof(factory_dir));

	if (!ncfg_config_load_with_profile(factory_dir, config_dir, &sources, err, err_size)) {
		ncfg_config_sources_free(&sources);
		return NULL;
	}
	/* The unwritten sink, deliberately: see the header for the two questions
	 * this site is asking and why the refusing one answers neither. */
	document = ncfg_config_compile(&sources, ncfg_hook_sink_unwritten(), &diags, err,
	    err_size);
	if (!document && diags.count > 0) {
		/*
		 * The first diagnostic, rendered with its file and line, rather than
		 * the sentence `ncfg_config_compile` left in `err`. One buffer and
		 * one sentence is `parse.h`'s join; a caller that wanted all of them
		 * compiles for itself and walks `diags`.
		 */
		ncfg_lower_diag_render(&diags.at[0], err, err_size);
	}
	ncfg_lower_diags_free(&diags);
	ncfg_config_sources_free(&sources);
	return document;
}

void ncfg_cli_refused_locally(int denied, const char *message, const char *socket_path, char *err,
    size_t err_size)
{
	if (!denied) {
		ncfg_error_set(err, err_size, "%s", message ? message : "");
		return;
	}
	ncfg_error_set(err, err_size,
	    "could not write the configuration (%s), and could not ask netcfgd to do it "
	    "either: nothing is listening on %s",
	    message ? message : "", socket_path ? socket_path : "");
}
