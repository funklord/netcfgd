/*
 * ncfg_client.h -- talking to netcfgd, below the widgets.
 *
 * WHY THIS EXISTS
 *   gui/project.md sec 3: two frontends are plausible and the expensive parts
 *   are not the drawing. Connection handling, request/response matching,
 *   event subscription and the models are non-visual, so they live here once.
 *   If a function here would need to know what a widget is, it is on the wrong
 *   side of the seam.
 *
 *   And C rather than C++ for the sibling's reason: everything here is
 *   plumbing, a C++ layer would be unusable from anything C, and it would
 *   complicate the Android story. C++ belongs on the Qt side of this seam.
 *
 * WHAT IT SPEAKS
 *   netcfgd's control socket: one JSON object per line, over AF_UNIX. The
 *   vocabulary is pinned by docs/schema/socket.json, which exists so that a
 *   second implementation is legitimate rather than a fork -- this is that
 *   second implementation, and the test beside it parses every line of that
 *   witness rather than a fixture somebody wrote to match.
 *
 *   The daemon reads requests from one connection in a loop, so a client may
 *   hold one open and ask repeatedly. `monitor` turns a connection into a
 *   stream and it never goes back, which is why it takes a connection of its
 *   own.
 *
 * WHAT IT DOES NOT DO YET
 *   The remote transport (gui/project.md sec 6). Every function here is the
 *   local socket, and the seam is shaped so the encrypted datagram transport
 *   arrives as a second implementation of it rather than as a second API.
 */
#ifndef NCFG_CLIENT_H
#define NCFG_CLIENT_H

#include <stddef.h>

#include "ncfg_json.h"

/* Long enough for a diagnostic that names a path, which is the longest thing
 * that goes in one. */
#define NCFG_ERROR_MAX 512

typedef struct ncfg_client ncfg_client_t;

/*
 * Where the daemon's socket is, without the caller having to know.
 *
 * $NCFG_RUN_DIR then the compiled-in default, matching what `ncfg` itself
 * resolves -- a client that disagreed with the CLI about which daemon it was
 * talking to would be a bad hour for somebody.
 */
const char *ncfg_client_default_socket(void);

/*
 * Open a connection. `socket_path` may be NULL for the default.
 *
 * Returns NULL and fills `err` with a sentence naming what could not be
 * reached. "Connection refused" alone sends the reader looking for a network
 * problem, so the message says which path and that the daemon has to be
 * running.
 */
ncfg_client_t *ncfg_client_open(const char *socket_path, char *err, size_t err_size);
void ncfg_client_close(ncfg_client_t *client);

/* The path this client is connected to, for a UI that has to say which machine
 * it is about to change. */
const char *ncfg_client_socket_path(const ncfg_client_t *client);

/*
 * One request, one response.
 *
 * `request` is a complete JSON object without its newline -- `{"request":
 * "status"}`. The reply is a parsed document the caller owns and frees with
 * ncfg_json_free.
 *
 * A response of `{"response":"error",...}` is returned as a document rather
 * than as a failure: it is the daemon answering, which is different from not
 * reaching it, and only the caller knows whether a refusal is fatal. Failure
 * here means the connection or the framing, and nothing else.
 */
ncfg_json_doc_t *ncfg_client_request(ncfg_client_t *client, const char *request,
				     char *err, size_t err_size);

/*
 * The three requests every client makes, spelled out so that no caller writes
 * the JSON by hand. There will be more; these are the ones the first screens
 * need, and each is one line of text so the cost of adding another is nil.
 */
ncfg_json_doc_t *ncfg_client_hello(ncfg_client_t *client, char *err, size_t err_size);
ncfg_json_doc_t *ncfg_client_status(ncfg_client_t *client, char *err, size_t err_size);
ncfg_json_doc_t *ncfg_client_plan(ncfg_client_t *client, char *err, size_t err_size);

/*
 * `{"response":"error","message":"..."}` -> the message, or NULL.
 *
 * Here rather than in each caller because "did the daemon refuse, and what did
 * it say" is asked of every response, and the shape of a refusal is the
 * protocol's business rather than a screen's.
 */
const char *ncfg_client_error_message(const ncfg_json_doc_t *doc, size_t *length_out);

/*
 * Escape a string into a JSON string literal, quotes included.
 *
 * Needed the moment a request carries an interface name, and an interface name
 * is not a safe thing to interpolate: netcfgd's own model says an SSID is
 * arbitrary octets (project.md sec 2.1), and a name with a quote in it would
 * otherwise produce a request that means something else. Returns the number of
 * bytes written, or 0 if it would not fit.
 */
size_t ncfg_client_quote(const char *text, char *out, size_t out_size);

#endif /* NCFG_CLIENT_H */
