/*
 * daemon_answer.c -- what a request means, once the socket has let it through.
 *
 * WHAT THIS IS AND WHAT IT IS NOT
 *   `ncfg_daemon_answer_fn` is the seam `server.c` calls with its lock held,
 *   and it is the last thing this port owed before `netcfgd` could start.
 *   Everything above it -- the framing, the peer credentials, the two
 *   authorisation gates -- has already happened, so nothing here re-decides
 *   who may do what: two answers to "may I" is what 0092 exists to prevent.
 *
 *   Nothing here computes anything either. Every arm is a call into the
 *   library and a buffer handed back, which is `main_internal.h`'s rule for
 *   this whole directory.
 *
 * WHY HALF OF IT REFUSES, AND WHY THAT IS NOT THE THING 0263 REFUSED
 *   `daemon_main.c` would not start this program because a daemon with no
 *   answer seam "would bind the control socket, let a client through and then
 *   answer `error` to everything asked of it" -- an operator reads a bare
 *   refusal as a request the daemon did not recognise. Two things make this
 *   different from that, and both are properties rather than intentions:
 *
 *     * fourteen of the thirty-two kinds are answered, including every wifi
 *       verb, `reload`, and everything that writes a drop-in, a secret or a
 *       profile;
 *     * every other kind is refused with a sentence that **names the request
 *       and says what is missing**, so it cannot be read as "unrecognised".
 *       `ncfg_main_answer_unported` is that table, reachable on its own so
 *       that a test walks all thirty-two rather than the handful somebody
 *       remembered.
 *
 *   The refusals are not a policy decision either: nothing in `c/src/` encodes
 *   a `status`, `plan`, `document`, `journal`, `explanation`, `secrets`,
 *   `modems`, `profiles`, `configs`, `hooks` or `probes` response, because
 *   `proto.h` decodes every response and encodes none and the encoders belong
 *   beside the requests that produce them. When one lands, one row of the
 *   table becomes an arm.
 */
#include "loop_internal.h"

#include "ncfg/wifi_profile.h"

#include "ncfg/config.h"
#include "ncfg/log.h"
#include "ncfg/secrets.h"

#include <stdlib.h>
#include <string.h>

/* The longest a name that becomes a path component may be. A drop-in name, a
 * secret name, a profile name and an interface name are all short, and each of
 * the calls below validates its own; this is only about getting the bytes off
 * the wire into something NUL-terminated. */
#define NAME_MAX_BYTES 256

/* What a credential may be, which is `src/cli/secret.c`'s ceiling for its
 * reason: both halves read to end of file in the Rust, so `ncfg secret set x <
 * /dev/zero` allocates until the machine stops. The refusal names the ceiling
 * rather than truncating -- a credential that is quietly half of itself fails
 * later and somewhere else. */
#define SECRET_MAX_BYTES (64u * 1024u)

/* ------------------------------------------------------------------------ *
 * Getting the bytes off the wire
 * ------------------------------------------------------------------------ */

/*
 * A counted field as a NUL-terminated name, into `out`.
 *
 * **A field carrying a NUL is refused rather than taken as the part before
 * it**, which is `explain.h`'s rule for a subject and is here for the same
 * reason: every call below turns one of these into a path component or an
 * interface, and the part before a NUL names something nobody asked about.
 */
static int name_of(ncfg_proto_str_t text, const char *what, char *out, size_t out_size,
    char *err, size_t err_size)
{
	if (!ncfg_proto_str_present(text)) {
		ncfg_error_set(err, err_size, "this request carries no %s", what);
		return 0;
	}
	if (text.length + 1u > out_size) {
		ncfg_error_set(err, err_size, "the %s is longer than the %zu bytes one may be",
		    what, out_size - 1u);
		return 0;
	}
	if (memchr(text.bytes, '\0', text.length)) {
		ncfg_error_set(err, err_size, "the %s carries a NUL, which no name may", what);
		return 0;
	}
	memcpy(out, text.bytes, text.length);
	out[text.length] = '\0';
	return 1;
}

/*
 * A counted field as NUL-terminated text the caller frees.
 *
 * Bounded and named, never truncated: half a drop-in that looks whole is the
 * failure 0263 refuses this for, and the ceiling is in the sentence so that an
 * operator knows what to do rather than that it was "too big".
 */
static char *text_of(ncfg_proto_str_t text, const char *what, size_t max, char *err,
    size_t err_size)
{
	char *copy;

	if (!ncfg_proto_str_present(text)) {
		ncfg_error_set(err, err_size, "this request carries no %s", what);
		return NULL;
	}
	if (text.length > max) {
		ncfg_error_set(err, err_size,
		    "this %s is %zu bytes and the most one may carry is %zu", what, text.length,
		    max);
		return NULL;
	}
	if (memchr(text.bytes, '\0', text.length)) {
		/* The store and the compiler both read what they are given as a C
		 * string, so a NUL inside would silently shorten it -- a credential or
		 * a configuration file that is quietly half of itself. */
		ncfg_error_set(err, err_size, "this %s carries a NUL, which it may not", what);
		return NULL;
	}
	copy = malloc(text.length + 1u);
	if (!copy) {
		ncfg_error_set(err, err_size, "there was not enough memory for this %s", what);
		return NULL;
	}
	memcpy(copy, text.bytes, text.length);
	copy[text.length] = '\0';
	return copy;
}

/* ------------------------------------------------------------------------ *
 * What this build cannot answer, and why
 * ------------------------------------------------------------------------ */

const char *ncfg_main_answer_unported(ncfg_proto_request_kind_t kind)
{
	/*
	 * Written as a switch rather than a table indexed by the enum, so that
	 * `-Wswitch` notices a request added to the protocol and not answered
	 * here. `NCFG_PROTO_REQ_COUNT` is the bound every exhaustive walk in this
	 * port uses in place of the `match` the Rust is checked for.
	 */
	switch (kind) {
	case NCFG_PROTO_REQ_HELLO:
		/* Never reaches the seam: everything `hello` carries is the server's
		 * -- the two versions and the tiers this connection satisfies -- and
		 * a seam computing the tier list would be the second implementation
		 * of "may I" that 0092 forbids. Named here anyway, because a kind
		 * with no row is a kind nothing walks. */
		return "`hello` is answered by the control socket itself, so nothing here "
		    "answers it; reaching this is a bug in the server rather than in the "
		    "request";
	case NCFG_PROTO_REQ_STATUS:
	case NCFG_PROTO_REQ_PLAN:
	case NCFG_PROTO_REQ_SHOW:
	case NCFG_PROTO_REQ_EXPLAIN:
	case NCFG_PROTO_REQ_CONFIG_LIST:
	case NCFG_PROTO_REQ_PROBE_LIST:
	case NCFG_PROTO_REQ_HOOK_LIST:
	case NCFG_PROTO_REQ_PROFILE_LIST:
	case NCFG_PROTO_REQ_MODEM_LIST:
	case NCFG_PROTO_REQ_SECRET_LIST:
		/* The verb is recognised and the answer cannot be written: `proto.h`
		 * decodes every response and encodes none, and the encoder for each
		 * of these belongs beside the request that produces it. `ncfg status`,
		 * `ncfg plan` and `ncfg explain` read the machine themselves and do
		 * not need a daemon, which is where to send somebody meanwhile. */
		return "this build of netcfgd understands the request and cannot write the "
		    "answer: nothing in the C port encodes that response yet. `ncfg status`, "
		    "`ncfg plan` and `ncfg explain` read the machine themselves and need no "
		    "daemon";
	case NCFG_PROTO_REQ_MONITOR:
		/* Never reaches the seam either, and for `hello`'s reason one step
		 * further out: the answer to `monitor` is the connection itself, and
		 * this seam is handed a request and a buffer and no descriptor at
		 * all. `server.c` takes it after the gate and hands it to
		 * `ncfg_daemon_stream_fn`, which is the Rust's arrangement too. Named
		 * here anyway, because a kind with no row is a kind nothing walks. */
		return "`monitor` is taken by the control socket itself, which hands the "
		    "connection to the event stream; reaching this is a bug in the server "
		    "rather than in the request";
	case NCFG_PROTO_REQ_PROBE_PUT:
		return "this build of netcfgd cannot write a probe drop-in: the writer that "
		    "renders a `probe` block is not ported. `ncfg config put` writes the same "
		    "file where a caller composes the block itself";
	case NCFG_PROTO_REQ_APPLY:
	case NCFG_PROTO_REQ_CONFIRM:
	case NCFG_PROTO_REQ_REVERT:
		/* 0263's facts about `ncfg apply` that are still facts -- the two it
		 * named about ownership are closed, and so is the third, the journal
		 * `ncfg_apply_write_journal` now publishes -- each of which is on its
		 * own enough, said in one sentence rather than two: this is a refusal
		 * an operator reads on a socket, not the decision record. */
		return "this build of netcfgd will not apply, and what is left is no longer "
		    "in the executor: every member of its service context is resolved, so the "
		    "fourteen ops that are not netlink are carried out rather than refused. "
		    "What is left is the planner, which does not read every block a document "
		    "can carry. `ncfg plan` names each one it is holding, against the same "
		    "document and the same machine, and changes nothing";
	case NCFG_PROTO_REQ_RELOAD:
	case NCFG_PROTO_REQ_WIFI_SCAN:
	case NCFG_PROTO_REQ_WIFI_STATUS:
	case NCFG_PROTO_REQ_WIFI_CONNECT:
	case NCFG_PROTO_REQ_WIFI_DISCONNECT:
	/* 0117's path, answered since `wifi_profile.h` landed. The refusal that
	 * used to stand here said the profile writer was a seam with no
	 * implementation, which stopped being true when that module was written
	 * and went on being said. */
	case NCFG_PROTO_REQ_WIFI_ADD:
	case NCFG_PROTO_REQ_WIFI_FORGET:
	case NCFG_PROTO_REQ_CONFIG_PUT:
	case NCFG_PROTO_REQ_PROFILE_SAVE:
	case NCFG_PROTO_REQ_PROFILE_SET:
	case NCFG_PROTO_REQ_SECRET_PUT:
	case NCFG_PROTO_REQ_CONFIG_DELETE:
	case NCFG_PROTO_REQ_SECRET_DELETE:
	case NCFG_PROTO_REQ_AP_STATIONS:
	case NCFG_PROTO_REQ_RADIOS:
	case NCFG_PROTO_REQ_RADIO_SET:
		return NULL;
	case NCFG_PROTO_REQ_COUNT:
	default:
		return "that is not a request this daemon speaks";
	}
}

/* ------------------------------------------------------------------------ *
 * The arms
 * ------------------------------------------------------------------------ */

static int answer_reload(ncfg_main_desk_t *desk, ncfg_buf_t *out, char *err, size_t err_size)
{
	ncfg_proto_event_t event;
	int                took;

	took = ncfg_daemon_state_reload(desk->state, err, err_size);
	/*
	 * Told either way, which is the Rust's arrangement: a client watching a
	 * machine wants to know that somebody asked and that it did not compile,
	 * and a `reloaded` event carrying the diagnostics is the only place it
	 * learns the second half.
	 */
	memset(&event, 0, sizeof(event));
	event.kind = NCFG_PROTO_EVENT_RELOADED;
	event.ok = took ? 1u : 0u;
	if (!took && desk->state->diagnostics) {
		event.diagnostics = ncfg_proto_str(desk->state->diagnostics);
	}
	ncfg_main_subscribers_tell(desk->subscribers, &event);
	if (!took) {
		return 0;
	}
	return ncfg_daemon_ok_encode(out, err, err_size);
}

static int answer_config_put(ncfg_main_desk_t *desk, const ncfg_proto_put_t *put,
    ncfg_buf_t *out, char *err, size_t err_size)
{
	char  name[NAME_MAX_BYTES];
	char *text;
	int   denied = 0;
	int   wrote;

	if (!name_of(put->name, "drop-in name", name, sizeof(name), err, err_size)) {
		return 0;
	}
	text = text_of(put->text, "configuration text", (size_t)NCFG_CONFIG_FILE_MAX, err,
	    err_size);
	if (!text) {
		return 0;
	}
	wrote = ncfg_config_install_drop_in(desk->state->paths.config, desk->state->paths.factory,
	    name, text, put->replace ? 1 : 0, NULL, &denied, err, err_size);
	free(text);
	if (!wrote) {
		return 0;
	}
	return ncfg_daemon_ok_encode(out, err, err_size);
}

static int answer_config_delete(ncfg_main_desk_t *desk, ncfg_proto_str_t which, ncfg_buf_t *out,
    char *err, size_t err_size)
{
	char name[NAME_MAX_BYTES];
	int  denied = 0;
	int  removed = 0;

	if (!name_of(which, "drop-in name", name, sizeof(name), err, err_size)) {
		return 0;
	}
	if (!ncfg_config_remove_drop_in(desk->state->paths.config, desk->state->paths.factory,
	    name, &removed, &denied, err, err_size)) {
		return 0;
	}
	/* Absent is success and `removed` is how a caller could tell -- but this
	 * response has nowhere to carry it, exactly as the Rust's does not. What
	 * 0263 fixes is the *client's* half, which asks the filesystem. */
	return ncfg_daemon_ok_encode(out, err, err_size);
}

static int answer_secret_put(ncfg_main_desk_t *desk, const ncfg_proto_secret_put_t *put,
    ncfg_buf_t *out, char *err, size_t err_size)
{
	char  name[NAME_MAX_BYTES];
	char *value;
	int   stored;

	if (!name_of(put->name, "secret name", name, sizeof(name), err, err_size)) {
		return 0;
	}
	value = text_of(put->value, "credential", (size_t)SECRET_MAX_BYTES, err, err_size);
	if (!value) {
		return 0;
	}
	stored = ncfg_secret_store_put(desk->state->paths.config, name, value,
	    put->replace ? 1 : 0, NULL, err, err_size);
	/* Overwritten before it is released: this process holds a passphrase or a
	 * private key and the only reason it exists here is the length of this
	 * call. `supplicant.h` takes the same trade. */
	memset(value, 0, strlen(value));
	free(value);
	if (!stored) {
		return 0;
	}
	return ncfg_daemon_ok_encode(out, err, err_size);
}

static int answer_secret_delete(ncfg_main_desk_t *desk, ncfg_proto_str_t which, ncfg_buf_t *out,
    char *err, size_t err_size)
{
	char name[NAME_MAX_BYTES];

	if (!name_of(which, "secret name", name, sizeof(name), err, err_size)) {
		return 0;
	}
	if (!ncfg_secret_store_remove(desk->state->paths.config, name, err, err_size)) {
		return 0;
	}
	return ncfg_daemon_ok_encode(out, err, err_size);
}

static int answer_profile_set(ncfg_main_desk_t *desk, ncfg_proto_str_t which, ncfg_buf_t *out,
    char *err, size_t err_size)
{
	char name[NAME_MAX_BYTES];
	int  denied = 0;
	int  removed = 0;

	/*
	 * **An absent name is the default state and not a profile called
	 * "none"** (0151): a machine with hand-written configuration and no
	 * selection is not running a profile, and spelling that as one would make
	 * it permanently confusable with the shipped `offline` profile.
	 */
	if (!ncfg_proto_str_present(which)) {
		if (!ncfg_profile_unset(desk->state->paths.config, desk->state->paths.factory,
		    &removed, &denied, err, err_size)) {
			return 0;
		}
		return ncfg_daemon_ok_encode(out, err, err_size);
	}
	if (!name_of(which, "profile name", name, sizeof(name), err, err_size)) {
		return 0;
	}
	if (!ncfg_profile_set(desk->state->paths.config, desk->state->paths.factory, name,
	    &denied, err, err_size)) {
		return 0;
	}
	return ncfg_daemon_ok_encode(out, err, err_size);
}

static int answer_profile_save(ncfg_main_desk_t *desk, const ncfg_proto_profile_save_t *save,
    ncfg_buf_t *out, char *err, size_t err_size)
{
	char name[NAME_MAX_BYTES];
	int  denied = 0;

	if (!name_of(save->name, "profile name", name, sizeof(name), err, err_size)) {
		return 0;
	}
	if (!desk->state->desired) {
		/* Saving what is running means saving the compiled document, and
		 * there is none. Said rather than saved empty, which would put a
		 * profile on the machine that restores nothing. */
		ncfg_error_set(err, err_size,
		    "there is no configuration in force to save: the directory does not "
		    "compile");
		return 0;
	}
	if (!ncfg_profile_save(desk->state->paths.config, desk->state->paths.factory, name,
	    save->replace ? 1 : 0, desk->state->desired, "`--replace`", NULL, &denied, err,
	    err_size)) {
		return 0;
	}
	return ncfg_daemon_ok_encode(out, err, err_size);
}

static int answer_radio_set(ncfg_main_desk_t *desk, const ncfg_proto_radio_set_t *set,
    ncfg_buf_t *out, char *err, size_t err_size)
{
	char interface[NAME_MAX_BYTES];

	if (!name_of(set->interface, "interface", interface, sizeof(interface), err, err_size)) {
		return 0;
	}
	/*
	 * **No apply seam, deliberately, and it is not skipped silently.**
	 * `ncfg_wifi_set_radio` refuses an activation with no way to apply, which
	 * is the whole point of that argument being required: activation that
	 * wrote a correct file and left the operator with "cannot reach the
	 * supplicant" is the defect the synchronous step was added to close. What
	 * an implementation needs here is a plan restricted to this interface and
	 * to starting a supplicant, and `backend.start` is one of the thirty-five
	 * ops this build's executor refuses -- so a seam here could only ever
	 * report that. Handing one back writes nothing further and is answered.
	 */
	return ncfg_wifi_set_radio(desk->state, interface, set->activate ? 1 : 0, NULL, NULL, out,
	    err, err_size);
}

/* The four that take an interface and read through the supplicant or hostapd.
 * One place that gets the name off the wire, because four call sites each
 * getting it themselves is four chances to forget the NUL. */
static int answer_for_interface(ncfg_main_desk_t *desk, ncfg_proto_request_kind_t kind,
    ncfg_proto_str_t which, ncfg_buf_t *out, char *err, size_t err_size)
{
	char interface[NAME_MAX_BYTES];

	if (!name_of(which, "interface", interface, sizeof(interface), err, err_size)) {
		return 0;
	}
	if (kind == NCFG_PROTO_REQ_WIFI_SCAN) {
		return ncfg_wifi_scan(&desk->where, desk->state->desired, desk->state->observed,
		    interface, out, err, err_size);
	}
	if (kind == NCFG_PROTO_REQ_WIFI_STATUS) {
		return ncfg_wifi_status(&desk->where, desk->state->desired, desk->state->observed,
		    interface, out, err, err_size);
	}
	if (kind == NCFG_PROTO_REQ_WIFI_DISCONNECT) {
		return ncfg_wifi_disconnect(&desk->where, desk->state->desired, interface, out, err,
		    err_size);
	}
	return ncfg_wifi_ap_stations(&desk->where, desk->state->desired, interface, out, err,
	    err_size);
}

/*
 * 0117's path: write a `network` block for a client that may not write the
 * file itself.
 *
 * **The rendering is `ncfg_wifi_configure_network`'s and the writing is
 * `wifi_profile.h`'s**, joined through the seam `daemon.h` declares. Two
 * implementations of "what a `network` block looks like" is the drift this tree
 * keeps finding, so the CLI and this arm reach the same two functions -- the
 * CLI calls the writer directly because it already holds the directories, and
 * this one hands them over as the seam's context.
 *
 * The credential travels as the request's own bytes and is never copied here:
 * `wifi_profile.h`'s rule is that a passphrase exists in exactly one place for
 * exactly as long as the decoded line does, and this arm is inside that line's
 * lifetime.
 */
static int answer_wifi_add(ncfg_main_desk_t *desk, const ncfg_proto_wifi_add_t *wanted,
    ncfg_buf_t *out, char *err, size_t err_size)
{
	ncfg_wifi_installer_t installer;
	int                   ok;

	if (!desk->config_dir || !desk->factory_dir) {
		ncfg_error_set(err, err_size,
		    "this daemon was not told where configuration is written, so it will not "
		    "write a `network` block: there is no default for it, because a daemon "
		    "pointed at a scratch tree must not write into the machine's own");
		return 0;
	}
	memset(&installer, 0, sizeof(installer));
	installer.config_dir = desk->config_dir;
	installer.factory_dir = desk->factory_dir;
	ok = ncfg_wifi_configure_network(desk->state->desired, wanted,
	    ncfg_wifi_profile_installer, &installer, out, err, err_size);
	ncfg_wifi_installed_free(&installer.installed);
	return ok;
}

/*
 * The same for `wifi forget`, which needs no seam.
 *
 * `ncfg_wifi_configure_network` exists because *rendering* a block is the
 * daemon's and *writing* one is the host module's; a forget renders nothing,
 * so this calls the writer straight. The drop-in goes before the credential,
 * which is `ncfg_wifi_profile_forget`'s rule: the other order takes a
 * passphrase away from a network that is still configured.
 */
static int answer_wifi_forget(ncfg_main_desk_t *desk, ncfg_proto_str_t id, ncfg_buf_t *out,
    char *err, size_t err_size)
{
	ncfg_wifi_forgotten_t forgotten;
	char                  label[NAME_MAX_BYTES];
	int                   denied = 0;
	int                   ok;

	/* Through `name_of`, which is what every other arm takes a
	 * `ncfg_proto_str_t` through: the protocol carries bytes and a length, and
	 * turning one into a C string is where an embedded NUL or a missing
	 * terminator becomes somebody else's problem. */
	if (!name_of(id, "network", label, sizeof(label), err, err_size)) {
		return 0;
	}
	if (!desk->config_dir || !desk->factory_dir) {
		ncfg_error_set(err, err_size,
		    "this daemon was not told where configuration is written, so it will not "
		    "take a `network` block away either");
		return 0;
	}
	memset(&forgotten, 0, sizeof(forgotten));
	ok = ncfg_wifi_profile_forget(desk->config_dir, desk->factory_dir, desk->state->desired,
	    label, &forgotten, &denied, err, err_size);
	ncfg_wifi_forgotten_free(&forgotten);
	if (!ok) {
		return 0;
	}
	/*
	 * A plain acknowledgement, which is what `ncfg_wifi_configure_network`
	 * answers for an add and what the client expects: `ncfg wifi forget`
	 * renders the credentials it removed only when *it* did the removing, and
	 * prints `daemon: true` otherwise. Sending the detail here would be a
	 * second shape of one reply for the client to handle.
	 */
	(void)denied;
	return ncfg_daemon_ok_encode(out, err, err_size);
}

static int answer_wifi_connect(ncfg_main_desk_t *desk, const ncfg_proto_wifi_connect_t *join,
    ncfg_buf_t *out, char *err, size_t err_size)
{
	char interface[NAME_MAX_BYTES];
	char network[NAME_MAX_BYTES];

	if (!name_of(join->interface, "interface", interface, sizeof(interface), err, err_size)) {
		return 0;
	}
	if (!name_of(join->network, "network", network, sizeof(network), err, err_size)) {
		return 0;
	}
	return ncfg_wifi_connect(&desk->where, desk->state->desired, desk->secrets_dir,
	    desk->certs_dir, interface, network, out, err, err_size);
}

/* ------------------------------------------------------------------------ *
 * The dispatch
 * ------------------------------------------------------------------------ */

int ncfg_main_answer(void *context, const ncfg_proto_request_t *request,
    const ncfg_peer_t *peer, ncfg_arrival_t arrival, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	ncfg_main_desk_t *desk = context;
	const char       *unported;

	/*
	 * Neither is read, and that is a property rather than an oversight: the
	 * request has already been through `ncfg_authz_permitted`, which is the
	 * one place in this library that decides who may do what. An arm here
	 * consulting the peer or the arrival would be the second implementation
	 * of that question.
	 */
	(void)peer;
	(void)arrival;

	if (!desk || !desk->state || !request || !out) {
		ncfg_error_set(err, err_size, "this daemon has nothing to answer a request with");
		return 0;
	}

	unported = ncfg_main_answer_unported(request->kind);
	if (unported) {
		const char *name = ncfg_proto_request_name(request->kind);

		/* The request is named in the refusal, always. A sentence that says
		 * only what is missing reads as a complaint about something else, and
		 * a client showing the operator a bare message has no other way to
		 * say which of its calls this answered. */
		ncfg_error_set(err, err_size, "%s: %s", name ? name : "that request", unported);
		return 0;
	}

	switch (request->kind) {
	case NCFG_PROTO_REQ_RELOAD:
		return answer_reload(desk, out, err, err_size);
	case NCFG_PROTO_REQ_WIFI_SCAN:
	case NCFG_PROTO_REQ_WIFI_STATUS:
	case NCFG_PROTO_REQ_WIFI_DISCONNECT:
	case NCFG_PROTO_REQ_AP_STATIONS:
		return answer_for_interface(desk, request->kind, request->u.interface, out, err,
		    err_size);
	case NCFG_PROTO_REQ_WIFI_CONNECT:
		return answer_wifi_connect(desk, &request->u.wifi_connect, out, err, err_size);
	case NCFG_PROTO_REQ_WIFI_ADD:
		return answer_wifi_add(desk, &request->u.wifi_add, out, err, err_size);
	case NCFG_PROTO_REQ_WIFI_FORGET:
		return answer_wifi_forget(desk, request->u.id, out, err, err_size);
	case NCFG_PROTO_REQ_RADIOS:
		return ncfg_wifi_radios(&desk->where, desk->state->desired, desk->state->observed,
		    out, err, err_size);
	case NCFG_PROTO_REQ_RADIO_SET:
		return answer_radio_set(desk, &request->u.radio_set, out, err, err_size);
	case NCFG_PROTO_REQ_CONFIG_PUT:
		return answer_config_put(desk, &request->u.put, out, err, err_size);
	case NCFG_PROTO_REQ_CONFIG_DELETE:
		return answer_config_delete(desk, request->u.name, out, err, err_size);
	case NCFG_PROTO_REQ_SECRET_PUT:
		return answer_secret_put(desk, &request->u.secret_put, out, err, err_size);
	case NCFG_PROTO_REQ_SECRET_DELETE:
		return answer_secret_delete(desk, request->u.name, out, err, err_size);
	case NCFG_PROTO_REQ_PROFILE_SET:
		return answer_profile_set(desk, request->u.name, out, err, err_size);
	case NCFG_PROTO_REQ_PROFILE_SAVE:
		return answer_profile_save(desk, &request->u.profile_save, out, err, err_size);
	/*
	 * Every kind `ncfg_main_answer_unported` answered with a sentence, listed
	 * so that `-Wswitch` notices a request added to the protocol and reaching
	 * neither the table above nor an arm here. Reaching this is the table and
	 * this switch having come to disagree, which is what the test that walks
	 * both is for.
	 */
	case NCFG_PROTO_REQ_HELLO:
	case NCFG_PROTO_REQ_STATUS:
	case NCFG_PROTO_REQ_PLAN:
	case NCFG_PROTO_REQ_APPLY:
	case NCFG_PROTO_REQ_CONFIRM:
	case NCFG_PROTO_REQ_REVERT:
	case NCFG_PROTO_REQ_SHOW:
	case NCFG_PROTO_REQ_EXPLAIN:
	case NCFG_PROTO_REQ_CONFIG_LIST:
	case NCFG_PROTO_REQ_MONITOR:
	case NCFG_PROTO_REQ_PROBE_LIST:
	case NCFG_PROTO_REQ_HOOK_LIST:
	case NCFG_PROTO_REQ_PROFILE_LIST:
	case NCFG_PROTO_REQ_MODEM_LIST:
	case NCFG_PROTO_REQ_SECRET_LIST:
	case NCFG_PROTO_REQ_PROBE_PUT:
	case NCFG_PROTO_REQ_COUNT:
	default:
		ncfg_error_set(err, err_size,
		    "this daemon has no arm for that request, which is a bug rather than a "
		    "refusal");
		return 0;
	}
}

/*
 * What `monitor` does, once the socket has let it through.
 *
 * WHY IT IS HERE RATHER THAN IN `server.c`
 *   The same reason the arms above are: that file owns sockets and threads,
 *   and what a request *means* is this one's. What `monitor` means is one
 *   line -- the connection joins the list an announcement is written to.
 *
 * WHY IT IS SAFE TO TOUCH THAT LIST FROM HERE
 *   Because this does not run on the connection's thread. It is reached
 *   through `ncfg_main_mailbox_stream`, which parks the connection and hands
 *   the descriptor over from inside `ncfg_main_mailbox_settle` -- so every
 *   call on the subscriber list, the pass announcing through it and this one
 *   adding to it, happens on the loop's thread, which is what lets that list
 *   hold no lock.
 */
int ncfg_main_stream(void *context, int fd, char *err, size_t err_size)
{
	ncfg_main_desk_t *desk = context;

	if (!desk || !desk->subscribers) {
		/*
		 * Refused rather than accepted and dropped. A daemon assembled
		 * without a subscriber list would otherwise take the connection,
		 * close nothing, and leave a client watching a socket that will never
		 * carry a line -- which is indistinguishable from a quiet machine.
		 */
		ncfg_error_set(err, err_size,
		    "this daemon has nowhere to put a subscribed connection, so it would "
		    "never be told anything");
		return 0;
	}
	/* The list's own rules from here: it takes the descriptor, puts it in
	 * non-blocking mode so that a client which stopped reading cannot stop
	 * the daemon reconciling, and refuses past its bound with a sentence the
	 * server sends back. */
	return ncfg_main_subscribers_add(desk->subscribers, fd, err, err_size);
}
