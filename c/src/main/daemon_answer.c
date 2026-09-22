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
 *     * twenty-five of the thirty-two kinds are answered: every wifi verb,
 *       `reload`, `status`, `show`, `plan`, `explain`, every listing, and
 *       everything that writes a drop-in, a secret, a profile or a probe
 *       script;
 *     * every other kind is refused with a sentence that **names the request
 *       and says what is missing**, so it cannot be read as "unrecognised".
 *       `ncfg_main_answer_unported` is that table, reachable on its own so
 *       that a test walks all thirty-two rather than the handful somebody
 *       remembered.
 *
 *   The refusals are not a policy decision either: nothing in `c/src/` encodes
 *   a `journal` response -- which is what an *apply* answers with, because `proto.h` decodes every
 *   response and encodes none and the encoders belong beside the requests that
 *   produce them. When one lands, one row of the table becomes an arm --
 *   `status` and `document` are the two that have, and `daemon.h` has them.
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

/*
 * A counted list of counted fields, as an array of C strings the caller frees.
 *
 * One allocation for the pointers and one per name, freed by `names_free`. An
 * empty list answers NULL with a count of zero, which is what every consent
 * list means when nobody named anything -- and is why this answers 1 for it
 * rather than treating it as a failure.
 */
static void names_free(char **names, size_t count)
{
	size_t at;

	if (!names) {
		return;
	}
	for (at = 0; at < count; at++) {
		free(names[at]);
	}
	free(names);
}

static int names_of(ncfg_proto_strs_t list, const char *what, char ***out, size_t *count_out,
    char *err, size_t err_size)
{
	char **names;
	size_t at;

	*out = NULL;
	*count_out = 0;
	if (list.count == 0u || !list.items) {
		return 1;
	}
	names = calloc(list.count, sizeof(*names));
	if (!names) {
		ncfg_error_set(err, err_size, "there was not enough memory for the %s list", what);
		return 0;
	}
	for (at = 0; at < list.count; at++) {
		names[at] = text_of(list.items[at], what, NAME_MAX_BYTES, err, err_size);
		if (!names[at]) {
			names_free(names, at);
			return 0;
		}
	}
	*out = names;
	*count_out = list.count;
	return 1;
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
	/* The three that change the machine. `daemon.h` has them beside the
	 * reconcile pass, whose seams they share, and `desk->loop` is how this
	 * seam reaches one -- a desk without it refuses them by name rather than
	 * applying through a loop nobody gave it. */
	case NCFG_PROTO_REQ_APPLY:
	case NCFG_PROTO_REQ_CONFIRM:
	case NCFG_PROTO_REQ_REVERT:
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
	/* The three that are a model and an envelope: `daemon.h` encodes each
	 * from the model's own writer, so none can come to disagree with the file
	 * of the same shape under `/run`. */
	case NCFG_PROTO_REQ_STATUS:
	case NCFG_PROTO_REQ_SHOW:
	case NCFG_PROTO_REQ_PLAN:
	/* And the two lists whose producers were already here: the credential
	 * names and the profiles, each a call in `secrets.h` and `config.h` that
	 * this only had to wrap in an envelope. */
	case NCFG_PROTO_REQ_SECRET_LIST:
	case NCFG_PROTO_REQ_PROFILE_LIST:
	case NCFG_PROTO_REQ_CONFIG_LIST:
	case NCFG_PROTO_REQ_HOOK_LIST:
	case NCFG_PROTO_REQ_EXPLAIN:
	case NCFG_PROTO_REQ_PROBE_LIST:
	case NCFG_PROTO_REQ_MODEM_LIST:
	case NCFG_PROTO_REQ_PROBE_PUT:
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

/* ------------------------------------------------------------------------ *
 * The three that change the machine
 * ------------------------------------------------------------------------ *
 *
 * Each of these is a decode and a call: `daemon.h` has the arms themselves,
 * beside the reconcile pass whose executor seam, confirm window and ownership
 * record they share. What is left here is what this file is for -- turning
 * counted fields into C strings, and a refusal into a sentence naming the
 * request.
 *
 * **A desk with no loop refuses all three by name.** That is this struct's
 * rule and it is load-bearing here rather than tidy: the loop is what carries
 * the way to the machine, so a desk without one is a daemon that was never
 * given permission to change anything.
 */

static int answer_apply(ncfg_main_desk_t *desk, const ncfg_proto_apply_t *ask, ncfg_buf_t *out,
    char *err, size_t err_size)
{
	ncfg_daemon_apply_ask_t wanted;
	ncfg_journal_t          journal;
	char                  **disruption = NULL;
	char                  **strand = NULL;
	char                  **wedged = NULL;
	size_t                  disruption_count = 0;
	size_t                  strand_count = 0;
	size_t                  wedged_count = 0;
	int                     encoded;

	if (!desk->loop) {
		ncfg_error_set(err, err_size, "this daemon was given no way to change the "
		    "machine, so it observes and reports and applies nothing");
		return 0;
	}
	if (!names_of(ask->allow_disruption, "allow_disruption name", &disruption,
	        &disruption_count, err, err_size) ||
	    !names_of(ask->strand_credentials, "strand_credentials name", &strand, &strand_count,
	        err, err_size) ||
	    !names_of(ask->restart_wedged, "restart_wedged name", &wedged, &wedged_count, err,
	        err_size)) {
		names_free(disruption, disruption_count);
		names_free(strand, strand_count);
		names_free(wedged, wedged_count);
		return 0;
	}
	memset(&wanted, 0, sizeof(wanted));
	wanted.confirm.has = ask->confirm.present ? 1 : 0;
	wanted.confirm.value = ask->confirm.value;
	wanted.allow_disruption = (const char *const *)disruption;
	wanted.allow_disruption_count = disruption_count;
	wanted.strand_credentials = (const char *const *)strand;
	wanted.strand_credentials_count = strand_count;
	wanted.restart_wedged = (const char *const *)wedged;
	wanted.restart_wedged_count = wedged_count;

	encoded = ncfg_daemon_apply_request(desk->loop, &wanted, &journal, err, err_size);
	names_free(disruption, disruption_count);
	names_free(strand, strand_count);
	names_free(wedged, wedged_count);
	if (!encoded) {
		return 0;
	}
	encoded = ncfg_daemon_journal_encode(&journal, out, err, err_size);
	ncfg_journal_free(&journal);
	return encoded;
}

static int answer_confirm(ncfg_main_desk_t *desk, ncfg_buf_t *out, char *err, size_t err_size)
{
	if (!desk->loop) {
		ncfg_error_set(err, err_size, "this daemon was given no way to change the "
		    "machine, so there is no window of its own to confirm");
		return 0;
	}
	if (!ncfg_daemon_confirm_request(desk->loop, err, err_size)) {
		return 0;
	}
	return ncfg_daemon_ok_encode(out, err, err_size);
}

static int answer_revert(ncfg_main_desk_t *desk, ncfg_buf_t *out, char *err, size_t err_size)
{
	if (!desk->loop) {
		ncfg_error_set(err, err_size, "this daemon was given no way to change the "
		    "machine, so it cannot put anything back");
		return 0;
	}
	/* The reason the log line carries, and it is the Rust's word: a revert
	 * asked for over the socket is not the same event as one a window's timer
	 * caused, and somebody reading the log afterwards is entitled to know
	 * which of the two happened. */
	if (!ncfg_daemon_revert_request(desk->loop, "asked to", err, err_size)) {
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

/*
 * Put a link-detection script on disk.
 *
 * **The privilege question is not asked here and that is deliberate.**
 * `ncfg_authz_check_content` refuses this request from anyone but local root
 * before it reaches this dispatcher, because a probe is a program netcfgd runs
 * as root on an interval -- and an authorization question answered in two
 * places is one where the two come to disagree. By the time execution is here
 * the answer is yes.
 *
 * The ceiling is a configuration file's rather than a credential's: a probe is
 * a script somebody wrote, and `NCFG_CONFIG_FILE_MAX` is the number this port
 * already reluctantly picked for "a file a person edits".
 */
static int answer_probe_put(ncfg_main_desk_t *desk, const ncfg_proto_put_t *put,
    ncfg_buf_t *out, char *err, size_t err_size)
{
	char  name[NAME_MAX_BYTES];
	char *text;
	int   wrote;

	if (!name_of(put->name, "probe name", name, sizeof(name), err, err_size)) {
		return 0;
	}
	text = text_of(put->text, "probe script", (size_t)NCFG_CONFIG_FILE_MAX, err, err_size);
	if (!text) {
		return 0;
	}
	wrote = ncfg_probe_install(desk->state->paths.config, name, text, put->replace ? 1 : 0,
	    NULL, err, err_size);
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
	    NULL, &denied, err, err_size)) {
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

/*
 * What netcfgd would do, with what stands in the way.
 *
 * **Built fresh rather than kept**, which is the Rust's arrangement: a plan is
 * a function of the document and the observation, and a stored one is a fourth
 * thing that has to be invalidated whenever either moves.
 *
 * A configuration that did not compile answers with the diagnostics rather
 * than with a plan for the last one that did. `ncfg_daemon_document_encode`
 * says why for `show` and it is the same reason: the asker wants to know what
 * went wrong, and a plan built from a document they can no longer see is worse
 * than a refusal.
 *
 * **The contention warnings are part of the answer and not an extra.** They
 * were only ever rendered by `ncfg plan` locally, so the one client that read
 * `/run` was the one that needed them least and every other client was told
 * nothing -- the report that produced them is a GUI wifi tab with no way to
 * say why scans on a contended radio fail every other attempt. One warning per
 * interface rather than one naming several, because a client filters by the
 * interface it is showing and a warning naming three belongs to none of them.
 *
 * The claims are the document's interfaces that the kernel knows, not the
 * backends netcfgd is running: this asks "who else manages what this
 * configuration claims", which is a wider question than
 * `ncfg_main_world_release_contended`'s "what is netcfgd holding that it
 * should give back", and the two are kept apart for that reason.
 */
static void warn_about_contenders(ncfg_main_desk_t *desk, ncfg_plan_t *plan)
{
	ncfg_interface_claim_t claims[NCFG_MAIN_CLAIMS_MAX];
	ncfg_contenders_t      found;
	ncfg_buf_t             said;
	char                   message[NCFG_ERROR_MAX];
	size_t                 claim_count = 0;
	size_t                 at;
	size_t                 which;

	/* Both roots, because `ncfg_contenders_find` needs both -- it reads the
	 * other daemons' state under `/run` and asks `/proc` whether they are
	 * running at all. A desk given neither says nothing rather than logging a
	 * note per plan. */
	if (!desk->contention.run_root || !desk->contention.proc_root ||
	    !desk->state->desired || !desk->state->observed) {
		return;
	}
	for (at = 0; at < desk->state->desired->interface_count &&
	    claim_count < (size_t)NCFG_MAIN_CLAIMS_MAX; at++) {
		const char                 *name = desk->state->desired->interfaces[at].name;
		const ncfg_observed_link_t *link = name ?
		    ncfg_observed_link(desk->state->observed, name) : NULL;

		/* `ncfg_main_claims_of`'s narrowing rule, for its reason: an index
		 * that does not fit is skipped rather than truncated, because a
		 * truncated one matches a contender against an interface nobody
		 * named. */
		if (!link || link->index < 0 || link->index > (int64_t)UINT32_MAX) {
			continue;
		}
		claims[claim_count].name = name;
		claims[claim_count].index = (uint32_t)link->index;
		claim_count++;
	}
	if (claim_count == 0u) {
		return;
	}
	memset(&found, 0, sizeof(found));
	message[0] = '\0';
	if (!ncfg_contenders_find(&desk->contention, claims, claim_count, &found, message,
	        sizeof(message))) {
		/* An allocation failure and nothing else -- `apply.h` says every
		 * ordinary absence reads as "nothing found". The plan is still the
		 * answer, so this is a note rather than a refusal. */
		ncfg_log_emitf("contention", NCFG_LOG_NOTE,
		    "the plan could not say who else manages these interfaces (%s)", message);
		return;
	}
	for (at = 0; at < found.count; at++) {
		ncfg_buf_init(&said, 0);
		message[0] = '\0';
		if (!ncfg_contender_describe(&found.at[at], &said, message, sizeof(message))) {
			ncfg_buf_free(&said);
			continue;
		}
		for (which = 0; which < found.at[at].interface_count; which++) {
			ncfg_plan_warn(plan, found.at[at].interfaces[which],
			    ncfg_buf_text(&said));
		}
		ncfg_buf_free(&said);
	}
	ncfg_contenders_free(&found);
}

/*
 * Every credential this machine knows about, and who wants it.
 *
 * **The document is passed where there is one and NULL where there is not**,
 * which is `ncfg_secret_list`'s own distinction and the reason this can answer
 * a machine whose configuration has stopped compiling: the store's contents
 * are still worth listing, and what is lost is only the `used_by` half.
 *
 * Nothing here reads a value. The list says whether a file exists and who
 * refers to the name, which is what makes it a thing a client may be told.
 */
static int answer_secret_list(ncfg_main_desk_t *desk, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	ncfg_secret_entry_t *entries = NULL;
	size_t               count = 0;
	int                  wrote;

	if (!ncfg_secret_list(desk->state->paths.config, desk->state->desired, &entries, &count,
	        err, err_size)) {
		return 0;
	}
	wrote = ncfg_daemon_secrets_encode(entries, count, out, err, err_size);
	ncfg_secret_entries_free(entries, count);
	return wrote;
}

/*
 * What profiles this machine has and which one it is running.
 *
 * **`chosen` comes from the compiled document rather than from the directory**,
 * which is the distinction `cli/profile.c` exists to preserve: listing the
 * local selection would show what is on disk, and the answer a client wants is
 * what netcfgd is actually running -- those differ for as long as it takes
 * somebody to edit a file without reloading.
 */
static int answer_profile_list(ncfg_main_desk_t *desk, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	ncfg_profile_entry_t *entries = NULL;
	size_t                count = 0;
	int                   wrote;

	if (!ncfg_profile_list(desk->state->paths.config, desk->state->paths.factory, &entries,
	        &count, err, err_size)) {
		return 0;
	}
	wrote = ncfg_daemon_profiles_encode(entries, count,
	    desk->state->desired ? desk->state->desired->globals.profile : NULL, out, err,
	    err_size);
	ncfg_profile_entries_free(entries, count);
	return wrote;
}

/*
 * Every configuration file netcfgd reads, with its text.
 *
 * The listing is `ncfg_config_list_drop_ins`', which enumerates exactly what
 * the loader reads: a client shown a different set would offer an editor for a
 * file that configures nothing, or hide one that does.
 */
static int answer_config_list(ncfg_main_desk_t *desk, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	ncfg_config_entry_t *entries = NULL;
	size_t               count = 0;
	int                  wrote;

	if (!ncfg_config_list_drop_ins(desk->state->paths.config, &entries, &count, err,
	        err_size)) {
		return 0;
	}
	wrote = ncfg_daemon_configs_encode(entries, count, out, err, err_size);
	ncfg_config_entries_free(entries, count);
	return wrote;
}

/*
 * Every hook the document declares, with the script that would run.
 *
 * Read from disk at the moment it is asked for rather than remembered, which
 * `hooks.h` argues: a copy kept here is a second answer to "what runs at
 * `post_up`" and can disagree with the file the runner opens.
 */
static int answer_hook_list(ncfg_main_desk_t *desk, ncfg_buf_t *out, char *err, size_t err_size)
{
	ncfg_hook_script_t *scripts = NULL;
	size_t              count = 0;
	int                 wrote;

	if (!ncfg_hooks_list(desk->state->desired, &scripts, &count, err, err_size)) {
		return 0;
	}
	wrote = ncfg_daemon_hooks_encode(scripts, count, out, err, err_size);
	ncfg_hook_scripts_free(scripts, count);
	return wrote;
}

/*
 * Why something is the way it is.
 *
 * **The positions are read from the run directory rather than kept.** Every
 * compile that succeeds writes them there -- the daemon's reload does, and so
 * does every `ncfg` that compiles -- so what an explanation names is the
 * configuration in force whichever binary compiled it last. A table held here
 * would be a second answer that disagrees with the file the moment somebody
 * runs `ncfg show`.
 *
 * An absent or unreadable file reads as an empty table, which
 * `ncfg_state_read_provenance` guarantees: an explanation that cannot name
 * files is still worth having, and `ncfg_explain` says so as its first fact
 * rather than quietly naming none.
 *
 * A document that does not compile is not a refusal here. `explain.h` argues
 * it: the moment somebody reaches for this is often the moment the
 * configuration has stopped compiling, and the observation half of the answer
 * is worth having on its own.
 */
/*
 * Every probe script, the operator's copy of a name hiding the shipped one.
 *
 * The listing is `ncfg_probe_list`', which reads in the order the probe runner
 * does -- a listing that showed both copies would offer an editor for a script
 * that never executes.
 */
static int answer_probe_list(ncfg_main_desk_t *desk, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	ncfg_probe_entry_t *entries = NULL;
	size_t              count = 0;
	int                 wrote;

	if (!ncfg_probe_list(desk->state->paths.config, desk->state->paths.factory, &entries,
	        &count, err, err_size)) {
		return 0;
	}
	wrote = ncfg_daemon_probes_encode(entries, count, out, err, err_size);
	ncfg_probe_entries_free(entries, count);
	return wrote;
}

/*
 * Every modem device, what it asks for and what is in force.
 *
 * **Refused where this desk was given no selection**, which is
 * `ncfg_main_desk_t`'s rule and right here rather than merely consistent: what
 * a client wants is where netcfgd has *got to*, and that is the loop's memory
 * rather than anything the document says. Answering from the document alone
 * would describe a machine on its first SIM whatever had happened since.
 */
static int answer_modem_list(ncfg_main_desk_t *desk, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	ncfg_proto_modem_t *modems = NULL;
	size_t              count = 0;
	int                 wrote;

	if (!desk->sims) {
		ncfg_error_set(err, err_size,
		    "this daemon was not given a SIM selection to report, so it cannot say "
		    "which source each modem is on");
		return 0;
	}
	if (!ncfg_sims_status(desk->sims, desk->state->desired, &modems, &count, err, err_size)) {
		return 0;
	}
	wrote = ncfg_daemon_modems_encode(modems, count, out, err, err_size);
	ncfg_sims_status_free(modems, count);
	return wrote;
}

static int answer_explain(ncfg_main_desk_t *desk, const ncfg_proto_subject_t *subject,
    ncfg_buf_t *out, char *err, size_t err_size)
{
	ncfg_provenance_t   provenance;
	ncfg_explanation_t *explanation;
	int                 wrote;

	memset(&provenance, 0, sizeof(provenance));
	(void)ncfg_state_read_provenance(desk->state->paths.run, &provenance, NULL, 0);
	explanation = ncfg_explain(subject, desk->state->desired, desk->state->observed,
	    &provenance, err, err_size);
	ncfg_provenance_free(&provenance);
	if (!explanation) {
		return 0;
	}
	wrote = ncfg_daemon_explanation_encode(explanation, out, err, err_size);
	ncfg_explanation_free(explanation);
	return wrote;
}

static int answer_plan(ncfg_main_desk_t *desk, ncfg_buf_t *out, char *err, size_t err_size)
{
	ncfg_plan_t *plan;
	int          wrote;

	if (!desk->state->desired) {
		ncfg_error_set(err, err_size, "%s",
		    desk->state->diagnostics && desk->state->diagnostics[0] ?
		        desk->state->diagnostics : "no configuration");
		return 0;
	}
	if (!desk->state->observed) {
		ncfg_error_set(err, err_size,
		    "this daemon has not managed to observe the machine, so it cannot say what "
		    "it would do to it");
		return 0;
	}
	plan = ncfg_plan_build(desk->state->desired, desk->state->observed, NULL, err, err_size);
	if (!plan) {
		return 0;
	}
	warn_about_contenders(desk, plan);
	wrote = ncfg_daemon_plan_encode(plan, out, err, err_size);
	ncfg_plan_free(plan);
	return wrote;
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
	case NCFG_PROTO_REQ_APPLY:
		return answer_apply(desk, &request->u.apply, out, err, err_size);
	case NCFG_PROTO_REQ_CONFIRM:
		return answer_confirm(desk, out, err, err_size);
	case NCFG_PROTO_REQ_REVERT:
		return answer_revert(desk, out, err, err_size);
	/*
	 * The two that are a model and an envelope. Both refuse rather than
	 * inventing an empty answer, and `daemon.h` argues each: an observation
	 * with no links is not a machine with nothing on it, and the reason a
	 * configuration did not compile is the answer to "show me the
	 * configuration".
	 */
	case NCFG_PROTO_REQ_STATUS:
		return ncfg_daemon_status_encode(desk->state->observed, out, err, err_size);
	case NCFG_PROTO_REQ_SHOW:
		return ncfg_daemon_document_encode(desk->state->desired, desk->state->diagnostics,
		    out, err, err_size);
	case NCFG_PROTO_REQ_PLAN:
		return answer_plan(desk, out, err, err_size);
	case NCFG_PROTO_REQ_SECRET_LIST:
		return answer_secret_list(desk, out, err, err_size);
	case NCFG_PROTO_REQ_PROFILE_LIST:
		return answer_profile_list(desk, out, err, err_size);
	case NCFG_PROTO_REQ_CONFIG_LIST:
		return answer_config_list(desk, out, err, err_size);
	case NCFG_PROTO_REQ_HOOK_LIST:
		return answer_hook_list(desk, out, err, err_size);
	case NCFG_PROTO_REQ_EXPLAIN:
		return answer_explain(desk, &request->u.explain, out, err, err_size);
	case NCFG_PROTO_REQ_PROBE_LIST:
		return answer_probe_list(desk, out, err, err_size);
	case NCFG_PROTO_REQ_MODEM_LIST:
		return answer_modem_list(desk, out, err, err_size);
	case NCFG_PROTO_REQ_PROBE_PUT:
		return answer_probe_put(desk, &request->u.put, out, err, err_size);
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
	case NCFG_PROTO_REQ_MONITOR:
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
