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

/* ------------------------------------------------------------------ models
 *
 * The shapes a screen draws, in C.
 *
 * gui/project.md sec 3 puts "the models behind interfaces/wifi/plan" below the
 * seam, and the first commit put the link conversion above it by mistake --
 * corrected here rather than left as a precedent, because three more screens
 * would have made it the pattern.
 *
 * Each is a flat array the caller frees with one call. Strings are owned by the
 * result and NUL-terminated: a widget wants a C string, and counted strings
 * were the reader's business rather than a screen's.
 */

/* One interface, as `status` reports it. */
typedef struct {
	char *name;
	char *kind;      /* the kernel's link kind; "" for a real NIC */
	char *mac;
	char *addresses; /* comma-separated, already ordered by the daemon */
	int   mtu;
	int   up;
	int   carrier;   /* up and carrier are separate answers: no cable is not
	          * the same state as not configured */
	/*
	 * Whether this link is a radio, so that a client can offer the wireless
	 * screens for it.
	 *
	 * Here rather than in a screen because it is not a visual question, and
	 * because the rule is a *heuristic* that should exist once: the kernel's
	 * link kind is `wlan` where it says anything at all, and otherwise the
	 * name is the only clue. `ncfg tui` asks it the same way, which is one
	 * rule in two languages until the protocol is specified -- the exact drift
	 * decision 0116 names and does not yet fix.
	 *
	 * The name half is a convention rather than a fact, in the same way `eth0`
	 * is, so it is the fallback and never the first test.
	 */
	int   wireless;
} ncfg_link_t;

typedef struct {
	ncfg_link_t *items;
	size_t       count;
} ncfg_links_t;

/*
 * One action in a plan.
 *
 * The reason is the half that matters. netcfgd's whole product claim is that
 * it is not a black box (project.md constraint 7), and an action without its
 * reason is exactly the black box -- so `field`, `desired` and `observed` are
 * carried through to the screen rather than summarised into a verb.
 */
typedef struct {
	long long id;
	char     *op;        /* "addr.add", "link.up", ... */
	char     *interface; /* "" where the op names none */
	char     *field;
	char     *desired;
	char     *observed;
	int       reversible; /* an action with no inverse is one a confirm
	               * window cannot undo, and the plan says so loudly */
} ncfg_action_t;

/*
 * A warning, a refusal or a stranded credential: three lists that all read as
 * "something the operator has to know", differing in how hard they stop the
 * apply.
 *
 * The two remedies are two, and not one, on purpose. `remedy` is the change
 * that makes the situation not arise -- `on_unmanage = "clear"` for a key
 * netcfgd is about to walk away from -- and `consent` is the flag that
 * proceeds anyway. `ncfg` prints them in that order deliberately, so that the
 * flag does not read as the fix, and flattening them into one field loses
 * whichever the client did not pick. The first draft of this struct did, and
 * kept the flag.
 *
 * The reason is here for the same argument that put it on an action: constraint
 * 7 says netcfgd is not a black box, and a refusal that cannot say what the
 * action would have been is the black box in the one place an operator is
 * already being told no. Empty where the note has no reason, which is every
 * warning and every stranded credential.
 */
typedef struct {
	char *message;
	char *interface;
	char *detail;  /* the guard's words or the credential's; empty for a
	        * plain warning */
	char *remedy;  /* the change that makes it not happen; empty where there
	        * is none, which is every refusal */
	char *consent; /* what to pass to proceed anyway; empty where nothing
	        * will */
	char *field;
	char *desired;
	char *observed;
} ncfg_note_t;

typedef struct {
	ncfg_action_t *actions;
	size_t         action_count;
	ncfg_note_t   *warnings;
	size_t         warning_count;
	ncfg_note_t   *refusals;
	size_t         refusal_count;
	ncfg_note_t   *stranded;
	size_t         stranded_count;
} ncfg_plan_t;

/* One line of what an apply did. `outcome` is the daemon's own word -- "done",
 * "failed", "skipped" -- because a client that renamed them would make two
 * vocabularies for one thing. */
typedef struct {
	long long id;
	char     *op;
	char     *interface;
	char     *outcome;
	char     *detail;
} ncfg_record_t;

typedef struct {
	ncfg_record_t *items;
	size_t         count;
} ncfg_journal_t;

/*
 * One event from a monitor stream.
 *
 * `kind` is the daemon's own: observed, reloaded, drift, confirm_armed,
 * confirm_resolved. The witness pins these payloads on their own as well as
 * wrapped in `{"response":"event",...}`, which is how the reader's test found
 * that a stream carries a third kind of line.
 *
 * `summary` is what to put on a line in a pane. `raw` is the whole event as it
 * arrived, for a pane that wants to show everything -- kept because an event
 * netcfgd grows a field for should not become invisible to a client built
 * before it.
 */
typedef struct {
	char *kind;
	char *interface;
	char *summary;
	char *raw;
} ncfg_event_t;

/*
 * What this connection may do, asked once.
 *
 * Three independent answers and not a level: netcfgd's tiers are three group
 * memberships, and a machine may grant `admin` to a group somebody is in while
 * `wifi` goes to one they are not. A client that treated them as a ladder would
 * offer something the daemon refuses.
 *
 * Why a screen needs this at all: without it the only way to learn what an
 * operator may do is to try it and read the refusal, so a window offers an
 * apply button and the first thing that happens when it is pressed is a no.
 * gui/project.md sec 4 asks for the opposite.
 */
typedef struct {
	int observe;
	int wifi;
	int admin;
} ncfg_tiers_t;

/*
 * Ask the daemon what this connection holds.
 *
 * Returns 1 on success. On failure `out` is left with nothing granted, which is
 * the safe direction: a client that could not ask should offer less rather than
 * more.
 */
int ncfg_client_tiers(ncfg_client_t *client, ncfg_tiers_t *out, char *err, size_t err_size);

/*
 * The machine's own commit-confirm window, in seconds, or 0 if it names none.
 *
 * `global { confirm = N }` in the configuration. A client that hardcoded a
 * default would disagree with `ncfg apply` on the same machine about how long
 * an operator has to confirm -- two clients, two answers, one question, which
 * is the shape this project keeps having to undo.
 *
 * Read out of the compiled document, which is the only place it is. That is a
 * large answer for one number and it is asked once, when a dialog opens.
 *
 * Returns 1 on success, including when the machine names none.
 */
int ncfg_client_confirm_default(ncfg_client_t *client, unsigned *out, char *err, size_t err_size);

/*
 * One access point a scan found.
 *
 * THREE NAMES, AND THEY ARE THREE
 *   `ssid` is hex and is the canonical one: an SSID is 32 arbitrary octets
 *   (project.md sec 2.1), so it is the only field always present and the only
 *   one two networks cannot collide in after rendering.
 *
 *   `name` is that SSID as text, and `named` says whether the daemon sent it at
 *   all. The daemon omits it rather than mangling it, "so a client can tell
 *   'not text' from 'empty'" -- and an empty name is a real thing, because that
 *   is what a hidden network broadcasts. Collapsing the two would make a hidden
 *   network and a network named in Shift-JIS the same row.
 *
 *   `configured` is the id of the `network` block describing it, and empty when
 *   the configuration has none. It is what decides whether this entry can be
 *   joined at all: decision 0013 puts joining a *known* network in the `wifi`
 *   tier, and writing config for an unknown one in `admin`. The proto's own note
 *   on this field asks the client to show the difference, because the
 *   alternative is the operator discovering it by being refused.
 */
typedef struct {
	char *bssid;
	char *ssid;       /* hex; always present */
	char *name;       /* the SSID as text, "" when it is not text */
	char *configured; /* network id, "" when the configuration has none */
	/*
	 * The three cases resolved into the one string a screen shows:
	 * the text where there is text, `(hidden)` for a name that arrived
	 * empty, and `hex:<ssid>` where none arrived at all.
	 *
	 * Here and not in a widget because it is vocabulary rather than
	 * layout, and every client has to say the same words -- the GUI said
	 * one thing, `ncfg wifi scan` another and the TUI a third until this
	 * moved down. netcfgd-cli's access_point_name() is the same three
	 * cases in Rust, and `make conformance` diffs the two.
	 */
	char *display;
	int   named;      /* whether a text name was sent at all */
	int   frequency;  /* MHz */
	int   signal;     /* dBm, closer to zero is stronger */
	int   secured;    /* joining it needs a credential */
} ncfg_access_point_t;

typedef struct {
	char                *interface;
	ncfg_access_point_t *items;
	size_t               count; /* strongest first, as the daemon ordered them */
} ncfg_scan_t;

/*
 * What a radio is currently doing.
 *
 * `state` is the supplicant's own word -- `COMPLETED`, `SCANNING`, `INACTIVE`
 * -- and is not translated here, for the reason every other daemon word in this
 * header is kept: a client that invented a vocabulary would give an operator two
 * names for one condition, and the supplicant's is the one that matches every
 * other tool on the machine.
 *
 * `network` empty while associated is worth showing rather than hiding. After
 * decision 0015 the supplicant holds no state of its own, so a radio on a
 * network the document did not put there is a discrepancy, not a gap.
 */
typedef struct {
	char *interface;
	char *state;
	char *ssid; /* hex, "" when not associated */
	char *name; /* as text, "" when not associated or not text */
	char *bssid;
	char *network; /* the `network` block it came from */
} ncfg_wifi_status_t;

/*
 * Whether a link with this kind and name is a radio.
 *
 * Exposed rather than left inside the conversion because it is a *rule*, and
 * the same rule is written again in Rust in `ncfg tui`. Two implementations of
 * one heuristic is the drift 0116 names; a conformance check can only compare
 * them if both are reachable, so this is the C half being reachable.
 *
 * `kind` may be NULL or empty, which is what the kernel reports for a real NIC.
 */
int ncfg_link_is_wireless(const char *kind, const char *name);

/*
 * The one string a screen shows for an access point's name, as a function.
 *
 * `ncfg_access_point_t` already carries the answer, and this is the same rule
 * reachable without a scan -- which is what lets the conformance dump ask for
 * the two cases the witness does not contain. Returns a string the caller
 * frees, or NULL if it could not be allocated.
 */
char *ncfg_access_point_display(int named, const char *name, const char *ssid);

void ncfg_links_free(ncfg_links_t *links);
void ncfg_plan_free(ncfg_plan_t *plan);
void ncfg_journal_free(ncfg_journal_t *journal);
void ncfg_event_free(ncfg_event_t *event);
void ncfg_scan_free(ncfg_scan_t *scan);
void ncfg_wifi_status_free(ncfg_wifi_status_t *status);

/*
 * The three requests the models above are for.
 *
 * Each returns 1 on success. On a refusal from the daemon they return 0 with
 * `err` holding the daemon's own message -- a refusal names the tier that would
 * have been needed (0013), and replacing it with a message of this library's
 * own would throw away the sentence that says what to do about it.
 */
int ncfg_client_links(ncfg_client_t *client, ncfg_links_t *out, char *err, size_t err_size);
int ncfg_client_plan_of(ncfg_client_t *client, ncfg_plan_t *out, char *err, size_t err_size);

/*
 * A network to add to the configuration.
 *
 * Typed fields and nothing else, which is decision 0117's whole point: a
 * config file may name a hook, and a hook's `run_as` defaults to root, so a
 * request able to carry config *text* would be remote code execution. There is
 * no field here that could name a hook, a path or a `run_as`, and there is no
 * enterprise arm because those carry certificate paths.
 *
 * `ssid` is lowercase hex and required -- an SSID is 0..32 arbitrary octets, so
 * hex is the only form that always works. Everything else may be NULL or
 * negative to leave it out, and the daemon applies netcfgd's own defaults
 * rather than this library inventing them.
 */
typedef struct {
	const char *ssid;       /* lowercase hex; required */
	const char *id;         /* NULL derives one from the ssid, where it is text */
	const char *passphrase; /* NULL for an open network */
	const char *proto;      /* NULL, "wpa2" or "wpa3" */
	int         hidden;
	int         priority; /* negative to leave it out */
} ncfg_network_t;

/*
 * Add a wireless network, and store its credential through the daemon.
 *
 * The **only** call in this library that carries a secret, and it carries it
 * one way: the daemon writes it through the secret provider and the config
 * file keeps an `@secret:` reference, so nothing reads one back out (0029,
 * 0031). Needs the `admin` tier, because writing configuration is what admin
 * names -- a refusal will say so.
 *
 * The request buffer is wiped before returning. That is not a guarantee about
 * the caller's own copy of the passphrase, which this cannot reach.
 */
int ncfg_client_wifi_add(ncfg_client_t *client, const ncfg_network_t *network, char *err,
             size_t err_size);

/*
 * The wireless half, on one named interface.
 *
 * `interface` is quoted rather than interpolated on the way out, for the reason
 * ncfg_client_quote() exists: a name is not guaranteed to be a bare word.
 *
 * A scan takes as long as a scan takes -- seconds, on a real radio, because the
 * card has to visit the channels. That is the caller's problem to present and
 * not this layer's to hide behind a cache: a stale list of access points is a
 * list of places that may no longer be there.
 *
 * ncfg_client_wifi_connect() names the network by its **id in the document**,
 * never by SSID and never with a credential. That is decision 0013's boundary
 * expressed as a signature: this call cannot be used to join something the
 * configuration does not already describe, so it stays inside the `wifi` tier,
 * and no passphrase ever crosses this interface in either direction (0029,
 * 0031). Joining something new is writing a config file (0069) and is not a
 * socket operation at all.
 */
int ncfg_client_wifi_scan(ncfg_client_t *client, const char *interface, ncfg_scan_t *out,
              char *err, size_t err_size);
int ncfg_client_wifi_status(ncfg_client_t *client, const char *interface,
                ncfg_wifi_status_t *out, char *err, size_t err_size);
int ncfg_client_wifi_connect(ncfg_client_t *client, const char *interface, const char *network,
                 char *err, size_t err_size);
int ncfg_client_wifi_disconnect(ncfg_client_t *client, const char *interface, char *err,
                size_t err_size);

/*
 * What an operator has agreed to, beyond the plan itself.
 *
 * Two lists and never a flag, which is netcfgd's own shape: `ncfg` spells these
 * `--allow-disruption IFACE` and `--strand-credentials DEV`, both repeatable and
 * "deliberately not a blanket --force". They consent to different things and a
 * client that ran them together would be offering one decision where the daemon
 * asks two -- an operator who accepted a brief outage on one interface has not
 * agreed to leave a private key on another.
 *
 * Empty is the ordinary case: a plan with no refusals needs neither.
 */
typedef struct {
	const char *const *disrupt; /* interfaces a guard is refusing */
	size_t             disrupt_count;
	const char *const *strand; /* devices whose credential would be left behind */
	size_t             strand_count;
} ncfg_consent_t;

/*
 * Apply, with a confirm window in seconds or 0 for none.
 *
 * The window is a parameter and not a default because it is a decision: a
 * change that cuts off the person making it is what commit-confirm exists for,
 * and a client that always armed one would make an operator confirm every
 * trivial apply -- while one that never did would let a bad change lock
 * somebody out of their own router. The screen asks.
 *
 * `consent` may be NULL, which means none was given and is what a plan with no
 * refusals passes. It is a separate argument rather than a field on the plan
 * because it is the operator's answer and not the daemon's question: the plan
 * says what is refused, and this says which of those the person at the screen
 * has agreed to. Sending back a mutated plan would blur which of the two said
 * what.
 */
int ncfg_client_apply(ncfg_client_t *client, unsigned confirm_seconds,
              const ncfg_consent_t *consent, ncfg_journal_t *out, char *err,
              size_t err_size);
int ncfg_client_confirm(ncfg_client_t *client, char *err, size_t err_size);
int ncfg_client_revert(ncfg_client_t *client, char *err, size_t err_size);

/* ----------------------------------------------------------------- monitor
 *
 * A stream, on a connection of its own.
 *
 * `monitor` turns a connection into a stream and it never goes back, so it
 * cannot share the one requests use -- the daemon reads requests from a
 * connection in a loop until this arrives, and after it the connection only
 * carries events.
 *
 * The file descriptor is exposed because a UI has an event loop already and
 * this library must not own one: Qt watches the descriptor and calls
 * ncfg_monitor_next when it is readable, and an ncurses client would put it in
 * its own poll set. A library that ran its own thread here would be a library
 * that decides how the program is structured.
 */
typedef struct ncfg_monitor ncfg_monitor_t;

ncfg_monitor_t *ncfg_monitor_open(const char *socket_path, char *err, size_t err_size);
void ncfg_monitor_close(ncfg_monitor_t *monitor);

/* Watchable, and never written to by the caller. */
int ncfg_monitor_fd(const ncfg_monitor_t *monitor);

/*
 * The next event, if a whole one has arrived.
 *
 * Returns 1 and fills `out` for an event, 0 when the descriptor has no
 * complete line waiting (which is the ordinary answer and not an error), and
 * -1 with `err` when the stream is gone -- which a UI shows rather than
 * hides, since a monitor that silently stopped would leave a pane looking
 * merely quiet.
 *
 * Never blocks. The descriptor is non-blocking and a partial line is kept for
 * the next call.
 */
int ncfg_monitor_next(ncfg_monitor_t *monitor, ncfg_event_t *out, char *err, size_t err_size);

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
