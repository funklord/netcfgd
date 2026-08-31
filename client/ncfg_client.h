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
 *   vocabulary is pinned by doc/schema/socket.json, which exists so that a
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
	 * Whether a default route leaves through this link, in the main table.
	 *
	 * **Three separate answers, and a screen that conflates them lies.** A
	 * link can be up with no carrier, carry traffic with no address, and hold
	 * an address with nothing to route through -- so "connected" is not any
	 * one of `up`, `carrier` or a non-empty `addresses`. The tray showed a
	 * radio as connected on association alone, which is the earliest of the
	 * four and the least informative: it is true of a machine that never got
	 * a lease.
	 *
	 * Table 254 (`main`) only. A default route in another table belongs to a
	 * policy rule and says nothing about where this machine's ordinary
	 * traffic goes.
	 *
	 * Still not a promise that anything answers -- that needs a packet, and
	 * decision 0061 declined to have netcfgd choose a host to send one to.
	 * It is the last thing observable without asking the network, which
	 * makes it the honest ceiling for an icon.
	 */
	int   default_route;
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
	int   enterprise; /* that credential is 802.1X, not a passphrase */
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
 * The 802.1X half of a network, for an enterprise one.
 *
 * WHY THE CERTIFICATES ARE NAMES
 *   Each of these is the **name of a secret the daemon already holds** and
 *   never a path. A path is an instruction to open a file as root, so
 *   configuration containing one is privileged and a client that is not root
 *   cannot send it. A name refers to content somebody already gave the daemon,
 *   so it grants nothing new.
 *
 *   Putting it there is ncfg_client_secret_put(), or `ncfg secret set NAME <
 *   file` at a terminal. Note the tier: storing a secret is `admin` and adding
 *   a network is `wifi`, so a client may well be able to do the second and not
 *   the first. Ask ncfg_client_tiers() before offering it.
 *
 *   There is no field here a path could be written in. That is the difference
 *   between a rule and a property: nothing has to remember to check.
 *
 *   This is why the header used to say there was no enterprise arm at all --
 *   "because those carry certificate paths". They no longer do.
 *
 * WHY THERE IS NO private_key
 *   It is the field a reader looks for first. For `tls` the private key *is*
 *   the credential: it travels in ncfg_network_t's `passphrase`, is stored
 *   under the network's own id, and the config file gets
 *   `private_key = "@secret:<id>"` from that. A second field naming a
 *   different stored secret would be a second answer to one question.
 */
typedef struct {
	const char *method;   /* "peap", "ttls", "tls" or "pwd"; required */
	const char *identity; /* who you are to the authentication server */
	const char *anonymous_identity; /* who you are outside the tunnel; NULL to omit */
	const char *phase2;             /* the inner method, such as "mschapv2" */
	const char *ca_cert;            /* name of a stored certificate; NULL to omit */
	const char *client_cert;        /* name of a stored certificate; NULL to omit */
} ncfg_eap_t;

/*
 * A network to add to the configuration.
 *
 * Typed fields and nothing else, which is decision 0117's whole point: a
 * config file may name a hook, and a hook's `run_as` defaults to root, so a
 * request able to carry config *text* would be remote code execution. There is
 * no field here that could name a hook, a path or a `run_as`.
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
	/*
	 * NULL for an ordinary network. With one, `proto` must be NULL: it pins
	 * the generation protecting a passphrase, and an enterprise network
	 * negotiates its own. The daemon refuses the pair rather than picking.
	 */
	const ncfg_eap_t *eap;
} ncfg_network_t;

/*
 * Add a wireless network, and store its credential through the daemon.
 *
 * The **only** call in this library that carries a secret, and it carries it
 * one way: the daemon writes it through the secret provider and the config
 * file keeps an `@secret:` reference, so nothing reads one back out (0029,
 * 0031). Needs the `wifi` tier: 0124 moved it there, because a request
 * carrying an SSID and a credential is not the thing `admin` exists to
 * bound -- that is a request carrying config *text*. A refusal names the
 * tier that would have been needed.
 *
 * The request buffer is wiped before returning. That is not a guarantee about
 * the caller's own copy of the passphrase, which this cannot reach.
 */
int ncfg_client_wifi_add(ncfg_client_t *client, const ncfg_network_t *network, char *err,
             size_t err_size);

/*
 * Store a credential the configuration refers to, under a name.
 *
 * The general form of what ncfg_client_wifi_add() does for one network: a
 * client cannot write `/etc/netcfgd/secrets`, so a value it holds -- a
 * certificate, a VPN password, an 802.1X password -- comes here and netcfgd
 * writes it at 0600.
 *
 * WHICH TIER, AND WHY IT IS NOT THE WIFI ONE
 *   `admin`, while ncfg_client_wifi_add() is `wifi`, and the difference is the
 *   blast radius of the **name**. An add writes a secret it also names, for a
 *   network it is creating, and refuses outright if either the network file or
 *   the secret already exists -- so it cannot touch anything that was already
 *   there. This writes any name the configuration might refer to, including
 *   one a `wireguard` block reads, which 0042 calls the one thing on a machine
 *   nobody can get back.
 *
 *   So a client may hold `wifi` and not `admin`, and offering this without
 *   asking ncfg_client_tiers() first produces a refusal after the operator has
 *   already done the work of choosing a file.
 *
 * `name` is a name and never a path, checked by the same rule a network id is.
 * `replace` opens the overwrite that the paragraph above is about: without it
 * an existing secret is refused rather than replaced.
 *
 * Inbound only. There is no call here that reads a secret back and there is
 * not going to be (0029, 0031): what crosses this socket is a value going in.
 *
 * The request buffer is wiped before returning, which is not a guarantee about
 * the caller's own copy of the value.
 */
/*
 * Write a configuration drop-in, by name, through the daemon.
 *
 * `name` is the file's stem under `conf.d`; `text` is the block it contains.
 * `replace` allows overwriting one that is already there, so that a client
 * cannot clobber a file by forgetting it existed.
 *
 * **This is `admin`, and the tier is not the whole guard.** It writes
 * configuration, so the daemon runs `check_content` over the text afterwards
 * and refuses anything granting more than configuring a network -- a hook, a
 * path, a `run_as`. That is what makes opening `admin` to a group survivable
 * rather than equivalent to handing it root (0117).
 *
 * The daemon re-reads its configuration on success, so a caller does not
 * follow this with a reload.
 */
int ncfg_client_config_put(ncfg_client_t *client, const char *name, const char *text, int replace,
    char *err, size_t err_size);

/*
 * One link-detection script, as netcfgd sees it.
 *
 * `editable` is whether netcfgd would overwrite this file. A shipped example
 * is not edited in place: an edit becomes a copy in /etc with the same name,
 * which then shadows it -- so a client can offer the right verb rather than
 * promising something the next upgrade undoes.
 */
typedef struct {
	char *name;
	char *directory;
	char *text;
	int   editable;
} ncfg_probe_t;

typedef struct {
	ncfg_probe_t *items;
	size_t        count;
} ncfg_probes_t;

void ncfg_probes_free(ncfg_probes_t *probes);

/*
 * One profile the machine could be switched to.
 *
 * `shipped` says the profile came from the factory directory rather than from
 * /etc, so a client can say whose it is. An operator's copy of a shipped
 * profile reads as theirs, because theirs is what layers on top.
 */
typedef struct {
	char *name;
	int   shipped;
} ncfg_profile_t;

typedef struct {
	ncfg_profile_t *items;
	size_t          count;
	/* The profile in effect, or NULL. NULL is the default and is not a
	 * profile called "none": it means the machine runs its own
	 * configuration. */
	char           *chosen;
} ncfg_profiles_t;

void ncfg_profiles_free(ncfg_profiles_t *profiles);

/*
 * The profiles netcfgd can see, and which one is chosen. Needs `observe`.
 *
 * Asked of the daemon rather than read off the disk, for the reason
 * `ncfg_client_probes` gives: a client listing its own /etc/netcfgd/profile
 * would be showing the machine it runs on while configuring a different one,
 * and would then offer to switch that machine to a profile it does not have.
 *
 * Choosing one is not a verb of its own -- it is `ncfg_client_config_put` of a
 * drop-in named "90-profile", which is an ordinary configuration write and
 * needs `admin` like any other.
 */
int ncfg_client_profiles(ncfg_client_t *client, ncfg_profiles_t *out, char *err,
                         size_t err_size);

/*
 * Choose a profile, or stop using one. `name` NULL means stop. Needs `admin`.
 *
 * **A verb rather than a write of a known filename.** netcfgd owns the drop-in
 * the selection lives in; a client that spelled that name would be a second
 * copy of it, going stale the day the name changes in a client nobody
 * rebuilt. A name with no profile directory is refused by the daemon, which is
 * the machine that would have to read it.
 *
 * The network is reconfigured as soon as this returns: netcfgd reconciles a
 * changed configuration on its own. There is no later step at which somebody
 * gets to look, so ask before calling it.
 */
int ncfg_client_profile_set(ncfg_client_t *client, const char *name, char *err,
                            size_t err_size);

/*
 * The link-detection scripts netcfgd can see. Needs `observe`.
 *
 * **Asked of the daemon rather than read off the disk, and that is the whole
 * point.** A client only ever talks to netcfgd; these files belong to the
 * machine netcfgd runs on. A client that listed its own /etc/netcfgd/probe
 * would be showing the machine it is running on while configuring a different
 * one -- and would then save an edit of one machine's script onto another.
 *
 * The text comes with the listing: they are a few hundred bytes each, and a
 * second round trip per script would buy nothing and would mean a list and a
 * body that could disagree.
 */
int ncfg_client_probes(ncfg_client_t *client, ncfg_probes_t *out, char *err, size_t err_size);

/*
 * Write a link-detection script, through the daemon.
 *
 * `name` is a plain filename; netcfgd chooses the directory
 * (`/etc/netcfgd/probe`) and a name carrying a separator is refused, because
 * otherwise the caller would be choosing where an executable lands.
 *
 * **Needs root on this machine, not merely the `admin` tier.** A probe is a
 * program netcfgd runs as root on an interval, which is the most dangerous
 * payload this socket carries -- more than the privileged *productions*
 * `config_put` is checked for, since those name a program and this one is the
 * program. A site that opened `admin` to a group has not thereby granted this.
 *
 * It exists rather than letting a client write the file because that is 0127:
 * a client cannot write system files, and system configuration cannot live
 * under a user.
 */
int ncfg_client_probe_put(ncfg_client_t *client, const char *name, const char *text, int replace,
    char *err, size_t err_size);

int ncfg_client_secret_put(ncfg_client_t *client, const char *name, const char *value,
               int replace, char *err, size_t err_size);

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
/*
 * One radio, and whether netcfgd has been given it.
 *
 * `activated` is a `device` block with a `wifi` section and no
 * `managed = false`: netcfgd's own record of being asked to manage the radio.
 * `supplicant` is whether a supplicant answers on it.
 *
 * THE THIRD STATE IS THE ONE THAT MATTERS
 *   Not activated with a supplicant answering means **another manager holds
 *   this radio** -- NetworkManager, most often. netcfgd declines those rather
 *   than taking them, so offering an "activate" that cannot work would waste
 *   somebody's afternoon. A client showing these should say who to stop.
 *
 * `supplicant` is netcfgd's answer rather than the machine's: the probe is a
 * connect to a socket wpa_supplicant gives to one group, so a daemon running
 * as an ordinary user reports 0 for one that is plainly there. That is the
 * right answer to "can netcfgd reach it", which is what a client needs.
 */
typedef struct {
	char *interface;
	int   activated;
	int   supplicant;
} ncfg_radio_t;

typedef struct {
	ncfg_radio_t *items;
	size_t        count;
} ncfg_radios_t;

void ncfg_radios_free(ncfg_radios_t *radios);

/*
 * The radios this machine has, whether or not netcfgd manages them.
 *
 * Every wireless interface the kernel reports, because the list exists so that
 * somebody can turn one on: a list of only the ones already on could not offer
 * that. Needs `observe`.
 */
int ncfg_client_radios(ncfg_client_t *client, ncfg_radios_t *out, char *err, size_t err_size);

/*
 * A wireless network the configuration describes, in range or not.
 *
 * **Distinct from a scan, and that is the whole point.** `ncfg_client_wifi_scan`
 * answers "what is around me", and every screen built on it can only show a
 * configured network while it happens to be broadcasting. An operator asking
 * "which networks do I have saved" is asking about the document, and before
 * this there was nowhere to read that: no client call, no `ncfg` subcommand
 * and no pane. The answer came from the compiled document, which is the only
 * place it is -- the same route `ncfg_client_confirm_default` takes.
 *
 * `ssid` is lowercase hex for the reason it is everywhere else here: an SSID
 * is 0..32 arbitrary octets and need not be text. Pass it through
 * ncfg_access_point_display() with `named` set from whether `name` is
 * non-empty, so that one rule spells these for every screen.
 *
 * `priority` is the document's, where higher wins -- wpa_supplicant's
 * convention, and the opposite of a route metric. A screen showing both should
 * not imply they order the same way.
 */
typedef struct {
	char *id;          /* the network's id in the document; how to name it */
	char *name;        /* the SSID as text, "" when it is not text */
	char *ssid;        /* lowercase hex; always present */
	char *security;    /* "psk", "eap", "open", "owe", or "" if unstated */
	/*
	 * The secret this network refers to, or "" where it needs none.
	 *
	 * **A reference, not a presence.** The document says the network wants
	 * `@secret:<name>`; whether that file exists is an observed fact and this
	 * comes from the compiled document. So a client may say a credential is
	 * *configured* and must not say it is *stored* -- the two differ exactly
	 * when a network was written and its passphrase never was, which is the
	 * case decision 0031 answers by asking an agent.
	 *
	 * Which key it came from depends on the security: `psk` for a passphrase,
	 * `password` for the inner one of an enterprise network, `private_key` for
	 * a certificate. A client showing dots does not need to care; one naming
	 * the reference does.
	 */
	char *credential;
	int   priority;    /* higher wins; 0 when the document names none */
	int   autoconnect; /* whether it may be joined without being asked */
	int   hidden;      /* whether the document says it does not broadcast */
} ncfg_saved_network_t;

typedef struct {
	ncfg_saved_network_t *items;
	size_t                count;
} ncfg_saved_networks_t;

void ncfg_saved_networks_free(ncfg_saved_networks_t *networks);

/*
 * Every wireless network the configuration describes. Needs `observe`.
 */
int ncfg_client_saved_networks(ncfg_client_t *client, ncfg_saved_networks_t *out, char *err,
    size_t err_size);

/*
 * What the configuration says about name resolution, and whether it is on.
 *
 * **`mode` is `none` unless a document says otherwise, and `none` means
 * netcfgd does not touch resolution at all.** That default is right -- it is
 * the correct answer on a machine where something else owns
 * /etc/resolv.conf -- and it is invisible: a machine whose resolv.conf was
 * written by a NetworkManager that has since been stopped keeps working off a
 * stale file, and nothing anywhere says netcfgd is deliberately not managing
 * it. That was a real report, from an operator whose DHCP was fine and whose
 * DNS never updated, and the fault was that no screen could show this field.
 *
 * `managing` is the observed half rather than the configured one: whether
 * netcfgd currently holds any resolver state. A `mode` that is not `none`
 * with `managing` zero is a configuration that has not taken effect yet.
 */
typedef struct {
	char  *mode;         /* "none", "write_resolv_conf", "resolved", ... */
	char **servers;      /* configured servers, if the document names any */
	size_t server_count;
	char **search;
	size_t search_count;
	int    managing;     /* netcfgd holds resolver state right now */
} ncfg_dns_t;

void ncfg_dns_free(ncfg_dns_t *dns);

/*
 * How name resolution is configured, and whether netcfgd is doing it.
 * Needs `observe`.
 */
int ncfg_client_dns(ncfg_client_t *client, ncfg_dns_t *out, char *err, size_t err_size);

/*
 * Take a radio on, or hand it back.
 *
 * Needs the `wifi` tier rather than `admin`, and the reason is the shape of
 * this call. What activation writes is a `device` block, and a client that
 * sent one as *text* would be sending configuration -- which is remote code
 * execution and is `admin`. An interface name and a flag can name no hook, no
 * path and no `run_as`, so the message bounds what it can ask for.
 */
int ncfg_client_radio_set(ncfg_client_t *client, const char *interface, int activate, char *err,
              size_t err_size);

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
