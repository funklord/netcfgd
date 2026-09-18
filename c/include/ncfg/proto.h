/*
 * proto.h -- the control socket's messages: what a client sends, what the
 * daemon answers, and the line they travel on.
 *
 * This is the port of `crates/netcfgd-proto`. The prose half of the contract
 * is `doc/socket-protocol.md` and the machine-checkable half is
 * `doc/schema/socket.json`; where this file and the witness disagree, the
 * witness is right.
 *
 * WHAT THIS MODULE IS, AND WHAT IT IS NOT
 *   It is the framing and the envelope. It is not a socket: resolving
 *   `$NCFG_RUN_DIR`, connecting, and reading from a file descriptor already
 *   exist in `client/ncfg_client.c` and are not copied here. What is here is
 *   the part that is pure bytes -- which is what makes the adversarial cases
 *   testable without a daemon at the other end, the same reason the wire
 *   layer landed before the sockets did (0263).
 *
 * A STRUCT WITH A KIND, NOT A TAGGED UNION PER MESSAGE
 *   Requests and responses are a `kind` plus a union of payload structs, and
 *   the choice is worth a paragraph because the obvious alternative was tried
 *   on paper first.
 *
 *   The Rust is an enum, and the compiler tells it when a `match` has missed
 *   an arm. C gives that up (0263 says so in as many words), so the question
 *   is which shape makes the *loss* cheapest. A union keyed by an enum keeps
 *   the property that matters -- a payload cannot be read as the wrong
 *   message, because the kind is what selects the arm -- and it keeps the
 *   arms named after the requests, so a reader comparing this file against
 *   `lib.rs` is comparing like with like.
 *
 *   What replaces the compiler's exhaustiveness is `NCFG_PROTO_REQ_COUNT` and
 *   the member table below: a request kind that is added and never given a
 *   name, a member list or an encoder is caught by `proto_test`, which walks
 *   every kind from 0 to the count rather than a list somebody maintains.
 *   That is the same construction as the Rust's `every_variant_is_in_the_fixture`,
 *   which exists because a table tested only against the variants somebody
 *   remembered is a table with a vacuous pass in it.
 *
 * COUNTED STRINGS, AND WHY NOTHING IS COPIED
 *   Every string in a decoded message is an `ncfg_proto_str_t`: a pointer and
 *   a length into the parsed document the message owns. The reader's strings
 *   are counted rather than terminated -- they sit end to end in one buffer --
 *   so `strlen` on one runs into the next member, and a JSON string may hold a
 *   NUL in the middle of itself besides. Copying each one into its own
 *   allocation would be a few hundred `malloc`s per `status` for no benefit,
 *   and would lose the NUL case that `ncfg_json_string` takes care to keep.
 *
 *   The consequence is the one rule a caller owes: **a decoded message owns
 *   the bytes its strings point into, so nothing taken out of it outlives
 *   `ncfg_proto_message_free`.** A caller keeping a name past that copies it.
 *
 * ABSENT, NULL AND EMPTY
 *   `bytes == NULL` is absent; a zero length with a non-NULL pointer is the
 *   empty string, and those are different answers -- an SSID that is present
 *   and empty is what a hidden network broadcasts, and section 8 of the
 *   protocol document renders it `(hidden)` while an absent one renders
 *   `hex:<ssid>`. A reader that mapped both to "" would merge two networks
 *   into one row.
 *
 *   JSON `null` lands in the same place as absent on every member this
 *   protocol has, because every optional member here is an `Option` that
 *   serde skips when it is `None` -- there is no member whose null means
 *   something its absence does not. A client that needs to tell the two apart
 *   anyway still can: the parsed document is kept, and
 *   `ncfg_proto_message_doc` hands it over.
 *
 * THE ASYMMETRY, WHICH IS THE PROTOCOL'S AND NOT AN OVERSIGHT
 *   **A request is read strictly and a response leniently**, which is why
 *   there are two entry points rather than one with a flag.
 *
 *   A request is untrusted input to a process holding `CAP_NET_ADMIN`, and
 *   section 7 tells every implementation to refuse a member it does not
 *   define -- in the envelope as well as the payload. The daemon was not
 *   keeping its own rule for a while, and the way it failed is the thing to
 *   remember: serde cannot put `deny_unknown_fields` on an internally-tagged
 *   enum, because the tag would be the first member refused, so the payload
 *   structs were strict and the envelope was not. The strict half was the one
 *   reading bytes that had already been parsed and the permissive half was the
 *   one facing the socket.
 *
 *   A response is read by a client that may be older than the daemon it is
 *   talking to, so refusing a member it does not recognise is how an upgrade
 *   breaks a working client. The asymmetry is between the two *directions*,
 *   not between an envelope and a payload.
 *
 *   **What that costs is stated rather than glossed**, because section 2 of
 *   the project's own `project.md` forbids silent field-dropping for the
 *   desired-state document on the grounds that a consumer acting on something
 *   it only half read is worse than one that refuses -- and the socket
 *   envelope does exactly what the document forbids. So: an implementation
 *   must not rely on the daemon rejecting a request member it invented, and
 *   must not conclude from acceptance that a member was understood. Closing
 *   that means checking members explicitly, which is what the member table is.
 *
 *   The leniency is about *members*, not about the tag. A `response` value
 *   this build does not know is refused, exactly as the Rust refuses it: a
 *   message whose kind is unknown is one a client cannot act on, and guessing
 *   which arm it belongs to is how a client renders the wrong thing.
 *
 * THE MEMBER TABLE
 *   `ncfg_proto_request_members` is the port of `Request::members()`, and it
 *   exists for the reason that one does: the envelope check needs a list of
 *   what a request may carry, and the cheap way to get one -- decode,
 *   re-encode, refuse whatever the round trip dropped -- was measured and is
 *   wrong. `confirm`, `id`, `passphrase`, `proto`, `metric` and `eap` are all
 *   skipped when unset, so that implementation refuses
 *   `{"request":"apply","confirm":null}`, which item 5 of section 10 entitles
 *   a client to send. A table that has to be maintained is the price of not
 *   refusing what the protocol permits, and `proto_test` compares it against
 *   what the encoder emits for a fully-populated request of every kind, in
 *   both directions -- so it cannot drift into refusing a member the protocol
 *   has just gained.
 *
 * CLOSED SETS ARE CARRIED AS SPELLINGS, NOT RE-ENUMERATED
 *   `tiers`, a hook's `phase` and a station report's `access_control` are
 *   `netcfgd_model`'s closed sets. They travel through here as the bytes that
 *   arrived, and the module that owns each set is what turns one into a value.
 *   A second copy of a spelling is how this project twice shipped a key
 *   written the model's way rather than the language's -- `wire_guard` for
 *   `wireguard`, `open_vpn` for `openvpn` -- each compiling into a block with
 *   the feature silently missing (0263).
 *
 * WHAT IS DECODED HERE AND WHAT IS HANDED ON
 *   `status`, `plan`, `document` and `journal` carry `netcfgd_model`'s,
 *   `netcfgd_plan`'s and `netcfgd_apply`'s own types -- the Rust writes them
 *   as `Response::Status(Box<Observed>)`, where proto names the arm and
 *   another crate owns the contents. Those modules do not exist in the port
 *   yet, so this decodes the envelope, reports the kind, and hands over the
 *   parsed object as `ncfg_proto_payload_t`. Nothing is lost and nothing is
 *   guessed: when `model`, `plan` and `apply` land, the payload becomes their
 *   argument rather than something this module has to be taught.
 */
#ifndef NCFG_PROTO_H
#define NCFG_PROTO_H

#include <stddef.h>
#include <stdint.h>

#include "ncfg/base.h"
#include "ncfg/buf.h"
/* The reader every decoded message is built on, for `ncfg_json_doc_t`. */
#include "ncfg_json.h"

/* ------------------------------------------------------------- the framing */

/*
 * The longest line either side will accept, counting the newline.
 *
 * Generous for anything the protocol carries -- a whole document compiles to
 * a few tens of kilobytes -- and small enough that a hostile client cannot
 * make a daemon holding `CAP_NET_ADMIN` allocate its way to being killed,
 * which is a denial of service with extra steps. It is the Rust's `MAX_LINE`
 * to the byte; two halves of one protocol disagreeing about a bound would be
 * a message one can send and the other refuses.
 */
#define NCFG_PROTO_MAX_LINE (1024u * 1024u)

/*
 * A line reader, fed bytes rather than a file descriptor.
 *
 * The socket belongs to `client/ncfg_client.c` and to the daemon; what is
 * hard about framing is the bound and the partial line, and both are testable
 * with no kernel in the way. So this takes whatever a `read` produced and
 * hands back whole lines, keeping the tail -- because a daemon that answered
 * two requests quickly may have put both in one read, and throwing the second
 * away would lose an answer somebody is waiting for.
 */
typedef struct {
	ncfg_buf_t pending;
	/* Bytes of the line last handed out, still sitting at the front of
	 * `pending` because the caller is decoding out of them. Dropped by the
	 * next call on this framer, which is why a line is valid only until
	 * then: consuming it before returning it would memmove the tail over
	 * the very bytes being handed back. */
	size_t     handed;
	/* Set by the first refusal and never cleared. Whatever is on this
	 * connection is no longer this protocol: the bytes already read cannot
	 * be put back, so a caller that read on would take the tail of one
	 * message for the head of the next. */
	int        broken;
} ncfg_proto_framer_t;

/*
 * What a take from the framer found.
 *
 * Three answers rather than the module's usual 1-or-0, and deliberately: this
 * is `io::Result<Option<T>>` in the Rust, and item 4 of section 10 --
 * "treat a clean end of stream as a disconnect, not a failure" -- is
 * precisely the defect that collapsing them produces. A client that reported
 * a closed connection as an error would tell an operator the daemon had
 * failed when it had merely gone away.
 */
typedef enum {
	/* A whole line, without its newline. */
	NCFG_PROTO_LINE = 0,
	/* Nothing complete yet; read more, or call `finish` at end of stream. */
	NCFG_PROTO_LINE_INCOMPLETE,
	/* The bound, or a framer already broken. `err` says which. */
	NCFG_PROTO_LINE_FAILED
} ncfg_proto_line_result_t;

void ncfg_proto_framer_init(ncfg_proto_framer_t *framer);
void ncfg_proto_framer_free(ncfg_proto_framer_t *framer);

/*
 * Add bytes that arrived. 0 with `err` where they cannot be held: the bound
 * is checked here rather than when a line is taken, so a flood is refused as
 * it arrives instead of after it has been absorbed.
 */
int ncfg_proto_framer_add(ncfg_proto_framer_t *framer, const void *bytes, size_t length,
    char *err, size_t err_size);

/*
 * The next whole line, pointing into the framer's own bytes and valid until
 * the next call on this framer.
 */
ncfg_proto_line_result_t ncfg_proto_framer_next(ncfg_proto_framer_t *framer,
    const char **line_out, size_t *length_out, char *err, size_t err_size);

/*
 * The peer stopped sending. 1 where nothing was pending, which is an ordinary
 * disconnect; 0 with `err` where a partial line is left, which is a message
 * that was cut in half and must not be half-read.
 */
int ncfg_proto_framer_finish(ncfg_proto_framer_t *framer, char *err, size_t err_size);

/*
 * Terminate a built line: refuse an embedded newline, refuse the bound, and
 * append the `\n`.
 *
 * The newline check is the Rust's and it survives for the same reason: a
 * message containing one would frame as two, and the peer would mis-parse
 * both halves. The JSON writer escapes newlines inside strings, so on an
 * encoded request this can only fire on a bug here -- which is why it is
 * checked rather than assumed, and why it is public: anything that builds a
 * line by other means goes through the same gate.
 */
int ncfg_proto_line_finish(ncfg_buf_t *line, char *err, size_t err_size);

/* ------------------------------------------------------------ the pieces */

/*
 * A counted string, or absent when `bytes` is NULL.
 *
 * See the header comment: absent, empty and null are three answers and this
 * carries the difference that the protocol actually uses.
 */
typedef struct {
	const char *bytes;
	size_t      length;
} ncfg_proto_str_t;

/* A NUL-terminated string as one of these, for a caller building a request. */
ncfg_proto_str_t ncfg_proto_str(const char *text);
/* The absent one, which is what an unfilled field already is. */
ncfg_proto_str_t ncfg_proto_str_none(void);
/* Whether it is there at all, and whether it reads as a given C string. */
int ncfg_proto_str_present(ncfg_proto_str_t text);
int ncfg_proto_str_equals(ncfg_proto_str_t text, const char *other);

/* A list of strings, as `allow_disruption` and `tiers` are. */
typedef struct {
	const ncfg_proto_str_t *items;
	size_t                  count;
} ncfg_proto_strs_t;

/*
 * An integer that may be absent -- a `confirm` window, a station's signal.
 *
 * A sentinel would have been shorter and is wrong: 0 is a real metric, and a
 * signal of 0 dBm is a station sitting on the antenna rather than a station
 * nobody measured.
 */
typedef struct {
	unsigned char present;
	int64_t       value;
} ncfg_proto_int_t;

/* A two-part version, as `hello` carries. */
typedef struct {
	int64_t major;
	int64_t minor;
} ncfg_proto_version_t;

/*
 * A payload this module names but does not own.
 *
 * `object` is the whole envelope, because members are flattened beside the
 * tag rather than nested under it -- so the fields of an `Observed` are
 * members of the response object itself.
 */
typedef struct {
	const ncfg_json_doc_t *doc;
	uint32_t               object;
} ncfg_proto_payload_t;

/* ---------------------------------------------------------- what is asked */

typedef enum {
	NCFG_PROTO_REQ_HELLO = 0,
	NCFG_PROTO_REQ_STATUS,
	NCFG_PROTO_REQ_PLAN,
	NCFG_PROTO_REQ_APPLY,
	NCFG_PROTO_REQ_CONFIRM,
	NCFG_PROTO_REQ_REVERT,
	NCFG_PROTO_REQ_RELOAD,
	NCFG_PROTO_REQ_SHOW,
	NCFG_PROTO_REQ_EXPLAIN,
	NCFG_PROTO_REQ_CONFIG_LIST,
	NCFG_PROTO_REQ_MONITOR,
	NCFG_PROTO_REQ_WIFI_SCAN,
	NCFG_PROTO_REQ_WIFI_STATUS,
	NCFG_PROTO_REQ_WIFI_ADD,
	NCFG_PROTO_REQ_WIFI_CONNECT,
	NCFG_PROTO_REQ_WIFI_DISCONNECT,
	NCFG_PROTO_REQ_WIFI_FORGET,
	NCFG_PROTO_REQ_CONFIG_PUT,
	NCFG_PROTO_REQ_PROBE_LIST,
	NCFG_PROTO_REQ_HOOK_LIST,
	NCFG_PROTO_REQ_PROFILE_LIST,
	NCFG_PROTO_REQ_MODEM_LIST,
	NCFG_PROTO_REQ_PROFILE_SAVE,
	NCFG_PROTO_REQ_SECRET_LIST,
	NCFG_PROTO_REQ_PROFILE_SET,
	NCFG_PROTO_REQ_PROBE_PUT,
	NCFG_PROTO_REQ_SECRET_PUT,
	NCFG_PROTO_REQ_CONFIG_DELETE,
	NCFG_PROTO_REQ_SECRET_DELETE,
	NCFG_PROTO_REQ_AP_STATIONS,
	NCFG_PROTO_REQ_RADIOS,
	NCFG_PROTO_REQ_RADIO_SET,
	/* Not a request. The bound every exhaustive walk in this module uses in
	 * place of the `match` the Rust gets checked for it. */
	NCFG_PROTO_REQ_COUNT
} ncfg_proto_request_kind_t;

/* What `explain` is being asked about. */
typedef enum {
	NCFG_PROTO_SUBJECT_INTERFACE = 0,
	NCFG_PROTO_SUBJECT_ADDRESS,
	NCFG_PROTO_SUBJECT_ROUTE,
	NCFG_PROTO_SUBJECT_COUNT
} ncfg_proto_subject_kind_t;

/*
 * The subject, flat rather than a union of three.
 *
 * Four members between three arms, and the tag says which are filled: a union
 * here would cost more punctuation at every use than it saves in bytes.
 */
typedef struct {
	ncfg_proto_subject_kind_t kind;
	ncfg_proto_str_t          name;        /* interface */
	ncfg_proto_str_t          interface;   /* address, route */
	ncfg_proto_str_t          address;     /* address */
	ncfg_proto_str_t          destination; /* route */
} ncfg_proto_subject_t;

/*
 * The 802.1X half of `wifi_add`.
 *
 * **Every certificate here is the name of a stored secret, never a path**,
 * and that is what lets this exist at all: a path is an instruction to open a
 * file as root, so configuration carrying one is privileged. A name refers to
 * content netcfgd already holds because somebody put it there with
 * `secret_put`, so it grants nothing new -- and there is no field here a path
 * could be written in, which is the difference between a rule and a property.
 *
 * There is deliberately no `private_key`, and it is the field a reader looks
 * for first. For `tls` the private key *is* the credential: it travels the
 * way a passphrase does, in `passphrase`, and is stored under the network's
 * own id. Two fields naming one thing would leave the daemon picking between
 * a caller's two disagreeing answers.
 */
typedef struct {
	unsigned char    present;
	ncfg_proto_str_t method;
	ncfg_proto_str_t identity;
	ncfg_proto_str_t anonymous_identity;
	ncfg_proto_str_t phase2;
	ncfg_proto_str_t ca_cert;
	ncfg_proto_str_t client_cert;
} ncfg_proto_eap_t;

typedef struct {
	ncfg_proto_int_t  confirm;
	ncfg_proto_strs_t allow_disruption;
	ncfg_proto_strs_t strand_credentials;
	ncfg_proto_strs_t restart_wedged;
} ncfg_proto_apply_t;

/*
 * `wifi_add`: typed fields, never config text and never a path.
 *
 * A config file may name a hook, and a hook's `run_as` is absent by default,
 * which means root -- so a request carrying config *text* is remote code
 * execution, and one carrying an SSID and a passphrase is not. This message
 * cannot express a hook, a path or a `run_as` because it has no such field:
 * the privilege it grants is bounded by its shape rather than by the caller's
 * good manners (0117).
 *
 * `ssid` is lowercase hex and always present, because an SSID is 0..32
 * arbitrary octets and is not guaranteed to be text.
 */
typedef struct {
	ncfg_proto_str_t ssid;
	ncfg_proto_str_t id;
	ncfg_proto_str_t passphrase;
	ncfg_proto_str_t proto;
	unsigned char    hidden;
	ncfg_proto_int_t metric;
	ncfg_proto_eap_t eap;
} ncfg_proto_wifi_add_t;

/* `config_put` and `probe_put`, which carry the same three members. */
typedef struct {
	ncfg_proto_str_t name;
	ncfg_proto_str_t text;
	unsigned char    replace;
} ncfg_proto_put_t;

typedef struct {
	ncfg_proto_str_t name;
	ncfg_proto_str_t value;
	unsigned char    replace;
} ncfg_proto_secret_put_t;

typedef struct {
	ncfg_proto_str_t name;
	unsigned char    replace;
} ncfg_proto_profile_save_t;

typedef struct {
	ncfg_proto_str_t interface;
	ncfg_proto_str_t network;
} ncfg_proto_wifi_connect_t;

typedef struct {
	ncfg_proto_str_t interface;
	unsigned char    activate;
} ncfg_proto_radio_set_t;

/*
 * One request.
 *
 * A request built by hand is zeroed first and then filled: every absent
 * member is already absent, which is what `ncfg_proto_str_none` and a zero
 * `present` mean. Nothing here is allocated by a caller, so a built request is
 * never freed -- see `ncfg_proto_message_t` for the decoded case, which is.
 */
typedef struct {
	ncfg_proto_request_kind_t kind;
	union {
		ncfg_proto_apply_t        apply;
		ncfg_proto_subject_t      explain;
		/* wifi_scan, wifi_status, wifi_disconnect, ap_stations */
		ncfg_proto_str_t          interface;
		ncfg_proto_wifi_add_t     wifi_add;
		ncfg_proto_wifi_connect_t wifi_connect;
		/* wifi_forget */
		ncfg_proto_str_t          id;
		/* config_put, probe_put */
		ncfg_proto_put_t          put;
		ncfg_proto_secret_put_t   secret_put;
		/* config_delete, secret_delete, and profile_set where a profile is
		 * named -- `profile_set` with none is the default state and is not a
		 * profile called "none". */
		ncfg_proto_str_t          name;
		ncfg_proto_profile_save_t profile_save;
		ncfg_proto_radio_set_t    radio_set;
	} u;
} ncfg_proto_request_t;

/* The tag's value, or NULL for a kind outside the enum. */
const char *ncfg_proto_request_name(ncfg_proto_request_kind_t kind);

/* The kind a tag names. 0 where no request is spelled that way. */
int ncfg_proto_request_kind_from(const char *name, size_t length,
    ncfg_proto_request_kind_t *kind_out);

/*
 * The members this request carries, beside the `request` tag itself.
 *
 * See the header comment for why this is a table rather than derived. The
 * order is the order the encoder emits, which is the order the witness pins.
 */
const char *const *ncfg_proto_request_members(ncfg_proto_request_kind_t kind, size_t *count_out);

/* The JSON object, appended to `out` with no newline. */
int ncfg_proto_request_encode(const ncfg_proto_request_t *request, ncfg_buf_t *out,
    char *err, size_t err_size);

/* The same, framed: the call a client makes to put a request on the wire. */
int ncfg_proto_request_write(const ncfg_proto_request_t *request, ncfg_buf_t *out,
    char *err, size_t err_size);

/* ------------------------------------------------------- what comes back */

typedef enum {
	NCFG_PROTO_RESP_HELLO = 0,
	NCFG_PROTO_RESP_STATUS,
	NCFG_PROTO_RESP_PLAN,
	NCFG_PROTO_RESP_DOCUMENT,
	NCFG_PROTO_RESP_JOURNAL,
	NCFG_PROTO_RESP_EXPLANATION,
	NCFG_PROTO_RESP_EVENT,
	NCFG_PROTO_RESP_WIFI_SCAN,
	NCFG_PROTO_RESP_SECRETS,
	NCFG_PROTO_RESP_MODEMS,
	NCFG_PROTO_RESP_PROFILES,
	NCFG_PROTO_RESP_CONFIGS,
	NCFG_PROTO_RESP_HOOKS,
	NCFG_PROTO_RESP_PROBES,
	NCFG_PROTO_RESP_RADIOS,
	NCFG_PROTO_RESP_WIFI_STATUS,
	NCFG_PROTO_RESP_AP_STATIONS,
	NCFG_PROTO_RESP_OK,
	NCFG_PROTO_RESP_ERROR,
	NCFG_PROTO_RESP_COUNT
} ncfg_proto_response_kind_t;

typedef enum {
	NCFG_PROTO_EVENT_OBSERVED = 0,
	NCFG_PROTO_EVENT_RELOADED,
	NCFG_PROTO_EVENT_DRIFT,
	NCFG_PROTO_EVENT_CONFIRM_ARMED,
	NCFG_PROTO_EVENT_CONFIRM_RESOLVED,
	NCFG_PROTO_EVENT_COUNT
} ncfg_proto_event_kind_t;

/*
 * Something that happened, on a monitor stream.
 *
 * Flat for `ncfg_proto_subject_t`'s reason: five arms and seven members
 * between them. The tag says which are filled.
 */
typedef struct {
	ncfg_proto_event_kind_t kind;
	ncfg_proto_str_t        summary;     /* observed, drift */
	unsigned char           ok;          /* reloaded */
	ncfg_proto_str_t        diagnostics; /* reloaded, absent where it compiled */
	ncfg_proto_str_t        interface;   /* drift */
	ncfg_proto_str_t        action;      /* drift */
	int64_t                 seconds;     /* confirm_armed */
	unsigned char           confirmed;   /* confirm_resolved */
} ncfg_proto_event_t;

/* One statement in an explanation. */
typedef struct {
	ncfg_proto_str_t topic;  /* desired, observed, ownership, guard */
	ncfg_proto_str_t detail;
	ncfg_proto_str_t source; /* absent where the fact has no place */
} ncfg_proto_fact_t;

typedef struct {
	ncfg_proto_str_t         subject;
	const ncfg_proto_fact_t *facts;
	size_t                   fact_count;
} ncfg_proto_explanation_t;

/*
 * One access point a scan found.
 *
 * `ssid` is the canonical identity and is always there; `name` is the same
 * value as text and is absent rather than mangled where the octets are not
 * UTF-8, so that a client can tell "not text" from "empty" (section 8).
 *
 * `configured` is decision 0013's boundary made visible: it names the
 * `network` block describing this access point, and a caller holding only the
 * `wifi` tier can join exactly the entries where it is set. A client that
 * shows the difference saves the operator discovering it by being refused.
 */
typedef struct {
	ncfg_proto_str_t bssid;
	int64_t          frequency;
	int64_t          signal;
	unsigned char    secured;
	unsigned char    owe;
	unsigned char    enterprise;
	ncfg_proto_str_t ssid;
	ncfg_proto_str_t name;
	/* Diagnostic, never a trust signal: the element is unauthenticated bytes
	 * in a beacon, so anything can claim any domain. */
	ncfg_proto_str_t mobility_domain;
	ncfg_proto_str_t configured;
} ncfg_proto_scan_entry_t;

typedef struct {
	ncfg_proto_str_t               interface;
	const ncfg_proto_scan_entry_t *access_points;
	size_t                         access_point_count;
	/* Why these are the *previous* scan's results, when they are. Absent on
	 * the ordinary answer, which is fresh. */
	ncfg_proto_str_t               stale;
} ncfg_proto_scan_t;

/* A network the supplicant knows and has stopped trying. */
typedef struct {
	ncfg_proto_str_t ssid;
	ncfg_proto_str_t name;
	/* The supplicant's own flags, passed through rather than translated:
	 * `[DISABLED]` and `[TEMP-DISABLED]` mean different things. */
	ncfg_proto_str_t flags;
} ncfg_proto_disabled_t;

typedef struct {
	ncfg_proto_str_t             interface;
	ncfg_proto_str_t             state;
	ncfg_proto_str_t             ssid;
	ncfg_proto_str_t             name;
	ncfg_proto_str_t             bssid;
	ncfg_proto_str_t             network;
	/* Why the radio is off, when it is. Without it the answer to "why is
	 * there no network" looks identical whether the kill switch is on or the
	 * network simply is not there (0199). */
	ncfg_proto_str_t             blocked;
	const ncfg_proto_disabled_t *not_trying;
	size_t                       not_trying_count;
} ncfg_proto_wifi_status_t;

typedef struct {
	ncfg_proto_str_t address;
	unsigned char    authorized;
	unsigned char    listed;
	ncfg_proto_int_t signal;
	ncfg_proto_int_t connected_seconds;
	ncfg_proto_int_t inactive_msec;
	ncfg_proto_int_t rx_bytes;
	ncfg_proto_int_t tx_bytes;
} ncfg_proto_station_t;

typedef struct {
	ncfg_proto_str_t            interface;
	ncfg_proto_str_t            access_point;
	/* `netcfgd_model`'s `AclPolicy`, carried as its spelling. Which way the
	 * list reads is here because `listed` means opposite things under the two
	 * policies and a client would otherwise have to guess. */
	ncfg_proto_str_t            access_control;
	const ncfg_proto_station_t *stations;
	size_t                      station_count;
} ncfg_proto_stations_t;

typedef struct {
	ncfg_proto_str_t  name;
	unsigned char     stored;
	/* The blocks that refer to it, as `network Cafe`. */
	ncfg_proto_strs_t used_by;
} ncfg_proto_secret_t;

typedef struct {
	ncfg_proto_str_t source;
	ncfg_proto_str_t iccid;
} ncfg_proto_sim_card_t;

typedef struct {
	ncfg_proto_str_t             device;
	/* What the document asks for, in the order it is tried. */
	ncfg_proto_strs_t            sim;
	/* Where netcfgd has got to, which moves when a probe says a source does
	 * not work. Separate from `sim` because a client showing only one of them
	 * either cannot say what was asked for or describes a machine that is not
	 * the machine. */
	ncfg_proto_str_t             selected;
	ncfg_proto_str_t             apn;
	unsigned char                cycle_pending;
	/* One per source a helper has actually reported a card for -- not one per
	 * listed source, because the only way to learn what is in the other
	 * socket is to switch to it. */
	const ncfg_proto_sim_card_t *cards;
	size_t                       card_count;
} ncfg_proto_modem_t;

typedef struct {
	ncfg_proto_str_t name;
	unsigned char    shipped;
} ncfg_proto_profile_t;

typedef struct {
	/* Empty for `netcfgd.conf`, which is not a drop-in and which no request
	 * can write or remove: giving it a name would offer a client a verb that
	 * does not exist for it. */
	ncfg_proto_str_t name;
	ncfg_proto_str_t file;
	unsigned char    removable;
	ncfg_proto_str_t text;
} ncfg_proto_config_file_t;

typedef struct {
	ncfg_proto_str_t name;
	ncfg_proto_str_t directory;
	ncfg_proto_str_t text;
	unsigned char    editable;
} ncfg_proto_probe_t;

typedef struct {
	ncfg_proto_str_t interface;
	/* `netcfgd_model`'s `HookPhase`, carried as its spelling. */
	ncfg_proto_str_t phase;
	ncfg_proto_str_t path;
	/* Empty where `readable` is false, which is not the same as a hook with
	 * nothing in it. **False is a fact a client must not round-trip**: the
	 * document names a hook netcfgd could not read back, so an editor that
	 * saved the block would write the body it does not have, which is to say
	 * delete it. */
	ncfg_proto_str_t text;
	unsigned char    readable;
} ncfg_proto_hook_t;

typedef struct {
	ncfg_proto_str_t interface;
	unsigned char    activated;
	/* Whether a supplicant is answering. The gap between this and `activated`
	 * is the interesting state, and it is netcfgd's answer rather than the
	 * machine's -- a daemon that cannot reach the supplicant's socket reports
	 * false for one that is plainly there. */
	unsigned char    supplicant;
} ncfg_proto_radio_t;

typedef struct {
	ncfg_proto_response_kind_t kind;
	union {
		struct {
			ncfg_proto_version_t protocol;
			ncfg_proto_version_t schema;
			/* Which control tiers *this* connection satisfies --
			 * peer-specific, not machine-specific. Asking beats
			 * discovering it by being refused (0092). */
			ncfg_proto_strs_t    tiers;
		} hello;
		/* status, plan, document, journal: named here, owned elsewhere. */
		ncfg_proto_payload_t     payload;
		ncfg_proto_explanation_t explanation;
		ncfg_proto_event_t       event;
		ncfg_proto_scan_t        wifi_scan;
		struct {
			const ncfg_proto_secret_t *items;
			size_t                     count;
		} secrets;
		struct {
			const ncfg_proto_modem_t *items;
			size_t                    count;
		} modems;
		struct {
			const ncfg_proto_profile_t *items;
			size_t                      count;
			ncfg_proto_str_t            chosen;
		} profiles;
		struct {
			const ncfg_proto_config_file_t *items;
			size_t                          count;
		} configs;
		struct {
			const ncfg_proto_hook_t *items;
			size_t                   count;
		} hooks;
		struct {
			const ncfg_proto_probe_t *items;
			size_t                    count;
		} probes;
		struct {
			const ncfg_proto_radio_t *items;
			size_t                    count;
		} radios;
		ncfg_proto_wifi_status_t wifi_status;
		ncfg_proto_stations_t    ap_stations;
		/*
		 * **A refusal is an answer**, which is a different thing from not
		 * reaching the daemon, and only the caller knows whether it is
		 * fatal. The sentence names the tier that would have been needed;
		 * replacing it with wording of your own throws away the part that
		 * says what to do about it.
		 */
		struct {
			ncfg_proto_str_t message;
		} error;
	} u;
} ncfg_proto_response_t;

const char *ncfg_proto_response_name(ncfg_proto_response_kind_t kind);
const char *ncfg_proto_event_name(ncfg_proto_event_kind_t kind);

/* ------------------------------------------------------------- a message */

typedef enum {
	NCFG_PROTO_MESSAGE_REQUEST = 0,
	NCFG_PROTO_MESSAGE_RESPONSE,
	/*
	 * A bare `{"event":...}` line.
	 *
	 * The third kind, and it surprised the C client on its first run. An
	 * event payload appears both on its own and wrapped in
	 * `{"response":"event",...}`, because a monitor stream carries it inside
	 * the wrapper and the payload is its own pinned shape. A client that knew
	 * only requests and responses would read a stream and recognise nothing.
	 */
	NCFG_PROTO_MESSAGE_EVENT
} ncfg_proto_message_kind_t;

/*
 * One decoded line, and everything it owns.
 *
 * The ownership lives here rather than in the request and response structs so
 * that a request a caller *builds* owns nothing at all -- there is no free to
 * forget, and no way to hand the encoder a struct whose strings it might take
 * for its own. Freeing one that was never filled in is nothing.
 */
typedef struct {
	ncfg_proto_message_kind_t kind;
	union {
		ncfg_proto_request_t  request;
		ncfg_proto_response_t response;
		ncfg_proto_event_t    event;
	} u;
	/* The parsed line every string above points into, and the blocks the
	 * decoder allocated for the lists. Private; use the calls below. */
	ncfg_json_doc_t          *doc;
	void                    **blocks;
	size_t                    block_count;
	size_t                    block_capacity;
} ncfg_proto_message_t;

/*
 * Read a request, strictly: an unknown member is refused and named, in the
 * envelope and in the payload alike. Anything that is not a request is
 * refused -- a daemon reading its own socket has asked for one.
 */
int ncfg_proto_request_read(const char *line, size_t length, ncfg_proto_message_t *out,
    char *err, size_t err_size);

/*
 * Read a response or a bare event, leniently: a member this build does not
 * know is ignored rather than refused, because a client may be older than the
 * daemon it is talking to.
 */
int ncfg_proto_response_read(const char *line, size_t length, ncfg_proto_message_t *out,
    char *err, size_t err_size);

/*
 * Read whichever of the three a line carries, each under its own direction's
 * rule. For a tool that reads both halves of a conversation -- a test against
 * the witness, a dump of a captured stream -- rather than for a daemon or a
 * client, each of which knows which way it is reading.
 */
int ncfg_proto_message_read(const char *line, size_t length, ncfg_proto_message_t *out,
    char *err, size_t err_size);

/* The parsed line, for a caller that needs what the typed shape does not
 * carry -- an unrecognised member, or absent told from null. */
const ncfg_json_doc_t *ncfg_proto_message_doc(const ncfg_proto_message_t *message);

void ncfg_proto_message_free(ncfg_proto_message_t *message);

#endif /* NCFG_PROTO_H */
