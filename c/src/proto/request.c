/*
 * request.c -- what a client asks for: the names, the member table, the
 * encoder, and the strict reader that faces the socket.
 */
#include "internal.h"

#include "ncfg/json_write.h"

#include <string.h>

/*
 * The tag's value for every kind, indexed by the kind.
 *
 * An array rather than a switch, and the difference matters: `proto_test`
 * walks 0 to `NCFG_PROTO_REQ_COUNT` and asks for each name, so a kind added
 * without one is a NULL rather than a silent fall-through to a default. That
 * is the cheapest replacement available for the exhaustive `match` the Rust
 * gets checked for free (0263).
 *
 * The spellings are serde's `rename_all = "snake_case"` applied to the enum
 * in `lib.rs`, read from there rather than from memory: this project has
 * twice shipped a key spelled the model's way rather than the language's --
 * `wire_guard` for `wireguard`, `open_vpn` for `openvpn` -- and each compiled
 * into a block with the feature silently missing.
 */
static const char *const request_names[NCFG_PROTO_REQ_COUNT] = {
	"hello",
	"status",
	"plan",
	"apply",
	"confirm",
	"revert",
	"reload",
	"show",
	"explain",
	"config_list",
	"monitor",
	"wifi_scan",
	"wifi_status",
	"wifi_add",
	"wifi_connect",
	"wifi_disconnect",
	"wifi_forget",
	"config_put",
	"probe_list",
	"hook_list",
	"profile_list",
	"modem_list",
	"profile_save",
	"secret_list",
	"profile_set",
	"probe_put",
	"secret_put",
	"config_delete",
	"secret_delete",
	"ap_stations",
	"radios",
	"radio_set",
};

/* The shared member lists, named after what they belong to. */
static const char *const members_none[1] = { NULL };
static const char *const members_apply[] = {
	"confirm", "allow_disruption", "strand_credentials", "restart_wedged"
};
static const char *const members_subject[] = { "subject" };
static const char *const members_interface[] = { "interface" };
static const char *const members_wifi_add[] = {
	"ssid", "id", "passphrase", "proto", "hidden", "metric", "eap"
};
static const char *const members_wifi_connect[] = { "interface", "network" };
static const char *const members_id[] = { "id" };
static const char *const members_put[] = { "name", "text", "replace" };
static const char *const members_secret_put[] = { "name", "value", "replace" };
static const char *const members_name[] = { "name" };
static const char *const members_profile_save[] = { "name", "replace" };
static const char *const members_radio_set[] = { "interface", "activate" };

typedef struct {
	const char *const *names;
	size_t             count;
} member_list_t;

#define LIST(array) { (array), sizeof(array) / sizeof((array)[0]) }
#define EMPTY       { members_none, 0 }

/*
 * The port of `Request::members()`.
 *
 * Hand-written for the reason the Rust's is: the envelope check needs to know
 * what a request may carry, and serde cannot answer at the point it matters
 * -- `deny_unknown_fields` is unsupported on an internally-tagged enum,
 * because the tag would be the first member refused. The cheap alternative,
 * refusing whatever a re-encode drops, needs no table and cannot drift, and
 * it refuses `{"request":"apply","confirm":null}`, which item 5 of section 10
 * entitles a client to send. A table that must be maintained is the price of
 * not refusing what the protocol permits.
 *
 * It cannot drift silently: `proto_test` builds every kind fully populated,
 * so nothing is skipped, and compares this against what the encoder emits --
 * both ways round, because a table that is merely a subset would refuse a
 * member the protocol has just gained.
 */
static const member_list_t request_members[NCFG_PROTO_REQ_COUNT] = {
	EMPTY,                  /* hello */
	EMPTY,                  /* status */
	EMPTY,                  /* plan */
	LIST(members_apply),
	EMPTY,                  /* confirm */
	EMPTY,                  /* revert */
	EMPTY,                  /* reload */
	EMPTY,                  /* show */
	LIST(members_subject),  /* explain */
	EMPTY,                  /* config_list */
	EMPTY,                  /* monitor */
	LIST(members_interface),/* wifi_scan */
	LIST(members_interface),/* wifi_status */
	LIST(members_wifi_add),
	LIST(members_wifi_connect),
	LIST(members_interface),/* wifi_disconnect */
	/* The id and nothing else, which is what keeps it at the `wifi` tier --
	 * the shape of the message is the bound. */
	LIST(members_id),       /* wifi_forget */
	LIST(members_put),      /* config_put */
	EMPTY,                  /* probe_list */
	EMPTY,                  /* hook_list */
	EMPTY,                  /* profile_list */
	EMPTY,                  /* modem_list */
	LIST(members_profile_save),
	EMPTY,                  /* secret_list */
	/* `profile_set` is here because its `name` is the same one member, even
	 * though it is skipped on the unset form -- the witness pins both. */
	LIST(members_name),     /* profile_set */
	LIST(members_put),      /* probe_put */
	LIST(members_secret_put),
	LIST(members_name),     /* config_delete */
	LIST(members_name),     /* secret_delete */
	LIST(members_interface),/* ap_stations */
	EMPTY,                  /* radios */
	LIST(members_radio_set),
};

#undef LIST
#undef EMPTY

/*
 * Whether a tag is one of the kinds this build knows.
 *
 * Through `int` rather than compared against the enum's own bounds, because
 * whether an enumerated type is signed is the compiler's choice: `kind < 0`
 * is a warning on a build that made it unsigned and a necessary check on one
 * that did not, and a cast is the only spelling that is right on both.
 */
static int kind_in_range(int kind, int count)
{
	return kind >= 0 && kind < count;
}

static const char *const subject_names[NCFG_PROTO_SUBJECT_COUNT] = {
	"interface",
	"address",
	"route",
};

const char *ncfg_proto_request_name(ncfg_proto_request_kind_t kind)
{
	if (!kind_in_range((int)kind, NCFG_PROTO_REQ_COUNT)) {
		return NULL;
	}
	return request_names[kind];
}

int ncfg_proto_request_kind_from(const char *name, size_t length,
    ncfg_proto_request_kind_t *kind_out)
{
	int at;

	if (!name) {
		return 0;
	}
	for (at = 0; at < NCFG_PROTO_REQ_COUNT; at++) {
		const char *candidate = request_names[at];

		if (candidate && strlen(candidate) == length &&
		    memcmp(candidate, name, length) == 0) {
			*kind_out = (ncfg_proto_request_kind_t)at;
			return 1;
		}
	}
	return 0;
}

const char *const *ncfg_proto_request_members(ncfg_proto_request_kind_t kind, size_t *count_out)
{
	if (!kind_in_range((int)kind, NCFG_PROTO_REQ_COUNT)) {
		*count_out = 0;
		return NULL;
	}
	*count_out = request_members[kind].count;
	return request_members[kind].names;
}

/* ------------------------------------------------------------- encoding */

static void member_str(ncfg_json_writer_t *writer, const char *name, ncfg_proto_str_t text)
{
	ncfg_json_write_key(writer, name);
	/* Counted, because a decoded string is not terminated and an SSID name
	 * may hold anything a beacon carried. A NULL here is the writer's own
	 * refusal, which is what an unfilled required member turns into. */
	ncfg_json_write_string_bytes(writer, text.bytes, text.length);
}

/* Absent members are not written at all -- serde's `skip_serializing_if`, and
 * the reason the witness lines differ in length for one request. */
static void member_str_if(ncfg_json_writer_t *writer, const char *name, ncfg_proto_str_t text)
{
	if (text.bytes) {
		member_str(writer, name, text);
	}
}

static void member_strs(ncfg_json_writer_t *writer, const char *name, ncfg_proto_strs_t list)
{
	size_t at;

	ncfg_json_write_key(writer, name);
	ncfg_json_write_array_begin(writer);
	for (at = 0; at < list.count; at++) {
		ncfg_json_write_string_bytes(writer, list.items[at].bytes, list.items[at].length);
	}
	ncfg_json_write_array_end(writer);
}

static void member_int_if(ncfg_json_writer_t *writer, const char *name, ncfg_proto_int_t value)
{
	if (value.present) {
		ncfg_json_write_member_int(writer, name, value.value);
	}
}

/* A boolean that is only written when it is true, which is what
 * `skip_serializing_if = "std::ops::Not::not"` emits. */
static void member_flag_if(ncfg_json_writer_t *writer, const char *name, unsigned char flag)
{
	if (flag) {
		ncfg_json_write_member_bool(writer, name, 1);
	}
}

static int missing(char *err, size_t err_size, const char *kind, const char *member)
{
	ncfg_error_set(err, err_size, "a `%s` request needs `%s` and has none", kind, member);
	return 0;
}

static int encode_subject(const ncfg_proto_subject_t *subject, ncfg_json_writer_t *writer,
    char *err, size_t err_size)
{
	if (!kind_in_range((int)subject->kind, NCFG_PROTO_SUBJECT_COUNT)) {
		ncfg_error_set(err, err_size, "an `explain` subject of no known kind");
		return 0;
	}
	ncfg_json_write_object_begin(writer);
	ncfg_json_write_member_string(writer, "subject", subject_names[subject->kind]);
	switch (subject->kind) {
	case NCFG_PROTO_SUBJECT_INTERFACE:
		if (!subject->name.bytes) {
			return missing(err, err_size, "explain", "subject.name");
		}
		member_str(writer, "name", subject->name);
		break;
	case NCFG_PROTO_SUBJECT_ADDRESS:
		if (!subject->interface.bytes || !subject->address.bytes) {
			return missing(err, err_size, "explain", "subject.interface and subject.address");
		}
		member_str(writer, "interface", subject->interface);
		member_str(writer, "address", subject->address);
		break;
	case NCFG_PROTO_SUBJECT_ROUTE:
	default:
		if (!subject->interface.bytes || !subject->destination.bytes) {
			return missing(err, err_size, "explain",
			    "subject.interface and subject.destination");
		}
		member_str(writer, "interface", subject->interface);
		member_str(writer, "destination", subject->destination);
		break;
	}
	ncfg_json_write_object_end(writer);
	return 1;
}

static int encode_payload(const ncfg_proto_request_t *request, ncfg_json_writer_t *writer,
    char *err, size_t err_size)
{
	const char *kind = request_names[request->kind];

	switch (request->kind) {
	case NCFG_PROTO_REQ_HELLO:
	case NCFG_PROTO_REQ_STATUS:
	case NCFG_PROTO_REQ_PLAN:
	case NCFG_PROTO_REQ_CONFIRM:
	case NCFG_PROTO_REQ_REVERT:
	case NCFG_PROTO_REQ_RELOAD:
	case NCFG_PROTO_REQ_SHOW:
	case NCFG_PROTO_REQ_CONFIG_LIST:
	case NCFG_PROTO_REQ_MONITOR:
	case NCFG_PROTO_REQ_PROBE_LIST:
	case NCFG_PROTO_REQ_HOOK_LIST:
	case NCFG_PROTO_REQ_PROFILE_LIST:
	case NCFG_PROTO_REQ_MODEM_LIST:
	case NCFG_PROTO_REQ_SECRET_LIST:
	case NCFG_PROTO_REQ_RADIOS:
		break;
	case NCFG_PROTO_REQ_APPLY:
		member_int_if(writer, "confirm", request->u.apply.confirm);
		/* The three consent lists are always written, empty or not: they
		 * carry no `skip_serializing_if`, and the witness pins
		 * `"restart_wedged":[]` on a request that consents to nothing.
		 * They are three lists rather than one because they consent to
		 * different things -- an operator who accepted a brief outage on
		 * one interface has not agreed to leave a private key loaded on
		 * another, nor to have a backend killed that may only be busy. */
		member_strs(writer, "allow_disruption", request->u.apply.allow_disruption);
		member_strs(writer, "strand_credentials", request->u.apply.strand_credentials);
		member_strs(writer, "restart_wedged", request->u.apply.restart_wedged);
		break;
	case NCFG_PROTO_REQ_EXPLAIN:
		ncfg_json_write_key(writer, "subject");
		if (!encode_subject(&request->u.explain, writer, err, err_size)) {
			return 0;
		}
		break;
	case NCFG_PROTO_REQ_WIFI_SCAN:
	case NCFG_PROTO_REQ_WIFI_STATUS:
	case NCFG_PROTO_REQ_WIFI_DISCONNECT:
	case NCFG_PROTO_REQ_AP_STATIONS:
		if (!request->u.interface.bytes) {
			return missing(err, err_size, kind, "interface");
		}
		member_str(writer, "interface", request->u.interface);
		break;
	case NCFG_PROTO_REQ_WIFI_ADD:
		if (!request->u.wifi_add.ssid.bytes) {
			return missing(err, err_size, kind, "ssid");
		}
		member_str(writer, "ssid", request->u.wifi_add.ssid);
		member_str_if(writer, "id", request->u.wifi_add.id);
		member_str_if(writer, "passphrase", request->u.wifi_add.passphrase);
		member_str_if(writer, "proto", request->u.wifi_add.proto);
		member_flag_if(writer, "hidden", request->u.wifi_add.hidden);
		member_int_if(writer, "metric", request->u.wifi_add.metric);
		if (request->u.wifi_add.eap.present) {
			const ncfg_proto_eap_t *eap = &request->u.wifi_add.eap;

			if (!eap->method.bytes || !eap->identity.bytes) {
				return missing(err, err_size, kind, "eap.method and eap.identity");
			}
			ncfg_json_write_key(writer, "eap");
			ncfg_json_write_object_begin(writer);
			member_str(writer, "method", eap->method);
			member_str(writer, "identity", eap->identity);
			member_str_if(writer, "anonymous_identity", eap->anonymous_identity);
			member_str_if(writer, "phase2", eap->phase2);
			member_str_if(writer, "ca_cert", eap->ca_cert);
			member_str_if(writer, "client_cert", eap->client_cert);
			ncfg_json_write_object_end(writer);
		}
		break;
	case NCFG_PROTO_REQ_WIFI_CONNECT:
		/* By id in the configuration, never by SSID and never with a
		 * credential: the request cannot be used to join something the
		 * configuration does not already describe, which is what keeps it
		 * inside the `wifi` tier (0013). */
		if (!request->u.wifi_connect.interface.bytes) {
			return missing(err, err_size, kind, "interface");
		}
		if (!request->u.wifi_connect.network.bytes) {
			return missing(err, err_size, kind, "network");
		}
		member_str(writer, "interface", request->u.wifi_connect.interface);
		member_str(writer, "network", request->u.wifi_connect.network);
		break;
	case NCFG_PROTO_REQ_WIFI_FORGET:
		if (!request->u.id.bytes) {
			return missing(err, err_size, kind, "id");
		}
		member_str(writer, "id", request->u.id);
		break;
	case NCFG_PROTO_REQ_CONFIG_PUT:
	case NCFG_PROTO_REQ_PROBE_PUT:
		/* A name, never a path: netcfgd decides where it goes, and the
		 * name is checked by the rule a wifi profile's id follows, so it
		 * cannot contain a separator, traverse upwards or begin with a
		 * dot. A request that could name a path would be one that could
		 * write anywhere root can. */
		if (!request->u.put.name.bytes) {
			return missing(err, err_size, kind, "name");
		}
		if (!request->u.put.text.bytes) {
			return missing(err, err_size, kind, "text");
		}
		member_str(writer, "name", request->u.put.name);
		member_str(writer, "text", request->u.put.text);
		member_flag_if(writer, "replace", request->u.put.replace);
		break;
	case NCFG_PROTO_REQ_SECRET_PUT:
		if (!request->u.secret_put.name.bytes) {
			return missing(err, err_size, kind, "name");
		}
		if (!request->u.secret_put.value.bytes) {
			return missing(err, err_size, kind, "value");
		}
		member_str(writer, "name", request->u.secret_put.name);
		member_str(writer, "value", request->u.secret_put.value);
		/* Absent means refuse: a `WireGuard` private key nobody has a copy
		 * of cannot be got back (0042), so replacing one is said rather
		 * than assumed. */
		member_flag_if(writer, "replace", request->u.secret_put.replace);
		break;
	case NCFG_PROTO_REQ_PROFILE_SET:
		/* Absent stops using one, which is the default state and is not a
		 * profile called "none". */
		member_str_if(writer, "name", request->u.name);
		break;
	case NCFG_PROTO_REQ_CONFIG_DELETE:
	case NCFG_PROTO_REQ_SECRET_DELETE:
		if (!request->u.name.bytes) {
			return missing(err, err_size, kind, "name");
		}
		member_str(writer, "name", request->u.name);
		break;
	case NCFG_PROTO_REQ_PROFILE_SAVE:
		if (!request->u.profile_save.name.bytes) {
			return missing(err, err_size, kind, "name");
		}
		member_str(writer, "name", request->u.profile_save.name);
		member_flag_if(writer, "replace", request->u.profile_save.replace);
		break;
	case NCFG_PROTO_REQ_RADIO_SET:
		if (!request->u.radio_set.interface.bytes) {
			return missing(err, err_size, kind, "interface");
		}
		member_str(writer, "interface", request->u.radio_set.interface);
		ncfg_json_write_member_bool(writer, "activate", request->u.radio_set.activate);
		break;
	case NCFG_PROTO_REQ_COUNT:
	default:
		ncfg_error_set(err, err_size, "a request of no known kind");
		return 0;
	}
	return 1;
}

int ncfg_proto_request_encode(const ncfg_proto_request_t *request, ncfg_buf_t *out,
    char *err, size_t err_size)
{
	ncfg_json_writer_t writer;

	if (!request || !out) {
		ncfg_error_set(err, err_size, "nothing to encode, or nowhere to put it");
		return 0;
	}
	if (!kind_in_range((int)request->kind, NCFG_PROTO_REQ_COUNT)) {
		ncfg_error_set(err, err_size, "a request of no known kind");
		return 0;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	/* The tag first, then the payload's members flattened beside it rather
	 * than nested under it -- which is the envelope's whole shape, and what
	 * a client looking for `entries` under a key got wrong in the TUI's
	 * wifi pane. */
	ncfg_json_write_member_string(&writer, "request", request_names[request->kind]);
	if (!encode_payload(request, &writer, err, err_size)) {
		/*
		 * Fail the line, not just the call. Reaching into `failed` is what
		 * `json/write.c` does and for the same reason: `ncfg_buf_t` has no
		 * call that says "you are ruined", and the alternative is a caller
		 * reading half a request out of a buffer that reports success.
		 * Half a message is the one that gets sent by accident.
		 */
		out->failed = 1;
		return 0;
	}
	ncfg_json_write_object_end(&writer);
	if (!ncfg_json_write_done(&writer)) {
		const char *why = ncfg_json_write_failure(&writer);

		ncfg_error_set(err, err_size, "the request could not be written: %s",
		    why ? why : "it was left unfinished");
		return 0;
	}
	return 1;
}

int ncfg_proto_request_write(const ncfg_proto_request_t *request, ncfg_buf_t *out,
    char *err, size_t err_size)
{
	if (!ncfg_proto_request_encode(request, out, err, err_size)) {
		return 0;
	}
	return ncfg_proto_line_finish(out, err, err_size);
}

/* ------------------------------------------------------------- decoding */

static int decode_subject(ncfg_proto_dec_t *dec, uint32_t object, ncfg_proto_subject_t *out)
{
	ncfg_proto_str_t tag;
	int at;
	static const char *const interface_members[] = { "name" };
	static const char *const address_members[] = { "interface", "address" };
	static const char *const route_members[] = { "interface", "destination" };
	const char *const *allowed;
	size_t allowed_count;

	memset(out, 0, sizeof(*out));
	if (ncfg_json_type(dec->doc, object) != NCFG_JSON_OBJECT) {
		return ncfg_proto_fail(dec, "`subject` on this request is not an object");
	}
	if (!ncfg_proto_get_str(dec, object, "subject", 1, "an `explain` subject", &tag)) {
		return 0;
	}
	for (at = 0; at < NCFG_PROTO_SUBJECT_COUNT; at++) {
		if (ncfg_proto_str_equals(tag, subject_names[at])) {
			break;
		}
	}
	if (at == NCFG_PROTO_SUBJECT_COUNT) {
		return ncfg_proto_fail(dec, "`%.*s` is not something `explain` can be asked about",
		    (int)tag.length, tag.bytes);
	}
	out->kind = (ncfg_proto_subject_kind_t)at;
	switch (out->kind) {
	case NCFG_PROTO_SUBJECT_INTERFACE:
		allowed = interface_members;
		allowed_count = 1u;
		if (!ncfg_proto_get_str(dec, object, "name", 1, "an `explain` subject", &out->name)) {
			return 0;
		}
		break;
	case NCFG_PROTO_SUBJECT_ADDRESS:
		allowed = address_members;
		allowed_count = 2u;
		if (!ncfg_proto_get_str(dec, object, "interface", 1, "an `explain` subject",
		        &out->interface) ||
		    !ncfg_proto_get_str(dec, object, "address", 1, "an `explain` subject",
		        &out->address)) {
			return 0;
		}
		break;
	case NCFG_PROTO_SUBJECT_ROUTE:
	default:
		allowed = route_members;
		allowed_count = 2u;
		if (!ncfg_proto_get_str(dec, object, "interface", 1, "an `explain` subject",
		        &out->interface) ||
		    !ncfg_proto_get_str(dec, object, "destination", 1, "an `explain` subject",
		        &out->destination)) {
			return 0;
		}
		break;
	}
	/*
	 * **Stricter than the Rust, deliberately, and this is the one place.**
	 * `Subject` is internally tagged, so it carries no `deny_unknown_fields`
	 * and cannot -- serde refuses the attribute on this representation,
	 * because the tag would be the first member denied, which is the same
	 * limitation section 7 records for the envelope. Every other request
	 * payload here *is* `deny_unknown_fields`; this one is the gap the
	 * derive left. Section 7 asks an implementation to refuse an unknown
	 * member in the payload as well as the envelope, and a hand-written
	 * table has no such limitation, so this keeps the stated rule rather
	 * than reproducing the mechanism's shortfall.
	 *
	 * Read from the Rust rather than measured against a running daemon: the
	 * attribute is absent in `lib.rs` and serde ignores unknown fields
	 * without it. Nothing in the witness turns on the difference -- no line
	 * carries an undefined member -- so this is a divergence to know about
	 * rather than one that shows up in the round trip.
	 */
	return ncfg_proto_check_members(dec, object, "subject", allowed, allowed_count,
	    "an `explain` subject");
}

static int decode_eap(ncfg_proto_dec_t *dec, uint32_t object, ncfg_proto_eap_t *out)
{
	static const char *const eap_members[] = {
		"method", "identity", "anonymous_identity", "phase2", "ca_cert", "client_cert"
	};
	const char *what = "a `wifi_add` eap";

	memset(out, 0, sizeof(*out));
	if (ncfg_json_type(dec->doc, object) != NCFG_JSON_OBJECT) {
		return ncfg_proto_fail(dec, "`eap` on this request is not an object");
	}
	out->present = 1;
	if (!ncfg_proto_get_str(dec, object, "method", 1, what, &out->method) ||
	    !ncfg_proto_get_str(dec, object, "identity", 1, what, &out->identity) ||
	    !ncfg_proto_get_str(dec, object, "anonymous_identity", 0, what,
	        &out->anonymous_identity) ||
	    !ncfg_proto_get_str(dec, object, "phase2", 0, what, &out->phase2) ||
	    !ncfg_proto_get_str(dec, object, "ca_cert", 0, what, &out->ca_cert) ||
	    !ncfg_proto_get_str(dec, object, "client_cert", 0, what, &out->client_cert)) {
		return 0;
	}
	/* `EapRequest` is `deny_unknown_fields` in the Rust, so this half was
	 * already strict there. A member that could name a path is exactly what
	 * must not be silently accepted here. */
	return ncfg_proto_check_members(dec, object, "method", eap_members,
	    sizeof(eap_members) / sizeof(eap_members[0]), what);
}

int ncfg_proto_decode_request(ncfg_proto_dec_t *dec, uint32_t object, ncfg_proto_request_t *out)
{
	ncfg_proto_str_t tag;
	ncfg_proto_request_kind_t kind;
	const char *const *allowed;
	size_t allowed_count;
	const char *what = "this request";
	uint32_t node;

	memset(out, 0, sizeof(*out));
	if (!ncfg_proto_get_str(dec, object, "request", 1, what, &tag)) {
		return 0;
	}
	if (!ncfg_proto_request_kind_from(tag.bytes, tag.length, &kind)) {
		/* An unknown request is refused rather than silently treated as
		 * some other one -- the same rule the document parser applies,
		 * and the reason a client cannot make the daemon guess. */
		return ncfg_proto_fail(dec, "`%.*s` is not a request this speaks",
		    (int)tag.length, tag.bytes);
	}
	out->kind = kind;

	switch (kind) {
	case NCFG_PROTO_REQ_HELLO:
	case NCFG_PROTO_REQ_STATUS:
	case NCFG_PROTO_REQ_PLAN:
	case NCFG_PROTO_REQ_CONFIRM:
	case NCFG_PROTO_REQ_REVERT:
	case NCFG_PROTO_REQ_RELOAD:
	case NCFG_PROTO_REQ_SHOW:
	case NCFG_PROTO_REQ_CONFIG_LIST:
	case NCFG_PROTO_REQ_MONITOR:
	case NCFG_PROTO_REQ_PROBE_LIST:
	case NCFG_PROTO_REQ_HOOK_LIST:
	case NCFG_PROTO_REQ_PROFILE_LIST:
	case NCFG_PROTO_REQ_MODEM_LIST:
	case NCFG_PROTO_REQ_SECRET_LIST:
	case NCFG_PROTO_REQ_RADIOS:
		break;
	case NCFG_PROTO_REQ_APPLY:
		if (!ncfg_proto_get_int(dec, object, "confirm", 0, what,
		        &out->u.apply.confirm) ||
		    !ncfg_proto_get_strs(dec, object, "allow_disruption", 0, what,
		        &out->u.apply.allow_disruption) ||
		    !ncfg_proto_get_strs(dec, object, "strand_credentials", 0, what,
		        &out->u.apply.strand_credentials) ||
		    !ncfg_proto_get_strs(dec, object, "restart_wedged", 0, what,
		        &out->u.apply.restart_wedged)) {
			return 0;
		}
		break;
	case NCFG_PROTO_REQ_EXPLAIN:
		node = ncfg_json_member(dec->doc, object, "subject");
		if (node == NCFG_JSON_NONE) {
			return ncfg_proto_fail(dec, "%s is missing `subject`", what);
		}
		if (!decode_subject(dec, node, &out->u.explain)) {
			return 0;
		}
		break;
	case NCFG_PROTO_REQ_WIFI_SCAN:
	case NCFG_PROTO_REQ_WIFI_STATUS:
	case NCFG_PROTO_REQ_WIFI_DISCONNECT:
	case NCFG_PROTO_REQ_AP_STATIONS:
		if (!ncfg_proto_get_str(dec, object, "interface", 1, what, &out->u.interface)) {
			return 0;
		}
		break;
	case NCFG_PROTO_REQ_WIFI_ADD:
		if (!ncfg_proto_get_str(dec, object, "ssid", 1, what, &out->u.wifi_add.ssid) ||
		    !ncfg_proto_get_str(dec, object, "id", 0, what, &out->u.wifi_add.id) ||
		    !ncfg_proto_get_str(dec, object, "passphrase", 0, what,
		        &out->u.wifi_add.passphrase) ||
		    !ncfg_proto_get_str(dec, object, "proto", 0, what, &out->u.wifi_add.proto) ||
		    !ncfg_proto_get_bool(dec, object, "hidden", 0, 0, what,
		        &out->u.wifi_add.hidden) ||
		    !ncfg_proto_get_int(dec, object, "metric", 0, what, &out->u.wifi_add.metric)) {
			return 0;
		}
		node = ncfg_json_member(dec->doc, object, "eap");
		if (node != NCFG_JSON_NONE && ncfg_json_type(dec->doc, node) != NCFG_JSON_NULL &&
		    !decode_eap(dec, node, &out->u.wifi_add.eap)) {
			return 0;
		}
		break;
	case NCFG_PROTO_REQ_WIFI_CONNECT:
		if (!ncfg_proto_get_str(dec, object, "interface", 1, what,
		        &out->u.wifi_connect.interface) ||
		    !ncfg_proto_get_str(dec, object, "network", 1, what,
		        &out->u.wifi_connect.network)) {
			return 0;
		}
		break;
	case NCFG_PROTO_REQ_WIFI_FORGET:
		if (!ncfg_proto_get_str(dec, object, "id", 1, what, &out->u.id)) {
			return 0;
		}
		break;
	case NCFG_PROTO_REQ_CONFIG_PUT:
	case NCFG_PROTO_REQ_PROBE_PUT:
		if (!ncfg_proto_get_str(dec, object, "name", 1, what, &out->u.put.name) ||
		    !ncfg_proto_get_str(dec, object, "text", 1, what, &out->u.put.text) ||
		    !ncfg_proto_get_bool(dec, object, "replace", 0, 0, what, &out->u.put.replace)) {
			return 0;
		}
		break;
	case NCFG_PROTO_REQ_SECRET_PUT:
		if (!ncfg_proto_get_str(dec, object, "name", 1, what, &out->u.secret_put.name) ||
		    !ncfg_proto_get_str(dec, object, "value", 1, what, &out->u.secret_put.value) ||
		    !ncfg_proto_get_bool(dec, object, "replace", 0, 0, what,
		        &out->u.secret_put.replace)) {
			return 0;
		}
		break;
	case NCFG_PROTO_REQ_PROFILE_SET:
		if (!ncfg_proto_get_str(dec, object, "name", 0, what, &out->u.name)) {
			return 0;
		}
		break;
	case NCFG_PROTO_REQ_CONFIG_DELETE:
	case NCFG_PROTO_REQ_SECRET_DELETE:
		if (!ncfg_proto_get_str(dec, object, "name", 1, what, &out->u.name)) {
			return 0;
		}
		break;
	case NCFG_PROTO_REQ_PROFILE_SAVE:
		if (!ncfg_proto_get_str(dec, object, "name", 1, what,
		        &out->u.profile_save.name) ||
		    !ncfg_proto_get_bool(dec, object, "replace", 0, 0, what,
		        &out->u.profile_save.replace)) {
			return 0;
		}
		break;
	case NCFG_PROTO_REQ_RADIO_SET:
		if (!ncfg_proto_get_str(dec, object, "interface", 1, what,
		        &out->u.radio_set.interface) ||
		    !ncfg_proto_get_bool(dec, object, "activate", 1, 0, what,
		        &out->u.radio_set.activate)) {
			return 0;
		}
		break;
	case NCFG_PROTO_REQ_COUNT:
	default:
		return ncfg_proto_fail(dec, "a request of no known kind");
	}

	/*
	 * The envelope last, after the payload -- the Rust's order, so that a
	 * malformed message keeps the parser's own message rather than being
	 * reported as an unknown member.
	 */
	allowed = ncfg_proto_request_members(kind, &allowed_count);
	return ncfg_proto_check_members(dec, object, "request", allowed, allowed_count, what);
}
