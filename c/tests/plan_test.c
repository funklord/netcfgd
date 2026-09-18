/*
 * plan_test.c -- the planner, against its frozen witness and against the
 * cases the Rust's own fixtures carry.
 *
 * WHAT THE WITNESS COMPARISON PROVES, AND HOW
 *   `doc/schema/plan.json` is one plan carrying **every op there is** -- one
 *   sample each, forty-eight of them -- with an inverse on every action, one
 *   warning, one refusal and one stranded credential. It is built here by hand
 *   exactly as `crates/netcfgd-plan/tests/frozen.rs` builds it, written, and
 *   compared **byte for byte against the witness with its whitespace
 *   removed**.
 *
 *   That is the strongest form available: the Rust writes the file with
 *   `serde_json::to_string_pretty` and this port's writer is compact, so the
 *   two differ by indentation and by nothing else if the port is right. Same
 *   members, same order, same values, same escaping -- and an op renamed, a
 *   member dropped, one written that should have been omitted, or an integer
 *   that lost a digit all show up as a byte that does not match, with the
 *   offset printed.
 *
 *   **The whole witness is reproducible from this side**, which is worth
 *   saying because it need not have been: every op in it is a value, not the
 *   output of a pass, so nothing here depends on a planner pass this port has
 *   not reached. What the witness does *not* prove is that the planner ever
 *   emits any particular one of them; the fixtures below are what does that,
 *   for the ops this build plans.
 *
 * WHAT ELSE IS HERE
 *   - **The model values a plan embeds**, checked against
 *     `doc/schema/document.json`: every interface kind, route, rule, DNS
 *     policy and peer in that file is written through the planner's own
 *     writers and must appear verbatim in the minified witness. That is what
 *     stops the planner's copy of those writers drifting from the model's.
 *   - **The cases from `tests/fixtures.rs`** for everything this build plans,
 *     each keeping the sentence that says which defect it is about.
 *   - **The ordering rule and the ownership guard by name**, because those are
 *     the two properties the module is for.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/json_write.h"
#include "ncfg/observed.h"
#include "ncfg/plan.h"

/*
 * The planner's own header, by path, because three of the things under test
 * are deliberately not in its public face: the writers for the model values a
 * plan embeds, and the subnet arithmetic ordering rule 4 is built on. Neither
 * is something a caller of `ncfg_plan_build` needs, and a surface widened for
 * a test is a surface somebody else then depends on.
 */
#include "../src/plan/plan_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The model's own structs hold `char *`, and a test's values are literals.
 * `-Wwrite-strings` makes a literal `const char[]`, so the cast is what lets a
 * fixture be written as data. Nothing here is ever modified or freed. */
#define LIT(text) ((char *)(uintptr_t)(text))

static int failures;
static int checks;

static void check(int condition, const char *what)
{
	checks++;
	printf("%-70s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* ------------------------------------------------------------------------ *
 * Reading the witnesses
 * ------------------------------------------------------------------------ */

static char *slurp(const char *path, size_t *length_out)
{
	FILE  *file = fopen(path, "rb");
	char  *text;
	long   size;
	size_t got;

	if (!file) {
		return NULL;
	}
	if (fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) < 0 ||
	    fseek(file, 0, SEEK_SET) != 0) {
		fclose(file);
		return NULL;
	}
	text = malloc((size_t)size + 1u);
	if (!text) {
		fclose(file);
		return NULL;
	}
	got = fread(text, 1u, (size_t)size, file);
	fclose(file);
	text[got] = '\0';
	*length_out = got;
	return text;
}

/*
 * The same bytes with the whitespace between tokens removed.
 *
 * Deliberately not a parser: it tracks whether it is inside a string and
 * whether the last byte was a backslash, and nothing else. A checker that
 * understood a plan could agree with a wrong writer about what the plan means;
 * this one cannot, because it does not know.
 */
static char *minify(const char *text, size_t length, size_t *length_out)
{
	char  *out = malloc(length + 1u);
	size_t at = 0;
	size_t i;
	int    in_string = 0;
	int    escaped = 0;

	if (!out) {
		return NULL;
	}
	for (i = 0; i < length; i++) {
		char c = text[i];

		if (in_string) {
			out[at++] = c;
			if (escaped) {
				escaped = 0;
			} else if (c == '\\') {
				escaped = 1;
			} else if (c == '"') {
				in_string = 0;
			}
			continue;
		}
		if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
			continue;
		}
		out[at++] = c;
		if (c == '"') {
			in_string = 1;
		}
	}
	out[at] = '\0';
	*length_out = at;
	return out;
}

/* Where two texts part, printed, because "they differ" is not a diagnostic. */
static void report_difference(const char *want, size_t want_length, const char *got,
    size_t got_length)
{
	size_t at = 0;
	size_t from;

	while (at < want_length && at < got_length && want[at] == got[at]) {
		at++;
	}
	from = at > 60u ? at - 60u : 0u;
	printf("  they part at byte %zu (witness %zu bytes, written %zu)\n", at, want_length,
	    got_length);
	printf("  witness: ...%.*s\n", (int)(want_length - from > 120u ? 120u : want_length - from),
	    want + from);
	printf("  written: ...%.*s\n", (int)(got_length - from > 120u ? 120u : got_length - from),
	    got + from);
}

static const char *find_witness(const char *name)
{
	static char       path[512];
	static const char *const roots[] = { "..", ".", "../.." };
	size_t             i;

	for (i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
		FILE *file;

		(void)snprintf(path, sizeof(path), "%s/doc/schema/%s", roots[i], name);
		file = fopen(path, "rb");
		if (file) {
			fclose(file);
			return path;
		}
	}
	(void)snprintf(path, sizeof(path), "../doc/schema/%s", name);
	return path;
}

/* ------------------------------------------------------------------------ *
 * The witness plan, built exactly as `frozen.rs` builds it
 * ------------------------------------------------------------------------ */

static ncfg_route_t witness_route(void)
{
	ncfg_route_t route;

	memset(&route, 0, sizeof(route));
	route.destination = LIT("10.0.0.0/8");
	route.via = LIT("192.168.1.1");
	route.metric.has = 1;
	route.metric.value = 700;
	route.table.has = 1;
	route.table.value = 254;
	route.src = LIT("192.168.1.10");
	route.scope.has = 1;
	route.scope.value = NCFG_ROUTE_SCOPE_GLOBAL;
	route.onlink = 1;
	route.proto.has = 1;
	route.proto.value = 110;
	return route;
}

static ncfg_routing_rule_t witness_rule(void)
{
	ncfg_routing_rule_t rule;

	memset(&rule, 0, sizeof(rule));
	rule.id = LIT("from-lan");
	rule.priority = 100;
	rule.family = NCFG_RULE_FAMILY_INET;
	rule.from = LIT("192.168.0.0/24");
	rule.to = LIT("10.0.0.0/8");
	rule.iif = LIT("eth0");
	rule.oif = LIT("eth1");
	rule.fwmark.has = 1;
	rule.fwmark.value = 3;
	rule.fwmask.has = 1;
	rule.fwmask.value = 0xffff;
	rule.table.has = 1;
	rule.table.value = 200;
	rule.action = NCFG_RULE_ACTION_LOOKUP;
	rule.suppress_prefixlength.has = 1;
	rule.suppress_prefixlength.value = 0;
	rule.l3mdev = 1;
	rule.invert = 1;
	return rule;
}

/* Every op there is, in the witness's order. */
static size_t witness_ops(ncfg_op_t *ops, size_t max, const ncfg_route_t *route,
    const ncfg_routing_rule_t *rule, const ncfg_interface_kind_t *dummy,
    const ncfg_wg_peer_t *peer, const ncfg_dns_policy_t *policy,
    const ncfg_offload_t *features, const char *const *profiles, const char *const *uplinks)
{
	size_t at = 0;

	memset(ops, 0, max * sizeof(*ops));
#define OP(k) (&ops[at])->kind = (k), (&ops[at++])
	OP(NCFG_OP_LINK_CREATE)->u.link_create.name = "br0";
	ops[at - 1u].u.link_create.kind = dummy;
	OP(NCFG_OP_LINK_DELETE)->u.named.name = "br0";
	OP(NCFG_OP_LINK_SET_MTU)->u.set_mtu.name = "eth0";
	ops[at - 1u].u.set_mtu.mtu = 9000;
	OP(NCFG_OP_LINK_SET_MAC)->u.set_mac.name = "eth0";
	ops[at - 1u].u.set_mac.mac = "02:00:00:00:00:01";
	OP(NCFG_OP_LINK_SET_MASTER)->u.set_master.name = "eth0";
	ops[at - 1u].u.set_master.master = "br0";
	OP(NCFG_OP_LINK_UNSET_MASTER)->u.named.name = "eth0";
	OP(NCFG_OP_LINK_UP)->u.named.name = "eth0";
	OP(NCFG_OP_LINK_DOWN)->u.named.name = "eth0";
	OP(NCFG_OP_ADDR_ADD)->u.addr_add.iface = "eth0";
	ops[at - 1u].u.addr_add.addr = "192.168.1.10/24";
	ops[at - 1u].u.addr_add.preferred_lifetime.has = 1;
	ops[at - 1u].u.addr_add.preferred_lifetime.value = 3600;
	ops[at - 1u].u.addr_add.valid_lifetime.has = 1;
	ops[at - 1u].u.addr_add.valid_lifetime.value = 7200;
	OP(NCFG_OP_ADDR_DEL)->u.addr_del.iface = "eth0";
	ops[at - 1u].u.addr_del.addr = "192.168.1.10/24";
	OP(NCFG_OP_ROUTE_ADD)->u.route.iface = "eth0";
	ops[at - 1u].u.route.route = route;
	OP(NCFG_OP_ROUTE_DEL)->u.route.iface = "eth0";
	ops[at - 1u].u.route.route = route;
	OP(NCFG_OP_BACKEND_START)->u.backend.iface = "eth0";
	ops[at - 1u].u.backend.kind = NCFG_BACKEND_DHCP4;
	OP(NCFG_OP_BACKEND_STOP)->u.backend.iface = "vpn0";
	ops[at - 1u].u.backend.kind = NCFG_BACKEND_OPENVPN;
	OP(NCFG_OP_BACKEND_RELOAD)->u.backend.iface = "wlan0";
	ops[at - 1u].u.backend.kind = NCFG_BACKEND_SUPPLICANT;
	OP(NCFG_OP_BRIDGE_VLAN_ADD)->u.bridge_vlan.iface = "eth0";
	ops[at - 1u].u.bridge_vlan.vid = 10;
	ops[at - 1u].u.bridge_vlan.pvid = 1;
	ops[at - 1u].u.bridge_vlan.untagged = 1;
	ops[at - 1u].u.bridge_vlan.on_self = 0;
	OP(NCFG_OP_BRIDGE_VLAN_DEL)->u.bridge_vlan.iface = "eth0";
	ops[at - 1u].u.bridge_vlan.vid = 10;
	ops[at - 1u].u.bridge_vlan.on_self = 1;
	OP(NCFG_OP_WIFI_SET_PROFILES)->u.set_profiles.device = "wlan0";
	ops[at - 1u].u.set_profiles.profiles = profiles;
	ops[at - 1u].u.set_profiles.profile_count = 1u;
	OP(NCFG_OP_WIFI_ASSOCIATE)->u.associate.device = "wlan0";
	ops[at - 1u].u.associate.network_id = "home";
	OP(NCFG_OP_WIFI_DISASSOCIATE)->u.device.device = "wlan0";
	OP(NCFG_OP_WIFI_SET_REGDOM)->u.regdom.device = "wlan0";
	ops[at - 1u].u.regdom.country = "SE";
	OP(NCFG_OP_ACCESS_CONTROL_ADD)->u.access_control.iface = "wlan0";
	ops[at - 1u].u.access_control.list = NCFG_ACL_POLICY_DENY;
	ops[at - 1u].u.access_control.station = "02:00:00:00:00:aa";
	OP(NCFG_OP_ACCESS_CONTROL_DEL)->u.access_control.iface = "wlan0";
	ops[at - 1u].u.access_control.list = NCFG_ACL_POLICY_ALLOW;
	ops[at - 1u].u.access_control.station = "02:00:00:00:00:bb";
	OP(NCFG_OP_LINK_SET_BOND)->u.set_bond.name = "bond0";
	ops[at - 1u].u.set_bond.mode = 1;
	OP(NCFG_OP_LINK_SET_BRIDGE)->u.named.name = "br0";
	OP(NCFG_OP_LINK_SET_MACVLAN)->u.named.name = "mv0";
	OP(NCFG_OP_LINK_SET_TUNNEL)->u.named.name = "tun-office";
	OP(NCFG_OP_LINK_SET_VXLAN)->u.named.name = "vx0";
	OP(NCFG_OP_WG_SET_DEVICE)->u.wg_device.iface = "wg0";
	/* A reference, never a key. The one thing in this witness worth checking
	 * by eye every time it moves: a plan goes to /run and over the socket. */
	ops[at - 1u].u.wg_device.private_key_ref = "@secret:wg0";
	ops[at - 1u].u.wg_device.listen_port.has = 1;
	ops[at - 1u].u.wg_device.listen_port.value = 51820;
	ops[at - 1u].u.wg_device.fwmark.has = 1;
	ops[at - 1u].u.wg_device.fwmark.value = 1;
	OP(NCFG_OP_WG_SET_PEERS)->u.wg_peers.iface = "wg0";
	ops[at - 1u].u.wg_peers.peers = peer;
	ops[at - 1u].u.wg_peers.peer_count = 1u;
	OP(NCFG_OP_DNS_APPLY)->u.dns.scope = "globals";
	ops[at - 1u].u.dns.policy = policy;
	OP(NCFG_OP_LINK_SET_OFFLOADS)->u.set_offloads.name = "eth0";
	ops[at - 1u].u.set_offloads.features = features;
	ops[at - 1u].u.set_offloads.feature_count = 1u;
	OP(NCFG_OP_LINK_SET_IPV6_TOKEN)->u.set_ipv6_token.name = "eth0";
	ops[at - 1u].u.set_ipv6_token.token = "::5";
	OP(NCFG_OP_RULE_ADD)->u.rule.rule = rule;
	OP(NCFG_OP_RULE_DEL)->u.rule.rule = rule;
	OP(NCFG_OP_QDISC_SET)->u.qdisc.iface = "eth0";
	ops[at - 1u].u.qdisc.kind = "cake";
	ops[at - 1u].u.qdisc.bandwidth_bits.has = 1;
	ops[at - 1u].u.qdisc.bandwidth_bits.value = 20000000;
	ops[at - 1u].u.qdisc.ingress = 1;
	OP(NCFG_OP_QDISC_RESET)->u.iface.iface = "eth0";
	OP(NCFG_OP_INGRESS_REDIRECT)->u.redirect.iface = "eth0";
	ops[at - 1u].u.redirect.target = "ifb-eth0";
	OP(NCFG_OP_INGRESS_REDIRECT_CLEAR)->u.iface.iface = "eth0";
	OP(NCFG_OP_SYSCTL_SET_FORWARDING)->u.forwarding.iface = "eth0";
	ops[at - 1u].u.forwarding.enabled = 1;
	OP(NCFG_OP_SYSCTL_SET_PRIVACY)->u.privacy.iface = "eth0";
	ops[at - 1u].u.privacy.prefer_temporary = 1;
	OP(NCFG_OP_SYSCTL_SET_ACCEPT_RA)->u.accept_ra.iface = "eth0";
	ops[at - 1u].u.accept_ra.value = 2;
	OP(NCFG_OP_HOSTNAME_SET)->u.named.name = "host.example";
	OP(NCFG_OP_NAT_REPLACE)->u.nat.uplinks = uplinks;
	ops[at - 1u].u.nat.uplink_count = 1u;
	OP(NCFG_OP_HOOK_RUN)->u.hook.iface = "eth0";
	ops[at - 1u].u.hook.phase = NCFG_HOOK_PHASE_POST_UP;
	ops[at - 1u].u.hook.path = "/run/netcfgd/hooks/eth0-post_up";
	ops[at - 1u].u.hook.value = "192.168.1.50/24";
	OP(NCFG_OP_COMMIT_ARM)->u.commit_arm.window_seconds = 90;
	OP(NCFG_OP_COMMIT_CONFIRM);
	OP(NCFG_OP_COMMIT_REVERT)->u.commit_revert.to_document_hash =
	    "0000000000000000000000000000000000000000000000000000000000000000";
#undef OP
	return at;
}

#define WITNESS_OP_MAX 64

static ncfg_plan_t *build_witness(ncfg_op_t *ops, size_t *count_out)
{
	static ncfg_route_t        route;
	static ncfg_routing_rule_t rule;
	static ncfg_interface_kind_t dummy;
	static ncfg_wg_peer_t      peer;
	static ncfg_dns_policy_t   policy;
	static ncfg_dns_server_t   server;
	static char               *search[1];
	static char               *allowed[1];
	static ncfg_offload_t      features[1];
	static const char         *profiles[1];
	static const char         *uplinks[1];
	ncfg_plan_t               *plan;
	ncfg_reason_t              reason;
	ncfg_warning_t             warning;
	ncfg_refusal_t             refusal;
	ncfg_stranded_t            stranded;
	uint32_t                   depends[1] = { 0 };
	size_t                     count;
	size_t                     i;

	route = witness_route();
	rule = witness_rule();
	memset(&dummy, 0, sizeof(dummy));
	dummy.kind = NCFG_KIND_DUMMY;

	memset(&peer, 0, sizeof(peer));
	peer.name = LIT("office");
	memset(peer.public_key, 7, sizeof(peer.public_key));
	peer.endpoint = LIT("vpn.example:51820");
	allowed[0] = LIT("10.0.0.0/24");
	peer.allowed_ips = allowed;
	peer.allowed_ip_count = 1u;
	peer.keepalive.has = 1;
	peer.keepalive.value = 25;

	memset(&policy, 0, sizeof(policy));
	policy.mode.mode = NCFG_DNS_MODE_WRITE_RESOLV_CONF;
	memset(&server, 0, sizeof(server));
	server.addr = LIT("9.9.9.9");
	policy.servers = &server;
	policy.server_count = 1u;
	search[0] = LIT("example.com");
	policy.search = search;
	policy.search_count = 1u;

	features[0].name = "rx-checksum";
	features[0].wanted = 1;
	profiles[0] = "home";
	uplinks[0] = "eth0";

	count = witness_ops(ops, WITNESS_OP_MAX, &route, &rule, &dummy, &peer, &policy, features,
	    profiles, uplinks);
	*count_out = count;

	plan = ncfg_plan_new(NULL, 0);
	if (!plan) {
		return NULL;
	}
	memset(&reason, 0, sizeof(reason));
	reason.interface = "eth0";
	reason.field = "addressing[0]";
	reason.desired = "192.168.1.10/24";
	reason.observed = "<absent>";
	for (i = 0; i < count; i++) {
		/* The inverse on every action rather than one: it is optional, and a
		 * member that is absent in the sample pins nothing. */
		(void)ncfg_plan_add(plan, &ops[i], &reason, depends, 1u, &ops[i]);
	}

	warning.message = "slaac is accepted but not yet applied by this build";
	warning.interface = "eth0";
	ncfg_plan_warn(plan, warning.interface, warning.message);

	memset(&refusal, 0, sizeof(refusal));
	refusal.interface = "eth0";
	refusal.op = "link.down";
	refusal.guard = "the office runs on this";
	refusal.reason.interface = "eth0";
	refusal.reason.field = "enabled";
	refusal.reason.desired = "false";
	refusal.reason.observed = "true";
	refusal.override_with = "ncfg apply --allow-disruption eth0";
	ncfg_plan_refuse(plan, &refusal);

	memset(&stranded, 0, sizeof(stranded));
	stranded.interface = "wg0";
	stranded.credential = "the WireGuard private key";
	stranded.irrevocable = "only every peer's administrator can revoke it";
	stranded.remove_with = "on_unmanage = \"clear\"";
	stranded.consent_with = "ncfg apply --strand-credentials wg0";
	ncfg_plan_strand(plan, &stranded);
	return plan;
}

/* ------------------------------------------------------------------------ *
 * Small plumbing for the fixtures
 * ------------------------------------------------------------------------ */

static char *written(const ncfg_plan_t *plan, size_t *length_out)
{
	ncfg_buf_t buf;
	char       message[NCFG_ERROR_MAX];
	char      *text;

	ncfg_buf_init(&buf, 0);
	if (!ncfg_plan_write(plan, &buf, message, sizeof(message))) {
		printf("  could not write the plan: %s\n", message);
		ncfg_buf_free(&buf);
		return NULL;
	}
	text = ncfg_buf_take(&buf, length_out);
	ncfg_buf_free(&buf);
	return text;
}

static ncfg_document_t *document_of(const char *globals, const char *body)
{
	char  text[8192];
	char  message[NCFG_ERROR_MAX];
	ncfg_document_t *document;

	(void)snprintf(text, sizeof(text),
	    "{\"schema_version\":{\"major\":1,\"minor\":1},\"generated_by\":\"plan_test\","
	    "\"globals\":%s,\"networks\":[],%s}",
	    globals, body);
	message[0] = '\0';
	document = ncfg_document_read(text, strlen(text), message, sizeof(message));
	if (!document) {
		printf("  fixture document did not read: %s\n", message);
	}
	return document;
}

static ncfg_observed_t *observed_of(const char *body)
{
	char  text[8192];
	char  message[NCFG_ERROR_MAX];
	ncfg_observed_t *observed;

	(void)snprintf(text, sizeof(text), "{%s}", body);
	message[0] = '\0';
	observed = ncfg_observed_read(text, strlen(text), message, sizeof(message));
	if (!observed) {
		printf("  fixture observation did not read: %s\n", message);
	}
	return observed;
}

/* A link that exists and is down, which is what a fresh boot looks like. */
#define LINK(name) \
	"{\"name\":\"" name "\",\"index\":2,\"mtu\":1500,\"up\":false,\"carrier\":true," \
	"\"ownership\":\"unknown\"}"
#define LINK_UP(name) \
	"{\"name\":\"" name "\",\"index\":2,\"mtu\":1500,\"up\":true,\"carrier\":true," \
	"\"ownership\":\"unknown\"}"

/* The op names of a plan, in order, joined so a mismatch prints readably. */
static void names_of(const ncfg_plan_t *plan, char *out, size_t out_size)
{
	size_t at = 0;
	size_t i;

	out[0] = '\0';
	for (i = 0; i < plan->action_count; i++) {
		int wrote = snprintf(out + at, out_size - at, "%s%s", at ? "," : "",
		    ncfg_op_name(&plan->actions[i].op));

		if (wrote < 0 || (size_t)wrote >= out_size - at) {
			return;
		}
		at += (size_t)wrote;
	}
}

static int has_name(const ncfg_plan_t *plan, const char *name)
{
	size_t i;

	for (i = 0; i < plan->action_count; i++) {
		if (strcmp(ncfg_op_name(&plan->actions[i].op), name) == 0) {
			return 1;
		}
	}
	return 0;
}

/* The index of the first action of this name, or -1. */
static long position(const ncfg_plan_t *plan, const char *name)
{
	size_t i;

	for (i = 0; i < plan->action_count; i++) {
		if (strcmp(ncfg_op_name(&plan->actions[i].op), name) == 0) {
			return (long)i;
		}
	}
	return -1;
}

static const ncfg_action_t *action_named(const ncfg_plan_t *plan, const char *name)
{
	long at = position(plan, name);

	return at < 0 ? NULL : &plan->actions[at];
}

static int depends_on(const ncfg_action_t *action, uint32_t id)
{
	size_t i;

	for (i = 0; i < action->depends_count; i++) {
		if (action->depends_on[i] == id) {
			return 1;
		}
	}
	return 0;
}

static int warned_about(const ncfg_plan_t *plan, const char *fragment)
{
	size_t i;

	for (i = 0; i < plan->warning_count; i++) {
		if (plan->warnings[i].message && strstr(plan->warnings[i].message, fragment)) {
			return 1;
		}
	}
	return 0;
}

/* One fixture: read the two documents, plan, and hand the plan to the caller. */
static ncfg_plan_t *plan_of(const char *globals, const char *body, const char *observation,
    const ncfg_plan_options_t *options, ncfg_document_t **document_out,
    ncfg_observed_t **observed_out)
{
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document = document_of(globals, body);
	ncfg_observed_t *observed = observed_of(observation);
	ncfg_plan_t     *plan;

	*document_out = document;
	*observed_out = observed;
	if (!document || !observed) {
		return NULL;
	}
	message[0] = '\0';
	plan = ncfg_plan_build(document, observed, options, message, sizeof(message));
	if (!plan) {
		printf("  could not build the plan: %s\n", message);
	}
	return plan;
}

static void release(ncfg_plan_t *plan, ncfg_document_t *document, ncfg_observed_t *observed)
{
	ncfg_plan_free(plan);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/* ------------------------------------------------------------------------ *
 * The sections
 * ------------------------------------------------------------------------ */

static void the_frozen_witness(void)
{
	const char  *path = find_witness("plan.json");
	size_t       raw_length = 0;
	char        *raw = slurp(path, &raw_length);
	ncfg_op_t    ops[WITNESS_OP_MAX];
	size_t       count = 0;
	ncfg_plan_t *plan;
	char        *text;
	size_t       text_length = 0;
	char        *wanted;
	size_t       wanted_length = 0;
	size_t       i;
	int          plain = 1;

	check(raw != NULL, "the frozen plan witness is there to be read");
	if (!raw) {
		return;
	}
	for (i = 0; i < raw_length; i++) {
		if ((unsigned char)raw[i] >= 0x80u) {
			plain = 0;
		}
	}
	/* Pure ASCII, and unlike the document witness it does carry one escape --
	 * the quoted `on_unmanage = "clear"` inside a sentence -- so the byte
	 * comparison below is also a check that the writer escapes a quote. */
	check(plain, "and carries no byte outside ASCII");
	check(strstr(raw, "\\\"clear\\\"") != NULL, "and one escaped quote, which is checked too");

	plan = build_witness(ops, &count);
	check(plan != NULL && !ncfg_plan_failed(plan), "the witness plan is built");
	check(count == 48u, "and carries every op there is: forty-eight");
	if (!plan) {
		free(raw);
		return;
	}
	text = written(plan, &text_length);
	wanted = minify(raw, raw_length, &wanted_length);
	if (text && wanted) {
		int same = text_length == wanted_length &&
		    memcmp(text, wanted, text_length) == 0;

		if (!same) {
			report_difference(wanted, wanted_length, text, text_length);
		}
		check(same, "the plan is written byte for byte as the witness has it");
	} else {
		check(0, "the plan is written byte for byte as the witness has it");
	}

	/*
	 * A plan carries references to secrets and never secrets. Constraint 5
	 * holds for `/run` and for the wire as well as for the document, and a
	 * plan is both. Cheap to state here, where the whole surface is in one
	 * value, and it fails the day somebody resolves a secret one step early.
	 */
	if (text) {
		static const char *const suspicious[] = { "-----BEGIN", "PRIVATE KEY",
			"passphrase", "password" };
		int clean = 1;

		check(strstr(text, "@secret:wg0") != NULL,
		    "the witness carries a reference to a secret, to check against");
		for (i = 0; i < sizeof(suspicious) / sizeof(suspicious[0]); i++) {
			if (strstr(text, suspicious[i])) {
				printf("  a plan carrying `%s` is carrying a secret\n",
				    suspicious[i]);
				clean = 0;
			}
		}
		check(clean, "and no secret material reaches a plan");
	}
	free(text);
	free(wanted);
	free(raw);
	ncfg_plan_free(plan);
}

/*
 * Every op's wire tag is the name it reports, for every op there is.
 *
 * The tag used to be serde's `snake_case` of the variant while the name was a
 * function, so one operation had two spellings and only a client outside the
 * workspace could see both at once (0082). Here they are one function, so what
 * this checks instead is the list: a sorted roll-call of forty-eight names,
 * which fails when one is renamed, added or lost.
 */
static void the_op_vocabulary(void)
{
	static const char *const expected[] = { "access_control.add", "access_control.del",
		"addr.add", "addr.del", "backend.reload", "backend.start", "backend.stop",
		"bridge.vlan.add", "bridge.vlan.del", "commit.arm", "commit.confirm",
		"commit.revert", "dns.apply", "hook.run", "hostname.set", "ingress.redirect",
		"ingress.redirect.clear", "link.create", "link.delete", "link.down",
		"link.set_bond", "link.set_bridge", "link.set_ipv6_token", "link.set_mac",
		"link.set_macvlan", "link.set_master", "link.set_mtu", "link.set_offloads",
		"link.set_tunnel", "link.set_vxlan", "link.unset_master", "link.up",
		"nat.replace", "qdisc.reset", "qdisc.set", "route.add", "route.del", "rule.add",
		"rule.del", "sysctl.set_accept_ra", "sysctl.set_forwarding",
		"sysctl.set_privacy", "wg.set_device", "wg.set_peers", "wifi.associate",
		"wifi.disassociate", "wifi.set_profiles", "wifi.set_regdom" };
	const size_t count = sizeof(expected) / sizeof(expected[0]);
	int          complete = 1;
	size_t       i;
	size_t       j;

	check(count == 48u, "the vocabulary is forty-eight ops");
	for (i = 0; i < count; i++) {
		int found = 0;

		for (j = 0; j < 48u; j++) {
			ncfg_op_t op;

			memset(&op, 0, sizeof(op));
			op.kind = (int)j;
			if (strcmp(ncfg_op_name(&op), expected[i]) == 0) {
				found = 1;
				break;
			}
		}
		if (!found) {
			printf("  nothing in the enum is called `%s`\n", expected[i]);
			complete = 0;
		}
	}
	for (j = 0; j < 48u; j++) {
		ncfg_op_t op;
		int       found = 0;

		memset(&op, 0, sizeof(op));
		op.kind = (int)j;
		for (i = 0; i < count; i++) {
			if (strcmp(ncfg_op_name(&op), expected[i]) == 0) {
				found = 1;
			}
		}
		if (!found) {
			printf("  `%s` is in the enum and in no list here\n", ncfg_op_name(&op));
			complete = 0;
		}
	}
	check(complete, "and the enum and the roll-call name exactly the same ops");
}

/*
 * The guard blocks what can interrupt traffic and nothing else.
 *
 * `link.set_mtu` is in the list deliberately: lowering an MTU interrupts
 * traffic in flight and raising it can black-hole a path until PMTU discovery
 * catches up. The hook phases are the case decision 0063 records -- a `down`
 * hook refused with the `link.down` it brackets, or the script that unmounts
 * the share runs and the guard keeps the interface up.
 */
static void what_counts_as_disruptive(void)
{
	ncfg_op_t op;

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_LINK_SET_MTU;
	check(ncfg_op_is_disruptive(&op), "link.set_mtu is disruptive, on purpose");
	op.kind = NCFG_OP_ADDR_ADD;
	check(!ncfg_op_is_disruptive(&op), "and adding an address is not");
	op.kind = NCFG_OP_ADDR_DEL;
	check(ncfg_op_is_disruptive(&op), "and taking one away is");

	op.kind = NCFG_OP_SYSCTL_SET_FORWARDING;
	op.u.forwarding.enabled = 1;
	check(!ncfg_op_is_disruptive(&op), "turning forwarding on interrupts nobody");
	op.u.forwarding.enabled = 0;
	check(ncfg_op_is_disruptive(&op), "turning it off cuts off everything behind it");

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_ACCESS_CONTROL_ADD;
	op.u.access_control.list = NCFG_ACL_POLICY_DENY;
	check(ncfg_op_is_disruptive(&op), "denying a station disconnects it");
	op.u.access_control.list = NCFG_ACL_POLICY_ALLOW;
	check(!ncfg_op_is_disruptive(&op), "allowing one interrupts nobody");
	op.kind = NCFG_OP_ACCESS_CONTROL_DEL;
	op.u.access_control.list = NCFG_ACL_POLICY_ALLOW;
	check(ncfg_op_is_disruptive(&op), "taking one off the allow list disconnects it");
	op.u.access_control.list = NCFG_ACL_POLICY_DENY;
	check(!ncfg_op_is_disruptive(&op), "taking one off the deny list interrupts nobody");

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_HOOK_RUN;
	op.u.hook.phase = NCFG_HOOK_PHASE_POST_DOWN;
	check(ncfg_op_is_disruptive(&op),
	    "a down hook is refused with the link.down it brackets (0063)");
	op.u.hook.phase = NCFG_HOOK_PHASE_POST_UP;
	check(!ncfg_op_is_disruptive(&op), "and an up hook is not");

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_DNS_APPLY;
	check(ncfg_op_is_host_wide_config(&op) && !ncfg_op_interface(&op),
	    "dns.apply is host-wide config and names no interface (0165)");
	op.kind = NCFG_OP_COMMIT_CONFIRM;
	check(!ncfg_op_is_host_wide_config(&op),
	    "and commit.confirm names none either and is not swept into a drift pass");
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_NAT_REPLACE;
	check(!ncfg_op_interface(&op),
	    "nat.replace names no interface, so no guard has standing to refuse it");
}

/*
 * The model values a plan embeds, against the model's own frozen witness.
 *
 * `doc/schema/document.json` carries every interface kind there is, a route, a
 * rule, DNS policies and a WireGuard peer. Each is read into the model and
 * written back through the planner's copy of the writers; the bytes must
 * appear verbatim in the minified witness. That is what stops the copy in
 * `src/plan/model_json.c` drifting from `src/model/document.c` -- a member
 * added on one side and not the other is bytes that are not there.
 */
static void the_model_values_a_plan_embeds(void)
{
	const char      *path = find_witness("document.json");
	size_t           raw_length = 0;
	char            *raw = slurp(path, &raw_length);
	size_t           flat_length = 0;
	char            *flat = raw ? minify(raw, raw_length, &flat_length) : NULL;
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document = NULL;
	size_t           i;
	size_t           j;
	int              kinds = 1;
	int              rest = 1;
	size_t           kind_count = 0;

	check(flat != NULL, "the frozen document witness is there to compare against");
	if (!flat) {
		free(raw);
		return;
	}
	message[0] = '\0';
	document = ncfg_document_read(raw, raw_length, message, sizeof(message));
	if (!document) {
		printf("  the document witness did not read: %s\n", message);
	}
	check(document != NULL, "and it reads");
	if (!document) {
		free(flat);
		free(raw);
		return;
	}

#define SAME_AS_WITNESS(call, what, flag)                                             \
	do {                                                                          \
		ncfg_buf_t         buf;                                               \
		ncfg_json_writer_t writer;                                            \
		ncfg_buf_init(&buf, 0);                                               \
		ncfg_json_write_init(&writer, &buf);                                  \
		call;                                                                 \
		if (!ncfg_json_write_done(&writer) ||                                 \
		    !strstr(flat, ncfg_buf_text(&buf))) {                             \
			printf("  %s is written as %s, which is not in the witness\n",\
			    what, ncfg_buf_text(&buf));                               \
			flag = 0;                                                     \
		}                                                                     \
		ncfg_buf_free(&buf);                                                  \
	} while (0)

	for (i = 0; i < document->device_count; i++) {
		SAME_AS_WITNESS(ncfg_plan_write_interface_kind(&writer,
		    &document->devices[i].kind), document->devices[i].name, kinds);
		kind_count++;
	}
	check(kind_count >= 15u, "every interface kind there is appears in the witness");
	check(kinds, "and the planner writes each of them exactly as the model does");

	for (i = 0; i < document->interface_count; i++) {
		const ncfg_interface_t *interface = &document->interfaces[i];

		for (j = 0; j < interface->route_count; j++) {
			SAME_AS_WITNESS(ncfg_plan_write_route(&writer, &interface->routes[j]),
			    "a route", rest);
		}
		if (interface->dns) {
			SAME_AS_WITNESS(ncfg_plan_write_dns_policy(&writer, interface->dns),
			    "a dns policy", rest);
		}
	}
	for (i = 0; i < document->rule_count; i++) {
		SAME_AS_WITNESS(ncfg_plan_write_rule(&writer, &document->rules[i]),
		    "a routing rule", rest);
	}
	SAME_AS_WITNESS(ncfg_plan_write_dns_policy(&writer, &document->globals.dns),
	    "the global dns policy", rest);
#undef SAME_AS_WITNESS
	check(rest, "and the same for a route, a rule and a DNS policy");
	ncfg_document_free(document);
	free(flat);
	free(raw);
}

/* ------------------------------------------------------------------------ *
 * The ordering rules
 * ------------------------------------------------------------------------ */

static void a_static_interface_is_brought_up_in_order(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"},\"mtu\":9000}],"
	    "\"interfaces\":[{\"name\":\"eth0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"192.168.1.10/24\"}],"
	    "\"routes\":[{\"destination\":\"default\",\"via\":\"192.168.1.1\"}]}]",
	    "\"links\":[" LINK("eth0") "]", NULL, &document, &observed);
	char names[512];

	if (plan) {
		names_of(plan, names, sizeof(names));
		if (strcmp(names, "link.set_mtu,link.up,addr.add,route.add") != 0) {
			printf("  the plan is: %s\n", names);
		}
		check(strcmp(names, "link.set_mtu,link.up,addr.add,route.add") == 0,
		    "a static interface is brought up in order");
	} else {
		check(0, "a static interface is brought up in order");
	}
	release(plan, document, observed);
}

/*
 * An already-correct system produces an empty plan.
 *
 * Section 4 calls this the normal case, and it is what makes running apply on
 * a timer harmless.
 */
static void an_already_correct_system_produces_no_actions(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"192.168.1.10/24\"}]}]",
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"addresses\":[{\"interface\":\"eth0\",\"address\":\"192.168.1.10/24\","
	    "\"proto\":110,\"ownership\":\"ours\",\"origin\":\"static\"}]",
	    NULL, &document, &observed);
	char names[512];

	if (plan) {
		names_of(plan, names, sizeof(names));
		if (!ncfg_plan_is_empty(plan) || plan->warning_count != 0u) {
			printf("  expected nothing to do: %s (%zu warnings)\n", names,
			    plan->warning_count);
		}
		check(ncfg_plan_is_empty(plan) && plan->warning_count == 0u,
		    "an already-correct system produces no actions and says nothing");
	} else {
		check(0, "an already-correct system produces no actions and says nothing");
	}
	release(plan, document, observed);
}

/* Rule 4: a route whose next hop lies in an address's subnet waits for that
 * address -- and a gateway outside every configured subnet gets no such edge,
 * because serialising work that need not be serialised is a cost with no
 * payoff. */
static void a_route_waits_only_for_the_address_that_covers_its_gateway(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"192.168.1.10/24\"}],"
	    "\"routes\":[{\"destination\":\"default\",\"via\":\"192.168.1.1\"},"
	    "{\"destination\":\"10.0.0.0/8\",\"via\":\"172.16.0.1\"}]}]",
	    "\"links\":[" LINK("eth0") "]", NULL, &document, &observed);

	if (plan && plan->action_count >= 4u) {
		const ncfg_action_t *address = action_named(plan, "addr.add");
		const ncfg_action_t *covered = &plan->actions[plan->action_count - 2u];
		const ncfg_action_t *outside = &plan->actions[plan->action_count - 1u];

		check(address && depends_on(covered, address->id),
		    "a route waits for the address that covers its gateway");
		check(address && !depends_on(outside, address->id),
		    "and a gateway outside every subnet gets no such edge");
	} else {
		check(0, "a route waits for the address that covers its gateway");
		check(0, "and a gateway outside every subnet gets no such edge");
	}
	release(plan, document, observed);
}

/* Rule 3: an address may be added to a link that is down, so `addr.add` does
 * not wait for `link.up` -- and a route on a down link is rejected by the
 * kernel, so `route.add` does. */
static void an_address_does_not_wait_for_the_link_and_a_route_does(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"192.168.1.10/24\"}],"
	    "\"routes\":[{\"destination\":\"default\",\"via\":\"192.168.1.1\"}]}]",
	    "\"links\":[" LINK("eth0") "]", NULL, &document, &observed);

	if (plan) {
		const ncfg_action_t *up = action_named(plan, "link.up");
		const ncfg_action_t *address = action_named(plan, "addr.add");
		const ncfg_action_t *route = action_named(plan, "route.add");

		check(up && address && !depends_on(address, up->id),
		    "an address may be added to a down link, so it does not wait");
		check(up && route && depends_on(route, up->id),
		    "and a route waits for link.up, which is not one of the eight rules");
	} else {
		check(0, "an address may be added to a down link, so it does not wait");
		check(0, "and a route waits for link.up, which is not one of the eight rules");
	}
	release(plan, document, observed);
}

/* Rule 2: the master waits for its members' enslavement, even though the
 * master sorts first and is therefore planned first. */
static void a_bridge_waits_for_its_members_even_though_it_sorts_first(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"br0\",\"kind\":{\"kind\":\"bridge\",\"members\":"
	    "[\"eth0\",\"eth1\"],\"stp\":false}},"
	    "{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"},\"master\":\"br0\"},"
	    "{\"name\":\"eth1\",\"kind\":{\"kind\":\"physical\"},\"master\":\"br0\"}],"
	    "\"interfaces\":[{\"name\":\"br0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"10.0.0.1/24\"}]}]",
	    "\"links\":[" LINK("eth0") "," LINK("eth1") "]", NULL, &document, &observed);
	int waits = 0;

	if (plan) {
		const ncfg_action_t *up = NULL;
		size_t               i;
		size_t               enslavements = 0;

		for (i = 0; i < plan->action_count; i++) {
			if (strcmp(ncfg_op_name(&plan->actions[i].op), "link.up") == 0 &&
			    strcmp(ncfg_op_interface(&plan->actions[i].op), "br0") == 0) {
				up = &plan->actions[i];
			}
		}
		waits = up != NULL;
		for (i = 0; i < plan->action_count && up; i++) {
			if (strcmp(ncfg_op_name(&plan->actions[i].op), "link.set_master") != 0) {
				continue;
			}
			enslavements++;
			if (!depends_on(up, plan->actions[i].id)) {
				waits = 0;
			}
		}
		if (enslavements != 2u) {
			waits = 0;
		}
	}
	check(waits, "a bridge waits for its members even though it sorts first");
	release(plan, document, observed);
}

/*
 * A port with no interface block is brought up.
 *
 * Measured before this, against real links: a bridge's members were created,
 * enslaved, and left administratively down -- and a bridge port that is down
 * is in the disabled STP state and forwards nothing, so the bridge never gets
 * carrier and a DHCP client over it never gets a lease.
 */
static void a_port_with_no_interface_block_is_brought_up(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"br0\",\"kind\":{\"kind\":\"bridge\",\"members\":"
	    "[\"eth0\"],\"stp\":false}},"
	    "{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"},\"master\":\"br0\"}],"
	    "\"interfaces\":[{\"name\":\"br0\"}]",
	    "\"links\":[" LINK("eth0") "]", NULL, &document, &observed);
	int brought_up = 0;

	if (plan) {
		size_t i;

		for (i = 0; i < plan->action_count; i++) {
			const ncfg_op_t *op = &plan->actions[i].op;

			if (strcmp(ncfg_op_name(op), "link.up") == 0 &&
			    strcmp(ncfg_op_interface(op), "eth0") == 0) {
				const ncfg_action_t *master =
				    action_named(plan, "link.set_master");

				brought_up = master != NULL &&
				    depends_on(&plan->actions[i], master->id);
			}
		}
	}
	check(brought_up,
	    "a port with no interface block is brought up, and after its enslavement");
	release(plan, document, observed);
}

/* Every action's dependencies point at actions that come earlier in the list,
 * so an executor that ignores the edges entirely still behaves correctly. */
static void the_action_list_is_a_valid_topological_order(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"br0\",\"kind\":{\"kind\":\"bridge\",\"members\":"
	    "[\"eth0\",\"eth1\"],\"stp\":false}},"
	    "{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"},\"master\":\"br0\"},"
	    "{\"name\":\"eth1\",\"kind\":{\"kind\":\"physical\"},\"master\":\"br0\",\"mtu\":9000}],"
	    "\"interfaces\":[{\"name\":\"br0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"10.0.0.1/24\"}],"
	    "\"routes\":[{\"destination\":\"default\",\"via\":\"10.0.0.254\"}],"
	    "\"hooks\":[{\"phase\":\"post_up\",\"path\":\"/run/h\",\"sha256\":\"00\"}]},"
	    "{\"name\":\"eth1\"}]",
	    "\"links\":[" LINK("eth0") "," LINK("eth1") "]", NULL, &document, &observed);
	int ordered = 1;

	if (plan) {
		size_t i;
		size_t j;

		check(plan->action_count > 4u, "the fixture produces a plan worth ordering");
		for (i = 0; i < plan->action_count; i++) {
			for (j = 0; j < plan->actions[i].depends_count; j++) {
				if (plan->actions[i].depends_on[j] >= plan->actions[i].id) {
					printf("  action %u depends on %u, which is not "
					    "earlier\n", plan->actions[i].id,
					    plan->actions[i].depends_on[j]);
					ordered = 0;
				}
			}
		}
	} else {
		check(0, "the fixture produces a plan worth ordering");
		ordered = 0;
	}
	check(ordered, "the action list is a valid topological order");
	release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * The ownership guard: nothing foreign is ever removed (decision 0002)
 * ------------------------------------------------------------------------ */

static void nothing_foreign_is_ever_removed(void)
{
	static const char *const body =
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"10.0.0.1/24\"}]}]";
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan;

	plan = plan_of("{}", body,
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"addresses\":[{\"interface\":\"eth0\",\"address\":\"192.168.99.1/24\","
	    "\"proto\":4,\"ownership\":\"foreign\",\"origin\":\"static\"}]",
	    NULL, &document, &observed);
	check(plan && !has_name(plan, "addr.del"), "a foreign address is never removed");
	release(plan, document, observed);

	/* An address whose ownership the kernel could not report is treated as
	 * foreign. On a pre-5.18 kernel that is most of them, and deleting on a
	 * guess is the one mistake that cannot be walked back. */
	plan = plan_of("{}", body,
	    "\"address_proto_supported\":false,\"links\":[" LINK_UP("eth0") "],"
	    "\"addresses\":[{\"interface\":\"eth0\",\"address\":\"192.168.99.1/24\","
	    "\"ownership\":\"unknown\",\"origin\":\"static\"}]",
	    NULL, &document, &observed);
	check(plan && !has_name(plan, "addr.del"),
	    "an address of unknown ownership is never removed");
	release(plan, document, observed);

	/* A route netcfgd did not install stays, and so does a link it did not
	 * create -- the same question asked of the other two objects a plan can
	 * take away. */
	plan = plan_of("{}", body,
	    "\"links\":[" LINK_UP("eth0") ",{\"name\":\"br9\",\"index\":3,\"mtu\":1500,"
	    "\"up\":true,\"carrier\":true,\"ownership\":\"foreign\",\"kind\":\"bridge\"}],"
	    "\"routes\":[{\"interface\":\"eth0\",\"destination\":\"10.9.0.0/16\","
	    "\"ownership\":\"foreign\",\"origin\":\"static\"}]",
	    NULL, &document, &observed);
	check(plan && !has_name(plan, "route.del") && !has_name(plan, "link.delete"),
	    "and neither a foreign route nor a foreign link");
	release(plan, document, observed);

	/* Ours, and no longer wanted, does come out -- and make-before-break: the
	 * new address is in place before the old one goes. On a machine being
	 * reconfigured over the network that ordering is the difference between a
	 * brief overlap and a lockout. */
	plan = plan_of("{}", body,
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"addresses\":[{\"interface\":\"eth0\",\"address\":\"10.0.0.99/24\","
	    "\"proto\":110,\"ownership\":\"ours\",\"origin\":\"static\"}]",
	    NULL, &document, &observed);
	check(plan && has_name(plan, "addr.del"),
	    "an address we installed and no longer want is removed");
	check(plan && position(plan, "addr.add") >= 0 &&
	    position(plan, "addr.add") < position(plan, "addr.del"),
	    "and the new one is in place before the old one goes");
	release(plan, document, observed);

	/* Decision 0006 rule 7: a lease's address belongs to the backend. Removing
	 * it here would fight the DHCP client for its own lease. */
	plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\",\"addressing\":[{\"source\":\"dhcp4\"}]}]",
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"addresses\":[{\"interface\":\"eth0\",\"address\":\"192.168.1.57/24\","
	    "\"proto\":110,\"ownership\":\"ours\",\"origin\":\"dhcp4\"}]",
	    NULL, &document, &observed);
	check(plan && !has_name(plan, "addr.del"),
	    "a lease's address is left to its backend (rule 7)");
	/* And the client that holds the lease is started, rather than the plan
	 * saying nothing about a config that asked for one. This was a warning
	 * while the backend half of the planner was missing. */
	check(plan && has_name(plan, "backend.start"),
	    "and the client that serves it is started");
	release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * The disruption guards (decision 0010)
 * ------------------------------------------------------------------------ */

static void a_guard_refuses_a_disruptive_action_at_plan_time(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan;

	/* The config no longer wants the address, so teardown would remove it --
	 * which is exactly what breaks an NFS mount on that interface. */
	plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"10.0.0.1/24\"}],"
	    "\"guard\":{\"reason\":\"nfs root\"}}]",
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"addresses\":[{\"interface\":\"eth0\",\"address\":\"10.0.0.99/24\","
	    "\"proto\":110,\"ownership\":\"ours\",\"origin\":\"static\"}]",
	    NULL, &document, &observed);
	check(plan && !has_name(plan, "addr.del"),
	    "a guarded interface is not disrupted at plan time");
	check(plan && plan->refusal_count == 1u &&
	    strcmp(plan->refusals[0].op, "addr.del") == 0 &&
	    strcmp(plan->refusals[0].guard, "nfs root") == 0 &&
	    strcmp(plan->refusals[0].override_with,
	        "ncfg apply --allow-disruption eth0") == 0,
	    "and the refusal names the op, the guard and the way to consent");
	check(plan && ncfg_plan_was_refused(plan), "and the plan says a guard stopped it");
	release(plan, document, observed);

	/* The guard blocks only what can interrupt traffic. Adding an address to a
	 * guarded interface is safe and still happens, or a guard would freeze the
	 * interface entirely. */
	plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\",\"addressing\":["
	    "{\"source\":\"static\",\"address\":\"10.0.0.1/24\"},"
	    "{\"source\":\"static\",\"address\":\"10.0.0.2/24\"}],"
	    "\"guard\":{\"reason\":\"nfs root\"}}]",
	    "\"links\":[" LINK_UP("eth0") "]", NULL, &document, &observed);
	if (plan) {
		char names[512];

		names_of(plan, names, sizeof(names));
		check(strcmp(names, "addr.add,addr.add") == 0 && plan->refusal_count == 0u,
		    "additive work survives a guard");
	} else {
		check(0, "additive work survives a guard");
	}
	release(plan, document, observed);
}

/* Consent is per interface, and it unblocks exactly that one. */
static void consent_unblocks_the_named_interface_and_no_other(void)
{
	static const char *const consented[] = { "eth0" };
	ncfg_plan_options_t options;
	ncfg_document_t    *document;
	ncfg_observed_t    *observed;
	ncfg_plan_t        *plan;
	int                 correct = 0;

	memset(&options, 0, sizeof(options));
	options.allow_disruption = consented;
	options.allow_disruption_count = 1u;

	plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}},"
	    "{\"name\":\"eth1\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"10.0.0.1/24\"}],"
	    "\"guard\":{\"reason\":\"nfs root\"}},"
	    "{\"name\":\"eth1\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"10.0.1.1/24\"}],"
	    "\"guard\":{\"reason\":\"database replication\"}}]",
	    "\"links\":[" LINK_UP("eth0") ","
	    "{\"name\":\"eth1\",\"index\":3,\"mtu\":1500,\"up\":true,\"carrier\":true,"
	    "\"ownership\":\"unknown\"}],"
	    "\"addresses\":[{\"interface\":\"eth0\",\"address\":\"10.0.0.99/24\","
	    "\"proto\":110,\"ownership\":\"ours\",\"origin\":\"static\"},"
	    "{\"interface\":\"eth1\",\"address\":\"10.0.1.99/24\","
	    "\"proto\":110,\"ownership\":\"ours\",\"origin\":\"static\"}]",
	    &options, &document, &observed);
	if (plan) {
		size_t i;
		size_t removed = 0;

		correct = 1;
		for (i = 0; i < plan->action_count; i++) {
			if (strcmp(ncfg_op_name(&plan->actions[i].op), "addr.del") != 0) {
				continue;
			}
			removed++;
			if (strcmp(ncfg_op_interface(&plan->actions[i].op), "eth0") != 0) {
				correct = 0;
			}
		}
		if (removed != 1u || plan->refusal_count != 1u ||
		    strcmp(plan->refusals[0].interface, "eth1") != 0) {
			correct = 0;
		}
	}
	check(correct, "consent unblocks the named interface and no other");
	release(plan, document, observed);
}

/* The case that motivated the guard: an interface dropped from the config is
 * not torn down while something depends on it. */
static void a_guarded_interface_is_not_torn_down_when_it_leaves_the_config(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	/* The bridge netcfgd created is gone from the device list, so teardown
	 * would delete it -- and the interface block that remains guards it. */
	ncfg_plan_t     *plan = plan_of("{}",
	    "\"devices\":[],\"interfaces\":[{\"name\":\"br0\","
	    "\"guard\":{\"reason\":\"the office runs on this\"}}]",
	    "\"links\":[{\"name\":\"br0\",\"index\":3,\"mtu\":1500,\"up\":true,"
	    "\"carrier\":true,\"kind\":\"bridge\",\"ownership\":\"ours\"}]",
	    NULL, &document, &observed);

	check(plan && !has_name(plan, "link.delete"),
	    "a guarded interface is not torn down when it leaves the config");
	check(plan && plan->refusal_count == 1u &&
	    strcmp(plan->refusals[0].op, "link.delete") == 0,
	    "and the refusal says what did not happen");
	release(plan, document, observed);
}

/*
 * `managed = false` means netcfgd never touches the device.
 *
 * The escape hatch documented for handing an interface to another daemon
 * planned three actions against it until the check moved into the one place
 * every action goes through.
 */
static void an_unmanaged_device_is_not_touched(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"},"
	    "\"managed\":false,\"mtu\":9000}],"
	    "\"interfaces\":[{\"name\":\"eth0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"10.0.0.1/24\"}]}]",
	    "\"links\":[" LINK("eth0") "]", NULL, &document, &observed);

	check(plan && ncfg_plan_is_empty(plan), "an unmanaged device is not touched");
	check(plan && warned_about(plan, "managed = false"),
	    "and one warning naming the device says why, rather than three naming actions");
	release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * Hooks, the confirm window, and the sentence a plan owes
 * ------------------------------------------------------------------------ */

/*
 * Rule 6: `pre_up` runs before `link.up`, `post_up` after the addressing.
 *
 * Both hooks used to be emitted unconditionally, and a converged interface ran
 * its `pre_up` and `post_up` on every apply -- so the second plan was never
 * empty, against the promise that an already-correct state runs zero hooks.
 * Decision 0063.
 */
static void hooks_bracket_the_interface_lifecycle(void)
{
	static const char *const body =
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"10.0.0.1/24\"}],"
	    "\"hooks\":[{\"phase\":\"pre_up\",\"path\":\"/run/pre\",\"sha256\":\"00\"},"
	    "{\"phase\":\"post_up\",\"path\":\"/run/post\",\"sha256\":\"11\"}]}]";
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}", body, "\"links\":[" LINK("eth0") "]", NULL,
	    &document, &observed);
	char names[512];

	if (plan) {
		const ncfg_action_t *address = action_named(plan, "addr.add");

		names_of(plan, names, sizeof(names));
		if (strcmp(names, "hook.run,link.up,addr.add,hook.run") != 0) {
			printf("  the plan is: %s\n", names);
		}
		check(strcmp(names, "hook.run,link.up,addr.add,hook.run") == 0,
		    "hooks bracket the interface lifecycle");
		check(address &&
		    depends_on(&plan->actions[plan->action_count - 1u], address->id),
		    "and post_up waits for the last addressing action");
		/* A hook is arbitrary shell, so netcfgd cannot undo it -- and a
		 * commit-confirm window that silently could not revert one action is
		 * worse than none. */
		check(warned_about(plan, "cannot be undone"),
		    "a hook is irreversible, and the plan says so");
	} else {
		check(0, "hooks bracket the interface lifecycle");
		check(0, "and post_up waits for the last addressing action");
		check(0, "a hook is irreversible, and the plan says so");
	}
	release(plan, document, observed);

	/* And a converged interface runs none of them. */
	plan = plan_of("{}", body,
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"addresses\":[{\"interface\":\"eth0\",\"address\":\"10.0.0.1/24\","
	    "\"proto\":110,\"ownership\":\"ours\",\"origin\":\"static\"}]",
	    NULL, &document, &observed);
	check(plan && ncfg_plan_is_empty(plan),
	    "an already-correct interface runs zero hooks (0063)");
	release(plan, document, observed);
}

/*
 * Rule 8: the confirm window is armed first, and its revert is computed now
 * rather than after a failure, when the network may already be unreachable.
 *
 * `confirm = 0` is the case 0094 records: the guard covered only the caller's
 * option, so a document saying zero armed a window of zero seconds -- which
 * arms and expires, the one state that cannot be meant.
 */
static void the_confirm_window_is_armed_first(void)
{
	static const char *const body =
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"10.0.0.1/24\"}]}]";
	ncfg_plan_options_t options;
	ncfg_document_t    *document;
	ncfg_observed_t    *observed;
	ncfg_plan_t        *plan;

	memset(&options, 0, sizeof(options));
	options.confirm_window.has = 1;
	options.confirm_window.value = 90;
	options.revert_to = "abc";
	plan = plan_of("{}", body, "\"links\":[" LINK_UP("eth0") "]", &options, &document,
	    &observed);
	check(plan && plan->action_count > 0u &&
	    plan->actions[0].op.kind == NCFG_OP_COMMIT_ARM &&
	    plan->actions[0].op.u.commit_arm.window_seconds == 90 &&
	    plan->actions[0].has_inverse &&
	    plan->actions[0].inverse.kind == NCFG_OP_COMMIT_REVERT,
	    "commit.arm comes first and carries its revert");
	release(plan, document, observed);

	plan = plan_of("{\"confirm_default\":90}", body, "\"links\":[" LINK_UP("eth0") "]", NULL,
	    &document, &observed);
	check(plan && plan->action_count > 0u &&
	    plan->actions[0].op.kind == NCFG_OP_COMMIT_ARM,
	    "a document's own confirm_default arms a window (0094)");
	release(plan, document, observed);

	plan = plan_of("{\"confirm_default\":0}", body, "\"links\":[" LINK_UP("eth0") "]", NULL,
	    &document, &observed);
	check(plan && !has_name(plan, "commit.arm"),
	    "and `confirm = 0` in the document means no window, not a window of none");
	release(plan, document, observed);

	memset(&options, 0, sizeof(options));
	options.confirm_window.has = 1;
	options.confirm_window.value = 0;
	plan = plan_of("{\"confirm_default\":90}", body, "\"links\":[" LINK_UP("eth0") "]",
	    &options, &document, &observed);
	check(plan && !has_name(plan, "commit.arm"),
	    "and a caller passing zero overrides a machine that set one");
	release(plan, document, observed);
}

/*
 * A physical device that is not present is not something a plan can fix.
 *
 * Say so rather than emitting actions that must fail on every reconcile.
 */
static void a_missing_physical_device_is_reported_not_planned_around(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"eth9\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth9\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"10.0.0.1/24\"}]}]",
	    "\"links\":[]", NULL, &document, &observed);

	check(plan && ncfg_plan_is_empty(plan) && warned_about(plan, "no such device"),
	    "a missing physical device is reported, not planned around");
	release(plan, document, observed);
}

/*
 * A veth whose peer's name is taken cannot be created, and saying so is the
 * whole fix.
 *
 * The kernel answers EEXIST and names the device being created rather than the
 * one in the way, so an operator reads "could not create w0: File exists" about
 * a `w0` that does not exist -- and the same action is planned again on every
 * reconcile, because nothing about the failure changes the state it was
 * computed from.
 */
static void a_veth_whose_peer_is_taken_is_declined_with_a_sentence(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"w0\",\"kind\":{\"kind\":\"veth\",\"peer\":\"w1\"}}],"
	    "\"interfaces\":[{\"name\":\"w0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"10.0.0.1/24\"}]}]",
	    "\"links\":[" LINK("w1") "]", NULL, &document, &observed);

	check(plan && !has_name(plan, "link.create") && ncfg_plan_is_empty(plan),
	    "a veth whose peer's name is taken is declined rather than attempted");
	check(plan && warned_about(plan, "the kernel refuses both ends at once"),
	    "and the sentence names the device holding the name");
	release(plan, document, observed);
}

/*
 * A link that is created is created before anything references it (rule 1).
 */
static void everything_on_a_created_link_waits_for_its_creation(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"d0\",\"kind\":{\"kind\":\"dummy\"}}],"
	    "\"interfaces\":[{\"name\":\"d0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"10.0.0.1/24\"}]}]",
	    "\"links\":[]", NULL, &document, &observed);
	int waits = 0;

	if (plan) {
		const ncfg_action_t *create = action_named(plan, "link.create");

		waits = create != NULL && create->id == 0u;
		if (waits) {
			size_t i;

			for (i = 1; i < plan->action_count; i++) {
				if (!depends_on(&plan->actions[i], create->id)) {
					printf("  %s does not wait for the creation\n",
					    ncfg_op_name(&plan->actions[i].op));
					waits = 0;
				}
			}
		}
	}
	check(waits, "everything on a created link waits for its creation");
	release(plan, document, observed);
}

/*
 * A disabled interface goes down in the order the phases describe.
 *
 * The middle step -- the addresses removed explicitly -- is what makes
 * `pre_down` and `down` different moments rather than the same one. It is also
 * a fix in its own right: `link.down` flushes IPv6 and leaves IPv4 behind,
 * measured on a real kernel, so a disabled interface kept a stale address that
 * netcfgd still recorded as its own.
 */
static void a_disabled_interface_goes_down_in_order(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\",\"enabled\":false,"
	    "\"hooks\":[{\"phase\":\"pre_down\",\"path\":\"/run/pre\",\"sha256\":\"00\"},"
	    "{\"phase\":\"post_down\",\"path\":\"/run/post\",\"sha256\":\"11\"}]}]",
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"addresses\":[{\"interface\":\"eth0\",\"address\":\"10.0.0.1/24\","
	    "\"ownership\":\"ours\"}]",
	    NULL, &document, &observed);
	char names[512];

	if (plan) {
		names_of(plan, names, sizeof(names));
		if (strcmp(names, "hook.run,addr.del,link.down,hook.run") != 0) {
			printf("  the plan is: %s\n", names);
		}
		check(strcmp(names, "hook.run,addr.del,link.down,hook.run") == 0,
		    "a disabled interface goes down in the order the phases describe");
	} else {
		check(0, "a disabled interface goes down in the order the phases describe");
	}
	release(plan, document, observed);

	/*
	 * **And the same address tagged as config's is withdrawn twice**, which is
	 * pinned here rather than left to be rediscovered.
	 *
	 * The teardown pass decides independently that an address on an interface
	 * with no matching static source is unwanted, and it does not know that
	 * the disable pass has already said so. The Rust behaves identically -- its
	 * own fixture for this happens to leave `origin` unset, which is the one
	 * value that makes the teardown pass skip the address -- so this is
	 * faithful rather than a port defect. Both actions are idempotent and the
	 * plan still converges; what is wrong is the plan describing one removal
	 * as two.
	 */
	plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\",\"enabled\":false}]",
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"addresses\":[{\"interface\":\"eth0\",\"address\":\"10.0.0.1/24\","
	    "\"proto\":110,\"ownership\":\"ours\",\"origin\":\"static\"}]",
	    NULL, &document, &observed);
	if (plan) {
		size_t i;
		size_t removals = 0;

		for (i = 0; i < plan->action_count; i++) {
			if (strcmp(ncfg_op_name(&plan->actions[i].op), "addr.del") == 0) {
				removals++;
			}
		}
		check(removals == 2u,
		    "a config address on a disabled interface is withdrawn twice, as in "
		    "the Rust");
	} else {
		check(0, "a config address on a disabled interface is withdrawn twice, as in "
		    "the Rust");
	}
	release(plan, document, observed);
}

/*
 * The port's own rule: nothing the document asks for is passed over in
 * silence.
 *
 * This build plans four of the Rust's thirty passes, and a plan that omitted
 * the rest without saying so would report "nothing to do" about a config that
 * asked for several things -- the exact failure this module's contract
 * forbids.
 */
static void nothing_the_document_asks_for_is_passed_over_in_silence(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"},"
	    "\"qdisc\":{\"kind\":\"cake\",\"bandwidth_bits\":100}}],"
	    "\"interfaces\":[{\"name\":\"eth0\",\"addressing\":["
	    "{\"source\":\"static\",\"address\":\"10.0.0.1/24\"},"
	    "{\"source\":\"slaac\"},{\"source\":\"link_local\"},{\"source\":\"dhcp4\"}],"
	    "\"dns\":{\"mode\":\"resolvconf\"},\"forwarding\":true}],"
	    "\"rules\":[{\"id\":\"r\",\"priority\":100}]",
	    "\"links\":[" LINK_UP("eth0") "]", NULL, &document, &observed);

	/*
	 * These two were "a qdisc block is named" and "a rule block is named"
	 * until the passes landed, and the arms came out of `warn_unported` in the
	 * same change -- a warning that outlives the gap it describes is the other
	 * way this goes wrong. Turned round rather than deleted, so a pass that
	 * disappears again is caught here as well as in `plan_tc_test.c`.
	 */
	check(plan && !warned_about(plan, "a `qdisc` block") && has_name(plan, "qdisc.set"),
	    "a qdisc block is acted on rather than named");
	check(plan && !warned_about(plan, "a `rule` block") && has_name(plan, "rule.add"),
	    "a rule block is acted on rather than named");
	/* The product's gap rather than the port's -- and the sentence now says
	 * that instead of contradicting it. It used to be the Rust's own, which
	 * promises "not yet applied by **this build**"; `plan_gaps_test.c` carries
	 * the case that checks the whole of the replacement. */
	check(plan && warned_about(plan, "nothing acts on it in the Rust either"),
	    "and link-local is marked as nobody's gap rather than as this port's");
	release(plan, document, observed);
}

/* The address arithmetic ordering rule 4 needs, and nothing more. */
static void the_subnet_arithmetic(void)
{
	check(ncfg_plan_subnet_contains("192.168.1.10/24", "192.168.1.1") &&
	    !ncfg_plan_subnet_contains("192.168.1.10/24", "192.168.2.1"),
	    "a gateway inside the subnet is covered and one outside is not");
	check(ncfg_plan_subnet_contains("10.0.0.1/12", "10.15.255.254") &&
	    !ncfg_plan_subnet_contains("10.0.0.1/12", "10.16.0.1"),
	    "a prefix that is not a whole number of bytes still works");
	check(ncfg_plan_subnet_contains("0.0.0.0/0", "8.8.8.8"),
	    "a zero-length prefix covers everything without overflowing");
	check(!ncfg_plan_subnet_contains("192.168.1.10/24", "fe80::1"),
	    "families do not cover each other");
	check(ncfg_plan_subnet_contains("2001:db8::1/64", "2001:db8::ffff") &&
	    !ncfg_plan_subnet_contains("2001:db8::1/64", "2001:db9::1"),
	    "and IPv6 prefixes work too");
	check(!ncfg_plan_subnet_contains("192.168.1.1", "192.168.1.2") &&
	    !ncfg_plan_subnet_contains("not/an/address", "192.168.1.2"),
	    "nonsense is rejected rather than guessed at");
}

/*
 * An absent optional member is written as `null`, not omitted.
 *
 * Exactly three members in this surface are omitted when absent, and an
 * `addr.add` with no lifetimes is not one of them. A writer that tidied that
 * away would produce a line the Rust cannot read back into the same value.
 */
static void an_absent_optional_member_is_written_as_null(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"10.0.0.1/24\"}]}]",
	    "\"links\":[" LINK_UP("eth0") "]", NULL, &document, &observed);
	size_t           length = 0;
	char            *text = plan ? written(plan, &length) : NULL;

	check(text && strstr(text, "\"preferred_lifetime\":null") != NULL &&
	    strstr(text, "\"valid_lifetime\":null") != NULL,
	    "an absent lifetime is written as null rather than omitted");
	free(text);
	release(plan, document, observed);
}

/*
 * A warning too long to print says it was cut.
 *
 * **`vsnprintf` truncates in silence and no test can see it.** A warning
 * written past `NCFG_ERROR_MAX` reaches an operator stopped at 511 characters
 * -- one reached one as "...still means t" -- and every check on it passed,
 * because each fragment asserted sat before the cut. The sabotage that should
 * have reddened those checks reddened none, which is how it was found.
 *
 * So this asserts the *end* of the sentence, which is the only place the
 * failure shows. A check on the beginning of a truncated warning is a check
 * that cannot fail.
 */
static void a_warning_too_long_to_print_says_it_was_cut(void)
{
	char         err[NCFG_ERROR_MAX];
	char         big[900];
	ncfg_plan_t *plan = ncfg_plan_new(err, sizeof(err));
	static const char marker[] = " [cut: this warning is longer than netcfgd prints]";
	size_t       at;

	for (at = 0; at < sizeof(big) - 1u; at++) {
		big[at] = 'x';
	}
	big[sizeof(big) - 1u] = '\0';
	if (!plan) {
		check(0, "a plan to warn on");
		return;
	}
	ncfg_plan_warnf(plan, "eth0", "%s", big);
	check(plan->warning_count == 1u, "an over-long warning is still kept");
	if (plan->warning_count == 1u) {
		const char *said = plan->warnings[0].message;
		size_t      length = strlen(said);

		check(length == NCFG_ERROR_MAX - 1u, "and is as long as netcfgd prints");
		/* **At the end, not merely present.** A marker anywhere in the
		 * sentence would be satisfied by one the caller happened to write;
		 * the property is that the *last* thing an operator reads says the
		 * rest is missing. Asserted by address from the end, which is the
		 * only place a truncation shows. */
		check(length > sizeof(marker) &&
		    strcmp(said + length - (sizeof(marker) - 1u), marker) == 0,
		    "and its last words say it was cut rather than stopping mid-word");
	}
	ncfg_plan_free(plan);
}

int main(void)
{
	the_frozen_witness();
	a_warning_too_long_to_print_says_it_was_cut();
	the_op_vocabulary();
	what_counts_as_disruptive();
	the_model_values_a_plan_embeds();

	a_static_interface_is_brought_up_in_order();
	an_already_correct_system_produces_no_actions();
	a_route_waits_only_for_the_address_that_covers_its_gateway();
	an_address_does_not_wait_for_the_link_and_a_route_does();
	a_bridge_waits_for_its_members_even_though_it_sorts_first();
	a_port_with_no_interface_block_is_brought_up();
	the_action_list_is_a_valid_topological_order();
	everything_on_a_created_link_waits_for_its_creation();

	nothing_foreign_is_ever_removed();
	a_guard_refuses_a_disruptive_action_at_plan_time();
	consent_unblocks_the_named_interface_and_no_other();
	a_guarded_interface_is_not_torn_down_when_it_leaves_the_config();
	an_unmanaged_device_is_not_touched();

	hooks_bracket_the_interface_lifecycle();
	a_disabled_interface_goes_down_in_order();
	the_confirm_window_is_armed_first();
	a_missing_physical_device_is_reported_not_planned_around();
	a_veth_whose_peer_is_taken_is_declined_with_a_sentence();
	nothing_the_document_asks_for_is_passed_over_in_silence();
	the_subnet_arithmetic();
	an_absent_optional_member_is_written_as_null();

	printf("\nplan: %d checks, %d failed\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
