/*
 * service_test.c -- the fourteen ops that change a machine away from netlink.
 *
 * WHAT IT MAY NOT TOUCH, AND HOW THAT IS ENFORCED
 *   This is the developer's own workstation. Its network is live, its
 *   `/etc/resolv.conf` is in use, its hostname is its own and its
 *   `wpa_supplicant` is running. **Not one op below is aimed at any of them.**
 *   Every path this file hands over is under one `mkdtemp` directory: the
 *   `/proc` these four sysctls write is a tree of ordinary files this test
 *   made, the control sockets are ones a forked fake bound, the resolver's
 *   three targets are files in the same directory, and every program a backend
 *   would run is one the test wrote.
 *
 *   The protection is the module's rather than this file's discipline, which
 *   is the point: **there is no default anywhere in `service.h`**, so a check
 *   that forgot a path gets a refusal naming it rather than the machine's own.
 *   Two checks below assert exactly that, by handing NULL and reading the
 *   sentence.
 *
 *   `ncfg_service_machine` is the one place the real paths appear, and it is
 *   asserted by *reading* it -- the constants are compared against the ones
 *   the modules that read the same files publish. Nothing is written through
 *   it.
 *
 * THE FAKE IS A RADIO AND AN ACCESS POINT, NOT A PROTOCOL
 *   `tests/live/fake_supplicant.py` and `fake_hostapd.py` are the shape this
 *   copies and their first paragraphs are the rule: the one thing this
 *   repository cannot produce on demand is a radio, so the hardware is faked
 *   and **the wire format is the real one**. The access control lists in
 *   particular are real state rather than a command that answers OK, which is
 *   `fake_hostapd.py`'s own sentence and is the whole reason the idempotence
 *   checks below can fail: *"a fake that answered OK to everything would let a
 *   converger pass while sending the same command forever."*
 *
 *   `hostapd_add_acl_maclist` refuses a duplicate, so this fake answers FAIL to
 *   `ADD_MAC` for an address already on the list. `fake_hostapd.py` answers OK
 *   there and says hostapd's are idempotent; hostapd 2.10's source says
 *   otherwise, and the executor is written for the source.
 *
 * THE CHILD, AND HOW IT CANNOT OUTLIVE THIS
 *   `supplicant_client_test.c`'s arrangement, unchanged and for its reasons:
 *   the fake puts itself in its own process group, sets an `alarm`, and wakes
 *   from `recvfrom` once a second to ask whether its parent is still there.
 *   It is stopped by **the recorded pid** and its group, never by name or
 *   pattern.
 */
#include "ncfg/apply.h"
#include "ncfg/base.h"
#include "ncfg/dns.h"
#include "ncfg/document.h"
#include "ncfg/hostapd.h"
#include "ncfg/observe.h"
#include "ncfg/observed.h"
#include "ncfg/plan.h"
#include "ncfg/process.h"
#include "ncfg/secrets.h"
#include "ncfg/service.h"
#include "ncfg/state.h"
#include "ncfg/supplicant.h"
#include "ncfg/value.h"

#include "hostapdfake.h"
#include "testdir.h"

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-76s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* A refusal has to name the thing it is about, or an operator cannot act on
 * it. Every failing check below goes through this rather than asserting only
 * that something returned 0. */
static void refused(int outcome, const char *message, const char *naming, const char *what)
{
	int named = message && naming && strstr(message, naming) != NULL;

	if (outcome != 0) {
		printf("%-76s %s\n", what, "FAILED (it succeeded)");
		failures++;
		return;
	}
	if (!named) {
		printf("%-76s FAILED (said `%s`)\n", what, message ? message : "");
		failures++;
		return;
	}
	printf("%-76s %s\n", what, "ok");
}

/* A writable copy of a literal, from a fixed arena: the document's fields are
 * `char *`, and these run under ASan where a fixture nobody frees is a
 * failure. */
static char   arena[8u * 1024u];
static size_t arena_used;

static char *text(const char *value)
{
	size_t length = strlen(value) + 1u;
	char  *out;

	if (arena_used + length > sizeof(arena)) {
		printf("the fixture arena is full\n");
		exit(1);
	}
	out = arena + arena_used;
	memcpy(out, value, length);
	arena_used += length;
	return out;
}

static const char *base;

static const char *under(const char *leaf, char *out, size_t out_size)
{
	(void)snprintf(out, out_size, "%s/%s", base, leaf);
	return out;
}

/*
 * Take the whole fixture tree away again.
 *
 * `testdir_remove` unwinds three levels and the `/proc` this test builds is
 * five (`proc/sys/net/ipv4/conf/eth0/forwarding`), so without this every run
 * left a directory behind -- measured, and found by counting them rather than
 * by anything going red, which is exactly the kind of litter
 * `~/.claude/guidelines/running-code.md` is about.
 *
 * The recursion is by pattern and is allowed to be, for `testdir.h`'s own
 * reason: **the directory is one this process created** with `mkdtemp`, the
 * path is checked against the recorded one before anything starts, and the
 * depth is bounded so a symlink loop cannot turn this into a walk of the
 * machine. `lstat` rather than `stat`, so a link is removed as a link and
 * never followed.
 */
static void remove_under(const char *path, int depth)
{
	DIR                 *open_dir;
	const struct dirent *found;

	if (depth > 8 || !path || strncmp(path, base, strlen(base)) != 0) {
		return;
	}
	open_dir = opendir(path);
	if (!open_dir) {
		return;
	}
	while ((found = readdir(open_dir)) != NULL) {
		char        child[1024];
		struct stat about;

		if (strcmp(found->d_name, ".") == 0 || strcmp(found->d_name, "..") == 0) {
			continue;
		}
		(void)snprintf(child, sizeof(child), "%s/%s", path, found->d_name);
		if (lstat(child, &about) != 0) {
			continue;
		}
		if (S_ISDIR(about.st_mode)) {
			remove_under(child, depth + 1);
			(void)rmdir(child);
			continue;
		}
		(void)unlink(child);
	}
	(void)closedir(open_dir);
}

/* `mkdir -p`, for the fixture trees. The paths are all under `base`. */
/* `testdir.h`'s, now that world_test builds the same shape of tree. Kept as a
 * name here so the fixtures below read as they did. */
static void make_tree(const char *path)
{
	testdir_mkdirp(path);
}

/* ------------------------------------------------------------------------ *
 * The fake control socket
 * ------------------------------------------------------------------------ *
 *
 * `hostapdfake.h`'s, now that the observer needs the same stand-in for the
 * round trip that reads those lists back. Two fakes of one daemon is two
 * beliefs about its protocol, and what would drift is the thing both sides of
 * netcfgd are written against.
 */
/* ------------------------------------------------------------------------ *
 * Ops, built by hand
 * ------------------------------------------------------------------------ */

static ncfg_op_t backend_op(int kind, int backend, const char *iface)
{
	ncfg_op_t op;

	memset(&op, 0, sizeof(op));
	op.kind = kind;
	op.u.backend.kind = backend;
	op.u.backend.iface = iface;
	return op;
}

/* ------------------------------------------------------------------------ *
 * What this build says it can carry out
 * ------------------------------------------------------------------------ */

static void the_fourteen_are_supported(void)
{
	static const int simple[] = {
		NCFG_OP_WIFI_SET_PROFILES, NCFG_OP_WIFI_ASSOCIATE, NCFG_OP_WIFI_DISASSOCIATE,
		NCFG_OP_WIFI_SET_REGDOM, NCFG_OP_ACCESS_CONTROL_ADD, NCFG_OP_ACCESS_CONTROL_DEL,
		NCFG_OP_DNS_APPLY, NCFG_OP_SYSCTL_SET_FORWARDING, NCFG_OP_SYSCTL_SET_PRIVACY,
		NCFG_OP_SYSCTL_SET_ACCEPT_RA, NCFG_OP_HOSTNAME_SET
	};
	static const int carried[] = {
		NCFG_BACKEND_ACCESS_POINT, NCFG_BACKEND_ROUTER_ADVERT, NCFG_BACKEND_OPENVPN,
		NCFG_BACKEND_DHCP4,
		/* The launcher landed, so a supplicant answers both verbs. The whole
		 * of it is `supplicant_launch_test.c`; what belongs here is that the
		 * single list of what this build carries out now says so. */
		NCFG_BACKEND_SUPPLICANT,
		/* And the session, whose `pppd` is `pppoe_test.c`'s: the list here
		 * moves in the same commit as the module, which is `build.c`'s rule
		 * for a warning applied to a list of what is carried. */
		NCFG_BACKEND_PPPOE
	};
	/*
	 * **What is left refused is refused for a reason that is not a missing
	 * port**, which is the whole of what changed when the session landed.
	 * WireGuard is a kernel device rather than a daemon -- `link.create` makes
	 * it and `wg.set_device` configures it -- and DNS is delivered by
	 * `dns.apply` rather than started, the resolver being somebody else's
	 * daemon. Neither has anything to start in either implementation.
	 */
	static const int refused_kinds[] = { NCFG_BACKEND_WIREGUARD, NCFG_BACKEND_DNS };
	char   message[NCFG_ERROR_MAX];
	size_t i;
	int    all = 1;

	for (i = 0; i < sizeof(simple) / sizeof(simple[0]); i++) {
		ncfg_op_t op;

		memset(&op, 0, sizeof(op));
		op.kind = simple[i];
		message[0] = '\0';
		if (!ncfg_apply_supported(&op, message, sizeof(message))) {
			printf("  %s is still refused: %s\n", ncfg_op_name(&op), message);
			all = 0;
		}
	}
	check(all, "the eleven ops with no kind of their own are carried out by this build");

	all = 1;
	for (i = 0; i < sizeof(carried) / sizeof(carried[0]); i++) {
		ncfg_op_t start = backend_op(NCFG_OP_BACKEND_START, carried[i], "wlan0");
		ncfg_op_t stop = backend_op(NCFG_OP_BACKEND_STOP, carried[i], "wlan0");

		message[0] = '\0';
		if (!ncfg_apply_supported(&start, message, sizeof(message)) ||
		    !ncfg_apply_supported(&stop, message, sizeof(message))) {
			printf("  %s is still refused: %s\n", ncfg_backend_kind_name(carried[i]),
			    message);
			all = 0;
		}
	}
	check(all,
	    "an access point, a radvd, an openvpn, a DHCPv4 client, a supplicant and a "
	    "pppoe session are carried out");

	/*
	 * **The DHCPv6 half answers differently for the two verbs, and that is the
	 * decision rather than an oversight.** Which v6 client can serve a
	 * document turns on whether it asked for a delegated prefix -- odhcp6c can
	 * report one and dhcpcd measurably cannot (0050) -- and a plain
	 * `backend.start` carries neither the request nor an odhcp6c. Stopping is
	 * a different question and is answerable: `dhcpcd -6 -k` and an odhcp6c's
	 * recorded pid are both this build's.
	 */
	{
		ncfg_op_t start = backend_op(NCFG_OP_BACKEND_START, NCFG_BACKEND_DHCP6, "eth0");
		ncfg_op_t stop = backend_op(NCFG_OP_BACKEND_STOP, NCFG_BACKEND_DHCP6, "eth0");

		message[0] = '\0';
		refused(ncfg_apply_supported(&start, message, sizeof(message)), message,
		    "delegated prefix",
		    "starting a DHCPv6 client is refused, naming what the op does not carry");
		message[0] = '\0';
		check(ncfg_apply_supported(&stop, message, sizeof(message)),
		    "and stopping one is carried out, which is a question this build can answer");
	}

	for (i = 0; i < sizeof(refused_kinds) / sizeof(refused_kinds[0]); i++) {
		ncfg_op_t op = backend_op(NCFG_OP_BACKEND_START, refused_kinds[i], "eth0");
		char      what[128];

		message[0] = '\0';
		(void)snprintf(what, sizeof(what), "starting a %s backend is refused by name",
		    ncfg_backend_kind_name(refused_kinds[i]));
		refused(ncfg_apply_supported(&op, message, sizeof(message)), message,
		    "backend.start", what);
	}

	{
		ncfg_op_t reload = backend_op(NCFG_OP_BACKEND_RELOAD, NCFG_BACKEND_ACCESS_POINT,
		    "wlan0");
		ncfg_op_t radvd = backend_op(NCFG_OP_BACKEND_RELOAD, NCFG_BACKEND_ROUTER_ADVERT,
		    "lan0");

		message[0] = '\0';
		refused(ncfg_apply_supported(&reload, message, sizeof(message)), message,
		    "no reload", "an access point has no reload, and the refusal says why");
		message[0] = '\0';
		check(ncfg_apply_supported(&radvd, message, sizeof(message)),
		    "a router advertisement daemon does have one");
	}
}

static void an_executor_with_no_context_refuses_by_name(void)
{
	ncfg_op_t op;
	char      message[NCFG_ERROR_MAX];

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_HOSTNAME_SET;
	op.u.named.name = "router";
	message[0] = '\0';
	refused(ncfg_service_execute(NULL, &op, message, sizeof(message)), message,
	    "service context", "an executor with no service context refuses and says so");

	op.kind = NCFG_OP_LINK_UP;
	op.u.named.name = "eth0";
	message[0] = '\0';
	refused(ncfg_service_execute(&(ncfg_service_t){ 0 }, &op, message, sizeof(message)),
	    message, "link.up", "an op that is not this module's is refused by name");
}

static void the_machines_paths_are_one_place(void)
{
	ncfg_service_t where;

	memset(&where, 0, sizeof(where));
	ncfg_service_machine(&where);
	check(strcmp(where.run_dir, NCFG_RUN_DIR_DEFAULT) == 0,
	    "the run directory is state.h's, rather than a second spelling of it");
	check(strcmp(where.proc_root, NCFG_OBSERVE_PROC_ROOT_DEFAULT) == 0,
	    "the /proc these write is the /proc the observation reads");
	check(strcmp(where.supplicant_dir, NCFG_SUPPLICANT_CTRL_DIR) == 0,
	    "the control directory is supplicant.h's");
	check(strcmp(where.dns.resolv_conf, NCFG_RESOLV_CONF) == 0 &&
	    strcmp(where.dns.dnsmasq_conf, NCFG_DNSMASQ_CONF) == 0 &&
	    strcmp(where.dns.unbound_conf, NCFG_UNBOUND_CONF) == 0,
	    "and the resolver's three targets are dns.h's");
	/* And the DHCP client's, which `dhcp.h` owns: the hook netcfgd ships, the
	 * run directory that is dhcpcd's rather than netcfgd's, and the operator's
	 * configuration that `-f` points at. Asserted by reading the constants,
	 * because the alternative is letting something write there. */
	check(where.dhcp.hook != NULL &&
	    strcmp(where.dhcp.hook, NCFG_DHCP_HOOK_DEFAULT) == 0 &&
	    where.dhcp.dhcpcd_run_dir != NULL &&
	    strcmp(where.dhcp.dhcpcd_run_dir, NCFG_DHCPCD_RUN_DIR_DEFAULT) == 0 &&
	    where.dhcp.dhcpcd_config != NULL &&
	    strcmp(where.dhcp.dhcpcd_config, NCFG_DHCPCD_CONFIG_DEFAULT) == 0,
	    "the hook, dhcpcd's own run directory and the operator's config are dhcp.h's");
	check(where.dhcp.dhcpcd_program == NULL && where.dhcp.udhcpc_program == NULL &&
	    where.dhcp.busybox_program == NULL && where.dhcp.patience_ms == 0,
	    "  with the three clients left to be found, which is what a daemon means");
	check(where.document == NULL && where.secrets == NULL && where.hostapd_program == NULL,
	    "a document, a resolver and a program have no machine-wide answer and are left");
}

/* ------------------------------------------------------------------------ *
 * The four that write to /proc
 * ------------------------------------------------------------------------ */

static char proc_root[512];

static void a_proc_tree(void)
{
	char path[1024];

	(void)snprintf(proc_root, sizeof(proc_root), "%s/proc", base);
	(void)snprintf(path, sizeof(path), "%s/sys/net/ipv4/conf/eth0", proc_root);
	make_tree(path);
	(void)snprintf(path, sizeof(path), "%s/sys/net/ipv4/conf/eth0/forwarding", proc_root);
	(void)testdir_write(path, "0\n", 2u);
	(void)snprintf(path, sizeof(path), "%s/sys/net/ipv6/conf/eth0", proc_root);
	make_tree(path);
	(void)snprintf(path, sizeof(path), "%s/sys/net/ipv6/conf/eth0/forwarding", proc_root);
	(void)testdir_write(path, "0\n", 2u);
	(void)snprintf(path, sizeof(path), "%s/sys/net/ipv6/conf/eth0/use_tempaddr", proc_root);
	(void)testdir_write(path, "0\n", 2u);
	(void)snprintf(path, sizeof(path), "%s/sys/net/ipv6/conf/eth0/accept_ra", proc_root);
	(void)testdir_write(path, "1\n", 2u);
	(void)snprintf(path, sizeof(path), "%s/sys/kernel", proc_root);
	make_tree(path);
	(void)snprintf(path, sizeof(path), "%s/sys/kernel/hostname", proc_root);
	(void)testdir_write(path, "before\n", 7u);
}

static char *value_at(const char *tail)
{
	char path[1024];

	(void)snprintf(path, sizeof(path), "%s/%s", proc_root, tail);
	return testdir_read(path, NULL);
}

static void the_sysctls_are_written_where_the_observation_looks(void)
{
	char  message[NCFG_ERROR_MAX];
	char *held;

	message[0] = '\0';
	check(ncfg_service_set_forwarding(proc_root, "eth0", 1, message, sizeof(message)),
	    "forwarding goes on");
	held = value_at("sys/net/ipv4/conf/eth0/forwarding");
	check(held && strcmp(held, "1") == 0, "  and IPv4 says so");
	free(held);
	held = value_at("sys/net/ipv6/conf/eth0/forwarding");
	check(held && strcmp(held, "1") == 0, "  and IPv6 with it, which is what `both` means");
	free(held);
	/*
	 * **The property the observation half proves.** Asserting the file's bytes
	 * says the write landed; asking `observe.h` says it landed where the thing
	 * that reads it looks. Two paths spelled twice is the failure that check
	 * exists for, and it is the one a byte comparison cannot see.
	 */
	check(ncfg_observe_forwarding(proc_root, "eth0").has &&
	    ncfg_observe_forwarding(proc_root, "eth0").value,
	    "  and the observation reads it back as forwarding");

	message[0] = '\0';
	check(ncfg_service_set_forwarding(proc_root, "eth0", 1, message, sizeof(message)),
	    "setting it again is the same write, which is what idempotent means here");
	held = value_at("sys/net/ipv4/conf/eth0/forwarding");
	check(held && strcmp(held, "1") == 0, "  and the value has not moved");
	free(held);

	message[0] = '\0';
	check(ncfg_service_set_privacy(proc_root, "eth0", 1, message, sizeof(message)),
	    "temporary addresses are preferred");
	held = value_at("sys/net/ipv6/conf/eth0/use_tempaddr");
	check(held && strcmp(held, "2") == 0, "  written as the kernel's 2, never its 1");
	free(held);
	check(ncfg_observe_privacy(proc_root, "eth0").has &&
	    ncfg_observe_privacy(proc_root, "eth0").value,
	    "  and the observation agrees");

	message[0] = '\0';
	check(ncfg_service_set_accept_ra(proc_root, "eth0", 2, message, sizeof(message)),
	    "accept_ra takes 2");
	held = value_at("sys/net/ipv6/conf/eth0/accept_ra");
	check(held && strcmp(held, "2") == 0, "  and lands");
	free(held);
	message[0] = '\0';
	check(ncfg_service_set_accept_ra(proc_root, "eth0", 1, message, sizeof(message)),
	    "and 1, which is the kernel's own default and the way back");
	message[0] = '\0';
	refused(ncfg_service_set_accept_ra(proc_root, "eth0", 0, message, sizeof(message)),
	    message, "never 0",
	    "0 is refused by name: switching advertisements off is nobody's document");
	message[0] = '\0';
	refused(ncfg_service_set_accept_ra(proc_root, "eth0", 3, message, sizeof(message)),
	    message, "eth0", "and so is a value outside the two");
	held = value_at("sys/net/ipv6/conf/eth0/accept_ra");
	check(held && strcmp(held, "1") == 0, "  with the file left where the last write put it");
	free(held);

	message[0] = '\0';
	check(ncfg_service_set_hostname(proc_root, "router.example", message, sizeof(message)),
	    "the hostname is set");
	held = value_at("sys/kernel/hostname");
	check(held && strcmp(held, "router.example") == 0, "  with no newline of netcfgd's own");
	free(held);
	held = ncfg_observe_hostname(proc_root);
	check(held && strcmp(held, "router.example") == 0,
	    "  and the observation reads the same name back");
	free(held);
}

static void nothing_falls_back_to_the_machine(void)
{
	char message[NCFG_ERROR_MAX];

	message[0] = '\0';
	refused(ncfg_service_set_hostname(NULL, "router", message, sizeof(message)), message,
	    "no default",
	    "a hostname with no /proc named refuses rather than writing a relative path");
	message[0] = '\0';
	refused(ncfg_service_set_forwarding("", "eth0", 1, message, sizeof(message)), message,
	    "no default", "and an empty root is the same refusal, not the working directory");
	message[0] = '\0';
	refused(ncfg_service_set_privacy(proc_root, "../../etc", 1, message, sizeof(message)),
	    message, "path separator",
	    "an interface name carrying a separator cannot become a path component");
	message[0] = '\0';
	refused(ncfg_service_set_forwarding(proc_root, "..", 1, message, sizeof(message)),
	    message, "not an interface name", "and neither can `..`");
	message[0] = '\0';
	refused(ncfg_service_set_hostname(proc_root, "two\nlines", message, sizeof(message)),
	    message, "control character",
	    "a hostname carrying a newline is refused rather than silently cut");
}

static void a_missing_ipv6_stack_is_a_warning_and_a_missing_ipv4_is_not(void)
{
	char message[NCFG_ERROR_MAX];
	char path[1024];
	char saved[1024];

	/* The IPv6 file taken away: a kernel built with `ipv6.disable=1`. */
	(void)snprintf(path, sizeof(path), "%s/sys/net/ipv6/conf/eth0/forwarding", proc_root);
	(void)snprintf(saved, sizeof(saved), "%s/ipv6-forwarding.saved", base);
	check(rename(path, saved) == 0, "the IPv6 forwarding sysctl is taken away");
	message[0] = '\0';
	check(ncfg_service_set_forwarding(proc_root, "eth0", 0, message, sizeof(message)),
	    "forwarding still succeeds, so an IPv4 router is still configurable");
	check(rename(saved, path) == 0, "  and it is put back");

	/* The IPv4 one taken away: no such excuse. */
	(void)snprintf(path, sizeof(path), "%s/sys/net/ipv4/conf/eth0/forwarding", proc_root);
	(void)snprintf(saved, sizeof(saved), "%s/ipv4-forwarding.saved", base);
	check(rename(path, saved) == 0, "the IPv4 one is taken away");
	message[0] = '\0';
	refused(ncfg_service_set_forwarding(proc_root, "eth0", 1, message, sizeof(message)),
	    message, "IPv4", "and that is a failure naming the family");
	check(rename(saved, path) == 0, "  and it is put back");
}

/* ------------------------------------------------------------------------ *
 * hostapd's access control lists
 * ------------------------------------------------------------------------ */

static char run_dir[512];

static void the_acl_command_is_named_once(void)
{
	check(strcmp(ncfg_service_acl_command(NCFG_ACL_POLICY_ALLOW), "ACCEPT_ACL") == 0,
	    "an allow policy reads hostapd's accept list");
	check(strcmp(ncfg_service_acl_command(NCFG_ACL_POLICY_DENY), "DENY_ACL") == 0,
	    "and a deny policy its deny list");
	check(ncfg_service_acl_command(7) == NULL,
	    "a policy outside the set gets no word at all, which the caller refuses");
}

static void a_station_is_added_once_and_not_twice(void)
{
	char message[NCFG_ERROR_MAX];
	char directory[1024];

	if (!ncfg_hostapd_ctrl_dir(run_dir, directory, sizeof(directory), message,
	    sizeof(message))) {
		check(0, "the access point's control directory could be named");
		return;
	}
	make_tree(directory);
	memset(&fake_config, 0, sizeof(fake_config));
	(void)snprintf(fake_config.deny_list[0], sizeof(fake_config.deny_list[0]),
	    "66:77:88:99:aa:bb");
	fake_config.deny_count = 1u;
	if (!fake_start(directory, "wlan0")) {
		check(0, "a fake access point could be started");
		return;
	}

	message[0] = '\0';
	check(ncfg_service_access_control(run_dir, "wlan0", NCFG_ACL_POLICY_DENY,
	    "AA-BB-CC-DD-EE-FF", 1, 500, message, sizeof(message)),
	    "a station is put on the deny list");
	check(heard_times("DENY_ACL ADD_MAC aa:bb:cc:dd:ee:ff") == 1,
	    "  normalised on the way, so the spelling in the file is not the one sent");

	message[0] = '\0';
	check(ncfg_service_access_control(run_dir, "wlan0", NCFG_ACL_POLICY_DENY,
	    "aa:bb:cc:dd:ee:ff", 1, 500, message, sizeof(message)),
	    "adding it again succeeds, which is what a second apply does");
	/*
	 * **The check this whole arrangement exists for.** hostapd answers FAIL to
	 * `ADD_MAC` for an address already on the list, so an executor that sent it
	 * blind would fail here -- and the count, rather than the outcome, is what
	 * says it was not sent at all.
	 */
	check(heard_times("DENY_ACL ADD_MAC aa:bb:cc:dd:ee:ff") == 1,
	    "  and sends nothing, because hostapd answers FAIL to a duplicate");

	message[0] = '\0';
	check(ncfg_service_access_control(run_dir, "wlan0", NCFG_ACL_POLICY_DENY,
	    "aa:bb:cc:dd:ee:ff", 0, 500, message, sizeof(message)),
	    "and it comes off again");
	check(heard_times("DENY_ACL DEL_MAC aa:bb:cc:dd:ee:ff") == 1, "  once");
	message[0] = '\0';
	check(ncfg_service_access_control(run_dir, "wlan0", NCFG_ACL_POLICY_DENY,
	    "aa:bb:cc:dd:ee:ff", 0, 500, message, sizeof(message)),
	    "removing one that is not there is the state it was asked for");
	check(heard_times("DENY_ACL DEL_MAC aa:bb:cc:dd:ee:ff") == 1,
	    "  and sends nothing a second time");

	/* The other list is a different list, which is why the observation carries
	 * both: a stale accept entry overrides the deny list meant to refuse it. */
	message[0] = '\0';
	check(ncfg_service_access_control(run_dir, "wlan0", NCFG_ACL_POLICY_ALLOW,
	    "11:22:33:44:55:66", 1, 500, message, sizeof(message)),
	    "the accept list is a separate list");
	check(heard_times("ACCEPT_ACL ADD_MAC 11:22:33:44:55:66") == 1, "  and takes its own");

	message[0] = '\0';
	refused(ncfg_service_access_control(run_dir, "wlan0", NCFG_ACL_POLICY_DENY, "zz:zz",
	    1, 500, message, sizeof(message)), message, "zz:zz",
	    "a station that is not an address is refused before anything is sent");
	message[0] = '\0';
	refused(ncfg_service_access_control(run_dir, "wlan0", 9, "aa:bb:cc:dd:ee:ff", 1, 500,
	    message, sizeof(message)), message, "neither of hostapd's two lists",
	    "and so is a policy that names neither list");
	message[0] = '\0';
	refused(ncfg_service_access_control(NULL, "wlan0", NCFG_ACL_POLICY_DENY,
	    "aa:bb:cc:dd:ee:ff", 1, 500, message, sizeof(message)), message, "no default",
	    "with no run directory it refuses rather than reaching for the machine's");

	fake_stop();

	message[0] = '\0';
	refused(ncfg_service_access_control(run_dir, "wlan0", NCFG_ACL_POLICY_DENY,
	    "aa:bb:cc:dd:ee:ff", 1, 200, message, sizeof(message)), message,
	    "cannot reach the access point",
	    "an access point that has gone is a failure, never a converged list");
}

/* ------------------------------------------------------------------------ *
 * The supplicant-side ops
 * ------------------------------------------------------------------------ */

static char supplicant_dir[512];

/* A document with one radio, one open network and one access point. Every
 * string is from the arena, so nothing here is freed and nothing leaks. */
static ncfg_document_t        fixture;
static ncfg_device_t          fixture_device;
static ncfg_wifi_device_policy_t fixture_wifi;
static ncfg_wifi_network_t    fixture_network;
static ncfg_access_point_t    fixture_ap;

static void a_document(int autoconnect, int randomise)
{
	memset(&fixture, 0, sizeof(fixture));
	memset(&fixture_device, 0, sizeof(fixture_device));
	memset(&fixture_wifi, 0, sizeof(fixture_wifi));
	memset(&fixture_network, 0, sizeof(fixture_network));
	memset(&fixture_ap, 0, sizeof(fixture_ap));

	fixture_wifi.autoconnect = autoconnect;
	fixture_wifi.scan_randomization = randomise;
	fixture_wifi.mac_policy = NCFG_MAC_POLICY_PERMANENT;
	fixture_device.name = text("wlan0");
	fixture_device.managed = 1;
	fixture_device.wifi = &fixture_wifi;
	fixture.devices = &fixture_device;
	fixture.device_count = 1u;

	fixture_network.id = text("home");
	fixture_network.ssid.has = 1;
	fixture_network.ssid.length = 4u;
	memcpy(fixture_network.ssid.bytes, "Cafe", 4u);
	fixture_network.security.kind = NCFG_SECURITY_OPEN;
	fixture_network.autoconnect = 1;
	fixture.networks = &fixture_network;
	fixture.network_count = 1u;

	fixture_ap.id = text("lan-ap");
	fixture_ap.device = text("wlan0");
	fixture.access_points = &fixture_ap;
	fixture.access_point_count = 1u;
}

static ncfg_service_t a_context(void)
{
	static ncfg_secret_resolver_t resolver;
	ncfg_service_t                service;

	memset(&service, 0, sizeof(service));
	resolver.secrets_dir = base;
	resolver.materialise_dir = base;
	service.run_dir = run_dir;
	service.proc_root = proc_root;
	service.supplicant_dir = supplicant_dir;
	service.document = &fixture;
	service.secrets = &resolver;
	service.patience_ms = 500;
	return service;
}

static void a_supplicant_is_filled_from_the_document(void)
{
	ncfg_service_t service;
	char           message[NCFG_ERROR_MAX];
	char           record[1024];
	char          *held;

	make_tree(supplicant_dir);
	a_document(1, 1);
	memset(&fake_config, 0, sizeof(fake_config));
	if (!fake_start(supplicant_dir, "wlan0")) {
		check(0, "a fake supplicant could be started");
		return;
	}
	service = a_context();
	message[0] = '\0';
	check(ncfg_service_set_profiles(&service, "wlan0", message, sizeof(message)),
	    "a radio is given the document's networks");
	check(heard_times("SET update_config 0") == 1,
	    "  with `update_config` pinned explicitly, which is 0015's whole point");
	check(heard_times("REMOVE_NETWORK all") == 1,
	    "  cleared first, so nothing the document cannot account for survives");
	check(heard_times("SET preassoc_mac_addr 1") == 1,
	    "  and the scanning address policy sent in the direction the document asks");
	check(heard_times("SET rand_addr_lifetime ") == 1,
	    "  with the lifetime that separates the two randomising policies");
	check(heard_times("ADD_NETWORK") == 1, "  and one network added");
	check(heard_times("DISABLE_NETWORK all") == 0,
	    "  a radio that joins by itself is not told to leave its networks unselected");

	check(ncfg_service_networks_record_path(run_dir, "wlan0", record, sizeof(record),
	    message, sizeof(message)), "the digest has a path under the run directory");
	held = testdir_read(record, NULL);
	check(held && strlen(held) == 64u,
	    "  and a digest is written there, so the next observation can compare");
	free(held);

	fake_stop();
}

static void a_radio_told_not_to_join_is_told_so(void)
{
	ncfg_service_t service;
	char           message[NCFG_ERROR_MAX];

	a_document(0, 0);
	memset(&fake_config, 0, sizeof(fake_config));
	if (!fake_start(supplicant_dir, "wlan0")) {
		check(0, "a fake supplicant could be started");
		return;
	}
	service = a_context();
	message[0] = '\0';
	check(ncfg_service_set_profiles(&service, "wlan0", message, sizeof(message)),
	    "a radio with `autoconnect = false` is still populated");
	check(heard_times("DISABLE_NETWORK all") == 1,
	    "  and told to leave them unselected, after the additions rather than before");
	check(heard_times("SET preassoc_mac_addr 0") == 1,
	    "  with the scanning policy sent in the other direction, not left unset");
	fake_stop();
}

static void joining_asks_before_it_acts(void)
{
	ncfg_service_t service;
	char           message[NCFG_ERROR_MAX];

	a_document(1, 0);

	/* Already on the network the plan names. */
	memset(&fake_config, 0, sizeof(fake_config));
	(void)snprintf(fake_config.associated, sizeof(fake_config.associated), "Cafe");
	(void)snprintf(fake_config.networks[0], sizeof(fake_config.networks[0]), "Cafe");
	fake_config.network_count = 1u;
	if (!fake_start(supplicant_dir, "wlan0")) {
		check(0, "a fake supplicant could be started");
		return;
	}
	service = a_context();
	message[0] = '\0';
	check(ncfg_service_associate(&service, "wlan0", "home", message, sizeof(message)),
	    "joining a network the radio is already on succeeds");
	/*
	 * **The check the idempotence rule turns on.** Re-selecting is a
	 * disassociation and a rejoin: an outage produced by a plan that had
	 * nothing to do, on exactly the machine `plan.h` says must produce an empty
	 * second plan.
	 */
	check(heard_times("SELECT_NETWORK") == 0, "  and sends nothing at all");
	fake_stop();

	/* Not associated: the slot is looked up and selected. */
	memset(&fake_config, 0, sizeof(fake_config));
	(void)snprintf(fake_config.networks[0], sizeof(fake_config.networks[0]), "Other");
	(void)snprintf(fake_config.networks[1], sizeof(fake_config.networks[1]), "Cafe");
	fake_config.network_count = 2u;
	if (!fake_start(supplicant_dir, "wlan0")) {
		check(0, "a fake supplicant could be started");
		return;
	}
	service = a_context();
	message[0] = '\0';
	check(ncfg_service_associate(&service, "wlan0", "home", message, sizeof(message)),
	    "a radio on nothing joins the network the profile names");
	check(heard_times("SELECT_NETWORK 1") == 1,
	    "  by the slot the supplicant put it in, not by the plan's own numbering");

	message[0] = '\0';
	refused(ncfg_service_associate(&service, "wlan0", "nowhere", message, sizeof(message)),
	    message, "nowhere",
	    "a profile the document does not carry is refused rather than guessed at");
	fake_stop();

	/* A network the supplicant was never given. */
	memset(&fake_config, 0, sizeof(fake_config));
	if (!fake_start(supplicant_dir, "wlan0")) {
		check(0, "a fake supplicant could be started");
		return;
	}
	service = a_context();
	message[0] = '\0';
	refused(ncfg_service_associate(&service, "wlan0", "home", message, sizeof(message)),
	    message, "wifi.set_profiles",
	    "and a supplicant holding no such network is told which op should have");
	fake_stop();
}

static void leaving_and_the_regulatory_domain(void)
{
	ncfg_service_t service;
	char           message[NCFG_ERROR_MAX];

	a_document(1, 0);
	memset(&fake_config, 0, sizeof(fake_config));
	(void)snprintf(fake_config.associated, sizeof(fake_config.associated), "Cafe");
	if (!fake_start(supplicant_dir, "wlan0")) {
		check(0, "a fake supplicant could be started");
		return;
	}
	service = a_context();
	message[0] = '\0';
	check(ncfg_service_disassociate(&service, "wlan0", message, sizeof(message)),
	    "a radio leaves the network it is on");
	check(heard_times("DISCONNECT") == 1, "  with one command");
	message[0] = '\0';
	check(ncfg_service_disassociate(&service, "wlan0", message, sizeof(message)),
	    "and leaving again succeeds, the command naming a state rather than a change");

	message[0] = '\0';
	check(ncfg_service_set_regdom(&service, "wlan0", "se", message, sizeof(message)),
	    "a regulatory domain is set through the supplicant");
	check(heard_times("SET country SE") == 1,
	    "  upper cased, which is what the renderer writes and the comparison expects");
	message[0] = '\0';
	refused(ncfg_service_set_regdom(&service, "wlan0", "sweden", message, sizeof(message)),
	    message, "two letters",
	    "a country that is not two letters never reaches the control command");
	message[0] = '\0';
	refused(ncfg_service_set_regdom(&service, "wlan0", "s1", message, sizeof(message)),
	    message, "two letters", "and neither does one carrying a digit");
	check(heard_times("SET country") == 1, "  with nothing sent for either");

	service.supplicant_dir = NULL;
	message[0] = '\0';
	refused(ncfg_service_disassociate(&service, "wlan0", message, sizeof(message)), message,
	    "no default",
	    "with no control directory named it refuses rather than finding the machine's");
	fake_stop();
}

/* ------------------------------------------------------------------------ *
 * Backends
 * ------------------------------------------------------------------------ */


/* ------------------------------------------------------------------------ *
 * Taking back a daemon netcfgd started and lost the record of
 * ------------------------------------------------------------------------ */

/*
 * A stand-in for a daemon of netcfgd's, carrying the mark in its own argv.
 *
 * `sh -c "sleep 30; :"` rather than `sleep 30`, because dash execs the last
 * command of a `-c` script in place of itself and the marker would go with it
 * -- which `pppoe_test.c` paid for first.
 */
static pid_t marked_process(const char *marker)
{
	pid_t pid = fork();

	if (pid == 0) {
		execl("/bin/sh", "sh", "-c", "sleep 30; :", marker, (char *)NULL);
		_exit(127);
	}
	return pid;
}

/* Wait, bounded, for the child to have exec'd -- before that its command line
 * is this test binary's, so a check made too early asks about the wrong
 * process and passes for the wrong reason. */
static int carries_the_mark(pid_t pid, const char *marker)
{
	struct timespec pause = { 0, 20L * 1000L * 1000L };
	int             attempt;

	for (attempt = 0; attempt < 100; attempt++) {
		if (ncfg_process_pid_by_marker(marker) == pid) {
			return 1;
		}
		(void)nanosleep(&pause, NULL);
	}
	return 0;
}

static void reap(pid_t pid)
{
	int status = 0;

	if (pid > 0) {
		(void)kill(pid, SIGKILL);
		(void)waitpid(pid, &status, 0);
	}
}

/*
 * The three answers, each driven against a process this test started.
 *
 * **The case this exists for is `systemctl stop netcfgd`**: it takes
 * `/run/netcfgd` with it and `KillMode=process` leaves the daemons running, so
 * the pid file is gone and the process is not. Until this, only the supplicant
 * could be recovered from that, and every other kind was started again beside
 * the one already there.
 */
static void a_backend_netcfgd_lost_the_record_of(void)
{
	ncfg_service_t service = a_context();
	char           pid_path[512];
	char           marker[512];
	char           message[NCFG_ERROR_MAX];
	pid_t          daemon_pid;
	int            adopted = -1;

	printf("\n-- taking back a backend whose pid file has gone\n");
	make_tree(run_dir);

	/* A kind with no control socket answers `yes` to "does it answer", which
	 * is the honest answer for a radvd: there is no way to ask one. */
	check(ncfg_service_backend_handle(run_dir, NCFG_BACKEND_ROUTER_ADVERT, "lan0", pid_path,
	          sizeof(pid_path), marker, sizeof(marker)),
	    "a router advertisement daemon has a pid file and a mark");
	check(strstr(marker, "lan0.conf") != NULL,
	    "  and the mark is the configuration it recites, which netcfgd wrote");

	daemon_pid = marked_process(marker);
	check(daemon_pid > 0 && carries_the_mark(daemon_pid, marker),
	    "a daemon of netcfgd's is running, with no pid file to its name");
	(void)unlink(pid_path);

	message[0] = '\0';
	check(ncfg_service_backend_adopt(&service, NCFG_BACKEND_ROUTER_ADVERT, "lan0", &adopted,
	          message, sizeof(message)) && adopted == 1,
	    "it is adopted rather than started again");
	if (message[0] != '\0') {
		printf("       said: %s\n", message);
	}
	check(ncfg_process_pid_of(pid_path, marker) == daemon_pid,
	    "  and the record is written again, so the next pass does not adopt it twice");

	/* And the converged case, which is every pass after that one. */
	adopted = -1;
	message[0] = '\0';
	check(ncfg_service_backend_adopt(&service, NCFG_BACKEND_ROUTER_ADVERT, "lan0", &adopted,
	          message, sizeof(message)) && adopted == 1,
	    "a pid file that still names it is enough on its own");
	reap(daemon_pid);
	(void)unlink(pid_path);

	/*
	 * **The orphan, which is the branch that stops something.** A supplicant
	 * can be asked whether it answers, and this one cannot: there is no
	 * socket for it in the control directory. It is netcfgd's by the mark in
	 * its own argv, it cannot be driven, and starting a second beside it is
	 * what drops the association -- so it is stopped and the caller starts
	 * fresh.
	 */
	check(ncfg_service_backend_handle(run_dir, NCFG_BACKEND_SUPPLICANT, "wlan9", pid_path,
	          sizeof(pid_path), marker, sizeof(marker)),
	    "a supplicant's mark is the pid file's own path");
	daemon_pid = marked_process(marker);
	check(daemon_pid > 0 && carries_the_mark(daemon_pid, marker),
	    "an orphan carrying it is running");
	(void)unlink(pid_path);

	adopted = -1;
	message[0] = '\0';
	check(ncfg_service_backend_adopt(&service, NCFG_BACKEND_SUPPLICANT, "wlan9", &adopted,
	          message, sizeof(message)) && adopted == 0,
	    "one that cannot be reached is not adopted");
	{
		/* Bounded: the signal is delivered to a process this test forked, and
		 * what is being checked is that it was sent at all. */
		struct timespec pause = { 0, 20L * 1000L * 1000L };
		int             attempt;
		int             gone = 0;

		for (attempt = 0; attempt < 100 && !gone; attempt++) {
			if (waitpid(daemon_pid, NULL, WNOHANG) == daemon_pid) {
				gone = 1;
				break;
			}
			(void)nanosleep(&pause, NULL);
		}
		check(gone, "  it is stopped, because a corpse holding a radio is worse than none");
		if (!gone) {
			reap(daemon_pid);
		}
	}

	/* And the kinds netcfgd has no handle on say so rather than guessing. */
	check(!ncfg_service_backend_handle(run_dir, NCFG_BACKEND_DHCP4, "eth0", pid_path,
	          sizeof(pid_path), marker, sizeof(marker)),
	    "a DHCP client's marker is an interface name, which is too weak to scan for");
	adopted = -1;
	message[0] = '\0';
	check(ncfg_service_backend_adopt(&service, NCFG_BACKEND_DHCP4, "eth0", &adopted, message,
	          sizeof(message)) && adopted == 0,
	    "  so adopting one is not an error, it is a caller that goes on to start it");
}

static void a_backend_op_says_what_it_was_not_given(void)
{
	ncfg_service_t service;
	char           message[NCFG_ERROR_MAX];

	a_document(1, 0);
	service = a_context();

	message[0] = '\0';
	refused(ncfg_service_backend_start(&service, NCFG_BACKEND_ROUTER_ADVERT, "lan0",
	    message, sizeof(message)), message, "resolved `advertise`",
	    "a radvd with no resolved prefixes refuses rather than advertising nothing");
	message[0] = '\0';
	refused(ncfg_service_backend_start(&service, NCFG_BACKEND_OPENVPN, "vpn0", message,
	    sizeof(message)), message, "no configuration file",
	    "a tunnel with no configuration refuses rather than starting openvpn bare");
	message[0] = '\0';
	refused(ncfg_service_backend_start(&service, NCFG_BACKEND_ACCESS_POINT, "wlan9",
	    message, sizeof(message)), message, "no `access_point` block",
	    "an access point on a radio the document says nothing about is refused by name");

	service.run_dir = NULL;
	message[0] = '\0';
	refused(ncfg_service_backend_start(&service, NCFG_BACKEND_ACCESS_POINT, "wlan0",
	    message, sizeof(message)), message, "no default",
	    "and with no run directory it refuses rather than writing the machine's");

	service = a_context();
	message[0] = '\0';
	refused(ncfg_service_backend_reload(&service, NCFG_BACKEND_ACCESS_POINT, "wlan0",
	    message, sizeof(message)), message, "access_point",
	    "reloading an access point is refused rather than being a restart in disguise");
}

static void stopping_an_access_point_takes_the_passphrase_with_it(void)
{
	ncfg_service_t service;
	char           message[NCFG_ERROR_MAX];
	char           directory[1024];
	char           config[1024];
	char           pid_file[1024];

	a_document(1, 0);
	service = a_context();
	if (!ncfg_hostapd_ctrl_dir(run_dir, directory, sizeof(directory), message,
	    sizeof(message)) ||
	    !ncfg_hostapd_config_path(run_dir, "wlan0", config, sizeof(config), message,
	    sizeof(message)) ||
	    !ncfg_hostapd_pid_path(run_dir, "wlan0", pid_file, sizeof(pid_file), message,
	    sizeof(message))) {
		check(0, "the access point's paths could be named");
		return;
	}
	make_tree(directory);

	/* A running access point, answering. */
	memset(&fake_config, 0, sizeof(fake_config));
	if (!fake_start(directory, "wlan0")) {
		check(0, "a fake access point could be started");
		return;
	}
	(void)testdir_write(config, "wpa_passphrase=hunter2\n", 23u);
	(void)testdir_write(pid_file, "1\n", 2u);
	message[0] = '\0';
	check(ncfg_service_backend_stop(&service, NCFG_BACKEND_ACCESS_POINT, "wlan0", message,
	    sizeof(message)), "a running access point is stopped");
	check(heard_times("TERMINATE") == 1,
	    "  through its control socket, never by signalling something found by name");
	check(!testdir_exists(config),
	    "  and the generated configuration goes, because it holds the passphrase");
	check(!testdir_exists(pid_file), "  and the pid file with it, so 0080 cannot recur");
	fake_stop();

	/* Nothing there at all: the state this was asked to produce. */
	(void)testdir_write(config, "wpa_passphrase=hunter2\n", 23u);
	message[0] = '\0';
	check(ncfg_service_backend_stop(&service, NCFG_BACKEND_ACCESS_POINT, "wlan0", message,
	    sizeof(message)), "stopping one that is already gone is success");
	check(!testdir_exists(config),
	    "  and the passphrase still goes, which is the case nobody comes back to tidy");

	/* Bound and silent, which is neither of the two above. */
	memset(&fake_config, 0, sizeof(fake_config));
	fake_config.wedged = 1;
	if (!fake_start(directory, "wlan0")) {
		check(0, "a wedged fake access point could be started");
		return;
	}
	service.patience_ms = 200;
	message[0] = '\0';
	refused(ncfg_service_backend_stop(&service, NCFG_BACKEND_ACCESS_POINT, "wlan0", message,
	    sizeof(message)), message, "did not answer",
	    "one that holds its socket and says nothing is a failure, which is 0109");
	fake_stop();
}

/* ------------------------------------------------------------------------ *
 * DNS
 * ------------------------------------------------------------------------ */

static void a_resolver_configuration_is_delivered_and_recorded(void)
{
	ncfg_service_t    service;
	ncfg_dns_policy_t policy;
	ncfg_dns_server_t server;
	ncfg_dns_scope_t  scope;
	char              message[NCFG_ERROR_MAX];
	char              resolv[1024];
	char              record[1024];
	char             *held;
	char             *again;

	memset(&policy, 0, sizeof(policy));
	memset(&server, 0, sizeof(server));
	server.addr = text("192.0.2.53");
	policy.mode.mode = NCFG_DNS_MODE_WRITE_RESOLV_CONF;
	policy.servers = &server;
	policy.server_count = 1u;
	scope.name = NCFG_DNS_GLOBAL_SCOPE;
	scope.policy = &policy;

	a_document(1, 0);
	service = a_context();
	(void)under("resolv.conf", resolv, sizeof(resolv));
	service.dns.resolv_conf = resolv;
	service.dns.run_dir = run_dir;
	service.dns_scopes = &scope;
	service.dns_scope_count = 1u;

	message[0] = '\0';
	check(ncfg_service_dns_apply(&service, NCFG_DNS_GLOBAL_SCOPE, &policy, message,
	    sizeof(message)), "a resolver configuration is delivered");
	held = testdir_read(resolv, NULL);
	check(held && strstr(held, "nameserver 192.0.2.53") != NULL,
	    "  into the file the context named, and nowhere near /etc");
	(void)snprintf(record, sizeof(record), "%s/dns/%s.conf", run_dir, NCFG_DNS_GLOBAL_SCOPE);
	check(testdir_exists(record),
	    "  with the record the observation reads, without which every plan asks again");

	message[0] = '\0';
	check(ncfg_service_dns_apply(&service, NCFG_DNS_GLOBAL_SCOPE, &policy, message,
	    sizeof(message)), "delivering it a second time succeeds");
	again = testdir_read(resolv, NULL);
	check(held && again && strcmp(held, again) == 0,
	    "  and writes the same bytes, which is what the idempotence gate needs");
	free(held);
	free(again);

	service.dns.run_dir = NULL;
	message[0] = '\0';
	refused(ncfg_service_dns_apply(&service, NCFG_DNS_GLOBAL_SCOPE, &policy, message,
	    sizeof(message)), message, "record what it delivered",
	    "a delivery with nowhere to record it refuses, rather than planning for ever");

	service = a_context();
	service.dns.resolv_conf = resolv;
	service.dns.run_dir = run_dir;
	message[0] = '\0';
	refused(ncfg_service_dns_apply(&service, NULL, NULL, message, sizeof(message)), message,
	    "nothing to deliver",
	    "and one with neither a scope list nor a scope of its own says so");
}

/* ------------------------------------------------------------------------ *
 * The dispatch
 * ------------------------------------------------------------------------ */

static void the_dispatch_reaches_the_right_verb(void)
{
	ncfg_service_t service;
	ncfg_op_t      op;
	char           message[NCFG_ERROR_MAX];
	char          *held;

	a_document(1, 0);
	service = a_context();

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_HOSTNAME_SET;
	op.u.named.name = "through-the-dispatch";
	message[0] = '\0';
	check(ncfg_service_execute(&service, &op, message, sizeof(message)),
	    "`hostname.set` reaches the writer through the dispatch");
	held = value_at("sys/kernel/hostname");
	check(held && strcmp(held, "through-the-dispatch") == 0, "  and the name is the op's");
	free(held);

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_SYSCTL_SET_ACCEPT_RA;
	op.u.accept_ra.iface = "eth0";
	op.u.accept_ra.value = 2;
	message[0] = '\0';
	check(ncfg_service_execute(&service, &op, message, sizeof(message)),
	    "`sysctl.set_accept_ra` carries the op's own value");
	held = value_at("sys/net/ipv6/conf/eth0/accept_ra");
	check(held && strcmp(held, "2") == 0, "  which is the one that lands");
	free(held);

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_SYSCTL_SET_PRIVACY;
	op.u.privacy.iface = "eth0";
	op.u.privacy.prefer_temporary = 0;
	message[0] = '\0';
	check(ncfg_service_execute(&service, &op, message, sizeof(message)),
	    "`sysctl.set_privacy` carries its boolean rather than a fixed value");
	held = value_at("sys/net/ipv6/conf/eth0/use_tempaddr");
	check(held && strcmp(held, "0") == 0, "  and turns the mechanism off when asked to");
	free(held);

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_BACKEND_RELOAD;
	op.u.backend.kind = NCFG_BACKEND_DHCP4;
	op.u.backend.iface = "eth0";
	message[0] = '\0';
	refused(ncfg_service_execute(&service, &op, message, sizeof(message)), message, "dhcp4",
	    "and a backend the dispatch cannot reload names the kind rather than the op");
}

int main(void)
{
	base = testdir_make("service");

	(void)snprintf(run_dir, sizeof(run_dir), "%s/run", base);
	make_tree(run_dir);
	(void)snprintf(supplicant_dir, sizeof(supplicant_dir), "%s/wpa", base);
	make_tree(supplicant_dir);
	a_proc_tree();

	the_fourteen_are_supported();
	an_executor_with_no_context_refuses_by_name();
	the_machines_paths_are_one_place();

	the_sysctls_are_written_where_the_observation_looks();
	nothing_falls_back_to_the_machine();
	a_missing_ipv6_stack_is_a_warning_and_a_missing_ipv4_is_not();

	the_acl_command_is_named_once();
	a_station_is_added_once_and_not_twice();

	a_supplicant_is_filled_from_the_document();
	a_radio_told_not_to_join_is_told_so();
	joining_asks_before_it_acts();
	leaving_and_the_regulatory_domain();

	a_backend_netcfgd_lost_the_record_of();
	a_backend_op_says_what_it_was_not_given();
	stopping_an_access_point_takes_the_passphrase_with_it();
	a_resolver_configuration_is_delivered_and_recorded();
	the_dispatch_reaches_the_right_verb();

	/* Whatever a check left running goes with its recorded pid, never by
	 * name: a worker in this tree once matched on a binary path and killed 76
	 * netcfgd processes, 74 of them somebody else's. */
	fake_stop();
	remove_under(base, 0);
	testdir_remove(base);
	if (failures) {
		printf("service: %d check(s) failed\n", failures);
		return 1;
	}
	printf("service: every check passed\n");
	return 0;
}
