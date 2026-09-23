/*
 * dns_test.c -- what each resolver is handed, and the four defects the writing
 * has already had.
 *
 * WHAT THESE CASES ARE FOR
 *   The rendering cases are the Rust's, each keeping the sentence that says
 *   which defect it is about:
 *
 *   * **Interface scopes come before the global one**, because a flat
 *     resolver's only notion of "more specific" is "earlier in the list".
 *   * **Duplicates keep their first position** -- 0006 rule 4.
 *   * **Beyond three servers the rest are commented, not dropped silently.**
 *     glibc reads at most `MAXNS` nameserver lines and ignores the rest, so
 *     writing more would look like it worked and quietly not.
 *   * **`resolv.conf` says who wrote it.**
 *   * **A resolvconf blob covers one scope only.** Pre-merging would throw away
 *     the one thing `resolvconf(8)` is for.
 *   * **An empty scope renders empty**, rather than a header with nothing under
 *     it.
 *
 *   And the writing cases, which are where the defects were:
 *
 *   * **A writable file in a read-only directory is still written** (0161).
 *     `ProtectSystem=full` mounts `/etc` read-only and the unit opens one path
 *     back up with `ReadWritePaths=-/etc/resolv.conf` -- which grants the
 *     *file*. Staging a temporary beside it is creating a new entry, which is
 *     still refused, so on every systemd machine this failed with a permission
 *     error naming a dotfile the operator had never seen.
 *   * **And the fallback will not write through a symlink.** systemd-resolved
 *     and openresolv both leave one behind. A rename replaces the link, which
 *     is what the mode asks for; writing through it would edit the other
 *     daemon's runtime state, silently, on the one path where the sandbox makes
 *     the fallback engage.
 *   * **Two writers of one file must not share a temporary.** netcfgd applies
 *     from two processes and every temporary used to be `<name>.tmp` -- one
 *     path for everyone. The loser renames a file that is no longer there and
 *     is told it could not replace `resolv.conf` when it had written it
 *     perfectly well. **Threads here, deliberately**: a temporary named after
 *     the process alone would pass a two-process check and still be one path
 *     for every thread inside one.
 *   * **The staging file does not outlive the write.**
 *
 *   The rest are the C port's, and two of them cover renderers the Rust has no
 *   test for at all -- `dnsmasq_conf` and `unbound_conf`, which are the two
 *   scope-capable modes and therefore the two where flattening would be a
 *   disclosure rather than a degradation.
 *
 * NOTHING OUTSIDE ITS OWN DIRECTORY, AND NO RESOLVER
 *   This machine's real `/etc/resolv.conf` is managed by something. Every path
 *   here is under one `mkdtemp` directory and **is passed explicitly**: the C
 *   port reads no environment variable for a resolver path, which is the whole
 *   reason a check cannot reach one by forgetting to set something. Nothing
 *   here runs `resolvconf`, `resolvectl`, dnsmasq or unbound; the one program
 *   started is a shell script this test wrote, for the `exec` mode.
 */
#include "ncfg/base.h"
#include "ncfg/dns.h"
#include "ncfg/document.h"
#include "ncfg/value.h"

#include "testdir.h"

#include <dirent.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-70s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static void check_text(const char *got, const char *want, const char *what)
{
	int same = got != NULL && strcmp(got, want) == 0;

	check(same, what);
	if (!same) {
		printf("  wanted:\n%s\n  got:\n%s\n", want, got ? got : "(null)");
	}
}

/* ------------------------------------------------------------- fixtures */

/* A policy built from literals. Nothing here is freed, because nothing here
 * allocates: the arrays are the caller's and the model's strings are borrowed
 * for the length of one check. */
static ncfg_dns_policy_t policy_of(ncfg_dns_server_t *servers, size_t server_count,
    char **search, size_t search_count)
{
	ncfg_dns_policy_t policy;

	memset(&policy, 0, sizeof(policy));
	policy.mode.mode = NCFG_DNS_MODE_WRITE_RESOLV_CONF;
	policy.servers = servers;
	policy.server_count = server_count;
	policy.search = search;
	policy.search_count = search_count;
	return policy;
}

static ncfg_dns_server_t server_of(char *addr)
{
	ncfg_dns_server_t server;

	memset(&server, 0, sizeof(server));
	server.addr = addr;
	return server;
}

/* ------------------------------------------------------------ flattening */

/* Interface scopes come before the global one, because a flat resolver's only
 * notion of "more specific" is "earlier in the list". */
static void interface_scopes_come_before_globals(void)
{
	char              *global_search[] = { (char *)(void *)"fallback.example" };
	char              *eth0_search[] = { (char *)(void *)"lan.example" };
	ncfg_dns_server_t  global_servers[] = { { 0 } };
	ncfg_dns_server_t  eth0_servers[] = { { 0 } };
	ncfg_dns_policy_t  global;
	ncfg_dns_policy_t  eth0;
	ncfg_dns_scope_t   scopes[2];
	ncfg_dns_flat_t    flat;
	char               message[NCFG_ERROR_MAX];

	global_servers[0] = server_of((char *)(void *)"1.1.1.1");
	eth0_servers[0] = server_of((char *)(void *)"10.0.0.1");
	global = policy_of(global_servers, 1u, global_search, 1u);
	eth0 = policy_of(eth0_servers, 1u, eth0_search, 1u);

	/* The global scope is first in the list, which is the arrangement that
	 * would put it first in the answer if the ordering were the caller's. */
	scopes[0].name = NCFG_DNS_GLOBAL_SCOPE;
	scopes[0].policy = &global;
	scopes[1].name = "eth0";
	scopes[1].policy = &eth0;

	check(ncfg_dns_flatten(scopes, 2u, &flat, message, sizeof(message)), "the scopes flatten");
	check(flat.server_count == 2u && strcmp(flat.servers[0]->addr, "10.0.0.1") == 0 &&
	    strcmp(flat.servers[1]->addr, "1.1.1.1") == 0,
	    "the interface's server is consulted before the global fallback");
	check(flat.search_count == 2u && strcmp(flat.search[0], "lan.example") == 0 &&
	    strcmp(flat.search[1], "fallback.example") == 0,
	    "and its search suffix comes first too");
	ncfg_dns_flat_free(&flat);
}

/* Decision 0006 rule 4: deduplicated, first occurrence wins. */
static void duplicates_keep_their_first_position(void)
{
	ncfg_dns_server_t one_servers[2];
	ncfg_dns_server_t two_servers[2];
	ncfg_dns_policy_t one;
	ncfg_dns_policy_t two;
	ncfg_dns_scope_t  scopes[2];
	ncfg_dns_flat_t   flat;
	char              message[NCFG_ERROR_MAX];

	one_servers[0] = server_of((char *)(void *)"10.0.0.1");
	one_servers[1] = server_of((char *)(void *)"1.1.1.1");
	two_servers[0] = server_of((char *)(void *)"1.1.1.1");
	two_servers[1] = server_of((char *)(void *)"10.0.0.1");
	one = policy_of(one_servers, 2u, NULL, 0u);
	two = policy_of(two_servers, 2u, NULL, 0u);
	scopes[0].name = "eth0";
	scopes[0].policy = &one;
	scopes[1].name = "eth1";
	scopes[1].policy = &two;

	check(ncfg_dns_flatten(scopes, 2u, &flat, message, sizeof(message)), "two scopes flatten");
	check(flat.server_count == 2u && strcmp(flat.servers[0]->addr, "10.0.0.1") == 0,
	    "a repeated server keeps the position of its first occurrence");
	ncfg_dns_flat_free(&flat);
}

/*
 * Beyond three servers the rest are commented, not dropped silently.
 *
 * glibc reads at most `MAXNS` nameserver lines. Writing more would look like it
 * worked and quietly not, so the extras are listed in a comment and a reader
 * can see what was dropped. Asserted against the published constant rather than
 * against a 3 spelled here, so the two cannot disagree.
 */
static void beyond_three_servers_the_rest_are_commented(void)
{
	ncfg_dns_server_t many[4];
	ncfg_dns_policy_t policy;
	ncfg_dns_scope_t  scope;
	ncfg_dns_flat_t   flat;
	char              message[NCFG_ERROR_MAX];
	char             *text;

	many[0] = server_of((char *)(void *)"10.0.0.1");
	many[1] = server_of((char *)(void *)"10.0.0.2");
	many[2] = server_of((char *)(void *)"10.0.0.3");
	many[3] = server_of((char *)(void *)"10.0.0.4");
	policy = policy_of(many, 4u, NULL, 0u);
	scope.name = "eth0";
	scope.policy = &policy;

	check(ncfg_dns_flatten(&scope, 1u, &flat, message, sizeof(message)), "one scope flattens");
	text = ncfg_dns_resolv_conf(&flat, "netcfgd test", message, sizeof(message));
	check_text(text,
	    "# Generated by netcfgd test. Edits will be overwritten.\n"
	    "nameserver 10.0.0.1\n"
	    "nameserver 10.0.0.2\n"
	    "nameserver 10.0.0.3\n"
	    "# 1 further server(s) omitted: the resolver reads at most 3\n"
	    "#   10.0.0.4\n",
	    "the fourth server is commented and labelled, not dropped");
	check(NCFG_DNS_MAXNS == 3, "and the limit is glibc's MAXNS, published rather than spelled");
	free(text);
	ncfg_dns_flat_free(&flat);
}

static void resolv_conf_says_who_wrote_it(void)
{
	ncfg_dns_flat_t flat;
	char            message[NCFG_ERROR_MAX];
	char           *text;

	check(ncfg_dns_flatten(NULL, 0u, &flat, message, sizeof(message)), "no scopes flatten");
	text = ncfg_dns_resolv_conf(&flat, "netcfgd", message, sizeof(message));
	check_text(text, "# Generated by netcfgd. Edits will be overwritten.\n",
	    "an empty resolv.conf still says who wrote it and that edits are lost");
	free(text);
	ncfg_dns_flat_free(&flat);
}

/* ----------------------------------------------------- the per-scope blob */

static void a_resolvconf_blob_covers_one_scope_only(void)
{
	char             *search[] = { (char *)(void *)"lan.example" };
	ncfg_dns_server_t servers[1];
	ncfg_dns_policy_t policy;
	ncfg_dns_policy_t empty;
	char              message[NCFG_ERROR_MAX];
	char             *blob;

	servers[0] = server_of((char *)(void *)"10.0.0.1");
	policy = policy_of(servers, 1u, search, 1u);
	blob = ncfg_dns_resolvconf_blob(&policy, message, sizeof(message));
	check_text(blob, "search lan.example\nnameserver 10.0.0.1\n",
	    "a resolvconf blob is one scope's own, because that is the interface it defines");
	free(blob);

	/* An empty policy renders to an empty blob rather than a header with
	 * nothing under it, so `resolvconf -a` is not handed a file that says
	 * nothing in several lines. */
	memset(&empty, 0, sizeof(empty));
	blob = ncfg_dns_resolvconf_blob(&empty, message, sizeof(message));
	check_text(blob, "", "and an empty scope renders empty");
	free(blob);
}

/* ---------------------------------------------- the scope-capable modes */

/*
 * dnsmasq's and unbound's renderings, asserted whole.
 *
 * **The Rust has no test for either of these.** They are the two scope-capable
 * modes, so they are exactly the two where getting it wrong sends internal
 * queries to a public resolver -- the disclosure 0007 exists to refuse. A
 * rendering nobody checks is one where `server=/suffix/addr` becoming
 * `server=addr` would be noticed by whoever is reading the queries.
 */
static void the_forwarders_route_rather_than_flatten(void)
{
	ncfg_dns_server_t     servers[1];
	ncfg_routing_domain_t domains[2];
	ncfg_dns_policy_t     policy;
	ncfg_dns_scope_t      scope;
	char                  message[NCFG_ERROR_MAX];
	char                 *text;

	servers[0] = server_of((char *)(void *)"10.0.0.53");
	memset(domains, 0, sizeof(domains));
	domains[0].suffix = (char *)(void *)"corp.example.";
	domains[0].exclusive = 1;
	domains[1].suffix = (char *)(void *)"lab.example";
	domains[1].exclusive = 0;
	policy = policy_of(servers, 1u, NULL, 0u);
	policy.mode.mode = NCFG_DNS_MODE_DNSMASQ;
	policy.domains = domains;
	policy.domain_count = 2u;
	scope.name = "vpn0";
	scope.policy = &policy;

	text = ncfg_dns_dnsmasq_conf(&scope, 1u, message, sizeof(message));
	/* The exclusive domain routes and nothing else; the non-exclusive one
	 * routes *and* leaves the server usable generally, because dnsmasq has no
	 * "prefer but do not restrict". The trailing dot on a suffix is dnsmasq's
	 * to not have. */
	check_text(text,
	    "# Generated by netcfgd. Edits will be overwritten.\n"
	    "\n# scope: vpn0\n"
	    "server=/corp.example/10.0.0.53\n"
	    "server=/lab.example/10.0.0.53\n"
	    "server=10.0.0.53\n",
	    "dnsmasq routes the exclusive suffix and keeps the other usable generally");
	free(text);

	policy.mode.mode = NCFG_DNS_MODE_UNBOUND;
	policy.transport.has = 1;
	policy.transport.value = NCFG_DNS_TRANSPORT_TLS;
	text = ncfg_dns_unbound_conf(&scope, 1u, message, sizeof(message));
	check_text(text,
	    "# Generated by netcfgd. Edits will be overwritten.\n"
	    "\n# scope: vpn0\n"
	    "forward-zone:\n"
	    "\tname: \"corp.example.\"\n"
	    "\tforward-addr: 10.0.0.53\n"
	    "\tforward-tls-upstream: yes\n"
	    "forward-zone:\n"
	    "\tname: \"lab.example\"\n"
	    "\tforward-addr: 10.0.0.53\n"
	    "\tforward-tls-upstream: yes\n",
	    "unbound gets a forward-zone per routing domain, over TLS where asked");
	free(text);

	/* No routing domain at all is the catch-all zone, which is how a flat
	 * scope reaches a scope-capable resolver without being flattened away. */
	policy.domain_count = 0u;
	policy.transport.has = 0;
	text = ncfg_dns_unbound_conf(&scope, 1u, message, sizeof(message));
	check_text(text,
	    "# Generated by netcfgd. Edits will be overwritten.\n"
	    "\n# scope: vpn0\n"
	    "forward-zone:\n"
	    "\tname: \".\"\n"
	    "\tforward-addr: 10.0.0.53\n",
	    "and a scope with no routing domain is the catch-all zone");
	free(text);
}

/*
 * The escape hatch's wire format, asserted whole.
 *
 * A script reading this is an integration somebody wrote once and expects to
 * keep working, which is why it is hand-rolled rather than derived from an
 * internal type -- and why the control-character escaping is checked: JSON
 * requires every control character escaped and not only the five with short
 * forms, and a suffix that arrived with a tab in it would otherwise produce a
 * document the script's own parser refuses.
 */
static void the_exec_modes_document_is_json_a_script_can_read(void)
{
	ncfg_dns_server_t     servers[1];
	ncfg_routing_domain_t domains[1];
	char                 *search[] = { (char *)(void *)"a\tb" };
	ncfg_dns_policy_t     policy;
	ncfg_dns_scope_t      scope;
	char                  message[NCFG_ERROR_MAX];
	char                 *text;

	servers[0] = server_of((char *)(void *)"10.0.0.53");
	memset(domains, 0, sizeof(domains));
	domains[0].suffix = (char *)(void *)"corp.example";
	domains[0].exclusive = 1;
	policy = policy_of(servers, 1u, search, 1u);
	policy.mode.mode = NCFG_DNS_MODE_EXEC;
	policy.domains = domains;
	policy.domain_count = 1u;
	scope.name = "vpn0";
	scope.policy = &policy;

	text = ncfg_dns_scopes_json(&scope, 1u, message, sizeof(message));
	check_text(text,
	    "{\"scopes\":[{\"name\":\"vpn0\",\"servers\":[\"10.0.0.53\"],\"search\":[\"a\\tb\"],"
	    "\"domains\":[{\"suffix\":\"corp.example\",\"exclusive\":true}]}]}\n",
	    "the exec mode's document escapes control characters and keeps the scopes apart");
	free(text);
}

/* ------------------------------------------------------------ the writing */

/* Whether this process can create a file in a 0555 directory, which root with
 * CAP_DAC_OVERRIDE can. Probed rather than asked of `geteuid`: what matters is
 * whether the directory refuses a write, and identity and capability disagree
 * in a container without the capability or on a read-only filesystem. */
static int can_write_a_closed_directory(const char *dir)
{
	char probe[1024];
	int  made;

	(void)snprintf(probe, sizeof(probe), "%s/.ncfg-writable-probe", dir);
	made = testdir_write(probe, "x", 1u);
	if (made) {
		(void)unlink(probe);
	}
	return made;
}

/*
 * A writable file in a read-only directory is still written (0161).
 *
 * **This reproduces the shape and not the mechanism**, which is worth saying
 * because the difference bit once already: a `chmod` gives an unprivileged
 * caller `EACCES`, the real machine gives `EROFS` from a read-only mount, and
 * root walks through a mode but not through a mount. `tests/live/dns_sandbox.sh`
 * makes the mounts and is the one that answers for the packaged unit; this
 * covers the other error kind, which an unprivileged caller really does hit.
 */
static void a_writable_file_in_a_read_only_directory_is_still_written(const char *base)
{
	char  dir[512];
	char  path[1024];
	char  message[NCFG_ERROR_MAX];
	char *body;
	int   outcome;

	(void)testdir_in(base, "sandboxed", dir, sizeof(dir));
	check(mkdir(dir, 0755) == 0, "a directory to close");
	(void)testdir_in(dir, "resolv.conf", path, sizeof(path));
	check(testdir_write(path, "nameserver 192.0.2.1\n", 21u), "the file starts out there");

	check(chmod(dir, 0555) == 0, "the directory is closed");
	if (can_write_a_closed_directory(dir)) {
		(void)chmod(dir, 0755);
		printf("%-70s %s\n",
		    "a writable file in a read-only directory is still written",
		    "skipped: this process writes a 0555 directory");
		return;
	}
	message[0] = '\0';
	outcome = ncfg_dns_replace(path, "nameserver 192.0.2.9\n", message, sizeof(message));
	/* Reopened before the assertion, or a failure leaves a directory the
	 * harness cannot remove and every later run trips over it. */
	check(chmod(dir, 0755) == 0, "the directory is reopened");

	check(outcome, "a writable file in a read-only directory is written through the fallback");
	if (!outcome) {
		printf("  said: %s\n", message);
	}
	body = testdir_read(path, NULL);
	check_text(body, "nameserver 192.0.2.9\n", "and it holds what was written");
	free(body);
}

/* And it refuses to write through a symlink. */
static void the_fallback_will_not_write_through_a_symlink(const char *base)
{
	char  dir[512];
	char  real[1024];
	char  link[1024];
	char  message[NCFG_ERROR_MAX];
	char *body;
	int   outcome;

	(void)testdir_in(base, "symlinked", dir, sizeof(dir));
	check(mkdir(dir, 0755) == 0, "a directory for the link");
	(void)testdir_in(dir, "stub-resolv.conf", real, sizeof(real));
	(void)testdir_in(dir, "resolv.conf", link, sizeof(link));
	check(testdir_write(real, "nameserver 192.0.2.53\n", 22u), "the resolver's own file");
	check(symlink(real, link) == 0, "the link a resolver leaves");

	check(chmod(dir, 0555) == 0, "the directory is closed");
	if (can_write_a_closed_directory(dir)) {
		(void)chmod(dir, 0755);
		/* **A mode does not close a directory to root, and this needs it
		 * closed.** `CAP_DAC_OVERRIDE` walks straight through 0555, so the
		 * staging path succeeds, `ncfg_dns_replace` never falls back, and the
		 * refusal this exists to check is never reached -- the failure would
		 * read as "writing through the link must be refused" against a run
		 * where nothing was written through any link. That is 0161's own
		 * finding: its first reproduction used a mode, passed, and passed just
		 * as happily with the fix reverted. */
		printf("%-70s %s\n", "the fallback will not write through a symlink",
		    "skipped: this process writes a 0555 directory");
		return;
	}
	message[0] = '\0';
	outcome = ncfg_dns_replace(link, "nameserver 192.0.2.9\n", message, sizeof(message));
	check(chmod(dir, 0755) == 0, "the directory is reopened");

	check(!outcome && strstr(message, "is a symlink") != NULL,
	    "writing through the link is refused, and the refusal says which situation it is in");
	body = testdir_read(real, NULL);
	check_text(body, "nameserver 192.0.2.53\n", "and the resolver's own file is untouched");
	free(body);
}

/* ------------------------------------------------- two writers, one file */

typedef struct {
	const char *path;
	const char *text;
	int         rounds;
	int         refusals;
} writer_t;

static void *write_over_and_over(void *raw)
{
	writer_t *writer = raw;
	char      message[NCFG_ERROR_MAX];
	int       round;

	for (round = 0; round < writer->rounds; round++) {
		if (!ncfg_dns_replace(writer->path, writer->text, message, sizeof(message))) {
			writer->refusals++;
		}
	}
	return NULL;
}

/*
 * Two writers of one resolver file must not tread on each other.
 *
 * netcfgd applies from two processes -- `ncfg apply` and the daemon -- and
 * either may deliver DNS, so `/etc/resolv.conf` had one staging name for every
 * writer there would ever be. The loser of that race renames a file that is no
 * longer there, and the caller is told it could not replace `resolv.conf` when
 * it had in fact written it perfectly well.
 *
 * **Threads, because a temporary named after the process alone would pass a
 * two-process check and still be one path for every thread inside one.**
 */
static void two_writers_of_one_file_do_not_share_a_temporary(const char *base)
{
	char      path[512];
	char     *one;
	char     *two;
	size_t    at;
	writer_t  writers[2];
	pthread_t threads[2];
	char     *final_text;
	int       spawned = 0;

	(void)testdir_in(base, "two-writers.conf", path, sizeof(path));
	/* Long enough that a writer cannot finish inside one scheduler slice, which
	 * is what makes the interleaving real rather than hoped for. */
	one = malloc(2048u * 21u + 1u);
	two = malloc(2048u * 21u + 1u);
	check(one != NULL && two != NULL, "two bodies to write");
	if (!one || !two) {
		free(one);
		free(two);
		return;
	}
	one[0] = '\0';
	two[0] = '\0';
	for (at = 0u; at < 2048u; at++) {
		memcpy(one + at * 21u, "nameserver 192.0.2.1\n", 21u);
		memcpy(two + at * 21u, "nameserver 192.0.2.2\n", 21u);
	}
	one[2048u * 21u] = '\0';
	two[2048u * 21u] = '\0';

	writers[0].path = path;
	writers[0].text = one;
	writers[0].rounds = 200;
	writers[0].refusals = 0;
	writers[1] = writers[0];
	writers[1].text = two;

	for (at = 0u; at < 2u; at++) {
		if (pthread_create(&threads[at], NULL, write_over_and_over, &writers[at]) == 0) {
			spawned++;
		}
	}
	check(spawned == 2, "two writers start");
	for (at = 0u; at < (size_t)spawned; at++) {
		(void)pthread_join(threads[at], NULL);
	}

	check(writers[0].refusals == 0 && writers[1].refusals == 0,
	    "neither writer was told it could not replace a file it had written");
	final_text = testdir_read(path, NULL);
	check(final_text != NULL &&
	    (strcmp(final_text, one) == 0 || strcmp(final_text, two) == 0),
	    "and the file holds one writer's content whole, never half of each");
	free(final_text);
	free(one);
	free(two);
}

/*
 * And nothing is left beside it for the resolver to find.
 *
 * The staging file is a dotfile so a `*.conf` glob cannot match it and
 * dnsmasq's `conf-dir` skips it, but the stronger property is that it is not
 * there at all once the write returns.
 */
static void the_staging_file_does_not_outlive_the_write(const char *base)
{
	char           dir[512];
	char           path[1024];
	char           message[NCFG_ERROR_MAX];
	DIR           *open_dir;
	const struct dirent *found;
	int            strays = 0;

	(void)testdir_in(base, "staging", dir, sizeof(dir));
	check(mkdir(dir, 0755) == 0, "a directory of its own");
	(void)testdir_in(dir, "netcfgd.conf", path, sizeof(path));
	check(ncfg_dns_replace(path, "server=192.0.2.1\n", message, sizeof(message)), "written");

	open_dir = opendir(dir);
	while (open_dir != NULL && (found = readdir(open_dir)) != NULL) {
		if (strcmp(found->d_name, ".") == 0 || strcmp(found->d_name, "..") == 0 ||
		    strcmp(found->d_name, "netcfgd.conf") == 0) {
			continue;
		}
		printf("  left behind: %s\n", found->d_name);
		strays++;
	}
	if (open_dir) {
		(void)closedir(open_dir);
	}
	check(strays == 0, "the staging file does not outlive the write");
}

/* --------------------------------------------------------- the delivery */

/*
 * A delivery with nowhere to write fails by name.
 *
 * The Rust reaches for `/etc/resolv.conf` when nothing says otherwise, guarded
 * by an environment variable a check has to remember to set -- and its own
 * comment records that a test very nearly rewrote this machine's. Here the
 * target is a parameter and an absent one is a refusal, so the failure mode is
 * a sentence rather than an edited resolver.
 */
static void a_delivery_with_no_target_writes_nothing(void)
{
	ncfg_dns_server_t  servers[1];
	ncfg_dns_policy_t  policy;
	ncfg_dns_scope_t   scope;
	ncfg_dns_targets_t targets;
	char               message[NCFG_ERROR_MAX];

	servers[0] = server_of((char *)(void *)"192.0.2.1");
	policy = policy_of(servers, 1u, NULL, 0u);
	scope.name = NCFG_DNS_GLOBAL_SCOPE;
	scope.policy = &policy;
	memset(&targets, 0, sizeof(targets));

	message[0] = '\0';
	check(!ncfg_dns_deliver(&scope, 1u, &targets, NULL, NULL, message, sizeof(message)) &&
	    strstr(message, "no resolv.conf named") != NULL,
	    "a write_resolv_conf delivery with no file named refuses rather than guessing");
	check(strcmp(NCFG_RESOLV_CONF, "/etc/resolv.conf") == 0,
	    "and the default is asserted by reading the constant, never by writing to it");
}

/* Scopes that disagree about the mode are a config error, not something to
 * resolve by picking one: a host cannot both own resolv.conf and hand it to
 * resolvconf. */
static void scopes_that_disagree_about_the_mode_are_refused(void)
{
	ncfg_dns_policy_t  one;
	ncfg_dns_policy_t  two;
	ncfg_dns_scope_t   scopes[2];
	ncfg_dns_targets_t targets;
	char               message[NCFG_ERROR_MAX];

	one = policy_of(NULL, 0u, NULL, 0u);
	two = policy_of(NULL, 0u, NULL, 0u);
	two.mode.mode = NCFG_DNS_MODE_RESOLVCONF;
	scopes[0].name = "eth0";
	scopes[0].policy = &one;
	scopes[1].name = "eth1";
	scopes[1].policy = &two;
	memset(&targets, 0, sizeof(targets));

	message[0] = '\0';
	check(!ncfg_dns_deliver(scopes, 2u, &targets, NULL, NULL, message, sizeof(message)) &&
	    strstr(message, "disagree about the dns mode") != NULL &&
	    strstr(message, "write_resolv_conf") != NULL &&
	    strstr(message, "resolvconf") != NULL,
	    "scopes that disagree about the mode are refused, with both modes named");
}

/*
 * `none` writes nothing and records nothing.
 *
 * The default, and the one the GUI had to learn to say out loud: `dns { mode }`
 * defaults to `none`, which means netcfgd does not touch resolution -- and a
 * record claiming a delivered scope would be netcfgd asserting ownership of a
 * file something else wrote.
 */
static void the_none_mode_touches_nothing(const char *base)
{
	ncfg_dns_policy_t  policy;
	ncfg_dns_scope_t   scope;
	ncfg_dns_targets_t targets;
	char               message[NCFG_ERROR_MAX];
	char               recorded[1024];

	policy = policy_of(NULL, 0u, NULL, 0u);
	policy.mode.mode = NCFG_DNS_MODE_NONE;
	scope.name = NCFG_DNS_GLOBAL_SCOPE;
	scope.policy = &policy;
	memset(&targets, 0, sizeof(targets));
	targets.run_dir = base;

	message[0] = '\0';
	check(ncfg_dns_deliver(&scope, 1u, &targets, NULL, NULL, message, sizeof(message)),
	    "mode none delivers successfully");
	(void)snprintf(recorded, sizeof(recorded), "%s/dns", base);
	check(!testdir_exists(recorded),
	    "and records nothing, because netcfgd delivered nothing to claim");
}

/*
 * A whole delivery, into a directory this test made.
 *
 * The record is the half the observer reads back, so it is asserted whole:
 * without it a plan could not tell an already-applied policy from an unapplied
 * one, and every run would emit a `dns.apply` -- which would fail the
 * plan-idempotence gate.
 */
static void a_delivery_writes_the_file_and_the_record(const char *base)
{
	char                 *search[] = { (char *)(void *)"lan.example" };
	ncfg_dns_server_t     servers[1];
	ncfg_routing_domain_t domains[1];
	ncfg_dns_policy_t     policy;
	ncfg_dns_scope_t      scope;
	ncfg_dns_targets_t    targets;
	char                  run[512];
	char                  resolv[1024];
	char                  record[2048];
	char                  message[NCFG_ERROR_MAX];
	char                **delivered = NULL;
	size_t                delivered_count = 0;
	char                 *body;

	(void)testdir_in(base, "delivery", run, sizeof(run));
	check(mkdir(run, 0755) == 0, "a run directory of its own");
	(void)testdir_in(run, "resolv.conf", resolv, sizeof(resolv));

	servers[0] = server_of((char *)(void *)"10.0.0.1");
	memset(domains, 0, sizeof(domains));
	domains[0].suffix = (char *)(void *)"corp.example";
	domains[0].exclusive = 1;
	policy = policy_of(servers, 1u, search, 1u);
	policy.domains = domains;
	policy.domain_count = 1u;
	scope.name = "eth0";
	scope.policy = &policy;

	memset(&targets, 0, sizeof(targets));
	targets.resolv_conf = resolv;
	targets.run_dir = run;

	message[0] = '\0';
	check(ncfg_dns_deliver(&scope, 1u, &targets, &delivered, &delivered_count, message,
	      sizeof(message)),
	    "the scope is delivered to the file it was pointed at");
	if (message[0] != '\0') {
		printf("  said: %s\n", message);
	}
	check(delivered_count == 1u && delivered && strcmp(delivered[0], "eth0") == 0,
	    "and the caller is told which scope was delivered");
	ncfg_dns_delivered_free(delivered, delivered_count);

	body = testdir_read(resolv, NULL);
	check_text(body,
	    "# Generated by netcfgd. Edits will be overwritten.\n"
	    "search lan.example\n"
	    "nameserver 10.0.0.1\n",
	    "the resolver file is the flattened rendering");
	free(body);

	(void)snprintf(record, sizeof(record), "%s/dns/eth0.conf", run);
	body = testdir_read(record, NULL);
	check_text(body,
	    "# scope: eth0\n"
	    "# mode:  write_resolv_conf\n"
	    "search lan.example\n"
	    "nameserver 10.0.0.1\n"
	    "# routing domain corp.example (exclusive)\n",
	    "and the record says which scope, which mode, and which domains routed");
	free(body);
}

/*
 * The exec mode hands the scopes to a script on stdin, without a shell.
 *
 * The command is a config value, and a shell would make the DNS mode a place
 * where a config file becomes arbitrary code with word splitting attached --
 * the same rule the secret resolver's exec provider follows. The stand-in here
 * is a script this test wrote; no resolver is involved.
 */
static void the_exec_mode_feeds_a_script_on_stdin(const char *base)
{
	ncfg_dns_server_t  servers[1];
	ncfg_dns_policy_t  policy;
	ncfg_dns_scope_t   scope;
	ncfg_dns_targets_t targets;
	char               run[512];
	char               script[1024];
	char               seen[1024];
	char               command[2048];
	char               body[4096];
	char               message[NCFG_ERROR_MAX];
	char              *got;

	(void)testdir_in(base, "exec", run, sizeof(run));
	check(mkdir(run, 0755) == 0, "a run directory for the exec mode");
	(void)testdir_in(run, "hatch.sh", script, sizeof(script));
	(void)testdir_in(run, "stdin", seen, sizeof(seen));
	(void)snprintf(body, sizeof(body), "#!/bin/sh\ncat > '%s'\nprintf '%%s' \"$1\" >> '%s'\n",
	    seen, seen);
	check(testdir_write(script, body, strlen(body)) && chmod(script, 0755) == 0,
	    "the stand-in script is written and executable");

	servers[0] = server_of((char *)(void *)"10.0.0.53");
	policy = policy_of(servers, 1u, NULL, 0u);
	policy.mode.mode = NCFG_DNS_MODE_EXEC;
	/* Two words, so the splitting is exercised -- and split on whitespace
	 * alone, never by a shell. */
	(void)snprintf(command, sizeof(command), "%s an-argument", script);
	policy.mode.command = command;
	scope.name = NCFG_DNS_GLOBAL_SCOPE;
	scope.policy = &policy;

	memset(&targets, 0, sizeof(targets));
	targets.run_dir = run;

	message[0] = '\0';
	check(ncfg_dns_deliver(&scope, 1u, &targets, NULL, NULL, message, sizeof(message)),
	    "the exec mode runs the script the document named");
	if (message[0] != '\0') {
		printf("  said: %s\n", message);
	}
	got = testdir_read(seen, NULL);
	check_text(got,
	    "{\"scopes\":[{\"name\":\"globals\",\"servers\":[\"10.0.0.53\"],\"search\":[],"
	    "\"domains\":[]}]}\nan-argument",
	    "and hands it the whole scope document on stdin, with its arguments split");
	free(got);

	/* A script that is not there is named rather than reported as a generic
	 * failure to run something. */
	policy.mode.command = (char *)(void *)"/nonexistent/dns-hatch";
	message[0] = '\0';
	check(!ncfg_dns_deliver(&scope, 1u, &targets, NULL, NULL, message, sizeof(message)) &&
	    strstr(message, "/nonexistent/dns-hatch") != NULL &&
	    strstr(message, "is not there") != NULL,
	    "a script that is not there is named in the refusal");
}

/*
 * A forwarder whose directory does not exist is refused rather than created.
 *
 * An absent `/etc/dnsmasq.d` means dnsmasq is not installed or does not read
 * that directory, and creating it would leave a file nothing consumes while
 * reporting success. Constraint 2 -- the filesystem reflects use -- cuts both
 * ways.
 */
static void a_forwarder_with_no_directory_is_refused(const char *base)
{
	ncfg_dns_policy_t  policy;
	ncfg_dns_scope_t   scope;
	ncfg_dns_targets_t targets;
	char               absent[512];
	char               message[NCFG_ERROR_MAX];
	char               dir[512];

	(void)testdir_in(base, "no-dnsmasq-d/netcfgd.conf", absent, sizeof(absent));
	policy = policy_of(NULL, 0u, NULL, 0u);
	policy.mode.mode = NCFG_DNS_MODE_DNSMASQ;
	scope.name = NCFG_DNS_GLOBAL_SCOPE;
	scope.policy = &policy;
	memset(&targets, 0, sizeof(targets));
	targets.dnsmasq_conf = absent;
	targets.run_dir = base;

	message[0] = '\0';
	check(!ncfg_dns_deliver(&scope, 1u, &targets, NULL, NULL, message, sizeof(message)) &&
	    strstr(message, "does not exist") != NULL &&
	    strstr(message, "dnsmasq") != NULL,
	    "a forwarder whose drop-in directory is missing is refused by name");
	(void)testdir_in(base, "no-dnsmasq-d", dir, sizeof(dir));
	check(!testdir_exists(dir), "and the directory is not created on the way to refusing");
}

/*
 * **Where the machine's resolver configuration is, asked once.**
 *
 * This file's own header says the library defaults nothing: a delivery handed
 * no path fails rather than reaching for `/etc`. That leaves the choice to the
 * program -- and the programs made it by writing the constant out at three
 * call sites, so `NCFG_RESOLV_CONF` was in this port's documentation and
 * honoured nowhere.
 *
 * What that cost is not hypothetical and is not about tests only: every live
 * script that keeps a resolver test off the real file does it by setting that
 * variable, so the first one pointed at these programs would have rewritten
 * the `/etc/resolv.conf` of whatever machine it ran on. It was found by very
 * nearly doing exactly that.
 */
static void the_resolver_file_is_the_one_the_caller_asked_for(void)
{
	/*
	 * **All three, walked.** The rule is one function underneath, and the
	 * reason it is one function is that three copies of it is how one of them
	 * comes to check its variable and another not to -- which is not a
	 * hypothetical: this port shipped `resolv.conf` resolved and the two
	 * forwarders still written out as constants for a round, because they were
	 * fixed separately.
	 */
	static const struct {
		const char *(*resolve)(const char *, char *, size_t);
		const char *variable;
		const char *fallback;
		const char *what;
	} files[] = {
		{ ncfg_dns_resolve_conf_path, NCFG_RESOLV_CONF_ENV, NCFG_RESOLV_CONF,
		    "resolv.conf" },
		{ ncfg_dns_resolve_dnsmasq_path, NCFG_DNSMASQ_CONF_ENV, NCFG_DNSMASQ_CONF,
		    "dnsmasq's drop-in" },
		{ ncfg_dns_resolve_unbound_path, NCFG_UNBOUND_CONF_ENV, NCFG_UNBOUND_CONF,
		    "unbound's drop-in" },
	};
	size_t   at;
	unsigned obeyed = 0;
	char     out[256];

	printf("\n-- where the three resolver files are\n");
	for (at = 0; at < sizeof(files) / sizeof(files[0]); at++) {
		char buffer[256];

		(void)setenv(files[at].variable, "/from-the-environment", 1);
		if (strcmp(files[at].resolve(NULL, buffer, sizeof(buffer)),
		    "/from-the-environment") != 0) {
			printf("       %s does not read its variable\n", files[at].what);
			continue;
		}
		(void)unsetenv(files[at].variable);
		if (strcmp(files[at].resolve(NULL, buffer, sizeof(buffer)),
		    files[at].fallback) != 0) {
			printf("       %s does not fall back to the machine's\n", files[at].what);
			continue;
		}
		if (strcmp(files[at].resolve("/explicit", buffer, sizeof(buffer)),
		    "/explicit") != 0) {
			printf("       %s does not take an explicit path\n", files[at].what);
			continue;
		}
		obeyed++;
	}
	check(obeyed == sizeof(files) / sizeof(files[0]),
	    "each of the three resolver files takes the explicit path, then its "
	    "environment variable, then the machine's");

	check(strcmp(ncfg_dns_resolve_conf_path("/somewhere/resolv.conf", out, sizeof(out)),
	    "/somewhere/resolv.conf") == 0, "an explicit path wins");
	(void)setenv(NCFG_RESOLV_CONF_ENV, "/from-the-environment", 1);
	check(strcmp(ncfg_dns_resolve_conf_path(NULL, out, sizeof(out)),
	    "/from-the-environment") == 0,
	    "and the environment beats the default, which is what keeps a test off the "
	    "machine's own");
	check(strcmp(ncfg_dns_resolve_conf_path("/explicit", out, sizeof(out)), "/explicit") == 0,
	    "  and an explicit path still beats the environment");
	(void)unsetenv(NCFG_RESOLV_CONF_ENV);
	check(strcmp(ncfg_dns_resolve_conf_path(NULL, out, sizeof(out)), NCFG_RESOLV_CONF) == 0,
	    "with nothing said, the machine's");
	/* An empty variable is nothing said rather than an empty path: a caller
	 * that exported one and did not fill it would otherwise deliver to "". */
	(void)setenv(NCFG_RESOLV_CONF_ENV, "", 1);
	check(strcmp(ncfg_dns_resolve_conf_path(NULL, out, sizeof(out)), NCFG_RESOLV_CONF) == 0,
	    "and an empty variable says nothing rather than naming an empty path");
	(void)unsetenv(NCFG_RESOLV_CONF_ENV);
	check(strcmp(ncfg_dns_resolve_conf_path(NULL, NULL, 0), NCFG_RESOLV_CONF) == 0,
	    "and asked with nowhere to put it, the answer is still a usable path");
}

int main(void)
{
	the_resolver_file_is_the_one_the_caller_asked_for();
	const char *base = testdir_make("dns");

	interface_scopes_come_before_globals();
	duplicates_keep_their_first_position();
	beyond_three_servers_the_rest_are_commented();
	resolv_conf_says_who_wrote_it();
	a_resolvconf_blob_covers_one_scope_only();
	the_forwarders_route_rather_than_flatten();
	the_exec_modes_document_is_json_a_script_can_read();

	a_writable_file_in_a_read_only_directory_is_still_written(base);
	the_fallback_will_not_write_through_a_symlink(base);
	two_writers_of_one_file_do_not_share_a_temporary(base);
	the_staging_file_does_not_outlive_the_write(base);

	a_delivery_with_no_target_writes_nothing();
	scopes_that_disagree_about_the_mode_are_refused();
	the_none_mode_touches_nothing(base);
	a_delivery_writes_the_file_and_the_record(base);
	the_exec_mode_feeds_a_script_on_stdin(base);
	a_forwarder_with_no_directory_is_refused(base);

	testdir_remove(base);
	if (failures > 0) {
		printf("dns: %d check(s) failed\n", failures);
		return 1;
	}
	printf("dns: every check passed\n");
	return 0;
}
