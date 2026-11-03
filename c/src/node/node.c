/*
 * node.c -- the store, the claim and the identity, in the order fuzznetd takes
 * them (its `node/daemon.c`): the claim before anything is booted, because a
 * follower writes nothing, then the store, then the identity asked of the
 * store part by part -- and then, unlike fuzznetd, the claim given back,
 * for the reason `ncfg/node.h` gives.
 *
 * Everything fuzznet is behind this file. The rest of the daemon sees
 * `ncfg/node.h`, which names no fuzznet type, so the include paths and the
 * feature flags fuzznet's headers need are this directory's alone.
 */
#include "ncfg/node.h"

#include "ncfg/base.h"

#include "chain/sign_monocypher.h"
#include "claim/claim_file.h"
#include "cli/cli.h"
#include "node/daemon.h"
#include "local/vocabulary.h"
#include "node/identity.h"
#include "node/types.h"
#include "persist/persist_file.h"
#include "session/agree_monocypher.h"
#include "session/hash_monocypher.h"
#include "session/random_system.h"
#include "state/scope.h"
#include "trust/trust.h"

#include "ncfg/scope.h"

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/*
 * **netcfgd's scope copy held to fuzznet's, in the daemon's own build** (0308,
 * project.md 10.669). The language's table keeps `ncfg_scope_t` so that the
 * compiler -- and everything that includes `ncfg/scope.h` -- needs no fuzznet
 * header; this module is the one place both are visible in the program that
 * ships, so it is where the build refuses a drift. `bridge/record_encode.c`
 * holds the same assertion for the bridge.
 */
_Static_assert((int)NCFG_SCOPE_HOST_PRIVATE == (int)FZN_SCOPE_HOST_PRIVATE &&
        (int)NCFG_SCOPE_HOST == (int)FZN_SCOPE_HOST &&
        (int)NCFG_SCOPE_GROUP == (int)FZN_SCOPE_GROUP &&
        (int)NCFG_SCOPE_ESTATE == (int)FZN_SCOPE_ESTATE,
    "netcfgd's scope copy has drifted from fuzznet's state/scope.h");

/* netcfgd's remote types inside fuzznet's extensions' range, checked where
 * both are visible, as the scope table's are. */
_Static_assert(NCFG_NODE_TYPE_REQUEST >= FZN_TYPES_EXTENSION_FIRST &&
        NCFG_NODE_TYPE_REQUEST <= FZN_TYPES_EXTENSION_LAST &&
        NCFG_NODE_TYPE_ANSWER >= FZN_TYPES_EXTENSION_FIRST &&
        NCFG_NODE_TYPE_ANSWER <= FZN_TYPES_EXTENSION_LAST,
    "netcfgd's remote types are outside fuzznet's extensions' range");

/* Everything the identity points into, in one allocation that outlives it:
 * `identity.agree_secret` is a pointer to `agree_secret`, and the signer the
 * seat arms is `signer`. */
struct ncfg_node {
	char                   dir[NCFG_NODE_DIR_MAX];
	/* `<run>/node` once published, so closing takes it away: a file naming a
	 * face that has gone would be a claim nothing holds. */
	char                   published[NCFG_NODE_DIR_MAX + 16u];
	ncfg_node_found_t      found;
	int                    created;
	fzn_persist_file_t     store_file;
	const fzn_persist_ops_t *store;
	fzn_hash_ops_t         hash;
	fzn_random_ops_t       rng;
	fzn_sign_monocypher_t  signer;
	fzn_sign_ops_t         sign;
	fzn_sign_seat_t        seat;
	fzn_agree_ops_t        agree;
	fzn_agree_secret_t     agree_secret;
	fzn_trust_t            trust;
	fzn_node_identity_t    identity;
};

/* fuzznet's default for this user, with the password database standing in
 * for an unset `$HOME`, which is how a service is usually started. */
static int default_dir(char out[NCFG_NODE_DIR_MAX], char *err, size_t err_size)
{
	struct passwd *account;
	int            wrote;

	if (fzn_cli_default_dir(out, NCFG_NODE_DIR_MAX) == FZN_CLI_OK) {
		return 1;
	}
	account = getpwuid(geteuid());
	if (!account || !account->pw_dir || account->pw_dir[0] != '/') {
		ncfg_error_set(err, err_size,
		    "no fuzznet store: $XDG_DATA_HOME and $HOME are unset, and this account has "
		    "no home directory to keep one in; name one with --fuzznet-dir");
		return 0;
	}
	wrote = snprintf(out, NCFG_NODE_DIR_MAX, "%s/.local/share/%s", account->pw_dir,
	    FZN_CLI_DEFAULT_DIR_NAME);
	if (wrote < 0 || (size_t)wrote >= NCFG_NODE_DIR_MAX) {
		ncfg_error_set(err, err_size, "the default fuzznet store's path is too long");
		return 0;
	}
	return 1;
}

int ncfg_node_where(const char *named, int default_run_dir, char out[NCFG_NODE_DIR_MAX],
    int *made, char *err, size_t err_size)
{
	out[0] = '\0';
	*made = 0;
	if (named) {
		if (!named[0]) {
			return 0;
		}
		if (strlen(named) >= NCFG_NODE_DIR_MAX) {
			ncfg_error_set(err, err_size, "the fuzznet store's path is too long");
			return 0;
		}
		(void)snprintf(out, NCFG_NODE_DIR_MAX, "%s", named);
		return 1;
	}
	if (!default_run_dir) {
		return 0;
	}
	if (!default_dir(out, err, err_size)) {
		return 0;
	}
	*made = 1;
	return 1;
}

/* `mkdir -p`, each new directory 0700: a store holds a signing seed. */
static int make_dirs(const char *dir, char *err, size_t err_size)
{
	char   path[NCFG_NODE_DIR_MAX];
	size_t at;

	(void)snprintf(path, sizeof(path), "%s", dir);
	for (at = 1u; path[at] != '\0'; at++) {
		if (path[at] != '/') {
			continue;
		}
		path[at] = '\0';
		if (mkdir(path, 0700) != 0 && errno != EEXIST) {
			ncfg_error_set(err, err_size, "cannot make %s: %s", path, strerror(errno));
			return 0;
		}
		path[at] = '/';
	}
	if (mkdir(path, 0700) != 0 && errno != EEXIST) {
		ncfg_error_set(err, err_size, "cannot make %s: %s", path, strerror(errno));
		return 0;
	}
	return 1;
}

static uint64_t wall_clock(void)
{
	time_t now = time(NULL);

	return now < 0 ? 0u : (uint64_t)now;
}

static void wipe(ncfg_node_t *node)
{
	fzn_agree_secret_wipe(&node->agree_secret);
	explicit_bzero(node, sizeof(*node));
	free(node);
}

ncfg_node_t *ncfg_node_open(const char *dir, int make_dir, char *err, size_t err_size)
{
	fzn_claim_file_t          claim_file;
	fzn_claim_ops_t           claim_ops;
	fzn_claim_t               claim;
	ncfg_node_t              *node;
	fzn_node_identity_env_t   env;
	fzn_node_identity_found_t found;
	fzn_node_identity_err_t   booted;
	fzn_claim_err_t           claimed;
	char                      claim_path[NCFG_NODE_DIR_MAX + 8u];
	struct stat               seen;

	if (!dir || !dir[0] || strlen(dir) >= NCFG_NODE_DIR_MAX) {
		ncfg_error_set(err, err_size, "a fuzznet store was opened with no usable path");
		return NULL;
	}
	if (stat(dir, &seen) != 0) {
		if (errno != ENOENT || !make_dir) {
			ncfg_error_set(err, err_size,
			    "the fuzznet store %s is not there, and a store that is named is never "
			    "made: a mistyped path would otherwise become a second node", dir);
			return NULL;
		}
		if (!make_dirs(dir, err, err_size)) {
			return NULL;
		}
	} else if (!S_ISDIR(seen.st_mode)) {
		ncfg_error_set(err, err_size, "the fuzznet store %s is not a directory", dir);
		return NULL;
	}

	node = calloc(1u, sizeof(*node));
	if (!node) {
		ncfg_error_set(err, err_size, "out of memory opening the fuzznet store");
		return NULL;
	}
	(void)snprintf(node->dir, sizeof(node->dir), "%s", dir);
	claim_file.fd = -1;

	/* THE CLAIM FIRST, fuzznet sec 666: the face writes, and only the face --
	 * held for this function and no longer. */
	(void)snprintf(claim_path, sizeof(claim_path), "%s/claim", dir);
	if (fzn_claim_file_open(&claim_file, claim_path, &claim_ops) != FZN_CLAIM_OK ||
	    fzn_claim_init(&claim, &claim_ops) != FZN_CLAIM_OK) {
		ncfg_error_set(err, err_size, "the claim at %s would not open: %s", claim_path,
		    strerror(errno));
		(void)fzn_claim_file_close(&claim_file);
		wipe(node);
		return NULL;
	}
	claimed = fzn_claim_take(&claim);
	if (claimed == FZN_CLAIM_OK) {
		node->found = NCFG_NODE_ALONE;
	} else if (claimed == FZN_CLAIM_ERR_HELD) {
		node->found = NCFG_NODE_BESIDE_FACE;
	} else {
		ncfg_error_set(err, err_size, "the claim at %s cannot be decided: %s", claim_path,
		    fzn_claim_err_str(claimed));
		(void)fzn_claim_file_close(&claim_file);
		wipe(node);
		return NULL;
	}

	node->store = fzn_persist_file_init(&node->store_file, node->dir);
	if (!node->store) {
		ncfg_error_set(err, err_size, "the fuzznet store %s would not open", dir);
		(void)fzn_claim_file_close(&claim_file);
		wipe(node);
		return NULL;
	}
	fzn_hash_monocypher_init(&node->hash);
	fzn_random_system_init(&node->rng);
	fzn_sign_monocypher_init(&node->sign, &node->signer);
	fzn_sign_monocypher_seat_init(&node->seat, &node->signer);
	fzn_agree_monocypher_init(&node->agree);

	memset(&env, 0, sizeof(env));
	env.store = node->store;
	env.rng = &node->rng;
	env.seat = &node->seat;
	env.sign = &node->sign;
	env.hash = &node->hash;
	env.agree = &node->agree;
	env.log = NULL;
	/* Asked of the store part by part, because "could not read" is not
	 * "absent", and generating over the first destroys a node. */
	found.seed = fzn_persist_file_holds(&node->store_file, FZN_PERSIST_OWN_IDENTITY, NULL);
	found.prekey = fzn_persist_file_holds(&node->store_file, FZN_PERSIST_OWN_PREKEY, NULL);
	found.trust = fzn_persist_file_holds(&node->store_file, FZN_PERSIST_TRUST, NULL);

	if (node->found == NCFG_NODE_BESIDE_FACE) {
		/* A follower makes nothing: an identity is the face's to create. */
		if (found.seed != FZN_PERSIST_OK || found.prekey != FZN_PERSIST_OK ||
		    found.trust != FZN_PERSIST_OK) {
			ncfg_error_set(err, err_size,
			    "another process holds the fuzznet store %s and it holds no complete "
			    "identity yet; this daemon follows it and makes none", dir);
			(void)fzn_claim_file_close(&claim_file);
			wipe(node);
			return NULL;
		}
		booted = fzn_node_identity_load(&env, wall_clock(), &node->agree_secret,
		    &node->trust, &node->identity);
	} else {
		booted = fzn_node_identity_boot(&env, &found, wall_clock(), &node->agree_secret,
		    &node->trust, &node->identity, &node->created);
	}
	/* Given back now, booted or not: a fuzznetd following it takes it within
	 * a second and becomes the face. */
	(void)fzn_claim_file_close(&claim_file);
	if (booted != FZN_NODE_IDENTITY_OK) {
		if (booted == FZN_NODE_IDENTITY_PARTIAL) {
			ncfg_error_set(err, err_size,
			    "the fuzznet store %s holds part of an identity (seed %s, prekey %s, "
			    "anchor %s), which is refused rather than repaired", dir,
			    found.seed == FZN_PERSIST_OK ? "present" : "absent",
			    found.prekey == FZN_PERSIST_OK ? "present" : "absent",
			    found.trust == FZN_PERSIST_OK ? "present" : "absent");
		} else {
			ncfg_error_set(err, err_size, "no identity from the fuzznet store %s: %s", dir,
			    fzn_node_identity_err_str(booted));
		}
		wipe(node);
		return NULL;
	}
	return node;
}

const uint8_t *ncfg_node_key(const ncfg_node_t *node)
{
	return node->identity.pubkey;
}

ncfg_node_found_t ncfg_node_found(const ncfg_node_t *node)
{
	return node->found;
}

const char *ncfg_node_dir(const ncfg_node_t *node)
{
	return node->dir;
}

int ncfg_node_created(const ncfg_node_t *node)
{
	return node->created;
}

void ncfg_node_key_hex(const uint8_t key[NCFG_NODE_KEY_LEN], char out[NCFG_NODE_KEY_HEX])
{
	static const char hex[] = "0123456789abcdef";
	size_t            at;

	for (at = 0u; at < NCFG_NODE_KEY_LEN; at++) {
		out[at * 2u] = hex[key[at] >> 4];
		out[at * 2u + 1u] = hex[key[at] & 0x0fu];
	}
	out[NCFG_NODE_KEY_LEN * 2u] = '\0';
}

int ncfg_node_publish(ncfg_node_t *node, const char *run_dir, char *err, size_t err_size)
{
	char  path[NCFG_NODE_DIR_MAX + 16u];
	char  next[NCFG_NODE_DIR_MAX + 24u];
	char  key[NCFG_NODE_KEY_HEX];
	FILE *file;
	int   ok;

	(void)snprintf(path, sizeof(path), "%s/node", run_dir);
	(void)snprintf(next, sizeof(next), "%s.new", path);
	file = fopen(next, "w");
	if (!file) {
		ncfg_error_set(err, err_size, "cannot write %s: %s", next, strerror(errno));
		return 0;
	}
	ncfg_node_key_hex(ncfg_node_key(node), key);
	ok = fprintf(file, "key=%s\nstore=%s\n", key, node->dir) > 0;
	ok = fclose(file) == 0 && ok;
	if (!ok || rename(next, path) != 0) {
		ncfg_error_set(err, err_size, "cannot write %s: %s", path, strerror(errno));
		(void)unlink(next);
		return 0;
	}
	(void)snprintf(node->published, sizeof(node->published), "%s", path);
	return 1;
}

void ncfg_node_close(ncfg_node_t *node)
{
	if (!node) {
		return;
	}
	if (node->published[0]) {
		(void)unlink(node->published);
	}
	wipe(node);
}

/* ------------------------------------------------------------------------ *
 * Serving the store, inside fuzznet's loop (project.md 10.676)
 * ------------------------------------------------------------------------ */

/*
 * The loop being served. **One serve per process**, as `fzn_daemon_main` is:
 * it keeps its state in statics, so a second would be a second node in one
 * address space. `stopped` says the end was asked for, rather than fuzznet's
 * loop ending by itself.
 */
static const ncfg_node_loop_t *serving;
static int                     stopped;

static size_t serve_fds(void *ctx, int *out, size_t cap)
{
	(void)ctx;
	return serving->fds(serving->context, out, cap);
}

static void serve_ready(void *ctx, int fd)
{
	(void)ctx;
	serving->ready(serving->context, fd);
}

/* fuzznet's caller as netcfgd's, which is what the tiers judge. */
static void peer_of(const fzn_peer_t *from, ncfg_peer_t *peer)
{
	memset(peer, 0, sizeof(*peer));
	peer->pid = (pid_t)from->pid;
	peer->uid = (uid_t)from->uid;
	peer->gid = (gid_t)from->primary_gid;
	peer->groups_known = from->groups_known;
	if (from->groups_known) {
		size_t at;

		peer->group_total = from->group_count;
		for (at = 0; at < from->group_count && at < NCFG_PEER_GROUPS_MAX; at++) {
			peer->groups[at] = (gid_t)from->groups[at];
		}
		peer->group_count = at;
	}
}

/* A request fuzznet declined, with its caller, as netcfgd's own types: the
 * peer as `ncfg_peer_t`, which is what the tiers judge, and the line as text.
 * A remote origin is not answered here: 0128 decides what a remote caller may
 * do, and that is not this hook. */
static size_t serve_local_from(void *ctx, fzn_origin_t origin, const fzn_peer_t *from,
    const fzn_request_t *request, char *reply, size_t cap)
{
	ncfg_peer_t peer;
	char        line[1024];
	size_t      length;

	(void)ctx;
	if (!serving->local || !from || !request || origin == FZN_ORIGIN_REMOTE) {
		return 0u;
	}
	peer_of(from, &peer);
	length = request->verb_len + (request->arg_len ? 1u + request->arg_len : 0u);
	if (length >= sizeof(line)) {
		return 0u;
	}
	memcpy(line, request->verb, request->verb_len);
	if (request->arg_len) {
		line[request->verb_len] = ' ';
		memcpy(line + request->verb_len + 1u, request->arg, request->arg_len);
	}
	line[length] = '\0';
	return serving->local(serving->context, &peer, line, reply, cap);
}

/* A remote request of netcfgd's type, its two type bytes taken off and the
 * answer's put on: version 2, `NCFG_NODE_TYPE_ANSWER`. Any other type is not
 * this daemon's, and fuzznet answers it `unsupported`. */
static size_t serve_remote(void *ctx, const uint8_t sender[FZN_PUBKEY_LEN], int contact,
    const uint8_t *request, size_t request_len, uint8_t *reply, size_t cap)
{
	size_t n;

	(void)ctx;
	if (!serving->remote || !request || request_len < 2u || cap < 3u ||
	    request[0] != FZN_TYPES_VERSION_SHARED || request[1] != NCFG_NODE_TYPE_REQUEST) {
		return 0u;
	}
	n = serving->remote(serving->context, sender, contact, (const char *)request + 2,
	    request_len - 2u, (char *)reply + 2, cap - 2u);
	if (n == 0u) {
		return 0u;
	}
	reply[0] = FZN_TYPES_VERSION_SHARED;
	reply[1] = NCFG_NODE_TYPE_ANSWER;
	return n + 2u;
}

/* A call of `status` (fuzznet's sec 853): the arguments as text, the caller
 * as netcfgd's. fuzznet calls it only for an estate member or for a local
 * caller this node's permits let call. */
static size_t serve_status(void *ctx, const uint8_t *caller, const fzn_peer_t *from,
    const uint8_t *args, size_t args_len, uint8_t *answer, size_t cap)
{
	ncfg_peer_t peer;

	(void)ctx;
	if (!serving || !serving->call || (!caller && !from)) {
		return 0u;
	}
	if (!caller) {
		peer_of(from, &peer);
	}
	/* The most an answer may be, escaped, and still reach its caller, here
	 * or across hosts: fuzznet's own bound (its sec 863), which this
	 * computed as FZN_REPLY_MAX - 5 until fuzznet named it. */
	return serving->call(serving->context, NCFG_NODE_PROCEDURE_STATUS, caller,
	    caller ? NULL : &peer, (const char *)args, args_len, (char *)answer, cap,
	    FZN_DAEMON_CALL_ESCAPED_MAX);
}

/* A call of `ask` (0312): the same shape, its own name. */
static size_t serve_ask(void *ctx, const uint8_t *caller, const fzn_peer_t *from,
    const uint8_t *args, size_t args_len, uint8_t *answer, size_t cap)
{
	ncfg_peer_t peer;

	(void)ctx;
	if (!serving || !serving->call || (!caller && !from)) {
		return 0u;
	}
	if (!caller) {
		peer_of(from, &peer);
	}
	return serving->call(serving->context, NCFG_NODE_PROCEDURE_ASK, caller,
	    caller ? NULL : &peer, (const char *)args, args_len, (char *)answer, cap,
	    FZN_DAEMON_CALL_ESCAPED_MAX);
}

/* A call of `askpart` (10.695): a piece of a long request. Its answer is a
 * short line, so no escaped bound beyond the plain one. */
static size_t serve_ask_part(void *ctx, const uint8_t *caller, const fzn_peer_t *from,
    const uint8_t *args, size_t args_len, uint8_t *answer, size_t cap)
{
	ncfg_peer_t peer;

	(void)ctx;
	if (!serving || !serving->call || (!caller && !from)) {
		return 0u;
	}
	if (!caller) {
		peer_of(from, &peer);
	}
	return serving->call(serving->context, NCFG_NODE_PROCEDURE_ASK_PART, caller,
	    caller ? NULL : &peer, (const char *)args, args_len, (char *)answer, cap,
	    FZN_DAEMON_CALL_ESCAPED_MAX);
}

static const fzn_daemon_procedure_t procedures[] = {
	{ NCFG_NODE_PROCEDURE_STATUS, serve_status },
	{ NCFG_NODE_PROCEDURE_ASK, serve_ask },
	{ NCFG_NODE_PROCEDURE_ASK_PART, serve_ask_part },
};

static void serve_tick(void *ctx, uint64_t now)
{
	(void)ctx;
	(void)now;
	/* fuzznet's stop (its sec 835): after this pass, its socket closed and
	 * removed, `face` removed, the claim released, and `fzn_daemon_main`
	 * returns -- so the daemon's own shutdown runs after it, as after its
	 * own loop. */
	if (!stopped && serving->tick(serving->context)) {
		stopped = 1;
		fzn_daemon_stop();
	}
}

void ncfg_node_refuse_huge_pages(char *const *argv)
{
	fzn_daemon_refuse_huge_pages(argv);
}

size_t ncfg_node_local(const char *line, char *reply, size_t cap)
{
	return fzn_daemon_local(line, reply, cap);
}

ncfg_node_serve_t ncfg_node_serve(ncfg_node_t *node, const char *const *extra,
    size_t extra_count, char *const *restart_argv, const ncfg_node_loop_t *loop, char *err,
    size_t err_size)
{
	static fzn_daemon_ext_t ext;
	static char             dir_arg[NCFG_NODE_DIR_MAX + 16u];
	static char            *argv[3u + 32u + 1u];
	int                     argc = 0;
	int                     code;
	size_t                  at;

	if (serving || extra_count > 32u) {
		ncfg_error_set(err, err_size, serving ? "this process is already serving a node"
		    : "more than 32 fuzznet options");
		return NCFG_NODE_SERVE_ENDED;
	}
	/* Face or follower, whichever the claim makes this process: since
	 * fuzznet's 7d85b54 (its sec 838) a follower runs the extension too, so a
	 * daemon started beside a running fuzznetd still watches the network,
	 * and becomes the face, by restarting itself, when that one goes. */
	(void)snprintf(dir_arg, sizeof(dir_arg), "--fuzznet-dir=%s", node->dir);
	argv[argc++] = (char *)"netcfgd";
	argv[argc++] = dir_arg;
	for (at = 0; at < extra_count; at++) {
		argv[argc++] = (char *)extra[at];
	}
	argv[argc] = NULL;

	memset(&ext, 0, sizeof(ext));
	ext.fds = serve_fds;
	ext.ready = serve_ready;
	ext.tick = serve_tick;
	ext.local_from = serve_local_from;
	ext.remote = serve_remote;
	ext.procedures = procedures;
	ext.n_procedures = sizeof(procedures) / sizeof(procedures[0]);
	/* A join's restart, or a follower's on taking the claim, executes the
	 * daemon's own command line rather than the fuzznet options above. */
	ext.restart_argv = restart_argv;
	serving = loop;
	stopped = 0;
	if (loop->begin) {
		loop->begin(loop->context);
	}
	code = fzn_daemon_main(argc, argv, &ext);
	serving = NULL;
	if (loop->end) {
		loop->end(loop->context);
	}
	if (stopped) {
		return NCFG_NODE_SERVE_STOPPED;
	}
	ncfg_error_set(err, err_size, "fuzznet's loop ended with status %d", code);
	return NCFG_NODE_SERVE_ENDED;
}
