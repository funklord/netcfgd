/*
 * node.h -- netcfgd as a fuzznet node: its identity, from a fuzznet store.
 *
 * WHY THE DAEMON IS A NODE AT ALL
 *   0308: fuzznet is linked into netcfgd, and all peer networking and IPC is
 *   fuzznet's. A node is an identity -- an Ed25519 key, the agree secret
 *   behind its sessions, and the anchor it trusts -- kept in a store, and
 *   everything later (records, remote access, the local socket of 0309)
 *   speaks as it. This module is the first of those: the store opened, the
 *   claim taken, the identity loaded or made.
 *
 * ONE STORE, ONE IDENTITY, ONE WRITER (fuzznet sec 827)
 *   The holder wants fuzznetd and netcfgd able to run at once on one machine,
 *   "delegating and lock-writing the same files". fuzznet's answer is the
 *   claim it already has: the first process to take a store's `claim` is its
 *   FACE and alone writes; any other is a FOLLOWER, which reads the store and
 *   forwards writes to the face over the socket the face names in `face`. So
 *   two processes sharing files are one node.
 *
 * NETCFGD HOLDS THE CLAIM ONLY WHILE IT BOOTS
 *   A face serves the store -- its socket, the rounds that carry records to
 *   the estate -- and that loop is fuzznetd's; netcfgd does not run it yet.
 *   Holding the claim for good would make a fuzznetd started afterwards a
 *   follower forwarding every client to a face that never answers, which is
 *   fuzznetd broken by netcfgd starting first. So the claim is taken to load
 *   or make the identity, which only a face may make, and released at once:
 *   a fuzznetd following retries it every second and becomes the face. When
 *   netcfgd runs the node loop itself it will keep the claim it takes.
 *
 * WHERE THE STORE IS
 *   fuzznet's own default for the user running it (`fzn_cli_default_dir`,
 *   `$XDG_DATA_HOME/fuzznet` or `~/.local/share/fuzznet`), so a fuzznetd and
 *   a netcfgd started as root on a router meet in one store without either
 *   being told. A service is often started with neither variable set; the
 *   account's home from the password database stands in for `$HOME` then,
 *   which is where a fuzznetd run from that account's shell looks.
 *   `ncfg_node_where` decides it; project.md 10.669 has the reasons.
 *
 * WHAT A FAILURE COSTS
 *   Nothing on the network. A node that cannot open is logged and the daemon
 *   runs without one: networking may never wait on the peer layer.
 */
#ifndef NCFG_NODE_H
#define NCFG_NODE_H

#include <stddef.h>
#include <stdint.h>

/* An Ed25519 public key. */
#define NCFG_NODE_KEY_LEN 32u
/* A store's path, and the key as hex with its terminator. */
#define NCFG_NODE_DIR_MAX 1024u
#define NCFG_NODE_KEY_HEX (NCFG_NODE_KEY_LEN * 2u + 1u)

/* Where a daemon's store is named from: `--fuzznet-dir`, then this. */
#define NCFG_FUZZNET_DIR_ENV "NCFG_FUZZNET_DIR"

/* What netcfgd found when it opened the store -- a moment, not a standing
 * role, since the claim is not kept. */
typedef enum {
	/* No process held the claim: netcfgd took it, booted, released it. */
	NCFG_NODE_ALONE,
	/* Another process is the face; the identity was loaded from its store. */
	NCFG_NODE_BESIDE_FACE
} ncfg_node_found_t;

typedef struct ncfg_node ncfg_node_t;

/*
 * Which store a daemon keeps, into `out`: 1 with a path, 0 for none.
 *
 * `named` is `--fuzznet-dir` or the environment's, and is used as given; an
 * empty one asks for no node at all. With none named, fuzznet's default --
 * but **only for a daemon on the default run directory**, the one that is
 * the machine's network manager. A daemon on another run directory is a test
 * or a second instance, and the default would hand it the operator's own
 * identity, or the claim on a running fuzznetd's store; it gets no node
 * unless one is named. `*made` says whether the path is the default, which
 * is the one this module may create.
 */
int ncfg_node_where(const char *named, int default_run_dir, char out[NCFG_NODE_DIR_MAX],
    int *made, char *err, size_t err_size);

/*
 * Open the store at `dir` and load its identity -- or, with the claim free and
 * the store holding none, take the claim, make one, and release it. `make_dir`
 * creates `dir` (0700, and its parents) when it is absent; a named directory
 * is never made, so a mistyped one is refused rather than becoming a second
 * node. The claim is not held when this returns.
 *
 * NULL with a sentence in `err`. A store holding some parts of an identity and
 * not others is refused by name and left alone, which is fuzznet's rule: the
 * repair is the operator's, made with the files in front of them.
 */
ncfg_node_t *ncfg_node_open(const char *dir, int make_dir, char *err, size_t err_size);

const uint8_t     *ncfg_node_key(const ncfg_node_t *node);
ncfg_node_found_t  ncfg_node_found(const ncfg_node_t *node);
const char        *ncfg_node_dir(const ncfg_node_t *node);
/* Whether this open made the identity, which is the event an operator most
 * needs to be able to find afterwards. */
int              ncfg_node_created(const ncfg_node_t *node);

/* The key as lowercase hex, into `out`. */
void ncfg_node_key_hex(const uint8_t key[NCFG_NODE_KEY_LEN], char out[NCFG_NODE_KEY_HEX]);

/* What `<run>/node` holds: `key` and `store`, one `name=value` a line, for
 * `ncfg status` and for anybody with `cat`. No role: which process serves the
 * store can change after netcfgd opens it. Closing the node removes it. */
int ncfg_node_publish(ncfg_node_t *node, const char *run_dir, char *err, size_t err_size);

void ncfg_node_close(ncfg_node_t *node);

/*
 * SERVING THE STORE: netcfgd as its face, inside fuzznet's loop (project.md
 * 10.676, the holder's "in-loop"). One loop owns the process's descriptors
 * (fuzznet sec 831), so the daemon's own is not run: `loop` is asked for its
 * descriptors each pass of the node's, told which are readable, and ticked
 * after the pass. `tick` answers nonzero once the daemon is stopping;
 * fuzznet's loop then ends after that pass, and `ncfg_node_serve` returns.
 */
typedef struct {
	void   *context;
	/* Called once this process is to be the face, just before fuzznet's loop
	 * starts, and `end` once that loop has ended by itself. Either may be NULL. */
	void   (*begin)(void *context);
	void   (*end)(void *context);
	size_t (*fds)(void *context, int *out, size_t cap);
	void   (*ready)(void *context, int fd);
	int    (*tick)(void *context);
} ncfg_node_loop_t;

/* How a serve ended. */
typedef enum {
	/* `tick` asked to stop and the node's loop was left. */
	NCFG_NODE_SERVE_STOPPED,
	/* fuzznet's loop returned on its own -- refused to start, or an identity
	 * reset -- and the caller carries on with its own loop. */
	NCFG_NODE_SERVE_ENDED
} ncfg_node_serve_t;

/* `extra` are fuzznet's own node options, passed as given (`--fuzznet-arg`),
 * after `--fuzznet-dir` naming this node's store; `restart_argv`, NULL-ended,
 * is what a restart after a join executes -- the daemon's own command line.
 * `err` says why where the answer is not STOPPED. */
ncfg_node_serve_t ncfg_node_serve(ncfg_node_t *node, const char *const *extra,
    size_t extra_count, char *const *restart_argv, const ncfg_node_loop_t *loop, char *err,
    size_t err_size);

/* A line asked of this node in-process, as its own user (fuzznet's
 * `fzn_daemon_local`): the reply's length with its newline, or 0 where the node
 * is not serving. Only from the loop's `tick`. */
size_t ncfg_node_local(const char *line, char *reply, size_t cap);

#endif /* NCFG_NODE_H */
