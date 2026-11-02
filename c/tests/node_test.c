/*
 * node_test.c -- netcfgd's fuzznet node: where its store is, the identity made
 * once and found again, the claim taken to boot and given back, and the two
 * refusals that protect an identity (a named store that is not there, and a
 * store holding only part of one).
 *
 * The store is a real fuzznet file store in a scratch directory, and the
 * claim a real flock: a descriptor the test locks is a second open file
 * description, so netcfgd meets it exactly as it would meet a fuzznetd.
 */
#include "ncfg/node.h"

#include "ncfg/base.h"

#include "testdir.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

static int checks;
static int failures;

static void check(int condition, const char *what)
{
	checks++;
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static const char *base;

static int ends_with(const char *text, const char *tail)
{
	size_t length = strlen(text);
	size_t want = strlen(tail);

	return length >= want && strcmp(text + length - want, tail) == 0;
}

/* ------------------------------------------------------------------------ *
 * Where
 * ------------------------------------------------------------------------ */

static void where_the_store_is(void)
{
	char dir[NCFG_NODE_DIR_MAX];
	char err[NCFG_ERROR_MAX];
	char xdg[600];
	int  made = 1;

	err[0] = '\0';
	check(!ncfg_node_where("", 1, dir, &made, err, sizeof(err)) && !err[0],
	    "an empty --fuzznet-dir asks for no node, and that is not an error");
	check(ncfg_node_where("/srv/fuzznet", 0, dir, &made, err, sizeof(err)) &&
	        strcmp(dir, "/srv/fuzznet") == 0 && !made,
	    "a named store is used as named, on any run directory, and is never made");
	check(!ncfg_node_where(NULL, 0, dir, &made, err, sizeof(err)) && !err[0],
	    "a daemon on another run directory gets no default store: it is a test or a "
	    "second instance");

	(void)snprintf(xdg, sizeof(xdg), "%s/data", base);
	(void)setenv("XDG_DATA_HOME", xdg, 1);
	check(ncfg_node_where(NULL, 1, dir, &made, err, sizeof(err)) && made &&
	        strncmp(dir, xdg, strlen(xdg)) == 0 && ends_with(dir, "/fuzznet"),
	    "the machine's daemon keeps fuzznet's own default, $XDG_DATA_HOME/fuzznet");
	(void)unsetenv("XDG_DATA_HOME");
	(void)setenv("HOME", base, 1);
	check(ncfg_node_where(NULL, 1, dir, &made, err, sizeof(err)) &&
	        strncmp(dir, base, strlen(base)) == 0 && ends_with(dir, "/.local/share/fuzznet"),
	    "  or ~/.local/share/fuzznet, as fuzznetd would");
	(void)unsetenv("HOME");
	err[0] = '\0';
	check(ncfg_node_where(NULL, 1, dir, &made, err, sizeof(err)) &&
	        ends_with(dir, "/.local/share/fuzznet") && dir[0] == '/',
	    "  and with neither set, as a service starts, the account's home stands in");
}

/* ------------------------------------------------------------------------ *
 * The identity and the claim
 * ------------------------------------------------------------------------ */

/* Whether the store's claim can be taken now, as a fuzznetd would take it:
 * an exclusive flock on `<store>/claim`, which is all fuzznet's claim is
 * (`claim/claim_file.c`). The descriptor comes back held, or -1. */
static int take_claim(const char *store)
{
	char path[800];
	int  fd;

	(void)snprintf(path, sizeof(path), "%s/claim", store);
	fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0) {
		return -1;
	}
	if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
		(void)close(fd);
		return -1;
	}
	return fd;
}

static void one_identity_made_once(void)
{
	char         store[700];
	char         path[800];
	char         run[700];
	char         err[NCFG_ERROR_MAX];
	char         first[NCFG_NODE_KEY_HEX];
	char         second[NCFG_NODE_KEY_HEX];
	char         want[NCFG_NODE_KEY_HEX + 8u];
	char        *published;
	ncfg_node_t *node;
	ncfg_node_t *beside;
	int          face;

	(void)snprintf(store, sizeof(store), "%s/state/fuzznet", base);
	err[0] = '\0';
	node = ncfg_node_open(store, 1, err, sizeof(err));
	if (!node) {
		printf("  %s\n", err);
		check(0, "a node opens on a store that is not there yet, when it may make it");
		return;
	}
	check(ncfg_node_found(node) == NCFG_NODE_ALONE && ncfg_node_created(node),
	    "with nobody serving the store, the claim is taken and the identity made");
	check(testdir_mode(store) == 0700, "  in a directory only this user can read");
	ncfg_node_key_hex(ncfg_node_key(node), first);
	check(strspn(first, "0") != strlen(first), "  and the key is a key rather than zeroes");

	/*
	 * **The claim is free while netcfgd's node is open**, which is the whole
	 * of why it is given back: a fuzznetd started now must be able to become
	 * the face, or it follows a face that never answers. The first version
	 * kept the claim and this would have failed.
	 */
	face = take_claim(store);
	check(face >= 0, "the claim is given back: a fuzznetd started now can be the face");

	(void)snprintf(run, sizeof(run), "%s/run", base);
	testdir_mkdirp(run);
	check(ncfg_node_publish(node, run, err, sizeof(err)), "the node is published under /run");
	(void)snprintf(path, sizeof(path), "%s/node", run);
	published = testdir_read(path, NULL);
	(void)snprintf(want, sizeof(want), "key=%s\n", first);
	check(published && strstr(published, want) && strstr(published, "store=") &&
	        !strstr(published, "role="),
	    "  as key= and store= lines anybody can read with cat, and no role that would go "
	    "stale");
	free(published);

	if (face >= 0) {
		beside = ncfg_node_open(store, 0, err, sizeof(err));
		check(beside && ncfg_node_found(beside) == NCFG_NODE_BESIDE_FACE &&
		        !ncfg_node_created(beside),
		    "with another process the face, the identity is loaded and nothing made");
		if (beside) {
			ncfg_node_key_hex(ncfg_node_key(beside), second);
			check(strcmp(first, second) == 0,
			    "  and is the same node -- one store, one identity (fuzznet sec 827)");
			ncfg_node_close(beside);
		}
		(void)close(face);
	}

	ncfg_node_close(node);
	check(!testdir_exists(path), "closing the node takes its /run file away");
	node = ncfg_node_open(store, 0, err, sizeof(err));
	check(node && ncfg_node_found(node) == NCFG_NODE_ALONE && !ncfg_node_created(node),
	    "opened again, it loads the identity it made and makes nothing");
	if (node) {
		ncfg_node_key_hex(ncfg_node_key(node), second);
		check(strcmp(first, second) == 0, "  and it is the same key");
		ncfg_node_close(node);
	}
}

static void what_is_refused(void)
{
	char         store[700];
	char         part[800];
	char         err[NCFG_ERROR_MAX];
	ncfg_node_t *node;

	(void)snprintf(store, sizeof(store), "%s/nowhere/fuzznet", base);
	err[0] = '\0';
	node = ncfg_node_open(store, 0, err, sizeof(err));
	check(!node && strstr(err, "never made"),
	    "a named store that is not there is refused, rather than becoming a second node");
	ncfg_node_close(node);

	(void)snprintf(store, sizeof(store), "%s/partial", base);
	node = ncfg_node_open(store, 1, err, sizeof(err));
	ncfg_node_close(node);
	/* The anchor gone, which is the mixture a repair would get most wrong:
	 * self-rooting again would drop the node out of the estate it joined. */
	(void)snprintf(part, sizeof(part), "%s/1-h", store);
	check(node && testdir_exists(part) && unlink(part) == 0,
	    "a store's trust anchor is taken away");
	err[0] = '\0';
	node = ncfg_node_open(store, 0, err, sizeof(err));
	check(!node && strstr(err, "part of an identity") && strstr(err, "anchor absent"),
	    "  and the store holding the rest is refused by name, not repaired");
	ncfg_node_close(node);
	check(!testdir_exists(part), "  nor written: the anchor is not made again");
}

int main(void)
{
	const char *made = testdir_make("node");

	base = made;
	printf("== node_test in %s\n", base);
	where_the_store_is();
	one_identity_made_once();
	what_is_refused();
	testdir_remove(made);
	printf("node_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("node_test: all checks passed\n");
	} else {
		printf("node_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
