/*
 * live_association.c -- what a live observation makes of each link's wifi
 * association, from the C port.
 *
 * The counterpart of `crates/netcfgd-host/examples/live_association.rs`, and it
 * exists because `tests/live/association.sh` compares two paths through **one**
 * implementation: `ncfg wifi status` resolves the association through the
 * control socket, and this resolves it through the observation path. They share
 * only `network_for`, so agreement is evidence the wiring is right and a
 * disagreement names which side is wrong.
 *
 * **Which is why a Rust probe could not stand in for this one.** With the C
 * daemon installed, pointing that script at the Rust example compares the C's
 * socket path against the Rust's observation path -- so a disagreement no
 * longer says which side is wrong, only that two programs differ. The script
 * looks for `$build/examples/live_association`, and after 0266 `$build` is
 * `c/`, so before this there was nothing there to find.
 *
 * **Read-only, and deliberately the daemon's own path rather than a shortcut to
 * the interesting function.** It reads the document netcfgd is running and
 * calls `ncfg_observe_current`, which is the call a reconcile pass makes. A
 * probe that called `ncfg_supplicant_associated` directly would prove the
 * function and say nothing about whether the observation is wired to it, which
 * is the half that has actually been wrong before.
 *
 * It writes nothing. `ncfg_observe_current` reads netlink, sysfs and the
 * supplicant's control socket; persisting an observation is the caller's job.
 * Running it beside a live daemon adds one reader and no writer.
 *
 * Needs root, because the supplicant's control socket is `root:root` with no
 * write bit for anybody else -- and without being able to connect, the
 * association read reports "not associated" for a radio that is. That failure
 * is silent, which is why this refuses rather than reporting it as a result.
 *
 *     make -C c examples
 *     sudo ./c/examples/live_association
 *
 * One line per link, tab separated: name, whether it is a radio, and the
 * configured network it is associated to (`-` for none). The same three columns
 * in the same order as the Rust probe, because `association.sh` reads column
 * three of the row whose column one is the interface.
 */
#include "ncfg/config.h"
#include "ncfg/dns.h"
#include "ncfg/document.h"
#include "ncfg/observe.h"
#include "ncfg/observed.h"
#include "ncfg/secrets.h"
#include "ncfg/state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROBE_PATH_MAX 4096u

/*
 * The document netcfgd compiled, as it wrote it out.
 *
 * Read from `/run` rather than recompiled from `/etc`, so this sees what the
 * running daemon is actually working from -- a tree edited since the last apply
 * would otherwise give this probe a different document from the one the
 * association is being resolved against.
 */
static ncfg_document_t *read_document(const char *run_dir, char *err, size_t err_size)
{
	char             path[PROBE_PATH_MAX];
	char            *text;
	long             length;
	size_t           got;
	FILE            *file;
	ncfg_document_t *document;

	if ((size_t)snprintf(path, sizeof(path), "%s/desired.json", run_dir) >= sizeof(path)) {
		ncfg_error_set(err, err_size, "the run directory's name is too long");
		return NULL;
	}
	/*
	 * Plain stdio rather than `ncfg_host_read_file`, which is in
	 * `src/host/host_internal.h`: an example is a caller from outside the
	 * library and reaching into an internal header would make this the one
	 * program that does. The file is a document netcfgd wrote, so its size is
	 * the library's problem rather than this reader's -- `ncfg_document_read`
	 * refuses anything it cannot represent.
	 */
	file = fopen(path, "rb");
	if (!file) {
		ncfg_error_set(err, err_size, "cannot read %s", path);
		return NULL;
	}
	if (fseek(file, 0L, SEEK_END) != 0 || (length = ftell(file)) < 0 ||
	    fseek(file, 0L, SEEK_SET) != 0) {
		ncfg_error_set(err, err_size, "cannot measure %s", path);
		(void)fclose(file);
		return NULL;
	}
	text = malloc((size_t)length + 1u);
	if (!text) {
		ncfg_error_set(err, err_size, "out of memory reading %s", path);
		(void)fclose(file);
		return NULL;
	}
	got = fread(text, 1u, (size_t)length, file);
	(void)fclose(file);
	if (got != (size_t)length) {
		ncfg_error_set(err, err_size, "%s ended early", path);
		free(text);
		return NULL;
	}
	text[got] = '\0';
	document = ncfg_document_read(text, got, err, err_size);
	free(text);
	return document;
}

int main(int argc, char **argv)
{
	const char            *run_dir = argc > 1 ? argv[1] : NCFG_RUN_DIR_DEFAULT;
	ncfg_observe_roots_t   roots;
	ncfg_secret_resolver_t secrets;
	char                   secrets_dir[PROBE_PATH_MAX];
	char                   config_dir[PROBE_PATH_MAX];
	ncfg_document_t       *document;
	ncfg_observed_t       *observed = NULL;
	char                   err[NCFG_ERROR_MAX];
	size_t                 at;

	/*
	 * The supplicant's socket refuses a connection from anybody but root, and
	 * a refused connection is indistinguishable from an unassociated radio in
	 * the result. Refusing up front is the difference between "no association"
	 * and "this probe could not have seen one".
	 *
	 * `geteuid` rather than reading `/proc/self/status`, which is what the Rust
	 * does to avoid libc for one call; C has the call.
	 */
	if (geteuid() != 0) {
		(void)fprintf(stderr,
		    "live_association: needs root: the supplicant control socket is root-only,\n");
		(void)fprintf(stderr,
		    "live_association:   and without it every radio reads as unassociated\n");
		return 2;
	}

	err[0] = '\0';
	document = read_document(run_dir, err, sizeof(err));
	if (!document) {
		(void)fprintf(stderr, "live_association: %s\n", err);
		return 2;
	}

	err[0] = '\0';
	if (!ncfg_observe_roots_default(&roots, err, sizeof(err))) {
		(void)fprintf(stderr, "live_association: %s\n", err);
		ncfg_document_free(document);
		return 2;
	}
	/* The resolver file, which `ncfg_observe_roots_default` leaves empty for
	 * the reason `run.c` gives where it does the same: the path is the DNS
	 * backend's to name, not the observer's. */
	(void)ncfg_dns_resolve_conf_path(NULL, roots.resolv_conf, sizeof(roots.resolv_conf));

	/*
	 * The secret store, resolved the way `ncfg` resolves it, because without it
	 * `key_matches` and the passphrase digests come back unanswered -- and an
	 * unanswered question is not what this probe is for. A directory name that
	 * does not fit leaves the resolver absent, which is honest rather than
	 * wrong.
	 */
	memset(&secrets, 0, sizeof(secrets));
	(void)ncfg_config_resolve_dir(NULL, config_dir, sizeof(config_dir));
	if (config_dir[0] != '\0' &&
	    (size_t)snprintf(secrets_dir, sizeof(secrets_dir), "%s/secrets", config_dir) <
	        sizeof(secrets_dir)) {
		secrets.secrets_dir = secrets_dir;
	}

	/*
	 * Said out loud, as the Rust probe says its backend count: this reads the
	 * ownership record out of `run_dir`, and `ncfg_observe_supplicants` only
	 * asks a supplicant netcfgd believes it started. Pointed at an empty run
	 * directory every radio reads as unassociated for a reason that has nothing
	 * to do with the code under test, and the line below is what makes that
	 * visible rather than a mystery.
	 */
	(void)fprintf(stderr, "live_association: observing against %s\n", run_dir);

	err[0] = '\0';
	if (!ncfg_observe_current(run_dir, &roots, secrets.secrets_dir ? &secrets : NULL, document,
	        &observed, err, sizeof(err))) {
		(void)fprintf(stderr, "live_association: cannot observe: %s\n", err);
		ncfg_document_free(document);
		return 2;
	}

	for (at = 0; at < observed->link_count; at++) {
		const ncfg_observed_link_t *link = &observed->links[at];

		(void)printf("%s\t%s\t%s\n", link->name ? link->name : "?",
		    link->wireless ? "radio" : "wired", link->network ? link->network : "-");
	}

	ncfg_observed_free(observed);
	ncfg_document_free(document);
	return 0;
}
