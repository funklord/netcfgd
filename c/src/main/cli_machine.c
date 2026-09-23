/*
 * cli_machine.c -- how `ncfg apply` reaches the machine.
 *
 * WHY THIS IS HERE AND NOT IN `src/cli/`
 *   `cli.h` declares the seam and says why: the library half of this program
 *   reads, and the one verb that changes something must not be able to do it
 *   by itself. So the implementation lives with the other code that touches
 *   the machine, and a test that installs nothing cannot apply at all.
 *
 * WHY IT IS THE DAEMON'S WORLD
 *   `ncfg_main_world_executor_open` already arranges every piece an apply
 *   needs: the apply lock with its patience, the netlink socket, the service
 *   context for the ops that are not netlink, the hooks a `hook.run` is
 *   checked against, the document the six link setters read and the secret
 *   resolver a key comes from. Composing a second arrangement of those here
 *   would be a second answer to "what can an executor do", and the two would
 *   drift in the direction that matters -- an op refused in one program and
 *   carried out in the other.
 *
 *   So this builds the same world, over the same machine paths the daemon
 *   spells, for the length of one apply. The difference from the daemon is the
 *   lifetime and nothing else: open to close is one plan rather than one pass
 *   of a loop.
 *
 * WHAT IT DOES NOT DO
 *   It does not reconcile, watch, serve or arm anything. `ncfg apply
 *   --confirm-within` is the daemon's, for the reason `run.c` gives: the
 *   window is a timer that outlives this process.
 */
#include "loop_internal.h"

#include "ncfg/base.h"
#include "ncfg/cli.h"
#include "ncfg/dhcp.h"
#include "ncfg/dns.h"
#include "ncfg/secrets.h"
#include "ncfg/supplicant.h"

#include <stdint.h>
#include <stdio.h>

#include <string.h>

/*
 * What one apply holds while it runs.
 *
 * The document and the observation are the caller's and are borrowed for the
 * length of the call; the state is a shim, because a world is opened over a
 * `ncfg_daemon_state_t` and this program has no daemon. Its three members are
 * the only ones an executor reads: where things are, what is wanted, and what
 * is there.
 */
typedef struct {
	ncfg_main_world_t       world;
	ncfg_daemon_state_t     state;
	ncfg_main_world_where_t where;
	ncfg_secret_resolver_t  secrets;
	char                    config_dir[NCFG_MAIN_LOOP_PATH_MAX];
	/* Room for the leaf this composes onto the configuration directory, so
	 * that a directory at the ceiling gives a truncated path rather than a
	 * compiler warning about one. */
	char                    secrets_dir[NCFG_MAIN_LOOP_PATH_MAX + 16];
	char                    certs_dir[NCFG_MAIN_LOOP_PATH_MAX + 16];
	/* The resolver file this invocation writes, which is the environment's
	 * where one is set. `dns.h` has why that matters more than it looks. */
	char                    resolv_conf[NCFG_MAIN_LOOP_PATH_MAX + 16];
	char                    dnsmasq_conf[NCFG_MAIN_LOOP_PATH_MAX + 16];
	char                    unbound_conf[NCFG_MAIN_LOOP_PATH_MAX + 16];
	int                     open;
} apply_world_t;

static apply_world_t the_world;

static int machine_executor_open(void *context, const char *config_dir, const char *run_dir,
    const ncfg_document_t *desired, const ncfg_observed_t *observed, ncfg_executor_t *out,
    char *err, size_t err_size)
{
	apply_world_t *held = context;

	(void)snprintf(held->config_dir, sizeof(held->config_dir), "%s",
	    config_dir ? config_dir : NCFG_CONFIG_DIR_DEFAULT);
	(void)snprintf(held->secrets_dir, sizeof(held->secrets_dir), "%s/secrets",
	    held->config_dir);
	(void)snprintf(held->certs_dir, sizeof(held->certs_dir), "%s/certs", held->config_dir);

	(void)memset(&held->state, 0, sizeof(held->state));
	(void)memset(&held->where, 0, sizeof(held->where));
	/*
	 * Cast away `const` for the state's two document members, which the
	 * daemon owns and this does not: nothing under an executor writes through
	 * them, and the alternative is a copy of a document per apply to satisfy a
	 * type. `ncfg_daemon_state_free` is never called on this shim, so nothing
	 * frees what it points at either.
	 */
	held->state.desired = (ncfg_document_t *)(uintptr_t)(const void *)desired;
	held->state.observed = (ncfg_observed_t *)(uintptr_t)(const void *)observed;
	held->state.paths.run = (char *)(uintptr_t)(const void *)run_dir;
	held->state.paths.config = held->config_dir;
	held->state.paths.factory = held->config_dir;

	/*
	 * The machine's own paths, spelled where the daemon spells them. Not
	 * `ncfg_service_machine`'s, which fills a service rather than a world --
	 * the world takes the same answers one layer up, and taking them here is
	 * what makes this executor the daemon's rather than a second one.
	 */
	held->where.run_dir = run_dir;
	held->where.proc_root = "/proc";
	held->where.supplicant_dir = NCFG_SUPPLICANT_CTRL_DIR;
	held->where.secrets_dir = held->secrets_dir;
	held->where.certs_dir = held->certs_dir;
	held->where.resolv_conf = ncfg_dns_resolve_conf_path(NULL, held->resolv_conf,
	    sizeof(held->resolv_conf));
	held->where.dnsmasq_conf = ncfg_dns_resolve_dnsmasq_path(NULL, held->dnsmasq_conf,
	    sizeof(held->dnsmasq_conf));
	held->where.unbound_conf = ncfg_dns_resolve_unbound_path(NULL, held->unbound_conf,
	    sizeof(held->unbound_conf));
	ncfg_dhcp_machine(&held->where.dhcp);

	if (!ncfg_main_world_open(&held->world, &held->where, &held->state, NULL, NULL, err,
	        err_size)) {
		return 0;
	}
	if (!ncfg_main_world_executor_open(&held->world, out, err, err_size)) {
		ncfg_main_world_close(&held->world);
		return 0;
	}
	held->open = 1;
	return 1;
}

static void machine_executor_close(void *context, ncfg_executor_t *executor)
{
	apply_world_t *held = context;

	if (!held->open) {
		return;
	}
	ncfg_main_world_executor_close(&held->world, executor);
	ncfg_main_world_close(&held->world);
	held->open = 0;
}

const ncfg_cli_machine_t *ncfg_main_cli_machine(void)
{
	static ncfg_cli_machine_t machine;

	(void)memset(&the_world, 0, sizeof(the_world));
	machine.context = &the_world;
	machine.executor_open = machine_executor_open;
	machine.executor_close = machine_executor_close;
	return &machine;
}
