/*
 * resolv.c -- whether the resolver file netcfgd delivered is still its own.
 *
 * WHAT THIS CLOSES, AND WHAT IT REPLACED
 *   `observed.dns` is netcfgd's record of what it delivered, and the planner
 *   reads it as "already applied". Nothing checked that the file still said
 *   so. While the record had no writer at all the question did not arise --
 *   the list was empty on every machine and every pass re-delivered, which
 *   corrected an overwritten `resolv.conf` by accident and cost a `dns.apply`
 *   for ever. The record has a writer now (project.md 10.205), so the accident
 *   is gone and this is what notices in its place.
 *
 * WHY IT CLEARS EVERYTHING RATHER THAN ONE SCOPE
 *   `resolv.conf` is written whole, from every scope at once: there is no
 *   line in it that belongs to one scope and not another. So "this file is not
 *   what netcfgd wrote" is a statement about the delivery, not about a scope,
 *   and reporting one scope as stale would be a guess about which one. The
 *   planner then plans one delivery, which rewrites the file whole -- the same
 *   repair either way.
 *
 * WHY ONLY ONE MODE
 *   netcfgd owns `/etc/resolv.conf` under `write_resolv_conf` and under no
 *   other mode. With `resolvconf`, `resolved`, `dnsmasq` or `unbound` the file
 *   is somebody else's to write, and a difference there is not drift netcfgd
 *   may correct -- it is the other daemon doing its job.
 */
#include "ncfg/observe.h"

#include "ncfg/base.h"
#include "ncfg/dns.h"
#include "observe_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* What the file should hold, from the scopes the record says were delivered.
 * NULL where it could not be rendered, which leaves the observation alone: a
 * comparison that could not be made is not a difference. */
static char *expected_text(const ncfg_observed_t *observed, char *err, size_t err_size)
{
	ncfg_dns_scope_t *scopes;
	ncfg_dns_flat_t   flat;
	char             *text;
	size_t            at;

	scopes = calloc(observed->dns_count, sizeof(*scopes));
	if (!scopes) {
		ncfg_error_set(err, err_size,
		    "there was no memory to work out what resolv.conf should hold");
		return NULL;
	}
	for (at = 0u; at < observed->dns_count; at++) {
		scopes[at].name = observed->dns[at].scope;
		scopes[at].policy = &observed->dns[at].policy;
	}
	if (!ncfg_dns_flatten(scopes, observed->dns_count, &flat, err, err_size)) {
		free(scopes);
		return NULL;
	}
	/*
	 * The same generator the delivery names. A second spelling here would make
	 * every comparison differ on the first line, which reads as a resolver
	 * somebody else overwrote and would have netcfgd rewrite it on every pass
	 * -- the failure this pass exists to notice, arrived at by causing it.
	 */
	text = ncfg_dns_resolv_conf(&flat, "netcfgd", err, err_size);
	ncfg_dns_flat_free(&flat);
	free(scopes);
	return text;
}

int ncfg_observe_resolv_currency(ncfg_observed_t *observed, const char *resolv_conf, char *err,
    size_t err_size)
{
	char  *expected;
	char  *actual;
	size_t at;
	int    owns = 0;

	if (!observed) {
		ncfg_error_set(err, err_size, "there is no observation to check the resolver of");
		return 0;
	}
	if (!resolv_conf || !resolv_conf[0] || observed->dns_count == 0u) {
		/* Nothing delivered, or nowhere named to compare against. Saying
		 * nothing is the answer in both cases: an observation that was given
		 * no path must not read the machine's own resolver. */
		return 1;
	}
	for (at = 0u; at < observed->dns_count; at++) {
		if (observed->dns[at].policy.mode.mode == NCFG_DNS_MODE_WRITE_RESOLV_CONF) {
			owns = 1;
			break;
		}
	}
	if (!owns) {
		return 1;
	}
	expected = expected_text(observed, err, err_size);
	if (!expected) {
		/* Reported and left alone: a render that failed is netcfgd not knowing
		 * what the file should say, which is not the same as the file being
		 * wrong. */
		return 0;
	}
	/*
	 * Read through the link rather than `lstat`-ing it, which is what makes a
	 * `resolv.conf` replaced by a symlink into another daemon's runtime state
	 * read as *different* rather than as an error -- and that state wants
	 * rewriting exactly as an edited file does.
	 */
	actual = observe_read_generated(resolv_conf);
	if (!actual || strcmp(actual, expected) != 0) {
		ncfg_applied_dns_free(observed->dns, observed->dns_count);
		observed->dns = NULL;
		observed->dns_count = 0;
	}
	free(actual);
	free(expected);
	return 1;
}
