/*
 * strand.c -- secret material a plan walks away from and cannot take back.
 *
 * WHAT THIS IS NOT
 *   A refusal, which is an *action* a guard dropped and can name. Nothing is
 *   dropped here: `managed = false` already means netcfgd plans nothing for
 *   the device (0035), and the hazard is that absence continuing. Only
 *   credentials that **cannot be revoked from this host** get a notice, since
 *   one that fires for everything is one people learn to pass over (0042).
 *
 * WHY IT IS DRIVEN BY THE OBSERVATION AND NOT THE DOCUMENT
 *   Twice over. **The kernel is what decides whether a key is really there**:
 *   a document declaring one for an interface that was never applied strands
 *   nothing, and a notice about that would be a notice about a file. And a
 *   WireGuard interface whose block has been *deleted* while its `device`
 *   block still says `managed = false` still has the key loaded -- which the
 *   document no longer mentions at all.
 *
 *   It also means the rule has no second opinion about which links are
 *   WireGuard. `private_key_loaded` is set in one place, for links the kernel
 *   calls `wireguard` and no others; a `kind` check here would be a branch no
 *   test could make fail.
 *
 * WHY A CLEARING DEVICE IS NOT REPORTED
 *   `on_unmanage = "clear"` removes the link and the key with it, which is the
 *   answer this notice exists to point at. Reporting it as well would be
 *   reporting a hazard the operator has already dealt with.
 */
#include "plan_internal.h"

#include "ncfg/base.h"

#include <stdio.h>
#include <string.h>

void ncfg_plan_stranded_credentials(ncfg_builder_t *builder)
{
	size_t at;

	for (at = 0; at < builder->observed->link_count; at++) {
		const ncfg_observed_link_t *link = &builder->observed->links[at];
		ncfg_stranded_t    stranded;
		char               credential[NCFG_ERROR_MAX];
		char               remove_with[NCFG_ERROR_MAX];
		char               consent_with[NCFG_ERROR_MAX];

		if (!link->name || !link->private_key_loaded) {
			continue;
		}
		/* Only a device the document is walking away from. */
		if (!ncfg_plan_names(builder->unmanaged, builder->unmanaged_count, link->name) ||
		    ncfg_plan_clearing(builder, link->name)) {
			continue;
		}
		if (builder->options &&
		    ncfg_plan_names(builder->options->strand_credentials,
		        builder->options->strand_credentials_count, link->name)) {
			continue;
		}
		(void)snprintf(credential, sizeof(credential),
		    "a WireGuard private key, loaded in the kernel on `%s` and readable there "
		    "by root", link->name);
		(void)snprintf(remove_with, sizeof(remove_with),
		    "device %s { managed = false; on_unmanage = \"clear\" }", link->name);
		(void)snprintf(consent_with, sizeof(consent_with),
		    "ncfg apply --strand-credentials %s", link->name);

		memset(&stranded, 0, sizeof(stranded));
		stranded.interface = link->name;
		stranded.credential = credential;
		stranded.irrevocable =
		    "its authority is the matching public key in every peer's configuration, so "
		    "withdrawing it means changing each of them -- netcfgd cannot, and the "
		    "machines may not be yours";
		stranded.remove_with = remove_with;
		stranded.consent_with = consent_with;
		ncfg_plan_strand(builder->plan, &stranded);
	}
}
