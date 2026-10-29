/*
 * live_firewall.c -- send a configuration's firewall to the kernel, the way
 * the executor will, and nothing else.
 *
 * project.md 10.592 slice 2: the bytes `ncfg_nft_build_replace` writes are only
 * proved by a kernel taking them, and only read back honestly by something
 * that is not netcfgd. So `tests/live/firewall.sh` runs this in an unprivileged
 * user and network namespace -- which can hold an nftables table, measured --
 * and reads the result with `nft list ruleset`.
 *
 *     unshare -rn ./c/examples/live_firewall CONFIG_DIR
 *
 * Compiles CONFIG_DIR, builds the table's transaction with the firewall and
 * no NAT, and sends it as a fresh table (or as a replacement, with
 * `--replace`, after an earlier run). Exits 0 when the kernel accepted it, and
 * 1 with the reason otherwise. Writes nothing outside the namespace it runs
 * in, since netlink is the namespace's.
 */
#include "ncfg/config.h"
#include "ncfg/hooks.h"
#include "ncfg/lower.h"
#include "ncfg/netlink.h"
#include "ncfg/nft.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
	ncfg_config_sources_t sources;
	ncfg_lower_diags_t    diags;
	ncfg_document_t      *document;
	ncfg_netlink_t        socket;
	ncfg_netlink_reply_t  reply;
	ncfg_nft_batch_t      batch;
	ncfg_buf_t            transaction;
	char                  err[512];
	int                   replace = argc > 2 && strcmp(argv[2], "--replace") == 0;
	int                   ok;

	if (argc < 2) {
		fprintf(stderr, "usage: live_firewall CONFIG_DIR [--replace]\n");
		return 2;
	}
	memset(&sources, 0, sizeof(sources));
	memset(&diags, 0, sizeof(diags));
	if (!ncfg_config_load(argv[1], &sources, err, sizeof(err))) {
		fprintf(stderr, "live_firewall: %s\n", err);
		return 1;
	}
	document = ncfg_config_compile(&sources, ncfg_hook_sink_unwritten(), &diags, err,
	    sizeof(err));
	ncfg_config_sources_free(&sources);
	ncfg_lower_diags_free(&diags);
	if (!document) {
		fprintf(stderr, "live_firewall: %s\n", err);
		return 1;
	}
	ncfg_netlink_init(&socket);
	if (!ncfg_netlink_open_protocol(&socket, NCFG_NFT_NETLINK_PROTOCOL, 0, err, sizeof(err))) {
		fprintf(stderr, "live_firewall: %s\n", err);
		return 1;
	}
	ncfg_buf_init(&transaction, 0);
	ok = ncfg_nft_build_replace(&transaction, ncfg_netlink_take_seq(&socket), replace, NULL, 0,
	    document->firewall, &batch, err, sizeof(err));
	if (ok && !batch.empty) {
		memset(&reply, 0, sizeof(reply));
		ok = ncfg_netlink_send_batch(&socket, transaction.data, transaction.length,
		    batch.last_acked, &reply, err, sizeof(err));
		ncfg_netlink_reply_free(&reply);
	}
	if (!ok) {
		fprintf(stderr, "live_firewall: %s\n", err);
	}
	ncfg_buf_free(&transaction);
	ncfg_netlink_close(&socket);
	ncfg_document_free(document);
	return ok ? 0 : 1;
}
