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
 *
 *     unshare -rn ./c/examples/live_firewall --read
 *
 * Dumps netcfgd's table and prints each kernel rule as the decoder (0295 A)
 * read it, one per line, with whether the digest recomputed from what was
 * read is the one in its comment -- which, for a rule written with one value
 * per match, says the decoder and the writer agree.
 */
#include "ncfg/config.h"
#include "ncfg/hooks.h"
#include "ncfg/lower.h"
#include "ncfg/netlink.h"
#include "ncfg/nft.h"

#include "ncfg/sha256.h"

#include <stdio.h>
#include <string.h>

/* Print one kernel rule, and whether its digest is recomputed from it. */
static void print_rule(const ncfg_nft_kernel_rule_t *one)
{
	static const char *const words[] = { "new", "established", "related", "invalid" };
	static const char *const actions[] = { "accept", "drop", "reject" };
	ncfg_firewall_rule_t     rule;
	int64_t                  port = one->port;
	char                    *from = (char *)one->from;
	char                    *to = (char *)one->to;
	char                    *mac = (char *)one->mac;
	char                    *states[4];
	size_t                   state_count = 0;
	size_t                   at;
	ncfg_buf_t               text;
	char                     digest[NCFG_SHA256_HEX_SIZE];

	for (at = 0; at < 4u; at++) {
		if (one->states & (1u << at)) {
			states[state_count++] = (char *)words[at];
		}
	}
	memset(&rule, 0, sizeof(rule));
	rule.name = (char *)one->name;
	rule.action = one->action;
	rule.protocol = one->protocol;
	rule.ports = one->has_port ? &port : NULL;
	rule.port_count = one->has_port ? 1u : 0u;
	rule.from = one->from[0] ? &from : NULL;
	rule.from_count = one->from[0] ? 1u : 0u;
	rule.to = one->to[0] ? &to : NULL;
	rule.to_count = one->to[0] ? 1u : 0u;
	rule.interface = one->interface[0] ? (char *)one->interface : NULL;
	rule.states = state_count ? states : NULL;
	rule.state_count = state_count;
	rule.mac = one->mac[0] ? &mac : NULL;
	rule.mac_count = one->mac[0] ? 1u : 0u;
	ncfg_buf_init(&text, 0);
	(void)ncfg_nft_firewall_rule_text(one->chain, &rule, &text);
	ncfg_sha256_hex(text.data, text.length, digest);
	ncfg_buf_free(&text);

	printf("%s %s %s protocol=%d", one->chain, one->name,
	    actions[one->action >= 0 && one->action < 3 ? one->action : 0], one->protocol);
	if (one->has_port) {
		printf(" port=%u", (unsigned)one->port);
	}
	if (one->from[0]) {
		printf(" from=%s", one->from);
	}
	if (one->to[0]) {
		printf(" to=%s", one->to);
	}
	if (one->interface[0]) {
		printf(" interface=%s", one->interface);
	}
	for (at = 0; at < state_count; at++) {
		printf(" state=%s", states[at]);
	}
	if (one->mac[0]) {
		printf(" mac=%s", one->mac);
	}
	printf(" digest=%s\n",
	    strncmp(digest, one->digest, NCFG_NFT_DIGEST_HEX) == 0 ? "recomputed" : "other");
}

/* Dump netcfgd's table and print what the decoder reads. */
static int read_back(void)
{
	ncfg_netlink_t       socket;
	ncfg_netlink_reply_t reply;
	ncfg_buf_t           message;
	char                 err[512];
	uint32_t             seq;
	size_t               at;
	int                  ok;

	ncfg_netlink_init(&socket);
	if (!ncfg_netlink_open_protocol(&socket, NCFG_NFT_NETLINK_PROTOCOL, 0, err, sizeof(err))) {
		fprintf(stderr, "live_firewall: %s\n", err);
		return 1;
	}
	seq = ncfg_netlink_take_seq(&socket);
	memset(&reply, 0, sizeof(reply));
	ncfg_buf_init(&message, 0);
	ok = ncfg_nft_build_table_rule_dump(&message, seq, err, sizeof(err)) &&
	    ncfg_netlink_send_batch(&socket, message.data, message.length, seq, &reply, err,
	        sizeof(err));
	for (at = 0; ok && at < reply.count; at++) {
		ncfg_nft_kernel_rule_t one;
		char                   why[512];

		if (ncfg_nft_firewall_rule_read(reply.items[at].bytes, reply.items[at].length, &one,
		        why, sizeof(why))) {
			print_rule(&one);
		} else {
			printf("refused %s\n", why);
		}
	}
	if (!ok) {
		fprintf(stderr, "live_firewall: %s\n", err);
	}
	ncfg_netlink_reply_free(&reply);
	ncfg_buf_free(&message);
	ncfg_netlink_close(&socket);
	return ok ? 0 : 1;
}

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
		fprintf(stderr, "usage: live_firewall CONFIG_DIR [--replace] | --read\n");
		return 2;
	}
	if (strcmp(argv[1], "--read") == 0) {
		return read_back();
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
