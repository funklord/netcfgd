/*
 * nft.h -- nftables over `NETLINK_NETFILTER`: one table, NAT, and nothing
 * else.
 *
 * **Bytes in, structures out, and no socket anywhere**, which is wire.h's
 * split: everything here builds a transaction into a buffer or reads a dump
 * payload the caller already has.
 *
 * THE WHOLE LICENCE THIS MODULE HAS
 *   Decision 0022: **netcfgd may own exactly one nftables table, named
 *   `netcfgd`, containing NAT and nothing else.** It replaces that table
 *   wholesale on every apply and never writes to or deletes any other. The
 *   reason the rule is stated as an invariant rather than as a default is
 *   container runtimes: Docker, podman and libvirt insert rules into their own
 *   tables as containers come and go, and a netcfgd that touched what it did
 *   not recognise would break every container host intermittently, depending on
 *   what happened to be running when the apply landed.
 *
 *   **NAT, never filtering.** netcfgd translates addresses because address
 *   translation is addressing; it does not filter packets, because filtering is
 *   security policy and netcfgd has no model of risk. The practical test is
 *   whether a rule's content is derivable from the addressing already in the
 *   document: masquerade on the interface marked as the uplink is, and `accept
 *   tcp dport 22` is not and never will be.
 *
 * HOW THAT IS ENFORCED HERE, RATHER THAN PROMISED
 *   Three things, and the third is the one that would survive a mistake in the
 *   first two:
 *
 *     * **No call in this header takes a table or chain name.** There is no
 *       argument a caller could pass to reach another table; `NCFG_NFT_TABLE`
 *       and `NCFG_NFT_CHAIN` are the only two names written, and they are
 *       constants.
 *     * **Every read refuses a payload from another table.** The kernel's dump
 *       filter is asked to return only netcfgd's rules and is not trusted to
 *       have done it -- see `ncfg_nft_rule_uplink`.
 *     * **The assembled transaction is audited as bytes before it is handed
 *       back.** `ncfg_nft_build_replace_nat` builds privately, walks what it
 *       built with `ncfg_nft_writes_only_our_table`, and appends nothing to the
 *       caller's buffer if any message in it names anything else. A rule about
 *       what the code intends is a rule nobody checked; this one is checked
 *       against the artifact.
 *
 *   Reading another table is deliberately *not* refused, and that is not a
 *   hole. 0022 requires netcfgd to detect a second table doing source NAT at
 *   the same hook -- which double-translates -- and report it. Detecting it
 *   means dumping every table and every chain. Reporting is all that ever
 *   happens: deleting somebody's table to resolve a NAT conflict would trade a
 *   working firewall for working NAT, silently, and that is not a trade a
 *   network daemon makes on an operator's behalf.
 *
 * TWO WAYS THIS PROTOCOL DIFFERS FROM RTNETLINK, BOTH SILENT WHEN GOT WRONG
 *   **Integers are big-endian.** rtnetlink attributes carry the host's byte
 *   order and nftables attributes do not. A chain priority sent native-endian
 *   is accepted and the chain sits at 1677721600 instead of 100. wire.h says
 *   there is no `ntohl` anywhere in that file and one would be a bug; here the
 *   opposite holds, and every integer attribute this module writes or reads
 *   goes through a byte-order conversion on purpose.
 *
 *   **Changes are transactional.** A modification is a run of messages between
 *   a batch-begin and a batch-end, applied all or nothing. A `NEWRULE` sent on
 *   its own does not fail -- the kernel ignores it, because it was not inside a
 *   transaction. One failure rolls the whole thing back, so the previous table
 *   survives a bad apply.
 *
 * NO ALLOCATION, SO NO FREE
 *   Every aggregate below is fixed-size and the caller owns it.
 */
#ifndef NCFG_NFT_H
#define NCFG_NFT_H

#include <stddef.h>
#include <stdint.h>

#include "ncfg/base.h"
#include "ncfg/buf.h"

/* The one table netcfgd owns, and the one chain in it. Decision 0022. */
#define NCFG_NFT_TABLE "netcfgd"
#define NCFG_NFT_CHAIN "postrouting"

/*
 * `NETLINK_NETFILTER`, the protocol a socket for this module is opened with.
 *
 * Published here because it is the one fact about nftables that lives outside
 * the bytes, and the socket module has to know it. Written out rather than
 * included, so that a caller of this header is not handed the whole netfilter
 * vocabulary along with it; nft.c proves the number against
 * `linux/netlink.h` at compile time.
 */
#define NCFG_NFT_NETLINK_PROTOCOL 12

/*
 * `NFT_NAME_MAXLEN`, the longest a table or chain name can be, and the size of
 * the buffer one is read into. Written out and proved in nft.c, as above.
 */
#define NCFG_NFT_NAME_MAX 256u

/*
 * How long an interface name in a masquerade rule can be.
 *
 * `IFNAMSIZ`, and also `NFT_REG_SIZE` -- the two are the same 16 and the
 * second is why: `meta oifname` loads the name into one register and the
 * comparison is against those 16 bytes, so a longer name has no expressible
 * rule at all rather than a truncated one. nft.c proves this against the
 * kernel's `NFT_REG_SIZE`, which is the half that can be checked without
 * pulling `linux/if.h` into everything that includes this header.
 */
#define NCFG_NFT_IFNAME_MAX 16u

/* `sizeof(struct nfgenmsg)`: the family, a version byte and a big-endian
 * `res_id`, in front of every nftables message's attributes. */
#define NCFG_NFT_NFGENMSG_LEN 4u

/* A table the kernel currently holds. */
typedef struct {
	/* Address family, as `NFPROTO_*`. Part of a table's identity: `inet
	 * netcfgd` and `ip netcfgd` are two different tables. */
	uint8_t family;
	char    name[NCFG_NFT_NAME_MAX];
} ncfg_nft_table_t;

/* A chain, and enough about it to tell whether it does NAT. */
typedef struct {
	/* Which table it belongs to. */
	char     table[NCFG_NFT_NAME_MAX];
	char     name[NCFG_NFT_NAME_MAX];
	/* Its type where it is a base chain: `filter`, `nat`, `route`. Empty
	 * where it is a regular chain, which has neither a type nor a hook. */
	char     kind[NCFG_NFT_NAME_MAX];
	/* Which hook it registers at, where it is a base chain. */
	uint32_t hook;
	int      has_hook;
} ncfg_nft_chain_t;

/*
 * What one transaction used, so the caller can wait for the right reply.
 *
 * `last_acked` is the last message *inside* the transaction that asked for an
 * acknowledgement, and it is deliberately not the batch-end marker: the kernel
 * acknowledges the contents of a transaction and says nothing about its end,
 * so a reply loop waiting for the end waits for the timeout instead.
 */
typedef struct {
	uint32_t last_acked;
	/* One past the last sequence number the transaction used. */
	uint32_t next_seq;
	/* **Nothing was built and nothing must be sent.** There was no table to
	 * remove and none to create, so the transaction would be a begin and an
	 * end with no contents -- which asks for no acknowledgement, receives no
	 * reply, and leaves a reply loop waiting for a message the kernel was
	 * never going to send. */
	int      empty;
} ncfg_nft_batch_t;

/* ------------------------------------------------------------------------ *
 * Building requests
 * ------------------------------------------------------------------------ */

/* Every table the kernel holds, in every family, and every chain with enough
 * detail to tell what it hooks. Both dumps read outside netcfgd's table on
 * purpose: they are the conflict check of 0022 and they only ever report. */
int ncfg_nft_build_table_dump(ncfg_buf_t *out, uint32_t seq, char *err, size_t err_size);
int ncfg_nft_build_chain_dump(ncfg_buf_t *out, uint32_t seq, char *err, size_t err_size);

/* The rules in netcfgd's own chain, which is the observation half of the
 * reconciliation: what the kernel holds, in the same shape as what the
 * document asks for, so the two can be compared without either side knowing
 * how a rule is encoded. `ENOENT` in the reply means the table does not exist,
 * which is not an error -- no table is no uplinks. */
int ncfg_nft_build_rule_dump(ncfg_buf_t *out, uint32_t seq, char *err, size_t err_size);

/*
 * Replace netcfgd's table with one masquerading each named interface.
 *
 * The whole table goes and comes back inside one transaction, so there is no
 * moment where a packet could be translated by half a configuration. An empty
 * `uplinks` removes the table and puts nothing back, which is how a document
 * that stops asking for NAT is honoured -- and rules an operator added by hand
 * inside netcfgd's table go with it, exactly as an address netcfgd owns is
 * removed when the document stops asking for it. That is what owning a table
 * means, and it is ordinary reconciliation rather than special machinery.
 *
 * `table_exists` says whether `inet netcfgd` is currently there, from a table
 * dump the caller has already read. The delete is conditional on it because
 * deleting a table that is not there is `ENOENT`, and one failure aborts the
 * whole transaction -- so the error would not be "no table", it would be "no
 * NAT".
 *
 * Nothing is appended to `out` unless the finished transaction passes
 * `ncfg_nft_writes_only_our_table`.
 */
int ncfg_nft_build_replace_nat(ncfg_buf_t *out, uint32_t first_seq, int table_exists,
    const char *const *uplinks, size_t uplink_count, ncfg_nft_batch_t *batch,
    char *err, size_t err_size);

/*
 * Whether every nftables message in `bytes` that would *change* something
 * names netcfgd's own table and chain.
 *
 * This is decision 0022 written as a check rather than as a comment, and it is
 * public because a test asserts it directly on messages this module would
 * never build -- which is the only way to show that the refusal is real and
 * not just absent input.
 *
 * A message type this module does not write is refused outright, rather than
 * inspected for a table name it might not carry: the set of things netcfgd
 * sends is closed, and a set-element or flowtable message arriving here means
 * something upstream is doing more than NAT.
 */
int ncfg_nft_writes_only_our_table(const void *bytes, size_t length, char *err,
    size_t err_size);

/* ------------------------------------------------------------------------ *
 * Reading replies
 * ------------------------------------------------------------------------ */

/* One entry of a table dump. */
int ncfg_nft_table_read(const void *payload, size_t length, ncfg_nft_table_t *out,
    char *err, size_t err_size);
/* One entry of a chain dump. */
int ncfg_nft_chain_read(const void *payload, size_t length, ncfg_nft_chain_t *out,
    char *err, size_t err_size);

/* Whether this is the table netcfgd owns -- family and name together, because
 * `ip netcfgd` would be somebody else's table with the same name. */
int ncfg_nft_table_is_ours(const ncfg_nft_table_t *table);

/*
 * Whether this chain translates source addresses on the way out.
 *
 * Two of these on one machine double-NAT, which is the conflict 0022 says to
 * detect and report in the same words and the same places as the
 * NetworkManager contention check.
 */
int ncfg_nft_chain_is_source_nat(const ncfg_nft_chain_t *chain);

/*
 * The interface one rule masquerades, if the rule has the shape
 * `ncfg_nft_build_replace_nat` writes.
 *
 * Reads the three expressions back the way they went out: a `meta` loading
 * `oifname` into a register, a `cmp` testing that register for equality with
 * the name, and a `masq`. All three must be there, and a rule from any other
 * table is refused before its expressions are looked at.
 *
 * Anything else is refused rather than guessed at. A rule with the comparison
 * and no `masq` matches traffic and does nothing to it, and calling that an
 * uplink would report NAT that is not happening; a rule netcfgd did not write
 * is not netcfgd's to describe, and the next apply replaces the table wholesale
 * anyway -- so reporting one as an uplink would produce a plan claiming to
 * remove something it never installed.
 */
int ncfg_nft_rule_uplink(const void *payload, size_t length, char *out, size_t out_size,
    char *err, size_t err_size);

#endif /* NCFG_NFT_H */
