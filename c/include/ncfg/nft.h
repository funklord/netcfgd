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
#include "ncfg/document.h"
#include "ncfg/observed.h"

/* The one table netcfgd owns, and the chains in it. Decision 0022 gave it the
 * NAT chain; 0294 added the three filter chains of layer one's firewall. */
#define NCFG_NFT_TABLE "netcfgd"
#define NCFG_NFT_CHAIN "postrouting"
#define NCFG_NFT_CHAIN_INPUT   "input"
#define NCFG_NFT_CHAIN_FORWARD "forward"
#define NCFG_NFT_CHAIN_OUTPUT  "output"
/* Port forwards (0298): a `nat` chain at the prerouting hook, written only
 * when some interface forwards a port. */
#define NCFG_NFT_CHAIN_PREROUTING "prerouting"

/*
 * What a rule's comment can hold: nft refuses a comment over 128 characters,
 * measured (0295), so the name and the digest share that rather than the
 * kernel's 256.
 */
#define NCFG_NFT_COMMENT_MAX 128u
/* The digest's hex characters in a comment: the first 64 bits of SHA-256,
 * which is identity against accidental difference rather than a signature. */
#define NCFG_NFT_DIGEST_HEX 16u

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
	/* A base chain's policy, `NF_ACCEPT` or `NF_DROP` (10.592). */
	uint32_t policy;
	int      has_policy;
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
 * The ruleset's generation, which is how netcfgd tells a torn read from a
 * quiet machine.
 *
 * **nftables has no compare-and-swap.** A transaction is atomic, so what
 * netcfgd *writes* is never half-applied -- but the conflict report in
 * `observe/netfilter.c` is computed from dumps taken one after another, and
 * docker, podman, libvirt and `firewalld` all add and remove tables while
 * netcfgd runs. A table that appears or vanishes between two dumps makes that
 * report wrong in both directions: a conflict named that has gone, or one
 * missed that arrived.
 *
 * The kernel bumps a counter on every committed change and will hand it over,
 * which is the only synchronisation nftables offers. Read it, take the dumps,
 * read it again: equal means the dumps describe one ruleset, and different
 * means they describe two and the observation should be taken again. 0283 and
 * 0284.
 *
 * `NFT_MSG_GETGEN` answers with one message rather than a dump, so the reply
 * carries exactly one payload for `ncfg_nft_gen_read`.
 */
int ncfg_nft_build_gen_request(ncfg_buf_t *out, uint32_t seq, char *err, size_t err_size);

/*
 * The kernel's own name for an nftables message type, or NULL where this port
 * has none.
 *
 * It is what makes one errno legible. Three unrelated faults refuse a NAT
 * transaction with `ENOENT` -- no `nat` chain type, no `masq` expression, and
 * a table that vanished between the dump and the send -- and the message the
 * kernel echoes back is the only thing that says which. `socket.c` reaches for
 * this when `ncfg_netlink_kind_text` has no name, and nft.c says why no
 * protocol is passed and which single message type is ambiguous.
 */
const char *ncfg_nft_message_text(uint16_t kind);

/*
 * The generation out of that answer.
 *
 * 1 with `out` set. 0 for a payload that is not one, which includes the reply
 * from a kernel that answered something else -- the attribute is required and
 * its absence is a message netcfgd did not ask for rather than a generation of
 * zero, because zero is a value a counter can hold.
 */
int ncfg_nft_gen_read(const void *payload, size_t length, uint32_t *out, char *err,
    size_t err_size);

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
 * The same transaction, carrying layer one's firewall as well (0294, 10.592).
 *
 * **One transaction for the whole table**, because the NAT chain and the
 * three filter chains share it and the table is replaced wholesale: a NAT
 * replacement that did not carry the firewall would delete it, and the
 * reverse. `firewall` NULL is a document with no `firewall` block, which is
 * the NAT-only transaction above, byte for byte.
 *
 * Each filter chain is a base chain at `filter` priority 0 on its hook, with
 * the document's policy. Each rule is the expressions nftables itself would
 * write for it, then the verdict, and carries its identity in nft's comment
 * TLV (0295 B): `name=NAME sha256=DIGEST`, the digest over
 * `ncfg_nft_firewall_rule_text`.
 *
 * **A rule with several values is several kernel rules**, one per
 * combination, each carrying the written rule's comment -- so a decoder groups
 * them by name. A combination of an IPv4 source and an IPv6 destination
 * matches no packet and is not written.
 *
 * **Refused before a byte is written**, rather than half-built: a rule whose
 * name and digest do not fit a comment, a rule no combination of which any
 * packet could match, and one that would become more kernel rules than the
 * bound in nft.c allows.
 */
int ncfg_nft_build_replace(ncfg_buf_t *out, uint32_t first_seq, int table_exists,
    const char *const *uplinks, size_t uplink_count, const ncfg_firewall_t *firewall,
    ncfg_nft_batch_t *batch, char *err, size_t err_size);

/*
 * The whole table with port forwards as well: `ncfg_nft_build_replace` with
 * a `prerouting` nat chain carrying one rule per forward, written only where
 * `forward_count` is not 0. Each rule is the expressions nft 1.1.3 writes for
 * `iifname "IF" tcp dport P dnat ip to A:Q`, measured, and carries 0295's
 * comment with `name=IF/NAME`. Refused before a byte is written where a
 * forward's interface, address or name cannot be expressed.
 */
int ncfg_nft_build_replace_all(ncfg_buf_t *out, uint32_t first_seq, int table_exists,
    const char *const *uplinks, size_t uplink_count, const ncfg_firewall_t *firewall,
    const ncfg_forward_rule_t *forwards, size_t forward_count, ncfg_nft_batch_t *batch,
    char *err, size_t err_size);

/* The text a forward's digest is taken over, as `ncfg_nft_firewall_rule_text`
 * is for a firewall rule: every field, one fixed order. */
int ncfg_nft_forward_text(const ncfg_forward_rule_t *forward, ncfg_buf_t *out);

/* One port forward rule read back (0298, 0299): a forward or a reflection out
 * of `prerouting`, or a return path out of `postrouting`. For a return path
 * `port` is the host's, as the planner gives it. */
typedef struct {
	int      kind; /* ncfg_forward_rule_kind_t */
	char     interface[NCFG_NFT_IFNAME_MAX];
	char     name[NCFG_NFT_COMMENT_MAX + 1u];
	char     digest[NCFG_NFT_DIGEST_HEX + 1u];
	int      protocol;
	uint16_t port;
	char     to[48];       /* an IPv6 host only for a forward (0305) */
	uint16_t to_port;
	char     address[16];  /* reflect */
	char     network[20];  /* hairpin, a CIDR */
	char     via[NCFG_NFT_IFNAME_MAX]; /* hairpin */
} ncfg_nft_kernel_forward_t;

/*
 * Read one entry of a rule dump as a port forward rule netcfgd wrote: in
 * netcfgd's `prerouting` chain, or a return path in `postrouting`, with
 * exactly the matches the builder writes for the role its `name=IF/NAME[@ROLE]
 * sha256=...` comment names. Anything else is refused, saying what.
 */
int ncfg_nft_forward_read(const void *payload, size_t length, ncfg_nft_kernel_forward_t *out,
    char *err, size_t err_size);

/*
 * The text a rule's digest is taken over: every field that decides what the
 * rule does, in one fixed order, with the chain it sits in.
 *
 * **netcfgd's own form, never the kernel's**: the bytes a dump returns are
 * normalised by the kernel and differ between kernel versions (0295), so the
 * digest is of what netcfgd meant. Public because the decoder (0295 A)
 * recomputes it from what it read back, and the two must agree.
 */
int ncfg_nft_firewall_rule_text(const char *chain, const ncfg_firewall_rule_t *rule,
    ncfg_buf_t *out);

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

/* Every rule in netcfgd's table, in every chain: what the firewall's reader
 * walks (0295 A). */
int ncfg_nft_build_table_rule_dump(ncfg_buf_t *out, uint32_t seq, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * Reading replies
 * ------------------------------------------------------------------------ */

/*
 * One kernel rule of the firewall, read back (0295 A, 10.592 slice 2c).
 *
 * Every match single-valued, because that is what one kernel rule holds; a
 * written rule with several values is several of these sharing a name, and
 * putting them back together is the observer's. Addresses are in the form
 * `ncfg_nft_firewall_rule_text` uses -- the network masked, the prefix
 * written only where it is short of the family's length -- so a digest
 * recomputed from this agrees with the one netcfgd wrote.
 */
typedef struct {
	char     chain[NCFG_NFT_NAME_MAX];
	char     name[NCFG_NFT_COMMENT_MAX + 1u];
	char     digest[NCFG_NFT_DIGEST_HEX + 1u];
	int      action;   /* ncfg_firewall_action_t */
	int      protocol; /* ncfg_firewall_protocol_t */
	int      has_port;
	uint16_t port;
	char     from[64]; /* "" where the rule matches no source address */
	char     to[64];
	char     interface[NCFG_NFT_IFNAME_MAX];
	char     out_interface[NCFG_NFT_IFNAME_MAX]; /* forward chain only, 0302 */
	/* Conntrack states as bits: new, established, related, invalid, in the
	 * language's order -- bit 0 is `new`. */
	unsigned states;
	char     mac[NCFG_STATION_ADDRESS_SIZE];
} ncfg_nft_kernel_rule_t;

/*
 * Read one entry of a rule dump as a firewall rule netcfgd wrote.
 *
 * **Refused, not guessed at**: a rule from another table, from the NAT chain,
 * with an expression or a comparison netcfgd does not write, or with no
 * `name=... sha256=...` comment. A refusal says which, because a rule inside
 * netcfgd's table that is not as netcfgd writes rules is somebody's hand edit,
 * reported as such and replaced on the next apply.
 */
int ncfg_nft_firewall_rule_read(const void *payload, size_t length,
    ncfg_nft_kernel_rule_t *out, char *err, size_t err_size);

/* The words the observation and `ncfg status` use: `accept`, `drop`,
 * `reject`; `any`, `tcp`, `udp`, `icmp`, `icmpv6`; and the state for one of
 * `ncfg_nft_kernel_rule_t`'s bits, by index. NULL outside each set. */
const char *ncfg_nft_action_word(int action);
const char *ncfg_nft_protocol_word(int protocol);
const char *ncfg_nft_state_word(unsigned bit);

/*
 * Whether an installed rule, as observed, is exactly this decoded one.
 *
 * What the planner converges on (10.592): it encodes the document's firewall,
 * decodes its own transaction into the kernel rules it should find, and
 * compares those against the observation in order with this -- every field and
 * the identity -- so a hand edit is a difference even where it kept the
 * comment.
 */
int ncfg_nft_kernel_rule_matches(const ncfg_nft_kernel_rule_t *expected,
    const ncfg_observed_firewall_rule_t *observed);

/*
 * Whether the installed firewall is the document's, exactly (10.592): each
 * policy, no rule the decoder refused, and every kernel rule the document's
 * own transaction decodes to, matched in order. NULL and NULL agree.
 * `refusal` is set, and the answer is 0, where the document's firewall cannot
 * be built at all.
 */
int ncfg_nft_firewall_matches(const ncfg_firewall_t *desired,
    const ncfg_observed_firewall_t *observed, char *refusal, size_t refusal_size);

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
