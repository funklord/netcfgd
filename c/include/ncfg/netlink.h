/*
 * netlink.h -- the kernel, as netcfgd sees it: a socket and the records it
 * answers with.
 *
 * ONE HEADER, TWO SOURCES, AND WHY THAT IS ONE RESPONSIBILITY
 *   `code-style.md` says a module whose statement of purpose needs an "and"
 *   wants splitting, so this one says where the split already is. The
 *   responsibility is *the kernel's side of netcfgd*: ask, and be told. It is
 *   implemented in two files because the two halves must not be able to touch
 *   each other's problem -- `socket.c` holds every syscall and parses nothing,
 *   `dump.c` parses and holds no descriptor -- and that is the same division
 *   `wire.h` states for the layer below. A caller does not get one without the
 *   other: a record with no socket has nothing to decode, and a socket with no
 *   records hands back bytes. So they share a header and not a source file.
 *
 * WHAT THIS ADDS TO `wire.h`
 *   `wire.h` is bytes in, structures out. Here the bytes come from somewhere:
 *   a bound socket, a sequence number, a multipart reply that ends with
 *   `NLMSG_DONE`, and an `NLMSG_ERROR` that is an acknowledgement when its
 *   code is zero -- netlink's least obvious convention. And here the
 *   structures become facts: a link's name, whether its cable is in, an
 *   address's prefix, a route's table.
 *
 * WHAT IS NOT HERE
 *   No model types. This module depends on `base`, `buf`, `wire`, libc and the
 *   kernel headers, exactly as `netcfgd-sys` depends on nothing but libc and
 *   the kernel -- which is what lets the decoding be tested against captured
 *   bytes with no model in sight, and what lets `c/tests/netlink_test.c` run
 *   with no socket, no privilege and no hardware.
 *
 * ABSENCE, WHICH THE RUST SPELLS `Option` AND C HAS TO SPELL OUT
 *   Two spellings, both deliberate:
 *
 *     * A number that may be missing carries a `has_x` beside it, as
 *       `ncfg_address_t` does for its prefix. The field itself is zero where
 *       `has_x` is 0, so a caller that forgets the flag reads a zero rather
 *       than a stale value -- but zero is a legitimate answer for a GRE key
 *       and for `mtu`, so the flag is the only correct test.
 *     * An address that may be missing carries `family == AF_UNSPEC`, because
 *       `ncfg_wire_attr_ip` only ever writes `AF_INET` or `AF_INET6` and a
 *       second flag beside it would be a second thing to keep true. The
 *       kernel's own "none" -- an all-zero endpoint -- is read as absence
 *       here, for the reason each field's comment gives.
 */
#ifndef NCFG_NETLINK_H
#define NCFG_NETLINK_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/wire.h"

/*
 * The multicast groups a watcher subscribes to.
 *
 * `bind` takes a *bitmask*, and `linux/rtnetlink.h` numbers the groups from 1,
 * so every one of these is `1 << (group - 1)`. Writing the mask out as a
 * constant is how a port comes to subscribe to the wrong thing: the numbers
 * are 1, 5, 7, 9 and 11 and the bits are 0x1, 0x10, 0x40, 0x100 and 0x400,
 * which look nothing like each other.
 */
#define NCFG_NETLINK_GROUP_LINK (1u << (RTNLGRP_LINK - 1))
#define NCFG_NETLINK_GROUP_IPV4_IFADDR (1u << (RTNLGRP_IPV4_IFADDR - 1))
#define NCFG_NETLINK_GROUP_IPV4_ROUTE (1u << (RTNLGRP_IPV4_ROUTE - 1))
#define NCFG_NETLINK_GROUP_IPV6_IFADDR (1u << (RTNLGRP_IPV6_IFADDR - 1))
#define NCFG_NETLINK_GROUP_IPV6_ROUTE (1u << (RTNLGRP_IPV6_ROUTE - 1))

/* Everything the observed model is built from. */
#define NCFG_NETLINK_GROUPS_OBSERVED                                          \
	(NCFG_NETLINK_GROUP_LINK | NCFG_NETLINK_GROUP_IPV4_IFADDR |           \
	    NCFG_NETLINK_GROUP_IPV4_ROUTE | NCFG_NETLINK_GROUP_IPV6_IFADDR |  \
	    NCFG_NETLINK_GROUP_IPV6_ROUTE)

/*
 * The buffer a reply starts in, and the ceiling it may grow to.
 *
 * The kernel caps a dump's datagrams just under 32 KiB -- measured, 31,944
 * bytes for a link dump of 800 interfaces -- so the starting size is never
 * exceeded by a dump. What does exceed it is a single oversized *message*,
 * since one netlink message is delivered whole or not at all, and a WireGuard
 * device with a great many peers is one message.
 *
 * A megabyte is far past anything the kernel sends in one datagram, and the
 * point of the number is that the growth is bounded rather than that this is
 * the right size. A reply past it is refused *with its size*, which is the
 * number whoever raises it needs.
 */
#define NCFG_NETLINK_REPLY_INITIAL (32u * 1024u)
#define NCFG_NETLINK_MAX_REPLY (1024u * 1024u)

/*
 * WHO SENT THIS, WHICH IS A QUESTION THE KERNEL DOES NOT ANSWER FOR YOU
 *
 * A netlink socket is not a private channel to the kernel. **Any local process
 * may unicast a datagram to another process's netlink socket**, and it does not
 * have to guess where to aim: `/proc/net/netlink` is world-readable and lists
 * netcfgd's rtnl socket with its port id. Sequence numbers are small
 * consecutive integers, so a forged reply that matches the one in flight is not
 * a hard thing to write.
 *
 * What that buys an attacker, if nothing checks: a forged `RTM_NEWLINK` joins a
 * dump in progress and becomes part of what a root daemon believes about the
 * machine, and a forged `NLMSG_ERROR` fails an operation that the kernel was
 * about to acknowledge.
 *
 * So every receive here is a `recvfrom`, and **a datagram whose `nl_pid` is not
 * 0 did not come from the kernel.**
 *
 * **It is dropped, and it is not an error, and that is the whole decision.**
 * The tempting answer is to refuse -- a forged message is an attack and an
 * attack should be loud. It is the wrong half: a refusal hands the same local
 * process the other end of the same hole, since one packet then aborts any dump
 * it likes on a daemon holding `CAP_NET_ADMIN`. Dropping costs an attacker
 * everything, because nothing they send reaches anything that reads it, and
 * costs a legitimate conversation nothing at all, because the kernel's own
 * datagrams are untouched and still queued behind the one discarded. A flood
 * can still stall a conversation for as long as it is kept up -- that is the
 * residue, and it is strictly better than a single packet ending one.
 *
 * **Dropping silently would be a third mistake**, since a message discarded and
 * a message that never arrived look identical from above. So both counters
 * below exist and neither is decoration: they are how "the dump came back
 * short" is told apart from "somebody is writing to our socket".
 */

/* A bound netlink socket. Treat the fields as private; `fd` is -1 when
 * nothing is open. */
typedef struct {
	int      fd;
	uint32_t seq;
	/* Datagrams discarded since this socket was opened because they did not
	 * come from the kernel. Nonzero means somebody local is writing to it,
	 * which is worth a line in a log even though nothing went wrong. */
	uint32_t dropped;
} ncfg_netlink_t;

/* One reply message's payload: everything after the netlink header. */
typedef struct {
	uint8_t *bytes;
	size_t   length;
} ncfg_netlink_payload_t;

/*
 * Every payload belonging to one request, in the order the kernel sent them.
 *
 * Copied out of the read buffer rather than pointed into it, because the
 * buffer is reused and regrown for the next datagram of the same multipart
 * reply -- a record pointing into it would change under the caller between one
 * message and the next.
 *
 * This is the one thing in the port that grows without a ceiling, and the
 * reason is that its size is the kernel's rather than a client's: a machine
 * with a full routing table has a million routes and refusing to read them is
 * not a safety property, it is a daemon that cannot see its own machine. The
 * bound that does apply is `NCFG_NETLINK_MAX_REPLY`, on each datagram.
 */
typedef struct {
	ncfg_netlink_payload_t *items;
	size_t                  count;
	size_t                  capacity;
	/*
	 * Datagrams discarded during *this* answer because they did not come
	 * from the kernel. Survives a refusal, since a forgery may be what the
	 * refusal is about -- an answer that came back empty with this set is a
	 * different fact from one that came back empty.
	 */
	size_t                  dropped;
} ncfg_netlink_reply_t;

/* Release the payloads and leave the reply usable and empty. Freeing one that
 * was never filled in is nothing. */
void ncfg_netlink_reply_free(ncfg_netlink_reply_t *reply);

/* Leave a socket closed and unopened. `ncfg_netlink_close` on one that has
 * been through this is nothing, which is what makes a failure path cheap. */
void ncfg_netlink_init(ncfg_netlink_t *netlink);

/*
 * Open and bind a socket that receives only replies to its own requests.
 *
 * Which is right for a one-shot and useless for a watcher: see
 * `ncfg_netlink_open_groups`.
 */
int ncfg_netlink_open(ncfg_netlink_t *netlink, char *err, size_t err_size);

/*
 * Open a socket subscribed to multicast groups.
 *
 * The daemon binds `NCFG_NETLINK_GROUPS_OBSERVED` and then sits in a blocking
 * receive: a change to a link, an address or a route wakes it, and it
 * re-reads.
 *
 * **Subscribing is not the same as reading the changes.** A multicast message
 * is "something moved, look again" rather than a delta to apply. Deltas can be
 * lost -- a socket whose buffer overflows gets `ENOBUFS` and a gap -- so a
 * full re-read is the only version that cannot drift, and it costs three dumps
 * on a machine that is not changing constantly.
 */
int ncfg_netlink_open_groups(ncfg_netlink_t *netlink, uint32_t groups,
    char *err, size_t err_size);

/*
 * Open a socket on a specific netlink protocol.
 *
 * Everything above this speaks rtnetlink (`NETLINK_ROUTE`). Generic netlink
 * (`NETLINK_GENERIC`) is a second protocol on the same socket family with its
 * own message layout on top of the shared header, so it needs its own socket
 * and cannot share one with the route socket -- a family id from one is
 * meaningless on the other.
 */
int ncfg_netlink_open_protocol(ncfg_netlink_t *netlink, int protocol, uint32_t groups,
    char *err, size_t err_size);

/* Close it. Nothing where it was never opened. */
void ncfg_netlink_close(ncfg_netlink_t *netlink);

/*
 * The descriptor, for a caller that multiplexes several of them.
 *
 * -1 where nothing is open. The field above is private and this is the one
 * thing outside this module that has a reason to know it: `src/main/`'s
 * descriptor loop polls this socket beside the configuration watch,
 * `/dev/rfkill` and a timer, and `poll` takes an integer. Reaching into the
 * struct for it would make every field it has reachable by the same route.
 *
 * **It is for waiting on and for nothing else.** Everything that reads the
 * socket goes through this module, because the sender check and the
 * `ENOBUFS` rule live here and a second reader would be a second place they
 * could be got wrong.
 */
int ncfg_netlink_descriptor(const ncfg_netlink_t *netlink);

/*
 * Set how long a receive waits before giving up.
 *
 * Without this a lost message wedges the caller for ever, which on a daemon
 * holding `CAP_NET_ADMIN` is worse than an error.
 */
int ncfg_netlink_set_timeout(const ncfg_netlink_t *netlink, long seconds,
    char *err, size_t err_size);

/* The next sequence number, for a caller building its own messages. */
uint32_t ncfg_netlink_take_seq(ncfg_netlink_t *netlink);

/*
 * Send a request and collect every reply message belonging to it.
 *
 * Handles the multipart protocol: a dump answers with a run of messages
 * carrying `NLM_F_MULTI` and ends with `NLMSG_DONE`; a single-shot request
 * answers with one `NLMSG_ERROR`, which is an acknowledgement when its code is
 * zero.
 *
 * `body` and `attrs` may be NULL for none, and a buffer that has already
 * failed is refused rather than sent as the empty string it hands out.
 */
int ncfg_netlink_request(ncfg_netlink_t *netlink, uint16_t kind, uint16_t flags,
    const ncfg_buf_t *body, const ncfg_buf_t *attrs, ncfg_netlink_reply_t *out,
    char *err, size_t err_size);

/*
 * The same, starting from a buffer of a given size.
 *
 * **The size is a parameter so that the growth can be tested.** The kernel
 * will not make an oversized reply on demand -- it caps a dump's datagrams
 * just under 32 KiB whatever the interface count -- so no test could make the
 * ordinary buffer overflow by asking for more interfaces. Starting
 * deliberately small reaches the same code the way a single oversized message
 * does, which is the case that happens on a real machine.
 */
int ncfg_netlink_request_from(ncfg_netlink_t *netlink, uint16_t kind, uint16_t flags,
    const ncfg_buf_t *body, const ncfg_buf_t *attrs, size_t initial,
    ncfg_netlink_reply_t *out, char *err, size_t err_size);

/*
 * Send a pre-built buffer and collect replies until `last_acked` is
 * acknowledged.
 *
 * nftables is transactional: a change is a run of messages between a
 * batch-begin and a batch-end, and the kernel applies all of them or none.
 * That does not fit `ncfg_netlink_request`, which sends one message and waits,
 * so this exists alongside it rather than inside it.
 *
 * `last_acked` is the sequence number of the last message that asked for an
 * acknowledgement -- **not** the batch-end marker. The kernel acknowledges the
 * messages inside the transaction and says nothing about the end marker, so
 * waiting for that one waits until the socket times out.
 *
 * The first errno any message in the batch replies with is the failure
 * reported: one failure means the whole transaction was rolled back, so the
 * first is the cause.
 */
int ncfg_netlink_send_batch(ncfg_netlink_t *netlink, const void *bytes, size_t length,
    uint32_t last_acked, ncfg_netlink_reply_t *out, char *err, size_t err_size);

/*
 * Block until the kernel reports a change on a subscribed group.
 *
 * `*changed` is 1 where something moved and 0 where the receive timed out, so
 * a caller can use the timeout as its own tick without distinguishing the two
 * at the syscall level. The return value is the usual 1-or-0: a real failure.
 *
 * A datagram from anything but the kernel is discarded, counted in
 * `netlink->dropped`, and reported as "nothing yet" -- the same answer a signal
 * gets, and for the same reason: the caller's loop asks again. It is not
 * reported as a change, or any local process could make a root daemon re-read
 * the machine as fast as it cares to send.
 *
 * Takes a mutable socket rather than a const one because of that counter,
 * which is the point: a watch that discards something has to be able to say so.
 */
int ncfg_netlink_wait_for_change(ncfg_netlink_t *netlink, int *changed,
    char *err, size_t err_size);

/*
 * What a netlink receive meant: a change, nothing yet, or a real failure.
 *
 * Split from `ncfg_netlink_wait_for_change` so it can be asked without a
 * socket, which is the only way this is testable at all. `read` and `code` are
 * what `recv` returned and what it left in `errno`. Four outcomes are not
 * failures:
 *
 *   * a receive that returned anything is a change -- including zero bytes,
 *     since a zero-length message is still a message;
 *   * `EAGAIN`/`EWOULDBLOCK` or `ETIMEDOUT` is `SO_RCVTIMEO` expiring, which
 *     the caller uses as its own tick;
 *   * **`EINTR` is a signal arriving mid-syscall**, which means call it again.
 *     Treating it as a failure cost a machine its network configuration for
 *     fifty-two minutes (0233): netcfgd spawns children, `SIGCHLD` landed on
 *     this syscall two seconds before a network change, the watcher thread
 *     took the error as fatal and returned -- and since the same thread sent
 *     the reconcile tick, the daemon answered clients for another fifty
 *     minutes with the previous network's search domain in
 *     `/etc/resolv.conf`. Reported as "nothing yet" rather than retried in a
 *     loop here, which is the same answer a timeout gets and what the caller's
 *     loop already does. It cannot spin: every `EINTR` is a signal that really
 *     arrived.
 *   * **`ENOBUFS` is a change**, not a failure. It means the socket's buffer
 *     overflowed and messages were dropped; since the daemon re-reads rather
 *     than applying deltas a gap costs nothing, and a watcher that stopped
 *     here would stop precisely when the most was happening.
 *
 * Everything else is a failure and says so.
 */
int ncfg_netlink_change_from(ssize_t read, int code, int *changed,
    char *err, size_t err_size);

/*
 * One datagram source: `recv`, with the two flags this module uses.
 *
 * **The seam that makes the receive loop testable without a kernel.** Binding
 * a multicast group and waiting is a test that hangs on somebody's desk, and a
 * dump read from the running kernel is a test whose expected answer is
 * whatever that machine happens to be doing. A fake source is neither: it
 * answers with bytes a test wrote, including the bytes a kernel will not
 * produce on demand -- a datagram larger than the buffer, a datagram past the
 * ceiling, a reply to somebody else's sequence number.
 *
 * Returns the datagram's *true* size, which may exceed `length`, or -1 with
 * `errno` set -- exactly as `recv` with `MSG_TRUNC` does. `peek` asks for
 * `MSG_PEEK`, which leaves the datagram queued.
 *
 * `*from` is set to the sending port id: 0 for the kernel and anything else for
 * a local process, which is the check described above. A source that cannot
 * vouch for the sender -- no address returned, or one that is not
 * `AF_NETLINK` -- sets a nonzero value rather than 0, so that "I do not know"
 * lands on the safe side of the one comparison the caller makes. It is set on a
 * failing call too, for the same reason.
 */
typedef ssize_t (*ncfg_netlink_recv_t)(void *context, void *bytes, size_t length, int peek,
    uint32_t *from);

/*
 * Read datagrams from `source` until the reply to `seq` is complete.
 *
 * **A buffer too small is a re-read, not a truncation, and never a re-send.**
 * Netlink delivers a datagram whole or not at all: a plain `recv` fills the
 * buffer, discards the rest, and reports the buffer's length -- so the caller
 * parses the messages that fit and never learns there were more. What that
 * costs is not a failure but an incomplete observation, interfaces or routes
 * missing from a dump with nothing anywhere saying so, and where the lost tail
 * held the `NLMSG_DONE`, a wait that runs to the socket's timeout for no
 * reason anybody could see. `MSG_PEEK | MSG_TRUNC` asks the size without
 * consuming, the buffer grows to it, and the same datagram is then taken
 * whole.
 *
 * **The first version doubled the buffer and re-sent the request, and the test
 * caught it** (0183). Re-sending leaves the truncated reply's remaining
 * datagrams queued on the same socket, to be read and skipped against the new
 * sequence number while the new reply queues behind them; it passed once and
 * returned an empty dump on the next run. Asking the size first has no such
 * state -- and note that nothing in this function can send anything, which is
 * what keeps that defect from coming back.
 *
 * `request_flags` are the flags the request carried: without `NLM_F_DUMP` a
 * reply that collected anything is complete on its own, or a single-shot
 * request that gets no acknowledgement blocks until the timeout.
 *
 * A datagram from anything but the kernel is discarded and counted in
 * `out->dropped` -- see the note above the socket type for why that is a drop
 * and not a refusal. It is discarded before the buffer is grown for it, so a
 * forged datagram claiming a megabyte costs nothing and cannot reach the
 * ceiling refusal, which would otherwise be a way to end a dump with one
 * packet.
 */
int ncfg_netlink_collect(ncfg_netlink_recv_t source, void *context, uint32_t seq,
    uint16_t request_flags, size_t initial, ncfg_netlink_reply_t *out,
    char *err, size_t err_size);

/*
 * The same, for a batch: read until a message at or past `last_acked` is
 * acknowledged.
 *
 * Separate from `ncfg_netlink_collect` because a batch ends on a *different
 * question* -- which sequence number was acknowledged, rather than whether
 * this request is done -- and folding the two into one function with a mode
 * flag would put that question behind a boolean nobody reads.
 */
int ncfg_netlink_collect_batch(ncfg_netlink_recv_t source, void *context,
    uint32_t last_acked, size_t initial, ncfg_netlink_reply_t *out,
    char *err, size_t err_size);

/*
 * The kernel's own name for a message type, or NULL where this port has none.
 *
 * For the sentence a failure becomes: "RTM_NEWLINK was refused" is a thing an
 * operator can look up and "message type 16 was refused" is not.
 */
const char *ncfg_netlink_kind_text(uint16_t kind);

/*
 * What this errno means *here*, or NULL where there is nothing to add.
 *
 * `strerror` gives "Invalid argument", which on a netlink socket is true and
 * useless: it is what the kernel says when an attribute is one it does not
 * know, when a nest arrived without `NLA_F_NESTED`, and when a value is out of
 * range. The sentence is the part an operator can act on.
 */
const char *ncfg_netlink_errno_text(int code);

/*
 * Turn a netlink failure into the sentence `err` carries, and return 0.
 *
 * Always 0, so a failure path reads `return ncfg_netlink_fail(err, err_size,
 * "the link dump", code);` -- which is what keeps the message and the return
 * value from disagreeing.
 */
int ncfg_netlink_fail(char *err, size_t err_size, const char *doing, int code);

/* ------------------------------------------------------------------------ */
/* The dumps.                                                               */
/* ------------------------------------------------------------------------ */

/* `IFNAMSIZ`, written out rather than included: `linux/if.h` and `net/if.h`
 * redefine each other's `struct ifreq`, and a caller of this header is very
 * likely to want the second one. Same reason `wire.h` writes out
 * `ALTIFNAMSIZ`. */
#define NCFG_LINK_NAME_MAX 16u

/*
 * Room for a link kind: `bridge`, `vlan`, `wireguard`, `ip6gre`.
 *
 * The kernel's longest is a module name, and 64 is past every one that exists.
 * A kind that did not fit would read as the empty string -- a plain device --
 * which is why this is generous rather than exact: the kind decides which
 * numbering the `INFO_DATA` nest is read with, and reading one kind's nest
 * with another's numbering is how a VXLAN comes to report a forward delay.
 */
#define NCFG_LINK_KIND_MAX 64u

/* `IFF_UP` from `net/if.h`, written out for the same reason as the name
 * length above. The administrative flag, which is not carrier. */
#define NCFG_LINK_IFF_UP 0x1u

/*
 * What a bridge reports about itself.
 *
 * In the units the kernel uses, which are hundredths of a second for the three
 * timers. The conversion to seconds belongs where the conversion *to* the
 * kernel already is, so that one place owns it -- a reader that divided here
 * and a writer that multiplied there is how the same bridge comes to differ
 * from itself by a factor of a hundred.
 */
typedef struct {
	/* The kernel reports the STP *state*, 0 for off and non-zero for a
	 * running protocol; the document holds a boolean. */
	int      stp;
	int      has_forward_delay;
	uint32_t forward_delay;
	int      has_hello_time;
	uint32_t hello_time;
	int      has_ageing_time;
	uint32_t ageing_time;
	int      has_priority;
	/*
	 * **Two bytes, not four.** `IFLA_BR_PRIORITY` is a `__u16` in
	 * `if_link.h`, and a 32-bit read of it returns nothing -- so this field
	 * read as absent on every kernel, always. Nothing noticed because the
	 * planner did not compare it; the moment it did, an apply set the
	 * priority and the observation still said absent, so the plan asked for
	 * it again for ever. The writer had it right, which is what makes the
	 * two-byte width the answer rather than a guess.
	 */
	uint16_t priority;
	int      vlan_filtering;
} ncfg_bridge_info_t;

/*
 * What a bond reports about itself.
 *
 * Only the two netcfgd sets. A bond has thirty-odd parameters and reading all
 * of them would put a page of kernel detail in `/run` to answer a question
 * about two.
 */
typedef struct {
	int      has_mode;
	/* As the kernel numbers them. */
	uint8_t  mode;
	int      has_miimon;
	/* Link monitoring interval, milliseconds. */
	uint32_t miimon;
} ncfg_bond_info_t;

/*
 * What a macvlan reports about itself.
 *
 * The mode is flags rather than an enumeration, which is not obvious and
 * matters: the kernel numbers them 1, 2, 4, 8 and 16 and its validator rejects
 * any other value outright, so 0 for the first mode and 3 for the fourth are
 * `EINVAL` rather than a wrong mode. Kept as the number here and named a level
 * up, the way a bond's mode is.
 */
typedef struct {
	int      has_mode;
	uint32_t mode;
} ncfg_macvlan_info_t;

/*
 * What a VLAN reports about itself.
 *
 * Read even though neither field can be *set* on a live device: the kernel
 * accepts a change to either and ignores it, so the only way to apply an
 * edited id is to make the interface again -- and knowing that it differs is
 * what decides to.
 */
typedef struct {
	int      has_id;
	uint16_t id;
	int      has_protocol;
	/* An ethertype: 0x8100 or 0x88a8. Big-endian on the wire, because it is
	 * something the wire defines rather than a number the kernel chose. */
	uint16_t protocol;
} ncfg_vlan_info_t;

/* Which attribute numbering a tunnel kind's `INFO_DATA` uses.
 *
 * Three families for seven kinds, and reading one with another's constants is
 * how a tunnel comes to report somebody else's field: GRE puts its endpoints
 * at 6 and 7 where an ip tunnel has them at 2 and 3, and geneve puts its VNI
 * at 1 where GRE has a flags word. */
typedef enum {
	NCFG_TUNNEL_NONE = 0,
	/* `IFLA_GRE_*`: gre, gretap and ip6gre. */
	NCFG_TUNNEL_GRE = 1,
	/* `IFLA_IPTUN_*`: ipip, sit and ip6tnl. */
	NCFG_TUNNEL_IP = 2,
	/* `IFLA_GENEVE_*`, numbered on its own again. */
	NCFG_TUNNEL_GENEVE = 3
} ncfg_tunnel_family_t;

/*
 * Which family a kernel link kind belongs to, for the kinds netcfgd builds.
 *
 * Matched exactly rather than by substring. The writing half may ask whether
 * the kind contains `gre`, which is safe there because it is only ever handed
 * one of seven names netcfgd chose; here the string comes from the kernel and
 * could be any link kind on the machine, and a kind this does not know is one
 * nothing is compared for.
 */
ncfg_tunnel_family_t ncfg_tunnel_family(const char *kind);

/* What a point-to-point tunnel reports about itself. */
typedef struct {
	/* `AF_UNSPEC` for absent. An unset endpoint comes back as all zeroes
	 * rather than as a missing attribute, and the document spells that
	 * absence -- reading it as the address 0.0.0.0 would make every tunnel
	 * differ from a document that cannot say it. */
	ncfg_wire_ip_t local;
	ncfg_wire_ip_t remote;
	int            has_ttl;
	/* Outer TTL, where the kind has one. Zero means inherit, which is why
	 * the flag beside it is the only correct test for absence. */
	uint8_t        ttl;
	int            has_key;
	/*
	 * The GRE key, or a geneve tunnel's VNI, which netcfgd spells the same
	 * way.
	 *
	 * The kernel emits a GRE `IKEY` whether or not the tunnel has a key, so
	 * a zero there is ambiguous -- either no key, or the key `0`, which a
	 * document may legitimately ask for. `GRE_KEY` in the flags word is
	 * what distinguishes them, and reading it is what keeps `key = 0` from
	 * differing from itself for ever.
	 */
	uint32_t       key;
} ncfg_tunnel_info_t;

/*
 * What a VXLAN reports about itself.
 *
 * Only what netcfgd can set. Two of the five cannot be corrected once the
 * device exists -- the kernel refuses a changed `id` and refuses the `port`
 * even at the value it already has -- and they are read anyway, because the
 * plan's job is to say that they differ.
 */
typedef struct {
	int            has_id;
	uint32_t       id;
	int            has_link;
	/* Index of the underlay device, which for this kind alone lives in the
	 * nest rather than in the outer `IFLA_LINK`. */
	uint32_t       link;
	/* `AF_UNSPEC` for absent, as a tunnel's are and for the same reason. */
	ncfg_wire_ip_t local;
	ncfg_wire_ip_t remote;
	int            has_port;
	/* Big-endian on the wire, like every port number. */
	uint16_t       port;
} ncfg_vxlan_info_t;

/* A link, as decoded from one `RTM_NEWLINK` message. */
typedef struct {
	uint32_t index;
	char     name[NCFG_LINK_NAME_MAX];
	/* From the `LINKINFO` nest: `bridge`, `vlan`, and so on. Empty for a
	 * plain device, which is normal rather than a failure. */
	char     kind[NCFG_LINK_KIND_MAX];
	/*
	 * Alternative names, from the `IFLA_PROP_LIST` nest.
	 *
	 * netcfgd stamps one on every link it creates, which is how a link's
	 * ownership survives losing `/run` (0136). A list rather than one name:
	 * `IFLA_ALT_IFNAME` repeats, a device may carry names from several
	 * sources, and netcfgd must not assume its own is the only one -- a
	 * reader that took the first would see somebody else's name and decide
	 * the link was not its own.
	 *
	 * Owned by the record; `ncfg_link_record_free` releases them.
	 */
	char   **altnames;
	size_t   altname_count;
	/* Whether `IFF_UP` is set: the administrative flag. */
	int      up;
	/*
	 * Whether the kernel reports carrier, which is a *different question*.
	 * A link can be up with the cable out, and conflating the two is how a
	 * plan decides to reconfigure a perfectly good interface.
	 *
	 * **A link with no `IFLA_CARRIER` at all counts as having carrier**,
	 * which is the kernel's older shape and the conservative reading: a
	 * device that does not report the attribute is not a device with no
	 * cable.
	 */
	int      carrier;
	uint32_t mtu;
	int      has_mac;
	char     mac[NCFG_WIRE_MAC_TEXT_MAX];
	int      has_master;
	/* Index of the master, where enslaved. */
	uint32_t master;
	int      has_parent;
	/*
	 * Index of the device this virtual link rides on, where it has one.
	 *
	 * From the outer `IFLA_LINK` for every kind that reports one there, and
	 * from the `INFO_DATA` nest for a VXLAN, which is the one kind that
	 * does not -- measured, because the two disagreeing is how a parent came
	 * to be sent to the wrong place for years.
	 */
	uint32_t parent;
	int      has_bond;
	ncfg_bond_info_t bond;
	int      has_bridge;
	/* Read because a bridge configured at creation and never compared is a
	 * bridge whose edited `stp` or `forward_delay` does nothing, and the
	 * name of a bridge encodes neither. */
	ncfg_bridge_info_t bridge;
	int      has_macvlan;
	ncfg_macvlan_info_t macvlan;
	int      has_vlan;
	ncfg_vlan_info_t vlan;
	int      has_tunnel;
	ncfg_tunnel_info_t tunnel;
	int      has_vxlan;
	ncfg_vxlan_info_t vxlan;
	/*
	 * The IPv6 interface identifier set with `ip token`, if any --
	 * `AF_UNSPEC` for none.
	 *
	 * Reported two levels down, inside `IFLA_AF_SPEC`'s `AF_INET6` block, so
	 * it needs no second request. All-zero is how the kernel spells "no
	 * token", and it is read as absence rather than as the address `::`,
	 * which would make every interface look as though it had one.
	 */
	ncfg_wire_ip_t ipv6_token;
} ncfg_link_record_t;

/* An address, as decoded from one `RTM_NEWADDR` message. */
typedef struct {
	uint32_t       index;
	ncfg_wire_ip_t address;
	uint8_t        prefix_len;
	int            has_proto;
	/* `IFA_PROTO`, where the kernel supplied it. Absent means a kernel
	 * older than 5.18 rather than an address with no protocol, and decision
	 * 0002 turns on the difference. */
	uint8_t        proto;
} ncfg_address_record_t;

/* A route, as decoded from one `RTM_NEWROUTE` message. */
typedef struct {
	int            has_index;
	/* Output interface index. */
	uint32_t       index;
	/* `AF_UNSPEC` for a default route. */
	ncfg_wire_ip_t destination;
	uint8_t        dst_len;
	ncfg_wire_ip_t gateway;
	int            has_metric;
	uint32_t       metric;
	/* Table id. Above 255 it does not fit `rtm_table` and arrives in
	 * `RTA_TABLE` instead, which is why this is 32 bits wide. */
	uint32_t       table;
	ncfg_wire_ip_t prefsrc;
	/* `rtm_protocol`: `NCFG_WIRE_RTPROT_NETCFGD` on a route netcfgd
	 * installed, which is how it knows which routes are its own. */
	uint8_t        protocol;
	uint8_t        scope;
} ncfg_route_record_t;

/*
 * One VLAN on one bridge port, as the kernel reports it.
 *
 * **`_record_t`, like the address and the route above it, because
 * `document.h` has an `ncfg_bridge_vlan_t` of its own** -- the *desired* VLAN,
 * which carries no interface index and holds its id as the model's `int64_t`.
 * Both names described the same words and neither could be included beside the
 * other, which nothing noticed until a module needed a rule from one and a
 * VLAN from the other. An executor is exactly that module, so the collision
 * was renamed out before one arrived rather than worked around inside it.
 */
typedef struct {
	uint32_t index;
	uint16_t vid;
	/* Untagged ingress joins this VLAN. */
	int      pvid;
	/* Egress leaves without a tag. */
	int      untagged;
} ncfg_bridge_vlan_record_t;

/* The VLANs of one bridge message: a port with four arrives as one link with
 * four attributes. */
typedef struct {
	ncfg_bridge_vlan_record_t *items;
	size_t              count;
	size_t              capacity;
} ncfg_bridge_vlan_records_t;

void ncfg_bridge_vlan_records_free(ncfg_bridge_vlan_records_t *vlans);

/*
 * Release what a link record owns, and leave it empty.
 *
 * Only the alternative names are allocated; everything else is inside the
 * struct. Freeing a record that was never filled in is nothing, which is what
 * lets a caller declare one, call the decode, and free it on either answer.
 *
 * `ncfg_address_record_t` and `ncfg_route_record_t` own nothing at all and so
 * have no free beside them -- said here because "there isn't one" is a thing a
 * reader has to be able to find out without reading the decoder.
 */
void ncfg_link_record_free(ncfg_link_record_t *record);

/* The flags a dump request carries. */
uint16_t ncfg_dump_flags(void);

/*
 * The four dump requests: a family struct in `body`, attributes in `attrs`.
 *
 * `void`, for the reason the wire encoders are: failure is the buffer's and it
 * is sticky, so a caller builds a request and checks `ncfg_buf_failed` once --
 * and `ncfg_wire_build_request` refuses a failed buffer rather than sending
 * the empty string it hands out.
 */
void ncfg_dump_link_request(ncfg_buf_t *body, ncfg_buf_t *attrs);
void ncfg_dump_address_request(ncfg_buf_t *body, ncfg_buf_t *attrs);
void ncfg_dump_route_request(ncfg_buf_t *body, ncfg_buf_t *attrs);
/*
 * Bridge VLANs, which come back on a link dump under another family.
 *
 * A separate dump from the ordinary one and it cannot be folded in: it needs
 * `AF_BRIDGE` and an explicit `RTEXT_FILTER_BRVLAN`, and without the filter a
 * bridge link dump reports no VLANs at all -- which reads as "this bridge has
 * none" rather than "you did not ask".
 */
void ncfg_dump_bridge_vlan_request(ncfg_buf_t *body, ncfg_buf_t *attrs);

/* The message type each dump asks for. Two of them are the same message, which
 * is why the bridge one is named rather than assumed. */
#define NCFG_DUMP_LINK RTM_GETLINK
#define NCFG_DUMP_ADDRESS RTM_GETADDR
#define NCFG_DUMP_ROUTE RTM_GETROUTE
#define NCFG_DUMP_BRIDGE_VLAN RTM_GETLINK

/*
 * Decode one payload into a record.
 *
 * A message that is not one of these, or whose attributes do not make sense,
 * is a refusal with a sentence -- and a refusal is the ordinary case rather
 * than an alarming one, since a link dump under `AF_BRIDGE` and a link dump
 * under `AF_UNSPEC` arrive on the same socket. A caller that dumps and decodes
 * skips what it cannot read and says how many, the way the Rust's
 * `filter_map` does.
 *
 * `out` is left zeroed and safe to free on a refusal.
 */
int ncfg_dump_link(const void *payload, size_t length, ncfg_link_record_t *out,
    char *err, size_t err_size);
int ncfg_dump_address(const void *payload, size_t length, ncfg_address_record_t *out,
    char *err, size_t err_size);
int ncfg_dump_route(const void *payload, size_t length, ncfg_route_record_t *out,
    char *err, size_t err_size);

/*
 * Decode the VLANs in one `AF_BRIDGE` link payload.
 *
 * Several records per message, sorted. The kernel compresses consecutive ids
 * into a pair flagged `RANGE_BEGIN` and `RANGE_END` rather than one entry
 * each; expanding them here means everything above works in single VLANs and
 * never has to know ranges exist.
 */
int ncfg_dump_bridge_vlans(const void *payload, size_t length, ncfg_bridge_vlan_records_t *out,
    char *err, size_t err_size);

/*
 * An address in CIDR notation, which is how the model spells it.
 *
 * `out_size` must be at least `NCFG_WIRE_IP_TEXT_MAX + 5` -- the address, a
 * slash and three digits.
 */
int ncfg_address_record_cidr(const ncfg_address_record_t *record, char *out, size_t out_size,
    char *err, size_t err_size);

/* A route's destination in the model's spelling: CIDR, or `default`. Same
 * buffer requirement. */
int ncfg_route_record_destination(const ncfg_route_record_t *record, char *out, size_t out_size,
    char *err, size_t err_size);

/* Room for either of the two above. */
#define NCFG_CIDR_TEXT_MAX (NCFG_WIRE_IP_TEXT_MAX + 5u)

#endif /* NCFG_NETLINK_H */
