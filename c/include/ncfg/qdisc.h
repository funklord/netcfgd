/*
 * qdisc.h -- traffic control: the root qdisc, its rate, and the ingress
 * redirect.
 *
 * **Bytes in, structures out, and no socket anywhere**, which is wire.h's
 * split one layer up: everything here builds a request into a buffer or reads
 * a dump payload the caller already has. The syscalls live next door, and
 * keeping them there is what makes this file testable with no kernel, no
 * privileges and no interface to break.
 *
 * WHAT NETCFGD IS ALLOWED TO DO HERE
 *   Decision 0023: the **root** qdisc on an interface it manages -- a named
 *   algorithm and at most a rate -- plus the ingress hook and the one filter
 *   that redirects onto an `ifb`. No class tree, no filter language, nothing
 *   below the root. The filter this module writes carries no policy at all: it
 *   matches every packet unconditionally and the only configurable thing about
 *   it is which device the traffic lands on.
 *
 * THE UNIT IS THE TRAP
 *   `tc` takes `bandwidth 100mbit`, the document stores bits per second, and
 *   the kernel's `TCA_CAKE_BASE_RATE64` is **bytes** per second. The
 *   conversion is a division by eight that nothing in the protocol checks: a
 *   rate sent in bits is accepted and shapes at one eighth of what was asked
 *   for, which looks like a slow line rather than a bug, and it is somebody's
 *   uplink. `ncfg_qdisc_rate_bytes` and `ncfg_qdisc_rate_bits` are the only
 *   two places the factor appears, and both refuse what they cannot express
 *   rather than rounding it -- see their comments for what a rounded rate
 *   does.
 *
 * OWNERSHIP IS A HANDLE
 *   Decision 0137: the root qdisc netcfgd installs wears handle `6e:` and its
 *   redirect filter wears `110`, so reading one back says who asked for it. A
 *   qdisc has no protocol field and no property list; the handle is the only
 *   field netcfgd controls and it was carrying nothing.
 *
 * NO ALLOCATION, SO NO FREE
 *   Every aggregate below is fixed-size and the caller owns it. base.h's third
 *   convention -- an `ncfg_x_free` beside every aggregate -- is about the ones
 *   this library allocates, and this module allocates nothing except into the
 *   `ncfg_buf_t` its caller passes in and already owns.
 */
#ifndef NCFG_QDISC_H
#define NCFG_QDISC_H

#include <stddef.h>
#include <stdint.h>

#include "ncfg/base.h"
#include "ncfg/buf.h"

/*
 * The message types, attribute numbers and `struct tcmsg` come from
 * `linux/rtnetlink.h`, `linux/pkt_sched.h`, `linux/pkt_cls.h` and
 * `linux/tc_act/tc_mirred.h`, which qdisc.c includes. The Rust writes them all
 * out because `libc` exports none of them; copying the numbers into a C port
 * that has the kernel's own headers would be inventing a second place for them
 * to be wrong. What follows is only what those headers cannot give.
 */

/*
 * The handle netcfgd stamps on the root qdisc it installs (0137): major 110,
 * minor 0, which `tc qdisc show` prints as `6e:`.
 *
 * Duplicated from the model rather than depended on, because this module must
 * stay free of anything but libc and the kernel -- the same arrangement
 * `NCFG_WIRE_RTPROT_NETCFGD` has, and for the same reason. Disagreement
 * between the two copies means netcfgd stamps one handle and looks for
 * another, so every qdisc it installs becomes foreign to it; the Rust holds
 * the two together with a test in `netcfgd-observe` and qdisc_test.c holds
 * this one to the same number.
 */
#define NCFG_QDISC_HANDLE (110u << 16)

/*
 * The handle netcfgd stamps on its ingress redirect filter (0137).
 *
 * The handle and deliberately not the priority: the filter has to run at
 * priority 1, because a redirect that runs after another filter has already
 * stolen the packet does nothing. That is a correctness constraint, and
 * overloading it with an ownership marker would trade it for a bookkeeping
 * one. A handle carries no ordering at all.
 */
#define NCFG_QDISC_FILTER_HANDLE 110u

/* `sizeof(struct tcmsg)`, checked against the kernel's own at compile time in
 * qdisc.c. A convenience for callers skipping the body of a dump payload, not
 * a second opinion. */
#define NCFG_QDISC_TCMSG_LEN 20u

/*
 * How long a scheduler's name can be.
 *
 * `IFNAMSIZ`, because that is the width of `Qdisc_ops.id` in the kernel, and
 * it is written out rather than included for the reason wire.h gives about
 * `ALTIFNAMSIZ`: `linux/if.h` and `net/if.h` redefine each other's `struct
 * ifreq`, and a caller of this file is very likely to want the second one.
 */
#define NCFG_QDISC_KIND_MAX 16u

/* `struct tcmsg`, with the names this port uses. The two pad fields the kernel
 * declares are not here: they are written as zero and never read. */
typedef struct {
	uint8_t  family;
	/* Interface index. Signed, as the kernel declares it. */
	int32_t  index;
	/* `major << 16 | minor`. */
	uint32_t handle;
	uint32_t parent;
	/* Priority in the top half and protocol in the bottom, for a filter;
	 * unused for a qdisc. */
	uint32_t info;
} ncfg_qdisc_tcmsg_t;

/* The root qdisc on one interface, as the kernel reports it. */
typedef struct {
	/* Which interface. */
	uint32_t index;
	/* The `tc` handle. `NCFG_QDISC_HANDLE` means netcfgd installed this one;
	 * anything else is a handle the kernel assigned or somebody else chose. */
	uint32_t handle;
	/* The algorithm, as the kernel spells it: `fq_codel`, `cake`, `noqueue`. */
	char     kind[NCFG_QDISC_KIND_MAX];
	/* The shaped rate in **bits** per second, meaningful only where
	 * `has_bandwidth` is set.
	 *
	 * Bits rather than the kernel's bytes, because bits is what an operator
	 * writes and what every other tool prints. The conversion happens here
	 * and in `ncfg_qdisc_build_set_root`, and nowhere else. */
	uint64_t bandwidth_bits;
	int      has_bandwidth;
	/* Whether `cake` was told it is shaping traffic that has already
	 * arrived. */
	int      ingress;
} ncfg_qdisc_record_t;

/* What to install as the root qdisc. */
typedef struct {
	/* The algorithm. */
	const char *kind;
	/* Shaped rate in bits per second, read only where `has_bandwidth` is
	 * set. */
	uint64_t    bandwidth_bits;
	int         has_bandwidth;
	/* Whether this shaper is metering traffic that has already arrived.
	 *
	 * It changes what the shaper counts: on the way out it meters what it
	 * sends, and on the way in the only lever it has is dropping, so it has
	 * to account for what the sender will retransmit. Without it an ingress
	 * shaper undershoots. */
	int         ingress;
} ncfg_qdisc_root_t;

/* What one `RTM_GETQDISC` dump entry turned out to be. */
typedef enum {
	/* Neither the root nor the ingress hook: a child of somebody's class
	 * tree, which is outside 0023's scope and is not read. */
	NCFG_QDISC_ENTRY_OTHER = 0,
	/* The root qdisc. `record` is filled in. */
	NCFG_QDISC_ENTRY_ROOT = 1,
	/* The ingress hook, which is where a redirect filter lives. Only the
	 * interface index of `record` means anything. */
	NCFG_QDISC_ENTRY_INGRESS = 2
} ncfg_qdisc_entry_t;

/* One redirect, read back off a filter dump. */
typedef struct {
	/* The interface traffic arriving here is redirected to. */
	uint32_t target;
	/* Whether it wears netcfgd's filter handle (0137). A redirect somebody
	 * else installed is reported and never cleared. */
	int      ours;
} ncfg_qdisc_redirect_t;

/* ------------------------------------------------------------------------ *
 * The rate, and the factor of eight
 * ------------------------------------------------------------------------ */

/*
 * Bits per second to the bytes per second the kernel's rate field carries.
 *
 * **A rate that cannot be expressed is refused rather than rounded**, which is
 * this port's one behavioural change to the arithmetic and the reason is that
 * both roundings are silent and both are wrong in the dangerous direction:
 *
 *   * A rate below 8 bits per second truncates to zero, and zero in
 *     `TCA_CAKE_BASE_RATE64` means *unshaped*. Somebody asking for the slowest
 *     line expressible would get no shaper at all -- the opposite of what they
 *     wrote, and invisible in `tc qdisc show`, which prints no rate for both.
 *   * A rate that is not a whole number of bytes shapes at up to seven bits
 *     per second less than asked. That is nothing on an uplink and everything
 *     in a test that compares what was written with what was read back, which
 *     is exactly the comparison the units trap made necessary.
 *
 * The document can express both: `bandwidth` takes a bare number in bits, so
 * anything finer than a kbit reaches here unrounded.
 */
int ncfg_qdisc_rate_bytes(uint64_t bits, uint64_t *out, char *err, size_t err_size);

/*
 * The inverse, for a rate read back off the kernel.
 *
 * Refuses a byte rate above `UINT64_MAX / 8`, which has no answer in bits. The
 * Rust multiplies unconditionally: that panics under overflow checks and wraps
 * to a small number without them, so the same dump either kills the daemon or
 * reports a 40-gigabit line as a few hundred bits depending on the profile it
 * was built with.
 */
int ncfg_qdisc_rate_bits(uint64_t bytes, uint64_t *out, char *err, size_t err_size);

/*
 * Whether this scheduler takes a bandwidth.
 *
 * A fact about the kernel's schedulers rather than about netcfgd's
 * configuration language, which is why it is here and not in the model.
 */
int ncfg_qdisc_shapes(const char *kind);

/* ------------------------------------------------------------------------ *
 * Building requests
 * ------------------------------------------------------------------------ *
 *
 * Each appends one complete netlink message to `out` and returns 1, or leaves
 * a sentence in `err` and returns 0. None of them sends anything, and the
 * errno each one's reply may carry is documented with it, because that
 * knowledge is the expensive half of this module and it must not be lost
 * between here and the socket.
 */

/* Every qdisc on the machine. The ingress hooks come out of this dump too --
 * they are in it -- and knowing which interfaces have one is what makes the
 * filter dump affordable, since that has to be asked per interface. */
int ncfg_qdisc_build_dump(ncfg_buf_t *out, uint32_t seq, char *err, size_t err_size);

/*
 * Replace the root qdisc on one interface.
 *
 * `NLM_F_REPLACE` rather than a delete followed by an add: the two-step
 * version leaves the interface on the kernel default in between, which on a
 * shaped uplink is a window where traffic is unshaped.
 *
 * `ENOENT` in the reply means the module for this scheduler is not loaded and
 * could not be autoloaded -- the ordinary failure for `cake` on a kernel that
 * does not ship it.
 *
 * **`EINVAL` in the reply is the one case that has to be met rather than
 * avoided.** Naming a handle turns a replace into a change of the qdisc
 * already wearing it, and a qdisc cannot change kind: replacing `fq_codel 6e:`
 * with `cake` at the same handle answers `EINVAL`, and `tc qdisc replace ...
 * handle 6e: cake` fails identically with "Invalid qdisc name". netcfgd names
 * a handle so the qdisc carries its own ownership (0137), so the caller
 * answers `EINVAL` by sending `ncfg_qdisc_build_delete_root` and then **building
 * this same request again**, at a fresh sequence number: nothing in it depends
 * on what the delete changed, and a resent buffer would reuse a sequence number
 * a reply loop has already matched an error against.
 * That reopens the unshaped window `NLM_F_REPLACE` was chosen to close, for
 * one round trip, and only when the scheduler itself changes, which is a
 * config edit somebody made rather than something netcfgd does on its own.
 */
int ncfg_qdisc_build_set_root(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_qdisc_root_t *root, char *err, size_t err_size);

/*
 * Remove the root qdisc, which restores whatever the kernel defaults to.
 *
 * Not deletion in the sense an address deletion is: there is no such thing as
 * an interface without a qdisc, so the kernel immediately puts
 * `net.core.default_qdisc` back. That is the correct meaning of "netcfgd no
 * longer manages this", and it is why nothing here has to know what the
 * default was. `ENOENT` and `EINVAL` in the reply both mean there was nothing
 * to remove.
 */
int ncfg_qdisc_build_delete_root(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    char *err, size_t err_size);

/*
 * Attach the ingress qdisc, which is the hook a redirect filter hangs off.
 *
 * It queues nothing -- there is no queue on the way in -- it exists so that a
 * classifier has somewhere to live. `EEXIST` in the reply is not an error: the
 * qdisc is a fixed singleton, so one that is already there is already correct.
 */
int ncfg_qdisc_build_add_ingress(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    char *err, size_t err_size);

/* Remove the ingress qdisc, and with it every filter hanging off it. `ENOENT`
 * and `EINVAL` mean it was not there. */
int ncfg_qdisc_build_delete_ingress(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    char *err, size_t err_size);

/*
 * Redirect everything arriving on `index` to the device at `target`.
 *
 * One `matchall` classifier with one `mirred` action, which is the whole of
 * the filter machinery netcfgd generates. `ENOENT` in the reply means
 * `cls_matchall` or `act_mirred` is missing from this kernel.
 *
 * There is no counterpart that deletes one: removing the ingress qdisc takes
 * every filter hanging off it, so netcfgd never has to delete a filter
 * individually and never has to know which of them it wrote.
 */
int ncfg_qdisc_build_redirect(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    uint32_t target, char *err, size_t err_size);

/*
 * The filters on one interface's ingress hook.
 *
 * Per interface, not machine-wide, and that is not a preference:
 * `RTM_GETTFILTER` resolves the ifindex in the request and returns an empty
 * dump for one it cannot find, so a request with a zero index quietly succeeds
 * and reports nothing. It looks exactly like "no redirects are installed",
 * which is a plan that reinstalls one on every apply -- so a zero index is
 * refused here instead. `ENOENT` and `EINVAL` in the reply mean the interface
 * has no ingress qdisc, which is to say no filters.
 */
int ncfg_qdisc_build_filter_dump(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * Reading replies
 * ------------------------------------------------------------------------ */

/* `struct tcmsg` off the front of a dump payload, or a refusal for a payload
 * too short to hold one. */
int ncfg_qdisc_tcmsg_decode(const void *bytes, size_t length, ncfg_qdisc_tcmsg_t *out,
    char *err, size_t err_size);
/* The encoder, which is public because the tests build dump payloads with it
 * and because a caller assembling a request by hand has no other way to write
 * the body. */
void ncfg_qdisc_tcmsg_encode(const ncfg_qdisc_tcmsg_t *message, ncfg_buf_t *out);

/*
 * Read one `RTM_GETQDISC` dump payload.
 *
 * `*what` says which of the three kinds of entry it was; `record->index` is
 * filled for all three and the rest of `record` only for a root. A payload
 * this cannot make sense of is a refusal with a sentence, not a silent skip:
 * the Rust's `filter_map` drops a malformed entry and a truncated dump and a
 * quiet machine look the same afterwards.
 */
int ncfg_qdisc_entry_read(const void *payload, size_t length, ncfg_qdisc_entry_t *what,
    ncfg_qdisc_record_t *record, char *err, size_t err_size);

/*
 * One `RTM_GETTFILTER` dump entry, if it is a match-all redirect.
 *
 * Returns 1 and fills `out` for the exact shape `ncfg_qdisc_build_redirect`
 * writes, and 0 for everything else -- a `u32` classifier somebody added by
 * hand is not netcfgd's, and reporting it as one would produce a plan that
 * removed it. That is the same rule the NAT reader follows, and it is why
 * neither of them guesses.
 */
int ncfg_qdisc_redirect_read(const void *payload, size_t length,
    ncfg_qdisc_redirect_t *out, char *err, size_t err_size);

#endif /* NCFG_QDISC_H */
