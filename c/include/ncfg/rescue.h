/*
 * rescue.h -- netrescue's parts: which ports, which document, and whether a
 * gateway answers.
 *
 * WHAT NETRESCUE IS
 *   A box booting on a network it may not know, with nobody at the console,
 *   has to end up reachable. netrescue climbs a ladder: it writes a netcfgd
 *   document for the rung it is on, a daemon applies it, and when no gateway
 *   answers by the rung's deadline the next rung's document replaces it.
 *   0326 is the decision and says why each rung is a document rather than a
 *   command.
 *
 * WHAT IS HERE AND WHAT IS NOT
 *   Everything a test can drive without a network: the ports, read from a
 *   sysfs directory the caller names; the document, rendered from the ports
 *   and the rung; the default gateways, parsed from `/proc/net/route` text.
 *   The one call that touches the network is `ncfg_rescue_gateway_answers`.
 *   The loop, the daemon it starts and the report it prints are the
 *   program's, in `src/main/rescue_main.c`, because a library never prints.
 */
#ifndef NCFG_RESCUE_H
#define NCFG_RESCUE_H

#include <stddef.h>
#include <stdint.h>

/* More than any of the machines this is for has: an HP G6 carries four, and a
 * card or two besides. A port past the limit is reported, not silently lost --
 * see `ncfg_rescue_ports`. */
#define NCFG_RESCUE_PORT_MAX 32

/* IFNAMSIZ, without pulling `net/if.h` into every includer. */
#define NCFG_RESCUE_NAME_MAX 16

/* The fallback address when none is given: the rescue stick's own, 2026-11-20.
 * A /16 in 10/8 because a laptop on a direct cable is told "use 10.0.x.y". */
#define NCFG_RESCUE_FALLBACK_DEFAULT "10.0.0.250/16"

typedef struct {
	char name[NCFG_RESCUE_NAME_MAX];
	/* 1 with a carrier, 0 without, -1 when the kernel would not say -- which
	 * is what reading `carrier` on a link that is administratively down does. */
	int carrier;
	/* What listening learned on this port (the LISTEN rung): an address with
	 * its prefix, and the gateway, both empty until it has. Kept by the
	 * caller across rungs, so climbing never takes it away. */
	char learned[24];
	char gateway[16];
} ncfg_rescue_port_t;

typedef struct {
	ncfg_rescue_port_t ports[NCFG_RESCUE_PORT_MAX];
	size_t             count;
	/* Ethernet ports found past the limit, or whose name the configuration
	 * language could not carry; counted so the report can say so. */
	size_t skipped;
} ncfg_rescue_ports_t;

/*
 * The rungs. Each one keeps everything the rungs below it put on the machine:
 * climbing must never take a way in away.
 */
typedef enum {
	/* DHCP on every port, and the fixed fallback on one. */
	NCFG_RESCUE_RUNG_ADDRESS = 1,
	/* And on a port with a carrier and no lease, an address learned by
	 * listening to the network's ARP, with its gateway. Before the forcing
	 * rungs because it disturbs nothing, and they are for the other ports. */
	NCFG_RESCUE_RUNG_LISTEN,
	/* And autonegotiation off at 1000/full on every port with no carrier. */
	NCFG_RESCUE_RUNG_FORCE_1000,
	/* The same at 100/full: an old switch, or a cable with two pairs. */
	NCFG_RESCUE_RUNG_FORCE_100,
	/* And the driver of every port still without a carrier unbound and
	 * bound again, with what the kernel said about it reported. The
	 * document is rung 4's: the rebind is netrescue's own act (0326). */
	NCFG_RESCUE_RUNG_REBIND
} ncfg_rescue_rung_t;

#define NCFG_RESCUE_RUNG_LAST NCFG_RESCUE_RUNG_REBIND

/* A sentence for the report: what this rung tries. */
const char *ncfg_rescue_rung_says(ncfg_rescue_rung_t rung);

/*
 * The Ethernet ports under `sysfs_net` -- `/sys/class/net` on a machine, a
 * directory a test built otherwise.
 *
 * A port is an entry whose `type` is 1, which has a `device` (hardware, USB
 * included -- so a tethered phone counts and a bridge or a veth does not),
 * and which is not a radio: no `wireless` or `phy80211` in it, and no
 * `DEVTYPE=wlan` or `DEVTYPE=wwan` in its `uevent`. Sorted by name, so the
 * same machine renders the same document. 0 only when the directory cannot
 * be read at all; a machine with no ports is a count of 0, not a failure.
 */
int ncfg_rescue_ports(const char *sysfs_net, ncfg_rescue_ports_t *out, char *err, size_t err_size);

/*
 * Which port carries the fallback address: `keep` again while it is still
 * present and has not lost its carrier, so the address does not wander;
 * otherwise the first with a carrier; otherwise the first. -1 when there are
 * no ports. `keep` may be NULL or empty.
 */
int ncfg_rescue_fallback_port(const ncfg_rescue_ports_t *ports, const char *keep);

/*
 * The document for `rung`, as configuration-language text, into `out`.
 *
 * `fallback` is an address with its prefix, put on the port at index
 * `fallback_at` beside DHCP; NULL or an index of -1 puts none. It is checked
 * here only for characters the language would have to escape -- the compiler
 * the daemon runs is what says whether it is an address, and it says so in
 * the daemon's log, which the report points at.
 *
 * `renegotiate` is for the first rung once the ladder has gone round: a port
 * a forcing rung left at a fixed speed keeps it when the setting leaves the
 * document -- the kernel holds it, not netcfgd -- so autonegotiation is asked
 * for back, on the ports with no carrier, which are the ones that were forced.
 */
int ncfg_rescue_render(const ncfg_rescue_ports_t *ports, ncfg_rescue_rung_t rung,
    const char *fallback, int fallback_at, int renegotiate, char *out, size_t out_size, char *err,
    size_t err_size);

/* The IPv4 default routes' gateways, from `/proc/net/route`'s text: network
 * byte order, in the order the table lists them. */
size_t ncfg_rescue_default_gateways(const char *route_text, uint32_t *out, size_t max);

/*
 * Whether `/proc/net/arp`'s text holds a completed entry for `gateway`
 * (network byte order): the flags say `ATF_COM` and the hardware address is
 * not zero. A router that drops pings still answers ARP -- it has to, to
 * route at all -- so after an echo nobody answered, this is the second way a
 * gateway counts as there. Pure.
 */
int ncfg_rescue_arp_resolved(const char *arp_text, uint32_t gateway);

/*
 * Whether `gateway` (network byte order) answers an ICMP echo within
 * `timeout_ms`. Needs a raw socket, so root or CAP_NET_RAW; without one the
 * answer is 0 with the reason in `err`, which is not the same as silence and
 * the report says which.
 */
int ncfg_rescue_gateway_answers(uint32_t gateway, int timeout_ms, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * Listening
 * ------------------------------------------------------------------------ */

/* One ARP frame heard: who sent it, whom it asked about, network byte order.
 * A probe (sender 0.0.0.0) is kept too: its target is an address somebody is
 * about to take. */
typedef struct {
	uint32_t sender;
	uint32_t target;
} ncfg_rescue_heard_t;

typedef struct {
	uint32_t network;  /* the /24 most of what was heard is in */
	uint32_t gateway;  /* its busiest address: asked about and asking most */
	uint32_t address;  /* one in it nobody was heard using, or 0 */
	size_t   heard;    /* how many frames were in that /24 */
} ncfg_rescue_learned_t;

/*
 * What a port's ARP says about the network it is on. Pure, so a test can hand
 * it any traffic it likes.
 *
 * **A /24, and the busiest address is the gateway.** Every host on a LAN asks
 * for its gateway and the gateway asks for every host, so whatever the
 * network's real prefix it is the address heard most; and a /24 around it is
 * the guess that is right on almost every network a rescue meets and never
 * wider than the truth. Link-local, loopback, multicast and the zero address
 * are passed over. The address chosen is the highest in .200-.250 nobody was
 * heard using, high because DHCP pools usually start low; `taken` is more
 * addresses to avoid (one a probe already found in use). 0 when fewer than
 * `minimum` frames were in any one /24.
 */
int ncfg_rescue_learn(const ncfg_rescue_heard_t *heard, size_t count, size_t minimum,
    const uint32_t *taken, size_t taken_count, ncfg_rescue_learned_t *out);

/*
 * Listen for ARP on `port` for `seconds`, filling `heard` up to `max`. Needs
 * a packet socket, so root or CAP_NET_RAW. 0 with a sentence where it could
 * not listen at all.
 */
int ncfg_rescue_listen(const char *port, int seconds, ncfg_rescue_heard_t *heard, size_t max,
    size_t *count, char *err, size_t err_size);

/*
 * RFC 5227's probe: ask, from 0.0.0.0, who has `address` on `port`, and
 * listen `timeout_ms` for an answer -- or for another host probing for the
 * same address. 1 when nobody claimed it, 0 when somebody did or the probe
 * could not be sent (with a sentence then).
 */
int ncfg_rescue_address_free(const char *port, uint32_t address, int timeout_ms, char *err,
    size_t err_size);

/* ------------------------------------------------------------------------ *
 * Rebinding a driver
 * ------------------------------------------------------------------------ */

/*
 * Unbind `port`'s device from its driver and bind it again, through
 * `sysfs_net`/PORT/device and its `driver` link: the device's own name (a PCI
 * address, `virtio1`, a USB interface) written to the driver's `unbind` and
 * then its `bind`. What a module reload does for one device, without
 * touching the others the module drives. `driver` gets the driver's name and
 * `device` the device's, for the report and for finding what the kernel said.
 * 0 with a sentence where the port has no device or driver to rebind, or a
 * write was refused.
 */
int ncfg_rescue_rebind(const char *sysfs_net, const char *port, char *driver, size_t driver_size,
    char *device, size_t device_size, char *err, size_t err_size);

/*
 * Whether one kernel log record, as `/dev/kmsg` gives it, is about `driver`
 * or `device` and says something went wrong -- a firmware load, a reset, a
 * failure. The text after the record's header goes in `out`. Pure.
 */
int ncfg_rescue_kmsg_complaint(const char *record, const char *driver, const char *device,
    char *out, size_t out_size);

/* ------------------------------------------------------------------------ *
 * A name on the local link
 * ------------------------------------------------------------------------ */

#define NCFG_RESCUE_MDNS_PORT 5353
#define NCFG_RESCUE_NAME_DEFAULT "rescue"

/*
 * The answer to one mDNS query, if it asks for `name`.local: A records for
 * `ipv4` and AAAA records for `ipv6` (network byte order, 4 and 16 bytes
 * each), whichever the question asks -- A, AAAA or ANY, class IN, the
 * unicast-response bit ignored since every answer here is multicast. The
 * name is compared without case, as DNS does. Returns the length written to
 * `out`, or 0 where the query is malformed, is a response, or asks for
 * something else. Pure, and the only part of the responder that reads bytes
 * from the network, so it is what is fuzzed and tested.
 */
size_t ncfg_rescue_mdns_answer(const uint8_t *query, size_t length, const char *name,
    const uint32_t *ipv4, size_t ipv4_count, const uint8_t (*ipv6)[16], size_t ipv6_count,
    uint8_t *out, size_t out_size);

#endif /* NCFG_RESCUE_H */
