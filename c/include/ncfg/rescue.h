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
	/* And autonegotiation off at 1000/full on every port with no carrier. */
	NCFG_RESCUE_RUNG_FORCE_1000,
	/* The same at 100/full: an old switch, or a cable with two pairs. */
	NCFG_RESCUE_RUNG_FORCE_100
} ncfg_rescue_rung_t;

#define NCFG_RESCUE_RUNG_LAST NCFG_RESCUE_RUNG_FORCE_100

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
 * Whether `gateway` (network byte order) answers an ICMP echo within
 * `timeout_ms`. Needs a raw socket, so root or CAP_NET_RAW; without one the
 * answer is 0 with the reason in `err`, which is not the same as silence and
 * the report says which.
 */
int ncfg_rescue_gateway_answers(uint32_t gateway, int timeout_ms, char *err, size_t err_size);

#endif /* NCFG_RESCUE_H */
