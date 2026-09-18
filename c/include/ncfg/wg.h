/*
 * wg.h -- WireGuard over generic netlink: the SET the daemon sends and the
 * GET it reads back.
 *
 * The device itself is an ordinary rtnetlink link of kind `wireguard`, and
 * `wire.h` makes that one. Its configuration -- keys, peers, allowed IPs --
 * is not: it goes through the `wireguard` generic netlink family, which is
 * why nothing here could be written before `genl.h` existed.
 *
 * NESTING, WHICH IS THE PART THAT GOES WRONG
 *   Generic netlink validates strictly. An attribute the family declares as
 *   nested must carry `NLA_F_NESTED`, or the whole message is rejected with
 *   `EINVAL` naming nothing at all. rtnetlink does not enforce it, which is
 *   why netcfgd sent unflagged nests for years and only met this here. Every
 *   nest below goes through `ncfg_wire_attr_put_nested`, which sets the bit,
 *   and the test walks the raw bytes to prove it -- the ordinary reader masks
 *   the bit off, so the one property under test is invisible through it.
 *
 *   The peers are a nest of nests: `WGDEVICE_A_PEERS` holds an array whose
 *   attribute *types are indices rather than meanings*, each index holding a
 *   peer, each peer holding another such array of allowed IPs.
 *
 * KEY MATERIAL IS BYTES, AND NEVER REACHES A DIAGNOSTIC
 *   The document carries keys as `ncfg_secret_ref_t` -- a reference, never the
 *   material -- so the 32 raw octets arrive here from whatever resolved that
 *   reference, beside the document rather than inside it. Nothing in this
 *   module renders a key, quotes one in an error, or hands one back: a `GET`
 *   reports only whether a preshared key is *set*, which is the kernel's own
 *   asymmetry and the reason reconciliation can compare what it reads without
 *   ever observing a secret. `ncfg_wg_messages_free` scrubs the message bytes
 *   before releasing them, because a built `SET_DEVICE` carries the private
 *   key in the clear and freed heap is handed to the next caller.
 *
 * THE NUMBERS ARE THE KERNEL'S
 *   `WGDEVICE_A_*`, `WGPEER_A_*`, `WGALLOWEDIP_A_*` and the two flags come
 *   from <linux/wireguard.h>. The Rust spells them out and warns about the
 *   gap that makes it worth it: `WGDEVICE_A_PUBLIC_KEY` sits at 4 between the
 *   private key and the flags, because a `GET` reports the derived key even
 *   though nothing sets it. Numbering `FLAGS` as 4 by hand sends four bytes
 *   where 32 octets are expected and the kernel answers `ERANGE`, naming
 *   neither the attribute nor the length. Found exactly that way, in the Rust,
 *   and not repeatable here because the numbers are no longer written down
 *   twice.
 */
#ifndef NCFG_WG_H
#define NCFG_WG_H

#include <stddef.h>
#include <stdint.h>

#include <linux/wireguard.h>

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/genl.h"
#include "ncfg/wire.h"

/* The family to resolve before any of this can be sent. */
#define NCFG_WG_FAMILY WG_GENL_NAME

/* A key, as the kernel wants it: 32 raw octets, never text. */
#define NCFG_WG_KEY_LEN WG_KEY_LEN

/* `[2001:db8::1]:51820` and its terminator. */
#define NCFG_WG_ENDPOINT_TEXT_MAX 54u

/*
 * How many bytes one netlink attribute can carry.
 *
 * **This is the bound the peer list crosses**, and it is the defect this port
 * fixes rather than carries across. An attribute's length field is 16 bits and
 * counts its own 4-byte header, so 65,531 bytes is the whole of it -- and the
 * Rust builds the entire peer set as one attribute, casting the length to
 * `u16` with the lint suppressed. At somewhere between five hundred and a
 * thousand peers that cast wraps, the attribute claims a length of nearly
 * nothing, and the kernel reads the next attribute out of the middle of the
 * peer list. Nothing refuses it and nothing says so.
 *
 * `ncfg_wg_set_device_build` splits instead: see the note on it.
 */
#define NCFG_WG_ATTR_VALUE_MAX 65531u

/*
 * What the document refers to but cannot carry, resolved by the caller.
 *
 * One of these per peer, in the document's own peer order. Two things live
 * here rather than in `ncfg_wg_peer_t` and for the same reason -- the document
 * is a pure function of the config files and neither of these is:
 *
 *   * a preshared key is a `ncfg_secret_ref_t` in the document, and resolving
 *     it reads a file, a keyring or a subprocess;
 *   * an endpoint is text in the document and may name a host, and resolving a
 *     name is a DNS lookup. This module does no I/O, so the lookup belongs to
 *     the caller -- `ncfg_wg_endpoint_parse` handles the literal case, which
 *     is most of them.
 */
typedef struct {
	/* 32 octets, or NULL where the document names no preshared key. */
	const unsigned char *preshared_key;
	/* Whether `endpoint` means anything. A peer with no endpoint is a
	 * roaming peer, which is ordinary rather than an omission. */
	int                  has_endpoint;
	ncfg_wire_ip_t       endpoint;
	uint16_t             endpoint_port;
} ncfg_wg_peer_material_t;

/*
 * A `SET_DEVICE` to build: the document's desired state, plus the material.
 *
 * **The document's own types, not a second shape of them.** `ncfg_wg_peer_t`
 * already holds the public key as octets, the allowed IPs as text and the
 * keepalive as an optional integer, and a parallel peer type here would be a
 * second place for the model to be wrong -- which is how this project once
 * shipped `wire_guard` for `wireguard`. What is added is only what the
 * document cannot hold.
 *
 * Both halves are optional, because the kernel's `SET_DEVICE` is deliberately
 * partial: an attribute that is not present is left alone, and the peer list
 * is replaced only when the flag says so. That is how `wg set wg0 listen-port
 * 51821` changes a port without touching a peer, and decision 0054 needs the
 * same thing for the same reason -- `wg.set_device` and `wg.set_peers` are two
 * ops that are supposed to mean different things.
 */
typedef struct {
	/* The interface, for `WGDEVICE_A_IFNAME`. */
	const char                    *name;
	/* The desired state. `peers` is read only when `replace_peers` is set. */
	const ncfg_wireguard_config_t *config;
	/* 32 octets, or NULL to leave the loaded private key alone. */
	const unsigned char           *private_key;
	/* `config->peer_count` entries, or NULL where no peer needs either. */
	const ncfg_wg_peer_material_t *material;
	/*
	 * Whether `config->peers` is the whole list, replacing what the device
	 * holds.
	 *
	 * **Never true with an empty list by accident.** True and no peers is a
	 * legitimate instruction -- it is how the last peer is removed -- and it
	 * is also what a caller that forgot to fill the list produces. Without
	 * it a `SET_DEVICE` merges, and a peer the document has removed goes on
	 * accepting traffic: constraint 1 applied to a peer list.
	 */
	int                            replace_peers;
} ncfg_wg_request_t;

/* One complete netlink message, ready for a socket that this module does not
 * hold. */
typedef struct {
	uint8_t *bytes;
	size_t   length;
} ncfg_wg_message_t;

/* The messages one `SET_DEVICE` became. See `ncfg_wg_set_device_build`. */
typedef struct {
	ncfg_wg_message_t *message;
	size_t             count;
} ncfg_wg_messages_t;

/*
 * Build the `SET_DEVICE` for a device, as one message or as several.
 *
 * **Several, when the peer list does not fit one attribute.** That is not this
 * port inventing a protocol: <linux/wireguard.h> says in as many words that
 * where the configuration exceeds one message, "several messages should be
 * sent one after another, with each successive one filling in information not
 * contained in the prior", and that `WGDEVICE_F_REPLACE_PEERS` "probably
 * should not be specified in fragments that come after, so that the list of
 * peers is only cleared the first time but appended after". Which is exactly
 * what `wg(8)` does, and what the kernel's own dumps do coming back.
 *
 * So the first message carries the device -- name, flags, private key, port,
 * mark -- and as many peers as fit; each one after it carries the name and
 * more peers, and *never the replace flag*, because a fragment that repeated
 * it would clear the peers the fragment before it had just installed, and the
 * device would end up holding only the last few hundred.
 *
 * The alternative was to refuse a peer set past the bound with a sentence. It
 * was not taken because the bound is not netcfgd's: a hub with a thousand
 * peers is an ordinary WireGuard deployment, one attribute cannot hold it on
 * any kernel, and a refusal would make netcfgd unable to configure a device
 * that `wg(8)` configures without comment. What is refused is only what has no
 * wire form at all -- a *single* peer too large for one attribute, which is a
 * peer with some 2,700 allowed IPs -- and that refusal names the peer and the
 * size.
 *
 * **The messages must be sent in order, and every one of them sent.** Stopping
 * after the first leaves a device holding the first few hundred peers and the
 * replace flag already spent.
 *
 * The nth message carries sequence number `seq + n`; a caller must not reuse
 * those numbers for anything else.
 */
int ncfg_wg_set_device_build(ncfg_wg_messages_t *out, const ncfg_genl_family_t *family,
    uint32_t seq, const ncfg_wg_request_t *request, char *err, size_t err_size);

/* Release the messages, scrubbing them first: see the header comment. Freeing
 * something that was never built is nothing. */
void ncfg_wg_messages_free(ncfg_wg_messages_t *messages);

/* Build the `GET_DEVICE` dump request for one interface. */
int ncfg_wg_get_device_request(ncfg_buf_t *out, const ncfg_genl_family_t *family,
    uint32_t seq, const char *name, char *err, size_t err_size);

/* One entry of a peer's allowed IPs. */
typedef struct {
	ncfg_wire_ip_t address;
	uint8_t        prefix;
} ncfg_wg_allowed_ip_t;

/*
 * One peer as the kernel holds it.
 *
 * Not the same shape as the document's peer, and the asymmetry is the point:
 * there is no name here, because the local label is netcfgd's and the kernel
 * has never heard of it, and there is no preshared key, because the kernel
 * does not report one. `has_preshared_key` is the whole of what can be known,
 * which is what lets reconciliation compare a device it never observed a
 * secret of.
 */
typedef struct {
	unsigned char         public_key[NCFG_WG_KEY_LEN];
	/* Whether one is set. The value is not reported, and asking for it would
	 * be asking the kernel to hand back a secret. */
	int                   has_preshared_key;
	int                   has_endpoint;
	ncfg_wire_ip_t        endpoint;
	uint16_t              endpoint_port;
	ncfg_wg_allowed_ip_t *allowed_ips;
	size_t                allowed_ip_count;
	/* Seconds, zero meaning off. */
	uint16_t              keepalive;
} ncfg_wg_peer_state_t;

/*
 * What the kernel currently holds for a device.
 *
 * The public key is the derived one; the private key is never reported, which
 * is the asymmetry that makes an observation safe to keep.
 */
typedef struct {
	int                   has_public_key;
	unsigned char         public_key[NCFG_WG_KEY_LEN];
	int                   has_listen_port;
	uint16_t              listen_port;
	int                   has_fwmark;
	uint32_t              fwmark;
	ncfg_wg_peer_state_t *peers;
	size_t                peer_count;
} ncfg_wg_state_t;

/*
 * Fold one `GET_DEVICE` reply payload into a state.
 *
 * **Called for every reply, not just the first.** A device with many peers
 * arrives as several messages, each carrying a slice of the list, and taking
 * only the first reports a truncated configuration as the whole of it -- which
 * a reconciler then reads as "these peers are missing" and reinstalls on every
 * pass.
 *
 * The kernel may also split one peer across messages, repeating it with only
 * its public key and more allowed IPs. Such a continuation is folded into the
 * peer already there rather than appended beside it: the Rust appends, which
 * reports one peer twice, each with half its allowed IPs. <linux/wireguard.h>
 * says the receiver is the one that must "coalesce adjacent peers", so this is
 * the reader's job and not a nicety.
 *
 * `state` must be zeroed before the first call. A refusal leaves it valid and
 * freeable; it is never partly a different device.
 */
int ncfg_wg_state_merge(ncfg_wg_state_t *state, const void *payload, size_t length,
    char *err, size_t err_size);

/* Release what a state holds, and leave it usable and empty. */
void ncfg_wg_state_free(ncfg_wg_state_t *state);

/*
 * `127.0.0.1:51820` or `[2001:db8::1]:51820` into an address and a port.
 *
 * Literals only. A host name is a DNS lookup, which is I/O, and nothing in
 * this module does any -- a caller with a name resolves it and fills in
 * `ncfg_wg_peer_material_t` directly. The brackets are required around an IPv6
 * literal for the reason they exist at all: `fd00::1:51820` is a perfectly
 * good address, and reading a port off the end of one would silently
 * reconfigure a peer to talk to somewhere else.
 */
int ncfg_wg_endpoint_parse(const char *text, ncfg_wire_ip_t *address, uint16_t *port,
    char *err, size_t err_size);

/* The inverse, in the spelling the document uses. `out_size` must be at least
 * `NCFG_WG_ENDPOINT_TEXT_MAX`. */
int ncfg_wg_endpoint_text(const ncfg_wire_ip_t *address, uint16_t port, char *out,
    size_t out_size, char *err, size_t err_size);

#endif /* NCFG_WG_H */
