/*
 * supplicant.h -- driving `wpa_supplicant` over its control socket.
 *
 * WHAT THIS IS
 *   Decision 0014 makes `wpa_supplicant` the floor rather than the fallback,
 *   and decision 0015 says it holds no state: netcfgd supplies every network
 *   at apply time and removes them when the document stops asking. This module
 *   is the mechanism for both, and for wired 802.1X (decision 0008), which
 *   speaks the same protocol through the same socket.
 *
 * THE SPLIT, WHICH IS DELIBERATE
 *   The protocol and the configuration are pure text and can be tested
 *   exhaustively on a machine with no radio and no supplicant installed. The
 *   client is the socket, and needs something answering to say anything about.
 *   `supplicant_test.c` is the first; `supplicant_client_test.c` drives the
 *   second against a socket of its own making.
 *
 * THE CREDENTIAL IS A REFERENCE, AND IT IS RESOLVED AT THE WRITE
 *   **This is where the C diverges from the Rust on purpose.** There, a
 *   `Setting` carries the rendered value, so a resolved passphrase sits in a
 *   `Vec<Setting>` for as long as the network takes to configure -- through a
 *   loop that formats each command, through the error path that formats a
 *   refusal, and through a `Drop` that does not wipe. Here a sensitive setting
 *   carries `secret`, a borrowed `ncfg_secret_ref_t`, and no value at all;
 *   `ncfg_supplicant_setting_command` resolves it, formats one line, and the
 *   caller wipes that line the moment it has been sent.
 *
 *   The cost is that a credential is resolved twice per network: once while
 *   the settings are built, to answer "can this network be expressed at all"
 *   before anything is sent, and once at the write. That is the price of not
 *   holding it, and it is paid by the `file` provider as one extra read.
 *
 *   **No passphrase, key or password reaches a log line, a diagnostic or a
 *   file netcfgd does not own.** `ncfg_supplicant_setting_redacted` is what a
 *   message may quote and it never resolves anything;
 *   `supplicant_client_test.c` proves the rule the way `secrets_test.c` does,
 *   with one canary swept through every channel.
 *
 * THE THREE CONVENTIONS
 *   `base.h`'s, unchanged: 1 for success and 0 for failure with a sentence in
 *   `err`; NULL for a pointer; an `ncfg_x_free` beside every aggregate, and
 *   freeing something never filled in is nothing.
 */
#ifndef NCFG_SUPPLICANT_H
#define NCFG_SUPPLICANT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/secrets.h"

/* ------------------------------------------------------------------------ *
 * The protocol's text, in and out
 * ------------------------------------------------------------------------ */

/*
 * How much of one reply this will accept.
 *
 * **A unix datagram is truncated silently.** `recv` into a buffer smaller than
 * the datagram returns the buffer's worth and discards the rest, with no error
 * and no flag -- the real length is only available through `MSG_TRUNC`.
 *
 * So the size is chosen to be past anything the supplicant sends, and a
 * datagram that filled it exactly is reported as a failure rather than used.
 * Measured against `wpa_supplicant` 2.10 on the reporting machine, largest
 * reply first: `GET_CAPABILITY freq` 1647 bytes, `STATUS` 359,
 * `GET_CAPABILITY channels` 297, `SCAN_RESULTS` 110 with one access point in
 * range. `SCAN_RESULTS` is the only one without a bound: a row is roughly 70
 * to 110 bytes, so this holds something like seventy-five to a hundred access
 * points. 0224.
 */
#define NCFG_SUPPLICANT_REPLY_MAX 8192u

/* What the supplicant said. */
typedef enum {
	/* `OK`. */
	NCFG_SUPPLICANT_REPLY_OK,
	/* `FAIL`, or an unsolicited failure. */
	NCFG_SUPPLICANT_REPLY_FAIL,
	/* Anything else: the body, with the trailing newline removed. */
	NCFG_SUPPLICANT_REPLY_DATA
} ncfg_supplicant_reply_t;

/*
 * Which kind a raw reply is, trimming it in place.
 *
 * **In place rather than into an owned string**, because the body is already
 * in the caller's buffer and a copy of it would be a second place a `PONG`
 * could be read from. The trailing newlines and NULs the supplicant appends
 * are removed, so the body afterwards is `raw` itself.
 */
int ncfg_supplicant_reply_parse(char *raw);

/*
 * Whether a line is an unsolicited event rather than a reply.
 *
 * `wpa_supplicant` prefixes events with a priority in angle brackets --
 * `<3>CTRL-EVENT-CONNECTED ...` -- and sends them on the same socket as
 * replies once a client has attached. A client that does not separate them
 * will eventually read an event as the answer to a command and act on it.
 */
int ncfg_supplicant_is_event(const char *line);

/*
 * An unsolicited event, with its priority stripped.
 *
 * The text is as long as a reply may be, because events and replies share one
 * socket and one datagram size. Truncating an event quietly is the failure
 * this module refuses everywhere else.
 */
typedef struct {
	/* Priority, 0 (most) to 4 (least). */
	int  priority;
	char text[NCFG_SUPPLICANT_REPLY_MAX];
} ncfg_supplicant_event_t;

/* Parse an event line. 0 where it is not one. */
int ncfg_supplicant_event_parse(const char *line, ncfg_supplicant_event_t *out);

/*
 * The event's name: the first word, such as `CTRL-EVENT-CONNECTED`.
 *
 * Written into `out` and returned, so it can be used in a comparison directly.
 * Empty for an event with no text at all.
 */
const char *ncfg_supplicant_event_name(const ncfg_supplicant_event_t *event, char *out,
    size_t out_size);

/* Whether the event's name is exactly this one. */
int ncfg_supplicant_event_is(const ncfg_supplicant_event_t *event, const char *name);

/*
 * The access point a `CTRL-EVENT-CONNECTED` says was joined.
 *
 * The format is `wpa_supplicant`'s own, read out of the binary rather than
 * from documentation, which does not give it:
 *
 *     CTRL-EVENT-CONNECTED - Connection to %02x:...:%02x completed [id=%d id_str=%s%s]
 *
 * So the address is the fifth word. Positional rather than matched on
 * "Connection to", because that phrase is prose and the shape around it is
 * what the format string fixes -- and a reader keyed on the prose would break
 * on a translation that never comes while missing a reordering that might.
 *
 * 0 for every other event, including a connect that did not name an address: a
 * caller comparing addresses must not be handed an empty one, which would read
 * as "moved to nowhere". `out` needs 18 bytes.
 */
int ncfg_supplicant_event_connected_bssid(const ncfg_supplicant_event_t *event, char *out,
    size_t out_size);

/*
 * Which configured network a `CTRL-EVENT-CONNECTED` says the station is on.
 *
 * The same format string one field along, so the id is the seventh word,
 * carrying the opening bracket. **This is what tells a roam from a network
 * change**: a station moving between access points on one network keeps this
 * id; a station leaving for a network it also holds credentials for does not,
 * and both arrive as a `CONNECTED` naming an address that is not the last one.
 * 0239.
 *
 * 0 where there is no id to have: the supplicant writes `-1` when the
 * association has no configured network behind it, which does not parse as an
 * unsigned number and needs no separate case.
 */
int ncfg_supplicant_event_network_id(const ncfg_supplicant_event_t *event, uint32_t *out);

/*
 * A `key=value` field of the event text, with any quotes taken off.
 *
 * **The value is not always whitespace-delimited**, which is why this is not a
 * split on spaces. `ssid=` is quoted, and an SSID is escaped by
 * `printf_encode` -- which leaves a space alone, a space being printable
 * ASCII. So `ssid="Guest Wifi" auth_failures=3` splits into two fields on
 * whitespace and the network is reported as `"Guest`, with the failure count
 * lost behind it. Names with spaces in them are not exotic; they are what a
 * router ships with.
 *
 * The key is matched at a field boundary, so asking for `id` does not answer
 * with the tail of `bssid=a0:a4:7f:23:9a:cf`.
 */
int ncfg_supplicant_event_field(const ncfg_supplicant_event_t *event, const char *key, char *out,
    size_t out_size);

/*
 * Decode `wpa_supplicant`'s escaping of a text field.
 *
 * The supplicant does not hand back the octets it was given. It runs them
 * through `printf_encode`, which escapes a quote, a backslash, `\n`, `\r`,
 * `\t`, `\e`, and **every byte outside printable ASCII** as `\xHH`. So an SSID
 * of `caf<e-acute>` comes back as the eleven characters `caf\xc3\xa9`, and a
 * reader that takes the field literally shows that to the operator.
 *
 * This was found by running against a real supplicant rather than by reading
 * the documentation, which does not mention it. Octets rather than text
 * because the encoding is bytewise: a multi-byte character arrives as several
 * `\xHH` escapes and only becomes text again once they are joined.
 *
 * Returns how many octets the whole decoding is, writing at most `out_size` of
 * them -- so a caller checks the return against its buffer the way it would
 * check `snprintf`.
 */
size_t ncfg_supplicant_printf_decode(const char *text, unsigned char *out, size_t out_size);

/* One scan result. */
typedef struct {
	/* The access point's address, as the supplicant spelled it. */
	char       *bssid;
	int64_t     frequency; /* centre frequency in MHz */
	int64_t     signal;    /* dBm */
	/* The flags string, for example `[WPA2-PSK-CCMP][ESS]`. */
	char       *flags;
	ncfg_ssid_t ssid;
} ncfg_supplicant_scan_t;

/*
 * Parse `SCAN_RESULTS`.
 *
 * The first line is a header and is skipped. A row netcfgd cannot make sense
 * of is skipped rather than failing the whole scan: one malformed entry from a
 * misbehaving access point should not make a laptop unable to list networks.
 *
 * Fails only where there is nothing to allocate with, which is why an empty
 * list is a success.
 */
int ncfg_supplicant_parse_scan_results(const char *body, ncfg_supplicant_scan_t **out,
    size_t *count_out, char *err, size_t err_size);

void ncfg_supplicant_scans_free(ncfg_supplicant_scan_t *scans, size_t count);

/* Whether this access point requires a passphrase. */
int ncfg_supplicant_scan_is_secured(const ncfg_supplicant_scan_t *scan);

/*
 * Whether joining it means 802.1X rather than a passphrase.
 *
 * `wpa_supplicant` spells the key management `WPA2-EAP-CCMP`, or
 * `WPA2-EAP+FT/EAP-CCMP` where it also does fast transition, so the substring
 * is the whole test. Both are secured as well -- an enterprise network needs a
 * credential; what differs is which kind, and a client that cannot tell asks
 * for the wrong one.
 *
 * **Unauthenticated, like everything else in a beacon.** It says what to put
 * in a dialog, not what to trust.
 */
int ncfg_supplicant_scan_is_enterprise(const ncfg_supplicant_scan_t *scan);

/*
 * Whether it is opportunistic wireless encryption.
 *
 * **Encrypted and unauthenticated, which is neither of the other two.**
 * `is_secured` asks whether joining needs a credential and OWE needs none, so
 * it answers false -- correctly, and a client that stops there calls the
 * network open and writes an open profile for it. That profile cannot
 * associate: OWE is `key_mgmt=OWE` with management frame protection required.
 * The scan was the one place that could not say so. 0227.
 */
int ncfg_supplicant_scan_is_owe(const ncfg_supplicant_scan_t *scan);

/*
 * What a scan row is secured with, as an `ncfg_security_kind_t`.
 *
 * The three questions above composed into the document's vocabulary, for
 * `ncfg_wifi_network_for`: a listing says which `network` block each access
 * point matches, and two blocks may share an SSID and differ only in this.
 * Without it a scan credits an open access point to a WPA2 block of the same
 * name -- the association is resolved correctly and the listing beside it was
 * not.
 *
 * `NCFG_WIFI_SECURITY_UNSTATED` for a row that is secured with something no
 * `network` block can express, which today means WEP. Guessing `psk` there
 * would be worse than not answering: it would name a block that does not
 * describe the access point.
 */
int ncfg_supplicant_scan_security(const ncfg_supplicant_scan_t *scan);

/*
 * Whether it advertises 802.11r fast transition.
 *
 * Not the mobility *domain* -- two access points can both do fast transition
 * and belong to different domains -- it is the cheap test for whether asking
 * about the domain is worth a round trip at all.
 */
int ncfg_supplicant_scan_does_fast_transition(const ncfg_supplicant_scan_t *scan);

/*
 * The mobility domain id from a `BSS <bssid>` reply.
 *
 * **Not a trust signal, and nothing here should treat it as one.** The element
 * is unauthenticated bytes in a beacon, so anything can advertise any id. What
 * it is good for is diagnosis: two access points a client will not roam
 * between, both claiming fast transition, are worth looking at differently
 * depending on whether they claim the same domain.
 *
 * 0 where the reply has no `mdid=`, which is the ordinary case for a BSS that
 * does not do fast transition at all -- and for an empty one, because an empty
 * string is something a caller would print.
 */
int ncfg_supplicant_parse_mobility_domain(const char *body, char *out, size_t out_size);

/* One entry of `LIST_NETWORKS`. */
typedef struct {
	uint32_t    id;
	ncfg_ssid_t ssid;
	/* Flags such as `[CURRENT]` or `[DISABLED]`, passed through rather than
	 * translated: `[DISABLED]` and `[TEMP-DISABLED]` mean different things. */
	char       *flags;
} ncfg_supplicant_entry_t;

int ncfg_supplicant_parse_network_list(const char *body, ncfg_supplicant_entry_t **out,
    size_t *count_out, char *err, size_t err_size);

void ncfg_supplicant_entries_free(ncfg_supplicant_entry_t *entries, size_t count);

/* Whether this is the network currently selected. */
int ncfg_supplicant_entry_is_current(const ncfg_supplicant_entry_t *entry);

/* One `key=value` line of `STATUS`. */
typedef struct {
	char *key;
	char *value;
} ncfg_supplicant_status_pair_t;

int ncfg_supplicant_parse_status(const char *body, ncfg_supplicant_status_pair_t **out,
    size_t *count_out, char *err, size_t err_size);

void ncfg_supplicant_status_free(ncfg_supplicant_status_pair_t *pairs, size_t count);

/* The value of one `STATUS` key, or NULL. */
const char *ncfg_supplicant_status_field(const ncfg_supplicant_status_pair_t *pairs, size_t count,
    const char *key);

/* 32 octets, two hex digits each, and the terminator. */
#define NCFG_SUPPLICANT_SSID_HEX_SIZE 65u

/*
 * Render an SSID for `SET_NETWORK`, as hex.
 *
 * `wpa_supplicant` accepts either a quoted string or an unquoted hex blob, and
 * netcfgd always sends hex. Three reasons, in increasing order of how much
 * they matter:
 *
 *   - the model already stores an SSID as octets with hex as its canonical
 *     encoding, so this is a direct mapping rather than a conversion;
 *   - an SSID is not required to be UTF-8, and quoting one that is not means
 *     choosing an escaping scheme for bytes that have no text;
 *   - an SSID is 32 arbitrary octets chosen by whoever named the network, and
 *     quoting is where a value from a config file becomes protocol syntax. A
 *     network called `"; REMOVE_NETWORK all; "` should be a network with a
 *     silly name, not a command. Hex removes the question rather than
 *     answering it carefully.
 *
 * `out` is `NCFG_SUPPLICANT_SSID_HEX_SIZE` bytes.
 */
int ncfg_supplicant_ssid_argument(const ncfg_ssid_t *ssid, char *out, size_t out_size);

/*
 * Quote a value for the control protocol, appending to `out`.
 *
 * Unlike an SSID a passphrase cannot be hex: an unquoted 64-character hex
 * value means a pre-computed PMK rather than a passphrase, so a quoted string
 * is the only way to say "this is the text the user typed". The escaping is
 * therefore load-bearing, and the same injection concern applies.
 *
 * `wpa_supplicant`'s parser understands C-style escapes inside quotes, so a
 * quote and a backslash are the two characters that must not pass through
 * unaltered. Identities and certificate paths go through the same function --
 * a RADIUS realm and a path from a config are attacker-influenced often enough
 * that treating them as trusted text would be a distinction without a reason.
 */
void ncfg_supplicant_quote(ncfg_buf_t *out, const char *value);

/*
 * Whether a passphrase can be sent at all.
 *
 * A newline would end the command, and everything after it would be read as
 * the next one. There is no escape for it in the control protocol, so the only
 * safe answer is to refuse -- WPA passphrases are printable characters, so
 * nothing legitimate is being turned away.
 */
int ncfg_supplicant_passphrase_is_sendable(const char *passphrase);

/* ------------------------------------------------------------------------ *
 * A network from the document, as control-socket commands
 * ------------------------------------------------------------------------ */

/*
 * A `SET_NETWORK` variable and its already-quoted value.
 *
 * The value carries its own quoting because the two kinds are not
 * interchangeable: `ssid` is hex and must not be quoted, `psk` is a quoted
 * string. Deciding that here rather than at the call site means there is one
 * place to be right.
 */
typedef struct {
	/* The variable name, such as `ssid` or `key_mgmt`. */
	char *variable;
	/*
	 * The value as it goes on the wire. NULL **exactly** when `secret` is
	 * set: a setting that names a credential does not carry one.
	 */
	char *value;
	/*
	 * The credential this setting sends, borrowed from the document and
	 * resolved only by `ncfg_supplicant_setting_command`. See the header
	 * comment for why the value is not here.
	 */
	const ncfg_secret_ref_t *secret;
	/*
	 * Whether the value must not be logged. True for `secret` settings and
	 * also for an EAP `identity`, which is a username the document carries in
	 * the clear and is still half of a credential.
	 */
	int sensitive;
} ncfg_supplicant_setting_t;

typedef struct {
	ncfg_supplicant_setting_t *items;
	size_t                     count;
} ncfg_supplicant_settings_t;

void ncfg_supplicant_settings_free(ncfg_supplicant_settings_t *settings);

/*
 * The settings for one network, in the order they should be sent.
 *
 * `resolved_ssid` is the name read off a scan for a network that names access
 * points instead of one, and is NULL for every other network. It is a
 * parameter rather than a copied network because WPA derives its key from the
 * passphrase *and* the SSID, so there is nothing to send without a name and
 * the caller is the only thing that can have read one.
 *
 * Every credential is resolved here and discarded again, so that a network
 * that cannot be expressed says so before anything reaches the socket -- and
 * none of them is kept: `items[i].secret` is what survives the call.
 */
int ncfg_supplicant_settings(const ncfg_wifi_network_t *network,
    const ncfg_ssid_t *resolved_ssid, int mac_policy, const ncfg_secret_resolver_t *resolver,
    ncfg_supplicant_settings_t *out, char *err, size_t err_size);

/*
 * The settings for a wired 802.1X port.
 *
 * Not the same as a wifi EAP network, and the difference is the one that
 * matters: wired uses `key_mgmt = IEEE8021X`, bare EAPOL with no WPA handshake
 * wrapped around it. Sending `WPA-EAP` to a `wired` driver produces a network
 * the supplicant accepts and never authenticates with, which is the worst
 * available outcome -- everything looks configured and the port stays blocked.
 *
 * Decision 0008 puts wired 802.1X on this supplicant precisely so the EAP
 * method handling is shared; this is the part that must not be.
 */
int ncfg_supplicant_wired_settings(const ncfg_eap_config_t *eap,
    const ncfg_secret_resolver_t *resolver, ncfg_supplicant_settings_t *out, char *err,
    size_t err_size);

/*
 * The command line, with the credential in it. **Never log this.**
 *
 * Resolves `secret` at this moment and at no other, and holds nothing of it
 * once the line is built. The caller owns `out` and owes it
 * `ncfg_supplicant_buf_wipe` rather than `ncfg_buf_free`.
 */
int ncfg_supplicant_setting_command(const ncfg_supplicant_setting_t *setting, uint32_t id,
    const ncfg_secret_resolver_t *resolver, ncfg_buf_t *out, char *err, size_t err_size);

/*
 * The command line as it is safe to print, which resolves nothing.
 *
 * The failing command is what gets reported when a setting is refused, and the
 * one most likely to be refused is the one carrying the passphrase.
 */
void ncfg_supplicant_setting_redacted(const ncfg_supplicant_setting_t *setting, uint32_t id,
    ncfg_buf_t *out);

/*
 * Clear a buffer that held a rendered credential, then release it.
 *
 * The wipe is not in the Rust and is not a claim about it. It costs a `memset`
 * and shortens the window in which a core dump, a swapped page or a later
 * allocation of the same block carries a passphrase.
 */
void ncfg_supplicant_buf_wipe(ncfg_buf_t *buf);

/*
 * How a `mac_policy` is spelled in the control protocol.
 *
 * `wpa_supplicant`'s `mac_addr` is a small integer whose meanings are not
 * guessable from the number:
 *
 *     0 = use permanent MAC address
 *     1 = use random MAC address for each ESS connection
 *     2 = like 1, but maintain OUI (with local admin bit set)
 *
 * **`per_connection` sent 2 until 0230, and 2 is a different axis.** It is not
 * "a random address per association" -- it is 1 with the manufacturer prefix
 * preserved, so for the policy netcfgd documents as the strongest it was
 * sending the one value that says who made the radio.
 *
 * What actually separates the two randomising policies is how long a random
 * address is kept, which is `rand_addr_lifetime` below.
 */
const char *ncfg_supplicant_mac_addr_value(int mac_policy);

/*
 * How long a random address is kept, in seconds, for each policy.
 *
 * Sent in both directions rather than left at the supplicant's own 60, for
 * decision 0015's reason: a privacy property that depends on somebody else's
 * default is not a property. `permanent` gets the same number as
 * `per_network` because no random address exists for it to govern, and a value
 * that means nothing is better sent than branched on.
 */
const char *ncfg_supplicant_rand_addr_lifetime_value(int mac_policy);

/*
 * A digest of everything a radio's networks would be given.
 *
 * **The supplicant cannot be asked what it holds.** `LIST_NETWORKS` returns
 * ids and SSIDs and nothing else -- a passphrase is write-only, by design --
 * so "does the running supplicant still match the document" cannot be answered
 * by reading the supplicant. It is answered the way netcfgd already answers
 * the same question for a WireGuard key and an openvpn config: record a digest
 * of what was handed over, and compare it against a digest of what the
 * document says now.
 *
 * Covers the passphrase, because the rendered settings contain it -- **as a
 * digest and never as a value**. So rotating a secret changes this, which is
 * the case that mattered most: it is invisible to every other observation.
 *
 * **A network naming access points instead of an SSID is fingerprinted, and
 * used not to be.** One such network returned no digest for the whole list,
 * and where there is no digest the record is removed -- which cost exactly
 * what `kernel.rs` says: "changing a passphrase, pinning a bssid, adding a
 * network or deleting one all planned nothing, measured, and the supplicant
 * kept the original credentials indefinitely".
 *
 * 0 still covers a network that cannot be rendered at all -- an unusable
 * credential, or a secret that will not resolve. netcfgd could not have handed
 * such a network over, so it genuinely cannot say what the supplicant holds.
 *
 * `out` is `NCFG_SUPPLICANT_SSID_HEX_SIZE` bytes, which is the same 65 a
 * SHA-256 in hex needs.
 */
int ncfg_supplicant_fingerprint(const ncfg_wifi_network_t *networks, size_t count,
    int mac_policy, int scan_randomization, int device_autoconnect,
    const ncfg_secret_resolver_t *resolver, char *out, char *err, size_t err_size);

/*
 * Which name the listed access points agree on, given what was seen.
 *
 * Split from the socket so the choosing can be checked without one: "none of
 * them is in range" and "they are on different networks" are the two answers
 * that matter and neither needs a supplicant to produce.
 *
 * **A hidden access point is in range and still says nothing.** Its beacons
 * carry an empty SSID -- that is what hiding is -- so a scan result for one has
 * a zero-octet name, and this used to return it: the network was then sent as
 * `ssid ""`, which matches nothing and, for anything but an open network,
 * cannot even derive the right key. Silent ones are dropped rather than
 * compared, because a hidden access point does not disagree with a named one
 * about what the network is called; it declines to say. 0223.
 */
int ncfg_supplicant_pick_ssid(const ncfg_wifi_network_t *network,
    const ncfg_supplicant_scan_t *seen, size_t seen_count, ncfg_ssid_t *out, char *err,
    size_t err_size);

/* ------------------------------------------------------------------------ *
 * The control socket itself
 * ------------------------------------------------------------------------ */

/* Where `wpa_supplicant` puts its per-interface sockets by default. */
#define NCFG_SUPPLICANT_CTRL_DIR "/run/wpa_supplicant"

/*
 * What overrides it.
 *
 * So a test can point at a directory that is not the real one: a network
 * namespace is not a mount namespace, so without this a test would share
 * `/run/wpa_supplicant` with whatever the host is running.
 */
#define NCFG_SUPPLICANT_CTRL_DIR_ENV "NCFG_WPA_CTRL_DIR"

/*
 * How long to wait for a reply, in milliseconds.
 *
 * Generous, because `SCAN_RESULTS` on a busy band is not instant, and a
 * timeout here is reported to the operator as the supplicant being
 * unresponsive -- a false one of those is worse than a slow command. It is
 * also the ceiling: a connection cannot be given longer.
 */
#define NCFG_SUPPLICANT_REPLY_TIMEOUT_MS 10000

/*
 * How long anything with something waiting behind it gives a control socket.
 *
 * One second, and it is the number every caller arrived at independently
 * before this constant existed. Measured from both ends: with a wedged access
 * point recorded, pulling the cable took 12.2 seconds to switch to wifi on the
 * ten-second default against 106ms with nothing wedged (0111); and against a
 * real `wpa_supplicant` every command an apply sends answers in 0.07-0.13ms,
 * four orders of magnitude inside this.
 */
#define NCFG_SUPPLICANT_IMPATIENT_MS 1000

/*
 * How long a scan gets before its results are read anyway.
 *
 * A scan is not a round trip. The radio leaves the channel it is on and visits
 * every other one it is allowed to use, dwelling on each long enough to hear a
 * beacon. Seconds, not milliseconds -- and the number is a property of the band
 * plan and the regulatory domain rather than of anything netcfgd controls.
 */
#define NCFG_SUPPLICANT_SCAN_PATIENCE_MS 10000

/*
 * How long a join gets before netcfgd says it did not happen.
 *
 * Association is milliseconds; the key exchange is a few round trips; EAP is a
 * TLS handshake against a server somewhere else, and on the reporting machine
 * a successful PEAP join took a little over two seconds. Twenty is generous
 * for all of them and short enough that a person waiting on it has not gone to
 * do something else.
 */
#define NCFG_SUPPLICANT_CONNECT_PATIENCE_MS 20000

/* A connection to one interface's control socket. */
typedef struct ncfg_supplicant_client ncfg_supplicant_client_t;

/*
 * Where the control sockets are, honouring the override.
 *
 * One function rather than the byte-identical copies it replaces. Three copies
 * of a path and an environment variable is three chances for them to stop
 * agreeing.
 */
int ncfg_supplicant_ctrl_dir(char *out, size_t out_size, char *err, size_t err_size);

/*
 * Connect to the control socket for `interface` under `dir`.
 *
 * NULL if the socket does not exist, cannot be bound to, or does not answer
 * `PING`.
 */
ncfg_supplicant_client_t *ncfg_supplicant_connect(const char *dir, const char *interface,
    char *err, size_t err_size);

/*
 * The same, waiting less than the default for every reply including the
 * opening `PING`.
 *
 * The `PING` is why this is a parameter rather than something set on a
 * connection afterwards. It happens inside the connect, so a deadline applied
 * to the returned client is a deadline that never covers the one round trip a
 * wedged daemon is most likely to eat -- which is exactly what it did here,
 * measured at ten seconds against a process that had bound its socket and
 * stopped answering. 0114.
 *
 * Shortening only: a longer value than the default is clamped, so this cannot
 * be used to make a scan time out.
 */
ncfg_supplicant_client_t *ncfg_supplicant_connect_within(const char *dir, const char *interface,
    int timeout_ms, char *err, size_t err_size);

/* Detach if attached, remove the bound path, close. Freeing NULL is nothing. */
void ncfg_supplicant_client_free(ncfg_supplicant_client_t *client);

/* Which interface this client talks to. */
const char *ncfg_supplicant_client_interface(const ncfg_supplicant_client_t *client);

/*
 * The descriptor, for a caller that multiplexes several of them.
 *
 * -1 where there is none. `ncfg_supplicant_next_event` takes a timeout because
 * a caller watching several radios wants a short one -- which is a round of
 * short waits, one per radio, and is what the Rust's watcher thread does. A
 * daemon that already waits on netlink, the configuration and `/dev/rfkill`
 * together has a better answer: put these descriptors in the same `poll` and
 * read only the radio that spoke. So the integer is needed, and the struct
 * stays opaque.
 *
 * **For waiting on, and for nothing else.** A read taken anywhere but
 * `ncfg_supplicant_next_event` would be a second place that has to know an
 * event from a reply, which is the classic `wpa_supplicant` client bug this
 * module exists to hold in one file.
 */
int ncfg_supplicant_client_descriptor(const ncfg_supplicant_client_t *client);

/*
 * Send a command and read its reply.
 *
 * A `FAIL` reply is not a failure here -- it is
 * `NCFG_SUPPLICANT_REPLY_FAIL` in `*kind`, because several callers treat it as
 * information rather than a fault. `body` receives the reply text, which is
 * `OK` for an `OK`.
 *
 * Events share this socket once anything has attached, and they arrive
 * interleaved with replies; reading one as the answer to a command is the
 * classic bug in a `wpa_supplicant` client, so they are skipped until the
 * deadline.
 */
int ncfg_supplicant_request(ncfg_supplicant_client_t *client, const char *command, char *body,
    size_t body_size, int *kind, char *err, size_t err_size);

/* Send a command, requiring a body rather than a failure. */
int ncfg_supplicant_ask(ncfg_supplicant_client_t *client, const char *command, char *body,
    size_t body_size, char *err, size_t err_size);

/* Send a command that must answer `OK`. */
int ncfg_supplicant_command(ncfg_supplicant_client_t *client, const char *command, char *err,
    size_t err_size);

/* Check the supplicant is alive: it must answer `PONG`. */
int ncfg_supplicant_ping(ncfg_supplicant_client_t *client, char *err, size_t err_size);

/*
 * Ask to be sent unsolicited events on this connection.
 *
 * `ATTACH` is per connection, not per supplicant: a client that has not asked
 * gets replies only. So this is the whole difference between a connection that
 * can watch a radio and one that can only interrogate it, and it is
 * deliberately a separate call -- the request path drops events while waiting
 * for a reply, and a connection doing both would throw away the ones that
 * arrived at the wrong moment.
 */
int ncfg_supplicant_attach(ncfg_supplicant_client_t *client, char *err, size_t err_size);

/*
 * The next unsolicited event, or `*got == 0` if none arrived in time.
 *
 * Nothing arriving is the ordinary answer on a quiet radio and is not a
 * failure -- which is why the timeout is an argument: a caller polling several
 * interfaces wants a short one, and one waiting on a single radio wants a long
 * one rather than a spin. Replies are skipped rather than returned.
 */
/*
 * `timeout_ms` must be at least 1 and a smaller one is refused by name.
 * `SO_RCVTIMEO` of `{0, 0}` is the kernel's "no deadline at all", so zero --
 * the value a caller reads as "do not block" -- is the one that blocks for
 * ever, and on a single-threaded daemon that is a wedge rather than a slow
 * path.
 */
int ncfg_supplicant_next_event(ncfg_supplicant_client_t *client, int timeout_ms,
    ncfg_supplicant_event_t *out, int *got, char *err, size_t err_size);

/*
 * Is this directory entry one of netcfgd's own reply sockets?
 *
 * A datagram client must bind an address to be replied to, and it binds it in
 * the control directory beside the sockets it talks to -- that being the
 * directory both ends are known to be able to write. The consequence is that
 * **the control directory contains entries that are not interfaces**, and
 * anything reading it has to know which.
 *
 * It exists because one reader was not doing this. The roam watcher took every
 * entry as an interface name and connected to it, which against a reply socket
 * waits out the whole timeout -- the far end is a live process that is not a
 * server -- and lands a `PING` in another client's reply queue, where it is not
 * an event, so that client can return it as the answer to whatever it had just
 * sent. 0112.
 */
int ncfg_supplicant_is_reply_socket(const char *name);

/*
 * Whether a failed connect means there is nothing to talk to.
 *
 * Two kinds mean absence and no others. `ENOENT` is the socket not existing.
 * `ECONNREFUSED` is a socket file left behind by a process that is gone -- the
 * kernel's answer for a unix datagram address nobody has open. **A timeout is
 * not in the list, and that is the whole point of the list**: reading a wedged
 * daemon as absent tells the operator an access point was stopped while it is
 * still on the air with its passphrase in memory.
 */
int ncfg_supplicant_nothing_is_listening(int error_number);

/*
 * Remove reply sockets left behind by processes that are gone.
 *
 * **Nothing unwinds on the way out.** netcfgd installs no `SIGTERM` handler,
 * so an ordinary `systemctl restart netcfgd` took the directory from 18
 * entries to 20, two per daemon lifetime, for ever.
 *
 * **This deletes files, so it parses rather than prefix-matches.** Three
 * things must hold and a candidate failing any of them is left alone: the name
 * is exactly `netcfgd-<pid>-<serial>` with both of them digits; it is a
 * socket, by `lstat` so a symlink is never followed; and **nothing has the
 * address open**, which the kernel is asked directly.
 *
 * **The third used to be `/proc/<pid>`, and that is a proxy for the question
 * rather than the question (0224).** A pid is a name that gets reused, and the
 * numbers most likely to be taken are the low ones, which on Linux belong to
 * kernel threads that live as long as the boot. Found seven days into a boot:
 * `netcfgd-8-0` and `netcfgd-8-1`, three days old, no owner, skipped by every
 * reap since -- pid 8 was `kworker/R-netns`.
 *
 * So ask the kernel. Connecting to a unix datagram address gives
 * `ECONNREFUSED` when nobody has it bound, and that is the definition of a
 * stale socket file rather than a guess at one. `EPERM` is the kernel refusing
 * to connect to one that is already connected elsewhere, which every live
 * reply socket is -- so the live case answers loudly rather than by absence.
 *
 * Returns how many were removed, for the caller to say so.
 */
size_t ncfg_supplicant_reap_reply_sockets(const char *dir);

/*
 * Wait for a scan to finish.
 *
 * **`SCAN` does not answer with results and `SCAN_RESULTS` does not scan.**
 * The first queues a scan and returns at once; the second reads the cache the
 * last completed scan filled. Sending one and immediately reading the other
 * therefore returns *the previous scan's* results, always.
 *
 * Measured before this existed: `ncfg wifi scan` returned in 7 milliseconds,
 * four orders of magnitude short of a real scan, and three consecutive calls
 * returned 15, then 20, then 20 access points.
 *
 * The caller must have sent `ATTACH` -- without it no event reaches this
 * connection and every scan waits out the full patience. It is not done here
 * because attaching has to happen *before* `SCAN` is sent, and this is called
 * after.
 *
 * Failing says the scan is not finished; the caller can still read
 * `SCAN_RESULTS`, and the point of the message is that it now knows the
 * answer is stale.
 */
int ncfg_supplicant_wait_for_scan(ncfg_supplicant_client_t *client, int patience_ms, char *err,
    size_t err_size);

/*
 * Wait for a join to succeed or fail.
 *
 * **`SELECT_NETWORK` answering OK means the supplicant accepted the command**,
 * not that the machine joined anything. Association, the key exchange and --
 * on an enterprise network -- a whole TLS handshake all happen afterwards, and
 * every way they fail is an event rather than a reply. netcfgd used to return
 * success the moment the command was acknowledged, and `ncfg wifi connect`
 * printed "joining; `ncfg wifi status` says whether it worked" -- the program
 * admitting it did not know the answer to the question it had just been asked.
 * On the network that started this work that answer was forty-five consecutive
 * authentication failures. 0197.
 */
int ncfg_supplicant_wait_for_connect(ncfg_supplicant_client_t *client, int patience_ms,
    char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * What netcfgd asks a supplicant to do
 * ------------------------------------------------------------------------ */

/*
 * Does the supplicant on `interface` answer its control socket?
 *
 * A question about the *process*, not about wifi: a supplicant that has bound
 * its socket and stopped answering looks, from every other angle netcfgd has,
 * exactly like one that is working and has not associated yet.
 *
 * 0 covers "the socket is gone" as well as "it did not answer in time", and
 * deliberately: netcfgd asks this only of a supplicant it believes is running,
 * and a running process whose socket has vanished is not in a state anything
 * should be configured against.
 */
int ncfg_supplicant_answers(const char *dir, const char *interface);

/*
 * The network a supplicant is currently associated with: its name, and the
 * access point serving it.
 *
 * Both halves come back because resolving an association to a configured
 * network needs both -- a network that lists BSSIDs instead of an SSID is
 * identified by the second.
 *
 * 0 covers every way there is no answer: the socket is gone, the supplicant is
 * scanning rather than associated, or the name is not a name this module will
 * accept. The observation asks this only of a supplicant it already believes
 * is running, and treats no answer as no association -- so a wireless link
 * falls back to its interface's own preference rather than borrowing a stale
 * network's metric.
 *
 * **Takes an open client rather than connecting**: the observation already has
 * one, and connecting a second time would double the round trips for a fact
 * the first connection could have carried. `bssid` and `key_mgmt` may both be
 * NULL.
 *
 * `key_mgmt` is the field as the supplicant spells it, for
 * `ncfg_supplicant_key_mgmt_security` to read. It comes back from this call
 * rather than from a second `STATUS` for the reason in the paragraph above:
 * the round trip that carries the SSID and the BSSID carries this too, and
 * asking again would be two answers to one question as well as two trips.
 */
/*
 * What `key_mgmt=` in a `STATUS` means, as an `ncfg_security_kind_t`.
 *
 * **The one thing that separates two `network` blocks sharing an SSID and no
 * BSSID** -- an open network beside a WPA2 one of the same name, which is an
 * ordinary arrangement and was reported from a machine that has it in other
 * software. `ncfg_wifi_network_for` asks this so that a join is credited to
 * the block that actually describes it, and the metric that follows is the
 * right one.
 *
 * The vocabulary is wpa_supplicant's and is matched by what it contains rather
 * than by equality: a station reports `WPA2-PSK`, `WPA2-PSK-SHA256`,
 * `FT-PSK`, `SAE`, `WPA2-EAP`, `FT-EAP`, `IEEE8021X` or `NONE`, and a list of
 * them joined by `+` while more than one is negotiated. `OWE` is its own kind
 * rather than an open network, which is what the document says it is.
 *
 * `NCFG_WIFI_SECURITY_UNSTATED` where the string is absent, empty or none of
 * those -- which is a caller that could not tell, never a guess.
 */
int ncfg_supplicant_key_mgmt_security(const char *key_mgmt);

int ncfg_supplicant_associated(ncfg_supplicant_client_t *client, ncfg_ssid_t *ssid_out,
    char *bssid, size_t bssid_size, char *key_mgmt, size_t key_mgmt_size);

/*
 * The supplicant's own state name, such as `COMPLETED` or `SCANNING`.
 *
 * `UNKNOWN` where `STATUS` did not carry one, which is what a caller renders
 * rather than an absence it would have to decide about.
 */
int ncfg_supplicant_state(ncfg_supplicant_client_t *client, char *out, size_t out_size,
    char *err, size_t err_size);

/*
 * Remove every network the supplicant currently holds.
 *
 * Decision 0015: called before adding anything, so a supplicant started by
 * something else -- or one that survived a netcfgd crash -- does not contribute
 * networks the document cannot account for.
 */
int ncfg_supplicant_clear_networks(ncfg_supplicant_client_t *client, char *err, size_t err_size);

/*
 * Hand one network to the supplicant, and say which slot it took.
 *
 * The SSID is resolved from the last scan first for a network named by address
 * rather than by name. No `SCAN` is issued: a scan takes seconds, interrupts
 * traffic on the radio, and this runs inside an apply. If the access point is
 * not in the last results the honest answer is that netcfgd cannot see it --
 * with its address in the message, because "network not found" about a network
 * named by address is not a sentence anybody can act on.
 *
 * Everything is resolved before anything is sent, so a network whose access
 * points are out of range leaves nothing half-configured behind. Where a
 * setting is refused anyway the network is removed before the failure is
 * reported, and the failure quotes the **redacted** form -- the failing command
 * may be the one carrying the passphrase.
 */
int ncfg_supplicant_add_network(ncfg_supplicant_client_t *client,
    const ncfg_wifi_network_t *network, int mac_policy, const ncfg_secret_resolver_t *resolver,
    uint32_t *id_out, char *err, size_t err_size);

/*
 * Configure a wired 802.1X port: one network, enabled, nothing else.
 *
 * A wired supplicant has exactly one thing to authenticate with, so this
 * clears first -- the port cannot be "on" two profiles, and leaving a stale one
 * would let the supplicant fall back to it.
 */
int ncfg_supplicant_configure_wired(ncfg_supplicant_client_t *client,
    const ncfg_eap_config_t *eap, const ncfg_secret_resolver_t *resolver, uint32_t *id_out,
    char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * Launching one
 * ------------------------------------------------------------------------ *
 *
 * THE MARK, AND WHY IT IS THE PID FILE'S OWN PATH
 *   `process.h` states the rule and this module is the example its own header
 *   quotes: a process is netcfgd's when it carries, **as a whole `argv`
 *   element**, an absolute path netcfgd composed out of its own run directory
 *   and one interface -- and when it belongs to root or to whoever is asking.
 *   netcfgd starts its supplicant with `-P <run>/supplicant/<iface>.pid`, so
 *   that path is in `/proc/<pid>/cmdline` for as long as the process lives.
 *
 *   **That is udhcpc's arrangement exactly, and deliberately not dhcpcd's.**
 *   The four marks that already exist are the generated configuration radvd is
 *   started with (`ncfg_ra_running_pid`), the management socket a tunnel is
 *   started with (`ncfg_openvpn_running_pid`), the pid file udhcpc is started
 *   with (`ncfg_dhcp_running_pid`) and dhcpcd's three-valued answer over its
 *   own control socket (`ncfg_dhcpcd_whose`). Only the last of those is a
 *   different *mechanism*, and it exists because dhcpcd calls `setproctitle`
 *   and destroys its own argv. `wpa_supplicant` does not: it re-execs nothing
 *   and rewrites nothing, so the cheaper mark survives and this module reads
 *   it the way the first three do. A fifth spelling would be a fifth chance
 *   for two of them to disagree about what ownership is.
 *
 *   **Whose a *stranger's* supplicant is comes from the socket, not the
 *   process**, and that is the one place this differs from the three above. A
 *   supplicant nobody marked is not thereby somebody's: it may be a dead one's
 *   leftover socket file. So the question "is another manager running one
 *   here?" is asked by connecting -- `ncfg_supplicant_answers` -- and only a
 *   socket that answers is a manager to decline in favour of.
 *
 * ADOPTION IS THE ORDINARY CASE AND NOT THE EXCEPTIONAL ONE
 *   `RuntimeDirectory=netcfgd` empties `/run/netcfgd` on every daemon stop
 *   while `KillMode=process` deliberately leaves the supplicant running
 *   (0134), so **the pid file is an index into a fact rather than the fact
 *   itself** and losing it happens on every restart. Decision 0140 is what
 *   that cost when the recovery was missing: netcfgd refused its own child for
 *   ever, naming `NetworkManager`, while two supplicants and two DHCP clients
 *   fought over one radio. `ncfg_supplicant_adopt` is the recovery -- find the
 *   process by the mark it still carries and write the pid back down -- and
 *   adopting rather than restarting is what keeps the association 0134 wanted
 *   kept.
 *
 * WHAT IS NOT ON THE COMMAND LINE
 *   No configuration file, and not an empty one: 0015 makes the supplicant
 *   hold no state, `-C` supplies the control interface, and a file that does
 *   not exist cannot be edited by anything else. `update_config 0` is set on
 *   the running instance instead, because there is no flag for it -- see
 *   `ncfg_service_set_profiles`, which is what fills a supplicant netcfgd has
 *   just started.
 */

/* Long enough for a run directory, `supplicant/` and `<iface>.pid`. */
#define NCFG_SUPPLICANT_PATH_MAX 512

/*
 * Room for the vector below and its terminator: the program, `-B`,
 * `-D<driver>`, `-s`, `-i`, the interface, `-C`, the directory, `-P` and the
 * pid file.
 */
#define NCFG_SUPPLICANT_ARGV_MAX 12

/*
 * The two drivers, which are a property of the interface rather than a
 * preference.
 *
 * A wired port authenticating with 802.1X needs `wired` -- bare EAPOL with no
 * WPA handshake around it -- and a radio needs `nl80211`. **Guessing wrong
 * produces a supplicant that starts and never authenticates**, which is the
 * worst available outcome: everything looks configured and the port stays
 * blocked. `wext` is behind `nl80211` for a kernel whose driver has no
 * `cfg80211` support, which is what the Rust sends and is kept.
 */
#define NCFG_SUPPLICANT_DRIVER_RADIO "nl80211,wext"
#define NCFG_SUPPLICANT_DRIVER_WIRED "wired"

/*
 * `<run>/supplicant/<iface>.pid` -- where a supplicant netcfgd started records
 * its pid, and the mark it carries in its own `argv`.
 *
 * One function because the writer, the reader and the `-P` argument are three
 * views of one path, which is `ncfg_dhcp_pid_path`'s reason: three spellings
 * is how two of them come to disagree, and a disagreement here is silent --
 * every lookup answers "not running" and netcfgd starts a second supplicant
 * beside the first.
 */
int ncfg_supplicant_pid_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size);

/*
 * `<run>/supplicant/<iface>.log` -- where the launch's two output streams go.
 *
 * **Not where the supplicant logs.** `-s` sends everything after the fork to
 * syslog, which is the Rust's own hard-won flag: a daemonised
 * `wpa_supplicant` that was not told to use syslog writes to a stdout nothing
 * reads, and every association failure, authentication error and disconnect
 * reason is simply gone. This file holds what it said *before* it forked,
 * which is where "it would not start" is written.
 */
int ncfg_supplicant_log_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size);

/*
 * A command line, built rather than written out at the call site.
 *
 * `ncfg_dhcp_args_t`'s arrangement and its reason: the alternative is an
 * `argv[10]` filled by index inside a function that also forks, and the flags
 * then have nowhere to be asserted. **`argv` borrows every string but the
 * driver**, which is formatted into this struct so that nothing points at a
 * local that has gone.
 */
typedef struct {
	const char *argv[NCFG_SUPPLICANT_ARGV_MAX];
	size_t      count;
	/* `-D<driver>`, one argument as `wpa_supplicant` spells it. */
	char        driver[32];
} ncfg_supplicant_args_t;

/*
 * What netcfgd starts `wpa_supplicant` with.
 *
 * `-B` daemonises, `-s` sends its log to syslog, `-i` names the interface,
 * `-C` is the control directory and `-P` is the pid file that is also the
 * mark. There is deliberately no `-c`: see the note above.
 */
int ncfg_supplicant_arguments(const char *program, const char *driver, const char *iface,
    const char *dir, const char *pid_path, ncfg_supplicant_args_t *out, char *err,
    size_t err_size);

/*
 * The pid of a supplicant of netcfgd's, if it is still there.
 *
 * `ncfg_dhcp_running_pid`'s rule with this module's marker: the pid file
 * netcfgd named on the command line, and `/proc/<pid>/cmdline` checked for
 * that same path as a whole argument. 0 covers every way of not knowing -- no
 * file, no number in it, no such process, or a process that is somebody
 * else's.
 */
pid_t ncfg_supplicant_running_pid(const char *run, const char *iface);

/*
 * Take back a supplicant netcfgd started and lost the record of.
 *
 * `ncfg_dhcp_adopt` with one addition: **the process must also be answering
 * its control socket**, which is the Rust's filter and is not caution for its
 * own sake. A supplicant that holds its socket and answers nothing is
 * netcfgd's by every marker and no use to it, and writing the pid down would
 * claim a radio that netcfgd cannot drive -- where `ncfg_supplicant_start`'s
 * next question, "is somebody else answering here?", is the one that decides
 * whether the radio may be taken at all.
 *
 * 1 with `*pid_out` set to the pid adopted, 1 with `*pid_out` 0 where there
 * was nothing to adopt -- which is not a failure and is the ordinary answer --
 * and 0 with a sentence where the record could not be written. A record that
 * cannot be kept **is** a failure here, for `ncfg_dhcp_adopt`'s reason: the
 * next pass would find no record, adopt again, and go on adopting for ever.
 */
int ncfg_supplicant_adopt(const char *run, const char *dir, const char *iface, pid_t *pid_out,
    char *err, size_t err_size);

/*
 * Start one, adopt one, or say why neither is possible.
 *
 * In order, because the order is the whole of it:
 *
 *   1. **One netcfgd's own record already names is already running**, and
 *      starting a second is what this exists to prevent. Asked first because
 *      it is the state a converged machine is in on every reconcile.
 *   2. **One carrying the mark with no record left is adopted**, which is 0140
 *      and is what a restart produces.
 *   3. **One answering that carries no mark is somebody else's**, and netcfgd
 *      declines the radio rather than binding a second supplicant to the same
 *      path. Two supplicants on one radio drop the association, which takes
 *      the address and the default route with it -- measured, and it is the
 *      whole of the fault 0140 reports.
 *   4. **A socket file with nothing behind it is stale** and is removed, since
 *      the next supplicant could not bind it otherwise. That is 0080's case
 *      and is exactly the one step 3 must not swallow.
 *
 * `program` NULL means "find the conventional name", which is
 * `ncfg_hostapd_start`'s convention: `/usr/sbin` is searched first because it
 * is not on a non-root `PATH` on Debian. **A test passes a program it wrote**,
 * and nothing here reads an environment variable to decide -- the Rust's
 * `NCFG_WPA_SUPPLICANT` exists because its search had no other seam.
 */
int ncfg_supplicant_start(const char *run, const char *dir, const char *iface,
    const char *driver, const char *program, char *err, size_t err_size);

/*
 * Stop netcfgd's own supplicant on one interface.
 *
 * **Through its control socket, never by signalling a process found by name**,
 * which is 0014's rule: an operator's own `wpa_supplicant` is an ordinary
 * thing to have and would be reached along with netcfgd's.
 *
 * Nothing listening is the state this was asked to produce, so that is
 * success -- but **only nothing listening**. A supplicant that has bound its
 * socket and gone silent fails here, which is 0109's shape and is kept in step
 * with the access point's stop deliberately: they are one mechanism, and
 * fixing one of them would leave the other saying a daemon had stopped while
 * it was still holding the radio.
 *
 * The pid file goes either way (0080): `wpa_supplicant` removes its own on a
 * clean exit, one that was killed leaves it, and a stale file would have the
 * next observation asking about a pid that belongs to somebody else by then.
 *
 * `patience_ms` of 0 is `NCFG_SUPPLICANT_IMPATIENT_MS`.
 */
int ncfg_supplicant_stop(const char *run, const char *dir, const char *iface, int patience_ms,
    char *err, size_t err_size);

#endif /* NCFG_SUPPLICANT_H */
