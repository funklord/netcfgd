/*
 * value.h -- the small values every larger type in the model is built out of.
 *
 * **What these types are is their spelling.** An address, a hardware address
 * and the closed word sets below carry almost no behaviour; what they carry is
 * a rendering, and each one is here because a rendering that drifted cost
 * something that was measured rather than feared.
 *
 *   * An address is compared against the kernel's own text, so whichever
 *     spelling the operator wrote has to become the kernel's before anything
 *     compares them. `ncfg_address_canonical` is that step and says what it
 *     cost when it was missing.
 *   * A closed set is a word in the configuration language. An enum here whose
 *     table said something plausible would compile a block that means
 *     something else -- and that has happened twice in this project, once as
 *     `wire_guard` for `wireguard` and once as `open_vpn` for `openvpn`. So
 *     every spelling below was read out of the Rust rather than remembered,
 *     and each set names the file it was read from.
 *
 * Two conventions hold across every set, and they are base.h's:
 *
 *   * `_from_name` returns 1 and writes `*out`, or returns 0 with a sentence
 *     in `err` and **`*out` untouched**. Not the first variant, which is the
 *     silent version of the same defect -- a misspelled word becoming
 *     `lookup`, or `report`, and nothing said.
 *   * `_name` returns NULL for a value outside its set. A plausible word for a
 *     value that is not one is worse than no word, for the reason above.
 */
#ifndef NCFG_VALUE_H
#define NCFG_VALUE_H

#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------------ *
 * Addresses
 * ------------------------------------------------------------------------ */

/*
 * An IPv4 or IPv6 address, with or without a prefix length.
 *
 * **The family is a flag rather than an `AF_INET`**, so that this header pulls
 * in nothing from the socket API. `project.md` section 5 keeps the model pure
 * and hardware-free, which is what makes the planner testable against
 * fixtures; a model header that drags in <sys/socket.h> is the first step away
 * from that, and the flag costs one line in the two functions that do call
 * `inet_pton` and `inet_ntop`.
 */
typedef struct {
	/* Zero for IPv4, which uses the first four bytes; one for IPv6. */
	int           is_ipv6;
	/* Network byte order, as `inet_pton` writes them. */
	unsigned char bytes[16];
	/*
	 * Whether the text carried `/length` at all.
	 *
	 * A bare address and a `/32` are different things to the kernel and to a
	 * routing rule's `from`, which takes either and prints a bare one back
	 * unchanged. Defaulting the absent one to the full length would make the
	 * rendering stop matching what the kernel reports, which is the whole
	 * defect `ncfg_address_canonical` exists for.
	 */
	int           has_prefix;
	/* 0..32 for IPv4 and 0..128 for IPv6, meaningful only with `has_prefix`. */
	unsigned int  prefix;
} ncfg_address_t;

/*
 * Room for any rendered address, prefix included.
 *
 * `xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255.255.255.255` is the longest an address
 * renders to at 45 characters; `/128` is four more, and one for the NUL.
 */
#define NCFG_ADDRESS_MAX 50

/*
 * Read `192.0.2.10/24`, `2001:db8::/32`, or either with no prefix length.
 *
 * `inet_pton` does the parsing rather than anything written here, which is
 * what makes "and nothing after it" true: a trailing space, a second slash or
 * a word after the address are all refused by it, and a hand-rolled scanner is
 * where that kind of leniency gets in.
 */
int ncfg_address_parse(const char *text, ncfg_address_t *out, char *err, size_t err_size);

/*
 * Write the kernel's spelling of an address into `out`.
 *
 * `out_size` must be at least `NCFG_ADDRESS_MAX`; a buffer that could truncate
 * is refused rather than truncated into, because half an address is a string
 * that still looks like one.
 */
int ncfg_address_render(const ncfg_address_t *address, char *out, size_t out_size, char *err,
    size_t err_size);

/*
 * Parse and re-render in one step: the kernel's spelling of `text`.
 *
 * **This is `canonical_address` from `crates/netcfgd-compile/src/lower.rs`,
 * and the behaviour is preserved deliberately rather than inherited.** The
 * desired side is compared against the kernel's rendering *as a string*, so a
 * spelling the kernel does not use never matches and the apply does the same
 * work for ever. Every one of these was measured on a dummy device, on the
 * second plan after a successful apply:
 *
 *     config  = "2001:0db8::1/64"    addr.add + addr.del, every apply
 *     config  = "2001:DB8::2/64"     the same
 *     from    = "2001:0DB8::/32"     rule.del + rule.add, every apply
 *     routes  = "2001:0DB8:2::/64"   route.add fails EEXIST, plan stops
 *
 * A rule written `2001:0DB8::/32` was torn down and reinstalled on every
 * apply, which is the case this module was split out for. The canonical
 * spelling converges on the first apply, so this is a spelling fault and not
 * anything about IPv6: `inet_ntop` prints the compressed lowercase form the
 * kernel also prints, and parsing then re-rendering is the whole of it.
 *
 * Takes a bare address as well as a prefix, because a rule's `from` may be
 * either.
 */
int ncfg_address_canonical(const char *text, char *out, size_t out_size, char *err,
    size_t err_size);

/*
 * The address a delegated prefix, a subnet selector and a suffix produce.
 *
 * **This is `netcfgd_model::derive_from_delegation`**, and it is here rather
 * than in one of its callers because there are now two of them: `ncfg explain`
 * has to follow the indirection to say where an address came from, and the
 * planner has to resolve it twice -- once to add the address and once to
 * answer "is this one still wanted?" in the teardown. A second copy of this
 * arithmetic is a plan that adds an address and deletes it again for ever,
 * which is the one failure `plan.h` is arranged to make impossible. 0263
 * named `value.h` as where it belongs and said the second caller takes it.
 *
 * `subnet` is `ncfg_prefix_ref_t.subnet`, passed as a number because this
 * header is below `document.h` and stays there -- the model's small values do
 * not depend on the document that is built out of them.
 *
 * Bit arithmetic on the sixteen octets rather than on a 128-bit integer, which
 * C does not have: the prefix keeps its own top bits, the subnet selector is
 * shifted so its last bit lands on the sub-prefix boundary, and the suffix
 * contributes everything below that boundary.
 *
 * `out` must hold `NCFG_ADDRESS_MAX`. Every refusal names what did not fit,
 * because the planner puts the sentence in front of the operator: a suffix
 * that cannot be carved out of the delegation is a configuration that will
 * never produce an address, and "nothing happened" is not an answer to it.
 */
int ncfg_address_from_delegation(const char *delegation, int64_t subnet, const char *suffix,
    char *out, size_t out_size, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * Hardware addresses
 * ------------------------------------------------------------------------ */

/* `AA:BB:CC:DD:EE:FF` and a NUL: the only shape either function writes. */
#define NCFG_HARDWARE_ADDRESS_MAX 18

/*
 * Six colon-separated hex octets, uppercased. **What the configuration
 * language accepts, and the stricter of the two.**
 *
 * This is `normalise_address` from `crates/netcfgd-compile/src/lower.rs`. It
 * uppercases rather than accepting what was written, because the same address
 * in two cases is two strings to everything downstream -- a diff, a duplicate
 * check, a comparison against what the adapter reports. BlueZ prints
 * uppercase, so that is what both of these converge on.
 *
 * It is strict on purpose: the language is the part that cannot be changed
 * quietly later. A separator accepted here is one every future document may
 * use, and taking one away afterwards breaks configurations that worked.
 */
int ncfg_hardware_address_strict(const char *text, char *out, size_t out_size, char *err,
    size_t err_size);

/*
 * The same address from a human being's fingers. **More forgiving, and only
 * for an editor.**
 *
 * This is `ncfg_bluetooth_address` from `gui/src/bluetooth_dialog.cpp`: it
 * trims, accepts colons or dashes or neither, takes hex digits in either case,
 * and writes the canonical form. Somebody pasting an address off a label or a
 * `bluetoothctl` listing has all three forms in front of them, and refusing
 * two of them teaches nothing -- whereas the file the editor then writes is
 * canonical, so the language never sees the leniency.
 *
 * **Which is why these are two functions and not one flag.** The forgiving
 * form belongs where a person is typing and a dialog can show them the result;
 * a compiler that quietly accepted `aa-bb-cc-dd-ee-ff` would have widened the
 * language by accident, and nothing would have said so.
 */
int ncfg_hardware_address_typed(const char *text, char *out, size_t out_size, char *err,
    size_t err_size);

/* ------------------------------------------------------------------------ *
 * The closed sets
 * ------------------------------------------------------------------------ */

/*
 * When a hook runs. Spellings from `crates/netcfgd-model/src/hook.rs`
 * (`HookPhase::name`), which is one table for two consumers on purpose: it is
 * the value of `NCFG_PHASE` in the script's environment *and* the name the
 * compiler materialises the script's file under, and a spelling that drifted
 * between them would be a hook running with an environment naming a phase its
 * own filename does not.
 *
 * **Six are written bare and five only after `on`.** `HOOK_PHASES` in
 * `crates/netcfgd-compile/src/parse.rs` is the bare list -- `pre_up`, `up`,
 * `post_up`, `pre_down`, `down`, `post_down` -- and the parser reaches the
 * rest through `on <event> { ... }`, so `on carrier`, `on lease`, `on roam`,
 * `on portal` and `on drift`. The word is the same either way, which is why
 * one table serves both; what differs is only what the parser accepts at the
 * head of a block, and `carrier { }` with no `on` is not a hook at all.
 */
typedef enum {
	NCFG_HOOK_PHASE_PRE_UP,
	NCFG_HOOK_PHASE_UP,
	NCFG_HOOK_PHASE_POST_UP,
	NCFG_HOOK_PHASE_PRE_DOWN,
	NCFG_HOOK_PHASE_DOWN,
	NCFG_HOOK_PHASE_POST_DOWN,
	NCFG_HOOK_PHASE_CARRIER,
	NCFG_HOOK_PHASE_LEASE,
	NCFG_HOOK_PHASE_ROAM,
	NCFG_HOOK_PHASE_PORTAL,
	NCFG_HOOK_PHASE_DRIFT
} ncfg_hook_phase_t;

const char *ncfg_hook_phase_name(ncfg_hook_phase_t phase);
int ncfg_hook_phase_from_name(const char *name, ncfg_hook_phase_t *out, char *err,
    size_t err_size);

/*
 * What happens when a policy routing rule matches. Spellings from
 * `crates/netcfgd-model/src/rule.rs` (`RuleAction::name`).
 *
 * `lookup` is the document default and is also the zero value here, so a
 * zeroed rule means what the Rust's `#[default]` means. That is luck rather
 * than design -- see `ncfg_drift_policy_t`, where it does not hold.
 */
typedef enum {
	NCFG_RULE_ACTION_LOOKUP,
	NCFG_RULE_ACTION_BLACKHOLE,
	NCFG_RULE_ACTION_UNREACHABLE,
	NCFG_RULE_ACTION_PROHIBIT
} ncfg_rule_action_t;

const char *ncfg_rule_action_name(ncfg_rule_action_t action);
int ncfg_rule_action_from_name(const char *name, ncfg_rule_action_t *out, char *err,
    size_t err_size);

/*
 * Which address family a rule belongs to. Spellings from
 * `crates/netcfgd-model/src/rule.rs` (`RuleFamily::name`).
 *
 * Explicit rather than inferred from the selectors, because the common shape
 * -- `from all fwmark 0x1 lookup 100` -- has no address to infer from, and
 * guessing would install the rule in one family only and say nothing.
 */
typedef enum {
	NCFG_RULE_FAMILY_INET,
	NCFG_RULE_FAMILY_INET6
} ncfg_rule_family_t;

const char *ncfg_rule_family_name(ncfg_rule_family_t family);
int ncfg_rule_family_from_name(const char *name, ncfg_rule_family_t *out, char *err,
    size_t err_size);

/*
 * What this machine uses a Bluetooth device for. Spellings from
 * `crates/netcfgd-model/src/bluetooth.rs` (`BluetoothProfile::as_str`).
 *
 * **Kebab-cased, and the only set here that is.** The rest of the language
 * spells its words with underscores, so `a2dp-sink` is the one an author
 * writes from memory and gets wrong; it is serde's `kebab-case` on that enum
 * and not a typo to be tidied up.
 *
 * A closed set from the start, deliberately: the configuration language is the
 * part that cannot be changed quietly later, and a free-form string would have
 * to go on accepting whatever anybody had already written.
 */
typedef enum {
	NCFG_BLUETOOTH_PROFILE_A2DP_SINK,
	NCFG_BLUETOOTH_PROFILE_A2DP_SOURCE,
	NCFG_BLUETOOTH_PROFILE_HFP,
	NCFG_BLUETOOTH_PROFILE_PAN,
	NCFG_BLUETOOTH_PROFILE_NAP
} ncfg_bluetooth_profile_t;

const char *ncfg_bluetooth_profile_name(ncfg_bluetooth_profile_t profile);
int ncfg_bluetooth_profile_from_name(const char *name, ncfg_bluetooth_profile_t *out, char *err,
    size_t err_size);

/*
 * What to do when observed state stops matching desired state. Spellings from
 * `DriftPolicy` in `crates/netcfgd-model/src/lib.rs`, and the same three words
 * `lower.rs` accepts for `on_drift`.
 *
 * **The document default is `reconcile`, which is not the zero value here.**
 * Rust puts `#[default]` on the second variant and the order is the order the
 * policies were written in; C has no such thing, so a calloc'd structure means
 * `report` -- a daemon that watches its configuration go unimplemented and
 * changes nothing. Whoever builds the aggregate sets this explicitly. That
 * default was changed by the copyright holder for exactly this reason: every
 * symptom of the milestone was a configuration written, a correct plan, and
 * nothing that ran it.
 */
typedef enum {
	NCFG_DRIFT_POLICY_REPORT,
	NCFG_DRIFT_POLICY_RECONCILE,
	NCFG_DRIFT_POLICY_IGNORE
} ncfg_drift_policy_t;

const char *ncfg_drift_policy_name(ncfg_drift_policy_t policy);
int ncfg_drift_policy_from_name(const char *name, ncfg_drift_policy_t *out, char *err,
    size_t err_size);

/*
 * How a resolved DNS policy reaches the system. Spellings from
 * `crates/netcfgd-model/src/dns.rs` (`DnsMode::name`), which agree with
 * `render.rs`'s renderer and `lower.rs`'s reader.
 *
 * A mode is a contract with a specific tool rather than a preference, and
 * there is deliberately no `auto`: the mode decides where queries go, and that
 * is not a thing to pick by heuristic (`doc/decision/0007`).
 *
 * **Two asymmetries, both real and both in the Rust.** `lower.rs` also accepts
 * `resolv.conf` for `write_resolv_conf` -- the file's own name, which is what
 * an operator reaches for -- so this reader takes it too and `name` renders
 * the underscored spelling back. And `exec` is a mode the model has and the
 * language cannot yet write: `DnsMode::Exec` carries the command, `lower.rs`
 * has no arm for the word, and `render.rs` reports the mode as one it cannot
 * express. The word is here because `DnsMode::name` returns it and a document
 * arriving as JSON carries it; the command it carries belongs to the policy
 * this enum is a field of, not to the enum.
 */
typedef enum {
	NCFG_DNS_MODE_NONE,
	NCFG_DNS_MODE_WRITE_RESOLV_CONF,
	NCFG_DNS_MODE_RESOLVCONF,
	NCFG_DNS_MODE_OPENRESOLV,
	NCFG_DNS_MODE_RESOLVED,
	NCFG_DNS_MODE_DNSMASQ,
	NCFG_DNS_MODE_UNBOUND,
	NCFG_DNS_MODE_EXEC
} ncfg_dns_mode_t;

const char *ncfg_dns_mode_name(ncfg_dns_mode_t mode);
int ncfg_dns_mode_from_name(const char *name, ncfg_dns_mode_t *out, char *err, size_t err_size);

#endif /* NCFG_VALUE_H */
