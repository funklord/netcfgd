/*
 * lower_internal.h -- what the lowering files share.
 *
 * Private to `src/compile/lower*.c`. Nothing outside this directory includes
 * it, and nothing in `lower.h` mentions any of it.
 *
 * WHY THE LOWERING IS SEVERAL FILES
 *   The Rust it replaces is one 5,166-line module, which is the largest file
 *   in the compiler by a factor of three. It is split here by the block the
 *   code is about -- interface, device, network, rule -- because that is the
 *   axis along which somebody reads it: a question about `access_point` is
 *   answered in one file rather than by scrolling past wireguard peers. The
 *   shared readers are here and in `lower_value.c` so that there is one
 *   `as_string` and one "is this an interface name", which is the property
 *   the Rust got from having a single module.
 *
 * THE FAILURE MODEL, WHICH IS `buf.h`'S
 *   `ncfg_lower_ctx_t.failed` is set by the first allocation that fails and
 *   never cleared, and every allocator here is a no-op afterwards. That is
 *   what lets a hundred lowering sites be written without an out-of-memory
 *   branch each -- which is what makes the error handling get done at all --
 *   and the entry point checks once, at the end, and hands back nothing.
 *
 *   A *diagnostic* is a different thing from a failure: it means the operator
 *   wrote something wrong, the lowering carries on so that the next mistake is
 *   found too, and the document is discarded at the end.
 */
#ifndef NCFG_LOWER_INTERNAL_H
#define NCFG_LOWER_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "ncfg/lower.h"

/* ------------------------------------------------------------------------ *
 * The merged form
 * ------------------------------------------------------------------------ */

/*
 * One statement of a merged block, with the file it was written in.
 *
 * Every block carries a list of these rather than using the AST's items
 * directly, and the reason is `global`: it is folded together from several
 * files, so one block's items do not all come from one place. Built for every
 * block rather than only for that one, because a special case that exists for
 * a single head is a special case somebody reads the wrong way round.
 */
typedef struct {
	const ncfg_ast_item_t *item;
	const char            *source;
} ncfg_merged_item_t;

typedef struct {
	const ncfg_ast_block_t *block;
	const char             *source;
	ncfg_merged_item_t     *items;
	size_t                  item_count;
	size_t                  item_capacity;
} ncfg_merged_block_t;

typedef struct {
	const ncfg_ast_assignment_t *assignment;
	const char                  *source;
} ncfg_merged_assignment_t;

struct ncfg_merged {
	ncfg_merged_block_t      *blocks;
	size_t                    block_count;
	size_t                    block_capacity;
	ncfg_merged_assignment_t *assignments;
	size_t                    assignment_count;
	size_t                    assignment_capacity;
};

/* ------------------------------------------------------------------------ *
 * The state one lowering carries
 * ------------------------------------------------------------------------ */

typedef struct {
	/* The file whose text the current item came from, for a diagnostic. */
	const char             *source;
	ncfg_lower_diags_t     *diags;
	const ncfg_hook_sink_t *hooks;
	ncfg_document_t        *document;
	/* Where each field was written, or NULL for a caller that wants none.
	 * Appended to by `ncfg_record` and by nothing else. */
	ncfg_provenance_t      *provenance;
	/* Set by the first allocation failure and never cleared. */
	int                     failed;
} ncfg_lower_ctx_t;

/* Note that something could not be allocated. Sticky. */
void ncfg_lower_oom(ncfg_lower_ctx_t *ctx);

/*
 * Report a mistake in the configuration at `span`.
 *
 * One sentence, with any help joined on after a colon -- `parse.h`'s rule, so
 * that a grep for a diagnostic finds all of it rather than half.
 */
void ncfg_diag(ncfg_lower_ctx_t *ctx, ncfg_span_t span, const char *format, ...);

/* Whether any diagnostic has been reported, which is what decides whether the
 * document is handed over. */
int ncfg_diags_any(const ncfg_lower_ctx_t *ctx);

/* ------------------------------------------------------------------------ *
 * Where a field was written
 * ------------------------------------------------------------------------ */

/*
 * Record that the field at `format` was written at `span`, in `source`.
 *
 * Nothing happens where the context was given no table, which is the ordinary
 * case: `ncfg_compile` asks for none and pays one NULL test per field for it.
 *
 * **`source` is an argument and is deliberately not read from the context.**
 * `lex.h`'s span carries no source id (0263), so the file name has to come
 * from beside the span rather than out of it -- and `ctx->source` is a
 * *moving* variable, reassigned per item as a block is walked. A record taken
 * after that walk would name whichever file the block's last item came from,
 * which on a `global` folded out of two drop-ins is a different file from the
 * one the block was opened in. So the caller passes the name it means:
 * `block->source` where the block is the subject, `ctx->source` where the item
 * being lowered is.
 *
 * A path that does not fit the buffer records nothing rather than a truncated
 * key: a key spelled wrong is a lookup that misses while the table looks full,
 * which is the one failure `explain` cannot see. So is the bound:
 * `NCFG_PROVENANCE_MAX` entries and no more.
 */
void ncfg_record(ncfg_lower_ctx_t *ctx, const char *source, ncfg_span_t span, const char *format,
    ...);

/* ------------------------------------------------------------------------ *
 * Allocation
 * ------------------------------------------------------------------------ */

/* A copy of `text`, or NULL with the context marked failed. Copying NULL is
 * NULL and is not a failure. */
char *ncfg_dup(ncfg_lower_ctx_t *ctx, const char *text);

/*
 * Append one zeroed element to a counted array, and return it.
 *
 * `array` is the address of the `T *`. The array is grown to exactly the new
 * count: these lists are tens of entries at most, and exact sizing means the
 * document's own free walk -- which knows a pointer and a count and no
 * capacity -- describes the allocation exactly.
 */
void *ncfg_push(ncfg_lower_ctx_t *ctx, void *array, size_t *count, size_t element_size);

/* The same, for a list of strings. `text` is copied. */
int ncfg_push_string(ncfg_lower_ctx_t *ctx, char ***array, size_t *count, const char *text);

/* Take ownership of an already-allocated string, which saves a copy where the
 * caller built the text itself. Frees `text` and fails on out of memory. */
int ncfg_push_string_owned(ncfg_lower_ctx_t *ctx, char ***array, size_t *count, char *text);

/* Whether a list of strings already holds this one. */
int ncfg_has_string(char *const *array, size_t count, const char *text);

/*
 * Releasing a piece of a document that never became part of one.
 *
 * **The document's own free walk is table-driven and private to the model**,
 * and it can only be asked to free a whole document. A block this module
 * refuses after it has already built half of it -- a network with no `wifi`, a
 * rule with no `priority` -- never reaches the document, so these are what
 * stop a refusal from being a leak. There is one per aggregate, which is
 * `base.h`'s third convention applied to the pieces rather than to the whole.
 */
void ncfg_strings_free(char **list, size_t count);
void ncfg_security_free(ncfg_security_t *security);
void ncfg_dns_policy_free(ncfg_dns_policy_t *dns);
void ncfg_address_sources_free(ncfg_address_source_t *list, size_t count);
void ncfg_routes_free(ncfg_route_t *list, size_t count);
void ncfg_hooks_free(ncfg_hook_ref_t *list, size_t count);

/* ------------------------------------------------------------------------ *
 * Words
 * ------------------------------------------------------------------------ */

/* One word of a list or a string, with the span to complain at. */
typedef struct {
	char       *text;
	ncfg_span_t span;
} ncfg_word_t;

typedef struct {
	ncfg_word_t *at;
	size_t       count;
} ncfg_words_t;

void ncfg_words_free(ncfg_words_t *words);

/* ------------------------------------------------------------------------ *
 * Reading a value
 *
 * Each returns 1 and writes `*out`, or returns 0 having reported why -- which
 * is `value.h`'s convention, for its reason: a reader that returned the first
 * variant on a misspelling would be the silent version of the same defect.
 * ------------------------------------------------------------------------ */

char *ncfg_as_string(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value);
int   ncfg_as_bool(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value, int *out);
int   ncfg_as_i64(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value, int64_t *out);
int   ncfg_as_u32(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value, int64_t *out);
/* `as_u32` into an `ncfg_optint_t`, which is what most of the model's numbers
 * are. Leaves the slot alone where the value was not a number. */
void  ncfg_as_u32_opt(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value, ncfg_optint_t *out);
/*
 * `as_u32` narrowed to `high`, dropped **silently** where it does not fit.
 *
 * The Rust spells this `as_u32(..).and_then(|n| u16::try_from(n).ok())` at six
 * sites, and the `.ok()` is why `listen_port = 70000` compiles to a document
 * with no listen port and no diagnostic. Preserved rather than corrected: the
 * port is judged against the Rust's own tests for the same behaviour, and the
 * places this is wrong are named in the record rather than fixed one at a time
 * here.
 */
void  ncfg_as_narrow_opt(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value, int64_t high,
    ncfg_optint_t *out);

/* A string splits on whitespace, a list gives its elements. */
int ncfg_as_words(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value, ncfg_words_t *out);
/* A string splits on newlines, a list gives its elements. The netifrc spelling
 * puts several addresses or routes in one quoted string, one per line, and
 * that is the shape most existing configs are in. */
int ncfg_as_lines(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value, ncfg_words_t *out);

/* `"@secret:NAME"` or `"@secret:provider:NAME"`. */
int ncfg_as_secret(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value, ncfg_secret_ref_t *out);
/* A path on this machine, or `@secret:` content netcfgd holds. */
int ncfg_as_cert_source(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value,
    ncfg_cert_source_t *out);
/* One of the three drift policies. */
int ncfg_as_drift(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value, int *out);

/* ------------------------------------------------------------------------ *
 * Names, addresses and the other small checks
 * ------------------------------------------------------------------------ */

/* Why the name matters, where a link is referred to. */
extern const char *const ncfg_link_name_help;
/* The same, where a block is named for the link it declares. */
extern const char *const ncfg_link_label_help;

/* The one place the "not an interface name" diagnostic is built. */
int   ncfg_name_ok(ncfg_lower_ctx_t *ctx, const char *text, ncfg_span_t span, const char *help);
/* A string that has to be a name the kernel would take for a link. */
char *ncfg_as_interface_name(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value);

/* A block's label, or NULL having said that it needs one. */
char *ncfg_require_label(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block);
/* The same, for a block whose label names a link. */
char *ncfg_require_interface_label(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block);

/* The kernel's own spelling of an address or prefix, or NULL where it is not
 * one. This is `value.h`'s `ncfg_address_canonical`, which records what it
 * cost when it was missing. */
char *ncfg_canonical_address(ncfg_lower_ctx_t *ctx, const char *text);
/* Whether text is an address with no prefix length. */
int   ncfg_is_bare_address(const char *text);
/* Whether text is `address/length`, which is what an allowed IP is. */
int   ncfg_is_prefix(const char *text);
/* Reject an address that is not `IP/prefixlen` here rather than at apply time,
 * when the interface is half configured. */
int   ncfg_check_cidr(ncfg_lower_ctx_t *ctx, const char *text, ncfg_span_t span);
/*
 * The network a prefix names, masked.
 *
 * Returns 1 with the canonical text in `*out` where no host bit was set, 0
 * with the masked text in `*out` where one was, and -1 where the text is not a
 * prefix at all. `*out` is allocated on 1 and 0 and NULL on -1.
 */
int   ncfg_network_of(ncfg_lower_ctx_t *ctx, const char *text, char **out);
/* Whether a string is a hostname the kernel will take. */
int   ncfg_is_hostname(const char *name);
/* An IPv4 netmask as a prefix length, or -1 for a non-contiguous one. */
int   ncfg_netmask_to_prefix(const char *text);

/* An SSID: 0 to 32 arbitrary octets. Returns 1, or 0 with the reason in
 * `*why` -- a static sentence, never allocated. */
int ncfg_ssid_from_bytes(const char *text, size_t length, ncfg_ssid_t *out, const char **why);
/* Lowercase hex, which is the canonical encoding. Uppercase is refused,
 * because two spellings of one SSID would break the byte-identical
 * guarantee. */
int ncfg_ssid_from_hex(const char *text, ncfg_ssid_t *out, const char **why);

/*
 * A station address as an access control list holds it: lowercase, colons.
 *
 * `normalize_station` from `crates/netcfgd-model/src/device.rs`, and neither
 * of `value.h`'s two hardware-address readers: both of those uppercase,
 * because BlueZ prints uppercase, and `document.h` requires this list to be
 * lowercase so that a comparison against what hostapd reports is a string
 * comparison rather than a parse.
 *
 * Returns an allocated string, or NULL with the reason in `*why`.
 */
char *ncfg_normalize_station(ncfg_lower_ctx_t *ctx, const char *text, char *why, size_t why_size);


/* ------------------------------------------------------------------------ *
 * The block lowerers
 * ------------------------------------------------------------------------ */

void ncfg_lower_global_key(ncfg_lower_ctx_t *ctx, const ncfg_ast_assignment_t *assignment);
void ncfg_lower_global_block(ncfg_lower_ctx_t *ctx, const ncfg_merged_block_t *block);
/* A `dns` scope, wherever one is written: in `global`, on an interface, or on
 * a network. One reader, because three spellings of one scope is how they come
 * to accept different words. */
void ncfg_lower_dns_key(ncfg_lower_ctx_t *ctx, ncfg_dns_policy_t *policy,
    const ncfg_ast_assignment_t *assignment);

int ncfg_lower_device(ncfg_lower_ctx_t *ctx, const ncfg_merged_block_t *block,
    ncfg_device_t *out);
/* Whether a block head names a kind, so a caller can route it before parsing.
 * `device` and `interface` both ask, the second so that it can say the block
 * moved rather than "unknown". */
int ncfg_is_kind_block(const char *head);
/* The block that says what kind of thing to create. Returns 0 where the head
 * is not a kind at all, leaving `out` alone. */
int ncfg_lower_kind_block(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *inner,
    ncfg_interface_kind_t *out);
/* The `qdisc { ... }` block. Returns 0 having reported why. */
int ncfg_lower_qdisc(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_qdisc_policy_t *out);
/* One of the schedulers decision 0023 allows, or a diagnostic naming them. */
int ncfg_qdisc_kind(ncfg_lower_ctx_t *ctx, const char *name, ncfg_span_t span, int *out);
/* One bridge VLAN entry: `10`, `10 pvid untagged`, or a range `10-19`. */
void ncfg_lower_bridge_vlans(ncfg_lower_ctx_t *ctx, const ncfg_word_t *entry,
    ncfg_bridge_vlan_t **list, size_t *count);

int ncfg_lower_interface(ncfg_lower_ctx_t *ctx, const ncfg_merged_block_t *block,
    ncfg_interface_t *out);
/*
 * One entry of a `config` value, appended to `list`.
 *
 * `owner` is the interface the list belongs to, and each entry's position is
 * recorded under `interfaces[<owner>].addressing[<index>]`. It is NULL for a
 * list that is not an interface's -- a `network` block's -- which records
 * nothing, because nothing looks an addressing entry up by any other path.
 *
 * **The index is safe to key by only because `ncfg_document_canonicalize`
 * leaves `addressing` in the order it was written.** It sorts routes, hooks,
 * members and stations; this one list it deliberately does not, and that is
 * what makes `addressing[0]` mean the same entry in the table and in the
 * document a reader is holding. A route is keyed by its destination for the
 * other half of the same reason.
 */
void ncfg_lower_config(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value,
    ncfg_address_source_t **list, size_t *count, const char *owner);
/* One entry of a `routes` value. */
int ncfg_lower_route(ncfg_lower_ctx_t *ctx, const ncfg_word_t *entry, ncfg_route_t *out);
/* A hook body, through the sink. Appends to `list` or reports why not. */
void ncfg_lower_hook(ncfg_lower_ctx_t *ctx, const ncfg_ast_hook_t *hook, const char *owner,
    ncfg_hook_ref_t **list, size_t *count);

int ncfg_lower_network(ncfg_lower_ctx_t *ctx, const ncfg_merged_block_t *block,
    ncfg_wifi_network_t *out);
int ncfg_lower_access_point(ncfg_lower_ctx_t *ctx, const ncfg_merged_block_t *block,
    ncfg_access_point_t *out);
/*
 * The keys a `wifi` block can carry, before they become an `ncfg_security_t`.
 *
 * Collected first and interpreted second, because which fields matter depends
 * on which kind of security was named -- and that may be named after them.
 * Shared with an interface's `dot1x`, so that the two cannot drift into
 * accepting different spellings of one thing.
 */
typedef struct {
	int                has_psk;
	ncfg_secret_ref_t  psk;
	int                proto; /* ncfg_psk_proto_t */
	int                open;
	int                owe;
	int                has_eap;
	int                eap; /* ncfg_eap_method_t */
	char              *identity;
	char              *anonymous_identity;
	int                has_password;
	ncfg_secret_ref_t  password;
	ncfg_cert_source_t ca_cert;
	ncfg_cert_source_t client_cert;
	ncfg_cert_source_t private_key;
	char              *phase2;
	char              *domain_suffix_match;
} ncfg_wifi_keys_t;

void ncfg_wifi_keys_free(ncfg_wifi_keys_t *keys);
/* One `key = value` inside a network's `wifi` block. `network` may be NULL
 * where there is none, which is what an access point and a `dot1x` block
 * have. */
void ncfg_lower_wifi_key(ncfg_lower_ctx_t *ctx, ncfg_wifi_keys_t *keys,
    ncfg_wifi_network_t *network, const ncfg_ast_assignment_t *assignment);
/* One `key = value` inside an interface's `dot1x` block. */
void ncfg_lower_dot1x_key(ncfg_lower_ctx_t *ctx, ncfg_wifi_keys_t *keys,
    const ncfg_ast_assignment_t *assignment);
/* Turn the collected keys into the one security mode they describe. Takes
 * ownership of what `keys` holds on success. */
int ncfg_build_security(ncfg_lower_ctx_t *ctx, ncfg_wifi_keys_t *keys,
    const ncfg_ast_block_t *block, ncfg_security_t *out);
/* The `wifi` block of a network or an access point: how to authenticate.
 * Returns 0 where it named no security, having said so. */
int ncfg_lower_wifi_block(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_wifi_network_t *network, ncfg_security_t *out);
/* The `band` and `regdom` keys, checked here rather than at render time.
 * Both spellings of `regdom` come here, and until 0221 only one did. */
void ncfg_lower_band(ncfg_lower_ctx_t *ctx, char **band, const ncfg_ast_assignment_t *assignment);
void ncfg_lower_regdom(ncfg_lower_ctx_t *ctx, char **regdom,
    const ncfg_ast_assignment_t *assignment);

int ncfg_lower_rule(ncfg_lower_ctx_t *ctx, const ncfg_merged_block_t *block,
    ncfg_routing_rule_t *out);
int ncfg_lower_linkset(ncfg_lower_ctx_t *ctx, const ncfg_merged_block_t *block,
    ncfg_linkset_t *out);
int ncfg_lower_bluetooth(ncfg_lower_ctx_t *ctx, const ncfg_merged_block_t *block,
    ncfg_bluetooth_device_t *out);

#endif /* NCFG_LOWER_INTERNAL_H */
