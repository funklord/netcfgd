/*
 * render.h -- the desired-state document, back as configuration text.
 *
 * The compiler goes one way and everything else in this port renders one block
 * it already knows about. This is the other direction for a *whole* document,
 * which is what `ncfg profile save` needs: a profile has to mean later exactly
 * what the machine is running now, and the only exact form of that is the
 * document itself written back out.
 *
 * **COVERAGE IS PARTIAL AND REFUSAL IS EXPLICIT, WHICH IS THE WHOLE MODULE.**
 *
 *   What this cannot render it *names*, rather than leaving out. A renderer
 *   that silently drops a field is worse than no renderer at all, because the
 *   field is gone from a profile nobody will read again until they need it --
 *   and by then the machine is the only record of what it used to say. So
 *   `ncfg_render` fails with a list, `ncfg profile save` prints the list, and
 *   the operator writes that part of the profile by hand knowing which part.
 *
 *   That is not a style preference. Every named defect this module carries a
 *   test for was a *silent* drop rather than a refusal: a device whose only
 *   setting was `on_unmanage` vanished from the profile entirely, a wireless
 *   network lost its `bssid` pins and its `roam` policy and its own `config`,
 *   `routes` and `dns`, and a switch port lost its VLANs. Every one of them
 *   reported success.
 *
 *   **Which is why `missing` is not optional.** A caller that passes NULL for
 *   it is a caller discarding the refusal list, which is exactly the failure
 *   above wearing a different hat, so it is refused rather than tolerated.
 *
 * WHAT IT REFUSES, AND WHY EACH ONE IS THERE
 *
 *   * `rule` and `access_point` blocks, and an interface's or a network's
 *     `hooks`: no rendering exists for the shape yet.
 *   * `wireguard`, `openvpn`, `tunnel`, `tun` and `ifb` devices. The split is
 *     by what a block carries rather than by effort -- the kinds that *do*
 *     render say who they are made of and nothing secret, while wireguard has
 *     peers and a private key and openvpn names an operator's file. Those need
 *     a decision about what a snapshot may contain, not more keys.
 *   * A device's `match`, `wifi` policy, `qdisc` and ethtool settings, and a
 *     DNS scope's `options`, `dnssec`, `transport` and a server's `port` or
 *     `sni`: the *model* has them and the configuration language does not, so
 *     these refusals cannot fire from a document the compiler produced. They
 *     cost nothing and are kept, because this takes a document and not a
 *     config file and a missing refusal costs a silent drop.
 *   * A device's `ingress_redirect`, **which must stay refused**. It is not a
 *     config key at all: the compiler synthesises it, and the `ifb` it points
 *     at, from `ingress_bandwidth`. Rendering it would make the next compile
 *     synthesise a second one on top of the first. A derived field is not a
 *     missing feature, and treating it as one would be the bug.
 *
 * WHAT IT OMITS ON PURPOSE, WITH THE REASON STATED
 *
 *   Three fields are neither rendered nor refused, and each has a reason that
 *   is not "nobody got to it":
 *
 *   * `globals.profile`. `ncfg profile save` writes the selection through its
 *     own drop-in, and a profile that named itself would make the loader
 *     choose again -- which the loader refuses.
 *   * `schema_version` and `generated_by`. The configuration language cannot
 *     express either and the compiler regenerates both.
 *
 * OVERRIDES: A PROFILE LAYERS OVER A BASE, AND ONLY THE CALLER KNOWS
 *
 *   A block the base already defines has to say `override`, and one it does
 *   not must not -- `override` with nothing to override is a compile error, so
 *   getting this wrong produces a profile that cannot load at all. Nothing in
 *   the document says which is which, so the caller does, keyed by kind and
 *   name.
 */
#ifndef NCFG_RENDER_H
#define NCFG_RENDER_H

#include <stddef.h>

#include "ncfg/buf.h"
#include "ncfg/document.h"

/*
 * The blocks that must be written as `override`, by kind and name.
 *
 * The Rust holds a `BTreeSet<String>` keyed `"<kind> <name>"`; this holds the
 * same joined keys in a counted array and searches them linearly. A profile
 * names a handful of blocks at most, so a tree would be machinery bought for
 * nothing -- and the key spelling is kept identical so that a caller ported
 * from the Rust side needs no translation.
 */
typedef struct {
	char **keys;
	size_t count;
	size_t capacity;
} ncfg_overrides_t;

/* Start an empty set. Freeing one that was only initialised is nothing. */
void ncfg_overrides_init(ncfg_overrides_t *overrides);

/*
 * Record that the base defines `<kind> <name>`, so the profile must override
 * it. `kind` is the block word: `interface`, `network`, `device`, `bluetooth`
 * or `linkset`.
 */
int ncfg_overrides_add(ncfg_overrides_t *overrides, const char *kind, const char *name, char *err,
    size_t err_size);

/* Whether the base defines that block. A NULL set is an empty one. */
int ncfg_overrides_has(const ncfg_overrides_t *overrides, const char *kind, const char *name);

void ncfg_overrides_free(ncfg_overrides_t *overrides);

/*
 * What could not be rendered, one sentence each, in the order the document was
 * walked.
 *
 * **Returned whole rather than one at a time**, so that somebody looking at an
 * exotic configuration learns everything that is in the way at once instead of
 * finding out one `save` at a time.
 *
 * `failed` is buf.h's sticky-failure idea applied to a list: an allocation
 * that could not be made while collecting sets it and is never cleared, so the
 * collector may push twenty entries and the caller check once -- and a list
 * that silently lost an entry cannot be mistaken for a shorter list of real
 * refusals, which would be this module's own defect committed against itself.
 */
typedef struct {
	char **items;
	size_t count;
	size_t capacity;
	int    failed;
} ncfg_unrenderable_t;

void ncfg_unrenderable_init(ncfg_unrenderable_t *missing);
void ncfg_unrenderable_free(ncfg_unrenderable_t *missing);

/*
 * Render a whole document as configuration text.
 *
 * Returns 1 with the text in `text`. Returns 0 with `missing` holding every
 * part that has no rendering here and a sentence in `err`; **`text` is emptied
 * in that case**, because half a profile that looks whole is the failure
 * buf.h's sticky flag exists to refuse and this is the same argument one level
 * up.
 *
 * `overrides` may be NULL, which means the base defines nothing. `missing` may
 * not: see the header comment.
 */
int ncfg_render(const ncfg_document_t *document, const ncfg_overrides_t *overrides,
    ncfg_buf_t *text, ncfg_unrenderable_t *missing, char *err, size_t err_size);

#endif /* NCFG_RENDER_H */
