/*
 * render_private.h -- what the renderer's three sources share.
 *
 * The renderer is one module and three files because it passed a thousand
 * lines in one, and the split is by what a block *is* rather than by size:
 *
 *   render.c         the machinery, host-wide policy, DNS, and the walk
 *   render_link.c    interfaces and wireless networks, which share addressing,
 *                    routes and the eight 802.1X keys
 *   render_device.c  devices, link kinds, bluetooth and linksets
 *
 * **Nothing here is public.** `ncfg/render.h` is the module's face; this is
 * three files agreeing with each other, and it lives beside them rather than
 * under `include/` so that nothing outside the module can come to depend on
 * it. The `ncfg_render_` prefix is not decoration: code-style.md requires a
 * distinct prefix for any symbol that reaches the linker, whether or not it is
 * part of an API, because a bare `quote` here would collide at a call site
 * nobody touched.
 */
#ifndef NCFG_RENDER_PRIVATE_H
#define NCFG_RENDER_PRIVATE_H

#include <stddef.h>

#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/render.h"

#define NCFG_COUNT_OF(array) (sizeof(array) / sizeof((array)[0]))

/*
 * The word for a value, or NULL where the value is outside the set.
 *
 * NULL rather than a plausible word, which is value.h's rule: a word for a
 * value that is not one is worse than no word. Nothing here can be reached
 * with a value outside its set from a document `ncfg_document_read` produced,
 * because the reader checks every closed set on the way in -- so the second
 * function exists for a document somebody built by hand, where the alternative
 * is a NULL at a `%s` and undefined behaviour in a library that is not allowed
 * to crash.
 */
const char *ncfg_render_word(const char *const *words, size_t count, int which);
const char *ncfg_render_word_or_gap(const char *word);

/*
 * Record what could not be rendered: "`scope` `name`: what", or "`scope`: what"
 * where the scope is a singleton such as `global`, or bare "what" for the
 * document as a whole.
 *
 * The scope is carried in two pieces rather than pre-joined by every caller
 * because joining it allocates, and an allocation per refusal site would be an
 * error path per refusal site. Here it is one path, and its failure is sticky
 * in `missing->failed`.
 */
void ncfg_render_refuse(ncfg_unrenderable_t *missing, const char *scope, const char *name,
    const char *format, ...);

/*
 * A string as the lexer reads it back.
 *
 * A quote or a backslash left raw would end the string early and produce a
 * file that does not compile -- which takes every *other* block with it, since
 * the loader compiles the whole directory as one document.
 */
void ncfg_render_quote(ncfg_buf_t *out, const char *value);

/*
 * A credential as the document refers to it -- **never as its value.**
 *
 * The provider is written only when it is not the default, which keeps an
 * ordinary `psk` reading as `@secret:home-wifi` rather than as something with
 * machinery in it.
 */
void ncfg_render_quote_secret(ncfg_buf_t *out, const ncfg_secret_ref_t *reference);

/*
 * One value bare, several as a list.
 *
 * Both are legal and the compiler reads either; a single-element list is noise
 * in a file somebody has to read. A DNS server list and a linkset's members
 * are always bracketed, which is what `always_bracket` is for.
 *
 * The entries are joined as they arrive rather than held in an array, so an
 * entry may be quoted, escaped or built up a piece at a time without this
 * needing to know which: `next` opens the slot and hands back the buffer to
 * write it into.
 */
typedef struct {
	ncfg_buf_t joined;
	size_t     count;
} ncfg_render_list_t;

void        ncfg_render_list_init(ncfg_render_list_t *list);
void        ncfg_render_list_free(ncfg_render_list_t *list);
ncfg_buf_t *ncfg_render_list_next(ncfg_render_list_t *list);
void        ncfg_render_list_emit(ncfg_buf_t *body, const char *indent, const char *key,
               const ncfg_render_list_t *list, int always_bracket);

/* `override ` when the base defines this block, nothing when it does not, with
 * the blank line and the block word that always precede a name. */
void ncfg_render_opening(ncfg_buf_t *text, const char *kind, const char *name,
    const ncfg_overrides_t *overrides);

/* One DNS scope. Returns whether it wrote a block at all, which the callers
 * that have an empty-block meaning need; see the definition. */
int ncfg_render_dns(const ncfg_dns_policy_t *dns, const char *indent, ncfg_buf_t *body,
    ncfg_unrenderable_t *missing, const char *scope, const char *name);

void ncfg_render_interface(const ncfg_interface_t *interface, const ncfg_overrides_t *overrides,
    ncfg_buf_t *text, ncfg_unrenderable_t *missing);
void ncfg_render_network(const ncfg_wifi_network_t *network, const ncfg_overrides_t *overrides,
    ncfg_buf_t *text, ncfg_unrenderable_t *missing);
void ncfg_render_device(const ncfg_device_t *device, const ncfg_overrides_t *overrides,
    ncfg_buf_t *text, ncfg_unrenderable_t *missing);
void ncfg_render_bluetooth(const ncfg_bluetooth_device_t *device,
    const ncfg_overrides_t *overrides, ncfg_buf_t *text);
void ncfg_render_linkset(const ncfg_linkset_t *set, const ncfg_overrides_t *overrides,
    ncfg_buf_t *text);

#endif /* NCFG_RENDER_PRIVATE_H */
