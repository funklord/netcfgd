/*
 * walk.c -- the walk, the path accumulation, and the four refusals.
 *
 * `walk.h` carries why this slices the source rather than re-spelling a value,
 * and why nothing is skipped silently. This carries the tree walk.
 */
#include "ncfg/walk.h"

#include "ncfg/ast.h"
#include "ncfg/parse.h"

#include <stdio.h>
#include <string.h>

/*
 * How deep a key path may go, and how long.
 *
 * `wifi.roam.slow_interval` is the deepest the language reaches today at three
 * components. The bound is here because this builds a path into a fixed buffer
 * -- nothing in `compile/` allocates for a diagnostic -- and because a
 * document nesting further than the parser's own limit is a document the
 * parser already refused.
 */
#define WALK_PATH_MAX 160u

typedef struct {
	const char  *text;
	size_t       length;
	ncfg_walk_fn visit;
	void        *ctx;
	/* Zero once the visit asks to stop. */
	int          going;
} walk_t;

/*
 * The keys whose value may be either a stored secret or a PATH.
 *
 * Matched on the LEAF alone and deliberately wider than the three sites that
 * call `ncfg_as_cert_source`: over-matching here withholds a value that could
 * have travelled, which an operator sees and can ask about, while
 * under-matching sends a root-readable path to every host in the estate. The
 * asymmetry decides the width.
 */
static const char *const CREDENTIAL_LEAVES[] = { "ca_cert", "client_cert", "private_key" };

/*
 * The keys whose value may be a stored secret and NOTHING else.
 *
 * Enumerated from the call sites rather than guessed: every `ncfg_as_secret`
 * in `lower_kind.c` and `lower_network.c` is reached under one of these three
 * spellings, and that function emits a diagnostic for a bare string rather
 * than falling through to a path -- which is what makes these strict where
 * `CREDENTIAL_LEAVES` above is dual.
 *
 * **They are here because a compile-time refusal does not reach this path.**
 * `scope.c` gives `wifi.psk` a wire number on the stated ground that
 * "`ncfg_as_secret` refuses a bare string", and it does. But a walk parses and
 * does not lower, so a document holding a literal passphrase -- one the
 * compiler would reject and the daemon would never run -- walked clean and the
 * passphrase went out as a record. The property was true of the compiler and
 * assumed of the walker, which is an unstated precondition rather than a
 * shared one.
 *
 * `private_key` stays in the dual list and deliberately not here: two keys
 * share that leaf, wireguard's being strict and dot1x's a cert source, and
 * nothing at this layer tells them apart. The dual verdict withholds either
 * way, so over-matching there costs a value that could have travelled and
 * under-matching here would cost the key itself.
 */
static const char *const SECRET_LEAVES[] = { "psk", "password", "preshared_key" };

/* The one spelling `ncfg_as_secret` accepts, so anything else under one of the
 * keys above is a path. Named here rather than guessed: `lower_value.c`
 * refuses a bare string precisely so that "a config file stays safe to
 * commit". */
static const char SECRET_PREFIX[] = "@secret:";

static const char *leaf_of(const char *path)
{
	const char *dot = strrchr(path, '.');

	return dot ? dot + 1 : path;
}

static int names_a_credential(const char *path)
{
	const char *leaf = leaf_of(path);
	size_t      at;

	for (at = 0u; at < sizeof(CREDENTIAL_LEAVES) / sizeof(CREDENTIAL_LEAVES[0]); at++) {
		if (strcmp(leaf, CREDENTIAL_LEAVES[at]) == 0) {
			return 1;
		}
	}
	return 0;
}

static int names_a_secret(const char *path)
{
	const char *leaf = leaf_of(path);
	size_t      at;

	for (at = 0u; at < sizeof(SECRET_LEAVES) / sizeof(SECRET_LEAVES[0]); at++) {
		if (strcmp(leaf, SECRET_LEAVES[at]) == 0) {
			return 1;
		}
	}
	return 0;
}

/*
 * Whether a written value is a stored reference rather than a path.
 *
 * The slice carries its quotes, this being the source text, so the prefix is
 * looked for just inside the opening one. A value that is not a quoted string
 * at all is not a secret reference either, and falls through to "path" --
 * which is the safe direction.
 */
static int is_secret_reference(const char *value, size_t len)
{
	size_t at = 0u;

	if (len > 0u && value[0] == '"') {
		at = 1u;
	}
	if (len - at < sizeof(SECRET_PREFIX) - 1u) {
		return 0;
	}
	return memcmp(value + at, SECRET_PREFIX, sizeof(SECRET_PREFIX) - 1u) == 0;
}

static void report(walk_t *walk, ncfg_walk_item_t *item)
{
	if (!walk->going) {
		return;
	}
	if (!walk->visit(walk->ctx, item)) {
		walk->going = 0;
	}
}

/* Append `.name` to a path, or `name` at the top of a block. Returns 0 when it
 * would not fit, which the caller reports rather than truncating: a truncated
 * path is a different key. */
static int path_push(char *path, size_t cap, size_t *len, const char *name)
{
	size_t want = strlen(name);
	size_t need = *len + want + (*len > 0u ? 1u : 0u) + 1u;

	if (need > cap) {
		return 0;
	}
	if (*len > 0u) {
		path[(*len)++] = '.';
	}
	memcpy(path + *len, name, want);
	*len += want;
	path[*len] = '\0';
	return 1;
}

static void walk_items(walk_t *walk, const ncfg_ast_items_t *items, ncfg_block_t block,
    const char *block_name, const char *label, size_t label_len, char *path, size_t path_len);

/* One `key = value`, once its path is known. */
static void walk_assignment(walk_t *walk, const ncfg_ast_assignment_t *assignment,
    ncfg_block_t block, const char *block_name, const char *label, size_t label_len,
    const char *path)
{
	ncfg_walk_item_t item;

	memset(&item, 0, sizeof(item));
	item.block = block;
	item.block_name = block_name;
	item.label = label;
	item.label_len = label_len;
	item.path = path;
	item.span = assignment->span;
	item.value = walk->text + assignment->value->span.offset;
	item.value_len = assignment->value->span.length;
	item.scope = ncfg_scope_of(block, path);
	item.kind = ncfg_kind_of(block, path);

	/*
	 * **In order of permanence, not in the order they are cheap to
	 * check.** A caller telling an operator why a value did not replicate
	 * wants the answer that will still be true tomorrow: "this is a path"
	 * outlives "this key has no number yet", and reporting the second
	 * would invite somebody to close a registry gap that changes nothing
	 * for the value in front of them.
	 */
	if (item.scope == NCFG_SCOPE_HOST_PRIVATE) {
		item.what = NCFG_WALK_WITHHELD;
		item.withheld = NCFG_WITHHELD_HOST_PRIVATE;
	} else if (names_a_credential(path) && !is_secret_reference(item.value, item.value_len)) {
		/*
		 * **The refusal `bridge/record_encode.c` could not own.** It
		 * takes bytes and has no document model, so it cannot tell a
		 * stored reference from a path; here the written value is in
		 * hand. project.md 10.327 named this as the layer it belongs
		 * in, and this is that layer.
		 */
		item.what = NCFG_WALK_WITHHELD;
		item.withheld = NCFG_WITHHELD_PRIVILEGED;
	} else if (names_a_secret(path) && !is_secret_reference(item.value, item.value_len)) {
		item.what = NCFG_WALK_WITHHELD;
		item.withheld = NCFG_WITHHELD_PLAINTEXT;
	} else if (item.kind == NCFG_KIND_NONE) {
		item.what = NCFG_WALK_WITHHELD;
		item.withheld = NCFG_WITHHELD_UNREGISTERED;
	} else {
		item.what = NCFG_WALK_EMIT;
	}
	report(walk, &item);
}

/* A `phase { }` body, or an `include`. Reported rather than passed over, so
 * that a caller mirroring a file knows the file holds something the estate
 * will never see. */
static void walk_program(walk_t *walk, ncfg_block_t block, const char *block_name,
    const char *label, size_t label_len, const char *path, ncfg_span_t span)
{
	ncfg_walk_item_t item;

	memset(&item, 0, sizeof(item));
	item.what = NCFG_WALK_WITHHELD;
	item.withheld = NCFG_WITHHELD_PROGRAM;
	item.block = block;
	item.block_name = block_name;
	item.label = label;
	item.label_len = label_len;
	item.path = path;
	item.span = span;
	report(walk, &item);
}

static void walk_items(walk_t *walk, const ncfg_ast_items_t *items, ncfg_block_t block,
    const char *block_name, const char *label, size_t label_len, char *path, size_t path_len)
{
	size_t at;

	for (at = 0u; at < items->count && walk->going; at++) {
		const ncfg_ast_item_t *item = items->at[at];
		size_t                 saved = path_len;

		switch (item->kind) {
		case NCFG_AST_ITEM_ASSIGNMENT:
			if (!path_push(path, WALK_PATH_MAX, &path_len, item->as.assignment.key)) {
				/* Too long to name, so it cannot be looked up
				 * either. Withheld as unregistered, which is
				 * what an unnameable key is. */
				ncfg_walk_item_t over;

				memset(&over, 0, sizeof(over));
				over.what = NCFG_WALK_WITHHELD;
				over.withheld = NCFG_WITHHELD_UNREGISTERED;
				over.block = block;
				over.block_name = block_name;
				over.label = label;
				over.label_len = label_len;
				over.path = path;
				over.span = item->as.assignment.span;
				report(walk, &over);
				break;
			}
			walk_assignment(walk, &item->as.assignment, block, block_name, label,
			    label_len, path);
			break;
		case NCFG_AST_ITEM_BLOCK:
			if (!path_push(path, WALK_PATH_MAX, &path_len, item->as.block.head)) {
				break;
			}
			/* A sub-block's own label, where it has one, is not part
			 * of the key path: the path names the KEY and the label
			 * names an instance, and folding one into the other
			 * would give two instances one number. */
			walk_items(walk, &item->as.block.items, block, block_name, label,
			    label_len, path, path_len);
			break;
		case NCFG_AST_ITEM_HOOK:
			if (path_push(path, WALK_PATH_MAX, &path_len, item->as.hook.phase)) {
				walk_program(walk, block, block_name, label, label_len, path,
				    item->as.hook.span);
			}
			break;
		case NCFG_AST_ITEM_INCLUDE:
			walk_program(walk, block, block_name, label, label_len, path,
			    item->as.include.span);
			break;
		default:
			break;
		}
		path_len = saved;
		path[path_len] = '\0';
	}
}

/* A top-level block, or a report that this build does not know it. */
static void walk_block(walk_t *walk, const ncfg_ast_block_t *block)
{
	char         path[WALK_PATH_MAX];
	ncfg_block_t which;

	path[0] = '\0';
	if (!ncfg_block_from_name(block->head, &which)) {
		/*
		 * One report for the whole block rather than a refusal per key.
		 * Nothing here can say what a key inside an unknown block
		 * means, so listing them would be inventing paths -- and a
		 * caller that has met a block this build does not know has a
		 * version problem rather than a key problem.
		 */
		ncfg_walk_item_t item;

		memset(&item, 0, sizeof(item));
		item.what = NCFG_WALK_WITHHELD;
		item.withheld = NCFG_WITHHELD_UNKNOWN_BLOCK;
		item.block = (ncfg_block_t)NCFG_BLOCK_COUNT;
		item.block_name = block->head;
		item.label = block->label;
		item.label_len = block->label_length;
		item.path = "";
		item.span = block->span;
		report(walk, &item);
		return;
	}
	walk_items(walk, &block->items, which, block->head, block->label, block->label_length,
	    path, 0u);
}

int ncfg_walk(const char *text, size_t length, ncfg_walk_fn visit, void *ctx, char *err,
    size_t err_size)
{
	ncfg_ast_file_t *file = NULL;
	walk_t           walk;
	size_t           at;

	if (!text || !visit) {
		if (err && err_size > 0u) {
			snprintf(err, err_size, "nothing to walk");
		}
		return 0;
	}
	if (!ncfg_parse(text, length, &file, NULL, err, err_size)) {
		return 0;
	}

	walk.text = text;
	walk.length = length;
	walk.visit = visit;
	walk.ctx = ctx;
	walk.going = 1;

	for (at = 0u; at < file->items.count && walk.going; at++) {
		const ncfg_ast_item_t *item = file->items.at[at];

		if (item->kind == NCFG_AST_ITEM_BLOCK) {
			walk_block(&walk, &item->as.block);
		} else if (item->kind == NCFG_AST_ITEM_INCLUDE) {
			walk_program(&walk, (ncfg_block_t)NCFG_BLOCK_COUNT, "", NULL, 0u, "",
			    item->as.include.span);
		}
		/* An assignment outside any block is not a key of any block, so
		 * there is nothing to say about it here. The compiler refuses
		 * it where refusing belongs. */
	}

	ncfg_ast_file_free(file);
	return 1;
}

const char *ncfg_withheld_why(ncfg_withheld_t withheld)
{
	switch (withheld) {
	case NCFG_WITHHELD_NONE:
		return "nothing withheld";
	case NCFG_WITHHELD_PROGRAM:
		return "a hook body is shell and an include is a path: neither ever travels";
	case NCFG_WITHHELD_PRIVILEGED:
		return "the value names a file to open as root; write `@secret:NAME` to share it";
	case NCFG_WITHHELD_HOST_PRIVATE:
		return "this key is host-private and must not leave the machine";
	case NCFG_WITHHELD_UNREGISTERED:
		return "this key has no wire number yet, so it cannot be carried";
	case NCFG_WITHHELD_UNKNOWN_BLOCK:
		return "this build does not know this block, so nothing in it can be read";
	case NCFG_WITHHELD_PLAINTEXT:
		return "the value is a credential written out, not a reference: write "
		       "`@secret:NAME` so the name travels and the secret stays here";
	case NCFG_WITHHELD_REASONS:
		break;
	default:
		break;
	}
	return "unknown";
}
