/*
 * merge.c -- drop-in precedence.
 *
 * `netcfgd.conf` first, then every `.conf` under `conf.d` in lexical filename
 * order. Later wins for scalar keys. A block that redefines an existing one is
 * an error unless it says `override`, because silent last-wins is where every
 * config system becomes unpredictable (project.md section 3).
 *
 * Nothing here interprets a word of the language: that is what lets it say
 * "`interface eth0` is already defined" without knowing what an interface is,
 * and it is why the two passes are separate.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lower_internal.h"

#include "ncfg/base.h"

/* ------------------------------------------------------------------------ *
 * Diagnostics, allocation and the sticky failure
 * ------------------------------------------------------------------------ */

void ncfg_lower_diags_free(ncfg_lower_diags_t *diags)
{
	size_t i;

	if (!diags) {
		return;
	}
	for (i = 0; i < diags->count; i++) {
		free(diags->at[i].message);
	}
	free(diags->at);
	diags->at = NULL;
	diags->count = 0;
	diags->total = 0;
	diags->capacity = 0;
}

void ncfg_lower_diag_render(const ncfg_lower_diag_t *diag, char *out, size_t out_size)
{
	const char *name;

	if (!out || out_size == 0) {
		return;
	}
	if (!diag) {
		out[0] = '\0';
		return;
	}
	name = (diag->source && diag->source[0]) ? diag->source : "<unknown>";
	(void)snprintf(out, out_size, "%s:%zu:%zu: %s", name, diag->span.line, diag->span.column,
	    diag->message ? diag->message : "");
}

void ncfg_lower_oom(ncfg_lower_ctx_t *ctx)
{
	ctx->failed = 1;
}

int ncfg_diags_any(const ncfg_lower_ctx_t *ctx)
{
	return ctx->diags && ctx->diags->total > 0;
}

void ncfg_diag(ncfg_lower_ctx_t *ctx, ncfg_span_t span, const char *format, ...)
{
	ncfg_lower_diags_t *diags = ctx->diags;
	char                message[NCFG_ERROR_MAX];
	va_list             args;

	if (!diags) {
		return;
	}
	diags->total++;
	/*
	 * Past the bound the count goes on rising and nothing more is kept.
	 * `parse.h` has the argument: a diagnostic per line is a file-sized
	 * allocation bought with a malformed file, and a client that shows
	 * "64 of 900" is showing more than one that shows nine hundred nobody
	 * scrolls through.
	 */
	if (diags->count >= NCFG_DIAGS_MAX) {
		return;
	}
	if (diags->count == diags->capacity) {
		size_t             want = diags->capacity ? diags->capacity * 2u : 8u;
		ncfg_lower_diag_t *grown;

		if (want > NCFG_DIAGS_MAX) {
			want = NCFG_DIAGS_MAX;
		}
		grown = realloc(diags->at, want * sizeof(*grown));
		if (!grown) {
			ncfg_lower_oom(ctx);
			return;
		}
		diags->at = grown;
		diags->capacity = want;
	}

	va_start(args, format);
	ncfg_error_setv(message, sizeof(message), format, args);
	va_end(args);

	diags->at[diags->count].source = ctx->source;
	diags->at[diags->count].span = span;
	diags->at[diags->count].message = malloc(strlen(message) + 1u);
	if (!diags->at[diags->count].message) {
		ncfg_lower_oom(ctx);
		return;
	}
	memcpy(diags->at[diags->count].message, message, strlen(message) + 1u);
	diags->count++;
}

char *ncfg_dup(ncfg_lower_ctx_t *ctx, const char *text)
{
	char  *copy;
	size_t length;

	if (!text || ctx->failed) {
		return NULL;
	}
	length = strlen(text);
	copy = malloc(length + 1u);
	if (!copy) {
		ncfg_lower_oom(ctx);
		return NULL;
	}
	memcpy(copy, text, length + 1u);
	return copy;
}

void *ncfg_push(ncfg_lower_ctx_t *ctx, void *array, size_t *count, size_t element_size)
{
	void **slot = array;
	char  *grown;

	if (ctx->failed) {
		return NULL;
	}
	grown = realloc(*slot, (*count + 1u) * element_size);
	if (!grown) {
		ncfg_lower_oom(ctx);
		return NULL;
	}
	*slot = grown;
	memset(grown + *count * element_size, 0, element_size);
	*count += 1u;
	return grown + (*count - 1u) * element_size;
}

int ncfg_push_string_owned(ncfg_lower_ctx_t *ctx, char ***array, size_t *count, char *text)
{
	char **slot;

	if (!text) {
		return 0;
	}
	slot = ncfg_push(ctx, array, count, sizeof(char *));
	if (!slot) {
		free(text);
		return 0;
	}
	*slot = text;
	return 1;
}

int ncfg_push_string(ncfg_lower_ctx_t *ctx, char ***array, size_t *count, const char *text)
{
	return ncfg_push_string_owned(ctx, array, count, ncfg_dup(ctx, text));
}

int ncfg_has_string(char *const *array, size_t count, const char *text)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (array[i] && text && strcmp(array[i], text) == 0) {
			return 1;
		}
	}
	return 0;
}

void ncfg_words_free(ncfg_words_t *words)
{
	size_t i;

	if (!words) {
		return;
	}
	for (i = 0; i < words->count; i++) {
		free(words->at[i].text);
	}
	free(words->at);
	words->at = NULL;
	words->count = 0;
}

/* ------------------------------------------------------------------------ *
 * The merge itself
 * ------------------------------------------------------------------------ */

void ncfg_merged_free(ncfg_merged_t *merged)
{
	size_t i;

	if (!merged) {
		return;
	}
	for (i = 0; i < merged->block_count; i++) {
		free(merged->blocks[i].items);
	}
	free(merged->blocks);
	free(merged->assignments);
	free(merged);
}

/* Remember one statement of a block, with the file it was written in. */
static int keep_item(ncfg_lower_ctx_t *ctx, ncfg_merged_block_t *target,
    const ncfg_ast_item_t *item, const char *source)
{
	ncfg_merged_item_t *slot;

	if (target->item_count == target->item_capacity) {
		size_t              want = target->item_capacity ? target->item_capacity * 2u : 8u;
		ncfg_merged_item_t *grown = realloc(target->items, want * sizeof(*grown));

		if (!grown) {
			ncfg_lower_oom(ctx);
			return 0;
		}
		target->items = grown;
		target->item_capacity = want;
	}
	slot = &target->items[target->item_count++];
	slot->item = item;
	slot->source = source;
	return 1;
}

/* Fill a merged block in from a block as written, replacing whatever it held.
 * This is what `override` does: **wholesale**, never key by key. */
static int take_block(ncfg_lower_ctx_t *ctx, ncfg_merged_block_t *target,
    const ncfg_ast_block_t *block, const char *source)
{
	size_t i;

	target->block = block;
	target->source = source;
	target->item_count = 0;
	for (i = 0; i < block->items.count; i++) {
		if (!keep_item(ctx, target, block->items.at[i], source)) {
			return 0;
		}
	}
	return 1;
}

/* The one place the "already defined" sentence is built, so that the merge and
 * the `global` fold cannot come to disagree about what it says. */
static void say_already(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    const char *first_source, size_t first_line, const char *inside)
{
	char described[NCFG_ERROR_MAX];

	ncfg_ast_block_describe(block, described, sizeof(described));
	if (inside) {
		/*
		 * Naming the file, not just the line. The two definitions are usually
		 * in different files -- that is what drop-ins are for -- and with a
		 * factory layer under a writable one they are in different
		 * directories, where "line 1" on its own sends the reader to the
		 * wrong file.
		 */
		ncfg_diag(ctx, block->span,
		    "`%s` is already set in `%s`: first set at %s:%zu; two files disagreeing about "
		    "one setting is the case `override` is for",
		    described, inside, first_source ? first_source : "<unknown>", first_line);
		return;
	}
	ncfg_diag(ctx, block->span,
	    "`%s` is already defined: first defined at %s:%zu; write `override %s` to replace it",
	    described, first_source ? first_source : "<unknown>", first_line, described);
}

/*
 * Fold one `global` block's items into the one already seen.
 *
 * A sub-block or a key that both files set is a real disagreement and gets the
 * same error any other duplicate would: the point is to let independent
 * contributions coexist, not to make the last file quietly win.
 */
static void merge_into_global(ncfg_lower_ctx_t *ctx, ncfg_merged_block_t *target,
    const ncfg_ast_block_t *block, const char *source)
{
	size_t i;
	size_t seen;

	for (i = 0; i < block->items.count; i++) {
		const ncfg_ast_item_t *item = block->items.at[i];

		if (item->kind == NCFG_AST_ITEM_BLOCK) {
			const ncfg_ast_block_t *inner = &item->as.block;
			int                     clashed = 0;

			for (seen = 0; seen < target->item_count; seen++) {
				const ncfg_ast_item_t *earlier = target->items[seen].item;

				if (earlier->kind != NCFG_AST_ITEM_BLOCK ||
				    !ncfg_ast_block_same_key(&earlier->as.block, inner)) {
					continue;
				}
				/* The clash is reported against the file that wrote the
				 * second one, which is the one the reader is editing. */
				ctx->source = source;
				say_already(ctx, inner, target->items[seen].source,
				    earlier->as.block.span.line, "global");
				clashed = 1;
				break;
			}
			if (clashed) {
				continue;
			}
			(void)keep_item(ctx, target, item, source);
			continue;
		}
		if (item->kind == NCFG_AST_ITEM_ASSIGNMENT) {
			/* A scalar directly in `global` -- `confirm_default`, say.
			 * Later wins, which is what the language says for a key. */
			int replaced = 0;

			for (seen = 0; seen < target->item_count; seen++) {
				const ncfg_ast_item_t *earlier = target->items[seen].item;

				if (earlier->kind != NCFG_AST_ITEM_ASSIGNMENT ||
				    strcmp(earlier->as.assignment.key, item->as.assignment.key) != 0) {
					continue;
				}
				target->items[seen].item = item;
				target->items[seen].source = source;
				replaced = 1;
				break;
			}
			if (!replaced) {
				(void)keep_item(ctx, target, item, source);
			}
			continue;
		}
		/* A hook inside `global` is already refused where hooks are checked;
		 * carrying it through unchanged keeps that one error. */
		(void)keep_item(ctx, target, item, source);
	}
}

static void merge_block(ncfg_lower_ctx_t *ctx, ncfg_merged_t *merged,
    const ncfg_ast_block_t *block, const char *source)
{
	ncfg_merged_block_t *existing = NULL;
	ncfg_merged_block_t *slot;
	size_t               i;

	for (i = 0; i < merged->block_count; i++) {
		if (ncfg_ast_block_same_key(merged->blocks[i].block, block)) {
			existing = &merged->blocks[i];
			break;
		}
	}

	if (existing && block->overrides) {
		/*
		 * `override` replaces wholesale rather than merging keys. Merging
		 * would make the result depend on which keys the earlier block
		 * happened to set, which is exactly the unpredictability the keyword
		 * exists to remove.
		 */
		(void)take_block(ctx, existing, block, source);
		return;
	}
	if (existing && strcmp(block->head, "global") == 0) {
		/*
		 * **`global` is a singleton several independent things contribute
		 * to**, and a drop-in model has no other way to say so. `control`,
		 * `dns`, `hostname_policy`, `remote` and `confirm_default` all live in
		 * it and are written by different tools: `ncfg control set` writes
		 * one, the gui writes another. One file owning the block means the
		 * first writer locks out every other, and `override` is worse than the
		 * error it silences -- the config example says so in its own words,
		 * that an `override global` carrying only a `control` block "silently
		 * discards the `dns` block the file it replaced was carrying, and
		 * takes name resolution away from the machine in order to change who
		 * may open a socket".
		 *
		 * So distinct contributions combine and a genuine collision is still
		 * an error. That is the rule the language already states for scalars
		 * -- later wins for a single key -- extended to the one block that is
		 * not a collection. `interface eth0` twice is still two files
		 * disagreeing about one interface, which is what the error is for.
		 */
		merge_into_global(ctx, existing, block, source);
		return;
	}
	if (existing) {
		ctx->source = source;
		say_already(ctx, block, existing->source, existing->block->span.line, NULL);
		return;
	}
	if (block->overrides) {
		char described[NCFG_ERROR_MAX];

		/* Overriding something that was never defined is a typo with a
		 * confident tone, and silently accepting it hides the typo. */
		ncfg_ast_block_describe(block, described, sizeof(described));
		ctx->source = source;
		ncfg_diag(ctx, block->span,
		    "`override %s` has nothing to override: remove `override`, or check the name",
		    described);
		return;
	}

	if (merged->block_count == merged->block_capacity) {
		size_t               want = merged->block_capacity ? merged->block_capacity * 2u : 8u;
		ncfg_merged_block_t *grown = realloc(merged->blocks, want * sizeof(*grown));

		if (!grown) {
			ncfg_lower_oom(ctx);
			return;
		}
		merged->blocks = grown;
		merged->block_capacity = want;
	}
	slot = &merged->blocks[merged->block_count++];
	memset(slot, 0, sizeof(*slot));
	(void)take_block(ctx, slot, block, source);
}

static void merge_assignment(ncfg_lower_ctx_t *ctx, ncfg_merged_t *merged,
    const ncfg_ast_assignment_t *assignment, const char *source)
{
	ncfg_merged_assignment_t *slot;
	size_t                    i;

	/*
	 * Later wins, so replace in place rather than appending; keeping both
	 * would leave the winner ambiguous to every later pass.
	 */
	for (i = 0; i < merged->assignment_count; i++) {
		if (strcmp(merged->assignments[i].assignment->key, assignment->key) == 0) {
			merged->assignments[i].assignment = assignment;
			merged->assignments[i].source = source;
			return;
		}
	}
	if (merged->assignment_count == merged->assignment_capacity) {
		size_t                    want = merged->assignment_capacity
		    ? merged->assignment_capacity * 2u : 8u;
		ncfg_merged_assignment_t *grown = realloc(merged->assignments, want * sizeof(*grown));

		if (!grown) {
			ncfg_lower_oom(ctx);
			return;
		}
		merged->assignments = grown;
		merged->assignment_capacity = want;
	}
	slot = &merged->assignments[merged->assignment_count++];
	slot->assignment = assignment;
	slot->source = source;
}

int ncfg_merge(const ncfg_source_t *sources, size_t count, ncfg_merged_t **out,
    ncfg_lower_diags_t *diags, char *err, size_t err_size)
{
	ncfg_lower_ctx_t ctx;
	ncfg_merged_t   *merged;
	size_t           file;
	size_t           i;

	if (out) {
		*out = NULL;
	}
	if (!sources || !out) {
		ncfg_error_set(err, err_size, "nothing to merge");
		return 0;
	}
	memset(&ctx, 0, sizeof(ctx));
	ctx.diags = diags;

	merged = calloc(1, sizeof(*merged));
	if (!merged) {
		ncfg_error_set(err, err_size, "out of memory merging the configuration");
		return 0;
	}

	for (file = 0; file < count; file++) {
		const ncfg_ast_file_t *parsed = sources[file].file;

		if (!parsed) {
			continue;
		}
		ctx.source = sources[file].name;
		for (i = 0; i < parsed->items.count; i++) {
			const ncfg_ast_item_t *item = parsed->items.at[i];

			switch (item->kind) {
			case NCFG_AST_ITEM_BLOCK:
				merge_block(&ctx, merged, &item->as.block, sources[file].name);
				/* `merge_block` moves the cursor when it complains about the
				 * file that wrote the second definition. */
				ctx.source = sources[file].name;
				break;
			case NCFG_AST_ITEM_ASSIGNMENT:
				merge_assignment(&ctx, merged, &item->as.assignment, sources[file].name);
				break;
			case NCFG_AST_ITEM_HOOK:
				ncfg_diag(&ctx, item->as.hook.span,
				    "a hook block must be inside an interface block: hooks belong to the "
				    "interface whose lifecycle they follow");
				break;
			case NCFG_AST_ITEM_INCLUDE:
				ncfg_diag(&ctx, item->as.include.span,
				    "include was not resolved before compiling: the caller expands "
				    "includes; the compiler opens no files");
				break;
			default:
				break;
			}
		}
	}

	if (ctx.failed) {
		ncfg_merged_free(merged);
		ncfg_error_set(err, err_size, "out of memory merging the configuration");
		return 0;
	}
	if (ncfg_diags_any(&ctx)) {
		ncfg_merged_free(merged);
		ncfg_error_set(err, err_size, "%s",
		    diags->count ? diags->at[0].message : "the configuration was refused");
		return 0;
	}
	*out = merged;
	return 1;
}
