/*
 * ast.c -- what a tree owns, and the two questions it answers about itself.
 *
 * There is no constructor here. The parser is the only thing that builds one
 * of these, and it builds nodes from tokens it already owns -- so a set of
 * constructors would be an API whose only caller hands it strings it has just
 * stolen from somewhere else. What the tree owes the rest of the program is
 * a way to be released and a way to describe itself, and that is what is
 * below.
 */
#include "ncfg/ast.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void values_free(ncfg_ast_values_t *values);
static void items_free(ncfg_ast_items_t *items);

void ncfg_ast_value_free(ncfg_ast_value_t *value)
{
	if (!value) {
		return;
	}
	free(value->string);
	/* Recursive, and bounded by the parser's nesting limit rather than by
	 * anything here. See `ncfg_ast_file_free`. */
	values_free(&value->entries);
	free(value);
}

static void values_free(ncfg_ast_values_t *values)
{
	size_t i;

	if (!values) {
		return;
	}
	for (i = 0u; i < values->count; i++) {
		ncfg_ast_value_free(values->at[i]);
	}
	free(values->at);
	values->at = NULL;
	values->count = 0u;
	values->capacity = 0u;
}

void ncfg_ast_item_free(ncfg_ast_item_t *item)
{
	if (!item) {
		return;
	}
	/* Every arm, by name. A `default:` here would quietly leak the day a
	 * kind is added, which is the one thing the compiler can still catch
	 * for us now that it no longer checks a `match` for us. */
	switch (item->kind) {
	case NCFG_AST_ITEM_BLOCK:
		free(item->as.block.head);
		free(item->as.block.label);
		items_free(&item->as.block.items);
		break;
	case NCFG_AST_ITEM_ASSIGNMENT:
		free(item->as.assignment.key);
		ncfg_ast_value_free(item->as.assignment.value);
		break;
	case NCFG_AST_ITEM_HOOK:
		free(item->as.hook.phase);
		free(item->as.hook.body);
		break;
	case NCFG_AST_ITEM_INCLUDE:
		free(item->as.include.path);
		break;
	}
	free(item);
}

static void items_free(ncfg_ast_items_t *items)
{
	size_t i;

	if (!items) {
		return;
	}
	for (i = 0u; i < items->count; i++) {
		ncfg_ast_item_free(items->at[i]);
	}
	free(items->at);
	items->at = NULL;
	items->count = 0u;
	items->capacity = 0u;
}

void ncfg_ast_file_free(ncfg_ast_file_t *file)
{
	if (!file) {
		return;
	}
	items_free(&file->items);
	free(file);
}

const char *ncfg_ast_value_describe(const ncfg_ast_value_t *value)
{
	if (!value) {
		return "nothing";
	}
	switch (value->kind) {
	case NCFG_AST_STRING:
		return "a string";
	case NCFG_AST_NUMBER:
		return "a number";
	case NCFG_AST_BOOL:
		return "a boolean";
	case NCFG_AST_LIST:
		return "a list";
	}
	return "a value this module does not name";
}

void ncfg_ast_block_describe(const ncfg_ast_block_t *block, char *out, size_t out_size)
{
	if (!out || !out_size) {
		return;
	}
	if (!block || !block->head) {
		(void)snprintf(out, out_size, "a block with no name");
		return;
	}
	if (block->label) {
		(void)snprintf(out, out_size, "%s %s", block->head, block->label);
		return;
	}
	(void)snprintf(out, out_size, "%s", block->head);
}

int ncfg_ast_block_same_key(const ncfg_ast_block_t *first, const ncfg_ast_block_t *second)
{
	if (!first || !second || !first->head || !second->head) {
		return 0;
	}
	if (strcmp(first->head, second->head) != 0) {
		return 0;
	}
	if (!first->label || !second->label) {
		/* `global` and `global` are the same block; `global` and
		 * `global x` are not. */
		return first->label == second->label;
	}
	/* Compared over the full length rather than to the first NUL: a label
	 * comes from a quoted string, an SSID is a quoted string, and an SSID
	 * may hold any bytes at all. Two labels that differ only past a NUL
	 * are two networks. */
	if (first->label_length != second->label_length) {
		return 0;
	}
	return memcmp(first->label, second->label, first->label_length) == 0;
}
