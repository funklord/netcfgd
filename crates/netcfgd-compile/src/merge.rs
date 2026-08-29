//! Drop-in precedence.
//!
//! `netcfgd.conf` first, then `conf.d/*.conf` in lexical filename order. Later
//! wins for scalar keys. A block that redefines an existing one is an error
//! unless it says `override`, because silent last-wins is where every config
//! system becomes unpredictable (project.md section 3).

use crate::ast::{Block, File, Item};
use crate::diag::{Diagnostic, Diagnostics, SourceMap};

/// Everything the files collectively say, with precedence already applied.
#[derive(Debug, Clone, Default)]
pub struct Merged {
	/// Top-level blocks, in first-seen order.
	pub blocks: Vec<Block>,
	/// Top-level assignments, latest value winning.
	pub assignments: Vec<crate::ast::Assignment>,
}

/// Apply drop-in precedence across files given in precedence order.
///
/// # Errors
///
/// Returns a diagnostic for every block redefined without `override`, naming
/// both positions so the reader can see which two files disagree.
pub fn merge(files: &[File], sources: &SourceMap) -> Result<Merged, Diagnostics> {
	let mut diagnostics = Diagnostics::new();
	let mut merged = Merged::default();

	for file in files {
		for item in &file.items {
			match item {
				Item::Block(block) => merge_block(&mut merged, block, sources, &mut diagnostics),
				Item::Assignment(assignment) => {
					// Later wins, so replace in place rather than appending;
					// keeping both would leave the winner ambiguous to every
					// later pass.
					if let Some(existing) = merged
						.assignments
						.iter_mut()
						.find(|a| a.key == assignment.key)
					{
						*existing = assignment.clone();
					} else {
						merged.assignments.push(assignment.clone());
					}
				}
				Item::Hook(hook) => diagnostics.push(
					Diagnostic::new(hook.span, "a hook block must be inside an interface block")
						.with_help("hooks belong to the interface whose lifecycle they follow"),
				),
				Item::Include(include) => diagnostics.push(
					Diagnostic::new(include.span, "include was not resolved before compiling")
						.with_help("the caller expands includes; the compiler opens no files"),
				),
			}
		}
	}

	if diagnostics.is_empty() {
		Ok(merged)
	} else {
		Err(diagnostics)
	}
}

fn merge_block(
	merged: &mut Merged,
	block: &Block,
	sources: &SourceMap,
	diagnostics: &mut Diagnostics,
) {
	let key = block.key();
	let existing = merged.blocks.iter().position(|b| b.key() == key);

	match (existing, block.overrides) {
		(Some(index), true) => {
			// `override` replaces wholesale rather than merging keys. Merging
			// would make the result depend on which keys the earlier block
			// happened to set, which is exactly the unpredictability the
			// keyword exists to remove.
			merged.blocks[index] = block.clone();
		}
		// **`global` is a singleton several independent things contribute to**,
		// and a drop-in model has no other way to say so. `control`, `dns`,
		// `hostname_policy`, `remote` and `confirm_default` all live in it and
		// are written by different tools: `ncfg control set` writes one, the
		// gui writes another. One file owning the block means the first writer
		// locks out every other, and `override` is worse than the error it
		// silences -- the config example says so in its own words, that an
		// `override global` carrying only a `control` block "silently discards
		// the `dns` block the file it replaced was carrying, and takes name
		// resolution away from the machine in order to change who may open a
		// socket".
		//
		// So distinct contributions combine and a genuine collision is still
		// an error. That is the rule the language already states for scalars --
		// later wins for a single key -- extended to the one block that is not
		// a collection. `interface eth0` twice is still two files disagreeing
		// about one interface, which is what the error is for.
		(Some(index), false) if block.head == "global" => {
			merge_into_global(merged, index, block, sources, diagnostics);
		}
		(Some(index), false) => {
			let first = merged.blocks[index].span;
			diagnostics.push(
				Diagnostic::new(
					block.span,
					format!("`{}` is already defined", block.describe()),
				)
				// Naming the file, not just the line. The two definitions
				// are usually in different files -- that is what drop-ins are
				// for -- and with a factory layer under a writable one they
				// are in different directories, where "line 1" on its own
				// sends the reader to the wrong file.
				.with_help(format!(
					"first defined at {}:{}; write `override {}` to replace it",
					sources.name(first.source),
					first.line,
					block.describe()
				)),
			);
		}
		(None, true) => {
			// Overriding something that was never defined is a typo with a
			// confident tone, and silently accepting it hides the typo.
			diagnostics.push(
				Diagnostic::new(
					block.span,
					format!("`override {}` has nothing to override", block.describe()),
				)
				.with_help("remove `override`, or check the name"),
			);
		}
		(None, false) => merged.blocks.push(block.clone()),
	}
}

/// Fold one `global` block's items into the one already seen.
///
/// A sub-block or a key that both files set is a real disagreement and gets the
/// same error any other duplicate would: the point is to let independent
/// contributions coexist, not to make the last file quietly win.
fn merge_into_global(
	merged: &mut Merged,
	index: usize,
	block: &Block,
	sources: &SourceMap,
	diagnostics: &mut Diagnostics,
) {
	for item in &block.items {
		match item {
			Item::Block(inner) => {
				let clash = merged.blocks[index]
					.items
					.iter()
					.find_map(|existing| match existing {
						Item::Block(seen) if seen.key() == inner.key() => Some(seen.span),
						_ => None,
					});
				if let Some(first) = clash {
					diagnostics.push(
						Diagnostic::new(
							inner.span,
							format!("`{}` is already set in `global`", inner.describe()),
						)
						.with_help(format!(
							"first set at {}:{}; two files disagreeing about one \
							 setting is the case `override` is for",
							sources.name(first.source),
							first.line
						)),
					);
					continue;
				}
				merged.blocks[index].items.push(item.clone());
			}
			Item::Assignment(assignment) => {
				// A scalar directly in `global` -- `confirm_default`, say.
				// Later wins, which is what the language says for a key.
				if let Some(existing) =
					merged.blocks[index]
						.items
						.iter_mut()
						.find_map(|seen| match seen {
							Item::Assignment(a) if a.key == assignment.key => Some(a),
							_ => None,
						}) {
					*existing = assignment.clone();
				} else {
					merged.blocks[index].items.push(item.clone());
				}
			}
			// A hook inside `global` is already refused where hooks are
			// checked; carrying it through unchanged keeps that one error.
			other => merged.blocks[index].items.push(other.clone()),
		}
	}
}
