//! Drop-in precedence.
//!
//! `netcfgd.conf` first, then `conf.d/*.conf` in lexical filename order. Later
//! wins for scalar keys. A block that redefines an existing one is an error
//! unless it says `override`, because silent last-wins is where every config
//! system becomes unpredictable (project.md section 3).

use crate::ast::{Block, File, Item};
use crate::diag::{Diagnostic, Diagnostics};

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
pub fn merge(files: &[File]) -> Result<Merged, Diagnostics> {
	let mut diagnostics = Diagnostics::new();
	let mut merged = Merged::default();

	for file in files {
		for item in &file.items {
			match item {
				Item::Block(block) => merge_block(&mut merged, block, &mut diagnostics),
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

fn merge_block(merged: &mut Merged, block: &Block, diagnostics: &mut Diagnostics) {
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
		(Some(index), false) => {
			let first = merged.blocks[index].span;
			diagnostics.push(
				Diagnostic::new(
					block.span,
					format!("`{}` is already defined", block.describe()),
				)
				.with_help(format!(
					"first defined at line {}; write `override {}` to replace it",
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
