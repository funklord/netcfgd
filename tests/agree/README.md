Configurations the two `ncfg` programs must treat identically.

`tool/agree_gate.py` asks both of them two questions about every directory in
its corpus: what the configuration compiles to, and -- for the ones that
compile -- what `ncfg profile save` writes back. The second is the longer path:
it compiles what is on disk, renders it back to configuration text, writes the
profile, folds the previous selection into `conf.d` and selects the new one,
and the two programs are handed identical directories and have to produce
identical ones. The renderer has no other differential.

The directories here are the mistakes. A corpus of files that all compile would
never exercise the other half of the comparison: two compilers that agree about
valid input and disagree about where an error is are two compilers a person
cannot use interchangeably, and an operator reading a `file:line:column` is
reading the half that has to match.

Each is one mistake, and the gate requires both programs to refuse it **at the
same file, line and column, saying the same thing**. The C
joins a diagnostic's help onto one line where the Rust prints it as a `help:`
continuation -- 0263 records that -- so the Rust's sentence is a *prefix* of the
C's, and that is the comparison. A message reworded in one program is therefore
a message that has to be reworded in the other, which is a decision to take
rather than a difference to find out about later.

  - `wrong-block` states `mtu` on an `interface`, which the language moved to
    `device`. The smallest mistake the corpus could use: one key in the wrong
    place.
  - `unknown-key` is a misspelling.
  - `bad-value` is `mac_policy = "random"`, which is the fault
    `tool/example_gate.py` records having found in the shipped example file.
  - `defined-twice` is one block written twice; both programs point at the
    second, which is the line somebody has to change.
  - `unclosed` is the parser's failure rather than the lowerer's.
  - `override-alone` has nothing to override, and both point at the name rather
    than at the keyword.
  - `include-missing` is **the one case where neither program names a
    position**: an include that names a file which is not there is refused by
    the loader, before anything is parsed. What the gate compares there is that
    both refused and that neither invented a line -- a program that read a
    missing include as an empty file would compile a configuration the other
    one refuses.
