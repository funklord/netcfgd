A configuration both programs must refuse, in the same place.

`tool/agree_gate.py` compiles every configuration in its corpus with the Rust
`ncfg` and the C one and compares the documents. A corpus of files that all
compile would never exercise the other half of that comparison: two compilers
that agree about valid input and disagree about where an error is are two
compilers a person cannot use interchangeably, and an operator reading a
`file:line:column` is reading the half that has to match.

`refused/netcfgd.conf` states an `mtu` on an `interface`, which the language
moved to `device`. It is deliberately the *smallest* mistake the gate could
use -- one key in the wrong block -- because what is compared is the position
and not the sentence: the C joins a diagnostic's help onto one line and the
Rust prints it as a `help:` continuation, which is a rendering difference
recorded in 0263 rather than a disagreement about the configuration.
