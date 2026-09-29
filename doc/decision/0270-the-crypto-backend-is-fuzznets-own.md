# 0270: the crypto backend is fuzznet's own, not netcfgd's choice

Status: accepted
Date: 2026-09-29
Milestone: M10; fuzznet integration

Answers the question 0269 left open: what performs the AEAD and the hash.

## What this decides

**Nothing, and that is the finding.** fuzznet already vendors Monocypher as a
submodule of its own and pins it. netcfgd fetches fuzznet `--recursive` and
uses what fuzznet chose.

    fuzznet/monocypher   ab2b16d, which is tag 4.0.3

That is also the version fuzznet's golden-frame vector was produced against, so
matching it is not a coincidence to preserve by hand -- it falls out of taking
fuzznet's pin instead of making one.

## The wrong turn, which is why this is a record rather than a line

0269 said netcfgd "must choose a crypto backend, and fuzznet deliberately does
not choose for it". The first half was wrong.

What that reading produced: a second Monocypher submodule added at netcfgd's
own root, pinned by hand at 4.0.3 because fuzzypickles pins it there. It was
removed before it was committed, on reading `MONO_VENDORED := monocypher` in
fuzznet's Makefile and then its `.gitmodules`.

**The evidence that misled was real and the inference from it was not.**
`wire/seal.o` genuinely carries no undefined AEAD symbol, and there genuinely
was no Monocypher in the submodule -- because a plain `git submodule add` does
not recurse. An *uninitialised* nested submodule and an *absent* dependency are
indistinguishable from the consumer's side, and the second is the reading that
invents work.

The rule that would have caught it is this tree's own: ask the dependency what
it already decided before deciding for it. One `cat fuzznet/.gitmodules`.

## The failure this is written against

**Without `--recursive` the build succeeds and produces a library that cannot
verify a frame.** fuzznet's Makefile gates its Monocypher bindings on finding
`src/monocypher.c`, and when it cannot it SKIPS them with a notice rather than
failing -- which is correct for fuzznet, whose crypto is a vtable a consumer may
fill some other way. For netcfgd it means a green build of a bridge that can
refuse frames and never accept one.

That is raidcfgd's silent-backend failure (`build-and-commit.md`) arriving one
level of nesting down, and it is why the fetch guard tests for
`fuzznet/monocypher/src/monocypher.c` rather than for `fuzznet/Makefile` alone.

**Tested rather than assumed**: the nested submodule was deinitialised, `make
fuzznet` detected it, re-fetched recursively, and fuzznet's build reported
`monocypher: 4.0.3`.

## What it unblocked

The positive control 0269 said was impossible. `bridge/tests/peek_test`
builds a frame with the real AEAD and reads it back:

    the Monocypher bindings are wired          the control's own control
    a frame can be built at all
    the bridge's own read accepts it
    kind / msg / chunk / expires_at            each separately
    a zeroed frame is still refused            the pair discriminates
    the program accepts a real frame on stdin, exits 0
    and prints the fields it read, not a default

**The first version of that test proved fuzznet and not netcfgd.** Every check
called `fzn_seal_peek` directly, so all of them would have passed against a
`netcfgd-remote` that read the wrong descriptor or printed the wrong field. The
last three run the actual binary with the frame on its actual stdin; sabotaging
the program's `printf` fails exactly one of them.

**It is deliberately not a copy of fuzznet's golden vector.** That array has
provenance -- produced by another tree's build, reproduced byte for byte before
being committed -- and it answers "do two independently written builds agree".
Copying it here would put a second copy of somebody else's fixture in this tree
and answer a question netcfgd is not asking.

## One thing the crypto broke on the way in

The bridge links every fuzznet object that does not define `main`, and the
first version of that filter matched on filenames -- `/test/|_test\.o|main\.o`.
Turning Monocypher on built `node/fuzznetd.c`, which carries a `main`, matches
none of those, and the link failed with *multiple definition of `main`*.

It asks `nm` now. A filter over names is a claim about somebody else's file
naming; the objects know which of them has an entry point.

## What it costs

    bridge/netcfgd-remote   969,512 -> 1,236,488 bytes with the crypto linked
