# 0258: a hook is shell, and the window can write it

Status: accepted
Date: 2026-09-17
Milestone: M9; the window can configure the machine

## What could not be reached

A hook is a program netcfgd runs at a named moment in an interface's life, and
the hooks tab could list them: an interface, a phase, a path under `/run`, and
two columns that were always empty. What is *in* one was not shown anywhere,
and no client could write one -- the interface editor refused outright to save
any interface carrying a hook, because saving writes the block whole and a hook
it could not carry was a hook it would delete.

So the interface editor has a hooks list now, `ncfg_hook_dialog` edits one as
what it is -- a shell script, in a fixed-width box, with no form pretending a
program is a set of fields -- and the hooks tab's button opens the interface
that owns the block.

**The hooks live in the interface editor rather than in one of their own**, and
the reason is the drop-in model: a hook is inside an `interface` block, one
file owns that block whole, and a second file declaring the same interface is a
duplicate the loader refuses. An editor for hooks alone would have had to
compose everything the interface editor composes, and the two would drift.

## `hook_list`, and why it is `admin`

A document carries a hook as `{phase, path, sha256}` and never as shell --
section 2.2, and what keeps a desired-state document from being remote code
execution with extra steps. That leaves nothing for a client to show. So the
daemon reads the materialised script back and hands it over, which is a new
verb and the protocol's first *reading* verb at the `admin` tier.

`probe_list` is `observe` and this is not, and the difference is the content
rather than the location. A probe is a command the document states in the open,
in a file netcfgd keeps at 0755 so somebody debugging a link judged down can run
it by hand. A hook body is whatever an operator wrote, in a file the
materialiser opens 0700 *because* it runs as root and nobody else needs to read
it. Serving that to `observe` would publish the contents of the one file this
daemon takes care to keep to itself, and the client that wants it is an editor,
which is `admin` to save in any case.

A hook the daemon could not read is listed as itself with `readable: false`
rather than skipped: the document names it, so a client that never saw the row
would write the interface back without it.

Protocol 1.2 to **1.3**. Additive -- an older client is unaffected and a newer
one can tell.

## The defect underneath, which was bigger than the feature

The first attempt to save an interface with a hook was refused by the daemon
with *"that would stop the configuration compiling"*, naming a file the same
daemon loads on every reload. It compiles. What refused it was the sink.

`netcfgd_compile::NoHooks` refuses every hook, and its documentation is right
about why it exists: a caller producing a document to *act* on with nowhere to
put the scripts should refuse loudly rather than drop them. But **ten call
sites were using it to compile the configuration in order to read it** --
which profile is selected, does this drop-in still parse, what did forgetting
that network leave behind -- and every one of them gave a wrong answer on any
machine with a hook in its configuration. Two of them are not small:

* **`install_drop_in` refused every configuration write.** It verifies by
  compiling, so on a machine with one hook anywhere, every editor in the
  window and every `ncfg config put` was refused -- with a message blaming the
  file being written rather than the check doing the writing.
* **`load_with_profile` returned before adding the selected profile.** The
  compile it does to learn which profile is chosen failed, the function
  returned the sources it had, and the profile directory was never read. So
  `ncfg profile set` wrote a selection, reported success, and the profile did
  not load -- on this reload or any later one.

The others degrade rather than break: a forgotten network keeps every
credential, a profile written back is rejected and removed again, a fold
refuses to adopt.

`netcfgd_host::hooks::UnwrittenHooks` is the sink for a caller that compiles to
read: it accepts a hook, hashes exactly what `PendingHooks` would have written,
and names no file. The path it gives is `/nonexistent/netcfgd/...` -- absolute,
because `Document::validate` requires that and refused a parenthesised sentence
when one was tried, and under `/nonexistent` so that a document from it which
somehow reached the runner fails at the `exec` naming this path rather than
running whatever sits somewhere plausible. `NoHooks` stays for what its own
documentation describes.

The three remaining uses are in `probe.rs`'s tests, whose fixtures have no
hooks, and one in `profile save` that the renderer makes unreachable -- it
refuses a document with hooks before the comparison is reached. Changing
correct code in a passing test to match a fix elsewhere is how a fix becomes a
sweep.

## Two fields nobody can set, and a manual that said otherwise

`HookRef::run_as` and `HookRef::timeout` are in the model, and the hook runner
honours both -- it drops uid, primary gid and supplementary groups, and kills a
hook at its timeout. **The configuration language has no key for either**, so
they are `None` on every machine, every hook runs as root, and every hook gets
the default sixty seconds.

`netcfgd.conf.example` showed this, as a worked example:

    post_up {
        run_as=nobody
        timeout=30
        /usr/local/bin/announce-address
    }

A hook body is shell and nothing reads it but the shell. Those two lines set
two shell variables. The hook runs as root, for sixty seconds, exactly as it
would without them -- and the example reads as privilege being dropped where
none is. It is removed rather than corrected in place, because a wrong example
is worse than none; the paragraph now says a hook runs as root and says why
there is nothing to write instead. `DEFAULT_TIMEOUT_SECONDS` carried the same
claim in its own comment -- "a hook that genuinely needs longer says so with
`timeout` in its own block" -- and is corrected too.

So the count of model fields the configuration language cannot reach goes from
seven to **nine**, and these two are the only ones the documentation ever
promised. The editor offers neither, for the reason 0257 left `invert` out: a
form that wrote a key the parser does not have would write a block netcfgd
refuses. Giving the parser the keys is a decision about the language, and for
`run_as` it needs one more thing than grammar -- a materialiser that puts the
script somewhere the target user can read, which 0700 under root is not.

The same file also said braces inside a hook body "do not matter". They matter
a great deal: a body ends at the first line containing only a closing brace, so
a shell function written the usual way cuts the hook in half and the rest is
read as configuration. The README has said so for a while; the example now says
it too, and the editor refuses such a body beside the field rather than letting
the daemon report a syntax error about a line the operator wrote shell on.

## The round trip is why the body is not indented

The materialiser prepends `#!/bin/sh` to a body that does not start with one.
Indent the body when writing the block -- as every other block writer here
indents -- and the shebang stops being a shebang, so the next save gets another
one, and the script netcfgd runs grows by a line every time it is edited. The
body is therefore written verbatim, at column zero, and the headless probe
asserts the round trip rather than the indentation.

## Eight sabotages, all caught

The sink refusing again, in both of its consequences; the placeholder path made
relative; the body indented; an event phase written bare; the lone-brace rule
compared without trimming; the editor writing the block without the hooks it
loaded; an unreadable hook reported as readable; and the editor saving over a
hook whose body it does not have.

The seventh is the one that changed the tests: it passed unnoticed, because
nothing had ever taken a materialised script away. The live probe removes one
now and asserts all three consequences -- the flag, the empty text that is not
an empty hook, and the editor's refusal in its own words.
