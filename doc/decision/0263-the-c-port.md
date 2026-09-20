# 0263: the C port

Status: accepted
Date: 2026-09-18
Milestone: M9; the window can configure the machine

## What this is

netcfgd is being converted to C, on the branch `c-port`, module by module,
while the Rust it replaces goes on being the thing that runs. This record is
the contract the modules are written against, because a port done in parallel
with no contract is a pile of C that does not link.

**The size, so that nobody is surprised by it.** 112,282 lines of Rust across
`crates/`, `backend/` and `adapter/` -- a large part of which is doc comments
and tests, both of which come across too. The existing C is 10,293 lines: the
client library and the shell helpers. This is a campaign, not a round, and
every module lands with its tests or it has not landed.

**What is given up, stated once rather than rediscovered.** The Rust confines
`unsafe` to `netcfgd-sys` and the build gate `make unsafe-policy` proves it; in
C every module is that crate. Ownership stops being checked and becomes a rule
this record writes down. The compiler stops noticing an unhandled case in a
`match`. Those are the things the tests and the gates now have to carry, and
the discipline below is what carries them.

## The layout

    c/
      Makefile              one library, one test per module
      include/ncfg/*.h      the public face of each module
      src/<module>/*.c      base, json, model, compile, plan, apply, sys,
                            host, proto, daemon, cli
      tests/*_test.c        one binary per module, all of them run

Sources are a wildcard and the reason is in the Makefile: this tree grows a
module at a time, often in more than one working tree at once, and a listed
source is a merge conflict per module for nothing. `clean` removes what the
build produced and nothing by a pattern this directory does not own.

`client/ncfg_json.c` is compiled in rather than copied. Two readers of one
format is how the GUI and the CLI came to spell an access point's name three
ways, and the port is not starting a second copy of anything it can share.

## The three conventions

They are `client/ncfg_client.h`'s, unchanged, because that library has faced a
live daemon since M4 and a port that answered the same questions differently
would make two halves of one program argue about what a failure is.

* A call that can fail returns **1 for success, 0 for failure**, and takes
  `char *err, size_t err_size` last. Not `errno`, not a negative code: these
  failures are sentences an operator reads, and an integer cannot carry one.
* A call returning a pointer returns `NULL` for failure, same buffer.
* Every aggregate has an `ncfg_x_free` beside it, and freeing something never
  filled in is nothing.

Two more, which the base module makes cheap:

* **Text is built in `ncfg_buf_t`, which has a ceiling and a sticky failure.**
  A daemon rendering what a client sent it has to bound the result, and a
  buffer that reports failure once at the end is a buffer whose errors are
  actually checked. A failed buffer hands out the empty string rather than the
  part that fitted: half a configuration block that looks whole is the failure
  mode this refuses.
* **A library never exits, never asserts and never prints.** The one place in
  this project that ends a process on its own is `netcfgd_sys::out`, and it
  does it for a closed pipe (0261).

## The order, and why

Dependencies first, and each module is worth having on its own before the next
one starts:

1. **base** -- errors and the buffer. Done.
2. **json** -- the reader exists; the writer is what the model needs.
3. **model** -- the value types first (addresses, hardware addresses, the
   closed sets and their spellings), then the document.
4. **compile** -- lexer, parser, merge, lower, render.
5. **sys** -- the wire layer first, which is pure bytes and testable without a
   kernel; then the sockets and the ioctls.
6. **proto**, **host**, **plan**, **apply**, **daemon**, **cli**.

The first wave is the writer, the value types, the lexer and the wire layer:
four modules that depend on nothing but `base` and on each other not at all,
which is what makes them safe to write at the same time.

## What a module owes

Its header, its sources, and **its tests in the same wave** -- not afterwards.
The Rust being ported carries its tests beside it, most of them naming a defect
that shipped; those cases come across with the code, because the case is the
part that is expensive to rediscover. A module whose tests are "to follow" is a
module that has not been ported, and the wire layer in particular ships with
the adversarial cases or not at all.

The spellings are read from the Rust, never from memory. This project has twice
shipped a configuration key spelled the model's way rather than the language's
-- `wire_guard` for `wireguard`, `open_vpn` for `openvpn` -- and each compiled
into a block with the feature silently missing.

## Where the C differs from the Rust, on purpose

A port whose divergences live in module headers is a port nobody can answer
"is this the same program?" about. They are listed here instead, as they are
taken.

* **The parser keeps 64 diagnostics and counts the rest.** The Rust keeps
  every one, which is right in a test harness and wrong in a daemon: a
  diagnostic per token is a file-sized allocation bought with a malformed
  file, and nobody reads the sixty-fifth. `total` carries how many there were,
  so the fact is not lost -- and a client that shows "64 of 100" is showing
  more than one that shows a hundred nobody scrolls through. Tested at the
  boundary.
* **Spans carry no source id.** The Rust's `Span` names which file; the C
  lexer is handed one file's bytes and the caller knows which, so the name
  arrives when a diagnostic is rendered. One position type, used by both
  modules, rather than two spellings of it -- which is how a caret ends up
  under the wrong column.
* **A diagnostic's help line is joined to its message with a colon.** Rust
  carries them apart and renders them on two lines; the C has one sentence and
  one buffer, which `NCFG_ERROR_MAX` is sized for.
* **The walks in the wire layer return three outcomes, not two.** `OK`, `END`
  and `BAD`: one boolean cannot tell "nothing more" from "malformed", and
  folding them is the confusion that module exists to refuse.
* **The JSON writer refuses a string that is not valid UTF-8.** Rust's `&str`
  makes the question impossible; in C it is real, and every repair -- raw
  bytes, `\u00XX` per byte, U+FFFD -- puts a value in front of somebody that
  nobody typed.
* **A netlink datagram that did not come from the kernel is dropped and
  counted.** The Rust checks no sender at all. Dropping rather than failing is
  the deliberate half: failing would hand the same local process a way to end
  any dump with one packet.
* **A nest carries `NLA_F_NESTED`.** The Rust sets it on one nest of many.
  `VETH_INFO_PEER` is the exception and is written unflagged, because its value
  is an `ifinfomsg` with a list after it rather than an attribute list.
* **Narrowing is checked rather than cast**, everywhere the model's `int64_t`
  meets a kernel field, with the field named in the refusal.
* **The renderer writes five fields the Rust silently drops** (10.160) and
  refuses `dhcp`'s modifiers by name, since the language takes none.
* **A WireGuard peer set too large for one attribute is split**, which is what
  `linux/wireguard.h` says to do and what `wg(8)` does; the Rust truncates the
  length instead (10.157). One peer too large for one attribute is refused.
* **Lowering diagnostics carry the file name.** A span still carries no source
  id, because a parse is one file -- but merge sees several at once, and
  "already defined; first defined at conf.d/10-office.conf:3" is the whole
  point of the redefinition check.
* **`NCFG_DIAGS_MAX` bounds lowering too**, with `total` counting past it.
* **The provenance side table is produced, and the type stays in `state.h`.**
  This entry said for four waves that `compile_with_provenance` was not ported
  and that nothing in `src/compile/` recorded an entry. That has stopped being
  true: `ncfg_compile_with_provenance` and `ncfg_lower_with_provenance` are the
  Rust's two calls, `ncfg_compile` is the same pipeline with nowhere to put the
  table, and the lowering records the eleven kinds of entry the Rust records --
  the interface block, its `mtu`, `addressing[<index>]`, `routes[<destination>]`,
  `preference`, `guard` and `dns`, and `rule.<id>`, `access_point.<id>`,
  `network.<id>` and `linkset.<name>`.

  **The type is still declared in `state.h` and not in the compiler**, where
  the Rust keeps it. `state.h` already argued for that as the shape of a file
  this port reads whoever wrote it, and the argument is stronger now that
  something here writes one: two definitions of one file format is how a reader
  and a writer come to disagree about a member name, and the compiler including
  `state.h` costs one include against a second `Entry`.

  `ncfg explain` **is** the command that exists to answer where a value came
  from, so this is the whole of its subject rather than a detail of it. It
  takes the table as an argument exactly as the Rust does. **An explanation
  whose every lookup missed against an empty table says so, in its own output,
  as its first fact**, and names no file and no line anywhere. The alternative
  is an answer that silently stops naming files, which a reader cannot tell
  from a configuration that has nothing to name -- and an `explain` that
  invented a position would be worse than one that says it does not know. It is
  the *first* fact for the reason the radio fact comes before the addresses: a
  caveat about what an answer cannot contain is worth nothing printed after the
  answer. Where the table has entries and this field is not among them, nothing
  is said: that is a gap in a table rather than the absence of one, and a
  blanket claim about it would be wrong. Both directions are tested, and the
  fourth case is the one the producer made possible: the other three build a
  table by hand and so say nothing about whether anything produces one keyed
  the way `explain` asks, which is the seam where a full table and a silent
  notice could still name no file at all.
* **The linkset cycle walk is bounded**, and the bound is published so a test
  cannot spell the number itself. The Rust's recursion terminates on its own,
  which bounds its depth by the number of sets -- a bound on paper rather than
  on the stack, on input an unprivileged edit can produce.
* **Five `observed` structs are strict about unknown members** where the Rust
  marks every other one and not those; that reads as an omission rather than a
  decision, and the strict direction is the one section 2 argues for.
* **The confirm window's two files are in the daemon module**, where the Rust
  splits them into `netcfgd-host::confirm` and keeps the state machine in
  `netcfgd-daemon::confirm`. Nothing outside the daemon calls either half, and
  the format belongs beside the only code that reads it.
* **A window's clock is always an argument, and no form reads it.** The Rust
  has both, and its own tests say what that cost: a machine that slept through
  a window and a clock somebody moved were unwritable until the split was
  made, so neither had ever been checked. One form, and the shape that cannot
  be tested cannot be spelled.
* **Arming refuses where the window could not be written.** The Rust logs it
  and hands back the `confirm_armed` event anyway, so a full or read-only
  `/run` told every client the change was covered while nothing on disk would
  ever resolve it. Returning the failure is what its own comment says would be
  better; here both callers have already applied, so they are told and decide.
* **What a window covers is a plan of its own**, copied action by action rather
  than borrowed. A C plan borrows four deep trees from the document it was
  built from, and a reload *inside* a window replaces that document -- so the
  record has to own what it holds or the revert reads freed memory. None of the
  ops that declare an inverse carries one of those four, which is what makes
  the copy complete; the test frees the document and the plan before reverting,
  and ASan is the assertion.
* **Confirming records the document it is given**, not the daemon's current
  desired state. The Rust reads `desired` there, which the same file already
  knows may hold an edit that arrived inside the window and was never applied
  -- it says so where a revert takes its blacklist hash from the armed record
  for exactly that reason. So confirming can write a last-good the machine has
  never been in, and the next window's revert goes somewhere nobody chose.
* **A revert is handed an executor** rather than opening a netlink socket for
  itself, which is what lets the whole path be driven by a double. It does not
  write `plan.last.json` or fold the effects into `owned.json`: both are
  deferred with the types they need, and both are named here rather than
  quietly missing. **Both have since landed, and neither landed here.**
  `ncfg_apply_revert` is still a library call taking a plan, a journal and an
  executor, with no run directory -- what changed is that its *caller* does
  both, `confirm.c`'s `record_what_ran` folding the journal into `owned.json`
  and then writing it to `plan.last.json`. That is the right place for the same
  reason the executor is an argument: the revert path is driven by a double in
  the tests, and a library call that wrote into `/run` could not be.
* **The resolv sweep is driven through a seam, and the seam has no default.**
  The Rust's sweep ends in `SIGTERM` to a pid it found in `/proc`, which is why
  it has no unit tests at all and a live script instead -- on the machine these
  tests are built on, the process it would signal is the developer's. Here the
  four exclusions, the order they are asked in and the count are checked
  against a machine a test makes up, and whoever sweeps for real asks for the
  real one by name.
* **A set of netcfgd's own pids that does not fit stops the sweep.** This is
  `NCFG_PEER_GROUPS_MAX` pointed the other way and right for the same reason: a
  membership that did not fit denies, while a pid of netcfgd's own that did not
  fit would make its own DHCP client look foreign.
* **A probe's standard error is drained while the program runs.** The Rust
  reads the pipe only once `try_wait` has reported the child gone, so a probe
  that says more than a pipe buffer holds -- 64 KiB on Linux -- blocks in
  `write`, never exits, and is killed at its deadline. A link that works is
  then reported as "no answer within 5s, so it was killed" and loses its
  routes, which is 0119 firing on the daemon's own reading rather than on the
  network. Here the pipe is drained in the same loop that watches the clock,
  bounded per round, and only a window of the tail is kept -- the client is
  shown 400 bytes of it, so holding more would be an allocation bought with
  somebody else's `echo`. `probe_test.c` writes 150 KiB and then exits zero.
* **A probe's scheduling clock is a seam.** `interval` is in seconds and the
  compiler refuses zero, so the Rust's two dwell tests sleep 1050ms six times
  each and assert `>= 4` and `<= 1` -- twelve seconds of a suite, with a flake
  its own comments record. `ncfg_probes_clock` lets a test move the clock
  itself, and the C asserts exactly six changes and exactly one. It is the
  *scheduling* clock only: the deadline a running child is killed by is read
  from `CLOCK_MONOTONIC` directly, because a frozen clock against a live
  process is a wait that never ends.
* **A probe's deadline signals the whole process group, and signals it twice.**
  The Rust kills the child. A probe is a script and the `curl` it started is a
  grandchild, so killing the shell leaves the grandchild running and reparented
  to init -- work the daemon has stopped waiting for and can no longer stop.
  `SIGTERM` to the group, then `SIGKILL` to the group **even where the leader
  has already gone**, because a shell that exited on the first says nothing
  about what it forked. The two are deliberately redundant: each sabotaged
  alone leaves the other doing the job, and only removing both leaves a
  grandchild behind.
* **`ncfg_sims_advance` tells "nowhere to go" from "no such device".** The Rust
  answers `None` to both, and to two more -- a device with no `modem` block and
  one the document does not name at all. Stopping at the last source is the
  normal case a caller acts on (0152); a device name that does not resolve is a
  mistake, and folding them means a typo reads as a modem that has run out of
  SIMs. Here the call answers 1 with the source it moved to, 1 with none where
  it is already on the last, and 0 with a sentence naming the device otherwise.
* **A SIM selection is published through `ncfg_write_atomically`.** The Rust
  stages at `<name>.tmp`, which is the fixed shared path `state.h` records a
  defect for: two writers interleave, one's content is renamed into place by
  the other's rename, and the loser's rename fails with `ENOENT` into a
  discarded result. The port has one atomic write and this uses it.
* **A device that leaves the document takes its cards with it.** The Rust's
  `sync` drops the chosen index and the cycle note for a device that is gone
  and leaves the `cards` table alone, so a device edited out and put back comes
  back carrying an ICCID read before it left. A card can be swapped while a
  device is out of the configuration, which makes that a confident wrong answer
  to the one question the table exists to settle -- and the table's own
  documentation already says it is derived and disposable.
* **The probe verdicts and the SIM selection are not fields of the daemon
  state.** They are in the Rust's `State`; here a caller holds each beside a
  `ncfg_daemon_state_t` rather than inside one. A tally counts across ticks and
  a reload replaces the document, and a field freed with the state is an
  invitation to lose the counting on a reload that has nothing to do with it.
* **A `ncfg config rm` that removed nothing leaves the profile alone.** 0151
  makes a settings write by a person put the machine on "none chosen", with the
  profile folded into `conf.d` so that what is running does not move, and the
  Rust undoes that fold only where the write *fails*. Removing a drop-in that
  is not there neither fails nor writes -- absent is the state asked for -- so
  the fold stood: `ncfg config rm never-existed` printed "is not in", exited 0,
  and took the machine off its profile. Reproduced against the shipped binary.
  Here the removal reports whether anything was there and the fold is put back
  when nothing was. The fold is also announced *after* the write stands rather
  than before it is attempted, which is what lets a refused write say nothing
  about a state the machine passed through and left.
* **The scanner that finds a block lexes strings and comments.** The Rust's
  `block_span` is `str::find` plus a check of the character before the match,
  so `# the control { block` inside `global` is found as the block;
  `matching_brace` then counts from a brace that is inside a comment and the
  span runs to the end of `global`. Measured: the splice deleted the
  `dns { mode = "none" }` beside it and the block's closing brace, and
  `ncfg control set --observe group:netcfgd` came back with three diagnostics
  about keys it had written itself, blaming the operator's file. The invariant
  puts the file back, so nothing is lost -- what is lost is the command, on the
  one machine whose documented way out of the root-only default is that
  command.
* **`ncfg control set` looks for the `global` block in the writable layer
  only.** The Rust searches the *layered* source set, which is factory first --
  so on an image that ships a `global` block the command splices into
  `/usr/share/netcfgd`. Reproduced: it edited the factory file, reported
  success and printed that path. That is the image rather than the machine's
  configuration: the edit is lost at the next upgrade, or refused outright on a
  read-only root, for a policy `ncfg control show` goes on reporting correctly
  in the meantime. Here only `/etc` is searched, and a `global` that exists
  solely in the factory layer is a refusal naming the file -- because a drop-in
  genuinely cannot add one key to it, redefinition being an error and
  `override global` replacing the block whole.
* **`ncfg profile set` writes its selection through `ncfg_profile_set`.** That
  is `config.h`'s one spelling of `global { profile = "..." }`, and it
  validates the name as both halves of what a profile name is: a directory
  *and* a value in the configuration language. The Rust composes the line in
  the CLI and checks only `/`, a leading dot and emptiness, so a name carrying
  a quote reaches a quoted string. It costs the `wrote <path>` line the Rust
  prints on the local route, since the selection is no longer written through
  the drop-in writer that knew the path; what is left says the route taken and
  the profile now in force.
* **A local `ncfg secret set` that fails carries both halves of the sentence.**
  The Rust appends "and there was no daemon to ask" only where the kernel
  refused the process. `ncfg_secret_store_put` is the one door into the store
  and does not report `denied`, and inferring it from the words of a message is
  what `config.h` forbids by name -- so the second half is always appended.
  Every refusal reachable at that point *is* the filesystem refusing: the name,
  the value and an existing file have each been checked already.
* **Text a client sends and a credential it types are bounded** --
  `NCFG_CONFIG_FILE_MAX` for `ncfg config put`, and 64 KiB for
  `ncfg secret set`. Both read to end of file in the Rust, which is a process
  reading somebody's redirect: `ncfg secret set x < /dev/zero` allocates until
  the machine stops. The refusal names the ceiling rather than truncating,
  because a credential or a drop-in that is quietly half of itself fails later
  and somewhere else.

* **`ncfg tui` draws its own escape sequences, and does not link ncurses.**
  This is the largest divergence in the port and the one that gives most up, so
  it is written out. In the Rust ncurses is a *default-on cargo feature*:
  `--no-default-features` produces a byte-identical document and leaves the
  binary linking libc alone (0025, `make linkage`). C has no such gate here --
  `c/Makefile` builds every source into one `libncfg.a` -- so a link would make
  ncurses mandatory for the daemon, the client library and every test, and "no
  mandatory dependencies" is one of the things this project exists to prove.
  **What the subset does not do**, each named because `netcfgd-sys::curses`
  argues for it and each argument is sound: key decoding comes from a table of
  two sequences rather than from the terminal's own terminfo, so an arrow works
  and a sequence this does not know is consumed and ignored rather than mapped
  to the wrong action; there is no dirty-region diffing, so a frame that
  changed anything is rewritten whole -- 24 rows of 80 is under 2 KB, and the
  frame is composed only when something moved; and widths are counted in
  characters rather than columns, so a CJK access-point name misaligns the rows
  below it exactly as the pre-ncurses version did. That last one is the real
  loss and it is bounded to one pane's alignment.
* **The frame is scrolled by the height of the window, not the length of the
  list.** The Rust takes `lines.len().min(64)` -- the content -- so on an 80x24
  terminal any pane with between 22 and 64 rows never scrolls at all: the
  highlight walks past the last drawn row, `Pane::draw` marks nothing because
  the row it was handed is outside the window, and `c` goes on acting on a line
  nobody can see. Tested with the row addressed by number rather than by its
  text, since a pane draws `access_point: running` under more than one
  interface and a search for the words passes against the wrong row.
* **Every row is fitted to the window.** The Rust fits most and leaves a
  handful unfitted on the reasoning that they are short. A radio row's longest
  state is 34 characters, which on a 40-column terminal is not short: it wraps,
  and a wrap pushes everything below it down a row, which on a full-screen
  client scrolls the footer away. One rule is also one thing to test.
* **A pane is bounded at `NCFG_TUI_ROWS_MAX`, with `total` counting past it**,
  which is the parser's arrangement applied to a renderer whose input is a
  socket. The Rust grows a `Vec` per frame from whatever the daemon sent.
* **A keystroke moves the state and names an intent; it does not talk.** The
  Rust's `App::key` calls `refresh`, `apply` and `connect` itself, so the
  keymap cannot be exercised without a daemon. Here `ncfg_tui_key` returns what
  to do and `tui_term.c` is the only file that opens a descriptor -- which is
  what makes "what does `c` do to this row" an assertion rather than a pty.
* **The event stream is a second descriptor in the same `poll`, not a thread.**
  The Rust says the alternative to its detached thread is "`poll` on two
  descriptors and this client has no other reason to reach for one"; this one
  does, because without ncurses the keyboard already needs a timeout of its
  own. It costs no mutex and no threading library either.
* **The scan, the radios and the station list are read through `proto.h`;
  `status` and `plan` are read as JSON.** The Rust reads all five as
  `serde_json::Value` and says why -- the derived deserialiser for the full
  document is hundreds of kilobytes against a 1.75 MB install. That reason is
  Rust's and does not carry. The two exceptions are not a preference: they
  arrive as `ncfg_proto_payload_t`, which this wave has no typed reader for.
* **The clients pane says "no wireless device on this machine".** The Rust says
  "in the configuration" there, while the two arms above it argue at length
  that saying exactly that is wrong -- it reads as wording left behind rather
  than a decision. `run.c` already diverges the same way and for the same
  reason: the radio came from the kernel's link table, so sending somebody to
  edit a file is the wrong instruction.
* **The wifi handlers answer with a buffer or a sentence, not a `Response`.**
  The Rust's enum carries an `Error` arm, so a refusal and an answer come back
  the same way; here `daemon.h` already says what a handler does -- 1 with one
  JSON object in `out`, or 0 with a sentence the server sends back as `error`
  -- so every `Response::error` in `wifi.rs` is a 0 and the sentence is
  unchanged. One shape for both would have meant a translation step between the
  handler and the seam that calls it.
* **Two things `wifi.rs` does are seams here, because what they call is not
  ported yet.** The synchronous apply behind `wifi activate` needs the plan
  restriction and the reconcile loop's executor; writing a `network` block
  needs `netcfgd_host::wifi_profile`, which is 810 lines and shared with `ncfg
  wifi add`. A second copy of either is the drift this port exists to avoid, so
  each is a function pointer the caller supplies. **The apply seam is required
  rather than optional**: a caller with no way to apply is refused by name,
  because skipping it silently is exactly the defect the synchronous step was
  added to close -- activation that wrote a correct file and left the operator
  with "cannot reach the supplicant".
* **Three things live in the daemon's wifi module that belong elsewhere**, each
  because this port has only one caller for them so far: the radio drop-in's
  name and its two blocks, which are `netcfgd_host::config`'s and which `ncfg
  wifi activate` and `ncfg wifi add` both write; `network_for`, which is
  `netcfgd_model::wifi`'s and which the observation will want for the same
  answer; and the hostapd station walk, which `hostapd.h` already names as the
  round trip it does not carry. Each says in its comment where it goes and that
  the second caller takes this one rather than writing its own.
* **A `wifi_add` `metric` outside `u32` is refused by the handler.** The Rust's
  request type says `Option<u32>` and serde will not build one out of range, so
  the refusal is at the decode; `ncfg_proto_int_t` carries whatever integer
  arrived, so the check lands where the value is used and names the range.
* **The credential a `wifi_add` carries is never copied.** The Rust passes an
  `Option<&str>` into a `String` the profile holds; here the installer seam
  takes the request's own bytes and a length, so a passphrase -- or a TLS
  private key, which travels the same field -- exists in exactly one place for
  exactly as long as the decoded line does. `supplicant.h` took the same trade
  for the same reason.
* **The rfkill switch is looked up rather than passed.** The Rust hands `scan`
  and `status` an `Option<&ObservedRfkill>` that both call sites build the same
  way out of the observation; here the observation is the argument and the
  lookup happens once, inside. A fact two callers each dig out of one structure
  is a fact one of them eventually digs out differently.
* **The two ported activation tests assert the nearest outcome this planner can
  express.** The Rust asks for `backend.start` and `dns.apply`; this build's
  planner carries no backends and says so in a warning per block it is holding
  and not acting on. So they assert that the plan has an action at all --
  `link.up`, emitted because the planner visits the interface, which is exactly
  what the `device`-only first draft did not make it do -- and that the planner
  names the `wifi` and `dns` blocks it is holding. Measured both ways: with the
  `interface` block the plan has an action, without it the plan is empty, so
  the check still fails against the file that reported success and changed
  nothing. Each becomes its real op when the planner's backend half lands.
* **An address in an explanation is compared canonically, never as text.** The
  document's addresses come through the compiler's `canonical_address` and
  match the kernel's spelling already; a *report's* do not -- `read_report`
  keeps the text somebody's shell script wrote -- and the kernel reports back
  its own spelling of whatever was installed. The Rust compares the two as
  strings, so one address written twice reads as two, and `ncfg explain`
  answers "the configuration does not ask for this address" about an address
  netcfgd installed itself. Reproduced against the shipped binary, which
  plans the same address again on every run; the planner has the same
  comparison and pays more for it than `explain` does.
* **An ownership fact names the address it is about.** The Rust pushes it
  *before* the address it describes and puts no address in it, so on an
  interface holding two -- which is every dual-stack one -- the reader attaches
  each answer to the line above it, and the answer is whether netcfgd may
  delete that address. Here the address comes first and the ownership line
  names it. The single-address subject is unchanged, its subject being the
  address already.
* **An explanation is bounded at `NCFG_EXPLAIN_FACTS_MAX`, with `total`
  counting past it** -- the parser's arrangement again, applied to a renderer
  whose input is a file in the run directory and a message on the socket. Two
  facts per observed address means the count is chosen by whoever wrote the
  observation. The rendering ends with "showing 256 of 1202" rather than
  stopping without saying, and the bound is published so a test cannot spell
  the number itself.
* **A subject's names are bounded at `NCFG_EXPLAIN_SUBJECT_MAX`**, and one
  carrying a NUL is refused rather than compared as the part before it -- which
  would match an interface nobody asked about. The Rust's `Subject` holds
  `String`s that came off the wire; the refusal names the field and the bound.
* **A plan that could not be built is a fact, not a failure.** `pending` plans
  to answer "what happens next", and the Rust's planner cannot say no. This
  one can, and refusing the whole explanation over it would withhold the
  observation half at exactly the moment somebody needs it -- `explain` is what
  people reach for when things are already broken.
* **`explain` renders into a buffer and prints nothing**, and the layout is
  `command_explain`'s format string character for character. A library never
  prints; the caller hands the text to `ncfg_out_*`. The verb itself is not
  wired, its first step being a local observation, so `run.c`'s stub should now
  name the observer rather than the provenance table.
* **Two rules the Rust shares are spelled a second time in `explain.c`**, each
  because this port has one caller for them so far, and each says so where it
  is defined. `takes_reports` is `netcfgd-plan`'s -- the Rust calls it from
  `explain` precisely so the two cannot disagree about which reports are
  believed -- and this build's planner holds `reported` addressing rather than
  acting on it, so the rule is private there. `derive_from_delegation` is
  `netcfgd-model`'s and `value.h` has no port of it; without it an address
  netcfgd derived itself explains as one the configuration does not ask for.
  The second caller takes these rather than writing a third.
* **The ownership, backend and drift words are the model's spellings, not
  Rust's `Debug`.** `ours`, `access_point`, `reconcile` -- what `ncfg status`
  prints and what the JSON carries -- where the Rust's `{:?}` gives `Ours`,
  `AccessPoint` and `Reconcile`. One word per concept, and `explain` is not the
  place a second spelling of an enum enters the vocabulary.
* **The portal helper's image is an argument, and there is no default.** The
  Rust runs `/proc/self/exe` under `argv[0] = netcfgd-probe`, which is right
  for a multi-call binary and wrong for a library: whatever links this is not
  necessarily netcfgd, and a default would have a test binary re-exec itself --
  once per case, and then again. `NCFG_PORTAL_OWN_IMAGE` is the value the
  daemon passes, written once so that a test can assert it by reading it.
  It is also what makes the parent's half testable at all: `probe_test.c` has
  no equivalent here because the Rust has no test of `probe` whatsoever -- it
  can only be reached with the real binary and a real network -- while
  `portal_test.c` drives every exit status the parent must tell apart against
  four-line scripts under its own directory.
* **The parent bounds the child as well, and the deadline signals the group
  twice.** The Rust leans entirely on the child's own alarm, which is sound
  while the child is netcfgd's own image and is a promise the caller makes once
  the image is an argument. So the read of the child's output is watched by a
  clock, and what the deadline signals is the process group -- `SIGTERM` then
  `SIGKILL` even where the leader has already gone, which is `probe.c`'s
  arrangement for `probe.c`'s reason. The case that tells the two apart is a
  helper that exits at once and leaves something of its own holding the pipe;
  that is what `portal_test.c` drives, and it is the one case in this port that
  deliberately waits out a deadline rather than mocking one.
* **A URL is split into an authority and a connect target, not one string.**
  The `Host:` header carries the authority the operator wrote and the
  connection gets a port whether or not the URL gave one. The Rust's `split`
  says exactly that in its own comment and then hands `exchange` the target, so
  `http://example.com/generate_204` is asked for under `Host: example.com:80`
  -- which is not what a browser sends, and a portal check is a comparison
  against what a browser would have got. Its own test asserts the target and
  there is no test of the request at all, so nothing was reading the comment
  against the code.
* **An IPv6 literal loses its brackets before the resolver sees it.** They are
  URL syntax rather than part of the address. The Rust keeps them, and every
  colon inside the literal then reads as a port separator: measured,
  `http://[2001:db8::1]/x` resolves to `cannot resolve [2001:db8::1]: invalid
  port value`, so a `portal_check` naming an address rather than a name
  compiles and can never be fetched.
* **The probe child's body is a function, not a `main`.** It answers the exit
  status and the one line to print; the caller prints and exits. The Rust's
  `helper_main` does both, which a library here may not (section *The three
  conventions*). It is the only difference between the two.
* **Where a contention check reads is an argument, not an environment
  variable.** The Rust reads `NCFG_RUN_ROOT` and `NCFG_PROC` so that its tests
  can point it at a fixture; here the two roots and "is this `/run` the
  machine's own" are a struct the caller fills, and
  `ncfg_contention_machine` is the one place `/run` and `/proc` are written
  down. That is `testdir.h`'s rule about defaults, and it buys a case the Rust
  cannot write: its namespace check is skipped outright whenever `NCFG_RUN_ROOT`
  is set, which is in every one of its tests, so the guard that
  `tests/live/hwsim.sh` proved necessary is exercised by nothing. Here the
  namespace links are part of the fixture and the hwsim case is a check.
* **`/proc` is walked once per contention check rather than once per daemon.**
  The Rust asks `daemon_is_running` separately for `NetworkManager` and for
  `systemd-networkd`, which is two full scans on every reconcile tick for one
  question about two names.
* **A dhcpcd control reply must be an absolute path, terminated.** The Rust
  takes the last run of printable bytes, which is right for the whole frame and
  wrong for half of one: the eight-byte length prefix of a 34-byte path is
  `22 00 00 00 00 00 00 00`, and on its own it answers `Some("\"")` --
  measured against a transcription. That is the very defect the tail rule
  replaced, coming back through a short read, and a caller comparing it against
  netcfgd's own `-f` reads it as somebody else's dhcpcd: a stop reports a client
  gone that is still running, and a start spawns beside one that is already
  there. So a reply with no terminator after its run, or one that is not an
  absolute path, is not an answer -- and `ncfg_dhcpcd_config_file_of` reads
  again under the same deadline rather than believing it. The Rust reads once.
  Both halves are driven over a real `AF_UNIX` socket in `contention_test.c`,
  with the reply cut at the prefix.

* **The reconcile loop is two files, and the split is the module.** `lib.rs`
  keeps its rules inside a loop that owns a channel, four watcher threads, a
  timer and a socket, so nearly none of them can be reached without standing a
  daemon up -- and the Rust says so once, where `a_window_is_requested` is
  split out of `defers_to_a_window` because "a predicate that cannot be
  exercised without building one is a predicate nothing exercises". Here
  `reconcile.c` is every rule as a value in and a value out, opening nothing
  and running nothing, and `reconcile_pass.c` is the order they are acted on
  in, reaching the world only through `ncfg_reconcile_world_t`. What that buys
  is the five orderings the Rust's comments call load-bearing -- the drift
  hooks before the reconcile, the portal checks after them, a contended radio
  given back before the reconcile rather than inside it, the observation never
  held by `--no-apply-on-start`, the documents compared either side of a
  reload -- each of which is now a list a test reads back rather than a
  sentence a reader has to take on trust. Thirty deliberate breakages were
  made against it and every one is named by a check.
* **The watchers are not ported and the wake is.** The Rust has four threads
  and a one-shot timer feeding one `mpsc`; what crosses into this module is
  `ncfg_reconcile_wake_t`, which `ncfg_reconcile_collapse` folds a burst into.
  Whoever owns the descriptors goes on owning them, which is what lets a test
  drive a pass without a kernel, a socket or a second of waiting. The roams
  and the waiting requests travel beside it as lists, because two roams are two
  events and collapsing them would tell a script once about a station that
  moved twice.
* **The loop serves no requests.** `ncfg_daemon_answer_fn` already says what a
  handler owes, so the requests are passed in for the two decisions that turn
  on them -- a pending window defers the reconcile, an explicit apply releases
  the `--no-apply-on-start` hold -- and answered elsewhere. The Rust's
  `answer` dispatcher is the same wave's, not this one's.
* **One plan per pass where the Rust builds two.** `detect_drift` builds one
  and `reconcile_drift` builds another a few lines later, from the same
  document and the same observation. Nothing between them touches either: the
  hooks and the contention stop change the *machine*, and neither re-observes,
  so the second build can only ever be the first again.
* **The restriction asks a predicate per action rather than taking a list of
  names.** The Rust collects `reconciling_interfaces` into a `Vec<String>` and
  searches it per action; `ncfg_reconcile_reconciles` answers the same question
  directly, so nothing has to bound a list whose length is the operator's to
  choose. Its warnings are deliberately not copied across, because
  `ncfg_plan_add` writes the "cannot be undone" one as each action is copied
  and carrying the source's list over would say it twice; the refusals and the
  stranded credentials are copied, since restricting a plan changes what will
  be done and not what is true about the configuration.
* **The drift a pass reports is bounded at `NCFG_DRIFT_MAX`, with `total`
  counting past it.** The parser's arrangement again, applied to a list whose
  length is how badly a machine is losing a fight: a client that shows "32 of
  60" shows more than one that shows sixty nobody scrolls through. Which
  action counts as an interface's drift is asked of the plan rather than of a
  `seen` list, so the count is right past the bound too.
* **The captive-portal record is here and the asking is `portal.h`'s.** That
  module carries the verdict, `ncfg_portal_is_routable` and the child that
  fetches; this one decides when to ask at all, what a `trying:N` record means,
  and when to give up -- which is the half the Rust could only reach with a
  real network behind a real portal, and which is now walked case by case.
* **Three event hooks lose their second environment variable.**
  `NCFG_ACTION`, `NCFG_BSSID` and `NCFG_URL` are not set, because
  `ncfg_hook_env_t` is `apply.h`'s and carries four fixed members. The pair is
  passed to the hook seam rather than dropped at the call site, so the loop is
  not where the fact is lost and the default runner is the one place the two
  lines go when that struct grows a general pair.
* **Giving a contended radio back and asking a URL are seams, with their
  implementations named.** Both reach the machine these tests are built on --
  one stops a backend, the other execs this process' own image -- so neither is
  called directly from a pass a test drives. `ncfg_reconcile_portal_probe` is
  the real one for the second. For the first, `ncfg_contenders_find` is what an
  implementation calls, **and it asks before opening an executor**: the Rust
  opens one as soon as netcfgd is running any backend at all, so on every
  machine it manages it takes the apply lock and a netlink socket every five
  seconds to discover there is nothing to give back -- against the same lock
  `ncfg apply` waits on (0184).
* **A pending SIM cycle is not cleared while the planner cannot carry one.**
  `ncfg_plan_options_t` has no `cycle`, so this build emits no `link.down` for
  a modem that has advanced, and `ncfg_sims_cycled` reads "no records at all"
  as "no cycle was needed" -- which is right for a planner that emits them and
  would silently drop the note here. The pass therefore passes only the
  devices whose cycle the plan actually carried, which is the same condition
  said where it can be checked: nothing is cleared today, and everything is
  cleared correctly the day the option lands.
* **Every seam may be absent, and the pass says what a missing one costs.** A
  loop with no executor observes, reports drift, runs its hooks and changes
  nothing; one with no portal probe checks no URLs; one with no subscriber
  list tells nobody. That is `ncfg_resolv_machine_t`'s bargain -- doing nothing
  on a missing seam is the point rather than the fallback -- and it is what
  lets a test install exactly the two seams its case is about.
* **The loop's clock is an argument too.** `ncfg_confirm_expired_at` already
  takes one; here the pass takes `now` from the same seam struct, so "a window
  with time left is not one that closed" is checked by moving a number rather
  than by waiting. `ncfg_reconcile_document_is_empty` is the other side of the
  same instinct: it answers by hashing against `ncfg_document_new` rather than
  by comparing fields, and **answers "empty" on any doubt**, which refuses a
  window rather than arming one whose revert would undo everything netcfgd has
  done.
* **`plan.last.json` and the fold into `owned.json` are deferred here as they
  are for the revert path**, and for the same reason: the executor seam reports
  no effects, so there is nothing to fold. Named rather than quietly missing.
  **Neither is deferred any more.** The fold closed when it stopped needing an
  effect list at all -- `ncfg_apply_record` takes the plan and the journal --
  and the journal writer closed with `ncfg_apply_write_journal`, which
  `reconcile_pass.c`'s `record_what_ran` calls straight after the fold, under
  the apply lock and before the executor is closed.

* **`src/main/` is not in `libncfg.a`, and it is the one directory the
  wildcard holds out.** The Makefile's rule is that the directory is the list;
  this is the exception and it is section *The three conventions* rather than
  convenience. A library never exits, and the archive that carries every file
  written to that rule would otherwise have a `main` inside it. What is under
  `src/main/` is therefore built into the program and `main_test` links the
  parts of it that are not the entry point -- which is the whole of why
  `main.c` is four lines: everything a test cannot reach lives in the one
  symbol a test cannot have twice.
* **The port links, and this is the first time it could be measured.** One
  image, two names, `argv[0]` deciding which -- 0024's arrangement, and the
  reason for it is the reason the port has one `main` rather than two: the
  Rust measured 775 KB duplicated between two binaries against a 2.89 MB
  install. Measured here at 441,336 bytes stripped, against the Rust's
  2,972,192, with one `NEEDED` entry -- `libc.so.6` -- where the Rust has
  four. **Neither number is a like-for-like comparison and the entry says so
  rather than leaving it to be read as one**: this build's planner is four
  passes of thirty, its executor refuses a handful of ops by kind, the daemon
  runtime is unreachable code, `--json` and the `network`-block writer are not
  ported. The figure also predates the provenance producer, which is a page of
  `src/compile/` the measurement did not include. Three of the Rust's four
  libraries
  are ncurses and its unwinder, which the port gives up deliberately (see
  `ncfg tui` above) rather than beats. The figure is worth recording because a
  port with no linked artefact has no size at all, and a symbol no binary
  needs is a symbol whose cost nobody has checked.
* **`make linkage` cannot be pointed at it.** The gate builds
  `target/release/netcfgd` and reads that path by name, so the C binary is
  checked by hand against the same `LINKAGE_ALLOWED` list -- one entry, and it
  is allowed. Teaching the gate a second binary is a Makefile change with an
  install decision behind it, which is what *What is not being decided here*
  holds back.
* **`argv[0]` is made legible before it is repeated back**, and so is an
  option name. The Rust prints both raw. In C the same string is a fixed array
  away from a byte that moves a cursor, clears a screen or sets a title, and
  the one thing the program knows at that moment is that the name it was given
  is wrong. Printable ASCII kept, everything else a dot, and a ceiling with an
  ellipsis so that a cut name does not read as a whole one.
* **A program name is the text after the last `/`, so a trailing slash
  resolves to nothing.** Rust's `file_name` answers the component above it --
  `/usr/bin/` is `bin` -- which is a directory being read as a program name.
  Answering nothing sends that case to the arm that refuses, and refusing is
  the only safe answer here: a wrong guess starts a network configuration
  daemon for somebody who typed a client's name.
* **The daemon's usage text is pasted together from the constants that decide
  its defaults.** The Rust writes `default /etc/netcfgd, or $NCFG_CONFIG_DIR`
  as literal text beside a `config` module that holds the same path, and the
  help is the copy nobody recompiles. Here a default that moves moves in the
  help or does not compile. The version and the copyright are read from
  `cli.h` for the same reason and a stronger one: the Rust shares
  `CARGO_PKG_VERSION` and `netcfgd_model::COPYRIGHT` between the two programs
  precisely so they cannot drift apart about a fact neither of them owns, and
  the C port has exactly one spelling of each, so the daemon reads the
  client's rather than growing a second.
* **`netcfgd` will not start, and it refuses by naming a symbol.** Nothing
  implements `ncfg_daemon_observe_fn`, so the loop would watch a machine it
  cannot see -- `ncfg_reconcile_pass` would run on every tick, report no drift
  because it can see none, and answer `ncfg plan` with an empty plan, which is
  an answer nobody can tell from a converged machine. The refusal names the
  type rather than describing the absence, because the only way to have typed
  `netcfgd` here is to have built it: nothing installs this program. The name
  is checked -- `main_test.c` pulls the identifier out of the sentence and
  looks it up in `daemon.h`, so a rename makes the refusal go red rather than
  leaving it pointing at a module under a name nothing has.
* **The watchers are this directory's work, and they are named where they
  would live.** *The watchers are not ported and the wake is*, above, says
  what crosses into the reconcile module; the other side of that sentence is
  that somebody owns the netlink socket, the configuration watch,
  `/dev/rfkill`, the supplicant directory and the window timer, and that
  somebody is a `main`. `ncfg_daemon_serve` is finished and would be bound
  from here; the loop that collapses a burst of wakes into one pass, drives
  `ncfg_reconcile_pass` and hands the waiting requests to
  `ncfg_daemon_answer_fn` was what `src/main/` still owed. **It is written**,
  and the entries below it are what writing it diverged on.

* **Four watcher threads and a sleeping timer become one `poll`.** The Rust
  says of itself that the reason was preference rather than `unsafe` (0235),
  and names what the threads cost: 0233 lost the loop's heartbeat when one
  returned, and 0234 found five spawns whose failure nothing reported. Both
  are faults a single loop does not have, and neither could have happened
  without the threads. So there are no threads here, no channel and no mutex
  between the watchers: `ncfg_main_round` waits on every descriptor at once
  and reads whichever became ready. The **workers** are untouched and remain
  threads for the reason that comment gives -- a client connection blocks on a
  reader that may stop reading -- which is why the request path below is a
  rendezvous rather than a call.
* **The split is the same one `reconcile.c` makes, one layer out.**
  `daemon_wake.c` is what the loop decides and every call in it takes values
  and answers one: what a `revents` mask means, what `poll`'s return meant,
  how long to wait, whether a source that has failed keeps its place, which
  wake a ready descriptor folds into, whether a round is worth a pass, whether
  a `CONNECTED` is a roam. It opens nothing. `daemon_loop.c` is the order, and
  the `poll` is the only thing in it that needs a live descriptor.
  `daemon_watchers.c` is the five real sources and is the only file that opens
  anything. What that buys is the list this port has not had before: a
  descriptor that hangs up, one that is not open, one that will not be read, a
  burst of fifty, a burst that never ends, `EINTR`, and a signal arriving
  between the check and the wait are each a check rather than a paragraph.
* **The backstop is measured from the top of the round, not from the last
  message.** The Rust has two producers of `Command::Tick` and neither fires
  on a machine the kernel is talking to: the netlink watcher sends one only
  when its own socket *times out*, and `next_command`'s `recv_timeout`
  restarts on every command that arrives. So on a machine reporting a link,
  address or route change at least every five seconds -- a router, a lease
  renewing, a link flapping -- `ticked` is never set at all, and `ticked` is
  half of `should_resolve_window`: a confirm window whose timer thread failed
  to start has nothing left to close it, which is 0234's mitigation switched
  off by exactly the machine that is busiest. Here the deadline is computed
  once per round and each wait is `ncfg_main_timeout_until`'s answer for what
  is left of it, so the tick happens on schedule however loud the machine
  is. A deadline already past is
  a wait of **zero and never a negative number**, which `poll` would read as
  "no timeout": that is the one arithmetic slip here that would stop a daemon
  dead, on exactly the quiet machine the backstop exists for.
* **A source that cannot answer is taken out of the set, and the drop is said
  out loud.** `POLLHUP` and `POLLNVAL` are answered at once and with no
  patience, because a hung-up descriptor is ready every single time it is
  polled -- so "give it another round" is a busy loop with a counter in it,
  and that is the ordinary way a daemon comes to spin at 100% CPU while still
  answering clients. `POLLERR` is given `NCFG_MAIN_SOURCE_PATIENCE` looks,
  since a read is what clears a queued error, and so is a drain that failed.
  The Rust has no equivalent because each of its watchers is a thread that
  returns; what it does instead is exactly what 0233 cost, and the log line
  here says what is no longer being watched rather than leaving a daemon that
  looks identical to one with nothing to watch.
* **`POLLIN` is answered before `POLLHUP`.** A writer that queued bytes and
  then closed sets both, and the order decides whether the last records are
  read or thrown away with the descriptor -- for `/dev/rfkill` that is the
  switch being flipped as the device went away. The hang-up is not lost by
  waiting: it is still there on the next look, with nothing behind it.
  `POLLNVAL` is the one exception and is answered first, since there is
  nothing to read from a descriptor this process does not have.
* **The burst collapse is bounded.** Collapsing is the point -- bringing an
  interface up produces a run of netlink messages and re-reading once per
  message would make the daemon's cost scale with the kernel's chattiness --
  but "keep collapsing while anything is ready" has no floor: one descriptor
  that is permanently readable means the pass never runs at all, and a daemon
  that stopped reconciling while spinning is the worst of both. So
  `NCFG_MAIN_DRAIN_ROUNDS` bounds it and whatever is left is the next round's,
  which is microseconds away. The bound is published so a test cannot spell
  the number itself.
* **The window's timer is a `timerfd` and not a thread that sleeps.** 0234 is
  the reason and it is the strongest one in this file: `spawn_expiry_timer`
  discarded the result of `spawn`, so a timer that could not start left a
  window open for ever -- the failure commit-confirm exists to prevent,
  arriving through the mechanism meant to prevent it. A descriptor cannot
  half-start, an arming that fails says so, and the tick asks the window
  anyway. A window of no seconds is armed one nanosecond out rather than
  `{0,0}`, which *disarms* a timerfd rather than firing it.
* **A signal is a byte on a pipe in the same `poll`, not a flag.** A handler
  that sets a flag races the loop, which checks the flag and then sleeps five
  seconds in `poll` with the flag already set; a byte in a descriptor cannot
  be missed by a wait that descriptor is part of. `write` is what a handler
  may call, the write is non-blocking so a full pipe cannot hold one, and
  `errno` is put back -- the syscall a handler here interrupts is the `poll`
  the whole daemon sleeps in, whose `EINTR` is read out of exactly that
  variable. The Rust installs no handler at all and is killed where it stands,
  which is what leaves two reply sockets behind on every restart (0193).
* **`EINTR` is asked again with what is left of the same deadline.** Not a
  failure, which is 0233, and not a fresh five seconds, which would let a
  machine generating signals hold the backstop off indefinitely -- netcfgd
  forks a child every time it runs a hook. It cannot spin: every one of them
  is a signal that really arrived, and the wait that follows is shorter each
  time until it is zero.
* **`ENOBUFS` is deliberately not told apart from an ordinary change.**
  `ncfg_netlink_change_from` already decides what a gap means -- it is a
  change, because the daemon re-reads the machine rather than applying deltas
  -- and the only thing a second decision could do differently is re-read the
  machine, which one change already causes. A loop that distinguished them
  would be a second answer to a question that module owns, and the bytes are
  thrown away either way. What the loop must not do is treat the failing
  receive as fatal, which is the arm that would make a daemon go deaf exactly
  when the most is happening.
* **The supplicants are descriptors in the same `poll`, and the control
  directory is watched.** The Rust's roam watcher is a thread that reads the
  directory, `stat`s each radio and waits 250ms on each in turn, which on a
  machine with one radio is a `read_dir` of that directory four times a
  second for the life of the daemon. Here the directory has an inotify watch
  whose only job is to end the wait promptly, the scan happens when it says
  something moved, and each attached radio's socket is polled with everything
  else. The identity check (0240), the reply-socket filter (0112), the
  impatient connect (0114) and the `ATTACH` failure being said out loud (0225)
  are all carried across unchanged.
* **A radio is drained only after `poll` has said there is something there.**
  `ncfg_supplicant_next_event` sets `SO_RCVTIMEO` from its argument, and a
  timeout of zero is `{0,0}`, which the kernel reads as *no deadline at all*
  -- a blocking read on the daemon's only thread. The supplicant's own scan
  wait already steps around this and says so; here the wait is what makes the
  deadline moot and the argument is one millisecond rather than zero, so that
  a race between the two costs a millisecond rather than the daemon.
  `ncfg_rfkill_next` and `ncfg_netlink_wait_for_change` are called under the
  same rule and for the same reason.
* **The roams a round carries are bounded, with the rest counted.** Two roams
  are two events, which is what `daemon.h` says about the list travelling
  beside the wake, so they are not collapsed -- but a radio flapping must not
  make one round's allocation the operator's to choose. `NCFG_MAIN_ROAMS_MAX`
  with a missed count is `NCFG_DRIFT_MAX`'s bargain: a number an operator has
  to interpret is better than a station that moved and nothing anywhere
  saying so.
* **A request crosses to the loop through a mailbox and is answered after the
  pass.** The Rust queues every request into the channel the watchers feed and
  serves them in the loop body, which is what keeps one thread inside the
  daemon's state; here the server is a thread per connection and calls
  `ncfg_daemon_answer_fn` with its own lock held, so the seam the loop
  installs parks the connection's thread, the round takes the request, drives
  `ncfg_reconcile_pass` with it and only then hands it to the answer seam.
  The order is the point rather than a consequence: a pending window defers
  the reconcile and an explicit apply releases the `--no-apply-on-start` hold,
  and a request answered first would have the change applied underneath it,
  with the window covering nothing. The server's lock means exactly one
  request can be inside the seam at a time, so `NCFG_MAIN_PENDING_MAX` is
  margin rather than a capacity; a mailbox that filled anyway **refuses by
  name** and one that is shut **answers every waiter** rather than leaving a
  connection thread parked for the life of the process.
* **The configuration watch may have no descriptor, and that is a shape rather
  than a failure.** `--poll-config` answers by walking the filesystem, so
  `ncfg_watch_descriptor` is -1 and the loop *asks* that source once a round
  instead of waiting on it. Inventing a pipe nobody writes to would make the
  two mechanisms look alike and leave the fall-back reporting nothing for
  ever, which is what `watch.h` says it exists to prevent.
* **Five modules grew a descriptor accessor, and they are named here because
  the loop is their only caller.** `ncfg_netlink_descriptor`,
  `ncfg_watch_descriptor`, `ncfg_inotify_descriptor`,
  `ncfg_rfkill_descriptor` and `ncfg_supplicant_client_descriptor`. Each of
  those modules waits on its own descriptor with a `poll` of one, which is
  right for a watcher whose whole job is that one thing and wrong for a daemon
  watching seven at once; and each says `fd` is private, so reaching into the
  struct from `src/main/` would have made every field it has reachable by the
  same route. Each accessor's comment says it is for waiting on and for
  nothing else: the reads stay in the module that owns the sender check, the
  `ENOBUFS` rule and the difference between an event and a reply.
* **A source with no drain has its readiness taken as the whole of its news**,
  which is the one shape in this file that a caller can get wrong: nothing
  reads the descriptor, so it stays ready and fills every look of the burst.
  It is bounded rather than forbidden, because forbidding it would mean the
  loop deciding what a caller may watch.
* **`netcfgd` still will not start, and the seam it names has changed.** The
  observation composition landed in the same wave --
  `ncfg_observe_source_observe` is `ncfg_daemon_observe_fn` signature for
  signature -- and the descriptors
  are this entry's subject, so what is left is the request dispatcher:
  **nothing in `c/src/` implements `ncfg_daemon_answer_fn`**. A daemon that
  bound the control socket and answered `error` to every request would be
  worse than one that will not start, in the way this record keeps refusing --
  an operator's `ncfg apply` reaching a daemon that cannot act, and a refusal
  that reads as a request the daemon did not recognise. `main_test.c` pulls
  the identifier out of the sentence and looks it up in `daemon.h`, so the
  check moves with the name.

* **The round of dumps is taken through a seam, and the seam has two
  implementations in the library.** `snapshot_with` takes a `&mut Netlink` and
  is therefore reachable only with a socket, which is why nothing in
  `netcfgd-sys` tests it and why its own crate's one attempt --
  `tests/wire.rs` -- gives up and writes `if let Ok(snapshot) = ...`.
  `ncfg_observe_exchange_t` is `ncfg_netlink_request` without its socket;
  `ncfg_observe_exchange_socket` is the live one and forwards, and
  `ncfg_observe_exchange_replay` is the same round with the send taken out,
  reading through `netlink.h`'s own `ncfg_netlink_recv_t`. That is
  `ncfg_netlink_change_from`'s split one layer up, and what it buys is the six
  cases a kernel will not produce on request: a dump ending in `NLMSG_ERROR`,
  a truncated final message, a message claiming more bytes than the datagram
  carried, `ENOBUFS` mid-round, an empty machine, and one record more than an
  observation holds. The replay still *builds* each request and refuses a
  buffer that failed, because a seam that skipped the step would test less
  than the thing it stands in for.
* **There is an aggregate that owns the arrays, and the snapshot borrows it.**
  `ncfg_observe_snapshot_t` borrows every field and has no free, which its own
  comment says in as many words -- so `ncfg_observe_capture_t` owns the seven
  arrays and the alternative names hanging off each link record, and 0263's
  rule about an `ncfg_x_free` per aggregate lands there rather than on a type
  the observer's input may not become. The snapshot is a member of it, filled
  in pointing at its neighbours, so the fourteen assignments happen once here
  rather than at each call site with one of them wrong. The cost is a rule
  written down where the borrow checker used to stand: a capture is not copied
  by value, because a copy's snapshot describes the original's arrays.
* **Records of one kind are bounded, and the bound is an argument.** The Rust
  collects into a `Vec` per dump with no ceiling at all. `NCFG_OBSERVE_RECORDS_MAX`
  is chosen for the routing table, which is the only one of the seven a
  *network* can make large, and the refusal names the kind and the number. It
  is a refusal rather than a truncation for the reason `total`-past-the-bound
  is right for a renderer and wrong here: an observation quietly missing half
  its routes is a plan that installs them all again. The ceiling is a field of
  `ncfg_observe_kernel_t` for the reason `ncfg_netlink_request_from`'s initial
  buffer size is a parameter -- the kernel will not grow a machine a million
  interfaces on demand, so a test that could not lower it could never reach
  the refusal. The growth deliberately does not lean on that comparison
  either: asking for one more than is held costs nothing, and without it an
  edit to the ceiling test turns a refusal into a write past the array, which
  is the failure a bound exists to prevent.
* **A payload a decoder refuses is skipped and counted, and the first sentence
  is kept.** `netlink.h` already asks this of a caller that dumps; the Rust's
  four `filter_map`s drop and say nothing, so a truncated dump and a quiet
  machine look identical afterwards. One buffer and not one per event, because
  a count with no sentence is a number nobody can act on and a sentence per
  payload is a log nobody reads. The forged-datagram count `ncfg_netlink_collect`
  keeps is carried up the same way, for the same reason it survives a refusal
  down there: a dump that came back empty having discarded three datagrams
  from a local process is a different fact from one that came back empty.
* **A filter dump that fails is counted rather than fatal**, which is the one
  deliberate softness in the round. The Rust excuses `ENOENT` and `EINVAL` on
  that path and propagates everything else with `?`, so one interface's filter
  dump failing ends the whole snapshot -- and with it the observation, on the
  tick a daemon is reading the machine. The interface was reported as carrying
  an ingress hook by a dump taken a moment earlier, so a failure now is a
  machine that moved between two of the seven; a USB device being unplugged is
  exactly that, and it is also what generates the event the observation is
  running on, which is the coincidence `observe.h` already records about the
  rfkill search. `redirects_unreadable` is what tells "no redirects" from "not
  asked", and `ingress_hooks` is kept in the capture -- it is not in the
  snapshot -- so that the distinction is readable at all.

  Measured while porting it, on the 6.12 kernel this was built on: a
  `RTM_GETTFILTER` dump aimed at an interface with no ingress qdisc, and one
  aimed at an ifindex that does not exist, both come back as an **empty dump**
  rather than as `ENOENT` or `EINVAL`. So the Rust's excuse never fires on a
  current kernel and what is left of that arm is the `?`.
* **The two traffic-control requests are taken apart rather than written
  again.** `qdisc.h`'s builders write a complete message with its own header,
  because that is what their other callers send, and `netlink.h` has no call
  that sends a prepared message and collects until `NLMSG_DONE` --
  `ncfg_netlink_send_batch` ends on an acknowledgement, which a dump never
  gets. So the collector builds the message with `ncfg_qdisc_build_dump` and
  `ncfg_qdisc_build_filter_dump`, walks it with the wire layer, and hands the
  exchange the kind, the flags and the body it finds there. Nothing about
  either request is spelled a second time: not the ingress parent, not the
  dump flags, and not the refusal of a zero index -- which is reachable, since
  a kernel can report an ingress hook on interface zero and the builder is
  what refuses to aim a dump at it. `collect_test.c` holds both bodies to the
  builders' own bytes, so the day a builder changes the proof moves with it.

* **The composition is one call, and both halves of the program take it.**
  `netcfgd_observe::current` is the Rust's, and `netcfgd_host::prior_state`
  beside it carries the reason in as many words -- one function so the two
  callers cannot disagree about whether the delegations are included. That
  reason is the port's too and is stronger here, because the C splits what the
  Rust does not: `augment` and `derive` are separate calls, the prior is
  assembled out of three files rather than one, and two of its six aggregate
  lists are *handed over* rather than copied. Written out at each call site
  that is a dozen lines with an ownership rule in the middle, twice.
  `ncfg_observe_current_from` takes the dump seam, `ncfg_observe_current`
  opens a socket of its own, and both end in `derive` -- which the Rust's
  `current` does not, its daemon calling `host::derive` a few lines later.
  Folding it in is what stops a caller shipping an observation with no link
  inventory and no connectivity rung, neither of which is an error and both of
  which read as a machine that has none.
* **Something implements `ncfg_daemon_observe_fn` now**, so the entry above
  about `netcfgd` refusing to start by naming that symbol is, from this wave,
  about the descriptors alone. `ncfg_observe_source_t` is what the seam's
  `void *` carries -- a run directory, the three roots and the round of dumps
  -- and `ncfg_observe_source_machine` resolves the first two **once**, which
  is `ncfg_observe_roots_default`'s rule applied one layer up: a seam that
  read the environment on every tick would answer differently depending on
  what had happened to `NCFG_PROC_ROOT` since the daemon started. The source
  carries the dump seam as well, and an absent one means this machine's own
  socket -- the choice `ncfg_observe_collect` already offers beside
  `ncfg_observe_collect_from`, and deliberately not `ncfg_resolv_machine_t`'s
  no-default rule: that sweep's default ends in a signal to a process on the
  developer's machine, and this one reads. What it buys is that the seam the
  daemon installs is the seam a test drives, rather than a second path that
  only ever runs against a live kernel.
* **A report or a delegated prefix that cannot be read fails the
  observation, and an unreadable `owned.json` does not.** The Rust cannot
  express the difference: `read_reports` and `read_delegations` return a `Vec`
  and swallow whatever went wrong. Here `ncfg_owned_read` still fails open --
  its own comment argues it, and the worst case is netcfgd under-claiming what
  is its own, which is the safe direction -- while the other two carry
  addressing a bearer or a DHCPv6 client negotiated and netcfgd did not. That
  appears in no kernel dump, so an observation missing it is the case
  `NCFG_OBSERVE_RECORDS_MAX` refuses a truncated dump for: a planner reading a
  machine that looks emptier than it is.
* **What a round of dumps counted is said rather than left in the capture.**
  `skipped`, `redirects_unreadable` and `dropped` exist so that a dump which
  came back empty having discarded three datagrams is a different fact from
  one that came back empty; the composition is the first caller in a position
  to say so, and a count nothing ever reads is a field with no reader. A
  warning each, through `log.h`, which `libncfg` may call.
* **`ncfg status`, `ncfg plan`, `ncfg explain` and `ncfg wait-online` are
  wired; `ncfg apply` is refused by name.** The four read the machine and
  print. The fifth changes it, and the refusal is a decision rather than a gap
  -- four facts, each of which is on its own enough:

  * the planner is four passes of thirty, so a plan from this build is not the
    whole change and an apply would converge part of a machine and report
    having converged it;
  * the executor carries every op kind and refuses a few by kind **as
    the plan runs**: `ncfg_apply_supported` is asked by `execute`, one action
    at a time, and `ncfg_apply` stops at the first failure, so a plan mixing
    a supported op with an unsupported one changes the machine and stops
    halfway. A sweep before the first action would fix the *order* of that
    refusal and none of the rest;
  * nothing folds what an apply did into `owned.json` -- deferred by name
    above, the executor seam reporting no effects. Addresses and routes
    survive that because the kernel carries netcfgd's tag; **a link does
    not.** `create_link` adds no `NCFG_OBSERVE_ALTNAME_PREFIX` alternative
    name and nothing records the name either, so a bridge this build created
    reads back `unknown` for ever and netcfgd can never delete it. That is a
    change to somebody's machine this port has no way to undo;
  * there is no confirm window. `ncfg_plan_confirm_window` answers from
    `global { confirm = ... }` as well as from `--confirm-within`, so a plan
    here carries `commit.arm` -- and the executor correctly does nothing for
    it, arming belonging to whoever owns the timer afterwards. Nothing here
    does, so an apply that cut the machine off would say a window was open
    and never revert.

  `ncfg plan` is offered in the refusal instead, because it is the same
  document against the same observation with every held block named, and it
  changes nothing.
* **`run.c` no longer says it is waiting for the observer, and the constant
  that said so is deleted rather than left pointing at something.** Five arms
  shared `NEEDS_OBSERVER`; the dump it named landed in this wave, and a
  refusal naming a module that is present is worse than one naming a module
  that is absent, because it looks right. `cli_test.c` reads `run.c` for that
  sentence, which is the same check that walks the usage against the dispatch.
  The `explain` entry above says the stub "should now name the observer rather
  than the provenance table"; it names neither, the verb being wired -- and it
  is handed an empty table, so its first fact is the notice that entry
  describes.
* **`ncfg status` prints the diagnostics of a configuration that will not
  compile, and answers anyway.** The Rust calls `compile(options).ok()` there
  and a broken configuration produces a status listing with no hint that the
  desired half of the answer is missing. The exit status stays 0: the question
  asked was about the kernel and the kernel answered.
* **`ncfg wait-online` compiles the configuration once, before the loop.** The
  Rust's loop calls `observe_with_document`, which compiles the directory on
  every iteration -- every configuration file read four times a second for the
  length of a DHCP timeout, with the diagnostics of a config that does not
  compile printed just as often into a boot log nobody is watching. The
  document is there only so the observation is the one `ncfg status` would
  show, and it does not move while the machine comes up.
* **`ncfg wait-online`'s default is pasted into the help from the constant
  behind it**, which is `daemon_main.c`'s rule and the reason is the same: the
  Rust writes `30 by default` as literal text beside a `DEFAULT_WAIT_ONLINE`
  holding the same number, and the help is the copy nobody recompiles.
* **A contention warning skips an interface whose kernel index does not fit.**
  0263's narrowing rule where the model's `int64_t` meets a field the width of
  the kernel's, pointed at a claim: truncating would match a contender against
  an interface nobody named, which is worse than not asking about it.

* **The executor's service-side half is `service.h`, and every path it uses is
  a member of one borrowed struct.** The Rust's `Kernel` reads
  `NCFG_PROC_ROOT`, `NCFG_RESOLV_CONF`, `NCFG_DNSMASQ_CONF`, `NCFG_UNBOUND_CONF`
  and `NCFG_WPA_CTRL_DIR` out of the environment, and `netcfgd-dns`'s own
  comment says why those variables exist: *"a test very nearly rewrote this
  machine's"*. `ncfg_service_t` carries `/run`, `/proc`, the supplicant control
  directory, the resolver's three targets and the three daemons' programs, and
  **none of them has a default** -- a member left NULL refuses the ops that
  need it, by name. `ncfg_service_machine` is the one place the machine's own
  paths are spelled, so a test asserts what a daemon would use by reading it,
  and it takes each constant from the module that *reads* the same file
  (`NCFG_OBSERVE_PROC_ROOT_DEFAULT`, `NCFG_RUN_DIR_DEFAULT`,
  `NCFG_SUPPLICANT_CTRL_DIR`, `dns.h`'s three) rather than spelling a second.
* **`ncfg_apply_supported` answers the three backend ops through
  `ncfg_service_backend_supported`**, which is `creatable`'s shape applied to a
  second family: the answer turns on the backend's *kind* as well as on the op.
  Five of the nine kinds have a module under `src/backend/` and are carried
  out -- an access point, a router advertisement daemon, an openvpn tunnel, a
  DHCPv4 client and a supplicant; a DHCPv6 client's *start* and a PPPoE session
  are refused, the first because the op does not carry the delegation request
  that decides which client can serve it and the second because `pppd` has no
  launcher here. The supplicant's refusal was in this list and is gone: the
  launcher is `src/backend/supplicant/launch.c`, and the entry near the end of
  this file that said the executor still declined one has been corrected
  rather than removed. `backend.reload` is radvd's alone, which is the
  Rust's arm too and 0026's reason: an access point's reload is a restart and a
  deauthenticated LAN, and a reload that stopped and started would hide that
  behind a word.
* **`wifi.set_regdom` is executed, through the supplicant, and the Rust never
  executes it at all.** `WifiSetRegdom` is an `Op` variant nothing constructs --
  `netcfgd-plan/src/lib.rs` records it as one of three radio settings with no
  consumer anywhere while the README advertises all three -- and this port's own
  refusal used to say it "goes over generic netlink, and this executor holds an
  rtnetlink socket only". `SET country <XX>` on the control socket is the route
  `wpa_supplicant`'s own `country=` takes into `nl80211`, so it needs no second
  netlink family; it does need a supplicant on the device, and says so where
  there is none. The country is checked for being two ASCII letters and upper
  cased before it is sent, because `SET` takes the rest of the line.
* **`access_control.add` and `.del` read the list back before they write.**
  The Rust sends `ADD_MAC` blind and its own comment claims the command is
  idempotent; hostapd 2.10's `hostapd_add_acl_maclist` refuses a duplicate and
  the socket answers `FAIL`, so the second apply of a converged machine fails
  its plan. Here `<LIST> SHOW` is parsed with `ncfg_hostapd_parse_acl_show` --
  the half `hostapd.h` says was missing was the round trip, and this is it --
  and a station already where it should be costs one round trip and no command.
  `tests/live/fake_hostapd.py` answers OK to a duplicate and says hostapd's are
  idempotent; it is the fake that is wrong, and the in-C fake answers `FAIL` as
  the source does.
* **`wifi.associate` asks `STATUS` before it selects, and resolves a profile id
  rather than a slot.** The op carries a `network` block's id because a plan is
  written before anything is added to a supplicant and cannot name a slot, so
  the SSID comes from the document -- or, for a network naming access points,
  from the last scan through `ncfg_supplicant_pick_ssid` -- and
  `LIST_NETWORKS` says which slot holds it. A radio already on that network is
  left alone: re-selecting is a disassociation and a rejoin, which is an outage
  produced by a plan that had nothing to do. The join is then waited for, since
  `SELECT_NETWORK` answering `OK` means the supplicant accepted the command
  (0197).
* **Stopping an access point lives in `src/apply/` and belongs in
  `src/backend/hostapd/`.** `hostapd.h` says its `stop` is not carried because
  it speaks the control socket and that client is the supplicant module's; the
  stop is written out of that client and hostapd's own path helpers, and this
  entry is where it says so -- the same arrangement the three things in the
  daemon's wifi module have, and the second caller takes it rather than writing
  a third.
* **A hostapd whose control socket is present and silent fails the stop, and
  absence is the socket file not being there.** The Rust asks
  `nothing_is_listening` of the error the connect failed with, forgiving
  `ENOENT` *and* `ECONNREFUSED` -- the second being a socket file a dead
  process left. `ncfg_supplicant_connect_within` releases the half-built client
  before returning NULL and that release closes and unlinks, so `errno` at the
  call site is the last of those calls rather than the connect's; the predicate
  exists in `supplicant.h` and has no C caller for exactly that reason. So the
  absence test here is the socket file, and the stricter half of 0109 is taken:
  a hostapd killed outright needs one refused stop before its socket file goes,
  against a silent success about an access point still on the air. The
  generated configuration and the pid file are removed either way, which is the
  half that matters most -- hostapd has no indirection for a passphrase.
* **A router advertisement's prefixes are an argument, with no default.** The
  Rust resolves `@pd:wan0` at the moment of the start, which is right -- a
  delegation arrives after the document does -- using `netcfgd-model`'s
  `derive_from_delegation`, which `value.h` has no port of and which `explain.c`
  already spells a private copy of and says so. A second private copy here
  would be the third reading of one rule, and the place the three could
  disagree is what a router announces to every host on the wire. So
  `ncfg_service_advertise_t` carries the resolved prefixes and the servers, and
  an interface with no entry is a refusal naming it rather than a router
  advertising nothing.
* **`sysctl.set_accept_ra` refuses anything but 1 and 2, by name.** 0073 says
  netcfgd writes `2` -- accept even while forwarding -- and `1`, the kernel's
  own default, and never `0`, because switching advertisements off is a choice
  no document here makes. The Rust's arm takes a `u8` and writes whatever
  arrives; `ncfg_op_t` carries an `int64_t`, so the check lands where the value
  is used and names the range.
* **`hostname.set` refuses a name carrying a control byte rather than writing
  it.** The kernel's file is one line, so a value with a newline in it sets the
  hostname to the part before it while the document, the plan and the journal
  all say the whole thing -- and every comparison afterwards plans the same
  change again. Refused rather than trimmed: a name somebody typed that is not
  the name they get is the quiet disagreement this project exists to refuse.
* **`dns.apply` demands the run directory before it delivers anything.**
  `ncfg_dns_deliver` ends in `ncfg_dns_record` itself, so nothing here writes
  the record a second time -- that duplicate was in the first draft and was
  found by sabotage rather than by reading, because removing it turned no check
  red. What is this module's is the *order*: `deliver` writes `resolv.conf` and
  only then discovers it has nowhere to record what it did, which leaves the
  machine changed and the planner unable to tell, so every following apply asks
  for the same delivery again.
* **`wifi.set_profiles` does not read the `profiles` the op carries**, which is
  the Rust's behaviour and is deliberate: the op names the device, and what
  that device gets is every network in the document. Filtering here would make
  the plan's list a second authority over the document's.

* **`derive_from_delegation` is `value.h`'s now, and it carries a sentence.**
  The entry above about `explain.c` said it belonged there and that the second
  caller takes it; the planner is that caller, twice over -- the forward pass
  resolves the reference to add the address and the teardown resolves it again
  to answer "is this one still wanted?". A second copy of that arithmetic is a
  plan that adds an address and deletes it again for ever, which is the
  property `plan.h` calls load-bearing. `ncfg_address_from_delegation` takes
  the subnet selector as a number rather than an `ncfg_prefix_ref_t`, because
  `value.h` sits below `document.h` and stays there; and it answers 0 with a
  sentence where the private copy answered 0 silently, since the planner puts
  that sentence in front of an operator whose configuration will never produce
  an address. `explain` passes NULL and drops it, a malformed pair being simply
  not the address it was asking about.
* **A merged DNS scope's policy is the plan's own, and it is the one exception
  to `plan.h`'s borrow.** A policy that came off the document is borrowed as
  that file says. A scope that merges a lease's nameservers into it is neither
  the document's nor the observer's -- it is the document's servers with the
  network's appended -- so it has to be somebody's, and the plan is the only
  thing on the right side of every one of those lifetimes.
  `ncfg_plan_intern_dns_policy` copies the struct and the two lists a merge
  appends to and leaves every string borrowed, which is the same borrow the
  policy itself would have been.
* **The DNS scope list is the planner's, and it is a rule this port has one
  caller for.** In the Rust it is `netcfgd_model::dns::scopes`, called by the
  planner and by the executor, and its comment says why in as many words: the
  planner learned that a report contributes nameservers and the executor went
  on building its list from the document alone, so the plan said `dns.apply`
  and the delivery wrote a `resolv.conf` with nothing in it. Here `dns.h` takes
  a scope list from whoever delivers and nothing in `c/src/` composes one, so
  the rule is spelled in `host_wide.c` where the only caller is. It belongs
  beside `ncfg_dns_flatten`, it says so at its definition, and the second
  caller takes this one rather than writing a third -- which is `explain.c`'s
  arrangement for `takes_reports` and carries the same obligation.
* **A nameserver a report named becomes the model's spelling of itself, and one
  written as a prefix is dropped.** The Rust parses each into an `IpAddr`,
  which does both by construction; in C the text survives the reader on
  purpose, so one bad line does not discard a whole report, and this is where
  it has to become an address. Canonical because the delivery records what it
  wrote and the observer reads that record back: a server carried through in
  the author's spelling compares unequal against netcfgd's own record of having
  delivered it, and `dns.apply` is then planned on every single run. That is
  10.169's defect one field over, and it is checked with a report naming
  `2001:0DB8:0000::0053`.
* **A DNS policy is compared by rendering it, not by walking it.** The
  planner's own writer is what a plan and the record under `<run>/dns/` are
  both made of, so a member added to `ncfg_dns_policy_t` and missed by the
  comparison is impossible rather than unlikely -- a hand-written field walk
  would be the third list to keep in step with the struct and the writer, and
  the list maintained by hand is the one this project has already got wrong
  twice. Two buffers that *failed* deliberately compare as different rather
  than as equal: the cost of that direction is a delivery already in force
  being written again, and the cost of the other is a machine whose resolver
  was never configured reporting nothing to do.
* **`backend.stop` is restricted to the two kinds this build starts.** The
  Rust's `backend_wanted` is exhaustive over all nine and says why -- a wildcard
  arm is what let the idempotence gate catch netcfgd starting something and
  stopping it on the next reconcile, twice. That is right in a planner where
  every pass that *starts* one exists. Here the supplicant, the access point,
  the tunnels and the router advertisement daemon are started by passes this
  build does not have, so answering "the document does not ask for this" about
  them would stop something netcfgd never started and start nothing in its
  place. It is the Rust's own excuse for `WireGuard` and `Dns` -- "not started
  by the planner, so not stopped by it either" -- applied to the kinds this
  port has not reached, and each becomes ordinary the day its pass lands.
* **`backend.reload` has no producer in this half.** Its one caller in the Rust
  is the router advertisement daemon being handed new prefixes, which is the
  `advertise` block's pass and is still named by `warn_unported`. The verb is
  in the taxonomy, the executor's answer to it is somebody else's, and nothing
  here emits one.
* **Teardown is four steps, and the backends go between the addresses and the
  links.** Rule 7 is the reverse of dependency order and the Rust says so;
  what the order buys here is specific: stopping a client before withdrawing
  what it installed leaves netcfgd removing a lease's address while the process
  holding it is still there to put it back, and stopping it after the links
  means signalling a process whose interface has already been deleted.
* **Three of `warn_unported`'s arms are gone and three checks moved with
  them.** The `slaac` arm, the DHCP arm, the `delegated` arm, the interface
  `dns` block, the `forwarding` setting, the global `dns` block and the
  hostname policy are each acted on now, so each sentence came out in the same
  change -- a warning that outlives the gap it describes is the other way this
  goes wrong. The shared tests that asserted those sentences moved rather than
  being deleted: `plan_test.c`'s DHCP case now asserts the `backend.start` it
  was waiting for, and `daemon_wifi_test.c`'s asserts `dns.apply`, which is
  exactly what the entry about the two ported activation tests said each would
  become. `cli_test.c`'s column check names a later action id, the plan having
  more in it.
* **`plan_forwarding` has no unreadable-sysctl arm and the port keeps it that
  way.** `plan_privacy` and `plan_accept_ra` both warn and skip where the
  interface exists and the sysctl cannot be read, each saying that an action
  planned before the thing that would make it succeed is a plan that never
  converges; the forwarding pass renders `<unreadable>` into the reason and
  plans the write anyway. It is carried across unchanged because the two halves
  of a port that disagree about a case are worse than a port that disagrees
  with nothing, and it is named here so the divergence is a decision when it is
  taken rather than an omission that was never noticed. The cost is real on the
  machines the other two arms were written for.

* **The per-port VLAN pass is driven from the device list, and that is a
  defect fixed rather than a preference.** The Rust calls
  `plan_bridge_vlans` from `plan_interface_contents`, which walks
  `desired.interfaces` -- so a port carrying `vlans` and **no `interface`
  block** has never had them planned at all. That is the ordinary shape of a
  trunk port: it carries no address and never will, which is the whole reason
  0155 pass 1b made a device with no interface representable in the first
  place. Every one of the Rust's four fixtures gives the port an
  `interface lan1 { config = "null" }`, so nothing was looking. Here the pass
  is called from the device walk, after `ncfg_plan_master` in the same
  iteration, which also puts a port's VLANs after its own enslavement --
  the kernel answers `EOPNOTSUPP` on a device in no bridge, and the Rust's
  `base` never carried that edge either.
* **A kind's endpoints are compared canonically, never as text.** The Rust
  holds `Option<IpAddr>` on both sides and compares them structurally; the C
  holds two strings, and *An address in an explanation is compared
  canonically* above is the same rule for the same reason one layer down. It
  reaches `ncfg_plan_address_equal` rather than `strcmp` for a tunnel's and a
  VXLAN's `local` and `remote`, for a routing rule's `from` and `to`, and for
  every `allowed_ips` prefix of a WireGuard peer. **The model's own readers
  canonicalise, so a document and an observation that arrived as JSON cannot
  express two spellings** -- which is why `plan_kind_test.c` edits the
  observation after reading it, and says so: a producer that assembles the
  struct itself, or a report that keeps the text somebody's shell script
  wrote, is the door this guards.
* **A WireGuard `allowed_ips` entry that will not parse is kept as written
  rather than dropped.** The Rust's `filter_map` drops it, so a peer whose
  prefixes hold something unparsable compares equal to a peer that holds
  none -- and the remedy for a difference that is not seen is a tunnel whose
  routes are silently not narrowed. Kept, sorted with the rest, and compared.
* **A peer comparison that ran out of memory is a difference, not
  agreement.** Rust cannot express the case; here the two comparable lists
  carry a failure flag and an unanswered comparison answers "replace", which
  is the direction that plans work rather than the one that silently skips
  the only action the pass exists for.
* **`wifi.set_profiles` is a pass of its own, driven from the observation's
  backend list.** The Rust reaches it through `plan_backend`, which this
  build does not have: the question it asks is about a supplicant that is
  *running* and holding something other than the document, and that is a fact
  the observation already carries. A radio with no supplicant is the backend
  pass's business either way.
* **An access point whose access control policy moved is reported rather
  than restarted.** `macaddr_acl` cannot be changed over hostapd's control
  socket, so the Rust stops the access point and starts it again; this build
  plans no backend actions at all, and converging the station lists without
  the restart would enforce the new list under the old default -- every
  unlisted station accepted, reported as applied. So it is a sentence naming
  both policies and nothing else, which is the same answer `unknown` already
  gets and for the same reason. `restart_if_identity_changed` is not ported
  for the same reason, and the `access_point` warning says so: an edited
  SSID, band or channel is not noticed by this build.
* **`wifi.associate`, `wifi.disassociate` and `wifi.set_regdom` are
  constructed by nothing, here as in the Rust.** All three are in the
  taxonomy because it is the vocabulary the socket speaks, and
  `crates/netcfgd-plan/src/lib.rs` builds none of them -- so what came across
  is `warn_wifi_device_policy` and `warn_regdom`, which say that a radio's
  `regdom` and `powersave` reach nothing and that an access point's `regdom`
  is the only one that becomes a `country_code`. Porting the ops instead
  would have been inventing behaviour the Rust does not have.
* **A `rule.del` for something only the kernel has is the plan's own.**
  `plan.h` names a routing rule as one of the four values a plan borrows from
  the document, which is right for the rules a document states and impossible
  for one built out of the observation -- so `ncfg_plan_intern_rule` is
  `ncfg_plan_intern_route`'s shape for the same reason, and the document's own
  rules stay borrowed.
* **The offload name table is spelled in the planner, and the second caller
  takes this one.** It is `netcfgd_model::interface::offload_names`, and the
  reader that has to agree with this writer is the observer's `read_offloads`,
  which is not implemented in this build -- so it is beside its only caller,
  with its own comment saying where it goes. Two lists of kernel feature names
  in two places is how a feature comes to be turned on under one spelling and
  read back under another.

* **`netcfgd` starts.** The request dispatcher is written, so the entry above
  about refusing to start by naming `ncfg_daemon_answer_fn` is spent: the
  program resolves its paths, holds a state, installs the observation seam,
  opens its descriptors, binds the control socket, runs the reconcile loop and
  stops on a signal. **The refusal is not replaced by a weaker one** --
  `ncfg_main_netcfgd_refuse` and `ncfg_main_netcfgd_waits_for` are deleted, and
  what kept a test from starting a daemon is now the linker rather than a rule:
  the assembly is a `static` function in `daemon_main.c` with no declaration
  anywhere, so no test can name it, and `main_test.c` still reads its own
  source to refuse a call to the one entry point that can. Both halves are
  sabotaged and both go red.
* **Fourteen of the thirty-two requests are answered and the other eighteen are
  refused by name.** Nothing in `c/src/` encodes a `status`, `plan`,
  `document`, `journal`, `explanation`, `secrets`, `modems`, `profiles`,
  `configs`, `hooks` or `probes` response -- `proto.h` decodes every response
  and encodes none, and each encoder belongs beside the request that produces
  it. So those refuse, and **the refusal names the request and says what is
  missing**, which is what keeps this from being the thing the old refusal
  existed to prevent: an operator reads a bare `error` as a request the daemon
  did not recognise. `ncfg_main_answer_unported` is that table, reachable on
  its own so a test walks all thirty-two rather than the ones somebody wrote
  out, and both directions are checked -- a kind the table calls unported must
  refuse with its own name in the sentence, and a kind it calls answered must
  not reach the arm that admits there is no arm.
* **`apply`, `confirm` and `revert` are refused on the socket for the four
  reasons `ncfg apply` is refused on the command line**, said in one sentence
  rather than four. The same build must not refuse an apply to somebody at a
  terminal and accept one over a socket.
* **The world's four seams share one struct, because that seam has one
  `void *`.** `ncfg_main_world_t` carries the apply lock and the kernel handle
  an executor is, the roots a contention check reads, the subscriber list an
  announcement goes to, and the watchers whose timer a window is armed on.
  Written as four contexts they could not be installed at once --
  `ncfg_reconcile_world_t::context` is shared by every member, and `expiry`
  belongs to the watchers while `executor_open` belongs here, so a daemon would
  have been choosing between arming a window on time and being able to change
  the machine. What the sharing also buys is the ordering below being a
  property of one function rather than a convention two of them keep: giving a
  radio back opens an executor through the very calls the pass uses.
* **Giving a contended radio back asks two questions before it takes the apply
  lock**, where the Rust asks neither. The first is the Rust's own defect
  (10.169): it opens an executor as soon as netcfgd runs any backend at all, so
  every machine it manages takes the global apply lock and a netlink socket
  every five seconds to discover there is nothing to give back, against the
  lock `ncfg apply` waits on (0184). Here `ncfg_contenders_find` answers first.
  The second is this build's: its executor refuses `backend.stop` by name, and
  `ncfg_apply_supported` costs nothing to ask, so the lock is not taken to be
  told that either -- what happens instead is a warning per contender naming
  the remedy, which is the half of this that never needed an executor. The
  proof is a measurement rather than a reading: `world_test.c` holds the apply
  lock itself and asserts the pass still answers, which a pass that opened an
  executor could not.
* **An executor is one at a time, refused by name rather than attempted.**
  `flock` is held by the open file description, so a second `open` in this same
  process conflicts with the first -- the call would wait out the whole
  patience and then report somebody else holding the lock, which is a sentence
  naming the wrong machine.
* **The executor's hooks are collected from the document into a bounded
  array.** `ncfg_kernel_set_hooks` takes a flat list and the document keeps one
  per interface and one per network, so somebody has to join them; without it
  `ncfg_hook_run` refuses every hook for having nothing to check it against,
  which is the safe direction and is also every hook in the configuration
  silently not firing. Past `NCFG_MAIN_HOOKS_MAX` they are counted and said out
  loud rather than dropped.
* **The subscriber list is bounded, its descriptors are non-blocking, and a
  short write drops the subscriber.** The Rust's is a `Vec` pruned only inside
  a broadcast, and a converged machine broadcasts nothing -- which 10.169
  already records. Bounding it matters for the same reason the refusal is an
  answer: `monitor` needs only the `observe` tier, which
  `control { observe = "any" }` opens to every local user. Non-blocking matters
  because the loop writes from the thread that reconciles, so one blocking
  `send` to a client that stopped reading is a daemon that stops correcting
  drift for as long as the client feels like it. And a partial write is a
  dropped subscriber rather than a retry, because what is then on the wire is
  half a line and the next event is read as its tail.
* **The event encoder is in `src/main/` rather than beside `answer.c`.** That
  file holds the three responses the authorization path decides for itself; an
  event is decided by the reconcile pass and written by the seam this directory
  installs, so it lives with the announcement. `world_test.c` round-trips all
  five kinds through `proto.h`'s own decoder rather than against a literal,
  since a literal would agree with this encoder for ever, including about a
  member name the decoder refuses.
* **Nothing hands a subscribed connection to the loop yet, and `monitor` says
  so.** The list, the encoder and the announcement are written and the pass
  announces through them; what is missing is the one step in `server.c` that
  gives the loop a connection's descriptor after a `monitor` passes
  authorization, which is where the Rust does it too. Until then the list is
  always empty, which `daemon.h` already calls an ordinary daemon with no
  monitor attached -- and the refusal `monitor` gets names that gap rather than
  reading as a request the daemon did not recognise.
* **The control policy the sockets are bound under is a copy taken at
  startup.** It has to be: `ncfg_daemon_serve_t` borrows the policies and they
  must outlive the server, while `state->desired` is replaced by every reload,
  so pointing the socket at the document's own block would read freed memory
  the first time somebody wrote in the configuration directory. The Rust clones
  it for the same reason. **What the copy costs is a defect in both** and is
  written up in project.md 10.171: the socket's mode and group are decided once
  and authorization follows the reload, so a widened policy is in force in the
  daemon and unreachable through the file.
* **A remote socket is bound beside the control socket, not under the run
  directory.** The Rust's `with_file_name` says the same thing; spelling it as
  `<run>/remote.sock` would put a second netcfgd's remote socket back in the
  first one's directory, which is the one place it must not write.
* **`netcfgd` will not refuse to start over a configuration that does not
  compile.** The diagnostics are said once and the daemon runs with no desired
  state, which is `ncfg_daemon_state_reload`'s bargain: an operator fixing the
  file gets a working daemon without restarting it, and a typo in a drop-in
  does not take the machine's network manager away.
* **What the assembly is not covered by is named rather than left to be
  assumed.** Every step it is made of is a call taking values and is tested --
  the paths, the policy copy, the world's seams, the hook collection, the
  claims a contention check is made about, the dispatcher, the mailbox, the
  watchers and the round. What no test reaches is the order they are called in,
  the two socket binds and the teardown, because reaching them means starting a
  daemon on the machine the suite is built on. That is the residue, it is one
  `static` function, and it has no name anything can call.

* **Eighteen more kernel-side ops land, and three of them open a socket of
  their own.** The five link-kind blocks, the IPv6 token, the offloads, the
  two bridge VLAN ops, the two WireGuard halves, the two rule ops, the four
  traffic-control ops and the NAT table. The executor holds an **rtnetlink**
  socket, and `netlink.h` says what that means: a generic netlink family id
  resolved on one socket is meaningless on another, and `NETLINK_NETFILTER` is
  a third protocol again. So `wg.set_device`, `wg.set_peers`,
  `link.set_offloads` and `nat.replace` each open what they need and close it
  before the arm returns, rather than every executor carrying two more
  descriptors and two cached family ids whether or not a plan has a WireGuard
  device in it. That is `ncfg_contenders_find`'s lesson pointed the other way:
  a machine with no WireGuard and no NAT now asks the controller nothing, and
  nothing outlives the call. It costs one extra round trip per op on a plan
  that has at most a handful of them.
* **Each op is a builder and a two-line send, and the builders are what the
  tests drive.** `apply_kernel_test.c` opens no socket and sends no byte: it
  walks built messages back with the wire layer and asserts the fields. That is
  `wire_test.c`'s standard and it is not a convenience here -- these ops attach
  shapers to an uplink, install policy routing rules and load private keys, and
  the machine the suite is built on is somebody's workstation.
* **`newlink_of` moved out of `kernel.c` and is the one conversion.** It served
  `link.create` alone and was private there; the five `link.set_*` ops need the
  identical nest, and 0057's sentence about a bridge is true of every kind --
  two encoders for one kind is how the create path and the correct-an-existing
  path come to disagree about what a setting is. It is `ncfg_kernel_newlink_of`
  in `src/apply/kernel_link.c` now, and `create_link` calls it. **This is the
  one edit to `kernel.c` beyond moving cases**, and it is recorded here rather
  than left to be found.
* **The model publishes the three numberings the executor needs, and the key
  decoder.** `ncfg_bond_mode_number`, `ncfg_macvlan_mode_number`,
  `ncfg_tunnel_kind_name` and `ncfg_key_parse`, in `document.h`. `apply.c`'s
  `creatable` says why they may not be written in `src/apply/`: "two lists of
  four numbers in two places is how a mode comes to mean one thing on the way
  out and another on the way back in", and the reader that has to agree with
  this writer is `src/observe/build.c`, which already reads the model's tables.
  So the numbering is published rather than copied. Two of them are not new
  facts either -- a bond's mode number *is* its ordinal, which `build.c`
  already relies on, and a macvlan's is a flag bit -- and this is where that is
  written down once and bounded. `ncfg_key_parse` is the base64 reader
  `document.c` already had privately: a private key arrives as text from
  `secrets.h` while a public key arrives as JSON, and two readers of one format
  is how the two halves of one program come to disagree about a key.
  **`creatable`'s refusal for a macvlan and a tunnel now names a reason that
  has stopped being true** -- nothing plans either, so the gate is still right
  and its sentence is stale; that arm belongs to whoever owns `apply.c` next.
  A VLAN's ethertype is deliberately *not* published, `link.set_vlan` not being
  an op and nothing else needing it.
* **`ncfg_netlink_reply_t` carries the errno the kernel refused with.**
  `ncfg_netlink_fail` renders one string out of `strerror`, a name and a
  clause, and reading a decision back out of the words of a message is what
  `config.h` forbids by name -- so the number survives beside the sentence
  rather than instead of it. It is set by `ncfg_netlink_collect_batch` and by
  nothing else, because the batch path is the one an executor sends through.
* **Idempotence is a list of errnos, and it is a value rather than a habit.**
  `plan.h` asks that applying a plan twice produce an empty second plan, and
  the executor's half of that is that the same op sent twice succeeds twice.
  Most of these are idempotent by construction -- an attribute set is a set,
  `NLM_F_REPLACE` replaces, a table is replaced whole -- and five are not:
  `EEXIST` for a rule already installed and for an ingress hook already there,
  `ENOENT` for a rule, a bridge VLAN, a root qdisc or an ingress hook already
  gone. `ncfg_kernel_tolerates` is the single place any of that is compared,
  so the test enumerates it; what it refuses is the general form, since
  forgiving `EEXIST` everywhere would turn a `link.create` racing another
  daemon into a silent success. The Rust forgives three of the five, each at
  its own call site, and has no arm for a rule already installed or a bridge
  VLAN already off the port.
* **What an errno means *for an op* is a value too.** `ncfg_kernel_hint` is
  the clause `netlink.h`'s general sentence cannot carry -- the bridge with no
  VLAN filtering, the scheduler whose module would not load, the missing
  `cls_matchall`, the four preconditions behind a token's bare `EINVAL`. A
  value rather than a `format!` per arm, so that the reading cannot be
  attached to one half of a pair and not the other.
* **A rule selector written without a prefix length is a host selector.** `ip
  rule from 10.0.0.5` means `/32` and `kernel.c`'s `route_of` already reads a
  route destination that way. The Rust's `parse_cidr` requires the slash, so
  `from = "10.0.0.5"` compiles, plans, and fails the apply -- see the defect
  reported with this wave.
* **A selector of the other family is refused by name, and so is a firewall
  mask with no mark.** The kernel takes a rule's family from the message
  header and reads the selector as that many bytes, so a mismatch is `EINVAL`
  naming nothing; and a mask applied before the comparison, with no mark beside
  it, selects packets marked zero. Neither is checked in the Rust. Both are
  configuration mistakes somebody can fix in a second once told.
* **The executor takes the document it is applying, and where secrets live.**
  Six ops carry a device's name and nothing else, because what they change is
  the document's and a plan that carried it would put a WireGuard key
  reference, every peer's public key and every allowed prefix into
  `plan.last.json`. `ncfg_kernel_set_document` is that, borrowed on
  `ncfg_kernel_set_hooks`' terms -- and **without one those six refuse by
  name** rather than configuring a bridge from an empty block, which would be
  every setting at the kernel's default reported as a successful apply.
  `ncfg_kernel_set_secrets` is a setter rather than an environment variable
  for `contention.h`'s reason: a test that forgets a variable reads the
  developer's real secrets directory, and one that forgets an argument does not
  compile.
* **`wg.set_device` refuses a private key reference the document does not
  name.** The op carries the reference's *name* and the document carries its
  provider, so both are needed; a document naming another is a plan built from
  another document, and for a WireGuard device the wrong key is a tunnel that
  comes up to the wrong peer rather than one that fails. The Rust reads the
  whole configuration from the document and never compares the two.
* **The executor declares which of its ops undoes which.** The inverse a revert
  replays is the plan's and that does not change; what `ncfg_kernel_inverse_kind`
  adds is the other half of the same sentence -- an op this build carries out
  whose inverse it could not carry out is a change that cannot be taken back,
  at the one moment that matters. The test walks the list against
  `ncfg_apply_supported`. Six of the eighteen declare none, and that is not a
  gap: they replace a *value*, so undoing one means re-stating what was there
  before, which only the previous document holds -- `apply.h`'s "a declared
  inverse carries the value it replaced". `qdisc.reset` is the inverse of
  `qdisc.set` and deliberately not the other way round.
* **`apply_test.c`'s list of what this build executes is now wrong for both
  halves of the executor, and neither worker changed it.** That file is shared
  and says so; its `executed[]` table still names fifteen ops, against a build
  that carries out forty-four. The two checks it fails name every op that
  moved, which is the arrangement working -- "nothing is silently ignored" is a
  property the table exists to pin, and a table nobody updates is the one thing
  that could let an op move without being noticed.

* **A created link wears `NCFG_OBSERVE_ALTNAME_PREFIX`, and the prefix is read
  from `observe.h` rather than written again.** That header asked for exactly
  this in as many words, and the reason is the one failure the whole mechanism
  has: netcfgd stamping one spelling and reading back another makes every link
  it creates foreign to it, for ever. The marking is built in `kernel_link.c`
  and sent by `create_link` after the acknowledgement and never before it -- a
  mark on a link the kernel refused to create would be aimed at whatever else
  holds the name. A refusal is a **warning and not a failed create**, which is
  the Rust's arrangement and its reason: an alternative name shares the lookup
  namespace with a real one, so `EEXIST` is possible, and a kernel too old for
  `RTM_NEWLINKPROP` refuses it outright. Neither is a reason to fail a link
  that was made perfectly well, and `ncfg_observe_link_ownership` is additive
  -- a recorded link with no marker is still ours.
* **The fold into `owned.json` takes the plan and the journal, not an effect
  list.** The Rust accumulates an `Effects` struct inside `KernelExecutor` and
  the daemon calls `OwnedState::absorb` on it. Here the effect of an action
  **is** the action: every member of that struct this record can carry is a
  pure function of the op that produced it. So there is no second aggregate to
  build, free and keep in step -- and, which is the point, the fold is driven
  through `ncfg_executor_t` like everything else and is checked against the
  recorder with no socket, no privilege and no interface. An accumulator inside
  the real executor would put the one piece of bookkeeping that decides what
  netcfgd may later delete behind a live netlink socket. This closes the two
  entries above that deferred it -- *`plan.last.json` and the fold into
  `owned.json` are deferred here as they are for the revert path* -- for the
  fold; the journal writer is still deferred and is now the whole of it.
* **A revert is recorded by reading the outcome, not by watching the executor.**
  `ncfg_apply_record` folds the **inverse** for every record
  `ncfg_apply_revert` marked `NCFG_OUTCOME_REVERTED`, so the claim leaves with
  the object; a record whose inverse failed stays `done` and is folded again,
  which is the honest answer, that change being still in effect. **The Rust
  reaches the same answer by a different route and it was checked rather than
  assumed**: its revert runs the inverses through the very executor it absorbs
  afterwards, so their removals are already in the effect list. What made the
  route matter here is that `ncfg_apply_revert` is a library call taking a
  plan, a journal and an executor -- no run directory, no effects -- which is
  precisely why 0263 deferred the fold on that path above. Folding one journal
  twice is therefore deliberate and safe, every rule replacing or removing
  before it adds.
* **Removals are not hoisted before additions; the plan's order is the order.**
  `OwnedState::absorb` applies every removal first "so that replacing an
  address in one plan leaves exactly one record, not zero", which is a
  correction for having lost the order on the way into the effect list --
  and it inverts the one case it does not cover: an apply that added an object
  and then removed it ends with the record claiming it. Folding the actions in
  plan order needs no correction and has no such case, the plan order being the
  execution order. Not reported as a defect in the Rust: nothing in that
  planner emits the pair, so it is a shape rather than a reproduction.
* **A hook's state is recorded because the hook ran.** The Rust pushes the
  effect *before* running it, so a script it refused to run -- a content hash
  that did not match the approved one -- is recorded as having been told, and
  the event is silently lost. Here a refusal is a failed action and folds
  nothing. The case the Rust's own comment is about, an event hook retried on
  every reconcile for ever, is closed either way: a hook that ran and exited
  non-zero is `NCFG_HOOK_NOTED`, which is a successful action.
* **What an apply saw is not folded, only what it did.** `observed_running` is
  the one member of `Effects` that is not an effect at all -- it is what the
  *observation* found running, and it is what clears a backend's restart count
  (0079). A start and a stop are folded here; the clearing belongs to whoever
  composes the observation and is named rather than quietly missing.
  `applied_dns` has nowhere to go for the reason `state.h` already gives: the
  DNS scopes and the backends are deferred in this build because their element
  types are the observed model's and its field tables are static.
* **The fold happens under the apply lock, before the executor is closed.**
  `ncfg_owned_update` takes `owned.lock` of its own, so the file cannot be
  interleaved either way; the apply lock is what makes the read, the change and
  the write describe one machine rather than two applies' worth of it. A plan
  with an empty journal does not enter `ncfg_owned_update` at all, so a pass
  that changed nothing does not rewrite a file another writer is in the middle
  of.
* **`netcfgd` still will not start, and the reason is no longer ownership.**
  Both facts the guard named are closed and `ncfg_main_netcfgd_may_reconcile`
  still answers 0. What is left is underneath it and is not `src/main/`'s: the
  planner holds ten kinds of configuration block and warns per block rather
  than acting (`warn_unported` in `src/plan/build.c` is the list); an op this
  executor cannot carry out is refused **while the plan is running**, so a plan
  mixing one with a supported op changes the machine and stops halfway; and
  `plan.last.json` is still not written, so a plan that stopped halfway leaves
  nothing under `/run` saying where. **That third fact is closed too**, by
  `ncfg_apply_write_journal`; what is left is the planner's ten blocks and the
  mid-plan refusal, and `daemon_answer.c`'s refusal on the socket says two
  things now rather than three. `main_test.c` asserts the closed facts
  closed and the executor's mid-plan refusal still true, so the check moves
  with the sentence in both directions -- the version before it grepped
  `kernel_link.c` for an alternative name, and `create_link` has never been in
  that file, so it could not have gone red however the marking landed.

* **A recorded position's file name comes from beside the span, never out of
  it.** *Spans carry no source id*, above, is what forces this: the Rust asks
  `sources.name(span.source)` and the C has no such member to ask. What it has
  instead is the name merge already put beside every item and every block, so
  `ncfg_record` **takes the name as an argument** rather than reading the
  lowering context's. That is not fussiness: `ctx->source` is a *moving*
  variable, reassigned per item as a block is walked, so a record taken after
  the walk would name whichever file the block's last item came from. Today
  those are the same file for every block but `global`, which records nothing
  -- so the explicit argument is a hazard closed before it is reachable rather
  than a defect fixed, and the sabotage that swapped it back caught nothing and
  is reported as having caught nothing.
* **The key is spelled at the site that records it, not through a helper.**
  The Rust has `interface_path` and `field_path`, which return `String`s; the
  C equivalent would allocate for every field of every compile to produce a
  string used once. `ncfg_record`'s format argument *is* the helper, and what
  holds the eleven sites to one spelling is a test that asserts each key
  literally against a compiled fixture -- the consumer's spellings, taken from
  `explain.c` rather than from memory. A key spelled differently is the one
  failure `explain` cannot see: every lookup misses while the table is
  non-empty, so the notice is correctly silent and no fact names a file.
* **`Provenance::under` is not ported.** The Rust's prefix iterator exists for
  "explaining a whole interface at once" and nothing in either program calls
  it. A lookup this port has no caller for is a second thing that has to go on
  agreeing with the writer.
* **The table is bounded at `NCFG_PROVENANCE_MAX`, and there is no count past
  it.** The parser's arrangement applied to the other list a compile produces,
  and for the same reason: its length is chosen by whoever writes the
  configuration directory, and a daemon re-reads that directory whenever
  anything in it changes. What is deliberately missing is the `total` that
  `NCFG_DIAGS_MAX` and `NCFG_DRIFT_MAX` carry beside them -- the count would
  have to live in `ncfg_provenance_t`, whose members are the members of
  `provenance.json`, and adding one would be a second definition of a file
  format this port reads whoever wrote it. A caller that wants to know compares
  `count` against the bound. What a short table costs is a gap per field, which
  is the state `explain` is already written and tested for.
* **A key too long to build is not recorded at all.** Not truncated, which
  would put a path in the table that belongs to no field and looks exactly like
  a field nobody wrote. It is reachable: a `rule` label is the operator's text
  and `rule.<id>` is as long as that label.
* **A refused compile hands back an empty table, not a partial one.** The Rust
  returns `Err` and the half-filled `Provenance` is dropped with the stack
  frame; in C the table is the caller's own structure and survives the call, so
  emptying it is a step rather than a consequence. It is not a nicety: the
  caller that asks for one is the caller that writes `provenance.json` beside a
  document, and a table of paths into a document nobody got would be read
  against the document from the compile before it.
* **`ncfg explain` is still not wired, and `run.c`'s stub still says the table
  is empty because nothing fills one in.** That sentence has stopped being
  true. `src/cli/` belongs to another worker in this wave; the correction is
  one comment and is named here rather than taken.

* **`--json` prints the payload and never the response envelope**, at every
  verb that renders something. *The port links* above counts `--json` among
  what was not ported when the binary was first measured, and `run.c` refused
  the flag at six verbs by name; both were true because there was no writer
  for a protocol answer. There is one now (`src/cli/json.c`), and the size
  entry stands as the measurement it was rather than being edited. What the
  writer writes is the members the control socket
  carries beside its `"response"` tag with the tag left off. The tag cannot be
  universal: `ncfg status --json` and `ncfg plan --json` are computed here
  rather than received, and their shapes are already frozen as
  `doc/schema/observed.json` and `doc/schema/plan.json`, neither of which has
  a `"response"` member. Tagging only the socket-answered verbs would be two
  rules for one flag. So there is none anywhere, and `cli_test.c` proves the
  agreement the other way round: each `{"response":...}` line of
  `doc/schema/socket.json` is decoded by `proto.h`, written back by the CLI's
  writer and compared against that same line with its tag cut off
  mechanically. A member renamed at either end is red.
* **The radios and the modems keep the object the socket wraps them in.** The
  Rust prints `serde_json::to_string(&radios)` and `(&modems)` -- bare arrays
  -- while printing an object for the scan, the radio status and the station
  list, which is `Response`'s wrapper surviving in three places and not in
  two. A bare array cannot grow a fact beside it, and `wifi_scan` already
  carries `stale` beside its list. One shape for all five is also one thing
  for a caller to learn.
* **A verb whose whole answer is `ok` prints `{"ok":true}`.** The payload rule
  above would make it `{}`, `{"response":"ok"}` carrying nothing beside its
  tag, which tells a script nothing the exit status had not. `ok` is the
  protocol's own word for the fact -- a `reloaded` event spells it exactly so.
  This covers `wifi activate`, `deactivate`, `connect`, `disconnect`,
  `reload`, `confirm` and `revert`; **the Rust prints its human sentence for
  all seven and ignores the flag**, which is the fault the six refusals in
  `run.c` existed to prevent, arriving through the verbs nobody had looked at.
  The last three were not among those six and were ignoring it here too.
* **`ncfg explain --json` carries `total` beside its facts.** The socket's
  `explanation` response is `{"subject", "facts"}` and the Rust's
  `Explanation` has no bound to report; this port's is bounded at
  `NCFG_EXPLAIN_FACTS_MAX` and the text form ends with "showing 256 of 1202"
  when it bites. A machine-readable form that dropped the count would be the
  one place `--json` says less than the table, which is what the flag exists
  to avoid. It is written always rather than only when the bound bites, so a
  reader compares it against the length of `facts` instead of having to know
  the member is sometimes absent. It is an addition to a shape `proto.h`
  reads strictly, so it is said here: an `explanation` **response** is
  unchanged and still carries neither.
* **`ncfg monitor --json` prints the line the daemon sent, decoded by
  nobody.** The one `--json` in this program that switches a rendering off
  rather than a writer on, and the Rust's own arrangement for the same reason:
  an event is already one JSON value on a line. Re-composing one from
  `ncfg_proto_event_t` would drop every member this build has never heard of,
  on the one verb whose whole argument for existing is that it does not
  swallow what it cannot name -- so the line is not even parsed first.
* **A name that is not valid UTF-8 fails the command rather than the
  program.** *The JSON writer refuses a string that is not valid UTF-8*, above,
  says what the writer does; this is what a CLI does with that refusal. It is
  reachable rather than theoretical: the JSON *reader* does not check a
  string's bytes, so a stray octet inside a `name` or a `configured` travels
  from a daemon into a decoded answer intact, and `ncfg explain`'s subject
  comes straight off `argv`. Nothing at all is printed -- `ncfg_buf_t` hands
  out the empty string for a buffer that failed, so a caller that printed
  anyway would emit half an object that looks whole -- and the sentence names
  the rule and points at the same command without the flag, which has no such
  rule because a table is text for a terminal. Driven end to end in
  `cli_test.c` against a fake daemon whose answer carries the octet.
* **`ncfg plan --json` prints the plan and neither note under it.** The
  empty-configuration note and the contention warning are sentences addressed
  to a person and are facts about the machine rather than members of the plan;
  printing them beside the document would put two lines that are not JSON on a
  stream that promised to be one value. The Rust skips them here too, which is
  the one place its `--json` handling is what this port would have chosen.
* **The subcommands that write still ignore `--json`, in both programs.**
  `ncfg wifi add`, `wifi forget`, `reset`, `control`, `config`, `profile` and
  `secret` each answer 1 or 0 and print their own sentences as they go, so the
  flag cannot be closed at the dispatch the way the seven `ok` verbs were --
  `say_json_ok` after one of them would print prose and then a document. It is
  named here rather than left as a gap somebody rediscovers: what it needs is
  the human lines behind the same test inside each writer, which is those
  files' work and not `run.c`'s. The Rust is in exactly this state and has
  been since the flag existed.
* **`ncfg show` takes no `--json` and never did.** It prints the document
  canonically whatever is passed, in both programs, because the document *is*
  the answer -- `doc/schema/document.json` is that output. Named here so that
  a reader counting the verbs that honour the flag does not read its absence
  as the omission the entries above are closing.

* **The `network` block writer is one module with two callers, and
  `ncfg_wifi_install_fn` has an implementation.** This record named the gap
  twice -- once as the seam the daemon's `wifi_add` handler was given because
  `netcfgd_host::wifi_profile` was not ported, and once as the reason `ncfg
  wifi add` and `ncfg wifi forget` were refusals. `wifi_profile.h` is that
  module, `ncfg_wifi_profile_installer` is the seam's one implementation, and
  the profile type is `daemon.h`'s rather than a second spelling of the same
  fields. The seam stays a seam: `daemon.h` may not depend on the host module,
  and a test of what a request is allowed to say should not have to write a
  file to reach it.
* **The round trip after an install compares every field the block can carry.**
  The Rust compares whether the network is there, whether it is secured, and
  the five enterprise fields -- while its own comment says the check covers "an
  SSID whose hex form did not round-trip", which nothing in it reads. The
  hidden flag, the metric, the WPA generation and which credential the block
  refers to are compared by nothing. Here all of them are, so the install *is*
  the comparison 10.160 found missing one layer up, and sabotaging any one
  rendered key turns a success into a refusal naming that field.
* **The install verifies through the loader that reads the selected profile.**
  `install_drop_in` was fixed to do that and this second writer of the same
  directory was not, so on a profiled machine the Rust checks a configuration
  the machine does not load. Both use the profiled loader here.
* **A credential carrying a NUL is refused, and so is an empty one.** Nothing
  downstream can carry a NUL -- the supplicant's control socket is lines,
  hostapd's file is lines, and anything treating the value as a C string stores
  the part before it, silently. Rust's `&str` may hold one and only the PSK
  path looks. The empty case is `ncfg_secret_store_put`'s rule applied at the
  other door into the same directory.
* **`ncfg wifi add` loads the configuration once.** The Rust loads it twice --
  `current` reads the layered sources to ask whether there is anything at all,
  then `compile` reads them again with the profile -- so the question "is there
  a configuration" is answered against a different source set from the one the
  answer is built from. One walk cannot disagree with itself.
* **`ncfg reset` compares its two directories resolved, not as text.** The
  Rust's `PathBuf` comparison is component-wise, which sees a trailing slash
  through and nothing else; a symlink walks straight past it, and the run that
  does removes the factory layer and then reports those same files as the ones
  that remain. Measured. Where a name does not resolve it is compared as it
  stands, which is right for the only case that produces: a directory that is
  not there has no files to delete and none to protect.
* **`ncfg reset` refuses an argument rather than ignoring one.** The Rust's
  dispatch drops every positional here, so `ncfg reset office --yes` empties
  the writable layer and says nothing about the word it did not understand.
  Measured. This is the wrong verb to be relaxed about an argument nobody can
  act on.
* **`ncfg reset` says `would remove` before, and `removed` after.** The Rust
  prints the whole list under the word `removed` and *then* runs the loop that
  removes, which stops at the first failure -- so a reset that could not finish
  has already told the operator that every file is gone, with the one that
  stopped it named in a sentence underneath a list saying otherwise. Measured:
  the base file gone, both drop-ins left, and three lines claiming all three.
  Here the whole list is `would remove` in both modes, because at that point
  nothing has been, and each `removed` line is printed once that file is
  actually gone; a failure names the path, the kernel's reason, and how many of
  how many had already gone. **The root case is not covered by a test and says
  so in the test rather than being counted**: `unlink` is not stopped by a
  directory's mode for this process, so a suite running as root cannot drive
  it.
* **`ncfg reset` counts the credentials that outlive it.** The Rust removes
  `writable_files` and nothing else, so the credential store survives whole
  while everything that referred to it goes -- which is the fault a credential
  listing exists to surface, manufactured by the one verb that empties the
  configuration. Not removing them is right (0042) and saying nothing is not,
  so the count and the directory are printed. Its note also says "the next
  reconcile or apply" where the Rust says "the next apply": a machine whose
  `on_drift` is `reconcile` does not wait to be asked.
* **`not_in_this_wave` and `NEEDS_WRITERS` are gone from `run.c`.** These three
  verbs were their last callers. That is what `NEEDS_OBSERVER` did before them
  and for the reason written there -- a refusal naming a module that is present
  is worse than one naming a module that is absent, because it looks right --
  and the next verb to need one writes the sentence it needs.

* **A `monitor` is handed over, and the entry above saying nothing hands one
  over is spent.** `server.c` takes `NCFG_PROTO_REQ_MONITOR` after the
  authorization gate and before anything else, exactly as it takes `hello`, and
  the reason is structural rather than a preference: `ncfg_daemon_answer_fn` is
  given a request and a buffer and **no descriptor**, so there is nothing it
  could hand over. That is why the Rust special-cases `monitor` in its server
  too, beside the loop it gives the stream to, rather than in the dispatcher
  behind it. The seam is `ncfg_daemon_stream_fn`, a second member of
  `ncfg_daemon_serve_t` sharing the one `context` -- two contexts would be two
  implementations of the daemon's state with nothing keeping them in step, and
  the Rust sends a request and a subscription down the same channel for the
  same reason. `ncfg_main_answer_unported` keeps a row for `monitor`, now
  `hello`'s row one step further out: reaching the dispatcher with one is a bug
  in the server.
* **The subscription crosses to the loop through the mailbox, which is what
  makes "the subscriber list holds no lock" true.** That claim was already
  written in `loop_internal.h` and was worth nothing while nothing added a
  subscriber: the list is only safe unlocked because every call on it -- the
  pass announcing through it and this one adding to it -- happens on the loop's
  thread. So `ncfg_main_mailbox_stream` parks the connection's thread exactly as
  a request does and the descriptor is handed to the seam from inside
  `ncfg_main_mailbox_settle`. A waiting subscription carries **no request**, so
  `ncfg_main_mailbox_take` never puts one in the array the pass reads; and a
  slot not in use holds `stream_fd` of -1 rather than 0, because zero is a
  descriptor and a request slot misread as a stream would subscribe this
  process' standard input. It settles **after** the pass rather than before,
  which is the Rust's order and the right one: a client that asks to watch is
  told what happens next, not about a pass that was already running when it
  asked.
* **What is handed over is a `dup`, and the connection thread then ends rather
  than parking on the connection.** The sketch this was written from said park;
  three things say otherwise and the first decides it. `ncfg_main_subscribers_add`
  puts the descriptor in non-blocking mode -- it must, the loop writing events
  from the thread that reconciles -- and `O_NONBLOCK` belongs to the open file
  description, which a `dup` *shares*: a parked `recv` on the connection would
  return `EAGAIN` at once, for ever, which is a thread spinning at 100% CPU for
  as long as somebody is watching. Second, a parked thread holds one of
  `NCFG_DAEMON_MAX_CONNECTIONS` for the life of a stream measured in hours.
  Third, there is nothing worth learning from that side: end of stream on the
  read half is **not** proof the client has gone, since a client may
  `shutdown(SHUT_WR)` once it has asked and go on reading for hours -- so the
  only reliable signal that a subscriber is gone is a write that fails, and that
  belongs to whoever writes. The copy is what makes the hand-over unambiguous:
  each side closes exactly what it opened, where handing over the connection's
  own number would have two owners closing one descriptor, which is how a daemon
  comes to write one client's events into another client's socket.
* **A hand-over that is refused leaves the descriptor with the caller**, which
  is `ncfg_main_subscribers_add`'s rule carried up through two layers: the seam
  answers 0 with a sentence, the server closes its copy and sends that sentence
  back as an `error`, and the connection goes on serving -- a refusal being an
  answer. A refusal that had closed the copy *and* left the seam holding the
  number is the double close this whole arrangement exists to avoid, so both
  halves are checked, including that a refused `monitor` leaks no descriptor.
* **The Rust's monitor thread holds a connection slot until something is
  announced, and this one does not.** The defect is reported in project.md
  10.176 and the divergence is the shape that avoids it: `handle` blocks in
  `for event in incoming` for the life of the stream, so a client that
  subscribes and hangs up holds one of sixty-four slots until the next
  broadcast -- which on a converged machine never comes. Here the slot goes back
  the moment the descriptor is handed over, and what a dead subscriber costs is
  one entry in a list bounded at `NCFG_MAIN_SUBSCRIBERS_MAX` rather than a share
  of the control socket. **What is left is named rather than claimed away**: a
  hung-up subscriber is still only found by the write that fails, so on a
  machine that announces nothing at all up to sixteen dead streams can sit in
  the list and the seventeenth `monitor` is refused -- bounded, and with a
  sentence saying so, where the Rust's is a `Vec` with no bound and says
  nothing. Closing that last gap means the loop watching the subscriber
  descriptors for `POLLHUP`, which is a `prune` in `daemon_world.c` and belongs
  to whoever owns that file next. **It is closed**, and the entries below say
  what the sweep decides with and why that is not what a source is judged by.

* **A tun is created, and `tun.h`'s mode enum is the model's rather than its
  own.** `ncfg_apply_supported` says a `tun` can be created again and
  `create_link` takes the kind before it builds anything, handing a tun to
  `ncfg_tun_create` rather than to `ncfg_kernel_newlink_of` -- which refuses
  one and always will, there being no `RTM_NEWLINK` for a device that comes
  from an ioctl. The planner followed without being touched, because
  `src/plan/link.c` asks the executor rather than keeping a list; that is now
  a check rather than a claim.

  **What the wiring found is that the two halves could never have been
  compiled together.** `tun.h` declared its own `ncfg_tun_mode_t`, with the
  same two enumerators and the same two values as `document.h`'s, and C makes
  a repeated enumerator a redeclaration rather than a redefinition -- so any
  translation unit including both failed to compile. Nothing did: `tun.c` and
  `tun_test.c` include `tun.h` alone, so the module built, its tests passed,
  and the clash was invisible for exactly as long as nothing called the module
  from anywhere the model was in scope. The model keeps the numbering, as it
  does for a bond's mode and a tunnel's kind word, and `tun.h` includes
  `document.h` for it -- which `ops.h` and `wg.h` already do from the same
  layer.

  **The conversion is a builder, and the owner and the group are why.** The
  document names a user and a group and the kernel wants a uid and a gid, so
  `ncfg_kernel_tun_spec_of` in `kernel_link.c` is where that happens, beside
  the one netlink conversion and for its reason. The lookup is
  `ncfg_peer_user_id`/`ncfg_peer_group_id` -- `daemon.h`'s, read out of
  `/etc/passwd` and `/etc/group` as files rather than through NSS -- which
  makes `src/apply/` include `daemon.h` for two functions. That is upward and
  is recorded rather than hidden; the alternative was a second reader of those
  two files in this directory, which is the duplication every other comment in
  it refuses. Both paths take the file as an argument, so the conversion is
  checked against a passwd and a group file a test wrote, on a machine where
  the names need not exist.

  **A tun this build creates wears the alternative name**, which is the one
  place this deliberately does not copy the Rust: its `Op::LinkCreate` returns
  from the tun arm twenty lines above the block that marks a created link, so
  the one kind whose ownership most needs the kernel's mark is the one kind
  without it (project.md 10.173). `create_tun` calls `mark_as_ours` exactly as
  the netlink path does, after the device exists and never before.

  **What is not tested, and cannot be here:** that a device actually appears.
  Making one needs `CAP_NET_ADMIN` and `/dev/net/tun`, and this suite runs on
  the machine netcfgd would configure -- a persistent tap left behind by a test
  is a device on somebody's workstation that only `ip link delete` removes. So
  `tun_test.c`'s arrangement is taken one layer up: the spec the executor built
  is handed to `ncfg_tun_create` with an ordinary file as the clone device, the
  open succeeds, `TUNSETIFF` answers `ENOTTY`, and what is asserted is that the
  refusal names the device -- which is the seam joining up, with the ioctls'
  order still `tun_test.c`'s subject and still asserted as a value.

* **`plan.last.json` is written, under `owned.lock`, and an empty journal is
  written too.** `ncfg_apply_write_journal` is the writer and `src/apply/` is
  its home, because the type is that module's -- `state.h` said so while
  deferring it and says where it went now. Three divergences from the Rust,
  each small and each deliberate:

  * **The lock.** The Rust's writer is an atomic rename and nothing else, so
    `plan.last.json` and `owned.json` can be replaced in either order by the
    two processes that write both. They are two halves of one statement about
    one apply, and a reader that finds a journal claiming a link was created
    beside a record that does not claim it has been handed two applies' worth
    of machine. The critical section is a render and a rename, which is what
    `ncfg_owned_update` already pays. The cost is a rule: this may not be
    called from inside that function's change callback, `flock` being held by
    the open file description, so every caller does the pair in sequence.
  * **An empty journal is written**, where the fold beside it deliberately
    writes nothing. Not an inconsistency: the record is a claim that
    accumulates and must not be rewritten by a pass that changed nothing,
    while this file answers a question about the *last* apply -- and "it did
    nothing" is that answer. A file left behind from an earlier apply would be
    read as this one's.
  * **A failure is reported to the caller**, which is the Rust's silent
    `let _ =` in all three of its daemon call sites and is a defect reported
    with this wave. Both C callers log a note and carry on, which is
    `state.h`'s bargain about a derived directory -- but they are told.

  **It is checked through the pass rather than only at the call.**
  `reconcile_test.c` drives a real reconcile over a run directory of its own
  with an executor that is a double, and reads the file back: once where the
  action stood, and once where the double refused it, so the failed outcome and
  the executor's own sentence are asserted to be in the file rather than only
  in the log. That is the case the file exists for -- a reconcile has no
  terminal, so an apply that stopped at its third action has nowhere else to
  say so.

* **A dead subscriber is swept once a round, and what a `revents` means for a
  stream is not what it means for a source.** `ncfg_main_subscribers_prune`
  closes the gap the entry above named: pruning used to happen only inside a
  broadcast, and a converged machine broadcasts nothing, so sixteen streams
  whose clients had gone could hold every place in the list and refuse the
  seventeenth `monitor`.

  **The decision is a value in `daemon_wake.c`** like every other reading of a
  `revents` in this program, and it is a *second* one rather than a reuse of
  `ncfg_main_readiness` -- which is the whole of what is interesting here.
  That function puts `POLLIN` ahead of `POLLHUP` because a source is drained by
  whoever owns it and its last records must not go with the hang-up. Nothing
  drains a subscriber: it is written to and never read. A client that closed
  leaves `POLLIN|POLLHUP` set together and set for ever, so borrowing the
  source's reading would keep exactly the descriptors the sweep exists to drop.
  `ncfg_main_subscriber_ended` answers on `POLLHUP|POLLERR|POLLNVAL` and reads
  a readable-only stream as a client being rude rather than a client leaving.
  Both readings of `POLLIN|POLLHUP` are asserted side by side, because the
  difference is the entire reason there are two functions.

  **The sweep asks `poll` about its own descriptors with a zero timeout rather
  than joining the loop's wait**, and the reason is what a subscriber is: it
  has no drain, no kind and no place in the source set, so putting sixteen of
  them into `ncfg_main_round`'s set would make the daemon wake for a hang-up it
  can do nothing about beyond dropping. What that costs is named rather than
  claimed away: a dead stream is carried for at most one tick
  (`NCFG_MAIN_TICK_MS`) instead of until the next event, which on the machine
  this is about was never. The call is made after the mailbox is emptied and
  before the pass, so a `monitor` that arrived this round is swept with
  everything else and an event is not written to a descriptor already known to
  be gone.

* **A report's addresses and routes are compared as addresses, never as text --
  and that includes a route's destination, where the Rust canonicalises only
  the next hop.** `reported` is the one addressing source whose value went
  through no compiler: every other address netcfgd installs came through
  `canonical_address` and already reads the way the kernel prints it, while a
  report is the text somebody's shell script produced. project.md 10.169
  measures what `strcmp` costs there against the shipped Rust -- an `addr.add`
  planned for an address the kernel is already holding, and, because the
  address is netcfgd's, an `addr.del` for it in the same plan, on every
  reconcile, for ever, each half succeeding.

  So `ncfg_plan_address_equal` is what the forward pass and the teardown both
  ask, and a reported gateway and a reported route's destination are
  canonicalised as they are synthesised. The next hop is the Rust's own
  behaviour by accident -- it parses to `IpAddr` and renders through `Display`
  -- and **the destination is not**: `normalize_destination` maps the three
  spellings of a default route to `default` and hands everything else back as
  written, so a VPN pushing `2001:0DB8:2::/64` is a route the kernel reports as
  `2001:db8:2::/64` and the comparison never matches. Reported with this wave.
  `ipv6_token` is compared the same way and is *not* a divergence: the Rust
  parses both sides there and says why.

  Two further consequences, each the removal of something rather than an
  addition. The teardown no longer declines to answer for an interface that
  takes a `reported` source -- it used to warn that nothing of netcfgd's would
  be withdrawn from such an interface, which was honest while the report was
  unread and is a lie now that it is read. And `ncfg_plan_routes_for` is the
  one function both directions ask for an interface's routes, which is the
  Rust's `routes_for` and its reason: two answers to "which routes does this
  interface want" is a plan that installs a route and deletes it on alternate
  reconciles.

* **`warn_block`'s sentence has gone, with the last three arms that made it.**
  The planner had two shapes of warning for a block it was holding:
  `warn_block`, which said "this build of the planner does not act on it", and
  `warn_unbuilt`, which says nothing acts on it in either language. The first
  is a promise that a later release will, and `reported`, `nat` and
  `ipv6_token` were the last three blocks it was made about. With those ported
  the function had no callers, which is a warning at the full set and an
  invitation for the next arm to reach for a promise nobody has checked -- so
  it is gone, and a block that is a real port gap now gets a sentence naming
  what is missing, in the arm itself, where a reader can check it against the
  pass that will fill it.

* **`takes_reports` is `plan.h`'s now, and `explain.c` calls it.** An earlier
  entry records it as one of two rules spelled a second time in `explain.c`,
  each because this port had one caller for it so far, and says the second
  caller takes that one rather than writing a third. The condition it named has
  ended: the planner no longer holds `reported` addressing, it acts on it, so
  the rule has two callers and one definition. `derive_from_delegation` went
  the same way a wave earlier and `explain.c`'s header no longer claims either.

  This is the arrangement the Rust has, and its reason is worth restating
  because it is not tidiness: `netcfgd-plan` makes the rule `pub` so that the
  explanation and the planner cannot disagree about which reports are believed.
  An operator asking why a route is there would otherwise be told the
  configuration does not ask for it, about a route netcfgd installed itself.

* **`--json` is answered at the seven verbs that write, which the entry above
  said still ignored it.** *The subcommands that write still ignore `--json`,
  in both programs* has stopped being true of this port. That entry named what
  it needed -- the human lines behind the same test inside each writer -- and
  that is what `control.c`, `drop_in.c`, `profile.c`, `secret.c`,
  `wifi_write.c` and `reset.c` now do: the table and the document are the two
  arms of one `if` at each verb, so a line added to either side has the other
  in front of it. **The Rust is still in the state that entry describes**; the
  five CLI modules and `command_reset` between them contain no reading of
  `options.json` at all.
* **The object is the payload, as everywhere else, and it borrows the socket's
  word wherever the socket has one.** `cli.h`'s rule is unchanged -- compact,
  one line, no `"response"` envelope, an optional member absent rather than
  null -- and the spelling of a fact is taken rather than invented: `chosen`
  for a profile (from the `profiles` response), `used_by` for a credential
  (from the `secrets` response), `secured` for a network (from a scan entry).
  So `ncfg profile set --json` and `ncfg profile get --json` answer in the same
  member, and a reader learns one name per fact rather than one per verb.
  What each verb prints:
  * `control show` -- `{"observe","wifi","admin"}`, the three tiers rendered by
    `ncfg_cli_principal_render` so that the document and the configuration file
    cannot spell `group:NAME` two ways. `control set` puts `path` in front of
    them, which is the file this run wrote; `show` has none, because it
    compiled the whole layered configuration rather than reading one file.
  * `config put` -- `{"name","daemon"}` with `path` where this process wrote
    the file and `folded` where a profile was folded into `conf.d`.
    `config rm` is the same plus `removed`.
  * `profile get` -- `{"chosen":"office"}`, or `{}`. `list` is the socket's
    `profiles` payload exactly. `set`, `save` and `unset` print `chosen` beside
    `daemon`, and `save` adds `path` on the local route only.
  * `secret set` -- `{"name","path","replaced","daemon","used_by"}`.
  * `wifi add` -- `{"id","secured","daemon"}` with `file`, `secret`,
    `activated` and `usable` where there is one. `wifi forget` --
    `{"id","daemon","removed","kept"}`.
  * `reset` -- `{"config_dir","factory_dir","factory_remaining"}` with
    `credentials_remaining` and exactly one of `removed` or `would_remove`.
* **A profile that is not chosen is an absent member, not a name.** `ncfg
  profile get --json` on a machine with no profile prints `{}`, and `unset`
  prints an object with no `chosen` in it, so `get` straight afterwards agrees
  by construction rather than by wording. 0151's rule is that an absent
  selection and the shipped do-nothing profile are different states; a document
  saying `"none"` would be the one sentence the text form refuses to print,
  spelled as JSON. The socket agrees -- its `profiles` response skips `chosen`
  when nothing is selected.
* **An absent member means "not known", and never "none".** These verbs have
  two routes and the daemon's answer is `ok`, which settles less than a local
  write does. So `removed` is written by `config rm` only on the route that
  looked; `removed` and `kept` by `wifi forget` only there; `usable` by `wifi
  add` only there; `used_by` by `secret set` only where the configuration
  compiled; and `credentials_remaining` by `reset` only where the store could
  be listed. **The alternative is the fault this record spends its length
  refusing**: an empty list written by a command that never looked is a finding
  nobody made, and a script cannot tell it from one that did.
* **`ncfg reset --json` writes `removed` from what `unlink` answered, and never
  beside `would_remove`.** project.md 10.175 is the reason and it is the worst
  case this flag has: the Rust prints the word `removed` over the whole list
  *before* the loop that removes anything, so a reset that stops on its second
  file has already reported that all of them are gone. A document claiming a
  removal is worse than a sentence doing it, because a script believes it. The
  two members are therefore mutually exclusive -- a run that attempted nothing
  prints the prediction, a run that removed prints the record, and the record
  is built from the paths `unlink` returned 0 for. **A run that stops part way
  prints no document at all**: the verb answers 0 and its sentence carries
  which file stopped it and how many of how many had gone, which is
  `say_json`'s rule for a render that failed and is right here for the same
  reason -- half an answer is the one that gets parsed.
* **The refusal these verbs print says that the command already happened.**
  `run.c`'s `say_json` does not need that clause, because the verbs it serves
  render and change nothing. These six write first and compose the answer
  after, so a name off `argv` that is not valid UTF-8 -- the refusal a caller
  actually meets, per *A name that is not valid UTF-8 fails the command rather
  than the program* above -- fails a command whose file is already on disk. A
  reader told only "could not be written as JSON" concludes the write did not
  happen and stores the credential somewhere else. Driven end to end in
  `cli_secret_test.c`, which asserts the sentence, that nothing at all is
  printed, and that the file is there.
* **The shared write helpers hand their facts back rather than printing a
  document.** `ncfg_cli_put_text` and `ncfg_cli_remove_named` are one helper
  with three callers, and `ncfg config rm` and `ncfg profile unset` do not have
  the same answer -- one is about a drop-in by name, the other about which
  profile the machine is on. A helper that wrote its own object would put two
  values on a stream that promised one, so it fills `ncfg_cli_wrote_t` and the
  verb composes. The human lines stay where they were, behind the same test.
* **The advice is not in the document, at any verb.** `ncfg plan` and `ncfg
  apply --confirm-within 60` after a profile switch, what to do about a
  root-only socket, that a group's member has to log in again, that an open
  network is readable by anybody in range -- each is a sentence addressed to a
  person and the same sentence on every run. This is `ncfg plan --json`'s own
  rule for the two notes under a plan, applied to the verbs that write.
* **`fresh_tree` in `cli_wifi_test.c` was removing two files that never
  existed.** Not a divergence but a fault in this port's own fixture, found
  while writing the `--json` cases: the radio drop-in is
  `radio-<interface>.conf`, from `ncfg_wifi_radio_drop_in`, and the list held
  `50-wifi-wlan0.conf` and `50-wifi-wlan1.conf`. So a radio handed over by one
  case stayed handed over for every case after it, and no case after the first
  could assert that `wifi add` activates a radio. Corrected, and the `--json`
  case asserts `activated` because of it.

* **Four of `warn_unported`'s seven arms were port gaps and three were not, and
  the three had to stop saying they were.** The arm's sentence -- "this build of
  the planner does not act on it" -- is a *promise*: it tells an operator that a
  later release will, and that waiting is the right response. Each of the seven
  was checked against `crates/` before anything was written, and they did not
  come out the same way.

  `advertise` is `plan_advertising` (`crates/netcfgd-plan/src/lib.rs:3885`),
  `dot1x` is the first arm of `plan_prerequisite` (`:2447`, the arm at `:2453`),
  a `linkset`'s choice is `standby_interfaces` (`:1376`) read by `plan_route`
  (`:4348`) and `teardown_routes` (`:5593`), and `on_unmanage = "clear"` is
  `prepare` (`:1477`), the exemption in `Builder::push` (`:1850`) and the
  filtered document in `plan_teardown` (`:5565`). Four real gaps, now four
  passes, and their arms are gone.

  A **`probe`** block is not the planner's at all: the daemon runs it
  (`crates/netcfgd-daemon/src/probe.rs:219`, ported at
  `c/src/daemon/probe.c:817`) and what the planner reads is the *verdict*,
  `Self::probe_failing` (`:1963`) at `plan_route:4380` and
  `teardown_routes:5626` -- both of which this port already has, at
  `c/src/plan/address.c:339` and `:435`. So the old sentence was wrong twice
  over: it named a gap that is not this port's, about a rule this port had
  already ported. A **`modem`** block is the same shape:
  `crates/netcfgd-daemon/src/sim.rs` reads it, ported at
  `c/src/daemon/sim.c:335`, and the planner's only interest is the SIM cycle,
  which is the `cycle` option this record already defers. A **`bluetooth`**
  block is acted on by nothing, in either language -- `warn_bluetooth`
  (`:1075`) says so in the Rust's own words, the only other readers are the
  compiler and an observer that lists adapters
  (`crates/netcfgd-observe/src/host.rs:874`), and `tests/live/bluetooth.sh`
  states in its own header that adapter observation "is all netcfgd's core
  does".

  So the three keep a warning and each now says which of the two things is
  true. `warn_block` has gone with the last arm that used it, and `warn_unbuilt`
  is what a block that nothing anywhere acts on gets: *nothing acts on it in the
  Rust either, so there is nothing to wait for*. Telling somebody to wait for
  something that is not coming is worse than saying nothing, and no check that
  looks only at what a plan *does* can find it -- so the wording is asserted,
  and putting each old sentence back turns a check red.
* **The `advertise` pass compares the two prefix lists as one space-joined
  string.** The Rust compares `Vec<String>` element by element and then joins
  each side for the reason line. No address contains a space, so the two
  questions have the same answer -- and this way the comparison is made of
  exactly the text the operator is shown, which a difference that did not reach
  the sentence could not be.
* **A `linkset`'s standby set is collected once, into a counted array, with its
  strings interned into the plan.** The Rust builds a `HashMap` in `prepare`;
  the shape here is the same decision for the same reason -- `ncfg_linkset_choose`
  walks nested sets, the link table and the probe verdicts, and asking it per
  route would make planning cost scale with the number of routes an operator
  wrote. Interning is what the C adds: the choice is freed before the first
  route is planned, so a borrowed name would be read afterwards. Replacing in
  place is the "last set wins" a `collect` into a map gives.
* **`on_unmanage = "clear"` filters a shallow copy of the document and swaps it
  in for the teardown only.** The Rust clones the whole `Document` and retains
  on the clone; here two arrays are allocated, every string in them is still the
  document's, and `ncfg_plan_clearing_end` puts the original back. Nothing in a
  teardown writes through the document and the original outlives the plan, so a
  deep copy would be a second lifetime to get wrong for no answer that differs.
  Both lists are filtered, and the device list is the one that matters: 10.16 is
  what filtering only the interfaces cost, and the sabotage that puts that back
  turns the `link.delete` check red.
* **`ncfg_plan_teardown_backends` asks a `backend_wanted` of its own, with a
  permissive default.** The Rust's is exhaustive over all nine kinds, which is
  right in a planner where every pass that starts one exists. Here the access
  point and the two tunnels are still started by passes this build does not
  have, so the default arm answers *wanted* -- stopping something netcfgd never
  started, and starting nothing in its place, is the worse direction. The
  supplicant and the router advertisement daemon have left that arm with their
  passes. The supplicant's rule is asked in `ncfg_plan_supplicant_wanted`,
  beside the pass that starts one rather than here, because the conditions that
  start a supplicant and the conditions that keep one have to stay the same --
  and its radio arm is what keeps this build from stopping one it cannot
  replace.
* **The supplicant and the advertisement daemon inherit `ncfg_plan_backend`'s
  `link.up` dependency, which the Rust's equivalents do not have.** The Rust's
  `base` at that point carries the gate, the enslavements and the `up` hook
  ids, and *not* the `link.up` id itself -- so on an interface with no `up`
  hook, `plan_prerequisite` and `plan_advertising` depend on nothing that
  brings the link up, and only the list order puts them after it. Rule 3 is
  already this port's answer for a DHCP client and it costs nothing to be right
  about here.
* **The two calls are in `link.c`'s interface walk rather than in `build.c`'s
  sequence, and that is where they have to be.** Both are defined in files of
  their own under `src/plan/`, but a supplicant has to be emitted between
  `link.up` and the addressing it gates, and the advertisement daemon has to
  carry the addressing ids it waits on -- and those ids are local to
  `ncfg_plan_interface_contents`. A whole-document pass called afterwards could
  reconstruct neither: `plan.h` says the action list is already a valid
  execution order, so emitting the supplicant after the DHCP client would be
  the defect the prerequisite exists to prevent, whatever the edges said. The
  other two are `build.c`'s: the standby set is collected before every pass that
  plans a route, and the clearing filter brackets the teardown.

* **The DHCP client's machine paths are members of a struct with no defaults,
  where the Rust reads two environment variables.** `NCFG_DHCPCD_HOOK` and
  `NCFG_DHCPCD_RUN_DIR` exist there so that a test can point them somewhere
  safe, which means the production path reads `/usr/libexec/netcfgd/dhcpcd-hook`
  and `/run/dhcpcd` whenever nobody remembered to set them. `ncfg_dhcp_machine_t`
  carries the hook, dhcpcd's own run directory, what `-f` points at, the three
  programs and the stop's patience; `ncfg_dhcp_machine` is the one place this
  machine's answers are written down, so a check asserts what a daemon would use
  by reading it. That is `ncfg_contention_machine`'s arrangement and
  `ncfg_service_t`'s bargain, taken here for the reason both give: the machine
  these tests are built on is a workstation whose network is live, and a default
  is how the difference between a check and an outage becomes a variable
  somebody remembered to set.
* **The dhcpcd hook is demanded of the dhcpcd candidate, not before a client is
  chosen.** The Rust resolves it at the top of the `Dhcp4` arm, before the three
  candidates are tried at all, so a machine whose only client is busybox udhcpc
  is refused its lease over a file it would never have run -- the hook is
  `-c`'s, and udhcpc has no equivalent. Reported in project.md 10.178. Here the
  check is inside the dhcpcd candidate, so a missing hook still refuses the
  machine that would have used one, by name and quoting the path, and no longer
  refuses the machine that would not.
* **The metric record is written only for the client that was given a metric.**
  `record_started_metric` runs on whichever of dhcpcd, udhcpc and busybox
  started, and the last two have no `-m` at all -- busybox udhcpc's script does
  the routing. So on a busybox machine the Rust writes down a number the client
  never heard, and 0241's own reader takes that record *instead of* comparing
  the installed route, which is the fallback that would have noticed. Here
  dhcpcd's start records the metric and the other two clear the record, which
  leaves the planner reading "cannot tell" -- the answer it had before the
  record existed, and the correct one.
* **A dhcpcd on the interface that is not netcfgd's refuses the start rather
  than being spawned beside.** The Rust's own comment at that point says
  "neither is a reason to spawn beside it" and the code then falls through and
  spawns: dhcpcd's instance lock refuses the second, it prints "sending commands
  to dhcpcd process" and **exits 0**, so netcfgd records a start it did not
  make, on a client whose `-f` it does not hold and which its own
  `confirm_dhcpcd_stopped` will decline to account for. The refusal here names
  what the running client recites and says why attempting it would have looked
  like success. `None` is unchanged and still starts: that is "netcfgd could not
  tell", which is the ordinary state of every machine whose client is udhcpc.
* **A stop asks whose the client is before it signals, not after.** `dhcpcd -k
  <iface>` finds a client by convention, which is exactly what 0014 forbids, and
  the Rust sends it first and asks the control socket afterwards -- so a
  stranger's `dhcpcd -4` on that interface is signalled, and
  `confirm_dhcpcd_stopped` then reports that the stop "neither reached nor
  disturbed" it, which is its own doc comment's claim and is false. Here the
  question comes first: netcfgd's own client is signalled and confirmed, a
  stranger's is left alone and named in a note, and what the op asked for --
  that no client *of netcfgd's* is running there -- is satisfied either way.
  0141 keeps what to do about somebody else's daemon a person's decision.
* **The marker a stop checks is the pid-file path, which is the marker the
  start already uses.** The Rust's `backend_pid_file` gives both DHCP clients
  the *interface name*, calling it in the same breath "the weakest marker
  netcfgd uses", and `stop_recorded_client` signals on it -- while the start
  path twelve hundred lines earlier adopts the same process by the `-p` path in
  its own `argv`. Two markers for one process, and the weaker one is where the
  signal goes. netcfgd puts that path there, busybox does not call
  `setproctitle`, and `ncfg_process_pid_of` already applies the whole-argument
  rule to it, so there is nothing to invent. Reported in project.md 10.178.
* **How long a stop waits for `dhcpcd -k` is an argument.** The Rust sleeps
  100ms at a time for three seconds against a live socket, which is why nothing
  exercises it; `patience_ms` lets a check drive both outcomes -- a client that
  goes and one that does not -- in a fifth of a second, and the constant is
  published so the default is not spelled twice.
* **A DHCPv6 start is refused and a DHCPv6 stop is carried out.** Which v6
  client can serve a document turns on whether it asked for a delegated prefix,
  since dhcpcd measurably reports one to a script and odhcp6c does (0050), and a
  plain `backend.start` carries neither the request nor an odhcp6c -- the Rust
  refuses it in the same words at the same point. Stopping is a different
  question and is answerable with what is here: `dhcpcd -6 -k` under the same
  ownership rule, and an odhcp6c by the pid it was told to record.
  `ncfg_apply_supported` therefore answers differently for the two verbs of one
  kind, which nothing else in this build does and which is the honest shape.
* **The metric that reaches the client is resolved by the caller.**
  `netcfgd_model::wifi::effective_metric` is the rule -- the network's `metric`
  where the radio is associated to one that carries it, the interface's own
  `preference` otherwise -- and half of it comes from the observation, which the
  service context does not hold. The Rust records what building it from the
  document alone cost: measured on a veth against a real server, the lease's
  route carried 1003, dhcpcd's own default, on a document whose network said
  100, and stayed 1003 across a switch to a network saying 400. So
  `ncfg_service_client_metric_t` is a list the caller fills, which is
  `ncfg_service_advertise_t`'s arrangement for `ncfg_service_advertise_t`'s
  reason. An interface with no entry starts a client with no `-m`, which is not
  a refusal: no metric is an ordinary document. **`value.h` has no port of
  `effective_metric` and this build has no reader for the record either** --
  `src/plan/` carries no metric-driven restart -- so both halves are named here
  rather than quietly missing.
* **The metric record is removed when the client is stopped.** The Rust leaves
  it, and a record of what a *running* client was started with is an account of
  nothing once there is no client. Nothing observable turned on it either way --
  the following start rewrites or clears it -- so this is tidiness with a reason
  rather than a defect closed, and it is here because the record's own rule is
  that a stale one says the running client carries a metric it was never given.
* **The udhcpc script refuses a path that carries a single quote.** Every one of
  the three is composed by netcfgd out of a run directory and an interface name,
  so none of them can hold one -- and "cannot" is the claim this project checks
  rather than makes, because what is on the other side of being wrong is a lease
  event running the rest of the path as root. The Rust interpolates all three
  unexamined.
* **`ncfg_dhcp_running_pid` and `ncfg_dhcp_adopt` are public**, where the Rust
  keeps the equivalents inside `start_backend` and reaches them from a unit test
  in the same file. A C test links against the library and can see only what the
  header publishes, which is `ncfg_process_pid_of_as`'s reason one module over;
  and adoption is the half of this backend that is worth exercising on its own,
  since the pid file going with the run directory is what happens on every
  restart rather than an edge case.

* **A `network` block was five fields under one sentence, and the sentence had
  the blame wrong for four of them.** `c/src/plan/wifi.c` said a network's
  addressing, routes, `dns` policy, hooks and metric were "carried in the
  document and this build of the planner does not act on them", which is the
  promise 10.180 took apart. Asked of `crates/` field by field, it split four to
  one.

  **Addressing, `routes` and a `dns` policy are acted on by nothing in either
  language.** Every `.addressing` the Rust planner reads is an *interface*'s --
  `crates/netcfgd-plan/src/lib.rs:2281`, `:4973`, `:5188`, `:5794`, `:5803`, and
  `crates/netcfgd-apply/src/kernel.rs` has no other kind either -- and
  `netcfgd_model::dns::scopes` (`crates/netcfgd-model/src/dns.rs:200`) builds
  its scope list from `document.globals` and `document.interfaces`, never from
  `document.networks`. The only readers of the three on either side are the
  canonicaliser, which sorts and validates them
  (`crates/netcfgd-model/src/canonical.rs:77` and `:122`;
  `c/src/model/canonical.c:471` and `:656`), and the renderer that `ncfg
  profile save` writes them back through
  (`crates/netcfgd-compile/src/render.rs:724`;
  `c/src/compile/render_link.c:591`).

  **Hooks are the same, and the Rust says so in its own words.**
  `warn_unfired_hooks` (`crates/netcfgd-plan/src/lib.rs:474`) warns per network
  that "a hook on a network is not run by this build at any phase", which is
  10.34's finding still standing. This port already collects a network's hooks
  into the list an executor verifies a script's hash against
  (`c/src/main/daemon_world.c:356`), so nothing has to remember to come back
  there -- and no pass in either language emits a `hook.run` naming one.

  **`metric` is the one real port gap of the five, so it keeps the promise and
  gets its own sentence.** The Rust planner applies
  `netcfgd_model::wifi::effective_metric`
  (`crates/netcfgd-model/src/wifi.rs:306`)
  to the routes an interface declares (`crates/netcfgd-plan/src/lib.rs:4391`) and
  restarts a DHCP client started with the old value (`restart_for_metric`,
  `:2275`). Here `with_metric` (`c/src/plan/address.c:169`) fills a route's metric
  from `interface->preference` alone and there is no restart pass at all. Said
  only where a network states a metric, and naming those two passes rather than
  "not acted on", so a reader can check the sentence against the work that would
  retire it.

  **And the old clause's tail was false as well.** "Only the set of network ids
  is handed to a running supplicant" describes the *op*, which carries ids; what
  reaches the supplicant is every network in the document, read from the document
  the plan was built against (`c/src/apply/wifi_ops.c:472`) -- and the metric
  among them, as `priority` (`c/src/backend/supplicant/network.c:617`). A
  `linkset` ranks its members by that same number (`c/src/model/linkset.c:283`).
  So the one field of the five that this build does act on outside the planner
  was the one the sentence called inert.

  **Warned only where a network states the thing**, which is `warn_device_policy`
  one function up and is a behaviour change: the old sentence fired on every
  document holding a network at all, so the ordinary saved SSID -- a name and a
  credential -- was told about four fields it had never written.

* **A warning longer than `NCFG_ERROR_MAX` is cut off and still reported as a
  warning.** Found by sabotaging the above rather than by reading it:
  `ncfg_plan_warnf` (`c/src/plan/plan.c:553`) formats into a 512-byte buffer and
  `vsnprintf` truncates without telling anybody, so the first draft of the
  four-field sentence reached an operator as "...still means t" at 511
  characters, and every check written against it passed because each fragment
  asserted sat before the cut. Both new sentences are now written to fit at the
  widest id the model allows -- an SSID is up to 32 octets, and a network naming
  one that is not valid text carries it as 64 hex characters -- and
  `plan_gaps_test.c` asserts the *last words* of each at exactly that width,
  which is the only form of the check that can fail. **The truncation itself is
  not fixed here.** Every other warning the planner emits fits today, the longest
  measured at 330 characters, and widening the buffer or teaching the helper to
  refuse touches `plan.c` and `base.h`'s single error width. Named rather than
  quietly designed around.

* **`ncfg_plan_warn_unbuilt` is published in `plan_internal.h`** rather than
  static in `build.c`, because the wifi passes have the same distinction to draw
  and 10.180's whole point is that "this port has not got there yet" and "there
  is nothing to wait for" must not become two sentences that can drift.

* **`effective_metric` and the absent `cycle` option were re-asked, and both are
  still deferrals rather than oversights.** `effective_metric` is half of a pair:
  `ncfg_service_client_metric_t` is a list the caller resolves and **nothing in
  this build fills it** -- `c/src/apply/backend_ops.c:323` is its only reader --
  so porting the planner's half alone would produce a plan that computes a metric
  no executor is ever handed, which is a worse state than the gap and a harder one
  to notice. The cost while it stands is worth writing down plainly, since the
  warning now says it to an operator: a radio associated to a
  `network { metric = 100 }` gets the routes its `interface` block declares at
  the interface's own `preference`, which is exactly the ranking 0154 exists to
  make expressible. `cycle` is unchanged from what is recorded above: a plan
  cannot be asked to cycle a modem link, and `ncfg_sims_cycled` is written to be
  correct on the day it can. Neither was ported.

* **`link.create` makes a bond, a vlan, a macvlan and a tunnel, and the reason
  they were refused is closed rather than worked around.** All four were refused
  by `creatable` in `apply.c` for one reason -- the kernel's numbering for a
  mode, an ethertype or a kind word is the model's and `src/apply/` may not keep
  a second copy of it. Three of the four stopped being true when `document.h`
  published `ncfg_bond_mode_number`, `ncfg_macvlan_mode_number` and
  `ncfg_tunnel_kind_name`; this record said so and left the stale sentence for
  whoever owned `apply.c` next. `ncfg_kernel_newlink_of` already built the
  macvlan's and the tunnel's nests, so for those two only the sentence was
  wrong. The bond and the vlan needed arms, and they have them.

  **This reverses one sentence of this record, deliberately.** The entry above
  says "a VLAN's ethertype is deliberately *not* published, `link.set_vlan` not
  being an op and nothing else needing it". `link.create` for a vlan is the
  caller that reason did not cover, and it is not a caller that can be avoided:
  a vlan's id and tag protocol are fixed at creation -- `vlan_changelink` reads
  neither -- so creation is the only place either can ever be stated, and a vlan
  netcfgd cannot create is a vlan netcfgd can never have. `document.h` publishes
  `ncfg_vlan_protocol_ethertype` now, which is also what the Rust does
  (`VlanProtocol::ethertype`, read by `netcfgd-apply`'s `new_link`), so the
  absence was a divergence rather than a design.

  **A bond's mode reaches the kernel by two routes and both are correct.** The
  creation nest always carries it, a bond being made having no members yet,
  which is the one state the kernel accepts a mode in; `ncfg_ops_set_bond_attrs`
  takes an *optional* mode because the correct-an-existing path meets bonds that
  already have members and the planner tells it which. Two builders, one
  encoder: what 0057 forbids is two answers to "what is a bond's mode", and both
  read `ncfg_bond_mode_number`.

  **A vlan id is range-checked rather than cast**, at 0 to 4095, which is the
  port's rule wherever the model's `int64_t` meets a kernel field and is a
  divergence from the Rust in the same direction as the VXLAN's 24-bit check.
  The Rust's `VlanConfig::id` is a `u16`, so 4096 to 65535 reach the kernel
  there and come back `ERANGE`.

* **`ncfg_apply_supported`'s link half is now `physical`, `pppoe` and
  `openvpn`, and `plan/link.c` reaches an arm of its own for each first.** So
  the executor probe at the end of that function is a backstop with nothing left
  to fire on. It stays: it is what covers the next kind to be held back, and the
  planner asks the executor rather than keeping a list. That it is still
  consulted is a check rather than a claim -- `plan_kind_test.c` drives five
  kinds that went from declined to planned with not a line of `src/plan/`
  touched, and `cli_test.c`'s plan rendering names `k-bond` again because the
  frozen witness's bond is planned once more.

* **The two halves are compared by kind, in the module that owns both.**
  10.177's defect was `ncfg_apply_supported` answering yes for a `tun` while
  `ncfg_kernel_newlink_of` refused one, and it was found by hand. It is a check
  now: `apply_kernel_test.c` walks every kind tag, asks the list and asks the
  two builders `create_link` chooses between, and requires them to agree. Both
  directions were sabotaged and both go red.

* **The mark a created link wears was guarded on one arm only.** 10.173 records
  the Rust's tun arm returning above the block that marks a created link, and
  `main_test.c` narrowed its check to `create_tun`'s body so that a search of
  the whole file could not give a false pass. Nothing then covered the arm it
  had narrowed away from: deleting `mark_as_ours` from `create_link` itself went
  green across the entire suite. Both bodies are asserted now, which matters
  more than it did -- four more kinds reach the netlink arm, and 0136's whole
  point is that a link has no protocol field, so an unmarked link's ownership
  lives only in `/run` and a restart loses it.

* **A test helper that crashed instead of failing, found by sabotage.**
  `apply_kernel_test.c`'s `kind_nest` left its output walk untouched when the
  parse failed, and a caller writing `kind_nest(...) && u16_of(&data, ...)` is
  protected only for as long as every caller remembers the `&&`. A builder made
  to refuse a vlan ended the suite six checks before the one that would have
  caught it -- so the sabotage was reported as "caught by two checks" when the
  truth was "aborted the binary". Both walk helpers empty their output first
  now: an empty area answers "not found" for everything, which is what a failed
  parse should say.

* **The band a restart names is the band it is moving to.** The access point's
  identity comparison derives the effective band before comparing it -- an
  absent `band` means "work it out from the channel", and the file records what
  was worked out -- and the Rust then prints the *stated* band in the reason.
  So an operator who deletes `band = "5"` gets `access_point.band:  (was 5)`,
  with an empty field where the value that caused the restart should be. This
  prints `2.4`, which is the value compared and the band the radio is about to
  come up in. project.md 10.181 has the measurement.
* **`ncfg_hostapd_key_mgmt_of` is published by the hostapd backend, not by the
  model.** The Rust keeps `key_mgmt_of` in `netcfgd-model` and says why: the
  planner compares the document's generation against the record of what hostapd
  was started with, so a second copy of the mapping is an access point that
  restarts for ever. The C model has grown neither this nor `effective_band`,
  and `hostapd.h` already carries the latter for the same reason and says the
  pair moves to the model when it grows them. The planner is the second caller
  that paragraph was written for. **It also returns NULL for `eap`** where the
  Rust names `WPA-EAP` for match exhaustiveness: the renderer refuses an
  enterprise access point before a byte is written, so no file and no record can
  ever hold that spelling, and offering one gives a comparison something to be
  equal to that nothing wrote.
* **`src/plan/access_point.c` includes a backend header**, which no other file
  under `src/plan/` does, and the Rust forbids the equivalent outright -- a
  planner crate may not depend on a backend crate. In C there is one library and
  the property that actually matters is one implementation: the alternative is a
  second copy of the band rule and of the generation rule inside the planner,
  which is the permanent deauthentication loop 0222 records having shipped
  twice. The include goes away when the model grows both rules.
* **An access point netcfgd has no record of starting is said out loud.** No
  Rust counterpart, because there the observer always writes the record and the
  case is unreachable. Here `started_with` is a field `src/observe/` does not
  yet fill, so an edited `ssid`, `band`, `channel`, `security`, `hidden` or
  `regdom` plans nothing and the machine looks converged. The sentence is
  emitted only for an access point that is *running* and has no record, so it
  goes quiet by itself the day the observation carries one -- and it is the
  narrowing of the blanket warning that used to say no access point was
  started, configured or restarted at all.
* **The reason for a policy change names the document's word.** `deny` and
  `allow`, through `ncfg_plan_acl_policy_word`, where the Rust's `{policy:?}`
  gives `Deny` and `Allow`. The same call the ownership, backend and drift words
  above make, extended to the plan's reasons: a reason line is not where a
  second spelling of an enum enters the vocabulary, and an operator cannot grep
  their configuration for `Allow`.
* **Five of `warn_access_points`' six arms are not ported.** The one that is --
  an access point on a device with no `interface` block, which is the
  arrangement where nothing is started at all -- is here because this wave
  removed the blanket sentence that had been covering it. The other five say
  that an access point has no address to serve its stations from, that a DFS
  channel means a minute of silence, that an empty `allow` list admits nobody,
  that a second access point on one radio is ignored, and that a radio running
  one is not also joining networks. They are diagnostics rather than planning,
  none of them changes an action, and they are named here so that the gap is a
  deferral on the record rather than five sentences nobody missed.

* **The nftables round is a second exchange, not an eighth dump.** `collect.c`
  asks seven questions over `NETLINK_ROUTE`; `read_netfilter`'s two go over
  `NETLINK_NETFILTER`, which `ncfg_netlink_open_protocol` says is a socket of
  its own. So `ncfg_observe_netfilter_from` takes an `ncfg_observe_kernel_t` of
  its own and `ncfg_observe_current_from` takes both. The seam is the same one
  for the same reason, and `nft.h`'s builders are taken apart by the same
  `request_parts` the traffic-control requests get: nothing about either dump
  -- not the subsystem number, not the dump flags, not the table filter -- is
  spelled a second time in the observer, which is what stops a dump being
  aimed at somebody else's table and read as netcfgd's.
* **A netfilter seam may be absent and a netfilter socket may refuse, and
  neither fails an observation.** No `nf_tables`, a netlink this process may
  not ask, and a machine where netcfgd never installed a table are one answer
  to a planner -- no NAT is installed -- which is what `observed.h` already
  says where the field is declared. The Rust reaches the same place with
  `unwrap_or_default` and says nothing; here the sentence goes to a note, so a
  machine that *stopped* answering is not silent. An observation refused over
  it would be an `ncfg status` that fails on a kernel built without a feature
  nobody asked for.
* **The uplinks are refused past the ceiling and the conflicts are truncated
  past it**, which is `NCFG_OBSERVE_RECORDS_MAX` split by what the list is
  for: the uplinks are what the planner compares against and what the op's
  inverse is made of, so a quietly shorter list plans a machine back to a
  state nobody asked for; the conflicting tables are only ever printed, and a
  warning that says "more than N" is a warning either way. The Rust bounds
  neither.
* **The uplinks are sorted and deduplicated, and that is load-bearing rather
  than tidy.** `ncfg_plan_nat` sorts the document's uplinks and compares the
  two lists in order. The Rust sorts and dedups too, in `nat_uplinks`; what is
  new here is that a test asserts it, because an unsorted observation is not a
  wrong answer anywhere visible -- it is `nat.replace` planned on every pass
  against a machine that is already right.
* **A chain is somebody else's by the table's name alone**, which is the
  Rust's comparison and is kept deliberately rather than improved:
  `ncfg_nft_chain_t` carries no family, so a source-NAT chain in an `ip
  netcfgd` table -- somebody else's table wearing netcfgd's name -- is not
  reported as a conflict by either language. `ncfg_nft_table_is_ours` compares
  family *and* name and is what the table dump uses; making the chain reader
  carry a family is an `nft.h` change and is named here rather than made in
  passing.
* **What the observer defers is counted rather than remembered.** The
  `observe.h` entry that named the deferred passes had been wrong for several
  waves in two directions at once -- it said six of eleven and listed nine,
  while all eleven were deferred -- and the blockers it named had been
  overtaken by the backend modules landing. project.md 10.182 has the count
  and the real blocker, which is that `ncfg_owned_state_t` carries no backends
  and so `observed.backends` is empty on every machine: six of the ten
  remaining passes walk that list, a seventh walks `observed.dns` beside it,
  and none of them can be written before the record carries them. The one
  ported is the one whose input is the kernel.

* **The interface's prerequisite is three of the Rust's five arms, and the
  order is the module rather than a sequence of passes.** `plan_prerequisite`
  returns at the first arm that applies -- `dot1x`, a PPPoE session, an OpenVPN
  tunnel, an access point, a radio -- which is what makes "one prerequisite per
  interface" true rather than hoped for. `ncfg_plan_interface_contents` calls
  `ncfg_plan_dot1x`, `ncfg_plan_access_point` and `ncfg_plan_radio_supplicant`
  in that order and each declines where an earlier one took the interface, so
  the early return is spelled as a guard per pass. The two absent arms are the
  two tunnels, whose backends no pass here starts and whose teardown
  `backend.c` already excuses by name. The order is load-bearing in both
  languages and for the Rust's reasons: an interface carrying a `dot1x` block
  has said what its supplicant is for, so asking again because the device is
  also a radio is two `backend.start` actions for one process; and a radio
  running hostapd does not also join networks with the same interface, one
  radio doing both only with a second virtual interface on the phy, which
  netcfgd does not create.
* **The radio set is a predicate, not a list collected up front.** The Rust's
  `prepare` builds `radios: Vec<String>` out of the document and the
  observation and both the prerequisite and `supplicant_wanted` search it;
  `ncfg_plan_radio_supplicant_wanted` answers the same question directly from
  the two. That is `ncfg_reconcile_reconciles`' shape for its reason -- nothing
  has to bound a list whose length is the operator's to choose -- and it costs
  the device-list walk `ncfg_plan_device` already is.
* **The supplicant's whole rule is one function, and the pass calls the same
  predicate the teardown does.** In the Rust `plan_prerequisite`'s radio arm
  and `supplicant_wanted`'s are two expressions over one `radios` list, which
  agree because somebody kept them agreeing; here
  `ncfg_plan_supplicant_wanted` is `dot1x` or `ncfg_plan_radio_supplicant_wanted`
  and the pass that starts one asks that second function too. "The conditions
  that start a backend and the conditions that keep one are the same" stops
  being a sentence a reader has to check and becomes one call site. The access
  point's arm is inside the radio half rather than beside it, because "this
  radio runs hostapd instead" is a statement about the radio and not about
  802.1X.
* **`managed` is in that rule although no plan can show it.** Every action on
  an unmanaged device is dropped by `ncfg_builder_push`, and a clearing one is
  filtered out of the document before the teardown reads it, so deleting the
  condition changes no plan -- measured. It stays because the rule is what both
  callers ask and an exported predicate that answered wrongly would be wrong,
  and `plan_radio_test.c` asks the function directly rather than leaving a
  condition nothing can see.
* **A radio the document declares and states no `interface` block for is
  said.** The Rust says nothing about it, and this is `access_point.c`'s
  narrowing applied to the supplicant: a prerequisite is planned from the
  interface walk, so a `device` block with a `wifi` section and no `interface`
  block gets no supplicant, no `link.up` and -- without the sentence -- no
  explanation either. It is what the blanket warning it replaces narrowed to;
  that one told every radio on the machine that the supplicant serving it was
  not started by this build, which plans no backend actions at all, and both
  halves are now untrue. Said only where the kernel agrees the interface is a
  radio, because a `wifi { portal_check = ... }` on a dummy is what
  `tests/live/portal.sh` writes and is not asking for a supplicant.
* **Two of the Rust's radio warnings are not ported, and are named here rather
  than left to be noticed.** `warn_blocked_radios`
  (`crates/netcfgd-plan/src/lib.rs:298`) says that a radio switched off at
  rfkill is configured anyway and will associate when the switch comes back,
  and names the remedy by switch kind; `ncfg_observed_link_t` carries the
  `rfkill` record it needs, so this is a pass nobody has written rather than a
  fact the port cannot reach. The second
  (`crates/netcfgd-plan/src/lib.rs:1299`) is the sentence that says out loud
  why the access point's arm comes before the radio's -- that a radio running
  one is not also joining the configured networks. Neither changes an action.

* **`owned.json` carries the backends and the DNS scopes, and two of the
  model's tables are published for it.** The record's two missing members are
  in, read and written through `ncfg_observed_backends_read` and
  `ncfg_applied_dns_read` -- the observation's own field tables, exported
  rather than copied, because a second DNS policy codec in `src/host/` is the
  duplication this document forbids. What is exported is the list walk; the
  element tables stay private. `carried_more` is gone with them: there is
  nothing left for it to report, and a flag that always reads false is a flag
  whose next reader believes something.
* **A `backend.start` records the backend as well as the restart, and the
  entry carries nothing but `{kind, interface, running}`.** That is what the
  Rust's `absorb` pushes and what this machine's own `/run/netcfgd/owned.json`
  holds, checked against it rather than derived from the struct: every other
  field of an `ObservedBackend` is read live by an observation pass, never
  recorded, and `skip_serializing_if` keeps each out of the file. `running` is
  netcfgd's memory of having started the daemon and is 0078's distinction
  exactly -- `answering` is absent, because nothing asked.
* **`dns.apply` is the one op that is not its own effect, so nothing folds it.**
  The argument this port's fold rests on is that every member of the Rust's
  `Effects` which the record can carry is a pure function of the op that
  produced it. This one is not: `ncfg_service_dns_apply` delivers every scope
  its context carries whatever the op names, and the C planner emits an op only
  for a scope that *differs*. Folding the op's own scope would leave a scope
  the document has dropped recorded for ever, and the planner asks for a
  re-delivery on every pass while that entry stands; replacing the whole list
  from the ops would drop the scopes that did not differ, and the two states
  then alternate. It would also want a deep copy of an `ncfg_dns_policy_t`,
  which exists nowhere in this port and which `observe.h` says is deliberate.
  So the record **carries** `dns` -- a file another netcfgd wrote round-trips
  through this build instead of losing it, which is the whole of what
  `carried_more` used to warn about -- and the producer that would fill it is a
  reader of `<run>/dns/`, which `dns.h` already names.
* **0079's third clear is still not written, and the reason has moved.** The
  clear a live backend performs needs `running` in an observation to be a fact
  about a process rather than netcfgd's memory, which is `read_backend_liveness`
  -- and that pass needs a backend kind mapped to a pid file and an `argv`
  marker, which the Rust has as one function (`netcfgd_apply::backend_pid_file`,
  seven kinds) and this port has as five per-module answers with no map. Each of
  those reaches `/proc` at a fixed path through `process.h`, which is that
  module's right and `observe.h`'s rule broken. Writing the clear without the
  pass would clear every count on every pass, so 0079's cap would never bite at
  all -- which is worse than the cap never lifting, and is why this wave
  stopped at the record.

* **Three more warnings settled against `crates/`, and all three were the same
  answer.** 10.180 published `ncfg_plan_warn_unbuilt` for the case where a
  block reads as this port's gap and is nobody's; these are the three that were
  left. Each was checked field by field rather than inherited, and each turned
  out to be acted on by nothing in either language, so all three now carry that
  helper's sentence instead of a promise.

  * **A radio's `regdom` and `powersave`.** `WifiSetRegdom` is an `Op` variant
    with no constructor anywhere in `crates/` -- the Rust's own doc comment
    says so of itself at `crates/netcfgd-plan/src/lib.rs:749` -- and outside
    the model and `lower.rs` the only mention of `powersave` there is the
    matching warning at `:955`. The *access point's* `regdom` is a different
    field, does reach hostapd as `country_code`, and the restart arm that
    landed with `access_point.c` acts on it; the reason gathered beside the
    name says that in the same breath, so the sentence no longer looks like it
    is about the spelling that works.
  * **`autoneg`, `speed`, `duplex`, `wol`, `rx_ring` and `tx_ring`.**
    `crates/netcfgd-plan/src/lib.rs:714` is this same warning, field for field
    and almost word for word, and the encoder it was waiting on exists on
    neither side: `crates/netcfgd-sys/src/ethtool.rs` defines
    `ETHTOOL_MSG_FEATURES_GET` and `..._SET` (`:36-37`) and no other ethtool
    message at all, which is exactly what `c/include/ncfg/ethtool.h` carries.
    The reason for that -- ring, link-mode and wake-on-LAN messages can only be
    exercised against a physical NIC -- was already in the sentence, one clause
    after the promise it contradicted.
  * **Link-local addressing.** The comment on the arm was right and the
    sentence under it was not: it said "the product's gap rather than the
    port's" over the Rust's own "not yet applied by **this build**".
    `crates/netcfgd-plan/src/lib.rs:4033` is the same warning on the same arm,
    and `AddressSource::LinkLocal` has no reader anywhere in `crates/` outside
    the model, the compiler and the renderer.

  The one thing that could go wrong with all three at once is length:
  `ncfg_plan_warnf` cuts at `NCFG_ERROR_MAX` and marks the cut at the *end*, so
  a check on a fragment near the front of a long warning cannot fail. The
  `ethtool` sentence is 481 of 512 characters at all six fields and the radio's
  is 437 at the widest device name a kernel takes, and both are asserted by
  their last words -- `PLANFIX_UNBUILT_TAIL` is the whole of what the helper
  appends rather than its closing phrase, which is a distinction that cost a
  sabotage: the first draft of that macro was the tail of the sentence
  `warn_unbuilt` *replaced* as well as of the one it writes, and putting the
  old wording back turned nothing red.

* **`wifi.set_regdom` has an executor here and none in the Rust**, which is the
  one place this port is ahead on a gap the sentence above calls shared.
  `ncfg_service_set_regdom` (`c/src/apply/wifi_ops.c:712`) validates the
  country as two letters, uppercases it and sends `SET country` on the
  supplicant's control socket, and `service_test.c` drives it; the Rust has no
  arm for the variant at all and falls into
  `other => Err("{} is not implemented in this build")`
  (`crates/netcfgd-apply/src/kernel.rs:1919`). So what is missing on both sides
  is the producer rather than the op or its execution, and a plan that
  constructed one would be carried out here and refused there. Recorded rather
  than removed: the executor is written and tested, and deleting it to match
  would be undoing work to preserve a symmetry nobody wants.

* **`effective_metric` stays deferred on both halves, and the reason has moved
  from one blocker to two.** The judgement it was deferred under was that
  `ncfg_service_client_metric_t` is a list the caller resolves and nothing
  fills, so the planner's half alone would compute a metric no executor is
  handed. The DHCP backend landing did not lift that, and re-checking found a
  second reason underneath it.

  The first is that **nothing composes an `ncfg_service_t` outside a test**.
  `ncfg_kernel_set_service` (`c/src/apply/kernel.c:780`) has no caller in
  `c/src/`, and none of the four resolved lists that struct carries --
  `dns_scopes`, `advertising`, `tunnels`, `client_metrics` -- is filled
  anywhere but `service_test.c`. What the DHCP wave landed is the *consumer*:
  `client_metric_on` and the `-m` it produces (`c/src/apply/backend_ops.c:323`
  and `:350`).

  The second is that **the rule's observation half is dead in this build**.
  `netcfgd_model::wifi::effective_metric` is *the network's `metric` while the
  radio is associated to one that carries it, and the interface's own
  `preference` otherwise*, and the first clause reads
  `ncfg_observed_link_t.network` (`c/include/ncfg/observed.h:597`). Nothing
  fills that field here: the readers are `derive.c:343`,
  `c/src/model/linkset.c:151` and `c/src/model/inventory.c:112` and `:270`, and
  the only writer in either language is `ask_supplicants`
  (`crates/netcfgd-observe/src/host.rs:604`), which walks `observed.backends`
  (`:522`) -- the list 10.182 records as empty on every machine because
  `ncfg_owned_state_t` carries no backends. So a producer written today would
  return `interface->preference` for every interface on every machine, which is
  precisely the defect `effective_metric`'s own doc comment records being
  measured: a lease route carrying dhcpcd's 1003 on a document whose network
  said 100, unchanged across a switch to one saying 400. It would be a function
  that looks like the rule and is the bug the rule exists to prevent, with
  nothing able to tell the two apart until the record carries backends.

  `restart_for_metric`, the other half, needs `started_metric` and `running` on
  an observed backend (`c/include/ncfg/observed.h:971`) and closes on the same
  record. `c/src/plan/address.c:169`'s `with_metric` already applies the
  *fallback* clause, which is why a machine that names no networks gets the
  right answer today and is the reason this is a deferral rather than a
  refusal.

* **`planfix.h` carries the two checks a warning's wording needs**, because
  three test files now assert the tail of a sentence rather than a fragment of
  it. `planfix_warning_with` hands back the whole message and `planfix_whole`
  compares its ending against `NCFG_ERROR_MAX`; both came out of
  `plan_gaps_test.c`, where they were private and where a second copy would
  have been made this wave. The Rust has no equivalent: its warnings are
  `String` and cannot be truncated, so this is a check the port owes and the
  original does not.

* **The offload feature names are the model's, and moving them was the whole
  cost of `read_offloads`.** The table lived privately in `src/plan/offload.c`
  above a comment saying the second caller would take it rather than write its
  own; `src/observe/offloads.c` is that caller, so it is now
  `ncfg_offload_field_names` in `document.h`, beside `ncfg_bond_mode_number`
  and for that paragraph's stated reason. `ncfg_link_settings_offload` moved
  with it: an enumerator whose mapping onto a member of `ncfg_link_settings_t`
  lived in the planner would be a second opinion that nothing fails to compile
  over. The Rust reached the same place first and says why --
  `netcfgd_model::interface::offload_names` is in the model "because the
  planner needs them and the planner is pure" -- so this is the port catching
  up rather than a divergence, and it is recorded because the *reason* it was
  ever anywhere else is a fact about this port and not about the Rust. Nothing
  under `src/plan/` or `src/observe/` spells a feature name now; three literals
  in `plan_tc_test.c` are what pins the spellings against the kernel's.
* **The offloads round is a third exchange, and its seam is named for the
  protocol.** `collect.c`'s seven dumps are `NETLINK_ROUTE` and
  `read_netfilter`'s two are `NETLINK_NETFILTER`; ethtool is a generic netlink
  family, which is a third socket again. So `ncfg_observe_current_from` takes a
  third `ncfg_observe_kernel_t` -- called `genl` and not `ethtool`, because one
  generic netlink socket carries every family and naming it after one of the
  questions it can be asked would mean a fourth seam the day the second
  question landed. `ncfg_observe_wireguard_from` is that second question and
  took this seam in the same wave, which is the arrangement working rather than
  a prediction about it.
* **A device the kernel will not answer about is counted, not fatal, and its
  half-read answer is thrown away.** `EOPNOTSUPP` is what a device with no
  ethtool operations answers and is most virtual interfaces, so an observation
  refused over one would be an `ncfg status` that fails on any machine with a
  veth. The Rust `continue`s and says nothing; here the count and the first
  sentence go to a note, so a machine that *stopped* answering is not silent.
  What is not kept is a partial set: where a payload will not decode, the names
  gathered for that device so far are dropped rather than stored, because a
  short list is not a smaller answer to the same question -- it is a feature
  the planner believes is off and sets on every pass. That is `collect.c`'s
  argument about a truncated dump, applied to the one list here that is input
  to a planner.
* **Every link's list is cleared before the round rather than only filled in.**
  `netfilter.c`'s rule, one field along: a second observation taken through a
  source whose seam has gone away must not carry the first one's answer, and a
  list left in place is indistinguishable from one just read. The Rust cannot
  have the question, because it builds a fresh `Observed` per observation.
* **An observed list is empty for two facts the model cannot tell apart**, and
  that is the Rust's shape kept deliberately rather than improved. `offloads`
  is a `Vec<String>` with no "not known", so "every managed offload is off" and
  "this device could not be asked" are the same value -- which means a document
  naming an offload on a device with no ethtool operations plans
  `link.set_offloads` on every pass and fails it on every pass. Telling the two
  apart needs a third state on the field in both languages; it is named here so
  that the residue is on the record rather than found again later.
* **Only `ACTIVE` is read, which is the Rust's shape and is a defect both
  languages have.** A `FEATURES_GET` reply carries `HW`, `WANTED`, `ACTIVE` and
  `NOCHANGE`; the executor writes `WANTED` and the observer reads `ACTIVE`, and
  the kernel does not promise they agree -- a feature the device forces on
  cannot be moved by the first and goes on being reported by the second, so
  `link.set_offloads` is planned, sent, acknowledged and planned again for
  ever. Measured read-only on this workstation: `rx-checksum` is in `ACTIVE`
  and not in `WANTED` on `lo`, `docker0` and both WireGuard devices, which is
  the post-refusal state sitting there before anything was applied. project.md
  10.185 has the measurement. Reading the third state needs somewhere to put
  it, and `ncfg_observed_link_t.offloads` is a list of names in both languages;
  the entry above is the same gap from the other side. Named here rather than
  closed in an observation pass, because closing it is a model change and a
  planner change in both languages.
* **The wiring is checked where the pass cannot see it.**
  `observe_offloads_test.c` drives `ncfg_observe_offloads_from` directly and
  stays green if the one line calling it from `ncfg_observe_current_from` is
  deleted -- which is exactly the state this wave found, a pass that exists and
  is never called. So `current_test.c` carries a case that composes a whole
  observation over a generic netlink replay, which is the file whose stated job
  is the join and is where the netfilter seam is checked for the same reason.
  Measured by deleting that line: the direct test passes and the composed one
  fails.
* **The plan is now right and the apply still refuses, by name.** *Corrected
  by the launcher wave below: `ncfg_service_backend_supported` no longer
  refuses a supplicant, and the sentence quoted here no longer exists. The
  entry stays because the reasoning it records -- why `link.c`'s rule was not
  applied to this op -- is unchanged and is still the reason the planner was
  allowed to emit an action the executor declined.*
  `ncfg_service_backend_supported` had no launcher for a supplicant --
  "needs a `wpa_supplicant` to be launched and adopted; this build talks to one
  that is already running and cannot start one" -- so the `backend.start` this
  arm emits was an action `ncfg apply` declined with that sentence. That was
  `dot1x.c`'s position unchanged rather than a new one, the op being the same
  op, and it was written down here so that nobody read "the supplicant gap is
  closed" as "a WPA laptop comes up": what closed then was the planner's half.
  The executor's half is the launcher, and `link.c`'s rule about not planning
  what the executor cannot do is deliberately not applied to it -- that arm
  exists for `link.create`, where a declined device changes the rest of the
  plan, while a refused `backend.start` is one action that says what is missing
  and 0079 stops counting after five.
* **A WireGuard device the observer could not read stays absent, where NAT and
  the offloads read the same shape as empty.** `ncfg_observe_netfilter_from` is
  right to call a netfilter socket it could not open "no NAT is installed", and
  `ncfg_observe_offloads_from` is right to leave a device's list empty: a kernel
  with no `nf_tables` genuinely has no NAT, and `observed.h` says an empty
  offload list already means off-or-unsupported. **The same reading here would
  change the machine.** A device reported with no peers is a device the planner
  corrects by sending the document's peer list with
  `WGDEVICE_F_REPLACE_PEERS` -- a working tunnel rebuilt from an answer nobody
  got. So a missing socket, a family that will not resolve, a device the kernel
  will not answer for and a reply that will not decode all leave
  `link->wireguard` at NULL, which the model already means "not observed" by,
  and `ncfg_plan_wireguard` returns without planning anything. The Rust takes
  the same direction (`host.rs:311`) without saying why; it is written down
  here because the two neighbouring passes in this module take the opposite one
  and the difference is not obvious from either.
* **The secret store is an argument to the observation and has no default.**
  `read_wireguard_currency` builds its resolver from `secrets_dir()`
  (`host.rs:197`), a process-global that reads an environment variable. Here it
  is a `ncfg_secret_resolver_t *` threaded through `ncfg_observe_current_from`
  and `ncfg_observe_source_t`, and **NULL is the question unasked rather than
  the machine's own store**: an observer that reached
  `NCFG_SECRETS_DIR_DEFAULT` for itself would read the developer's real
  credentials the first time a test forgot to override it, which is this
  module's rule about the three roots pointed at the one directory where it
  matters most. It is also the Rust defect project.md records beside this wave:
  that global does not see `--config-dir`.
* **The preshared-key record is keyed by the key each line parses to, not by
  its text.** The Rust renders the kernel's public key and compares strings
  (`host.rs:245`). Base64 has more than one spelling of one 32-octet key -- the
  last significant character carries four bits and two are not used -- which is
  the reason `document.h` keeps keys as octets and re-renders them, and the
  reason a comparison of two spellings is the wrong comparison. `ncfg_key_parse`
  is public already, so this costs nothing and removes a way for a record to
  miss a peer that is in it. Not a defect in the Rust as it stands, because
  netcfgd writes both sides with one renderer; a divergence because the
  property should not depend on that staying true.
* **The two record paths are declared in `observe.h`, beside the half that
  exists.** The Rust keeps `key_record_path` and `preset_record_path` in
  `netcfgd_apply::kernel` beside the writer, and the observer calls them. In
  this port **there is no writer yet** -- `apply/kernel_genl.c` does not record
  a digest when the kernel accepts a key -- so `key_matches` and
  `preshared_matches` come back absent on every real machine until it lands.
  That is a question left unanswered rather than one answered wrongly, and it
  is the one shape `plan/wireguard.c` is built to do nothing about. The paths
  are published so the writer names the file through them rather than spelling
  it a second time: `NCFG_OBSERVE_ALTNAME_PREFIX` is the same arrangement for
  the same reason, and two spellings of one path is a reader looking where
  nothing was written.
* **Residue, named rather than left to be found.** `request_parts` -- take a
  message this port built apart into the kind, the flags and the body an
  exchange wants -- is now written four times: `observe/collect.c`,
  `observe/netfilter.c`, `observe/offloads.c` and `observe/wireguard.c`, with a
  fifth in `apply/kernel_genl.c`. `family_of` is written twice, in the last two
  of those. Each copy is six lines and each says why it is not spelling the
  request again; none of them is wrong, and they are four chances for one to
  drift. `observe_internal.h` is where the shared pair would go, and moving
  them is a harmonizing pass over files three waves are currently in rather
  than this one's to take.

* **The supplicant's launcher lands, and its mark is udhcpc's rather than
  dhcpcd's.** `ncfg_supplicant_start` starts `wpa_supplicant` with `-P
  <run>/supplicant/<iface>.pid`, and `ncfg_supplicant_running_pid` reads that
  path back out of `/proc/<pid>/cmdline` as a whole `argv` element -- which is
  exactly `ncfg_dhcp_running_pid`, and the same rule as radvd's generated
  configuration and a tunnel's management socket. dhcpcd's three-valued
  `ncfg_dhcpcd_whose` is the only one of the four that is a different
  mechanism, and it exists because dhcpcd calls `setproctitle` and destroys its
  own argv; `wpa_supplicant` does not, so the cheaper mark survives and no
  fifth spelling of ownership was invented. `ncfg_supplicant_adopt` is 0140's
  recovery, `ncfg_dhcp_adopt` with one addition: the process must also be
  answering its control socket, because one that holds its socket and answers
  nothing is netcfgd's by every marker and no use to it.
* **Whose a *stranger's* supplicant is comes from the socket rather than from
  the process, and that is the one place this differs from the other four.** A
  process carrying no mark is not thereby somebody else's -- it may be a dead
  one's leftover socket file -- so `ncfg_supplicant_start` asks
  `ncfg_supplicant_answers` and declines the radio only for a socket that
  answers. A socket that does not is cleared, which is 0080's case and is
  exactly the one the refusal must not swallow. The refusal names the test it
  applied -- no process carries `-P <path>` -- which is 0140's correction, and
  both units to stop on Debian. **It deliberately does not name the socket's
  own path**: `err` is 512 bytes and two absolute paths do not fit beside that
  much prose, and the `-P` path is the one an operator can disprove. A check
  asserts the message is not truncated, because a refusal cut short loses the
  advice at the end of it.
* **Which driver a supplicant is started with comes from the document, where
  the Rust reads it from sysfs.** `start_supplicant` calls
  `netcfgd_sys::radio::is_wireless` for `-Dnl80211,wext` against `-Dwired`, and
  `populate_supplicant` decides between `configure_wired` and the radio's
  networks from the *document*'s `dot1x` block. Those are two answers to one
  question, and the failure they can produce is the worst one available:
  `supplicant.h` records that `WPA-EAP` on a wired port gives a network the
  supplicant accepts and never authenticates with -- everything looks
  configured and the port stays blocked. So the C asks once,
  `ncfg_service_supplicant_driver`, built out of the two lookups
  `ncfg_service_set_profiles` branches on, and the order is
  `ncfg_plan_radio_supplicant`'s: `dot1x` first, because an interface carrying
  that block has said what its supplicant is for. An interface the document
  describes as neither is refused by name rather than given a driver by
  elimination -- the planner emits a supplicant from those two passes and from
  nowhere else, so such an op did not come from this build's planner. The
  declaration lives in `src/apply/service_internal.h`, a second private header
  in that directory, because `kernel_internal.h` states in its first sentence
  that it is the kernel-side ops as messages and none of this is a message.
* **Filling a supplicant is part of starting it, and the start fails if the
  filling does.** `ncfg_service_backend_start` calls
  `ncfg_service_set_profiles` after `ncfg_supplicant_start` returns, which is
  the Rust's arrangement -- `populate_supplicant` is called from the
  `backend.start` arm, not on a later reconcile -- and `plan/wifi.c`'s
  `plan_profiles` comment says so. A start that returned with an empty
  supplicant would report a port authenticated that is not, and a radio holding
  credentials it was never given. The process is left running when the
  population fails, which is also the Rust's behaviour and is the honest one:
  the action did not achieve what it said, and `backend.stop` is what takes the
  process away.
* **`backend.stop` on a supplicant lands with the start, and a silent socket
  fails it.** The planner declares the start's inverse to be the stop and
  `ncfg_plan_teardown_backends` emits one whenever a supplicant stops being
  wanted, so a carried start with a refused stop would be an inverse a revert
  silently skips. `ncfg_supplicant_stop` is `stop_access_point`'s shape in the
  supplicant's own module -- `TERMINATE` over the control socket, never a
  signal to a process found by name (0014) -- and it takes the stricter half of
  0109 for that function's reason: absence is the socket file not being there,
  and a socket that is there and silent is a failure naming it rather than a
  radio reported released. **Nothing removes such a socket**, so a supplicant
  killed outright costs one refused stop until `ncfg_supplicant_start` clears
  it; that is the same trade the access point's stop takes, and the two are
  kept in step deliberately.
* **The supplicant is a fourth program in `ncfg_service_t` and there is no
  environment variable.** `supplicant_program` is the seam the Rust spells
  `NCFG_WPA_SUPPLICANT`, whose own comment records what its absence cost: the
  fixed directories are searched before `PATH`, so on any machine that has
  `wpa_supplicant` installed -- which is every machine this runs on -- a test
  could not put a stand-in in front of it, and the one thing that function does
  was only ever exercised by hand. NULL still means "find the conventional
  name", `/usr/sbin` first, which is `ncfg_hostapd_start`'s convention.
* **The service-side executor has no caller in `src/main/`, and that is the
  remaining gap rather than this one.** `ncfg_kernel_set_service` is called
  from nowhere outside the tests, so the daemon's executor carries out the
  netlink half of a plan and refuses every op in `service.h` by name --
  `dns.apply`, the four sysctls, the six wifi ops and all three backend verbs.
  Removing the supplicant's refusal from `ncfg_apply_supported` therefore makes
  `ncfg diff` and `ncfg apply --dry-run` right about a WPA laptop and does not
  on its own bring one up. Written down here for the reason the entry above it
  was: so that nobody reads "the launcher landed" as "a WPA laptop comes up".

### The entries above that have since closed

Five waves of divergences are recorded above and some of them describe a state
this port has left. They are **not rewritten**: a decision record is what was
decided and why, and editing the reasoning out of one leaves a citation
pointing at a claim nobody can check. What follows is the closing note for
each, in the order they appear.

* ***`effective_metric` stays deferred on both halves***. Closed, and that
  entry deserves credit it did not get: it named **both** blockers exactly,
  including that `ncfg_observed_link_t.network` had no writer in this port and
  that a producer written without one "would be a function that looks like the
  rule and is the bug the rule exists to prevent". A later wave rediscovered
  that second blocker independently, by re-deriving what `ask_supplicants`
  does, and only then found this paragraph had said it first (project.md
  10.202). The first blocker went when `ncfg_main_service_of` began composing
  an `ncfg_service_t` (10.189) and the four lists were filled over the waves
  that followed (10.189, 10.190, 10.192); the second went when
  `ncfg_observe_supplicants` landed (10.202). Both halves of the rule are
  applied now -- `with_metric` through `ncfg_observed_effective_metric`, and
  `ncfg_plan_metric_restart` for a client already running with the old one --
  and the warning that named the gap came out in the same commit that closed
  it, which is `build.c`'s rule.

* ***The service-side executor has no caller in `src/main/`***. Closed:
  `ncfg_main_world_executor_open` installs one (10.189). The entry's warning --
  "so that nobody reads *the launcher landed* as *a WPA laptop comes up*" -- is
  the reason it was worth writing, and the same shape recurred twice more
  afterwards: `ncfg_wifi_configure_network` had an implementation and no caller
  (10.203), and `ncfg_kernel_set_document` had none either, which left six
  netlink ops refusing by name (10.204). Both were found by **measuring** for
  a published function with no caller rather than by reasoning about what was
  left, which is the method 10.204 records and recommends repeating.

* ***`netcfgd_host::wifi_profile` was not ported***, and the arms that cited
  it. The module landed; what outlived it was the daemon's refusal, which went
  on saying the profile writer was "a seam with no implementation in the C
  port" until 10.203.

* ***The `observe.h` entry that named the deferred passes had been wrong for
  several waves***. It was wrong again afterwards, twice, and is now right:
  every observation pass that header names is written (10.199 through 10.202).

* ***The journal writer is still deferred and is now the whole of it***, which
  was the closing clause of the entry above it. Closed too:
  `ncfg_apply_write_journal` publishes `plan.last.json`, and both paths that
  apply a plan call it -- the reconcile pass and the confirm window's revert --
  through `ncfg_daemon_record_what_ran`.

* ***`applied_dns` has nowhere to go for the reason `state.h` already
  gives***. The reason had expired: `state.h` carries `dns`, reads it and
  writes it. What the entry could not see is that carrying a member is not
  having a writer for one, and this one had none -- so `observed.dns`, which is
  filled from that record and from nowhere else, was empty on every machine and
  the planner asked for a delivery it had already made, on every pass, for ever
  (project.md 10.205). It is folded now: `ncfg_apply_record` takes the scope
  list an apply delivered, because `dns.apply` is the one op that is not its
  own effect. The entry's own argument for deferring it -- that a deep copy of
  an `ncfg_dns_policy_t` "exists nowhere in this port" -- was sound and is
  answered rather than ignored: the copy is a render and a parse through the
  model's field tables, so no hand-written one exists now either.

**The pattern these share is the one worth carrying forward.** Every entry
above was true when written. What made them dangerous is that each described a
*gap*, and a gap is the one kind of claim that becomes false without anybody
touching the sentence. A deferral is therefore worth revisiting on a schedule
rather than when something reminds you of it -- and `grep` for the shape, not
for the words, because the words are what went stale.

**The last one goes further and is the reason to keep doing this.** The other
four were sentences that had outlived their subject and cost a reader some
confusion. That one was a sentence that had outlived its subject **and was
standing in for a defect**: while it said the member was waiting on something,
nobody asked who filled it, and a machine running this build would have
rewritten its resolver configuration on every reconcile until somebody noticed.
A stale deferral is not only bad documentation -- it is where a missing writer
hides.

## What is not being decided here

Whether the C replaces the Rust, and when. Nothing in `c/` is installed, the
packaging keeps shipping the Rust, and a module is a candidate only once it
passes the Rust's own tests for the same behaviour. That comparison is the next
decision and it needs the modules to exist first.
