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
* **No provenance side table, and `ncfg explain` says so rather than going
  quiet.** `compile_with_provenance` is not ported: nothing in `src/compile/`
  records an entry, because a side table nobody reads is a second thing that
  has to go on agreeing with the document. `state.h` declares the table and
  reads and writes `provenance.json` regardless, since that file's *shape* is
  something this port reads whoever wrote it.

  `ncfg explain` **is** in this wave, and it is the command that exists to
  answer where a value came from -- so this is the whole of its subject rather
  than a detail of it. It takes the table as an argument exactly as the Rust
  does and is complete the day lowering starts recording one; until then every
  lookup misses. **An explanation whose every lookup missed against an empty
  table says so, in its own output, as its first fact**, and names no file and
  no line anywhere. The alternative is an answer that silently stops naming
  files, which a reader cannot tell from a configuration that has nothing to
  name -- and an `explain` that invented a position would be worse than one
  that says it does not know. It is the *first* fact for the reason the radio
  fact comes before the addresses: a caveat about what an answer cannot contain
  is worth nothing printed after the answer. Where the table has entries and
  this field is not among them, nothing is said: that is a gap in a table
  rather than the absence of one, and a blanket claim about it would be wrong.
  Both directions are tested, including that the notice disappears the moment
  a table with one entry is handed in.
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
  quietly missing.
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
  passes of thirty, its executor takes thirteen ops of forty-eight, the daemon
  runtime is unreachable code, `--json` and the `network`-block writer are not
  ported, and nothing records provenance. Three of the Rust's four libraries
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
  * the executor takes thirteen ops of forty-eight and refuses the rest **as
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

## What is not being decided here

Whether the C replaces the Rust, and when. Nothing in `c/` is installed, the
packaging keeps shipping the Rust, and a module is a candidate only once it
passes the Rust's own tests for the same behaviour. That comparison is the next
decision and it needs the modules to exist first.
