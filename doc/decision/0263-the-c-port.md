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
* **No provenance side table.** `compile_with_provenance` is not ported;
  `ncfg explain` is not in this wave, and a side table nobody reads is a second
  thing that has to go on agreeing with the document.
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

## What is not being decided here

Whether the C replaces the Rust, and when. Nothing in `c/` is installed, the
packaging keeps shipping the Rust, and a module is a candidate only once it
passes the Rust's own tests for the same behaviour. That comparison is the next
decision and it needs the modules to exist first.
