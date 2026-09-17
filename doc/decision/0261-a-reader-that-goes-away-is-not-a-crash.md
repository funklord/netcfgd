# 0261: a reader that goes away is not a crash

Status: accepted
Date: 2026-09-18
Milestone: M9; the window can configure the machine

## What it did

    $ ncfg status | head -1
    docker0 up, no carrier mtu 1500

    thread 'main' panicked at library/std/src/io/stdio.rs:1123:9:
    failed printing to stdout: Broken pipe (os error 32)

Exit 134, and a crash report at somebody who had done nothing wrong. Every
ordinary shape did it -- `| head`, `| less` quit early,
`ncfg show | jq .interfaces[0]` -- and so did `netcfgd --version`, which is the
same binary under its other name.

`println!` unwraps its write. Rust sets `SIGPIPE` to ignore at startup, so a
reader that has gone comes back as `EPIPE` rather than as a signal, and the
unwrap turns that into a panic. Noticed while checking an install, from
`netcfgd --version | head -1`; the deterministic form is `| true`, which closes
the read end before the child has written anything.

## The one-line fix is the wrong one

Restoring `SIGPIPE` to its default would make stdout behave like every other
Unix tool in three lines of `unsafe` in `netcfgd-sys`. It would also apply to
**the socket the client writes its requests into**: a daemon restarted
mid-request would kill `ncfg` where today it prints *"cannot send to netcfgd"*,
and this tree has a test whose whole subject is that an unreachable daemon says
what to do.

The C client reached the same junction from the other side and answered it the
same way. `write_all` there is `send` with `MSG_NOSIGNAL`, per call, with a
comment refusing to change a process-wide disposition on behalf of a program
that did not ask: *"a host application that wants SIGPIPE for its own pipes
keeps it"*. A dead reader on **stdout** is the program's own business; a dead
peer on a **socket** is a diagnostic somebody needs.

So printing is what changes. `netcfgd_sys::out::emit` writes through
`write_fmt` -- the same thing `println!` does -- and where `println!` would
unwrap, it exits **141**: 128 + `SIGPIPE`, which is what a shell reports for
the tool this would have been if the signal were on its default. `say!` and
`sayln!` are the two macros, and the 160 print sites in `ncfg` and in the
daemon's usage and version paths use them.

`netcfgd_sys::log::emit` has always done the same for stderr: it writes with
`let _ =`, because a log line nobody can receive is not a reason to take a
daemon down. This is that rule, arriving at the other stream eleven months
later.

## `format_args!`, not `format!`

The first version took a `&str` and each site handed it a `String`. It cost a
page of binary -- 4,096 bytes, which is a size-budget entry -- and an
allocation per line printed. Passing `std::fmt::Arguments` through to
`write_fmt` is what `println!` itself expands to, and it costs **nothing**: the
installed size is byte-identical to the round before it.

## What is tested, and what is gated

**The behaviour**, in `netcfgd-cli`: a socket pair whose reader is dropped
*before* the spawn, so the child's first write cannot do anything but fail.
Dropping it afterwards would let a fast machine finish writing first and the
check would pass having proved nothing. Both names are driven, because they are
two programs in one binary and the printing paths are not shared.

**Every other print site**, by `tool/print_gate.py`: no `println!` or `print!`
in either program. A print site is never *wrong*, only absent from the path a
test drives -- the same reason the icon names needed a gate rather than a test
in 0259 -- and the sabotage that proved it is a `println!` on `ncfg`'s
no-arguments path, which the behavioural test does not reach and the gate names
by line.

`eprintln!` is left alone deliberately: stderr is not usually the pipe that
closes, and by the time it matters stdout has already ended the process.

## The proof the rewrite carries

160 sites changed mechanically, so the thing that must not change is the
output. The previous binary was still installed at `/usr/bin/ncfg`, so the two
were run side by side over ten read-only commands -- `--help`, `--version`,
`status`, `show`, `plan`, `config list`, `secret list`, `profile list`,
`wifi list`, `control show` -- and compared byte for byte. Ten identical, none
differing.
