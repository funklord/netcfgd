# 0278: client text cannot change a generated file's structure

Status: accepted
Date: 2026-10-21
Milestone: M9; the C port

## What this decides

`netcfgd-nm` renders a client's settings dictionary into netcfgd
configuration, and the daemon compiles whatever comes out. **So every piece of
client text the renderer writes has to be unable to change the file's
structure**, and there are exactly two ways to achieve that:

* **Refuse, where the text is a value somebody typed.** A `dns-search` entry,
  an address, a label: these are the client's content, and rewriting one
  silently would leave an operator with a configuration they did not ask for.
  A quote, a backslash or a control character in such a value is refused by
  name, the way a malformed address already was.
* **Sanitise, where the text is being quoted back in a comment.** The
  dropped-settings note names every setting netcfgd cannot express, which 0034
  requires -- so refusing a whole profile over a name would throw away
  something the client can otherwise have in order to protect a comment.
  Anything outside printable ASCII becomes `?`, and the name is bounded.

Neither is a stylistic preference. The third option -- write it through and
hope -- was what the code did, and it was a configuration injection.

## Why this is a decision and not just a fix

Because the next person adding a key to the renderer has to know which of the
two applies, and the answer follows from where the text lands rather than from
how dangerous it looks. A value goes inside quotes, so the quote is the
boundary and a client that can write one owns the rest of the line. A note
goes inside a comment, so the newline is the boundary. **Both boundaries are
one character wide**, and that is the whole of the reasoning.

It also says what NOT to do: do not reach for an escaping scheme. netcfgd's
language has no escape for a quote inside a quoted value, so there is nothing
to escape to -- which is why one site refuses and the other substitutes.

## What was wrong, exactly

A client that named a setting key with a newline had the name written into the
note, where the newline ended the comment and everything after it was
configuration the client chose:

    #   connection.x"
    }

    network "injected" {
    	ssid = "anything"
    	wifi { open = true }
    }
    #

    network "Victim" {
    	wifi { open = true }
    }

The second site was `dns-search`, whose entries went into `search = [...]`
unchecked, and which could close the list and the block the same way.

**What the caller is allowed to do, and what it got.** `AddConnection` is
authorized for a client that may add a wifi network -- the uid is checked
against the daemon's own rule. What this gave such a client was the ability to
write any configuration netcfgd will compile into a file under
`/etc/netcfgd/conf.d`, which is a different and much larger permission.

## How it was found, and what that says about the method

Fuzzing, on the day the shim's dictionary reader got a target (0277, project.md
10.509). Not by a crash: the renderer never crashed. A target assertion fired
on a near-miss -- a passphrase that happened to equal a group name the note
lists -- and reading that output showed the note echoing client text verbatim.
The injection itself was then reproduced by hand, because the generator could
not express a newline.

So the fuzzer did not find this defect; it put the output in front of somebody
who could. That is worth recording accurately rather than as a success story
for fuzzing, and it is why the targets now assert the block's SHAPE -- one
network block, every line a comment, a tab-indented key, the header or the
closing brace. With that assertion in place, the input that injects is a crash
rather than a quiet pass, and it is a committed corpus input from now on.
