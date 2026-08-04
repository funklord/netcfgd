# 0082: one operation has one name

Status: accepted
Date: 2026-08-04
Milestone: M8, found by the first second implementation of the protocol

## Context

netcfgd has had two names for every operation since M1, and nothing noticed,
because until now every program that read a plan was written in the same
workspace as the program that wrote it.

A plan serialises `Op` as an internally tagged enum, so the tag is serde's
`rename_all = "snake_case"` of the variant:

```json
{"op": {"op": "link_create", "name": "br0"}}
```

A journal record stores `Op::name()`, the short name the planner, the CLI and
the TUI all use:

```json
{"op": "link.create"}
```

`ncfg plan` prints the second because it holds the `Op` and can call `name()`.
`ncfg plan --json` emits the first. Both are netcfgd, so nobody ever saw them
side by side.

The GUI does. Its apply dialog shows the plan and then the journal the apply
returned, one above the other, and it read:

```
plan     0  link_create  probe0   kind: <absent> -> dummy
journal  1  link.create  probe0   done
```

Two names, one operation, four lines apart -- and neither of them is wrong.

## Why the client cannot fix it

The obvious repair is a transformation in the client: swap the first underscore
for a dot. It is right for forty-four of the forty-seven ops and wrong for
three:

| tag                      | actual name              | the guess               |
| ------------------------ | ------------------------ | ----------------------- |
| `bridge_vlan_add`        | `bridge.vlan.add`        | `bridge.vlan_add`       |
| `bridge_vlan_del`        | `bridge.vlan.del`        | `bridge.vlan_del`       |
| `ingress_redirect_clear` | `ingress.redirect.clear` | `ingress.redirect_clear`|

The other repair is a table of forty-seven names in the client. That is a copy
of something netcfgd already owns, in a language with no way to keep the two in
step, in a file that every future client would copy again.

## Decision

**The daemon sends the name.** `Action` gains `op_name`, serialised beside `op`
and holding exactly what `Op::name()` returns.

```rust
/// The op's short name, the one everything else already prints.
#[serde(default)]
pub op_name: String,
```

Set in `Planner::push`, which is the single place every action in a plan comes
through. `#[serde(default)]` so that a plan written before this field still
deserialises -- `Action` has `deny_unknown_fields`, and a struct that refuses
the future is only half the problem.

Additive: 48 lines in `docs/schema/plan.json`, no field changed or removed. A
**minor** bump.

## What was rejected

**Renaming the tags themselves**, so that `#[serde(rename = "link.create")]`
makes the wire carry one name and only one. Better design -- redundancy is what
went wrong here, and this adds more of it -- and not taken now for two reasons.
It is a breaking change to a pinned surface, and it is the kind of change whose
value is judged by whoever maintains the protocol rather than by whoever noticed
the symptom. `op_name` does not foreclose it: the day the tags become the names,
the field is deleted and clients that read it keep working through the fallback
below.

Recorded as open, deliberately, rather than done quietly.

## The gate

`client/tests/client_test.c` asserts the name of an action whose op is
`bridge_vlan_add`, and expects `bridge.vlan.add`. Removing the `op_name` lookup
makes it fail with `actual: bridge_vlan_add` -- which is also what the guessing
transformation would have produced for this op and not for most, which is why
this op and not `link_create` is the one in the fixture.

A second check pins the fallback: two actions in the same fixture carry no
`op_name`, and their op reads back as the tag. An older daemon gets a plan with
the wrong word in the op column, which is bad; an empty op column, which is what
a client insisting on the new field would show, is worse. A plan that will not
say what it is about to do is not a plan.

`crates/netcfgd-plan/tests/frozen.rs` went red on the witness the moment the
field appeared, before any of this was written down. That is the gate working:
a protocol change that did not reach `docs/schema/plan.json` is a protocol
change nobody reviewed.
