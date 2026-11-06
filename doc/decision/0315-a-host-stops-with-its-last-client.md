# 0315: a host stops with its last client

Status: accepted
Date: 2026-11-06
Milestone: fuzznet integration (project.md 10.738)
Amends: [0314](0314-a-client-configures-this-machine-or-is-a-host-of-its-own.md), whose ten seconds after nobody holds the lock this removes

## Decision

A daemon started with `--while-held` stops at its first look, once a second, that
finds nobody holding `ncfg-clients.lock`. There is no linger.

## Why

The ten seconds existed because a host started again within fuzznet's kept-reply
window was dropped as a stranger's copy. fuzznet fixed that at a3d1fd9 (its sec 910):
a caller begins its numbers at a random point. Its other reason, one daemon under a
script's run of `--at`, was measured and is worth nothing: an `--at` that starts a
daemon took 24 ms against 10 ms for one that finds it up.

## Rejected

Keeping a shorter linger. It would be a number with no reason behind it, and a person
who has finished would still have a process running for no purpose.
