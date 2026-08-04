# 0103: a check that asserted the machine rather than the code

Status: accepted
Date: 2026-08-04
Milestone: the last of 0101's Alpine failures

## Context

[0101](0101-a-fake-on-path-does-not-fake-what-netcfgd-finds-in-sbin.md) left two
Alpine failures beside the tunnel one. **One of them was not a failure at all**,
and finding that out is the more useful half of this record.

**`slaac.sh` was reported as failing on two distributions and passes.** Most
live scripts run under `unshare -rn` from the Makefile; three do not, because
they make their own namespaces — `unshare -rn` writes `deny` to
`/proc/self/setgroups`, which is what an unprivileged gid mapping costs, and
dnsmasq and dhcpcd then cannot drop privileges. A sweep that wrapped every
script alike broke `slaac.sh` and the breakage read as a broken feature: *"the
router did not start"*.

That knowledge lived in the Makefile and nowhere else. `slaac.sh` and
`dhcpcd.sh` now read `/proc/self/setgroups` and skip with the reason and the
remedy, so the next uniform sweep is told rather than misled.
`pppoe-session.sh` is the third and needs nothing: it drops no privileges.

**`ppp.sh`'s failure was real**, was not Alpine's, and is the subject below.

## The defect

```sh
check "and stops where an unprivileged machine has to" \
	"$(grep -c '/dev/ppp' "$work/parse.txt" || true)" "1"
```

The rp-pppoe plugin opens `/dev/ppp` as it loads. Where that device is out of
reach — an ordinary desk, an unprivileged container — the plugin fails there,
pppd never reaches the options after the plugin line, and the message names
`/dev/ppp`. The check demanded that message.

Where `/dev/ppp` **is** present — real root, or the privileged container
`project.md` recommends for the full suite — pppd parses the whole file and
**accepts it, exiting 0**. Measured on pppd 2.5.2 against the file netcfgd
actually writes. So the check went red on every machine that could open the
device, and green on every machine that could not.

That is the third instance of one shape found in a single session, after
`tunnel.sh` and `openvpn.sh`: **a check that is green on the machine in front of
you and red wherever the thing it tests is really available.** Here it is
sharpest, because the check was not merely environment-sensitive — it asserted a
fact about the *machine* while reading as a fact about netcfgd's options file.

## Decision

**The script says which world it is in, and asserts accordingly.**

- `/dev/ppp` out of reach: pppd stopped at the plugin, so nothing after it was
  parsed. The narrower check below — the file with `plugin`, `nic-` and
  `rp_pppoe_*` stripped, fed to pppd on its own — is the one carrying weight,
  and it always was.
- `/dev/ppp` available: pppd parsed the whole file and its exit status is
  asserted to be 0. That is a **stronger** result than the other branch can
  give, and it was what the old check called a failure.

Both branches are exercised, not assumed: the privileged container has the
device, and removing it reproduces the other world in the same image.

## The gates

|  | with `/dev/ppp` | without |
| --- | --- | --- |
| Debian, pppd 2.5.2 | 14 pass | 14 pass |
| Alpine, musl | 14 pass | 14 pass |

The break is the old single check, restored, on a machine that can open the
device: it goes red exactly where it always did.

## What building it found

**Removing `|| true` from a command whose failure is the point turns a failing
check into no checks at all.** Capturing pppd's exit status meant calling it
without the swallow — and `set -e` then killed the script at that line in
precisely the branch being added. The run reported **zero failures** and was not
a pass: it had stopped before every remaining check. `|| parsed=$?` is the
shape, and the near-miss is worth recording, because "0 failed" and "all checks
passed" look alike at a glance and only one of them is evidence.

**Three false starts came from measuring the wrong thing**, all recorded because
each was cheap to make: a glibc `ncfg` copied onto Alpine (twice), and a
hand-written options file whose `unrecognized option` I briefly read as
netcfgd's. netcfgd's real file is accepted in full.
