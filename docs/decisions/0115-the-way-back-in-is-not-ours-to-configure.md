# 0115: The way back in is not ours to configure

Status: accepted
Date: 2026-08-06
Milestone: direction; nothing here is scheduled

## Context

Asked whether netcfgd should speak IPMI or SNMP. They are not one question,
and [0036](0036-the-shim-is-not-the-roadmap.md) had already answered half of
one -- which is worth saying, because the two halves of SNMP get conflated the
same way 0036 found OVS and switch management being conflated.

IPMI had not been raised here at all: no mention of it, of Redfish, or of a BMC
anywhere in the tree before this record.

## SNMP: 0036 closed the manager, this closes the agent

**Configuring other devices over SNMP** is settled and stays settled. 0036:
"OVS is a switch running *on this host*; SNMP switch management configures
*other devices*. The second is not this machine's network configuration at
all." It needs design section 11.4's fleet tree, separate from `/etc/netcfgd`.

**Serving SNMP** -- netcfgd as an agent, exposing its own state through
`IF-MIB` -- is a different shape and was open. It is a northbound adapter,
structurally the same as `netcfgd-nm` and `netcfgd-restconf`, so nothing about
it threatens the core. It is still refused, for three reasons that compound:

- Section 7 picks RESTCONF as *the* northbound answer and puts it last on
  purpose, so that nothing before M9 is shaped by fleet considerations. A
  second northbound protocol arriving earlier spends exactly the ordering that
  decision bought.
- `net-snmp` already serves `ifTable` and `ifXTable` from the kernel on any
  Linux host. An agent here re-serves counters the operator already has.
- What netcfgd knows that nothing else does -- a plan, the reason an action
  exists, a drift verdict -- has no home in SNMP's data model. Expressing it
  means an enterprise MIB under an IANA enterprise number, written for no
  existing consumer. The same information maps onto YANG without inventing
  anything, which is why M9 is RESTCONF and not this.

If it is ever wanted it is `adapter/netcfgd-snmp`, after M9, under constraint
6 like every other adapter.

## IPMI passes the tests it ought to fail

This is why it deserves a record rather than a sentence. The obvious objections
do not land:

- **Constraint 9** asks whether a feature is directly useful for real-world
  networking. A BMC's LAN channel is real hardware on every rack server, with
  an address, a netmask, a gateway and often a VLAN id. It is not an overgrown
  VM topology.
- **Constraint 6, the one-way rule**, asks whether a local user would want the
  concept in their own config file independent of any adapter. Plausibly yes:
  `ipmitool lan set 1 ipaddr` is precisely the imperative, unversioned,
  drift-prone step netcfgd exists to replace with a file.
- **Constraint 3** is not threatened either. Local access is `/dev/ipmi0`
  through the kernel's OpenIPMI driver -- an ioctl on a character device. No
  D-Bus, no HTTP client, no TLS stack, nothing the dependency budget would
  notice.

A future reader will re-propose IPMI on exactly these grounds, and will be
right about all three. That is not where it fails.

## Where it fails

**Ownership is unanswerable.** Section 2.3 is load-bearing: drift detection is
meaningless unless netcfgd can distinguish objects it installed from objects
somebody else installed. Routes carry `rtm_protocol`, addresses carry
`IFA_PROTO`, and where the second is unavailable there is a recorded fallback
and `ncfg explain` says which mechanism answered. **IPMI has no equivalent, and
there is nowhere to put one.** A BMC's LAN settings can be changed from the
BIOS setup screen, the vendor's web interface, Redfish, or a DHCP server on the
management network, and none of those leaves a mark netcfgd could read back. So
netcfgd could overwrite a BMC but never reconcile one, and `ncfg plan` -- which
is the product, per constraint 7 -- would have to answer "I cannot tell whose
this is" on every run. A feature that cannot answer this project's central
question is a poor fit for this project regardless of how cheap it is.

**And it inverts the safety model.** The BMC is the way back into a machine you
have locked yourself out of. Everything netcfgd does about that risk assumes
the way back in is *outside* what netcfgd touches: commit-confirm arms a window
and reverts on a timer, `docs/first-run.md` opens by telling the operator to
have a second way onto the machine or physical access to the console, and
[0010](0010-interface-guards.md)'s guard exists so an operator can say
"something depends on this interface" out loud.

Letting netcfgd reconfigure the BMC makes the way back in and the thing being
changed the same object. Worse, it defeats the one property the revert relies
on: a bad host-network change is undone by a timer on the host, or failing
that by a reboot, and **a bad BMC change survives both** -- the BMC is powered
and reachable when the host is neither. Commit-confirm cannot cover the object
that exists to rescue commit-confirm.

That second reason is the one to remember. The first is an argument about fit;
this one is an argument about harm.

## Timing, independently

DMTF has moved management to Redfish, and the major server vendors announced no
new IPMI feature development years ago. Adopting it now would be adopting a
protocol on its way out, which is the same argument that keeps *teaming* out in
favour of bonding (0036) -- deprecated by its own sponsor.

## What would change the answer, and the shape if it did

Two things would reopen this, and neither is close:

- A BMC gaining something netcfgd could tag and read back, the way
  `IFA_PROTO` answered the same question for addresses. Then reconciling
  becomes possible and only the safety argument remains.
- The fleet tree of design section 11.4 actually existing. Managing a BMC is
  much more obviously a fleet concern than a single-host one, and the second
  half of SNMP already lives there.

If server management is ever wanted, the shape is already invented here and it
is **not** a core feature: the contained helper of
[0044](0044-the-modem-helper-is-contained-the-way-an-adapter-is.md) and
[0045](0045-the-contract-is-the-decision-and-the-helper-is-plural.md), where
the core learns nothing about the protocol and the contract is the decision.

One correction to make in advance, because it is the obvious wrong turn:
`docs/interface-report.md` is the wrong contract. It is **inbound** -- a DHCP
client, a pppd script or a VPN helper reporting addressing it obtained. A BMC
is **outbound**, something configured rather than something reporting. Reusing
the report contract for it would put a writer and a reader on the same file in
opposite directions, and 0113 is already the record of what happens when that
directory's rules are not thought through. It would need its own contract, and
it should target Redfish rather than IPMI.
