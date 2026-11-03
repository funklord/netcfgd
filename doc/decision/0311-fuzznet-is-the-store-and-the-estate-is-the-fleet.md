# 0311: fuzznet is the store, not an option, and the estate is the fleet

Status: accepted
Date: 2026-11-03
Milestone: fuzznet integration (project.md 10.676 to 10.684), and M9
Amends: [0308](0308-fuzznet-is-linked-into-netcfgd.md), which linked fuzznet and left serving opt-in

## The holder's words

> Fleet management is settled within the simple case = every node belonging
> to the same estate should work with an operator authenticated. Fuzznet is
> to be our distributed store by default, it is not optional. Everything
> internal goes via its protocols, netcfgd is precisely why it has those 3
> different models of communication.

## What changes

- **Serving is not a build option.** fuzznet's node loop is always linked,
  and a daemon with a node serves its store inside that loop (10.676): the
  local socket, the estate's rounds and the records. `NODE_SERVE=1` and its
  stub are gone, and `--fuzznet-serve` is accepted and does nothing. A daemon
  with no node -- a test, a second instance on another run directory --
  keeps its own loop, which is what a missing node always meant.
- **The size it costs is paid**, about 980 KB of the installed program,
  recorded in `size-budget.txt` with the reason. Most of it is fuzznet's
  consumer services, which fuzznet may make build options (its sec 842);
  that is a reduction to take when it comes, not a condition on this.
- **Everything internal goes over fuzznet's protocols.** 0309's local
  socket was already this; this record makes the store and the estate the
  same rule, rather than a direction.

## The fleet

**Multi-host management is the estate**, in the simple case the holder names:
every node of one estate does what an authenticated operator of that estate
asks. That replaces M9's premise that RESTCONF *is* the multi-host answer
(project.md section 7, design section 11.1). RESTCONF and NETCONF stay where
M9 put them, last, as a northbound interface for sites that want one --
**not** as how netcfgd's own nodes are managed together.

Beyond the simple case -- operators with partial authority, external callers
who are not estate operators -- is not decided here; the holder said of it
the same day that external auth "is a different story and not completely
fleshed out other than the simple case" (10.683).

## The three models

They are fuzznet's section 2, in the holder's words of 2026-09-06:

    1. local_user_client  -> local_user_daemon   authenticated by user
    2. local_user_client  -> local_root_daemon   authenticated by group
    3. local_client       -> remote_daemon       encrypted and authenticated

and every daemon may also connect to other daemons. netcfgd is the root
daemon of the second -- `ncfg` and the GUI as a user, judged by netcfgd's
group (10.683) -- and the remote daemon of the third, for an operator of its
estate. The first is fuzznet's own: a fuzznetd running as its user.
