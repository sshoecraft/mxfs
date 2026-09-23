---
name: trap-a-guard-whose-test-is-a-proxy-for-its-stated-question-refuses-the-wrong-cases
description: TRAP (s75): run.sh refused to power-cycle a wedged node whenever MXFS_NODE_LIST was set, as a proxy for "external host" — but every 2-node harness se…
metadata:
  type: feedback
tags: [harness, rig, run.sh]
---

# Ask the question the comment says you are asking

`run.sh` `power_cycle_node` refused recovery with:

> CANNOT auto-recover $n: MXFS_NODE_LIST nodes are external — virsh has no
> domain for them

Its comment states the real question precisely: *"it assumes the node IS a VM
in the local test fleet whose domain name equals the node name"*. Its test was
`[ -n "${MXFS_NODE_LIST:-}" ]` — a proxy that was true for the case it meant to
catch (a Proxmox host) and **also** true for every 2-node harness in `tests/`,
all of which export `MXFS_NODE_LIST=test1,test2`. Those are domains in this
fleet; `virsh list --all` lists them.

Cost: a wedged `test1` or `test2` is refused, prep fails `unusable after power
cycle`, and the whole lap is discarded. It happened twice in one session, and
each time the node recovered instantly with `virsh destroy` + `virsh start` by
hand.

The fix is to ask directly — `timeout 20 virsh -c qemu:///system domstate "$n"`
succeeds (rc 0) for a domain that exists, including a shut-off one, and fails
(rc 1) for an unknown name. Both branches verified on this host. A libvirtd
that cannot answer inside the bound must also refuse, because "cannot
establish" fails closed rather than falling through to a power cycle.

**The general shape**: when a guard's condition is a *proxy* for the property
its comment names, it fails on exactly the inputs where proxy and property
diverge — and those failures look like the guard working, because it prints its
own justification.

**Operational note that goes with it**: a `fence_lost_response` lap ends by
design with a blocked slice, the module held and the mount up on the prover, so
the *next* lap's prep has to power-cycle it. That is not a wedge to diagnose;
it is the previous lap's terminal state.
