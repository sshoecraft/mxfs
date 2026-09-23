---
name: trap-a-lone-fresh-mount-on-two-nodes-is-a-whole-cluster-bootstrap-that-recovers-the-victim-inline-or-refuses
description: TRAP (s151a/b): a survivor that unmounts and mounts again alone with the peer dead runs the total-outage bootstrap; it cannot stand a parked recovery…
metadata:
  type: feedback
tags: [bootstrap, transition, two-node, lap-design, trap]
---

# A lone fresh mount on a two-node rig is the whole-cluster bootstrap

Two sessions designed a "REMOUNT arm" to reach a page transition stalled on a dead
authority: prover unmounts, victim destroyed, prover mounts again as a fresh incarnation
whose view holds only itself, then unmounts against the standing recovery guard.

What the lap measured (s151a/s151b, 0.89.69, `REMOUNT=1 tests/nonfallible_transition_stall.sh`):
the fresh mount's task sat in `mxfs_bootstrap_survivor_scan` at 45 s and again at 100 s — the
first scan and the post-claim seal scan of `v5_bootstrap_run`. With no live member the mount IS
the total-outage bootstrap: two 62 s windows, then phase 3 fences and certifies every victim
inline, then adopts a victim slice and replays it as its own log. So either the victim is
recovered before the mount masters anything (no guard for the unmount), or the recovery cannot
complete (injector) and the bootstrap REFUSES the mount (`P-BOOT-FENCE-UNPROVEN`,
`P-BOOT-MOUNT-REFUSED`). There is no state in between.

On two nodes the only other routes to "live master, dead authority under judgement" are recovery
completion (guard gone) and the victim's own rejoin, which the admission barrier refuses while its
old incarnation is under recovery (s133d). A dead member keeps mastership of its pages until its
recovery completes, so requests on them fail fast (`-ENOTCONN`), never a transition wait.

Corollary found the same way: a refused bootstrap mount had started the fence-retry worker
(the fence arms the retry series) and freed the DLM context under it — the guest panicked
(`v5_fence_retry_worker_fn+0x8f`). Fixed in 0.89.70 (`v5_refused_mount_stop_workers`).

Before designing a two-node lap for a page-authority transition, ask whether the shape needs
a third identity. If it does, it is a 3-node lap.
