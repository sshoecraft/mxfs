---
name: caw-sess6-FIX-dir-slow-handoff-gate-build-B73D1E9F
description: sess6 dir_slow_handoff_gate (build B73D1E9F, default-off) REFUTED: passes cache_coherency@4 4/4 but breaks dir_reuse@4 0/4 (same cross-node-reuse fal…
metadata:
  type: project
---

## sess6 dir_slow_handoff_gate — REFUTED (keep default-off, do not enable)

### Result (build B73D1E9F, MXFS_EXTRA_MODARGS="dir_slow_handoff_gate=1 read_attr_probe=1", @4)
- cache_coherency@4 = PASS 4/4, strong_consistency@4 = PASS 4/4
- **dir_reuse_coherency@4 = FAIL 0/4** (timeout/stale) — the gate BROKE it.
- Gate fired heavily: DIR-SLOW-SKIP n=3072 ino=128 (root dir) — it IS skipping reloads, but skips
  ones dir_reuse NEEDS.

### Why it fails (same class as sess5's refutations)
dir_reuse is cross-node inode REUSE (rank1 rm-rf's + recreates the shared dir every round; peers
recreate freed inode numbers). The `genuine_handoff` epoch signal (ep==acq_epoch => "no peer EX")
gives a FALSE NEGATIVE under this churn: the CAW slot/epoch is reclaimed+restarted on the dir's
free+realloc, so a genuine peer recreate is not always reflected as an epoch advance at our acquire →
we skip the reload → serve the stale (pre-reuse) dir → dir_reuse fails. Same root-cause family as
[[caw-sess5-NEXT-correct-fix-mirror-iget-create-gate]] (prior-owner/handoff signals are unreliable
under aggressive cross-node inode reuse). CONFIRMED: reload-skip approaches based on any peer-EX/
handoff/epoch signal are a DEAD END for the reuse cells.

### What this means
The gate is PARAM-DEFAULT-OFF so the shipped build (B73D1E9F) is behaviorally unchanged — SAFE to
leave in the tree, inert. Do NOT enable it. The correct fix is NOT reload-skip; it is
**fua_disable=1** (route reads through the coherent SCST shared cache — a different mechanism that
doesn't skip any reload, so it can't serve stale from a reuse false-negative). See
[[caw-sess6-PIVOT-scst-confirmed-fua_disable-is-the-storm-fix]]. dir gate + the RELOAD-STALE-SPLIT
probe remain as inert diagnostics.
</body>
