---
name: AAA-ccloopa864-sess5-WEDGE3-release-abort-livelock-ino131
description: sess5 wedge#3 ROOT: default cfg progresses to r8 fails=0 then WEDGES on P15-REL-ABORT livelock (ino=131 handoff aborts on local re-acquire/orphan → p…
metadata:
  type: project
---

# sess5 — wedge#3 ROOT: release-abort livelock on shared dir ino=131 (default config's primary limiter)

## Observed (build 0349484E, DEFAULT config, /dev/mapper/mpatha)
A default-config run PROGRESSED r1→r8 with **fails=0, P-IOWAIT-STUCK=0** (no coherency loss, no bwrite hang), then HARD-STALLED at r8 create-start (~4.5min no advance). So the DEFAULT config's PRIMARY limiter is NOT wedge#2 (bwrite hang, intermittent) — it's **wedge#3 = acquire starvation via release-abort livelock**.

## Mechanism (RULE-4, dmesg-proven)
At the r8 stall, `P15-REL-ABORT ino=131` fires repeatedly (~every 40s, gen 115203→115254): "holder re-acquired during drain; release aborted, BAST re-armed (P58 averted)". Two sub-cases:
- `gen_moved=1` (entry_gen 115237→now 115238): local workload RE-ACQUIRED ino=131 during the release drain → abort keeps the fresh grant.
- `gen_moved=0 orph=1` (held_mode=0=NL, ex=pr=pin=0): orphan-shape; the sess4 wall-clock strand escape (P15H-STRAND-TIMEOUT, 3s continuous NL) does NOT converge because frequent local re-acquires reset i_dlm_orphan_since_ns.
Net: ino=131 (the single hot shared dir) NEVER hands off to the waiting peers → peers starve (P138-WAIT ino=131 mode=3/5 elapsed 20-40s+) → barrier stalls → FAIL. dir_reuse PASSES at 16 (contention survivable), tips over at 32.

## The abort site
xfs_mxfs_dlm.c:12056 `if (gen_moved || pin_only || orphan_live) { ...bast_pending=true; re-arm dwork; P15-REL-ABORT; return; }`. The abort is a P58-double-grant SAFETY, but under 32-node hot-dir load it livelocks: local re-acquire always beats the pending remote BAST.

## NEXT EXPERIMENT (modarg, NO rebuild — build 0349484E has it)
`MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS='caw_fair_handoff=1' ./run.sh 32 caw dir_reuse_coherency`
caw_fair_handoff=1 (dlm_caw.c:1655) makes a FRESH local acquirer DEFER to a pending peer yield-ticket instead of self-promoting → the release completes → handoff → starvation breaks. Keep durable_caw=1 (coherency). The hard-hang is ORTHOGONAL (occurred in default cfg too — test27), so fair_handoff isn't its cause; unknown_nmi_panic=1 is set on all nodes to capture it if it recurs (inject-nmi).
- If fair_handoff=1 PASSES 24 rounds fails=0 → make it DEFAULT (dlm_caw.c:88 `int mxfs_caw_fair_handoff = 1;`), rebuild, re-verify plain run + other counts.
- If it LIVELOCKS/hard-hangs → capture (inject-nmi) + attack the abort site directly: make a local re-acquire on ino=131 DEFER (block) when i_dlm_bast_pending is set, so the release can complete before the local op proceeds (BAST-priority over local re-acquire).
- Deeper alt: the release-abort at 12056 for the orphan case could PROCEED (release) when a peer has been waiting > X ms (starvation-aware), instead of aborting.

## Context: wedge#2a bwrite lost-wakeup (P-IOWAIT-STUCK probe in build 0349484E) is intermittent + separate; hard-hang spinlock separate. See sess5 COMPREHENSIVE-STATE + WEDGE2-FRESH + HARDHANG memories.
