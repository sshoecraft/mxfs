---
name: AAA-ccloopa864-sess5-durable0-fairhandoff-FAILED-hardhang
description: sess5: durable_caw=0+fair_handoff=1 FAILED@r6 — test32 HARD-HANG (core-kernel spinlock deadlock, RCU stall, net dead) + P-COUNTREGRESS lost-update. P…
metadata:
  type: project
---

# sess5 — durable_caw=0 + fair_handoff=1 run FAILED (hard-hang). Config is a dead end.

## What happened (RULE-4 evidence, run on build E5F760E6 / mpatha)
Combined-config run `MXFS_EXTRA_MODARGS='dirop_durable_caw=0 caw_fair_handoff=1'` wedged at round 6-7:
- **test32 HARD-HUNG** at ~r6. virsh domstate=running but SSH "No route to host", empty serial log. QEMU-monitor `info registers -a`: most vCPUs HALTED (HLT=1, idle), **ONE vCPU spinning** (HLT=0, RIP moving 0xffffffff9cfd0c77→0c90 across samples = ~25-byte busy-loop). KASLR ON (no nokaslr in cmdline); mxfs.ko@0xffffffffc0e01000 (module space) but the spin RIP 0x9cfd... is in **vmlinux core-kernel text** (same range as idle RIP 0x9be6b751) → almost certainly native_queued_spin_lock_slowpath. One CPU spinning with NO on-CPU holder (others idle) = **corrupted/leaked spinlock** (use-after-free of a lock-bearing struct — fits inode/daddr REUSE churn) → RCU stall → networking dead.
- **Barrier degraded**: coord_barrier timed out (120s) waiting for dead test32 at r6, proceeded with 31 → `mxfs-drc-FAIL round=6 readdir=3100 exp=3200 lookup_fail=0 missing=[]`. Shortfall EXACTLY 100 = test32's 50 files+50 md5 (its absence), lookup_fail=0 = NO leaf-hash holes.
- **P-COUNTREGRESS fired on test1**: `owner=131 daddr=50237848 cnt=53 prev_max=139 real_mode=5 in_ail=1 comm=xfsaild/dm-1 — dir-data write LOST entries vs high-water (stale-base RMW = silent readdir=799 lost-update)`. This is the durable_caw=0 lost-update mechanism BUT **confounded by test32 dying mid-write** (torn base). Can't cleanly attribute to durable_caw=0 alone — but combined with run.sh's documented r17-loss warning, durable_caw=0 is unsafe.

## CONCLUSIONS
1. **durable_caw=0 + fair_handoff=1 is a DEAD END** — introduces a hard-hang (likely fair_handoff=1 livelock/spinlock-corruption; sess130 documented fair_handoff livelocks) and risks lost-updates. Do NOT ship these modargs.
2. **Stop stacking workaround modargs.** Per RULE 4 + CLAUDE.md (workarounds only if user asks), fix the ROOT wedge in the DEFAULT config.

## NEXT (this session, in progress)
1. Killed the contaminated run. test32 needs virsh destroy+start (run.sh prep auto-does it).
2. **Launch CLEAN DEFAULT-config run** (NO modargs): `MXFS_DEV=/dev/mapper/mpatha ./run.sh 32 caw dir_reuse_coherency`. Purpose: confirm the REAL blocker of the default (safe, coherent) config = wedge #2 (per-unlink durable-signal AIL-flush hang, sess4). Verify: (a) no hard-hangs with default config (would confirm hard-hang was the modargs), (b) P-COUNTREGRESS does NOT fire with durable_caw=1, (c) where it wedges (expect r8-9).
3. Then INSTRUMENT wedge #2 (pre-bwrite probe at owner_scan xfs_mxfs_dlm.c:1135: daddr/b_flags/pin/bli li_flags/_XBF_MXFS_ALLOC_QUEUED; + why P91-protected cluster buf never destages) → fix at root (candidates: force-destage P91 buffer / sync log force / defer owner_scan sync-bwrite to release-drain). Keep durable_caw=1. Then wedge #3 (starvation) only if it re-appears — measure first, don't pre-add fair_handoff.

## Monitoring gotcha reconfirmed: drc_progress_watch reads dmesg; prep power-cycles only SOME nodes → clear dmesg on sample nodes after prep. Also: a dead node makes the barrier go degraded → drc-FAIL from absence (readdir short by exactly 100*dead_nodes, lookup_fail=0) — distinguish from a real coherency hole (lookup_fail>0).
