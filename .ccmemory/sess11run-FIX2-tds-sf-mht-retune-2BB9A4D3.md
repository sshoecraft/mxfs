---
name: sess11run-FIX2-tds-sf-mht-retune-2BB9A4D3
description: sess11 FIX2 (2BB9A4D3, KEEP): tds 71-75s FAIL root = post-bpend-fix MHT idle-coasts on hot SF dir; dir_sf_mht_ms 100→2 → tds 19.6s PASS (2.2× histori…
metadata:
  type: project
---

# sess11 FIX2 — tcp_dlm_scaling window FAIL after the bpend fix

## Chain of causation (all RULE-4 measured)
1. The eternal-refire bug (fixed in [[sess11run-ROOT-FIX-bpend-refire-storm-E7EB3081]]) had been ACCIDENTALLY LOAD-BEARING for tcp_dlm_scaling: stuck bast_pending released the contended hot dir at EVERY idle instant, defeating MHT batching → per-op handoffs at raw grant latency → historical 39-44s "good" runs.
2. Post-fix, tds went 71-75s (window 60) on ALL 4 nodes uniformly, clean boot, instrumentation on/off identical → structural.
3. P70-BP +held_ms histogram (per-release tenure hold): ~460 releases/150 rounds = one handoff PER OP (3/round). Two bands: ~300 eager (<10ms, qsrc=1 ilock_end consume) + **144 qsrc=9 coasts at 50-150ms = dir_sf_mht_ms=100 enforcing a minimum hold on an IDLE holder while 3 peers wait** (bast_notify defers BAST-in-MHT-window to the dwork at expiry).
4. Mount-phase red herring ruled out: 20s ACQ-SLOW events (ino=128 root, isdir=0, mount-time EX) precede the loop; loop elapsed excludes them. ALSO seen: dead prior-incarnation GRANTED entries convoying requests after lazy-umount teardowns (ino 2547 held_ms=206923 by dead node 2830486298; umount P36-RETRY loops) — SEPARATE issue, cross-run pollution, not the clean-boot cost. Not yet fixed.

## Fixes (build 2BB9A4D3, KEEP)
- `dir_sf_mht_ms` default 100 → **2** (xfs_mxfs_dlm.c ~8912): SF-dir BASTs honored ~immediately at idle. tds: **19.6-19.9s PASS** (3× headroom, 2.2× better than historical best). sess20's "40 broke cache_coherency" sensitivity RETESTED on current machinery: cache_coherency PASS ×2 with sf=2 (whole-inode SF reload handles handoff coherency now). Block dirs keep inode_mht_ms=300 (dir_reuse create-storm batching preserved).
- `mxfs_inode_unpin` (pinned_resource.c): added CACHED&&bast_pending arm mirroring ilock_end (with consume) — tenures whose last quiescent transition is an unpin (create/mv/rm trans) no longer coast to MHT expiry. (75→69s before the sf retune; both keep.)

## Watch items
- P11-ACQSTALE-SELFBAST + P70-BP qsrc/bpend/held_ms forensics are ino≤256-gated (P11) — per-node test dirs are AG-affine (e.g. 6291584) so P11 misses them; qsrc/held prints are uncapped-per-ino — fine.
- Suite-1 on E7EB3081 (pre-FIX2, armed): 15/17 — dir_reuse r2 397/400 durable loss (all-node agreement, classic face, NOT storm-caused) + tds window (now fixed). dir_reuse loss is the remaining correctness face.
- Dead-incarnation GRANTED entries after lazy-umount: candidate root for historical 120s wedge/convoy flakes; needs a reconcile/expiry (master should drop entries of departed members — check membership_cb coverage for INODE+AG types).

## Next: full 4/tcp ×3 on 2BB9A4D3 → then 8/2/1 ladder. dir_reuse loss is the blocker to chase if it recurs.
