---
name: AAA-ccloopa864-sess3-ROOT-hinted-unlock-misses-orphan-slot
description: sess3 STRONG ROOT (code-proven, forensic pending): dir_reuse@32/caw orphan = mxfs_dlm_caw_unlock_gen uses HINTED find_slot; if it lands on a slot wit…
metadata:
  type: project
---

# sess3 (ccloop a864) — dir_reuse@32/caw ROOT strongly localized + instrumented

## CRITERIA STATE
Only gap = `dir_reuse_coherency@32/caw` (criteria.json: dir_reuse has PASS at 2/4/8/16 caw, NO 32/caw entry; min_nodes=2 so 1-node N/A). ALL other tests+node-counts PASS. Fix THIS one test (must pass with DEFAULT modargs, MXFS_DEV=/dev/mapper/mpatha) and it's done.

## ROOT (code-proven; forensic confirmation running)
The orphan = a peer holds a reused dir inode's on-disk EX bit while incore i_dlm_mode=NL; it swallows every peer BAST → 31 waiters block 360s → rc=-110 cascade.

**Why the bit never clears (NEW, code-proven this session):** `mxfs_dlm_caw_unlock_gen` (dlm_caw.c:2978) locates the slot via **HINTED find_slot** (line 3055). At 3075-3081, if our node_bit is not in THAT slot's holder bitmaps, it early-returns rc=0 "nothing to unlock" WITHOUT a CAS. So if find_slot resolves a DIFFERENT slot than where the bit lives — because the resource lives in >1 live slot (claim-race dup) or the per-node slot_hint points at the wrong slot — the release NO-OPS while the orphan persists. bast_process's release (P70→unlock_gen) hits the same early-return, which is why v0.10.45's P72-STALE-REQUEUE (re-queue bast_process) fires 1000s of times but NEVER clears.

Corroborating: `find_slot` (dlm_caw.c:1177) is hinted (slot_hints direct-map, 4096) + linear probe; it only diverges from a full scan when nslots>1. `mxfs_dlm_caw_held`/`inode_held_rawmode` ALSO use hinted find_slot → same blind spot → explains the ROOT-memory "inode_held returns 0 while acquirer sees bit set" (they read different slots). resource_id has NO inode-gen (make_inode_resource, v5_mount.c:1293) so reused ino byte-matches → dup slots plausible.

## INSTRUMENTATION BUILT (v0.10.46 srcver 72B8FF8C, RUNNING now)
- `mxfs_dlm_caw_self_held_scan` (dlm_caw.c, read-only, FULL-CHAIN scan via caw_count_resource_slots) → 1 if our bit in holders_ex OR across ALL live slots; *nslots_out (>1=dup), *hex_or_out. Wrapper `mxfs_v5_dlm_inode_self_held_scan` (v5_mount.c/.h). Decls in dlm_caw.h.
- `mxfs_caw_orphan_forensic(ip, site)` (xfs_mxfs_dlm.c after mxfs_dlmtr_dump): at the two BAST-swallow exits (site0=P72 DEMOTING-swallow ~14271; site1=NONE/NL "no orphan" ~14551) logs `P-ORPH-FORENSIC ino sitemode state held_raw scan_mine nslots hex_or`; on proven orphan (scan_mine=1 && incore NL) dumps the dlmtr transition ring ONCE. Capped 200 + 150ms throttle. pr_warn (always-on; no dirwr/instr modarg needed). DIR inodes + CAW only.
- Run: `nohup timeout 5400 env MXFS_DEV=/dev/mapper/mpatha ./run.sh 32 caw dir_reuse_coherency` (default modargs). Log: scratchpad/drc32-C1.log, PID scratchpad/c1.pid.

## DISCRIMINATOR (what the forensic proves)
- scan_mine=1 && held_raw=0 (esp nslots>1) → HINTED-UNLOCK-MISSES-SLOT confirmed → FIX = scan-based force-clear.
- scan_mine=1 && held_raw>=EX (nslots=1) → held() correct; swallow is STATE-MACHINE gating (P72 DEMOTING never fires release) → FIX = force release at swallow when scan_mine=1.
- scan_mine=0 → NOT our orphan; re-diagnose.

## BUILD 2 FIX (ready to write once forensic confirms scan_mine=1)
Add `mxfs_dlm_caw_force_release_self(ctx, resource)`: walk WHOLE chain (base=fnv1a_hash%MAX_SLOTS; break on magic==0; skip tombstone/non-match); for each live slot matching resource with our bit in ANY holder/waiter/yield bitmap, CAS-clear our bit (model on unlock_gen 3083-3092: clear all holder bitmaps, recompute_granted_mode, generation++, last_modified_ms; caw_slot returns 0=ok, -EAGAIN=miscompare→re-read+retry, else err). Wrapper mxfs_v5_dlm_inode_force_release_self. Wire at swallow sites (or bast_process) ONLY when scan_mine=1 && incore mode==NL && ex=pr=pin=0, under a claim (state==DEMOTING already blocks local acquire — VERIFIED ilock_begin waits on DEMOTING at 19946-19982; TOCTOU-safe). Set i_dlm_stale=true after so next acquire reloads (invalidate-not-flush per Fable). Param-gate `caw_orphan_reclaim` default 1.

## Run mechanics: 31/32 up at start (test11 recovered via virsh destroy+start). Prep power-cycles down nodes + reloads .ko (build stamp in "prep OK" line). Lock /tmp/mxfs_run.lock. After kill: `for p in $(fuser /tmp/mxfs_run.lock); do kill -9 $p; done`.
