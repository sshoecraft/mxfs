---
name: sess131-ghost-writers-FIXED-selffence-gen-identity
description: sess131: ghost-writer root PROVEN+FIXED (build 06E672C2: P131 self-fence + fs_gen tags). New blocker = 16-node same-dir create throughput (~10-16/s,…
metadata:
  type: project
tags: [sess131, ghost-writers, self-fence, zero_silent_loss, throughput]
---

# sess131 (ccloop run 14d31183, session 9) — 2026-06-10

## Ghost-writer root cause PROVEN and FIXED (KEEP, build `06E672C25DAB577864929DE`)

zero_silent_loss(16) failure root: **live ghost writers** — old-generation mounts
(test5-16) still heartbeating every 2s into a LUN re-mkfs'd under them.
Proof: O_DIRECT dump of HB region (64×512B @ byte 67117056) twice 6s apart —
11 records' timestamps advanced ~6.1s. Plus 1,972 stale lock records held by
ghost slot bits in lock region (@ 67149824). New cluster saw advancing ts →
ghosts = live members → 120s waits on their stale locks → shutdown.
**Nothing tied HB/lock records to an mkfs generation.**

CRITICAL FORENSIC LESSON: buffered reads of /dev/sda over ssh return PAGE-CACHE
data — dumps looked frozen. Must use O_DIRECT (os.preadv into mmap buffer) for
on-disk truth.

### Fix (three parts, all verified)
1. **Self-fence** (dlm/disklock.c): HB thread re-reads MXFS super (sector 0)
   each 2s cycle (`fs_identity_changed`); fs_uuid mismatch → P131-SELF-FENCE,
   stop heartbeating, fence_cb → v5_self_fence_cb → fence_notify →
   mxfs_dlm_fence_notify (xfs_mxfs_dlm.c) → xfs_force_shutdown.
2. **fs_gen tag** in HB records (pad→fs_gen = folded FNV volume_id; 0=legacy).
   `hb_gen_foreign()` filter in monitor loop, claim_slot both passes,
   get_stale_slot_mask, get_slot_node_id.
3. **Foreign-volume lock-slot recycling** (dlm_caw.c find_slot_skip): live
   entry with resource.volume != ours = tombstone-like recyclable insert point.

Verified: re-mkfs from test3 while test1+test2 live-mounted → both self-fenced
≤2s, HB region stayed zero, test3 mounted new gen clean, fenced nodes
umount+rmmod clean. New APIs: mxfs_disklock_set_fs_identity/set_fence_cb,
mxfs_v5_dlm_set_fence_notify (wired at BOTH disklock_create sites, before
claim_slot).

## NEW blocker: 16-node same-dir create THROUGHPUT (RULE 0 perf fail)

Correctness now PASSES (silent=0). zero_silent_loss times out (300s budget):
- 16-way PR→EX conversion storm on the shared dir (ino=131), all nodes
  CAS-hammering ONE slot (lba 193238). 120s lock-timeout tail at dpn=100.
- Clean measurement (dpn=5): 80 creates, silent=0, storm ≈5-8s ≈ 10-16/s.
- Need ≥64 creates/s + zero 120s events to fit 300s budget (1600 creates
  ≤~25s/iter; mount_cluster(16) ≈55s/iter ×3).
- MHT batching EXISTS (mxfs_inode_mht_ms=50, sess124) yet ~10× too slow —
  what defeats it is UNPROVEN. Hypotheses H1 (tenure not applying), H2
  (handoff drain cost), H3 (CAS-race starvation tail) in state.md NEXT STEPS.
- MDS RPC plumbing (sess67) exists in dlm/ but NOT wired to xfs ops; don't
  pivot to MDS before exhausting symmetric fixes.
- Upgraders KEEP their PR bit while waiting for EX (compatible_excluding_self);
  caw_wait_for_grant has NO fairness — grant = CAS race winner.

## Ops notes
- pkill pattern matching the storm loop kills your own ssh wrapper bash —
  use a distinct pattern. Soft teardown of a contended cluster wedges; use
  scripts/cluster_reset_n.sh 16 (~3.5 min power-cycle+prep+verify).
- Full handoff detail: /src/mxfs/state.md (sess131).
