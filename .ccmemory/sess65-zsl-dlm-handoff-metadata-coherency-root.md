---
name: sess65-zsl-dlm-handoff-metadata-coherency-root
description: sess65: zsl ROOT reframed via Gemini+GPT — DLM EX serializes mkdir entry but NOT XFS metadata writeback/buffer lifecycle; torn di/leaf from owner wit…
metadata:
  type: project
---

## sess65 (ccloop 14d31183) — zero_silent_loss STILL FAILS; root reframed (Gemini ×2 + GPT escalation)

Build at session: **16520C7B** = B9C27147 (E6A40C95 flush-rebuild KEEP) + my P65-LEAF-FABRICATE
nheld=0 closer (xfs_mxfs_dlm.c mxfs_iflush_force_bmbt_durable, ~line 466). **P65 is INERT** — never
fired (nheld always ≥1 in the storm; the leaf IS cached). Harmless, closes a real-but-rare hole.

### FRESH DECISIVE EVIDENCE (iters=2, fresh 16-node reset, 8/16 nodes shut down, run SLOW/timed out)
- `P62-IFLUSH-FORCE ino=131 if_nextents=14 nheld=1 wrote=1 leafsum=14` (a CONSISTENT owner flush) …yet
  that same node as reader: `P59 loaded=14 if_nextents=15` → `Internal error ir.loaded != if_nextents
  at xfs_bmap.c:1286` → xfs_trans_cancel → xfs_create → shutdown. A DIFFERENT node published di=15
  over on-disk leaf=14.
- `P63-TORN-FLUSH ino=131 if_nextents=15 leafsum=16` — leaf has 16 recs while if_nextents=15. The
  rebuild's `cnt==if_nextents` guard FAILED → the in-core **iext TREE walk yielded 16 non-null extents
  while if_nextents=15**. So a node holds a **3-way divergence**: on-disk-leaf(14) / in-core-iext-tree(16)
  / if_nextents(15). Multiple owners concurrently publish mutually-inconsistent (di_nextents,leaf) pairs.

### ROOT (GPT gpt-5.5, architectural — the reframing):
DLM EX serializes *mkdir ENTRY* but NOT the full XFS metadata lifecycle (CIL→AIL→iflush→bmbt-buffer
writeback→local buffer-cache invalidation→peer reload). N nodes = N independent buffer caches; the DLM
must act like a GFS2/OCFS2 glock (sync-demote on release + invalidate/reload on acquire) and it doesn't
fully. **Mechanism A (matches the measured iext=16/if_nextents=15):** on EX ACQUIRE the reload
(xfs_idestroy_fork+xfs_inode_from_disk) refreshes if_nextents from the fresh dinode (15) but a STALE
**dirty/in-AIL** cached bmbt LEAF buffer (16) SURVIVES eviction — `mxfs_dir_evict_bmbt_blocks`
(xfs_mxfs_dlm.c:524, called at :2009 only when need_iread) SKIPS dirty/in-AIL/pinned buffers — so lazy
`xfs_iread_extents` rebuilds iext from the stale leaf=16. The owner then publishes a torn pair.
**Mechanism B:** the stale dirty leaf exists at acquire because the PRIOR release did not fully destage
it (Invariant #1 drain gap for the bmbt leaf class).

### KEY CONTROL-FLOW FACT (rules out one fear):
P119-NONEX-FLUSH-SKIP (xfs_inode.c:4144: `i_dlm_mode!=EX && !MXFS_IF_DLM_RELFLUSH` → goto flush_out)
runs BEFORE the `mxfs_iflush_force_bmbt_durable` call at xfs_inode.c:4219. So a NON-owner can't reach
the force — E6A40C95 only runs for EX/RELFLUSH owners. GPT's "non-owner writes stale leaf via the force"
is already prevented. The corruptor is an OWNER with a polluted iext (Mechanism A), not a non-owner flush.

### FIX DIRECTION (GPT, next session): move correctness from xfs_iflush reconcile → DLM HANDOFF.
1. EX RELEASE: synchronously destage THIS inode's item + its bmbt leaf buffer(s) BEFORE unlock (SCOPED —
   whole-AIL push DEADLOCKS here, sess32/39). RELFLUSH flag (xfs_mxfs_dlm.c:3167, set before
   i_dlm_mode=NL) already marks the release-window owner.
2. EX ACQUIRE: invalidate the stale bmbt leaf EVEN IF dirty/in-AIL (it is OUR superseded prior-tenure
   work once a peer changed the dir — gen bumped) using the EXISTING safe drain-the-pin-then-discard
   idiom (xfs_mxfs_dlm.c ~1931-2090 for pinned dir-data) so lazy iread cold-reads the peer's fresh leaf.
   Current evict skipping dirty leaves is the precise Mechanism-A hole.
3. The workload is adversarial (16 nodes hammering ONE dir inode = single-lock-serialized); sub-2×-native
   may need lock-stickiness/leasing or finer dir-leaf locking (GFS2/OCFS2 style). Slowness is a separate
   RULE-0 FAIL also present this run.

Links: [[sess64-zsl-torn-dinode-leaf-never-14-incore-leaf-lags]]
[[sess64-face2-leftcontig-desync-leaf-lags-iext-by-one]] [[sess60-zsl-writer-releases-inconsistent-dinode-bmbt]]
