---
name: sess49-GPT-design-dlm-epoch-authority-for-dir-buffer-coherency
description: sess49(ccloop) GPT-5.5 ARCHITECTURE for the 130-session dir-block lost-update: DLM-grant-epoch + per-buffer authority epoch + read/writeback/modify g…
metadata:
  type: project
---

## sess49 (ccloop 4cb2d0a2) — GPT-5.5 design (RULE 5 consult) for the dir-block lost-update CORE

### THE MISSING DISCRIMINATOR: authority = current DLM GRANT EPOCH, not disk content, not i_generation, not the (stuck) in-core dir_gen. A cached dir-metadata buffer is valid ONLY if its stamped epoch == the inode's current grant epoch. "Was this buffer image produced under MY CURRENT DLM authority epoch?"

### DLM master state: per dir-inode resource, monotonic `u64 authority_epoch`. Increment on EVERY EX grant + PR->EX conversion; return epoch with PR/EX grants (PR doesn't increment). Hold NL ref while any cache stamped with the resource exists (so epoch isn't reset under live stale cache). MXFS likely already has this as grant_gen / i_mxfs_ex_grant_seq (the acked-TCP per-grant token that changes on every cross-node EX handoff — RELIABLE, unlike the lossy evict-ring dir_gen).

### STAMPING DISCIPLINE (the crux — fixes prior over-suppression refutations):
Stamp bp epoch = ip.grant_epoch at EXACTLY two points, NEVER at writeback/modify:
  A. **Disk READ COMPLETION** under a valid PR/EX grant (xfs_da_read_buf / xfs_dir3_{data,leaf,free}_read).
  B. **BIRTH-INIT** of a newly-allocated block under EX (xfs_dir3_data_init / leaf/free init), BEFORE it is dirtied/logged. <-- THIS defeats the GHOST: a recreated dir reuses daddr 120 but the fresh block gets the CURRENT epoch and is allowed to overwrite the dead-incarnation ghost.
Do NOT stamp lazily at submit/modify time — that blesses stale data (the sess40/41 re-stamp-on-modify bug).

### GATES (mandatory, lazy per-buffer is enough for correctness — do NOT depend on eager evict which trylock/dirty-skips = the current hole):
- **READ** (readdir/lookup/leaf/free traversal, before serving): require PR/EX AND bp.epoch==ip.epoch AND bp.resid==ip.resid; else clear XBF_DONE + reread under grant. [Fixes FACE 2 reader-stale-block.]
- **MODIFY** (before logging any dir buf): require EX AND bp.epoch==ip.epoch; else reread under EX, or birth-init if newly allocated.
- **WRITEBACK/xfsaild submit** (xfs_buf_submit / AIL push, MXFS dir-meta bufs): require local EX AND !closing AND bp.epoch==current EX epoch; else DENY (fail closed, never submit, never stamp here). Take an authority_io_ref for the in-flight write; completion drops it. [Fixes FACE 1 xfsaild stale-flush. A fresh block passes because birth-stamped; a stale/ghost block fails because epoch mismatch.]

### DEMOTE/RELEASE (two-phase, GFS2/OCFS2 "demote removes cache AUTHORITY not just write permission"):
1. closing=true (block new mods + new writeback refs); wait active_ops==0.
2. Normal XFS drain (force log to LSNs, push AIL, wait dir-meta bufs clean+unpinned+!in-AIL+no in-flight IO + authority_ios==0). Do NOT hand-order leaf-then-data (that tears the index — the proven P21H leaf-tear).
3. INVALIDATE local cached dir-meta authority (bp.valid=false / clear XBF_DONE) BEFORE dropping/converting the grant.
A dirty stale-epoch buffer reaching xfsaild = INVARIANT VIOLATION (drain incomplete OR dirtied without authority) — fail closed + reacquire, never submit/merge (can't merge a stale full-block image).

### WHY IT WORKS w/o content-compare or per-op FUA: only a memcmp(epoch) + occasional reread on epoch transition. FACE1: stale bp epoch < current EX epoch -> writeback denied. FACE2: PR reacquire gives newer epoch -> stale bp reread. GHOST: dead-incarnation bp has OLD epoch -> never served/written; fresh block birth-stamped CURRENT -> overwrites ghost.

### MXFS MAPPING / GAP: pieces exist (b_mxfs_dir_epoch, b_mxfs_grant_gen, i_dlm_dir_valid_epoch, i_mxfs_ex_grant_seq, dir_grant_evict). GAPS to fix: (1) stamp at read-completion + birth-init ONLY (audit current stamp sites — sess40 stamps at modify = WRONG per GPT); (2) add the HARD writeback gate at xfs_buf_submit (currently detect-only mxfs_dirskip, enforce refuted because it used content/stuck-gen not the grant epoch + birth-stamp); (3) read gate reread-on-epoch-mismatch; (4) invalidate-on-demote. RISK: writeback-gate-denied dirty buf must not wedge AIL — relies on demote drain completing first (else fail-closed reacquire).

### IMPLEMENT INCREMENTALLY + TEST EACH (RULE 4). Verify grant_gen is reliably master-incremented per EX grant FIRST. See [[sess49-residual-two-modes-write-clobber-and-reader-stale-block]] [[sess-tcp-FIX-DESIGN-fence-stale-dir-inode-fork-flush]] [[sess41-FIX-tenure-gated-dataclobber-guard-AF02E775]].
</body>
</invoke>
