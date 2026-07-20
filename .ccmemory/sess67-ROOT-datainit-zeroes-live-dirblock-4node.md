---
name: sess67-ROOT-datainit-zeroes-live-dirblock-4node
description: sess67: 4/8-node dir_reuse loss ROOT (re-confirms sess36/62) = xfs_dir3_data_init ZEROES a live dir DATA block (stale extent map). Read-path coherenc…
metadata:
  type: project
---

## sess67 (ccloop 4cb2d0a2) — 4/8-node dir_reuse ROOT re-confirmed: data_init zeroes live block

### STATE OF PLAY
- **1/tcp = 16/16 PASS, 2/tcp = 17/17 PASS** on build with `mxfs_dir_force_block=1` DEFAULT (xfs_mxfs_dlm.c:3251). This is the criterion-meeting baseline for 1 and 2 nodes. Build lineage: 621FD271 (force_block via modarg) → EE5F752F (force_block=1 default) → 5DAA344C (+dir_postread_reread) → 92B569D6 (+dir_iflush_owner_fence). force_block=1 + the doc edits are KEEP.
- **4/tcp dir_reuse_coherency FAILS** ~1 round in 15 (durable single/adjacent-entry loss; under instr=1 a whole CONTIGUOUS data-block of entries is lost, e.g. node4_f6,f6.md5,f7,f7.md5,f8,f8.md5,f9,f9.md5).

### REFUTED this session (all with direct probe evidence — do NOT re-try):
1. **force_block=1 alone**: fixes 2 nodes, FAILS 4 (node4_f37 round 13).
2. **+ dir_epoch_adopt=1**: FAILS round 20 (node4_f19.md5).
3. **+ dir_postread_reread=1** (NEW: under-buffer-lock re-read of gen-stale clean dir blocks in xfs_da_read_buf after xfs_trans_read_buf_map; param default ON, build 5DAA344C): **P67-POSTREAD-REREAD NEVER fired on the clobber** → NOT a gen-mismatch stale cached read.
4. **+ dir_iflush_owner_fence=1** (NEW: skip dir-inode flush when i_dlm_mode!=EX && !RELFLUSH; xfs_inode.c, param default ON, build 92B569D6): **FENCE never fired** — P-DIRIFLUSH shows the only NL(mode=0) flushes are all relflush=1 (legit release-drains) with incore_nx==disk_nx, block0=fsb15 STABLE → extent map CONVERGED, NOT flip-flopping; fence inert.
5. **instr=1**: P60-GENMATCH-STALE=0 AND P67=0 → the read path NEVER serves a detectably-stale dir block. Release is home-durable (sess97 fence, xfs_mxfs_dlm.c:5676-5688, UNBOUNDED xfs_bwrite-until-durable-or-shutdown). So NOT read-side stale, NOT release-non-durable, NOT extent[0] flip-flop.

### PROVEN ROOT (this session + sess36 [[sess36-PROVEN-datainit-zeroes-live-block0-root]] + [[sess62-PROVEN-ROOT-4way-logical-block0-split-divergent-extent-map]]):
**xfs_dir3_data_init (xfs/libxfs/xfs_dir2_data.c:802) uses xfs_da_get_buf (NO read) then ZEROES the buffer.** The node's in-core data-fork extent map is STALE: it treats a logical dir block as new/hole and calls data_init for a physical daddr that ALREADY holds this dir's (peer-or-self-committed) LIVE dirents → the zero is the durable loss. Read-path coherency (P60/P67) is bypassed entirely (get_buf+zero, no read). Existing P31E/P32B detectors at :840-895 are instr-gated DETECTORS ONLY (log then proceed to zero). force_block fixed logical block0; HIGHER blocks (f6-f9) still hit this.

### FIX DIRECTION (sess36 plan, NOT yet implemented): in xfs_dir3_data_init, before the zero/header-init: plain-read the physical daddr (mxfs_pal_bdev_read_plain_bdev); if it holds a valid dir3 XDD3/XDB3 header with owner==dp->i_ino AND live entries>0, do NOT zero — either (a) read the live block into bp and skip re-init so the caller adds onto existing dirents, OR (b) mark dir stale + MXFS_IF_DIR_RELOAD + return -EAGAIN to abort+retry the op after adopting the correct extent map. (a) risks dir2 freesp accounting; (b) risks caller error-handling. TEST whichever; verify drc-FAIL=0 + no shutdown across ≥3 4/tcp runs, then 8/tcp, then re-confirm 2/tcp=17/17.

### GPT-5.5 consulted twice (RULE 5): designed the read-path under-lock coherency (implemented as postread_reread, refuted) and confirmed the release IS a durability barrier; pointed to hypothesis (A) "coherency-bypassing buffer access" = exactly xfs_da_get_buf in data_init.

[[sess67-ROOT-datainit-zeroes-live-dirblock-4node]] [[sess67-force-block-1-fixes-dir-reuse-2tcp-current-build]] [[sess67-4node-needs-force-block-plus-epoch-adopt]]
</body>
