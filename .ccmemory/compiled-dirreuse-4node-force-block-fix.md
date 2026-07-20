---
name: compiled-dirreuse-4node-force-block-fix
description: sess67 ccloop: dir_force_block=1 makes dir_reuse_coherency PASS 1/2 tcp; 4/8-node ROOT = xfs_dir3_data_init zeroes a live dir block via stale extent…
metadata:
  type: project
tags: [compiled, dir_reuse, force_block, data_init, tcp-dlm, extent-map, sess67]
---

## dir_reuse_coherency — force_block fix (1/2 node) + 4/8-node data_init root (sess67, ccloop 4cb2d0a2)

Criterion for the sess67 run: get the `dir_reuse_coherency` test passing at 1/2/4/8 nodes over TCP DLM, 100%. End state: **1✅ 2✅ 4❌ 8(untested)**. `dir_reuse_coherency` was the sole failing test across 1/2/4/tcp on the baseline build (`621FD271B9A2F505686CC08`, all sess65 module params default OFF: 2/tcp=0/2, 4/tcp=0/4); every other test PASSED at 1/2/4 nodes.

### The KEEP fix: mxfs_dir_force_block = 1 default
`mxfs_dir_force_block=1` (default flipped 0→1 at `xfs_mxfs_dlm.c:3251`; gate logic `mxfs_dir_should_force_block` at `xfs_mxfs_dlm.c:3265`) forces a fresh **multinode** shortform dir to **BLOCK format at mkdir**, eliminating the cross-node sf→block **conversion divergence** (two nodes independently converting a fresh shared dir → logical-block0 split → dirent loss). See [[sess67-force-block-1-fixes-dir-reuse-2tcp-current-build]].

PROVEN results (clean virsh reboots of test1-4 each run, full `./run.sh`):
- **1/tcp = 16/16 PASS**
- **2/tcp = 17/17 PASS**

Build lineage: `621FD271` (force_block via `MXFS_EXTRA_MODARGS="dir_force_block=1"` modarg) → `EE5F752F` (force_block=1 as default) → `5DAA344C` (+dir_postread_reread) → `92B569D6` (+dir_iflush_owner_fence) → shipped `91962D4A4D9DA8947ED40D8`. In the shipped build `91962D4A`, force_block=1 is the KEEP fix and **all sess67 experimental params are DEFAULT 0 / gated inert** (`dir_postread_reread`, `dir_iflush_owner_fence`, `dir_epoch_adopt`, `dir_modify_extent_adopt`), so it behaves identically to the proven `EE5F752F`. Force_block=1 + the doc edits are KEEP. See [[sess67-HANDOFF-state-and-4node-next-step]].

Regression concern cleared: sess44 (a ~40-session-older build) claimed force_block=1 REGRESSES dlm_fairness/cache_coherency (force_block keeps dir BLOCK in-core while a churning peer converts it to SHORTFORM on disk → P43B overrides P34D → bnobt double-free shutdown). The current build carries the **sess49 P43 soundness gate** (P43 fmtrevert-skip gated on `dfr_dirty || EX`, so a clean PR/NL cacher adopts the peer's durable shortform), and the feared regression NO LONGER occurs. Why 2 nodes pass but 4 fail: force_block fixes logical block0 (rank1 owns it → enough for 2 nodes); at 4 nodes the dir grows toward LEAF format and the same divergence recurs on higher data blocks, hit ~1 round in 15.

### 4/8-node ROOT (PROVEN, re-confirms sess36 / sess62)
The 4/tcp failure is durable single/adjacent-entry loss (~1/15 rounds, ~5min). Under `instr=1` a whole **CONTIGUOUS data-block** of one node's dirents vanishes (e.g. `node4_f6,f6.md5,f7,f7.md5,f8,f8.md5,f9,f9.md5`); clean runs lose 1-2 adjacent entries. All nodes including the creator miss them after `drop_caches` → genuinely off the LUN.

**Root: `xfs_dir3_data_init` (`xfs/libxfs/xfs_dir2_data.c:802`) uses `xfs_da_get_buf` (NO read) then ZEROES the buffer.** The node's in-core data-fork extent map is STALE: it treats a logical dir block as new/hole and calls data_init for a physical daddr that ALREADY holds this dir's (peer- or self-committed) LIVE dirents → the zero is the durable loss. The read-path coherency machinery (P60/P67) is **bypassed entirely** — get_buf+zero does no read. The existing P31E/P32B detectors at `:840-895` are instr-gated DETECTORS ONLY (log then proceed to zero). GPT-5.5 (RULE 5, consulted 2×) confirmed the release IS a durability barrier and pointed to hypothesis (A) "coherency-bypassing buffer access" = exactly `xfs_da_get_buf` in data_init. See [[sess67-ROOT-datainit-zeroes-live-dirblock-4node]].

### DECISIVELY REFUTED this session (direct probe evidence — DO NOT RETRY)
1. **force_block=1 alone at 4 nodes**: FAILS — `node4_f37` durably lost, round 13; all 4 nodes lose exactly one entry (LOOKUP_ENOENT + REREAD_MISS, missing even on creator test4 after drop_caches; readdir=399 exp=400). `P34-TRYLOCK-STALE` fired (test1=4, test3=2). See [[sess67-4node-needs-force-block-plus-epoch-adopt]].
2. **+ dir_epoch_adopt=1** (`xfs_mxfs_dlm.c:7093`): FAILS round 20 (`node4_f19.md5`). epoch_adopt alone converges the extent map (sess65: all 4 nodes' extent[0] agreed daddr=120) but was known to "drop the converter's own entries"; combining with force_block did not save it.
3. **+ dir_postread_reread=1** (build `5DAA344C`; new under-buffer-lock re-read of gen-stale clean dir blocks in `xfs_da_read_buf` after `xfs_trans_read_buf_map`): **P67-POSTREAD-REREAD NEVER fired** on the clobber → NOT a gen-mismatch stale cached read.
4. **+ dir_iflush_owner_fence=1** (build `92B569D6`; skip dir-inode flush when `i_dlm_mode!=EX && !RELFLUSH` in `xfs_inode.c`): **FENCE never fired** — P-DIRIFLUSH shows the only NL(mode=0) dir-inode flushes are all relflush=1 (legit release-drains) with block0=fsb15 STABLE and `incore_nx==disk_nx` → extent map CONVERGED, not flip-flopping.
5. **Read-side stale RMW / gen-mismatch**: under instr=1, `P60-GENMATCH-STALE=0` AND P67=0 → the read path NEVER serves a detectably-stale dir block.
6. **Release not home-durable** (GPT hypothesis C): REFUTED — the sess97 release fence (`xfs_mxfs_dlm.c:5676-5688`) is UNBOUNDED `xfs_bwrite`-until-durable-or-shutdown; dir DATA blocks ARE on the LUN at handoff.
7. **Dir-inode extent-map flip-flop / stale non-owner iflush**: refuted per (4); block0=fsb15 stable, extent map CONVERGED in count.
8. **Stale TOO-SMALL extent map at grow** (`dir_modify_extent_adopt`, count-compare): **P67-MODIFY-EXTENT-ADOPT never fired** even with direct disk FUA compare → `incore_nextents` is NEVER < `disk_nextents` at the modify prelock.

### KEY FINDING → next step
The extent maps diverge in **CONTENT, not count**: same nextents, but a DIFFERENT daddr per logical block. data_init zeroes a daddr D that IS on disk owned by this dir (sess36 P31E owner==ino, P32B-DOUBLEMAP=0) yet is NOT in the node's in-core extent map, while `incore_nextents` is NOT < `disk_nextents`. A count comparison is therefore useless. Two candidate fixes (neither implemented; both UNTRIED):

- **(A) MERGE-adopt at the modify prelock** (most promising): full per-logical-block daddr comparison disk-vs-in-core; on divergence, adopt disk's daddrs for blocks both/disk have but KEEP the node's own uncommitted appended higher blocks. A plain `from_disk` reload DROPS them (= the epoch_adopt "drops converter's own entries" regression). The prelock holds no ILOCK, so reload is safe there.
- **(B) defensive guard in `xfs_dir3_data_init`**: before zeroing, FUA-read the daddr (`mxfs_pal_bdev_read_plain_bdev`); if it holds a valid dir3 XDD3/XDB3 header with owner==`dp->i_ino` and live entries>0, do NOT zero — either read the live block into `bp` and skip re-init (risks dir2 freesp accounting), or mark dir stale + `MXFS_IF_DIR_RELOAD` + return `-EAGAIN` to abort/retry after adopting the correct map (risks caller error-handling). If D is a still-live block handed out as free, the deeper bug is the ALLOCATOR/freespace (AG bnobt / dir-freesp) considering D free — likely the same stale-extent-map → stale freesp.

Relevant reload code: `mxfs_dlm_reload_inode` (`xfs_mxfs_dlm.c:6980`); modify prelock `mxfs_dlm_dir_modify_reload_prelock` (`:2764`) — its block-adopt branches are gated on `if_format==LOCAL` (shortform) so they DON'T fire for grown LEAF dirs; only generic `MXFS_IF_DIR_RELOAD` reload (post_release=false) runs, and that is skipped if `mode==EX` (`:2927`).

### REPRO
Clean virsh reboot test1-4 (`virsh -c qemu:///system destroy+start`), then `./run.sh 4 tcp dir_reuse_coherency` (~1/15 rounds fails, ~5min). Probes: drc-CLASS (lost names), P-DIRIFLUSH, P31E (instr). Re-confirm 2/tcp=17/17 on `91962D4A` after any change. test5-8 exist in libvirt with shared LUN `/dev/sda` + NFS → 8/tcp ready once 4 passes. Validation bar for a candidate fix: drc-FAIL=0 + no shutdown across ≥3 4/tcp runs, then 8/tcp, then re-confirm 2/tcp=17/17.
