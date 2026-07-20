---
name: sess67-HANDOFF-state-and-4node-next-step
description: sess67 HANDOFF: build 91962D4A = force_block=1 default (1/tcp 16/16, 2/tcp 17/17 PROVEN), all sess67 experimental params gated OFF. 4/tcp dir_reuse s…
metadata:
  type: project
---

## sess67 HANDOFF (ccloop 4cb2d0a2) — criterion NOT met (4/8-node dir_reuse unsolved)

### CRITERION: get 1/2/4/8 node tcp dlm test 100%. STATUS: 1✅ 2✅ 4❌ 8(untested).

### SHIPPED BUILD: srcversion `91962D4A4D9DA8947ED40D8`.
- **mxfs_dir_force_block = 1 DEFAULT** (xfs_mxfs_dlm.c:3251) — the KEEP fix. PROVEN: **1/tcp = 16/16 PASS, 2/tcp = 17/17 PASS** (full ./run.sh, clean reboots) on the equivalent build EE5F752F. force_block makes a fresh multinode dir BLOCK format at mkdir → eliminates the cross-node sf→block conversion divergence on logical block0. sess44's feared dlm_fairness/cache_coherency regression NO LONGER occurs (sess49 P43 soundness gate). 2/tcp passes because at 2 nodes the dir-data-block double-alloc race (below) is rare enough not to hit in 24 rounds; 4 nodes hits it ~1/15 rounds.
- All sess67 EXPERIMENTAL params are DEFAULT 0 (gated, available for the relay): `dir_postread_reread`, `dir_iflush_owner_fence`, `dir_epoch_adopt`, `dir_modify_extent_adopt`. Code paths present but inert at default — the shipped build behaves == EE5F752F (proven 1/2). DO re-confirm 2/tcp=17/17 on 91962D4A (was running at handoff).

### 4/8-NODE ROOT (PROVEN this session, re-confirms sess36/sess62): xfs_dir3_data_init (xfs/libxfs/xfs_dir2_data.c:802) ZEROES a dir DATA block that already holds this dir's LIVE dirents → durable whole-block loss (under instr=1 a CONTIGUOUS block of one node's entries vanishes, e.g. node4_f6..f9 + .md5; clean runs lose 1-2 adjacent entries). All nodes incl. creator miss them after drop_caches = genuinely off the LUN.

### DECISIVELY REFUTED this session (direct probe evidence — DO NOT RETRY these):
1. Read-side stale RMW: **P67-POSTREAD-REREAD** (new under-buffer-lock re-read in xfs_da_read_buf) NEVER fired on the clobber; **P60-GENMATCH-STALE=0** under instr. The read path never serves a detectably-stale dir block.
2. Release not home-durable (GPT hypothesis C): REFUTED — the sess97 release fence (xfs_mxfs_dlm.c:5676-5688) is UNBOUNDED xfs_bwrite-until-durable-or-shutdown; dir DATA blocks ARE on the LUN at handoff.
3. Dir-inode extent-map FLIP-FLOP / stale non-owner iflush: **P67-IFLUSH-OWNER-FENCE never fired**; P-DIRIFLUSH shows the only NL(mode=0) dir-inode flushes are all relflush=1 (legit release-drains) with block0=fsb15 STABLE and incore_nx==disk_nx. Extent map block0 CONVERGED.
4. Stale TOO-SMALL extent map at grow (modify_extent_adopt count-compare): **P67-MODIFY-EXTENT-ADOPT never fired** even with direct disk FUA compare → incore_nextents is NEVER < disk_nextents at the modify prelock.

### KEY NEW FINDING → NEXT STEP: since (a) data_init zeroes a block at daddr D that IS on disk owned by this dir (sess36 P31E owner==ino, P32B-DOUBLEMAP=0) but is NOT in the node's in-core extent map, AND (b) incore_nextents is NOT < disk_nextents, the extent maps diverge in CONTENT (same count, DIFFERENT daddr per logical block), not in count. So a count comparison is useless. The fix needs a FULL per-logical-block daddr comparison disk-vs-in-core, and on divergence a MERGE-adopt (adopt disk's daddrs for blocks both have / disk has, but KEEP the node's own uncommitted appended higher blocks — a plain from_disk reload DROPS them = the epoch_adopt "drops converter's own entries" regression). The merge-adopt at the modify prelock (no ILOCK held, safe to reload) is the most promising untried fix. Alternatively defensively guard xfs_dir3_data_init: before zeroing, FUA-read the daddr; if it holds a live dir3 block owned by this dir, the alloc double-allocated a still-live block → the real bug is the ALLOCATOR/freespace giving out D; investigate why the AG bnobt/dir-freesp considers D free when it holds this dir's live block (likely the same stale-extent-map → stale freesp).

### GPT-5.5 consulted 2× (RULE 5): (1) read-path under-lock coherency design (→postread_reread, refuted); (2) confirmed release IS durable, pointed to "coherency-bypassing buffer access" = exactly xfs_da_get_buf in data_init.

### REPRO: clean virsh reboot test1-4, `./run.sh 4 tcp dir_reuse_coherency` (~1/15 rounds fails, ~5min). Probes: drc-CLASS (lost names), P-DIRIFLUSH, P31E (instr). test5-8 exist in libvirt + have shared LUN /dev/sda + NFS (8/tcp ready once 4 passes).

[[sess67-ROOT-datainit-zeroes-live-dirblock-4node]] [[sess36-PROVEN-datainit-zeroes-live-block0-root]] [[sess62-PROVEN-ROOT-4way-logical-block0-split-divergent-extent-map]] [[sess67-force-block-1-fixes-dir-reuse-2tcp-current-build]]
</body>
