---
name: sess34-run14d-zsl-p119-consume-skip-race
description: sess34(14d): zsl double-map ROOT(s) PROVEN: (1) P91-RELOAD-PROTECT stale-dinode adoption → fix P34D-RELOAD-FRESHSRC (90A647F4, unverified-0-fires); (…
metadata:
  type: project
---

# sess34 (ccloop 14d31183) — zero_silent_loss: two stale-extent-map producers proven

## Status at handoff
Build `91BB755E51C3E88E7F5C058` BUILT, NOT yet deployed/tested. Carries everything from `6AB6018C` + this session's probes P34B/P34C + fixes P34D + RELFLUSH-window. zsl still FAILing (94/31/156 losses per iter across runs).

## Probes added (all in tree, gated dirwr||instr, multinode, dirs)
- **P34B-BMBT-STALEREAD/AHEAD** (xfs_bmap.c xfs_iread_bmbt_block): FUA-compare consumed bmbt child block vs platter. RESULT: 0 STALEREAD ever → bmbt-child-buffer staleness REFUTED (sess33's prime suspect). P34B-IREAD logs each dir extent-map (re)load.
- **P34C-DIRGROW/DIRSHRINK** (xfs_da_btree.c grow_inode_int/shrink_inode): logs every dir-space (startoff→fsb) map/unmap + next= (post-insert if_nextents) + size. Cross-node merge by (ino,startoff) within-iter finds double-maps. Segment by >30s realns gaps = iters; collision = same startoff diff fsb within segment. 'next=' is if_nextents AFTER insert; consecutive-fsb grows MERGE so next doesn't increment.

## ROOT #1 (PROVEN, fix unverified): P91-RELOAD-PROTECT stale adoption
Run 13:32Z iter1: test10 grew startoff=1→0x100009 (~94 dirents), test15 grew startoff=1→0x180009 272ms later under a LEGIT later EX (slot history clean, no concurrent EX, no strip). test15's 3 prior acquires all reloaded nextents=2 because the inode-cluster invalidate was REFUSED: `P91-RELOAD-PROTECT` (mxfs_buf_has_uncheckpointed_mods=true: BLI attached from own logged timestamp mods) → reload adopted STALE cached cluster (P133-DINO-READSTALE buf nx=2 vs disk nx=3 logged the truth) → test15's next release-drain iflush wrote nx=2 over disk nx=3 (durable revert, orphaning test10's block) → grow collided.
**FIX (in `90A647F4`, in tree)**: mxfs_dlm_reload_inode snapshot block — when kept_protected, FUA-read cluster privately, verify, memcpy fresh dinode into snap (P34D-RELOAD-FRESHSRC log). Buffer untouched. NOTE: next run had 0 P91 fires so P34D never exercised — needs a run where P91 fires to verify.

## ROOT #2 (PROVEN, fix BUILT NOT RUN): P119 consume-skip races the release window
Run 14:00Z iter1 (156 lost, test12 dabuf-HOLE shutdown): test9 SELF-double-mapped startoff 7/8 (0x48000b/c → 0x48000d/e 160ms later). Timeline (test9 gen230 release, 14:02:46): grows so=5..8 commit in-core (size 36864; extents merge so nx stays 9); REL → bast_process sets i_dlm_mode=NL EARLY; concurrent xfsaild iflush hits `P119-NONEX-FLUSH-SKIP` (xfs_inode.c:4048, mode!=EX && !MXFS_IF_DLM_RELFLUSH) whose `error=0; goto flush_out` CONSUMES ili_fields WITHOUT copy-in; buffer written with old payload (P133-DIRINO-WR size=28672, P136-WRDONE 28672 — NO 36864 write ever); drain's iflush_cluster finds nothing dirty → -EAGAIN → !IN_AIL → flushed=true → release. Next acquire reloads disk 28672 (disk went BACKWARD), in-core map loses so=7,8 → re-grow → own committed blocks orphaned.
**FIX (in `91BB755E`)**: in mxfs_dlm_bast_process, set MXFS_IF_DLM_RELFLUSH (REG||DIR) BEFORE the `i_dlm_mode = NL` clear (was only set later, just before the durable-flush loop ~L2780). Concurrent flushes in the release window now write real in-core state (safe: tenure owned until on-disk unlock). Flag still cleared at reg_durable_done.

## NEXT (in order)
1. Power-cycle all 16 (`virsh -c qemu:///system destroy/start test1..16`), deploy `91BB755E` (NFS-visible at /src/mxfs/mxfs.ko), run `INSMOD_OPTS="dirwr=1" ./tests/criteria/zero_silent_loss.sh --iters 3` (budget 480s; power-cycle between failing runs — shutdown iters leave D-state umounts).
2. Check: P34C within-iter double-maps (esp. SELF maps), P119-NONEX-FLUSH-SKIP during release windows, P34D fires, P133-DIRINO-WR size-regression (WR size < prior WRDONE size for same ino).
3. If still lossy: remaining suspects — other i_dlm_mode=NL clear sites (xfs_mxfs_dlm.c ~4664/6309/6396/6419/11556) opening the same P119 window; consume-skip may need a mid-release no-consume variant (dlm_state==BAST → leave dirty); dabuf-HOLE storm = read-side of same stale map.
4. Then clean iters=3 ×N, then verify_ship.sh end-to-end.

## Env notes
- iter2 of 14:00Z run INFRA-failed (test12 D-state wedge after shutdown) — teardown barrier refused mkfs. Power-cycle mandatory after any shutdown iter.
- zsl criterion 480s timeout kills iter3 of slow runs; per-iter walls 139-286s with verify storms. RULE 0: don't widen — slowness correlates with the storm mode.
