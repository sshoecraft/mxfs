---
name: caw-uv-single-dirent-leak-hunt
description: uv dangling-dirent: dual-representation divergence (early sf-convert node edits inode core while peers edit block); surgical_inode_write=1 REFUTED; n…
metadata:
  type: project
---

# uv single-dirent leak — diagnosis tree (sess4 ccloop 186320ae, head build 9C634772)

## Failure shape
cache_coherency uv: deleted dirent(s) survive on disk pointing at freed inodes
(P26-IGET-FAIL err=-2 makes t2/3/4 pass; only test1 stat FAILs). Instances:
node2_file28 (run 232526Z), node3_file21 (run 003620Z), node2_file26+node3_file26
(run 005227Z, TWO entries, ino=156, with surgical_inode_write=1 → LEVER REFUTED
as sole fix; may still be a needed ingredient but did not stop the family).

## PROVEN structure (run 003620Z forensics)
1. During the 120-unlink storm the dir (ino=157, single XDB3 block daddr=2376)
   nears the block→sf threshold; ONE node (t3) converts block→sf IN-CORE early
   (its view crossed threshold first). From then on t3's removals edit the
   INODE CORE (sf); peers keep editing BLOCK 2376 — two on-disk representations
   with NO serialization between them (block writes vs inode-cluster writes).
2. t3 wrote NOTHING to 2376 after ~:12.9 (P35E silent; ~129 P11-FLUSH-CLEANSKIP
   = correct skips, block genuinely had no local mods post-conversion).
3. t1's :14.0 EX tenures cold-read STALE disk (still block, still carrying
   node3_file20/21 because t3's removals lived in its sf core, not the block)
   → t1's release-drain writes re-asserted them (crc=03b70f75 nent=18, then
   nent=14,13 — the resurrect writes, comm=rm).
4. Final crystallization: t3's sf (carrying stale membership from divergence
   era) is what P56-RELOAD-MERGE later shows as disk=[node3_file21].
5. Peer whole-cluster inode writes (P136-DIRINO-WRDONE daddr=128 from ALL
   nodes) can revert t3's fmt=LOCAL dinode — sess90 clobber write-side; BUT
   surgical_inode_write=1 (per-dinode FUA sectors) did NOT stop the family →
   the dominant leak is the BLOCK-side resurrect (item 3), not (only) the
   dinode revert.

## ELIMINATED (evidence, this session)
- Phantom-EX as uv cause (0 STALE-EX in failing runs; Fix A prebump holds).
- Split-slot (32-bit FNV: all slots at home, 1 slot/resource, 0 dups).
- b_epoch stamp fraud (stamps only on fresh reads).
- Eviction-never-runs (P4O evict=1 fires; drain_evict ungated at dir ACQ).
- Systemic lineage divergence (time-aligned fcnts agree cross-node).
- FUA transport staleness (SCST fileio shares backing page cache).
- P34F self-ahead early-return (0 fires for storm dir).
- CLOCK TRAP: never compare raw monotonic stamps cross-node; derive per-node
  offset from same-line realns pairs. HASH TRAP: C fnv1a is 32-BIT.

## OPEN QUESTIONS for next session
- Why didn't t1's acquires adopt t3's sf conversion? P43-FMTREVERT-SKIP keeps
  in-core BLOCK when (dirty||mode==EX)&&!genuine_handoff — mode==EX is ALWAYS
  true at EX-acquire reload (acquire sets mode before reload); genuine_handoff
  = my P65 epoch-consume gate (adopt=1 clean=1 fires but is partially defeated:
  modify-path hooks 5318/5342 sync valid_epoch up, erasing the lag the acquire
  gate needs). CANDIDATE FIX: separate acquire-side epoch tracker
  (i_dlm_dir_acq_epoch) so every real handoff triggers adopt at EX-acquire;
  and/or force fmt-transition tenures to destage + peers to accept
  (same-incarnation sf adopt when self-clean post-release).
- Was t3's conversion committed+destaged before t1's :14 tenle? (If not, t1's
  cold read was honest-stale and the fix is release-side: force destage of the
  CONVERSION transaction (inode core + block free) before unlock.)
- Residual P106-STALE-EX events (non-uv): P142-STALE-IMG probe armed (build
  9C634772), no capture yet.
- iter8-style test1 guest-reboot wedge: klog_tail.sh collectors + persistent
  journald armed; unreproduced since.

## State
- Build 9C634772 (= v0.6.4 prebump + epoch-consume + P141/P142 probes) on tree
  and nodes. Loop: MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="dirwr=1
  dirland=1" ./run.sh 4 caw precond_readiness cache_coherency. Fail rate ~1/2
  to 1/5 iterations (uv/rv family), so reproduction is cheap.
- 4/caw matrix otherwise: strong_consistency..dlm_lock_correctness PASS except
  posix_multi FAIL 3/4 (untouched); precond+cache_coherency cycling.
- 1/caw + 2/caw: 17/17 PASS. 8/16/32: pending. mpath_up.sh apostrophe bug fixed.
- P35E names[] truncates at ~16 entries; kernlog spans PREVIOUS iterations
  (same ino/daddr reused per mkfs!) — always window by realns/run start.
[[caw-v064-prebump-epochconsume-fixes]] [[caw-phantom-cached-ex-dirent-loss-rootcause]]
