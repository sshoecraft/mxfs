---
name: sess4-MID-classB-dangler-inode-reuse-staleness-guards
description: sess4 MID: class-B dangler (r10 lookup_fail) = reused-ino iget guards misfire: reader igrab-fail falls through to ENOENT (disk VALID 0x81a4); creator…
metadata:
  type: project
---

# sess4 MID checkpoint — class-B (lookup_fail dangler) root analysis

## Symptom (runs 20/22/23, always ~round 10 of 8/tcp dir_reuse_coherency, build 2AED5AD3B129F3C0E9893B9)
`readdir=800 lookup_fail=N missing=[nodeX_fY...]` persisting every round after onset; on-disk dir structures PERFECT (verified raw via scripts/mxfs_dirdump.py — dirent present, leaf hash present+sorted+routed; NOTE decoder initially had off-by-8: da3_blkinfo=56B, count@0x38, ents@0x40).

## Proven chain (run23, node4_f29 / ino 4196252, P4X/P4I/P4C + P-IGET-ENOENT):
1. test1's rm -rf frees the ino each round (P4I-IFREE comm=rm; P4C-IFREE-WR lands ~1.5ms later — frees destage promptly).
2. r9 (341.9s): test4 re-creates node4_f29 → SAME ino 4196252, **pino=132** (dir ino drifted 131→132 at r9 = the dir inode itself hit the same reuse wall at mkdir!). fmt=1.
3. 353.1s: test4's OWN lookup ENOENTs (P26-IGET-FAIL) — creator's in-core inode mode became 0 within 11s of create. Suspect: late freed-hint/reload read PRE-DESTAGE disk (mode=0) and zeroed the fresh in-core inode (sess87-family reload-over-newer-in-core hazard). The committed create's ILI still destaged later → disk becomes VALID.
4. r10 verify (357-361s): ALL nodes P-IGET-ENOENT with `incore_mode=0 cached_disk_mode=0x81a4 fua_disk_mode=0x81a4 flags=0x0 dlm_stale=1` — **disk is VALID, in-core shells are stale-free, non-IRECLAIMABLE**.
5. Reader-side hole (xfs_icache.c): the sess38 live-shell reload branch (non-reclaimable && mode==0 && non-CREATE) SKIPS entirely when `igrab(inode)` fails (VFS teardown race — the verify does drop_caches right before!) → falls through to xfs_iget_check_free_state → **-ENOENT** (P-IGET-ENOENT fires = proof the branch was bypassed, since the branch returns directly). Upstream's own igrab-failure paths do `goto out_skip` → -EAGAIN retry.
6. The sess40 IRECLAIMABLE reuse-reload branch requires XFS_IRECLAIMABLE — flags=0x0 shells don't qualify either.

## Fix plan (in progress)
- FIX B1 (reader): sess38 branch igrab-failure → goto out_skip (retry) instead of fallthrough; retry lands on cache-miss/fresh state → reads valid disk.
- FIX B2 (creator, needs verify): mxfs_dlm_reload_inode must refuse dinode from_disk when in-core inode is AHEAD of disk (ILI dirty/pinned/in-CIL committed-not-destaged) — check existing guards before patching (sess87 added snapshot+verify for the shutdown case; the mode-zeroing path may bypass it).
- After B1/B2: rerun; if verify still fails ~r10 check the dir-ino drift (mkdir hitting same wall — B1/B2 should cover it: mkdir's iget(CREATE) uses reset_inode_for_create path).

## Class A recap (FIXED this session, build 131347C2+): DLM unlock-fallback ate live requests → concurrent EX → stale-base RMW. pend_waiter linkage + P4U-SKIP-INFLIGHT + P4G guard. 0 double-grants + 0 readdir-loss in runs 21-23 (vs every earlier run). See [[sess4-ROOT-FIX-unlock-fallback-eats-live-request-concurrent-EX]].

## Session infra added (build 2AED5AD3)
- P4X-UNLINK at xfs_remove std_return — NOTE success path returned early; NOW routed via `error=0; goto std_return` (fixed after run23).
- P4I-IFREE in xfs_ifree; P4C-IALLOC-WR/IFREE-WR per-slot dinode transition decode at inode-cluster write submit (BEFORE partial-write interception); P27 now prints hex masks (logged_m/dirty_m/skip_m).
- Round times healthy 24-35s; run21's 143s round-8 stall = host-transient (whole-guest silence; swap 6/7GB; did not recur). hung_task 30s armed in prep_node.sh.
- dir_reuse test structure: rank1 mkdirs $D and rm -rf's it each round; every node creates nodeR_f1..50 + .md5 (dd+bash); verify = ls count + per-name [ -e ] after drop_caches.

Links: [[sess4-ROOT-FIX-unlock-fallback-eats-live-request-concurrent-EX]]
