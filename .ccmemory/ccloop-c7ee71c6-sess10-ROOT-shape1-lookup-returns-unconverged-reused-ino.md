---
name: ccloop-c7ee71c6-sess10-ROOT-shape1-lookup-returns-unconverged-reused-ino
description: sess10 ROOT+FIX Shape-1: xfs_lookup returned reused-ino inodes whose in-place reload silently BAILED (typeflip ENOTDIR ~1s window = lost creates; sam…
metadata:
  type: project
---

# sess10 — Shape-1 family ROOT CAUSE + FIX (v0.11.105/106, srcver 46E8567FA082F020D2E197E)

## The defect (RULE 4 proven, three live captures)
`xfs_lookup` (xfs/xfs_inode.c P95 block) could return an inode whose in-core state was a
**stale prior incarnation of a reused inode number**, because the in-place
`mxfs_dlm_reload_inode` it armed **silently bails** under storm (down_write_trylock
contention + P34J-RELOAD-RACE-BAIL), and the old code single-shotted it:

- **Type-flip arm** (captures: run 233839Z test16 ino=27263107; run 001124Z test6 ino=18874507):
  in-core = stale FILE shell, dirent+disk agree DIR (RELOAD-TYPEFLIP-DIRENT-OK), but the flip
  keeps losing to bails for ~1s (P95 tries=6). Every walk into the name fails **ENOTDIR**
  (bash: "Not a directory" in node shell log — the smoking gun artifact) → `echo > file`
  creates silently lost (uv census 127/128, 126/128). The evict path can't help: refs pin the
  struct (concurrent walks + DLM work), retry_iget cache-hits the same shell.
- **Same-type arm** (capture: run 003359Z test1): 8 reused node5_after_* inos, gen-stale
  FILE→FILE; single-shot reload bailed on all 8 → lookup returned pre-write **size=0 shells**
  → `cat` returned empty (rv content failed=8) while 15 cold-iget peers read the platter fine
  (proves disk was current; reader-side in-core staleness only).

## The fix (xfs/xfs_inode.c, both arms in the P95 block)
Lookup must NOT return an inode that mismatches the just-read dirent / whose armed reload
didn't land. Bounded blocking retry (no locks held there — function-entry comment):
loop ≤200 × 10ms re-arming `i_dlm_stale` + `mxfs_dlm_reload_inode`, until
(typeflip) in-core ftype == dirent ftype, or (sametype) `i_dlm_stale` cleared
(reload contract: cleared on success, left set on any bail). Periodic
`mxfs_dlm_force_peer_flush` re-kick every 16 rounds (typeflip arm).
Prints: `P95B-TYPEFLIP-WAIT resolved= rounds=` (always), `P95C-SAMETYPE-WAIT` (only when
>1 round or unresolved).

## Verification (v0.11.106 = 46E8567F)
- cc@16/tcp: **26 consecutive PASS** (pre-fix rate ~2/7..1/22 across shapes), 12-14s/run.
- Arms exercised heavily during green runs: P95-SAMETYPE-RELOAD ~200/node,
  P95B-TYPEFLIP-WAIT 17-32/node, **resolved=1 rounds=1 every time, unresolved=0**.
- v0.11.104 probe interlude: P165-AFFINE-STALE (d_revalidate affine fast-path serves
  epoch-mismatched positive dentries ~40/run/node) — that path was NOT the failing vector
  (disproven for these instances) but remains an epoch-blind reval exit; the probe print is
  still in the tree (cap 100000). Consider epoch-gating later with its own evidence.

## Wrong turns to not repeat
- The uv census `ls got=127` is readdir+stat; the missing create's error was in the NODE'S
  SHELL OUTPUT (`$D/testN` file: "Not a directory") the whole time — CHECK SHELL ARTIFACTS FIRST.
- dcache/dentry-resurrection theories (d_splice_alias etc.) were dead ends; the binding was
  fresh each time — the STALE thing was the in-core inode struct behind a correct dirent.
- P-DIRWR/P-DIRRD (mxfs.dirwr=2, runtime togglable) gave the decisive block-content lineage:
  the write chain count 18→121→conversion was CORRECT — the platter was never wrong in these
  failures. Reader-side in-core staleness was the whole story.

## Related state
- dirwr=2 left ENABLED on all 16 nodes (re-set after each prep; it's a module param, reload resets).
- P-REG-DURABLE-FAIL rerr=-11 size=14/15 lines correlate with the uv "delete_me" files —
  re-examine post-fix whether they still occur (may have been victims' shells flushing).
- Next: cc to ~40 greens, drc@16 ×3, full 16/tcp board at 46E8567F, then 8/tcp, 32, CAW, physrig.
