---
name: caw-phantom-cached-ex-dirent-loss-rootcause
description: PROVEN 4/caw dirent-loss root: P106 stale cached EX served probe-only → dual-writer on one dir block (dland zigzag). Fix candidate: dir_ex_revalidate…
metadata:
  type: project
---

# 4/caw random dirent-loss family — phantom cached EX (2026-07-05, sess2 ccloop 186320ae)

## Symptom (moves between tests run-to-run)
One node's dirent adds/renames vanish for EVERYONE (incl. itself): mmap_coherency
node4.bin MISSING 0/4; cache_coherency cv "node3.txt got=''"; rv after_8/9 lost;
uv "pre-delete exp=120 got=115". ~100% of 4-node runs hit ONE of these.

## Proof chain (RULE 4)
1. `dirland=1` completion-ring (`echo 1 > /sys/module/mxfs/parameters/dland_dump`,
   P-DLAND d=<daddr> o=<ino> s=<fnv> n=<dirent-count> t=<realns>): merged
   cross-node timeline showed **t1 AND t4 writing the SAME dir block
   (daddr=8372968, uv dir ino 10485888) INTERLEAVED for ~60ms**, each climbing
   its own count ladder (t1: 66..90, t4: 67..89 behind it) — two uncoordinated
   RMW streams; final image lacks the loser's latest adds.
2. `P106-STALE-EX ino=10485888 cached_mode=EX on_disk_held=0` fired on t1 at
   the window start (61× that run). The dir-EX fast path (xfs_mxfs_dlm.c
   ~16990-17080) verifies the on-disk CAW slot (`dir_ex_verify_held`, ON) but is
   **PROBE-ONLY** — comment literally says "no behavior change yet (the fix
   falls through to slow-path re-acquire once this is confirmed firing)". It
   logs P106 then SERVES the phantom cached EX anyway.
3. P108-REACQUIRE (idle-only enforcement) can't act: gated pin==0 AND
   ex/pr_holders==0 AND 1000ms throttle — never fires inside an active create
   storm (pin oscillates, entries every ~3ms).
4. Phantom genesis (per sess108 comment): own BAST demote clears the disk bit;
   re-grant racing demote leaves i_dlm_mode=EX/state=CACHED stale.

## Fix being validated
`dir_ex_revalidate=1` (sess51 knob, xfs_mxfs_dlm.c:4860, default 0 — built for
the same phantom on TCP): diverts every published !self_created dir EX-modify
(pin==0) to the slow path = authoritative on-disk acquire (already-held check =
1 slot read ≈ same I/O as the probe it replaces; phantom ⇒ real blocking
re-acquire + adopt). If loop passes → make default-on, rebuild, full ladder.

## Red herrings eliminated en route
- lseq/wseq(=0) "never-written" theory: P3W-DIRWR logs at SUBMIT; wseq=0 =
  in-flight overlap snapshot, not broken accounting.
- "log I/O error -52" bursts every ~80s = prep_fs PR CLEAR hitting the PREVIOUS
  iteration's dying mounts during teardown (benign, per-iteration cadence).
- P26-LKFMT fmt=1 ≠ shortform: XFS_DIR2_FMT enum (SF=0, BLOCK=1) — fmt=1 is the
  BLOCK lookup path; content, not format, was missing entries.
- Tombstone epoch-inherit (v0.6.1) NOT implicated: epoch ramps clean (0→3).
- dirwr modarg must be `dirwr=1` (insmod), NOT `mxfs.dirwr=1` (silently dropped).
[[pr-ua-register-fence-out-rootcause]] [[caw-multipath-matrix-progress]]

## Genesis PROVEN (same run, t1 ino 10485888, µs trail)
```
:637.263808 P106-EXREL   bast_process drain+unlock (t1 releases EX on disk)
:637.264909 P106-EXREL   second unlock pass
:637.265003 P106-EXGRANT local slow-path re-acquire GRANTS EX (P-DIR-SEQ gen=4)
:637.266627 P106-STALE-EX on_disk_held=0  ← disk lost the bit 1.6ms after grant
```
The bast unlock's CAS -EAGAIN retry re-reads the slot, sees OUR bit (the fresh
re-grant), and clears it — releasing a grant a concurrent LOCAL acquire just
took. In-core keeps the acquire's CACHED-EX; disk is released. Offense fix
(task: snapshot per-inode acquire seq at BAST start, abort unlock retry when it
advances) filed; dir_ex_revalidate is the validated defense meanwhile.
