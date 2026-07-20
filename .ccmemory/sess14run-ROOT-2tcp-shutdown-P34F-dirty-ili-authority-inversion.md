---
name: sess14run-ROOT-2tcp-shutdown-P34F-dirty-ili-authority-inversion
description: sess14 ROOT (2/tcp 13/17): test2 FS shutdown = use_free on 13-gen-stale base. Chain: undestageable ili (0x5,in_ail) + releases proceed anyway + P34F…
metadata:
  type: project
---

# sess14 — 2/tcp failure root chain (artifact /tmp/run_dir_reuse_coherency_20260704T192640Z)

## Verdict shape
2/tcp iter s14a = 13/17: drc 0/2, fence 1/2, netpart 1/2, tds 1/2 — ALL
ONE EVENT: test2's FS shut down at drc round ~10 (19:30:02), everything
after failed on the dead mount (EIO). test1 kept running (readdir=100/200
= only its own files; test2 readdir=0 + empty DIRID = stat EIO).

## Proven chain on test2 (dir ino=540033, fmt=2/EXTENTS, 3 dir blocks)
1. Dir inode's ili became UNDESTAGEABLE (ili=0x5, in_ail=1 persisting
   minutes; why not flushed = OPEN QUESTION — pin=0, fmt=2 so NOT the
   P22/P14 sf-skip paths).
2. Releases still completed → test1 advanced the dir 13 GENERATIONS
   (disk gen 68 vs test2 loaded gen 55) — i.e. unlock-with-dirty-ili
   happens on some path (vs the gap-run 184s AIL-STALL case which
   correctly REFUSED to unlock — inconsistent drain contracts!).
3. Every test2 re-acquire hit P34F-RELOAD-SELFAHEAD-SKIP (xfs_mxfs_dlm.c
   ~13300): premise "dirty ili ⇒ platter behind us ⇒ in-core
   authoritative" is INVERTED when the dirtiness is a stuck-flush
   leftover — kept serving the 13-gen-stale image in a skip LOOP
   (P34F ×dozens, same dgen=68 lgen=55).
4. Concurrent local create RMW'd the stale base → xfs_dir2_data_use_free
   internal error (libxfs/xfs_dir2_data.c:2421) via xfs_create →
   trans_cancel → SHUTDOWN 19:30:02. Preceding: P21S-EVICTSKIP-LEAF
   undest=1 (leaf kept), P68-EVDECIDE undurable=1 same-epoch (all three
   blocks SKIP evict), P50-RD cnt=155/34 mode=EX.

## Fix directions (next session, RULE 4 order)
A. Find the iflush wedge: why ili=0x5 in_ail=1 never destaged (xfsaild
   skipping it? iflush erroring? cluster buf issue?). Instrument: log
   iflush rc for watch dirs, or always-on capped "ili stuck >Ns" sentinel.
B. P34F must distinguish "dirty because mid-op" from "dirty because
   flush is STUCK across handoffs": e.g. compare dgen vs lgen — if disk
   gen is AHEAD of loaded gen (peer tenures happened since we loaded),
   our dirty in-core is NOT authoritative-for-the-whole-dir; the safe
   move is (i) force-destage our ili first (log_force+ail push+retry),
   then (ii) reload/merge fresh base, THEN apply new op. NEVER RMW a
   base that is generations behind the platter.
C. The unlock-with-dirty-ili path (step 2) violates Invariant #1 for the
   dir inode — find which release path allows it (P51-REL? the release
   drain's inode step) and whether it must block (like the AIL-STALL
   case) or destage-or-abort.

## Sibling faces (same root, different symptoms)
- 8-node drc 795/800 5-file miss (r6 daddr=62796800): the stale-base RMW
  publishing durably = swallowed peers' adds (victims hash to ONE block).
- 8-node whole-blob 700/800 in r4/r6 = DIFFERENT (drop_caches hang,
  fixed/instrumented in the test script sess14).
- gap-run test4 sf-corrupt AIL wedge = possibly the same stuck-ili class
  with an sf dir (count/bytes desync now guarded by P14 tripwires).

## 8/tcp + 4/tcp are GREEN on 8E654A57 (r8 modargs + r9 default + 4/tcp
   17/17). 2/tcp = this bug. 1/tcp not yet run this session.
