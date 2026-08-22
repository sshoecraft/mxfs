---
name: ccloop-c7ee71c6-sess317-zsl-mechanism-poisoned-shell-serves-reads
description: sess317: zsl .512 regression MECHANISM PROVEN — P34H poison fired correctly but retire loop cache-hits same shell (inew=0 tries=6) and file reads hav…
metadata:
  type: project
---

# sess317 — zsl silent-loss mechanism pinned (sess316 hypothesis refuted)

## Refuted
sess316's hypothesis (sess315 ilock_begin edit admits re-acquire without
reload) is DEAD: test1 dmesg 30920.079 shows the protective reload RAN and
DETECTED the reuse — `P34H-INCARN-POISON ino=136 src=freshsrc
incore_gen=1866888366 fresh_gen=3133349002 — poisoning (ESTALE)`.
Also: sess315's wait-loop/postwait edits only NARROW admission (add park
conditions / add !defer-episode qualifiers); they cannot admit more than
.511 did. P79-NESTADMIT / postwait re-admit arms are pre-existing.

## Proven serving mechanism (live dmesg, test1, uptime stamps)
1. Poisoned-shell retirement FAILS: xfs_inode.c:1534-1548 retire arm
   (d_prune_aliases + xfs_irele + retry_iget, bounded 4 tries) fired at
   30920/31011/31022/31369; `P-EVICT-RESULT ino=136 inew=0 tries=6
   gen=3133349002 name=node7_data1` — retry_iget CACHE-HITs the same
   shell; lookup falls through RETURNING the poisoned inode.
2. File reads are NOT gated on MXFS_IF_INCARN_STALE. All test sites:
   dp-lookup entry (xfs_inode.c:1247 → -ESTALE), create 2270, unlink
   5880, rename 6361/6365, readdir (xfs_dir2_readdir.c:844). Nothing on
   open/read_iter/mmap for REG files → md5sum happily reads the stale
   bmap = silent loss + CROSS-FILE DATA LEAK (stale bmap's blocks now
   belong to node7_data1.md5).
3. Why cache-hit forever: retire loop never d_mark_dontcache()s the
   shell; xfs_fs_drop_inode → inode_generic_drop keeps hashed clean
   inodes in the icache, so last iput ≠ evict; MXFS_IF_INCARN_STALE only
   resets on IRECLAIM recycle, which never happens. Possible extra ref:
   P15 orphan dwork igrab (xfs_mxfs_dlm.c:16863 bastq_src=14) —
   P15-REL-ABORT orph=1 age_ms=0 storm during reads (16918), silent in
   the idle 31022→31369 gap, so a plain hashed-cached shell suffices to
   explain inew=0.
4. Served shell = SECOND stale incarnation: gen=3133349002 size=14 was
   re-igot fresh after the first poison, node7 then reused ino 136 again
   (256K node7_data1); the second INCARN-POISON was ratelimit-hidden
   (all P34H prints are pr_warn_ratelimited).

## Open (RULE 4)
- What keeps the shell hit-able: instrument P34H-POISON-EVICT with
  i_count/i_state/bast_pending/dwork_pending.
- .511-vs-.512 delta: poison path is sess3-era and previously worked
  (P-EVICT-RESULT inew=1 in past logs). Suspect sess315 release/defer
  changes alter how long the shell stays cached/BAST. Uninstrumented.

## State
Rig: .512 knob-on prepped, zsl dir cleaned (live evidence gone), repro =
re-run zero_silent_loss (~60s). Defect STILL UNLEDGERED. Next: RULE 5
consult on fix shape (DONTCACHE in retire loop vs file-op ESTALE gate vs
both), then instrument → fix → verify. Handoff.md has full detail.
