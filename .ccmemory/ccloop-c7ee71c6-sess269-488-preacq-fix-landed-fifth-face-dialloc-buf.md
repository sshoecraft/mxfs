---
name: ccloop-c7ee71c6-sess269-488-preacq-fix-landed-fifth-face-dialloc-buf
description: sess269: -488 4th-face preacquire handoff LANDED 0.11.495 (GPT-ruled), rsync_paired run1 PASS 32/32; run2 exposed 5th face: xfs_create/dialloc blocki…
metadata:
  type: project
---

# sess269 — preacquire handoff landed; fifth face opens (dialloc/buf)

## Landed (0.11.495 sv 4E7207C471AEBE2EEB10784, deployed 32/caw)
GPT-ruled (full ruling in sess269 transcript) fourth-face fix:
- `mxfs_trans_agwait_handoff(tp,pag,why,backoff_ms)` extracted from
  mxfs_defer_agwait (probe P271-AGWAIT-%s: "SEAM"/"PREACQ"); backoff
  slept only after ILOCKs handed off; consumes pag ref.
- `mxfs_trans_preacquire_inode_ags`: trylock-only sweep, on miss →
  handoff (drain grants, detach+iunlock, block holding nothing,
  pregrant→cached, relock+rejoin, restart). 8-handoff budget →
  P271-PREACQ-EXHAUST + -EAGAIN.
- xfs_rename: preacq -EAGAIN → cancel + xfs_iunlock_rename + jittered
  msleep + goto retry (≤3); exhaust → -ETIMEDOUT (never userspace
  -EAGAIN, per ruling). xfs_remove P13-CLEANRETRY: backoff on -EAGAIN,
  exhaust → -ETIMEDOUT.
GPT ruling highlights: existing rename revalidation (src + tgt both
polarities + ftype) accepted as unlocked-window guard; warm only missed
AG; follow-up = central assertion in blocking AG-DLM primitive
(per-task ILOCK/AG census) — call-site review alone breeds new faces.

## Verified
rsync_paired run1 PASS 32/32 24s/60s (was 0/32 wedge). P271-AGWAIT-
PREACQ fires fleet-wide (inodes=2..3, comm=rsync). Zero EXHAUST.
scaling_curve regression check NOT yet run this build.

## FIFTH face (run2 FAIL 0/32 NO_TERMINAL_RECORD; specimen LIVE test2)
test2 rsync 13975 blocked 120s+: caw_wait_for_grant ← mxfs_ag_dlm_lock
(BLOCKING wrapper) ← xfs_dialloc+0x91b ← xfs_create. P1-AGWAIT ag=3
trans_dirty=0 trans_held_ags=[].
Timeline on test2: 16077 P12 ag=3 holders=1 holder=13975 page_ms=0
(just granted); 16080 P67 AG-AIL-STALL agno=3 iter=256 buf=1(pinned=0)
inode=2 stuck_ino=12583847 iflags=0x20040 ili_fields=0x4001 in_ail=1
buf_flags=0x30 buf_locked=0 ilocked=0 — drain stuck on a BUFFER/
IFLUSHING inode, NOT an ILOCK; 16081+ 13975 re-blocks wanting ag=3.
Whole fleet BASTs ag=3 with holders=0 cached=0 everywhere → bit likely
stranded at test2 (P5N-AG-ORPHAN-NAK family). Open questions: (a) is
this the _XBF_DELWRI_Q / _XBF_MXFS_ALLOC_QUEUED collision (CLAUDE.md
design tension) starving the drain? (b) how did holders go 1→0 without
on-disk release? (c) does dialloc hold dp ILOCK here (v0.3.148 said
dropped) — P67 says ilocked=0 so poison is NOT ILOCK this time.
iflags=0x20040 decode needed (0x20000 likely XFS_IFLUSHING).

## Next
1) Decode P67 fields; read xfs_dialloc AG-walk mxfs hooks (blocking
   mxfs_ag_dlm_lock at xfs_dialloc+0x91b — why not
   trylock/lock_bounded?). 2) On test2: is the stuck buf mxfs-managed
   (P67 buf list) and why isn't xfsaild/bast drain writing it?
3) 3× scaling_curve + rsync_paired reruns after fix. GPT audit list
   (sess269 ruling): create/mkdir/symlink/link dialloc paths were named
   as suspect — this face confirms it.
