---
name: ccloop-c7ee71c6-sess6-C-torn-write-ROOT-stale-image-subEX-writes
description: sess6-C ROOT CAPTURED: torn da3 CRC = leaf1→node split + PEER STALE-IMAGE dir-block writes at gmode=3/0 (P-DIRWR proof, 19×PR +1×NL writes incl. post…
metadata:
  type: project
tags: [torn-write, dircrc, root-cause, P-DIRWR, gmode, leaf-split, crash_consistency, 8tcp]
---

# sess6-C: torn-block ROOT captured (run 20260725T182439Z, fresh-mkfs repro)

## The proof (P-DIRWR gmode instrumentation, v0.11.94 srcver 5286608AE926903F567B7FC)
crash_consistency@8/tcp reproduces the da3 CRC corruption ON A FRESH LUN within
~30s (28-109 CRC errors/node; blocks 0xa7e220 first run, 0x9fb620=10466848
second — daddr differs per mkfs, anatomy identical).

Merged cross-node P-DIRWR timeline for daddr 10466848 (owner dir 12583040,
the .crash_consistency shared dir, 800 entries):
- Normal phase: strictly sequential per-node EX bursts (t3 counts 127-137,
  t6 138-152, t2 153-155, ... t8 ...-502), every write gmode=5, comm=xfsaild
  (in_ail=1 done=1) with a final same-crc kworker done=0 write at each handoff
  (the release drain's sync flush — duplicate submission of identical content).
- THE CRIME WINDOW (18:24:56, all within ms):
  t8 leaf1 count=502 gmode=5 (last legit holder writes)
  t5 leaf1 count=502 gmode=3 crc=88b05775 comm=kworker  ← PR WRITE
  t1 leaf1 count=502 gmode=3 crc=88b05775 comm=kworker  ← PR WRITE
  t2 leaf1 count=502 gmode=3 crc=88b05775 comm=kworker  ← PR WRITE
  t6 danode count=2 gmode=0 in_ail=1 comm=xfsaild       ← POST-RELEASE NL WRITE of the SPLIT
  t8 leaf1 count=502 gmode=3 comm=kworker               ← PR WRITE
- Distribution for the daddr: 227× gmode=5, 19× gmode=3, 1× gmode=0.
- Decode: dir crossed ~500 entries → LEAF1→NODE split: the leaf's daddr
  becomes the da3 ROOT NODE (count=2 children), entries move to new leafn
  blocks.  t6 (the splitter) had its danode image pushed by xfsaild AFTER
  tenure (gmode=0, in_ail=1 — AIL retained the item post-release).  Peers'
  drains/evicts re-flushed their CACHED leaf1 image (identical crc 88b05775
  = same stale content) at PR because undest-tracking (lseq/wseq,
  P48-OWNEREVICT-DIRTYSKIP "undestaged this-tenure", P5-UNDEST-SALVAGE)
  still claimed their copy needed destaging.  Interleaved at the LIO target:
  danode header + leaf1 tail sectors = CRC-torn hybrid; read verifier calls
  it "xfs_da3_node block" (header magic 0x3ebe) → EUCLEAN in
  xfs_trans_read_buf_map → FORCE SHUTDOWN (5/8 nodes, both runs).
- 18:26:15 (post-kill stragglers): t3 re-wrote leaf1 count=470 (REGRESSED
  content, gmode=3) — stale-image writes also REGRESS platter content, not
  just tear it (the lost-update arm of the same root).

## Defect B connection
P14-DABUF-HOLE (dir 131, bno=8388608=LEAF_OFFSET, fmt=2 nextents=1
disize=4096, EX held, fresh gen-matched reload) = the SAME
format-transformation family read-side: walker's leaf/node decision predates
a format change (block↔leaf↔node) it then walks.  EUCLEAN-only so far.

## Fix design constraints (for the consult / implementation)
1. A dir-block write submission with granted-mode < EX is NEVER legal —
   EXCEPT the release drain's own sanctioned flush, which runs AFTER
   bast_process pre-clears mode (mode=NL + RELFLUSH set + demoter ctx).
   Fence must key on sanction (RELFLUSH/demoter/dlm-epoch), not raw gmode.
2. Post-release AIL pushes of dir buffers must be impossible: sess99
   PUBLISH-AND-DISCARD (xfs_buf_stale on release) has skip paths
   (P35F-STALE-RETRY-EXHAUSTED, pinned/locked skips) — skipped blocks
   survive on AIL/delwri and fire later at gmode<EX (t6's danode write).
   Also the _XBF_DELWRI_Q / _XBF_MXFS_ALLOC_QUEUED design tension file.
3. Undest-tracking false positives (lseq/wseq vs later-tenure supersession)
   cause CLEAN-buffer stale-image rewrites (dirty=0 delwri=0 done=0 writes!)
   — must be epoch-gated (b_epoch vs current mount/dir epoch exists:
   P68-EVDECIDE b_epoch/cur_mep/valid_epoch).
4. sess32 history: bounded-ail-push violating Invariant 1 was REVERTED —
   any fence here must not let the drain skip real flushes (no unlock
   without drain).  Safe direction: BLOCK/discard sub-EX writes (stale them),
   never skip drain writes.
5. Quick kill-switch idea: in the P-DIRWR site (xfs_buf submit chokepoint),
   refusing/staling dir-block writes when gmode<EX && !sanctioned would stop
   platter damage immediately (fail-safe), then root out the producers.

## State: cluster on v0.11.94, LUN freshly mkfs'd but RE-CORRUPTED by the
repro run (blocks 0x9fb620 family) — mkfs again before next verification.
Kernlogs: /tmp/run_crash_consistency_20260725T182439Z/ (all 8, P-DIRWR-rich).
