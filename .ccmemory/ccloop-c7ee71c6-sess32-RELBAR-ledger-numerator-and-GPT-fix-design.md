---
name: ccloop-c7ee71c6-sess32-RELBAR-ledger-numerator-and-GPT-fix-design
description: BREAKTHROUGH: ledger predicate (pend!=dur) at tenure end fires 19-41/lap where IFLUSHING=0 — typed: live child dirs ili_f=0x3 at completed-release; G…
metadata:
  type: project
---

# sess32 — D-RELEASE-BARRIER-OPEN: the numerator exists, typed, fix designed

## The measurement that broke it open (0.11.276/277)
Added the LEDGER predicate — `i_mxfs_pub_pending_seq != i_mxfs_pub_durable_seq`
(pending++ at every xfs_trans_log_inode; durable promoted only at real home
iodone) — to mxfs_dlm_relbar_check (unlock tails, new counter `obligation` +
P220-UNLOCK-LEDGER-OPEN) and mxfs_relbar_epoch_check (every epoch++ site, new
counter `epoch_obligation` + P220-EPOCH-LEDGER-OPEN, epsrc names the site).
Per dirent_durability lap @32/caw: unlocks=8234 obligation=10; epoch_ends=8918
**epoch_obligation=19..41** while epoch_flushing=0 — the IFLUSHING probe is
now PROVEN blind (P220's old verdict "the tails are clean" was an artifact of
the wrong predicate).

## Typed (0.11.277 prints: isdir/nlink/istale/ili_f)
Dominant class 15/16: **isdir=1 nlink=2 istale=0 ili_f=0x3 (DIRTY ITEM),
pend-dur=4, mode already NL, comm=kworker bast-drain, all at the
completed-release tail** — the workload's freshly self-created empty child
dirs, BASTed by peers' readdir. The Phase-2 drain COMPLETED and released while
the inode's 4 committed core changes sat unflushed on a dirty item.
Minority 1/16: isdir=0 nlink=0 ili_f=0x1 (orphan/inodegc family — GPT's
original D target; deferred until after the dominant fix).
Downstream same-family confirmation: P222 skip with stage_mode=NL (xfsaild
STAGED the residue at NL later — class Y copy-without-authority) and
pend=12>dur=10 persisting. P176=0 (leak bypasses that one guarded branch).
P56/P187 rollbacks 0-1/node uncorrelated — refuted as producer.
REFUTED by source read: restamp-at-attach (ISTALE attach stamps are honest;
restamping would launder; ifree_cluster BINVALs the buffer anyway — it is
never written through the mask).

## Mechanism hypothesis (UNPROVEN — instrument first)
The 4 commits sit in the CIL unforced at drain time → inode PINNED →
xfs_iflush skips pinned → drain finds nothing flushable → completes →
NL → later CIL push makes it flushable → xfsaild stages at NL. Alternatives
GPT insists be excluded by the SAME instrument: drain never visits the
releasing inode at all; visited-but-relogged-after; submitted-but-no-wait.

## GPT-approved fix design (transcript task: sess32 second consult)
1. FIRST: correlated drain trace keyed {ino, epoch, release attempt}:
   visited?, ili_fields before/after attempt, pin before/after, flush return
   /skip reason, writeback submitted?, pending/durable before attempt and at
   tail, any xfs_trans_log_inode after the attempt while RELFLUSH set.
2. Fix sequence (knobbed): enter RELFLUSH as a REAL ADMISSION INTERLOCK
   (paths starting protected mutations must wait/retry BEFORE deep trans
   code; never block writeback/CIL/AIL/iodone/force) → wait admitted
   mutators out → snapshot generation → ordinary drain → if open:
   XFS_LOG_SYNC force (targeted force only after LSN mapping proven) →
   reflush → wait iodone to snapshot → final cache flush → recheck no newer
   obligation → only then wire unlock + mode:=NL. Timeout BEFORE unlock →
   keep tenure, re-arm BAST (P15-REL-ABORT pattern), backoff + counters,
   escalate per shutdown policy. Trigger on ledger (pend!=dur), and MEASURE
   force frequency (ili_f||pin would over-trigger).
3. Core ledger = valid trigger/verify for THIS fix; full released⇒landed
   certificate ALSO needs dir-DATA/buffer obligations per tenure generation
   (register at logging, retire at home iodone) — parent dir blocks close at
   the PARENT's boundary; child-core predicate cannot certify them.
4. Rollout: trace → baseline classify → fix under knob → verify
   epoch_obligation→0 AND class-Y NL staging→0 → latency/force-freq →
   reclassify residue (esp. nlink=0) → inodegc reacquire for orphan class →
   buffer certificate → only then the defect can close.

## State: tree 0.11.277 (8C904A5BEAA1468EC77BA44) deployed all 32; board
green (cache 26s, crash 77s, dd 64-66s, dir_reuse 109-112s). Next concrete
step: the drain trace in mxfs_dlm_bast_process Phase 2 (find the inode flush
pass; add the per-attempt record; one lap; classify).
