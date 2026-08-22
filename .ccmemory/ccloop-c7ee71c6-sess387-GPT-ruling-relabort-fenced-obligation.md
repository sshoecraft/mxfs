---
name: ccloop-c7ee71c6-sess387-GPT-ruling-relabort-fenced-obligation
description: sess387 RULE-5 ruling: fenced-obligation corpse fix = (b) release/reacquire state machine (no writable reacquire survives real EX->PR; terminal gate…
metadata:
  type: project
tags: [sess387, rule5, p119, rel-abort, obligations, agi-unlinked]
---

## sess387 ruling #2 — the fenced-obligation corpse chain (mid-chain P84 deaths)

### Measured chain (test18/test23, 0.19.29)
P15-REL-ABORT (holder re-acquired during inode-DLM drain; BAST re-armed) →
unlink commits 500us later (P82-ADD, conversion dirty ili_f=0x1) → mode already
PR(3) → P244-REL-TERMINAL-DEFER (obligation detected, too late) → xfsaild flush
fenced by P119-NONEX-FLUSH-SKIP (same gen/mode, disk_nlink=1 incore 0) →
conversion permanently fenced → ili_fields later evaporates by an UNIDENTIFIED
path → shell reclaimed clean (P88-PUBOB-RECLAIM clean=1 flushed=0) → stranded
bucket entry reads LINKED → adjacent remove/rename -117 → node shutdown.

### Ruling (GPT, full text in transcript)
- **(b) is the root fix**: the release/reacquire state machine. No writable
  local reacquire may survive a REAL EX→PR transition. If DLM still held EX,
  the PR i_dlm_mode is bookkeeping corruption — retain EX until the true
  downconvert linearization. If DLM completed the downconvert, the reacquirer
  must re-take EX before dirtying. Sequencing: hold EX → close gate to new
  writers → drain+flush → check obligations + dirty/reacquire SEQUENCE →
  anything new during drain ⇒ restart drain RETAINING EX → only then
  downconvert. The terminal obligation gate must sit BEFORE the downconvert
  (current P244 gate is after = too late), sequence-validated.
- **(d) independently mandatory**: a live obligation must survive re-log,
  staging, stale, abort, detach, reclaim, item replacement. Reclaim must
  REFUSE an inode with a live obligation regardless of ili_fields. Clearing
  the last relevant ili_fields bit while an obligation is live = fatal
  diagnostic (caller, LSN, stale state, release epoch, buffer-I/O state).
  Instrument EVERY fields-clearing transition — the evaporation point may
  precede reclaim substantially.
- **(a) REJECTED**: gen-equality + mode + disk_nlink>incore is provenance,
  not authority; do not weaken P119 in the normal flush path.
- **(c) RELFLUSH** is a scoped capability of a release EPOCH: valid only under
  continuous exclusion (active demoter blocking all peer grants, downconvert
  not yet linearized). Post-PR RELFLUSH = fence violation; reacquire EX first.

### State of the campaign at this point (build 0.19.29 CCC6E0A4ADABC6055D1A6DE)
- Rename-path (#361) head-split deaths: FIXED by target-flush+obligations
  (0 dirty-cancels in last 3 laps vs 1-3 before).
- Remaining head-split refusals: stage=ilock (rm/rsync holds ILOCK across DLM
  poll for whole 3s budget) — counted, published only because refuse knob off.
- Corpse chain: root understood per this ruling; (b)+(d) to build.
- Obligation store lives: xfs_mxfs_dlm.c (mxfs_pubob_*), flags MXFS_IF_PUBOB/
  _FLUSHED, tripwire P88-PUBOB-RECLAIM in xfs_reclaim_inode.
