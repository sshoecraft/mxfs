---
name: ccloop-c7ee71c6-sess350-idle-slice-natural-refusal-ag0-quarantine
description: sess350: race-6 run fenced idle test2; replayer REFUSED its 2-SB-image slice (v3 class=2 st=3 wskip counted as torn) → AG0 quarantined cluster-wide.…
metadata:
  type: project
---

# sess350 — idle-victim slice natural refusal → AG 0 quarantine (evidence package)

## Incident (2026-08-15 16:08:57–16:10:05Z, 0.13.0 sv F191408004F380B726E4887)
Race-6 first attempt (tests/clean_depart_lineage_race.sh, new): suspended test2,
umount+remount test3. test3's remount blocked ~53s in P225-SETTLE-VERIFY
(v5_mount.c v5_settle_resolve, 31 samples/62s — frozen test2 held authority
mask 0x40) → suspend window 65s ≥ death threshold → test1 declared test2 dead
at 16:10:02, fenced; test2 self-fenced on resume (P236/P131 SLOT_TAKEOVER).

## The load-bearing finding
test3 (elected replayer, P238-RECOV-LEASE stage=2) refused IDLE test2's slice:
- slice content: exactly 2 committed txns, each 1 SB buffer image (blkno=0
  len=1), P227-TOKEN v=3 class=2 st=3 res=0 gepoch=0; TOKENSUM tokened=1
  untagged=0 wapply=0 wskip=1.
- Each txn → ATOMIC-SKIP (xfs_log_recover.c:2963 "contains untagged image(s)"
  — WRONG, images were tagged v3; message conflates wskip with untagged).
- → P227-FR-TORN-UNPUBLISHED (xfs_log.c:1057) "refused 2 committed untagged
  image(s)" → replay rc=-117 → P241-RECOV-TERMINAL reason=1 domain=2
  ag_mask=0x1 digest=947b79e6 → **AG 0 quarantined cluster-wide, slot 6 frozen
  until operator action**.
- P273-SHADOW-EVAL: buf=2 csum=2 sb=2 WOULD_APPLY=0 — shadow evaluator agrees
  nothing would apply; yet the outcome is quarantine, not clean completion.

An idle, healthy-but-frozen node's routine slice (lazy SB counter logging)
poisons AG 0 for the entire cluster. This is the sess346 "natural refusal ⇒
quarantine" owed item with a full natural repro. NOT in the ledger (#8
D-FOREIGN-REPLAY-REFUSAL-CLUSTERWIDE-SUICIDE-513 covers the pre-containment
suicide; #15 D-MASS-FALSE-DEATH-FROZEN-GRANT-STALL-482 covers frozen grants).
Next: ledger it; RULE-5 on whether st=3-wskip SB images should ever count as
refusal-grade torn evidence.

## Race 6/7 choreography fix (proven mechanism)
P225 mount barrier is AUTHORITY-GATED: only frozen slots in mount_stale_mask
(held cross-instance authority at mount) trigger the 62s confirm. Fix: fresh
umount+remount A first (drops cached authority; verify with caw_slotdump
--held-only no holder bit for A), then suspend A → B remounts ~12s each
(membership settle 7000ms), CYCLES=2 ≈ 26s < 40s.

## Incidental positives
- P163-CLEAN-DEPART-LINEAGE fired correctly on BOTH test1 and resumed test2
  for test3's slot 7 (successor seq=+1 chain=2) — the #92 lineage arm works.
- test3 rejoin epoch/prov arithmetic verified on disk via extended slotdump.
- tools/caw_slotdump now prints epoch+prov{prev_node,prev_epoch,seq,chain}
  (build: gcc -O2 -Wall -Iinclude). test1=hb0, test2=hb6, test3=hb7.
- P225-SETTLE-ALIVE on test3 correctly declined to double-declare test2 when
  test1's GUARD takeover changed the record mid-confirm (sample 22/31).

## Cluster state at handoff
DIRTY: AG 0 quarantined, slot 6 frozen, test2 fenced+shutdown (still
"mounted" in shutdown state). Requires full re-prep (./run.sh 32 caw
prep_cluster) before any further board/race work.
