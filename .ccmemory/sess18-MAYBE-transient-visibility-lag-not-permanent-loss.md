---
name: sess18-MAYBE-transient-visibility-lag-not-permanent-loss
description: sess18 LIVE THREAD (verify next): the 2/tcp "durable loss" MAY actually be a TRANSIENT visibility/durability LAG, not permanent data loss. Evidence:…
metadata:
  type: project
---

## sess18 (ccloop 8ddb16a2) — CRITICAL LIVE THREAD to resolve FIRST next session.

## THE REFRAME: I (and prior sessions) called the 2/tcp crash_consistency dir-entry loss a PERMANENT durable lost-update. But new evidence suggests it may be a TRANSIENT visibility/durability LAG (eventually-consistent), NOT permanent loss:
- With dirwr=1, cc_blockdir_probe iter2 (ino=1962, dir .ccb_2) reported 199/200, and BOTH recovery probes at that instant failed (pureLUN drop_caches+LUN-reread=199, direx touch+reread=199). I concluded "durable". BUT minutes later (when I listed the dir to find the missing entry) it was 200/200 — the entry REAPPEARED with NO corrective action. 
- All my earlier "durable, unrecoverable" verdicts this session (baseline iter4/14/16; force_block iter2/15) checked pureLUN+direx ONCE at the failure instant and moved on — NEVER re-checked seconds/minutes later. So they may ALSO have been transient.

## WHY THIS MATTERS: a transient lag (entry visible within seconds, converges) is a DIFFERENT bug than permanent data loss — less severe, and the fix target shifts to COHERENCY PROMPTNESS (the dir-EX handoff / writeback-visibility latency), per [[feedback_timing_is_failure]] (coherency must be prompt ~ms, eventual-consistency is still a fail but not corruption). It would also explain why the release path looks "clean" (no escape detectors) — the data IS eventually written, just not visible at the check instant. AND it would mean the whole merge/clobber framing this session may be partly misdirected.

## TEST RUNNING (resolve this first): task be4d24oir, script /tmp/transience_test.sh (RELOCATE to tests/ per RULE 3 if kept). Baseline (dirwr=0), full data+md5 workload (200 entries), 20 iters; on first short it re-polls the count every 4s for 32s (NO further writes) — if it climbs to 200 => TRANSIENT (visibility lag); if still short after 32s + a forced dir-EX touch cycle + test2-view check => PERMANENT. Read /tmp/claude-1000/-src-mxfs/5e810ddd-d219-4443-a289-36474bed76f2/tasks/be4d24oir.output for the verdict.

## IF TRANSIENT: pivot the investigation from "durable clobber / merge" to "dir-entry visibility lag at the DLM handoff" — why does a peer's committed+(eventually-durable) dirent take seconds to become visible to the other node even after drop_caches + a dir-EX touch cycle? Candidates: writeback not landing until a later AIL/log push; the reader's evict/refresh gen not advancing until a later event; SCST write-cache vs platter timing. IF PERMANENT: continue the insert-time / shortform-conversion lost-update path [[sess18-FINAL-insert-time-loss-reconciliation-and-path]].

## STATE: cluster baseline healthy (F13B9FB0, dir_merge=0 force_block=0 dirwr=0, mounted). Marker NOT written. All sess18 findings in the sess18-* memories. [[sess18-FINAL-insert-time-loss-reconciliation-and-path]] [[sess18-readside-ruled-out-writeside-clobber-confirmed]]
