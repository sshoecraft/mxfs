---
name: ccloop-c7ee71c6-sess33-EX-gate-shipped-P234-sensor-lesson
description: 0.11.289-290: EX-side epoch gate default-ON (numerator ~1/node, 0 unlanded); P234 LESSON: i_dlm_mode is the wrong authority sensor mid-drain — use ex…
metadata:
  type: project
---

# sess33 — EX gate shipped + the authority-sensor lesson

## EX-side epoch gate (0.11.289, knob mxfs.stale_stage_skip_ex, DEFAULT ON)
Sibling of the NL mask in pal/linux/xfs_buf.c's logged-slot submit branch:
`stale && ex && !rf && !dem && !ISTALE` → skip slot + PUB_SKIPPED
UNCONDITIONAL (P187 iodone re-arm restages CURRENT in-core under the live
grant — retry succeeds at EX) + unlanded → flush-watermark rollback.
ISTALE excluded per GPT (freed-state write must publish under live ifree
tenure — class-X). rf/dem contexts: counted in stale_ex, never skipped.
Counters in P219 dump: stale_ex / sskip_ex / sskip_ex_unl.
VALIDATED: 289 full 11-criterion board + 290 producing-mix, all green,
walls unchanged. Numerator ~1/node/board; sskip_ex fires exactly where
eligible; **sskip_ex_unl=0 always** (every skip was a landed byte-redundant
image). Rationale: skip-at-EX is ALWAYS safe — staged bytes are either
equal to current (restage = no-op) or peer-reverting (skip prevents
corruption); only cost is restage latency.

## THE SENSOR LESSON (cost a build cycle; do not relearn)
**`i_dlm_mode` is NOT the authority truth mid-drain.** Drain site 2 sets
`i_dlm_mode = NL` BEFORE the wire unlock; the FIX-25/26/27 nested
admissions (ioend conversion, writeback submitters — xfs_bmapi_finish,
xfs_iomap_write_unwritten, truncate tails, even the inactivation tail
xfs_attr_fork_remove/xfs_inode_uninit) legitimately take ILOCK_EXCL and
log in that window. Their admission incs `i_dlm_ex_holders`, and ANY
local EX holder PINS the wire grant (P15 holders-recheck aborts + re-arms
the release; the re-drain lands their commits before handoff). Correct
authority predicate at a log stamp:
`mode==EX || i_dlm_ex_holders>0 || i_mxfs_pipe_relog`.
The true bypasses (atomic ilock_try, ILOCK-nowait callers) increment
NOTHING and stay caught. P234 with this predicate = STRICT ZERO across
posix+mmap+strong+zsl+crash+dd on 290 (8 nodes sampled). Also explains
why dirent-workloads (dd/zsl) showed zero on 288 while the data-heavy
board fired it: ioend-during-drain collisions need writeback conversion.

## Where this leaves D-RELEASE-BARRIER-OPEN closure (GPT criteria)
DONE: criterion 1 (audit — sync-inactive structurally reacquires),
criterion 3 first counters (dirty-at-NL/PR strict zero, permanent
tripwire; stage-at-NL = P222 counters, quiet; sskip_unlanded=0 standing).
REMAINING: (2) deterministic race injection, (4) extended stress,
(5) reacquired-tenure drain cleanliness, (6) pace envelope, (7) 5-point
fault matrix, + the dir-DATA per-dir charge aggregation (survives buffer
struct recycle — the run64 blindness; no measured numerator today).
