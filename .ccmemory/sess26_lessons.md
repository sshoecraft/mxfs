---
name: sess26_lessons
description: Sess26 root-cause findings — trans_dup AG-DLM release fix v0.3.106 + SCSI CAW under stress is broken (P49 evidence)
type: project
originSessionId: 73e1c997-3582-4131-ae15-23edc80ce38e
---
# Sess26 — root-cause analysis of bnobt LEFT/RIGHT-FAIL

## Headline findings

1. **Two independent root causes** behind sess24/25 bnobt LEFT/RIGHT-FAIL.

2. **Root cause #1 (FIXED in v0.3.106)**: `xfs_trans_dup` doesn't migrate
   `t_mxfs_ag_unlocks` to the new tp.  trans_free of the old tp drains
   pendings → releases AG-DLM mid-defer-chain.  Peer mutates bnobt;
   our new tp's defer items process against a stale view → corruption.
   Fix: `list_splice_init(&tp->t_mxfs_ag_unlocks, &ntp->t_mxfs_ag_unlocks)`.
   DO NOT migrate `t_mxfs_inode_unlocks` (causes peer ETIMEDOUT for
   ilock(ino=128, EX) at remount).

3. **Root cause #2 (OPEN at sess26 end)**: SCSI CAW on this LIO target
   under sustained concurrent stress is broken.  P49-INSTR confirms:
   after `caw_slot` returns CAS-success, immediate FUA-readback shows
   the slot still has pre-CAS content (zeros or stale-prior-session
   garbage).  Target reports SUCCESS but doesn't persist the write.

4. **Single-node 15×256 PASSES 15/15**.  The bug is exclusively
   cross-node.  Local XFS, buffer cache, defer-chain are all fine.

## Key evidence collected

### Experiment 1 (raw bnobt root capture at fail moment)
- T1 in-memory P33 bnobt = T1 disk hex = T2 disk hex (sha256 match)
- Falsifies all "stale buffer / cross-init read coherency" hypotheses
- Capture infra: `/tmp/sess26-{capture,exp1}.sh`

### Experiment 2 (trans_dup pending-AG count)
- P47-INSTR fired ~70 times in 70-second 15×256 run
- Each fire = AG-DLM grant about to be released because old tp drains
- Confirmed mechanism for root cause #1

### Experiment 3 (post-CAS verify)
- P49-INSTR fires every fail run on T2: post-CAS readback shows
  `v_magic=0xa29380 v_h_ex=a41c40 v_our_mode=4 expected=5`
- Garbage data unchanged across multiple retry attempts (deterministic
  divergence, not transient race)
- v0.3.107 retry-on-divergence caused infinite loop because target
  keeps reporting success without persisting

### Experiment 4 (single-node bisect)
- T2 unmounted, T1 only: 15×256 PASSES 15/15 cleanly
- Confirms cross-node origin of root cause #2

## What NOT to repeat in sess27

- Don't add more drain_meta_buffers / log_force / msleep tuning.
  Sess25 exhausted that design space; sess26 confirmed the bug is
  *above* the buffer cache.
- Don't add more cached-state instrumentation in `xfs_mxfs_dlm.c`.
  Sess26 P39 + P15 + P49 traces showed the cached state is
  downstream of the CAW issue.
- Don't revert v0.3.106.  It closes a real coherency hole proven by
  P47 evidence.
- Don't try retry-on-divergence in caw_lock without a way to skip
  poisoned slots.  Sess26 v0.3.107-retry caused infinite loop.

## Suggested sess27 path

1. Run `caw_verify` from both nodes IN PARALLEL while stress runs to
   confirm SCSI CAW divergence in isolation.  Look at LIO targetcli
   config (`emulate_caw`, backstore type, write-thru/back).
   **DONE in sess26**: caw_verify under load PASSES (zero LOCAL
   DIVERGENCE). LIO target is correct.  The bug is MXFS-specific.
2. Try TCP DLM transport (`mxfs_dlm_transport=TCP`) — avoids SCSI
   CAW entirely.  If passes 100% → primary path forward.
3. Investigate slot-collision: find_slot's linear probe selects an
   empty slot containing prior-session/inode-DLM data.  Our CAS
   targets it; in some race, our write doesn't take effect.  Add P52
   to log resource type + slot collision combos.
4. mkfs WRITE-FUA zeroing of disklock region (CLAUDE.md notes
   pwrite-O_SYNC isn't durable on LIO).  Would eliminate "magic-not-
   matching" corner case from prior sessions.

## Sess26 P51 finding (sense data on CAW)

Added P51-INSTR to log every CAW return + sense info.  Result: P51
NEVER fires — every CAW returns ret==0 with NO sense data.  So:
- Not a MISCOMPARE-being-missed bug
- Not a sense-data-with-success bug
- CAW genuinely returns SUCCESS with GOOD status

Yet post-CAS verify shows divergence.  Sess27 needs different angle
— possibly slot-collision (#3 above) or ABA race within tight
acquire/release ping-pong.

## v0.3.108 final state
- VERSION 0.3.108
- srcversion: `7C4289EA87BE01A8286E108`
- Pass rate 5×256 single-shot: ~50-83% across runs (similar to
  sess25 ~60% baseline; v0.3.106 trans_dup fix adds correctness
  but doesn't change observable pass rate due to remaining bug).
- All instrumentation log-only and dormant in pass paths.

## v0.3.109 final (sess26 truly final)
- VERSION 0.3.109
- srcversion: `6E8D09629680A3B131EB8F4`
- All v0.3.108 changes PLUS:
  - **P49 verify-read DISABLED in production** — `if (0 && resource->type ...)`
    in dlm/dlm_caw.c claim-empty.  Reduces SCSI command count per CAS-success
    by half.  Set the `0` to `1` to re-enable for diagnostics.
- Pass rate 5×256: HIGHLY VARIABLE.  Single-batch observations:
  - One run of 10: 9/10 PASS
  - Another run of 5: 0/5 FAIL (all bnobt LEFT-FAIL)
- 15×256: similarly variable (one PASS 15/15, then 5 consecutive fails)
- Disk-state contamination is real: after a 0/5 batch the disk has lots
  of corrupted state that mkfs's pwrite-O_SYNC doesn't durably zero.
  Subsequent runs may pick up that contamination.

## What did NOT work for root cause #2
- Global mutex around bdev_compare_and_write — caused inode-DLM
  ETIMEDOUT under contention
- Bucketed mutexes (16 buckets by LBA) — same issue
- blkdev_issue_flush after CAS-success — slight degradation
- retries=0 in scsi_execute_cmd — same pass rate
- DEADBEEF poison pre-fill of read buffer — confirmed read works
- P53 pre/post compare of CAW data buffer — confirmed write data not
  mutated by scsi_execute_cmd

## Confirmed about root cause #2 (kernel SCSI CAW)
- caw_verify userspace SG_IO ioctl works correctly under cross-init load
  (zero LOCAL DIVERGENCE in concurrent dual-writer test)
- MXFS kernel scsi_execute_cmd CAW: SOMETIMES reports success without
  the disk reflecting the write (confirmed via P49 hex dump showing
  cur_slot==diverged-bytes==prior content, write-bytes==MXCW magic)
- Bug is exclusively in the in-kernel SCSI passthrough path.  Sess27
  needs to investigate kernel scsi_execute_cmd vs SG_IO differences,
  OR port TCP DLM transport to v5_mount.c (currently CAW-only).
