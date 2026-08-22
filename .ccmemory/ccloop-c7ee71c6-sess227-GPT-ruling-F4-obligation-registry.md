---
name: ccloop-c7ee71c6-sess227-GPT-ruling-F4-obligation-registry
description: sess227 RULE-5 ruling on F4 dir committed-never-submitted registry: enumerable records not count-only, own u64 gen, shutdown-only abort cancel, tenur…
metadata:
  type: project
tags: [f4, obligation-registry, foreign-replay, gpt-ruling, rule5]
---

# sess227 GPT ruling — F4 obligation registry (D-FOREIGN-REPLAY step 4)

Full text in sess227 transcript (task kwp0on94b). Consolidated dispositions:

## Overall: shape directionally correct, NOT yet a hard barrier. Fix before enforcement:

1. **Count-only registry insufficient.** Records must be ENUMERABLE with buffer
   identity — hold a bp reference OR a stable {daddr, length, owner, committed_gen}
   repair descriptor — so release can re-drive the exact buffer. A fence-suppressed
   "success" can leave the buffer apparently clean and invisible to the fork walk
   forever (the (f) permanent-wedge scenario); {ino,count} cannot repair it.
2. **Do NOT reuse b_mxfs_logged_seq.** It's a log-call counter, not a dirty
   generation, and XFS_BLI_ORDERED buffers are dirty WITHOUT advancing it. Use an
   F4-own u64 generation (no wrap analysis needed). Ordered F4-class buffers:
   handle explicitly — open the obligation anyway (fail-closed) + probe occurrence.
3. **Abort cancel too broad.** A later aborting transaction must NOT cancel an
   older committed obligation. Cancel ONLY under xlog_is_shutdown (terminal),
   tracked as shutdown_cancelled (separate from stale_cancelled). aborted &&
   !shutdown with open obligation = loud probe + KEEP open. Raw xfs_buf_stale()
   is NOT a cancel point; only finish_stale (committed XFS_BLF_CANCEL).
4. **Registry keyed only by ino is safe ONLY under induction** (obligation blocks
   unlock ⇒ cannot cross tenure). Induction does NOT hold in telemetry-only mode
   or during dynamic enablement. Before knob=1 enforcement: tag obligations with
   tenure generation OR require full drain/reset at enable.
5. **Close/check race:** iop_committing opening an obligation AFTER the proof
   observes zero makes the barrier unsound. Enforcement needs linearized
   close-new-opens → observe-zero → unlock (the oblig_cas/tenure-close protocol).
6. **Eviction/reuse:** buffer destruction with open obligation must fail closed —
   free-time assertion probe + orphan the record (keep count, mark buffer-gone),
   never silently clear F4 fields at reuse.
7. **Retire condition:** any successful non-suppressed FULL covering write whose
   submit snapshot >= latest committed gen. Do NOT lean on "abort stales newer
   uncommitted data" — assert instead that a write cannot be submitted with
   uncommitted newer mods (pin/lock rules should already guarantee; verify).
8. **Owner from v5 header: OK** with magic/type validation, be64 decode, and
   fail-closed on owner==0/invalid (open into unknown-owner poison bucket, probe).
   Assert extracted owner == b_mxfs_f4_owner while open.
9. **bmbt: include NOW** (same exposure; counting non-dir bmbt too is conservative
   and fine — only dir release consults by owner ino).
10. **Certificate: SEPARATE F4 fields** (f4_open_before/after_pass, f4_unknown/
    overflow, f4_blocked, stale_cancelled vs shutdown_cancelled). Never fold into
    the pending-durable oblig_* delta.
11. **Overflow:** mempool/prealloc preferred over sticky mount-wide poison flag
    (operationally severe); keep poison as last resort.

## Implementation decisions taken (sess227)
- Descriptor approach WITHOUT bp hold (bp hold would wedge xfs_buftarg_drain at
  unmount on a leak; descriptor + free-time orphan probe is fail-closed & loud
  without wedging the rig).
- Per-buffer u64 f4_committed_gen/f4_submit_gen/f4_retired_gen + f4_owner +
  record ptr; all under b_sema. Registry: per-mount 256-bucket hash + spinlock,
  mempool-backed records.
- Telemetry-first (knob default 0), census probe P285 = registry-open+walk-clean,
  P284 family for lifecycle anomalies. Ship 0.11.481.
- Enforcement (knob=1) BLOCKED on items 4+5 (tenure tagging / drain-at-enable +
  close-race linearization) — record in ledger next-steps.
