---
name: gpt-consult-dir_reuse32-architectural-review
description: GPT-5.6 architectural review of dir_reuse_coherency@32/caw (asked 2026-07-11, v0.10.61/run61b r14 in flight): whack-a-mole verdict + concrete redesig…
metadata:
  type: project
tags: [dir_reuse_coherency, gpt-consult, architecture, caw, dlm, xfs_buf]
---

## Context
Asked 2026-07-11 per explicit user direction (bypassed the usual Fable-first chain). At the
time of asking: build v0.10.61 (srcversion 65CA8C4E) deployed for the `m_mxfs_dir_wr_inflight`
counter-leak fix; validation run "run61b" was live, round 14/24 clean (further than the two
preceding attempts, which died ~r11-13). Full problem statement sent to GPT is preserved at
`/tmp/claude-1000/-src-mxfs/6d1b9378-0788-4dca-876d-78c61534187a/scratchpad/dir_reuse_gpt_consult.md`
(scratchpad — may not survive; this note is the durable copy of the verdict).

## Verdict
v0.10.61 is a reasonable tactical patch but the overall multi-session trajectory (half a dozen
non-atomic latch fields added successively to `xfs_buf`/`xfs_inode`) is **architectural
whack-a-mole**. Three root mismatches named:
1. A cached on-disk lock grant is represented by an inode/buffer object with a *shorter*
   lifetime than the grant itself (inode reclaim can silently orphan a still-published grant).
2. Durability tracking uses mutable flags on reusable `xfs_buf`s instead of a per-lock-tenure
   I/O state machine.
3. No first-class "resource incarnation" in the DLM resource ID → inode-number reuse is a real
   ABA hazard by design, not an edge case.

## Specific critiques of the current fix (v0.10.61)
- The "already counted → skip" boolean is only correct for 2 of 4 possible resubmit shapes
  (dup submission, retry) — cannot distinguish those from "genuinely new write to a reused
  buffer" or "multiple bios for one logical write." Recommends an explicit logical-I/O
  incarnation context instead of a per-buffer bool.
- **The counter should be scoped per directory-lock-tenure, not per-mount.** A global counter
  means any unrelated directory's inflight write delays THIS directory's release — flagged as
  a design defect independent of the leak bug itself.
- **New blind spot**: counting at `xfs_buf_submit_bio` time is too late — a buffer can be
  dirty-but-unsubmitted, or queued for delayed writeback that fires AFTER lock release. The
  reference needs to start when the buffer/transaction is claimed by the tenure, not at submit.
- **Validation criterion is weak**: "zero P-WRCNT-RESUBMIT in a clean run" proves the buggy
  path wasn't exercised, not that it's correct. Wants a targeted fault-injection test that
  deliberately forces the resubmit shape and checks exactly-once accounting.
- **Timeout math**: 20s/release × up to 31 waiters vs a 120s acquire timeout means only ~6
  serialized releases fit before the oldest waiter expires — a queueing design defect that
  guarantees convoy failure under contention, separate from whether the specific leak recurs.
  Wants ONE single-flight downconvert state machine (the two independent 10s-capped wait sites
  in xfs_mxfs_dlm.c should collapse to one), waiters observing downconvert *progress* rather
  than blind timeouts, and the DLM distinguishing "incompatible + active progressing
  downconvert" vs "live but stuck" vs "dead session" vs "holderless/stale" — not one uniform
  timeout for all four.

## Positions that cut against current team assumptions
- **Calls the write-time "graft disk-only dirents into our buffer" merge logic (writemerge/
  drain_merge in pal/linux/xfs_buf.c) "a major smell."** Argument: if EX properly serializes
  directory mutation, there should be no legitimate concurrent peer add to merge at
  write-verify time; finding one means the base was stale at grant, a prior holder released
  before durability, or two tenures overlapped — i.e. this machinery may be masking/compensating
  for a serialization gap rather than correctly handling a real case, and risks manufacturing
  the exact leaf/data desync class this test hunts. Recommends treating it as a
  diagnostic/recovery guard only, not a substitute for correct exclusive serialization.
- **The H29→H30→H32 TCP-only-counter dead-code finding (orphan-escape silently no-op on CAW)
  is symptomatic, not isolated**: means recovery/orphan semantics aren't actually abstracted at
  the DLM layer — only the transport's message/atomic primitives should differ, not safety/
  liveness invariants. Wants an audit for other `if (transport-specific-counter) ...` guards
  that silently no-op on CAW.
- **Missing inode-generation in the DLM resource ID** (`{volume,ino,offset,AG,type}`, no
  generation): agrees this needs a protocol-level fix eventually, but says mixing generation
  into the hash alone is insufficient (collisions still occur in the fixed 65536-slot table) —
  wants full-key comparison, not hash-only mixing. Also: the DLM resource object should
  **outlive inode reclaim** (survive eviction, not reset to NL) so a peer can still find it and
  invoke a downconvert rather than seeing a stale slot. Flags a chicken-and-egg discovery
  problem (dirent gives inode number, not generation) → proposes a 2-stage lock (discovery/AG
  serialization, then generation-specific content lock) for the eventual protocol revision.
- **SB summary-counter drift (sess33 lead)**: worth actively rechecking but probably NOT the
  source of the exact 20.0xx-second signature — a separate, real defect. Gave a concrete test
  protocol: capture per-node in-core free/inode totals + which alloc branch (existing free vs
  new chunk) is taken + AG-btree-derived truth, then compare after a coordinated clean
  quiesce/unmount (a crash-image chk_mxfs run alone isn't fully conclusive re: replay state).
- Also: broader recommendation to audit for OTHER upstream-XFS state wrongly instantiated
  per-mount instead of per-filesystem (quota accounting, orphan processing, log/checkpoint
  ownership assumptions, speculative reservations, reclaim state, background writeback) — says
  this audit is more valuable right now than another narrow dir_reuse-specific probe pass.
- The known-open "ILOCK held across CAW poll" analog in the write/bmap-alloc path: don't
  timeout-tune it, enforce a structural lock-hierarchy rule ("no short-tenure content lock held
  across an unbounded/120s remote AG-allocation acquire") and stress-test across multiple
  AGs/dirs independently of this hot-single-directory test.

## Harness recommendation (fix independently of the kernel bug, cheap win)
Current aggregator can't distinguish "ran to completion, correctness checks failed" from
"nobody finished" — both collapse to low/zero nodes_pass. Wants structured per-rank terminal
states (PASS / CORRECTNESS_FAIL+round+counts / BARRIER_TIMEOUT+which-rank-missing /
SYSCALL_HANG+op+duration / KERNEL_SHUTDOWN / PROCESS_SSH_FAILURE / COORDINATOR_FAILURE /
NO_TERMINAL_RECORD), global-abort-on-first-detected-hang instead of cascading through all
remaining barriers (this round's failure burned ~2+ hours of predictable barrier-timeout
cascade), and capturing the blocked rank's kernel stack + DLM/downconvert state at the moment
of first failure rather than only post-hoc.

## Priority order GPT gave
1. Finish current validation run, keep the fix if invariants hold.
2. Add a targeted fault-injection test for the resubmit branch (clean-run silence isn't proof).
3. Replace the per-mount counter + per-buffer bool with per-resource/per-tenure logical-I/O
   accounting, referenced from tenure-claim time not submit-bio time.
4. Make DLM resource objects survive inode reclaim; eliminate bare in-core NL resets of
   possibly-published grants (audit the "never fully published inode" fast path specifically).
5. Collapse the two release-path barrier checks into one transport-independent downconvert
   state machine.
6. Add incarnation identity (full-key compare) in the next on-disk/protocol revision.
7. Recheck SB summary counters after a coordinated clean quiesce; trace whether false
   ifree==0 actually drives new-chunk allocation in the hot AG.
8. Fix the harness now (independent, cheap).
9. Separately address the write-path ILOCK-across-CAW-poll analog + broader mount-global-state
   audit.

## Cross-reference
This is layered on top of the exhaustive internal history already captured in
`.ccmemory/AAA-ccloop46ef-*` (Thread 1, 7 sessions) and `.ccmemory/AAA-ccloopa864-*` (Thread 2,
current, 9+ sessions) — see those for the full proven/refuted hypothesis chronology this
consult was built from.
