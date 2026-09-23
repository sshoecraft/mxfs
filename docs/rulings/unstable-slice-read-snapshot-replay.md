<!-- sess411 RULE-5 ruling on -117 replay failure: snapshot+stabilize before replay, retryable-not-TORN before stability proven, record incarnation stamp… -->
# GPT ruling (sess411): foreign-replay unstable-slice-read fix design

Query: full evidence chain of the fln4_hb_churn -117 (see docs/history/replay-117-root-cause-live-slice-read-race.md). GPT verdict: hypothesis credible; later-clean platter does not exonerate storage path; item-position argument sound IF the batch counter and forensic ordinal count the same objects (instrument to be sure).

## Alternatives GPT wants ruled out (priority order)
a. Fence ineffective (new victim WRITEs ADMITTED post-PROUT — other key/nexus/path, cert before PROUT completion) — distinguish "victim completion after fencing" from "target ADMITTED write after fencing". Target-side SCST/AIO lifecycle tracing is the sharp discriminator.
b. Wrong/unstable replay bounds (capture kernel's tail/head decisions).
c. Another agent writing the slice LBAs post-fence.
d. Recovery-buffer in-memory corruption (hash at bio-complete / pre-CRC / post-assembly / pre-recover).
e. LUN/offset aliasing.

## Fix shape (ruled)
1. FENCE CONTRACT (Phase 3): certification must eventually mean access fence + I/O drain + durability barrier. SCST PA&A completing before backing-AIO side effects end is a target defect to fix/verify.
2. INTERIM STABILIZATION (Phase 2, land now): capture slice snapshot A (per-record manifest), wait, capture B, require A==B, wait, capture C, require B==C; validate AND REPLAY FROM THE SAME IMMUTABLE SNAPSHOT (never re-read between validate and replay — TOCTOU). Deadline >=15-30s (2-3s too short; observed landing window ~6s, past PA&A wait 12.4s). Non-quiescing at deadline => RECOVERY_IO_NOT_QUIESCED (blocked, retryable) — a DIFFERENT failure class from TORN.
3. RECORD INCARNATION (Phase 4, deep fix): versioned CRC-covered per-record binding {fs UUID, slot, writer/mount incarnation, generation, lsn}; persist incarnation before writer emits records; NEVER bridge a txn across an incarnation mismatch; current-gen records AFTER a mismatched record = mixed snapshot => retry/reject, not truncate-and-continue. Do NOT silently overload h_fmt/padding — version the format + incompat feature + update all tools.
4. UNKNOWN-TID tolerance: instrument every unknown-tid ophdr (lsn, tid, flags, open-txn count); during unstable/first attempt treat as retryable ambiguity; NEVER let regions after a discontinuity complete an item that began before it; validate item region counts/sizes/magics before pass 2.
5. RETRY POLICY: retryable = snapshot changed / incarnation mixed / suspicious unknown-tid / CRC-or-structure fail on unproven-stable image. Blocked-not-torn = still changing at deadline / drain not establishable. TERMINAL TORN only when: fence certified + drained/stable + one immutable snapshot + expected incarnation + repeated reads agree + full no-write validation still fails. Prefer full parse/validate BEFORE enabling home-block writes; distinguish slot-local from FSWIDE quarantine.
6. mkfs durable zero/stamp = defense-in-depth only.

## Key safety assertion (the bar)
No home-block replay write unless every contributing region came from ONE immutable snapshot, expected incarnation, passed CRC+structural validation, and belongs to a fully reconstructed committed txn.

## Verification matrix (subset to build into arms)
delayed backing AIO completing after PA&A; stale prev-incarnation CRC-valid same-cycle records; crash at each ophdr/continuation position; open txns at head; wraparound; retry-after-validation-failure asserting zero prior replay writes; stable genuinely-corrupt slice; genuine crashed victim with partial final iclog; live-fenced victim with seconds of AIO backlog.

## Notes vs current code
- Mid-pass delwri drain means earlier txns' buffers DO land before a later pass-2 failure — retry-from-tail is crash-restart-equivalent (safe); "zero replay writes" holds only for aborts before recovery starts. GPT wants full-validate-then-write eventually (Phase 2 proper).
- Existing retryable-abort pathway to reuse: P227-FR-ENFORCE-CFG-ABORT "aborting elected recovery (slice stays dirty, retryable)".
- PROBE-A/P88 firing on the replay worker is diagnostic noise for the authorized-recovery path.
