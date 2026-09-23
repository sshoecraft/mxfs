<!-- sess444 RULE-5 ruling on the 4.4 s/slice slice-snapshot stability proof: pipelining across slices GO (each slice keeps pass0 + 2 sleep-separated comp… -->
# Ruling: mxfs_xlog_slice_snapshot cost (2 x 2 s compare passes per foreign slice; 31 x 4.5 s = 136 s of the 32-node bootstrap)

- A. PIPELINE — GO with invariants: each slice independently performs pass 0 + two sleep-separated compare passes; a mismatch folds and resets that slice's stable count; the 45 s deadline is per slice and starts at that slice's snapshot attempt (queueing must not consume it); N+1 is never replayed before its own proof completes; once replay of a buffer begins no asynchronous compare may modify it; snapshot reads of N+1 vs replay writes of N are on disjoint slice LBAs (assert); replay should follow stability promptly (don't prove many slices early and leave them waiting); on cancellation/error never fall back to live reads. Start N+1 after N's pass 0 (or phase two buffers) for ~2x; 2 x 64 MiB resident is acceptable.
- B. Credit time since the PREEMPT&ABORT certificate — STOP-SHIP: orphaned backing AIO can land after pass 0 regardless of certificate age; B shrinks the detection window (counter-example given).
- C. One compare pass for old certificates — STOP-SHIP: no enforced upper bound on orphaned-AIO completion; only a hard backend guarantee could justify it.
- D. Keep as is — safe, unnecessary.
- Long term: a target/backend DRAIN primitive whose completion guarantees every pre-abort write completed or was cancelled, recorded in the certificate; SYNCHRONIZE CACHE is not sufficient without explicit ordering after orphaned AIO.
Absence of P-FRSTAB-UNSTABLE in 128 bootstrap slices = 95% upper bound ~2.3% on the event rate; performance evidence, not a correctness proof.
